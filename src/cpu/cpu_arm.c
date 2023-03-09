/*
 * cpu_arm.c: CPU driver for arm CPUs
 *
 * Copyright (C) 2020 Huawei Technologies Co., Ltd.
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright (C) Canonical Ltd. 2012
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#if defined(__aarch64__)
# if defined(WITH_ASM_HWCAP_H)
#  include <asm/hwcap.h>
# endif
# if defined(WITH_SYS_AUXV_H)
#  include <sys/auxv.h>
# endif
#endif

#include "viralloc.h"
#include "cpu.h"
#include "cpu_arm.h"
#include "cpu_map.h"
#include "virlog.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_CPU

/* Shift bit mask for parsing cpu flags */
#define BIT_SHIFTS(n) (1UL << (n))
/* The current max number of cpu flags on ARM is 32 */
#define MAX_CPU_FLAGS 32


VIR_LOG_INIT("cpu.cpu_arm");

static const virArch archs[] = {
    VIR_ARCH_ARMV6L,
    VIR_ARCH_ARMV7B,
    VIR_ARCH_ARMV7L,
    VIR_ARCH_AARCH64,
};

typedef struct _virCPUarmVendor virCPUarmVendor;
struct _virCPUarmVendor {
    char *name;
    unsigned long long value;
};

typedef struct _virCPUarmModel virCPUarmModel;
struct _virCPUarmModel {
    char *name;
    virCPUarmVendor *vendor;
    virCPUarmData data;
};

typedef struct _virCPUarmFeature virCPUarmFeature;
struct _virCPUarmFeature {
    char *name;
};

static virCPUarmFeature *
virCPUarmFeatureNew(void)
{
    return g_new0(virCPUarmFeature, 1);
}

static void
virCPUarmFeatureFree(virCPUarmFeature *feature)
{
    if (!feature)
        return;

    g_free(feature->name);

    g_free(feature);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmFeature, virCPUarmFeatureFree);

typedef struct _virCPUarmMap virCPUarmMap;
struct _virCPUarmMap {
    size_t nvendors;
    virCPUarmVendor **vendors;
    size_t nmodels;
    virCPUarmModel **models;
    GPtrArray *features;
};

static virCPUarmMap *
virCPUarmMapNew(void)
{
    virCPUarmMap *map;

    map = g_new0(virCPUarmMap, 1);

    map->features = g_ptr_array_new();
    g_ptr_array_set_free_func(map->features,
                              (GDestroyNotify) virCPUarmFeatureFree);

    return map;
}

static void
virCPUarmDataClear(virCPUarmData *data)
{
    if (!data)
        return;

    g_strfreev(data->features);
}

static virCPUCompareResult
virCPUarmDataIsIdentical(const virCPUData *a,
                         const virCPUData *b)
{
    size_t i;

    if (!a || !b)
        return VIR_CPU_COMPARE_ERROR;

    if (a->arch != b->arch)
        return VIR_CPU_COMPARE_INCOMPATIBLE;

    if (a->data.arm.pvr != b->data.arm.pvr)
        return VIR_CPU_COMPARE_INCOMPATIBLE;

    if (a->data.arm.vendor_id != b->data.arm.vendor_id)
        return VIR_CPU_COMPARE_INCOMPATIBLE;

    for (i = 0; i < MAX_CPU_FLAGS; ++i) {
        if (STRNEQ(a->data.arm.features[i], b->data.arm.features[i]))
            return VIR_CPU_COMPARE_INCOMPATIBLE;
    }

    return VIR_CPU_COMPARE_IDENTICAL;
}

static virCPUData *
virCPUarmDataCopyNew(virCPUData *data)
{
    virCPUData *copy;
    size_t i;

    if (!data)
        return NULL;

    copy = virCPUDataNew(data->arch);
    copy->data.arm.pvr = data->data.arm.pvr;
    copy->data.arm.vendor_id = data->data.arm.vendor_id;
    copy->data.arm.features = g_new0(char *, MAX_CPU_FLAGS + 1);
    for (i = 0; i < MAX_CPU_FLAGS; ++i)
        copy->data.arm.features[i] = g_strdup(data->data.arm.features[i]);

    return copy;
}

static void
virCPUarmDataFree(virCPUData *cpuData)
{
    if (!cpuData)
        return;

    virCPUarmDataClear(&cpuData->data.arm);
    g_free(cpuData);
}

static void
virCPUarmModelFree(virCPUarmModel *model)
{
    if (!model)
        return;

    virCPUarmDataClear(&model->data);
    g_free(model->name);
    g_free(model);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmModel, virCPUarmModelFree);

static void
virCPUarmVendorFree(virCPUarmVendor *vendor)
{
    if (!vendor)
        return;

    g_free(vendor->name);
    g_free(vendor);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmVendor, virCPUarmVendorFree);

static void
virCPUarmMapFree(virCPUarmMap *map)
{
    size_t i;

    if (!map)
        return;

    for (i = 0; i < map->nmodels; i++)
        virCPUarmModelFree(map->models[i]);
    g_free(map->models);

    for (i = 0; i < map->nvendors; i++)
        virCPUarmVendorFree(map->vendors[i]);
    g_free(map->vendors);

    g_ptr_array_free(map->features, TRUE);

    g_free(map);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmMap, virCPUarmMapFree);

static virCPUarmFeature *
virCPUarmMapFeatureFind(virCPUarmMap *map,
                        const char *name)
{
    size_t i;

    for (i = 0; i < map->features->len; i++) {
        virCPUarmFeature *feature = g_ptr_array_index(map->features, i);

        if (STREQ(feature->name, name))
            return feature;
    }

    return NULL;
}

static int
virCPUarmMapFeatureParse(xmlXPathContextPtr ctxt G_GNUC_UNUSED,
                         const char *name,
                         void *data)
{
    g_autoptr(virCPUarmFeature) feature = NULL;
    virCPUarmMap *map = data;

    if (virCPUarmMapFeatureFind(map, name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU feature %1$s already defined"), name);
        return -1;
    }

    feature = virCPUarmFeatureNew();
    feature->name = g_strdup(name);

    g_ptr_array_add(map->features, g_steal_pointer(&feature));

    return 0;
}

static virCPUarmVendor *
virCPUarmVendorFindByID(virCPUarmMap *map,
                        unsigned long long vendor_id)
{
    size_t i;

    for (i = 0; i < map->nvendors; i++) {
        if (map->vendors[i]->value == vendor_id)
            return map->vendors[i];
    }

    return NULL;
}


static virCPUarmVendor *
virCPUarmVendorFindByName(virCPUarmMap *map,
                          const char *name)
{
    size_t i;

    for (i = 0; i < map->nvendors; i++) {
        if (STREQ(map->vendors[i]->name, name))
            return map->vendors[i];
    }

    return NULL;
}


static int
virCPUarmVendorParse(xmlXPathContextPtr ctxt,
                     const char *name,
                     void *data)
{
    virCPUarmMap *map = data;
    g_autoptr(virCPUarmVendor) vendor = NULL;

    vendor = g_new0(virCPUarmVendor, 1);
    vendor->name = g_strdup(name);

    if (virCPUarmVendorFindByName(map, vendor->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU vendor %1$s already defined"),
                       vendor->name);
        return -1;
    }

    if (virXMLPropULongLong(ctxt->node, "value", 16, VIR_XML_PROP_REQUIRED,
                            &vendor->value) < 0)
        return -1;

    if (virCPUarmVendorFindByID(map, vendor->value)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU vendor value 0x%1$2llx already defined"),
                       vendor->value);
        return -1;
    }

    VIR_APPEND_ELEMENT(map->vendors, map->nvendors, vendor);

    return 0;
}

static virCPUarmModel *
virCPUarmModelFind(virCPUarmMap *map,
                   const char *name)
{
    size_t i;

    for (i = 0; i < map->nmodels; i++) {
        if (STREQ(map->models[i]->name, name))
            return map->models[i];
    }

    return NULL;
}

#if defined(__aarch64__)
static virCPUarmModel *
virCPUarmModelFindByPVR(virCPUarmMap *map,
                        unsigned long long pvr)
{
    size_t i;

    for (i = 0; i < map->nmodels; i++) {
        if (map->models[i]->data.pvr == pvr)
            return map->models[i];
    }

    return NULL;
}
#endif

static int
virCPUarmModelParse(xmlXPathContextPtr ctxt,
                    const char *name,
                    void *data)
{
    virCPUarmMap *map = data;
    g_autoptr(virCPUarmModel) model = NULL;
    xmlNodePtr vendorNode = NULL;
    xmlNodePtr pvrNode = NULL;

    model = g_new0(virCPUarmModel, 1);
    model->name = g_strdup(name);

    if (virCPUarmModelFind(map, model->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU model %1$s already defined"),
                       model->name);
        return -1;
    }

    if ((vendorNode = virXPathNode("./vendor", ctxt))) {
        g_autofree char *vendor = NULL;

        if (!(vendor = virXMLPropStringRequired(vendorNode, "name")))
            return -1;

        if (!(model->vendor = virCPUarmVendorFindByName(map, vendor))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown vendor %1$s referenced by CPU model %2$s"),
                           vendor, model->name);
            return -1;
        }
    }

    if (!(pvrNode = virXPathNode("./pvr", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing PVR information for CPU model %1$s"),
                       model->name);
        return -1;
    }

    if (virXMLPropULongLong(pvrNode, "value", 16, VIR_XML_PROP_REQUIRED,
                            &model->data.pvr) < 0)
        return -1;

    VIR_APPEND_ELEMENT(map->models, map->nmodels, model);

    return 0;
}

static virCPUarmMap *
virCPUarmLoadMap(void)
{
    g_autoptr(virCPUarmMap) map = NULL;

    map = virCPUarmMapNew();

    if (cpuMapLoad("arm", virCPUarmVendorParse, virCPUarmMapFeatureParse,
                   virCPUarmModelParse, map) < 0)
        return NULL;

    return g_steal_pointer(&map);
}

static virCPUarmMap *cpuMap;

int virCPUarmDriverOnceInit(void);
VIR_ONCE_GLOBAL_INIT(virCPUarmDriver);

int
virCPUarmDriverOnceInit(void)
{
    if (!(cpuMap = virCPUarmLoadMap()))
        return -1;

    return 0;
}

static virCPUarmMap *
virCPUarmGetMap(void)
{
    if (virCPUarmDriverInitialize() < 0)
        return NULL;

    return cpuMap;
}

static int
virCPUarmUpdate(virCPUDef *guest,
                const virCPUDef *host,
                bool relative)
{
    g_autoptr(virCPUDef) updated = virCPUDefCopyWithoutModel(guest);

    if (!relative || guest->mode != VIR_CPU_MODE_HOST_MODEL)
        return 0;

    if (!host) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unknown host CPU model"));
        return -1;
    }

    updated->mode = VIR_CPU_MODE_CUSTOM;
    virCPUDefCopyModel(updated, host, true);

    virCPUDefStealModel(guest, updated, false);
    guest->mode = VIR_CPU_MODE_CUSTOM;
    guest->match = VIR_CPU_MATCH_EXACT;

    return 0;
}


static virCPUDef *
virCPUarmBaseline(virCPUDef **cpus,
                  unsigned int ncpus G_GNUC_UNUSED,
                  virDomainCapsCPUModels *models G_GNUC_UNUSED,
                  const char **features G_GNUC_UNUSED,
                  bool migratable G_GNUC_UNUSED)
{
    virCPUDef *cpu = NULL;

    cpu = virCPUDefNew();

    cpu->model = g_strdup(cpus[0]->model);

    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;

    return cpu;
}

static virCPUCompareResult
virCPUarmCompare(virCPUDef *host,
                 virCPUDef *cpu,
                 bool failIncompatible)
{
    /* Only support host to host CPU compare for ARM */
    if (cpu->type != VIR_CPU_TYPE_HOST)
        return VIR_CPU_COMPARE_IDENTICAL;

    if (!host || !host->model) {
        if (failIncompatible) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s",
                           _("unknown host CPU"));
            return VIR_CPU_COMPARE_ERROR;
        }

        VIR_WARN("unknown host CPU");
        return VIR_CPU_COMPARE_INCOMPATIBLE;
    }

    /* Compare vendor and model to check if CPUs are identical */
    if (STRNEQ_NULLABLE(host->vendor, cpu->vendor) ||
        STRNEQ_NULLABLE(host->model, cpu->model)) {
        VIR_DEBUG("Host CPU model does not match required CPU "
                  "vendor %s or(and) model %s",
                  NULLSTR(cpu->vendor), NULLSTR(cpu->model));

        if (failIncompatible) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE,
                           _("Host CPU model does not match required CPU vendor %1$s or(and) model %2$s"),
                           NULLSTR(cpu->vendor), NULLSTR(cpu->model));
            return VIR_CPU_COMPARE_ERROR;
        }

        return VIR_CPU_COMPARE_INCOMPATIBLE;
    }

    return VIR_CPU_COMPARE_IDENTICAL;
}

static int
virCPUarmValidateFeatures(virCPUDef *cpu)
{
    virCPUarmMap *map;
    size_t i;

    if (!(map = virCPUarmGetMap()))
        return -1;

    for (i = 0; i < cpu->nfeatures; i++) {
        virCPUFeatureDef *feature = &cpu->features[i];

        if (!virCPUarmMapFeatureFind(map, feature->name)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown CPU feature: %1$s"),
                           feature->name);
            return -1;
        }
    }

    return 0;
}

#if defined(__aarch64__) && (defined(WITH_GETAUXVAL) || defined(WITH_ELF_AUX_INFO))
/* Generate human readable flag list according to the order of */
/* AT_HWCAP bit map */
const char *aarch64_cpu_flags[MAX_CPU_FLAGS] = {
    "fp", "asimd", "evtstrm", "aes", "pmull", "sha1", "sha2",
    "crc32", "atomics", "fphp", "asimdhp", "cpuid", "asimdrdm",
    "jscvt", "fcma", "lrcpc", "dcpop", "sha3", "sm3", "sm4",
    "asimddp", "sha512", "sve", "asimdfhm", "dit", "uscat",
    "ilrcpc", "flagm", "ssbs", "sb", "paca", "pacg"};
/**
 * virCPUarmCpuDataFromRegs:
 *
 * @data: 64-bit arm CPU specific data
 *
 * Fetches CPU vendor_id and part_id from MIDR_EL1 register, parse CPU
 * flags from AT_HWCAP. There are currently 32 valid flags  on ARM arch
 * represented by each bit.
 */
static int
virCPUarmCpuDataFromRegs(virCPUarmData *data)
{
    unsigned long cpuid;
    unsigned long hwcaps;
    g_auto(GStrv) features = NULL;
    int cpu_feature_index = 0;
    size_t i;

# if defined(WITH_GETAUXVAL)
    hwcaps = getauxval(AT_HWCAP);
# elif defined(WITH_ELF_AUX_INFO)
    elf_aux_info(AT_HWCAP, &hwcaps, sizeof(u_long));
# endif
    VIR_DEBUG("CPU flags read from register:  0x%016lx", hwcaps);

    if (!(hwcaps & HWCAP_CPUID)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("CPUID registers unavailable"));
            return -1;
    }

    /* read the cpuid data from MIDR_EL1 register */
    asm("mrs %0, MIDR_EL1" : "=r" (cpuid));
    VIR_DEBUG("CPUID read from register:  0x%016lx", cpuid);

    /* parse the corresponding part_id bits */
    data->pvr = (cpuid >> 4) & 0xfff;
    /* parse the corresponding vendor_id bits */
    data->vendor_id = (cpuid >> 24) & 0xff;

    features = g_new0(char *, MAX_CPU_FLAGS + 1);

    /* shift bit map mask to parse for CPU flags */
    for (i = 0; i < MAX_CPU_FLAGS; i++) {
        if (hwcaps & BIT_SHIFTS(i)) {
            features[cpu_feature_index] = g_strdup(aarch64_cpu_flags[i]);
            cpu_feature_index++;
        }
    }

    if (cpu_feature_index > 0)
        data->features = g_steal_pointer(&features);

    return 0;
}

static int
virCPUarmDecode(virCPUDef *cpu,
                const virCPUarmData *cpuData,
                virDomainCapsCPUModels *models)
{
    size_t i;
    virCPUarmMap *map;
    virCPUarmModel *model;
    virCPUarmVendor *vendor = NULL;

    if (!cpuData || !(map = virCPUarmGetMap()))
        return -1;

    if (!(model = virCPUarmModelFindByPVR(map, cpuData->pvr))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Cannot find CPU model with PVR 0x%1$03llx"),
                       cpuData->pvr);
        return -1;
    }

    if (!virCPUModelIsAllowed(model->name, models)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("CPU model %1$s is not supported by hypervisor"),
                       model->name);
        return -1;
    }

    cpu->model = g_strdup(model->name);

    if (cpuData->vendor_id &&
        !(vendor = virCPUarmVendorFindByID(map, cpuData->vendor_id))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Cannot find CPU vendor with vendor id 0x%1$02llx"),
                       cpuData->vendor_id);
        return -1;
    }

    if (vendor)
        cpu->vendor = g_strdup(vendor->name);

    if (cpuData->features) {
        cpu->nfeatures = g_strv_length(cpuData->features);
        cpu->features = g_new0(virCPUFeatureDef, cpu->nfeatures);

        for (i = 0; i < cpu->nfeatures; i++) {
            cpu->features[i].policy = VIR_CPU_FEATURE_REQUIRE;
            cpu->features[i].name = g_strdup(cpuData->features[i]);
        }
    }

    return 0;
}

static int
virCPUarmGetHost(virCPUDef *cpu,
                 virDomainCapsCPUModels *models)
{
    g_autoptr(virCPUData) cpuData = NULL;

    if (virCPUarmDriverInitialize() < 0)
        return -1;

    if (!(cpuData = virCPUDataNew(archs[0])))
        return -1;

    if (virCPUarmCpuDataFromRegs(&cpuData->data.arm) < 0)
        return -1;

    return virCPUarmDecode(cpu, &cpuData->data.arm, models);
}
#endif


struct cpuArchDriver cpuDriverArm = {
    .name = "arm",
    .arch = archs,
    .narch = G_N_ELEMENTS(archs),
    .compare = virCPUarmCompare,
#if defined(__aarch64__) && (defined(WITH_GETAUXVAL) || defined(WITH_ELF_AUX_INFO))
    .getHost = virCPUarmGetHost,
#endif
    .decode = NULL,
    .encode = NULL,
    .getVendorForModel = NULL,
    .dataCopyNew = virCPUarmDataCopyNew,
    .dataFree = virCPUarmDataFree,
    .baseline = virCPUarmBaseline,
    .update = virCPUarmUpdate,
    .validateFeatures = virCPUarmValidateFeatures,
    .dataIsIdentical = virCPUarmDataIsIdentical,
};
