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

#include "viralloc.h"
#include "cpu.h"
#include "cpu_arm.h"
#include "cpu_map.h"
#include "virlog.h"
#include "virstring.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_CPU

VIR_LOG_INIT("cpu.cpu_arm");

static const virArch archs[] = {
    VIR_ARCH_ARMV6L,
    VIR_ARCH_ARMV7B,
    VIR_ARCH_ARMV7L,
    VIR_ARCH_AARCH64,
};

typedef struct _virCPUarmVendor virCPUarmVendor;
typedef virCPUarmVendor *virCPUarmVendorPtr;
struct _virCPUarmVendor {
    char *name;
    unsigned long value;
};

typedef struct _virCPUarmModel virCPUarmModel;
typedef virCPUarmModel *virCPUarmModelPtr;
struct _virCPUarmModel {
    char *name;
    virCPUarmVendorPtr vendor;
    virCPUarmData data;
};

typedef struct _virCPUarmFeature virCPUarmFeature;
typedef virCPUarmFeature *virCPUarmFeaturePtr;
struct _virCPUarmFeature {
    char *name;
};

static virCPUarmFeaturePtr
virCPUarmFeatureNew(void)
{
    return g_new0(virCPUarmFeature, 1);
}

static void
virCPUarmFeatureFree(virCPUarmFeaturePtr feature)
{
    if (!feature)
        return;

    g_free(feature->name);

    g_free(feature);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmFeature, virCPUarmFeatureFree);

typedef struct _virCPUarmMap virCPUarmMap;
typedef virCPUarmMap *virCPUarmMapPtr;
struct _virCPUarmMap {
    size_t nvendors;
    virCPUarmVendorPtr *vendors;
    size_t nmodels;
    virCPUarmModelPtr *models;
    GPtrArray *features;
};

static virCPUarmMapPtr
virCPUarmMapNew(void)
{
    virCPUarmMapPtr map;

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

    virStringListFree(data->features);
}

static void
virCPUarmDataFree(virCPUDataPtr cpuData)
{
    if (!cpuData)
        return;

    virCPUarmDataClear(&cpuData->data.arm);
    g_free(cpuData);
}

static void
virCPUarmModelFree(virCPUarmModelPtr model)
{
    if (!model)
        return;

    virCPUarmDataClear(&model->data);
    g_free(model->name);
    g_free(model);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmModel, virCPUarmModelFree);

static void
virCPUarmVendorFree(virCPUarmVendorPtr vendor)
{
    if (!vendor)
        return;

    g_free(vendor->name);
    g_free(vendor);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUarmVendor, virCPUarmVendorFree);

static void
virCPUarmMapFree(virCPUarmMapPtr map)
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

static virCPUarmFeaturePtr
virCPUarmMapFeatureFind(virCPUarmMapPtr map,
                        const char *name)
{
    size_t i;

    for (i = 0; i < map->features->len; i++) {
        virCPUarmFeaturePtr feature = g_ptr_array_index(map->features, i);

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
    virCPUarmMapPtr map = data;

    if (virCPUarmMapFeatureFind(map, name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU feature %s already defined"), name);
        return -1;
    }

    feature = virCPUarmFeatureNew();
    feature->name = g_strdup(name);

    g_ptr_array_add(map->features, g_steal_pointer(&feature));

    return 0;
}

static virCPUarmVendorPtr
virCPUarmVendorFindByID(virCPUarmMapPtr map,
                        unsigned long vendor_id)
{
    size_t i;

    for (i = 0; i < map->nvendors; i++) {
        if (map->vendors[i]->value == vendor_id)
            return map->vendors[i];
    }

    return NULL;
}


static virCPUarmVendorPtr
virCPUarmVendorFindByName(virCPUarmMapPtr map,
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
    virCPUarmMapPtr map = data;
    g_autoptr(virCPUarmVendor) vendor = NULL;

    vendor = g_new0(virCPUarmVendor, 1);
    vendor->name = g_strdup(name);

    if (virCPUarmVendorFindByName(map, vendor->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU vendor %s already defined"),
                       vendor->name);
        return -1;
    }

    if (virXPathULongHex("string(@value)", ctxt, &vendor->value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Missing CPU vendor value"));
        return -1;
    }

    if (virCPUarmVendorFindByID(map, vendor->value)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU vendor value 0x%2lx already defined"),
                       vendor->value);
        return -1;
    }

    if (VIR_APPEND_ELEMENT(map->vendors, map->nvendors, vendor) < 0)
        return -1;

    return 0;
}

static virCPUarmModelPtr
virCPUarmModelFind(virCPUarmMapPtr map,
                   const char *name)
{
    size_t i;

    for (i = 0; i < map->nmodels; i++) {
        if (STREQ(map->models[i]->name, name))
            return map->models[i];
    }

    return NULL;
}

static int
virCPUarmModelParse(xmlXPathContextPtr ctxt,
                    const char *name,
                    void *data)
{
    virCPUarmMapPtr map = data;
    g_autoptr(virCPUarmModel) model = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    g_autofree char *vendor = NULL;

    model = g_new0(virCPUarmModel, 1);
    model->name = g_strdup(name);

    if (virCPUarmModelFind(map, model->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU model %s already defined"),
                       model->name);
        return -1;
    }

    if (virXPathBoolean("boolean(./vendor)", ctxt)) {
        vendor = virXPathString("string(./vendor/@name)", ctxt);
        if (!vendor) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid vendor element in CPU model %s"),
                           model->name);
            return -1;
        }

        if (!(model->vendor = virCPUarmVendorFindByName(map, vendor))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown vendor %s referenced by CPU model %s"),
                           vendor, model->name);
            return -1;
        }
    }

    if (!virXPathBoolean("boolean(./pvr)", ctxt)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing PVR information for CPU model %s"),
                       model->name);
        return -1;
    }

    if (virXPathULongHex("string(./pvr/@value)", ctxt, &model->data.pvr) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing or invalid PVR value in CPU model %s"),
                       model->name);
        return -1;
    }

    if (VIR_APPEND_ELEMENT(map->models, map->nmodels, model) < 0)
        return -1;

    return 0;
}

static virCPUarmMapPtr
virCPUarmLoadMap(void)
{
    g_autoptr(virCPUarmMap) map = NULL;

    map = virCPUarmMapNew();

    if (cpuMapLoad("arm", virCPUarmVendorParse, virCPUarmMapFeatureParse,
                   virCPUarmModelParse, map) < 0)
        return NULL;

    return g_steal_pointer(&map);
}

static virCPUarmMapPtr cpuMap;

int virCPUarmDriverOnceInit(void);
VIR_ONCE_GLOBAL_INIT(virCPUarmDriver);

int
virCPUarmDriverOnceInit(void)
{
    if (!(cpuMap = virCPUarmLoadMap()))
        return -1;

    return 0;
}

static virCPUarmMapPtr
virCPUarmGetMap(void)
{
    if (virCPUarmDriverInitialize() < 0)
        return NULL;

    return cpuMap;
}

static int
virCPUarmUpdate(virCPUDefPtr guest,
                const virCPUDef *host)
{
    int ret = -1;
    virCPUDefPtr updated = NULL;

    if (guest->mode != VIR_CPU_MODE_HOST_MODEL)
        return 0;

    if (!host) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unknown host CPU model"));
        goto cleanup;
    }

    if (!(updated = virCPUDefCopyWithoutModel(guest)))
        goto cleanup;

    updated->mode = VIR_CPU_MODE_CUSTOM;
    if (virCPUDefCopyModel(updated, host, true) < 0)
        goto cleanup;

    virCPUDefStealModel(guest, updated, false);
    guest->mode = VIR_CPU_MODE_CUSTOM;
    guest->match = VIR_CPU_MATCH_EXACT;
    ret = 0;

 cleanup:
    virCPUDefFree(updated);
    return ret;
}


static virCPUDefPtr
virCPUarmBaseline(virCPUDefPtr *cpus,
                  unsigned int ncpus G_GNUC_UNUSED,
                  virDomainCapsCPUModelsPtr models G_GNUC_UNUSED,
                  const char **features G_GNUC_UNUSED,
                  bool migratable G_GNUC_UNUSED)
{
    virCPUDefPtr cpu = NULL;

    cpu = virCPUDefNew();

    cpu->model = g_strdup(cpus[0]->model);

    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;

    return cpu;
}

static virCPUCompareResult
virCPUarmCompare(virCPUDefPtr host G_GNUC_UNUSED,
                 virCPUDefPtr cpu G_GNUC_UNUSED,
                 bool failMessages G_GNUC_UNUSED)
{
    return VIR_CPU_COMPARE_IDENTICAL;
}

static int
virCPUarmValidateFeatures(virCPUDefPtr cpu)
{
    virCPUarmMapPtr map;
    size_t i;

    if (!(map = virCPUarmGetMap()))
        return -1;

    for (i = 0; i < cpu->nfeatures; i++) {
        virCPUFeatureDefPtr feature = &cpu->features[i];

        if (!virCPUarmMapFeatureFind(map, feature->name)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown CPU feature: %s"),
                           feature->name);
            return -1;
        }
    }

    return 0;
}

struct cpuArchDriver cpuDriverArm = {
    .name = "arm",
    .arch = archs,
    .narch = G_N_ELEMENTS(archs),
    .compare = virCPUarmCompare,
    .decode = NULL,
    .encode = NULL,
    .dataFree = virCPUarmDataFree,
    .baseline = virCPUarmBaseline,
    .update = virCPUarmUpdate,
    .validateFeatures = virCPUarmValidateFeatures,
};
