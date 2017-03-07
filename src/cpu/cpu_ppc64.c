/*
 * cpu_ppc64.c: CPU driver for 64-bit PowerPC CPUs
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright (C) IBM Corporation, 2010
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
 *
 * Authors:
 *      Anton Blanchard <anton@au.ibm.com>
 *      Prerna Saxena <prerna@linux.vnet.ibm.com>
 *      Li Zhang <zhlcindy@linux.vnet.ibm.com>
 */

#include <config.h>
#include <stdint.h>

#include "virlog.h"
#include "viralloc.h"
#include "cpu.h"
#include "virstring.h"
#include "cpu_map.h"
#include "virbuffer.h"

#define VIR_FROM_THIS VIR_FROM_CPU

VIR_LOG_INIT("cpu.cpu_ppc64");

static const virArch archs[] = { VIR_ARCH_PPC64, VIR_ARCH_PPC64LE };

struct ppc64_vendor {
    char *name;
};

struct ppc64_model {
    char *name;
    const struct ppc64_vendor *vendor;
    virCPUppc64Data data;
};

struct ppc64_map {
    size_t nvendors;
    struct ppc64_vendor **vendors;
    size_t nmodels;
    struct ppc64_model **models;
};

/* Convert a legacy CPU definition by transforming
 * model names to generation names:
 *   POWER7_v2.1  => POWER7
 *   POWER7_v2.3  => POWER7
 *   POWER7+_v2.1 => POWER7
 *   POWER8_v1.0  => POWER8 */
static int
virCPUppc64ConvertLegacy(virCPUDefPtr cpu)
{
    if (cpu->model &&
        (STREQ(cpu->model, "POWER7_v2.1") ||
         STREQ(cpu->model, "POWER7_v2.3") ||
         STREQ(cpu->model, "POWER7+_v2.1") ||
         STREQ(cpu->model, "POWER8_v1.0"))) {
        cpu->model[strlen("POWERx")] = 0;
    }

    return 0;
}

/* Some hosts can run guests in compatibility mode, but not all
 * host CPUs support this and not all combinations are valid.
 * This function performs the necessary checks */
static virCPUCompareResult
ppc64CheckCompatibilityMode(const char *host_model,
                            const char *compat_mode)
{
    int host;
    int compat;
    char *tmp;
    virCPUCompareResult ret = VIR_CPU_COMPARE_ERROR;

    if (!compat_mode)
        return VIR_CPU_COMPARE_IDENTICAL;

    /* Valid host CPUs: POWER6, POWER7, POWER8 */
    if (!STRPREFIX(host_model, "POWER") ||
        !(tmp = (char *) host_model + strlen("POWER")) ||
        virStrToLong_i(tmp, NULL, 10, &host) < 0 ||
        host < 6 || host > 8) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("Host CPU does not support compatibility modes"));
        goto out;
    }

    /* Valid compatibility modes: power6, power7, power8 */
    if (!STRPREFIX(compat_mode, "power") ||
        !(tmp = (char *) compat_mode + strlen("power")) ||
        virStrToLong_i(tmp, NULL, 10, &compat) < 0 ||
        compat < 6 || compat > 8) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown compatibility mode %s"),
                       compat_mode);
        goto out;
    }

    /* Version check */
    if (compat > host)
        ret = VIR_CPU_COMPARE_INCOMPATIBLE;
    else
        ret = VIR_CPU_COMPARE_IDENTICAL;

 out:
    return ret;
}

static void
ppc64DataClear(virCPUppc64Data *data)
{
    if (!data)
        return;

    VIR_FREE(data->pvr);
}

static int
ppc64DataCopy(virCPUppc64Data *dst, const virCPUppc64Data *src)
{
    size_t i;

    if (VIR_ALLOC_N(dst->pvr, src->len) < 0)
        return -1;

    dst->len = src->len;

    for (i = 0; i < src->len; i++) {
        dst->pvr[i].value = src->pvr[i].value;
        dst->pvr[i].mask = src->pvr[i].mask;
    }

    return 0;
}

static void
ppc64VendorFree(struct ppc64_vendor *vendor)
{
    if (!vendor)
        return;

    VIR_FREE(vendor->name);
    VIR_FREE(vendor);
}

static struct ppc64_vendor *
ppc64VendorFind(const struct ppc64_map *map,
                const char *name)
{
    size_t i;

    for (i = 0; i < map->nvendors; i++) {
        if (STREQ(map->vendors[i]->name, name))
            return map->vendors[i];
    }

    return NULL;
}

static void
ppc64ModelFree(struct ppc64_model *model)
{
    if (!model)
        return;

    ppc64DataClear(&model->data);
    VIR_FREE(model->name);
    VIR_FREE(model);
}

static struct ppc64_model *
ppc64ModelCopy(const struct ppc64_model *model)
{
    struct ppc64_model *copy;

    if (VIR_ALLOC(copy) < 0)
        goto error;

    if (VIR_STRDUP(copy->name, model->name) < 0)
        goto error;

    if (ppc64DataCopy(&copy->data, &model->data) < 0)
        goto error;

    copy->vendor = model->vendor;

    return copy;

 error:
    ppc64ModelFree(copy);
    return NULL;
}

static struct ppc64_model *
ppc64ModelFind(const struct ppc64_map *map,
               const char *name)
{
    size_t i;

    for (i = 0; i < map->nmodels; i++) {
        if (STREQ(map->models[i]->name, name))
            return map->models[i];
    }

    return NULL;
}

static struct ppc64_model *
ppc64ModelFindPVR(const struct ppc64_map *map,
                  uint32_t pvr)
{
    size_t i;
    size_t j;

    for (i = 0; i < map->nmodels; i++) {
        struct ppc64_model *model = map->models[i];
        for (j = 0; j < model->data.len; j++) {
            if ((pvr & model->data.pvr[j].mask) == model->data.pvr[j].value)
                return model;
        }
    }

    return NULL;
}

static struct ppc64_model *
ppc64ModelFromCPU(const virCPUDef *cpu,
                  const struct ppc64_map *map)
{
    struct ppc64_model *model;

    if (!(model = ppc64ModelFind(map, cpu->model))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown CPU model %s"), cpu->model);
        return NULL;
    }

    return ppc64ModelCopy(model);
}

static void
ppc64MapFree(struct ppc64_map *map)
{
    size_t i;

    if (!map)
        return;

    for (i = 0; i < map->nmodels; i++)
        ppc64ModelFree(map->models[i]);
    VIR_FREE(map->models);

    for (i = 0; i < map->nvendors; i++)
        ppc64VendorFree(map->vendors[i]);
    VIR_FREE(map->vendors);

    VIR_FREE(map);
}

static struct ppc64_vendor *
ppc64VendorParse(xmlXPathContextPtr ctxt,
                 struct ppc64_map *map)
{
    struct ppc64_vendor *vendor;

    if (VIR_ALLOC(vendor) < 0)
        return NULL;

    vendor->name = virXPathString("string(@name)", ctxt);
    if (!vendor->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Missing CPU vendor name"));
        goto error;
    }

    if (ppc64VendorFind(map, vendor->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU vendor %s already defined"), vendor->name);
        goto error;
    }

    return vendor;

 error:
    ppc64VendorFree(vendor);
    return NULL;
}


static int
ppc64VendorsLoad(struct ppc64_map *map,
                 xmlXPathContextPtr ctxt,
                 xmlNodePtr *nodes,
                 int n)
{
    struct ppc64_vendor *vendor;
    size_t i;

    if (VIR_ALLOC_N(map->vendors, n) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];
        if (!(vendor = ppc64VendorParse(ctxt, map)))
            return -1;
        map->vendors[map->nvendors++] = vendor;
    }

    return 0;
}


static struct ppc64_model *
ppc64ModelParse(xmlXPathContextPtr ctxt,
                struct ppc64_map *map)
{
    struct ppc64_model *model;
    xmlNodePtr *nodes = NULL;
    char *vendor = NULL;
    unsigned long pvr;
    size_t i;
    int n;

    if (VIR_ALLOC(model) < 0)
        goto error;

    model->name = virXPathString("string(@name)", ctxt);
    if (!model->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Missing CPU model name"));
        goto error;
    }

    if (ppc64ModelFind(map, model->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU model %s already defined"), model->name);
        goto error;
    }

    if (virXPathBoolean("boolean(./vendor)", ctxt)) {
        vendor = virXPathString("string(./vendor/@name)", ctxt);
        if (!vendor) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid vendor element in CPU model %s"),
                           model->name);
            goto error;
        }

        if (!(model->vendor = ppc64VendorFind(map, vendor))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown vendor %s referenced by CPU model %s"),
                           vendor, model->name);
            goto error;
        }
    }

    if ((n = virXPathNodeSet("./pvr", ctxt, &nodes)) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing PVR information for CPU model %s"),
                       model->name);
        goto error;
    }

    if (VIR_ALLOC_N(model->data.pvr, n) < 0)
        goto error;

    model->data.len = n;

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];

        if (virXPathULongHex("string(./@value)", ctxt, &pvr) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing or invalid PVR value in CPU model %s"),
                           model->name);
            goto error;
        }
        model->data.pvr[i].value = pvr;

        if (virXPathULongHex("string(./@mask)", ctxt, &pvr) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing or invalid PVR mask in CPU model %s"),
                           model->name);
            goto error;
        }
        model->data.pvr[i].mask = pvr;
    }

 cleanup:
    VIR_FREE(vendor);
    VIR_FREE(nodes);
    return model;

 error:
    ppc64ModelFree(model);
    model = NULL;
    goto cleanup;
}


static int
ppc64ModelsLoad(struct ppc64_map *map,
                xmlXPathContextPtr ctxt,
                xmlNodePtr *nodes,
                int n)
{
    struct ppc64_model *model;
    size_t i;

    if (VIR_ALLOC_N(map->models, n) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];
        if (!(model = ppc64ModelParse(ctxt, map)))
            return -1;
        map->models[map->nmodels++] = model;
    }

    return 0;
}


static int
ppc64MapLoadCallback(cpuMapElement element,
                     xmlXPathContextPtr ctxt,
                     xmlNodePtr *nodes,
                     int n,
                     void *data)
{
    struct ppc64_map *map = data;

    switch (element) {
    case CPU_MAP_ELEMENT_VENDOR:
        return ppc64VendorsLoad(map, ctxt, nodes, n);
    case CPU_MAP_ELEMENT_MODEL:
        return ppc64ModelsLoad(map, ctxt, nodes, n);
    case CPU_MAP_ELEMENT_FEATURE:
    case CPU_MAP_ELEMENT_LAST:
        break;
    }

    return 0;
}

static struct ppc64_map *
ppc64LoadMap(void)
{
    struct ppc64_map *map;

    if (VIR_ALLOC(map) < 0)
        goto error;

    if (cpuMapLoad("ppc64", ppc64MapLoadCallback, map) < 0)
        goto error;

    return map;

 error:
    ppc64MapFree(map);
    return NULL;
}

static virCPUDataPtr
ppc64MakeCPUData(virArch arch,
                 virCPUppc64Data *data)
{
    virCPUDataPtr cpuData;

    if (VIR_ALLOC(cpuData) < 0)
        return NULL;

    cpuData->arch = arch;

    if (ppc64DataCopy(&cpuData->data.ppc64, data) < 0)
        VIR_FREE(cpuData);

    return cpuData;
}

static virCPUCompareResult
ppc64Compute(virCPUDefPtr host,
             const virCPUDef *other,
             virCPUDataPtr *guestData,
             char **message)
{
    struct ppc64_map *map = NULL;
    struct ppc64_model *host_model = NULL;
    struct ppc64_model *guest_model = NULL;
    virCPUDefPtr cpu = NULL;
    virCPUCompareResult ret = VIR_CPU_COMPARE_ERROR;
    virArch arch;
    size_t i;

    /* Ensure existing configurations are handled correctly */
    if (!(cpu = virCPUDefCopy(other)) ||
        virCPUppc64ConvertLegacy(cpu) < 0)
        goto cleanup;

    if (cpu->arch != VIR_ARCH_NONE) {
        bool found = false;

        for (i = 0; i < ARRAY_CARDINALITY(archs); i++) {
            if (archs[i] == cpu->arch) {
                found = true;
                break;
            }
        }

        if (!found) {
            VIR_DEBUG("CPU arch %s does not match host arch",
                      virArchToString(cpu->arch));
            if (message &&
                virAsprintf(message,
                            _("CPU arch %s does not match host arch"),
                            virArchToString(cpu->arch)) < 0)
                goto cleanup;

            ret = VIR_CPU_COMPARE_INCOMPATIBLE;
            goto cleanup;
        }
        arch = cpu->arch;
    } else {
        arch = host->arch;
    }

    if (cpu->vendor &&
        (!host->vendor || STRNEQ(cpu->vendor, host->vendor))) {
        VIR_DEBUG("host CPU vendor does not match required CPU vendor %s",
                  cpu->vendor);
        if (message &&
            virAsprintf(message,
                        _("host CPU vendor does not match required "
                        "CPU vendor %s"),
                        cpu->vendor) < 0)
            goto cleanup;

        ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        goto cleanup;
    }

    if (!(map = ppc64LoadMap()))
        goto cleanup;

    /* Host CPU information */
    if (!(host_model = ppc64ModelFromCPU(host, map)))
        goto cleanup;

    if (cpu->type == VIR_CPU_TYPE_GUEST) {
        /* Guest CPU information */
        virCPUCompareResult tmp;
        switch (cpu->mode) {
        case VIR_CPU_MODE_HOST_MODEL:
            /* host-model only:
             * we need to take compatibility modes into account */
            tmp = ppc64CheckCompatibilityMode(host->model, cpu->model);
            if (tmp != VIR_CPU_COMPARE_IDENTICAL) {
                ret = tmp;
                goto cleanup;
            }
            /* fallthrough */

        case VIR_CPU_MODE_HOST_PASSTHROUGH:
            /* host-model and host-passthrough:
             * the guest CPU is the same as the host */
            guest_model = ppc64ModelCopy(host_model);
            break;

        case VIR_CPU_MODE_CUSTOM:
            /* custom:
             * look up guest CPU information */
            guest_model = ppc64ModelFromCPU(cpu, map);
            break;
        }
    } else {
        /* Other host CPU information */
        guest_model = ppc64ModelFromCPU(cpu, map);
    }

    if (!guest_model)
        goto cleanup;

    if (STRNEQ(guest_model->name, host_model->name)) {
        VIR_DEBUG("host CPU model does not match required CPU model %s",
                  guest_model->name);
        if (message &&
            virAsprintf(message,
                        _("host CPU model does not match required "
                        "CPU model %s"),
                        guest_model->name) < 0)
            goto cleanup;

        ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        goto cleanup;
    }

    if (guestData)
        if (!(*guestData = ppc64MakeCPUData(arch, &guest_model->data)))
            goto cleanup;

    ret = VIR_CPU_COMPARE_IDENTICAL;

 cleanup:
    virCPUDefFree(cpu);
    ppc64MapFree(map);
    ppc64ModelFree(host_model);
    ppc64ModelFree(guest_model);
    return ret;
}

static virCPUCompareResult
virCPUppc64Compare(virCPUDefPtr host,
                   virCPUDefPtr cpu,
                   bool failIncompatible)
{
    virCPUCompareResult ret;
    char *message = NULL;

    if (!host || !host->model) {
        if (failIncompatible) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s",
                           _("unknown host CPU"));
        } else {
            VIR_WARN("unknown host CPU");
            ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        }
        return -1;
    }

    ret = ppc64Compute(host, cpu, NULL, &message);

    if (failIncompatible && ret == VIR_CPU_COMPARE_INCOMPATIBLE) {
        ret = VIR_CPU_COMPARE_ERROR;
        if (message) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s", message);
        } else {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, NULL);
        }
    }
    VIR_FREE(message);

    return ret;
}

static int
ppc64DriverDecode(virCPUDefPtr cpu,
                  const virCPUData *data,
                  const char **models,
                  unsigned int nmodels,
                  const char *preferred ATTRIBUTE_UNUSED,
                  unsigned int flags)
{
    int ret = -1;
    struct ppc64_map *map;
    const struct ppc64_model *model;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, -1);

    if (!data || !(map = ppc64LoadMap()))
        return -1;

    if (!(model = ppc64ModelFindPVR(map, data->data.ppc64.pvr[0].value))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Cannot find CPU model with PVR 0x%08x"),
                       data->data.ppc64.pvr[0].value);
        goto cleanup;
    }

    if (!virCPUModelIsAllowed(model->name, models, nmodels)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("CPU model %s is not supported by hypervisor"),
                       model->name);
        goto cleanup;
    }

    if (VIR_STRDUP(cpu->model, model->name) < 0 ||
        (model->vendor && VIR_STRDUP(cpu->vendor, model->vendor->name) < 0)) {
        goto cleanup;
    }

    ret = 0;

 cleanup:
    ppc64MapFree(map);

    return ret;
}

static void
virCPUppc64DataFree(virCPUDataPtr data)
{
    if (!data)
        return;

    ppc64DataClear(&data->data.ppc64);
    VIR_FREE(data);
}


static int
virCPUppc64GetHost(virCPUDefPtr cpu,
                   const char **models,
                   unsigned int nmodels)
{
    virCPUDataPtr cpuData = NULL;
    virCPUppc64Data *data;
    int ret = -1;

    if (!(cpuData = virCPUDataNew(archs[0])))
        goto cleanup;

    data = &cpuData->data.ppc64;

    if (VIR_ALLOC_N(data->pvr, 1) < 0)
        goto cleanup;

    data->len = 1;

#if defined(__powerpc__) || defined(__powerpc64__)
    asm("mfpvr %0"
        : "=r" (data->pvr[0].value));
#endif
    data->pvr[0].mask = 0xfffffffful;

    ret = ppc64DriverDecode(cpu, cpuData, models, nmodels, NULL, 0);

 cleanup:
    virCPUppc64DataFree(cpuData);
    return ret;
}


static int
virCPUppc64Update(virCPUDefPtr guest,
                  const virCPUDef *host ATTRIBUTE_UNUSED)
{
    /*
     * - host-passthrough doesn't even get here
     * - host-model is used for host CPU running in a compatibility mode and
     *   it needs to remain unchanged
     * - custom doesn't support any optional features, there's nothing to
     *   update
     */

    if (guest->mode == VIR_CPU_MODE_CUSTOM)
        guest->match = VIR_CPU_MATCH_EXACT;

    return 0;
}

static virCPUDefPtr
ppc64DriverBaseline(virCPUDefPtr *cpus,
                    unsigned int ncpus,
                    const char **models ATTRIBUTE_UNUSED,
                    unsigned int nmodels ATTRIBUTE_UNUSED,
                    unsigned int flags)
{
    struct ppc64_map *map;
    const struct ppc64_model *model;
    const struct ppc64_vendor *vendor = NULL;
    virCPUDefPtr cpu = NULL;
    size_t i;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES |
                  VIR_CONNECT_BASELINE_CPU_MIGRATABLE, NULL);

    if (!(map = ppc64LoadMap()))
        goto error;

    if (!(model = ppc64ModelFind(map, cpus[0]->model))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown CPU model %s"), cpus[0]->model);
        goto error;
    }

    for (i = 0; i < ncpus; i++) {
        const struct ppc64_vendor *vnd;

        /* Hosts running old (<= 1.2.18) versions of libvirt will report
         * strings like 'power7+' or 'power8e' instead of proper CPU model
         * names in the capabilities XML; moreover, they lack information
         * about some proper CPU models like 'POWER8'.
         * This implies two things:
         *   1) baseline among such hosts never worked
         *   2) while a few models, eg. 'POWER8_v1.0', could work on both
         *      old and new versions of libvirt, the information we have
         *      here is not enough to pick such a model
         * Hence we just compare models by name to decide whether or not
         * two hosts are compatible */
        if (STRNEQ(cpus[i]->model, model->name)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("CPUs are incompatible"));
            goto error;
        }

        if (!cpus[i]->vendor)
            continue;

        if (!(vnd = ppc64VendorFind(map, cpus[i]->vendor))) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Unknown CPU vendor %s"), cpus[i]->vendor);
            goto error;
        }

        if (model->vendor) {
            if (model->vendor != vnd) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("CPU vendor %s of model %s differs from "
                                 "vendor %s"),
                               model->vendor->name, model->name,
                               vnd->name);
                goto error;
            }
        } else if (vendor) {
            if (vendor != vnd) {
                virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                               _("CPU vendors do not match"));
                goto error;
            }
        } else {
            vendor = vnd;
        }
    }

    if (VIR_ALLOC(cpu) < 0 ||
        VIR_STRDUP(cpu->model, model->name) < 0)
        goto error;

    if (vendor && VIR_STRDUP(cpu->vendor, vendor->name) < 0)
        goto error;

    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;
    cpu->fallback = VIR_CPU_FALLBACK_FORBID;

 cleanup:
    ppc64MapFree(map);

    return cpu;

 error:
    virCPUDefFree(cpu);
    cpu = NULL;
    goto cleanup;
}

static int
virCPUppc64DriverGetModels(char ***models)
{
    struct ppc64_map *map;
    size_t i;
    int ret = -1;

    if (!(map = ppc64LoadMap()))
        goto error;

    if (models) {
        if (VIR_ALLOC_N(*models, map->nmodels + 1) < 0)
            goto error;

        for (i = 0; i < map->nmodels; i++) {
            if (VIR_STRDUP((*models)[i], map->models[i]->name) < 0)
                goto error;
        }
    }

    ret = map->nmodels;

 cleanup:
    ppc64MapFree(map);
    return ret;

 error:
    if (models) {
        virStringListFree(*models);
        *models = NULL;
    }
    goto cleanup;
}

struct cpuArchDriver cpuDriverPPC64 = {
    .name       = "ppc64",
    .arch       = archs,
    .narch      = ARRAY_CARDINALITY(archs),
    .compare    = virCPUppc64Compare,
    .decode     = ppc64DriverDecode,
    .encode     = NULL,
    .dataFree   = virCPUppc64DataFree,
    .getHost    = virCPUppc64GetHost,
    .baseline   = ppc64DriverBaseline,
    .update     = virCPUppc64Update,
    .getModels  = virCPUppc64DriverGetModels,
    .convertLegacy = virCPUppc64ConvertLegacy,
};
