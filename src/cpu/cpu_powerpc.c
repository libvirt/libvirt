/*
 * cpu_powerpc.c: CPU driver for PowerPC CPUs
 *
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

static const virArch archs[] = { VIR_ARCH_PPC64 };

struct ppc_vendor {
    char *name;
    struct ppc_vendor *next;
};

struct ppc_model {
    char *name;
    const struct ppc_vendor *vendor;
    struct cpuPPCData data;
    struct ppc_model *next;
};

struct ppc_map {
    struct ppc_vendor *vendors;
    struct ppc_model *models;
};


static void
ppcModelFree(struct ppc_model *model)
{
    if (model == NULL)
        return;

    VIR_FREE(model->name);
    VIR_FREE(model);
}

static struct ppc_model *
ppcModelFind(const struct ppc_map *map,
             const char *name)
{
    struct ppc_model *model;

    model = map->models;
    while (model != NULL) {
        if (STREQ(model->name, name))
            return model;

        model = model->next;
    }

    return NULL;
}

static struct ppc_model *
ppcModelFindPVR(const struct ppc_map *map,
                uint32_t pvr)
{
    struct ppc_model *model;

    model = map->models;
    while (model != NULL) {
        if (model->data.pvr == pvr)
            return model;

        model = model->next;
    }

    return NULL;
}

static struct ppc_vendor *
ppcVendorFind(const struct ppc_map *map,
              const char *name)
{
    struct ppc_vendor *vendor;

    vendor = map->vendors;
    while (vendor) {
        if (STREQ(vendor->name, name))
            return vendor;

        vendor = vendor->next;
    }

    return NULL;
}

static void
ppcVendorFree(struct ppc_vendor *vendor)
{
    if (!vendor)
        return;

    VIR_FREE(vendor->name);
    VIR_FREE(vendor);
}

static int
ppcVendorLoad(xmlXPathContextPtr ctxt,
              struct ppc_map *map)
{
    struct ppc_vendor *vendor = NULL;

    if (VIR_ALLOC(vendor) < 0)
        return -1;

    vendor->name = virXPathString("string(@name)", ctxt);
    if (!vendor->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Missing CPU vendor name"));
        goto ignore;
    }

    if (ppcVendorFind(map, vendor->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU vendor %s already defined"), vendor->name);
        goto ignore;
    }

    if (!map->vendors) {
        map->vendors = vendor;
    } else {
        vendor->next = map->vendors;
        map->vendors = vendor;
    }

cleanup:
    return 0;

ignore:
    ppcVendorFree(vendor);
    goto cleanup;
}

static int
ppcModelLoad(xmlXPathContextPtr ctxt,
             struct ppc_map *map)
{
    struct ppc_model *model;
    char *vendor = NULL;
    unsigned long pvr;

    if (VIR_ALLOC(model) < 0)
        return -1;

    model->name = virXPathString("string(@name)", ctxt);
    if (!model->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Missing CPU model name"));
        goto ignore;
    }

    if (ppcModelFind(map, model->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU model %s already defined"), model->name);
        goto ignore;
    }

    if (virXPathBoolean("boolean(./vendor)", ctxt)) {
        vendor = virXPathString("string(./vendor/@name)", ctxt);
        if (!vendor) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid vendor element in CPU model %s"),
                           model->name);
            goto ignore;
        }

        if (!(model->vendor = ppcVendorFind(map, vendor))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown vendor %s referenced by CPU model %s"),
                           vendor, model->name);
            goto ignore;
        }
    }

    if (!virXPathBoolean("boolean(./pvr)", ctxt) ||
        virXPathULongHex("string(./pvr/@value)", ctxt, &pvr) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing or invalid PVR value in CPU model %s"),
                       model->name);
        goto ignore;
    }
    model->data.pvr = pvr;

    if (map->models == NULL) {
        map->models = model;
    } else {
        model->next = map->models;
        map->models = model;
    }

cleanup:
    VIR_FREE(vendor);
    return 0;

ignore:
    ppcModelFree(model);
    goto cleanup;
}

static int
ppcMapLoadCallback(enum cpuMapElement element,
                   xmlXPathContextPtr ctxt,
                   void *data)
{
    struct ppc_map *map = data;

    switch (element) {
    case CPU_MAP_ELEMENT_VENDOR:
        return ppcVendorLoad(ctxt, map);
    case CPU_MAP_ELEMENT_MODEL:
        return ppcModelLoad(ctxt, map);
    case CPU_MAP_ELEMENT_FEATURE:
    case CPU_MAP_ELEMENT_LAST:
        break;
    }

    return 0;
}

static void
ppcMapFree(struct ppc_map *map)
{
    if (map == NULL)
        return;

    while (map->models != NULL) {
        struct ppc_model *model = map->models;
        map->models = model->next;
        ppcModelFree(model);
    }

    while (map->vendors != NULL) {
        struct ppc_vendor *vendor = map->vendors;
        map->vendors = vendor->next;
        ppcVendorFree(vendor);
    }

    VIR_FREE(map);
}

static struct ppc_map *
ppcLoadMap(void)
{
    struct ppc_map *map;

    if (VIR_ALLOC(map) < 0)
        return NULL;

    if (cpuMapLoad("ppc64", ppcMapLoadCallback, map) < 0)
        goto error;

    return map;

error:
    ppcMapFree(map);
    return NULL;
}

static virCPUCompareResult
ppcCompare(virCPUDefPtr host,
           virCPUDefPtr cpu)
{
    if ((cpu->arch == VIR_ARCH_NONE || host->arch == cpu->arch) &&
        STREQ(host->model, cpu->model))
        return VIR_CPU_COMPARE_IDENTICAL;

    return VIR_CPU_COMPARE_INCOMPATIBLE;
}

static int
ppcDecode(virCPUDefPtr cpu,
          const virCPUDataPtr data,
          const char **models,
          unsigned int nmodels,
          const char *preferred ATTRIBUTE_UNUSED)
{
    int ret = -1;
    struct ppc_map *map;
    const struct ppc_model *model;

    if (data == NULL || (map = ppcLoadMap()) == NULL)
        return -1;

    if (!(model = ppcModelFindPVR(map, data->data.ppc.pvr))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Cannot find CPU model with PVR 0x%08x"),
                       data->data.ppc.pvr);
        goto cleanup;
    }

    if (!cpuModelIsAllowed(model->name, models, nmodels)) {
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
    ppcMapFree(map);

    return ret;
}


static void
ppcDataFree(virCPUDataPtr data)
{
    if (data == NULL)
        return;

    VIR_FREE(data);
}

#if defined(__powerpc__) || defined(__powerpc64__)
static virCPUDataPtr
ppcNodeData(void)
{
    virCPUDataPtr cpuData;

    if (VIR_ALLOC(cpuData) < 0)
        return NULL;

    asm("mfpvr %0"
        : "=r" (cpuData->data.ppc.pvr));

    return cpuData;
}
#endif

static int
ppcUpdate(virCPUDefPtr guest ATTRIBUTE_UNUSED,
          const virCPUDefPtr host ATTRIBUTE_UNUSED)
{
   return 0;
}

static virCPUDefPtr
ppcBaseline(virCPUDefPtr *cpus,
            unsigned int ncpus,
            const char **models,
            unsigned int nmodels)
{
    struct ppc_map *map = NULL;
    const struct ppc_model *model;
    const struct ppc_vendor *vendor = NULL;
    virCPUDefPtr cpu = NULL;
    size_t i;

    if (!(map = ppcLoadMap()))
        goto error;

    if (!(model = ppcModelFind(map, cpus[0]->model))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown CPU model %s"), cpus[0]->model);
        goto error;
    }

    if (!cpuModelIsAllowed(model->name, models, nmodels)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("CPU model %s is not supported by hypervisor"),
                        model->name);
        goto error;
    }

    for (i = 0; i < ncpus; i++) {
        const struct ppc_vendor *vnd;

        if (STRNEQ(cpus[i]->model, model->name)) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("CPUs are incompatible"));
            goto error;
        }

        if (!cpus[i]->vendor)
            continue;

        if (!(vnd = ppcVendorFind(map, cpus[i]->vendor))) {
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

cleanup:
    ppcMapFree(map);

    return cpu;

error:
    virCPUDefFree(cpu);
    cpu = NULL;
    goto cleanup;
}

struct cpuArchDriver cpuDriverPowerPC = {
    .name = "ppc64",
    .arch = archs,
    .narch = ARRAY_CARDINALITY(archs),
    .compare    = ppcCompare,
    .decode     = ppcDecode,
    .encode     = NULL,
    .free       = ppcDataFree,
#if defined(__powerpc__) || defined(__powerpc64__)
    .nodeData   = ppcNodeData,
#else
    .nodeData   = NULL,
#endif
    .guestData  = NULL,
    .baseline   = ppcBaseline,
    .update     = ppcUpdate,
    .hasFeature = NULL,
};
