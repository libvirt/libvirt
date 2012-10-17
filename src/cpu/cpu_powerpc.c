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

#include "logging.h"
#include "memory.h"
#include "util.h"
#include "cpu.h"

#include "cpu_map.h"
#include "buf.h"

#define VIR_FROM_THIS VIR_FROM_CPU

static const char *archs[] = { "ppc64" };

struct cpuPowerPC {
    const char *name;
    const char *vendor;
    uint32_t pvr;
};

static const struct cpuPowerPC cpu_defs[] = {
    {"POWER7", "IBM", 0x003f0200},
    {"POWER7_v2.1", "IBM", 0x003f0201},
    {"POWER7_v2.3", "IBM", 0x003f0203},
    {NULL, NULL, 0xffffffff}
};


struct ppc_vendor {
    char *name;
    struct ppc_vendor *next;
};

struct ppc_model {
    char *name;
    const struct ppc_vendor *vendor;
    union cpuData *data;
    struct ppc_model *next;
};

struct ppc_map {
    struct ppc_vendor *vendors;
    struct ppc_model *models;
};

static int
ConvertModelVendorFromPVR(char ***model,
                          char ***vendor,
                          uint32_t pvr)
{
    int i;

    for (i = 0; cpu_defs[i].name; i++) {
        if (cpu_defs[i].pvr == pvr) {
            **model = strdup(cpu_defs[i].name);
            **vendor = strdup(cpu_defs[i].vendor);
            return 0;
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("Missing the definition of this model"));
    return -1;
}

static int
ConvertPVRFromModel(const char *model,
                    uint32_t *pvr)
{
    int i;

    for (i = 0; cpu_defs[i].name; i++) {
        if (STREQ(cpu_defs[i].name, model)) {
            *pvr = cpu_defs[i].pvr;
            return 0;
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("Missing the definition of this model"));
    return -1;
}

static int
cpuMatch(const union cpuData *data,
         char **cpu_model,
         char **cpu_vendor,
         const struct ppc_model *model)
{
    int ret = 0;

    ret = ConvertModelVendorFromPVR(&cpu_model, &cpu_vendor, data->ppc.pvr);

    if (STREQ(model->name, *cpu_model) &&
        STREQ(model->vendor->name, *cpu_vendor))
        ret = 1;

    return ret;
}


static struct ppc_model *
ppcModelNew(void)
{
    struct ppc_model *model;

    if (VIR_ALLOC(model) < 0)
        return NULL;

    if (VIR_ALLOC(model->data) < 0) {
        VIR_FREE(model);
        return NULL;
    }

    return model;
}

static void
ppcModelFree(struct ppc_model *model)
{
    if (model == NULL)
        return;

    VIR_FREE(model->name);

    VIR_FREE(model->data);

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
    char *string = NULL;
    int ret = -1;

    if (VIR_ALLOC(vendor) < 0)
        goto no_memory;

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

    string = virXPathString("string(@string)", ctxt);
    if (!string) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing vendor string for CPU vendor %s"), vendor->name);
        goto ignore;
    }
    if (!map->vendors)
        map->vendors = vendor;
    else {
        vendor->next = map->vendors;
        map->vendors = vendor;
    }

    ret = 0;

out:
    VIR_FREE(string);
    return ret;

no_memory:
    virReportOOMError();

ignore:
    ppcVendorFree(vendor);
    goto out;
}

static int
ppcModelLoad(xmlXPathContextPtr ctxt,
             struct ppc_map *map)
{
    xmlNodePtr *nodes = NULL;
    struct ppc_model *model;
    char *vendor = NULL;
    int ret = -1;

    if (!(model = ppcModelNew()))
        goto no_memory;

    model->name = virXPathString("string(@name)", ctxt);
    if (model->name == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Missing CPU model name"));
        goto ignore;
    }

    ret = ConvertPVRFromModel(model->name, &model->data->ppc.pvr);
    if (ret < 0)
       goto ignore;


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

    if (map->models == NULL)
        map->models = model;
    else {
        model->next = map->models;
        map->models = model;
    }

    ret = 0;

out:
    VIR_FREE(vendor);
    VIR_FREE(nodes);
    return ret;

no_memory:
    virReportOOMError();

ignore:
    ppcModelFree(model);
    goto out;
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
    default:
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

    if (VIR_ALLOC(map) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (cpuMapLoad("ppc64", ppcMapLoadCallback, map) < 0)
        goto error;

    return map;

error:
    ppcMapFree(map);
    return NULL;
}

static struct ppc_model *
ppcModelCopy(const struct ppc_model *model)
{
    struct ppc_model *copy;

    if (VIR_ALLOC(copy) < 0
        || VIR_ALLOC(copy->data) < 0
        || !(copy->name = strdup(model->name))){
        ppcModelFree(copy);
        return NULL;
    }

    copy->data->ppc.pvr = model->data->ppc.pvr;
    copy->vendor = model->vendor;

    return copy;
}

static struct ppc_model *
ppcModelFromCPU(const virCPUDefPtr cpu,
                const struct ppc_map *map)
{
    struct ppc_model *model = NULL;

    if ((model = ppcModelFind(map, cpu->model))) {
        if ((model = ppcModelCopy(model)) == NULL) {
            goto no_memory;
        }
    } else if (!(model = ppcModelNew())) {
        goto no_memory;
    }

    return model;

no_memory:
    virReportOOMError();
    ppcModelFree(model);

    return NULL;
}

static virCPUCompareResult
PowerPCCompare(virCPUDefPtr host,
           virCPUDefPtr cpu)
{
    if ((cpu->arch && STRNEQ(host->arch, cpu->arch)) ||
        STRNEQ(host->model, cpu->model))
        return VIR_CPU_COMPARE_INCOMPATIBLE;

    return VIR_CPU_COMPARE_IDENTICAL;
}

static int
PowerPCDecode(virCPUDefPtr cpu,
          const union cpuData *data,
          const char **models,
          unsigned int nmodels,
          const char *preferred)
{
    int ret = -1;
    struct ppc_map *map;
    const struct ppc_model *candidate;
    virCPUDefPtr cpuCandidate;
    virCPUDefPtr cpuModel = NULL;
    char *cpu_vendor = NULL;
    char *cpu_model = NULL;
    unsigned int i;

    if (data == NULL || (map = ppcLoadMap()) == NULL)
        return -1;

    candidate = map->models;

    while (candidate != NULL) {
        bool allowed = (models == NULL);

        for (i = 0; i < nmodels; i++) {
            if (models && models[i] && STREQ(models[i], candidate->name)) {
                allowed = true;
                break;
            }
        }

        if (!allowed) {
            if (preferred && STREQ(candidate->name, preferred)) {
                if (cpu->fallback != VIR_CPU_FALLBACK_ALLOW) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("CPU model %s is not supported by hypervisor"),
                                   preferred);
                    goto out;
                } else {
                    VIR_WARN("Preferred CPU model %s not allowed by"
                             " hypervisor; closest supported model will be"
                             " used", preferred);
                }
            } else {
                VIR_DEBUG("CPU model %s not allowed by hypervisor; ignoring",
                          candidate->name);
            }
            goto next;
        }

        if (VIR_ALLOC(cpuCandidate) < 0) {
            virReportOOMError();
            goto out;
        }

        cpuCandidate->model = strdup(candidate->name);
        cpuCandidate->vendor = strdup(candidate->vendor->name);

        if (preferred && STREQ(cpuCandidate->model, preferred)) {
            virCPUDefFree(cpuModel);
            cpuModel = cpuCandidate;
            break;
        }

        ret = cpuMatch(data, &cpu_model, &cpu_vendor, candidate);
        if (ret < 0) {
            VIR_FREE(cpuCandidate);
            goto out;
        } else if (ret == 1) {
            cpuCandidate->model = cpu_model;
            cpuCandidate->vendor = cpu_vendor;
            virCPUDefFree(cpuModel);
            cpuModel = cpuCandidate;
            break;
        }

        virCPUDefFree(cpuCandidate);

    next:
        candidate = candidate->next;
    }

    if (cpuModel == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Cannot find suitable CPU model for given data"));
        goto out;
    }

    cpu->model = cpuModel->model;
    cpu->vendor = cpuModel->vendor;
    VIR_FREE(cpuModel);

    ret = 0;

out:
    ppcMapFree(map);
    virCPUDefFree(cpuModel);

    return ret;
}

#if defined(__powerpc__) || \
    defined(__powerpc64__)
static uint32_t ppc_mfpvr(void)
{
    uint32_t pvr;
    asm("mfpvr %0"
        : "=r"(pvr));
    return pvr;
}
#endif

static void
PowerPCDataFree(union cpuData *data)
{
    if (data == NULL)
        return;

    VIR_FREE(data);
}

static union cpuData *
PowerPCNodeData(void)
{
    union cpuData *data;

    if (VIR_ALLOC(data) < 0) {
        virReportOOMError();
        return NULL;
    }

#if defined(__powerpc__) || \
    defined(__powerpc64__)
    data->ppc.pvr = ppc_mfpvr();
#endif

    return data;
}

static int
PowerPCUpdate(virCPUDefPtr guest ATTRIBUTE_UNUSED,
          const virCPUDefPtr host ATTRIBUTE_UNUSED)
{
   return 0;
}
static virCPUDefPtr
PowerPCBaseline(virCPUDefPtr *cpus,
                unsigned int ncpus ATTRIBUTE_UNUSED,
                const char **models ATTRIBUTE_UNUSED,
                unsigned int nmodels ATTRIBUTE_UNUSED)
{
    struct ppc_map *map = NULL;
    struct ppc_model *base_model = NULL;
    virCPUDefPtr cpu = NULL;
    struct ppc_model *model = NULL;
    bool outputModel = true;

    if (!(map = ppcLoadMap())) {
        goto error;
    }

    if (!(base_model = ppcModelFromCPU(cpus[0], map))) {
        goto error;
    }

    if (VIR_ALLOC(cpu) < 0 ||
        !(cpu->arch = strdup(cpus[0]->arch)))
        goto no_memory;
    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;

    if (!cpus[0]->model) {
        outputModel = false;
    } else if (!(model = ppcModelFind(map, cpus[0]->model))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Unknown CPU vendor %s"), cpus[0]->model);
        goto error;
    }

    base_model->data->ppc.pvr = model->data->ppc.pvr;
    if (PowerPCDecode(cpu, base_model->data, models, nmodels, NULL) < 0)
        goto error;

    if (!outputModel)
        VIR_FREE(cpu->model);

    VIR_FREE(cpu->arch);

cleanup:
    ppcModelFree(base_model);
    ppcMapFree(map);

    return cpu;
no_memory:
    virReportOOMError();
error:
    ppcModelFree(model);
    virCPUDefFree(cpu);
    cpu = NULL;
    goto cleanup;
}

struct cpuArchDriver cpuDriverPowerPC = {
    .name = "ppc64",
    .arch = archs,
    .narch = ARRAY_CARDINALITY(archs),
    .compare    = PowerPCCompare,
    .decode     = PowerPCDecode,
    .encode     = NULL,
    .free       = PowerPCDataFree,
    .nodeData   = PowerPCNodeData,
    .guestData  = NULL,
    .baseline   = PowerPCBaseline,
    .update     = PowerPCUpdate,
    .hasFeature = NULL,
};
