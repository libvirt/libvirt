/*
 * cpu_x86.c: CPU driver for CPUs with x86 compatible CPUID instruction
 *
 * Copyright (C) 2009-2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *      Jiri Denemark <jdenemar@redhat.com>
 */

#include <config.h>

#include <stdint.h>

#include "logging.h"
#include "memory.h"
#include "util.h"
#include "cpu.h"
#include "cpu_map.h"
#include "cpu_x86.h"


#define VIR_FROM_THIS VIR_FROM_CPU

static const char *archs[] = { "i686", "x86_64" };

struct x86_feature {
    char *name;
    unsigned int ncpuid;
    struct cpuX86cpuid *cpuid;

    struct x86_feature *next;
};

struct x86_model {
    char *name;
    unsigned int ncpuid;
    struct cpuX86cpuid *cpuid;

    struct x86_model *next;
};

struct x86_map {
    struct x86_feature *features;
    struct x86_model *models;
};


enum compare_result {
    SUBSET,
    EQUAL,
    SUPERSET,
    UNRELATED
};


static struct cpuX86cpuid *
x86cpuidFind(struct cpuX86cpuid *cpuids,
             unsigned int ncpuids,
             uint32_t function)
{
    unsigned int i;

    for (i = 0; i < ncpuids; i++) {
        if (cpuids[i].function == function)
            return cpuids + i;
    }

    return NULL;
}


static inline int
x86cpuidMatch(const struct cpuX86cpuid *cpuid1,
              const struct cpuX86cpuid *cpuid2)
{
    return (cpuid1->eax == cpuid2->eax &&
            cpuid1->ebx == cpuid2->ebx &&
            cpuid1->ecx == cpuid2->ecx &&
            cpuid1->edx == cpuid2->edx);
}


static inline int
x86cpuidMatchMasked(const struct cpuX86cpuid *cpuid,
                    const struct cpuX86cpuid *mask)
{
    return ((cpuid->eax & mask->eax) == mask->eax &&
            (cpuid->ebx & mask->ebx) == mask->ebx &&
            (cpuid->ecx & mask->ecx) == mask->ecx &&
            (cpuid->edx & mask->edx) == mask->edx);
}


static inline int
x86cpuidMatchAny(const struct cpuX86cpuid *cpuid,
                 const struct cpuX86cpuid *mask)
{
    return ((cpuid->eax & mask->eax) ||
            (cpuid->ebx & mask->ebx) ||
            (cpuid->ecx & mask->ecx) ||
            (cpuid->edx & mask->edx));
}


static inline void
x86cpuidSetBits(struct cpuX86cpuid *cpuid,
                const struct cpuX86cpuid *mask)
{
    cpuid->eax |= mask->eax;
    cpuid->ebx |= mask->ebx;
    cpuid->ecx |= mask->ecx;
    cpuid->edx |= mask->edx;
}


static inline void
x86cpuidClearBits(struct cpuX86cpuid *cpuid,
                  const struct cpuX86cpuid *mask)
{
    cpuid->eax &= ~mask->eax;
    cpuid->ebx &= ~mask->ebx;
    cpuid->ecx &= ~mask->ecx;
    cpuid->edx &= ~mask->edx;
}


static inline void
x86cpuidAndBits(struct cpuX86cpuid *cpuid,
                const struct cpuX86cpuid *mask)
{
    cpuid->eax &= mask->eax;
    cpuid->ebx &= mask->ebx;
    cpuid->ecx &= mask->ecx;
    cpuid->edx &= mask->edx;
}


static struct cpuX86cpuid *
x86DataCpuid(const union cpuData *data,
             uint32_t function)
{
    struct cpuX86cpuid *cpuids;
    int len;
    unsigned int i;

    if (function < CPUX86_EXTENDED) {
        cpuids = data->x86.basic;
        len = data->x86.basic_len;
        i = function;
    }
    else {
        cpuids = data->x86.extended;
        len = data->x86.extended_len;
        i = function - CPUX86_EXTENDED;
    }

    if (i < len)
        return cpuids + i;
    else
        return NULL;
}


static void
x86DataFree(union cpuData *data)
{
    if (data == NULL)
        return;

    VIR_FREE(data->x86.basic);
    VIR_FREE(data->x86.extended);
    VIR_FREE(data);
}


static union cpuData *
x86DataCopy(const union cpuData *data)
{
    union cpuData *copy = NULL;
    int i;

    if (VIR_ALLOC(copy) < 0
        || VIR_ALLOC_N(copy->x86.basic, data->x86.basic_len) < 0
        || VIR_ALLOC_N(copy->x86.extended, data->x86.extended_len) < 0) {
        x86DataFree(copy);
        return NULL;
    }

    copy->x86.basic_len = data->x86.basic_len;
    for (i = 0; i < data->x86.basic_len; i++)
        copy->x86.basic[i] = data->x86.basic[i];

    copy->x86.extended_len = data->x86.extended_len;
    for (i = 0; i < data->x86.extended_len; i++)
        copy->x86.extended[i] = data->x86.extended[i];

    return copy;
}


static void
x86DataSubtract(union cpuData *data1,
                const union cpuData *data2)
{
    unsigned int i;
    unsigned int len;

    len = MIN(data1->x86.basic_len, data2->x86.basic_len);
    for (i = 0; i < len; i++) {
        x86cpuidClearBits(data1->x86.basic + i,
                          data2->x86.basic + i);
    }

    len = MIN(data1->x86.extended_len, data2->x86.extended_len);
    for (i = 0; i < len; i++) {
        x86cpuidClearBits(data1->x86.extended + i,
                          data2->x86.extended + i);
    }
}


static union cpuData *
x86DataFromModel(const struct x86_model *model)
{
    union cpuData *data = NULL;
    uint32_t basic_len = 0;
    uint32_t extended_len = 0;
    struct cpuX86cpuid *cpuid;
    int i;

    for (i = 0; i < model->ncpuid; i++) {
        cpuid = model->cpuid + i;
        if (cpuid->function < CPUX86_EXTENDED) {
            if (cpuid->function >= basic_len)
                basic_len = cpuid->function + 1;
        }
        else if (cpuid->function - CPUX86_EXTENDED >= extended_len)
            extended_len = cpuid->function - CPUX86_EXTENDED + 1;
    }

    if (VIR_ALLOC(data) < 0
        || VIR_ALLOC_N(data->x86.basic, basic_len) < 0
        || VIR_ALLOC_N(data->x86.extended, extended_len) < 0) {
        x86DataFree(data);
        return NULL;
    }

    data->x86.basic_len = basic_len;
    data->x86.extended_len = extended_len;

    for (i = 0; i < model->ncpuid; i++) {
        cpuid = x86DataCpuid(data, model->cpuid[i].function);
        *cpuid = model->cpuid[i];
    }

    return data;
}


/* also removes all detected features from data */
static int
x86DataToCPUFeatures(virCPUDefPtr cpu,
                     int policy,
                     union cpuData *data,
                     const struct x86_map *map)
{
    const struct x86_feature *feature = map->features;
    struct cpuX86cpuid *cpuid;
    unsigned int i;

    while (feature != NULL) {
        for (i = 0; i < feature->ncpuid; i++) {
            if ((cpuid = x86DataCpuid(data, feature->cpuid[i].function))
                && x86cpuidMatchMasked(cpuid, feature->cpuid + i)) {
                x86cpuidClearBits(cpuid, feature->cpuid + i);
                if (virCPUDefAddFeature(cpu, feature->name, policy) < 0)
                    return -1;
            }
        }
        feature = feature->next;
    }

    return 0;
}


static virCPUDefPtr
x86DataToCPU(const union cpuData *data,
             const struct x86_model *model,
             const struct x86_map *map)
{
    virCPUDefPtr cpu;
    union cpuData *copy = NULL;
    union cpuData *modelData = NULL;

    if (VIR_ALLOC(cpu) < 0 ||
        !(cpu->model = strdup(model->name)) ||
        !(copy = x86DataCopy(data)) ||
        !(modelData = x86DataFromModel(model)))
        goto no_memory;

    x86DataSubtract(copy, modelData);
    x86DataSubtract(modelData, data);

    /* because feature policy is ignored for host CPU */
    cpu->type = VIR_CPU_TYPE_GUEST;

    if (x86DataToCPUFeatures(cpu, VIR_CPU_FEATURE_REQUIRE, copy, map) ||
        x86DataToCPUFeatures(cpu, VIR_CPU_FEATURE_DISABLE, modelData, map))
        goto error;

cleanup:
    x86DataFree(modelData);
    x86DataFree(copy);
    return cpu;

no_memory:
    virReportOOMError();
error:
    virCPUDefFree(cpu);
    cpu = NULL;
    goto cleanup;
}


static void
x86FeatureFree(struct x86_feature *feature)
{
    if (feature == NULL)
        return;

    VIR_FREE(feature->name);
    VIR_FREE(feature->cpuid);
    VIR_FREE(feature);
}


static struct x86_feature *
x86FeatureFind(const struct x86_map *map,
               const char *name)
{
    struct x86_feature *feature;

    feature = map->features;
    while (feature != NULL) {
        if (STREQ(feature->name, name))
            return feature;

        feature = feature->next;
    }

    return NULL;
}


static int
x86FeatureLoad(xmlXPathContextPtr ctxt,
               void *data)
{
    struct x86_map *map = data;
    xmlNodePtr *nodes = NULL;
    xmlNodePtr ctxt_node = ctxt->node;
    struct x86_feature *feature = NULL;
    int ret = 0;
    int i;
    int n;

    if (VIR_ALLOC(feature) < 0)
        goto no_memory;

    feature->name = virXPathString("string(@name)", ctxt);
    if (feature->name == NULL) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                "%s", _("Missing CPU feature name"));
        goto ignore;
    }

    if (x86FeatureFind(map, feature->name)) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                _("CPU feature %s already defined"), feature->name);
        goto ignore;
    }

    n = virXPathNodeSet("./cpuid", ctxt, &nodes);
    if (n < 0)
        goto ignore;

    if (n > 0) {
        if (VIR_ALLOC_N(feature->cpuid, n) < 0)
            goto no_memory;
        feature->ncpuid = n;
    }

    for (i = 0; i < n; i++) {
        struct cpuX86cpuid *cpuid = feature->cpuid + i;
        unsigned long fun, eax, ebx, ecx, edx;
        int ret_fun, ret_eax, ret_ebx, ret_ecx, ret_edx;

        ctxt->node = nodes[i];
        fun = eax = ebx = ecx = edx = 0;
        ret_fun = virXPathULongHex("string(@function)", ctxt, &fun);
        ret_eax = virXPathULongHex("string(@eax)", ctxt, &eax);
        ret_ebx = virXPathULongHex("string(@ebx)", ctxt, &ebx);
        ret_ecx = virXPathULongHex("string(@ecx)", ctxt, &ecx);
        ret_edx = virXPathULongHex("string(@edx)", ctxt, &edx);

        if (ret_fun < 0 || ret_eax == -2 || ret_ebx == -2
            || ret_ecx == -2 || ret_edx == -2) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Invalid cpuid[%d] in %s feature"), i, feature->name);
            goto ignore;
        }

        cpuid->function =  fun;
        cpuid->eax =  eax;
        cpuid->ebx =  ebx;
        cpuid->ecx =  ecx;
        cpuid->edx =  edx;
    }

    if (map->features == NULL)
        map->features = feature;
    else {
        feature->next = map->features;
        map->features = feature;
    }

out:
    ctxt->node = ctxt_node;
    VIR_FREE(nodes);

    return ret;

no_memory:
    virReportOOMError();
    ret = -1;

ignore:
    x86FeatureFree(feature);
    goto out;
}


static void
x86ModelFree(struct x86_model *model)
{
    if (model == NULL)
        return;

    VIR_FREE(model->name);
    VIR_FREE(model->cpuid);
    VIR_FREE(model);
}


static struct x86_model *
x86ModelCopy(const struct x86_model *model)
{
    struct x86_model *copy;
    int i;

    if (VIR_ALLOC(copy) < 0
        || (copy->name = strdup(model->name)) == NULL
        || VIR_ALLOC_N(copy->cpuid, model->ncpuid) < 0) {
        x86ModelFree(copy);
        return NULL;
    }

    copy->ncpuid = model->ncpuid;
    for (i = 0; i < model->ncpuid; i++)
        copy->cpuid[i] = model->cpuid[i];

    return copy;
}


static int
x86ModelAddCpuid(struct x86_model *model,
                 const struct cpuX86cpuid *cpuid)
{
    struct cpuX86cpuid *model_cpuid;

    model_cpuid = x86cpuidFind(model->cpuid, model->ncpuid, cpuid->function);

    if (model_cpuid != NULL)
        x86cpuidSetBits(model_cpuid, cpuid);
    else {
        if (VIR_REALLOC_N(model->cpuid, model->ncpuid + 1) < 0)
            return -1;

        model->cpuid[model->ncpuid] = *cpuid;
        model->ncpuid++;
    }

    return 0;
}


static void
x86ModelSubtract(struct x86_model *model1,
                 const struct x86_model *model2)
{
    int i;
    struct cpuX86cpuid *cpuid;

    for (i = 0; i < model2->ncpuid; i++) {
        cpuid = x86cpuidFind(model1->cpuid,
                             model1->ncpuid,
                             model2->cpuid[i].function);
        if (cpuid != NULL)
            x86cpuidClearBits(cpuid, model2->cpuid + i);
    }
}


static void
x86ModelIntersect(struct x86_model *model1,
                  const struct x86_model *model2)
{
    int i;
    struct cpuX86cpuid *cpuid;

    for (i = 0; i < model1->ncpuid; i++) {
        struct cpuX86cpuid *intersection = model1->cpuid + i;

        cpuid = x86cpuidFind(model2->cpuid,
                             model2->ncpuid,
                             intersection->function);
        if (cpuid != NULL)
            x86cpuidAndBits(intersection, cpuid);
        else
            x86cpuidClearBits(intersection, intersection);
    }
}


static int
x86ModelAdd(struct x86_model *model1,
            const struct x86_model *model2)
{
    int i;

    for (i = 0; i < model2->ncpuid; i++) {
        if (x86ModelAddCpuid(model1, model2->cpuid + i))
            return -1;
    }

    return 0;
}


static struct x86_model *
x86ModelFind(const struct x86_map *map,
             const char *name)
{
    struct x86_model *model;

    model = map->models;
    while (model != NULL) {
        if (STREQ(model->name, name))
            return model;

        model = model->next;
    }

    return NULL;
}


static int
x86ModelMergeFeature(struct x86_model *model,
                     const struct x86_feature *feature)
{
    int i;

    if (feature == NULL)
        return 0;

    for (i = 0; i < feature->ncpuid; i++) {
        if (x86ModelAddCpuid(model, feature->cpuid + i))
            return -1;
    }

    return 0;
}


static bool
x86ModelHasFeature(struct x86_model *model,
                   const struct x86_feature *feature)
{
    unsigned int i;
    struct cpuX86cpuid *cpuid;
    struct cpuX86cpuid *model_cpuid;

    if (feature == NULL)
        return false;

    for (i = 0; i < feature->ncpuid; i++) {
        cpuid = feature->cpuid + i;
        model_cpuid = x86cpuidFind(model->cpuid, model->ncpuid,
                                   cpuid->function);
        if (!model_cpuid || !x86cpuidMatchMasked(model_cpuid, cpuid))
            return false;
    }

    return true;
}


static struct x86_model *
x86ModelFromCPU(const virCPUDefPtr cpu,
                const struct x86_map *map,
                int policy)
{
    struct x86_model *model = NULL;
    int i;

    if (cpu->type == VIR_CPU_TYPE_HOST
        || policy == VIR_CPU_FEATURE_REQUIRE) {
        if ((model = x86ModelFind(map, cpu->model)) == NULL) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Unknown CPU model %s"), cpu->model);
            goto error;
        }

        if ((model = x86ModelCopy(model)) == NULL)
            goto no_memory;
    }
    else if (VIR_ALLOC(model) < 0)
        goto no_memory;

    for (i = 0; i < cpu->nfeatures; i++) {
        const struct x86_feature *feature;

        if (cpu->type == VIR_CPU_TYPE_GUEST
            && cpu->features[i].policy != policy)
            continue;

        if ((feature = x86FeatureFind(map, cpu->features[i].name)) == NULL) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Unknown CPU feature %s"), cpu->features[i].name);
            goto error;
        }

        if (x86ModelMergeFeature(model, feature))
            goto no_memory;
    }

    return model;

no_memory:
    virReportOOMError();

error:
    x86ModelFree(model);
    return NULL;
}


static int
x86ModelSubtractCPU(struct x86_model *model,
                    const virCPUDefPtr cpu,
                    const struct x86_map *map)
{
    const struct x86_model *cpu_model;
    unsigned int i;

    if (!(cpu_model = x86ModelFind(map, cpu->model))) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                          _("Unknown CPU model %s"),
                          cpu->model);
        return -1;
    }

    x86ModelSubtract(model, cpu_model);

    for (i = 0; i < cpu->nfeatures; i++) {
        const struct x86_feature *feature;
        unsigned int j;

        if (!(feature = x86FeatureFind(map, cpu->features[i].name))) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Unknown CPU feature %s"),
                              cpu->features[i].name);
            return -1;
        }

        for (j = 0; j < feature->ncpuid; j++) {
            struct cpuX86cpuid *cpuid;
            cpuid = x86cpuidFind(model->cpuid, model->ncpuid,
                                 feature->cpuid[j].function);
            if (cpuid)
                x86cpuidClearBits(cpuid, feature->cpuid + j);
        }
    }

    return 0;
}


static enum compare_result
x86ModelCompare(const struct x86_model *model1,
                const struct x86_model *model2)
{
    enum compare_result result = EQUAL;
    struct cpuX86cpuid *cpuid1;
    struct cpuX86cpuid *cpuid2;
    int i;

    for (i = 0; i < model1->ncpuid; i++) {
        enum compare_result match = SUPERSET;

        cpuid1 = model1->cpuid + i;
        cpuid2 = x86cpuidFind(model2->cpuid,
                              model2->ncpuid,
                              cpuid1->function);
        if (cpuid2 != NULL) {
            if (x86cpuidMatch(cpuid1, cpuid2))
                continue;
            else if (!x86cpuidMatchMasked(cpuid1, cpuid2))
                match = SUBSET;
        }

        if (result == EQUAL)
            result = match;
        else if (result != match)
            return UNRELATED;
    }

    for (i = 0; i < model2->ncpuid; i++) {
        enum compare_result match = SUBSET;

        cpuid2 = model2->cpuid + i;
        cpuid1 = x86cpuidFind(model1->cpuid,
                              model1->ncpuid,
                              cpuid2->function);
        if (cpuid1 != NULL) {
            if (x86cpuidMatch(cpuid2, cpuid1))
                continue;
            else if (!x86cpuidMatchMasked(cpuid2, cpuid1))
                match = SUPERSET;
        }

        if (result == EQUAL)
            result = match;
        else if (result != match)
            return UNRELATED;
    }

    return result;
}


static int
x86ModelLoad(xmlXPathContextPtr ctxt,
             void *data)
{
    struct x86_map *map = data;
    xmlNodePtr *nodes = NULL;
    struct x86_model *model = NULL;
    int ret = 0;
    int i;
    int n;

    if (VIR_ALLOC(model) < 0)
        goto no_memory;

    model->name = virXPathString("string(@name)", ctxt);
    if (model->name == NULL) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                "%s", _("Missing CPU model name"));
        goto ignore;
    }

    if (virXPathNode("./model", ctxt) != NULL) {
        const struct x86_model *ancestor;
        char *name;

        name = virXPathString("string(./model/@name)", ctxt);
        if (name == NULL) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Missing ancestor's name in CPU model %s"),
                    model->name);
            goto ignore;
        }

        if ((ancestor = x86ModelFind(map, name)) == NULL) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Ancestor model %s not found for CPU model %s"),
                    name, model->name);
            VIR_FREE(name);
            goto ignore;
        }

        VIR_FREE(name);

        if (VIR_ALLOC_N(model->cpuid, ancestor->ncpuid) < 0)
            goto no_memory;

        model->ncpuid = ancestor->ncpuid;
        memcpy(model->cpuid, ancestor->cpuid,
               sizeof(*model->cpuid) * model->ncpuid);
    }

    n = virXPathNodeSet("./feature", ctxt, &nodes);
    if (n < 0)
        goto ignore;

    for (i = 0; i < n; i++) {
        const struct x86_feature *feature;
        char *name;

        if ((name = virXMLPropString(nodes[i], "name")) == NULL) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Missing feature name for CPU model %s"), model->name);
            goto ignore;
        }

        if ((feature = x86FeatureFind(map, name)) == NULL) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Feature %s required by CPU model %s not found"),
                    name, model->name);
            VIR_FREE(name);
            goto ignore;
        }
        VIR_FREE(name);

        if (x86ModelMergeFeature(model, feature))
            goto no_memory;
    }

    if (map->models == NULL)
        map->models = model;
    else {
        model->next = map->models;
        map->models = model;
    }

out:
    VIR_FREE(nodes);
    return ret;

no_memory:
    virReportOOMError();
    ret = -1;

ignore:
    x86ModelFree(model);
    goto out;
}


static void
x86MapFree(struct x86_map *map)
{
    if (map == NULL)
        return;

    while (map->features != NULL) {
        struct x86_feature *feature = map->features;
        map->features = feature->next;
        x86FeatureFree(feature);
    }

    while (map->models != NULL) {
        struct x86_model *model = map->models;
        map->models = model->next;
        x86ModelFree(model);
    }

    VIR_FREE(map);
}


static struct x86_map *
x86LoadMap(void)
{
    struct x86_map *map;

    if (VIR_ALLOC(map) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (cpuMapLoad("x86",
                   x86FeatureLoad, map,
                   x86ModelLoad, map) < 0)
        goto error;

    return map;

error:
    x86MapFree(map);
    return NULL;
}


static virCPUCompareResult
x86Compute(virCPUDefPtr host,
           virCPUDefPtr cpu,
           union cpuData **guest)
{
    struct cpuX86cpuid cpuid_zero = { 0, 0, 0, 0, 0 };
    struct x86_map *map = NULL;
    struct x86_model *host_model = NULL;
    struct x86_model *cpu_force = NULL;
    struct x86_model *cpu_require = NULL;
    struct x86_model *cpu_optional = NULL;
    struct x86_model *cpu_disable = NULL;
    struct x86_model *cpu_forbid = NULL;
    struct x86_model *diff = NULL;
    struct x86_model *guest_model = NULL;
    virCPUCompareResult ret;
    enum compare_result result;
    unsigned int i;

    if (cpu->arch != NULL) {
        bool found = false;

        for (i = 0; i < ARRAY_CARDINALITY(archs); i++) {
            if (STREQ(archs[i], cpu->arch)) {
                found = true;
                break;
            }
        }

        if (!found) {
            VIR_DEBUG("CPU arch %s does not match host arch", cpu->arch);
            return VIR_CPU_COMPARE_INCOMPATIBLE;
        }
    }

    if (!(map = x86LoadMap()) ||
        !(host_model = x86ModelFromCPU(host, map, 0)) ||
        !(cpu_force = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_FORCE)) ||
        !(cpu_require = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_REQUIRE)) ||
        !(cpu_optional = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_OPTIONAL)) ||
        !(cpu_disable = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_DISABLE)) ||
        !(cpu_forbid = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_FORBID)))
        goto error;

    for (i = 0; i < cpu_forbid->ncpuid; i++) {
        const struct cpuX86cpuid *cpuid1;
        const struct cpuX86cpuid *cpuid2;

        cpuid1 = cpu_forbid->cpuid + i;
        cpuid2 = x86cpuidFind(host_model->cpuid,
                              host_model->ncpuid,
                              cpuid1->function);

        if (cpuid2 != NULL && x86cpuidMatchAny(cpuid2, cpuid1)) {
            VIR_DEBUG("Host CPU provides forbidden features in CPUID function 0x%x",
                      cpuid1->function);
            ret = VIR_CPU_COMPARE_INCOMPATIBLE;
            goto out;
        }
    }

    x86ModelSubtract(cpu_require, cpu_disable);
    result = x86ModelCompare(host_model, cpu_require);
    if (result == SUBSET || result == UNRELATED) {
        VIR_DEBUG0("Host CPU does not provide all required features");
        ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        goto out;
    }

    ret = VIR_CPU_COMPARE_IDENTICAL;

    if ((diff = x86ModelCopy(host_model)) == NULL)
        goto no_memory;

    x86ModelSubtract(diff, cpu_optional);
    x86ModelSubtract(diff, cpu_require);
    x86ModelSubtract(diff, cpu_disable);
    x86ModelSubtract(diff, cpu_force);

    for (i = 0; i < diff->ncpuid; i++) {
        if (!x86cpuidMatch(diff->cpuid + i, &cpuid_zero)) {
            ret = VIR_CPU_COMPARE_SUPERSET;
            break;
        }
    }

    if (ret == VIR_CPU_COMPARE_SUPERSET
        && cpu->type == VIR_CPU_TYPE_GUEST
        && cpu->match == VIR_CPU_MATCH_STRICT) {
        VIR_DEBUG0("Host CPU does not strictly match guest CPU");
        ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        goto out;
    }

    if (guest != NULL) {
        if ((guest_model = x86ModelCopy(host_model)) == NULL)
            goto no_memory;

        if (cpu->type == VIR_CPU_TYPE_GUEST
            && cpu->match == VIR_CPU_MATCH_EXACT)
            x86ModelSubtract(guest_model, diff);

        if (x86ModelAdd(guest_model, cpu_force))
            goto no_memory;

        x86ModelSubtract(guest_model, cpu_disable);

        if ((*guest = x86DataFromModel(guest_model)) == NULL)
            goto no_memory;
    }

out:
    x86MapFree(map);
    x86ModelFree(host_model);
    x86ModelFree(diff);
    x86ModelFree(cpu_force);
    x86ModelFree(cpu_require);
    x86ModelFree(cpu_optional);
    x86ModelFree(cpu_disable);
    x86ModelFree(cpu_forbid);
    x86ModelFree(guest_model);

    return ret;

no_memory:
    virReportOOMError();

error:
    ret = VIR_CPU_COMPARE_ERROR;
    goto out;
}


static virCPUCompareResult
x86Compare(virCPUDefPtr host,
           virCPUDefPtr cpu)
{
    return x86Compute(host, cpu, NULL);
}


static virCPUCompareResult
x86GuestData(virCPUDefPtr host,
             virCPUDefPtr guest,
             union cpuData **data)
{
    return x86Compute(host, guest, data);
}


static int
x86Decode(virCPUDefPtr cpu,
          const union cpuData *data,
          const char **models,
          unsigned int nmodels,
          const char *preferred)
{
    int ret = -1;
    struct x86_map *map;
    const struct x86_model *candidate;
    virCPUDefPtr cpuCandidate;
    virCPUDefPtr cpuModel = NULL;
    unsigned int i;

    if (data == NULL || (map = x86LoadMap()) == NULL)
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
            VIR_DEBUG("CPU model %s not allowed by hypervisor; ignoring",
                      candidate->name);
            goto next;
        }

        if (!(cpuCandidate = x86DataToCPU(data, candidate, map)))
            goto out;

        if (cpu->type == VIR_CPU_TYPE_HOST) {
            cpuCandidate->type = VIR_CPU_TYPE_HOST;
            for (i = 0; i < cpuCandidate->nfeatures; i++) {
                switch (cpuCandidate->features[i].policy) {
                case VIR_CPU_FEATURE_DISABLE:
                    virCPUDefFree(cpuCandidate);
                    goto next;
                default:
                    cpuCandidate->features[i].policy = -1;
                }
            }
        }

        if (preferred && STREQ(cpuCandidate->model, preferred)) {
            virCPUDefFree(cpuModel);
            cpuModel = cpuCandidate;
            break;
        }

        if (cpuModel == NULL
            || cpuModel->nfeatures > cpuCandidate->nfeatures) {
            virCPUDefFree(cpuModel);
            cpuModel = cpuCandidate;
        } else
            virCPUDefFree(cpuCandidate);

    next:
        candidate = candidate->next;
    }

    if (cpuModel == NULL) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                "%s", _("Cannot find suitable CPU model for given data"));
        goto out;
    }

    cpu->model = cpuModel->model;
    cpu->nfeatures = cpuModel->nfeatures;
    cpu->features = cpuModel->features;
    VIR_FREE(cpuModel);

    ret = 0;

out:
    x86MapFree(map);
    virCPUDefFree(cpuModel);

    return ret;
}


static union cpuData *
x86EncodePolicy(const virCPUDefPtr cpu,
                const struct x86_map *map,
                enum virCPUFeaturePolicy policy)
{
    struct x86_model *model;
    union cpuData *data = NULL;

    if (!(model = x86ModelFromCPU(cpu, map, policy)))
        return NULL;

    if (!(data = x86DataFromModel(model)))
        virReportOOMError();

    x86ModelFree(model);

    return data;
}


static int
x86Encode(const virCPUDefPtr cpu,
          union cpuData **forced,
          union cpuData **required,
          union cpuData **optional,
          union cpuData **disabled,
          union cpuData **forbidden)
{
    struct x86_map *map = NULL;
    union cpuData *data_forced = NULL;
    union cpuData *data_required = NULL;
    union cpuData *data_optional = NULL;
    union cpuData *data_disabled = NULL;
    union cpuData *data_forbidden = NULL;
    int ret = -1;

    if ((map = x86LoadMap()) == NULL)
        goto error;

    if (forced) {
        data_forced = x86EncodePolicy(cpu, map, VIR_CPU_FEATURE_FORCE);
        if (!data_forced)
            goto error;
    }

    if (required) {
        data_required = x86EncodePolicy(cpu, map, VIR_CPU_FEATURE_REQUIRE);
        if (!data_required)
            goto error;
    }

    if (optional) {
        data_optional = x86EncodePolicy(cpu, map, VIR_CPU_FEATURE_OPTIONAL);
        if (!data_optional)
            goto error;
    }

    if (disabled) {
        data_disabled = x86EncodePolicy(cpu, map, VIR_CPU_FEATURE_DISABLE);
        if (!data_disabled)
            goto error;
    }

    if (forbidden) {
        data_forbidden = x86EncodePolicy(cpu, map, VIR_CPU_FEATURE_FORBID);
        if (!data_forbidden)
            goto error;
    }

    if (forced)
        *forced = data_forced;
    if (required)
        *required = data_required;
    if (optional)
        *optional = data_optional;
    if (disabled)
        *disabled = data_disabled;
    if (forbidden)
        *forbidden = data_forbidden;

    ret = 0;

cleanup:
    x86MapFree(map);

    return ret;

error:
    x86DataFree(data_forced);
    x86DataFree(data_required);
    x86DataFree(data_optional);
    x86DataFree(data_disabled);
    x86DataFree(data_forbidden);
    goto cleanup;
}


#if HAVE_CPUID
static inline void
cpuidCall(struct cpuX86cpuid *cpuid)
{
# if __x86_64__
    asm("cpuid"
        : "=a" (cpuid->eax),
          "=b" (cpuid->ebx),
          "=c" (cpuid->ecx),
          "=d" (cpuid->edx)
        : "a" (cpuid->function));
# else
    /* we need to avoid direct use of ebx for CPUID output as it is used
     * for global offset table on i386 with -fPIC
     */
    asm("push %%ebx;"
        "cpuid;"
        "mov %%ebx, %1;"
        "pop %%ebx;"
        : "=a" (cpuid->eax),
          "=r" (cpuid->ebx),
          "=c" (cpuid->ecx),
          "=d" (cpuid->edx)
        : "a" (cpuid->function)
        : "cc");
# endif
}


static int
cpuidSet(uint32_t base, struct cpuX86cpuid **set)
{
    uint32_t max;
    uint32_t i;
    struct cpuX86cpuid cpuid = { base, 0, 0, 0, 0 };

    cpuidCall(&cpuid);
    max = cpuid.eax - base;

    if (VIR_ALLOC_N(*set, max + 1) < 0) {
        virReportOOMError();
        return -1;
    }

    for (i = 0; i <= max; i++) {
        cpuid.function = base | i;
        cpuidCall(&cpuid);
        (*set)[i] = cpuid;
    }

    return max + 1;
}


static union cpuData *
x86NodeData(void)
{
    union cpuData *data;

    if (VIR_ALLOC(data) < 0) {
        virReportOOMError();
        return NULL;
    }

    data->x86.basic_len = cpuidSet(CPUX86_BASIC, &data->x86.basic);
    if (data->x86.basic_len < 0)
        goto error;

    data->x86.extended_len = cpuidSet(CPUX86_EXTENDED, &data->x86.extended);
    if (data->x86.extended_len < 0)
        goto error;

    return data;

error:
    x86DataFree(data);

    return NULL;
}
#endif


static virCPUDefPtr
x86Baseline(virCPUDefPtr *cpus,
            unsigned int ncpus,
            const char **models,
            unsigned int nmodels)
{
    struct x86_map *map = NULL;
    struct x86_model *base_model = NULL;
    union cpuData *data = NULL;
    virCPUDefPtr cpu = NULL;
    unsigned int i;

    if (!(map = x86LoadMap()))
        goto error;

    if (!(base_model = x86ModelFromCPU(cpus[0], map, 0)))
        goto error;

    if (VIR_ALLOC(cpu) < 0 ||
        !(cpu->arch = strdup(cpus[0]->arch)))
        goto no_memory;
    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;

    for (i = 1; i < ncpus; i++) {
        struct x86_model *model;
        if (!(model = x86ModelFromCPU(cpus[i], map, 0)))
            goto error;

        x86ModelIntersect(base_model, model);
        x86ModelFree(model);
    }

    if (!(data = x86DataFromModel(base_model)))
        goto no_memory;

    if (x86Decode(cpu, data, models, nmodels, NULL) < 0)
        goto error;

cleanup:
    x86DataFree(data);
    x86ModelFree(base_model);
    x86MapFree(map);

    return cpu;

no_memory:
    virReportOOMError();
error:
    virCPUDefFree(cpu);
    cpu = NULL;
    goto cleanup;
}


static int
x86Update(virCPUDefPtr guest,
          const virCPUDefPtr host)
{
    int ret = -1;
    unsigned int i;
    struct x86_map *map;
    struct x86_model *host_model = NULL;
    union cpuData *data = NULL;

    if (!(map = x86LoadMap()) ||
        !(host_model = x86ModelFromCPU(host, map, 0)))
        goto cleanup;

    for (i = 0; i < guest->nfeatures; i++) {
        if (guest->features[i].policy == VIR_CPU_FEATURE_OPTIONAL) {
            const struct x86_feature *feature;
            if (!(feature = x86FeatureFind(map, guest->features[i].name))) {
                virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                                  _("Unknown CPU feature %s"),
                                  guest->features[i].name);
                goto cleanup;
            }

            if (x86ModelHasFeature(host_model, feature))
                guest->features[i].policy = VIR_CPU_FEATURE_REQUIRE;
            else
                guest->features[i].policy = VIR_CPU_FEATURE_DISABLE;
        }
    }

    if (guest->match == VIR_CPU_MATCH_MINIMUM) {
        guest->match = VIR_CPU_MATCH_EXACT;
        if (x86ModelSubtractCPU(host_model, guest, map)
            || !(data = x86DataFromModel(host_model))
            || x86DataToCPUFeatures(guest, VIR_CPU_FEATURE_REQUIRE, data, map))
            goto cleanup;
    }

    ret = 0;

cleanup:
    x86MapFree(map);
    x86ModelFree(host_model);
    x86DataFree(data);
    return ret;
}


struct cpuArchDriver cpuDriverX86 = {
    .name = "x86",
    .arch = archs,
    .narch = ARRAY_CARDINALITY(archs),
    .compare    = x86Compare,
    .decode     = x86Decode,
    .encode     = x86Encode,
    .free       = x86DataFree,
#if HAVE_CPUID
    .nodeData   = x86NodeData,
#else
    .nodeData   = NULL,
#endif
    .guestData  = x86GuestData,
    .baseline   = x86Baseline,
    .update     = x86Update,
};
