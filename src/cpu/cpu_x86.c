/*
 * cpu_x86.c: CPU driver for CPUs with x86 compatible CPUID instruction
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
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

#define VENDOR_STRING_LENGTH    12

static const struct cpuX86cpuid cpuidNull = { 0, 0, 0, 0, 0 };

static const char *archs[] = { "i686", "x86_64" };

struct x86_vendor {
    char *name;
    struct cpuX86cpuid cpuid;

    struct x86_vendor *next;
};

struct x86_feature {
    char *name;
    union cpuData *data;

    struct x86_feature *next;
};

struct x86_model {
    char *name;
    const struct x86_vendor *vendor;
    union cpuData *data;

    struct x86_model *next;
};

struct x86_map {
    struct x86_vendor *vendors;
    struct x86_feature *features;
    struct x86_model *models;
};


enum compare_result {
    SUBSET,
    EQUAL,
    SUPERSET,
    UNRELATED
};


struct data_iterator {
    union cpuData *data;
    int pos;
    bool extended;
};


#define DATA_ITERATOR_INIT(data) \
    { data, -1, false }


static void
x86DataIteratorInit(struct data_iterator *iter,
                    union cpuData *data)
{
    struct data_iterator init = DATA_ITERATOR_INIT(data);

    *iter = init;
}


static int
x86cpuidMatch(const struct cpuX86cpuid *cpuid1,
              const struct cpuX86cpuid *cpuid2)
{
    return (cpuid1->eax == cpuid2->eax &&
            cpuid1->ebx == cpuid2->ebx &&
            cpuid1->ecx == cpuid2->ecx &&
            cpuid1->edx == cpuid2->edx);
}


static int
x86cpuidMatchMasked(const struct cpuX86cpuid *cpuid,
                    const struct cpuX86cpuid *mask)
{
    return ((cpuid->eax & mask->eax) == mask->eax &&
            (cpuid->ebx & mask->ebx) == mask->ebx &&
            (cpuid->ecx & mask->ecx) == mask->ecx &&
            (cpuid->edx & mask->edx) == mask->edx);
}


static int
x86cpuidMatchAny(const struct cpuX86cpuid *cpuid,
                 const struct cpuX86cpuid *mask)
{
    return ((cpuid->eax & mask->eax) ||
            (cpuid->ebx & mask->ebx) ||
            (cpuid->ecx & mask->ecx) ||
            (cpuid->edx & mask->edx));
}


static void
x86cpuidSetBits(struct cpuX86cpuid *cpuid,
                const struct cpuX86cpuid *mask)
{
    cpuid->eax |= mask->eax;
    cpuid->ebx |= mask->ebx;
    cpuid->ecx |= mask->ecx;
    cpuid->edx |= mask->edx;
}


static void
x86cpuidClearBits(struct cpuX86cpuid *cpuid,
                  const struct cpuX86cpuid *mask)
{
    cpuid->eax &= ~mask->eax;
    cpuid->ebx &= ~mask->ebx;
    cpuid->ecx &= ~mask->ecx;
    cpuid->edx &= ~mask->edx;
}


static void
x86cpuidAndBits(struct cpuX86cpuid *cpuid,
                const struct cpuX86cpuid *mask)
{
    cpuid->eax &= mask->eax;
    cpuid->ebx &= mask->ebx;
    cpuid->ecx &= mask->ecx;
    cpuid->edx &= mask->edx;
}


/* skips all zero CPUID leafs */
static struct cpuX86cpuid *
x86DataCpuidNext(struct data_iterator *iterator)
{
    struct cpuX86cpuid *ret;
    struct cpuX86Data *data;

    if (!iterator->data)
        return NULL;

    data = &iterator->data->x86;

    do {
        ret = NULL;
        iterator->pos++;

        if (!iterator->extended) {
            if (iterator->pos < data->basic_len)
                ret = data->basic + iterator->pos;
            else {
                iterator->extended = true;
                iterator->pos = 0;
            }
        }

        if (iterator->extended && iterator->pos < data->extended_len) {
            ret = data->extended + iterator->pos;
        }
    } while (ret && x86cpuidMatch(ret, &cpuidNull));

    return ret;
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

    if (i < len && !x86cpuidMatch(cpuids + i, &cpuidNull))
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


static int
x86DataExpand(union cpuData *data,
              int basic_by,
              int extended_by)
{
    size_t i;

    if (basic_by > 0) {
        size_t len = data->x86.basic_len;
        if (VIR_EXPAND_N(data->x86.basic, data->x86.basic_len, basic_by) < 0)
            goto no_memory;

        for (i = 0; i < basic_by; i++)
            data->x86.basic[len + i].function = len + i;
    }

    if (extended_by > 0) {
        size_t len = data->x86.extended_len;
        if (VIR_EXPAND_N(data->x86.extended, data->x86.extended_len, extended_by) < 0)
            goto no_memory;

        for (i = 0; i < extended_by; i++)
            data->x86.extended[len + i].function = len + i + CPUX86_EXTENDED;
    }

    return 0;

no_memory:
    virReportOOMError();
    return -1;
}


static int
x86DataAddCpuid(union cpuData *data,
                const struct cpuX86cpuid *cpuid)
{
    unsigned int basic_by = 0;
    unsigned int extended_by = 0;
    struct cpuX86cpuid **cpuids;
    unsigned int pos;

    if (cpuid->function < CPUX86_EXTENDED) {
        pos = cpuid->function;
        basic_by = pos + 1 - data->x86.basic_len;
        cpuids = &data->x86.basic;
    } else {
        pos = cpuid->function - CPUX86_EXTENDED;
        extended_by = pos + 1 - data->x86.extended_len;
        cpuids = &data->x86.extended;
    }

    if (x86DataExpand(data, basic_by, extended_by) < 0)
        return -1;

    x86cpuidSetBits((*cpuids) + pos, cpuid);

    return 0;
}


static int
x86DataAdd(union cpuData *data1,
           const union cpuData *data2)
{
    unsigned int i;

    if (x86DataExpand(data1,
                      data2->x86.basic_len - data1->x86.basic_len,
                      data2->x86.extended_len - data1->x86.extended_len) < 0)
        return -1;

    for (i = 0; i < data2->x86.basic_len; i++) {
        x86cpuidSetBits(data1->x86.basic + i,
                        data2->x86.basic + i);
    }

    for (i = 0; i < data2->x86.extended_len; i++) {
        x86cpuidSetBits(data1->x86.extended + i,
                        data2->x86.extended + i);
    }

    return 0;
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


static void
x86DataIntersect(union cpuData *data1,
                 const union cpuData *data2)
{
    struct data_iterator iter = DATA_ITERATOR_INIT(data1);
    struct cpuX86cpuid *cpuid1;
    struct cpuX86cpuid *cpuid2;

    while ((cpuid1 = x86DataCpuidNext(&iter))) {
        cpuid2 = x86DataCpuid(data2, cpuid1->function);
        if (cpuid2)
            x86cpuidAndBits(cpuid1, cpuid2);
        else
            x86cpuidClearBits(cpuid1, cpuid1);
    }
}


static bool
x86DataIsEmpty(union cpuData *data)
{
    struct data_iterator iter = DATA_ITERATOR_INIT(data);

    return x86DataCpuidNext(&iter) == NULL;
}


static bool
x86DataIsSubset(const union cpuData *data,
                const union cpuData *subset)
{

    struct data_iterator iter = DATA_ITERATOR_INIT((union cpuData *) subset);
    const struct cpuX86cpuid *cpuid;
    const struct cpuX86cpuid *cpuidSubset;

    while ((cpuidSubset = x86DataCpuidNext(&iter))) {
        if (!(cpuid = x86DataCpuid(data, cpuidSubset->function)) ||
            !x86cpuidMatchMasked(cpuid, cpuidSubset))
            return false;
    }

    return true;
}


/* also removes all detected features from data */
static int
x86DataToCPUFeatures(virCPUDefPtr cpu,
                     int policy,
                     union cpuData *data,
                     const struct x86_map *map)
{
    const struct x86_feature *feature = map->features;

    while (feature != NULL) {
        if (x86DataIsSubset(data, feature->data)) {
            x86DataSubtract(data, feature->data);
            if (virCPUDefAddFeature(cpu, feature->name, policy) < 0)
                return -1;
        }
        feature = feature->next;
    }

    return 0;
}


/* also removes bits corresponding to vendor string from data */
static const struct x86_vendor *
x86DataToVendor(union cpuData *data,
                const struct x86_map *map)
{
    const struct x86_vendor *vendor = map->vendors;
    struct cpuX86cpuid *cpuid;

    while (vendor) {
        if ((cpuid = x86DataCpuid(data, vendor->cpuid.function)) &&
            x86cpuidMatchMasked(cpuid, &vendor->cpuid)) {
            x86cpuidClearBits(cpuid, &vendor->cpuid);
            return vendor;
        }
        vendor = vendor->next;
    }

    return NULL;
}


static virCPUDefPtr
x86DataToCPU(const union cpuData *data,
             const struct x86_model *model,
             const struct x86_map *map)
{
    virCPUDefPtr cpu;
    union cpuData *copy = NULL;
    union cpuData *modelData = NULL;
    const struct x86_vendor *vendor;

    if (VIR_ALLOC(cpu) < 0 ||
        !(cpu->model = strdup(model->name)) ||
        !(copy = x86DataCopy(data)) ||
        !(modelData = x86DataCopy(model->data)))
        goto no_memory;

    if ((vendor = x86DataToVendor(copy, map)) &&
        !(cpu->vendor = strdup(vendor->name)))
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
x86VendorFree(struct x86_vendor *vendor)
{
    if (!vendor)
        return;

    VIR_FREE(vendor->name);
    VIR_FREE(vendor);
}


static struct x86_vendor *
x86VendorFind(const struct x86_map *map,
              const char *name)
{
    struct x86_vendor *vendor;

    vendor = map->vendors;
    while (vendor) {
        if (STREQ(vendor->name, name))
            return vendor;

        vendor = vendor->next;
    }

    return NULL;
}


static int
x86VendorLoad(xmlXPathContextPtr ctxt,
              struct x86_map *map)
{
    struct x86_vendor *vendor = NULL;
    char *string = NULL;
    int ret = 0;

    if (VIR_ALLOC(vendor) < 0)
        goto no_memory;

    vendor->name = virXPathString("string(@name)", ctxt);
    if (!vendor->name) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                "%s", _("Missing CPU vendor name"));
        goto ignore;
    }

    if (x86VendorFind(map, vendor->name)) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                _("CPU vendor %s already defined"), vendor->name);
        goto ignore;
    }

    string = virXPathString("string(@string)", ctxt);
    if (!string) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                _("Missing vendor string for CPU vendor %s"), vendor->name);
        goto ignore;
    }
    if (strlen(string) != VENDOR_STRING_LENGTH) {
        virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                _("Invalid CPU vendor string '%s'"), string);
        goto ignore;
    }

    vendor->cpuid.function = 0;
    vendor->cpuid.ebx = (string[0]       ) |
                        (string[1]  <<  8) |
                        (string[2]  << 16) |
                        (string[3]  << 24);
    vendor->cpuid.edx = (string[4]       ) |
                        (string[5]  <<  8) |
                        (string[6]  << 16) |
                        (string[7]  << 24);
    vendor->cpuid.ecx = (string[8]       ) |
                        (string[9]  <<  8) |
                        (string[10] << 16) |
                        (string[11] << 24);

    if (!map->vendors)
        map->vendors = vendor;
    else {
        vendor->next = map->vendors;
        map->vendors = vendor;
    }

out:
    VIR_FREE(string);

    return ret;

no_memory:
    virReportOOMError();
    ret = -1;
ignore:
    x86VendorFree(vendor);
    goto out;
}


static struct x86_feature *
x86FeatureNew(void)
{
    struct x86_feature *feature;

    if (VIR_ALLOC(feature) < 0)
        return NULL;

    if (VIR_ALLOC(feature->data) < 0) {
        VIR_FREE(feature);
        return NULL;
    }

    return feature;
}


static void
x86FeatureFree(struct x86_feature *feature)
{
    if (feature == NULL)
        return;

    VIR_FREE(feature->name);
    x86DataFree(feature->data);
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
               struct x86_map *map)
{
    xmlNodePtr *nodes = NULL;
    xmlNodePtr ctxt_node = ctxt->node;
    struct x86_feature *feature;
    int ret = 0;
    int i;
    int n;

    if (!(feature = x86FeatureNew()))
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

    for (i = 0; i < n; i++) {
        struct cpuX86cpuid cpuid;
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

        cpuid.function = fun;
        cpuid.eax = eax;
        cpuid.ebx = ebx;
        cpuid.ecx = ecx;
        cpuid.edx = edx;

        if (x86DataAddCpuid(feature->data, &cpuid))
            goto no_memory;
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


static struct x86_model *
x86ModelNew(void)
{
    struct x86_model *model;

    if (VIR_ALLOC(model) < 0)
        return NULL;

    if (VIR_ALLOC(model->data) < 0) {
        VIR_FREE(model);
        return NULL;
    }

    return model;
}


static void
x86ModelFree(struct x86_model *model)
{
    if (model == NULL)
        return;

    VIR_FREE(model->name);
    x86DataFree(model->data);
    VIR_FREE(model);
}


static struct x86_model *
x86ModelCopy(const struct x86_model *model)
{
    struct x86_model *copy;

    if (VIR_ALLOC(copy) < 0
        || !(copy->name = strdup(model->name))
        || !(copy->data = x86DataCopy(model->data))) {
        x86ModelFree(copy);
        return NULL;
    }

    copy->vendor = model->vendor;

    return copy;
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


static struct x86_model *
x86ModelFromCPU(const virCPUDefPtr cpu,
                const struct x86_map *map,
                int policy)
{
    struct x86_model *model = NULL;
    int i;

    if (policy == VIR_CPU_FEATURE_REQUIRE) {
        if ((model = x86ModelFind(map, cpu->model)) == NULL) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Unknown CPU model %s"), cpu->model);
            goto error;
        }

        if ((model = x86ModelCopy(model)) == NULL)
            goto no_memory;
    } else if (!(model = x86ModelNew())) {
        goto no_memory;
    } else if (cpu->type == VIR_CPU_TYPE_HOST) {
        return model;
    }

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

        if (x86DataAdd(model->data, feature->data))
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

    x86DataSubtract(model->data, cpu_model->data);

    for (i = 0; i < cpu->nfeatures; i++) {
        const struct x86_feature *feature;

        if (!(feature = x86FeatureFind(map, cpu->features[i].name))) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                              _("Unknown CPU feature %s"),
                              cpu->features[i].name);
            return -1;
        }

        x86DataSubtract(model->data, feature->data);
    }

    return 0;
}


static enum compare_result
x86ModelCompare(const struct x86_model *model1,
                const struct x86_model *model2)
{
    enum compare_result result = EQUAL;
    struct data_iterator iter1 = DATA_ITERATOR_INIT(model1->data);
    struct data_iterator iter2 = DATA_ITERATOR_INIT(model2->data);
    struct cpuX86cpuid *cpuid1;
    struct cpuX86cpuid *cpuid2;

    while ((cpuid1 = x86DataCpuidNext(&iter1))) {
        enum compare_result match = SUPERSET;

        if ((cpuid2 = x86DataCpuid(model2->data, cpuid1->function))) {
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

    while ((cpuid2 = x86DataCpuidNext(&iter2))) {
        enum compare_result match = SUBSET;

        if ((cpuid1 = x86DataCpuid(model1->data, cpuid2->function))) {
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
             struct x86_map *map)
{
    xmlNodePtr *nodes = NULL;
    struct x86_model *model;
    char *vendor = NULL;
    int ret = 0;
    int i;
    int n;

    if (!(model = x86ModelNew()))
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

        model->vendor = ancestor->vendor;
        x86DataFree(model->data);
        if (!(model->data = x86DataCopy(ancestor->data)))
            goto no_memory;
    }

    if (virXPathBoolean("boolean(./vendor)", ctxt)) {
        vendor = virXPathString("string(./vendor/@name)", ctxt);
        if (!vendor) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Invalid vendor element in CPU model %s"),
                    model->name);
            goto ignore;
        }

        if (!(model->vendor = x86VendorFind(map, vendor))) {
            virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                    _("Unknown vendor %s referenced by CPU model %s"),
                    vendor, model->name);
            goto ignore;
        }
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

        if (x86DataAdd(model->data, feature->data))
            goto no_memory;
    }

    if (map->models == NULL)
        map->models = model;
    else {
        model->next = map->models;
        map->models = model;
    }

out:
    VIR_FREE(vendor);
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

    while (map->vendors != NULL) {
        struct x86_vendor *vendor = map->vendors;
        map->vendors = vendor->next;
        x86VendorFree(vendor);
    }

    VIR_FREE(map);
}


static int
x86MapLoadCallback(enum cpuMapElement element,
                   xmlXPathContextPtr ctxt,
                   void *data)
{
    struct x86_map *map = data;

    switch (element) {
    case CPU_MAP_ELEMENT_VENDOR:
        return x86VendorLoad(ctxt, map);
    case CPU_MAP_ELEMENT_FEATURE:
        return x86FeatureLoad(ctxt, map);
    case CPU_MAP_ELEMENT_MODEL:
        return x86ModelLoad(ctxt, map);
    case CPU_MAP_ELEMENT_LAST:
        break;
    }

    return 0;
}


static struct x86_map *
x86LoadMap(void)
{
    struct x86_map *map;

    if (VIR_ALLOC(map) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (cpuMapLoad("x86", x86MapLoadCallback, map) < 0)
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
    struct x86_map *map = NULL;
    struct x86_model *host_model = NULL;
    struct x86_model *cpu_force = NULL;
    struct x86_model *cpu_require = NULL;
    struct x86_model *cpu_optional = NULL;
    struct x86_model *cpu_disable = NULL;
    struct x86_model *cpu_forbid = NULL;
    struct x86_model *diff = NULL;
    struct x86_model *guest_model = NULL;
    struct data_iterator iter;
    const struct cpuX86cpuid *cpuid;
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

    if (cpu->vendor &&
        (!host->vendor || STRNEQ(cpu->vendor, host->vendor))) {
        VIR_DEBUG("host CPU vendor does not match required CPU vendor %s",
                  cpu->vendor);
        return VIR_CPU_COMPARE_INCOMPATIBLE;
    }

    if (!(map = x86LoadMap()) ||
        !(host_model = x86ModelFromCPU(host, map, VIR_CPU_FEATURE_REQUIRE)) ||
        !(cpu_force = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_FORCE)) ||
        !(cpu_require = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_REQUIRE)) ||
        !(cpu_optional = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_OPTIONAL)) ||
        !(cpu_disable = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_DISABLE)) ||
        !(cpu_forbid = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_FORBID)))
        goto error;

    x86DataIteratorInit(&iter, cpu_forbid->data);
    while ((cpuid = x86DataCpuidNext(&iter))) {
        const struct cpuX86cpuid *cpuid2;

        cpuid2 = x86DataCpuid(host_model->data, cpuid->function);
        if (cpuid2 != NULL && x86cpuidMatchAny(cpuid2, cpuid)) {
            VIR_DEBUG("Host CPU provides forbidden features in CPUID function 0x%x",
                      cpuid->function);
            ret = VIR_CPU_COMPARE_INCOMPATIBLE;
            goto out;
        }
    }

    x86DataSubtract(cpu_require->data, cpu_disable->data);
    result = x86ModelCompare(host_model, cpu_require);
    if (result == SUBSET || result == UNRELATED) {
        VIR_DEBUG("Host CPU does not provide all required features");
        ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        goto out;
    }

    ret = VIR_CPU_COMPARE_IDENTICAL;

    if ((diff = x86ModelCopy(host_model)) == NULL)
        goto no_memory;

    x86DataSubtract(diff->data, cpu_optional->data);
    x86DataSubtract(diff->data, cpu_require->data);
    x86DataSubtract(diff->data, cpu_disable->data);
    x86DataSubtract(diff->data, cpu_force->data);

    if (!x86DataIsEmpty(diff->data))
        ret = VIR_CPU_COMPARE_SUPERSET;

    if (ret == VIR_CPU_COMPARE_SUPERSET
        && cpu->type == VIR_CPU_TYPE_GUEST
        && cpu->match == VIR_CPU_MATCH_STRICT) {
        VIR_DEBUG("Host CPU does not strictly match guest CPU");
        ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        goto out;
    }

    if (guest != NULL) {
        if ((guest_model = x86ModelCopy(host_model)) == NULL)
            goto no_memory;

        if (cpu->type == VIR_CPU_TYPE_GUEST
            && cpu->match == VIR_CPU_MATCH_EXACT)
            x86DataSubtract(guest_model->data, diff->data);

        if (x86DataAdd(guest_model->data, cpu_force->data))
            goto no_memory;

        x86DataSubtract(guest_model->data, cpu_disable->data);

        if ((*guest = x86DataCopy(guest_model->data)) == NULL)
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
            if (preferred && STREQ(candidate->name, preferred)) {
                if (cpu->fallback != VIR_CPU_FALLBACK_ALLOW) {
                    virCPUReportError(VIR_ERR_CONFIG_UNSUPPORTED,
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

        if (!(cpuCandidate = x86DataToCPU(data, candidate, map)))
            goto out;

        if (candidate->vendor && cpuCandidate->vendor &&
            STRNEQ(candidate->vendor->name, cpuCandidate->vendor)) {
            VIR_DEBUG("CPU vendor %s of model %s differs from %s; ignoring",
                      candidate->vendor->name, candidate->name,
                      cpuCandidate->vendor);
            virCPUDefFree(cpuCandidate);
            goto next;
        }

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
    cpu->vendor = cpuModel->vendor;
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

    data = model->data;
    model->data = NULL;
    x86ModelFree(model);

    return data;
}


static int
x86Encode(const virCPUDefPtr cpu,
          union cpuData **forced,
          union cpuData **required,
          union cpuData **optional,
          union cpuData **disabled,
          union cpuData **forbidden,
          union cpuData **vendor)
{
    struct x86_map *map = NULL;
    union cpuData *data_forced = NULL;
    union cpuData *data_required = NULL;
    union cpuData *data_optional = NULL;
    union cpuData *data_disabled = NULL;
    union cpuData *data_forbidden = NULL;
    union cpuData *data_vendor = NULL;
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

    if (vendor) {
        const struct x86_vendor *v = NULL;

        if (cpu->vendor && !(v = x86VendorFind(map, cpu->vendor))) {
            virCPUReportError(VIR_ERR_OPERATION_FAILED,
                    _("CPU vendor %s not found"), cpu->vendor);
            goto error;
        }

        if (v &&
            (VIR_ALLOC(data_vendor) < 0 ||
             x86DataAddCpuid(data_vendor, &v->cpuid) < 0)) {
            virReportOOMError();
            goto error;
        }
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
    if (vendor)
        *vendor = data_vendor;

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
    x86DataFree(data_vendor);
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
    int ret;

    if (VIR_ALLOC(data) < 0) {
        virReportOOMError();
        return NULL;
    }

    if ((ret = cpuidSet(CPUX86_BASIC, &data->x86.basic)) < 0)
        goto error;
    data->x86.basic_len = ret;

    if ((ret = cpuidSet(CPUX86_EXTENDED, &data->x86.extended)) < 0)
        goto error;
    data->x86.extended_len = ret;

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
    virCPUDefPtr cpu = NULL;
    unsigned int i;
    const struct x86_vendor *vendor = NULL;
    struct x86_model *model = NULL;
    bool outputVendor = true;

    if (!(map = x86LoadMap()))
        goto error;

    if (!(base_model = x86ModelFromCPU(cpus[0], map, VIR_CPU_FEATURE_REQUIRE)))
        goto error;

    if (VIR_ALLOC(cpu) < 0 ||
        !(cpu->arch = strdup(cpus[0]->arch)))
        goto no_memory;
    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;

    if (!cpus[0]->vendor)
        outputVendor = false;
    else if (!(vendor = x86VendorFind(map, cpus[0]->vendor))) {
        virCPUReportError(VIR_ERR_OPERATION_FAILED,
                _("Unknown CPU vendor %s"), cpus[0]->vendor);
        goto error;
    }

    for (i = 1; i < ncpus; i++) {
        const char *vn = NULL;

        if (!(model = x86ModelFromCPU(cpus[i], map, VIR_CPU_FEATURE_REQUIRE)))
            goto error;

        if (cpus[i]->vendor && model->vendor &&
            STRNEQ(cpus[i]->vendor, model->vendor->name)) {
            virCPUReportError(VIR_ERR_OPERATION_FAILED,
                    _("CPU vendor %s of model %s differs from vendor %s"),
                    model->vendor->name, model->name, cpus[i]->vendor);
            goto error;
        }

        if (cpus[i]->vendor)
            vn = cpus[i]->vendor;
        else {
            outputVendor = false;
            if (model->vendor)
                vn = model->vendor->name;
        }

        if (vn) {
            if (!vendor) {
                if (!(vendor = x86VendorFind(map, vn))) {
                    virCPUReportError(VIR_ERR_OPERATION_FAILED,
                            _("Unknown CPU vendor %s"), vn);
                    goto error;
                }
            } else if (STRNEQ(vendor->name, vn)) {
                virCPUReportError(VIR_ERR_OPERATION_FAILED,
                        "%s", _("CPU vendors do not match"));
                goto error;
            }
        }

        x86DataIntersect(base_model->data, model->data);
        x86ModelFree(model);
        model = NULL;
    }

    if (x86DataIsEmpty(base_model->data)) {
        virCPUReportError(VIR_ERR_OPERATION_FAILED,
                "%s", _("CPUs are incompatible"));
        goto error;
    }

    if (vendor && x86DataAddCpuid(base_model->data, &vendor->cpuid) < 0)
        goto no_memory;

    if (x86Decode(cpu, base_model->data, models, nmodels, NULL) < 0)
        goto error;

    if (!outputVendor)
        VIR_FREE(cpu->vendor);

    VIR_FREE(cpu->arch);

cleanup:
    x86ModelFree(base_model);
    x86MapFree(map);

    return cpu;

no_memory:
    virReportOOMError();
error:
    x86ModelFree(model);
    virCPUDefFree(cpu);
    cpu = NULL;
    goto cleanup;
}


static int
x86UpdateCustom(virCPUDefPtr guest,
                const virCPUDefPtr host)
{
    int ret = -1;
    unsigned int i;
    struct x86_map *map;
    struct x86_model *host_model = NULL;

    if (!(map = x86LoadMap()) ||
        !(host_model = x86ModelFromCPU(host, map, VIR_CPU_FEATURE_REQUIRE)))
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

            if (x86DataIsSubset(host_model->data, feature->data))
                guest->features[i].policy = VIR_CPU_FEATURE_REQUIRE;
            else
                guest->features[i].policy = VIR_CPU_FEATURE_DISABLE;
        }
    }

    if (guest->match == VIR_CPU_MATCH_MINIMUM) {
        guest->match = VIR_CPU_MATCH_EXACT;
        if (x86ModelSubtractCPU(host_model, guest, map)
            || x86DataToCPUFeatures(guest, VIR_CPU_FEATURE_REQUIRE,
                                    host_model->data, map))
            goto cleanup;
    }

    ret = 0;

cleanup:
    x86MapFree(map);
    x86ModelFree(host_model);
    return ret;
}

static int
x86Update(virCPUDefPtr guest,
          const virCPUDefPtr host)
{
    switch ((enum virCPUMode) guest->mode) {
    case VIR_CPU_MODE_CUSTOM:
        return x86UpdateCustom(guest, host);

    case VIR_CPU_MODE_HOST_MODEL:
    case VIR_CPU_MODE_HOST_PASSTHROUGH:
        if (guest->mode == VIR_CPU_MODE_HOST_MODEL)
            guest->match = VIR_CPU_MATCH_EXACT;
        else
            guest->match = VIR_CPU_MATCH_MINIMUM;
        virCPUDefFreeModel(guest);
        return virCPUDefCopyModel(guest, host, true);

    case VIR_CPU_MODE_LAST:
        break;
    }

    virCPUReportError(VIR_ERR_INTERNAL_ERROR,
                      _("Unexpected CPU mode: %d"), guest->mode);
    return -1;
}

static int x86HasFeature(const union cpuData *data,
                         const char *name)
{
    struct x86_map *map;
    struct x86_feature *feature;
    int ret = -1;

    if (!(map = x86LoadMap()))
        return -1;

    if (!(feature = x86FeatureFind(map, name)))
        goto cleanup;

    ret = x86DataIsSubset(data, feature->data) ? 1 : 0;

cleanup:
    x86MapFree(map);
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
    .hasFeature = x86HasFeature,
};
