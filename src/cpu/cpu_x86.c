/*
 * cpu_x86.c: CPU driver for CPUs with x86 compatible CPUID instruction
 *
 * Copyright (C) 2009-2014 Red Hat, Inc.
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
 *      Jiri Denemark <jdenemar@redhat.com>
 */

#include <config.h>

#include <stdint.h>

#include "virlog.h"
#include "viralloc.h"
#include "cpu.h"
#include "cpu_map.h"
#include "cpu_x86.h"
#include "virbuffer.h"
#include "virendian.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_CPU

VIR_LOG_INIT("cpu.cpu_x86");

#define VENDOR_STRING_LENGTH    12

static const virCPUx86CPUID cpuidNull = { 0, 0, 0, 0, 0 };

static const virArch archs[] = { VIR_ARCH_I686, VIR_ARCH_X86_64 };

typedef struct _virCPUx86Vendor virCPUx86Vendor;
typedef virCPUx86Vendor *virCPUx86VendorPtr;
struct _virCPUx86Vendor {
    char *name;
    virCPUx86CPUID cpuid;
};

typedef struct _virCPUx86Feature virCPUx86Feature;
typedef virCPUx86Feature *virCPUx86FeaturePtr;
struct _virCPUx86Feature {
    char *name;
    virCPUx86Data *data;
    bool migratable;
};

typedef struct _virCPUx86KVMFeature virCPUx86KVMFeature;
typedef virCPUx86KVMFeature *virCPUx86KVMFeaturePtr;
struct _virCPUx86KVMFeature {
    const char *name;
    const virCPUx86CPUID cpuid;
};

static const virCPUx86KVMFeature x86_kvm_features[] =
{
    {VIR_CPU_x86_KVM_CLOCKSOURCE,  { .function = 0x40000001, .eax = 0x00000001 }},
    {VIR_CPU_x86_KVM_NOP_IO_DELAY, { .function = 0x40000001, .eax = 0x00000002 }},
    {VIR_CPU_x86_KVM_MMU_OP,       { .function = 0x40000001, .eax = 0x00000004 }},
    {VIR_CPU_x86_KVM_CLOCKSOURCE2, { .function = 0x40000001, .eax = 0x00000008 }},
    {VIR_CPU_x86_KVM_ASYNC_PF,     { .function = 0x40000001, .eax = 0x00000010 }},
    {VIR_CPU_x86_KVM_STEAL_TIME,   { .function = 0x40000001, .eax = 0x00000020 }},
    {VIR_CPU_x86_KVM_PV_EOI,       { .function = 0x40000001, .eax = 0x00000040 }},
    {VIR_CPU_x86_KVM_PV_UNHALT,    { .function = 0x40000001, .eax = 0x00000080 }},
    {VIR_CPU_x86_KVM_CLOCKSOURCE_STABLE_BIT,
                                   { .function = 0x40000001, .eax = 0x01000000 }},
    {VIR_CPU_x86_KVM_HV_RUNTIME,   { .function = 0x40000003, .eax = 0x00000001 }},
    {VIR_CPU_x86_KVM_HV_SYNIC,     { .function = 0x40000003, .eax = 0x00000004 }},
    {VIR_CPU_x86_KVM_HV_STIMER,    { .function = 0x40000003, .eax = 0x00000008 }},
    {VIR_CPU_x86_KVM_HV_RELAXED,   { .function = 0x40000003, .eax = 0x00000020 }},
    {VIR_CPU_x86_KVM_HV_SPINLOCK,  { .function = 0x40000003, .eax = 0x00000022 }},
    {VIR_CPU_x86_KVM_HV_VAPIC,     { .function = 0x40000003, .eax = 0x00000030 }},
    {VIR_CPU_x86_KVM_HV_VPINDEX,   { .function = 0x40000003, .eax = 0x00000040 }},
    {VIR_CPU_x86_KVM_HV_RESET,     { .function = 0x40000003, .eax = 0x00000080 }},
};

typedef struct _virCPUx86Model virCPUx86Model;
typedef virCPUx86Model *virCPUx86ModelPtr;
struct _virCPUx86Model {
    char *name;
    virCPUx86VendorPtr vendor;
    virCPUx86Data *data;
};

typedef struct _virCPUx86Map virCPUx86Map;
typedef virCPUx86Map *virCPUx86MapPtr;
struct _virCPUx86Map {
    size_t nvendors;
    virCPUx86VendorPtr *vendors;
    size_t nfeatures;
    virCPUx86FeaturePtr *features;
    size_t nmodels;
    virCPUx86ModelPtr *models;
    size_t nblockers;
    virCPUx86FeaturePtr *migrate_blockers;
};

static virCPUx86MapPtr cpuMap;
int virCPUx86MapOnceInit(void);
VIR_ONCE_GLOBAL_INIT(virCPUx86Map);


typedef enum {
    SUBSET,
    EQUAL,
    SUPERSET,
    UNRELATED
} virCPUx86CompareResult;


typedef struct _virCPUx86DataIterator virCPUx86DataIterator;
typedef virCPUx86DataIterator *virCPUx86DataIteratorPtr;
struct _virCPUx86DataIterator {
    const virCPUx86Data *data;
    int pos;
};


#define virCPUx86DataIteratorInit(data) \
    { data, -1 }


static bool
x86cpuidMatch(const virCPUx86CPUID *cpuid1,
              const virCPUx86CPUID *cpuid2)
{
    return (cpuid1->eax == cpuid2->eax &&
            cpuid1->ebx == cpuid2->ebx &&
            cpuid1->ecx == cpuid2->ecx &&
            cpuid1->edx == cpuid2->edx);
}


static bool
x86cpuidMatchMasked(const virCPUx86CPUID *cpuid,
                    const virCPUx86CPUID *mask)
{
    return ((cpuid->eax & mask->eax) == mask->eax &&
            (cpuid->ebx & mask->ebx) == mask->ebx &&
            (cpuid->ecx & mask->ecx) == mask->ecx &&
            (cpuid->edx & mask->edx) == mask->edx);
}


static void
x86cpuidSetBits(virCPUx86CPUID *cpuid,
                const virCPUx86CPUID *mask)
{
    if (!mask)
        return;

    cpuid->eax |= mask->eax;
    cpuid->ebx |= mask->ebx;
    cpuid->ecx |= mask->ecx;
    cpuid->edx |= mask->edx;
}


static void
x86cpuidClearBits(virCPUx86CPUID *cpuid,
                  const virCPUx86CPUID *mask)
{
    if (!mask)
        return;

    cpuid->eax &= ~mask->eax;
    cpuid->ebx &= ~mask->ebx;
    cpuid->ecx &= ~mask->ecx;
    cpuid->edx &= ~mask->edx;
}


static void
x86cpuidAndBits(virCPUx86CPUID *cpuid,
                const virCPUx86CPUID *mask)
{
    if (!mask)
        return;

    cpuid->eax &= mask->eax;
    cpuid->ebx &= mask->ebx;
    cpuid->ecx &= mask->ecx;
    cpuid->edx &= mask->edx;
}

static int
virCPUx86CPUIDSorter(const void *a, const void *b)
{
    virCPUx86CPUID *da = (virCPUx86CPUID *) a;
    virCPUx86CPUID *db = (virCPUx86CPUID *) b;

    if (da->function > db->function)
        return 1;
    else if (da->function < db->function)
        return -1;

    return 0;
}


/* skips all zero CPUID leafs */
static virCPUx86CPUID *
x86DataCpuidNext(virCPUx86DataIteratorPtr iterator)
{
    const virCPUx86Data *data = iterator->data;

    if (!data)
        return NULL;

    while (++iterator->pos < data->len) {
        if (!x86cpuidMatch(data->data + iterator->pos, &cpuidNull))
            return data->data + iterator->pos;
    }

    return NULL;
}


static virCPUx86CPUID *
x86DataCpuid(const virCPUx86Data *data,
             uint32_t function)
{
    size_t i;

    for (i = 0; i < data->len; i++) {
        if (data->data[i].function == function)
            return data->data + i;
    }

    return NULL;
}

void
virCPUx86DataFree(virCPUx86Data *data)
{
    if (!data)
        return;

    VIR_FREE(data->data);
    VIR_FREE(data);
}


virCPUDataPtr
virCPUx86MakeData(virArch arch, virCPUx86Data **data)
{
    virCPUDataPtr cpuData;

    if (VIR_ALLOC(cpuData) < 0)
        return NULL;

    cpuData->arch = arch;
    cpuData->data.x86 = *data;
    *data = NULL;

    return cpuData;
}

static void
x86FreeCPUData(virCPUDataPtr data)
{
    if (!data)
        return;

    virCPUx86DataFree(data->data.x86);
    VIR_FREE(data);
}


static virCPUx86Data *
x86DataCopy(const virCPUx86Data *data)
{
    virCPUx86Data *copy = NULL;
    size_t i;

    if (VIR_ALLOC(copy) < 0 ||
        VIR_ALLOC_N(copy->data, data->len) < 0) {
        virCPUx86DataFree(copy);
        return NULL;
    }

    copy->len = data->len;
    for (i = 0; i < data->len; i++)
        copy->data[i] = data->data[i];

    return copy;
}


int
virCPUx86DataAddCPUID(virCPUx86Data *data,
                      const virCPUx86CPUID *cpuid)
{
    virCPUx86CPUID *existing;

    if ((existing = x86DataCpuid(data, cpuid->function))) {
        x86cpuidSetBits(existing, cpuid);
    } else {
        if (VIR_APPEND_ELEMENT_COPY(data->data, data->len,
                                    *((virCPUx86CPUID *)cpuid)) < 0)
            return -1;

        qsort(data->data, data->len,
              sizeof(virCPUx86CPUID), virCPUx86CPUIDSorter);
    }

    return 0;
}


static int
x86DataAdd(virCPUx86Data *data1,
           const virCPUx86Data *data2)
{
    virCPUx86DataIterator iter = virCPUx86DataIteratorInit(data2);
    virCPUx86CPUID *cpuid1;
    virCPUx86CPUID *cpuid2;

    while ((cpuid2 = x86DataCpuidNext(&iter))) {
        cpuid1 = x86DataCpuid(data1, cpuid2->function);

        if (cpuid1) {
            x86cpuidSetBits(cpuid1, cpuid2);
        } else {
            if (virCPUx86DataAddCPUID(data1, cpuid2) < 0)
                return -1;
        }
    }

    return 0;
}


static void
x86DataSubtract(virCPUx86Data *data1,
                const virCPUx86Data *data2)
{
    virCPUx86DataIterator iter = virCPUx86DataIteratorInit(data1);
    virCPUx86CPUID *cpuid1;
    virCPUx86CPUID *cpuid2;

    while ((cpuid1 = x86DataCpuidNext(&iter))) {
        cpuid2 = x86DataCpuid(data2, cpuid1->function);
        x86cpuidClearBits(cpuid1, cpuid2);
    }
}


static void
x86DataIntersect(virCPUx86Data *data1,
                 const virCPUx86Data *data2)
{
    virCPUx86DataIterator iter = virCPUx86DataIteratorInit(data1);
    virCPUx86CPUID *cpuid1;
    virCPUx86CPUID *cpuid2;

    while ((cpuid1 = x86DataCpuidNext(&iter))) {
        cpuid2 = x86DataCpuid(data2, cpuid1->function);
        if (cpuid2)
            x86cpuidAndBits(cpuid1, cpuid2);
        else
            x86cpuidClearBits(cpuid1, cpuid1);
    }
}


static bool
x86DataIsEmpty(virCPUx86Data *data)
{
    virCPUx86DataIterator iter = virCPUx86DataIteratorInit(data);

    return !x86DataCpuidNext(&iter);
}


static bool
x86DataIsSubset(const virCPUx86Data *data,
                const virCPUx86Data *subset)
{

    virCPUx86DataIterator iter = virCPUx86DataIteratorInit((virCPUx86Data *)subset);
    const virCPUx86CPUID *cpuid;
    const virCPUx86CPUID *cpuidSubset;

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
                     virCPUx86Data *data,
                     virCPUx86MapPtr map)
{
    size_t i;

    for (i = 0; i < map->nfeatures; i++) {
        virCPUx86FeaturePtr feature = map->features[i];
        if (x86DataIsSubset(data, feature->data)) {
            x86DataSubtract(data, feature->data);
            if (virCPUDefAddFeature(cpu, feature->name, policy) < 0)
                return -1;
        }
    }

    return 0;
}


/* also removes bits corresponding to vendor string from data */
static virCPUx86VendorPtr
x86DataToVendor(const virCPUx86Data *data,
                virCPUx86MapPtr map)
{
    virCPUx86CPUID *cpuid;
    size_t i;

    for (i = 0; i < map->nvendors; i++) {
        virCPUx86VendorPtr vendor = map->vendors[i];
        if ((cpuid = x86DataCpuid(data, vendor->cpuid.function)) &&
            x86cpuidMatchMasked(cpuid, &vendor->cpuid)) {
            x86cpuidClearBits(cpuid, &vendor->cpuid);
            return vendor;
        }
    }

    return NULL;
}


static virCPUDefPtr
x86DataToCPU(const virCPUx86Data *data,
             virCPUx86ModelPtr model,
             virCPUx86MapPtr map)
{
    virCPUDefPtr cpu;
    virCPUx86Data *copy = NULL;
    virCPUx86Data *modelData = NULL;
    virCPUx86VendorPtr vendor;

    if (VIR_ALLOC(cpu) < 0 ||
        VIR_STRDUP(cpu->model, model->name) < 0 ||
        !(copy = x86DataCopy(data)) ||
        !(modelData = x86DataCopy(model->data)))
        goto error;

    if ((vendor = x86DataToVendor(copy, map)) &&
        VIR_STRDUP(cpu->vendor, vendor->name) < 0)
        goto error;

    x86DataSubtract(copy, modelData);
    x86DataSubtract(modelData, data);

    /* because feature policy is ignored for host CPU */
    cpu->type = VIR_CPU_TYPE_GUEST;

    if (x86DataToCPUFeatures(cpu, VIR_CPU_FEATURE_REQUIRE, copy, map) ||
        x86DataToCPUFeatures(cpu, VIR_CPU_FEATURE_DISABLE, modelData, map))
        goto error;

 cleanup:
    virCPUx86DataFree(modelData);
    virCPUx86DataFree(copy);
    return cpu;

 error:
    virCPUDefFree(cpu);
    cpu = NULL;
    goto cleanup;
}


static void
x86VendorFree(virCPUx86VendorPtr vendor)
{
    if (!vendor)
        return;

    VIR_FREE(vendor->name);
    VIR_FREE(vendor);
}


static virCPUx86VendorPtr
x86VendorFind(virCPUx86MapPtr map,
              const char *name)
{
    size_t i;

    for (i = 0; i < map->nvendors; i++) {
        if (STREQ(map->vendors[i]->name, name))
            return map->vendors[i];
    }

    return NULL;
}


static virCPUx86VendorPtr
x86VendorParse(xmlXPathContextPtr ctxt,
               virCPUx86MapPtr map)
{
    virCPUx86VendorPtr vendor = NULL;
    char *string = NULL;

    if (VIR_ALLOC(vendor) < 0)
        goto error;

    vendor->name = virXPathString("string(@name)", ctxt);
    if (!vendor->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing CPU vendor name"));
        goto error;
    }

    if (x86VendorFind(map, vendor->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU vendor %s already defined"), vendor->name);
        goto error;
    }

    string = virXPathString("string(@string)", ctxt);
    if (!string) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing vendor string for CPU vendor %s"),
                       vendor->name);
        goto error;
    }
    if (strlen(string) != VENDOR_STRING_LENGTH) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid CPU vendor string '%s'"), string);
        goto error;
    }

    vendor->cpuid.function = 0;
    vendor->cpuid.ebx = virReadBufInt32LE(string);
    vendor->cpuid.edx = virReadBufInt32LE(string + 4);
    vendor->cpuid.ecx = virReadBufInt32LE(string + 8);

 cleanup:
    VIR_FREE(string);
    return vendor;

 error:
    x86VendorFree(vendor);
    vendor = NULL;
    goto cleanup;
}


static int
x86VendorsLoad(virCPUx86MapPtr map,
               xmlXPathContextPtr ctxt,
               xmlNodePtr *nodes,
               int n)
{
    virCPUx86VendorPtr vendor;
    size_t i;

    if (VIR_ALLOC_N(map->vendors, n) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];
        if (!(vendor = x86VendorParse(ctxt, map)))
            return -1;
        map->vendors[map->nvendors++] = vendor;
    }

    return 0;
}


static virCPUx86FeaturePtr
x86FeatureNew(void)
{
    virCPUx86FeaturePtr feature;

    if (VIR_ALLOC(feature) < 0)
        return NULL;

    if (VIR_ALLOC(feature->data) < 0) {
        VIR_FREE(feature);
        return NULL;
    }

    return feature;
}


static void
x86FeatureFree(virCPUx86FeaturePtr feature)
{
    if (!feature)
        return;

    VIR_FREE(feature->name);
    virCPUx86DataFree(feature->data);
    VIR_FREE(feature);
}


static virCPUx86FeaturePtr
x86FeatureFind(virCPUx86MapPtr map,
               const char *name)
{
    size_t i;

    for (i = 0; i < map->nfeatures; i++) {
        if (STREQ(map->features[i]->name, name))
            return map->features[i];
    }

    return NULL;
}


static char *
x86FeatureNames(virCPUx86MapPtr map,
                const char *separator,
                virCPUx86Data *data)
{
    virBuffer ret = VIR_BUFFER_INITIALIZER;
    bool first = true;
    size_t i;

    virBufferAdd(&ret, "", 0);

    for (i = 0; i < map->nfeatures; i++) {
        virCPUx86FeaturePtr feature = map->features[i];
        if (x86DataIsSubset(data, feature->data)) {
            if (!first)
                virBufferAdd(&ret, separator, -1);
            else
                first = false;

            virBufferAdd(&ret, feature->name, -1);
        }
    }

    return virBufferContentAndReset(&ret);
}


static int
x86ParseCPUID(xmlXPathContextPtr ctxt,
              virCPUx86CPUID *cpuid)
{
    unsigned long fun, eax, ebx, ecx, edx;
    int ret_fun, ret_eax, ret_ebx, ret_ecx, ret_edx;

    memset(cpuid, 0, sizeof(*cpuid));

    fun = eax = ebx = ecx = edx = 0;
    ret_fun = virXPathULongHex("string(@function)", ctxt, &fun);
    ret_eax = virXPathULongHex("string(@eax)", ctxt, &eax);
    ret_ebx = virXPathULongHex("string(@ebx)", ctxt, &ebx);
    ret_ecx = virXPathULongHex("string(@ecx)", ctxt, &ecx);
    ret_edx = virXPathULongHex("string(@edx)", ctxt, &edx);

    if (ret_fun < 0 || ret_eax == -2 || ret_ebx == -2
        || ret_ecx == -2 || ret_edx == -2)
        return -1;

    cpuid->function = fun;
    cpuid->eax = eax;
    cpuid->ebx = ebx;
    cpuid->ecx = ecx;
    cpuid->edx = edx;
    return 0;
}


static virCPUx86FeaturePtr
x86FeatureParse(xmlXPathContextPtr ctxt,
                virCPUx86MapPtr map)
{
    xmlNodePtr *nodes = NULL;
    virCPUx86FeaturePtr feature;
    virCPUx86CPUID cpuid;
    size_t i;
    int n;
    char *str = NULL;

    if (!(feature = x86FeatureNew()))
        goto error;

    feature->migratable = true;
    feature->name = virXPathString("string(@name)", ctxt);
    if (!feature->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Missing CPU feature name"));
        goto error;
    }

    if (x86FeatureFind(map, feature->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("CPU feature %s already defined"), feature->name);
        goto error;
    }

    str = virXPathString("string(@migratable)", ctxt);
    if (STREQ_NULLABLE(str, "no"))
        feature->migratable = false;

    n = virXPathNodeSet("./cpuid", ctxt, &nodes);
    if (n < 0)
        goto error;

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];
        if (x86ParseCPUID(ctxt, &cpuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid cpuid[%zu] in %s feature"),
                           i, feature->name);
            goto error;
        }
        if (virCPUx86DataAddCPUID(feature->data, &cpuid))
            goto error;
    }

 cleanup:
    VIR_FREE(nodes);
    VIR_FREE(str);
    return feature;

 error:
    x86FeatureFree(feature);
    feature = NULL;
    goto cleanup;
}


static int
x86FeaturesLoad(virCPUx86MapPtr map,
                xmlXPathContextPtr ctxt,
                xmlNodePtr *nodes,
                int n)
{
    virCPUx86FeaturePtr feature;
    size_t i;

    if (VIR_ALLOC_N(map->features, n) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];
        if (!(feature = x86FeatureParse(ctxt, map)))
            return -1;
        map->features[map->nfeatures++] = feature;
        if (!feature->migratable &&
            VIR_APPEND_ELEMENT(map->migrate_blockers,
                               map->nblockers,
                               feature) < 0)
            return -1;
    }

    return 0;
}

static virCPUx86Data *
x86DataFromCPUFeatures(virCPUDefPtr cpu,
                       virCPUx86MapPtr map)
{
    virCPUx86Data *data;
    size_t i;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    for (i = 0; i < cpu->nfeatures; i++) {
        virCPUx86FeaturePtr feature;
        if (!(feature = x86FeatureFind(map, cpu->features[i].name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown CPU feature %s"), cpu->features[i].name);
            goto error;
        }

        if (x86DataAdd(data, feature->data) < 0)
            goto error;
    }

    return data;

 error:
    virCPUx86DataFree(data);
    return NULL;
}


static virCPUx86ModelPtr
x86ModelNew(void)
{
    virCPUx86ModelPtr model;

    if (VIR_ALLOC(model) < 0)
        return NULL;

    if (VIR_ALLOC(model->data) < 0) {
        VIR_FREE(model);
        return NULL;
    }

    return model;
}


static void
x86ModelFree(virCPUx86ModelPtr model)
{
    if (!model)
        return;

    VIR_FREE(model->name);
    virCPUx86DataFree(model->data);
    VIR_FREE(model);
}


static virCPUx86ModelPtr
x86ModelCopy(virCPUx86ModelPtr model)
{
    virCPUx86ModelPtr copy;

    if (VIR_ALLOC(copy) < 0 ||
        VIR_STRDUP(copy->name, model->name) < 0 ||
        !(copy->data = x86DataCopy(model->data))) {
        x86ModelFree(copy);
        return NULL;
    }

    copy->vendor = model->vendor;

    return copy;
}


static virCPUx86ModelPtr
x86ModelFind(virCPUx86MapPtr map,
             const char *name)
{
    size_t i;

    for (i = 0; i < map->nmodels; i++) {
        if (STREQ(map->models[i]->name, name))
            return map->models[i];
    }

    return NULL;
}


static virCPUx86ModelPtr
x86ModelFromCPU(const virCPUDef *cpu,
                virCPUx86MapPtr map,
                int policy)
{
    virCPUx86ModelPtr model = NULL;
    size_t i;

    if (policy == VIR_CPU_FEATURE_REQUIRE) {
        if (!(model = x86ModelFind(map, cpu->model))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown CPU model %s"), cpu->model);
            goto error;
        }

        if (!(model = x86ModelCopy(model)))
            goto error;
    } else if (!(model = x86ModelNew())) {
        goto error;
    } else if (cpu->type == VIR_CPU_TYPE_HOST) {
        return model;
    }

    for (i = 0; i < cpu->nfeatures; i++) {
        virCPUx86FeaturePtr feature;

        if (cpu->type == VIR_CPU_TYPE_GUEST
            && cpu->features[i].policy != policy)
            continue;

        if (!(feature = x86FeatureFind(map, cpu->features[i].name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown CPU feature %s"), cpu->features[i].name);
            goto error;
        }

        if (x86DataAdd(model->data, feature->data))
            goto error;
    }

    return model;

 error:
    x86ModelFree(model);
    return NULL;
}


static int
x86ModelSubtractCPU(virCPUx86ModelPtr model,
                    const virCPUDef *cpu,
                    virCPUx86MapPtr map)
{
    virCPUx86ModelPtr cpu_model;
    size_t i;

    if (!(cpu_model = x86ModelFind(map, cpu->model))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown CPU model %s"),
                       cpu->model);
        return -1;
    }

    x86DataSubtract(model->data, cpu_model->data);

    for (i = 0; i < cpu->nfeatures; i++) {
        virCPUx86FeaturePtr feature;

        if (!(feature = x86FeatureFind(map, cpu->features[i].name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown CPU feature %s"),
                           cpu->features[i].name);
            return -1;
        }

        x86DataSubtract(model->data, feature->data);
    }

    return 0;
}


static virCPUx86CompareResult
x86ModelCompare(virCPUx86ModelPtr model1,
                virCPUx86ModelPtr model2)
{
    virCPUx86CompareResult result = EQUAL;
    virCPUx86DataIterator iter1 = virCPUx86DataIteratorInit(model1->data);
    virCPUx86DataIterator iter2 = virCPUx86DataIteratorInit(model2->data);
    virCPUx86CPUID *cpuid1;
    virCPUx86CPUID *cpuid2;

    while ((cpuid1 = x86DataCpuidNext(&iter1))) {
        virCPUx86CompareResult match = SUPERSET;

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
        virCPUx86CompareResult match = SUBSET;

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


static virCPUx86ModelPtr
x86ModelParse(xmlXPathContextPtr ctxt,
              virCPUx86MapPtr map)
{
    xmlNodePtr *nodes = NULL;
    virCPUx86ModelPtr model;
    char *vendor = NULL;
    size_t i;
    int n;

    if (!(model = x86ModelNew()))
        goto error;

    model->name = virXPathString("string(@name)", ctxt);
    if (!model->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Missing CPU model name"));
        goto error;
    }

    if (virXPathNode("./model", ctxt)) {
        virCPUx86ModelPtr ancestor;
        char *name;

        name = virXPathString("string(./model/@name)", ctxt);
        if (!name) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing ancestor's name in CPU model %s"),
                           model->name);
            goto error;
        }

        if (!(ancestor = x86ModelFind(map, name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Ancestor model %s not found for CPU model %s"),
                           name, model->name);
            VIR_FREE(name);
            goto error;
        }

        VIR_FREE(name);

        model->vendor = ancestor->vendor;
        virCPUx86DataFree(model->data);
        if (!(model->data = x86DataCopy(ancestor->data)))
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

        if (!(model->vendor = x86VendorFind(map, vendor))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown vendor %s referenced by CPU model %s"),
                           vendor, model->name);
            goto error;
        }
    }

    n = virXPathNodeSet("./feature", ctxt, &nodes);
    if (n < 0)
        goto error;

    for (i = 0; i < n; i++) {
        virCPUx86FeaturePtr feature;
        char *name;

        if (!(name = virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing feature name for CPU model %s"), model->name);
            goto error;
        }

        if (!(feature = x86FeatureFind(map, name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Feature %s required by CPU model %s not found"),
                           name, model->name);
            VIR_FREE(name);
            goto error;
        }
        VIR_FREE(name);

        if (x86DataAdd(model->data, feature->data))
            goto error;
    }

 cleanup:
    VIR_FREE(vendor);
    VIR_FREE(nodes);
    return model;

 error:
    x86ModelFree(model);
    model = NULL;
    goto cleanup;
}


static int
x86ModelsLoad(virCPUx86MapPtr map,
              xmlXPathContextPtr ctxt,
              xmlNodePtr *nodes,
              int n)
{
    virCPUx86ModelPtr model;
    size_t i;

    if (VIR_ALLOC_N(map->models, n) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];
        if (!(model = x86ModelParse(ctxt, map)))
            return -1;
        map->models[map->nmodels++] = model;
    }

    return 0;
}


static void
x86MapFree(virCPUx86MapPtr map)
{
    size_t i;

    if (!map)
        return;

    for (i = 0; i < map->nfeatures; i++)
        x86FeatureFree(map->features[i]);
    VIR_FREE(map->features);

    for (i = 0; i < map->nmodels; i++)
        x86ModelFree(map->models[i]);
    VIR_FREE(map->models);

    for (i = 0; i < map->nvendors; i++)
        x86VendorFree(map->vendors[i]);
    VIR_FREE(map->vendors);

    /* migrate_blockers only points to the features from map->features list,
     * which were already freed above
     */
    VIR_FREE(map->migrate_blockers);

    VIR_FREE(map);
}


static int
x86MapLoadCallback(cpuMapElement element,
                   xmlXPathContextPtr ctxt,
                   xmlNodePtr *nodes,
                   int n,
                   void *data)
{
    virCPUx86MapPtr map = data;

    switch (element) {
    case CPU_MAP_ELEMENT_VENDOR:
        return x86VendorsLoad(map, ctxt, nodes, n);
    case CPU_MAP_ELEMENT_FEATURE:
        return x86FeaturesLoad(map, ctxt, nodes, n);
    case CPU_MAP_ELEMENT_MODEL:
        return x86ModelsLoad(map, ctxt, nodes, n);
    case CPU_MAP_ELEMENT_LAST:
        break;
    }

    return 0;
}


static int
x86MapLoadInternalFeatures(virCPUx86MapPtr map)
{
    size_t i;
    virCPUx86FeaturePtr feature = NULL;
    size_t nfeatures = map->nfeatures;
    size_t count = ARRAY_CARDINALITY(x86_kvm_features);

    if (VIR_EXPAND_N(map->features, nfeatures, count) < 0)
        goto error;

    for (i = 0; i < count; i++) {
        const char *name = x86_kvm_features[i].name;

        if (x86FeatureFind(map, name)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("CPU feature %s already defined"), name);
            goto error;
        }

        if (!(feature = x86FeatureNew()))
            goto error;

        if (VIR_STRDUP(feature->name, name) < 0)
            goto error;

        if (virCPUx86DataAddCPUID(feature->data, &x86_kvm_features[i].cpuid))
            goto error;

        map->features[map->nfeatures++] = feature;
        feature = NULL;
    }

    return 0;

 error:
    x86FeatureFree(feature);
    return -1;
}


static virCPUx86MapPtr
virCPUx86LoadMap(void)
{
    virCPUx86MapPtr map;

    if (VIR_ALLOC(map) < 0)
        return NULL;

    if (cpuMapLoad("x86", x86MapLoadCallback, map) < 0)
        goto error;

    if (x86MapLoadInternalFeatures(map) < 0)
        goto error;

    return map;

 error:
    x86MapFree(map);
    return NULL;
}


int
virCPUx86MapOnceInit(void)
{
    if (!(cpuMap = virCPUx86LoadMap()))
        return -1;

    return 0;
}


static virCPUx86MapPtr
virCPUx86GetMap(void)
{
    if (virCPUx86MapInitialize() < 0)
        return NULL;

    return cpuMap;
}


static char *
x86CPUDataFormat(const virCPUData *data)
{
    virCPUx86DataIterator iter = virCPUx86DataIteratorInit(data->data.x86);
    virCPUx86CPUID *cpuid;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "<cpudata arch='x86'>\n");
    while ((cpuid = x86DataCpuidNext(&iter))) {
        virBufferAsprintf(&buf,
                          "  <cpuid function='0x%08x'"
                          " eax='0x%08x' ebx='0x%08x'"
                          " ecx='0x%08x' edx='0x%08x'/>\n",
                          cpuid->function,
                          cpuid->eax, cpuid->ebx, cpuid->ecx, cpuid->edx);
    }
    virBufferAddLit(&buf, "</cpudata>\n");

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


static virCPUDataPtr
x86CPUDataParse(const char *xmlStr)
{
    xmlDocPtr xml = NULL;
    xmlXPathContextPtr ctxt = NULL;
    xmlNodePtr *nodes = NULL;
    virCPUDataPtr cpuData = NULL;
    virCPUx86Data *data = NULL;
    virCPUx86CPUID cpuid;
    size_t i;
    int n;

    if (VIR_ALLOC(data) < 0)
        goto cleanup;

    if (!(xml = virXMLParseStringCtxt(xmlStr, _("CPU data"), &ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot parse CPU data"));
        goto cleanup;
    }
    ctxt->node = xmlDocGetRootElement(xml);

    n = virXPathNodeSet("/cpudata[@arch='x86']/data", ctxt, &nodes);
    if (n < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no x86 CPU data found"));
        goto cleanup;
    }

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];
        if (x86ParseCPUID(ctxt, &cpuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse cpuid[%zu]"), i);
            goto cleanup;
        }
        if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
            goto cleanup;
    }

    cpuData = virCPUx86MakeData(VIR_ARCH_X86_64, &data);

 cleanup:
    VIR_FREE(nodes);
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(xml);
    virCPUx86DataFree(data);
    return cpuData;
}


/* A helper macro to exit the cpu computation function without writing
 * redundant code:
 * MSG: error message
 * CPU_DEF: a virCPUx86Data pointer with flags that are conflicting
 * RET: return code to set
 *
 * This macro generates the error string outputs it into logs.
 */
#define virX86CpuIncompatible(MSG, CPU_DEF)                             \
        do {                                                            \
            char *flagsStr = NULL;                                      \
            if (!(flagsStr = x86FeatureNames(map, ", ", (CPU_DEF)))) {  \
                virReportOOMError();                                    \
                goto error;                                             \
            }                                                           \
            if (message &&                                              \
                virAsprintf(message, "%s: %s", _(MSG), flagsStr) < 0) { \
                VIR_FREE(flagsStr);                                     \
                goto error;                                             \
            }                                                           \
            VIR_DEBUG("%s: %s", MSG, flagsStr);                         \
            VIR_FREE(flagsStr);                                         \
            ret = VIR_CPU_COMPARE_INCOMPATIBLE;                         \
        } while (0)


static virCPUCompareResult
x86Compute(virCPUDefPtr host,
           virCPUDefPtr cpu,
           virCPUDataPtr *guest,
           char **message)
{
    virCPUx86MapPtr map = NULL;
    virCPUx86ModelPtr host_model = NULL;
    virCPUx86ModelPtr cpu_force = NULL;
    virCPUx86ModelPtr cpu_require = NULL;
    virCPUx86ModelPtr cpu_optional = NULL;
    virCPUx86ModelPtr cpu_disable = NULL;
    virCPUx86ModelPtr cpu_forbid = NULL;
    virCPUx86ModelPtr diff = NULL;
    virCPUx86ModelPtr guest_model = NULL;
    virCPUCompareResult ret;
    virCPUx86CompareResult result;
    virArch arch;
    size_t i;

    if (!cpu->model) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("no guest CPU model specified"));
        return VIR_CPU_COMPARE_ERROR;
    }

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
                goto error;
            return VIR_CPU_COMPARE_INCOMPATIBLE;
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
            goto error;

        return VIR_CPU_COMPARE_INCOMPATIBLE;
    }

    if (!(map = virCPUx86GetMap()) ||
        !(host_model = x86ModelFromCPU(host, map, VIR_CPU_FEATURE_REQUIRE)) ||
        !(cpu_force = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_FORCE)) ||
        !(cpu_require = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_REQUIRE)) ||
        !(cpu_optional = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_OPTIONAL)) ||
        !(cpu_disable = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_DISABLE)) ||
        !(cpu_forbid = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_FORBID)))
        goto error;

    x86DataIntersect(cpu_forbid->data, host_model->data);
    if (!x86DataIsEmpty(cpu_forbid->data)) {
        virX86CpuIncompatible(N_("Host CPU provides forbidden features"),
                              cpu_forbid->data);
        goto cleanup;
    }

    /* first remove features that were inherited from the CPU model and were
     * explicitly forced, disabled, or made optional
     */
    x86DataSubtract(cpu_require->data, cpu_force->data);
    x86DataSubtract(cpu_require->data, cpu_optional->data);
    x86DataSubtract(cpu_require->data, cpu_disable->data);
    result = x86ModelCompare(host_model, cpu_require);
    if (result == SUBSET || result == UNRELATED) {
        x86DataSubtract(cpu_require->data, host_model->data);
        virX86CpuIncompatible(N_("Host CPU does not provide required "
                                 "features"),
                              cpu_require->data);
        goto cleanup;
    }

    ret = VIR_CPU_COMPARE_IDENTICAL;

    if (!(diff = x86ModelCopy(host_model)))
        goto error;

    x86DataSubtract(diff->data, cpu_optional->data);
    x86DataSubtract(diff->data, cpu_require->data);
    x86DataSubtract(diff->data, cpu_disable->data);
    x86DataSubtract(diff->data, cpu_force->data);

    if (!x86DataIsEmpty(diff->data))
        ret = VIR_CPU_COMPARE_SUPERSET;

    if (ret == VIR_CPU_COMPARE_SUPERSET
        && cpu->type == VIR_CPU_TYPE_GUEST
        && cpu->match == VIR_CPU_MATCH_STRICT) {
        virX86CpuIncompatible(N_("Host CPU does not strictly match guest CPU: "
                                 "Extra features"),
                              diff->data);
        goto cleanup;
    }

    if (guest) {
        virCPUx86Data *guestData;

        if (!(guest_model = x86ModelCopy(host_model)))
            goto error;

        if (cpu->type == VIR_CPU_TYPE_GUEST
            && cpu->match == VIR_CPU_MATCH_EXACT)
            x86DataSubtract(guest_model->data, diff->data);

        if (x86DataAdd(guest_model->data, cpu_force->data))
            goto error;

        x86DataSubtract(guest_model->data, cpu_disable->data);

        if (!(guestData = x86DataCopy(guest_model->data)) ||
            !(*guest = virCPUx86MakeData(arch, &guestData))) {
            virCPUx86DataFree(guestData);
            goto error;
        }
    }

 cleanup:
    x86ModelFree(host_model);
    x86ModelFree(diff);
    x86ModelFree(cpu_force);
    x86ModelFree(cpu_require);
    x86ModelFree(cpu_optional);
    x86ModelFree(cpu_disable);
    x86ModelFree(cpu_forbid);
    x86ModelFree(guest_model);

    return ret;

 error:
    ret = VIR_CPU_COMPARE_ERROR;
    goto cleanup;
}
#undef virX86CpuIncompatible


static virCPUCompareResult
x86Compare(virCPUDefPtr host,
           virCPUDefPtr cpu,
           bool failIncompatible)
{
    virCPUCompareResult ret;
    char *message = NULL;

    ret = x86Compute(host, cpu, NULL, &message);

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


static virCPUCompareResult
x86GuestData(virCPUDefPtr host,
             virCPUDefPtr guest,
             virCPUDataPtr *data,
             char **message)
{
    return x86Compute(host, guest, data, message);
}


/*
 * Checks whether cpuCandidate is a better fit for the CPU data than the
 * currently selected one from cpuCurrent.
 *
 * Returns 0 if cpuCurrent is better,
 *         1 if cpuCandidate is better,
 *         2 if cpuCandidate is the best one (search should stop now).
 */
static int
x86DecodeUseCandidate(virCPUDefPtr cpuCurrent,
                      virCPUDefPtr cpuCandidate,
                      const char *preferred,
                      bool checkPolicy)
{
    if (checkPolicy) {
        size_t i;
        for (i = 0; i < cpuCandidate->nfeatures; i++) {
            if (cpuCandidate->features[i].policy == VIR_CPU_FEATURE_DISABLE)
                return 0;
            cpuCandidate->features[i].policy = -1;
        }
    }

    if (preferred &&
        STREQ(cpuCandidate->model, preferred))
        return 2;

    if (!cpuCurrent)
        return 1;

    if (cpuCurrent->nfeatures > cpuCandidate->nfeatures)
        return 1;

    return 0;
}


static int
x86Decode(virCPUDefPtr cpu,
          const virCPUx86Data *data,
          const char **models,
          unsigned int nmodels,
          const char *preferred,
          unsigned int flags)
{
    int ret = -1;
    virCPUx86MapPtr map;
    virCPUx86ModelPtr candidate;
    virCPUDefPtr cpuCandidate;
    virCPUDefPtr cpuModel = NULL;
    virCPUx86Data *copy = NULL;
    virCPUx86Data *features = NULL;
    const virCPUx86Data *cpuData = NULL;
    virCPUx86VendorPtr vendor;
    ssize_t i;
    int rc;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES |
                  VIR_CONNECT_BASELINE_CPU_MIGRATABLE, -1);

    if (!data || !(map = virCPUx86GetMap()))
        return -1;

    vendor = x86DataToVendor(data, map);

    /* Walk through the CPU models in reverse order to check newest
     * models first.
     */
    for (i = map->nmodels - 1; i >= 0; i--) {
        candidate = map->models[i];
        if (!cpuModelIsAllowed(candidate->name, models, nmodels)) {
            if (preferred && STREQ(candidate->name, preferred)) {
                if (cpu->fallback != VIR_CPU_FALLBACK_ALLOW) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("CPU model %s is not supported by hypervisor"),
                                   preferred);
                    goto cleanup;
                } else {
                    VIR_WARN("Preferred CPU model %s not allowed by"
                             " hypervisor; closest supported model will be"
                             " used", preferred);
                }
            } else {
                VIR_DEBUG("CPU model %s not allowed by hypervisor; ignoring",
                          candidate->name);
            }
            continue;
        }

        /* Both vendor and candidate->vendor are pointers to a single list of
         * known vendors stored in the map.
         */
        if (vendor && candidate->vendor && vendor != candidate->vendor) {
            VIR_DEBUG("CPU vendor %s of model %s differs from %s; ignoring",
                      candidate->vendor->name, candidate->name, vendor->name);
            continue;
        }

        if (!(cpuCandidate = x86DataToCPU(data, candidate, map)))
            goto cleanup;
        cpuCandidate->type = cpu->type;

        if ((rc = x86DecodeUseCandidate(cpuModel, cpuCandidate, preferred,
                                        cpu->type == VIR_CPU_TYPE_HOST))) {
            virCPUDefFree(cpuModel);
            cpuModel = cpuCandidate;
            cpuData = candidate->data;
            if (rc == 2)
                break;
        } else {
            virCPUDefFree(cpuCandidate);
        }
    }

    if (!cpuModel) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Cannot find suitable CPU model for given data"));
        goto cleanup;
    }

    /* Remove non-migratable features if requested
     * Note: this only works as long as no CPU model contains non-migratable
     * features directly */
    if (flags & VIR_CONNECT_BASELINE_CPU_MIGRATABLE) {
        for (i = 0; i < cpuModel->nfeatures; i++) {
            size_t j;
            for (j = 0; j < map->nblockers; j++) {
                if (STREQ(map->migrate_blockers[j]->name,
                          cpuModel->features[i].name)) {
                    VIR_FREE(cpuModel->features[i].name);
                    VIR_DELETE_ELEMENT_INPLACE(cpuModel->features, i,
                                               cpuModel->nfeatures);
                }
            }
        }
    }

    if (flags & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES) {
        if (!(copy = x86DataCopy(cpuData)) ||
            !(features = x86DataFromCPUFeatures(cpuModel, map)))
            goto cleanup;

        x86DataSubtract(copy, features);
        if (x86DataToCPUFeatures(cpuModel, VIR_CPU_FEATURE_REQUIRE,
                                 copy, map) < 0)
            goto cleanup;
    }

    if (vendor && VIR_STRDUP(cpu->vendor, vendor->name) < 0)
        goto cleanup;

    cpu->model = cpuModel->model;
    cpu->nfeatures = cpuModel->nfeatures;
    cpu->features = cpuModel->features;
    VIR_FREE(cpuModel);

    ret = 0;

 cleanup:
    virCPUDefFree(cpuModel);
    virCPUx86DataFree(copy);
    virCPUx86DataFree(features);
    return ret;
}

static int
x86DecodeCPUData(virCPUDefPtr cpu,
                 const virCPUData *data,
                 const char **models,
                 unsigned int nmodels,
                 const char *preferred,
                 unsigned int flags)
{
    return x86Decode(cpu, data->data.x86, models, nmodels, preferred, flags);
}


static virCPUx86Data *
x86EncodePolicy(const virCPUDef *cpu,
                virCPUx86MapPtr map,
                virCPUFeaturePolicy policy)
{
    virCPUx86ModelPtr model;
    virCPUx86Data *data = NULL;

    if (!(model = x86ModelFromCPU(cpu, map, policy)))
        return NULL;

    data = model->data;
    model->data = NULL;
    x86ModelFree(model);

    return data;
}


static int
x86Encode(virArch arch,
          const virCPUDef *cpu,
          virCPUDataPtr *forced,
          virCPUDataPtr *required,
          virCPUDataPtr *optional,
          virCPUDataPtr *disabled,
          virCPUDataPtr *forbidden,
          virCPUDataPtr *vendor)
{
    virCPUx86MapPtr map = NULL;
    virCPUx86Data *data_forced = NULL;
    virCPUx86Data *data_required = NULL;
    virCPUx86Data *data_optional = NULL;
    virCPUx86Data *data_disabled = NULL;
    virCPUx86Data *data_forbidden = NULL;
    virCPUx86Data *data_vendor = NULL;

    if (forced)
        *forced = NULL;
    if (required)
        *required = NULL;
    if (optional)
        *optional = NULL;
    if (disabled)
        *disabled = NULL;
    if (forbidden)
        *forbidden = NULL;
    if (vendor)
        *vendor = NULL;

    if (!(map = virCPUx86GetMap()))
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
        virCPUx86VendorPtr v = NULL;

        if (cpu->vendor && !(v = x86VendorFind(map, cpu->vendor))) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("CPU vendor %s not found"), cpu->vendor);
            goto error;
        }

        if (v &&
            (VIR_ALLOC(data_vendor) < 0 ||
             virCPUx86DataAddCPUID(data_vendor, &v->cpuid) < 0)) {
            goto error;
        }
    }

    if (forced &&
        !(*forced = virCPUx86MakeData(arch, &data_forced)))
        goto error;
    if (required &&
        !(*required = virCPUx86MakeData(arch, &data_required)))
        goto error;
    if (optional &&
        !(*optional = virCPUx86MakeData(arch, &data_optional)))
        goto error;
    if (disabled &&
        !(*disabled = virCPUx86MakeData(arch, &data_disabled)))
        goto error;
    if (forbidden &&
        !(*forbidden = virCPUx86MakeData(arch, &data_forbidden)))
        goto error;
    if (vendor &&
        !(*vendor = virCPUx86MakeData(arch, &data_vendor)))
        goto error;

    return 0;

 error:
    virCPUx86DataFree(data_forced);
    virCPUx86DataFree(data_required);
    virCPUx86DataFree(data_optional);
    virCPUx86DataFree(data_disabled);
    virCPUx86DataFree(data_forbidden);
    virCPUx86DataFree(data_vendor);
    if (forced)
        x86FreeCPUData(*forced);
    if (required)
        x86FreeCPUData(*required);
    if (optional)
        x86FreeCPUData(*optional);
    if (disabled)
        x86FreeCPUData(*disabled);
    if (forbidden)
        x86FreeCPUData(*forbidden);
    if (vendor)
        x86FreeCPUData(*vendor);
    return -1;
}


#if HAVE_CPUID
static inline void
cpuidCall(virCPUx86CPUID *cpuid)
{
# if __x86_64__
    asm("xor %%ebx, %%ebx;" /* clear the other registers as some cpuid */
        "xor %%ecx, %%ecx;" /* functions may use them as additional */
        "xor %%edx, %%edx;" /* arguments */
        "cpuid;"
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
        "xor %%ebx, %%ebx;" /* clear the other registers as some cpuid */
        "xor %%ecx, %%ecx;" /* functions may use them as additional */
        "xor %%edx, %%edx;" /* arguments */
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
cpuidSet(uint32_t base, virCPUx86Data *data)
{
    uint32_t max;
    uint32_t i;
    virCPUx86CPUID cpuid = { base, 0, 0, 0, 0 };

    cpuidCall(&cpuid);
    max = cpuid.eax;

    for (i = base; i <= max; i++) {
        cpuid.function = i;
        cpuidCall(&cpuid);
        if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
            return -1;
    }

    return 0;
}


static virCPUDataPtr
x86NodeData(virArch arch)
{
    virCPUDataPtr cpuData = NULL;
    virCPUx86Data *data;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    if (cpuidSet(CPUX86_BASIC, data) < 0)
        goto error;

    if (cpuidSet(CPUX86_EXTENDED, data) < 0)
        goto error;

    if (!(cpuData = virCPUx86MakeData(arch, &data)))
        goto error;

    return cpuData;

 error:
    virCPUx86DataFree(data);

    return NULL;
}
#endif


static virCPUDefPtr
x86Baseline(virCPUDefPtr *cpus,
            unsigned int ncpus,
            const char **models,
            unsigned int nmodels,
            unsigned int flags)
{
    virCPUx86MapPtr map = NULL;
    virCPUx86ModelPtr base_model = NULL;
    virCPUDefPtr cpu = NULL;
    size_t i;
    virCPUx86VendorPtr vendor = NULL;
    virCPUx86ModelPtr model = NULL;
    bool outputVendor = true;
    const char *modelName;
    bool matchingNames = true;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES |
                  VIR_CONNECT_BASELINE_CPU_MIGRATABLE, NULL);

    if (!(map = virCPUx86GetMap()))
        goto error;

    if (!(base_model = x86ModelFromCPU(cpus[0], map, VIR_CPU_FEATURE_REQUIRE)))
        goto error;

    if (VIR_ALLOC(cpu) < 0)
        goto error;

    cpu->arch = cpus[0]->arch;
    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;

    if (!cpus[0]->vendor) {
        outputVendor = false;
    } else if (!(vendor = x86VendorFind(map, cpus[0]->vendor))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Unknown CPU vendor %s"), cpus[0]->vendor);
        goto error;
    }

    modelName = cpus[0]->model;
    for (i = 1; i < ncpus; i++) {
        const char *vn = NULL;

        if (matchingNames && cpus[i]->model) {
            if (!modelName) {
                modelName = cpus[i]->model;
            } else if (STRNEQ(modelName, cpus[i]->model)) {
                modelName = NULL;
                matchingNames = false;
            }
        }

        if (!(model = x86ModelFromCPU(cpus[i], map, VIR_CPU_FEATURE_REQUIRE)))
            goto error;

        if (cpus[i]->vendor && model->vendor &&
            STRNEQ(cpus[i]->vendor, model->vendor->name)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("CPU vendor %s of model %s differs from vendor %s"),
                           model->vendor->name, model->name, cpus[i]->vendor);
            goto error;
        }

        if (cpus[i]->vendor) {
            vn = cpus[i]->vendor;
        } else {
            outputVendor = false;
            if (model->vendor)
                vn = model->vendor->name;
        }

        if (vn) {
            if (!vendor) {
                if (!(vendor = x86VendorFind(map, vn))) {
                    virReportError(VIR_ERR_OPERATION_FAILED,
                                   _("Unknown CPU vendor %s"), vn);
                    goto error;
                }
            } else if (STRNEQ(vendor->name, vn)) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               "%s", _("CPU vendors do not match"));
                goto error;
            }
        }

        x86DataIntersect(base_model->data, model->data);
        x86ModelFree(model);
        model = NULL;
    }

    if (x86DataIsEmpty(base_model->data)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("CPUs are incompatible"));
        goto error;
    }

    if (vendor && virCPUx86DataAddCPUID(base_model->data, &vendor->cpuid) < 0)
        goto error;

    if (x86Decode(cpu, base_model->data, models, nmodels, modelName, flags) < 0)
        goto error;

    if (STREQ_NULLABLE(cpu->model, modelName))
        cpu->fallback = VIR_CPU_FALLBACK_FORBID;

    if (!outputVendor)
        VIR_FREE(cpu->vendor);

    cpu->arch = VIR_ARCH_NONE;

 cleanup:
    x86ModelFree(base_model);

    return cpu;

 error:
    x86ModelFree(model);
    virCPUDefFree(cpu);
    cpu = NULL;
    goto cleanup;
}


static int
x86UpdateCustom(virCPUDefPtr guest,
                const virCPUDef *host)
{
    int ret = -1;
    size_t i;
    virCPUx86MapPtr map;
    virCPUx86ModelPtr host_model = NULL;

    if (!(map = virCPUx86GetMap()) ||
        !(host_model = x86ModelFromCPU(host, map, VIR_CPU_FEATURE_REQUIRE)))
        goto cleanup;

    for (i = 0; i < guest->nfeatures; i++) {
        if (guest->features[i].policy == VIR_CPU_FEATURE_OPTIONAL) {
            virCPUx86FeaturePtr feature;
            if (!(feature = x86FeatureFind(map, guest->features[i].name))) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
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
        if (x86ModelSubtractCPU(host_model, guest, map) ||
            x86DataToCPUFeatures(guest, VIR_CPU_FEATURE_REQUIRE,
                                 host_model->data, map))
            goto cleanup;
    }

    ret = 0;

 cleanup:
    x86ModelFree(host_model);
    return ret;
}


static int
x86UpdateHostModel(virCPUDefPtr guest,
                   const virCPUDef *host,
                   bool passthrough)
{
    virCPUDefPtr oldguest = NULL;
    virCPUx86MapPtr map;
    size_t i;
    int ret = -1;

    if (!(map = virCPUx86GetMap()))
        goto cleanup;

    /* update the host model according to the desired configuration */
    if (!(oldguest = virCPUDefCopy(guest)))
        goto cleanup;

    virCPUDefFreeModel(guest);
    if (virCPUDefCopyModel(guest, host, true) < 0)
        goto cleanup;

    if (oldguest->vendor_id) {
        VIR_FREE(guest->vendor_id);
        if (VIR_STRDUP(guest->vendor_id, oldguest->vendor_id) < 0)
            goto cleanup;
    }

    /* Remove non-migratable features by default
     * Note: this only works as long as no CPU model contains non-migratable
     * features directly */
    for (i = 0; i < guest->nfeatures; i++) {
        size_t j;
        for (j = 0; j < map->nblockers; j++) {
            if (STREQ(map->migrate_blockers[j]->name, guest->features[i].name)) {
                VIR_FREE(guest->features[i].name);
                VIR_DELETE_ELEMENT_INPLACE(guest->features, i, guest->nfeatures);
            }
        }
    }
    for (i = 0; !passthrough && i < oldguest->nfeatures; i++) {
        if (virCPUDefUpdateFeature(guest,
                                   oldguest->features[i].name,
                                   oldguest->features[i].policy) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virCPUDefFree(oldguest);
    return ret;
}


static int
x86Update(virCPUDefPtr guest,
          const virCPUDef *host)
{
    switch ((virCPUMode) guest->mode) {
    case VIR_CPU_MODE_CUSTOM:
        return x86UpdateCustom(guest, host);

    case VIR_CPU_MODE_HOST_MODEL:
        guest->match = VIR_CPU_MATCH_EXACT;
        return x86UpdateHostModel(guest, host, false);

    case VIR_CPU_MODE_HOST_PASSTHROUGH:
        guest->match = VIR_CPU_MATCH_MINIMUM;
        return x86UpdateHostModel(guest, host, true);

    case VIR_CPU_MODE_LAST:
        break;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unexpected CPU mode: %d"), guest->mode);
    return -1;
}


static int
x86HasFeature(const virCPUData *data,
              const char *name)
{
    virCPUx86MapPtr map;
    virCPUx86FeaturePtr feature;
    int ret = -1;

    if (!(map = virCPUx86GetMap()))
        return -1;

    if (!(feature = x86FeatureFind(map, name)))
        goto cleanup;

    ret = x86DataIsSubset(data->data.x86, feature->data) ? 1 : 0;

 cleanup:
    return ret;
}

static int
x86GetModels(char ***models)
{
    virCPUx86MapPtr map;
    size_t i;

    if (!(map = virCPUx86GetMap()))
        return -1;

    if (models) {
        if (VIR_ALLOC_N(*models, map->nmodels + 1) < 0)
            goto error;

        for (i = 0; i < map->nmodels; i++) {
            if (VIR_STRDUP((*models)[i], map->models[i]->name) < 0)
                goto error;
        }
    }

    return map->nmodels;

 error:
    if (models) {
        virStringFreeList(*models);
        *models = NULL;
    }
    return -1;
}


struct cpuArchDriver cpuDriverX86 = {
    .name = "x86",
    .arch = archs,
    .narch = ARRAY_CARDINALITY(archs),
    .compare    = x86Compare,
    .decode     = x86DecodeCPUData,
    .encode     = x86Encode,
    .free       = x86FreeCPUData,
#if HAVE_CPUID
    .nodeData   = x86NodeData,
#else
    .nodeData   = NULL,
#endif
    .guestData  = x86GuestData,
    .baseline   = x86Baseline,
    .update     = x86Update,
    .hasFeature = x86HasFeature,
    .dataFormat = x86CPUDataFormat,
    .dataParse  = x86CPUDataParse,
    .getModels  = x86GetModels,
};
