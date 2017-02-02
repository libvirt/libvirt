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

static const virCPUx86CPUID cpuidNull = { 0 };

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
    virCPUx86Data data;
    bool migratable;
};


#define KVM_FEATURE_DEF(Name, Eax_in, Eax)                          \
    static virCPUx86CPUID Name ## _cpuid[] = {                      \
        { .eax_in = Eax_in, .eax = Eax },                           \
    }

#define KVM_FEATURE(Name)                                           \
    {                                                               \
        .name = (char *) Name,                                      \
        .data = {                                                   \
            .len = ARRAY_CARDINALITY(Name ## _cpuid),               \
            .data = Name ## _cpuid                                  \
        }                                                           \
    }

KVM_FEATURE_DEF(VIR_CPU_x86_KVM_CLOCKSOURCE,
                0x40000001, 0x00000001);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_NOP_IO_DELAY,
                0x40000001, 0x00000002);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_MMU_OP,
                0x40000001, 0x00000004);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_CLOCKSOURCE2,
                0x40000001, 0x00000008);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_ASYNC_PF,
                0x40000001, 0x00000010);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_STEAL_TIME,
                0x40000001, 0x00000020);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_PV_EOI,
                0x40000001, 0x00000040);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_PV_UNHALT,
                0x40000001, 0x00000080);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_CLOCKSOURCE_STABLE_BIT,
                0x40000001, 0x01000000);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_HV_RUNTIME,
                0x40000003, 0x00000001);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_HV_SYNIC,
                0x40000003, 0x00000004);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_HV_STIMER,
                0x40000003, 0x00000008);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_HV_RELAXED,
                0x40000003, 0x00000020);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_HV_SPINLOCKS,
                0x40000003, 0x00000022);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_HV_VAPIC,
                0x40000003, 0x00000030);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_HV_VPINDEX,
                0x40000003, 0x00000040);
KVM_FEATURE_DEF(VIR_CPU_x86_KVM_HV_RESET,
                0x40000003, 0x00000080);

static virCPUx86Feature x86_kvm_features[] =
{
    KVM_FEATURE(VIR_CPU_x86_KVM_CLOCKSOURCE),
    KVM_FEATURE(VIR_CPU_x86_KVM_NOP_IO_DELAY),
    KVM_FEATURE(VIR_CPU_x86_KVM_MMU_OP),
    KVM_FEATURE(VIR_CPU_x86_KVM_CLOCKSOURCE2),
    KVM_FEATURE(VIR_CPU_x86_KVM_ASYNC_PF),
    KVM_FEATURE(VIR_CPU_x86_KVM_STEAL_TIME),
    KVM_FEATURE(VIR_CPU_x86_KVM_PV_EOI),
    KVM_FEATURE(VIR_CPU_x86_KVM_PV_UNHALT),
    KVM_FEATURE(VIR_CPU_x86_KVM_CLOCKSOURCE_STABLE_BIT),
    KVM_FEATURE(VIR_CPU_x86_KVM_HV_RUNTIME),
    KVM_FEATURE(VIR_CPU_x86_KVM_HV_SYNIC),
    KVM_FEATURE(VIR_CPU_x86_KVM_HV_STIMER),
    KVM_FEATURE(VIR_CPU_x86_KVM_HV_RELAXED),
    KVM_FEATURE(VIR_CPU_x86_KVM_HV_SPINLOCKS),
    KVM_FEATURE(VIR_CPU_x86_KVM_HV_VAPIC),
    KVM_FEATURE(VIR_CPU_x86_KVM_HV_VPINDEX),
    KVM_FEATURE(VIR_CPU_x86_KVM_HV_RESET),
};

typedef struct _virCPUx86Model virCPUx86Model;
typedef virCPUx86Model *virCPUx86ModelPtr;
struct _virCPUx86Model {
    char *name;
    virCPUx86VendorPtr vendor;
    uint32_t signature;
    virCPUx86Data data;
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

    if (da->eax_in > db->eax_in)
        return 1;
    else if (da->eax_in < db->eax_in)
        return -1;

    if (da->ecx_in > db->ecx_in)
        return 1;
    else if (da->ecx_in < db->ecx_in)
        return -1;

    return 0;
}


/* skips all zero CPUID leaves */
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
             const virCPUx86CPUID *cpuid)
{
    size_t i;

    for (i = 0; i < data->len; i++) {
        if (data->data[i].eax_in == cpuid->eax_in &&
            data->data[i].ecx_in == cpuid->ecx_in)
            return data->data + i;
    }

    return NULL;
}

static void
virCPUx86DataClear(virCPUx86Data *data)
{
    if (!data)
        return;

    VIR_FREE(data->data);
}


static void
virCPUx86DataFree(virCPUDataPtr data)
{
    if (!data)
        return;

    virCPUx86DataClear(&data->data.x86);
    VIR_FREE(data);
}


static int
x86DataCopy(virCPUx86Data *dst, const virCPUx86Data *src)
{
    size_t i;

    if (VIR_ALLOC_N(dst->data, src->len) < 0)
        return -1;

    dst->len = src->len;
    for (i = 0; i < src->len; i++)
        dst->data[i] = src->data[i];

    return 0;
}


static int
virCPUx86DataAddCPUIDInt(virCPUx86Data *data,
                         const virCPUx86CPUID *cpuid)
{
    virCPUx86CPUID *existing;

    if ((existing = x86DataCpuid(data, cpuid))) {
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
        cpuid1 = x86DataCpuid(data1, cpuid2);

        if (cpuid1) {
            x86cpuidSetBits(cpuid1, cpuid2);
        } else {
            if (virCPUx86DataAddCPUIDInt(data1, cpuid2) < 0)
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
        cpuid2 = x86DataCpuid(data2, cpuid1);
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
        cpuid2 = x86DataCpuid(data2, cpuid1);
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
        if (!(cpuid = x86DataCpuid(data, cpuidSubset)) ||
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
        if (x86DataIsSubset(data, &feature->data)) {
            x86DataSubtract(data, &feature->data);
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
        if ((cpuid = x86DataCpuid(data, &vendor->cpuid)) &&
            x86cpuidMatchMasked(cpuid, &vendor->cpuid)) {
            x86cpuidClearBits(cpuid, &vendor->cpuid);
            return vendor;
        }
    }

    return NULL;
}


static int
virCPUx86VendorToCPUID(const char *vendor,
                       virCPUx86CPUID *cpuid)
{
    if (strlen(vendor) != VENDOR_STRING_LENGTH) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid CPU vendor string '%s'"), vendor);
        return -1;
    }

    cpuid->eax_in = 0;
    cpuid->ecx_in = 0;
    cpuid->ebx = virReadBufInt32LE(vendor);
    cpuid->edx = virReadBufInt32LE(vendor + 4);
    cpuid->ecx = virReadBufInt32LE(vendor + 8);

    return 0;
}


static uint32_t
x86MakeSignature(unsigned int family,
                 unsigned int model)
{
    uint32_t sig = 0;

    /*
     * CPU signature (eax from 0x1 CPUID leaf):
     *
     * |31 .. 28|27 .. 20|19 .. 16|15 .. 14|13 .. 12|11 .. 8|7 .. 4|3 .. 0|
     * |   R    | extFam | extMod |   R    | PType  |  Fam  | Mod  | Step |
     *
     * R        reserved
     * extFam   extended family (valid only if Fam == 0xf)
     * extMod   extended model
     * PType    processor type
     * Fam      family
     * Mod      model
     * Step     stepping
     *
     * family = eax[27:20] + eax[11:8]
     * model = eax[19:16] << 4 + eax[7:4]
     */

    /* extFam */
    if (family > 0xf) {
        sig |= (family - 0xf) << 20;
        family = 0xf;
    }

    /* extMod */
    sig |= (model >> 4) << 16;

    /* PType is always 0 */

    /* Fam */
    sig |= family << 8;

    /* Mod */
    sig |= (model & 0xf) << 4;

    /* Step is irrelevant, it is used to distinguish different revisions
     * of the same CPU model
     */

    return sig;
}


/* Mask out irrelevant bits (R and Step) from processor signature. */
#define SIGNATURE_MASK  0x0fff3ff0

static uint32_t
x86DataToSignature(const virCPUx86Data *data)
{
    virCPUx86CPUID leaf1 = { .eax_in = 0x1 };
    virCPUx86CPUID *cpuid;

    if (!(cpuid = x86DataCpuid(data, &leaf1)))
        return 0;

    return cpuid->eax & SIGNATURE_MASK;
}


static int
x86DataAddSignature(virCPUx86Data *data,
                    uint32_t signature)
{
    virCPUx86CPUID cpuid = { .eax_in = 0x1, .eax = signature };

    return virCPUx86DataAddCPUIDInt(data, &cpuid);
}


static virCPUDefPtr
x86DataToCPU(const virCPUx86Data *data,
             virCPUx86ModelPtr model,
             virCPUx86MapPtr map)
{
    virCPUDefPtr cpu;
    virCPUx86Data copy = VIR_CPU_X86_DATA_INIT;
    virCPUx86Data modelData = VIR_CPU_X86_DATA_INIT;
    virCPUx86VendorPtr vendor;

    if (VIR_ALLOC(cpu) < 0 ||
        VIR_STRDUP(cpu->model, model->name) < 0 ||
        x86DataCopy(&copy, data) < 0 ||
        x86DataCopy(&modelData, &model->data) < 0)
        goto error;

    if ((vendor = x86DataToVendor(&copy, map)) &&
        VIR_STRDUP(cpu->vendor, vendor->name) < 0)
        goto error;

    x86DataSubtract(&copy, &modelData);
    x86DataSubtract(&modelData, data);

    /* because feature policy is ignored for host CPU */
    cpu->type = VIR_CPU_TYPE_GUEST;

    if (x86DataToCPUFeatures(cpu, VIR_CPU_FEATURE_REQUIRE, &copy, map) ||
        x86DataToCPUFeatures(cpu, VIR_CPU_FEATURE_DISABLE, &modelData, map))
        goto error;

 cleanup:
    virCPUx86DataClear(&modelData);
    virCPUx86DataClear(&copy);
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

    if (virCPUx86VendorToCPUID(string, &vendor->cpuid) < 0)
        goto error;

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

    return feature;
}


static void
x86FeatureFree(virCPUx86FeaturePtr feature)
{
    if (!feature)
        return;

    VIR_FREE(feature->name);
    virCPUx86DataClear(&feature->data);
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


static virCPUx86FeaturePtr
x86FeatureFindInternal(const char *name)
{
    size_t i;
    size_t count = ARRAY_CARDINALITY(x86_kvm_features);

    for (i = 0; i < count; i++) {
        if (STREQ(x86_kvm_features[i].name, name))
            return x86_kvm_features + i;
    }

    return NULL;
}


static int
x86FeatureInData(const char *name,
                 const virCPUx86Data *data,
                 virCPUx86MapPtr map)
{
    virCPUx86FeaturePtr feature;

    if (!(feature = x86FeatureFind(map, name)) &&
        !(feature = x86FeatureFindInternal(name))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown CPU feature %s"), name);
        return -1;
    }

    if (x86DataIsSubset(data, &feature->data))
        return 1;
    else
        return 0;
}


static bool
x86FeatureIsMigratable(const char *name,
                       void *cpu_map)
{
    virCPUx86MapPtr map = cpu_map;
    size_t i;

    for (i = 0; i < map->nblockers; i++) {
        if (STREQ(name, map->migrate_blockers[i]->name))
            return false;
    }

    return true;
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
        if (x86DataIsSubset(data, &feature->data)) {
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
    unsigned long eax_in, ecx_in;
    unsigned long eax, ebx, ecx, edx;
    int ret_eax_in, ret_ecx_in, ret_eax, ret_ebx, ret_ecx, ret_edx;

    memset(cpuid, 0, sizeof(*cpuid));

    eax_in = ecx_in = 0;
    eax = ebx = ecx = edx = 0;
    ret_eax_in = virXPathULongHex("string(@eax_in)", ctxt, &eax_in);
    ret_ecx_in = virXPathULongHex("string(@ecx_in)", ctxt, &ecx_in);
    ret_eax = virXPathULongHex("string(@eax)", ctxt, &eax);
    ret_ebx = virXPathULongHex("string(@ebx)", ctxt, &ebx);
    ret_ecx = virXPathULongHex("string(@ecx)", ctxt, &ecx);
    ret_edx = virXPathULongHex("string(@edx)", ctxt, &edx);

    if (ret_eax_in < 0 || ret_ecx_in == -2 ||
        ret_eax == -2 || ret_ebx == -2 || ret_ecx == -2 || ret_edx == -2)
        return -1;

    cpuid->eax_in = eax_in;
    cpuid->ecx_in = ecx_in;
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
        if (virCPUx86DataAddCPUIDInt(&feature->data, &cpuid))
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

static int
x86DataFromCPUFeatures(virCPUx86Data *data,
                       virCPUDefPtr cpu,
                       virCPUx86MapPtr map)
{
    size_t i;

    for (i = 0; i < cpu->nfeatures; i++) {
        virCPUx86FeaturePtr feature;
        if (!(feature = x86FeatureFind(map, cpu->features[i].name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown CPU feature %s"), cpu->features[i].name);
            return -1;
        }

        if (x86DataAdd(data, &feature->data) < 0)
            return -1;
    }

    return 0;
}


static virCPUx86ModelPtr
x86ModelNew(void)
{
    virCPUx86ModelPtr model;

    if (VIR_ALLOC(model) < 0)
        return NULL;

    return model;
}


static void
x86ModelFree(virCPUx86ModelPtr model)
{
    if (!model)
        return;

    VIR_FREE(model->name);
    virCPUx86DataClear(&model->data);
    VIR_FREE(model);
}


static virCPUx86ModelPtr
x86ModelCopy(virCPUx86ModelPtr model)
{
    virCPUx86ModelPtr copy;

    if (VIR_ALLOC(copy) < 0 ||
        VIR_STRDUP(copy->name, model->name) < 0 ||
        x86DataCopy(&copy->data, &model->data) < 0) {
        x86ModelFree(copy);
        return NULL;
    }

    copy->vendor = model->vendor;
    copy->signature = model->signature;

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


/*
 * Computes CPU model data from a CPU definition associated with features
 * matching @policy. If @policy equals -1, the computed model will describe
 * all CPU features, i.e., it will contain:
 *
 *      features from model
 *      + required and forced features
 *      - disabled and forbidden features
 */
static virCPUx86ModelPtr
x86ModelFromCPU(const virCPUDef *cpu,
                virCPUx86MapPtr map,
                int policy)
{
    virCPUx86ModelPtr model = NULL;
    size_t i;

    /* host CPU only contains required features; requesting other features
     * just returns an empty model
     */
    if (cpu->type == VIR_CPU_TYPE_HOST &&
        policy != VIR_CPU_FEATURE_REQUIRE &&
        policy != -1)
        return x86ModelNew();

    if (cpu->model &&
        (policy == VIR_CPU_FEATURE_REQUIRE || policy == -1)) {
        if (!(model = x86ModelFind(map, cpu->model))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown CPU model %s"), cpu->model);
            return NULL;
        }

        model = x86ModelCopy(model);
    } else {
        model = x86ModelNew();
    }

    if (!model)
        return NULL;

    for (i = 0; i < cpu->nfeatures; i++) {
        virCPUx86FeaturePtr feature;
        virCPUFeaturePolicy fpol;

        if (cpu->features[i].policy == -1)
            fpol = VIR_CPU_FEATURE_REQUIRE;
        else
            fpol = cpu->features[i].policy;

        if ((policy == -1 && fpol == VIR_CPU_FEATURE_OPTIONAL) ||
            (policy != -1 && fpol != policy))
            continue;

        if (!(feature = x86FeatureFind(map, cpu->features[i].name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown CPU feature %s"), cpu->features[i].name);
            goto error;
        }

        if (policy == -1) {
            switch (fpol) {
            case VIR_CPU_FEATURE_FORCE:
            case VIR_CPU_FEATURE_REQUIRE:
                if (x86DataAdd(&model->data, &feature->data) < 0)
                    goto error;
                break;

            case VIR_CPU_FEATURE_DISABLE:
            case VIR_CPU_FEATURE_FORBID:
                x86DataSubtract(&model->data, &feature->data);
                break;

            /* coverity[dead_error_condition] */
            case VIR_CPU_FEATURE_OPTIONAL:
            case VIR_CPU_FEATURE_LAST:
                break;
            }
        } else if (x86DataAdd(&model->data, &feature->data) < 0) {
            goto error;
        }
    }

    return model;

 error:
    x86ModelFree(model);
    return NULL;
}


static virCPUx86CompareResult
x86ModelCompare(virCPUx86ModelPtr model1,
                virCPUx86ModelPtr model2)
{
    virCPUx86CompareResult result = EQUAL;
    virCPUx86DataIterator iter1 = virCPUx86DataIteratorInit(&model1->data);
    virCPUx86DataIterator iter2 = virCPUx86DataIteratorInit(&model2->data);
    virCPUx86CPUID *cpuid1;
    virCPUx86CPUID *cpuid2;

    while ((cpuid1 = x86DataCpuidNext(&iter1))) {
        virCPUx86CompareResult match = SUPERSET;

        if ((cpuid2 = x86DataCpuid(&model2->data, cpuid1))) {
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

        if ((cpuid1 = x86DataCpuid(&model1->data, cpuid2))) {
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
        if (x86DataCopy(&model->data, &ancestor->data) < 0)
            goto error;
    }

    if (virXPathBoolean("boolean(./signature)", ctxt)) {
        unsigned int sigFamily = 0;
        unsigned int sigModel = 0;
        int rc;

        rc = virXPathUInt("string(./signature/@family)", ctxt, &sigFamily);
        if (rc < 0 || sigFamily == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid CPU signature family in model %s"),
                           model->name);
            goto cleanup;
        }

        rc = virXPathUInt("string(./signature/@model)", ctxt, &sigModel);
        if (rc < 0 || sigModel == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid CPU signature model in model %s"),
                           model->name);
            goto cleanup;
        }

        model->signature = x86MakeSignature(sigFamily, sigModel);
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

        if (x86DataAdd(&model->data, &feature->data))
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


static virCPUx86MapPtr
virCPUx86LoadMap(void)
{
    virCPUx86MapPtr map;

    if (VIR_ALLOC(map) < 0)
        return NULL;

    if (cpuMapLoad("x86", x86MapLoadCallback, map) < 0)
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
virCPUx86DataFormat(const virCPUData *data)
{
    virCPUx86DataIterator iter = virCPUx86DataIteratorInit(&data->data.x86);
    virCPUx86CPUID *cpuid;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "<cpudata arch='x86'>\n");
    while ((cpuid = x86DataCpuidNext(&iter))) {
        virBufferAsprintf(&buf,
                          "  <cpuid eax_in='0x%08x' ecx_in='0x%08x'"
                          " eax='0x%08x' ebx='0x%08x'"
                          " ecx='0x%08x' edx='0x%08x'/>\n",
                          cpuid->eax_in, cpuid->ecx_in,
                          cpuid->eax, cpuid->ebx, cpuid->ecx, cpuid->edx);
    }
    virBufferAddLit(&buf, "</cpudata>\n");

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


static virCPUDataPtr
virCPUx86DataParse(xmlXPathContextPtr ctxt)
{
    xmlNodePtr *nodes = NULL;
    virCPUDataPtr cpuData = NULL;
    virCPUx86CPUID cpuid;
    size_t i;
    int n;

    n = virXPathNodeSet("/cpudata/cpuid", ctxt, &nodes);
    if (n <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no x86 CPU data found"));
        goto error;
    }

    if (!(cpuData = virCPUDataNew(VIR_ARCH_X86_64)))
        goto error;

    for (i = 0; i < n; i++) {
        ctxt->node = nodes[i];
        if (x86ParseCPUID(ctxt, &cpuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse cpuid[%zu]"), i);
            goto error;
        }
        if (virCPUx86DataAddCPUID(cpuData, &cpuid) < 0)
            goto error;
    }

 cleanup:
    VIR_FREE(nodes);
    return cpuData;

 error:
    virCPUx86DataFree(cpuData);
    cpuData = NULL;
    goto cleanup;
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
    virCPUDataPtr guestData = NULL;
    virCPUCompareResult ret;
    virCPUx86CompareResult result;
    virArch arch;
    size_t i;

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
        !(host_model = x86ModelFromCPU(host, map, -1)) ||
        !(cpu_force = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_FORCE)) ||
        !(cpu_require = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_REQUIRE)) ||
        !(cpu_optional = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_OPTIONAL)) ||
        !(cpu_disable = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_DISABLE)) ||
        !(cpu_forbid = x86ModelFromCPU(cpu, map, VIR_CPU_FEATURE_FORBID)))
        goto error;

    x86DataIntersect(&cpu_forbid->data, &host_model->data);
    if (!x86DataIsEmpty(&cpu_forbid->data)) {
        virX86CpuIncompatible(N_("Host CPU provides forbidden features"),
                              &cpu_forbid->data);
        goto cleanup;
    }

    /* first remove features that were inherited from the CPU model and were
     * explicitly forced, disabled, or made optional
     */
    x86DataSubtract(&cpu_require->data, &cpu_force->data);
    x86DataSubtract(&cpu_require->data, &cpu_optional->data);
    x86DataSubtract(&cpu_require->data, &cpu_disable->data);
    result = x86ModelCompare(host_model, cpu_require);
    if (result == SUBSET || result == UNRELATED) {
        x86DataSubtract(&cpu_require->data, &host_model->data);
        virX86CpuIncompatible(N_("Host CPU does not provide required "
                                 "features"),
                              &cpu_require->data);
        goto cleanup;
    }

    ret = VIR_CPU_COMPARE_IDENTICAL;

    if (!(diff = x86ModelCopy(host_model)))
        goto error;

    x86DataSubtract(&diff->data, &cpu_optional->data);
    x86DataSubtract(&diff->data, &cpu_require->data);
    x86DataSubtract(&diff->data, &cpu_disable->data);
    x86DataSubtract(&diff->data, &cpu_force->data);

    if (!x86DataIsEmpty(&diff->data))
        ret = VIR_CPU_COMPARE_SUPERSET;

    if (ret == VIR_CPU_COMPARE_SUPERSET
        && cpu->type == VIR_CPU_TYPE_GUEST
        && cpu->match == VIR_CPU_MATCH_STRICT) {
        virX86CpuIncompatible(N_("Host CPU does not strictly match guest CPU: "
                                 "Extra features"),
                              &diff->data);
        goto cleanup;
    }

    if (guest) {
        if (!(guest_model = x86ModelCopy(host_model)))
            goto error;

        if (cpu->vendor && host_model->vendor &&
            virCPUx86DataAddCPUIDInt(&guest_model->data,
                                     &host_model->vendor->cpuid) < 0)
            goto error;

        if (x86DataAddSignature(&guest_model->data, host_model->signature) < 0)
            goto error;

        if (cpu->type == VIR_CPU_TYPE_GUEST
            && cpu->match == VIR_CPU_MATCH_EXACT)
            x86DataSubtract(&guest_model->data, &diff->data);

        if (x86DataAdd(&guest_model->data, &cpu_force->data))
            goto error;

        x86DataSubtract(&guest_model->data, &cpu_disable->data);

        if (!(guestData = virCPUDataNew(arch)) ||
            x86DataCopy(&guestData->data.x86, &guest_model->data) < 0)
            goto error;

        *guest = guestData;
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
    virCPUx86DataFree(guestData);
    ret = VIR_CPU_COMPARE_ERROR;
    goto cleanup;
}
#undef virX86CpuIncompatible


static virCPUCompareResult
virCPUx86Compare(virCPUDefPtr host,
                 virCPUDefPtr cpu,
                 bool failIncompatible)
{
    virCPUCompareResult ret = VIR_CPU_COMPARE_ERROR;
    virCPUx86MapPtr map;
    virCPUx86ModelPtr model = NULL;
    char *message = NULL;

    if (!host || !host->model) {
        if (failIncompatible) {
            virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s",
                           _("unknown host CPU"));
        } else {
            VIR_WARN("unknown host CPU");
            ret = VIR_CPU_COMPARE_INCOMPATIBLE;
        }
        goto cleanup;
    }

    ret = x86Compute(host, cpu, NULL, &message);

    if (ret == VIR_CPU_COMPARE_INCOMPATIBLE) {
        bool noTSX = false;

        if (STREQ_NULLABLE(cpu->model, "Haswell") ||
            STREQ_NULLABLE(cpu->model, "Broadwell")) {
            if (!(map = virCPUx86GetMap()))
                goto cleanup;

            if (!(model = x86ModelFromCPU(cpu, map, -1)))
                goto cleanup;

            noTSX = !x86FeatureInData("hle", &model->data, map) ||
                    !x86FeatureInData("rtm", &model->data, map);
        }

        if (failIncompatible) {
            ret = VIR_CPU_COMPARE_ERROR;
            if (message) {
                if (noTSX) {
                    virReportError(VIR_ERR_CPU_INCOMPATIBLE,
                                   _("%s; try using '%s-noTSX' CPU model"),
                                   message, cpu->model);
                } else {
                    virReportError(VIR_ERR_CPU_INCOMPATIBLE, "%s", message);
                }
            } else {
                if (noTSX) {
                    virReportError(VIR_ERR_CPU_INCOMPATIBLE,
                                   _("try using '%s-noTSX' CPU model"),
                                   cpu->model);
                } else {
                    virReportError(VIR_ERR_CPU_INCOMPATIBLE, NULL);
                }
            }
        }
    }

 cleanup:
    VIR_FREE(message);
    x86ModelFree(model);
    return ret;
}


/*
 * Checks whether a candidate model is a better fit for the CPU data than the
 * current model.
 *
 * Returns 0 if current is better,
 *         1 if candidate is better,
 *         2 if candidate is the best one (search should stop now).
 */
static int
x86DecodeUseCandidate(virCPUx86ModelPtr current,
                      virCPUDefPtr cpuCurrent,
                      virCPUx86ModelPtr candidate,
                      virCPUDefPtr cpuCandidate,
                      uint32_t signature,
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

    /* Ideally we want to select a model with family/model equal to
     * family/model of the real CPU. Once we found such model, we only
     * consider candidates with matching family/model.
     */
    if (signature &&
        current->signature == signature &&
        candidate->signature != signature)
        return 0;

    if (cpuCurrent->nfeatures > cpuCandidate->nfeatures)
        return 1;

    /* Prefer a candidate with matching signature even though it would
     * result in longer list of features.
     */
    if (signature &&
        candidate->signature == signature &&
        current->signature != signature)
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
    virCPUx86ModelPtr model = NULL;
    virCPUDefPtr cpuModel = NULL;
    virCPUx86Data copy = VIR_CPU_X86_DATA_INIT;
    virCPUx86Data features = VIR_CPU_X86_DATA_INIT;
    virCPUx86VendorPtr vendor;
    uint32_t signature;
    ssize_t i;
    int rc;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES |
                  VIR_CONNECT_BASELINE_CPU_MIGRATABLE, -1);

    if (!data || !(map = virCPUx86GetMap()))
        return -1;

    vendor = x86DataToVendor(data, map);
    signature = x86DataToSignature(data);

    /* Walk through the CPU models in reverse order to check newest
     * models first.
     */
    for (i = map->nmodels - 1; i >= 0; i--) {
        candidate = map->models[i];
        if (!virCPUModelIsAllowed(candidate->name, models, nmodels)) {
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

        if ((rc = x86DecodeUseCandidate(model, cpuModel,
                                        candidate, cpuCandidate,
                                        signature, preferred,
                                        cpu->type == VIR_CPU_TYPE_HOST))) {
            virCPUDefFree(cpuModel);
            cpuModel = cpuCandidate;
            model = candidate;
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
        i = 0;
        while (i < cpuModel->nfeatures) {
            if (x86FeatureIsMigratable(cpuModel->features[i].name, map)) {
                i++;
            } else {
                VIR_FREE(cpuModel->features[i].name);
                VIR_DELETE_ELEMENT_INPLACE(cpuModel->features, i,
                                           cpuModel->nfeatures);
            }
        }
    }

    if (flags & VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES) {
        if (x86DataCopy(&copy, &model->data) < 0 ||
            x86DataFromCPUFeatures(&features, cpuModel, map) < 0)
            goto cleanup;

        x86DataSubtract(&copy, &features);
        if (x86DataToCPUFeatures(cpuModel, VIR_CPU_FEATURE_REQUIRE,
                                 &copy, map) < 0)
            goto cleanup;
    }

    if (vendor && VIR_STRDUP(cpu->vendor, vendor->name) < 0)
        goto cleanup;

    VIR_STEAL_PTR(cpu->model, cpuModel->model);
    VIR_STEAL_PTR(cpu->features, cpuModel->features);
    cpu->nfeatures = cpuModel->nfeatures;
    cpuModel->nfeatures = 0;
    cpu->nfeatures_max = cpuModel->nfeatures_max;
    cpuModel->nfeatures_max = 0;

    ret = 0;

 cleanup:
    virCPUDefFree(cpuModel);
    virCPUx86DataClear(&copy);
    virCPUx86DataClear(&features);
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
    return x86Decode(cpu, &data->data.x86, models, nmodels, preferred, flags);
}


static int
x86EncodePolicy(virCPUx86Data *data,
                const virCPUDef *cpu,
                virCPUx86MapPtr map,
                virCPUFeaturePolicy policy)
{
    virCPUx86ModelPtr model;

    if (!(model = x86ModelFromCPU(cpu, map, policy)))
        return -1;

    *data = model->data;
    model->data.len = 0;
    model->data.data = NULL;
    x86ModelFree(model);

    return 0;
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
    virCPUDataPtr data_forced = NULL;
    virCPUDataPtr data_required = NULL;
    virCPUDataPtr data_optional = NULL;
    virCPUDataPtr data_disabled = NULL;
    virCPUDataPtr data_forbidden = NULL;
    virCPUDataPtr data_vendor = NULL;

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

    if (forced &&
        (!(data_forced = virCPUDataNew(arch)) ||
         x86EncodePolicy(&data_forced->data.x86, cpu, map,
                         VIR_CPU_FEATURE_FORCE) < 0))
        goto error;

    if (required &&
        (!(data_required = virCPUDataNew(arch)) ||
         x86EncodePolicy(&data_required->data.x86, cpu, map,
                         VIR_CPU_FEATURE_REQUIRE) < 0))
        goto error;

    if (optional &&
        (!(data_optional = virCPUDataNew(arch)) ||
         x86EncodePolicy(&data_optional->data.x86, cpu, map,
                         VIR_CPU_FEATURE_OPTIONAL) < 0))
        goto error;

    if (disabled &&
        (!(data_disabled = virCPUDataNew(arch)) ||
         x86EncodePolicy(&data_disabled->data.x86, cpu, map,
                         VIR_CPU_FEATURE_DISABLE) < 0))
        goto error;

    if (forbidden &&
        (!(data_forbidden = virCPUDataNew(arch)) ||
         x86EncodePolicy(&data_forbidden->data.x86, cpu, map,
                         VIR_CPU_FEATURE_FORBID) < 0))
        goto error;

    if (vendor) {
        virCPUx86VendorPtr v = NULL;

        if (cpu->vendor && !(v = x86VendorFind(map, cpu->vendor))) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("CPU vendor %s not found"), cpu->vendor);
            goto error;
        }

        if (!(data_vendor = virCPUDataNew(arch)))
            goto error;

        if (v && virCPUx86DataAddCPUID(data_vendor, &v->cpuid) < 0)
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
    if (vendor)
        *vendor = data_vendor;

    return 0;

 error:
    virCPUx86DataFree(data_forced);
    virCPUx86DataFree(data_required);
    virCPUx86DataFree(data_optional);
    virCPUx86DataFree(data_disabled);
    virCPUx86DataFree(data_forbidden);
    virCPUx86DataFree(data_vendor);
    return -1;
}


#if defined(__i386__) || defined(__x86_64__)
static inline void
cpuidCall(virCPUx86CPUID *cpuid)
{
# if __x86_64__
    asm("xor %%ebx, %%ebx;" /* clear the other registers as some cpuid */
        "xor %%edx, %%edx;" /* functions may use them as additional arguments */
        "cpuid;"
        : "=a" (cpuid->eax),
          "=b" (cpuid->ebx),
          "=c" (cpuid->ecx),
          "=d" (cpuid->edx)
        : "a" (cpuid->eax_in),
          "c" (cpuid->ecx_in));
# else
    /* we need to avoid direct use of ebx for CPUID output as it is used
     * for global offset table on i386 with -fPIC
     */
    asm("push %%ebx;"
        "xor %%ebx, %%ebx;" /* clear the other registers as some cpuid */
        "xor %%edx, %%edx;" /* functions may use them as additional arguments */
        "cpuid;"
        "mov %%ebx, %1;"
        "pop %%ebx;"
        : "=a" (cpuid->eax),
          "=r" (cpuid->ebx),
          "=c" (cpuid->ecx),
          "=d" (cpuid->edx)
        : "a" (cpuid->eax_in),
          "c" (cpuid->ecx_in)
        : "cc");
# endif
}


/* Leaf 0x04: deterministic cache parameters
 *
 * Sub leaf n+1 is invalid if eax[4:0] in sub leaf n equals 0.
 */
static int
cpuidSetLeaf4(virCPUDataPtr data,
              virCPUx86CPUID *subLeaf0)
{
    virCPUx86CPUID cpuid = *subLeaf0;

    if (virCPUx86DataAddCPUID(data, subLeaf0) < 0)
        return -1;

    while (cpuid.eax & 0x1f) {
        cpuid.ecx_in++;
        cpuidCall(&cpuid);
        if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
            return -1;
    }
    return 0;
}


/* Leaf 0x07: structured extended feature flags enumeration
 *
 * Sub leaf n is invalid if n > eax in sub leaf 0.
 */
static int
cpuidSetLeaf7(virCPUDataPtr data,
              virCPUx86CPUID *subLeaf0)
{
    virCPUx86CPUID cpuid = { .eax_in = 0x7 };
    uint32_t sub;

    if (virCPUx86DataAddCPUID(data, subLeaf0) < 0)
        return -1;

    for (sub = 1; sub <= subLeaf0->eax; sub++) {
        cpuid.ecx_in = sub;
        cpuidCall(&cpuid);
        if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
            return -1;
    }
    return 0;
}


/* Leaf 0x0b: extended topology enumeration
 *
 * Sub leaf n is invalid if it returns 0 in ecx[15:8].
 * Sub leaf n+1 is invalid if sub leaf n is invalid.
 * Some output values do not depend on ecx, thus sub leaf 0 provides
 * meaningful data even if it was (theoretically) considered invalid.
 */
static int
cpuidSetLeafB(virCPUDataPtr data,
              virCPUx86CPUID *subLeaf0)
{
    virCPUx86CPUID cpuid = *subLeaf0;

    while (cpuid.ecx & 0xff00) {
        if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
            return -1;
        cpuid.ecx_in++;
        cpuidCall(&cpuid);
    }
    return 0;
}


/* Leaf 0x0d: processor extended state enumeration
 *
 * Sub leaves 0 and 1 are valid.
 * Sub leaf n (2 <= n < 32) is invalid if eax[n] from sub leaf 0 is not set
 * and ecx[n] from sub leaf 1 is not set.
 * Sub leaf n (32 <= n < 64) is invalid if edx[n-32] from sub leaf 0 is not set
 * and edx[n-32] from sub leaf 1 is not set.
 */
static int
cpuidSetLeafD(virCPUDataPtr data,
              virCPUx86CPUID *subLeaf0)
{
    virCPUx86CPUID cpuid = { .eax_in = 0xd };
    virCPUx86CPUID sub0;
    virCPUx86CPUID sub1;
    uint32_t sub;

    if (virCPUx86DataAddCPUID(data, subLeaf0) < 0)
        return -1;

    cpuid.ecx_in = 1;
    cpuidCall(&cpuid);
    if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
        return -1;

    sub0 = *subLeaf0;
    sub1 = cpuid;
    for (sub = 2; sub < 64; sub++) {
        if (sub < 32 &&
            !(sub0.eax & (1 << sub)) &&
            !(sub1.ecx & (1 << sub)))
            continue;
        if (sub >= 32 &&
            !(sub0.edx & (1 << (sub - 32))) &&
            !(sub1.edx & (1 << (sub - 32))))
            continue;

        cpuid.ecx_in = sub;
        cpuidCall(&cpuid);
        if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
            return -1;
    }
    return 0;
}


/* Leaf 0x0f: L3 cached RDT monitoring capability enumeration
 * Leaf 0x10: RDT allocation enumeration
 *
 * res reports valid resource identification (ResID) starting at bit 1.
 * Values associated with each valid ResID are reported by ResID sub leaf.
 *
 * 0x0f: Sub leaf n is valid if edx[n] (= res[ResID]) from sub leaf 0 is set.
 * 0x10: Sub leaf n is valid if ebx[n] (= res[ResID]) from sub leaf 0 is set.
 */
static int
cpuidSetLeafResID(virCPUDataPtr data,
                  virCPUx86CPUID *subLeaf0,
                  uint32_t res)
{
    virCPUx86CPUID cpuid = { .eax_in = subLeaf0->eax_in };
    uint32_t sub;

    if (virCPUx86DataAddCPUID(data, subLeaf0) < 0)
        return -1;

    for (sub = 1; sub < 32; sub++) {
        if (!(res & (1 << sub)))
            continue;
        cpuid.ecx_in = sub;
        cpuidCall(&cpuid);
        if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
            return -1;
    }
    return 0;
}


/* Leaf 0x12: SGX capability enumeration
 *
 * Sub leaves 0 and 1 is supported if ebx[2] from leaf 0x7 (SGX) is set.
 * Sub leaves n >= 2 are valid as long as eax[3:0] != 0.
 */
static int
cpuidSetLeaf12(virCPUDataPtr data,
               virCPUx86CPUID *subLeaf0)
{
    virCPUx86CPUID cpuid = { .eax_in = 0x7 };
    virCPUx86CPUID *cpuid7;

    if (!(cpuid7 = x86DataCpuid(&data->data.x86, &cpuid)) ||
        !(cpuid7->ebx & (1 << 2)))
        return 0;

    if (virCPUx86DataAddCPUID(data, subLeaf0) < 0)
        return -1;

    cpuid.eax_in = 0x12;
    cpuid.ecx_in = 1;
    cpuidCall(&cpuid);
    if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
        return -1;

    cpuid.ecx_in = 2;
    cpuidCall(&cpuid);
    while (cpuid.eax & 0xf) {
        if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
            return -1;
        cpuid.ecx_in++;
        cpuidCall(&cpuid);
    }
    return 0;
}


/* Leaf 0x14: processor trace enumeration
 *
 * Sub leaf 0 reports the maximum supported sub leaf in eax.
 */
static int
cpuidSetLeaf14(virCPUDataPtr data,
               virCPUx86CPUID *subLeaf0)
{
    virCPUx86CPUID cpuid = { .eax_in = 0x14 };
    uint32_t sub;

    if (virCPUx86DataAddCPUID(data, subLeaf0) < 0)
        return -1;

    for (sub = 1; sub <= subLeaf0->eax; sub++) {
        cpuid.ecx_in = sub;
        cpuidCall(&cpuid);
        if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
            return -1;
    }
    return 0;
}


/* Leaf 0x17: SOC Vendor
 *
 * Sub leaf 0 is valid if eax >= 3.
 * Sub leaf 0 reports the maximum supported sub leaf in eax.
 */
static int
cpuidSetLeaf17(virCPUDataPtr data,
               virCPUx86CPUID *subLeaf0)
{
    virCPUx86CPUID cpuid = { .eax_in = 0x17 };
    uint32_t sub;

    if (subLeaf0->eax < 3)
        return 0;

    if (virCPUx86DataAddCPUID(data, subLeaf0) < 0)
        return -1;

    for (sub = 1; sub <= subLeaf0->eax; sub++) {
        cpuid.ecx_in = sub;
        cpuidCall(&cpuid);
        if (virCPUx86DataAddCPUID(data, &cpuid) < 0)
            return -1;
    }
    return 0;
}


static int
cpuidSet(uint32_t base, virCPUDataPtr data)
{
    int rc;
    uint32_t max;
    uint32_t leaf;
    virCPUx86CPUID cpuid = { .eax_in = base };

    cpuidCall(&cpuid);
    max = cpuid.eax;

    for (leaf = base; leaf <= max; leaf++) {
        cpuid.eax_in = leaf;
        cpuid.ecx_in = 0;
        cpuidCall(&cpuid);

        /* Handle CPUID leaves that depend on previously queried bits or
         * which provide additional sub leaves for ecx_in > 0
         */
        if (leaf == 0x4)
            rc = cpuidSetLeaf4(data, &cpuid);
        else if (leaf == 0x7)
            rc = cpuidSetLeaf7(data, &cpuid);
        else if (leaf == 0xb)
            rc = cpuidSetLeafB(data, &cpuid);
        else if (leaf == 0xd)
            rc = cpuidSetLeafD(data, &cpuid);
        else if (leaf == 0xf)
            rc = cpuidSetLeafResID(data, &cpuid, cpuid.edx);
        else if (leaf == 0x10)
            rc = cpuidSetLeafResID(data, &cpuid, cpuid.ebx);
        else if (leaf == 0x12)
            rc = cpuidSetLeaf12(data, &cpuid);
        else if (leaf == 0x14)
            rc = cpuidSetLeaf14(data, &cpuid);
        else if (leaf == 0x17)
            rc = cpuidSetLeaf17(data, &cpuid);
        else
            rc = virCPUx86DataAddCPUID(data, &cpuid);

        if (rc < 0)
            return -1;
    }

    return 0;
}


static virCPUDataPtr
x86NodeData(virArch arch)
{
    virCPUDataPtr cpuData = NULL;

    if (!(cpuData = virCPUDataNew(arch)))
        goto error;

    if (cpuidSet(CPUX86_BASIC, cpuData) < 0)
        goto error;

    if (cpuidSet(CPUX86_EXTENDED, cpuData) < 0)
        goto error;

    return cpuData;

 error:
    virCPUx86DataFree(cpuData);
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

        x86DataIntersect(&base_model->data, &model->data);
        x86ModelFree(model);
        model = NULL;
    }

    if (x86DataIsEmpty(&base_model->data)) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("CPUs are incompatible"));
        goto error;
    }

    if (vendor &&
        virCPUx86DataAddCPUIDInt(&base_model->data, &vendor->cpuid) < 0)
        goto error;

    if (x86Decode(cpu, &base_model->data, models, nmodels, modelName, flags) < 0)
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
x86UpdateHostModel(virCPUDefPtr guest,
                   const virCPUDef *host,
                   virCPUx86MapPtr map)
{
    virCPUDefPtr updated = NULL;
    size_t i;
    int ret = -1;

    if (!(updated = virCPUDefCopyWithoutModel(host)))
        goto cleanup;

    /* Remove non-migratable features by default */
    updated->type = VIR_CPU_TYPE_GUEST;
    updated->mode = VIR_CPU_MODE_CUSTOM;
    if (virCPUDefCopyModelFilter(updated, host, true,
                                 x86FeatureIsMigratable, map) < 0)
        goto cleanup;

    if (guest->vendor_id) {
        VIR_FREE(updated->vendor_id);
        if (VIR_STRDUP(updated->vendor_id, guest->vendor_id) < 0)
            goto cleanup;
    }

    for (i = 0; i < guest->nfeatures; i++) {
        if (virCPUDefUpdateFeature(updated,
                                   guest->features[i].name,
                                   guest->features[i].policy) < 0)
            goto cleanup;
    }

    virCPUDefStealModel(guest, updated,
                        guest->mode == VIR_CPU_MODE_CUSTOM);
    guest->mode = VIR_CPU_MODE_CUSTOM;
    guest->match = VIR_CPU_MATCH_EXACT;
    ret = 0;

 cleanup:
    virCPUDefFree(updated);
    return ret;
}


static int
virCPUx86Update(virCPUDefPtr guest,
                const virCPUDef *host)
{
    virCPUx86ModelPtr model = NULL;
    virCPUx86MapPtr map;
    int ret = -1;
    size_t i;

    if (!host) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("unknown host CPU model"));
        return -1;
    }

    if (!(map = virCPUx86GetMap()))
        return -1;

    if (!(model = x86ModelFromCPU(host, map, -1)))
        goto cleanup;

    for (i = 0; i < guest->nfeatures; i++) {
        if (guest->features[i].policy == VIR_CPU_FEATURE_OPTIONAL) {
            int supported = x86FeatureInData(guest->features[i].name,
                                             &model->data, map);
            if (supported < 0)
                goto cleanup;
            else if (supported)
                guest->features[i].policy = VIR_CPU_FEATURE_REQUIRE;
            else
                guest->features[i].policy = VIR_CPU_FEATURE_DISABLE;
        }
    }

    if (guest->mode == VIR_CPU_MODE_HOST_MODEL ||
        guest->match == VIR_CPU_MATCH_MINIMUM)
        ret = x86UpdateHostModel(guest, host, map);
    else
        ret = 0;

 cleanup:
    x86ModelFree(model);
    return ret;
}


static int
virCPUx86CheckFeature(const virCPUDef *cpu,
                      const char *name)
{
    int ret = -1;
    virCPUx86MapPtr map;
    virCPUx86ModelPtr model = NULL;

    if (!(map = virCPUx86GetMap()))
        return -1;

    if (!(model = x86ModelFromCPU(cpu, map, -1)))
        goto cleanup;

    ret = x86FeatureInData(name, &model->data, map);

 cleanup:
    x86ModelFree(model);
    return ret;
}


static int
virCPUx86DataCheckFeature(const virCPUData *data,
                          const char *name)
{
    virCPUx86MapPtr map;

    if (!(map = virCPUx86GetMap()))
        return -1;

    return x86FeatureInData(name, &data->data.x86, map);
}

static int
virCPUx86GetModels(char ***models)
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
        virStringListFree(*models);
        *models = NULL;
    }
    return -1;
}


static int
virCPUx86Translate(virCPUDefPtr cpu,
                   const char **models,
                   unsigned int nmodels)
{
    virCPUDefPtr translated = NULL;
    virCPUx86MapPtr map;
    virCPUx86ModelPtr model = NULL;
    size_t i;
    int ret = -1;

    if (!(map = virCPUx86GetMap()))
        goto cleanup;

    if (!(model = x86ModelFromCPU(cpu, map, -1)))
        goto cleanup;

    if (model->vendor &&
        virCPUx86DataAddCPUIDInt(&model->data, &model->vendor->cpuid) < 0)
        goto cleanup;

    if (x86DataAddSignature(&model->data, model->signature) < 0)
        goto cleanup;

    if (!(translated = virCPUDefCopyWithoutModel(cpu)))
        goto cleanup;

    if (x86Decode(translated, &model->data, models, nmodels, NULL, 0) < 0)
        goto cleanup;

    for (i = 0; i < cpu->nfeatures; i++) {
        virCPUFeatureDefPtr f = cpu->features + i;
        if (virCPUDefUpdateFeature(translated, f->name, f->policy) < 0)
            goto cleanup;
    }

    virCPUDefStealModel(cpu, translated, true);
    ret = 0;

 cleanup:
    virCPUDefFree(translated);
    x86ModelFree(model);
    return ret;
}


int
virCPUx86DataAddCPUID(virCPUDataPtr cpuData,
                      const virCPUx86CPUID *cpuid)
{
    return virCPUx86DataAddCPUIDInt(&cpuData->data.x86, cpuid);
}


int
virCPUx86DataSetSignature(virCPUDataPtr cpuData,
                          unsigned int family,
                          unsigned int model)
{
    uint32_t signature = x86MakeSignature(family, model);

    return x86DataAddSignature(&cpuData->data.x86, signature);
}


int
virCPUx86DataSetVendor(virCPUDataPtr cpuData,
                       const char *vendor)
{
    virCPUx86CPUID cpuid = { 0 };

    if (virCPUx86VendorToCPUID(vendor, &cpuid) < 0)
        return -1;

    return virCPUx86DataAddCPUID(cpuData, &cpuid);
}


struct cpuArchDriver cpuDriverX86 = {
    .name = "x86",
    .arch = archs,
    .narch = ARRAY_CARDINALITY(archs),
    .compare    = virCPUx86Compare,
    .decode     = x86DecodeCPUData,
    .encode     = x86Encode,
    .dataFree   = virCPUx86DataFree,
#if defined(__i386__) || defined(__x86_64__)
    .nodeData   = x86NodeData,
#else
    .nodeData   = NULL,
#endif
    .baseline   = x86Baseline,
    .update     = virCPUx86Update,
    .checkFeature = virCPUx86CheckFeature,
    .dataCheckFeature = virCPUx86DataCheckFeature,
    .dataFormat = virCPUx86DataFormat,
    .dataParse  = virCPUx86DataParse,
    .getModels  = virCPUx86GetModels,
    .translate  = virCPUx86Translate,
};
