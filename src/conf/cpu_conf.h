/*
 * cpu_conf.h: CPU XML handling
 *
 * Copyright (C) 2009-2011, 2013, 2014 Red Hat, Inc.
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

#pragma once

#include "virutil.h"
#include "virbuffer.h"
#include "virxml.h"
#include "virbitmap.h"
#include "virarch.h"
#include "numa_conf.h"
#include "virenum.h"
#include "virhostcpu.h"

#define VIR_CPU_VENDOR_ID_LENGTH 12

typedef enum {
    VIR_CPU_TYPE_HOST,
    VIR_CPU_TYPE_GUEST,
    VIR_CPU_TYPE_AUTO,

    VIR_CPU_TYPE_LAST
} virCPUType;

VIR_ENUM_DECL(virCPU);

typedef enum {
    VIR_CPU_MODE_CUSTOM,
    VIR_CPU_MODE_HOST_MODEL,
    VIR_CPU_MODE_HOST_PASSTHROUGH,

    VIR_CPU_MODE_LAST
} virCPUMode;

VIR_ENUM_DECL(virCPUMode);

typedef enum {
    VIR_CPU_MATCH_MINIMUM,
    VIR_CPU_MATCH_EXACT,
    VIR_CPU_MATCH_STRICT,

    VIR_CPU_MATCH_LAST
} virCPUMatch;

VIR_ENUM_DECL(virCPUMatch);

typedef enum {
    VIR_CPU_CHECK_DEFAULT,
    VIR_CPU_CHECK_NONE,
    VIR_CPU_CHECK_PARTIAL,
    VIR_CPU_CHECK_FULL,

    VIR_CPU_CHECK_LAST
} virCPUCheck;

VIR_ENUM_DECL(virCPUCheck);

typedef enum {
    VIR_CPU_FALLBACK_ALLOW,
    VIR_CPU_FALLBACK_FORBID,

    VIR_CPU_FALLBACK_LAST
} virCPUFallback;

VIR_ENUM_DECL(virCPUFallback);

typedef enum {
    VIR_CPU_FEATURE_FORCE,
    VIR_CPU_FEATURE_REQUIRE,
    VIR_CPU_FEATURE_OPTIONAL,
    VIR_CPU_FEATURE_DISABLE,
    VIR_CPU_FEATURE_FORBID,

    VIR_CPU_FEATURE_LAST
} virCPUFeaturePolicy;

VIR_ENUM_DECL(virCPUFeaturePolicy);

typedef struct _virCPUFeatureDef virCPUFeatureDef;
typedef virCPUFeatureDef *virCPUFeatureDefPtr;
struct _virCPUFeatureDef {
    char *name;
    int policy;         /* enum virCPUFeaturePolicy */
};


typedef enum {
    VIR_CPU_CACHE_MODE_EMULATE,
    VIR_CPU_CACHE_MODE_PASSTHROUGH,
    VIR_CPU_CACHE_MODE_DISABLE,

    VIR_CPU_CACHE_MODE_LAST
} virCPUCacheMode;

VIR_ENUM_DECL(virCPUCacheMode);

typedef struct _virCPUCacheDef virCPUCacheDef;
typedef virCPUCacheDef *virCPUCacheDefPtr;
struct _virCPUCacheDef {
    int level;          /* -1 for unspecified */
    virCPUCacheMode mode;
};


typedef struct _virCPUDef virCPUDef;
typedef virCPUDef *virCPUDefPtr;
struct _virCPUDef {
    int type;           /* enum virCPUType */
    int mode;           /* enum virCPUMode */
    int match;          /* enum virCPUMatch */
    virCPUCheck check;
    virArch arch;
    char *model;
    char *vendor_id;    /* vendor id returned by CPUID in the guest */
    int fallback;       /* enum virCPUFallback */
    char *vendor;
    unsigned int microcodeVersion;
    unsigned int sockets;
    unsigned int cores;
    unsigned int threads;
    size_t nfeatures;
    size_t nfeatures_max;
    virCPUFeatureDefPtr features;
    virCPUCacheDefPtr cache;
    virHostCPUTscInfoPtr tsc;
};


void ATTRIBUTE_NONNULL(1)
virCPUDefFreeFeatures(virCPUDefPtr def);

void ATTRIBUTE_NONNULL(1)
virCPUDefFreeModel(virCPUDefPtr def);

void
virCPUDefFree(virCPUDefPtr def);

int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
virCPUDefCopyModel(virCPUDefPtr dst,
                   const virCPUDef *src,
                   bool resetPolicy);

/*
 * Returns true if feature @name should copied, false otherwise.
 */
typedef bool (*virCPUDefFeatureFilter)(const char *name,
                                       void *opaque);

int
virCPUDefCopyModelFilter(virCPUDefPtr dst,
                         const virCPUDef *src,
                         bool resetPolicy,
                         virCPUDefFeatureFilter filter,
                         void *opaque)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void
virCPUDefStealModel(virCPUDefPtr dst,
                    virCPUDefPtr src,
                    bool keepVendor);

virCPUDefPtr
virCPUDefCopy(const virCPUDef *cpu);

virCPUDefPtr
virCPUDefCopyWithoutModel(const virCPUDef *cpu);

int
virCPUDefParseXML(xmlXPathContextPtr ctxt,
                  const char *xpath,
                  virCPUType mode,
                  virCPUDefPtr *cpu);

bool
virCPUDefIsEqual(virCPUDefPtr src,
                 virCPUDefPtr dst,
                 bool reportError);

char *
virCPUDefFormat(virCPUDefPtr def,
                virDomainNumaPtr numa);

int
virCPUDefFormatBuf(virBufferPtr buf,
                   virCPUDefPtr def);
int
virCPUDefFormatBufFull(virBufferPtr buf,
                       virCPUDefPtr def,
                       virDomainNumaPtr numa);

int
virCPUDefAddFeature(virCPUDefPtr cpu,
                    const char *name,
                    int policy);

int
virCPUDefUpdateFeature(virCPUDefPtr cpu,
                       const char *name,
                       int policy);

virCPUFeatureDefPtr
virCPUDefFindFeature(virCPUDefPtr def,
                     const char *name);

int
virCPUDefFilterFeatures(virCPUDefPtr cpu,
                        virCPUDefFeatureFilter filter,
                        void *opaque);

int
virCPUDefCheckFeatures(virCPUDefPtr cpu,
                       virCPUDefFeatureFilter filter,
                       void *opaque,
                       char ***features);

virCPUDefPtr *
virCPUDefListParse(const char **xmlCPUs,
                   unsigned int ncpus,
                   virCPUType cpuType);
void
virCPUDefListFree(virCPUDefPtr *cpus);
