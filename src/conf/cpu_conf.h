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

#include "virbuffer.h"
#include "virxml.h"
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
    VIR_CPU_MODE_MAXIMUM,

    VIR_CPU_MODE_LAST
} virCPUMode;

VIR_ENUM_DECL(virCPUMode);

typedef enum {
    VIR_CPU_MATCH_EXACT,
    VIR_CPU_MATCH_MINIMUM,
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
struct _virCPUCacheDef {
    int level;          /* -1 for unspecified */
    virCPUCacheMode mode;
};


typedef enum {
    VIR_CPU_MAX_PHYS_ADDR_MODE_EMULATE,
    VIR_CPU_MAX_PHYS_ADDR_MODE_PASSTHROUGH,

    VIR_CPU_MAX_PHYS_ADDR_MODE_LAST
} virCPUMaxPhysAddrMode;

VIR_ENUM_DECL(virCPUMaxPhysAddrMode);

typedef struct _virCPUMaxPhysAddrDef virCPUMaxPhysAddrDef;
struct _virCPUMaxPhysAddrDef {
    int bits;           /* -1 for unspecified */
    unsigned int limit; /* 0 for unspecified */
    virCPUMaxPhysAddrMode mode;
};


typedef struct _virCPUDef virCPUDef;
struct _virCPUDef {
    int refs;
    int type;           /* enum virCPUType */
    int mode;           /* enum virCPUMode */
    virCPUMatch match;
    virCPUCheck check;
    virArch arch;
    char *model;
    char *vendor_id;    /* vendor id returned by CPUID in the guest */
    int fallback;       /* enum virCPUFallback */
    char *vendor;
    unsigned int microcodeVersion;
    unsigned int sockets;
    unsigned int dies;
    unsigned int cores;
    unsigned int threads;
    unsigned int sigFamily;
    unsigned int sigModel;
    unsigned int sigStepping;
    size_t nfeatures;
    size_t nfeatures_max;
    virCPUFeatureDef *features;
    virCPUCacheDef *cache;
    virCPUMaxPhysAddrDef *addr;
    virHostCPUTscInfo *tsc;
    virTristateSwitch migratable; /* for host-passthrough mode */
};

virCPUDef *virCPUDefNew(void);

void ATTRIBUTE_NONNULL(1)
virCPUDefFreeFeatures(virCPUDef *def);

void ATTRIBUTE_NONNULL(1)
virCPUDefFreeModel(virCPUDef *def);

void
virCPUDefRef(virCPUDef *def);
void
virCPUDefFree(virCPUDef *def);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCPUDef, virCPUDefFree);

void ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
virCPUDefCopyModel(virCPUDef *dst,
                   const virCPUDef *src,
                   bool resetPolicy);

/*
 * Returns true if feature @name should copied, false otherwise.
 */
typedef bool (*virCPUDefFeatureFilter)(const char *name,
                                       virCPUFeaturePolicy policy,
                                       void *opaque);

void
virCPUDefCopyModelFilter(virCPUDef *dst,
                         const virCPUDef *src,
                         bool resetPolicy,
                         virCPUDefFeatureFilter filter,
                         void *opaque)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void
virCPUDefStealModel(virCPUDef *dst,
                    virCPUDef *src,
                    bool keepVendor);

virCPUDef *
virCPUDefCopy(const virCPUDef *cpu)
    ATTRIBUTE_NONNULL(1);

virCPUDef *
virCPUDefCopyWithoutModel(const virCPUDef *cpu)
    ATTRIBUTE_NONNULL(1);

int
virCPUDefParseXMLString(const char *xml,
                        virCPUType type,
                        virCPUDef **cpu,
                        bool validateXML);

int
virCPUDefParseXML(xmlXPathContextPtr ctxt,
                  const char *xpath,
                  virCPUType mode,
                  virCPUDef **cpu,
                  bool validateXML);

bool
virCPUDefIsEqual(virCPUDef *src,
                 virCPUDef *dst,
                 bool reportError);

char *
virCPUDefFormat(virCPUDef *def,
                virDomainNuma *numa);

int
virCPUDefFormatBuf(virBuffer *buf,
                   virCPUDef *def);
int
virCPUDefFormatBufFull(virBuffer *buf,
                       virCPUDef *def,
                       virDomainNuma *numa);

int
virCPUDefAddFeature(virCPUDef *cpu,
                    const char *name,
                    int policy);

int
virCPUDefUpdateFeature(virCPUDef *cpu,
                       const char *name,
                       int policy);

int
virCPUDefAddFeatureIfMissing(virCPUDef *def,
                             const char *name,
                             int policy);

virCPUFeatureDef *
virCPUDefFindFeature(const virCPUDef *def,
                     const char *name);

int
virCPUDefFilterFeatures(virCPUDef *cpu,
                        virCPUDefFeatureFilter filter,
                        void *opaque);

int
virCPUDefCheckFeatures(virCPUDef *cpu,
                       virCPUDefFeatureFilter filter,
                       void *opaque,
                       char ***features);

virCPUDef **
virCPUDefListParse(const char **xmlCPUs,
                   unsigned int ncpus,
                   virCPUType cpuType);
void
virCPUDefListFree(virCPUDef **cpus);
