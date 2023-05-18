/*
 * numa_conf.h
 *
 * Copyright (C) 2014-2015 Red Hat, Inc.
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

#include <libxml/xpath.h>

#include "internal.h"
#include "virbitmap.h"
#include "virbuffer.h"
#include "virenum.h"


typedef struct _virDomainNuma virDomainNuma;

typedef enum {
    VIR_DOMAIN_NUMATUNE_PLACEMENT_DEFAULT = 0,
    VIR_DOMAIN_NUMATUNE_PLACEMENT_STATIC,
    VIR_DOMAIN_NUMATUNE_PLACEMENT_AUTO,

    VIR_DOMAIN_NUMATUNE_PLACEMENT_LAST
} virDomainNumatunePlacement;

VIR_ENUM_DECL(virDomainNumatunePlacement);
VIR_ENUM_DECL(virDomainNumatuneMemMode);

typedef enum {
    VIR_DOMAIN_MEMORY_ACCESS_DEFAULT = 0,  /*  No memory access defined */
    VIR_DOMAIN_MEMORY_ACCESS_SHARED,    /* Memory access is set as shared */
    VIR_DOMAIN_MEMORY_ACCESS_PRIVATE,   /* Memory access is set as private */

    VIR_DOMAIN_MEMORY_ACCESS_LAST,
} virDomainMemoryAccess;
VIR_ENUM_DECL(virDomainMemoryAccess);

typedef enum {
    VIR_NUMA_CACHE_ASSOCIATIVITY_NONE,    /* No associativity */
    VIR_NUMA_CACHE_ASSOCIATIVITY_DIRECT,  /* Direct mapped cache */
    VIR_NUMA_CACHE_ASSOCIATIVITY_FULL,    /* Fully associative cache */

    VIR_NUMA_CACHE_ASSOCIATIVITY_LAST
} virNumaCacheAssociativity;
VIR_ENUM_DECL(virNumaCacheAssociativity);

typedef enum {
    VIR_NUMA_CACHE_POLICY_NONE,           /* No policy */
    VIR_NUMA_CACHE_POLICY_WRITEBACK,      /* Write-back policy */
    VIR_NUMA_CACHE_POLICY_WRITETHROUGH,   /* Write-through policy */

    VIR_NUMA_CACHE_POLICY_LAST
} virNumaCachePolicy;
VIR_ENUM_DECL(virNumaCachePolicy);

typedef enum {
    VIR_NUMA_INTERCONNECT_TYPE_LATENCY,
    VIR_NUMA_INTERCONNECT_TYPE_BANDWIDTH,
} virNumaInterconnectType;

typedef enum {
    VIR_MEMORY_LATENCY_NONE = 0, /* No memory latency defined */
    VIR_MEMORY_LATENCY_ACCESS,   /* Access latency */
    VIR_MEMORY_LATENCY_READ,     /* Read latency */
    VIR_MEMORY_LATENCY_WRITE,    /* Write latency */

    VIR_MEMORY_LATENCY_LAST
} virMemoryLatency;
VIR_ENUM_DECL(virMemoryLatency);


virDomainNuma *virDomainNumaNew(void);
void virDomainNumaFree(virDomainNuma *numa);

/*
 * XML Parse/Format functions
 */
int virDomainNumatuneParseXML(virDomainNuma *numa,
                              bool placement_static,
                              xmlXPathContextPtr ctxt)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);

int virDomainNumatuneFormatXML(virBuffer *buf, virDomainNuma *numatune)
    ATTRIBUTE_NONNULL(1);

/*
 * Getters
 */
int virDomainNumatuneGetMode(virDomainNuma *numatune,
                             int cellid,
                             virDomainNumatuneMemMode *mode);

virBitmap *virDomainNumatuneGetNodeset(virDomainNuma *numatune,
                                         virBitmap *auto_nodeset,
                                         int cellid);

int virDomainNumatuneMaybeGetNodeset(virDomainNuma *numatune,
                                     virBitmap *auto_nodeset,
                                     virBitmap **retNodeset,
                                     int cellid);

size_t virDomainNumaGetNodeCount(virDomainNuma *numa);

bool virDomainNumaNodeDistanceIsUsingDefaults(virDomainNuma *numa,
                                              size_t node,
                                              size_t sibling)
    ATTRIBUTE_NONNULL(1);
bool virDomainNumaNodesDistancesAreBeingSet(virDomainNuma *numa)
    ATTRIBUTE_NONNULL(1);
size_t virDomainNumaGetNodeDistance(virDomainNuma *numa,
                                    size_t node,
                                    size_t sibling)
    ATTRIBUTE_NONNULL(1);

virBitmap *virDomainNumaGetNodeCpumask(virDomainNuma *numa,
                                         size_t node)
    ATTRIBUTE_NONNULL(1);
virDomainMemoryAccess virDomainNumaGetNodeMemoryAccessMode(virDomainNuma *numa,
                                                      size_t node)
    ATTRIBUTE_NONNULL(1);
virTristateBool virDomainNumaGetNodeDiscard(virDomainNuma *numa,
                                            size_t node)
    ATTRIBUTE_NONNULL(1);
unsigned long long virDomainNumaGetNodeMemorySize(virDomainNuma *numa,
                                                  size_t node)
    ATTRIBUTE_NONNULL(1);
unsigned long long virDomainNumaGetMemorySize(virDomainNuma *numa)
    ATTRIBUTE_NONNULL(1);

unsigned int
virDomainNumaGetMaxCPUID(virDomainNuma *numa);

/*
 * Formatters
 */
char *virDomainNumatuneFormatNodeset(virDomainNuma *numatune,
                                     virBitmap *auto_nodeset,
                                     int cellid);

int virDomainNumatuneMaybeFormatNodeset(virDomainNuma *numatune,
                                        virBitmap *auto_nodeset,
                                        char **mask,
                                        int cellid);

/*
 * Setters
 */
int virDomainNumatuneSet(virDomainNuma *numa,
                         bool placement_static,
                         int placement,
                         int mode,
                         virBitmap *nodeset)
    ATTRIBUTE_NONNULL(1);

size_t virDomainNumaSetNodeCount(virDomainNuma *numa,
                                 size_t nmem_nodes)
    ATTRIBUTE_NONNULL(1);

void virDomainNumaSetNodeMemorySize(virDomainNuma *numa,
                                    size_t node,
                                    unsigned long long size)
    ATTRIBUTE_NONNULL(1);

int virDomainNumaSetNodeDistance(virDomainNuma *numa,
                                 size_t node,
                                 size_t sibling,
                                 unsigned int value)
    ATTRIBUTE_NONNULL(1);

size_t virDomainNumaSetNodeDistanceCount(virDomainNuma *numa,
                                         size_t node,
                                         size_t ndistances)
    ATTRIBUTE_NONNULL(1);

void  virDomainNumaSetNodeCpumask(virDomainNuma *numa,
                                  size_t node,
                                  virBitmap *cpumask)
    ATTRIBUTE_NONNULL(1);

/*
 * Other accessors
 */
bool virDomainNumaEquals(virDomainNuma *n1,
                         virDomainNuma *n2);

bool virDomainNumaCheckABIStability(virDomainNuma *src,
                                    virDomainNuma *tgt);

bool virDomainNumatuneHasPlacementAuto(virDomainNuma *numatune);

bool virDomainNumatuneHasPerNodeBinding(virDomainNuma *numatune);

int virDomainNumatuneSpecifiedMaxNode(virDomainNuma *numatune);

bool virDomainNumatuneNodesetIsAvailable(virDomainNuma *numatune,
                                         virBitmap *auto_nodeset);

bool virDomainNumatuneNodeSpecified(const virDomainNuma *numatune,
                                    int cellid);

int virDomainNumaDefParseXML(virDomainNuma *def, xmlXPathContextPtr ctxt);
int virDomainNumaDefFormatXML(virBuffer *buf, virDomainNuma *def);
int virDomainNumaDefValidate(const virDomainNuma *def);

unsigned int virDomainNumaGetCPUCountTotal(virDomainNuma *numa);

int virDomainNumaFillCPUsInNode(virDomainNuma *numa, size_t node,
                                unsigned int maxCpus);

bool virDomainNumaHasHMAT(const virDomainNuma *numa);

size_t virDomainNumaGetNodeCacheCount(const virDomainNuma *numa,
                                       size_t node);

int virDomainNumaGetNodeCache(const virDomainNuma *numa,
                              size_t node,
                              size_t cache,
                              unsigned int *level,
                              unsigned int *size,
                              unsigned int *line,
                              virNumaCacheAssociativity *associativity,
                              virNumaCachePolicy *policy);

ssize_t virDomainNumaGetNodeInitiator(const virDomainNuma *numa,
                                      size_t node);

size_t virDomainNumaGetInterconnectsCount(const virDomainNuma *numa);

int virDomainNumaGetInterconnect(const virDomainNuma *numa,
                                 size_t i,
                                 virNumaInterconnectType *type,
                                 unsigned int *initiator,
                                 unsigned int *target,
                                 unsigned int *cache,
                                 virMemoryLatency *accessType,
                                 unsigned long *value);

typedef struct _virNumaDistance virNumaDistance;
struct _virNumaDistance {
    unsigned int value; /* locality value for node i->j or j->i */
    unsigned int cellid;
};

void virNumaDistanceFormat(virBuffer *buf,
                           const virNumaDistance *distances,
                           size_t ndistances);

typedef struct _virNumaCache virNumaCache;
struct _virNumaCache {
    unsigned int level; /* cache level */
    unsigned long long size;  /* cache size */
    unsigned int line;  /* line size, !!! in bytes !!! */
    virNumaCacheAssociativity associativity; /* cache associativity */
    virNumaCachePolicy policy; /* cache policy */
};

void virNumaCacheFormat(virBuffer *buf,
                        const virNumaCache *caches,
                        size_t ncaches);

typedef struct _virNumaInterconnect virNumaInterconnect;
struct _virNumaInterconnect {
    virNumaInterconnectType type;  /* whether structure describes latency
                                      or bandwidth */
    unsigned int initiator; /* the initiator NUMA node */
    unsigned int target;    /* the target NUMA node */
    unsigned int cache;     /* the target cache on @target; if 0 then the
                               memory on @target */
    virMemoryLatency accessType;  /* what type of access is defined */
    unsigned long value;    /* value itself */
};

void virNumaInterconnectFormat(virBuffer *buf,
                               const virNumaInterconnect *interconnects,
                               size_t ninterconnects);
