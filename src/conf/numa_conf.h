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
typedef virDomainNuma *virDomainNumaPtr;

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
    VIR_DOMAIN_CACHE_ASSOCIATIVITY_NONE,    /* No associativity */
    VIR_DOMAIN_CACHE_ASSOCIATIVITY_DIRECT,  /* Direct mapped cache */
    VIR_DOMAIN_CACHE_ASSOCIATIVITY_FULL,    /* Fully associative cache */

    VIR_DOMAIN_CACHE_ASSOCIATIVITY_LAST
} virDomainCacheAssociativity;
VIR_ENUM_DECL(virDomainCacheAssociativity);

typedef enum {
    VIR_DOMAIN_CACHE_POLICY_NONE,           /* No policy */
    VIR_DOMAIN_CACHE_POLICY_WRITEBACK,      /* Write-back policy */
    VIR_DOMAIN_CACHE_POLICY_WRITETHROUGH,   /* Write-through policy */

    VIR_DOMAIN_CACHE_POLICY_LAST
} virDomainCachePolicy;
VIR_ENUM_DECL(virDomainCachePolicy);

typedef enum {
    VIR_DOMAIN_NUMA_INTERCONNECT_TYPE_LATENCY,
    VIR_DOMAIN_NUMA_INTERCONNECT_TYPE_BANDWIDTH,
} virDomainNumaInterconnectType;

typedef enum {
    VIR_DOMAIN_MEMORY_LATENCY_NONE = 0, /* No memory latency defined */
    VIR_DOMAIN_MEMORY_LATENCY_ACCESS,   /* Access latency */
    VIR_DOMAIN_MEMORY_LATENCY_READ,     /* Read latency */
    VIR_DOMAIN_MEMORY_LATENCY_WRITE,    /* Write latency */

    VIR_DOMAIN_MEMORY_LATENCY_LAST
} virDomainMemoryLatency;
VIR_ENUM_DECL(virDomainMemoryLatency);


virDomainNumaPtr virDomainNumaNew(void);
void virDomainNumaFree(virDomainNumaPtr numa);

/*
 * XML Parse/Format functions
 */
int virDomainNumatuneParseXML(virDomainNumaPtr numa,
                              bool placement_static,
                              xmlXPathContextPtr ctxt)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);

int virDomainNumatuneFormatXML(virBufferPtr buf, virDomainNumaPtr numatune)
    ATTRIBUTE_NONNULL(1);

/*
 * Getters
 */
int virDomainNumatuneGetMode(virDomainNumaPtr numatune,
                             int cellid,
                             virDomainNumatuneMemMode *mode);

virBitmapPtr virDomainNumatuneGetNodeset(virDomainNumaPtr numatune,
                                         virBitmapPtr auto_nodeset,
                                         int cellid);

int virDomainNumatuneMaybeGetNodeset(virDomainNumaPtr numatune,
                                     virBitmapPtr auto_nodeset,
                                     virBitmapPtr *retNodeset,
                                     int cellid);

size_t virDomainNumaGetNodeCount(virDomainNumaPtr numa);

bool virDomainNumaNodeDistanceIsUsingDefaults(virDomainNumaPtr numa,
                                              size_t node,
                                              size_t sibling)
    ATTRIBUTE_NONNULL(1);
bool virDomainNumaNodesDistancesAreBeingSet(virDomainNumaPtr numa)
    ATTRIBUTE_NONNULL(1);
size_t virDomainNumaGetNodeDistance(virDomainNumaPtr numa,
                                    size_t node,
                                    size_t sibling)
    ATTRIBUTE_NONNULL(1);

virBitmapPtr virDomainNumaGetNodeCpumask(virDomainNumaPtr numa,
                                         size_t node)
    ATTRIBUTE_NONNULL(1);
virDomainMemoryAccess virDomainNumaGetNodeMemoryAccessMode(virDomainNumaPtr numa,
                                                      size_t node)
    ATTRIBUTE_NONNULL(1);
virTristateBool virDomainNumaGetNodeDiscard(virDomainNumaPtr numa,
                                            size_t node)
    ATTRIBUTE_NONNULL(1);
unsigned long long virDomainNumaGetNodeMemorySize(virDomainNumaPtr numa,
                                                  size_t node)
    ATTRIBUTE_NONNULL(1);
unsigned long long virDomainNumaGetMemorySize(virDomainNumaPtr numa)
    ATTRIBUTE_NONNULL(1);

unsigned int
virDomainNumaGetMaxCPUID(virDomainNumaPtr numa);

/*
 * Formatters
 */
char *virDomainNumatuneFormatNodeset(virDomainNumaPtr numatune,
                                     virBitmapPtr auto_nodeset,
                                     int cellid);

int virDomainNumatuneMaybeFormatNodeset(virDomainNumaPtr numatune,
                                        virBitmapPtr auto_nodeset,
                                        char **mask,
                                        int cellid);

/*
 * Setters
 */
int virDomainNumatuneSet(virDomainNumaPtr numa,
                         bool placement_static,
                         int placement,
                         int mode,
                         virBitmapPtr nodeset)
    ATTRIBUTE_NONNULL(1);

size_t virDomainNumaSetNodeCount(virDomainNumaPtr numa,
                                 size_t nmem_nodes)
    ATTRIBUTE_NONNULL(1);

void virDomainNumaSetNodeMemorySize(virDomainNumaPtr numa,
                                    size_t node,
                                    unsigned long long size)
    ATTRIBUTE_NONNULL(1);

int virDomainNumaSetNodeDistance(virDomainNumaPtr numa,
                                 size_t node,
                                 size_t sibling,
                                 unsigned int value)
    ATTRIBUTE_NONNULL(1);

size_t virDomainNumaSetNodeDistanceCount(virDomainNumaPtr numa,
                                         size_t node,
                                         size_t ndistances)
    ATTRIBUTE_NONNULL(1);

void  virDomainNumaSetNodeCpumask(virDomainNumaPtr numa,
                                  size_t node,
                                  virBitmapPtr cpumask)
    ATTRIBUTE_NONNULL(1);

/*
 * Other accessors
 */
bool virDomainNumaEquals(virDomainNumaPtr n1,
                         virDomainNumaPtr n2);

bool virDomainNumaCheckABIStability(virDomainNumaPtr src,
                                    virDomainNumaPtr tgt);

bool virDomainNumatuneHasPlacementAuto(virDomainNumaPtr numatune);

bool virDomainNumatuneHasPerNodeBinding(virDomainNumaPtr numatune);

int virDomainNumatuneSpecifiedMaxNode(virDomainNumaPtr numatune);

bool virDomainNumatuneNodesetIsAvailable(virDomainNumaPtr numatune,
                                         virBitmapPtr auto_nodeset);

bool virDomainNumatuneNodeSpecified(virDomainNumaPtr numatune,
                                    int cellid);

int virDomainNumaDefParseXML(virDomainNumaPtr def, xmlXPathContextPtr ctxt);
int virDomainNumaDefFormatXML(virBufferPtr buf, virDomainNumaPtr def);
int virDomainNumaDefValidate(const virDomainNuma *def);

unsigned int virDomainNumaGetCPUCountTotal(virDomainNumaPtr numa);

int virDomainNumaFillCPUsInNode(virDomainNumaPtr numa, size_t node,
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
                              virDomainCacheAssociativity *associativity,
                              virDomainCachePolicy *policy);

ssize_t virDomainNumaGetNodeInitiator(const virDomainNuma *numa,
                                      size_t node);

size_t virDomainNumaGetInterconnectsCount(const virDomainNuma *numa);

int virDomainNumaGetInterconnect(const virDomainNuma *numa,
                                 size_t i,
                                 virDomainNumaInterconnectType *type,
                                 unsigned int *initiator,
                                 unsigned int *target,
                                 unsigned int *cache,
                                 virDomainMemoryLatency *accessType,
                                 unsigned long *value);
