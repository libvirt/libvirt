/*
 * capabilities.h: hypervisor capabilities
 *
 * Copyright (C) 2006-2019 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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

#include "internal.h"
#include "virconftypes.h"
#include "cpu_conf.h"
#include "virarch.h"
#include "virobject.h"
#include "virresctrl.h"

#include <libxml/xpath.h>

typedef enum {
    VIR_CAPS_GUEST_FEATURE_TYPE_PAE = 0,
    VIR_CAPS_GUEST_FEATURE_TYPE_NONPAE,
    VIR_CAPS_GUEST_FEATURE_TYPE_IA64_BE,
    VIR_CAPS_GUEST_FEATURE_TYPE_ACPI,
    VIR_CAPS_GUEST_FEATURE_TYPE_APIC,
    VIR_CAPS_GUEST_FEATURE_TYPE_CPUSELECTION,
    VIR_CAPS_GUEST_FEATURE_TYPE_DEVICEBOOT,
    VIR_CAPS_GUEST_FEATURE_TYPE_DISKSNAPSHOT,
    VIR_CAPS_GUEST_FEATURE_TYPE_HAP,
    VIR_CAPS_GUEST_FEATURE_TYPE_EXTERNAL_SNAPSHOT,

    VIR_CAPS_GUEST_FEATURE_TYPE_LAST
} virCapsGuestFeatureType;

struct _virCapsGuestFeature {
    bool present;
    virTristateSwitch defaultOn;
    virTristateBool toggle;
};

struct _virCapsGuestMachine {
    char *name;
    char *canonical;
    unsigned int maxCpus;
    bool deprecated;
};

struct _virCapsGuestDomainInfo {
    char *emulator;
    char *loader;
    int nmachines;
    virCapsGuestMachine **machines;
};

struct _virCapsGuestDomain {
    int type; /* virDomainVirtType */
    virCapsGuestDomainInfo info;
};

struct _virCapsGuestArch {
    virArch id;
    unsigned int wordsize;
    virCapsGuestDomainInfo defaultInfo;
    size_t ndomains;
    size_t ndomains_max;
    virCapsGuestDomain **domains;
};

struct _virCapsGuest {
    int ostype;
    virCapsGuestArch arch;
    virCapsGuestFeature features[VIR_CAPS_GUEST_FEATURE_TYPE_LAST];
};

struct _virCapsHostNUMACellCPU {
    unsigned int id;
    unsigned int socket_id;
    unsigned int die_id;
    unsigned int core_id;
    virBitmap *siblings;
};

struct _virCapsHostNUMACellPageInfo {
    unsigned int size;      /* page size in kibibytes */
    unsigned long long avail;           /* the size of pool */
};

struct _virCapsHostNUMACell {
    int num;
    int ncpus;
    unsigned long long mem; /* in kibibytes */
    virCapsHostNUMACellCPU *cpus;
    size_t ndistances;
    virNumaDistance *distances;
    int npageinfo;
    virCapsHostNUMACellPageInfo *pageinfo;
    GArray *caches; /* virNumaCache */
};

struct _virCapsHostNUMA {
    gint refs;
    GPtrArray *cells;
    GArray *interconnects; /* virNumaInterconnect */
};

struct _virCapsHostSecModelLabel {
    char *type;
    char *label;
};

struct _virCapsHostSecModel {
    char *model;
    char *doi;
    size_t nlabels;
    virCapsHostSecModelLabel *labels;
};

struct _virCapsHostCacheBank {
    unsigned int id;
    unsigned int level; /* 1=L1, 2=L2, 3=L3, etc. */
    unsigned long long size; /* B */
    virCacheType type;  /* Data, Instruction or Unified */
    virBitmap *cpus;    /* All CPUs that share this bank */
    size_t ncontrols;
    virResctrlInfoPerCache **controls;
};

void virCapsHostCacheBankFree(virCapsHostCacheBank *ptr);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCapsHostCacheBank, virCapsHostCacheBankFree);

struct _virCapsHostCache {
    size_t nbanks;
    virCapsHostCacheBank **banks;

    virResctrlInfoMon *monitor;
};

struct _virCapsHostMemBWNode {
    unsigned int id;
    virBitmap *cpus;  /* All CPUs that belong to this node */
    virResctrlInfoMemBWPerNode control;
};

struct _virCapsHostMemBW {
    size_t nnodes;
    virCapsHostMemBWNode **nodes;

    virResctrlInfoMon *monitor;
};

struct _virCapsHost {
    virArch arch;
    size_t nfeatures;
    size_t nfeatures_max;
    char **features;
    unsigned int powerMgmt;    /* Bitmask of the PM capabilities.
                                * See enum virHostPMCapability.
                                */
    bool offlineMigrate;
    bool liveMigrate;
    size_t nmigrateTrans;
    size_t nmigrateTrans_max;
    char **migrateTrans;

    virCapsHostNUMA *numa;

    virResctrlInfo *resctrl;

    virCapsHostCache cache;

    virCapsHostMemBW memBW;

    size_t nsecModels;
    virCapsHostSecModel *secModels;

    char *netprefix;
    virCPUDef *cpu;
    int nPagesSize;             /* size of pagesSize array */
    unsigned int *pagesSize;    /* page sizes support on the system */
    unsigned char host_uuid[VIR_UUID_BUFLEN];
    bool iommu;
};

struct _virCapsStoragePool {
    int type;
};


struct _virCaps {
    virObject parent;

    virCapsHost host;
    size_t nguests;
    size_t nguests_max;
    virCapsGuest **guests;

    size_t npools;
    size_t npools_max;
    virCapsStoragePool **pools;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCaps, virObjectUnref);


struct _virCapsDomainData {
    int ostype;
    int arch;
    int domaintype; /* virDomainVirtType */
    const char *emulator;
    const char *machinetype;
};


virCaps *
virCapabilitiesNew(virArch hostarch,
                   bool offlineMigrate,
                   bool liveMigrate);

void
virCapabilitiesHostNUMAUnref(virCapsHostNUMA *caps);
void
virCapabilitiesHostNUMARef(virCapsHostNUMA *caps);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCapsHostNUMA, virCapabilitiesHostNUMAUnref);

int
virCapabilitiesAddHostFeature(virCaps *caps,
                              const char *name);

int
virCapabilitiesAddHostMigrateTransport(virCaps *caps,
                                       const char *name);

int
virCapabilitiesSetNetPrefix(virCaps *caps,
                            const char *prefix);

void
virCapabilitiesHostNUMAAddCell(virCapsHostNUMA *caps,
                               int num,
                               unsigned long long mem,
                               int ncpus,
                               virCapsHostNUMACellCPU **cpus,
                               int ndistances,
                               virNumaDistance **distances,
                               int npageinfo,
                               virCapsHostNUMACellPageInfo **pageinfo,
                               GArray **caches);

virCapsGuestMachine **
virCapabilitiesAllocMachines(const char *const *names,
                             int *nnames);

void
virCapabilitiesFreeGuest(virCapsGuest *guest);

virCapsGuest *
virCapabilitiesAddGuest(virCaps *caps,
                        int ostype,
                        virArch arch,
                        const char *emulator,
                        const char *loader,
                        int nmachines,
                        virCapsGuestMachine **machines);

virCapsGuestDomain *
virCapabilitiesAddGuestDomain(virCapsGuest *guest,
                              int hvtype,
                              const char *emulator,
                              const char *loader,
                              int nmachines,
                              virCapsGuestMachine **machines);

void
virCapabilitiesAddGuestFeature(virCapsGuest *guest,
                               virCapsGuestFeatureType feature);
void
virCapabilitiesAddGuestFeatureWithToggle(virCapsGuest *guest,
                                         virCapsGuestFeatureType feature,
                                         bool defaultOn,
                                         bool toggle);

int
virCapabilitiesAddStoragePool(virCaps *caps,
                              int poolType);

int
virCapabilitiesHostSecModelAddBaseLabel(virCapsHostSecModel *secmodel,
                                        const char *type,
                                        const char *label);

virCapsDomainData *
virCapabilitiesDomainDataLookup(virCaps *caps,
                                int ostype,
                                virArch arch,
                                int domaintype,
                                const char *emulator,
                                const char *machinetype);

bool
virCapabilitiesDomainSupported(virCaps *caps,
                               int ostype,
                               virArch arch,
                               int domaintype);


void
virCapabilitiesClearHostNUMACellCPUTopology(virCapsHostNUMACellCPU *cpu,
                                            size_t ncpus);

char *
virCapabilitiesFormatXML(virCaps *caps);

virBitmap *virCapabilitiesHostNUMAGetCpus(virCapsHostNUMA *caps,
                                            virBitmap *nodemask);

int virCapabilitiesHostNUMAGetMaxNode(virCapsHostNUMA *caps);

int virCapabilitiesGetNodeInfo(virNodeInfoPtr nodeinfo);

int virCapabilitiesInitPages(virCaps *caps);

virCapsHostNUMA *virCapabilitiesHostNUMANew(void);
virCapsHostNUMA *virCapabilitiesHostNUMANewHost(void);

bool virCapsHostCacheBankEquals(virCapsHostCacheBank *a,
                                virCapsHostCacheBank *b);
void virCapsHostCacheBankFree(virCapsHostCacheBank *ptr);

int virCapabilitiesInitCaches(virCaps *caps);

void virCapabilitiesHostInitIOMMU(virCaps *caps);
