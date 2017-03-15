/*
 * capabilities.h: hypervisor capabilities
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_CAPABILITIES_H
# define __VIR_CAPABILITIES_H

# include "internal.h"
# include "virbuffer.h"
# include "cpu_conf.h"
# include "virarch.h"
# include "virmacaddr.h"
# include "virobject.h"

# include <libxml/xpath.h>

typedef struct _virCapsGuestFeature virCapsGuestFeature;
typedef virCapsGuestFeature *virCapsGuestFeaturePtr;
struct _virCapsGuestFeature {
    char *name;
    bool defaultOn;
    bool toggle;
};

typedef struct _virCapsGuestMachine virCapsGuestMachine;
typedef virCapsGuestMachine *virCapsGuestMachinePtr;
struct _virCapsGuestMachine {
    char *name;
    char *canonical;
    unsigned int maxCpus;
};

typedef struct _virCapsGuestDomainInfo virCapsGuestDomainInfo;
typedef virCapsGuestDomainInfo *virCapsGuestDomainInfoPtr;
struct _virCapsGuestDomainInfo {
    char *emulator;
    char *loader;
    int nmachines;
    virCapsGuestMachinePtr *machines;
};

typedef struct _virCapsGuestDomain virCapsGuestDomain;
typedef virCapsGuestDomain *virCapsGuestDomainPtr;
struct _virCapsGuestDomain {
    int type; /* virDomainVirtType */
    virCapsGuestDomainInfo info;
};

typedef struct _virCapsGuestArch virCapsGuestArch;
typedef virCapsGuestArch *virCapsGuestArchptr;
struct _virCapsGuestArch {
    virArch id;
    unsigned int wordsize;
    virCapsGuestDomainInfo defaultInfo;
    size_t ndomains;
    size_t ndomains_max;
    virCapsGuestDomainPtr *domains;
};

typedef struct _virCapsGuest virCapsGuest;
typedef virCapsGuest *virCapsGuestPtr;
struct _virCapsGuest {
    int ostype;
    virCapsGuestArch arch;
    size_t nfeatures;
    size_t nfeatures_max;
    virCapsGuestFeaturePtr *features;
};

typedef struct _virCapsHostNUMACellCPU virCapsHostNUMACellCPU;
typedef virCapsHostNUMACellCPU *virCapsHostNUMACellCPUPtr;
struct _virCapsHostNUMACellCPU {
    unsigned int id;
    unsigned int socket_id;
    unsigned int core_id;
    virBitmapPtr siblings;
};

typedef struct _virCapsHostNUMACellSiblingInfo virCapsHostNUMACellSiblingInfo;
typedef virCapsHostNUMACellSiblingInfo *virCapsHostNUMACellSiblingInfoPtr;
struct _virCapsHostNUMACellSiblingInfo {
    int node;               /* foreign NUMA node */
    unsigned int distance;  /* distance to the node */
};

typedef struct _virCapsHostNUMACellPageInfo virCapsHostNUMACellPageInfo;
typedef virCapsHostNUMACellPageInfo *virCapsHostNUMACellPageInfoPtr;
struct _virCapsHostNUMACellPageInfo {
    unsigned int size;      /* page size in kibibytes */
    size_t avail;           /* the size of pool */
};

typedef struct _virCapsHostNUMACell virCapsHostNUMACell;
typedef virCapsHostNUMACell *virCapsHostNUMACellPtr;
struct _virCapsHostNUMACell {
    int num;
    int ncpus;
    unsigned long long mem; /* in kibibytes */
    virCapsHostNUMACellCPUPtr cpus;
    int nsiblings;
    virCapsHostNUMACellSiblingInfoPtr siblings;
    int npageinfo;
    virCapsHostNUMACellPageInfoPtr pageinfo;
};

typedef struct _virCapsHostSecModelLabel virCapsHostSecModelLabel;
typedef virCapsHostSecModelLabel *virCapsHostSecModelLabelPtr;
struct _virCapsHostSecModelLabel {
    char *type;
    char *label;
};

typedef struct _virCapsHostSecModel virCapsHostSecModel;
typedef virCapsHostSecModel *virCapsHostSecModelPtr;
struct _virCapsHostSecModel {
    char *model;
    char *doi;
    size_t nlabels;
    virCapsHostSecModelLabelPtr labels;
};

typedef struct _virCapsHost virCapsHost;
typedef virCapsHost *virCapsHostPtr;
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
    size_t nnumaCell;
    size_t nnumaCell_max;
    virCapsHostNUMACellPtr *numaCell;

    size_t nsecModels;
    virCapsHostSecModelPtr secModels;

    char *netprefix;
    virCPUDefPtr cpu;
    int nPagesSize;             /* size of pagesSize array */
    unsigned int *pagesSize;    /* page sizes support on the system */
    unsigned char host_uuid[VIR_UUID_BUFLEN];
};

typedef int (*virDomainDefNamespaceParse)(xmlDocPtr, xmlNodePtr,
                                          xmlXPathContextPtr, void **);
typedef void (*virDomainDefNamespaceFree)(void *);
typedef int (*virDomainDefNamespaceXMLFormat)(virBufferPtr, void *);
typedef const char *(*virDomainDefNamespaceHref)(void);

typedef struct _virDomainXMLNamespace virDomainXMLNamespace;
typedef virDomainXMLNamespace *virDomainXMLNamespacePtr;
struct _virDomainXMLNamespace {
    virDomainDefNamespaceParse parse;
    virDomainDefNamespaceFree free;
    virDomainDefNamespaceXMLFormat format;
    virDomainDefNamespaceHref href;
};

typedef struct _virCaps virCaps;
typedef virCaps *virCapsPtr;
struct _virCaps {
    virObject parent;

    virCapsHost host;
    size_t nguests;
    size_t nguests_max;
    virCapsGuestPtr *guests;
};

typedef struct _virCapsDomainData virCapsDomainData;
typedef virCapsDomainData *virCapsDomainDataPtr;
struct _virCapsDomainData {
    int ostype;
    int arch;
    int domaintype; /* virDomainVirtType */
    const char *emulator;
    const char *machinetype;
};


virCapsPtr
virCapabilitiesNew(virArch hostarch,
                   bool offlineMigrate,
                   bool liveMigrate);

void
virCapabilitiesFreeNUMAInfo(virCapsPtr caps);

int
virCapabilitiesAddHostFeature(virCapsPtr caps,
                              const char *name);

int
virCapabilitiesAddHostMigrateTransport(virCapsPtr caps,
                                       const char *name);

int
virCapabilitiesSetNetPrefix(virCapsPtr caps,
                            const char *prefix);

int
virCapabilitiesAddHostNUMACell(virCapsPtr caps,
                               int num,
                               unsigned long long mem,
                               int ncpus,
                               virCapsHostNUMACellCPUPtr cpus,
                               int nsiblings,
                               virCapsHostNUMACellSiblingInfoPtr siblings,
                               int npageinfo,
                               virCapsHostNUMACellPageInfoPtr pageinfo);


int
virCapabilitiesSetHostCPU(virCapsPtr caps,
                          virCPUDefPtr cpu);


virCapsGuestMachinePtr *
virCapabilitiesAllocMachines(const char *const *names,
                             int nnames);
void
virCapabilitiesFreeMachines(virCapsGuestMachinePtr *machines,
                            int nmachines);

void
virCapabilitiesFreeGuest(virCapsGuestPtr guest);

virCapsGuestPtr
virCapabilitiesAddGuest(virCapsPtr caps,
                        int ostype,
                        virArch arch,
                        const char *emulator,
                        const char *loader,
                        int nmachines,
                        virCapsGuestMachinePtr *machines);

virCapsGuestDomainPtr
virCapabilitiesAddGuestDomain(virCapsGuestPtr guest,
                              int hvtype,
                              const char *emulator,
                              const char *loader,
                              int nmachines,
                              virCapsGuestMachinePtr *machines);

virCapsGuestFeaturePtr
virCapabilitiesAddGuestFeature(virCapsGuestPtr guest,
                               const char *name,
                               bool defaultOn,
                               bool toggle);

int
virCapabilitiesHostSecModelAddBaseLabel(virCapsHostSecModelPtr secmodel,
                                        const char *type,
                                        const char *label);

virCapsDomainDataPtr
virCapabilitiesDomainDataLookup(virCapsPtr caps,
                                int ostype,
                                virArch arch,
                                int domaintype,
                                const char *emulator,
                                const char *machinetype);

void
virCapabilitiesClearHostNUMACellCPUTopology(virCapsHostNUMACellCPUPtr cpu,
                                            size_t ncpus);

char *
virCapabilitiesFormatXML(virCapsPtr caps);

virBitmapPtr virCapabilitiesGetCpusForNodemask(virCapsPtr caps,
                                               virBitmapPtr nodemask);

#endif /* __VIR_CAPABILITIES_H */
