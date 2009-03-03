/*
 * capabilities.h: hypervisor capabilities
 *
 * Copyright (C) 2006-2008 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_CAPABILITIES_H
#define __VIR_CAPABILITIES_H

#include "internal.h"
#include "util.h"

typedef struct _virCapsGuestFeature virCapsGuestFeature;
typedef virCapsGuestFeature *virCapsGuestFeaturePtr;
struct _virCapsGuestFeature {
    char *name;
    int defaultOn;
    int toggle;
};

typedef struct _virCapsGuestDomainInfo virCapsGuestDomainInfo;
typedef virCapsGuestDomainInfo *virCapsGuestDomainInfoPtr;
struct _virCapsGuestDomainInfo {
    char *emulator;
    char *loader;
    int nmachines;
    char **machines;
};

typedef struct _virCapsGuestDomain virCapsGuestDomain;
typedef virCapsGuestDomain *virCapsGuestDomainPtr;
struct _virCapsGuestDomain {
    char *type;
    virCapsGuestDomainInfo info;
};

typedef struct _virCapsGuestArch virCapsGuestArch;
typedef virCapsGuestArch *virCapsGuestArchptr;
struct _virCapsGuestArch {
    char *name;
    int wordsize;
    virCapsGuestDomainInfo defaultInfo;
    int ndomains;
    virCapsGuestDomainPtr *domains;
};

typedef struct _virCapsGuest virCapsGuest;
typedef virCapsGuest *virCapsGuestPtr;
struct _virCapsGuest {
    char *ostype;
    virCapsGuestArch arch;
    int nfeatures;
    virCapsGuestFeaturePtr *features;
};

typedef struct _virCapsHostNUMACell virCapsHostNUMACell;
typedef virCapsHostNUMACell *virCapsHostNUMACellPtr;
struct _virCapsHostNUMACell {
    int num;
    int ncpus;
    int *cpus;
};

typedef struct _virCapsHostSecModel virCapsHostSecModel;
struct _virCapsHostSecModel {
    char *model;
    char *doi;
};

typedef struct _virCapsHost virCapsHost;
typedef virCapsHost *virCapsHostPtr;
struct _virCapsHost {
    char *arch;
    int nfeatures;
    char **features;
    int offlineMigrate;
    int liveMigrate;
    int nmigrateTrans;
    char **migrateTrans;
    int nnumaCell;
    virCapsHostNUMACellPtr *numaCell;
    virCapsHostSecModel secModel;
};

typedef struct _virCaps virCaps;
typedef virCaps* virCapsPtr;
struct _virCaps {
    virCapsHost host;
    int nguests;
    virCapsGuestPtr *guests;
    unsigned char macPrefix[VIR_MAC_PREFIX_BUFLEN];
};


extern virCapsPtr
virCapabilitiesNew(const char *arch,
                   int offlineMigrate,
                   int liveMigrate);

extern void
virCapabilitiesFree(virCapsPtr caps);

extern void
virCapabilitiesSetMacPrefix(virCapsPtr caps,
                            unsigned char *prefix);

extern void
virCapabilitiesGenerateMac(virCapsPtr caps,
                           unsigned char *mac);

extern int
virCapabilitiesAddHostFeature(virCapsPtr caps,
                              const char *name);

extern int
virCapabilitiesAddHostMigrateTransport(virCapsPtr caps,
                                       const char *name);


extern int
virCapabilitiesAddHostNUMACell(virCapsPtr caps,
                               int num,
                               int ncpus,
                               const int *cpus);



extern virCapsGuestPtr
virCapabilitiesAddGuest(virCapsPtr caps,
                        const char *ostype,
                        const char *arch,
                        int wordsize,
                        const char *emulator,
                        const char *loader,
                        int nmachines,
                        const char *const *machines);

extern virCapsGuestDomainPtr
virCapabilitiesAddGuestDomain(virCapsGuestPtr guest,
                              const char *hvtype,
                              const char *emulator,
                              const char *loader,
                              int nmachines,
                              const char *const *machines);

extern virCapsGuestFeaturePtr
virCapabilitiesAddGuestFeature(virCapsGuestPtr guest,
                               const char *name,
                               int defaultOn,
                               int toggle);

extern int
virCapabilitiesSupportsGuestOSType(virCapsPtr caps,
                                   const char *ostype);
extern int
virCapabilitiesSupportsGuestArch(virCapsPtr caps,
                                 const char *ostype,
                                 const char *arch);


extern const char *
virCapabilitiesDefaultGuestArch(virCapsPtr caps,
                                const char *ostype);
extern const char *
virCapabilitiesDefaultGuestMachine(virCapsPtr caps,
                                   const char *ostype,
                                   const char *arch);
extern const char *
virCapabilitiesDefaultGuestEmulator(virCapsPtr caps,
                                    const char *ostype,
                                    const char *arch,
                                    const char *domain);

extern char *
virCapabilitiesFormatXML(virCapsPtr caps);


#endif /* __VIR_CAPABILITIES_H */
