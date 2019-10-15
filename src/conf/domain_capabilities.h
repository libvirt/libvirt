/*
 * domain_capabilities.h: domain capabilities XML processing
 *
 * Copyright (C) 2014 Red Hat, Inc.
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
#include "domain_conf.h"
#include "virenum.h"

typedef const char * (*virDomainCapsValToStr)(int value);

typedef struct _virDomainCaps virDomainCaps;
typedef virDomainCaps *virDomainCapsPtr;

typedef struct _virDomainCapsEnum virDomainCapsEnum;
typedef virDomainCapsEnum *virDomainCapsEnumPtr;
struct _virDomainCapsEnum {
    bool report; /* Whether the format the enum at all */
    unsigned int values; /* Bitmask of values supported in the corresponding enum */
};

typedef struct _virDomainCapsStringValues virDomainCapsStringValues;
typedef virDomainCapsStringValues *virDomainCapsStringValuesPtr;
struct _virDomainCapsStringValues {
    char **values;  /* raw string values */
    size_t nvalues; /* number of strings */
};

typedef struct _virDomainCapsLoader virDomainCapsLoader;
typedef virDomainCapsLoader *virDomainCapsLoaderPtr;
struct _virDomainCapsLoader {
    virTristateBool supported;
    virDomainCapsStringValues values;   /* Info about values for the element */
    virDomainCapsEnum type;     /* Info about virDomainLoader */
    virDomainCapsEnum readonly; /* Info about readonly:virTristateBool */
    virDomainCapsEnum secure;   /* Info about secure:virTristateBool */
};

typedef struct _virDomainCapsOS virDomainCapsOS;
typedef virDomainCapsOS *virDomainCapsOSPtr;
struct _virDomainCapsOS {
    virTristateBool supported;
    virDomainCapsEnum firmware;     /* Info about virDomainOsDefFirmware */
    virDomainCapsLoader loader;     /* Info about virDomainLoaderDef */
};

typedef struct _virDomainCapsDeviceDisk virDomainCapsDeviceDisk;
typedef virDomainCapsDeviceDisk *virDomainCapsDeviceDiskPtr;
struct _virDomainCapsDeviceDisk {
    virTristateBool supported;
    virDomainCapsEnum diskDevice;   /* Info about virDomainDiskDevice enum values */
    virDomainCapsEnum bus;          /* Info about virDomainDiskBus enum values */
    virDomainCapsEnum model;        /* Info about virDomainDiskModel enum values */
    /* add new fields here */
};

typedef struct _virDomainCapsDeviceGraphics virDomainCapsDeviceGraphics;
typedef virDomainCapsDeviceGraphics *virDomainCapsDeviceGraphicsPtr;
struct _virDomainCapsDeviceGraphics {
    virTristateBool supported;
    virDomainCapsEnum type;   /* virDomainGraphicsType */
};

typedef struct _virDomainCapsDeviceVideo virDomainCapsDeviceVideo;
typedef virDomainCapsDeviceVideo *virDomainCapsDeviceVideoPtr;
struct _virDomainCapsDeviceVideo {
    virTristateBool supported;
    virDomainCapsEnum modelType;   /* virDomainVideoType */
};

typedef struct _virDomainCapsDeviceHostdev virDomainCapsDeviceHostdev;
typedef virDomainCapsDeviceHostdev *virDomainCapsDeviceHostdevPtr;
struct _virDomainCapsDeviceHostdev {
    virTristateBool supported;
    virDomainCapsEnum mode;             /* Info about virDomainHostdevMode */
    virDomainCapsEnum startupPolicy;    /* Info about virDomainStartupPolicy */
    virDomainCapsEnum subsysType;       /* Info about virDomainHostdevSubsysType */
    virDomainCapsEnum capsType;         /* Info about virDomainHostdevCapsType */
    virDomainCapsEnum pciBackend;       /* Info about virDomainHostdevSubsysPCIBackendType */
    /* add new fields here */
};

typedef struct _virDomainCapsDeviceRNG virDomainCapsDeviceRNG;
typedef virDomainCapsDeviceRNG *virDomainCapsDeviceRNGPtr;
struct _virDomainCapsDeviceRNG {
    virTristateBool supported;
    virDomainCapsEnum model;   /* virDomainRNGModel */
    virDomainCapsEnum backendModel;   /* virDomainRNGBackend */
};

typedef struct _virDomainCapsFeatureGIC virDomainCapsFeatureGIC;
typedef virDomainCapsFeatureGIC *virDomainCapsFeatureGICPtr;
struct _virDomainCapsFeatureGIC {
    virTristateBool supported;
    virDomainCapsEnum version; /* Info about virGICVersion */
};

typedef enum {
    VIR_DOMCAPS_CPU_USABLE_UNKNOWN,
    VIR_DOMCAPS_CPU_USABLE_YES,
    VIR_DOMCAPS_CPU_USABLE_NO,

    VIR_DOMCAPS_CPU_USABLE_LAST
} virDomainCapsCPUUsable;
VIR_ENUM_DECL(virDomainCapsCPUUsable);

typedef struct _virDomainCapsCPUModel virDomainCapsCPUModel;
typedef virDomainCapsCPUModel *virDomainCapsCPUModelPtr;
struct _virDomainCapsCPUModel {
    char *name;
    virDomainCapsCPUUsable usable;
    char **blockers; /* NULL-terminated list of usability blockers */
};

typedef struct _virDomainCapsCPUModels virDomainCapsCPUModels;
typedef virDomainCapsCPUModels *virDomainCapsCPUModelsPtr;
struct _virDomainCapsCPUModels {
    virObject parent;

    size_t nmodels_max;
    size_t nmodels;
    virDomainCapsCPUModelPtr models;
};

typedef struct _virDomainCapsCPU virDomainCapsCPU;
typedef virDomainCapsCPU *virDomainCapsCPUPtr;
struct _virDomainCapsCPU {
    bool hostPassthrough;
    virCPUDefPtr hostModel;
    virDomainCapsCPUModelsPtr custom;
};

typedef struct _virSEVCapability virSEVCapability;
typedef virSEVCapability *virSEVCapabilityPtr;
struct _virSEVCapability {
    char *pdh;
    char *cert_chain;
    unsigned int cbitpos;
    unsigned int reduced_phys_bits;
};

struct _virDomainCaps {
    virObjectLockable parent;

    char *path;                     /* path to emulator binary */
    virDomainVirtType virttype;     /* virtualization type */
    char *machine;                  /* machine type */
    virArch arch;                   /* domain architecture */

    /* Some machine specific info */
    int maxvcpus;
    virTristateBool iothreads;  /* Whether I/O threads are supported or not. */

    virDomainCapsOS os;
    virDomainCapsCPU cpu;
    virDomainCapsDeviceDisk disk;
    virDomainCapsDeviceGraphics graphics;
    virDomainCapsDeviceVideo video;
    virDomainCapsDeviceHostdev hostdev;
    virDomainCapsDeviceRNG rng;
    /* add new domain devices here */

    virDomainCapsFeatureGIC gic;
    virTristateBool vmcoreinfo;
    virTristateBool genid;
    virSEVCapabilityPtr sev;
    /* add new domain features here */
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virDomainCaps, virObjectUnref);


virDomainCapsPtr virDomainCapsNew(const char *path,
                                  const char *machine,
                                  virArch arch,
                                  virDomainVirtType virttype);

virDomainCapsCPUModelsPtr virDomainCapsCPUModelsNew(size_t nmodels);
virDomainCapsCPUModelsPtr virDomainCapsCPUModelsCopy(virDomainCapsCPUModelsPtr old);
virDomainCapsCPUModelsPtr virDomainCapsCPUModelsFilter(virDomainCapsCPUModelsPtr old,
                                                       const char **models,
                                                       const char **blacklist);
int virDomainCapsCPUModelsAddSteal(virDomainCapsCPUModelsPtr cpuModels,
                                   char **name,
                                   virDomainCapsCPUUsable usable,
                                   char ***blockers);
int virDomainCapsCPUModelsAdd(virDomainCapsCPUModelsPtr cpuModels,
                              const char *name,
                              ssize_t nameLen,
                              virDomainCapsCPUUsable usable,
                              char **blockers);
virDomainCapsCPUModelPtr
virDomainCapsCPUModelsGet(virDomainCapsCPUModelsPtr cpuModels,
                          const char *name);


#define VIR_DOMAIN_CAPS_ENUM_SET(capsEnum, ...) \
    do { \
        unsigned int __values[] = {__VA_ARGS__}; \
        size_t __nvalues = G_N_ELEMENTS(__values); \
        virDomainCapsEnumSet(&(capsEnum), #capsEnum, \
                             __nvalues, __values); \
    } while (0)


int virDomainCapsEnumSet(virDomainCapsEnumPtr capsEnum,
                         const char *capsEnumName,
                         size_t nvalues,
                         unsigned int *values);
void virDomainCapsEnumClear(virDomainCapsEnumPtr capsEnum);

char * virDomainCapsFormat(virDomainCapsPtr const caps);

int virDomainCapsDeviceDefValidate(virDomainCapsPtr const caps,
                                   const virDomainDeviceDef *dev,
                                   const virDomainDef *def);

void
virSEVCapabilitiesFree(virSEVCapability *capabilities);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSEVCapability, virSEVCapabilitiesFree);
