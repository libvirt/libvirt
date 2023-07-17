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

typedef struct _virDomainCapsEnum virDomainCapsEnum;
struct _virDomainCapsEnum {
    bool report; /* Whether the format the enum at all */
    unsigned int values; /* Bitmask of values supported in the corresponding enum */
};

#define STATIC_ASSERT_ENUM(last) \
    G_STATIC_ASSERT(last <= sizeof(unsigned int) * CHAR_BIT)

typedef struct _virDomainCapsStringValues virDomainCapsStringValues;
struct _virDomainCapsStringValues {
    char **values;  /* raw string values */
    size_t nvalues; /* number of strings */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_LOADER_TYPE_LAST);
STATIC_ASSERT_ENUM(VIR_TRISTATE_BOOL_LAST);
typedef struct _virDomainCapsLoader virDomainCapsLoader;
struct _virDomainCapsLoader {
    virTristateBool supported;
    virDomainCapsStringValues values;   /* Info about values for the element */
    virDomainCapsEnum type;     /* Info about virDomainLoader */
    virDomainCapsEnum readonly; /* Info about readonly:virTristateBool */
    virDomainCapsEnum secure;   /* Info about secure:virTristateBool */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_OS_DEF_FIRMWARE_LAST);
typedef struct _virDomainCapsOS virDomainCapsOS;
struct _virDomainCapsOS {
    virTristateBool supported;
    virDomainCapsEnum firmware;     /* Info about virDomainOsDefFirmware */
    virDomainCapsLoader loader;     /* Info about virDomainLoaderDef */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_MEMORY_SOURCE_LAST);
typedef struct _virDomainCapsMemoryBacking virDomainCapsMemoryBacking;
struct _virDomainCapsMemoryBacking {
    virTristateBool supported;
    virDomainCapsEnum sourceType; /* virDomainMemorySource */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_DISK_DEVICE_LAST);
STATIC_ASSERT_ENUM(VIR_DOMAIN_DISK_BUS_LAST);
STATIC_ASSERT_ENUM(VIR_DOMAIN_DISK_MODEL_LAST);
typedef struct _virDomainCapsDeviceDisk virDomainCapsDeviceDisk;
struct _virDomainCapsDeviceDisk {
    virTristateBool supported;
    virDomainCapsEnum diskDevice;   /* Info about virDomainDiskDevice enum values */
    virDomainCapsEnum bus;          /* Info about virDomainDiskBus enum values */
    virDomainCapsEnum model;        /* Info about virDomainDiskModel enum values */
    /* add new fields here */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_GRAPHICS_TYPE_LAST);
typedef struct _virDomainCapsDeviceGraphics virDomainCapsDeviceGraphics;
struct _virDomainCapsDeviceGraphics {
    virTristateBool supported;
    virDomainCapsEnum type;   /* virDomainGraphicsType */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_VIDEO_TYPE_LAST);
typedef struct _virDomainCapsDeviceVideo virDomainCapsDeviceVideo;
struct _virDomainCapsDeviceVideo {
    virTristateBool supported;
    virDomainCapsEnum modelType;   /* virDomainVideoType */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_HOSTDEV_MODE_LAST);
STATIC_ASSERT_ENUM(VIR_DOMAIN_STARTUP_POLICY_LAST);
STATIC_ASSERT_ENUM(VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST);
STATIC_ASSERT_ENUM(VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST);
STATIC_ASSERT_ENUM(VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST);
typedef struct _virDomainCapsDeviceHostdev virDomainCapsDeviceHostdev;
struct _virDomainCapsDeviceHostdev {
    virTristateBool supported;
    virDomainCapsEnum mode;             /* Info about virDomainHostdevMode */
    virDomainCapsEnum startupPolicy;    /* Info about virDomainStartupPolicy */
    virDomainCapsEnum subsysType;       /* Info about virDomainHostdevSubsysType */
    virDomainCapsEnum capsType;         /* Info about virDomainHostdevCapsType */
    virDomainCapsEnum pciBackend;       /* Info about virDomainHostdevSubsysPCIBackendType */
    /* add new fields here */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_RNG_MODEL_LAST);
STATIC_ASSERT_ENUM(VIR_DOMAIN_RNG_BACKEND_LAST);
typedef struct _virDomainCapsDeviceRNG virDomainCapsDeviceRNG;
struct _virDomainCapsDeviceRNG {
    virTristateBool supported;
    virDomainCapsEnum model;   /* virDomainRNGModel */
    virDomainCapsEnum backendModel;   /* virDomainRNGBackend */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_TPM_MODEL_LAST);
STATIC_ASSERT_ENUM(VIR_DOMAIN_TPM_TYPE_LAST);
typedef struct _virDomainCapsDeviceTPM virDomainCapsDeviceTPM;
struct _virDomainCapsDeviceTPM {
    virTristateBool supported;
    virDomainCapsEnum model;   /* virDomainTPMModel */
    virDomainCapsEnum backendModel;   /* virDomainTPMBackendType */
    virDomainCapsEnum backendVersion; /* virDomainTPMVersion */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_REDIRDEV_BUS_LAST);
typedef struct _virDomainCapsDeviceRedirdev virDomainCapsDeviceRedirdev;
struct _virDomainCapsDeviceRedirdev {
    virTristateBool supported;
    virDomainCapsEnum bus;   /* virDomainRedirdevBus */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_CHR_TYPE_LAST);
typedef struct _virDomainCapsDeviceChannel virDomainCapsDeviceChannel;
struct _virDomainCapsDeviceChannel {
    virTristateBool supported;
    virDomainCapsEnum type;   /* virDomainChrType */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_FS_DRIVER_TYPE_LAST);
typedef struct _virDomainCapsDeviceFilesystem virDomainCapsDeviceFilesystem;
struct _virDomainCapsDeviceFilesystem {
    virTristateBool supported;
    virDomainCapsEnum driverType; /* virDomainFSDriverType */
};

STATIC_ASSERT_ENUM(VIR_GIC_VERSION_LAST);
typedef struct _virDomainCapsFeatureGIC virDomainCapsFeatureGIC;
struct _virDomainCapsFeatureGIC {
    virTristateBool supported;
    virDomainCapsEnum version; /* Info about virGICVersion */
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_HYPERV_LAST);
typedef struct _virDomainCapsFeatureHyperv virDomainCapsFeatureHyperv;
struct _virDomainCapsFeatureHyperv {
    virTristateBool supported;
    virDomainCapsEnum features; /* Info about supported virDomainHyperv features */
};

typedef enum {
    VIR_DOMCAPS_CPU_USABLE_UNKNOWN,
    VIR_DOMCAPS_CPU_USABLE_YES,
    VIR_DOMCAPS_CPU_USABLE_NO,

    VIR_DOMCAPS_CPU_USABLE_LAST
} virDomainCapsCPUUsable;
VIR_ENUM_DECL(virDomainCapsCPUUsable);

typedef struct _virDomainCapsCPUModel virDomainCapsCPUModel;
struct _virDomainCapsCPUModel {
    char *name;
    virDomainCapsCPUUsable usable;
    char **blockers; /* NULL-terminated list of usability blockers */
    bool deprecated;
    char *vendor;
};

typedef struct _virDomainCapsCPUModels virDomainCapsCPUModels;
struct _virDomainCapsCPUModels {
    virObject parent;

    size_t nmodels_max;
    size_t nmodels;
    virDomainCapsCPUModel *models;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virDomainCapsCPUModels, virObjectUnref);

typedef struct _virDomainCapsCPU virDomainCapsCPU;
struct _virDomainCapsCPU {
    bool hostPassthrough;
    virDomainCapsEnum hostPassthroughMigratable;
    bool maximum;
    virDomainCapsEnum maximumMigratable;
    virCPUDef *hostModel;
    virDomainCapsCPUModels *custom;
};

typedef struct _virSEVCapability virSEVCapability;
struct _virSEVCapability {
    char *pdh;
    char *cert_chain;
    char *cpu0_id;
    unsigned int cbitpos;
    unsigned int reduced_phys_bits;
    unsigned int max_guests;
    unsigned int max_es_guests;
};

typedef struct _virSGXSection virSGXSection;
struct _virSGXSection {
    unsigned long long size;
    unsigned int node;
};

typedef struct _virSGXCapability virSGXCapability;
struct _virSGXCapability {
    bool flc;
    bool sgx1;
    bool sgx2;
    unsigned long long section_size;
    size_t nSgxSections;
    virSGXSection *sgxSections;
};

STATIC_ASSERT_ENUM(VIR_DOMAIN_CRYPTO_MODEL_LAST);
STATIC_ASSERT_ENUM(VIR_DOMAIN_CRYPTO_TYPE_LAST);
STATIC_ASSERT_ENUM(VIR_DOMAIN_CRYPTO_BACKEND_LAST);
typedef struct _virDomainCapsDeviceCrypto virDomainCapsDeviceCrypto;
struct _virDomainCapsDeviceCrypto {
    virTristateBool supported;
    virDomainCapsEnum model;   /* virDomainCryptoModel */
    virDomainCapsEnum type;   /* virDomainCryptoType */
    virDomainCapsEnum backendModel;   /* virDomainCryptoBackend */
};

typedef enum {
    VIR_DOMAIN_CAPS_FEATURE_IOTHREADS = 0,
    VIR_DOMAIN_CAPS_FEATURE_VMCOREINFO,
    VIR_DOMAIN_CAPS_FEATURE_GENID,
    VIR_DOMAIN_CAPS_FEATURE_BACKING_STORE_INPUT,
    VIR_DOMAIN_CAPS_FEATURE_BACKUP,
    VIR_DOMAIN_CAPS_FEATURE_ASYNC_TEARDOWN,
    VIR_DOMAIN_CAPS_FEATURE_S390_PV,

    VIR_DOMAIN_CAPS_FEATURE_LAST
} virDomainCapsFeature;

struct _virDomainCaps {
    virObjectLockable parent;

    char *path;                     /* path to emulator binary */
    virDomainVirtType virttype;     /* virtualization type */
    char *machine;                  /* machine type */
    virArch arch;                   /* domain architecture */

    /* Some machine specific info */
    int maxvcpus;

    virDomainCapsOS os;
    virDomainCapsCPU cpu;
    virDomainCapsMemoryBacking memoryBacking;
    virDomainCapsDeviceDisk disk;
    virDomainCapsDeviceGraphics graphics;
    virDomainCapsDeviceVideo video;
    virDomainCapsDeviceHostdev hostdev;
    virDomainCapsDeviceRNG rng;
    virDomainCapsDeviceFilesystem filesystem;
    virDomainCapsDeviceTPM tpm;
    virDomainCapsDeviceRedirdev redirdev;
    virDomainCapsDeviceChannel channel;
    virDomainCapsDeviceCrypto crypto;
    /* add new domain devices here */

    virDomainCapsFeatureGIC gic;
    virSEVCapability *sev;
    virSGXCapability *sgx;
    virDomainCapsFeatureHyperv *hyperv;
    /* add new domain features here */

    virTristateBool features[VIR_DOMAIN_CAPS_FEATURE_LAST];
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virDomainCaps, virObjectUnref);


virDomainCaps *virDomainCapsNew(const char *path,
                                  const char *machine,
                                  virArch arch,
                                  virDomainVirtType virttype);

virDomainCapsCPUModels *virDomainCapsCPUModelsNew(size_t nmodels);
virDomainCapsCPUModels *virDomainCapsCPUModelsCopy(virDomainCapsCPUModels *old);
void
virDomainCapsCPUModelsAdd(virDomainCapsCPUModels *cpuModels,
                          const char *name,
                          virDomainCapsCPUUsable usable,
                          char **blockers,
                          bool deprecated,
                          const char *vendor);
virDomainCapsCPUModel *
virDomainCapsCPUModelsGet(virDomainCapsCPUModels *cpuModels,
                          const char *name);

#define VIR_DOMAIN_CAPS_ENUM_IS_SET(capsEnum, value) \
    ((capsEnum).values & (1U << value))

#define VIR_DOMAIN_CAPS_ENUM_SET(capsEnum, ...) \
    do { \
        unsigned int __values[] = {__VA_ARGS__}; \
        size_t __nvalues = G_N_ELEMENTS(__values); \
        virDomainCapsEnumSet(&(capsEnum), #capsEnum, \
                             __nvalues, __values); \
    } while (0)


int virDomainCapsEnumSet(virDomainCapsEnum *capsEnum,
                         const char *capsEnumName,
                         size_t nvalues,
                         unsigned int *values);
void virDomainCapsEnumClear(virDomainCapsEnum *capsEnum);

char * virDomainCapsFormat(const virDomainCaps *caps);

void
virSEVCapabilitiesFree(virSEVCapability *capabilities);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSEVCapability, virSEVCapabilitiesFree);

void
virSGXCapabilitiesFree(virSGXCapability *capabilities);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSGXCapability, virSGXCapabilitiesFree);
