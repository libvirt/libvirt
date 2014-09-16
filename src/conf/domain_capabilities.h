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
 *
 * Author: Michal Privoznik <mprivozn@redhat.com>
 */

#ifndef __DOMAIN_CAPABILITIES_H__
# define __DOMAIN_CAPABILITIES_H__

# include "internal.h"
# include "domain_conf.h"

typedef const char * (*virDomainCapsValToStr)(int value);

typedef struct _virDomainCaps virDomainCaps;
typedef virDomainCaps *virDomainCapsPtr;

typedef struct _virDomainCapsEnum virDomainCapsEnum;
typedef virDomainCapsEnum *virDomainCapsEnumPtr;
struct _virDomainCapsEnum {
    unsigned int values; /* Bitmask of values supported in the corresponding enum */
};

typedef struct _virDomainCapsStringValues virDomainCapsStringValues;
typedef virDomainCapsStringValues *virDomainCapsStringValuesPtr;
struct _virDomainCapsStringValues {
    char **values;  /* raw string values */
    size_t nvalues; /* number of strings */
};

typedef struct _virDomainCapsDevice virDomainCapsDevice;
typedef virDomainCapsDevice *virDomainCapsDevicePtr;
struct _virDomainCapsDevice {
    bool supported; /* true if <devtype> is supported by hypervisor */
};

typedef struct _virDomainCapsLoader virDomainCapsLoader;
typedef virDomainCapsLoader *virDomainCapsLoaderPtr;
struct _virDomainCapsLoader {
    virDomainCapsDevice device;
    virDomainCapsStringValues values;   /* Info about values for the element */
    virDomainCapsEnum type;     /* Info about virDomainLoader */
    virDomainCapsEnum readonly; /* Info about readonly:virTristateBool */
};

typedef struct _virDomainCapsOS virDomainCapsOS;
typedef virDomainCapsOS *virDomainCapsOSPtr;
struct _virDomainCapsOS {
    virDomainCapsDevice device;
    virDomainCapsLoader loader;     /* Info about virDomainLoaderDef */
};

typedef struct _virDomainCapsDeviceDisk virDomainCapsDeviceDisk;
typedef virDomainCapsDeviceDisk *virDomainCapsDeviceDiskPtr;
struct _virDomainCapsDeviceDisk {
    virDomainCapsDevice device;
    virDomainCapsEnum diskDevice;   /* Info about virDomainDiskDevice enum values */
    virDomainCapsEnum bus;          /* Info about virDomainDiskBus enum values */
    /* add new fields here */
};

typedef struct _virDomainCapsDeviceHostdev virDomainCapsDeviceHostdev;
typedef virDomainCapsDeviceHostdev *virDomainCapsDeviceHostdevPtr;
struct _virDomainCapsDeviceHostdev {
    virDomainCapsDevice device;
    virDomainCapsEnum mode;             /* Info about virDomainHostdevMode */
    virDomainCapsEnum startupPolicy;    /* Info about virDomainStartupPolicy */
    virDomainCapsEnum subsysType;       /* Info about virDomainHostdevSubsysType */
    virDomainCapsEnum capsType;         /* Info about virDomainHostdevCapsType */
    virDomainCapsEnum pciBackend;       /* Info about virDomainHostdevSubsysPCIBackendType */
    /* add new fields here */
};

struct _virDomainCaps {
    virObjectLockable parent;

    char *path;                     /* path to emulator binary */
    virDomainVirtType virttype;     /* virtualization type */
    char *machine;                  /* machine type */
    virArch arch;                   /* domain architecture */

    /* Some machine specific info */
    int maxvcpus;

    virDomainCapsOS os;
    virDomainCapsDeviceDisk disk;
    virDomainCapsDeviceHostdev hostdev;
    /* add new domain devices here */
};

virDomainCapsPtr virDomainCapsNew(const char *path,
                                  const char *machine,
                                  virArch arch,
                                  virDomainVirtType virttype);

# define VIR_DOMAIN_CAPS_ENUM_SET(capsEnum, ...)            \
    do {                                                    \
        unsigned int __values[] = {__VA_ARGS__};            \
        size_t __nvalues = ARRAY_CARDINALITY(__values);     \
        virDomainCapsEnumSet(&(capsEnum), #capsEnum,        \
                             __nvalues, __values);          \
    } while (0)

int virDomainCapsEnumSet(virDomainCapsEnumPtr capsEnum,
                         const char *capsEnumName,
                         size_t nvalues,
                         unsigned int *values);
void virDomainCapsEnumClear(virDomainCapsEnumPtr capsEnum);

char * virDomainCapsFormat(virDomainCapsPtr const caps);
#endif /* __DOMAIN_CAPABILITIES_H__ */
