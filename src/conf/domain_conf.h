/*
 * domain_conf.h: domain XML processing
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
 * Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#ifndef __DOMAIN_CONF_H
# define __DOMAIN_CONF_H

# include <libxml/parser.h>
# include <libxml/tree.h>
# include <libxml/xpath.h>

# include "internal.h"
# include "capabilities.h"
# include "virstorageencryption.h"
# include "cpu_conf.h"
# include "virthread.h"
# include "virhash.h"
# include "virsocketaddr.h"
# include "networkcommon_conf.h"
# include "nwfilter_params.h"
# include "numa_conf.h"
# include "virnetdevmacvlan.h"
# include "virsysinfo.h"
# include "virnetdev.h"
# include "virnetdevip.h"
# include "virnetdevvportprofile.h"
# include "virnetdevbandwidth.h"
# include "virnetdevvlan.h"
# include "virobject.h"
# include "device_conf.h"
# include "virbitmap.h"
# include "virstoragefile.h"
# include "virseclabel.h"
# include "virprocess.h"
# include "virgic.h"
# include "virperf.h"
# include "virtypedparam.h"
# include "virsavecookie.h"

/* forward declarations of all device types, required by
 * virDomainDeviceDef
 */
typedef struct _virDomainDiskDef virDomainDiskDef;
typedef virDomainDiskDef *virDomainDiskDefPtr;

typedef struct _virDomainControllerDef virDomainControllerDef;
typedef virDomainControllerDef *virDomainControllerDefPtr;

typedef struct _virDomainLeaseDef virDomainLeaseDef;
typedef virDomainLeaseDef *virDomainLeaseDefPtr;

typedef struct _virDomainFSDef virDomainFSDef;
typedef virDomainFSDef *virDomainFSDefPtr;

typedef struct _virDomainNetDef virDomainNetDef;
typedef virDomainNetDef *virDomainNetDefPtr;

typedef struct _virDomainInputDef virDomainInputDef;
typedef virDomainInputDef *virDomainInputDefPtr;

typedef struct _virDomainSoundCodecDef virDomainSoundCodecDef;
typedef virDomainSoundCodecDef *virDomainSoundCodecDefPtr;

typedef struct _virDomainSoundDef virDomainSoundDef;
typedef virDomainSoundDef *virDomainSoundDefPtr;

typedef struct _virDomainVideoDef virDomainVideoDef;
typedef virDomainVideoDef *virDomainVideoDefPtr;

typedef struct _virDomainHostdevDef virDomainHostdevDef;
typedef virDomainHostdevDef *virDomainHostdevDefPtr;

typedef struct _virDomainWatchdogDef virDomainWatchdogDef;
typedef virDomainWatchdogDef *virDomainWatchdogDefPtr;

typedef struct _virDomainGraphicsDef virDomainGraphicsDef;
typedef virDomainGraphicsDef *virDomainGraphicsDefPtr;

typedef struct _virDomainHubDef virDomainHubDef;
typedef virDomainHubDef *virDomainHubDefPtr;

typedef struct _virDomainRedirdevDef virDomainRedirdevDef;
typedef virDomainRedirdevDef *virDomainRedirdevDefPtr;

typedef struct _virDomainRedirFilterUSBDevDef virDomainRedirFilterUSBDevDef;
typedef virDomainRedirFilterUSBDevDef *virDomainRedirFilterUSBDevDefPtr;

typedef struct _virDomainRedirFilterDef virDomainRedirFilterDef;
typedef virDomainRedirFilterDef *virDomainRedirFilterDefPtr;

typedef struct _virDomainSmartcardDef virDomainSmartcardDef;
typedef virDomainSmartcardDef *virDomainSmartcardDefPtr;

typedef struct _virDomainChrDef virDomainChrDef;
typedef virDomainChrDef *virDomainChrDefPtr;

typedef struct _virDomainMemballoonDef virDomainMemballoonDef;
typedef virDomainMemballoonDef *virDomainMemballoonDefPtr;

typedef struct _virDomainNVRAMDef virDomainNVRAMDef;
typedef virDomainNVRAMDef *virDomainNVRAMDefPtr;

typedef struct _virDomainSnapshotObj virDomainSnapshotObj;
typedef virDomainSnapshotObj *virDomainSnapshotObjPtr;

typedef struct _virDomainSnapshotObjList virDomainSnapshotObjList;
typedef virDomainSnapshotObjList *virDomainSnapshotObjListPtr;

typedef struct _virDomainRNGDef virDomainRNGDef;
typedef virDomainRNGDef *virDomainRNGDefPtr;

typedef struct _virDomainIdMapEntry virDomainIdMapEntry;
typedef virDomainIdMapEntry *virDomainIdMapEntryPtr;

typedef struct _virDomainIdMapDef virDomainIdMapDef;
typedef virDomainIdMapDef *virDomainIdMapDefPtr;

typedef struct _virDomainPanicDef virDomainPanicDef;
typedef virDomainPanicDef *virDomainPanicDefPtr;

typedef struct _virDomainMemoryDef virDomainMemoryDef;
typedef virDomainMemoryDef *virDomainMemoryDefPtr;

/* forward declarations virDomainChrSourceDef, required by
 * virDomainNetDef
 */
typedef struct _virDomainChrSourceDef virDomainChrSourceDef;
typedef virDomainChrSourceDef *virDomainChrSourceDefPtr;

typedef struct _virDomainShmemDef virDomainShmemDef;
typedef virDomainShmemDef *virDomainShmemDefPtr;

typedef struct _virDomainTPMDef virDomainTPMDef;
typedef virDomainTPMDef *virDomainTPMDefPtr;

typedef struct _virDomainIOMMUDef virDomainIOMMUDef;
typedef virDomainIOMMUDef *virDomainIOMMUDefPtr;

typedef struct _virDomainVirtioOptions virDomainVirtioOptions;
typedef virDomainVirtioOptions *virDomainVirtioOptionsPtr;

/* Flags for the 'type' field in virDomainDeviceDef */
typedef enum {
    VIR_DOMAIN_DEVICE_NONE = 0,
    VIR_DOMAIN_DEVICE_DISK,
    VIR_DOMAIN_DEVICE_LEASE,
    VIR_DOMAIN_DEVICE_FS,
    VIR_DOMAIN_DEVICE_NET,
    VIR_DOMAIN_DEVICE_INPUT,
    VIR_DOMAIN_DEVICE_SOUND,
    VIR_DOMAIN_DEVICE_VIDEO,
    VIR_DOMAIN_DEVICE_HOSTDEV,
    VIR_DOMAIN_DEVICE_WATCHDOG,
    VIR_DOMAIN_DEVICE_CONTROLLER,
    VIR_DOMAIN_DEVICE_GRAPHICS,
    VIR_DOMAIN_DEVICE_HUB,
    VIR_DOMAIN_DEVICE_REDIRDEV,
    VIR_DOMAIN_DEVICE_SMARTCARD,
    VIR_DOMAIN_DEVICE_CHR,
    VIR_DOMAIN_DEVICE_MEMBALLOON,
    VIR_DOMAIN_DEVICE_NVRAM,
    VIR_DOMAIN_DEVICE_RNG,
    VIR_DOMAIN_DEVICE_SHMEM,
    VIR_DOMAIN_DEVICE_TPM,
    VIR_DOMAIN_DEVICE_PANIC,
    VIR_DOMAIN_DEVICE_MEMORY,
    VIR_DOMAIN_DEVICE_IOMMU,

    VIR_DOMAIN_DEVICE_LAST
} virDomainDeviceType;

typedef struct _virDomainDeviceDef virDomainDeviceDef;
typedef virDomainDeviceDef *virDomainDeviceDefPtr;
struct _virDomainDeviceDef {
    int type; /* enum virDomainDeviceType */
    union {
        virDomainDiskDefPtr disk;
        virDomainControllerDefPtr controller;
        virDomainLeaseDefPtr lease;
        virDomainFSDefPtr fs;
        virDomainNetDefPtr net;
        virDomainInputDefPtr input;
        virDomainSoundDefPtr sound;
        virDomainVideoDefPtr video;
        virDomainHostdevDefPtr hostdev;
        virDomainWatchdogDefPtr watchdog;
        virDomainGraphicsDefPtr graphics;
        virDomainHubDefPtr hub;
        virDomainRedirdevDefPtr redirdev;
        virDomainSmartcardDefPtr smartcard;
        virDomainChrDefPtr chr;
        virDomainMemballoonDefPtr memballoon;
        virDomainNVRAMDefPtr nvram;
        virDomainRNGDefPtr rng;
        virDomainShmemDefPtr shmem;
        virDomainTPMDefPtr tpm;
        virDomainPanicDefPtr panic;
        virDomainMemoryDefPtr memory;
        virDomainIOMMUDefPtr iommu;
    } data;
};

/* Different types of hypervisor */
/* NB: Keep in sync with virDomainVirtTypeToString impl */
typedef enum {
    VIR_DOMAIN_VIRT_NONE = 0,
    VIR_DOMAIN_VIRT_QEMU,
    VIR_DOMAIN_VIRT_KQEMU,
    VIR_DOMAIN_VIRT_KVM,
    VIR_DOMAIN_VIRT_XEN,
    VIR_DOMAIN_VIRT_LXC,
    VIR_DOMAIN_VIRT_UML,
    VIR_DOMAIN_VIRT_OPENVZ,
    VIR_DOMAIN_VIRT_TEST,
    VIR_DOMAIN_VIRT_VMWARE,
    VIR_DOMAIN_VIRT_HYPERV,
    VIR_DOMAIN_VIRT_VBOX,
    VIR_DOMAIN_VIRT_PHYP,
    VIR_DOMAIN_VIRT_PARALLELS,
    VIR_DOMAIN_VIRT_BHYVE,
    VIR_DOMAIN_VIRT_VZ,

    VIR_DOMAIN_VIRT_LAST
} virDomainVirtType;

typedef enum {
    VIR_DOMAIN_OSTYPE_HVM,
    VIR_DOMAIN_OSTYPE_XEN,
    VIR_DOMAIN_OSTYPE_LINUX,
    VIR_DOMAIN_OSTYPE_EXE,
    VIR_DOMAIN_OSTYPE_UML,

    VIR_DOMAIN_OSTYPE_LAST
} virDomainOSType;
VIR_ENUM_DECL(virDomainOS)


typedef struct _virDomainHostdevOrigStates virDomainHostdevOrigStates;
typedef virDomainHostdevOrigStates *virDomainHostdevOrigStatesPtr;
struct _virDomainHostdevOrigStates {
    union {
        struct {
            /* Does the device need to unbind from stub when
             * reattaching to host?
             */
            bool unbind_from_stub;

            /* Does it need to use remove_slot when reattaching
             * the device to host?
             */
            bool remove_slot;

            /* Does it need to reprobe driver for the device when
             * reattaching to host?
             */
            bool reprobe;
        } pci;

        /* Perhaps 'usb' in future */
    } states;
};

struct _virDomainLeaseDef {
    char *lockspace;
    char *key;
    char *path;
    unsigned long long offset;
};


typedef enum {
    VIR_DOMAIN_HOSTDEV_MODE_SUBSYS,
    VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES,

    VIR_DOMAIN_HOSTDEV_MODE_LAST
} virDomainHostdevMode;

typedef enum {
    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB,
    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI,
    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI,
    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST,
    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV,

    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST
} virDomainHostdevSubsysType;

/* the backend driver used for PCI hostdev devices */
typedef enum {
    VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT, /* detect automatically, prefer VFIO */
    VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM,    /* force legacy kvm style */
    VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO,   /* force vfio */
    VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN,    /* force legacy xen style, use pciback */

    VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST
} virDomainHostdevSubsysPCIBackendType;

VIR_ENUM_DECL(virDomainHostdevSubsysPCIBackend)

typedef enum {
    VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_NONE,
    VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI,

    VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_LAST,
} virDomainHostdevSCSIProtocolType;

VIR_ENUM_DECL(virDomainHostdevSubsysSCSIProtocol)

typedef struct _virDomainHostdevSubsysUSB virDomainHostdevSubsysUSB;
typedef virDomainHostdevSubsysUSB *virDomainHostdevSubsysUSBPtr;
struct _virDomainHostdevSubsysUSB {
    bool autoAddress; /* bus/device were filled automatically based
                         on vendor/product */
    unsigned bus;
    unsigned device;

    unsigned vendor;
    unsigned product;
};

typedef struct _virDomainHostdevSubsysPCI virDomainHostdevSubsysPCI;
typedef virDomainHostdevSubsysPCI *virDomainHostdevSubsysPCIPtr;
struct _virDomainHostdevSubsysPCI {
    virPCIDeviceAddress addr; /* host address */
    int backend; /* enum virDomainHostdevSubsysPCIBackendType */
};

typedef struct _virDomainHostdevSubsysSCSIHost virDomainHostdevSubsysSCSIHost;
typedef virDomainHostdevSubsysSCSIHost *virDomainHostdevSubsysSCSIHostPtr;
struct _virDomainHostdevSubsysSCSIHost {
    char *adapter;
    unsigned bus;
    unsigned target;
    unsigned long long unit;
};

typedef struct _virDomainHostdevSubsysSCSIiSCSI virDomainHostdevSubsysSCSIiSCSI;
typedef virDomainHostdevSubsysSCSIiSCSI *virDomainHostdevSubsysSCSIiSCSIPtr;
struct _virDomainHostdevSubsysSCSIiSCSI {
    char *path;
    size_t nhosts;
    virStorageNetHostDefPtr hosts;
    virStorageAuthDefPtr auth;
};

typedef struct _virDomainHostdevSubsysSCSI virDomainHostdevSubsysSCSI;
typedef virDomainHostdevSubsysSCSI *virDomainHostdevSubsysSCSIPtr;
struct _virDomainHostdevSubsysSCSI {
    int protocol; /* enum virDomainHostdevSCSIProtocolType */
    int sgio; /* enum virDomainDeviceSGIO */
    int rawio; /* enum virTristateBool */
    union {
        virDomainHostdevSubsysSCSIHost host;
        virDomainHostdevSubsysSCSIiSCSI iscsi;
    } u;
};

typedef struct _virDomainHostdevSubsysMediatedDev virDomainHostdevSubsysMediatedDev;
typedef virDomainHostdevSubsysMediatedDev *virDomainHostdevSubsysMediatedDevPtr;
struct _virDomainHostdevSubsysMediatedDev {
    int model;                          /* enum virMediatedDeviceModelType */
    char uuidstr[VIR_UUID_STRING_BUFLEN];   /* mediated device's uuid string */
};

typedef enum {
    VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_NONE,
    VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_VHOST,

    VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_LAST,
} virDomainHostdevSubsysSCSIHostProtocolType;

VIR_ENUM_DECL(virDomainHostdevSubsysSCSIHostProtocol)

typedef struct _virDomainHostdevSubsysSCSIVHost virDomainHostdevSubsysSCSIVHost;
typedef virDomainHostdevSubsysSCSIVHost *virDomainHostdevSubsysSCSIVHostPtr;
struct _virDomainHostdevSubsysSCSIVHost {
    int protocol; /* enum virDomainHostdevSubsysSCSIHostProtocolType */
    char *wwpn;
};

typedef struct _virDomainHostdevSubsys virDomainHostdevSubsys;
typedef virDomainHostdevSubsys *virDomainHostdevSubsysPtr;
struct _virDomainHostdevSubsys {
    int type; /* enum virDomainHostdevSubsysType */
    union {
        virDomainHostdevSubsysUSB usb;
        virDomainHostdevSubsysPCI pci;
        virDomainHostdevSubsysSCSI scsi;
        virDomainHostdevSubsysSCSIVHost scsi_host;
        virDomainHostdevSubsysMediatedDev mdev;
    } u;
};


typedef enum {
    VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE,
    VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC,
    VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET,

    VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST
} virDomainHostdevCapsType;

typedef struct _virDomainHostdevCaps virDomainHostdevCaps;
typedef virDomainHostdevCaps *virDomainHostdevCapsPtr;
struct _virDomainHostdevCaps {
    int type; /* enum virDOmainHostdevCapsType */
    union {
        struct {
            char *block;
        } storage;
        struct {
            char *chardev;
        } misc;
        struct {
            char *ifname;
            virNetDevIPInfo ip;
        } net;
    } u;
};


/* basic device for direct passthrough */
struct _virDomainHostdevDef {
    virDomainDeviceDef parent; /* higher level Def containing this */
    virObjectPtr privateData;

    int mode; /* enum virDomainHostdevMode */
    int startupPolicy; /* enum virDomainStartupPolicy */
    bool managed;
    bool missing;
    bool readonly;
    bool shareable;
    union {
        virDomainHostdevSubsys subsys;
        virDomainHostdevCaps caps;
    } source;
    virDomainHostdevOrigStates origstates;
    virDomainDeviceInfoPtr info; /* Guest address */
};


/* Types of disk frontend (guest view).  For backends (host view), see
 * virStorageType in util/virstoragefile.h */
typedef enum {
    VIR_DOMAIN_DISK_DEVICE_DISK,
    VIR_DOMAIN_DISK_DEVICE_CDROM,
    VIR_DOMAIN_DISK_DEVICE_FLOPPY,
    VIR_DOMAIN_DISK_DEVICE_LUN,

    VIR_DOMAIN_DISK_DEVICE_LAST
} virDomainDiskDevice;

typedef enum {
    VIR_DOMAIN_DISK_BUS_IDE,
    VIR_DOMAIN_DISK_BUS_FDC,
    VIR_DOMAIN_DISK_BUS_SCSI,
    VIR_DOMAIN_DISK_BUS_VIRTIO,
    VIR_DOMAIN_DISK_BUS_XEN,
    VIR_DOMAIN_DISK_BUS_USB,
    VIR_DOMAIN_DISK_BUS_UML,
    VIR_DOMAIN_DISK_BUS_SATA,
    VIR_DOMAIN_DISK_BUS_SD,

    VIR_DOMAIN_DISK_BUS_LAST
} virDomainDiskBus;

typedef enum {
    VIR_DOMAIN_DISK_CACHE_DEFAULT,
    VIR_DOMAIN_DISK_CACHE_DISABLE,
    VIR_DOMAIN_DISK_CACHE_WRITETHRU,
    VIR_DOMAIN_DISK_CACHE_WRITEBACK,
    VIR_DOMAIN_DISK_CACHE_DIRECTSYNC,
    VIR_DOMAIN_DISK_CACHE_UNSAFE,

    VIR_DOMAIN_DISK_CACHE_LAST
} virDomainDiskCache;

typedef enum {
    VIR_DOMAIN_DISK_ERROR_POLICY_DEFAULT,
    VIR_DOMAIN_DISK_ERROR_POLICY_STOP,
    VIR_DOMAIN_DISK_ERROR_POLICY_REPORT,
    VIR_DOMAIN_DISK_ERROR_POLICY_IGNORE,
    VIR_DOMAIN_DISK_ERROR_POLICY_ENOSPACE,

    VIR_DOMAIN_DISK_ERROR_POLICY_LAST
} virDomainDiskErrorPolicy;


typedef enum {
    VIR_DOMAIN_DISK_TRAY_CLOSED = 0,
    VIR_DOMAIN_DISK_TRAY_OPEN,

    VIR_DOMAIN_DISK_TRAY_LAST
} virDomainDiskTray;

typedef enum {
    VIR_DOMAIN_DISK_TRANS_DEFAULT = 0,
    VIR_DOMAIN_DISK_TRANS_NONE,
    VIR_DOMAIN_DISK_TRANS_AUTO,
    VIR_DOMAIN_DISK_TRANS_LBA,

    VIR_DOMAIN_DISK_TRANS_LAST
} virDomainDiskGeometryTrans;

typedef enum {
    VIR_DOMAIN_DISK_IO_DEFAULT = 0,
    VIR_DOMAIN_DISK_IO_NATIVE,
    VIR_DOMAIN_DISK_IO_THREADS,

    VIR_DOMAIN_DISK_IO_LAST
} virDomainDiskIo;

typedef enum {
    VIR_DOMAIN_STARTUP_POLICY_DEFAULT = 0,
    VIR_DOMAIN_STARTUP_POLICY_MANDATORY,
    VIR_DOMAIN_STARTUP_POLICY_REQUISITE,
    VIR_DOMAIN_STARTUP_POLICY_OPTIONAL,

    VIR_DOMAIN_STARTUP_POLICY_LAST
} virDomainStartupPolicy;


typedef enum {
    VIR_DOMAIN_DEVICE_SGIO_DEFAULT = 0,
    VIR_DOMAIN_DEVICE_SGIO_FILTERED,
    VIR_DOMAIN_DEVICE_SGIO_UNFILTERED,

    VIR_DOMAIN_DEVICE_SGIO_LAST
} virDomainDeviceSGIO;

typedef enum {
    VIR_DOMAIN_DISK_DISCARD_DEFAULT = 0,
    VIR_DOMAIN_DISK_DISCARD_UNMAP,
    VIR_DOMAIN_DISK_DISCARD_IGNORE,

    VIR_DOMAIN_DISK_DISCARD_LAST
} virDomainDiskDiscard;

typedef enum {
    VIR_DOMAIN_DISK_DETECT_ZEROES_DEFAULT = 0,
    VIR_DOMAIN_DISK_DETECT_ZEROES_OFF,
    VIR_DOMAIN_DISK_DETECT_ZEROES_ON,
    VIR_DOMAIN_DISK_DETECT_ZEROES_UNMAP,

    VIR_DOMAIN_DISK_DETECT_ZEROES_LAST
} virDomainDiskDetectZeroes;

typedef struct _virDomainBlockIoTuneInfo virDomainBlockIoTuneInfo;
struct _virDomainBlockIoTuneInfo {
    unsigned long long total_bytes_sec;
    unsigned long long read_bytes_sec;
    unsigned long long write_bytes_sec;
    unsigned long long total_iops_sec;
    unsigned long long read_iops_sec;
    unsigned long long write_iops_sec;
    unsigned long long total_bytes_sec_max;
    unsigned long long read_bytes_sec_max;
    unsigned long long write_bytes_sec_max;
    unsigned long long total_iops_sec_max;
    unsigned long long read_iops_sec_max;
    unsigned long long write_iops_sec_max;
    unsigned long long size_iops_sec;
    char *group_name;
    unsigned long long total_bytes_sec_max_length;
    unsigned long long read_bytes_sec_max_length;
    unsigned long long write_bytes_sec_max_length;
    unsigned long long total_iops_sec_max_length;
    unsigned long long read_iops_sec_max_length;
    unsigned long long write_iops_sec_max_length;
};
typedef virDomainBlockIoTuneInfo *virDomainBlockIoTuneInfoPtr;


typedef enum {
    VIR_DOMAIN_DISK_MIRROR_STATE_NONE = 0, /* No job, or job still not synced */
    VIR_DOMAIN_DISK_MIRROR_STATE_READY, /* Job in second phase */
    VIR_DOMAIN_DISK_MIRROR_STATE_ABORT, /* Job aborted, waiting for event */
    VIR_DOMAIN_DISK_MIRROR_STATE_PIVOT, /* Job pivoted, waiting for event */

    VIR_DOMAIN_DISK_MIRROR_STATE_LAST
} virDomainDiskMirrorState;

typedef enum {
    VIR_DOMAIN_MEMORY_SOURCE_NONE = 0,  /* No memory source defined */
    VIR_DOMAIN_MEMORY_SOURCE_FILE,      /* Memory source is set as file */
    VIR_DOMAIN_MEMORY_SOURCE_ANONYMOUS, /* Memory source is set as anonymous */

    VIR_DOMAIN_MEMORY_SOURCE_LAST,
} virDomainMemorySource;

typedef enum {
    VIR_DOMAIN_MEMORY_ALLOCATION_NONE = 0,  /* No memory allocation defined */
    VIR_DOMAIN_MEMORY_ALLOCATION_IMMEDIATE, /* Memory allocation is set as immediate */
    VIR_DOMAIN_MEMORY_ALLOCATION_ONDEMAND,  /* Memory allocation is set as ondemand */

    VIR_DOMAIN_MEMORY_ALLOCATION_LAST,
} virDomainMemoryAllocation;


/* Stores the virtual disk configuration */
struct _virDomainDiskDef {
    virStorageSourcePtr src; /* non-NULL.  XXX Allow NULL for empty cdrom? */

    virObjectPtr privateData;

    int device; /* enum virDomainDiskDevice */
    int bus; /* enum virDomainDiskBus */
    char *dst;
    int tray_status; /* enum virDomainDiskTray */
    int removable; /* enum virTristateSwitch */

    virStorageSourcePtr mirror;
    int mirrorState; /* enum virDomainDiskMirrorState */
    int mirrorJob; /* virDomainBlockJobType */

    struct {
        unsigned int cylinders;
        unsigned int heads;
        unsigned int sectors;
        int trans; /* enum virDomainDiskGeometryTrans */
    } geometry;

    struct {
        unsigned int logical_block_size;
        unsigned int physical_block_size;
    } blockio;

    virDomainBlockIoTuneInfo blkdeviotune;

    char *serial;
    char *wwn;
    char *vendor;
    char *product;
    int cachemode; /* enum virDomainDiskCache */
    int error_policy;  /* enum virDomainDiskErrorPolicy */
    int rerror_policy; /* enum virDomainDiskErrorPolicy */
    int iomode; /* enum virDomainDiskIo */
    int ioeventfd; /* enum virTristateSwitch */
    int event_idx; /* enum virTristateSwitch */
    int copy_on_read; /* enum virTristateSwitch */
    int snapshot; /* virDomainSnapshotLocation, snapshot_conf.h */
    int startupPolicy; /* enum virDomainStartupPolicy */
    bool transient;
    virDomainDeviceInfo info;
    int rawio; /* enum virTristateBool */
    int sgio; /* enum virDomainDeviceSGIO */
    int discard; /* enum virDomainDiskDiscard */
    unsigned int iothread; /* unused = 0, > 0 specific thread # */
    int detect_zeroes; /* enum virDomainDiskDetectZeroes */
    char *domain_name; /* backend domain name */
    virDomainVirtioOptionsPtr virtio;
};


typedef enum {
    VIR_DOMAIN_CONTROLLER_TYPE_IDE,
    VIR_DOMAIN_CONTROLLER_TYPE_FDC,
    VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
    VIR_DOMAIN_CONTROLLER_TYPE_SATA,
    VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL,
    VIR_DOMAIN_CONTROLLER_TYPE_CCID,
    VIR_DOMAIN_CONTROLLER_TYPE_USB,
    VIR_DOMAIN_CONTROLLER_TYPE_PCI,

    VIR_DOMAIN_CONTROLLER_TYPE_LAST
} virDomainControllerType;


typedef enum {
    VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT,
    VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT,
    VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE,
    VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE,
    VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT,
    VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT,
    VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT,
    VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS,
    VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS,

    VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST
} virDomainControllerModelPCI;

typedef enum {
    VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE,
    VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCI_BRIDGE,
    VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_I82801B11_BRIDGE,
    VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_IOH3420,
    VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_X3130_UPSTREAM,
    VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_XIO3130_DOWNSTREAM,
    VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PXB,
    VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PXB_PCIE,
    VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCIE_ROOT_PORT,

    VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_LAST
} virDomainControllerPCIModelName;

typedef enum {
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1078,

    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LAST
} virDomainControllerModelSCSI;

typedef enum {
    VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX4_UHCI,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_EHCI,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_VT82C686B_UHCI,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_PCI_OHCI,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_NEC_XHCI,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB1,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_QEMU_XHCI,
    VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE,

    VIR_DOMAIN_CONTROLLER_MODEL_USB_LAST
} virDomainControllerModelUSB;

# define IS_USB2_CONTROLLER(ctrl) \
    (((ctrl)->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) && \
     ((ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3))

typedef struct _virDomainVirtioSerialOpts virDomainVirtioSerialOpts;
typedef virDomainVirtioSerialOpts *virDomainVirtioSerialOptsPtr;
struct _virDomainVirtioSerialOpts {
    int ports;   /* -1 == undef */
    int vectors; /* -1 == undef */
};

typedef struct _virDomainPCIControllerOpts virDomainPCIControllerOpts;
typedef virDomainPCIControllerOpts *virDomainPCIControllerOptsPtr;
struct _virDomainPCIControllerOpts {
    bool pcihole64;
    unsigned long pcihole64size;

    /* the exact controller name is in the "model" subelement, e.g.:
     * <controller type='pci' model='pcie-root-port'>
     *   <model name='ioh3420''/>
     *   ...
     */
    int modelName; /* the exact name of the device in hypervisor */

    /* the following items are attributes of the "target" subelement
     * of controller type='pci'. They are bits of configuration that
     * are specified on the qemu commandline and are visible to the
     * guest OS, so they must be preserved to ensure ABI
     * compatibility.
     */
    int chassisNr; /* used by pci-bridge, -1 == unspecified */
    /* chassis & port used by
     * pcie-root-port/pcie-switch-downstream-port, -1 = unspecified */
    int chassis;
    int port;
    int busNr; /* used by pci-expander-bus, -1 == unspecified */
    /* numaNode is a *subelement* of target (to match existing
     * item in memory target config) -1 == unspecified
     */
    int numaNode;
};

typedef struct _virDomainUSBControllerOpts virDomainUSBControllerOpts;
typedef virDomainUSBControllerOpts *virDomainUSBControllerOptsPtr;
struct _virDomainUSBControllerOpts {
    int ports;   /* -1 == undef */
};

/* Stores the virtual disk controller configuration */
struct _virDomainControllerDef {
    int type;
    int idx;
    int model; /* -1 == undef */
    unsigned int queues;
    unsigned int cmd_per_lun;
    unsigned int max_sectors;
    int ioeventfd; /* enum virTristateSwitch */
    unsigned int iothread; /* unused = 0, > 0 specific thread # */
    union {
        virDomainVirtioSerialOpts vioserial;
        virDomainPCIControllerOpts pciopts;
        virDomainUSBControllerOpts usbopts;
    } opts;
    virDomainDeviceInfo info;
};


/* Types of disk backends */
typedef enum {
    VIR_DOMAIN_FS_TYPE_MOUNT, /* Mounts (binds) a host dir on a guest dir */
    VIR_DOMAIN_FS_TYPE_BLOCK, /* Mounts a host block dev on a guest dir */
    VIR_DOMAIN_FS_TYPE_FILE,  /* Loopback mounts a host file on a guest dir */
    VIR_DOMAIN_FS_TYPE_TEMPLATE, /* Expands a OS template to a guest dir */
    VIR_DOMAIN_FS_TYPE_RAM,   /* Mount a RAM filesystem on a guest dir */
    VIR_DOMAIN_FS_TYPE_BIND,  /* Binds a guest dir to another guest dir */
    VIR_DOMAIN_FS_TYPE_VOLUME, /* Mounts storage pool volume to a guest */

    VIR_DOMAIN_FS_TYPE_LAST
} virDomainFSType;

/* Filesystem driver type */
typedef enum {
    VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT = 0,
    VIR_DOMAIN_FS_DRIVER_TYPE_PATH,
    VIR_DOMAIN_FS_DRIVER_TYPE_HANDLE,
    VIR_DOMAIN_FS_DRIVER_TYPE_LOOP,
    VIR_DOMAIN_FS_DRIVER_TYPE_NBD,
    VIR_DOMAIN_FS_DRIVER_TYPE_PLOOP,

    VIR_DOMAIN_FS_DRIVER_TYPE_LAST
} virDomainFSDriverType;

/* Filesystem mount access mode  */
typedef enum {
    VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH,
    VIR_DOMAIN_FS_ACCESSMODE_MAPPED,
    VIR_DOMAIN_FS_ACCESSMODE_SQUASH,

    VIR_DOMAIN_FS_ACCESSMODE_LAST
} virDomainFSAccessMode;

/* Filesystem Write policy */
typedef enum {
    VIR_DOMAIN_FS_WRPOLICY_DEFAULT = 0,
    VIR_DOMAIN_FS_WRPOLICY_IMMEDIATE,

    VIR_DOMAIN_FS_WRPOLICY_LAST
} virDomainFSWrpolicy;

/* Allow 2 MB ram usage */
# define VIR_DOMAIN_FS_RAM_DEFAULT_USAGE (1024 * 2)

struct _virDomainFSDef {
    int type;
    int fsdriver; /* enum virDomainFSDriverType */
    int accessmode; /* enum virDomainFSAccessMode */
    int wrpolicy; /* enum virDomainFSWrpolicy */
    int format; /* virStorageFileFormat */
    unsigned long long usage; /* in bytes */
    virStorageSourcePtr src;
    char *dst;
    bool readonly;
    virDomainDeviceInfo info;
    unsigned long long space_hard_limit; /* in bytes */
    unsigned long long space_soft_limit; /* in bytes */
    bool symlinksResolved;
};


/* network config types */
typedef enum {
    VIR_DOMAIN_NET_TYPE_USER,
    VIR_DOMAIN_NET_TYPE_ETHERNET,
    VIR_DOMAIN_NET_TYPE_VHOSTUSER,
    VIR_DOMAIN_NET_TYPE_SERVER,
    VIR_DOMAIN_NET_TYPE_CLIENT,
    VIR_DOMAIN_NET_TYPE_MCAST,
    VIR_DOMAIN_NET_TYPE_NETWORK,
    VIR_DOMAIN_NET_TYPE_BRIDGE,
    VIR_DOMAIN_NET_TYPE_INTERNAL,
    VIR_DOMAIN_NET_TYPE_DIRECT,
    VIR_DOMAIN_NET_TYPE_HOSTDEV,
    VIR_DOMAIN_NET_TYPE_UDP,

    VIR_DOMAIN_NET_TYPE_LAST
} virDomainNetType;

/* the backend driver used for virtio interfaces */
typedef enum {
    VIR_DOMAIN_NET_BACKEND_TYPE_DEFAULT, /* prefer kernel, fall back to user */
    VIR_DOMAIN_NET_BACKEND_TYPE_QEMU,    /* userland */
    VIR_DOMAIN_NET_BACKEND_TYPE_VHOST,   /* kernel */

    VIR_DOMAIN_NET_BACKEND_TYPE_LAST
} virDomainNetBackendType;

/* the TX algorithm used for virtio interfaces */
typedef enum {
    VIR_DOMAIN_NET_VIRTIO_TX_MODE_DEFAULT, /* default for this version of qemu */
    VIR_DOMAIN_NET_VIRTIO_TX_MODE_IOTHREAD,
    VIR_DOMAIN_NET_VIRTIO_TX_MODE_TIMER,

    VIR_DOMAIN_NET_VIRTIO_TX_MODE_LAST
} virDomainNetVirtioTxModeType;

/* link interface states */
typedef enum {
        VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DEFAULT = 0, /* Default link state (up) */
        VIR_DOMAIN_NET_INTERFACE_LINK_STATE_UP,          /* Link is up. ("cable" connected) */
        VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN ,       /* Link is down. ("cable" disconnected) */

        VIR_DOMAIN_NET_INTERFACE_LINK_STATE_LAST
} virDomainNetInterfaceLinkState;

/* Config that was actually used to bring up interface, after
 * resolving network reference. This is private data, only used within
 * libvirt, but still must maintain backward compatibility, because
 * different versions of libvirt may read the same data file.
 */
typedef struct _virDomainActualNetDef virDomainActualNetDef;
typedef virDomainActualNetDef *virDomainActualNetDefPtr;
struct _virDomainActualNetDef {
    int type; /* enum virDomainNetType */
    union {
        struct {
            char *brname;
            int macTableManager; /* enum virNetworkBridgeMACTableManagerType */
        } bridge;
        struct {
            char *linkdev;
            int mode; /* enum virMacvtapMode from util/macvtap.h */
        } direct;
        struct {
            virDomainHostdevDef def;
        } hostdev;
    } data;
    virNetDevVPortProfilePtr virtPortProfile;
    virNetDevBandwidthPtr bandwidth;
    virNetDevVlan vlan;
    int trustGuestRxFilters; /* enum virTristateBool */
    unsigned int class_id; /* class ID for bandwidth 'floor' */
};

/* Stores the virtual network interface configuration */
struct _virDomainNetDef {
    virDomainNetType type;
    virMacAddr mac;
    char *model;
    union {
        struct {
            virDomainNetBackendType name; /* which driver backend to use */
            virDomainNetVirtioTxModeType txmode;
            virTristateSwitch ioeventfd;
            virTristateSwitch event_idx;
            unsigned int queues; /* Multiqueue virtio-net */
            unsigned int rx_queue_size;
            struct {
                virTristateSwitch csum;
                virTristateSwitch gso;
                virTristateSwitch tso4;
                virTristateSwitch tso6;
                virTristateSwitch ecn;
                virTristateSwitch ufo;
                virTristateSwitch mrg_rxbuf;
            } host;
            struct {
                virTristateSwitch csum;
                virTristateSwitch tso4;
                virTristateSwitch tso6;
                virTristateSwitch ecn;
                virTristateSwitch ufo;
            } guest;
        } virtio;
    } driver;
    struct {
        char *tap;
        char *vhost;
    } backend;
    union {
        virDomainChrSourceDefPtr vhostuser;
        struct {
            char *address;
            int port;
            char *localaddr;
            int localport;
        } socket; /* any of NET_CLIENT or NET_SERVER or NET_MCAST */
        struct {
            char *name;
            char *portgroup;
            /* actual has info about the currently used physical
             * device (if the network is of type
             * bridge/private/vepa/passthrough). This is saved in the
             * domain state, but never written to persistent config,
             * since it needs to be re-allocated whenever the domain
             * is restarted. It is also never shown to the user, and
             * the user cannot specify it in XML documents.
             */
            virDomainActualNetDefPtr actual;
        } network;
        struct {
            char *brname;
        } bridge;
        struct {
            char *name;
        } internal;
        struct {
            char *linkdev;
            int mode; /* enum virMacvtapMode from util/macvtap.h */
        } direct;
        struct {
            virDomainHostdevDef def;
        } hostdev;
    } data;
    /* virtPortProfile is used by network/bridge/direct/hostdev */
    virNetDevVPortProfilePtr virtPortProfile;
    struct {
        bool sndbuf_specified;
        unsigned long sndbuf;
    } tune;
    char *script;
    char *domain_name; /* backend domain name */
    char *ifname; /* interface name on the host (<target dev='x'/>) */
    virNetDevIPInfo hostIP;
    char *ifname_guest_actual;
    char *ifname_guest;
    virNetDevIPInfo guestIP;
    virDomainDeviceInfo info;
    char *filter;
    virNWFilterHashTablePtr filterparams;
    virNetDevBandwidthPtr bandwidth;
    virNetDevVlan vlan;
    int trustGuestRxFilters; /* enum virTristateBool */
    int linkstate;
    unsigned int mtu;
    virNetDevCoalescePtr coalesce;
    virDomainVirtioOptionsPtr virtio;
};

typedef enum {
    VIR_DOMAIN_CHR_DEVICE_STATE_DEFAULT = 0,
    VIR_DOMAIN_CHR_DEVICE_STATE_CONNECTED,
    VIR_DOMAIN_CHR_DEVICE_STATE_DISCONNECTED,

    VIR_DOMAIN_CHR_DEVICE_STATE_LAST
} virDomainChrDeviceState;

VIR_ENUM_DECL(virDomainChrDeviceState)

typedef enum {
    VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL = 0,
    VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL,
    VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE,
    VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL,

    VIR_DOMAIN_CHR_DEVICE_TYPE_LAST
} virDomainChrDeviceType;

typedef enum {
    VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA = 0,
    VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB,
    VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI,

    VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_LAST
} virDomainChrSerialTargetType;

typedef enum {
    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_NONE = 0,
    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD,
    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO,
    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN,

    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_LAST
} virDomainChrChannelTargetType;

typedef enum {
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_NONE  = 0,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_UML,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LXC,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_OPENVZ,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLP,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLPLM,

    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LAST
} virDomainChrConsoleTargetType;

typedef enum {
    VIR_DOMAIN_CHR_TYPE_NULL,
    VIR_DOMAIN_CHR_TYPE_VC,
    VIR_DOMAIN_CHR_TYPE_PTY,
    VIR_DOMAIN_CHR_TYPE_DEV,
    VIR_DOMAIN_CHR_TYPE_FILE,
    VIR_DOMAIN_CHR_TYPE_PIPE,
    VIR_DOMAIN_CHR_TYPE_STDIO,
    VIR_DOMAIN_CHR_TYPE_UDP,
    VIR_DOMAIN_CHR_TYPE_TCP,
    VIR_DOMAIN_CHR_TYPE_UNIX,
    VIR_DOMAIN_CHR_TYPE_SPICEVMC,
    VIR_DOMAIN_CHR_TYPE_SPICEPORT,
    VIR_DOMAIN_CHR_TYPE_NMDM,

    VIR_DOMAIN_CHR_TYPE_LAST
} virDomainChrType;

typedef enum {
    VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW,
    VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET,
    VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNETS, /* secure telnet */
    VIR_DOMAIN_CHR_TCP_PROTOCOL_TLS,

    VIR_DOMAIN_CHR_TCP_PROTOCOL_LAST
} virDomainChrTcpProtocol;

typedef enum {
    VIR_DOMAIN_CHR_SPICEVMC_VDAGENT,
    VIR_DOMAIN_CHR_SPICEVMC_SMARTCARD,
    VIR_DOMAIN_CHR_SPICEVMC_USBREDIR,

    VIR_DOMAIN_CHR_SPICEVMC_LAST
} virDomainChrSpicevmcName;

/* The host side information for a character device.  */
struct _virDomainChrSourceDef {
    int type; /* virDomainChrType */
    virObjectPtr privateData;
    union {
        /* no <source> for null, vc, stdio */
        struct {
            char *path;
            int append; /* enum virTristateSwitch */
        } file; /* pty, file, pipe, or device */
        struct {
            char *master;
            char *slave;
        } nmdm;
        struct {
            char *host;
            char *service;
            bool listen;
            int protocol;
            bool tlscreds;
            int haveTLS; /* enum virTristateBool */
            bool tlsFromConfig;
        } tcp;
        struct {
            char *bindHost;
            char *bindService;
            char *connectHost;
            char *connectService;
        } udp;
        struct {
            char *path;
            bool listen;
        } nix;
        int spicevmc;
        struct {
            char *channel;
        } spiceport;
    } data;
    char *logfile;
    int logappend;
};

/* A complete character device, both host and domain views.  */
struct _virDomainChrDef {
    int deviceType; /* enum virDomainChrDeviceType */

    bool targetTypeAttr;
    int targetType; /* enum virDomainChrConsoleTargetType ||
                       enum virDomainChrChannelTargetType ||
                       enum virDomainChrSerialTargetType according to deviceType */

    union {
        int port; /* parallel, serial, console */
        virSocketAddrPtr addr; /* guestfwd */
        char *name; /* virtio */
    } target;

    virDomainChrDeviceState state;

    virDomainChrSourceDefPtr source;

    virDomainDeviceInfo info;

    size_t nseclabels;
    virSecurityDeviceLabelDefPtr *seclabels;
};

typedef enum {
    VIR_DOMAIN_SMARTCARD_TYPE_HOST,
    VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES,
    VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH,

    VIR_DOMAIN_SMARTCARD_TYPE_LAST
} virDomainSmartcardType;

# define VIR_DOMAIN_SMARTCARD_NUM_CERTIFICATES 3
# define VIR_DOMAIN_SMARTCARD_DEFAULT_DATABASE "/etc/pki/nssdb"

struct _virDomainSmartcardDef {
    int type; /* virDomainSmartcardType */
    union {
        /* no extra data for 'host' */
        struct {
            char *file[VIR_DOMAIN_SMARTCARD_NUM_CERTIFICATES];
            char *database;
        } cert; /* 'host-certificates' */
        virDomainChrSourceDefPtr passthru; /* 'passthrough' */
    } data;

    virDomainDeviceInfo info;
};

struct _virDomainHubDef {
    int type;
    virDomainDeviceInfo info;
};

typedef enum {
    VIR_DOMAIN_TPM_MODEL_TIS,

    VIR_DOMAIN_TPM_MODEL_LAST
} virDomainTPMModel;

typedef enum {
    VIR_DOMAIN_TPM_TYPE_PASSTHROUGH,

    VIR_DOMAIN_TPM_TYPE_LAST
} virDomainTPMBackendType;

# define VIR_DOMAIN_TPM_DEFAULT_DEVICE "/dev/tpm0"

struct _virDomainTPMDef {
    virDomainTPMBackendType type;
    virDomainDeviceInfo info;
    virDomainTPMModel model;
    union {
        struct {
            virDomainChrSourceDef source;
        } passthrough;
    } data;
};

typedef enum {
    VIR_DOMAIN_INPUT_TYPE_MOUSE,
    VIR_DOMAIN_INPUT_TYPE_TABLET,
    VIR_DOMAIN_INPUT_TYPE_KBD,
    VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH,

    VIR_DOMAIN_INPUT_TYPE_LAST
} virDomainInputType;

typedef enum {
    VIR_DOMAIN_INPUT_BUS_PS2,
    VIR_DOMAIN_INPUT_BUS_USB,
    VIR_DOMAIN_INPUT_BUS_XEN,
    VIR_DOMAIN_INPUT_BUS_PARALLELS, /* pseudo device for VNC in containers */
    VIR_DOMAIN_INPUT_BUS_VIRTIO,

    VIR_DOMAIN_INPUT_BUS_LAST
} virDomainInputBus;

struct _virDomainInputDef {
    int type;
    int bus;
    struct {
        char *evdev;
    } source;
    virDomainDeviceInfo info;
};

typedef enum {
    VIR_DOMAIN_SOUND_CODEC_TYPE_DUPLEX,
    VIR_DOMAIN_SOUND_CODEC_TYPE_MICRO,

    VIR_DOMAIN_SOUND_CODEC_TYPE_LAST
} virDomainSoundCodecType;

typedef enum {
    VIR_DOMAIN_SOUND_MODEL_SB16,
    VIR_DOMAIN_SOUND_MODEL_ES1370,
    VIR_DOMAIN_SOUND_MODEL_PCSPK,
    VIR_DOMAIN_SOUND_MODEL_AC97,
    VIR_DOMAIN_SOUND_MODEL_ICH6,
    VIR_DOMAIN_SOUND_MODEL_ICH9,
    VIR_DOMAIN_SOUND_MODEL_USB,

    VIR_DOMAIN_SOUND_MODEL_LAST
} virDomainSoundModel;

struct _virDomainSoundCodecDef {
    int type;
    int cad;
};

struct _virDomainSoundDef {
    int model;
    virDomainDeviceInfo info;

    size_t ncodecs;
    virDomainSoundCodecDefPtr *codecs;
};

typedef enum {
    VIR_DOMAIN_WATCHDOG_MODEL_I6300ESB,
    VIR_DOMAIN_WATCHDOG_MODEL_IB700,
    VIR_DOMAIN_WATCHDOG_MODEL_DIAG288,

    VIR_DOMAIN_WATCHDOG_MODEL_LAST
} virDomainWatchdogModel;

typedef enum {
    VIR_DOMAIN_WATCHDOG_ACTION_RESET,
    VIR_DOMAIN_WATCHDOG_ACTION_SHUTDOWN,
    VIR_DOMAIN_WATCHDOG_ACTION_POWEROFF,
    VIR_DOMAIN_WATCHDOG_ACTION_PAUSE,
    VIR_DOMAIN_WATCHDOG_ACTION_DUMP,
    VIR_DOMAIN_WATCHDOG_ACTION_NONE,
    VIR_DOMAIN_WATCHDOG_ACTION_INJECTNMI,

    VIR_DOMAIN_WATCHDOG_ACTION_LAST
} virDomainWatchdogAction;

struct _virDomainWatchdogDef {
    int model;
    int action;
    virDomainDeviceInfo info;
};


typedef enum {
    VIR_DOMAIN_VIDEO_TYPE_VGA,
    VIR_DOMAIN_VIDEO_TYPE_CIRRUS,
    VIR_DOMAIN_VIDEO_TYPE_VMVGA,
    VIR_DOMAIN_VIDEO_TYPE_XEN,
    VIR_DOMAIN_VIDEO_TYPE_VBOX,
    VIR_DOMAIN_VIDEO_TYPE_QXL,
    VIR_DOMAIN_VIDEO_TYPE_PARALLELS, /* pseudo device for VNC in containers */
    VIR_DOMAIN_VIDEO_TYPE_VIRTIO,
    VIR_DOMAIN_VIDEO_TYPE_GOP,

    VIR_DOMAIN_VIDEO_TYPE_LAST
} virDomainVideoType;


typedef struct _virDomainVideoAccelDef virDomainVideoAccelDef;
typedef virDomainVideoAccelDef *virDomainVideoAccelDefPtr;
struct _virDomainVideoAccelDef {
    int accel2d; /* enum virTristateBool */
    int accel3d; /* enum virTristateBool */
};


struct _virDomainVideoDef {
    int type;
    unsigned int ram;  /* kibibytes (multiples of 1024) */
    unsigned int vram; /* kibibytes (multiples of 1024) */
    unsigned int vram64; /* kibibytes (multiples of 1024) */
    unsigned int vgamem; /* kibibytes (multiples of 1024) */
    unsigned int heads;
    bool primary;
    virDomainVideoAccelDefPtr accel;
    virDomainDeviceInfo info;
};

/* graphics console modes */
typedef enum {
    VIR_DOMAIN_GRAPHICS_TYPE_SDL,
    VIR_DOMAIN_GRAPHICS_TYPE_VNC,
    VIR_DOMAIN_GRAPHICS_TYPE_RDP,
    VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP,
    VIR_DOMAIN_GRAPHICS_TYPE_SPICE,

    VIR_DOMAIN_GRAPHICS_TYPE_LAST
} virDomainGraphicsType;

typedef enum {
    VIR_DOMAIN_GRAPHICS_VNC_SHARE_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_VNC_SHARE_ALLOW_EXCLUSIVE,
    VIR_DOMAIN_GRAPHICS_VNC_SHARE_FORCE_SHARED,
    VIR_DOMAIN_GRAPHICS_VNC_SHARE_IGNORE,

    VIR_DOMAIN_GRAPHICS_VNC_SHARE_LAST
} virDomainGraphicsVNCSharePolicy;

typedef enum {
    VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_FAIL,
    VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_DISCONNECT,
    VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_KEEP,

    VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_LAST
} virDomainGraphicsAuthConnectedType;

typedef struct _virDomainGraphicsAuthDef virDomainGraphicsAuthDef;
typedef virDomainGraphicsAuthDef *virDomainGraphicsAuthDefPtr;
struct _virDomainGraphicsAuthDef {
    char *passwd;
    bool expires; /* Whether there is an expiry time set */
    time_t validTo;  /* seconds since epoch */
    int connected; /* action if connected */
};

typedef enum {
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MAIN,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_DISPLAY,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_INPUT,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_CURSOR,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_PLAYBACK,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_RECORD,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_SMARTCARD,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_USBREDIR,

    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST
} virDomainGraphicsSpiceChannelName;

typedef enum {
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE,

    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_LAST
} virDomainGraphicsSpiceChannelMode;

typedef enum {
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_AUTO_GLZ,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_AUTO_LZ,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_QUIC,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_GLZ,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_LZ,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_OFF,

    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_LAST
} virDomainGraphicsSpiceImageCompression;

typedef enum {
    VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_AUTO,
    VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_NEVER,
    VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_ALWAYS,

    VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_LAST
} virDomainGraphicsSpiceJpegCompression;

typedef enum {
    VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_AUTO,
    VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_NEVER,
    VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_ALWAYS,

    VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_LAST
} virDomainGraphicsSpiceZlibCompression;

typedef enum {
    VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_SERVER,
    VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_CLIENT,

    VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_LAST
} virDomainGraphicsSpiceMouseMode;

typedef enum {
    VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_FILTER,
    VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_ALL,
    VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_OFF,

    VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_LAST
} virDomainGraphicsSpiceStreamingMode;

typedef enum {
    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE = 0,
    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS,
    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK,
    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET,

    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST
} virDomainGraphicsListenType;

typedef enum {
    VIR_DOMAIN_HUB_TYPE_USB,

    VIR_DOMAIN_HUB_TYPE_LAST
} virDomainHubType;

typedef struct _virDomainGraphicsListenDef virDomainGraphicsListenDef;
typedef virDomainGraphicsListenDef *virDomainGraphicsListenDefPtr;
struct _virDomainGraphicsListenDef {
    virDomainGraphicsListenType type;
    char *address;
    char *network;
    char *socket;
    bool fromConfig;    /* true if the @address is config file originated */
    bool autoGenerated;
};

struct _virDomainGraphicsDef {
    /* Port value discipline:
     * Value -1 is legacy syntax indicating that it should be auto-allocated.
     * Value 0 means port wasn't specified in XML at all.
     * Positive value is actual port number given in XML.
     */
    virDomainGraphicsType type;
    union {
        struct {
            int port;
            bool portReserved;
            int websocket;
            bool websocketGenerated;
            bool autoport;
            char *keymap;
            virDomainGraphicsAuthDef auth;
            int sharePolicy;
        } vnc;
        struct {
            char *display;
            char *xauth;
            bool fullscreen;
        } sdl;
        struct {
            int port;
            bool autoport;
            bool replaceUser;
            bool multiUser;
        } rdp;
        struct {
            char *display;
            bool fullscreen;
        } desktop;
        struct {
            int port;
            int tlsPort;
            bool portReserved;
            bool tlsPortReserved;
            virDomainGraphicsSpiceMouseMode mousemode;
            char *keymap;
            virDomainGraphicsAuthDef auth;
            bool autoport;
            int channels[VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST];
            virDomainGraphicsSpiceChannelMode defaultMode;
            int image;
            int jpeg;
            int zlib;
            int playback;
            int streaming;
            virTristateBool copypaste;
            virTristateBool filetransfer;
            virTristateBool gl;
            char *rendernode;
        } spice;
    } data;
    /* nListens, listens, and *port are only useful if type is vnc,
     * rdp, or spice. They've been extracted from the union only to
     * simplify parsing code.*/
    size_t nListens;
    virDomainGraphicsListenDefPtr listens;
};

typedef enum {
    VIR_DOMAIN_REDIRDEV_BUS_USB,

    VIR_DOMAIN_REDIRDEV_BUS_LAST
} virDomainRedirdevBus;

struct _virDomainRedirdevDef {
    int bus; /* enum virDomainRedirdevBus */

    virDomainChrSourceDefPtr source;

    virDomainDeviceInfo info; /* Guest address */
};

struct _virDomainRedirFilterUSBDevDef {
    int usbClass;
    int vendor;
    int product;
    int version;
    bool allow;
};

struct _virDomainRedirFilterDef {
    size_t nusbdevs;
    virDomainRedirFilterUSBDevDefPtr *usbdevs;
};

typedef enum {
    VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO,
    VIR_DOMAIN_MEMBALLOON_MODEL_XEN,
    VIR_DOMAIN_MEMBALLOON_MODEL_NONE,

    VIR_DOMAIN_MEMBALLOON_MODEL_LAST
} virDomainMemballoonModel;

struct _virDomainMemballoonDef {
    int model;
    virDomainDeviceInfo info;
    int period; /* seconds between collections */
    int autodeflate; /* enum virTristateSwitch */
    virDomainVirtioOptionsPtr virtio;
};

struct _virDomainNVRAMDef {
    virDomainDeviceInfo info;
};

typedef enum {
    VIR_DOMAIN_SHMEM_MODEL_IVSHMEM,
    VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_PLAIN,
    VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_DOORBELL,

    VIR_DOMAIN_SHMEM_MODEL_LAST
} virDomainShmemModel;

struct _virDomainShmemDef {
    char *name;
    unsigned long long size;
    int model; /* enum virDomainShmemModel */
    struct {
        bool enabled;
        virDomainChrSourceDef chr;
    } server;
    struct {
        bool enabled;
        unsigned vectors;
        virTristateSwitch ioeventfd;
    } msi;
    virDomainDeviceInfo info;
};

typedef enum {
    VIR_DOMAIN_SMBIOS_NONE = 0,
    VIR_DOMAIN_SMBIOS_EMULATE,
    VIR_DOMAIN_SMBIOS_HOST,
    VIR_DOMAIN_SMBIOS_SYSINFO,

    VIR_DOMAIN_SMBIOS_LAST
} virDomainSmbiosMode;


# define VIR_DOMAIN_MAX_BOOT_DEVS 4

typedef enum {
    VIR_DOMAIN_BOOT_FLOPPY,
    VIR_DOMAIN_BOOT_CDROM,
    VIR_DOMAIN_BOOT_DISK,
    VIR_DOMAIN_BOOT_NET,

    VIR_DOMAIN_BOOT_LAST
} virDomainBootOrder;

typedef enum {
    VIR_DOMAIN_FEATURE_ACPI,
    VIR_DOMAIN_FEATURE_APIC,
    VIR_DOMAIN_FEATURE_PAE,
    VIR_DOMAIN_FEATURE_HAP,
    VIR_DOMAIN_FEATURE_VIRIDIAN,
    VIR_DOMAIN_FEATURE_PRIVNET,
    VIR_DOMAIN_FEATURE_HYPERV,
    VIR_DOMAIN_FEATURE_KVM,
    VIR_DOMAIN_FEATURE_PVSPINLOCK,
    VIR_DOMAIN_FEATURE_CAPABILITIES,
    VIR_DOMAIN_FEATURE_PMU,
    VIR_DOMAIN_FEATURE_VMPORT,
    VIR_DOMAIN_FEATURE_GIC,
    VIR_DOMAIN_FEATURE_SMM,
    VIR_DOMAIN_FEATURE_IOAPIC,

    VIR_DOMAIN_FEATURE_LAST
} virDomainFeature;

# define VIR_DOMAIN_HYPERV_VENDOR_ID_MAX 12

typedef enum {
    VIR_DOMAIN_HYPERV_RELAXED = 0,
    VIR_DOMAIN_HYPERV_VAPIC,
    VIR_DOMAIN_HYPERV_SPINLOCKS,
    VIR_DOMAIN_HYPERV_VPINDEX,
    VIR_DOMAIN_HYPERV_RUNTIME,
    VIR_DOMAIN_HYPERV_SYNIC,
    VIR_DOMAIN_HYPERV_STIMER,
    VIR_DOMAIN_HYPERV_RESET,
    VIR_DOMAIN_HYPERV_VENDOR_ID,

    VIR_DOMAIN_HYPERV_LAST
} virDomainHyperv;

typedef enum {
    VIR_DOMAIN_KVM_HIDDEN = 0,

    VIR_DOMAIN_KVM_LAST
} virDomainKVM;

typedef enum {
    VIR_DOMAIN_CAPABILITIES_POLICY_DEFAULT = 0,
    VIR_DOMAIN_CAPABILITIES_POLICY_ALLOW,
    VIR_DOMAIN_CAPABILITIES_POLICY_DENY,

    VIR_DOMAIN_CAPABILITIES_POLICY_LAST
} virDomainCapabilitiesPolicy;

/* The capabilities are ordered alphabetically to help check for new ones */
typedef enum {
    VIR_DOMAIN_CAPS_FEATURE_AUDIT_CONTROL = 0,
    VIR_DOMAIN_CAPS_FEATURE_AUDIT_WRITE,
    VIR_DOMAIN_CAPS_FEATURE_BLOCK_SUSPEND,
    VIR_DOMAIN_CAPS_FEATURE_CHOWN,
    VIR_DOMAIN_CAPS_FEATURE_DAC_OVERRIDE,
    VIR_DOMAIN_CAPS_FEATURE_DAC_READ_SEARCH,
    VIR_DOMAIN_CAPS_FEATURE_FOWNER,
    VIR_DOMAIN_CAPS_FEATURE_FSETID,
    VIR_DOMAIN_CAPS_FEATURE_IPC_LOCK,
    VIR_DOMAIN_CAPS_FEATURE_IPC_OWNER,
    VIR_DOMAIN_CAPS_FEATURE_KILL,
    VIR_DOMAIN_CAPS_FEATURE_LEASE,
    VIR_DOMAIN_CAPS_FEATURE_LINUX_IMMUTABLE,
    VIR_DOMAIN_CAPS_FEATURE_MAC_ADMIN,
    VIR_DOMAIN_CAPS_FEATURE_MAC_OVERRIDE,
    VIR_DOMAIN_CAPS_FEATURE_MKNOD,
    VIR_DOMAIN_CAPS_FEATURE_NET_ADMIN,
    VIR_DOMAIN_CAPS_FEATURE_NET_BIND_SERVICE,
    VIR_DOMAIN_CAPS_FEATURE_NET_BROADCAST,
    VIR_DOMAIN_CAPS_FEATURE_NET_RAW,
    VIR_DOMAIN_CAPS_FEATURE_SETGID,
    VIR_DOMAIN_CAPS_FEATURE_SETFCAP,
    VIR_DOMAIN_CAPS_FEATURE_SETPCAP,
    VIR_DOMAIN_CAPS_FEATURE_SETUID,
    VIR_DOMAIN_CAPS_FEATURE_SYS_ADMIN,
    VIR_DOMAIN_CAPS_FEATURE_SYS_BOOT,
    VIR_DOMAIN_CAPS_FEATURE_SYS_CHROOT,
    VIR_DOMAIN_CAPS_FEATURE_SYS_MODULE,
    VIR_DOMAIN_CAPS_FEATURE_SYS_NICE,
    VIR_DOMAIN_CAPS_FEATURE_SYS_PACCT,
    VIR_DOMAIN_CAPS_FEATURE_SYS_PTRACE,
    VIR_DOMAIN_CAPS_FEATURE_SYS_RAWIO,
    VIR_DOMAIN_CAPS_FEATURE_SYS_RESOURCE,
    VIR_DOMAIN_CAPS_FEATURE_SYS_TIME,
    VIR_DOMAIN_CAPS_FEATURE_SYS_TTY_CONFIG,
    VIR_DOMAIN_CAPS_FEATURE_SYSLOG,
    VIR_DOMAIN_CAPS_FEATURE_WAKE_ALARM,
    VIR_DOMAIN_CAPS_FEATURE_LAST
} virDomainCapsFeature;

typedef enum {
    VIR_DOMAIN_LIFECYCLE_DESTROY,
    VIR_DOMAIN_LIFECYCLE_RESTART,
    VIR_DOMAIN_LIFECYCLE_RESTART_RENAME,
    VIR_DOMAIN_LIFECYCLE_PRESERVE,

    VIR_DOMAIN_LIFECYCLE_LAST
} virDomainLifecycleAction;

typedef enum {
    VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY,
    VIR_DOMAIN_LIFECYCLE_CRASH_RESTART,
    VIR_DOMAIN_LIFECYCLE_CRASH_RESTART_RENAME,
    VIR_DOMAIN_LIFECYCLE_CRASH_PRESERVE,
    VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_DESTROY,
    VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_RESTART,

    VIR_DOMAIN_LIFECYCLE_CRASH_LAST
} virDomainLifecycleCrashAction;

typedef enum {
    VIR_DOMAIN_LOCK_FAILURE_DEFAULT,
    VIR_DOMAIN_LOCK_FAILURE_POWEROFF,
    VIR_DOMAIN_LOCK_FAILURE_RESTART,
    VIR_DOMAIN_LOCK_FAILURE_PAUSE,
    VIR_DOMAIN_LOCK_FAILURE_IGNORE,

    VIR_DOMAIN_LOCK_FAILURE_LAST
} virDomainLockFailureAction;

VIR_ENUM_DECL(virDomainLockFailure)

typedef struct _virDomainBIOSDef virDomainBIOSDef;
typedef virDomainBIOSDef *virDomainBIOSDefPtr;
struct _virDomainBIOSDef {
    int useserial; /* enum virTristateBool */
    /* reboot-timeout parameters */
    bool rt_set;
    int rt_delay;
};

typedef enum {
    VIR_DOMAIN_LOADER_TYPE_ROM = 0,
    VIR_DOMAIN_LOADER_TYPE_PFLASH,

    VIR_DOMAIN_LOADER_TYPE_LAST
} virDomainLoader;

VIR_ENUM_DECL(virDomainLoader)

typedef struct _virDomainLoaderDef virDomainLoaderDef;
typedef virDomainLoaderDef *virDomainLoaderDefPtr;
struct _virDomainLoaderDef {
    char *path;
    int readonly;   /* enum virTristateBool */
    virDomainLoader type;
    int secure;     /* enum virTristateBool */
    char *nvram;    /* path to non-volatile RAM */
    char *templt;   /* user override of path to master nvram */
};

void virDomainLoaderDefFree(virDomainLoaderDefPtr loader);

typedef enum {
    VIR_DOMAIN_IOAPIC_QEMU = 0,
    VIR_DOMAIN_IOAPIC_KVM,

    VIR_DOMAIN_IOAPIC_LAST
} virDomainIOAPIC;

VIR_ENUM_DECL(virDomainIOAPIC);

/* Operating system configuration data & machine / arch */
typedef struct _virDomainOSDef virDomainOSDef;
typedef virDomainOSDef *virDomainOSDefPtr;
struct _virDomainOSDef {
    int type;
    virArch arch;
    char *machine;
    size_t nBootDevs;
    int bootDevs[VIR_DOMAIN_BOOT_LAST];
    int bootmenu; /* enum virTristateBool */
    unsigned int bm_timeout;
    bool bm_timeout_set;
    char *init;
    char **initargv;
    char *kernel;
    char *initrd;
    char *cmdline;
    char *dtb;
    char *root;
    char *slic_table;
    virDomainLoaderDefPtr loader;
    char *bootloader;
    char *bootloaderArgs;
    int smbios_mode;

    virDomainBIOSDef bios;
};

typedef enum {
    VIR_DOMAIN_TIMER_NAME_PLATFORM = 0,
    VIR_DOMAIN_TIMER_NAME_PIT,
    VIR_DOMAIN_TIMER_NAME_RTC,
    VIR_DOMAIN_TIMER_NAME_HPET,
    VIR_DOMAIN_TIMER_NAME_TSC,
    VIR_DOMAIN_TIMER_NAME_KVMCLOCK,
    VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK,

    VIR_DOMAIN_TIMER_NAME_LAST
} virDomainTimerNameType;

typedef enum {
    VIR_DOMAIN_TIMER_TRACK_BOOT = 0,
    VIR_DOMAIN_TIMER_TRACK_GUEST,
    VIR_DOMAIN_TIMER_TRACK_WALL,

    VIR_DOMAIN_TIMER_TRACK_LAST
} virDomainTimerTrackType;

typedef enum {
    VIR_DOMAIN_TIMER_TICKPOLICY_DELAY = 0,
    VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP,
    VIR_DOMAIN_TIMER_TICKPOLICY_MERGE,
    VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD,

    VIR_DOMAIN_TIMER_TICKPOLICY_LAST
} virDomainTimerTickpolicyType;

typedef enum {
    VIR_DOMAIN_TIMER_MODE_AUTO = 0,
    VIR_DOMAIN_TIMER_MODE_NATIVE,
    VIR_DOMAIN_TIMER_MODE_EMULATE,
    VIR_DOMAIN_TIMER_MODE_PARAVIRT,
    VIR_DOMAIN_TIMER_MODE_SMPSAFE,

    VIR_DOMAIN_TIMER_MODE_LAST
} virDomainTimerModeType;

typedef enum {
    VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC = 0,
    VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO,

    VIR_DOMAIN_CPU_PLACEMENT_MODE_LAST
} virDomainCpuPlacementMode;

typedef struct _virDomainThreadSchedParam virDomainThreadSchedParam;
typedef virDomainThreadSchedParam *virDomainThreadSchedParamPtr;
struct _virDomainThreadSchedParam {
    virProcessSchedPolicy policy;
    int priority;
};

typedef struct _virDomainTimerCatchupDef virDomainTimerCatchupDef;
typedef virDomainTimerCatchupDef *virDomainTimerCatchupDefPtr;
struct _virDomainTimerCatchupDef {
    unsigned long threshold;
    unsigned long slew;
    unsigned long limit;
};

typedef struct _virDomainTimerDef virDomainTimerDef;
typedef virDomainTimerDef *virDomainTimerDefPtr;
struct _virDomainTimerDef {
    int name;
    int present;    /* unspecified = -1, no = 0, yes = 1 */
    int tickpolicy; /* none|catchup|merge|discard */

    virDomainTimerCatchupDef catchup;

    /* track is only valid for name='platform|rtc' */
    int track;  /* host|guest */

    /* frequency & mode are only valid for name='tsc' */
    unsigned long frequency; /* in Hz, unspecified = 0 */
    int mode;       /* auto|native|emulate|paravirt */
};

typedef enum {
    VIR_DOMAIN_CLOCK_OFFSET_UTC = 0,
    VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME = 1,
    VIR_DOMAIN_CLOCK_OFFSET_VARIABLE = 2,
    VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE = 3,

    VIR_DOMAIN_CLOCK_OFFSET_LAST
} virDomainClockOffsetType;

typedef enum {
    VIR_DOMAIN_CLOCK_BASIS_UTC = 0,
    VIR_DOMAIN_CLOCK_BASIS_LOCALTIME = 1,

    VIR_DOMAIN_CLOCK_BASIS_LAST
} virDomainClockBasis;

typedef struct _virDomainClockDef virDomainClockDef;
typedef virDomainClockDef *virDomainClockDefPtr;
struct _virDomainClockDef {
    int offset;

    union {
        /* Bug-compatibility-mode for Xen utc|localtime */
        int utc_reset;
        /* Adjustment in seconds, relative to UTC or LOCALTIME, when
         * offset == VIR_DOMAIN_CLOCK_OFFSET_VARIABLE */
        struct {
            long long adjustment;
            int basis;

            /* domain start-time adjustment. This is a
             * private/internal read-only value that only exists when
             * a domain is running, and only if the clock
             * offset='variable'
             */
            long long adjustment0;
        } variable;

        /* Timezone name, when
         * offset == VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME */
        char *timezone;
    } data;

    size_t ntimers;
    virDomainTimerDefPtr *timers;
};


typedef struct _virBlkioDevice virBlkioDevice;
typedef virBlkioDevice *virBlkioDevicePtr;
struct _virBlkioDevice {
    char *path;
    unsigned int weight;
    unsigned int riops;
    unsigned int wiops;
    unsigned long long rbps;
    unsigned long long wbps;
};

typedef enum {
    VIR_DOMAIN_RNG_MODEL_VIRTIO,

    VIR_DOMAIN_RNG_MODEL_LAST
} virDomainRNGModel;

typedef enum {
    VIR_DOMAIN_RNG_BACKEND_RANDOM,
    VIR_DOMAIN_RNG_BACKEND_EGD,
    /* VIR_DOMAIN_RNG_BACKEND_POOL, */

    VIR_DOMAIN_RNG_BACKEND_LAST
} virDomainRNGBackend;

struct _virDomainRNGDef {
    int model;
    int backend;
    unsigned int rate; /* bytes per period */
    unsigned int period; /* milliseconds */

    union {
        char *file; /* file name for 'random' source */
        virDomainChrSourceDefPtr chardev; /* a char backend for
                                             the EGD source */
    } source;

    virDomainDeviceInfo info;
};

typedef enum {
    VIR_DOMAIN_MEMORY_MODEL_NONE,
    VIR_DOMAIN_MEMORY_MODEL_DIMM, /* dimm hotpluggable memory device */
    VIR_DOMAIN_MEMORY_MODEL_NVDIMM, /* nvdimm memory device */

    VIR_DOMAIN_MEMORY_MODEL_LAST
} virDomainMemoryModel;

struct _virDomainMemoryDef {
    virDomainMemoryAccess access;

    /* source */
    virBitmapPtr sourceNodes;
    unsigned long long pagesize; /* kibibytes */
    char *nvdimmPath;

    /* target */
    int model; /* virDomainMemoryModel */
    int targetNode;
    unsigned long long size; /* kibibytes */
    unsigned long long labelsize; /* kibibytes; valid only for NVDIMM */

    virDomainDeviceInfo info;
};

void virDomainMemoryDefFree(virDomainMemoryDefPtr def);

struct _virDomainIdMapEntry {
    unsigned int start;
    unsigned int target;
    unsigned int count;
};

struct _virDomainIdMapDef {
    size_t nuidmap;
    virDomainIdMapEntryPtr uidmap;

    size_t ngidmap;
    virDomainIdMapEntryPtr gidmap;
};


typedef enum {
    VIR_DOMAIN_PANIC_MODEL_DEFAULT,
    VIR_DOMAIN_PANIC_MODEL_ISA,
    VIR_DOMAIN_PANIC_MODEL_PSERIES,
    VIR_DOMAIN_PANIC_MODEL_HYPERV,
    VIR_DOMAIN_PANIC_MODEL_S390,

    VIR_DOMAIN_PANIC_MODEL_LAST
} virDomainPanicModel;

struct _virDomainPanicDef {
    int model; /* virDomainPanicModel */
    virDomainDeviceInfo info;
};


void virBlkioDeviceArrayClear(virBlkioDevicePtr deviceWeights,
                              int ndevices);

typedef struct _virDomainResourceDef virDomainResourceDef;
typedef virDomainResourceDef *virDomainResourceDefPtr;
struct _virDomainResourceDef {
    char *partition;
};

typedef struct _virDomainHugePage virDomainHugePage;
typedef virDomainHugePage *virDomainHugePagePtr;

struct _virDomainHugePage {
    virBitmapPtr nodemask;      /* guest's NUMA node mask */
    unsigned long long size;    /* hugepage size in KiB */
};

# define VIR_DOMAIN_CPUMASK_LEN 1024

typedef struct _virDomainIOThreadIDDef virDomainIOThreadIDDef;
typedef virDomainIOThreadIDDef *virDomainIOThreadIDDefPtr;

struct _virDomainIOThreadIDDef {
    bool autofill;
    unsigned int iothread_id;
    int thread_id;
    virBitmapPtr cpumask;

    virDomainThreadSchedParam sched;
};

void virDomainIOThreadIDDefFree(virDomainIOThreadIDDefPtr def);


typedef struct _virDomainCputune virDomainCputune;
typedef virDomainCputune *virDomainCputunePtr;

struct _virDomainCputune {
    unsigned long long shares;
    bool sharesSpecified;
    unsigned long long period;
    long long quota;
    unsigned long long global_period;
    long long global_quota;
    unsigned long long emulator_period;
    long long emulator_quota;
    unsigned long long iothread_period;
    long long iothread_quota;
    virBitmapPtr emulatorpin;
};


typedef struct _virDomainVcpuDef virDomainVcpuDef;
typedef virDomainVcpuDef *virDomainVcpuDefPtr;

struct _virDomainVcpuDef {
    bool online;
    virTristateBool hotpluggable;
    unsigned int order;

    virBitmapPtr cpumask;

    virDomainThreadSchedParam sched;

    virObjectPtr privateData;
};

typedef struct _virDomainBlkiotune virDomainBlkiotune;
typedef virDomainBlkiotune *virDomainBlkiotunePtr;

struct _virDomainBlkiotune {
    unsigned int weight;

    size_t ndevices;
    virBlkioDevicePtr devices;
};

typedef struct _virDomainMemtune virDomainMemtune;
typedef virDomainMemtune *virDomainMemtunePtr;

struct _virDomainMemtune {
    /* total memory size including memory modules in kibibytes, this field
     * should be accessed only via accessors */
    unsigned long long total_memory;
    unsigned long long cur_balloon; /* in kibibytes, capped at ulong thanks
                                       to virDomainGetInfo */

    virDomainHugePagePtr hugepages;
    size_t nhugepages;

    /* maximum supported memory for a guest, for hotplugging */
    unsigned long long max_memory; /* in kibibytes */
    unsigned int memory_slots; /* maximum count of RAM memory slots */

    bool nosharepages;
    bool locked;
    int dump_core; /* enum virTristateSwitch */
    unsigned long long hard_limit; /* in kibibytes, limit at off_t bytes */
    unsigned long long soft_limit; /* in kibibytes, limit at off_t bytes */
    unsigned long long min_guarantee; /* in kibibytes, limit at off_t bytes */
    unsigned long long swap_hard_limit; /* in kibibytes, limit at off_t bytes */

    int source; /* enum virDomainMemorySource */
    int access; /* enum virDomainMemoryAccess */
    int allocation; /* enum virDomainMemoryAllocation */
};

typedef struct _virDomainPowerManagement virDomainPowerManagement;
typedef virDomainPowerManagement *virDomainPowerManagementPtr;

struct _virDomainPowerManagement {
    /* These options are of type enum virTristateBool */
    int s3;
    int s4;
};

typedef struct _virDomainPerfDef virDomainPerfDef;
typedef virDomainPerfDef *virDomainPerfDefPtr;
struct _virDomainPerfDef {
    /* These options are of type enum virTristateBool */
    int events[VIR_PERF_EVENT_LAST];
};

typedef struct _virDomainKeyWrapDef virDomainKeyWrapDef;
typedef virDomainKeyWrapDef *virDomainKeyWrapDefPtr;
struct _virDomainKeyWrapDef {
    int aes; /* enum virTristateSwitch */
    int dea; /* enum virTristateSwitch */
};

typedef enum {
    VIR_DOMAIN_IOMMU_MODEL_INTEL,

    VIR_DOMAIN_IOMMU_MODEL_LAST
} virDomainIOMMUModel;

struct _virDomainIOMMUDef {
    virDomainIOMMUModel model;
    virTristateSwitch intremap;
    virTristateSwitch caching_mode;
    virTristateSwitch eim;
    virTristateSwitch iotlb;
};

struct _virDomainVirtioOptions {
    virTristateSwitch iommu;
    virTristateSwitch ats;
};

/*
 * Guest VM main configuration
 *
 * NB: if adding to this struct, virDomainDefCheckABIStability
 * may well need an update
 */
typedef struct _virDomainDef virDomainDef;
typedef virDomainDef *virDomainDefPtr;
struct _virDomainDef {
    virDomainVirtType virtType;
    int id;
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *name;
    char *title;
    char *description;

    virDomainBlkiotune blkio;
    virDomainMemtune mem;

    virDomainVcpuDefPtr *vcpus;
    size_t maxvcpus;
    /* set if the vcpu definition was specified individually */
    bool individualvcpus;
    int placement_mode;
    virBitmapPtr cpumask;

    size_t niothreadids;
    virDomainIOThreadIDDefPtr *iothreadids;

    virDomainCputune cputune;

    virDomainNumaPtr numa;
    virDomainResourceDefPtr resource;
    virDomainIdMapDef idmap;

    /* These 3 are based on virDomainLifeCycleAction enum flags */
    int onReboot;
    int onPoweroff;
    int onCrash;

    int onLockFailure; /* enum virDomainLockFailureAction */

    virDomainPowerManagement pm;

    virDomainPerfDef perf;

    virDomainOSDef os;
    char *emulator;
    /* These three options are of type virTristateSwitch,
     * except VIR_DOMAIN_FEATURE_CAPABILITIES that is of type
     * virDomainCapabilitiesPolicy */
    int features[VIR_DOMAIN_FEATURE_LAST];
    int apic_eoi;
    int hyperv_features[VIR_DOMAIN_HYPERV_LAST];
    int kvm_features[VIR_DOMAIN_KVM_LAST];
    unsigned int hyperv_spinlocks;
    virGICVersion gic_version;
    char *hyperv_vendor_id;
    virDomainIOAPIC ioapic;

    /* These options are of type virTristateSwitch: ON = keep, OFF = drop */
    int caps_features[VIR_DOMAIN_CAPS_FEATURE_LAST];

    virDomainClockDef clock;

    size_t ngraphics;
    virDomainGraphicsDefPtr *graphics;

    size_t ndisks;
    virDomainDiskDefPtr *disks;

    size_t ncontrollers;
    virDomainControllerDefPtr *controllers;

    size_t nfss;
    virDomainFSDefPtr *fss;

    size_t nnets;
    virDomainNetDefPtr *nets;

    size_t ninputs;
    virDomainInputDefPtr *inputs;

    size_t nsounds;
    virDomainSoundDefPtr *sounds;

    size_t nvideos;
    virDomainVideoDefPtr *videos;

    size_t nhostdevs;
    virDomainHostdevDefPtr *hostdevs;

    size_t nredirdevs;
    virDomainRedirdevDefPtr *redirdevs;

    size_t nsmartcards;
    virDomainSmartcardDefPtr *smartcards;

    size_t nserials;
    virDomainChrDefPtr *serials;

    size_t nparallels;
    virDomainChrDefPtr *parallels;

    size_t nchannels;
    virDomainChrDefPtr *channels;

    size_t nconsoles;
    virDomainChrDefPtr *consoles;

    size_t nleases;
    virDomainLeaseDefPtr *leases;

    size_t nhubs;
    virDomainHubDefPtr *hubs;

    size_t nseclabels;
    virSecurityLabelDefPtr *seclabels;

    size_t nrngs;
    virDomainRNGDefPtr *rngs;

    size_t nshmems;
    virDomainShmemDefPtr *shmems;

    size_t nmems;
    virDomainMemoryDefPtr *mems;

    size_t npanics;
    virDomainPanicDefPtr *panics;

    /* Only 1 */
    virDomainWatchdogDefPtr watchdog;
    virDomainMemballoonDefPtr memballoon;
    virDomainNVRAMDefPtr nvram;
    virDomainTPMDefPtr tpm;
    virCPUDefPtr cpu;
    virSysinfoDefPtr sysinfo;
    virDomainRedirFilterDefPtr redirfilter;
    virDomainIOMMUDefPtr iommu;

    void *namespaceData;
    virDomainXMLNamespace ns;

    virDomainKeyWrapDefPtr keywrap;

    /* Application-specific custom metadata */
    xmlNodePtr metadata;
};


unsigned long long virDomainDefGetMemoryInitial(const virDomainDef *def);
void virDomainDefSetMemoryTotal(virDomainDefPtr def, unsigned long long size);
unsigned long long virDomainDefGetMemoryTotal(const virDomainDef *def);
bool virDomainDefHasMemoryHotplug(const virDomainDef *def);

typedef enum {
    VIR_DOMAIN_KEY_WRAP_CIPHER_NAME_AES,
    VIR_DOMAIN_KEY_WRAP_CIPHER_NAME_DEA,

    VIR_DOMAIN_KEY_WRAP_CIPHER_NAME_LAST
} virDomainKeyWrapCipherName;

typedef enum {
    VIR_DOMAIN_TAINT_CUSTOM_ARGV,      /* Custom ARGV passthrough from XML */
    VIR_DOMAIN_TAINT_CUSTOM_MONITOR,   /* Custom monitor commands issued */
    VIR_DOMAIN_TAINT_HIGH_PRIVILEGES,  /* Running with undesirably high privileges */
    VIR_DOMAIN_TAINT_SHELL_SCRIPTS,    /* Network configuration using opaque shell scripts */
    VIR_DOMAIN_TAINT_DISK_PROBING,     /* Relying on potentially unsafe disk format probing */
    VIR_DOMAIN_TAINT_EXTERNAL_LAUNCH,  /* Externally launched guest domain */
    VIR_DOMAIN_TAINT_HOST_CPU,         /* Host CPU passthrough in use */
    VIR_DOMAIN_TAINT_HOOK,             /* Domain (possibly) changed via hook script */
    VIR_DOMAIN_TAINT_CDROM_PASSTHROUGH,/* CDROM passthrough */
    VIR_DOMAIN_TAINT_CUSTOM_DTB,       /* Custom device tree blob was specified */

    VIR_DOMAIN_TAINT_LAST
} virDomainTaintFlags;

/* Guest VM runtime state */
typedef struct _virDomainStateReason virDomainStateReason;
struct _virDomainStateReason {
    int state;
    int reason;
};

typedef struct _virDomainObj virDomainObj;
typedef virDomainObj *virDomainObjPtr;
struct _virDomainObj {
    virObjectLockable parent;
    virCond cond;

    pid_t pid;
    virDomainStateReason state;

    unsigned int autostart : 1;
    unsigned int persistent : 1;
    unsigned int updated : 1;
    unsigned int removing : 1;

    virDomainDefPtr def; /* The current definition */
    virDomainDefPtr newDef; /* New definition to activate at shutdown */

    virDomainSnapshotObjListPtr snapshots;
    virDomainSnapshotObjPtr current_snapshot;

    bool hasManagedSave;

    void *privateData;
    void (*privateDataFreeFunc)(void *);

    int taint;

    unsigned long long original_memlock; /* Original RLIMIT_MEMLOCK, zero if no
                                          * restore will be required later */
};

typedef bool (*virDomainObjListACLFilter)(virConnectPtr conn,
                                          virDomainDefPtr def);


typedef enum {
    VIR_DOMAIN_DEF_FEATURE_WIDE_SCSI = (1 << 0),
    VIR_DOMAIN_DEF_FEATURE_MEMORY_HOTPLUG = (1 << 1),
    VIR_DOMAIN_DEF_FEATURE_OFFLINE_VCPUPIN = (1 << 2),
    VIR_DOMAIN_DEF_FEATURE_NAME_SLASH = (1 << 3),
    VIR_DOMAIN_DEF_FEATURE_INDIVIDUAL_VCPUS = (1 << 4),
} virDomainDefFeatures;


/* This structure holds various callbacks and data needed
 * while parsing and creating domain XMLs */
typedef struct _virDomainXMLOption virDomainXMLOption;
typedef virDomainXMLOption *virDomainXMLOptionPtr;

/* Called once after everything else has been parsed, for adjusting
 * overall domain defaults.
 * @parseOpaque is opaque data passed by virDomainDefParse* caller,
 * @opaque is opaque data set by driver (usually pointer to driver
 * private data). */
typedef int (*virDomainDefPostParseCallback)(virDomainDefPtr def,
                                             virCapsPtr caps,
                                             unsigned int parseFlags,
                                             void *opaque,
                                             void *parseOpaque);
/* Called once per device, for adjusting per-device settings while
 * leaving the overall domain otherwise unchanged.
 * @parseOpaque is opaque data passed by virDomainDefParse* caller,
 * @opaque is opaque data set by driver (usually pointer to driver
 * private data). */
typedef int (*virDomainDeviceDefPostParseCallback)(virDomainDeviceDefPtr dev,
                                                   const virDomainDef *def,
                                                   virCapsPtr caps,
                                                   unsigned int parseFlags,
                                                   void *opaque,
                                                   void *parseOpaque);
/* Drive callback for assigning device addresses, called at the end
 * of parsing, after all defaults and implicit devices have been added.
 * @parseOpaque is opaque data passed by virDomainDefParse* caller,
 * @opaque is opaque data set by driver (usually pointer to driver
 * private data). */
typedef int (*virDomainDefAssignAddressesCallback)(virDomainDef *def,
                                                   virCapsPtr caps,
                                                   unsigned int parseFlags,
                                                   void *opaque,
                                                   void *parseOpaque);

/* Called in appropriate places where the domain conf parser can return failure
 * for configurations that were previously accepted. This shall not modify the
 * config. */
typedef int (*virDomainDefValidateCallback)(const virDomainDef *def,
                                            virCapsPtr caps,
                                            void *opaque);

/* Called once per device, for adjusting per-device settings while
 * leaving the overall domain otherwise unchanged.  */
typedef int (*virDomainDeviceDefValidateCallback)(const virDomainDeviceDef *dev,
                                                  const virDomainDef *def,
                                                  void *opaque);

typedef struct _virDomainDefParserConfig virDomainDefParserConfig;
typedef virDomainDefParserConfig *virDomainDefParserConfigPtr;
struct _virDomainDefParserConfig {
    /* driver domain definition callbacks */
    virDomainDefPostParseCallback domainPostParseCallback;
    virDomainDeviceDefPostParseCallback devicesPostParseCallback;
    virDomainDefAssignAddressesCallback assignAddressesCallback;

    /* validation callbacks */
    virDomainDefValidateCallback domainValidateCallback;
    virDomainDeviceDefValidateCallback deviceValidateCallback;

    /* private data for the callbacks */
    void *priv;
    virFreeCallback privFree;

    /* data */
    unsigned int features; /* virDomainDefFeatures */
    unsigned char macPrefix[VIR_MAC_PREFIX_BUFLEN];
};

typedef void *(*virDomainXMLPrivateDataAllocFunc)(void);
typedef void (*virDomainXMLPrivateDataFreeFunc)(void *);
typedef virObjectPtr (*virDomainXMLPrivateDataNewFunc)(void);
typedef int (*virDomainXMLPrivateDataFormatFunc)(virBufferPtr,
                                                 virDomainObjPtr);
typedef int (*virDomainXMLPrivateDataParseFunc)(xmlXPathContextPtr,
                                                virDomainObjPtr,
                                                virDomainDefParserConfigPtr);

typedef struct _virDomainXMLPrivateDataCallbacks virDomainXMLPrivateDataCallbacks;
typedef virDomainXMLPrivateDataCallbacks *virDomainXMLPrivateDataCallbacksPtr;
struct _virDomainXMLPrivateDataCallbacks {
    virDomainXMLPrivateDataAllocFunc  alloc;
    virDomainXMLPrivateDataFreeFunc   free;
    /* note that private data for devices are not copied when using
     * virDomainDefCopy and similar functions */
    virDomainXMLPrivateDataNewFunc    diskNew;
    virDomainXMLPrivateDataNewFunc    hostdevNew;
    virDomainXMLPrivateDataNewFunc    vcpuNew;
    virDomainXMLPrivateDataNewFunc    chrSourceNew;
    virDomainXMLPrivateDataFormatFunc format;
    virDomainXMLPrivateDataParseFunc  parse;
};

typedef bool (*virDomainABIStabilityDomain)(const virDomainDef *src,
                                            const virDomainDef *dst);

typedef struct _virDomainABIStability virDomainABIStability;
typedef virDomainABIStability *virDomainABIStabilityPtr;
struct _virDomainABIStability {
    virDomainABIStabilityDomain domain;
};

virDomainXMLOptionPtr virDomainXMLOptionNew(virDomainDefParserConfigPtr config,
                                            virDomainXMLPrivateDataCallbacksPtr priv,
                                            virDomainXMLNamespacePtr xmlns,
                                            virDomainABIStabilityPtr abi,
                                            virSaveCookieCallbacksPtr saveCookie);

virSaveCookieCallbacksPtr
virDomainXMLOptionGetSaveCookie(virDomainXMLOptionPtr xmlopt);

void virDomainNetGenerateMAC(virDomainXMLOptionPtr xmlopt, virMacAddrPtr mac);

virDomainXMLNamespacePtr
virDomainXMLOptionGetNamespace(virDomainXMLOptionPtr xmlopt)
    ATTRIBUTE_NONNULL(1);

int virDomainDefPostParse(virDomainDefPtr def,
                          virCapsPtr caps,
                          unsigned int parseFlags,
                          virDomainXMLOptionPtr xmlopt,
                          void *parseOpaque);

int virDomainDefValidate(virDomainDefPtr def,
                         virCapsPtr caps,
                         unsigned int parseFlags,
                         virDomainXMLOptionPtr xmlopt);

static inline bool
virDomainObjIsActive(virDomainObjPtr dom)
{
    return dom->def->id != -1;
}

int virDomainDefSetVcpusMax(virDomainDefPtr def,
                            unsigned int vcpus,
                            virDomainXMLOptionPtr xmlopt);
bool virDomainDefHasVcpusOffline(const virDomainDef *def);
unsigned int virDomainDefGetVcpusMax(const virDomainDef *def);
int virDomainDefSetVcpus(virDomainDefPtr def, unsigned int vcpus);
unsigned int virDomainDefGetVcpus(const virDomainDef *def);
virBitmapPtr virDomainDefGetOnlineVcpumap(const virDomainDef *def);
virDomainVcpuDefPtr virDomainDefGetVcpu(virDomainDefPtr def, unsigned int vcpu)
    ATTRIBUTE_RETURN_CHECK;
void virDomainDefVcpuOrderClear(virDomainDefPtr def);
int  virDomainDefGetVcpusTopology(const virDomainDef *def,
                                  unsigned int *maxvcpus);

virDomainObjPtr virDomainObjNew(virDomainXMLOptionPtr caps)
    ATTRIBUTE_NONNULL(1);

void virDomainObjEndAPI(virDomainObjPtr *vm);

bool virDomainObjTaint(virDomainObjPtr obj,
                       virDomainTaintFlags taint);

void virDomainObjBroadcast(virDomainObjPtr vm);
int virDomainObjWait(virDomainObjPtr vm);
int virDomainObjWaitUntil(virDomainObjPtr vm,
                          unsigned long long whenms);

void virDomainPanicDefFree(virDomainPanicDefPtr panic);
void virDomainResourceDefFree(virDomainResourceDefPtr resource);
void virDomainGraphicsDefFree(virDomainGraphicsDefPtr def);
void virDomainInputDefFree(virDomainInputDefPtr def);
virDomainDiskDefPtr virDomainDiskDefNew(virDomainXMLOptionPtr xmlopt);
void virDomainDiskDefFree(virDomainDiskDefPtr def);
void virDomainLeaseDefFree(virDomainLeaseDefPtr def);
int virDomainDiskGetType(virDomainDiskDefPtr def);
void virDomainDiskSetType(virDomainDiskDefPtr def, int type);
const char *virDomainDiskGetSource(virDomainDiskDef const *def);
int virDomainDiskSetSource(virDomainDiskDefPtr def, const char *src)
    ATTRIBUTE_RETURN_CHECK;
void virDomainDiskEmptySource(virDomainDiskDefPtr def);
const char *virDomainDiskGetDriver(virDomainDiskDefPtr def);
int virDomainDiskSetDriver(virDomainDiskDefPtr def, const char *name)
    ATTRIBUTE_RETURN_CHECK;
int virDomainDiskGetFormat(virDomainDiskDefPtr def);
void virDomainDiskSetFormat(virDomainDiskDefPtr def, int format);
int virDomainDeviceFindControllerModel(const virDomainDef *def,
                                       virDomainDeviceInfoPtr info,
                                       int controllerType);
virDomainDiskDefPtr virDomainDiskFindByBusAndDst(virDomainDefPtr def,
                                                 int bus,
                                                 char *dst);
void virDomainControllerDefFree(virDomainControllerDefPtr def);
virDomainFSDefPtr virDomainFSDefNew(void);
virDomainControllerDefPtr
virDomainControllerDefNew(virDomainControllerType type);
void virDomainFSDefFree(virDomainFSDefPtr def);
void virDomainActualNetDefFree(virDomainActualNetDefPtr def);
void virDomainNetDefClear(virDomainNetDefPtr def);
void virDomainNetDefFree(virDomainNetDefPtr def);
void virDomainSmartcardDefFree(virDomainSmartcardDefPtr def);
void virDomainChrDefFree(virDomainChrDefPtr def);
void virDomainChrSourceDefFree(virDomainChrSourceDefPtr def);
int virDomainChrSourceDefCopy(virDomainChrSourceDefPtr src,
                              virDomainChrSourceDefPtr dest);
void virDomainSoundCodecDefFree(virDomainSoundCodecDefPtr def);
void virDomainSoundDefFree(virDomainSoundDefPtr def);
void virDomainMemballoonDefFree(virDomainMemballoonDefPtr def);
void virDomainNVRAMDefFree(virDomainNVRAMDefPtr def);
void virDomainWatchdogDefFree(virDomainWatchdogDefPtr def);
void virDomainVideoDefFree(virDomainVideoDefPtr def);
virDomainHostdevDefPtr virDomainHostdevDefAlloc(virDomainXMLOptionPtr xmlopt);
void virDomainHostdevDefClear(virDomainHostdevDefPtr def);
void virDomainHostdevDefFree(virDomainHostdevDefPtr def);
void virDomainHubDefFree(virDomainHubDefPtr def);
void virDomainRedirdevDefFree(virDomainRedirdevDefPtr def);
void virDomainRedirFilterDefFree(virDomainRedirFilterDefPtr def);
void virDomainShmemDefFree(virDomainShmemDefPtr def);
void virDomainDeviceDefFree(virDomainDeviceDefPtr def);
virDomainDeviceDefPtr virDomainDeviceDefCopy(virDomainDeviceDefPtr src,
                                             const virDomainDef *def,
                                             virCapsPtr caps,
                                             virDomainXMLOptionPtr xmlopt);
int virDomainDeviceAddressIsValid(virDomainDeviceInfoPtr info,
                                  int type);
virDomainDeviceInfoPtr virDomainDeviceGetInfo(virDomainDeviceDefPtr device);
int virDomainDeviceInfoCopy(virDomainDeviceInfoPtr dst,
                            virDomainDeviceInfoPtr src);
void virDomainDeviceInfoClear(virDomainDeviceInfoPtr info);
void virDomainTPMDefFree(virDomainTPMDefPtr def);

typedef int (*virDomainDeviceInfoCallback)(virDomainDefPtr def,
                                           virDomainDeviceDefPtr dev,
                                           virDomainDeviceInfoPtr info,
                                           void *opaque);

int virDomainDeviceInfoIterate(virDomainDefPtr def,
                               virDomainDeviceInfoCallback cb,
                               void *opaque);

bool virDomainDefHasDeviceAddress(virDomainDefPtr def,
                                  virDomainDeviceInfoPtr info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

void virDomainDefFree(virDomainDefPtr vm);

virDomainChrDefPtr virDomainChrDefNew(virDomainXMLOptionPtr xmlopt);

virDomainDefPtr virDomainDefNew(void);
virDomainDefPtr virDomainDefNewFull(const char *name,
                                    const unsigned char *uuid,
                                    int id);

void virDomainObjAssignDef(virDomainObjPtr domain,
                           virDomainDefPtr def,
                           bool live,
                           virDomainDefPtr *oldDef);
int virDomainObjSetDefTransient(virCapsPtr caps,
                                virDomainXMLOptionPtr xmlopt,
                                virDomainObjPtr domain);
void virDomainObjRemoveTransientDef(virDomainObjPtr domain);
virDomainDefPtr
virDomainObjGetPersistentDef(virCapsPtr caps,
                             virDomainXMLOptionPtr xmlopt,
                             virDomainObjPtr domain);

int virDomainObjUpdateModificationImpact(virDomainObjPtr vm,
                                         unsigned int *flags);

int virDomainObjGetDefs(virDomainObjPtr vm,
                        unsigned int flags,
                        virDomainDefPtr *liveDef,
                        virDomainDefPtr *persDef);
virDomainDefPtr virDomainObjGetOneDefState(virDomainObjPtr vm,
                                           unsigned int flags,
                                           bool *state);
virDomainDefPtr virDomainObjGetOneDef(virDomainObjPtr vm, unsigned int flags);

virDomainDefPtr virDomainDefCopy(virDomainDefPtr src,
                                 virCapsPtr caps,
                                 virDomainXMLOptionPtr xmlopt,
                                 void *parseOpaque,
                                 bool migratable);
virDomainDefPtr virDomainObjCopyPersistentDef(virDomainObjPtr dom,
                                              virCapsPtr caps,
                                              virDomainXMLOptionPtr xmlopt);

typedef enum {
    /* parse internal domain status information */
    VIR_DOMAIN_DEF_PARSE_STATUS          = 1 << 0,
    /* Parse only parts of the XML that would be present in an inactive libvirt
     * XML. Note that the flag does not imply that ABI incompatible
     * transformations can be used, since it's used to strip runtime info when
     * restoring save images/migration. */
    VIR_DOMAIN_DEF_PARSE_INACTIVE        = 1 << 1,
    /* parse <actual> element */
    VIR_DOMAIN_DEF_PARSE_ACTUAL_NET      = 1 << 2,
    /* parse original states of host PCI device */
    VIR_DOMAIN_DEF_PARSE_PCI_ORIG_STATES = 1 << 3,
    /* internal flag passed to device info sub-parser to allow using <rom> */
    VIR_DOMAIN_DEF_PARSE_ALLOW_ROM       = 1 << 4,
    /* internal flag passed to device info sub-parser to allow specifying boot order */
    VIR_DOMAIN_DEF_PARSE_ALLOW_BOOT      = 1 << 5,
    /* parse only source half of <disk> */
    VIR_DOMAIN_DEF_PARSE_DISK_SOURCE     = 1 << 6,
    /* perform RNG schema validation on the passed XML document */
    VIR_DOMAIN_DEF_PARSE_VALIDATE_SCHEMA = 1 << 7,
    /* don't validate os.type and arch against capabilities. Prevents
     * VMs from disappearing when qemu is removed and libvirtd is restarted */
    VIR_DOMAIN_DEF_PARSE_SKIP_OSTYPE_CHECKS = 1 << 8,
    /* allow updates in post parse callback that would break ABI otherwise */
    VIR_DOMAIN_DEF_PARSE_ABI_UPDATE = 1 << 9,
    /* skip definition validation checks meant to be executed on define time only */
    VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE = 1 << 10,
    /* skip parsing of security labels */
    VIR_DOMAIN_DEF_PARSE_SKIP_SECLABEL        = 1 << 11,
    /* Allows updates in post parse callback for incoming persistent migration
     * that would break ABI otherwise.  This should be used only if it's safe
     * to do such change. */
    VIR_DOMAIN_DEF_PARSE_ABI_UPDATE_MIGRATION = 1 << 12,
} virDomainDefParseFlags;

typedef enum {
    VIR_DOMAIN_DEF_FORMAT_SECURE          = 1 << 0,
    VIR_DOMAIN_DEF_FORMAT_INACTIVE        = 1 << 1,
    VIR_DOMAIN_DEF_FORMAT_UPDATE_CPU      = 1 << 2,
    VIR_DOMAIN_DEF_FORMAT_MIGRATABLE      = 1 << 3,
    /* format internal domain status information */
    VIR_DOMAIN_DEF_FORMAT_STATUS          = 1 << 4,
    /* format <actual> element */
    VIR_DOMAIN_DEF_FORMAT_ACTUAL_NET      = 1 << 5,
    /* format original states of host PCI device */
    VIR_DOMAIN_DEF_FORMAT_PCI_ORIG_STATES = 1 << 6,
    VIR_DOMAIN_DEF_FORMAT_ALLOW_ROM       = 1 << 7,
    VIR_DOMAIN_DEF_FORMAT_ALLOW_BOOT      = 1 << 8,
    VIR_DOMAIN_DEF_FORMAT_CLOCK_ADJUST    = 1 << 9,
} virDomainDefFormatFlags;

/* Use these flags to skip specific domain ABI consistency checks done
 * in virDomainDefCheckABIStabilityFlags.
 */
typedef enum {
    /* Set when domain lock must be released and there exists the possibility
     * that some external action could alter the value, such as cur_balloon. */
    VIR_DOMAIN_DEF_ABI_CHECK_SKIP_VOLATILE = 1 << 0,
} virDomainDefABICheckFlags;

virDomainDeviceDefPtr virDomainDeviceDefParse(const char *xmlStr,
                                              const virDomainDef *def,
                                              virCapsPtr caps,
                                              virDomainXMLOptionPtr xmlopt,
                                              unsigned int flags);
virStorageSourcePtr virDomainDiskDefSourceParse(const char *xmlStr,
                                                const virDomainDef *def,
                                                virDomainXMLOptionPtr xmlopt,
                                                unsigned int flags);
virDomainDefPtr virDomainDefParseString(const char *xmlStr,
                                        virCapsPtr caps,
                                        virDomainXMLOptionPtr xmlopt,
                                        void *parseOpaque,
                                        unsigned int flags);
virDomainDefPtr virDomainDefParseFile(const char *filename,
                                      virCapsPtr caps,
                                      virDomainXMLOptionPtr xmlopt,
                                      void *parseOpaque,
                                      unsigned int flags);
virDomainDefPtr virDomainDefParseNode(xmlDocPtr doc,
                                      xmlNodePtr root,
                                      virCapsPtr caps,
                                      virDomainXMLOptionPtr xmlopt,
                                      void *parseOpaque,
                                      unsigned int flags);
virDomainObjPtr virDomainObjParseNode(xmlDocPtr xml,
                                      xmlNodePtr root,
                                      virCapsPtr caps,
                                      virDomainXMLOptionPtr xmlopt,
                                      unsigned int flags);
virDomainObjPtr virDomainObjParseFile(const char *filename,
                                      virCapsPtr caps,
                                      virDomainXMLOptionPtr xmlopt,
                                      unsigned int flags);

bool virDomainDefCheckABIStability(virDomainDefPtr src,
                                   virDomainDefPtr dst,
                                   virDomainXMLOptionPtr xmlopt);

bool virDomainDefCheckABIStabilityFlags(virDomainDefPtr src,
                                        virDomainDefPtr dst,
                                        virDomainXMLOptionPtr xmlopt,
                                        unsigned int flags);

int virDomainDefAddImplicitDevices(virDomainDefPtr def);

virDomainIOThreadIDDefPtr virDomainIOThreadIDFind(const virDomainDef *def,
                                                  unsigned int iothread_id);
virDomainIOThreadIDDefPtr virDomainIOThreadIDAdd(virDomainDefPtr def,
                                                 unsigned int iothread_id);
void virDomainIOThreadIDDel(virDomainDefPtr def, unsigned int iothread_id);

unsigned int virDomainDefFormatConvertXMLFlags(unsigned int flags);

char *virDomainDefFormat(virDomainDefPtr def,
                         virCapsPtr caps,
                         unsigned int flags);
char *virDomainObjFormat(virDomainXMLOptionPtr xmlopt,
                         virDomainObjPtr obj,
                         virCapsPtr caps,
                         unsigned int flags);
int virDomainDefFormatInternal(virDomainDefPtr def,
                               virCapsPtr caps,
                               unsigned int flags,
                               virBufferPtr buf);

int virDomainDiskSourceFormat(virBufferPtr buf,
                              virStorageSourcePtr src,
                              int policy,
                              unsigned int flags);

int virDomainNetDefFormat(virBufferPtr buf,
                          virDomainNetDefPtr def,
                          char *prefix,
                          unsigned int flags);

typedef enum {
    VIR_DOMAIN_DEVICE_ACTION_ATTACH,
    VIR_DOMAIN_DEVICE_ACTION_DETACH,
    VIR_DOMAIN_DEVICE_ACTION_UPDATE,
} virDomainDeviceAction;

int virDomainDefCompatibleDevice(virDomainDefPtr def,
                                 virDomainDeviceDefPtr dev,
                                 virDomainDeviceAction action);

void virDomainRNGDefFree(virDomainRNGDefPtr def);

int virDomainDiskIndexByAddress(virDomainDefPtr def,
                                virPCIDeviceAddressPtr pci_controller,
                                unsigned int bus, unsigned int target,
                                unsigned int unit);
virDomainDiskDefPtr virDomainDiskByAddress(virDomainDefPtr def,
                                           virPCIDeviceAddressPtr pci_controller,
                                           unsigned int bus,
                                           unsigned int target,
                                           unsigned int unit);
int virDomainDiskIndexByName(virDomainDefPtr def, const char *name,
                             bool allow_ambiguous);
virDomainDiskDefPtr virDomainDiskByName(virDomainDefPtr def,
                                        const char *name,
                                        bool allow_ambiguous);
const char *virDomainDiskPathByName(virDomainDefPtr, const char *name);
int virDomainDiskInsert(virDomainDefPtr def,
                        virDomainDiskDefPtr disk)
    ATTRIBUTE_RETURN_CHECK;
void virDomainDiskInsertPreAlloced(virDomainDefPtr def,
                                   virDomainDiskDefPtr disk);
int virDomainDiskDefAssignAddress(virDomainXMLOptionPtr xmlopt,
                                  virDomainDiskDefPtr def,
                                  const virDomainDef *vmdef);

virDomainDiskDefPtr
virDomainDiskRemove(virDomainDefPtr def, size_t i);
virDomainDiskDefPtr
virDomainDiskRemoveByName(virDomainDefPtr def, const char *name);
int virDomainDiskSourceParse(xmlNodePtr node,
                             xmlXPathContextPtr ctxt,
                             virStorageSourcePtr src);

int virDomainNetFindIdx(virDomainDefPtr def, virDomainNetDefPtr net);
virDomainNetDefPtr virDomainNetFind(virDomainDefPtr def, const char *device);
bool virDomainHasNet(virDomainDefPtr def, virDomainNetDefPtr net);
int virDomainNetInsert(virDomainDefPtr def, virDomainNetDefPtr net);
virDomainNetDefPtr virDomainNetRemove(virDomainDefPtr def, size_t i);
void virDomainNetRemoveHostdev(virDomainDefPtr def, virDomainNetDefPtr net);

int virDomainHostdevInsert(virDomainDefPtr def, virDomainHostdevDefPtr hostdev);
virDomainHostdevDefPtr
virDomainHostdevRemove(virDomainDefPtr def, size_t i);
int virDomainHostdevFind(virDomainDefPtr def, virDomainHostdevDefPtr match,
                         virDomainHostdevDefPtr *found);

virDomainGraphicsListenDefPtr
virDomainGraphicsGetListen(virDomainGraphicsDefPtr def, size_t i);
int virDomainGraphicsListenAppendAddress(virDomainGraphicsDefPtr def,
                                         const char *address)
            ATTRIBUTE_NONNULL(1);
int virDomainGraphicsListenAppendSocket(virDomainGraphicsDefPtr def,
                                        const char *socket)
            ATTRIBUTE_NONNULL(1);

virDomainNetType virDomainNetGetActualType(virDomainNetDefPtr iface);
const char *virDomainNetGetActualBridgeName(virDomainNetDefPtr iface);
int virDomainNetGetActualBridgeMACTableManager(virDomainNetDefPtr iface);
const char *virDomainNetGetActualDirectDev(virDomainNetDefPtr iface);
int virDomainNetGetActualDirectMode(virDomainNetDefPtr iface);
virDomainHostdevDefPtr virDomainNetGetActualHostdev(virDomainNetDefPtr iface);
virNetDevVPortProfilePtr
virDomainNetGetActualVirtPortProfile(virDomainNetDefPtr iface);
virNetDevBandwidthPtr
virDomainNetGetActualBandwidth(virDomainNetDefPtr iface);
virNetDevVlanPtr virDomainNetGetActualVlan(virDomainNetDefPtr iface);
bool virDomainNetGetActualTrustGuestRxFilters(virDomainNetDefPtr iface);
int virDomainNetAppendIPAddress(virDomainNetDefPtr def,
                                const char *address,
                                int family,
                                unsigned int prefix);

int virDomainControllerInsert(virDomainDefPtr def,
                              virDomainControllerDefPtr controller)
    ATTRIBUTE_RETURN_CHECK;
void virDomainControllerInsertPreAlloced(virDomainDefPtr def,
                                         virDomainControllerDefPtr controller);
int virDomainControllerFind(const virDomainDef *def, int type, int idx);
int virDomainControllerFindByType(virDomainDefPtr def, int type);
int virDomainControllerFindByPCIAddress(virDomainDefPtr def,
                                        virPCIDeviceAddressPtr addr);
int virDomainControllerFindUnusedIndex(virDomainDef const *def, int type);
virDomainControllerDefPtr virDomainControllerRemove(virDomainDefPtr def, size_t i);
const char *virDomainControllerAliasFind(const virDomainDef *def,
                                         int type, int idx)
    ATTRIBUTE_NONNULL(1);

int virDomainLeaseIndex(virDomainDefPtr def,
                        virDomainLeaseDefPtr lease);
int virDomainLeaseInsert(virDomainDefPtr def,
                         virDomainLeaseDefPtr lease);
int virDomainLeaseInsertPreAlloc(virDomainDefPtr def)
    ATTRIBUTE_RETURN_CHECK;
void virDomainLeaseInsertPreAlloced(virDomainDefPtr def,
                                    virDomainLeaseDefPtr lease);
virDomainLeaseDefPtr
virDomainLeaseRemoveAt(virDomainDefPtr def, size_t i);
virDomainLeaseDefPtr
virDomainLeaseRemove(virDomainDefPtr def,
                     virDomainLeaseDefPtr lease);

void
virDomainChrGetDomainPtrs(const virDomainDef *vmdef,
                          virDomainChrDeviceType type,
                          const virDomainChrDef ***arrPtr,
                          size_t *cntPtr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);
virDomainChrDefPtr
virDomainChrFind(virDomainDefPtr def,
                 virDomainChrDefPtr target);
bool
virDomainChrEquals(virDomainChrDefPtr src,
                   virDomainChrDefPtr tgt);
int
virDomainChrPreAlloc(virDomainDefPtr vmdef,
                     virDomainChrDefPtr chr);
void
virDomainChrInsertPreAlloced(virDomainDefPtr vmdef,
                             virDomainChrDefPtr chr);
virDomainChrDefPtr
virDomainChrRemove(virDomainDefPtr vmdef,
                   virDomainChrDefPtr chr);

ssize_t virDomainRNGFind(virDomainDefPtr def, virDomainRNGDefPtr rng);
virDomainRNGDefPtr virDomainRNGRemove(virDomainDefPtr def, size_t idx);

ssize_t virDomainRedirdevDefFind(virDomainDefPtr def,
                                 virDomainRedirdevDefPtr redirdev);
virDomainRedirdevDefPtr virDomainRedirdevDefRemove(virDomainDefPtr def, size_t idx);

int virDomainSaveXML(const char *configDir,
                     virDomainDefPtr def,
                     const char *xml);

int virDomainSaveConfig(const char *configDir,
                        virCapsPtr caps,
                        virDomainDefPtr def);
int virDomainSaveStatus(virDomainXMLOptionPtr xmlopt,
                        const char *statusDir,
                        virDomainObjPtr obj,
                        virCapsPtr caps) ATTRIBUTE_RETURN_CHECK;

typedef void (*virDomainLoadConfigNotify)(virDomainObjPtr dom,
                                          int newDomain,
                                          void *opaque);

int virDomainDeleteConfig(const char *configDir,
                          const char *autostartDir,
                          virDomainObjPtr dom);

char *virDomainConfigFile(const char *dir,
                          const char *name);

int virDiskNameToBusDeviceIndex(virDomainDiskDefPtr disk,
                                int *busIdx,
                                int *devIdx);

virDomainFSDefPtr virDomainGetFilesystemForTarget(virDomainDefPtr def,
                                                  const char *target);
int virDomainFSInsert(virDomainDefPtr def, virDomainFSDefPtr fs);
int virDomainFSIndexByName(virDomainDefPtr def, const char *name);
virDomainFSDefPtr virDomainFSRemove(virDomainDefPtr def, size_t i);

int virDomainVideoDefaultType(const virDomainDef *def);
unsigned int virDomainVideoDefaultRAM(const virDomainDef *def,
                                      const virDomainVideoType type);

typedef int (*virDomainSmartcardDefIterator)(virDomainDefPtr def,
                                             virDomainSmartcardDefPtr dev,
                                             void *opaque);

int virDomainSmartcardDefForeach(virDomainDefPtr def,
                                 bool abortOnError,
                                 virDomainSmartcardDefIterator iter,
                                 void *opaque);

typedef int (*virDomainChrDefIterator)(virDomainDefPtr def,
                                       virDomainChrDefPtr dev,
                                       void *opaque);

int virDomainChrDefForeach(virDomainDefPtr def,
                           bool abortOnError,
                           virDomainChrDefIterator iter,
                           void *opaque);

typedef int (*virDomainDiskDefPathIterator)(virDomainDiskDefPtr disk,
                                            const char *path,
                                            size_t depth,
                                            void *opaque);

typedef int (*virDomainUSBDeviceDefIterator)(virDomainDeviceInfoPtr info,
                                             void *opaque);
int virDomainUSBDeviceDefForeach(virDomainDefPtr def,
                                 virDomainUSBDeviceDefIterator iter,
                                 void *opaque,
                                 bool skipHubs);

int virDomainDiskDefForeachPath(virDomainDiskDefPtr disk,
                                bool ignoreOpenFailure,
                                virDomainDiskDefPathIterator iter,
                                void *opaque);

void
virDomainObjSetState(virDomainObjPtr obj, virDomainState state, int reason)
        ATTRIBUTE_NONNULL(1);
virDomainState
virDomainObjGetState(virDomainObjPtr obj, int *reason)
        ATTRIBUTE_NONNULL(1);

virSecurityLabelDefPtr
virDomainDefGetSecurityLabelDef(virDomainDefPtr def, const char *model);

virSecurityDeviceLabelDefPtr
virDomainChrDefGetSecurityLabelDef(virDomainChrDefPtr def, const char *model);

typedef const char* (*virEventActionToStringFunc)(int type);
typedef int (*virEventActionFromStringFunc)(const char *type);

int virDomainMemoryInsert(virDomainDefPtr def, virDomainMemoryDefPtr mem)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
virDomainMemoryDefPtr virDomainMemoryRemove(virDomainDefPtr def, int idx)
    ATTRIBUTE_NONNULL(1);
int virDomainMemoryFindByDef(virDomainDefPtr def, virDomainMemoryDefPtr mem)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virDomainMemoryFindInactiveByDef(virDomainDefPtr def,
                                     virDomainMemoryDefPtr mem)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virDomainShmemDefInsert(virDomainDefPtr def, virDomainShmemDefPtr shmem)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
bool virDomainShmemDefEquals(virDomainShmemDefPtr src, virDomainShmemDefPtr dst)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
ssize_t virDomainShmemDefFind(virDomainDefPtr def, virDomainShmemDefPtr shmem)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
virDomainShmemDefPtr virDomainShmemDefRemove(virDomainDefPtr def, size_t idx)
    ATTRIBUTE_NONNULL(1);

VIR_ENUM_DECL(virDomainTaint)
VIR_ENUM_DECL(virDomainVirt)
VIR_ENUM_DECL(virDomainBoot)
VIR_ENUM_DECL(virDomainFeature)
VIR_ENUM_DECL(virDomainCapabilitiesPolicy)
VIR_ENUM_DECL(virDomainCapsFeature)
VIR_ENUM_DECL(virDomainLifecycle)
VIR_ENUM_DECL(virDomainLifecycleCrash)
VIR_ENUM_DECL(virDomainDevice)
VIR_ENUM_DECL(virDomainDeviceAddress)
VIR_ENUM_DECL(virDomainDiskDevice)
VIR_ENUM_DECL(virDomainDiskGeometryTrans)
VIR_ENUM_DECL(virDomainDiskBus)
VIR_ENUM_DECL(virDomainDiskCache)
VIR_ENUM_DECL(virDomainDiskErrorPolicy)
VIR_ENUM_DECL(virDomainDiskIo)
VIR_ENUM_DECL(virDomainDeviceSGIO)
VIR_ENUM_DECL(virDomainDiskTray)
VIR_ENUM_DECL(virDomainDiskDiscard)
VIR_ENUM_DECL(virDomainDiskDetectZeroes)
VIR_ENUM_DECL(virDomainDiskMirrorState)
VIR_ENUM_DECL(virDomainController)
VIR_ENUM_DECL(virDomainControllerModelPCI)
VIR_ENUM_DECL(virDomainControllerPCIModelName)
VIR_ENUM_DECL(virDomainControllerModelSCSI)
VIR_ENUM_DECL(virDomainControllerModelUSB)
VIR_ENUM_DECL(virDomainFS)
VIR_ENUM_DECL(virDomainFSDriver)
VIR_ENUM_DECL(virDomainFSAccessMode)
VIR_ENUM_DECL(virDomainFSWrpolicy)
VIR_ENUM_DECL(virDomainNet)
VIR_ENUM_DECL(virDomainNetBackend)
VIR_ENUM_DECL(virDomainNetVirtioTxMode)
VIR_ENUM_DECL(virDomainNetInterfaceLinkState)
VIR_ENUM_DECL(virDomainChrDevice)
VIR_ENUM_DECL(virDomainChrChannelTarget)
VIR_ENUM_DECL(virDomainChrConsoleTarget)
VIR_ENUM_DECL(virDomainChrSerialTarget)
VIR_ENUM_DECL(virDomainSmartcard)
VIR_ENUM_DECL(virDomainChr)
VIR_ENUM_DECL(virDomainChrTcpProtocol)
VIR_ENUM_DECL(virDomainChrSpicevmc)
VIR_ENUM_DECL(virDomainSoundCodec)
VIR_ENUM_DECL(virDomainSoundModel)
VIR_ENUM_DECL(virDomainKeyWrapCipherName)
VIR_ENUM_DECL(virDomainMemballoonModel)
VIR_ENUM_DECL(virDomainSmbiosMode)
VIR_ENUM_DECL(virDomainWatchdogModel)
VIR_ENUM_DECL(virDomainWatchdogAction)
VIR_ENUM_DECL(virDomainPanicModel)
VIR_ENUM_DECL(virDomainVideo)
VIR_ENUM_DECL(virDomainHostdevMode)
VIR_ENUM_DECL(virDomainHostdevSubsys)
VIR_ENUM_DECL(virDomainHostdevCaps)
VIR_ENUM_DECL(virDomainHub)
VIR_ENUM_DECL(virDomainRedirdevBus)
VIR_ENUM_DECL(virDomainInput)
VIR_ENUM_DECL(virDomainInputBus)
VIR_ENUM_DECL(virDomainGraphics)
VIR_ENUM_DECL(virDomainGraphicsListen)
VIR_ENUM_DECL(virDomainGraphicsAuthConnected)
VIR_ENUM_DECL(virDomainGraphicsSpiceChannelName)
VIR_ENUM_DECL(virDomainGraphicsSpiceChannelMode)
VIR_ENUM_DECL(virDomainGraphicsSpiceImageCompression)
VIR_ENUM_DECL(virDomainGraphicsSpiceJpegCompression)
VIR_ENUM_DECL(virDomainGraphicsSpiceZlibCompression)
VIR_ENUM_DECL(virDomainGraphicsSpiceStreamingMode)
VIR_ENUM_DECL(virDomainGraphicsSpiceMouseMode)
VIR_ENUM_DECL(virDomainGraphicsVNCSharePolicy)
VIR_ENUM_DECL(virDomainHyperv)
VIR_ENUM_DECL(virDomainKVM)
VIR_ENUM_DECL(virDomainRNGModel)
VIR_ENUM_DECL(virDomainRNGBackend)
VIR_ENUM_DECL(virDomainTPMModel)
VIR_ENUM_DECL(virDomainTPMBackend)
VIR_ENUM_DECL(virDomainMemoryModel)
VIR_ENUM_DECL(virDomainMemoryBackingModel)
VIR_ENUM_DECL(virDomainMemorySource)
VIR_ENUM_DECL(virDomainMemoryAllocation)
VIR_ENUM_DECL(virDomainIOMMUModel)
VIR_ENUM_DECL(virDomainShmemModel)
/* from libvirt.h */
VIR_ENUM_DECL(virDomainState)
VIR_ENUM_DECL(virDomainNostateReason)
VIR_ENUM_DECL(virDomainRunningReason)
VIR_ENUM_DECL(virDomainBlockedReason)
VIR_ENUM_DECL(virDomainPausedReason)
VIR_ENUM_DECL(virDomainShutdownReason)
VIR_ENUM_DECL(virDomainShutoffReason)
VIR_ENUM_DECL(virDomainCrashedReason)
VIR_ENUM_DECL(virDomainPMSuspendedReason)

const char *virDomainStateReasonToString(virDomainState state, int reason);
int virDomainStateReasonFromString(virDomainState state, const char *reason);

VIR_ENUM_DECL(virDomainSeclabel)
VIR_ENUM_DECL(virDomainClockOffset)
VIR_ENUM_DECL(virDomainClockBasis)

VIR_ENUM_DECL(virDomainTimerName)
VIR_ENUM_DECL(virDomainTimerTrack)
VIR_ENUM_DECL(virDomainTimerTickpolicy)
VIR_ENUM_DECL(virDomainTimerMode)
VIR_ENUM_DECL(virDomainCpuPlacementMode)

VIR_ENUM_DECL(virDomainStartupPolicy)

virDomainControllerDefPtr
virDomainDefAddController(virDomainDefPtr def, int type, int idx, int model);
int
virDomainDefAddUSBController(virDomainDefPtr def, int idx, int model);
int
virDomainDefMaybeAddController(virDomainDefPtr def,
                               int type,
                               int idx,
                               int model);
int
virDomainDefMaybeAddInput(virDomainDefPtr def,
                          int type,
                          int bus);

char *virDomainDefGetDefaultEmulator(virDomainDefPtr def, virCapsPtr caps);

int virDomainDefFindDevice(virDomainDefPtr def,
                           const char *devAlias,
                           virDomainDeviceDefPtr dev,
                           bool reportError);

void virDomainChrSourceDefClear(virDomainChrSourceDefPtr def);

char *virDomainObjGetMetadata(virDomainObjPtr vm,
                              int type,
                              const char *uri,
                              unsigned int flags);

int virDomainObjSetMetadata(virDomainObjPtr vm,
                            int type,
                            const char *metadata,
                            const char *key,
                            const char *uri,
                            virCapsPtr caps,
                            virDomainXMLOptionPtr xmlopt,
                            const char *stateDir,
                            const char *configDir,
                            unsigned int flags);

int
virDomainParseMemory(const char *xpath,
                     const char *units_xpath,
                     xmlXPathContextPtr ctxt,
                     unsigned long long *mem,
                     bool required,
                     bool capped);

bool virDomainDefNeedsPlacementAdvice(virDomainDefPtr def)
    ATTRIBUTE_NONNULL(1);

int virDomainDiskDefCheckDuplicateInfo(const virDomainDiskDef *a,
                                       const virDomainDiskDef *b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virDomainDefGetVcpuPinInfoHelper(virDomainDefPtr def,
                                     int maplen,
                                     int ncpumaps,
                                     unsigned char *cpumaps,
                                     int hostcpus,
                                     virBitmapPtr autoCpuset)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4) ATTRIBUTE_RETURN_CHECK;

bool virDomainDefHasMemballoon(const virDomainDef *def) ATTRIBUTE_NONNULL(1);

char *virDomainObjGetShortName(const virDomainDef *def) ATTRIBUTE_NONNULL(1);

int
virDomainGetBlkioParametersAssignFromDef(virDomainDefPtr def,
                                         virTypedParameterPtr params,
                                         int *nparams,
                                         int maxparams);

bool
virDomainDeviceInfoAddressIsEqual(const virDomainDeviceInfo *a,
                                  const virDomainDeviceInfo *b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virDomainDiskSetBlockIOTune(virDomainDiskDefPtr disk,
                                virDomainBlockIoTuneInfo *info);

#endif /* __DOMAIN_CONF_H */
