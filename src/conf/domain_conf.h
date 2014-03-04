/*
 * domain_conf.h: domain XML processing
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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

#ifndef __DOMAIN_CONF_H
# define __DOMAIN_CONF_H

# include <libxml/parser.h>
# include <libxml/tree.h>
# include <libxml/xpath.h>

# include "internal.h"
# include "capabilities.h"
# include "storage_encryption_conf.h"
# include "cpu_conf.h"
# include "virthread.h"
# include "virhash.h"
# include "virsocketaddr.h"
# include "nwfilter_params.h"
# include "virnetdevmacvlan.h"
# include "virsysinfo.h"
# include "virnetdevvportprofile.h"
# include "virnetdevopenvswitch.h"
# include "virnetdevbandwidth.h"
# include "virnetdevvlan.h"
# include "virobject.h"
# include "device_conf.h"
# include "virbitmap.h"
# include "virstoragefile.h"
# include "virnuma.h"

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

typedef struct _virDomainRedirFilterUsbDevDef virDomainRedirFilterUsbDevDef;
typedef virDomainRedirFilterUsbDevDef *virDomainRedirFilterUsbDevDefPtr;

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
    } data;
};

/* Different types of hypervisor */
/* NB: Keep in sync with virDomainVirtTypeToString impl */
enum virDomainVirtType {
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

    VIR_DOMAIN_VIRT_LAST
};

enum virDomainDeviceAddressType {
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA,

    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST
};

enum virDomainPciRombarMode {
    VIR_DOMAIN_PCI_ROMBAR_DEFAULT = 0,
    VIR_DOMAIN_PCI_ROMBAR_ON,
    VIR_DOMAIN_PCI_ROMBAR_OFF,

    VIR_DOMAIN_PCI_ROMBAR_LAST
};

typedef struct _virDomainDeviceDriveAddress virDomainDeviceDriveAddress;
typedef virDomainDeviceDriveAddress *virDomainDeviceDriveAddressPtr;
struct _virDomainDeviceDriveAddress {
    unsigned int controller;
    unsigned int bus;
    unsigned int target;
    unsigned int unit;
};

typedef struct _virDomainDeviceVirtioSerialAddress virDomainDeviceVirtioSerialAddress;
typedef virDomainDeviceVirtioSerialAddress *virDomainDeviceVirtioSerialAddressPtr;
struct _virDomainDeviceVirtioSerialAddress {
    unsigned int controller;
    unsigned int bus;
    unsigned int port;
};

# define VIR_DOMAIN_DEVICE_CCW_MAX_CSSID    254
# define VIR_DOMAIN_DEVICE_CCW_MAX_SSID       3
# define VIR_DOMAIN_DEVICE_CCW_MAX_DEVNO  65535

typedef struct _virDomainDeviceCCWAddress virDomainDeviceCCWAddress;
typedef virDomainDeviceCCWAddress *virDomainDeviceCCWAddressPtr;
struct _virDomainDeviceCCWAddress {
    unsigned int cssid;
    unsigned int ssid;
    unsigned int devno;
    bool         assigned;
};

typedef struct _virDomainDeviceCcidAddress virDomainDeviceCcidAddress;
typedef virDomainDeviceCcidAddress *virDomainDeviceCcidAddressPtr;
struct _virDomainDeviceCcidAddress {
    unsigned int controller;
    unsigned int slot;
};

typedef struct _virDomainDeviceUSBAddress virDomainDeviceUSBAddress;
typedef virDomainDeviceUSBAddress *virDomainDeviceUSBAddressPtr;
struct _virDomainDeviceUSBAddress {
    unsigned int bus;
    char *port;
};

typedef struct _virDomainDeviceSpaprVioAddress virDomainDeviceSpaprVioAddress;
typedef virDomainDeviceSpaprVioAddress *virDomainDeviceSpaprVioAddressPtr;
struct _virDomainDeviceSpaprVioAddress {
    unsigned long long reg;
    bool has_reg;
};

enum virDomainControllerMaster {
    VIR_DOMAIN_CONTROLLER_MASTER_NONE,
    VIR_DOMAIN_CONTROLLER_MASTER_USB,

    VIR_DOMAIN_CONTROLLER_MASTER_LAST
};

typedef struct _virDomainDeviceUSBMaster virDomainDeviceUSBMaster;
typedef virDomainDeviceUSBMaster *virDomainDeviceUSBMasterPtr;
struct _virDomainDeviceUSBMaster {
    unsigned int startport;
};

typedef struct _virDomainDeviceISAAddress virDomainDeviceISAAddress;
typedef virDomainDeviceISAAddress *virDomainDeviceISAAddressPtr;
struct _virDomainDeviceISAAddress {
    unsigned int iobase;
    unsigned int irq;
};

typedef struct _virDomainDeviceInfo virDomainDeviceInfo;
typedef virDomainDeviceInfo *virDomainDeviceInfoPtr;
struct _virDomainDeviceInfo {
    /* If adding to this struct, ensure that
     * virDomainDeviceInfoIsSet() is updated
     * to consider the new fields
     */
    char *alias;
    int type;
    union {
        virDevicePCIAddress pci;
        virDomainDeviceDriveAddress drive;
        virDomainDeviceVirtioSerialAddress vioserial;
        virDomainDeviceCcidAddress ccid;
        virDomainDeviceUSBAddress usb;
        virDomainDeviceSpaprVioAddress spaprvio;
        virDomainDeviceCCWAddress ccw;
        virDomainDeviceISAAddress isa;
    } addr;
    int mastertype;
    union {
        virDomainDeviceUSBMaster usb;
    } master;
    /* rombar and romfile are only used for pci hostdev and network
     * devices. */
    int rombar;         /* enum virDomainPciRombarMode */
    char *romfile;
    /* bootIndex is only used for disk, network interface, hostdev
     * and redirdev devices */
    int bootIndex;
};

enum virDomainSeclabelType {
    VIR_DOMAIN_SECLABEL_DEFAULT,
    VIR_DOMAIN_SECLABEL_NONE,
    VIR_DOMAIN_SECLABEL_DYNAMIC,
    VIR_DOMAIN_SECLABEL_STATIC,

    VIR_DOMAIN_SECLABEL_LAST
};

/* Security configuration for domain */
typedef struct _virSecurityLabelDef virSecurityLabelDef;
typedef virSecurityLabelDef *virSecurityLabelDefPtr;
struct _virSecurityLabelDef {
    char *model;        /* name of security model */
    char *label;        /* security label string */
    char *imagelabel;   /* security image label string */
    char *baselabel;    /* base name of label string */
    int type;           /* virDomainSeclabelType */
    bool norelabel;
    bool implicit;      /* true if seclabel is auto-added */
};


/* Security configuration for domain */
typedef struct _virSecurityDeviceLabelDef virSecurityDeviceLabelDef;
typedef virSecurityDeviceLabelDef *virSecurityDeviceLabelDefPtr;
struct _virSecurityDeviceLabelDef {
    char *model;
    char *label;        /* image label string */
    bool norelabel;     /* true to skip label attempts */
    bool labelskip;     /* live-only; true if skipping failed label attempt */
};


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


enum virDomainHostdevMode {
    VIR_DOMAIN_HOSTDEV_MODE_SUBSYS,
    VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES,

    VIR_DOMAIN_HOSTDEV_MODE_LAST
};

enum virDomainHostdevSubsysType {
    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB,
    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI,
    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI,

    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST
};

/* the backend driver used for PCI hostdev devices */
typedef enum {
    VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT, /* detect automaticaly, prefer VFIO */
    VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM,    /* force legacy kvm style */
    VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO,   /* force vfio */
    VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN,    /* force legacy xen style, use pciback */

    VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST
} virDomainHostdevSubsysPciBackendType;

VIR_ENUM_DECL(virDomainHostdevSubsysPciBackend)

typedef struct _virDomainHostdevSubsys virDomainHostdevSubsys;
typedef virDomainHostdevSubsys *virDomainHostdevSubsysPtr;
struct _virDomainHostdevSubsys {
    int type; /* enum virDomainHostdevSubsysType */
    union {
        struct {
            bool autoAddress; /* bus/device were filled automatically based
                                 on vedor/product */
            unsigned bus;
            unsigned device;

            unsigned vendor;
            unsigned product;
        } usb;
        struct {
            virDevicePCIAddress addr; /* host address */
            int backend; /* enum virDomainHostdevSubsysPciBackendType */
        } pci;
        struct {
            char *adapter;
            unsigned bus;
            unsigned target;
            unsigned unit;
            int sgio; /* enum virDomainDeviceSGIO */
        } scsi;
    } u;
};


enum virDomainHostdevCapsType {
    VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE,
    VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC,
    VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET,

    VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST
};

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
            char *iface;
        } net;
    } u;
};


/* basic device for direct passthrough */
struct _virDomainHostdevDef {
    virDomainDeviceDef parent; /* higher level Def containing this */
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

/* Types of disk backends (host resource) */
enum virDomainDiskType {
    VIR_DOMAIN_DISK_TYPE_BLOCK,
    VIR_DOMAIN_DISK_TYPE_FILE,
    VIR_DOMAIN_DISK_TYPE_DIR,
    VIR_DOMAIN_DISK_TYPE_NETWORK,
    VIR_DOMAIN_DISK_TYPE_VOLUME,

    VIR_DOMAIN_DISK_TYPE_LAST
};

/* Types of disk frontend (guest view) */
enum virDomainDiskDevice {
    VIR_DOMAIN_DISK_DEVICE_DISK,
    VIR_DOMAIN_DISK_DEVICE_CDROM,
    VIR_DOMAIN_DISK_DEVICE_FLOPPY,
    VIR_DOMAIN_DISK_DEVICE_LUN,

    VIR_DOMAIN_DISK_DEVICE_LAST
};

enum virDomainDiskBus {
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
};

enum virDomainDiskCache {
    VIR_DOMAIN_DISK_CACHE_DEFAULT,
    VIR_DOMAIN_DISK_CACHE_DISABLE,
    VIR_DOMAIN_DISK_CACHE_WRITETHRU,
    VIR_DOMAIN_DISK_CACHE_WRITEBACK,
    VIR_DOMAIN_DISK_CACHE_DIRECTSYNC,
    VIR_DOMAIN_DISK_CACHE_UNSAFE,

    VIR_DOMAIN_DISK_CACHE_LAST
};

enum virDomainDiskErrorPolicy {
    VIR_DOMAIN_DISK_ERROR_POLICY_DEFAULT,
    VIR_DOMAIN_DISK_ERROR_POLICY_STOP,
    VIR_DOMAIN_DISK_ERROR_POLICY_REPORT,
    VIR_DOMAIN_DISK_ERROR_POLICY_IGNORE,
    VIR_DOMAIN_DISK_ERROR_POLICY_ENOSPACE,

    VIR_DOMAIN_DISK_ERROR_POLICY_LAST
};

enum virDomainDiskProtocol {
    VIR_DOMAIN_DISK_PROTOCOL_NBD,
    VIR_DOMAIN_DISK_PROTOCOL_RBD,
    VIR_DOMAIN_DISK_PROTOCOL_SHEEPDOG,
    VIR_DOMAIN_DISK_PROTOCOL_GLUSTER,
    VIR_DOMAIN_DISK_PROTOCOL_ISCSI,
    VIR_DOMAIN_DISK_PROTOCOL_HTTP,
    VIR_DOMAIN_DISK_PROTOCOL_HTTPS,
    VIR_DOMAIN_DISK_PROTOCOL_FTP,
    VIR_DOMAIN_DISK_PROTOCOL_FTPS,
    VIR_DOMAIN_DISK_PROTOCOL_TFTP,

    VIR_DOMAIN_DISK_PROTOCOL_LAST
};

enum virDomainDiskProtocolTransport {
    VIR_DOMAIN_DISK_PROTO_TRANS_TCP,
    VIR_DOMAIN_DISK_PROTO_TRANS_UNIX,
    VIR_DOMAIN_DISK_PROTO_TRANS_RDMA,

    VIR_DOMAIN_DISK_PROTO_TRANS_LAST
};

enum virDomainDiskTray {
    VIR_DOMAIN_DISK_TRAY_CLOSED,
    VIR_DOMAIN_DISK_TRAY_OPEN,

    VIR_DOMAIN_DISK_TRAY_LAST
};

enum virDomainDiskGeometryTrans {
    VIR_DOMAIN_DISK_TRANS_DEFAULT = 0,
    VIR_DOMAIN_DISK_TRANS_NONE,
    VIR_DOMAIN_DISK_TRANS_AUTO,
    VIR_DOMAIN_DISK_TRANS_LBA,

    VIR_DOMAIN_DISK_TRANS_LAST
};

typedef struct _virDomainDiskHostDef virDomainDiskHostDef;
typedef virDomainDiskHostDef *virDomainDiskHostDefPtr;
struct _virDomainDiskHostDef {
    char *name;
    char *port;
    int transport; /* enum virDomainDiskProtocolTransport */
    char *socket;  /* path to unix socket */
};

enum virDomainDiskIo {
    VIR_DOMAIN_DISK_IO_DEFAULT,
    VIR_DOMAIN_DISK_IO_NATIVE,
    VIR_DOMAIN_DISK_IO_THREADS,

    VIR_DOMAIN_DISK_IO_LAST
};

enum virDomainIoEventFd {
    VIR_DOMAIN_IO_EVENT_FD_DEFAULT = 0,
    VIR_DOMAIN_IO_EVENT_FD_ON,
    VIR_DOMAIN_IO_EVENT_FD_OFF,

    VIR_DOMAIN_IO_EVENT_FD_LAST
};

enum virDomainVirtioEventIdx {
    VIR_DOMAIN_VIRTIO_EVENT_IDX_DEFAULT = 0,
    VIR_DOMAIN_VIRTIO_EVENT_IDX_ON,
    VIR_DOMAIN_VIRTIO_EVENT_IDX_OFF,

    VIR_DOMAIN_VIRTIO_EVENT_IDX_LAST
};

enum virDomainDiskCopyOnRead {
    VIR_DOMAIN_DISK_COPY_ON_READ_DEFAULT = 0,
    VIR_DOMAIN_DISK_COPY_ON_READ_ON,
    VIR_DOMAIN_DISK_COPY_ON_READ_OFF,

    VIR_DOMAIN_DISK_COPY_ON_READ_LAST
};

enum virDomainStartupPolicy {
    VIR_DOMAIN_STARTUP_POLICY_DEFAULT = 0,
    VIR_DOMAIN_STARTUP_POLICY_MANDATORY,
    VIR_DOMAIN_STARTUP_POLICY_REQUISITE,
    VIR_DOMAIN_STARTUP_POLICY_OPTIONAL,

    VIR_DOMAIN_STARTUP_POLICY_LAST
};

enum virDomainDiskSecretType {
    VIR_DOMAIN_DISK_SECRET_TYPE_NONE,
    VIR_DOMAIN_DISK_SECRET_TYPE_UUID,
    VIR_DOMAIN_DISK_SECRET_TYPE_USAGE,

    VIR_DOMAIN_DISK_SECRET_TYPE_LAST
};

enum virDomainDeviceSGIO {
    VIR_DOMAIN_DEVICE_SGIO_DEFAULT = 0,
    VIR_DOMAIN_DEVICE_SGIO_FILTERED,
    VIR_DOMAIN_DEVICE_SGIO_UNFILTERED,

    VIR_DOMAIN_DEVICE_SGIO_LAST
};

enum virDomainDiskDiscard {
    VIR_DOMAIN_DISK_DISCARD_DEFAULT = 0,
    VIR_DOMAIN_DISK_DISCARD_UNMAP,
    VIR_DOMAIN_DISK_DISCARD_IGNORE,

    VIR_DOMAIN_DISK_DISCARD_LAST
};

typedef struct _virDomainBlockIoTuneInfo virDomainBlockIoTuneInfo;
struct _virDomainBlockIoTuneInfo {
    unsigned long long total_bytes_sec;
    unsigned long long read_bytes_sec;
    unsigned long long write_bytes_sec;
    unsigned long long total_iops_sec;
    unsigned long long read_iops_sec;
    unsigned long long write_iops_sec;
};
typedef virDomainBlockIoTuneInfo *virDomainBlockIoTuneInfoPtr;

/*
 * Used for volume "type" disk to indicate how to represent
 * the disk source if the specified "pool" is of iscsi type.
 */
enum virDomainDiskSourcePoolMode {
    VIR_DOMAIN_DISK_SOURCE_POOL_MODE_DEFAULT = 0,

    /* Use the path as it shows up on host, e.g.
     * /dev/disk/by-path/ip-$ip-iscsi-$iqn:iscsi.iscsi-pool0-lun-1
     */
    VIR_DOMAIN_DISK_SOURCE_POOL_MODE_HOST,

    /* Use the URI from the storage pool source element host attribute. E.g.
     * file=iscsi://demo.org:6000/iqn.1992-01.com.example/1.
     */
    VIR_DOMAIN_DISK_SOURCE_POOL_MODE_DIRECT,

    VIR_DOMAIN_DISK_SOURCE_POOL_MODE_LAST
};

typedef struct _virDomainDiskSourcePoolDef virDomainDiskSourcePoolDef;
struct _virDomainDiskSourcePoolDef {
    char *pool; /* pool name */
    char *volume; /* volume name */
    int voltype; /* enum virStorageVolType, internal only */
    int pooltype; /* enum virStoragePoolType, internal only */
    int actualtype; /* enum virDomainDiskType, internal only */
    int mode; /* enum virDomainDiskSourcePoolMode */
};
typedef virDomainDiskSourcePoolDef *virDomainDiskSourcePoolDefPtr;

typedef struct _virDomainDiskSourceDef virDomainDiskSourceDef;
typedef virDomainDiskSourceDef *virDomainDiskSourceDefPtr;

/* Stores information related to a host resource.  In the case of
 * backing chains, multiple source disks join to form a single guest
 * view.  TODO Move this to util/ */
struct _virDomainDiskSourceDef {
    int type; /* enum virDomainDiskType */
    char *path;
    int protocol; /* enum virDomainDiskProtocol */
    size_t nhosts;
    virDomainDiskHostDefPtr hosts;
    virDomainDiskSourcePoolDefPtr srcpool;
    struct {
        char *username;
        int secretType; /* enum virDomainDiskSecretType */
        union {
            unsigned char uuid[VIR_UUID_BUFLEN];
            char *usage;
        } secret;
    } auth;
    virStorageEncryptionPtr encryption;
    char *driverName;
    int format; /* enum virStorageFileFormat */

    size_t nseclabels;
    virSecurityDeviceLabelDefPtr *seclabels;
};

/* Stores the virtual disk configuration */
struct _virDomainDiskDef {
    virDomainDiskSourceDef src;

    int device; /* enum virDomainDiskDevice */
    int bus; /* enum virDomainDiskBus */
    char *dst;
    int tray_status; /* enum virDomainDiskTray */
    int removable; /* enum virDomainFeatureState */
    virStorageFileMetadataPtr backingChain;

    char *mirror;
    int mirrorFormat; /* enum virStorageFileFormat */
    bool mirroring;

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
    int ioeventfd; /* enum virDomainIoEventFd */
    int event_idx; /* enum virDomainVirtioEventIdx */
    int copy_on_read; /* enum virDomainDiskCopyOnRead */
    int snapshot; /* enum virDomainSnapshotLocation, snapshot_conf.h */
    int startupPolicy; /* enum virDomainStartupPolicy */
    bool readonly;
    bool shared;
    bool transient;
    virDomainDeviceInfo info;
    bool rawio_specified;
    int rawio; /* no = 0, yes = 1 */
    int sgio; /* enum virDomainDeviceSGIO */
    int discard; /* enum virDomainDiskDiscard */
};


enum virDomainControllerType {
    VIR_DOMAIN_CONTROLLER_TYPE_IDE,
    VIR_DOMAIN_CONTROLLER_TYPE_FDC,
    VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
    VIR_DOMAIN_CONTROLLER_TYPE_SATA,
    VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL,
    VIR_DOMAIN_CONTROLLER_TYPE_CCID,
    VIR_DOMAIN_CONTROLLER_TYPE_USB,
    VIR_DOMAIN_CONTROLLER_TYPE_PCI,

    VIR_DOMAIN_CONTROLLER_TYPE_LAST
};


typedef enum {
    VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT,
    VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT,
    VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE,
    VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE,

    VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST
} virDomainControllerModelPCI;

enum virDomainControllerModelSCSI {
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1078,

    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LAST
};

enum virDomainControllerModelUSB {
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
    VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE,

    VIR_DOMAIN_CONTROLLER_MODEL_USB_LAST
};

typedef struct _virDomainVirtioSerialOpts virDomainVirtioSerialOpts;
typedef virDomainVirtioSerialOpts *virDomainVirtioSerialOptsPtr;
struct _virDomainVirtioSerialOpts {
    int ports;   /* -1 == undef */
    int vectors; /* -1 == undef */
};

typedef struct _virDomainPciControllerOpts virDomainPciControllerOpts;
typedef virDomainPciControllerOpts *virDomainPciControllerOptsPtr;
struct _virDomainPciControllerOpts {
    bool pcihole64;
    unsigned long pcihole64size;
};

/* Stores the virtual disk controller configuration */
struct _virDomainControllerDef {
    int type;
    unsigned int idx;
    int model; /* -1 == undef */
    unsigned int queues;
    union {
        virDomainVirtioSerialOpts vioserial;
        virDomainPciControllerOpts pciopts;
    } opts;
    virDomainDeviceInfo info;
};


/* Two types of disk backends */
enum virDomainFSType {
    VIR_DOMAIN_FS_TYPE_MOUNT, /* Mounts (binds) a host dir on a guest dir */
    VIR_DOMAIN_FS_TYPE_BLOCK, /* Mounts a host block dev on a guest dir */
    VIR_DOMAIN_FS_TYPE_FILE,  /* Loopback mounts a host file on a guest dir */
    VIR_DOMAIN_FS_TYPE_TEMPLATE, /* Expands a OS template to a guest dir */
    VIR_DOMAIN_FS_TYPE_RAM,   /* Mount a RAM filesystem on a guest dir */
    VIR_DOMAIN_FS_TYPE_BIND,  /* Binds a guest dir to another guest dir */

    VIR_DOMAIN_FS_TYPE_LAST
};

/* Filesystem driver type */
enum virDomainFSDriverType {
    VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT = 0,
    VIR_DOMAIN_FS_DRIVER_TYPE_PATH,
    VIR_DOMAIN_FS_DRIVER_TYPE_HANDLE,
    VIR_DOMAIN_FS_DRIVER_TYPE_LOOP,
    VIR_DOMAIN_FS_DRIVER_TYPE_NBD,

    VIR_DOMAIN_FS_DRIVER_TYPE_LAST
};

/* Filesystem mount access mode  */
enum virDomainFSAccessMode {
    VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH,
    VIR_DOMAIN_FS_ACCESSMODE_MAPPED,
    VIR_DOMAIN_FS_ACCESSMODE_SQUASH,

    VIR_DOMAIN_FS_ACCESSMODE_LAST
};

/* Filesystem Write policy */
enum virDomainFSWrpolicy {
    VIR_DOMAIN_FS_WRPOLICY_DEFAULT = 0,
    VIR_DOMAIN_FS_WRPOLICY_IMMEDIATE,

    VIR_DOMAIN_FS_WRPOLICY_LAST
};

/* Allow 2 MB ram usage */
# define VIR_DOMAIN_FS_RAM_DEFAULT_USAGE (1024 * 2)

struct _virDomainFSDef {
    int type;
    int fsdriver; /* enum virDomainFSDriverType */
    int accessmode; /* enum virDomainFSAccessMode */
    int wrpolicy; /* enum virDomainFSWrpolicy */
    int format; /* enum virStorageFileFormat */
    unsigned long long usage; /* in bytes */
    char *src;
    char *dst;
    bool readonly;
    virDomainDeviceInfo info;
    unsigned long long space_hard_limit; /* in bytes */
    unsigned long long space_soft_limit; /* in bytes */
};


/* network config types */
enum virDomainNetType {
    VIR_DOMAIN_NET_TYPE_USER,
    VIR_DOMAIN_NET_TYPE_ETHERNET,
    VIR_DOMAIN_NET_TYPE_SERVER,
    VIR_DOMAIN_NET_TYPE_CLIENT,
    VIR_DOMAIN_NET_TYPE_MCAST,
    VIR_DOMAIN_NET_TYPE_NETWORK,
    VIR_DOMAIN_NET_TYPE_BRIDGE,
    VIR_DOMAIN_NET_TYPE_INTERNAL,
    VIR_DOMAIN_NET_TYPE_DIRECT,
    VIR_DOMAIN_NET_TYPE_HOSTDEV,

    VIR_DOMAIN_NET_TYPE_LAST
};

/* the backend driver used for virtio interfaces */
enum virDomainNetBackendType {
    VIR_DOMAIN_NET_BACKEND_TYPE_DEFAULT, /* prefer kernel, fall back to user */
    VIR_DOMAIN_NET_BACKEND_TYPE_QEMU,    /* userland */
    VIR_DOMAIN_NET_BACKEND_TYPE_VHOST,   /* kernel */

    VIR_DOMAIN_NET_BACKEND_TYPE_LAST
};

/* the TX algorithm used for virtio interfaces */
enum virDomainNetVirtioTxModeType {
    VIR_DOMAIN_NET_VIRTIO_TX_MODE_DEFAULT, /* default for this version of qemu */
    VIR_DOMAIN_NET_VIRTIO_TX_MODE_IOTHREAD,
    VIR_DOMAIN_NET_VIRTIO_TX_MODE_TIMER,

    VIR_DOMAIN_NET_VIRTIO_TX_MODE_LAST
};

/* link interface states */
enum virDomainNetInterfaceLinkState {
        VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DEFAULT = 0, /* Default link state (up) */
        VIR_DOMAIN_NET_INTERFACE_LINK_STATE_UP,          /* Link is up. ("cable" connected) */
        VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN ,       /* Link is down. ("cable" disconnected) */

        VIR_DOMAIN_NET_INTERFACE_LINK_STATE_LAST
};

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
    unsigned int class_id; /* class ID for bandwidth 'floor' */
};

/* Stores the virtual network interface configuration */
struct _virDomainNetDef {
    enum virDomainNetType type;
    virMacAddr mac;
    char *model;
    union {
        struct {
            enum virDomainNetBackendType name; /* which driver backend to use */
            enum virDomainNetVirtioTxModeType txmode;
            enum virDomainIoEventFd ioeventfd;
            enum virDomainVirtioEventIdx event_idx;
            unsigned int queues; /* Multiqueue virtio-net */
        } virtio;
    } driver;
    union {
        struct {
            char *dev;
            char *ipaddr;
        } ethernet;
        struct {
            char *address;
            int port;
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
            char *ipaddr;
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
    char *ifname;
    virDomainDeviceInfo info;
    char *filter;
    virNWFilterHashTablePtr filterparams;
    virNetDevBandwidthPtr bandwidth;
    virNetDevVlan vlan;
    int linkstate;
};

/* Used for prefix of ifname of any network name generated dynamically
 * by libvirt, and cannot be used for a persistent network name.  */
# define VIR_NET_GENERATED_PREFIX "vnet"

enum virDomainChrDeviceType {
    VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL = 0,
    VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL,
    VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE,
    VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL,

    VIR_DOMAIN_CHR_DEVICE_TYPE_LAST
};

enum virDomainChrSerialTargetType {
    VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA = 0,
    VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB,

    VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_LAST
};

enum virDomainChrChannelTargetType {
    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_NONE = 0,
    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD,
    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO,

    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_LAST
};

enum virDomainChrConsoleTargetType {
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
};

enum virDomainChrType {
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

    VIR_DOMAIN_CHR_TYPE_LAST
};

enum virDomainChrTcpProtocol {
    VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW,
    VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET,
    VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNETS, /* secure telnet */
    VIR_DOMAIN_CHR_TCP_PROTOCOL_TLS,

    VIR_DOMAIN_CHR_TCP_PROTOCOL_LAST
};

enum virDomainChrSpicevmcName {
    VIR_DOMAIN_CHR_SPICEVMC_VDAGENT,
    VIR_DOMAIN_CHR_SPICEVMC_SMARTCARD,
    VIR_DOMAIN_CHR_SPICEVMC_USBREDIR,

    VIR_DOMAIN_CHR_SPICEVMC_LAST
};

/* The host side information for a character device.  */
typedef struct _virDomainChrSourceDef virDomainChrSourceDef;
typedef virDomainChrSourceDef *virDomainChrSourceDefPtr;
struct _virDomainChrSourceDef {
    int type; /* virDomainChrType */
    union {
        /* no <source> for null, vc, stdio */
        struct {
            char *path;
        } file; /* pty, file, pipe, or device */
        struct {
            char *host;
            char *service;
            bool listen;
            int protocol;
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
};

/* A complete character device, both host and domain views.  */
struct _virDomainChrDef {
    int deviceType;

    bool targetTypeAttr;
    int targetType;
    union {
        int port; /* parallel, serial, console */
        virSocketAddrPtr addr; /* guestfwd */
        char *name; /* virtio */
    } target;

    virDomainChrSourceDef source;

    virDomainDeviceInfo info;

    size_t nseclabels;
    virSecurityDeviceLabelDefPtr *seclabels;
};

enum virDomainSmartcardType {
    VIR_DOMAIN_SMARTCARD_TYPE_HOST,
    VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES,
    VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH,

    VIR_DOMAIN_SMARTCARD_TYPE_LAST
};

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
        virDomainChrSourceDef passthru; /* 'passthrough' */
    } data;

    virDomainDeviceInfo info;
};

struct _virDomainHubDef {
    int type;
    virDomainDeviceInfo info;
};

enum virDomainTPMModel {
    VIR_DOMAIN_TPM_MODEL_TIS,

    VIR_DOMAIN_TPM_MODEL_LAST
};

enum virDomainTPMBackendType {
    VIR_DOMAIN_TPM_TYPE_PASSTHROUGH,

    VIR_DOMAIN_TPM_TYPE_LAST
};

# define VIR_DOMAIN_TPM_DEFAULT_DEVICE "/dev/tpm0"

typedef struct _virDomainTPMDef virDomainTPMDef;
typedef virDomainTPMDef *virDomainTPMDefPtr;
struct _virDomainTPMDef {
    enum virDomainTPMBackendType type;
    virDomainDeviceInfo info;
    enum virDomainTPMModel model;
    union {
        struct {
            virDomainChrSourceDef source;
        } passthrough;
    } data;
};

enum virDomainInputType {
    VIR_DOMAIN_INPUT_TYPE_MOUSE,
    VIR_DOMAIN_INPUT_TYPE_TABLET,
    VIR_DOMAIN_INPUT_TYPE_KBD,

    VIR_DOMAIN_INPUT_TYPE_LAST
};

enum virDomainInputBus {
    VIR_DOMAIN_INPUT_BUS_PS2,
    VIR_DOMAIN_INPUT_BUS_USB,
    VIR_DOMAIN_INPUT_BUS_XEN,

    VIR_DOMAIN_INPUT_BUS_LAST
};

struct _virDomainInputDef {
    int type;
    int bus;
    virDomainDeviceInfo info;
};

enum virDomainSoundCodecType {
    VIR_DOMAIN_SOUND_CODEC_TYPE_DUPLEX,
    VIR_DOMAIN_SOUND_CODEC_TYPE_MICRO,

    VIR_DOMAIN_SOUND_CODEC_TYPE_LAST
};

enum virDomainSoundModel {
    VIR_DOMAIN_SOUND_MODEL_SB16,
    VIR_DOMAIN_SOUND_MODEL_ES1370,
    VIR_DOMAIN_SOUND_MODEL_PCSPK,
    VIR_DOMAIN_SOUND_MODEL_AC97,
    VIR_DOMAIN_SOUND_MODEL_ICH6,
    VIR_DOMAIN_SOUND_MODEL_ICH9,

    VIR_DOMAIN_SOUND_MODEL_LAST
};

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

enum virDomainWatchdogModel {
    VIR_DOMAIN_WATCHDOG_MODEL_I6300ESB,
    VIR_DOMAIN_WATCHDOG_MODEL_IB700,

    VIR_DOMAIN_WATCHDOG_MODEL_LAST
};

enum virDomainWatchdogAction {
    VIR_DOMAIN_WATCHDOG_ACTION_RESET,
    VIR_DOMAIN_WATCHDOG_ACTION_SHUTDOWN,
    VIR_DOMAIN_WATCHDOG_ACTION_POWEROFF,
    VIR_DOMAIN_WATCHDOG_ACTION_PAUSE,
    VIR_DOMAIN_WATCHDOG_ACTION_DUMP,
    VIR_DOMAIN_WATCHDOG_ACTION_NONE,

    VIR_DOMAIN_WATCHDOG_ACTION_LAST
};

struct _virDomainWatchdogDef {
    int model;
    int action;
    virDomainDeviceInfo info;
};


enum virDomainVideoType {
    VIR_DOMAIN_VIDEO_TYPE_VGA,
    VIR_DOMAIN_VIDEO_TYPE_CIRRUS,
    VIR_DOMAIN_VIDEO_TYPE_VMVGA,
    VIR_DOMAIN_VIDEO_TYPE_XEN,
    VIR_DOMAIN_VIDEO_TYPE_VBOX,
    VIR_DOMAIN_VIDEO_TYPE_QXL,

    VIR_DOMAIN_VIDEO_TYPE_LAST
};


typedef struct _virDomainVideoAccelDef virDomainVideoAccelDef;
typedef virDomainVideoAccelDef *virDomainVideoAccelDefPtr;
struct _virDomainVideoAccelDef {
    bool support3d;
    bool support2d;
};


struct _virDomainVideoDef {
    int type;
    unsigned int ram;  /* kibibytes (multiples of 1024) */
    unsigned int vram; /* kibibytes (multiples of 1024) */
    unsigned int heads;
    bool primary;
    virDomainVideoAccelDefPtr accel;
    virDomainDeviceInfo info;
};

/* graphics console modes */
enum virDomainGraphicsType {
    VIR_DOMAIN_GRAPHICS_TYPE_SDL,
    VIR_DOMAIN_GRAPHICS_TYPE_VNC,
    VIR_DOMAIN_GRAPHICS_TYPE_RDP,
    VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP,
    VIR_DOMAIN_GRAPHICS_TYPE_SPICE,

    VIR_DOMAIN_GRAPHICS_TYPE_LAST
};

enum virDomainGraphicsVNCSharePolicy {
    VIR_DOMAIN_GRAPHICS_VNC_SHARE_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_VNC_SHARE_ALLOW_EXCLUSIVE,
    VIR_DOMAIN_GRAPHICS_VNC_SHARE_FORCE_SHARED,
    VIR_DOMAIN_GRAPHICS_VNC_SHARE_IGNORE,

    VIR_DOMAIN_GRAPHICS_VNC_SHARE_LAST
};

enum virDomainGraphicsAuthConnectedType {
    VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_FAIL,
    VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_DISCONNECT,
    VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_KEEP,

    VIR_DOMAIN_GRAPHICS_AUTH_CONNECTED_LAST
};

typedef struct _virDomainGraphicsAuthDef virDomainGraphicsAuthDef;
typedef virDomainGraphicsAuthDef *virDomainGraphicsAuthDefPtr;
struct _virDomainGraphicsAuthDef {
    char *passwd;
    bool expires; /* Whether there is an expiry time set */
    time_t validTo;  /* seconds since epoch */
    int connected; /* action if connected */
};

enum virDomainGraphicsSpiceChannelName {
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MAIN,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_DISPLAY,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_INPUT,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_CURSOR,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_PLAYBACK,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_RECORD,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_SMARTCARD,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_USBREDIR,

    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST
};

enum virDomainGraphicsSpiceChannelMode {
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE,
    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE,

    VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_LAST
};

enum virDomainGraphicsSpiceImageCompression {
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_AUTO_GLZ,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_AUTO_LZ,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_QUIC,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_GLZ,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_LZ,
    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_OFF,

    VIR_DOMAIN_GRAPHICS_SPICE_IMAGE_COMPRESSION_LAST
};

enum virDomainGraphicsSpiceJpegCompression {
    VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_AUTO,
    VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_NEVER,
    VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_ALWAYS,

    VIR_DOMAIN_GRAPHICS_SPICE_JPEG_COMPRESSION_LAST
};

enum virDomainGraphicsSpiceZlibCompression {
    VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_AUTO,
    VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_NEVER,
    VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_ALWAYS,

    VIR_DOMAIN_GRAPHICS_SPICE_ZLIB_COMPRESSION_LAST
};

enum virDomainGraphicsSpicePlaybackCompression {
    VIR_DOMAIN_GRAPHICS_SPICE_PLAYBACK_COMPRESSION_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_PLAYBACK_COMPRESSION_ON,
    VIR_DOMAIN_GRAPHICS_SPICE_PLAYBACK_COMPRESSION_OFF,

    VIR_DOMAIN_GRAPHICS_SPICE_PLAYBACK_COMPRESSION_LAST
};

enum virDomainGraphicsSpiceMouseMode {
    VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_SERVER,
    VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_CLIENT,

    VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_LAST
};

enum virDomainGraphicsSpiceStreamingMode {
    VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_FILTER,
    VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_ALL,
    VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_OFF,

    VIR_DOMAIN_GRAPHICS_SPICE_STREAMING_MODE_LAST
};

enum virDomainGraphicsSpiceClipboardCopypaste {
    VIR_DOMAIN_GRAPHICS_SPICE_CLIPBOARD_COPYPASTE_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_CLIPBOARD_COPYPASTE_YES,
    VIR_DOMAIN_GRAPHICS_SPICE_CLIPBOARD_COPYPASTE_NO,

    VIR_DOMAIN_GRAPHICS_SPICE_CLIPBOARD_COPYPASTE_LAST
};

enum virDomainGraphicsSpiceAgentFileTransfer {
    VIR_DOMAIN_GRAPHICS_SPICE_AGENT_FILE_TRANSFER_DEFAULT = 0,
    VIR_DOMAIN_GRAPHICS_SPICE_AGENT_FILE_TRANSFER_YES,
    VIR_DOMAIN_GRAPHICS_SPICE_AGENT_FILE_TRANSFER_NO,

    VIR_DOMAIN_GRAPHICS_SPICE_AGENT_FILE_TRANSFER_LAST
};

enum virDomainGraphicsListenType {
    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE = 0,
    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS,
    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK,

    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST
};

enum virDomainHubType {
    VIR_DOMAIN_HUB_TYPE_USB,

    VIR_DOMAIN_HUB_TYPE_LAST
};

typedef struct _virDomainGraphicsListenDef virDomainGraphicsListenDef;
typedef virDomainGraphicsListenDef *virDomainGraphicsListenDefPtr;
struct _virDomainGraphicsListenDef {
    int type;   /* enum virDomainGraphicsListenType */
    char *address;
    char *network;
    bool fromConfig;    /* true if the @address is config file originated */
};

struct _virDomainGraphicsDef {
    /* Port value discipline:
     * Value -1 is legacy syntax indicating that it should be auto-allocated.
     * Value 0 means port wasn't specified in XML at all.
     * Positive value is actual port number given in XML.
     */
    int type;
    union {
        struct {
            int port;
            int websocket;
            bool autoport;
            char *keymap;
            char *socket;
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
            int mousemode;
            char *keymap;
            virDomainGraphicsAuthDef auth;
            bool autoport;
            int channels[VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST];
            int defaultMode; /* enum virDomainGraphicsSpiceChannelMode */
            int image;
            int jpeg;
            int zlib;
            int playback;
            int streaming;
            int copypaste;
            int filetransfer;
        } spice;
    } data;
    /* nListens, listens, and *port are only useful if type is vnc,
     * rdp, or spice. They've been extracted from the union only to
     * simplify parsing code.*/
    size_t nListens;
    virDomainGraphicsListenDefPtr listens;
};

enum virDomainRedirdevBus {
    VIR_DOMAIN_REDIRDEV_BUS_USB,

    VIR_DOMAIN_REDIRDEV_BUS_LAST
};

struct _virDomainRedirdevDef {
    int bus; /* enum virDomainRedirdevBus */

    union {
        virDomainChrSourceDef chr;
    } source;

    virDomainDeviceInfo info; /* Guest address */
};

struct _virDomainRedirFilterUsbDevDef {
    int usbClass;
    int vendor;
    int product;
    int version;
    bool allow;
};

struct _virDomainRedirFilterDef {
    size_t nusbdevs;
    virDomainRedirFilterUsbDevDefPtr *usbdevs;
};

enum virDomainMemDump {
    VIR_DOMAIN_MEM_DUMP_DEFAULT = 0,
    VIR_DOMAIN_MEM_DUMP_ON,
    VIR_DOMAIN_MEM_DUMP_OFF,

    VIR_DOMAIN_MEM_DUMP_LAST,
};

enum {
    VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO,
    VIR_DOMAIN_MEMBALLOON_MODEL_XEN,
    VIR_DOMAIN_MEMBALLOON_MODEL_NONE,

    VIR_DOMAIN_MEMBALLOON_MODEL_LAST
};

struct _virDomainMemballoonDef {
    int model;
    virDomainDeviceInfo info;
    unsigned int period; /* seconds between collections */
};

struct _virDomainNVRAMDef {
    virDomainDeviceInfo info;
};

enum virDomainSmbiosMode {
    VIR_DOMAIN_SMBIOS_NONE = 0,
    VIR_DOMAIN_SMBIOS_EMULATE,
    VIR_DOMAIN_SMBIOS_HOST,
    VIR_DOMAIN_SMBIOS_SYSINFO,

    VIR_DOMAIN_SMBIOS_LAST
};


# define VIR_DOMAIN_MAX_BOOT_DEVS 4

enum virDomainBootOrder {
    VIR_DOMAIN_BOOT_FLOPPY,
    VIR_DOMAIN_BOOT_CDROM,
    VIR_DOMAIN_BOOT_DISK,
    VIR_DOMAIN_BOOT_NET,

    VIR_DOMAIN_BOOT_LAST
};

enum virDomainBootMenu {
    VIR_DOMAIN_BOOT_MENU_DEFAULT = 0,
    VIR_DOMAIN_BOOT_MENU_ENABLED,
    VIR_DOMAIN_BOOT_MENU_DISABLED,

    VIR_DOMAIN_BOOT_MENU_LAST
};

enum virDomainFeature {
    VIR_DOMAIN_FEATURE_ACPI,
    VIR_DOMAIN_FEATURE_APIC,
    VIR_DOMAIN_FEATURE_PAE,
    VIR_DOMAIN_FEATURE_HAP,
    VIR_DOMAIN_FEATURE_VIRIDIAN,
    VIR_DOMAIN_FEATURE_PRIVNET,
    VIR_DOMAIN_FEATURE_HYPERV,
    VIR_DOMAIN_FEATURE_PVSPINLOCK,

    VIR_DOMAIN_FEATURE_LAST
};

enum virDomainFeatureState {
    VIR_DOMAIN_FEATURE_STATE_DEFAULT = 0,
    VIR_DOMAIN_FEATURE_STATE_ON,
    VIR_DOMAIN_FEATURE_STATE_OFF,

    VIR_DOMAIN_FEATURE_STATE_LAST
};

enum virDomainHyperv {
    VIR_DOMAIN_HYPERV_RELAXED = 0,
    VIR_DOMAIN_HYPERV_VAPIC,
    VIR_DOMAIN_HYPERV_SPINLOCKS,

    VIR_DOMAIN_HYPERV_LAST
};

enum virDomainLifecycleAction {
    VIR_DOMAIN_LIFECYCLE_DESTROY,
    VIR_DOMAIN_LIFECYCLE_RESTART,
    VIR_DOMAIN_LIFECYCLE_RESTART_RENAME,
    VIR_DOMAIN_LIFECYCLE_PRESERVE,

    VIR_DOMAIN_LIFECYCLE_LAST
};

enum virDomainLifecycleCrashAction {
    VIR_DOMAIN_LIFECYCLE_CRASH_DESTROY,
    VIR_DOMAIN_LIFECYCLE_CRASH_RESTART,
    VIR_DOMAIN_LIFECYCLE_CRASH_RESTART_RENAME,
    VIR_DOMAIN_LIFECYCLE_CRASH_PRESERVE,
    VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_DESTROY,
    VIR_DOMAIN_LIFECYCLE_CRASH_COREDUMP_RESTART,

    VIR_DOMAIN_LIFECYCLE_CRASH_LAST
};

typedef enum {
    VIR_DOMAIN_LOCK_FAILURE_DEFAULT,
    VIR_DOMAIN_LOCK_FAILURE_POWEROFF,
    VIR_DOMAIN_LOCK_FAILURE_RESTART,
    VIR_DOMAIN_LOCK_FAILURE_PAUSE,
    VIR_DOMAIN_LOCK_FAILURE_IGNORE,

    VIR_DOMAIN_LOCK_FAILURE_LAST
} virDomainLockFailureAction;

VIR_ENUM_DECL(virDomainLockFailure)

enum virDomainPMState {
    VIR_DOMAIN_PM_STATE_DEFAULT = 0,
    VIR_DOMAIN_PM_STATE_ENABLED,
    VIR_DOMAIN_PM_STATE_DISABLED,

    VIR_DOMAIN_PM_STATE_LAST
};

enum virDomainBIOSUseserial {
    VIR_DOMAIN_BIOS_USESERIAL_DEFAULT = 0,
    VIR_DOMAIN_BIOS_USESERIAL_YES,
    VIR_DOMAIN_BIOS_USESERIAL_NO
};

typedef struct _virDomainBIOSDef virDomainBIOSDef;
typedef virDomainBIOSDef *virDomainBIOSDefPtr;
struct _virDomainBIOSDef {
    int useserial;
    /* reboot-timeout parameters */
    bool rt_set;
    int rt_delay;
};

/* Operating system configuration data & machine / arch */
typedef struct _virDomainOSDef virDomainOSDef;
typedef virDomainOSDef *virDomainOSDefPtr;
struct _virDomainOSDef {
    char *type;
    virArch arch;
    char *machine;
    size_t nBootDevs;
    int bootDevs[VIR_DOMAIN_BOOT_LAST];
    /* enum virDomainBootMenu */
    int bootmenu;
    char *init;
    char **initargv;
    char *kernel;
    char *initrd;
    char *cmdline;
    char *dtb;
    char *root;
    char *loader;
    char *bootloader;
    char *bootloaderArgs;
    int smbios_mode;

    virDomainBIOSDef bios;
};

enum virDomainTimerNameType {
    VIR_DOMAIN_TIMER_NAME_PLATFORM = 0,
    VIR_DOMAIN_TIMER_NAME_PIT,
    VIR_DOMAIN_TIMER_NAME_RTC,
    VIR_DOMAIN_TIMER_NAME_HPET,
    VIR_DOMAIN_TIMER_NAME_TSC,
    VIR_DOMAIN_TIMER_NAME_KVMCLOCK,
    VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK,

    VIR_DOMAIN_TIMER_NAME_LAST
};

enum virDomainTimerTrackType {
    VIR_DOMAIN_TIMER_TRACK_BOOT = 0,
    VIR_DOMAIN_TIMER_TRACK_GUEST,
    VIR_DOMAIN_TIMER_TRACK_WALL,

    VIR_DOMAIN_TIMER_TRACK_LAST
};

enum virDomainTimerTickpolicyType {
    VIR_DOMAIN_TIMER_TICKPOLICY_DELAY = 0,
    VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP,
    VIR_DOMAIN_TIMER_TICKPOLICY_MERGE,
    VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD,

    VIR_DOMAIN_TIMER_TICKPOLICY_LAST
};

enum virDomainTimerModeType {
    VIR_DOMAIN_TIMER_MODE_AUTO = 0,
    VIR_DOMAIN_TIMER_MODE_NATIVE,
    VIR_DOMAIN_TIMER_MODE_EMULATE,
    VIR_DOMAIN_TIMER_MODE_PARAVIRT,
    VIR_DOMAIN_TIMER_MODE_SMPSAFE,

    VIR_DOMAIN_TIMER_MODE_LAST
};

enum virDomainCpuPlacementMode {
    VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC = 0,
    VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO,

    VIR_DOMAIN_CPU_PLACEMENT_MODE_LAST
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

enum virDomainClockOffsetType {
    VIR_DOMAIN_CLOCK_OFFSET_UTC = 0,
    VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME = 1,
    VIR_DOMAIN_CLOCK_OFFSET_VARIABLE = 2,
    VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE = 3,

    VIR_DOMAIN_CLOCK_OFFSET_LAST
};

enum virDomainClockBasis {
    VIR_DOMAIN_CLOCK_BASIS_UTC = 0,
    VIR_DOMAIN_CLOCK_BASIS_LOCALTIME = 1,

    VIR_DOMAIN_CLOCK_BASIS_LAST
};

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

            /* Store the base date (-rtc base=$date, in seconds
             * since the Epoch) of guest process, internal only
             */
            unsigned long long basedate;
        } variable;

        /* Timezone name, when
         * offset == VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME */
        char *timezone;
    } data;

    size_t ntimers;
    virDomainTimerDefPtr *timers;
};

# define VIR_DOMAIN_CPUMASK_LEN 1024

typedef struct _virDomainVcpuPinDef virDomainVcpuPinDef;
typedef virDomainVcpuPinDef *virDomainVcpuPinDefPtr;
struct _virDomainVcpuPinDef {
    int vcpuid;
    virBitmapPtr cpumask;
};

void virDomainVcpuPinDefFree(virDomainVcpuPinDefPtr def);
void virDomainVcpuPinDefArrayFree(virDomainVcpuPinDefPtr *def, int nvcpupin);

virDomainVcpuPinDefPtr *virDomainVcpuPinDefCopy(virDomainVcpuPinDefPtr *src,
                                                int nvcpupin);

int virDomainVcpuPinIsDuplicate(virDomainVcpuPinDefPtr *def,
                                int nvcpupin,
                                int vcpu);

virDomainVcpuPinDefPtr virDomainVcpuPinFindByVcpu(virDomainVcpuPinDefPtr *def,
                                                  int nvcpupin,
                                                  int vcpu);

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

enum virDomainRNGModel {
    VIR_DOMAIN_RNG_MODEL_VIRTIO,

    VIR_DOMAIN_RNG_MODEL_LAST
};

enum virDomainRNGBackend {
    VIR_DOMAIN_RNG_BACKEND_RANDOM,
    VIR_DOMAIN_RNG_BACKEND_EGD,
    /* VIR_DOMAIN_RNG_BACKEND_POOL, */

    VIR_DOMAIN_RNG_BACKEND_LAST
};

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


struct _virDomainPanicDef {
    virDomainDeviceInfo info;
};


void virBlkioDeviceArrayClear(virBlkioDevicePtr deviceWeights,
                              int ndevices);

typedef struct _virDomainResourceDef virDomainResourceDef;
typedef virDomainResourceDef *virDomainResourceDefPtr;
struct _virDomainResourceDef {
    char *partition;
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
    int virtType;
    int id;
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *name;
    char *title;
    char *description;

    struct {
        unsigned int weight;

        size_t ndevices;
        virBlkioDevicePtr devices;
    } blkio;

    struct {
        unsigned long long max_balloon; /* in kibibytes */
        unsigned long long cur_balloon; /* in kibibytes */
        bool hugepage_backed;
        bool nosharepages;
        bool locked;
        int dump_core; /* enum virDomainMemDump */
        unsigned long long hard_limit; /* in kibibytes */
        unsigned long long soft_limit; /* in kibibytes */
        unsigned long long min_guarantee; /* in kibibytes */
        unsigned long long swap_hard_limit; /* in kibibytes */
    } mem;
    unsigned short vcpus;
    unsigned short maxvcpus;
    int placement_mode;
    virBitmapPtr cpumask;

    struct {
        unsigned long shares;
        bool sharesSpecified;
        unsigned long long period;
        long long quota;
        unsigned long long emulator_period;
        long long emulator_quota;
        size_t nvcpupin;
        virDomainVcpuPinDefPtr *vcpupin;
        virDomainVcpuPinDefPtr emulatorpin;
    } cputune;

    virNumaTuneDef numatune;
    virDomainResourceDefPtr resource;
    virDomainIdMapDef idmap;

    /* These 3 are based on virDomainLifeCycleAction enum flags */
    int onReboot;
    int onPoweroff;
    int onCrash;

    int onLockFailure; /* enum virDomainLockFailureAction */

    struct {
        /* These options are actually type of enum virDomainPMState */
        int s3;
        int s4;
    } pm;

    virDomainOSDef os;
    char *emulator;
    int features[VIR_DOMAIN_FEATURE_LAST];
    /* enum virDomainFeatureState */
    int apic_eoi;
    /* These options are of type virDomainFeatureState */
    int hyperv_features[VIR_DOMAIN_HYPERV_LAST];
    unsigned int hyperv_spinlocks;

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

    /* Only 1 */
    virDomainWatchdogDefPtr watchdog;
    virDomainMemballoonDefPtr memballoon;
    virDomainNVRAMDefPtr nvram;
    virDomainTPMDefPtr tpm;
    virCPUDefPtr cpu;
    virSysinfoDefPtr sysinfo;
    virDomainRedirFilterDefPtr redirfilter;
    virDomainRNGDefPtr rng;
    virDomainPanicDefPtr panic;

    void *namespaceData;
    virDomainXMLNamespace ns;

    /* Application-specific custom metadata */
    xmlNodePtr metadata;
};

enum virDomainTaintFlags {
    VIR_DOMAIN_TAINT_CUSTOM_ARGV,      /* Custom ARGV passthrough from XML */
    VIR_DOMAIN_TAINT_CUSTOM_MONITOR,   /* Custom monitor commands issued */
    VIR_DOMAIN_TAINT_HIGH_PRIVILEGES,  /* Running with undesirably high privileges */
    VIR_DOMAIN_TAINT_SHELL_SCRIPTS,    /* Network configuration using opaque shell scripts */
    VIR_DOMAIN_TAINT_DISK_PROBING,     /* Relying on potentially unsafe disk format probing */
    VIR_DOMAIN_TAINT_EXTERNAL_LAUNCH,  /* Externally launched guest domain */
    VIR_DOMAIN_TAINT_HOST_CPU,         /* Host CPU passthrough in use */
    VIR_DOMAIN_TAINT_HOOK,             /* Domain (possibly) changed via hook script */

    VIR_DOMAIN_TAINT_LAST
};

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

    pid_t pid;
    virDomainStateReason state;

    unsigned int autostart : 1;
    unsigned int persistent : 1;
    unsigned int updated : 1;

    virDomainDefPtr def; /* The current definition */
    virDomainDefPtr newDef; /* New definition to activate at shutdown */

    virDomainSnapshotObjListPtr snapshots;
    virDomainSnapshotObjPtr current_snapshot;

    bool hasManagedSave;

    void *privateData;
    void (*privateDataFreeFunc)(void *);

    int taint;
};

typedef struct _virDomainObjList virDomainObjList;
typedef virDomainObjList *virDomainObjListPtr;

typedef bool (*virDomainObjListFilter)(virConnectPtr conn,
                                       virDomainDefPtr def);


/* This structure holds various callbacks and data needed
 * while parsing and creating domain XMLs */
typedef struct _virDomainXMLOption virDomainXMLOption;
typedef virDomainXMLOption *virDomainXMLOptionPtr;

typedef void *(*virDomainXMLPrivateDataAllocFunc)(void);
typedef void (*virDomainXMLPrivateDataFreeFunc)(void *);
typedef int (*virDomainXMLPrivateDataFormatFunc)(virBufferPtr, void *);
typedef int (*virDomainXMLPrivateDataParseFunc)(xmlXPathContextPtr, void *);

/* Called once after everything else has been parsed, for adjusting
 * overall domain defaults.  */
typedef int (*virDomainDefPostParseCallback)(virDomainDefPtr def,
                                             virCapsPtr caps,
                                             void *opaque);
/* Called once per device, for adjusting per-device settings while
 * leaving the overall domain otherwise unchanged.  */
typedef int (*virDomainDeviceDefPostParseCallback)(virDomainDeviceDefPtr dev,
                                                   const virDomainDef *def,
                                                   virCapsPtr caps,
                                                   void *opaque);

typedef struct _virDomainDefParserConfig virDomainDefParserConfig;
typedef virDomainDefParserConfig *virDomainDefParserConfigPtr;
struct _virDomainDefParserConfig {
    /* driver domain definition callbacks */
    virDomainDefPostParseCallback domainPostParseCallback;
    virDomainDeviceDefPostParseCallback devicesPostParseCallback;

    /* private data for the callbacks */
    void *priv;
    virFreeCallback privFree;

    /* data */
    bool hasWideScsiBus;
    unsigned char macPrefix[VIR_MAC_PREFIX_BUFLEN];
};

typedef struct _virDomainXMLPrivateDataCallbacks virDomainXMLPrivateDataCallbacks;
typedef virDomainXMLPrivateDataCallbacks *virDomainXMLPrivateDataCallbacksPtr;
struct _virDomainXMLPrivateDataCallbacks {
    virDomainXMLPrivateDataAllocFunc  alloc;
    virDomainXMLPrivateDataFreeFunc   free;
    virDomainXMLPrivateDataFormatFunc format;
    virDomainXMLPrivateDataParseFunc  parse;
};

virDomainXMLOptionPtr virDomainXMLOptionNew(virDomainDefParserConfigPtr config,
                                            virDomainXMLPrivateDataCallbacksPtr priv,
                                            virDomainXMLNamespacePtr xmlns);

void virDomainNetGenerateMAC(virDomainXMLOptionPtr xmlopt, virMacAddrPtr mac);

virDomainXMLNamespacePtr
virDomainXMLOptionGetNamespace(virDomainXMLOptionPtr xmlopt)
    ATTRIBUTE_NONNULL(1);

int
virDomainDefPostParse(virDomainDefPtr def,
                      virCapsPtr caps,
                      virDomainXMLOptionPtr xmlopt);

static inline bool
virDomainObjIsActive(virDomainObjPtr dom)
{
    return dom->def->id != -1;
}

virDomainObjPtr virDomainObjNew(virDomainXMLOptionPtr caps)
    ATTRIBUTE_NONNULL(1);

virDomainObjListPtr virDomainObjListNew(void);

virDomainObjPtr virDomainObjListFindByID(virDomainObjListPtr doms,
                                         int id);
virDomainObjPtr virDomainObjListFindByUUID(virDomainObjListPtr doms,
                                           const unsigned char *uuid);
virDomainObjPtr virDomainObjListFindByName(virDomainObjListPtr doms,
                                           const char *name);

bool virDomainObjTaint(virDomainObjPtr obj,
                       enum virDomainTaintFlags taint);

void virDomainPanicDefFree(virDomainPanicDefPtr panic);
void virDomainResourceDefFree(virDomainResourceDefPtr resource);
void virDomainGraphicsDefFree(virDomainGraphicsDefPtr def);
void virDomainInputDefFree(virDomainInputDefPtr def);
void virDomainDiskDefFree(virDomainDiskDefPtr def);
void virDomainLeaseDefFree(virDomainLeaseDefPtr def);
void virDomainDiskAuthClear(virDomainDiskSourceDefPtr def);
void virDomainDiskHostDefClear(virDomainDiskHostDefPtr def);
void virDomainDiskHostDefFree(size_t nhosts, virDomainDiskHostDefPtr hosts);
virDomainDiskHostDefPtr virDomainDiskHostDefCopy(size_t nhosts,
                                                 virDomainDiskHostDefPtr hosts);
int virDomainDiskGetType(virDomainDiskDefPtr def);
void virDomainDiskSetType(virDomainDiskDefPtr def, int type);
int virDomainDiskGetActualType(virDomainDiskDefPtr def);
const char *virDomainDiskGetSource(virDomainDiskDefPtr def);
int virDomainDiskSetSource(virDomainDiskDefPtr def, const char *src)
    ATTRIBUTE_RETURN_CHECK;
const char *virDomainDiskGetDriver(virDomainDiskDefPtr def);
int virDomainDiskSetDriver(virDomainDiskDefPtr def, const char *name)
    ATTRIBUTE_RETURN_CHECK;
int virDomainDiskGetFormat(virDomainDiskDefPtr def);
void virDomainDiskSetFormat(virDomainDiskDefPtr def, int format);
int virDomainDeviceFindControllerModel(virDomainDefPtr def,
                                       virDomainDeviceInfoPtr info,
                                       int controllerType);
virDomainDiskDefPtr virDomainDiskFindByBusAndDst(virDomainDefPtr def,
                                                 int bus,
                                                 char *dst);
void virDomainControllerDefFree(virDomainControllerDefPtr def);
void virDomainFSDefFree(virDomainFSDefPtr def);
void virDomainActualNetDefFree(virDomainActualNetDefPtr def);
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
virDomainHostdevDefPtr virDomainHostdevDefAlloc(void);
void virDomainHostdevDefClear(virDomainHostdevDefPtr def);
void virDomainHostdevDefFree(virDomainHostdevDefPtr def);
void virDomainHubDefFree(virDomainHubDefPtr def);
void virDomainRedirdevDefFree(virDomainRedirdevDefPtr def);
void virDomainRedirFilterDefFree(virDomainRedirFilterDefPtr def);
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
void virDomainDefClearPCIAddresses(virDomainDefPtr def);
void virDomainDefClearCCWAddresses(virDomainDefPtr def);
void virDomainDefClearDeviceAliases(virDomainDefPtr def);
void virDomainTPMDefFree(virDomainTPMDefPtr def);

typedef int (*virDomainDeviceInfoCallback)(virDomainDefPtr def,
                                           virDomainDeviceDefPtr dev,
                                           virDomainDeviceInfoPtr info,
                                           void *opaque);

int virDomainDeviceInfoIterate(virDomainDefPtr def,
                               virDomainDeviceInfoCallback cb,
                               void *opaque);

void virDomainDefFree(virDomainDefPtr vm);

virDomainChrDefPtr virDomainChrDefNew(void);

virDomainDefPtr virDomainDefNew(const char *name,
                                const unsigned char *uuid,
                                int id);

enum {
    VIR_DOMAIN_OBJ_LIST_ADD_LIVE = (1 << 0),
    VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE = (1 << 1),
};
virDomainObjPtr virDomainObjListAdd(virDomainObjListPtr doms,
                                    virDomainDefPtr def,
                                    virDomainXMLOptionPtr xmlopt,
                                    unsigned int flags,
                                    virDomainDefPtr *oldDef);
void virDomainObjAssignDef(virDomainObjPtr domain,
                           virDomainDefPtr def,
                           bool live,
                           virDomainDefPtr *oldDef);
int virDomainObjSetDefTransient(virCapsPtr caps,
                                virDomainXMLOptionPtr xmlopt,
                                virDomainObjPtr domain,
                                bool live);
virDomainDefPtr
virDomainObjGetPersistentDef(virCapsPtr caps,
                             virDomainXMLOptionPtr xmlopt,
                             virDomainObjPtr domain);

int
virDomainLiveConfigHelperMethod(virCapsPtr caps,
                                virDomainXMLOptionPtr xmlopt,
                                virDomainObjPtr dom,
                                unsigned int *flags,
                                virDomainDefPtr *persistentDef);

virDomainDefPtr virDomainDefCopy(virDomainDefPtr src,
                                 virCapsPtr caps,
                                 virDomainXMLOptionPtr xmlopt,
                                 bool migratable);
virDomainDefPtr virDomainObjCopyPersistentDef(virDomainObjPtr dom,
                                              virCapsPtr caps,
                                              virDomainXMLOptionPtr xmlopt);

void virDomainObjListRemove(virDomainObjListPtr doms,
                            virDomainObjPtr dom);
void virDomainObjListRemoveLocked(virDomainObjListPtr doms,
                                  virDomainObjPtr dom);

virDomainDeviceDefPtr virDomainDeviceDefParse(const char *xmlStr,
                                              const virDomainDef *def,
                                              virCapsPtr caps,
                                              virDomainXMLOptionPtr xmlopt,
                                              unsigned int flags);
virDomainDefPtr virDomainDefParseString(const char *xmlStr,
                                        virCapsPtr caps,
                                        virDomainXMLOptionPtr xmlopt,
                                        unsigned int expectedVirtTypes,
                                        unsigned int flags);
virDomainDefPtr virDomainDefParseFile(const char *filename,
                                      virCapsPtr caps,
                                      virDomainXMLOptionPtr xmlopt,
                                      unsigned int expectedVirtTypes,
                                      unsigned int flags);
virDomainDefPtr virDomainDefParseNode(xmlDocPtr doc,
                                      xmlNodePtr root,
                                      virCapsPtr caps,
                                      virDomainXMLOptionPtr xmlopt,
                                      unsigned int expectedVirtTypes,
                                      unsigned int flags);

bool virDomainDefCheckABIStability(virDomainDefPtr src,
                                   virDomainDefPtr dst);

int virDomainDefAddImplicitControllers(virDomainDefPtr def);

char *virDomainDefFormat(virDomainDefPtr def,
                         unsigned int flags);
int virDomainDefFormatInternal(virDomainDefPtr def,
                               unsigned int flags,
                               virBufferPtr buf);

int virDomainDiskSourceDefFormatInternal(virBufferPtr buf,
                                         int type,
                                         const char *src,
                                         int policy,
                                         int protocol,
                                         size_t nhosts,
                                         virDomainDiskHostDefPtr hosts,
                                         size_t nseclabels,
                                         virSecurityDeviceLabelDefPtr *seclabels,
                                         virDomainDiskSourcePoolDefPtr srcpool,
                                         unsigned int flags);

int virDomainNetDefFormat(virBufferPtr buf,
                          virDomainNetDefPtr def,
                          unsigned int flags);

typedef enum {
    VIR_DOMAIN_DEVICE_ACTION_ATTACH,
    VIR_DOMAIN_DEVICE_ACTION_DETACH,
    VIR_DOMAIN_DEVICE_ACTION_UPDATE,
} virDomainDeviceAction;

int virDomainDefCompatibleDevice(virDomainDefPtr def,
                                 virDomainDeviceDefPtr dev,
                                 virDomainDeviceAction action);

int virDomainVcpuPinAdd(virDomainVcpuPinDefPtr **vcpupin_list,
                        size_t *nvcpupin,
                        unsigned char *cpumap,
                        int maplen,
                        int vcpu);

int virDomainVcpuPinDel(virDomainDefPtr def, int vcpu);

int virDomainEmulatorPinAdd(virDomainDefPtr def,
                              unsigned char *cpumap,
                              int maplen);

int virDomainEmulatorPinDel(virDomainDefPtr def);

void virDomainRNGDefFree(virDomainRNGDefPtr def);

int virDomainDiskIndexByName(virDomainDefPtr def, const char *name,
                             bool allow_ambiguous);
const char *virDomainDiskPathByName(virDomainDefPtr, const char *name);
int virDomainDiskInsert(virDomainDefPtr def,
                        virDomainDiskDefPtr disk)
    ATTRIBUTE_RETURN_CHECK;
void virDomainDiskInsertPreAlloced(virDomainDefPtr def,
                                   virDomainDiskDefPtr disk);
int virDomainDiskDefAssignAddress(virDomainXMLOptionPtr xmlopt,
                                  virDomainDiskDefPtr def);

virDomainDiskDefPtr
virDomainDiskRemove(virDomainDefPtr def, size_t i);
virDomainDiskDefPtr
virDomainDiskRemoveByName(virDomainDefPtr def, const char *name);
int virDomainDiskSourceDefParse(xmlNodePtr node,
                                int type,
                                char **source,
                                int *proto,
                                size_t *nhosts,
                                virDomainDiskHostDefPtr *hosts,
                                virDomainDiskSourcePoolDefPtr *srcpool);

bool virDomainHasDiskMirror(virDomainObjPtr vm);

int virDomainNetFindIdx(virDomainDefPtr def, virDomainNetDefPtr net);
virDomainNetDefPtr virDomainNetFind(virDomainDefPtr def, const char *device);
int virDomainNetInsert(virDomainDefPtr def, virDomainNetDefPtr net);
virDomainNetDefPtr virDomainNetRemove(virDomainDefPtr def, size_t i);
void virDomainNetRemoveHostdev(virDomainDefPtr def, virDomainNetDefPtr net);

int virDomainHostdevInsert(virDomainDefPtr def, virDomainHostdevDefPtr hostdev);
virDomainHostdevDefPtr
virDomainHostdevRemove(virDomainDefPtr def, size_t i);
int virDomainHostdevFind(virDomainDefPtr def, virDomainHostdevDefPtr match,
                         virDomainHostdevDefPtr *found);

int virDomainGraphicsListenGetType(virDomainGraphicsDefPtr def, size_t i)
            ATTRIBUTE_NONNULL(1);
int virDomainGraphicsListenSetType(virDomainGraphicsDefPtr def, size_t i, int val)
            ATTRIBUTE_NONNULL(1);
const char *virDomainGraphicsListenGetAddress(virDomainGraphicsDefPtr def,
                                              size_t i)
            ATTRIBUTE_NONNULL(1);
int virDomainGraphicsListenSetAddress(virDomainGraphicsDefPtr def,
                                      size_t i, const char *address,
                                      int len, bool setType)
            ATTRIBUTE_NONNULL(1);
const char *virDomainGraphicsListenGetNetwork(virDomainGraphicsDefPtr def,
                                              size_t i)
            ATTRIBUTE_NONNULL(1);
int virDomainGraphicsListenSetNetwork(virDomainGraphicsDefPtr def,
                                      size_t i, const char *network, int len)
            ATTRIBUTE_NONNULL(1);

int virDomainNetGetActualType(virDomainNetDefPtr iface);
const char *virDomainNetGetActualBridgeName(virDomainNetDefPtr iface);
const char *virDomainNetGetActualDirectDev(virDomainNetDefPtr iface);
int virDomainNetGetActualDirectMode(virDomainNetDefPtr iface);
virDomainHostdevDefPtr virDomainNetGetActualHostdev(virDomainNetDefPtr iface);
virNetDevVPortProfilePtr
virDomainNetGetActualVirtPortProfile(virDomainNetDefPtr iface);
virNetDevBandwidthPtr
virDomainNetGetActualBandwidth(virDomainNetDefPtr iface);
virNetDevVlanPtr virDomainNetGetActualVlan(virDomainNetDefPtr iface);

int virDomainControllerInsert(virDomainDefPtr def,
                              virDomainControllerDefPtr controller)
    ATTRIBUTE_RETURN_CHECK;
void virDomainControllerInsertPreAlloced(virDomainDefPtr def,
                                         virDomainControllerDefPtr controller);
int virDomainControllerFind(virDomainDefPtr def, int type, int idx);
virDomainControllerDefPtr virDomainControllerRemove(virDomainDefPtr def, size_t i);

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
                          enum virDomainChrDeviceType type,
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
virDomainChrInsert(virDomainDefPtr vmdef,
                   virDomainChrDefPtr chr);
virDomainChrDefPtr
virDomainChrRemove(virDomainDefPtr vmdef,
                   virDomainChrDefPtr chr);

int virDomainSaveXML(const char *configDir,
                     virDomainDefPtr def,
                     const char *xml);

int virDomainSaveConfig(const char *configDir,
                        virDomainDefPtr def);
int virDomainSaveStatus(virDomainXMLOptionPtr xmlopt,
                        const char *statusDir,
                        virDomainObjPtr obj) ATTRIBUTE_RETURN_CHECK;

typedef void (*virDomainLoadConfigNotify)(virDomainObjPtr dom,
                                          int newDomain,
                                          void *opaque);

int virDomainObjListLoadAllConfigs(virDomainObjListPtr doms,
                                   const char *configDir,
                                   const char *autostartDir,
                                   int liveStatus,
                                   virCapsPtr caps,
                                   virDomainXMLOptionPtr xmlopt,
                                   unsigned int expectedVirtTypes,
                                   virDomainLoadConfigNotify notify,
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
                                                  const char *path);
int virDomainFSInsert(virDomainDefPtr def, virDomainFSDefPtr fs);
int virDomainFSIndexByName(virDomainDefPtr def, const char *name);
virDomainFSDefPtr virDomainFSRemove(virDomainDefPtr def, size_t i);

int virDomainVideoDefaultType(const virDomainDef *def);
int virDomainVideoDefaultRAM(const virDomainDef *def, int type);

int virDomainObjListNumOfDomains(virDomainObjListPtr doms,
                                 bool active,
                                 virDomainObjListFilter filter,
                                 virConnectPtr conn);

int virDomainObjListGetActiveIDs(virDomainObjListPtr doms,
                                 int *ids,
                                 int maxids,
                                 virDomainObjListFilter filter,
                                 virConnectPtr conn);
int virDomainObjListGetInactiveNames(virDomainObjListPtr doms,
                                     char **const names,
                                     int maxnames,
                                     virDomainObjListFilter filter,
                                     virConnectPtr conn);

typedef int (*virDomainObjListIterator)(virDomainObjPtr dom,
                                        void *opaque);

int virDomainObjListForEach(virDomainObjListPtr doms,
                            virDomainObjListIterator callback,
                            void *opaque);

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
virDomainDiskDefGetSecurityLabelDef(virDomainDiskDefPtr def, const char *model);

virSecurityDeviceLabelDefPtr
virDomainChrDefGetSecurityLabelDef(virDomainChrDefPtr def, const char *model);

virSecurityLabelDefPtr
virDomainDefGenSecurityLabelDef(const char *model);

virSecurityDeviceLabelDefPtr
virDomainDiskDefGenSecurityLabelDef(const char *model);

void virSecurityLabelDefFree(virSecurityLabelDefPtr def);
void virSecurityDeviceLabelDefFree(virSecurityDeviceLabelDefPtr def);

typedef const char* (*virEventActionToStringFunc)(int type);
typedef int (*virEventActionFromStringFunc)(const char *type);

VIR_ENUM_DECL(virDomainTaint)

VIR_ENUM_DECL(virDomainVirt)
VIR_ENUM_DECL(virDomainBoot)
VIR_ENUM_DECL(virDomainBootMenu)
VIR_ENUM_DECL(virDomainFeature)
VIR_ENUM_DECL(virDomainFeatureState)
VIR_ENUM_DECL(virDomainLifecycle)
VIR_ENUM_DECL(virDomainLifecycleCrash)
VIR_ENUM_DECL(virDomainPMState)
VIR_ENUM_DECL(virDomainDevice)
VIR_ENUM_DECL(virDomainDeviceAddress)
VIR_ENUM_DECL(virDomainDisk)
VIR_ENUM_DECL(virDomainDiskDevice)
VIR_ENUM_DECL(virDomainDiskGeometryTrans)
VIR_ENUM_DECL(virDomainDiskBus)
VIR_ENUM_DECL(virDomainDiskCache)
VIR_ENUM_DECL(virDomainDiskErrorPolicy)
VIR_ENUM_DECL(virDomainDiskProtocol)
VIR_ENUM_DECL(virDomainDiskProtocolTransport)
VIR_ENUM_DECL(virDomainDiskIo)
VIR_ENUM_DECL(virDomainDiskSecretType)
VIR_ENUM_DECL(virDomainDeviceSGIO)
VIR_ENUM_DECL(virDomainDiskTray)
VIR_ENUM_DECL(virDomainDiskDiscard)
VIR_ENUM_DECL(virDomainDiskSourcePoolMode)
VIR_ENUM_DECL(virDomainIoEventFd)
VIR_ENUM_DECL(virDomainVirtioEventIdx)
VIR_ENUM_DECL(virDomainDiskCopyOnRead)
VIR_ENUM_DECL(virDomainController)
VIR_ENUM_DECL(virDomainControllerModelPCI)
VIR_ENUM_DECL(virDomainControllerModelSCSI)
VIR_ENUM_DECL(virDomainControllerModelUSB)
VIR_ENUM_DECL(virDomainFS)
VIR_ENUM_DECL(virDomainFSDriverType)
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
VIR_ENUM_DECL(virDomainMemDump)
VIR_ENUM_DECL(virDomainMemballoonModel)
VIR_ENUM_DECL(virDomainSmbiosMode)
VIR_ENUM_DECL(virDomainWatchdogModel)
VIR_ENUM_DECL(virDomainWatchdogAction)
VIR_ENUM_DECL(virDomainVideo)
VIR_ENUM_DECL(virDomainHostdevMode)
VIR_ENUM_DECL(virDomainHostdevSubsys)
VIR_ENUM_DECL(virDomainHostdevCaps)
VIR_ENUM_DECL(virDomainPciRombarMode)
VIR_ENUM_DECL(virDomainHub)
VIR_ENUM_DECL(virDomainRedirdevBus)
VIR_ENUM_DECL(virDomainInput)
VIR_ENUM_DECL(virDomainInputBus)
VIR_ENUM_DECL(virDomainGraphics)
VIR_ENUM_DECL(virDomainGraphicsListen)
VIR_ENUM_DECL(virDomainGraphicsAuthConnected)
VIR_ENUM_DECL(virDomainGraphicsSpiceAgentFileTransfer)
VIR_ENUM_DECL(virDomainGraphicsSpiceChannelName)
VIR_ENUM_DECL(virDomainGraphicsSpiceChannelMode)
VIR_ENUM_DECL(virDomainGraphicsSpiceImageCompression)
VIR_ENUM_DECL(virDomainGraphicsSpiceJpegCompression)
VIR_ENUM_DECL(virDomainGraphicsSpiceZlibCompression)
VIR_ENUM_DECL(virDomainGraphicsSpicePlaybackCompression)
VIR_ENUM_DECL(virDomainGraphicsSpiceStreamingMode)
VIR_ENUM_DECL(virDomainGraphicsSpiceClipboardCopypaste)
VIR_ENUM_DECL(virDomainGraphicsSpiceMouseMode)
VIR_ENUM_DECL(virDomainGraphicsVNCSharePolicy)
VIR_ENUM_DECL(virDomainHyperv)
VIR_ENUM_DECL(virDomainRNGModel)
VIR_ENUM_DECL(virDomainRNGBackend)
VIR_ENUM_DECL(virDomainTPMModel)
VIR_ENUM_DECL(virDomainTPMBackend)
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

# define VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE   \
                (VIR_CONNECT_LIST_DOMAINS_ACTIVE | \
                 VIR_CONNECT_LIST_DOMAINS_INACTIVE)

# define VIR_CONNECT_LIST_DOMAINS_FILTERS_PERSISTENT   \
                (VIR_CONNECT_LIST_DOMAINS_PERSISTENT | \
                 VIR_CONNECT_LIST_DOMAINS_TRANSIENT)

# define VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE     \
                (VIR_CONNECT_LIST_DOMAINS_RUNNING | \
                 VIR_CONNECT_LIST_DOMAINS_PAUSED  | \
                 VIR_CONNECT_LIST_DOMAINS_SHUTOFF | \
                 VIR_CONNECT_LIST_DOMAINS_OTHER)

# define VIR_CONNECT_LIST_DOMAINS_FILTERS_MANAGEDSAVE   \
                (VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE | \
                 VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE)

# define VIR_CONNECT_LIST_DOMAINS_FILTERS_AUTOSTART   \
                (VIR_CONNECT_LIST_DOMAINS_AUTOSTART | \
                 VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART)

# define VIR_CONNECT_LIST_DOMAINS_FILTERS_SNAPSHOT       \
                (VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT | \
                 VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT)

# define VIR_CONNECT_LIST_DOMAINS_FILTERS_ALL                   \
                (VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE      | \
                 VIR_CONNECT_LIST_DOMAINS_FILTERS_PERSISTENT  | \
                 VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE       | \
                 VIR_CONNECT_LIST_DOMAINS_FILTERS_MANAGEDSAVE | \
                 VIR_CONNECT_LIST_DOMAINS_FILTERS_AUTOSTART   | \
                 VIR_CONNECT_LIST_DOMAINS_FILTERS_SNAPSHOT)

int virDomainObjListExport(virDomainObjListPtr doms,
                           virConnectPtr conn,
                           virDomainPtr **domains,
                           virDomainObjListFilter filter,
                           unsigned int flags);

virDomainVcpuPinDefPtr virDomainLookupVcpuPin(virDomainDefPtr def,
                                              int vcpuid);

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

bool virDomainDiskSourceIsBlockType(virDomainDiskDefPtr def)
    ATTRIBUTE_NONNULL(1);

void virDomainChrSourceDefClear(virDomainChrSourceDefPtr def);

char *virDomainObjGetMetadata(virDomainObjPtr vm,
                              int type,
                              const char *uri,
                              virCapsPtr caps,
                              virDomainXMLOptionPtr xmlopt,
                              unsigned int flags);

int virDomainObjSetMetadata(virDomainObjPtr vm,
                            int type,
                            const char *metadata,
                            const char *key,
                            const char *uri,
                            virCapsPtr caps,
                            virDomainXMLOptionPtr xmlopt,
                            const char *configDir,
                            unsigned int flags);

#endif /* __DOMAIN_CONF_H */
