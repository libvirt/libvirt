/*
 * domain_conf.h: domain XML processing
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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

#ifndef __DOMAIN_CONF_H
# define __DOMAIN_CONF_H

# include <libxml/parser.h>
# include <libxml/tree.h>
# include <libxml/xpath.h>

# include "internal.h"
# include "capabilities.h"
# include "storage_encryption_conf.h"
# include "cpu_conf.h"
# include "util.h"
# include "threads.h"
# include "virhash.h"
# include "virsocketaddr.h"
# include "nwfilter_params.h"
# include "nwfilter_conf.h"
# include "virnetdevmacvlan.h"
# include "sysinfo.h"
# include "virnetdevvportprofile.h"
# include "virnetdevopenvswitch.h"
# include "virnetdevbandwidth.h"

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

typedef struct _virDomainSmartcardDef virDomainSmartcardDef;
typedef virDomainSmartcardDef *virDomainSmartcardDefPtr;

typedef struct _virDomainChrDef virDomainChrDef;
typedef virDomainChrDef *virDomainChrDefPtr;

typedef struct _virDomainMemballoonDef virDomainMemballoonDef;
typedef virDomainMemballoonDef *virDomainMemballoonDefPtr;

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

    VIR_DOMAIN_DEVICE_LAST,
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

    VIR_DOMAIN_VIRT_LAST,
};

enum virDomainDeviceAddressType {
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO,

    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST
};

enum virDomainDeviceAddressPciMulti {
    VIR_DOMAIN_DEVICE_ADDRESS_PCI_MULTI_DEFAULT = 0,
    VIR_DOMAIN_DEVICE_ADDRESS_PCI_MULTI_ON,
    VIR_DOMAIN_DEVICE_ADDRESS_PCI_MULTI_OFF,

    VIR_DOMAIN_DEVICE_ADDRESS_PCI_MULTI_LAST
};

enum virDomainPciRombarMode {
    VIR_DOMAIN_PCI_ROMBAR_DEFAULT = 0,
    VIR_DOMAIN_PCI_ROMBAR_ON,
    VIR_DOMAIN_PCI_ROMBAR_OFF,

    VIR_DOMAIN_PCI_ROMBAR_LAST
};

typedef struct _virDomainDevicePCIAddress virDomainDevicePCIAddress;
typedef virDomainDevicePCIAddress *virDomainDevicePCIAddressPtr;
struct _virDomainDevicePCIAddress {
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int function;
    int          multi;  /* enum virDomainDeviceAddressPciMulti */
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

typedef struct _virDomainDeviceInfo virDomainDeviceInfo;
typedef virDomainDeviceInfo *virDomainDeviceInfoPtr;
struct _virDomainDeviceInfo {
    char *alias;
    int type;
    union {
        virDomainDevicePCIAddress pci;
        virDomainDeviceDriveAddress drive;
        virDomainDeviceVirtioSerialAddress vioserial;
        virDomainDeviceCcidAddress ccid;
        virDomainDeviceUSBAddress usb;
        virDomainDeviceSpaprVioAddress spaprvio;
    } addr;
    int mastertype;
    union {
        virDomainDeviceUSBMaster usb;
    } master;
    /* rombar and romfile are only used for pci hostdev and network
     * devices. */
    int rombar;         /* enum virDomainPciRombarMode */
    char *romfile;
    /* bootIndex is only user for disk, network interface, and
     * hostdev devices. */
    int bootIndex;
};

enum virDomainSeclabelType {
    VIR_DOMAIN_SECLABEL_DEFAULT,
    VIR_DOMAIN_SECLABEL_NONE,
    VIR_DOMAIN_SECLABEL_DYNAMIC,
    VIR_DOMAIN_SECLABEL_STATIC,

    VIR_DOMAIN_SECLABEL_LAST,
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
};


/* Security configuration for domain */
typedef struct _virSecurityDeviceLabelDef virSecurityDeviceLabelDef;
typedef virSecurityDeviceLabelDef *virSecurityDeviceLabelDefPtr;
struct _virSecurityDeviceLabelDef {
    char *label;        /* image label string */
    bool norelabel;
};


typedef struct _virDomainHostdevOrigStates virDomainHostdevOrigStates;
typedef virDomainHostdevOrigStates *virDomainHostdevOrigStatesPtr;
struct _virDomainHostdevOrigStates {
    union {
        struct {
            /* Does the device need to unbind from stub when
             * reattaching to host?
             */
            unsigned int unbind_from_stub : 1;

            /* Does it need to use remove_slot when reattaching
             * the device to host?
             */
            unsigned int remove_slot : 1;

            /* Does it need to reprobe driver for the device when
             * reattaching to host?
             */
            unsigned int reprobe :1;
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

    VIR_DOMAIN_HOSTDEV_MODE_LAST,
};

enum virDomainHostdevSubsysType {
    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB,
    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI,

    VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST
};


typedef struct _virDomainHostdevSubsys virDomainHostdevSubsys;
typedef virDomainHostdevSubsys *virDomainHostdevSubsysPtr;
struct _virDomainHostdevSubsys {
    int type; /* enum virDomainHostdevBusType */
    union {
        struct {
            unsigned bus;
            unsigned device;

            unsigned vendor;
            unsigned product;
        } usb;
        virDomainDevicePCIAddress pci; /* host address */
    } u;
};

/* basic device for direct passthrough */
struct _virDomainHostdevDef {
    virDomainDeviceDef parent; /* higher level Def containing this */
    int mode; /* enum virDomainHostdevMode */
    unsigned int managed : 1;
    union {
        virDomainHostdevSubsys subsys;
        struct {
            /* TBD: struct capabilities see:
             * https://www.redhat.com/archives/libvir-list/2008-July/msg00429.html
             */
            int dummy;
        } caps;
    } source;
    virDomainHostdevOrigStates origstates;
    virDomainDeviceInfoPtr info; /* Guest address */
};

/* Two types of disk backends */
enum virDomainDiskType {
    VIR_DOMAIN_DISK_TYPE_BLOCK,
    VIR_DOMAIN_DISK_TYPE_FILE,
    VIR_DOMAIN_DISK_TYPE_DIR,
    VIR_DOMAIN_DISK_TYPE_NETWORK,

    VIR_DOMAIN_DISK_TYPE_LAST
};

/* Three types of disk frontend */
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

    VIR_DOMAIN_DISK_BUS_LAST
};

enum  virDomainDiskCache {
    VIR_DOMAIN_DISK_CACHE_DEFAULT,
    VIR_DOMAIN_DISK_CACHE_DISABLE,
    VIR_DOMAIN_DISK_CACHE_WRITETHRU,
    VIR_DOMAIN_DISK_CACHE_WRITEBACK,
    VIR_DOMAIN_DISK_CACHE_DIRECTSYNC,
    VIR_DOMAIN_DISK_CACHE_UNSAFE,

    VIR_DOMAIN_DISK_CACHE_LAST
};

enum  virDomainDiskErrorPolicy {
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

    VIR_DOMAIN_DISK_PROTOCOL_LAST
};

enum virDomainDiskTray {
    VIR_DOMAIN_DISK_TRAY_CLOSED,
    VIR_DOMAIN_DISK_TRAY_OPEN,

    VIR_DOMAIN_DISK_TRAY_LAST
};

typedef struct _virDomainDiskHostDef virDomainDiskHostDef;
typedef virDomainDiskHostDef *virDomainDiskHostDefPtr;
struct _virDomainDiskHostDef {
    char *name;
    char *port;
};

enum  virDomainDiskIo {
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

enum virDomainDiskSnapshot {
    VIR_DOMAIN_DISK_SNAPSHOT_DEFAULT = 0,
    VIR_DOMAIN_DISK_SNAPSHOT_NO,
    VIR_DOMAIN_DISK_SNAPSHOT_INTERNAL,
    VIR_DOMAIN_DISK_SNAPSHOT_EXTERNAL,

    VIR_DOMAIN_DISK_SNAPSHOT_LAST
};

enum virDomainSnapshotState {
    /* Inherit the VIR_DOMAIN_* states from virDomainState.  */
    VIR_DOMAIN_DISK_SNAPSHOT = VIR_DOMAIN_LAST,
    VIR_DOMAIN_SNAPSHOT_STATE_LAST
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

/* Stores the virtual disk configuration */
struct _virDomainDiskDef {
    int type;
    int device;
    int bus;
    char *src;
    virSecurityDeviceLabelDefPtr seclabel;
    char *dst;
    int tray_status;
    int protocol;
    int nhosts;
    virDomainDiskHostDefPtr hosts;
    struct {
        char *username;
        int secretType; /* enum virDomainDiskSecretType */
        union {
            unsigned char uuid[VIR_UUID_BUFLEN];
            char *usage;
        } secret;
    } auth;
    char *driverName;
    char *driverType;

    virDomainBlockIoTuneInfo blkdeviotune;

    char *serial;
    int cachemode;
    int error_policy;  /* enum virDomainDiskErrorPolicy */
    int rerror_policy; /* enum virDomainDiskErrorPolicy */
    int iomode;
    int ioeventfd;
    int event_idx;
    int copy_on_read;
    int snapshot; /* enum virDomainDiskSnapshot */
    int startupPolicy; /* enum virDomainStartupPolicy */
    unsigned int readonly : 1;
    unsigned int shared : 1;
    unsigned int transient : 1;
    virDomainDeviceInfo info;
    virStorageEncryptionPtr encryption;
    bool rawio_specified;
    int rawio; /* no = 0, yes = 1 */
};


enum virDomainControllerType {
    VIR_DOMAIN_CONTROLLER_TYPE_IDE,
    VIR_DOMAIN_CONTROLLER_TYPE_FDC,
    VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
    VIR_DOMAIN_CONTROLLER_TYPE_SATA,
    VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL,
    VIR_DOMAIN_CONTROLLER_TYPE_CCID,
    VIR_DOMAIN_CONTROLLER_TYPE_USB,

    VIR_DOMAIN_CONTROLLER_TYPE_LAST
};


enum virDomainControllerModelSCSI {
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI,
    VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI,

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

    VIR_DOMAIN_CONTROLLER_MODEL_USB_LAST
};

typedef struct _virDomainVirtioSerialOpts virDomainVirtioSerialOpts;
typedef virDomainVirtioSerialOpts *virDomainVirtioSerialOptsPtr;
struct _virDomainVirtioSerialOpts {
    int ports;   /* -1 == undef */
    int vectors; /* -1 == undef */
};

/* Stores the virtual disk controller configuration */
struct _virDomainControllerDef {
    int type;
    int idx;
    int model; /* -1 == undef */
    union {
        virDomainVirtioSerialOpts vioserial;
    } opts;
    virDomainDeviceInfo info;
};


/* Two types of disk backends */
enum virDomainFSType {
    VIR_DOMAIN_FS_TYPE_MOUNT,   /* Better named 'bind' */
    VIR_DOMAIN_FS_TYPE_BLOCK,
    VIR_DOMAIN_FS_TYPE_FILE,
    VIR_DOMAIN_FS_TYPE_TEMPLATE,

    VIR_DOMAIN_FS_TYPE_LAST
};

/* Filesystem driver type */
enum virDomainFSDriverType {
    VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT = 0,
    VIR_DOMAIN_FS_DRIVER_TYPE_PATH,
    VIR_DOMAIN_FS_DRIVER_TYPE_HANDLE,

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

struct _virDomainFSDef {
    int type;
    int fsdriver;
    int accessmode;
    int wrpolicy; /* enum virDomainFSWrpolicy */
    char *src;
    char *dst;
    unsigned int readonly : 1;
    virDomainDeviceInfo info;
};


/* 5 different types of networking config */
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

    VIR_DOMAIN_NET_TYPE_LAST,
};

/* the backend driver used for virtio interfaces */
enum virDomainNetBackendType {
    VIR_DOMAIN_NET_BACKEND_TYPE_DEFAULT, /* prefer kernel, fall back to user */
    VIR_DOMAIN_NET_BACKEND_TYPE_QEMU,    /* userland */
    VIR_DOMAIN_NET_BACKEND_TYPE_VHOST,   /* kernel */

    VIR_DOMAIN_NET_BACKEND_TYPE_LAST,
};

/* the TX algorithm used for virtio interfaces */
enum virDomainNetVirtioTxModeType {
    VIR_DOMAIN_NET_VIRTIO_TX_MODE_DEFAULT, /* default for this version of qemu */
    VIR_DOMAIN_NET_VIRTIO_TX_MODE_IOTHREAD,
    VIR_DOMAIN_NET_VIRTIO_TX_MODE_TIMER,

    VIR_DOMAIN_NET_VIRTIO_TX_MODE_LAST,
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
            virNetDevVPortProfilePtr virtPortProfile;
        } bridge;
        struct {
            char *linkdev;
            int mode; /* enum virMacvtapMode from util/macvtap.h */
            virNetDevVPortProfilePtr virtPortProfile;
        } direct;
        struct {
            virDomainHostdevDef def;
            virNetDevVPortProfilePtr virtPortProfile;
        } hostdev;
    } data;
    virNetDevBandwidthPtr bandwidth;
};

/* Stores the virtual network interface configuration */
struct _virDomainNetDef {
    enum virDomainNetType type;
    unsigned char mac[VIR_MAC_BUFLEN];
    char *model;
    union {
        struct {
            enum virDomainNetBackendType name; /* which driver backend to use */
            enum virDomainNetVirtioTxModeType txmode;
            enum virDomainIoEventFd ioeventfd;
            enum virDomainVirtioEventIdx event_idx;
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
            virNetDevVPortProfilePtr virtPortProfile;
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
            virNetDevVPortProfilePtr virtPortProfile;
        } bridge;
        struct {
            char *name;
        } internal;
        struct {
            char *linkdev;
            int mode; /* enum virMacvtapMode from util/macvtap.h */
            virNetDevVPortProfilePtr virtPortProfile;
        } direct;
        struct {
            virDomainHostdevDef def;
            virNetDevVPortProfilePtr virtPortProfile;
        } hostdev;
    } data;
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

    VIR_DOMAIN_CHR_DEVICE_TYPE_LAST,
};

enum virDomainChrChannelTargetType {
    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD = 0,
    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO,

    VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_LAST,
};

enum virDomainChrConsoleTargetType {
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL = 0,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_XEN,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_UML,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LXC,
    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_OPENVZ,

    VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_LAST,
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

    VIR_DOMAIN_CHR_TYPE_LAST,
};

enum virDomainChrTcpProtocol {
    VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW,
    VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET,
    VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNETS, /* secure telnet */
    VIR_DOMAIN_CHR_TCP_PROTOCOL_TLS,

    VIR_DOMAIN_CHR_TCP_PROTOCOL_LAST,
};

enum virDomainChrSpicevmcName {
    VIR_DOMAIN_CHR_SPICEVMC_VDAGENT,
    VIR_DOMAIN_CHR_SPICEVMC_SMARTCARD,
    VIR_DOMAIN_CHR_SPICEVMC_USBREDIR,

    VIR_DOMAIN_CHR_SPICEVMC_LAST,
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
    } data;
};

/* A complete character device, both host and domain views.  */
struct _virDomainChrDef {
    int deviceType;
    int targetType;
    union {
        int port; /* parallel, serial, console */
        virSocketAddrPtr addr; /* guestfwd */
        char *name; /* virtio */
    } target;

    virDomainChrSourceDef source;

    virDomainDeviceInfo info;
};

enum virDomainSmartcardType {
    VIR_DOMAIN_SMARTCARD_TYPE_HOST,
    VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES,
    VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH,

    VIR_DOMAIN_SMARTCARD_TYPE_LAST,
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

enum virDomainInputType {
    VIR_DOMAIN_INPUT_TYPE_MOUSE,
    VIR_DOMAIN_INPUT_TYPE_TABLET,

    VIR_DOMAIN_INPUT_TYPE_LAST,
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

enum virDomainSoundModel {
    VIR_DOMAIN_SOUND_MODEL_SB16,
    VIR_DOMAIN_SOUND_MODEL_ES1370,
    VIR_DOMAIN_SOUND_MODEL_PCSPK,
    VIR_DOMAIN_SOUND_MODEL_AC97,
    VIR_DOMAIN_SOUND_MODEL_ICH6,

    VIR_DOMAIN_SOUND_MODEL_LAST
};

struct _virDomainSoundDef {
    int model;
    virDomainDeviceInfo info;
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
    unsigned int support3d :1;
    unsigned int support2d :1;
};


struct _virDomainVideoDef {
    int type;
    unsigned int vram;
    unsigned int heads;
    virDomainVideoAccelDefPtr accel;
    virDomainDeviceInfo info;
};

/* 3 possible graphics console modes */
enum virDomainGraphicsType {
    VIR_DOMAIN_GRAPHICS_TYPE_SDL,
    VIR_DOMAIN_GRAPHICS_TYPE_VNC,
    VIR_DOMAIN_GRAPHICS_TYPE_RDP,
    VIR_DOMAIN_GRAPHICS_TYPE_DESKTOP,
    VIR_DOMAIN_GRAPHICS_TYPE_SPICE,

    VIR_DOMAIN_GRAPHICS_TYPE_LAST,
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
    unsigned int expires: 1; /* Whether there is an expiry time set */
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

enum virDomainGraphicsListenType {
    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE = 0,
    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS,
    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK,

    VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST,
};

enum virDomainHubType {
    VIR_DOMAIN_HUB_TYPE_USB,

    VIR_DOMAIN_HUB_TYPE_LAST,
};

typedef struct _virDomainGraphicsListenDef virDomainGraphicsListenDef;
typedef virDomainGraphicsListenDef *virDomainGraphicsListenDefPtr;
struct _virDomainGraphicsListenDef {
    int type;   /* enum virDomainGraphicsListenType */
    char *address;
    char *network;
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
            unsigned int autoport :1;
            char *keymap;
            char *socket;
            virDomainGraphicsAuthDef auth;
        } vnc;
        struct {
            char *display;
            char *xauth;
            int fullscreen;
        } sdl;
        struct {
            int port;
            unsigned int autoport :1;
            unsigned int replaceUser :1;
            unsigned int multiUser :1;
        } rdp;
        struct {
            char *display;
            unsigned int fullscreen :1;
        } desktop;
        struct {
            int port;
            int tlsPort;
            int mousemode;
            char *keymap;
            virDomainGraphicsAuthDef auth;
            unsigned int autoport :1;
            int channels[VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST];
            int image;
            int jpeg;
            int zlib;
            int playback;
            int streaming;
            int copypaste;
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

enum {
    VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO,
    VIR_DOMAIN_MEMBALLOON_MODEL_XEN,
    VIR_DOMAIN_MEMBALLOON_MODEL_NONE,

    VIR_DOMAIN_MEMBALLOON_MODEL_LAST
};

struct _virDomainMemballoonDef {
    int model;
    virDomainDeviceInfo info;
};


enum virDomainSmbiosMode {
    VIR_DOMAIN_SMBIOS_NONE,
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

    VIR_DOMAIN_BOOT_LAST,
};

enum virDomainBootMenu {
    VIR_DOMAIN_BOOT_MENU_DEFAULT = 0,
    VIR_DOMAIN_BOOT_MENU_ENABLED,
    VIR_DOMAIN_BOOT_MENU_DISABLED,
};

enum virDomainFeature {
    VIR_DOMAIN_FEATURE_ACPI,
    VIR_DOMAIN_FEATURE_APIC,
    VIR_DOMAIN_FEATURE_PAE,
    VIR_DOMAIN_FEATURE_HAP,
    VIR_DOMAIN_FEATURE_VIRIDIAN,
    VIR_DOMAIN_FEATURE_PRIVNET,

    VIR_DOMAIN_FEATURE_LAST
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

enum virDomainBIOSUseserial {
    VIR_DOMAIN_BIOS_USESERIAL_DEFAULT = 0,
    VIR_DOMAIN_BIOS_USESERIAL_YES,
    VIR_DOMAIN_BIOS_USESERIAL_NO
};

typedef struct _virDomainBIOSDef virDomainBIOSDef;
typedef virDomainBIOSDef *virDomainBIOSDefPtr;
struct _virDomainBIOSDef {
    int useserial;
};

/* Operating system configuration data & machine / arch */
typedef struct _virDomainOSDef virDomainOSDef;
typedef virDomainOSDef *virDomainOSDefPtr;
struct _virDomainOSDef {
    char *type;
    char *arch;
    char *machine;
    int nBootDevs;
    int bootDevs[VIR_DOMAIN_BOOT_LAST];
    int bootmenu;
    char *init;
    char **initargv;
    char *kernel;
    char *initrd;
    char *cmdline;
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

    VIR_DOMAIN_TIMER_NAME_LAST,
};

enum virDomainTimerTrackType {
    VIR_DOMAIN_TIMER_TRACK_BOOT = 0,
    VIR_DOMAIN_TIMER_TRACK_GUEST,
    VIR_DOMAIN_TIMER_TRACK_WALL,

    VIR_DOMAIN_TIMER_TRACK_LAST,
};

enum virDomainTimerTickpolicyType {
    VIR_DOMAIN_TIMER_TICKPOLICY_DELAY = 0,
    VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP,
    VIR_DOMAIN_TIMER_TICKPOLICY_MERGE,
    VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD,

    VIR_DOMAIN_TIMER_TICKPOLICY_LAST,
};

enum virDomainTimerModeType {
    VIR_DOMAIN_TIMER_MODE_AUTO = 0,
    VIR_DOMAIN_TIMER_MODE_NATIVE,
    VIR_DOMAIN_TIMER_MODE_EMULATE,
    VIR_DOMAIN_TIMER_MODE_PARAVIRT,
    VIR_DOMAIN_TIMER_MODE_SMPSAFE,

    VIR_DOMAIN_TIMER_MODE_LAST,
};

enum virDomainCpuPlacementMode {
    VIR_DOMAIN_CPU_PLACEMENT_MODE_DEFAULT = 0,
    VIR_DOMAIN_CPU_PLACEMENT_MODE_STATIC,
    VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO,

    VIR_DOMAIN_CPU_PLACEMENT_MODE_LAST,
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

    VIR_DOMAIN_CLOCK_OFFSET_LAST,
};

enum virDomainClockBasis {
    VIR_DOMAIN_CLOCK_BASIS_UTC = 0,
    VIR_DOMAIN_CLOCK_BASIS_LOCALTIME = 1,

    VIR_DOMAIN_CLOCK_BASIS_LAST,
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
        } variable;

        /* Timezone name, when
         * offset == VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME */
        char *timezone;
    } data;

    int ntimers;
    virDomainTimerDefPtr *timers;
};

# define VIR_DOMAIN_CPUMASK_LEN 1024

typedef struct _virDomainVcpuPinDef virDomainVcpuPinDef;
typedef virDomainVcpuPinDef *virDomainVcpuPinDefPtr;
struct _virDomainVcpuPinDef {
    int vcpuid;
    char *cpumask;
};

int virDomainVcpuPinIsDuplicate(virDomainVcpuPinDefPtr *def,
                                int nvcpupin,
                                int vcpu);

virDomainVcpuPinDefPtr virDomainVcpuPinFindByVcpu(virDomainVcpuPinDefPtr *def,
                                                  int nvcpupin,
                                                  int vcpu);

typedef struct _virDomainNumatuneDef virDomainNumatuneDef;
typedef virDomainNumatuneDef *virDomainNumatuneDefPtr;
struct _virDomainNumatuneDef {
    struct {
        char *nodemask;
        int mode;
    } memory;

    /* Future NUMA tuning related stuff should go here. */
};

typedef struct _virBlkioDeviceWeight virBlkioDeviceWeight;
typedef virBlkioDeviceWeight *virBlkioDeviceWeightPtr;
struct _virBlkioDeviceWeight {
    char *path;
    unsigned int weight;
};

void virBlkioDeviceWeightArrayClear(virBlkioDeviceWeightPtr deviceWeights,
                                    int ndevices);


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
        virBlkioDeviceWeightPtr devices;
    } blkio;

    struct {
        unsigned long long max_balloon; /* in kibibytes */
        unsigned long long cur_balloon; /* in kibibytes */
        bool hugepage_backed;
        unsigned long long hard_limit; /* in kibibytes */
        unsigned long long soft_limit; /* in kibibytes */
        unsigned long long min_guarantee; /* in kibibytes */
        unsigned long long swap_hard_limit; /* in kibibytes */
    } mem;
    unsigned short vcpus;
    unsigned short maxvcpus;
    int placement_mode;
    int cpumasklen;
    char *cpumask;

    struct {
        unsigned long shares;
        unsigned long long period;
        long long quota;
        int nvcpupin;
        virDomainVcpuPinDefPtr *vcpupin;
    } cputune;

    virDomainNumatuneDef numatune;

    /* These 3 are based on virDomainLifeCycleAction enum flags */
    int onReboot;
    int onPoweroff;
    int onCrash;

    virDomainOSDef os;
    char *emulator;
    int features;

    virDomainClockDef clock;

    int ngraphics;
    virDomainGraphicsDefPtr *graphics;

    int ndisks;
    virDomainDiskDefPtr *disks;

    int ncontrollers;
    virDomainControllerDefPtr *controllers;

    int nfss;
    virDomainFSDefPtr *fss;

    int nnets;
    virDomainNetDefPtr *nets;

    int ninputs;
    virDomainInputDefPtr *inputs;

    int nsounds;
    virDomainSoundDefPtr *sounds;

    int nvideos;
    virDomainVideoDefPtr *videos;

    int nhostdevs;
    virDomainHostdevDefPtr *hostdevs;

    int nredirdevs;
    virDomainRedirdevDefPtr *redirdevs;

    int nsmartcards;
    virDomainSmartcardDefPtr *smartcards;

    int nserials;
    virDomainChrDefPtr *serials;

    int nparallels;
    virDomainChrDefPtr *parallels;

    int nchannels;
    virDomainChrDefPtr *channels;

    int nconsoles;
    virDomainChrDefPtr *consoles;

    size_t nleases;
    virDomainLeaseDefPtr *leases;

    int nhubs;
    virDomainHubDefPtr *hubs;

    /* Only 1 */
    virSecurityLabelDef seclabel;
    virDomainWatchdogDefPtr watchdog;
    virDomainMemballoonDefPtr memballoon;
    virCPUDefPtr cpu;
    virSysinfoDefPtr sysinfo;

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

    VIR_DOMAIN_TAINT_LAST
};

/* Items related to snapshot state */

/* Stores disk-snapshot information */
typedef struct _virDomainSnapshotDiskDef virDomainSnapshotDiskDef;
typedef virDomainSnapshotDiskDef *virDomainSnapshotDiskDefPtr;
struct _virDomainSnapshotDiskDef {
    char *name; /* name matching the <target dev='...' of the domain */
    int index; /* index within snapshot->dom->disks that matches name */
    int snapshot; /* enum virDomainDiskSnapshot */
    char *file; /* new source file when snapshot is external */
    char *driverType; /* file format type of new file */
};

/* Stores the complete snapshot metadata */
typedef struct _virDomainSnapshotDef virDomainSnapshotDef;
typedef virDomainSnapshotDef *virDomainSnapshotDefPtr;
struct _virDomainSnapshotDef {
    /* Public XML.  */
    char *name;
    char *description;
    char *parent;
    long long creationTime; /* in seconds */
    int state; /* enum virDomainSnapshotState */

    size_t ndisks; /* should not exceed dom->ndisks */
    virDomainSnapshotDiskDef *disks;

    virDomainDefPtr dom;

    /* Internal use.  */
    bool current; /* At most one snapshot in the list should have this set */
};

typedef struct _virDomainSnapshotObj virDomainSnapshotObj;
typedef virDomainSnapshotObj *virDomainSnapshotObjPtr;
struct _virDomainSnapshotObj {
    virDomainSnapshotDefPtr def;

    virDomainSnapshotObjPtr parent; /* NULL if root */
    virDomainSnapshotObjPtr sibling; /* NULL if last child of parent */
    size_t nchildren;
    virDomainSnapshotObjPtr first_child; /* NULL if no children */
};

typedef struct _virDomainSnapshotObjList virDomainSnapshotObjList;
typedef virDomainSnapshotObjList *virDomainSnapshotObjListPtr;
struct _virDomainSnapshotObjList {
    /* name string -> virDomainSnapshotObj  mapping
     * for O(1), lockless lookup-by-name */
    virHashTable *objs;

    size_t nroots;
    virDomainSnapshotObjPtr first_root;
};

typedef enum {
    VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE = 1 << 0,
    VIR_DOMAIN_SNAPSHOT_PARSE_DISKS    = 1 << 1,
    VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL = 1 << 2,
} virDomainSnapshotParseFlags;

virDomainSnapshotDefPtr virDomainSnapshotDefParseString(const char *xmlStr,
                                                        virCapsPtr caps,
                                                        unsigned int expectedVirtTypes,
                                                        unsigned int flags);
void virDomainSnapshotDefFree(virDomainSnapshotDefPtr def);
char *virDomainSnapshotDefFormat(const char *domain_uuid,
                                 virDomainSnapshotDefPtr def,
                                 unsigned int flags,
                                 int internal);
int virDomainSnapshotAlignDisks(virDomainSnapshotDefPtr snapshot,
                                int default_snapshot,
                                bool require_match);
virDomainSnapshotObjPtr virDomainSnapshotAssignDef(virDomainSnapshotObjListPtr snapshots,
                                                   const virDomainSnapshotDefPtr def);

int virDomainSnapshotObjListInit(virDomainSnapshotObjListPtr objs);
int virDomainSnapshotObjListGetNames(virDomainSnapshotObjListPtr snapshots,
                                     char **const names, int maxnames,
                                     unsigned int flags);
int virDomainSnapshotObjListNum(virDomainSnapshotObjListPtr snapshots,
                                unsigned int flags);
int virDomainSnapshotObjListGetNamesFrom(virDomainSnapshotObjPtr snapshot,
                                         char **const names, int maxnames,
                                         unsigned int flags);
int virDomainSnapshotObjListNumFrom(virDomainSnapshotObjPtr snapshot,
                                    unsigned int flags);
virDomainSnapshotObjPtr virDomainSnapshotFindByName(const virDomainSnapshotObjListPtr snapshots,
                                                    const char *name);
void virDomainSnapshotObjListRemove(virDomainSnapshotObjListPtr snapshots,
                                    virDomainSnapshotObjPtr snapshot);
int virDomainSnapshotForEachChild(virDomainSnapshotObjPtr snapshot,
                                  virHashIterator iter,
                                  void *data);
int virDomainSnapshotForEachDescendant(virDomainSnapshotObjPtr snapshot,
                                       virHashIterator iter,
                                       void *data);
int virDomainSnapshotUpdateRelations(virDomainSnapshotObjListPtr snapshots);
void virDomainSnapshotDropParent(virDomainSnapshotObjListPtr snapshots,
                                 virDomainSnapshotObjPtr snapshot);

/* Guest VM runtime state */
typedef struct _virDomainStateReason virDomainStateReason;
struct _virDomainStateReason {
    int state;
    int reason;
};

typedef struct _virDomainObj virDomainObj;
typedef virDomainObj *virDomainObjPtr;
struct _virDomainObj {
    virMutex lock;
    int refs;

    pid_t pid;
    virDomainStateReason state;

    unsigned int autostart : 1;
    unsigned int persistent : 1;
    unsigned int updated : 1;

    virDomainDefPtr def; /* The current definition */
    virDomainDefPtr newDef; /* New definition to activate at shutdown */

    virDomainSnapshotObjList snapshots;
    virDomainSnapshotObjPtr current_snapshot;

    void *privateData;
    void (*privateDataFreeFunc)(void *);

    int taint;
};

typedef struct _virDomainObjList virDomainObjList;
typedef virDomainObjList *virDomainObjListPtr;
struct _virDomainObjList {
    /* uuid string -> virDomainObj  mapping
     * for O(1), lockless lookup-by-uuid */
    virHashTable *objs;
};

static inline bool
virDomainObjIsActive(virDomainObjPtr dom)
{
    return dom->def->id != -1;
}


int virDomainObjListInit(virDomainObjListPtr objs);
void virDomainObjListDeinit(virDomainObjListPtr objs);

virDomainObjPtr virDomainFindByID(const virDomainObjListPtr doms,
                                  int id);
virDomainObjPtr virDomainFindByUUID(const virDomainObjListPtr doms,
                                    const unsigned char *uuid);
virDomainObjPtr virDomainFindByName(const virDomainObjListPtr doms,
                                    const char *name);

bool virDomainObjTaint(virDomainObjPtr obj,
                       enum virDomainTaintFlags taint);

void virDomainGraphicsDefFree(virDomainGraphicsDefPtr def);
void virDomainInputDefFree(virDomainInputDefPtr def);
void virDomainDiskDefFree(virDomainDiskDefPtr def);
void virDomainLeaseDefFree(virDomainLeaseDefPtr def);
void virDomainDiskHostDefFree(virDomainDiskHostDefPtr def);
int virDomainDiskFindControllerModel(virDomainDefPtr def,
                                     virDomainDiskDefPtr disk,
                                     int controllerType);
void virDomainControllerDefFree(virDomainControllerDefPtr def);
void virDomainFSDefFree(virDomainFSDefPtr def);
void virDomainActualNetDefFree(virDomainActualNetDefPtr def);
void virDomainNetDefFree(virDomainNetDefPtr def);
void virDomainSmartcardDefFree(virDomainSmartcardDefPtr def);
void virDomainChrDefFree(virDomainChrDefPtr def);
void virDomainChrSourceDefFree(virDomainChrSourceDefPtr def);
int virDomainChrSourceDefCopy(virDomainChrSourceDefPtr src,
                              virDomainChrSourceDefPtr dest);
void virDomainSoundDefFree(virDomainSoundDefPtr def);
void virDomainMemballoonDefFree(virDomainMemballoonDefPtr def);
void virDomainWatchdogDefFree(virDomainWatchdogDefPtr def);
void virDomainVideoDefFree(virDomainVideoDefPtr def);
virDomainHostdevDefPtr virDomainHostdevDefAlloc(void);
void virDomainHostdevDefClear(virDomainHostdevDefPtr def);
void virDomainHostdevDefFree(virDomainHostdevDefPtr def);
void virDomainHubDefFree(virDomainHubDefPtr def);
void virDomainRedirdevDefFree(virDomainRedirdevDefPtr def);
void virDomainDeviceDefFree(virDomainDeviceDefPtr def);
virDomainDeviceDefPtr virDomainDeviceDefCopy(virCapsPtr caps,
                                             const virDomainDefPtr def,
                                             virDomainDeviceDefPtr src);
int virDomainDeviceAddressIsValid(virDomainDeviceInfoPtr info,
                                  int type);
int virDomainDevicePCIAddressIsValid(virDomainDevicePCIAddressPtr addr);
void virDomainDeviceInfoClear(virDomainDeviceInfoPtr info);
void virDomainDefClearPCIAddresses(virDomainDefPtr def);
void virDomainDefClearDeviceAliases(virDomainDefPtr def);

typedef int (*virDomainDeviceInfoCallback)(virDomainDefPtr def,
                                           virDomainDeviceDefPtr dev,
                                           virDomainDeviceInfoPtr info,
                                           void *opaque);

int virDomainDeviceInfoIterate(virDomainDefPtr def,
                               virDomainDeviceInfoCallback cb,
                               void *opaque);

void virDomainDefFree(virDomainDefPtr vm);
void virDomainObjRef(virDomainObjPtr vm);
/* Returns 1 if the object was freed, 0 if more refs exist */
int virDomainObjUnref(virDomainObjPtr vm) ATTRIBUTE_RETURN_CHECK;

virDomainChrDefPtr virDomainChrDefNew(void);

/* live == true means def describes an active domain (being migrated or
 * restored) as opposed to a new persistent configuration of the domain */
virDomainObjPtr virDomainAssignDef(virCapsPtr caps,
                                   virDomainObjListPtr doms,
                                   const virDomainDefPtr def,
                                   bool live);
void virDomainObjAssignDef(virDomainObjPtr domain,
                           const virDomainDefPtr def,
                           bool live);
int virDomainObjSetDefTransient(virCapsPtr caps,
                                virDomainObjPtr domain,
                                bool live);
virDomainDefPtr
virDomainObjGetPersistentDef(virCapsPtr caps,
                             virDomainObjPtr domain);

int
virDomainLiveConfigHelperMethod(virCapsPtr caps,
                                virDomainObjPtr dom,
                                unsigned int *flags,
                                virDomainDefPtr *persistentDef);

virDomainDefPtr
virDomainObjCopyPersistentDef(virCapsPtr caps, virDomainObjPtr dom);

void virDomainRemoveInactive(virDomainObjListPtr doms,
                             virDomainObjPtr dom);

virDomainDeviceDefPtr virDomainDeviceDefParse(virCapsPtr caps,
                                              const virDomainDefPtr def,
                                              const char *xmlStr,
                                              unsigned int flags);
virDomainDefPtr virDomainDefParseString(virCapsPtr caps,
                                        const char *xmlStr,
                                        unsigned int expectedVirtTypes,
                                        unsigned int flags);
virDomainDefPtr virDomainDefParseFile(virCapsPtr caps,
                                      const char *filename,
                                      unsigned int expectedVirtTypes,
                                      unsigned int flags);
virDomainDefPtr virDomainDefParseNode(virCapsPtr caps,
                                      xmlDocPtr doc,
                                      xmlNodePtr root,
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

int virDomainCpuSetParse(const char *str,
                         char sep,
                         char *cpuset,
                         int maxcpu);
char *virDomainCpuSetFormat(char *cpuset,
                            int maxcpu);

int virDomainVcpuPinAdd(virDomainDefPtr def,
                        unsigned char *cpumap,
                        int maplen,
                        int vcpu);

int virDomainVcpuPinDel(virDomainDefPtr def, int vcpu);

int virDomainDiskIndexByName(virDomainDefPtr def, const char *name,
                             bool allow_ambiguous);
const char *virDomainDiskPathByName(virDomainDefPtr, const char *name);
int virDomainDiskInsert(virDomainDefPtr def,
                        virDomainDiskDefPtr disk);
void virDomainDiskInsertPreAlloced(virDomainDefPtr def,
                                   virDomainDiskDefPtr disk);
int virDomainDiskDefAssignAddress(virCapsPtr caps, virDomainDiskDefPtr def);

virDomainDiskDefPtr
virDomainDiskRemove(virDomainDefPtr def, size_t i);
virDomainDiskDefPtr
virDomainDiskRemoveByName(virDomainDefPtr def, const char *name);

int virDomainNetIndexByMac(virDomainDefPtr def, const unsigned char *mac);
int virDomainNetInsert(virDomainDefPtr def, virDomainNetDefPtr net);
virDomainNetDefPtr
virDomainNetRemove(virDomainDefPtr def, size_t i);
virDomainNetDefPtr
virDomainNetRemoveByMac(virDomainDefPtr def, const unsigned char *mac);

int virDomainHostdevInsert(virDomainDefPtr def, virDomainHostdevDefPtr hostdev);
virDomainHostdevDefPtr
virDomainHostdevRemove(virDomainDefPtr def, size_t i);
int virDomainHostdevFind(virDomainDefPtr def, virDomainHostdevDefPtr match,
                         virDomainHostdevDefPtr *found);

int virDomainGraphicsListenGetType(virDomainGraphicsDefPtr def, size_t ii)
            ATTRIBUTE_NONNULL(1);
int virDomainGraphicsListenSetType(virDomainGraphicsDefPtr def, size_t ii, int val)
            ATTRIBUTE_NONNULL(1);
const char *virDomainGraphicsListenGetAddress(virDomainGraphicsDefPtr def,
                                              size_t ii)
            ATTRIBUTE_NONNULL(1);
int virDomainGraphicsListenSetAddress(virDomainGraphicsDefPtr def,
                                      size_t ii, const char *address,
                                      int len, bool setType)
            ATTRIBUTE_NONNULL(1);
const char *virDomainGraphicsListenGetNetwork(virDomainGraphicsDefPtr def,
                                              size_t ii)
            ATTRIBUTE_NONNULL(1);
int virDomainGraphicsListenSetNetwork(virDomainGraphicsDefPtr def,
                                      size_t ii, const char *network, int len)
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

int virDomainControllerInsert(virDomainDefPtr def,
                              virDomainControllerDefPtr controller);
void virDomainControllerInsertPreAlloced(virDomainDefPtr def,
                                         virDomainControllerDefPtr controller);


int virDomainLeaseIndex(virDomainDefPtr def,
                        virDomainLeaseDefPtr lease);
int virDomainLeaseInsert(virDomainDefPtr def,
                         virDomainLeaseDefPtr lease);
int virDomainLeaseInsertPreAlloc(virDomainDefPtr def);
void virDomainLeaseInsertPreAlloced(virDomainDefPtr def,
                                    virDomainLeaseDefPtr lease);
virDomainLeaseDefPtr
virDomainLeaseRemoveAt(virDomainDefPtr def, size_t i);
virDomainLeaseDefPtr
virDomainLeaseRemove(virDomainDefPtr def,
                     virDomainLeaseDefPtr lease);

int virDomainSaveXML(const char *configDir,
                     virDomainDefPtr def,
                     const char *xml);

int virDomainSaveConfig(const char *configDir,
                        virDomainDefPtr def);
int virDomainSaveStatus(virCapsPtr caps,
                        const char *statusDir,
                        virDomainObjPtr obj) ATTRIBUTE_RETURN_CHECK;

typedef void (*virDomainLoadConfigNotify)(virDomainObjPtr dom,
                                          int newDomain,
                                          void *opaque);

int virDomainLoadAllConfigs(virCapsPtr caps,
                            virDomainObjListPtr doms,
                            const char *configDir,
                            const char *autostartDir,
                            int liveStatus,
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

virDomainFSDefPtr virDomainGetRootFilesystem(virDomainDefPtr def);
int virDomainVideoDefaultType(virDomainDefPtr def);
int virDomainVideoDefaultRAM(virDomainDefPtr def, int type);

int virDomainObjIsDuplicate(virDomainObjListPtr doms,
                            virDomainDefPtr def,
                            unsigned int check_active);

void virDomainObjLock(virDomainObjPtr obj);
void virDomainObjUnlock(virDomainObjPtr obj);

int virDomainObjListNumOfDomains(virDomainObjListPtr doms, int active);

int virDomainObjListGetActiveIDs(virDomainObjListPtr doms,
                                 int *ids,
                                 int maxids);
int virDomainObjListGetInactiveNames(virDomainObjListPtr doms,
                                     char **const names,
                                     int maxnames);

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
                                bool allowProbing,
                                bool ignoreOpenFailure,
                                uid_t uid, gid_t gid,
                                virDomainDiskDefPathIterator iter,
                                void *opaque);

void
virDomainObjSetState(virDomainObjPtr obj, virDomainState state, int reason)
        ATTRIBUTE_NONNULL(1);
virDomainState
virDomainObjGetState(virDomainObjPtr obj, int *reason)
        ATTRIBUTE_NONNULL(1);

typedef const char* (*virLifecycleToStringFunc)(int type);
typedef int (*virLifecycleFromStringFunc)(const char *type);

VIR_ENUM_DECL(virDomainTaint)

VIR_ENUM_DECL(virDomainVirt)
VIR_ENUM_DECL(virDomainBoot)
VIR_ENUM_DECL(virDomainFeature)
VIR_ENUM_DECL(virDomainLifecycle)
VIR_ENUM_DECL(virDomainLifecycleCrash)
VIR_ENUM_DECL(virDomainDevice)
VIR_ENUM_DECL(virDomainDeviceAddress)
VIR_ENUM_DECL(virDomainDeviceAddressPciMulti)
VIR_ENUM_DECL(virDomainDisk)
VIR_ENUM_DECL(virDomainDiskDevice)
VIR_ENUM_DECL(virDomainDiskBus)
VIR_ENUM_DECL(virDomainDiskCache)
VIR_ENUM_DECL(virDomainDiskErrorPolicy)
VIR_ENUM_DECL(virDomainDiskProtocol)
VIR_ENUM_DECL(virDomainDiskIo)
VIR_ENUM_DECL(virDomainDiskSecretType)
VIR_ENUM_DECL(virDomainDiskSnapshot)
VIR_ENUM_DECL(virDomainDiskTray)
VIR_ENUM_DECL(virDomainIoEventFd)
VIR_ENUM_DECL(virDomainVirtioEventIdx)
VIR_ENUM_DECL(virDomainDiskCopyOnRead)
VIR_ENUM_DECL(virDomainController)
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
VIR_ENUM_DECL(virDomainSmartcard)
VIR_ENUM_DECL(virDomainChr)
VIR_ENUM_DECL(virDomainChrTcpProtocol)
VIR_ENUM_DECL(virDomainChrSpicevmc)
VIR_ENUM_DECL(virDomainSoundModel)
VIR_ENUM_DECL(virDomainMemballoonModel)
VIR_ENUM_DECL(virDomainSmbiosMode)
VIR_ENUM_DECL(virDomainWatchdogModel)
VIR_ENUM_DECL(virDomainWatchdogAction)
VIR_ENUM_DECL(virDomainVideo)
VIR_ENUM_DECL(virDomainHostdevMode)
VIR_ENUM_DECL(virDomainHostdevSubsys)
VIR_ENUM_DECL(virDomainPciRombarMode)
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
VIR_ENUM_DECL(virDomainGraphicsSpicePlaybackCompression)
VIR_ENUM_DECL(virDomainGraphicsSpiceStreamingMode)
VIR_ENUM_DECL(virDomainGraphicsSpiceClipboardCopypaste)
VIR_ENUM_DECL(virDomainGraphicsSpiceMouseMode)
VIR_ENUM_DECL(virDomainNumatuneMemMode)
VIR_ENUM_DECL(virDomainSnapshotState)
/* from libvirt.h */
VIR_ENUM_DECL(virDomainState)
VIR_ENUM_DECL(virDomainNostateReason)
VIR_ENUM_DECL(virDomainRunningReason)
VIR_ENUM_DECL(virDomainBlockedReason)
VIR_ENUM_DECL(virDomainPausedReason)
VIR_ENUM_DECL(virDomainShutdownReason)
VIR_ENUM_DECL(virDomainShutoffReason)
VIR_ENUM_DECL(virDomainCrashedReason)

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

virDomainNetDefPtr virDomainNetFind(virDomainDefPtr def,
                                    const char *device);
#endif /* __DOMAIN_CONF_H */
