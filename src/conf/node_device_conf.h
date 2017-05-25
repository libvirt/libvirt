/*
 * node_device_conf.h: config handling for node devices
 *
 * Copyright (C) 2009-2015 Red Hat, Inc.
 * Copyright (C) 2008 Virtual Iron Software, Inc.
 * Copyright (C) 2008 David F. Lively
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
 * Author: David F. Lively <dlively@virtualiron.com>
 */

#ifndef __VIR_NODE_DEVICE_CONF_H__
# define __VIR_NODE_DEVICE_CONF_H__

# include "internal.h"
# include "virbitmap.h"
# include "virutil.h"
# include "virscsihost.h"
# include "virpci.h"
# include "virvhba.h"
# include "device_conf.h"
# include "storage_adapter_conf.h"

# include <libxml/tree.h>

# define CREATE_DEVICE 1
# define EXISTING_DEVICE 0

typedef enum {
    /* Keep in sync with VIR_ENUM_IMPL in node_device_conf.c */
    VIR_NODE_DEV_DEVNODE_DEV,
    VIR_NODE_DEV_DEVNODE_LINK,

    VIR_NODE_DEV_DEVNODE_LAST
} virNodeDevDevnodeType;

VIR_ENUM_DECL(virNodeDevDevnode)

typedef enum {
    /* Keep in sync with VIR_ENUM_IMPL in node_device_conf.c */
    VIR_NODE_DEV_CAP_SYSTEM,		/* System capability */
    VIR_NODE_DEV_CAP_PCI_DEV,		/* PCI device */
    VIR_NODE_DEV_CAP_USB_DEV,		/* USB device */
    VIR_NODE_DEV_CAP_USB_INTERFACE,	/* USB interface */
    VIR_NODE_DEV_CAP_NET,		/* Network device */
    VIR_NODE_DEV_CAP_SCSI_HOST,		/* SCSI Host Bus Adapter */
    VIR_NODE_DEV_CAP_SCSI_TARGET,	/* SCSI Target */
    VIR_NODE_DEV_CAP_SCSI,		/* SCSI device */
    VIR_NODE_DEV_CAP_STORAGE,		/* Storage device */
    VIR_NODE_DEV_CAP_FC_HOST,		/* FC Host Bus Adapter */
    VIR_NODE_DEV_CAP_VPORTS,		/* HBA which is capable of vports */
    VIR_NODE_DEV_CAP_SCSI_GENERIC,      /* SCSI generic device */
    VIR_NODE_DEV_CAP_DRM,               /* DRM device */
    VIR_NODE_DEV_CAP_MDEV_TYPES,        /* Device capable of mediated devices */
    VIR_NODE_DEV_CAP_MDEV,              /* Mediated device */
    VIR_NODE_DEV_CAP_CCW_DEV,           /* s390 CCW device */

    VIR_NODE_DEV_CAP_LAST
} virNodeDevCapType;

typedef enum {
    /* Keep in sync with VIR_ENUM_IMPL in node_device_conf.c */
    VIR_NODE_DEV_CAP_NET_80203,		/* 802.03 network device */
    VIR_NODE_DEV_CAP_NET_80211,		/* 802.11 network device */
    VIR_NODE_DEV_CAP_NET_LAST
} virNodeDevNetCapType;

VIR_ENUM_DECL(virNodeDevCap)
VIR_ENUM_DECL(virNodeDevNetCap)

typedef enum {
    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE			= (1 << 0),
    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE	= (1 << 1),
    VIR_NODE_DEV_CAP_STORAGE_HOTPLUGGABLE		= (1 << 2),
} virNodeDevStorageCapFlags;

typedef enum {
    VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST			= (1 << 0),
    VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS			= (1 << 1),
} virNodeDevSCSIHostCapFlags;

typedef enum {
    VIR_NODE_DEV_CAP_FLAG_FC_RPORT			= (1 << 0),
} virNodeDevSCSITargetCapsFlags;

typedef enum {
    VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION     = (1 << 0),
    VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION      = (1 << 1),
    VIR_NODE_DEV_CAP_FLAG_PCIE                      = (1 << 2),
    VIR_NODE_DEV_CAP_FLAG_PCI_MDEV                  = (1 << 3),
} virNodeDevPCICapFlags;

typedef enum {
    /* Keep in sync with VIR_ENUM_IMPL in node_device_conf.c */
    VIR_NODE_DEV_DRM_PRIMARY,
    VIR_NODE_DEV_DRM_CONTROL,
    VIR_NODE_DEV_DRM_RENDER,

    VIR_NODE_DEV_DRM_LAST
} virNodeDevDRMType;

VIR_ENUM_DECL(virNodeDevDRM)

typedef struct _virNodeDevCapSystemHardware virNodeDevCapSystemHardware;
typedef virNodeDevCapSystemHardware *virNodeDevCapSystemHardwarePtr;
struct _virNodeDevCapSystemHardware {
    char *vendor_name;
    char *version;
    char *serial;
    unsigned char uuid[VIR_UUID_BUFLEN];
};

typedef struct _virNodeDevCapSystemFirmware virNodeDevCapSystemFirmware;
typedef virNodeDevCapSystemFirmware *virNodeDevCapSystemFirmwarePtr;
struct _virNodeDevCapSystemFirmware {
    char *vendor_name;
    char *version;
    char *release_date;
};

typedef struct _virNodeDevCapSystem virNodeDevCapSystem;
typedef virNodeDevCapSystem *virNodeDevCapSystemPtr;
struct _virNodeDevCapSystem {
    char *product_name;
    virNodeDevCapSystemHardware hardware;
    virNodeDevCapSystemFirmware firmware;
};

typedef struct _virNodeDevCapMdevType virNodeDevCapMdevType;
typedef virNodeDevCapMdevType *virNodeDevCapMdevTypePtr;
struct _virNodeDevCapMdevType {
    char *id;
    char *name;
    char *device_api;
    unsigned int available_instances;
};

typedef struct _virNodeDevCapMdev virNodeDevCapMdev;
typedef virNodeDevCapMdev *virNodeDevCapMdevPtr;
struct _virNodeDevCapMdev {
    char *type;
    unsigned int iommuGroupNumber;
};

typedef struct _virNodeDevCapPCIDev virNodeDevCapPCIDev;
typedef virNodeDevCapPCIDev *virNodeDevCapPCIDevPtr;
struct _virNodeDevCapPCIDev {
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int function;
    unsigned int product;
    unsigned int vendor;
    unsigned int class;
    char *product_name;
    char *vendor_name;
    virPCIDeviceAddressPtr physical_function;
    virPCIDeviceAddressPtr *virtual_functions;
    size_t num_virtual_functions;
    unsigned int max_virtual_functions;
    unsigned int flags;
    virPCIDeviceAddressPtr *iommuGroupDevices;
    size_t nIommuGroupDevices;
    unsigned int iommuGroupNumber;
    int numa_node;
    virPCIEDeviceInfoPtr pci_express;
    int hdrType; /* enum virPCIHeaderType or -1 */
    virNodeDevCapMdevTypePtr *mdev_types;
    size_t nmdev_types;
};

typedef struct _virNodeDevCapUSBDev virNodeDevCapUSBDev;
typedef virNodeDevCapUSBDev *virNodeDevCapUSBDevPtr;
struct _virNodeDevCapUSBDev {
   unsigned int bus;
   unsigned int device;
   unsigned int product;
   unsigned int vendor;
   char *product_name;
   char *vendor_name;
};

typedef struct _virNodeDevCapUSBIf virNodeDevCapUSBIf;
typedef virNodeDevCapUSBIf *virNodeDevCapUSBIfPtr;
struct _virNodeDevCapUSBIf {
    unsigned int number;
    unsigned int _class;		/* "class" is reserved in C */
    unsigned int subclass;
    unsigned int protocol;
    char *description;
};

typedef struct _virNodeDevCapNet virNodeDevCapNet;
typedef virNodeDevCapNet *virNodeDevCapNetPtr;
struct _virNodeDevCapNet {
    char *address;
    unsigned int address_len;
    char *ifname;
    virNetDevIfLink lnk;
    virNodeDevNetCapType subtype;  /* LAST -> no subtype */
    virBitmapPtr features; /* enum virNetDevFeature */
};

typedef struct _virNodeDevCapSCSIHost virNodeDevCapSCSIHost;
typedef virNodeDevCapSCSIHost *virNodeDevCapSCSIHostPtr;
struct _virNodeDevCapSCSIHost {
    unsigned int host;
    int unique_id;
    char *wwnn;
    char *wwpn;
    char *fabric_wwn;
    unsigned int flags;
    int max_vports;
    int vports;
};

typedef struct _virNodeDevCapSCSITarget virNodeDevCapSCSITarget;
typedef virNodeDevCapSCSITarget *virNodeDevCapSCSITargetPtr;
struct _virNodeDevCapSCSITarget {
    char *name;
    unsigned int flags; /* enum virNodeDevSCSITargetCapsFlags */
    char *rport;
    char *wwpn;
};

typedef struct _virNodeDevCapSCSI virNodeDevCapSCSI;
typedef virNodeDevCapSCSI *virNodeDevCapSCSIPtr;
struct _virNodeDevCapSCSI {
    unsigned int host;
    unsigned int bus;
    unsigned int target;
    unsigned int lun;
    char *type;
};

typedef struct _virNodeDevCapStorage virNodeDevCapStorage;
typedef virNodeDevCapStorage *virNodeDevCapStoragePtr;
struct _virNodeDevCapStorage {
    unsigned long long size;
    unsigned long long num_blocks;
    unsigned long long logical_block_size;
    unsigned long long removable_media_size;
    char *block;
    char *bus;
    char *drive_type;
    char *model;
    char *vendor;
    char *serial;
    char *media_label;
    unsigned int flags;	/* virNodeDevStorageCapFlags bits */
};

typedef struct _virNodeDevCapSCSIGeneric virNodeDevCapSCSIGeneric;
typedef virNodeDevCapSCSIGeneric *virNodeDevCapSCSIGenericPtr;
struct _virNodeDevCapSCSIGeneric {
    char *path;
};

typedef struct _virNodeDevCapDRM virNodeDevCapDRM;
typedef virNodeDevCapDRM *virNodeDevCapDRMPtr;
struct _virNodeDevCapDRM {
    virNodeDevDRMType type;
};

typedef struct _virNodeDevCapCCW virNodeDevCapCCW;
typedef virNodeDevCapCCW *virNodeDevCapCCWPtr;
struct _virNodeDevCapCCW {
    unsigned int cssid;
    unsigned int ssid;
    unsigned int devno;
};

typedef struct _virNodeDevCapData virNodeDevCapData;
typedef virNodeDevCapData *virNodeDevCapDataPtr;
struct _virNodeDevCapData {
    virNodeDevCapType type;
    union {
        virNodeDevCapSystem system;
        virNodeDevCapPCIDev pci_dev;
        virNodeDevCapUSBDev usb_dev;
        virNodeDevCapUSBIf usb_if;
        virNodeDevCapNet net;
        virNodeDevCapSCSIHost scsi_host;
        virNodeDevCapSCSITarget scsi_target;
        virNodeDevCapSCSI scsi;
        virNodeDevCapStorage storage;
        virNodeDevCapSCSIGeneric sg;
        virNodeDevCapDRM drm;
        virNodeDevCapMdev mdev;
        virNodeDevCapCCW ccw_dev;
    };
};

typedef struct _virNodeDevCapsDef virNodeDevCapsDef;
typedef virNodeDevCapsDef *virNodeDevCapsDefPtr;
struct _virNodeDevCapsDef {
    virNodeDevCapData data;
    virNodeDevCapsDefPtr next;          /* next capability */
};


typedef struct _virNodeDeviceDef virNodeDeviceDef;
typedef virNodeDeviceDef *virNodeDeviceDefPtr;
struct _virNodeDeviceDef {
    char *name;                         /* device name (unique on node) */
    char *sysfs_path;                   /* udev name/sysfs path */
    char *parent;			/* optional parent device name */
    char *parent_sysfs_path;            /* udev parent name/sysfs path */
    char *parent_wwnn;			/* optional parent wwnn */
    char *parent_wwpn;			/* optional parent wwpn */
    char *parent_fabric_wwn;		/* optional parent fabric_wwn */
    char *driver;                       /* optional driver name */
    char *devnode;                      /* /dev path */
    char **devlinks;                    /* /dev links */
    virNodeDevCapsDefPtr caps;		/* optional device capabilities */
};


typedef struct _virNodeDeviceObj virNodeDeviceObj;
typedef virNodeDeviceObj *virNodeDeviceObjPtr;
struct _virNodeDeviceObj {
    virMutex lock;

    virNodeDeviceDefPtr def;		/* device definition */

};

typedef struct _virNodeDeviceObjList virNodeDeviceObjList;
typedef virNodeDeviceObjList *virNodeDeviceObjListPtr;
struct _virNodeDeviceObjList {
    size_t count;
    virNodeDeviceObjPtr *objs;
};

char *
virNodeDeviceDefFormat(const virNodeDeviceDef *def);

virNodeDeviceDefPtr
virNodeDeviceDefParseString(const char *str,
                            int create,
                            const char *virt_type);

virNodeDeviceDefPtr
virNodeDeviceDefParseFile(const char *filename,
                          int create,
                          const char *virt_type);

virNodeDeviceDefPtr
virNodeDeviceDefParseNode(xmlDocPtr xml,
                          xmlNodePtr root,
                          int create,
                          const char *virt_type);

int
virNodeDeviceGetWWNs(virNodeDeviceDefPtr def,
                     char **wwnn,
                     char **wwpn);

void
virNodeDeviceDefFree(virNodeDeviceDefPtr def);

void
virNodeDevCapsDefFree(virNodeDevCapsDefPtr caps);

void
virNodeDevCapMdevTypeFree(virNodeDevCapMdevTypePtr type);

# define VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_CAP \
                (VIR_CONNECT_LIST_NODE_DEVICES_CAP_SYSTEM        | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_PCI_DEV       | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_DEV       | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_USB_INTERFACE | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_NET           | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_HOST     | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_TARGET   | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI          | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_STORAGE       | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_FC_HOST       | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_VPORTS        | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_GENERIC  | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_DRM           | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_MDEV_TYPES    | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_MDEV          | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_CCW_DEV)

char *
virNodeDeviceGetParentName(virConnectPtr conn,
                           const char *nodedev_name);

char *
virNodeDeviceCreateVport(virConnectPtr conn,
                         virStorageAdapterFCHostPtr fchost);

int
virNodeDeviceDeleteVport(virConnectPtr conn,
                         virStorageAdapterFCHostPtr fchost);

int
virNodeDeviceGetSCSIHostCaps(virNodeDevCapSCSIHostPtr scsi_host);

#endif /* __VIR_NODE_DEVICE_CONF_H__ */
