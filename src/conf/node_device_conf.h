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
 */

#pragma once

#include "internal.h"
#include "virbitmap.h"
#include "virccw.h"
#include "virpcivpd.h"
#include "virscsihost.h"
#include "virpci.h"
#include "virvhba.h"
#include "device_conf.h"
#include "virenum.h"

#include <libxml/tree.h>

#define CREATE_DEVICE 1
#define EXISTING_DEVICE 0

typedef enum {
    /* Keep in sync with VIR_ENUM_IMPL in node_device_conf.c */
    VIR_NODE_DEV_DEVNODE_DEV,
    VIR_NODE_DEV_DEVNODE_LINK,

    VIR_NODE_DEV_DEVNODE_LAST
} virNodeDevDevnodeType;

VIR_ENUM_DECL(virNodeDevDevnode);

typedef enum {
    /* Keep in sync with VIR_ENUM_IMPL in node_device_conf.c */
    VIR_NODE_DEV_CAP_SYSTEM,            /* System capability */
    VIR_NODE_DEV_CAP_PCI_DEV,           /* PCI device */
    VIR_NODE_DEV_CAP_USB_DEV,           /* USB device */
    VIR_NODE_DEV_CAP_USB_INTERFACE,     /* USB interface */
    VIR_NODE_DEV_CAP_NET,               /* Network device */
    VIR_NODE_DEV_CAP_SCSI_HOST,         /* SCSI Host Bus Adapter */
    VIR_NODE_DEV_CAP_SCSI_TARGET,       /* SCSI Target */
    VIR_NODE_DEV_CAP_SCSI,              /* SCSI device */
    VIR_NODE_DEV_CAP_STORAGE,           /* Storage device */
    VIR_NODE_DEV_CAP_FC_HOST,           /* FC Host Bus Adapter */
    VIR_NODE_DEV_CAP_VPORTS,            /* HBA which is capable of vports */
    VIR_NODE_DEV_CAP_SCSI_GENERIC,      /* SCSI generic device */
    VIR_NODE_DEV_CAP_DRM,               /* DRM device */
    VIR_NODE_DEV_CAP_MDEV_TYPES,        /* Device capable of mediated devices */
    VIR_NODE_DEV_CAP_MDEV,              /* Mediated device */
    VIR_NODE_DEV_CAP_CCW_DEV,           /* s390 CCW device */
    VIR_NODE_DEV_CAP_CSS_DEV,           /* s390 channel subsystem device */
    VIR_NODE_DEV_CAP_VDPA,              /* vDPA device */
    VIR_NODE_DEV_CAP_AP_CARD,           /* s390 AP Card device */
    VIR_NODE_DEV_CAP_AP_QUEUE,          /* s390 AP Queue */
    VIR_NODE_DEV_CAP_AP_MATRIX,         /* s390 AP Matrix device */
    VIR_NODE_DEV_CAP_VPD,               /* Device provides VPD */

    VIR_NODE_DEV_CAP_LAST
} virNodeDevCapType;

typedef enum {
    /* Keep in sync with VIR_ENUM_IMPL in node_device_conf.c */
    VIR_NODE_DEV_CAP_NET_80203,         /* 802.03 network device */
    VIR_NODE_DEV_CAP_NET_80211,         /* 802.11 network device */
    VIR_NODE_DEV_CAP_NET_LAST
} virNodeDevNetCapType;

VIR_ENUM_DECL(virNodeDevCap);
VIR_ENUM_DECL(virNodeDevNetCap);

typedef enum {
    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE                  = (1 << 0),
    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE  = (1 << 1),
    VIR_NODE_DEV_CAP_STORAGE_HOTPLUGGABLE               = (1 << 2),
} virNodeDevStorageCapFlags;

typedef enum {
    VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST                   = (1 << 0),
    VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS                 = (1 << 1),
} virNodeDevSCSIHostCapFlags;

typedef enum {
    VIR_NODE_DEV_CAP_FLAG_FC_RPORT                      = (1 << 0),
} virNodeDevSCSITargetCapsFlags;

typedef enum {
    VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION     = (1 << 0),
    VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION      = (1 << 1),
    VIR_NODE_DEV_CAP_FLAG_PCIE                      = (1 << 2),
    VIR_NODE_DEV_CAP_FLAG_PCI_MDEV                  = (1 << 3),
    VIR_NODE_DEV_CAP_FLAG_PCI_VPD                   = (1 << 4),
} virNodeDevPCICapFlags;

typedef enum {
    VIR_NODE_DEV_CAP_FLAG_CSS_MDEV                  = (1 << 0),
} virNodeDevCCWCapFlags;

typedef enum {
    VIR_NODE_DEV_CAP_FLAG_AP_MATRIX_MDEV            = (1 << 0),
} virNodeDevAPMatrixCapFlags;

typedef enum {
    /* Keep in sync with VIR_ENUM_IMPL in node_device_conf.c */
    VIR_NODE_DEV_DRM_PRIMARY,
    VIR_NODE_DEV_DRM_CONTROL,
    VIR_NODE_DEV_DRM_RENDER,

    VIR_NODE_DEV_DRM_LAST
} virNodeDevDRMType;

VIR_ENUM_DECL(virNodeDevDRM);

typedef struct _virNodeDevCapSystemHardware virNodeDevCapSystemHardware;
struct _virNodeDevCapSystemHardware {
    char *vendor_name;
    char *version;
    char *serial;
    unsigned char uuid[VIR_UUID_BUFLEN];
};

typedef struct _virNodeDevCapSystemFirmware virNodeDevCapSystemFirmware;
struct _virNodeDevCapSystemFirmware {
    char *vendor_name;
    char *version;
    char *release_date;
};

typedef struct _virNodeDevCapSystem virNodeDevCapSystem;
struct _virNodeDevCapSystem {
    char *product_name;
    virNodeDevCapSystemHardware hardware;
    virNodeDevCapSystemFirmware firmware;
};

typedef struct _virNodeDevCapMdev virNodeDevCapMdev;
struct _virNodeDevCapMdev {
    char *type;
    unsigned int iommuGroupNumber;
    char *uuid;
    virMediatedDeviceAttr **attributes;
    size_t nattributes;
    char *parent_addr;
    bool autostart;
};

typedef struct _virNodeDevCapPCIDev virNodeDevCapPCIDev;
struct _virNodeDevCapPCIDev {
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int function;
    unsigned int product;
    unsigned int vendor;
    int klass;
    char *product_name;
    char *vendor_name;
    virPCIDeviceAddress *physical_function;
    virPCIDeviceAddress **virtual_functions;
    size_t num_virtual_functions;
    unsigned int max_virtual_functions;
    unsigned int flags;
    virPCIDeviceAddress **iommuGroupDevices;
    size_t nIommuGroupDevices;
    unsigned int iommuGroupNumber;
    int numa_node;
    virPCIEDeviceInfo *pci_express;
    int hdrType; /* enum virPCIHeaderType or -1 */
    virMediatedDeviceType **mdev_types;
    size_t nmdev_types;
    virPCIVPDResource *vpd;
};

typedef struct _virNodeDevCapUSBDev virNodeDevCapUSBDev;
struct _virNodeDevCapUSBDev {
   unsigned int bus;
   unsigned int device;
   unsigned int product;
   unsigned int vendor;
   char *product_name;
   char *vendor_name;
};

typedef struct _virNodeDevCapUSBIf virNodeDevCapUSBIf;
struct _virNodeDevCapUSBIf {
    unsigned int number;
    unsigned int klass;
    unsigned int subclass;
    unsigned int protocol;
    char *description;
};

typedef struct _virNodeDevCapNet virNodeDevCapNet;
struct _virNodeDevCapNet {
    char *address;
    unsigned int address_len;
    char *ifname;
    virNetDevIfLink lnk;
    virNodeDevNetCapType subtype;  /* LAST -> no subtype */
    virBitmap *features; /* enum virNetDevFeature */
};

typedef struct _virNodeDevCapSCSIHost virNodeDevCapSCSIHost;
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
struct _virNodeDevCapSCSITarget {
    char *name;
    unsigned int flags; /* enum virNodeDevSCSITargetCapsFlags */
    char *rport;
    char *wwpn;
};

typedef struct _virNodeDevCapSCSI virNodeDevCapSCSI;
struct _virNodeDevCapSCSI {
    unsigned int host;
    unsigned int bus;
    unsigned int target;
    unsigned int lun;
    char *type;
};

typedef struct _virNodeDevCapStorage virNodeDevCapStorage;
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
    unsigned int flags; /* virNodeDevStorageCapFlags bits */
};

typedef struct _virNodeDevCapSCSIGeneric virNodeDevCapSCSIGeneric;
struct _virNodeDevCapSCSIGeneric {
    char *path;
};

typedef struct _virNodeDevCapDRM virNodeDevCapDRM;
struct _virNodeDevCapDRM {
    virNodeDevDRMType type;
};

typedef struct _virNodeDevCapCCW virNodeDevCapCCW;
struct _virNodeDevCapCCW {
    unsigned int cssid;
    unsigned int ssid;
    unsigned int devno;
    unsigned int flags; /* enum virNodeDevCCWCapFlags */
    virMediatedDeviceType **mdev_types;
    size_t nmdev_types;
    virCCWDeviceAddress *channel_dev_addr;
};

typedef struct _virNodeDevCapVDPA virNodeDevCapVDPA;
struct _virNodeDevCapVDPA {
    char *chardev;
};

typedef struct _virNodeDevCapAPCard virNodeDevCapAPCard;
struct _virNodeDevCapAPCard {
    unsigned int ap_adapter;
};

typedef struct _virNodeDevCapAPQueue virNodeDevCapAPQueue;
struct _virNodeDevCapAPQueue {
    unsigned int ap_adapter;
    unsigned int ap_domain;
};

typedef struct _virNodeDevCapAPMatrix virNodeDevCapAPMatrix;
struct _virNodeDevCapAPMatrix {
    char *addr;
    unsigned int flags; /* enum virNodeDevAPMatrixCapFlags */
    virMediatedDeviceType **mdev_types;
    size_t nmdev_types;
};


typedef struct _virNodeDevCapMdevParent virNodeDevCapMdevParent;
struct _virNodeDevCapMdevParent {
    virMediatedDeviceType **mdev_types;
    size_t nmdev_types;
    char *address;
};

typedef struct _virNodeDevCapData virNodeDevCapData;
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
        virNodeDevCapVDPA vdpa;
        virNodeDevCapAPCard ap_card;
        virNodeDevCapAPQueue ap_queue;
        virNodeDevCapAPMatrix ap_matrix;
        virNodeDevCapMdevParent mdev_parent;
    };
};

typedef struct _virNodeDevCapsDef virNodeDevCapsDef;
struct _virNodeDevCapsDef {
    virNodeDevCapData data;
    virNodeDevCapsDef *next;            /* next capability */
};


typedef struct _virNodeDeviceDef virNodeDeviceDef;
struct _virNodeDeviceDef {
    char *name;                         /* device name (unique on node) */
    char *sysfs_path;                   /* udev name/sysfs path */
    char *parent;                       /* optional parent device name */
    char *parent_sysfs_path;            /* udev parent name/sysfs path */
    char *parent_wwnn;                  /* optional parent wwnn */
    char *parent_wwpn;                  /* optional parent wwpn */
    char *parent_fabric_wwn;            /* optional parent fabric_wwn */
    char *driver;                       /* optional driver name */
    char *devnode;                      /* /dev path */
    char **devlinks;                    /* /dev links */
    virNodeDevCapsDef *caps;            /* optional device capabilities */
};

char *
virNodeDeviceDefFormat(const virNodeDeviceDef *def);


typedef int (*virNodeDeviceDefPostParseCallback)(virNodeDeviceDef *dev,
                                                 void *opaque);

typedef int (*virNodeDeviceDefValidateCallback)(virNodeDeviceDef *dev,
                                                void *opaque);

typedef struct _virNodeDeviceDefParserCallbacks {
    virNodeDeviceDefPostParseCallback postParse;
    virNodeDeviceDefValidateCallback validate;
} virNodeDeviceDefParserCallbacks;

virNodeDeviceDef *
virNodeDeviceDefParse(const char *str,
                      const char *filename,
                      int create,
                      const char *virt_type,
                      virNodeDeviceDefParserCallbacks *parserCallbacks,
                      void *opaque,
                      bool validate);

virNodeDeviceDef *
virNodeDeviceDefParseXML(xmlXPathContextPtr ctxt,
                         int create,
                         const char *virt_type);

int
virNodeDeviceGetWWNs(virNodeDeviceDef *def,
                     char **wwnn,
                     char **wwpn);

void
virNodeDeviceDefFree(virNodeDeviceDef *def);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNodeDeviceDef, virNodeDeviceDefFree);

void
virNodeDevCapsDefFree(virNodeDevCapsDef *caps);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNodeDevCapsDef, virNodeDevCapsDefFree);

#define VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_CAP \
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
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_CCW_DEV       | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_CSS_DEV       | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_VDPA          | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_AP_CARD       | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_AP_QUEUE      | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_AP_MATRIX     | \
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_VPD)

#define VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_ACTIVE \
    VIR_CONNECT_LIST_NODE_DEVICES_ACTIVE | \
    VIR_CONNECT_LIST_NODE_DEVICES_INACTIVE

#define VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_ALL \
    VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_CAP | \
    VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_ACTIVE

int
virNodeDeviceGetSCSIHostCaps(virNodeDevCapSCSIHost *scsi_host);

int
virNodeDeviceGetSCSITargetCaps(const char *sysfsPath,
                               virNodeDevCapSCSITarget *scsi_target);

int
virNodeDeviceGetPCIDynamicCaps(const char *sysfsPath,
                               virNodeDevCapPCIDev *pci_dev);

int
virNodeDeviceGetCSSDynamicCaps(const char *sysfsPath,
                               virNodeDevCapCCW *ccw_dev);

int
virNodeDeviceGetAPMatrixDynamicCaps(const char *sysfsPath,
                                    virNodeDevCapAPMatrix *ap_matrix);

int
virNodeDeviceGetMdevParentDynamicCaps(const char *sysfsPath,
                                      virNodeDevCapMdevParent *mdev_parent);

int
virNodeDeviceUpdateCaps(virNodeDeviceDef *def);

int
virNodeDeviceCapsListExport(virNodeDeviceDef *def,
                            virNodeDevCapType **list);
