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
# include "virthread.h"
# include "virpci.h"
# include "device_conf.h"
# include "object_event.h"

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
    VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION     = (1 << 0),
    VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION      = (1 << 1),
    VIR_NODE_DEV_CAP_FLAG_PCIE                      = (1 << 2),
} virNodeDevPCICapFlags;

typedef struct _virNodeDevCapData {
    virNodeDevCapType type;
    union {
        struct {
            char *product_name;
            struct {
                char *vendor_name;
                char *version;
                char *serial;
                unsigned char uuid[VIR_UUID_BUFLEN];
            } hardware;
            struct {
                char *vendor_name;
                char *version;
                char *release_date;
            } firmware;
        } system;
        struct {
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
        } pci_dev;
        struct {
            unsigned int bus;
            unsigned int device;
            unsigned int product;
            unsigned int vendor;
            char *product_name;
            char *vendor_name;
        } usb_dev;
        struct {
            unsigned int number;
            unsigned int _class;		/* "class" is reserved in C */
            unsigned int subclass;
            unsigned int protocol;
            char *description;
        } usb_if;
        struct {
            char *address;
            unsigned int address_len;
            char *ifname;
            virNetDevIfLink lnk;
            virNodeDevNetCapType subtype;  /* LAST -> no subtype */
            virBitmapPtr features; /* enum virNetDevFeature */
        } net;
        struct {
            unsigned int host;
            int unique_id;
            char *wwnn;
            char *wwpn;
            char *fabric_wwn;
            unsigned int flags;
            int max_vports;
            int vports;
        } scsi_host;
        struct {
            char *name;
        } scsi_target;
        struct {
            unsigned int host;
            unsigned int bus;
            unsigned int target;
            unsigned int lun;
            char *type;
        } scsi;
        struct {
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
        } storage;
        struct {
            char *path;
        } sg; /* SCSI generic device */
    };
} virNodeDevCapData, *virNodeDevCapDataPtr;

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
    void *privateData;			/* driver-specific private data */
    void (*privateFree)(void *data);	/* destructor for private data */

};

typedef struct _virNodeDeviceObjList virNodeDeviceObjList;
typedef virNodeDeviceObjList *virNodeDeviceObjListPtr;
struct _virNodeDeviceObjList {
    size_t count;
    virNodeDeviceObjPtr *objs;
};

typedef struct _virNodeDeviceDriverState virNodeDeviceDriverState;
typedef virNodeDeviceDriverState *virNodeDeviceDriverStatePtr;
struct _virNodeDeviceDriverState {
    virMutex lock;

    virNodeDeviceObjList devs;		/* currently-known devices */
    void *privateData;			/* driver-specific private data */

    /* Immutable pointer, self-locking APIs */
    virObjectEventStatePtr nodeDeviceEventState;
};


int virNodeDeviceHasCap(const virNodeDeviceObj *dev, const char *cap);

virNodeDeviceObjPtr virNodeDeviceFindByName(virNodeDeviceObjListPtr devs,
                                            const char *name);
virNodeDeviceObjPtr
virNodeDeviceFindBySysfsPath(virNodeDeviceObjListPtr devs,
                             const char *sysfs_path)
    ATTRIBUTE_NONNULL(2);

virNodeDeviceObjPtr virNodeDeviceAssignDef(virNodeDeviceObjListPtr devs,
                                           virNodeDeviceDefPtr def);

void virNodeDeviceObjRemove(virNodeDeviceObjListPtr devs,
                            virNodeDeviceObjPtr *dev);

char *virNodeDeviceDefFormat(const virNodeDeviceDef *def);

virNodeDeviceDefPtr virNodeDeviceDefParseString(const char *str,
                                                int create,
                                                const char *virt_type);
virNodeDeviceDefPtr virNodeDeviceDefParseFile(const char *filename,
                                              int create,
                                              const char *virt_type);
virNodeDeviceDefPtr virNodeDeviceDefParseNode(xmlDocPtr xml,
                                              xmlNodePtr root,
                                              int create,
                                              const char *virt_type);

int virNodeDeviceGetWWNs(virNodeDeviceDefPtr def,
                         char **wwnn,
                         char **wwpn);

int virNodeDeviceGetParentHost(virNodeDeviceObjListPtr devs,
                               const char *dev_name,
                               const char *parent_name,
                               int *parent_host);

int virNodeDeviceGetParentHostByWWNs(virNodeDeviceObjListPtr devs,
                                     const char *dev_name,
                                     const char *parent_wwnn,
                                     const char *parent_wwpn,
                                     int *parent_host);

int virNodeDeviceGetParentHostByFabricWWN(virNodeDeviceObjListPtr devs,
                                          const char *dev_name,
                                          const char *parent_fabric_wwn,
                                          int *parent_host);

int virNodeDeviceFindVportParentHost(virNodeDeviceObjListPtr devs,
                                     int *parent_host);

void virNodeDeviceDefFree(virNodeDeviceDefPtr def);

void virNodeDeviceObjFree(virNodeDeviceObjPtr dev);

void virNodeDeviceObjListFree(virNodeDeviceObjListPtr devs);

void virNodeDevCapsDefFree(virNodeDevCapsDefPtr caps);

void virNodeDeviceObjLock(virNodeDeviceObjPtr obj);
void virNodeDeviceObjUnlock(virNodeDeviceObjPtr obj);

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
                 VIR_CONNECT_LIST_NODE_DEVICES_CAP_SCSI_GENERIC)

typedef bool (*virNodeDeviceObjListFilter)(virConnectPtr conn,
                                           virNodeDeviceDefPtr def);

int virNodeDeviceObjListExport(virConnectPtr conn,
                               virNodeDeviceObjList devobjs,
                               virNodeDevicePtr **devices,
                               virNodeDeviceObjListFilter filter,
                               unsigned int flags);

#endif /* __VIR_NODE_DEVICE_CONF_H__ */
