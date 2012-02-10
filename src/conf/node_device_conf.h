/*
 * node_device_conf.h: config handling for node devices
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: David F. Lively <dlively@virtualiron.com>
 */

#ifndef __VIR_NODE_DEVICE_CONF_H__
# define __VIR_NODE_DEVICE_CONF_H__

# include "internal.h"
# include "util.h"
# include "threads.h"

# include <libxml/tree.h>

# define CREATE_DEVICE 1
# define EXISTING_DEVICE 0

enum virNodeDevCapType {
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
    VIR_NODE_DEV_CAP_LAST
};

enum virNodeDevNetCapType {
    /* Keep in sync with VIR_ENUM_IMPL in node_device_conf.c */
    VIR_NODE_DEV_CAP_NET_80203,		/* 802.03 network device */
    VIR_NODE_DEV_CAP_NET_80211,		/* 802.11 network device */
    VIR_NODE_DEV_CAP_NET_LAST
};

enum virNodeDevHBACapType {
    /* Keep in sync with VIR_ENUM_IMPL in node_device_conf.c */
    VIR_NODE_DEV_CAP_HBA_FC_HOST,	/* fibre channel HBA */
    VIR_NODE_DEV_CAP_HBA_VPORT_OPS,	/* capable of vport operations */
    VIR_NODE_DEV_CAP_HBA_LAST
};

VIR_ENUM_DECL(virNodeDevCap)
VIR_ENUM_DECL(virNodeDevNetCap)
VIR_ENUM_DECL(virNodeDevHBACap)

enum virNodeDevStorageCapFlags {
    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE			= (1 << 0),
    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE	= (1 << 1),
    VIR_NODE_DEV_CAP_STORAGE_HOTPLUGGABLE		= (1 << 2),
};

enum virNodeDevScsiHostCapFlags {
    VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST			= (1 << 0),
    VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS			= (1 << 1),
};

enum virNodeDevPCICapFlags {
    VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION		= (1 << 0),
    VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION		= (1 << 1),
};

typedef struct _virNodeDevCapsDef virNodeDevCapsDef;
typedef virNodeDevCapsDef *virNodeDevCapsDefPtr;
struct _virNodeDevCapsDef {
    enum virNodeDevCapType type;
    union _virNodeDevCapData {
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
            struct pci_config_address *physical_function;
            struct pci_config_address **virtual_functions;
            unsigned int num_virtual_functions;
            unsigned int flags;
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
            enum virNodeDevNetCapType subtype;  /* LAST -> no subtype */
        } net;
        struct {
            unsigned int host;
            char *wwnn;
            char *wwpn;
            char *fabric_wwn;
            unsigned int flags;
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
    } data;
    virNodeDevCapsDefPtr next;          /* next capability */
};


typedef struct _virNodeDeviceDef virNodeDeviceDef;
typedef virNodeDeviceDef *virNodeDeviceDefPtr;
struct _virNodeDeviceDef {
    char *name;                         /* device name (unique on node) */
    char *sysfs_path;                   /* udev name/sysfs path */
    char *parent;			/* optional parent device name */
    char *parent_sysfs_path;            /* udev parent name/sysfs path */
    char *driver;                       /* optional driver name */
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
    unsigned int count;
    virNodeDeviceObjPtr *objs;
};

typedef struct _virDeviceMonitorState virDeviceMonitorState;
typedef virDeviceMonitorState *virDeviceMonitorStatePtr;
struct _virDeviceMonitorState {
    virMutex lock;

    virNodeDeviceObjList devs;		/* currently-known devices */
    void *privateData;			/* driver-specific private data */
};

# define virNodeDeviceReportError(code, ...)                             \
    virReportErrorHelper(VIR_FROM_NODEDEV, code, __FILE__,               \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

int virNodeDeviceHasCap(const virNodeDeviceObjPtr dev, const char *cap);

virNodeDeviceObjPtr virNodeDeviceFindByName(const virNodeDeviceObjListPtr devs,
                                            const char *name);
virNodeDeviceObjPtr
virNodeDeviceFindBySysfsPath(const virNodeDeviceObjListPtr devs,
                             const char *sysfs_path)
    ATTRIBUTE_NONNULL(2);

virNodeDeviceObjPtr virNodeDeviceAssignDef(virNodeDeviceObjListPtr devs,
                                           const virNodeDeviceDefPtr def);

void virNodeDeviceObjRemove(virNodeDeviceObjListPtr devs,
                            const virNodeDeviceObjPtr dev);

char *virNodeDeviceDefFormat(const virNodeDeviceDefPtr def);

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

int virNodeDeviceGetParentHost(const virNodeDeviceObjListPtr devs,
                               const char *dev_name,
                               const char *parent_name,
                               int *parent_host);

void virNodeDeviceDefFree(virNodeDeviceDefPtr def);

void virNodeDeviceObjFree(virNodeDeviceObjPtr dev);

void virNodeDeviceObjListFree(virNodeDeviceObjListPtr devs);

void virNodeDevCapsDefFree(virNodeDevCapsDefPtr caps);

void virNodeDeviceObjLock(virNodeDeviceObjPtr obj);
void virNodeDeviceObjUnlock(virNodeDeviceObjPtr obj);

#endif /* __VIR_NODE_DEVICE_CONF_H__ */
