/*
 * node_device_conf.h: config handling for node devices
 *
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
#define __VIR_NODE_DEVICE_CONF_H__

#include "internal.h"
#include "util.h"
#include "threads.h"

enum virNodeDevCapType {
    /* Keep in sync with VIR_ENUM_IMPL in node_device_conf.c */
    VIR_NODE_DEV_CAP_SYSTEM,		/* System capability */
    VIR_NODE_DEV_CAP_PCI_DEV,		/* PCI device */
    VIR_NODE_DEV_CAP_USB_DEV,		/* USB device */
    VIR_NODE_DEV_CAP_USB_INTERFACE,	/* USB interface */
    VIR_NODE_DEV_CAP_NET,		/* Network device */
    VIR_NODE_DEV_CAP_SCSI_HOST,		/* SCSI Host Bus Adapter */
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

VIR_ENUM_DECL(virNodeDevCap)
VIR_ENUM_DECL(virNodeDevNetCap)

enum virNodeDevStorageCapFlags {
    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE			= (1 << 0),
    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE	= (1 << 1),
    VIR_NODE_DEV_CAP_STORAGE_HOTPLUGGABLE		= (1 << 2),
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
            unsigned domain;
            unsigned bus;
            unsigned slot;
            unsigned function;
            unsigned product;
            unsigned vendor;
            char *product_name;
            char *vendor_name;
        } pci_dev;
        struct {
            unsigned bus;
            unsigned device;
            unsigned product;
            unsigned vendor;
            char *product_name;
            char *vendor_name;
        } usb_dev;
        struct {
            unsigned number;
            unsigned _class;		/* "class" is reserved in C */
            unsigned subclass;
            unsigned protocol;
            char *description;
        } usb_if;
        struct {
            char *address;
            char *ifname;
            enum virNodeDevNetCapType subtype;  /* LAST -> no subtype */
        } net;
        struct {
            unsigned host;
        } scsi_host;
        struct {
            unsigned host;
            unsigned bus;
            unsigned target;
            unsigned lun;
            char *type;
        } scsi;
        struct {
            unsigned long long size;
            unsigned long long removable_media_size;
            char *block;
            char *bus;
            char *drive_type;
            char *model;
            char *vendor;
            unsigned flags;	/* virNodeDevStorageCapFlags bits */
        } storage;
    } data;
    virNodeDevCapsDefPtr next;          /* next capability */
};


typedef struct _virNodeDeviceDef virNodeDeviceDef;
typedef virNodeDeviceDef *virNodeDeviceDefPtr;
struct _virNodeDeviceDef {
    char *name;                         /* device name (unique on node) */
    char *parent;			/* optional parent device name */
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

#define virNodeDeviceReportError(conn, code, fmt...)			\
        virReportErrorHelper(conn, VIR_FROM_NODEDEV, code, __FILE__,	\
                               __FUNCTION__, __LINE__, fmt)

virNodeDeviceObjPtr virNodeDeviceFindByName(const virNodeDeviceObjListPtr devs,
                                            const char *name);

virNodeDeviceObjPtr virNodeDeviceAssignDef(virConnectPtr conn,
                                           virNodeDeviceObjListPtr devs,
                                           const virNodeDeviceDefPtr def);

void virNodeDeviceObjRemove(virNodeDeviceObjListPtr devs,
                            const virNodeDeviceObjPtr dev);

char *virNodeDeviceDefFormat(virConnectPtr conn,
                             const virNodeDeviceDefPtr def);

// TODO: virNodeDeviceDefParseString/File/Node for virNodeDeviceCreate

void virNodeDeviceDefFree(virNodeDeviceDefPtr def);

void virNodeDeviceObjFree(virNodeDeviceObjPtr dev);

void virNodeDeviceObjListFree(virNodeDeviceObjListPtr devs);

void virNodeDevCapsDefFree(virNodeDevCapsDefPtr caps);

void virNodeDeviceObjLock(virNodeDeviceObjPtr obj);
void virNodeDeviceObjUnlock(virNodeDeviceObjPtr obj);

#endif /* __VIR_NODE_DEVICE_CONF_H__ */
