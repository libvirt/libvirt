/*
 * storage_conf.h: config handling for storage driver
 *
 * Copyright (C) 2006-2008 Red Hat, Inc.
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

#ifndef __VIR_STORAGE_CONF_H__
#define __VIR_STORAGE_CONF_H__

#include <libvirt/libvirt.h>
#include "internal.h"

/* Shared structs */



typedef struct _virStoragePerms virStoragePerms;
typedef virStoragePerms *virStoragePermsPtr;
struct _virStoragePerms {
    int mode;
    int uid;
    int gid;
    char *label;
};

/* Storage volumes */


/*
 * How the volume's data is stored on underlying
 * physical devices - can potentially span many
 * devices in LVM case.
 */
typedef struct _virStorageVolSourceExtent virStorageVolSourceExtent;
typedef virStorageVolSourceExtent *virStorageVolSourceExtentPtr;
struct _virStorageVolSourceExtent {
    char *path;
    unsigned long long start;
    unsigned long long end;
};

typedef struct _virStorageVolSource virStorageVolSource;
typedef virStorageVolSource *virStorageVolSourcePtr;
struct _virStorageVolSource {
    int nextent;
    virStorageVolSourceExtentPtr extents;
};


/*
 * How the volume appears on the host
 */
typedef struct _virStorageVolTarget virStorageVolTarget;
typedef virStorageVolTarget *virStorageVolTargetPtr;
struct _virStorageVolTarget {
    char *path;
    int format;
    virStoragePerms perms;
};


typedef struct _virStorageVolDef virStorageVolDef;
typedef virStorageVolDef *virStorageVolDefPtr;
struct _virStorageVolDef {
    char *name;
    char *key;

    unsigned long long allocation;
    unsigned long long capacity;

    virStorageVolSource source;
    virStorageVolTarget target;

    virStorageVolDefPtr next;
};




/* Storage pools */

enum virStoragePoolType {
    VIR_STORAGE_POOL_DIR = 1,  /* Local directory */
    VIR_STORAGE_POOL_FS,       /* Local filesystem */
    VIR_STORAGE_POOL_NETFS,    /* Networked filesystem - eg NFS, GFS, etc */
    VIR_STORAGE_POOL_LOGICAL,  /* Logical volume groups / volumes */
    VIR_STORAGE_POOL_DISK,     /* Disk partitions */
    VIR_STORAGE_POOL_ISCSI,    /* iSCSI targets */
    VIR_STORAGE_POOL_SCSI,     /* SCSI HBA */
};


enum virStoragePoolAuthType {
    VIR_STORAGE_POOL_AUTH_NONE,
    VIR_STORAGE_POOL_AUTH_CHAP,
};

typedef struct _virStoragePoolAuthChap virStoragePoolAuthChap;
typedef virStoragePoolAuthChap *virStoragePoolAuthChapPtr;
struct _virStoragePoolAuthChap {
    char *login;
    char *passwd;
};


/*
 * For remote pools, info on how to reach the host
 */
typedef struct _virStoragePoolSourceHost virStoragePoolSourceHost;
typedef virStoragePoolSourceHost *virStoragePoolSourceHostPtr;
struct _virStoragePoolSourceHost {
    char *name;
    int port;
    int protocol;
};


/*
 * Available extents on the underlying storage
 */
typedef struct _virStoragePoolSourceDeviceExtent virStoragePoolSourceDeviceExtent;
typedef virStoragePoolSourceDeviceExtent *virStoragePoolSourceDeviceExtentPtr;
struct _virStoragePoolSourceDeviceExtent {
    unsigned long long start;
    unsigned long long end;
};


/*
 * Pools can be backed by one or more devices, and some
 * allow us to track free space on underlying devices.
 */
typedef struct _virStoragePoolSourceDevice virStoragePoolSourceDevice;
typedef virStoragePoolSourceDevice *virStoragePoolSourceDevicePtr;
struct _virStoragePoolSourceDevice {
    int nfreeExtent;
    virStoragePoolSourceDeviceExtentPtr freeExtents;
    char *path;
    int format;     /* Pool specific source format */
};



typedef struct _virStoragePoolSource virStoragePoolSource;
typedef virStoragePoolSource *virStoragePoolSourcePtr;
struct _virStoragePoolSource {
    /* An optional host */
    virStoragePoolSourceHost host;

    /* And either one or more devices ... */
    int ndevice;
    virStoragePoolSourceDevicePtr devices;

    /* Or a directory */
    char *dir;

    /* Or an adapter */
    char *adapter;

    int authType;       /* virStoragePoolAuthType */
    union {
        virStoragePoolAuthChap chap;
    } auth;

    int format; /* Pool type specific format such as filesystem type, or lvm version, etc */
};


typedef struct _virStoragePoolTarget virStoragePoolTarget;
typedef virStoragePoolTarget *virStoragePoolTargetPtr;
struct _virStoragePoolTarget {
    char *path;                /* Optional local filesystem mapping */
    virStoragePerms perms;     /* Default permissions for volumes */
};


typedef struct _virStoragePoolDef virStoragePoolDef;
typedef virStoragePoolDef *virStoragePoolDefPtr;
struct _virStoragePoolDef {
    /* General metadata */
    char *name;
    unsigned char uuid[VIR_UUID_BUFLEN];
    int type; /* virStoragePoolType */

    unsigned long long allocation;
    unsigned long long capacity;
    unsigned long long available;

    virStoragePoolSource source;
    virStoragePoolTarget target;
};

typedef struct _virStoragePoolObj virStoragePoolObj;
typedef virStoragePoolObj *virStoragePoolObjPtr;

struct _virStoragePoolObj {
    char *configFile;
    char *autostartLink;
    int active;
    int autostart;

    virStoragePoolDefPtr def;
    virStoragePoolDefPtr newDef;

    int nvolumes;
    virStorageVolDefPtr volumes;

    virStoragePoolObjPtr next;
};




typedef struct _virStorageDriverState virStorageDriverState;
typedef virStorageDriverState *virStorageDriverStatePtr;

struct _virStorageDriverState {
    int nactivePools;
    int ninactivePools;
    virStoragePoolObjPtr pools;
    char *configDir;
    char *autostartDir;
};


static inline int virStoragePoolObjIsActive(virStoragePoolObjPtr pool) {
    return pool->active;
}

void virStorageReportError(virConnectPtr conn,
                           int code,
                           const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf, 3, 4);

int virStoragePoolObjScanConfigs(virStorageDriverStatePtr driver);

virStoragePoolObjPtr virStoragePoolObjFindByUUID(virStorageDriverStatePtr driver,
                                                 const unsigned char *uuid);
virStoragePoolObjPtr virStoragePoolObjFindByName(virStorageDriverStatePtr driver,
                                                 const char *name);

virStorageVolDefPtr virStorageVolDefFindByKey(virStoragePoolObjPtr pool,
                                              const char *key);
virStorageVolDefPtr virStorageVolDefFindByPath(virStoragePoolObjPtr pool,
                                               const char *path);
virStorageVolDefPtr virStorageVolDefFindByName(virStoragePoolObjPtr pool,
                                               const char *name);

void virStoragePoolObjClearVols(virStoragePoolObjPtr pool);

virStoragePoolDefPtr virStoragePoolDefParse(virConnectPtr conn,
                                            const char *xml,
                                            const char *filename);
char *virStoragePoolDefFormat(virConnectPtr conn,
                              virStoragePoolDefPtr def);

virStorageVolDefPtr virStorageVolDefParse(virConnectPtr conn,
                                          virStoragePoolDefPtr pool,
                                          const char *xml,
                                          const char *filename);
char *virStorageVolDefFormat(virConnectPtr conn,
                             virStoragePoolDefPtr pool,
                             virStorageVolDefPtr def);

virStoragePoolObjPtr virStoragePoolObjAssignDef(virConnectPtr conn,
                                                virStorageDriverStatePtr driver,
                                                virStoragePoolDefPtr def);

int virStoragePoolObjSaveDef(virConnectPtr conn,
                             virStorageDriverStatePtr driver,
                             virStoragePoolObjPtr pool,
                             virStoragePoolDefPtr def);
int virStoragePoolObjDeleteDef(virConnectPtr conn,
                               virStoragePoolObjPtr pool);

void virStorageVolDefFree(virStorageVolDefPtr def);
void virStoragePoolDefFree(virStoragePoolDefPtr def);
void virStoragePoolObjFree(virStoragePoolObjPtr pool);
void virStoragePoolObjRemove(virStorageDriverStatePtr driver,
                             virStoragePoolObjPtr pool);

#endif /* __VIR_STORAGE_DRIVER_H__ */


/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
