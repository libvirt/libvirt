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

#include "internal.h"
#include "util.h"
#include "threads.h"

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
    int type; /* virStorageVolType enum */

    unsigned int building;

    unsigned long long allocation;
    unsigned long long capacity;

    virStorageVolSource source;
    virStorageVolTarget target;
    virStorageVolTarget backingStore;
};

typedef struct _virStorageVolDefList virStorageVolDefList;
typedef virStorageVolDefList *virStorageVolDefListPtr;
struct _virStorageVolDefList {
    unsigned int count;
    virStorageVolDefPtr *objs;
};



/* Storage pools */

enum virStoragePoolType {
    VIR_STORAGE_POOL_DIR,      /* Local directory */
    VIR_STORAGE_POOL_FS,       /* Local filesystem */
    VIR_STORAGE_POOL_NETFS,    /* Networked filesystem - eg NFS, GFS, etc */
    VIR_STORAGE_POOL_LOGICAL,  /* Logical volume groups / volumes */
    VIR_STORAGE_POOL_DISK,     /* Disk partitions */
    VIR_STORAGE_POOL_ISCSI,    /* iSCSI targets */
    VIR_STORAGE_POOL_SCSI,     /* SCSI HBA */

    VIR_STORAGE_POOL_LAST,
};

VIR_ENUM_DECL(virStoragePool)

enum virStoragePoolDeviceType {
    VIR_STORAGE_DEVICE_TYPE_DISK = 0x00,
    VIR_STORAGE_DEVICE_TYPE_ROM = 0x05,

    VIR_STORAGE_DEVICE_TYPE_LAST,
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

    /* Or a name */
    char *name;

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
    virMutex lock;

    char *configFile;
    char *autostartLink;
    int active;
    int autostart;
    unsigned int asyncjobs;

    virStoragePoolDefPtr def;
    virStoragePoolDefPtr newDef;

    virStorageVolDefList volumes;
};

typedef struct _virStoragePoolObjList virStoragePoolObjList;
typedef virStoragePoolObjList *virStoragePoolObjListPtr;
struct _virStoragePoolObjList {
    unsigned int count;
    virStoragePoolObjPtr *objs;
};




typedef struct _virStorageDriverState virStorageDriverState;
typedef virStorageDriverState *virStorageDriverStatePtr;

struct _virStorageDriverState {
    virMutex lock;

    virStoragePoolObjList pools;

    char *configDir;
    char *autostartDir;
};

typedef struct _virStoragePoolSourceList virStoragePoolSourceList;
typedef virStoragePoolSourceList *virStoragePoolSourceListPtr;
struct _virStoragePoolSourceList {
    int type;
    unsigned int nsources;
    virStoragePoolSourcePtr sources;
};


static inline int virStoragePoolObjIsActive(virStoragePoolObjPtr pool) {
    return pool->active;
}

#define virStorageReportError(conn, code, fmt...)                            \
        virReportErrorHelper(conn, VIR_FROM_STORAGE, code, __FILE__,       \
                               __FUNCTION__, __LINE__, fmt)

int virStoragePoolLoadAllConfigs(virConnectPtr conn,
                                 virStoragePoolObjListPtr pools,
                                 const char *configDir,
                                 const char *autostartDir);

virStoragePoolObjPtr virStoragePoolObjFindByUUID(virStoragePoolObjListPtr pools,
                                                 const unsigned char *uuid);
virStoragePoolObjPtr virStoragePoolObjFindByName(virStoragePoolObjListPtr pools,
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
                                                virStoragePoolObjListPtr pools,
                                                virStoragePoolDefPtr def);

int virStoragePoolObjSaveDef(virConnectPtr conn,
                             virStorageDriverStatePtr driver,
                             virStoragePoolObjPtr pool,
                             virStoragePoolDefPtr def);
int virStoragePoolObjDeleteDef(virConnectPtr conn,
                               virStoragePoolObjPtr pool);

void virStorageVolDefFree(virStorageVolDefPtr def);
void virStoragePoolSourceFree(virStoragePoolSourcePtr source);
void virStoragePoolDefFree(virStoragePoolDefPtr def);
void virStoragePoolObjFree(virStoragePoolObjPtr pool);
void virStoragePoolObjListFree(virStoragePoolObjListPtr pools);
void virStoragePoolObjRemove(virStoragePoolObjListPtr pools,
                             virStoragePoolObjPtr pool);

char *virStoragePoolSourceListFormat(virConnectPtr conn,
                                     virStoragePoolSourceListPtr def);

void virStoragePoolObjLock(virStoragePoolObjPtr obj);
void virStoragePoolObjUnlock(virStoragePoolObjPtr obj);


enum virStoragePoolFormatFileSystem {
    VIR_STORAGE_POOL_FS_AUTO = 0,
    VIR_STORAGE_POOL_FS_EXT2,
    VIR_STORAGE_POOL_FS_EXT3,
    VIR_STORAGE_POOL_FS_EXT4,
    VIR_STORAGE_POOL_FS_UFS,
    VIR_STORAGE_POOL_FS_ISO,
    VIR_STORAGE_POOL_FS_UDF,
    VIR_STORAGE_POOL_FS_GFS,
    VIR_STORAGE_POOL_FS_GFS2,
    VIR_STORAGE_POOL_FS_VFAT,
    VIR_STORAGE_POOL_FS_HFSPLUS,
    VIR_STORAGE_POOL_FS_XFS,
    VIR_STORAGE_POOL_FS_LAST,
};
VIR_ENUM_DECL(virStoragePoolFormatFileSystem)

enum virStoragePoolFormatFileSystemNet {
    VIR_STORAGE_POOL_NETFS_AUTO = 0,
    VIR_STORAGE_POOL_NETFS_NFS,
    VIR_STORAGE_POOL_NETFS_LAST,
};
VIR_ENUM_DECL(virStoragePoolFormatFileSystemNet)

enum virStoragePoolFormatDisk {
    VIR_STORAGE_POOL_DISK_UNKNOWN = 0,
    VIR_STORAGE_POOL_DISK_DOS = 1,
    VIR_STORAGE_POOL_DISK_DVH,
    VIR_STORAGE_POOL_DISK_GPT,
    VIR_STORAGE_POOL_DISK_MAC,
    VIR_STORAGE_POOL_DISK_BSD,
    VIR_STORAGE_POOL_DISK_PC98,
    VIR_STORAGE_POOL_DISK_SUN,
    VIR_STORAGE_POOL_DISK_LVM2,
    VIR_STORAGE_POOL_DISK_LAST,
};

VIR_ENUM_DECL(virStoragePoolFormatDisk)

enum virStoragePoolFormatLogical {
    VIR_STORAGE_POOL_LOGICAL_UNKNOWN = 0,
    VIR_STORAGE_POOL_LOGICAL_LVM2 = 1,
    VIR_STORAGE_POOL_LOGICAL_LAST,
};
VIR_ENUM_DECL(virStoragePoolFormatLogical)


enum virStorageVolFormatFileSystem {
    VIR_STORAGE_VOL_FILE_RAW = 0,
    VIR_STORAGE_VOL_FILE_DIR,
    VIR_STORAGE_VOL_FILE_BOCHS,
    VIR_STORAGE_VOL_FILE_CLOOP,
    VIR_STORAGE_VOL_FILE_COW,
    VIR_STORAGE_VOL_FILE_DMG,
    VIR_STORAGE_VOL_FILE_ISO,
    VIR_STORAGE_VOL_FILE_QCOW,
    VIR_STORAGE_VOL_FILE_QCOW2,
    VIR_STORAGE_VOL_FILE_VMDK,
    VIR_STORAGE_VOL_FILE_VPC,
    VIR_STORAGE_VOL_FILE_LAST,
};
VIR_ENUM_DECL(virStorageVolFormatFileSystem)

/*
 * XXX these are basically partition types.
 *
 * fdisk has a bazillion partition ID types
 * parted has practically none, and splits the
 * info across 3 different attributes.
 *
 * So this is a semi-generic set
 */
enum virStorageVolFormatDisk {
    VIR_STORAGE_VOL_DISK_NONE = 0,
    VIR_STORAGE_VOL_DISK_LINUX,
    VIR_STORAGE_VOL_DISK_FAT16,
    VIR_STORAGE_VOL_DISK_FAT32,
    VIR_STORAGE_VOL_DISK_LINUX_SWAP,
    VIR_STORAGE_VOL_DISK_LINUX_LVM,
    VIR_STORAGE_VOL_DISK_LINUX_RAID,
    VIR_STORAGE_VOL_DISK_EXTENDED,
    VIR_STORAGE_VOL_DISK_LAST,
};
VIR_ENUM_DECL(virStorageVolFormatDisk)



#endif /* __VIR_STORAGE_CONF_H__ */
