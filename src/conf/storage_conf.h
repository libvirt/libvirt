/*
 * storage_conf.h: config handling for storage driver
 *
 * Copyright (C) 2006-2008, 2010-2013 Red Hat, Inc.
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

#ifndef __VIR_STORAGE_CONF_H__
# define __VIR_STORAGE_CONF_H__

# include "internal.h"
# include "storage_encryption_conf.h"
# include "virbitmap.h"
# include "virthread.h"

# include <libxml/tree.h>

typedef struct _virStoragePerms virStoragePerms;
typedef virStoragePerms *virStoragePermsPtr;
struct _virStoragePerms {
    mode_t mode;
    uid_t uid;
    gid_t gid;
    char *label;
};

typedef struct _virStorageTimestamps virStorageTimestamps;
typedef virStorageTimestamps *virStorageTimestampsPtr;
struct _virStorageTimestamps {
    struct timespec atime;
    /* if btime.tv_nsec == -1 then
     * birth time is unknown
     */
    struct timespec btime;
    struct timespec ctime;
    struct timespec mtime;
};


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
    virStorageTimestampsPtr timestamps;
    int type; /* only used by disk backend for partition type */
    /* The next three are currently only used in vol->target,
     * not in vol->backingStore. */
    virStorageEncryptionPtr encryption;
    virBitmapPtr features;
    char *compat;
};

typedef struct _virStorageVolDef virStorageVolDef;
typedef virStorageVolDef *virStorageVolDefPtr;
struct _virStorageVolDef {
    char *name;
    char *key;
    int type; /* enum virStorageVolType */

    unsigned int building;

    unsigned long long allocation; /* bytes */
    unsigned long long capacity; /* bytes */

    virStorageVolSource source;
    virStorageVolTarget target;
    virStorageVolTarget backingStore;
};

typedef struct _virStorageVolDefList virStorageVolDefList;
typedef virStorageVolDefList *virStorageVolDefListPtr;
struct _virStorageVolDefList {
    size_t count;
    virStorageVolDefPtr *objs;
};

VIR_ENUM_DECL(virStorageVol)

enum virStoragePoolType {
    VIR_STORAGE_POOL_DIR,      /* Local directory */
    VIR_STORAGE_POOL_FS,       /* Local filesystem */
    VIR_STORAGE_POOL_NETFS,    /* Networked filesystem - eg NFS, GFS, etc */
    VIR_STORAGE_POOL_LOGICAL,  /* Logical volume groups / volumes */
    VIR_STORAGE_POOL_DISK,     /* Disk partitions */
    VIR_STORAGE_POOL_ISCSI,    /* iSCSI targets */
    VIR_STORAGE_POOL_SCSI,     /* SCSI HBA */
    VIR_STORAGE_POOL_MPATH,    /* Multipath devices */
    VIR_STORAGE_POOL_RBD,      /* RADOS Block Device */
    VIR_STORAGE_POOL_SHEEPDOG, /* Sheepdog device */
    VIR_STORAGE_POOL_GLUSTER,  /* Gluster device */

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
    VIR_STORAGE_POOL_AUTH_CEPHX,

    VIR_STORAGE_POOL_AUTH_LAST,
};
VIR_ENUM_DECL(virStoragePoolAuthType)

typedef struct _virStoragePoolAuthSecret virStoragePoolAuthSecret;
typedef virStoragePoolAuthSecret *virStoragePoolAuthSecretPtr;
struct _virStoragePoolAuthSecret {
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *usage;
    bool uuidUsable;
};

typedef struct _virStoragePoolAuthChap virStoragePoolAuthChap;
typedef virStoragePoolAuthChap *virStoragePoolAuthChapPtr;
struct _virStoragePoolAuthChap {
    char *username;
    virStoragePoolAuthSecret secret;
};

typedef struct _virStoragePoolAuthCephx virStoragePoolAuthCephx;
typedef virStoragePoolAuthCephx *virStoragePoolAuthCephxPtr;
struct _virStoragePoolAuthCephx {
    char *username;
    virStoragePoolAuthSecret secret;
};

/*
 * For remote pools, info on how to reach the host
 */
typedef struct _virStoragePoolSourceHost virStoragePoolSourceHost;
typedef virStoragePoolSourceHost *virStoragePoolSourceHostPtr;
struct _virStoragePoolSourceHost {
    char *name;
    int port;
};


/*
 * For MSDOS partitions, the free area is important when
 * creating logical partitions
 */
enum virStorageFreeType {
    VIR_STORAGE_FREE_NONE = 0,
    VIR_STORAGE_FREE_NORMAL,
    VIR_STORAGE_FREE_LOGICAL,
    VIR_STORAGE_FREE_LAST
};

/*
 * Available extents on the underlying storage
 */
typedef struct _virStoragePoolSourceDeviceExtent virStoragePoolSourceDeviceExtent;
typedef virStoragePoolSourceDeviceExtent *virStoragePoolSourceDeviceExtentPtr;
struct _virStoragePoolSourceDeviceExtent {
    unsigned long long start;
    unsigned long long end;
    int type; /* enum virStorageFreeType */
};

typedef struct _virStoragePoolSourceInitiatorAttr virStoragePoolSourceInitiatorAttr;
struct _virStoragePoolSourceInitiatorAttr {
    char *iqn; /* Initiator IQN */
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
    int format; /* Pool specific source format */

    /* When the source device is a physical disk,
     * the geometry data is needed
     */
    struct _geometry {
        int cylinders;
        int heads;
        int sectors;
    } geometry;
};

enum virStoragePoolSourceAdapterType {
    VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_DEFAULT = 0,
    VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_SCSI_HOST,
    VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_FC_HOST,

    VIR_STORAGE_POOL_SOURCE_ADAPTER_TYPE_LAST,
};
VIR_ENUM_DECL(virStoragePoolSourceAdapterType)

typedef struct _virStoragePoolSourceAdapter virStoragePoolSourceAdapter;
struct _virStoragePoolSourceAdapter {
    int type; /* enum virStoragePoolSourceAdapterType */

    union {
        char *name;
        struct {
            char *parent;
            char *wwnn;
            char *wwpn;
        } fchost;
    } data;
};

typedef struct _virStoragePoolSource virStoragePoolSource;
typedef virStoragePoolSource *virStoragePoolSourcePtr;
struct _virStoragePoolSource {
    /* An optional (maybe multiple) host(s) */
    size_t nhost;
    virStoragePoolSourceHostPtr hosts;

    /* And either one or more devices ... */
    size_t ndevice;
    virStoragePoolSourceDevicePtr devices;

    /* Or a directory */
    char *dir;

    /* Or an adapter */
    virStoragePoolSourceAdapter adapter;

    /* Or a name */
    char *name;

    /* Initiator IQN */
    virStoragePoolSourceInitiatorAttr initiator;

    int authType;       /* virStoragePoolAuthType */
    union {
        virStoragePoolAuthChap chap;
        virStoragePoolAuthCephx cephx;
    } auth;

    /* Vendor of the source */
    char *vendor;

    /* Product name of the source*/
    char *product;

    /* Pool type specific format such as filesystem type,
     * or lvm version, etc.
     */
    int format;
};

typedef struct _virStoragePoolTarget virStoragePoolTarget;
typedef virStoragePoolTarget *virStoragePoolTargetPtr;
struct _virStoragePoolTarget {
    char *path; /* Optional local filesystem mapping */
    virStoragePerms perms; /* Default permissions for volumes */
};

typedef struct _virStoragePoolDef virStoragePoolDef;
typedef virStoragePoolDef *virStoragePoolDefPtr;
struct _virStoragePoolDef {
    char *name;
    unsigned char uuid[VIR_UUID_BUFLEN];
    int type; /* enum virStoragePoolType */

    unsigned long long allocation; /* bytes */
    unsigned long long capacity; /* bytes */
    unsigned long long available; /* bytes */

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
    size_t count;
    virStoragePoolObjPtr *objs;
};

typedef struct _virStorageDriverState virStorageDriverState;
typedef virStorageDriverState *virStorageDriverStatePtr;

struct _virStorageDriverState {
    virMutex lock;

    virStoragePoolObjList pools;

    char *configDir;
    char *autostartDir;
    bool privileged;
};

typedef struct _virStoragePoolSourceList virStoragePoolSourceList;
typedef virStoragePoolSourceList *virStoragePoolSourceListPtr;
struct _virStoragePoolSourceList {
    int type;
    unsigned int nsources;
    virStoragePoolSourcePtr sources;
};

typedef bool (*virStoragePoolObjListFilter)(virConnectPtr conn,
                                            virStoragePoolDefPtr def);

static inline int
virStoragePoolObjIsActive(virStoragePoolObjPtr pool)
{
    return pool->active;
}

int virStoragePoolLoadAllConfigs(virStoragePoolObjListPtr pools,
                                 const char *configDir,
                                 const char *autostartDir);

virStoragePoolObjPtr
virStoragePoolObjFindByUUID(virStoragePoolObjListPtr pools,
                            const unsigned char *uuid);
virStoragePoolObjPtr
virStoragePoolObjFindByName(virStoragePoolObjListPtr pools,
                            const char *name);
virStoragePoolObjPtr
virStoragePoolSourceFindDuplicateDevices(virStoragePoolObjPtr pool,
                                         virStoragePoolDefPtr def);

virStorageVolDefPtr
virStorageVolDefFindByKey(virStoragePoolObjPtr pool,
                          const char *key);
virStorageVolDefPtr
virStorageVolDefFindByPath(virStoragePoolObjPtr pool,
                           const char *path);
virStorageVolDefPtr
virStorageVolDefFindByName(virStoragePoolObjPtr pool,
                           const char *name);

void virStoragePoolObjClearVols(virStoragePoolObjPtr pool);

virStoragePoolDefPtr virStoragePoolDefParseString(const char *xml);
virStoragePoolDefPtr virStoragePoolDefParseFile(const char *filename);
virStoragePoolDefPtr virStoragePoolDefParseNode(xmlDocPtr xml,
                                                xmlNodePtr root);
char *virStoragePoolDefFormat(virStoragePoolDefPtr def);

virStorageVolDefPtr
virStorageVolDefParseString(virStoragePoolDefPtr pool,
                            const char *xml);
virStorageVolDefPtr
virStorageVolDefParseFile(virStoragePoolDefPtr pool,
                          const char *filename);
virStorageVolDefPtr
virStorageVolDefParseNode(virStoragePoolDefPtr pool,
                          xmlDocPtr xml,
                          xmlNodePtr root);
char *virStorageVolDefFormat(virStoragePoolDefPtr pool,
                             virStorageVolDefPtr def);

virStoragePoolObjPtr
virStoragePoolObjAssignDef(virStoragePoolObjListPtr pools,
                           virStoragePoolDefPtr def);

int virStoragePoolObjSaveDef(virStorageDriverStatePtr driver,
                             virStoragePoolObjPtr pool,
                             virStoragePoolDefPtr def);
int virStoragePoolObjDeleteDef(virStoragePoolObjPtr pool);

void virStorageVolDefFree(virStorageVolDefPtr def);
void virStoragePoolSourceClear(virStoragePoolSourcePtr source);
void virStoragePoolSourceDeviceClear(virStoragePoolSourceDevicePtr dev);
void virStoragePoolSourceFree(virStoragePoolSourcePtr source);
void virStoragePoolDefFree(virStoragePoolDefPtr def);
void virStoragePoolObjFree(virStoragePoolObjPtr pool);
void virStoragePoolObjListFree(virStoragePoolObjListPtr pools);
void virStoragePoolObjRemove(virStoragePoolObjListPtr pools,
                             virStoragePoolObjPtr pool);

virStoragePoolSourcePtr
virStoragePoolDefParseSourceString(const char *srcSpec,
                                   int pool_type);
virStoragePoolSourcePtr
virStoragePoolSourceListNewSource(virStoragePoolSourceListPtr list);
char *virStoragePoolSourceListFormat(virStoragePoolSourceListPtr def);

int virStoragePoolObjIsDuplicate(virStoragePoolObjListPtr pools,
                                 virStoragePoolDefPtr def,
                                 unsigned int check_active);

int virStoragePoolSourceFindDuplicate(virStoragePoolObjListPtr pools,
                                      virStoragePoolDefPtr def);

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
    VIR_STORAGE_POOL_FS_OCFS2,
    VIR_STORAGE_POOL_FS_LAST,
};
VIR_ENUM_DECL(virStoragePoolFormatFileSystem)

enum virStoragePoolFormatFileSystemNet {
    VIR_STORAGE_POOL_NETFS_AUTO = 0,
    VIR_STORAGE_POOL_NETFS_NFS,
    VIR_STORAGE_POOL_NETFS_GLUSTERFS,
    VIR_STORAGE_POOL_NETFS_CIFS,
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

/*
 * XXX: these are basically partition types.
 *
 * fdisk has a bazillion partition ID types parted has
 * practically none, and splits the * info across 3
 * different attributes.
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

enum virStorageVolTypeDisk {
    VIR_STORAGE_VOL_DISK_TYPE_NONE = 0,
    VIR_STORAGE_VOL_DISK_TYPE_PRIMARY,
    VIR_STORAGE_VOL_DISK_TYPE_LOGICAL,
    VIR_STORAGE_VOL_DISK_TYPE_EXTENDED,
    VIR_STORAGE_VOL_DISK_TYPE_LAST,
};

/*
 * Mapping of Parted fs-types MUST be kept in the
 * same order as virStorageVolFormatDisk
 */
enum virStoragePartedFsType {
    VIR_STORAGE_PARTED_FS_TYPE_NONE = 0,
    VIR_STORAGE_PARTED_FS_TYPE_LINUX,
    VIR_STORAGE_PARTED_FS_TYPE_FAT16,
    VIR_STORAGE_PARTED_FS_TYPE_FAT32,
    VIR_STORAGE_PARTED_FS_TYPE_LINUX_SWAP,
    VIR_STORAGE_PARTED_FS_TYPE_LINUX_LVM,
    VIR_STORAGE_PARTED_FS_TYPE_LINUX_RAID,
    VIR_STORAGE_PARTED_FS_TYPE_EXTENDED,
    VIR_STORAGE_PARTED_FS_TYPE_LAST,
};
VIR_ENUM_DECL(virStoragePartedFsType)

# define VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ACTIVE   \
                (VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE)

# define VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_PERSISTENT   \
                (VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_TRANSIENT)

# define VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_AUTOSTART    \
                (VIR_CONNECT_LIST_STORAGE_POOLS_AUTOSTART |  \
                 VIR_CONNECT_LIST_STORAGE_POOLS_NO_AUTOSTART)

# define VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_POOL_TYPE  \
                (VIR_CONNECT_LIST_STORAGE_POOLS_DIR      | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_FS       | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_NETFS    | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_LOGICAL  | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_DISK     | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_ISCSI    | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_SCSI     | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_MPATH    | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_RBD      | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_SHEEPDOG | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_GLUSTER)

# define VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ALL                  \
                (VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ACTIVE     | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_PERSISTENT | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_AUTOSTART  | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_POOL_TYPE)

int virStoragePoolObjListExport(virConnectPtr conn,
                                virStoragePoolObjList poolobjs,
                                virStoragePoolPtr **pools,
                                virStoragePoolObjListFilter filter,
                                unsigned int flags);

#endif /* __VIR_STORAGE_CONF_H__ */
