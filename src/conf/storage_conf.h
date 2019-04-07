/*
 * storage_conf.h: config handling for storage driver
 *
 * Copyright (C) 2006-2008, 2010-2016 Red Hat, Inc.
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
 */

#ifndef LIBVIRT_STORAGE_CONF_H
# define LIBVIRT_STORAGE_CONF_H

# include "internal.h"
# include "virstorageencryption.h"
# include "virstoragefile.h"
# include "virbitmap.h"
# include "virthread.h"
# include "device_conf.h"
# include "object_event.h"
# include "storage_adapter_conf.h"

# include <libxml/tree.h>

/* Various callbacks needed to parse/create Storage Pool XML's using
 * a private namespace */
typedef int (*virStoragePoolDefNamespaceParse)(xmlXPathContextPtr, void **);
typedef void (*virStoragePoolDefNamespaceFree)(void *);
typedef int (*virStoragePoolDefNamespaceXMLFormat)(virBufferPtr, void *);
typedef const char *(*virStoragePoolDefNamespaceHref)(void);

typedef struct _virStoragePoolXMLNamespace virStoragePoolXMLNamespace;
typedef virStoragePoolXMLNamespace *virStoragePoolXMLNamespacePtr;
struct _virStoragePoolXMLNamespace {
    virStoragePoolDefNamespaceParse parse;
    virStoragePoolDefNamespaceFree free;
    virStoragePoolDefNamespaceXMLFormat format;
    virStoragePoolDefNamespaceHref href;
};

int
virStoragePoolOptionsPoolTypeSetXMLNamespace(int type,
                                             virStoragePoolXMLNamespacePtr ns);

int
virStoragePoolOptionsFormatPool(virBufferPtr buf,
                                int type);

int
virStoragePoolOptionsFormatVolume(virBufferPtr buf,
                                  int type);
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
    size_t nextent;
    virStorageVolSourceExtentPtr extents;

    int partType; /* virStorageVolTypeDisk, only used by disk
                   * backend for partition type creation */
};

typedef enum {
    VIR_STORAGE_VOL_DEF_REFRESH_ALLOCATION_DEFAULT,  /* compute actual allocation */
    VIR_STORAGE_VOL_DEF_REFRESH_ALLOCATION_CAPACITY, /* use logical capacity */
    VIR_STORAGE_VOL_DEF_REFRESH_ALLOCATION_LAST,
} virStorageVolDefRefreshAllocation;

VIR_ENUM_DECL(virStorageVolDefRefreshAllocation);

typedef struct _virStorageVolDef virStorageVolDef;
typedef virStorageVolDef *virStorageVolDefPtr;
struct _virStorageVolDef {
    char *name;
    char *key;
    int type; /* virStorageVolType */

    bool building;
    unsigned int in_use;

    virStorageVolSource source;
    virStorageSource target;
};

typedef struct _virStorageVolDefList virStorageVolDefList;
typedef virStorageVolDefList *virStorageVolDefListPtr;

VIR_ENUM_DECL(virStorageVol);

typedef enum {
    VIR_STORAGE_POOL_DIR,      /* Local directory */
    VIR_STORAGE_POOL_FS,       /* Local filesystem */
    VIR_STORAGE_POOL_NETFS,    /* Networked filesystem - eg NFS, GFS, etc */
    VIR_STORAGE_POOL_LOGICAL,  /* Logical volume groups / volumes */
    VIR_STORAGE_POOL_DISK,     /* Disk partitions */
    VIR_STORAGE_POOL_ISCSI,    /* iSCSI targets */
    VIR_STORAGE_POOL_ISCSI_DIRECT, /* iSCSI targets using libiscsi */
    VIR_STORAGE_POOL_SCSI,     /* SCSI HBA */
    VIR_STORAGE_POOL_MPATH,    /* Multipath devices */
    VIR_STORAGE_POOL_RBD,      /* RADOS Block Device */
    VIR_STORAGE_POOL_SHEEPDOG, /* Sheepdog device */
    VIR_STORAGE_POOL_GLUSTER,  /* Gluster device */
    VIR_STORAGE_POOL_ZFS,      /* ZFS */
    VIR_STORAGE_POOL_VSTORAGE, /* Virtuozzo Storage */

    VIR_STORAGE_POOL_LAST,
} virStoragePoolType;

VIR_ENUM_DECL(virStoragePool);

typedef enum {
    VIR_STORAGE_DEVICE_TYPE_DISK = 0x00,
    VIR_STORAGE_DEVICE_TYPE_ROM = 0x05,

    VIR_STORAGE_DEVICE_TYPE_LAST,
} virStoragePoolDeviceType;


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
typedef enum {
    VIR_STORAGE_FREE_NONE = 0,
    VIR_STORAGE_FREE_NORMAL,
    VIR_STORAGE_FREE_LOGICAL,
    VIR_STORAGE_FREE_LAST
} virStorageFreeType;

/*
 * Available extents on the underlying storage
 */
typedef struct _virStoragePoolSourceDeviceExtent virStoragePoolSourceDeviceExtent;
typedef virStoragePoolSourceDeviceExtent *virStoragePoolSourceDeviceExtentPtr;
struct _virStoragePoolSourceDeviceExtent {
    unsigned long long start;
    unsigned long long end;
    int type; /* virStorageFreeType */
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
    int part_separator;  /* enum virTristateSwitch */

    /* When the source device is a physical disk,
     * the geometry data is needed
     */
    struct _geometry {
        int cylinders;
        int heads;
        int sectors;
    } geometry;
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
    virStorageAdapter adapter;

    /* Or a name */
    char *name;

    /* Initiator IQN */
    virStorageSourceInitiatorDef initiator;

    /* Authentication information */
    virStorageAuthDefPtr auth;

    /* Vendor of the source */
    char *vendor;

    /* Product name of the source*/
    char *product;

    /* Pool type specific format such as filesystem type,
     * or lvm version, etc.
     */
    int format;

    /* Protocol version value for netfs */
    unsigned int protocolVer;
};

typedef struct _virStoragePoolTarget virStoragePoolTarget;
typedef virStoragePoolTarget *virStoragePoolTargetPtr;
struct _virStoragePoolTarget {
    char *path; /* Optional local filesystem mapping */
    virStoragePerms perms; /* Default permissions for volumes */
};


typedef struct _virStorageVolDefRefresh virStorageVolDefRefresh;
typedef virStorageVolDefRefresh *virStorageVolDefRefreshPtr;
struct _virStorageVolDefRefresh {
  int allocation; /* virStorageVolDefRefreshAllocation */
};


typedef struct _virStoragePoolDefRefresh virStoragePoolDefRefresh;
typedef virStoragePoolDefRefresh *virStoragePoolDefRefreshPtr;
struct _virStoragePoolDefRefresh {
  virStorageVolDefRefresh volume;
};


typedef struct _virStoragePoolDef virStoragePoolDef;
typedef virStoragePoolDef *virStoragePoolDefPtr;
struct _virStoragePoolDef {
    char *name;
    unsigned char uuid[VIR_UUID_BUFLEN];
    int type; /* virStoragePoolType */

    virStoragePoolDefRefreshPtr refresh;

    unsigned long long allocation; /* bytes */
    unsigned long long capacity; /* bytes */
    unsigned long long available; /* bytes */

    virStoragePoolSource source;
    virStoragePoolTarget target;

    /* Pool backend specific XML namespace data */
    void *namespaceData;
    virStoragePoolXMLNamespace ns;
};

typedef struct _virStoragePoolSourceList virStoragePoolSourceList;
typedef virStoragePoolSourceList *virStoragePoolSourceListPtr;
struct _virStoragePoolSourceList {
    int type;
    unsigned int nsources;
    virStoragePoolSourcePtr sources;
};

virStoragePoolDefPtr
virStoragePoolDefParseXML(xmlXPathContextPtr ctxt);

virStoragePoolDefPtr
virStoragePoolDefParseString(const char *xml);

virStoragePoolDefPtr
virStoragePoolDefParseFile(const char *filename);

virStoragePoolDefPtr
virStoragePoolDefParseNode(xmlDocPtr xml,
                           xmlNodePtr root);

char *
virStoragePoolDefFormat(virStoragePoolDefPtr def);

typedef enum {
    /* do not require volume capacity at all */
    VIR_VOL_XML_PARSE_NO_CAPACITY  = 1 << 0,
    /* do not require volume capacity if the volume has a backing store */
    VIR_VOL_XML_PARSE_OPT_CAPACITY = 1 << 1,
} virStorageVolDefParseFlags;

virStorageVolDefPtr
virStorageVolDefParseString(virStoragePoolDefPtr pool,
                            const char *xml,
                            unsigned int flags);

virStorageVolDefPtr
virStorageVolDefParseFile(virStoragePoolDefPtr pool,
                          const char *filename,
                          unsigned int flags);

virStorageVolDefPtr
virStorageVolDefParseNode(virStoragePoolDefPtr pool,
                          xmlDocPtr xml,
                          xmlNodePtr root,
                          unsigned int flags);

char *
virStorageVolDefFormat(virStoragePoolDefPtr pool,
                       virStorageVolDefPtr def);

int
virStoragePoolSaveState(const char *stateFile,
                        virStoragePoolDefPtr def);

int
virStoragePoolSaveConfig(const char *configFile,
                         virStoragePoolDefPtr def);

void
virStorageVolDefFree(virStorageVolDefPtr def);

void
virStoragePoolSourceClear(virStoragePoolSourcePtr source);

void
virStoragePoolSourceDeviceClear(virStoragePoolSourceDevicePtr dev);

void
virStoragePoolSourceFree(virStoragePoolSourcePtr source);

void
virStoragePoolDefFree(virStoragePoolDefPtr def);

virStoragePoolSourcePtr
virStoragePoolDefParseSourceString(const char *srcSpec,
                                   int pool_type);

virStoragePoolSourcePtr
virStoragePoolSourceListNewSource(virStoragePoolSourceListPtr list);

char *
virStoragePoolSourceListFormat(virStoragePoolSourceListPtr def);

typedef enum {
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
} virStoragePoolFormatFileSystem;
VIR_ENUM_DECL(virStoragePoolFormatFileSystem);

typedef enum {
    VIR_STORAGE_POOL_NETFS_AUTO = 0,
    VIR_STORAGE_POOL_NETFS_NFS,
    VIR_STORAGE_POOL_NETFS_GLUSTERFS,
    VIR_STORAGE_POOL_NETFS_CIFS,
    VIR_STORAGE_POOL_NETFS_LAST,
} virStoragePoolFormatFileSystemNet;
VIR_ENUM_DECL(virStoragePoolFormatFileSystemNet);

typedef enum {
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
} virStoragePoolFormatDisk;
VIR_ENUM_DECL(virStoragePoolFormatDisk);

typedef enum {
    VIR_STORAGE_POOL_LOGICAL_UNKNOWN = 0,
    VIR_STORAGE_POOL_LOGICAL_LVM2 = 1,
    VIR_STORAGE_POOL_LOGICAL_LAST,
} virStoragePoolFormatLogical;
VIR_ENUM_DECL(virStoragePoolFormatLogical);

/*
 * XXX: these are basically partition types.
 *
 * fdisk has a bazillion partition ID types parted has
 * practically none, and splits the * info across 3
 * different attributes.
 *
 * So this is a semi-generic set
 */
typedef enum {
    VIR_STORAGE_VOL_DISK_NONE = 0,
    VIR_STORAGE_VOL_DISK_LINUX,
    VIR_STORAGE_VOL_DISK_FAT16,
    VIR_STORAGE_VOL_DISK_FAT32,
    VIR_STORAGE_VOL_DISK_LINUX_SWAP,
    VIR_STORAGE_VOL_DISK_LINUX_LVM,
    VIR_STORAGE_VOL_DISK_LINUX_RAID,
    VIR_STORAGE_VOL_DISK_EXTENDED,
    VIR_STORAGE_VOL_DISK_LAST,
} virStorageVolFormatDisk;
VIR_ENUM_DECL(virStorageVolFormatDisk);

typedef enum {
    VIR_STORAGE_VOL_DISK_TYPE_NONE = 0,
    VIR_STORAGE_VOL_DISK_TYPE_PRIMARY,
    VIR_STORAGE_VOL_DISK_TYPE_LOGICAL,
    VIR_STORAGE_VOL_DISK_TYPE_EXTENDED,
    VIR_STORAGE_VOL_DISK_TYPE_LAST,
} virStorageVolTypeDisk;

/*
 * Mapping of Parted fs-types MUST be kept in the
 * same order as virStorageVolFormatDisk
 */
typedef enum {
    VIR_STORAGE_PARTED_FS_TYPE_NONE = 0,
    VIR_STORAGE_PARTED_FS_TYPE_LINUX,
    VIR_STORAGE_PARTED_FS_TYPE_FAT16,
    VIR_STORAGE_PARTED_FS_TYPE_FAT32,
    VIR_STORAGE_PARTED_FS_TYPE_LINUX_SWAP,
    VIR_STORAGE_PARTED_FS_TYPE_LINUX_LVM,
    VIR_STORAGE_PARTED_FS_TYPE_LINUX_RAID,
    VIR_STORAGE_PARTED_FS_TYPE_EXTENDED,
    VIR_STORAGE_PARTED_FS_TYPE_LAST,
} virStoragePartedFsType;
VIR_ENUM_DECL(virStoragePartedFs);

# define VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ACTIVE \
                (VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE)

# define VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_PERSISTENT \
                (VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_TRANSIENT)

# define VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_AUTOSTART \
                (VIR_CONNECT_LIST_STORAGE_POOLS_AUTOSTART | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_NO_AUTOSTART)

# define VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_POOL_TYPE \
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
                 VIR_CONNECT_LIST_STORAGE_POOLS_GLUSTER  | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_ZFS      | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_VSTORAGE)

# define VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ALL \
                (VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_ACTIVE     | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_PERSISTENT | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_AUTOSTART  | \
                 VIR_CONNECT_LIST_STORAGE_POOLS_FILTERS_POOL_TYPE)

VIR_DEFINE_AUTOPTR_FUNC(virStoragePoolSource, virStoragePoolSourceFree);
VIR_DEFINE_AUTOPTR_FUNC(virStoragePoolDef, virStoragePoolDefFree);
VIR_DEFINE_AUTOPTR_FUNC(virStorageVolDef, virStorageVolDefFree);

#endif /* LIBVIRT_STORAGE_CONF_H */
