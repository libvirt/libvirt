/*
 * libvirt-storage.h
 * Summary: APIs for management of storage pools and volumes
 * Description: Provides APIs for the management of storage pools and volumes
 * Author: Daniel Veillard <veillard@redhat.com>
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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

#ifndef __VIR_LIBVIRT_STORAGE_H__
# define __VIR_LIBVIRT_STORAGE_H__

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif


/**
 * virStoragePool:
 *
 * a virStoragePool is a private structure representing a storage pool
 */
typedef struct _virStoragePool virStoragePool;

/**
 * virStoragePoolPtr:
 *
 * a virStoragePoolPtr is pointer to a virStoragePool private structure, this is the
 * type used to reference a storage pool in the API.
 */
typedef virStoragePool *virStoragePoolPtr;


typedef enum {
    VIR_STORAGE_POOL_INACTIVE = 0, /* Not running */
    VIR_STORAGE_POOL_BUILDING = 1, /* Initializing pool, not available */
    VIR_STORAGE_POOL_RUNNING = 2,  /* Running normally */
    VIR_STORAGE_POOL_DEGRADED = 3, /* Running degraded */
    VIR_STORAGE_POOL_INACCESSIBLE = 4, /* Running, but not accessible */

# ifdef VIR_ENUM_SENTINELS
    VIR_STORAGE_POOL_STATE_LAST
# endif
} virStoragePoolState;

typedef enum {
    VIR_STORAGE_POOL_BUILD_NEW  = 0,   /* Regular build from scratch */
    VIR_STORAGE_POOL_BUILD_REPAIR = (1 << 0), /* Repair / reinitialize */
    VIR_STORAGE_POOL_BUILD_RESIZE = (1 << 1),  /* Extend existing pool */
    VIR_STORAGE_POOL_BUILD_NO_OVERWRITE = (1 << 2),  /* Do not overwrite existing pool */
    VIR_STORAGE_POOL_BUILD_OVERWRITE = (1 << 3),  /* Overwrite data */
} virStoragePoolBuildFlags;

typedef enum {
    VIR_STORAGE_POOL_DELETE_NORMAL = 0, /* Delete metadata only    (fast) */
    VIR_STORAGE_POOL_DELETE_ZEROED = 1 << 0,  /* Clear all data to zeros (slow) */
} virStoragePoolDeleteFlags;

typedef enum {
    VIR_STORAGE_POOL_CREATE_NORMAL = 0,

    /* Create the pool and perform pool build without any flags */
    VIR_STORAGE_POOL_CREATE_WITH_BUILD = 1 << 0,

    /* Create the pool and perform pool build using the
     * VIR_STORAGE_POOL_BUILD_OVERWRITE flag. This is mutually
     * exclusive to VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE */
    VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE = 1 << 1,

    /* Create the pool and perform pool build using the
     * VIR_STORAGE_POOL_BUILD_NO_OVERWRITE flag. This is mutually
     * exclusive to VIR_STORAGE_POOL_CREATE_WITH_BUILD_OVERWRITE */
    VIR_STORAGE_POOL_CREATE_WITH_BUILD_NO_OVERWRITE = 1 << 2,
} virStoragePoolCreateFlags;

typedef struct _virStoragePoolInfo virStoragePoolInfo;

struct _virStoragePoolInfo {
    int state;                     /* virStoragePoolState flags */
    unsigned long long capacity;   /* Logical size bytes */
    unsigned long long allocation; /* Current allocation bytes */
    unsigned long long available;  /* Remaining free space bytes */
};

typedef virStoragePoolInfo *virStoragePoolInfoPtr;


/**
 * virStorageVol:
 *
 * a virStorageVol is a private structure representing a storage volume
 */
typedef struct _virStorageVol virStorageVol;

/**
 * virStorageVolPtr:
 *
 * a virStorageVolPtr is pointer to a virStorageVol private structure, this is the
 * type used to reference a storage volume in the API.
 */
typedef virStorageVol *virStorageVolPtr;


typedef enum {
    VIR_STORAGE_VOL_FILE = 0,     /* Regular file based volumes */
    VIR_STORAGE_VOL_BLOCK = 1,    /* Block based volumes */
    VIR_STORAGE_VOL_DIR = 2,      /* Directory-passthrough based volume */
    VIR_STORAGE_VOL_NETWORK = 3,  /* Network volumes like RBD (RADOS Block Device) */
    VIR_STORAGE_VOL_NETDIR = 4,   /* Network accessible directory that can
                                   * contain other network volumes */
    VIR_STORAGE_VOL_PLOOP = 5,    /* Ploop based volumes */

# ifdef VIR_ENUM_SENTINELS
    VIR_STORAGE_VOL_LAST
# endif
} virStorageVolType;

typedef enum {
    VIR_STORAGE_VOL_DELETE_NORMAL = 0, /* Delete metadata only    (fast) */
    VIR_STORAGE_VOL_DELETE_ZEROED = 1 << 0,  /* Clear all data to zeros (slow) */
    VIR_STORAGE_VOL_DELETE_WITH_SNAPSHOTS = 1 << 1, /* Force removal of volume, even if in use */
} virStorageVolDeleteFlags;

typedef enum {
    VIR_STORAGE_VOL_WIPE_ALG_ZERO = 0, /* 1-pass, all zeroes */
    VIR_STORAGE_VOL_WIPE_ALG_NNSA = 1, /* 4-pass  NNSA Policy Letter
                                          NAP-14.1-C (XVI-8) */
    VIR_STORAGE_VOL_WIPE_ALG_DOD = 2, /* 4-pass DoD 5220.22-M section
                                         8-306 procedure */
    VIR_STORAGE_VOL_WIPE_ALG_BSI = 3, /* 9-pass method recommended by the
                                         German Center of Security in
                                         Information Technologies */
    VIR_STORAGE_VOL_WIPE_ALG_GUTMANN = 4, /* The canonical 35-pass sequence */
    VIR_STORAGE_VOL_WIPE_ALG_SCHNEIER = 5, /* 7-pass method described by
                                              Bruce Schneier in "Applied
                                              Cryptography" (1996) */
    VIR_STORAGE_VOL_WIPE_ALG_PFITZNER7 = 6, /* 7-pass random */

    VIR_STORAGE_VOL_WIPE_ALG_PFITZNER33 = 7, /* 33-pass random */

    VIR_STORAGE_VOL_WIPE_ALG_RANDOM = 8, /* 1-pass random */

    VIR_STORAGE_VOL_WIPE_ALG_TRIM = 9, /* 1-pass, trim all data on the
                                          volume by using TRIM or DISCARD */

# ifdef VIR_ENUM_SENTINELS
    VIR_STORAGE_VOL_WIPE_ALG_LAST
    /*
     * NB: this enum value will increase over time as new algorithms are
     * added to the libvirt API. It reflects the last algorithm supported
     * by this version of the libvirt API.
     */
# endif
} virStorageVolWipeAlgorithm;

typedef enum {
    VIR_STORAGE_VOL_USE_ALLOCATION = 0,

    /* Return the physical size in allocation */
    VIR_STORAGE_VOL_GET_PHYSICAL = 1 << 0,

} virStorageVolInfoFlags;

typedef struct _virStorageVolInfo virStorageVolInfo;

struct _virStorageVolInfo {
    int type;                      /* virStorageVolType flags */
    unsigned long long capacity;   /* Logical size bytes */
    unsigned long long allocation; /* Current allocation bytes */
};

typedef virStorageVolInfo *virStorageVolInfoPtr;

typedef enum {
    VIR_STORAGE_XML_INACTIVE    = (1 << 0), /* dump inactive pool/volume information */
} virStorageXMLFlags;

/*
 * Get connection from pool.
 */
virConnectPtr           virStoragePoolGetConnect        (virStoragePoolPtr pool);

/*
 * List active storage pools
 */
int                     virConnectNumOfStoragePools     (virConnectPtr conn);
int                     virConnectListStoragePools      (virConnectPtr conn,
                                                         char **const names,
                                                         int maxnames);

/*
 * List inactive storage pools
 */
int                     virConnectNumOfDefinedStoragePools(virConnectPtr conn);
int                     virConnectListDefinedStoragePools(virConnectPtr conn,
                                                          char **const names,
                                                          int maxnames);

/*
 * virConnectListAllStoragePoolsFlags:
 *
 * Flags used to tune pools returned by virConnectListAllStoragePools().
 * Note that these flags come in groups; if all bits from a group are 0,
 * then that group is not used to filter results.
 */
typedef enum {
    VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE      = 1 << 0,
    VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE        = 1 << 1,

    VIR_CONNECT_LIST_STORAGE_POOLS_PERSISTENT    = 1 << 2,
    VIR_CONNECT_LIST_STORAGE_POOLS_TRANSIENT     = 1 << 3,

    VIR_CONNECT_LIST_STORAGE_POOLS_AUTOSTART     = 1 << 4,
    VIR_CONNECT_LIST_STORAGE_POOLS_NO_AUTOSTART  = 1 << 5,

    /* List pools by type */
    VIR_CONNECT_LIST_STORAGE_POOLS_DIR           = 1 << 6,
    VIR_CONNECT_LIST_STORAGE_POOLS_FS            = 1 << 7,
    VIR_CONNECT_LIST_STORAGE_POOLS_NETFS         = 1 << 8,
    VIR_CONNECT_LIST_STORAGE_POOLS_LOGICAL       = 1 << 9,
    VIR_CONNECT_LIST_STORAGE_POOLS_DISK          = 1 << 10,
    VIR_CONNECT_LIST_STORAGE_POOLS_ISCSI         = 1 << 11,
    VIR_CONNECT_LIST_STORAGE_POOLS_SCSI          = 1 << 12,
    VIR_CONNECT_LIST_STORAGE_POOLS_MPATH         = 1 << 13,
    VIR_CONNECT_LIST_STORAGE_POOLS_RBD           = 1 << 14,
    VIR_CONNECT_LIST_STORAGE_POOLS_SHEEPDOG      = 1 << 15,
    VIR_CONNECT_LIST_STORAGE_POOLS_GLUSTER       = 1 << 16,
    VIR_CONNECT_LIST_STORAGE_POOLS_ZFS           = 1 << 17,
    VIR_CONNECT_LIST_STORAGE_POOLS_VSTORAGE      = 1 << 18,
} virConnectListAllStoragePoolsFlags;

int                     virConnectListAllStoragePools(virConnectPtr conn,
                                                      virStoragePoolPtr **pools,
                                                      unsigned int flags);
/*
 * Query a host for storage pools of a particular type
 */
char *                  virConnectFindStoragePoolSources(virConnectPtr conn,
                                                         const char *type,
                                                         const char *srcSpec,
                                                         unsigned int flags);

/*
 * Lookup pool by name or uuid
 */
virStoragePoolPtr       virStoragePoolLookupByName      (virConnectPtr conn,
                                                         const char *name);
virStoragePoolPtr       virStoragePoolLookupByUUID      (virConnectPtr conn,
                                                         const unsigned char *uuid);
virStoragePoolPtr       virStoragePoolLookupByUUIDString(virConnectPtr conn,
                                                         const char *uuid);
virStoragePoolPtr       virStoragePoolLookupByVolume    (virStorageVolPtr vol);

/*
 * Creating/destroying pools
 */
virStoragePoolPtr       virStoragePoolCreateXML         (virConnectPtr conn,
                                                         const char *xmlDesc,
                                                         unsigned int flags);
virStoragePoolPtr       virStoragePoolDefineXML         (virConnectPtr conn,
                                                         const char *xmlDesc,
                                                         unsigned int flags);
int                     virStoragePoolBuild             (virStoragePoolPtr pool,
                                                         unsigned int flags);
int                     virStoragePoolUndefine          (virStoragePoolPtr pool);
int                     virStoragePoolCreate            (virStoragePoolPtr pool,
                                                         unsigned int flags);
int                     virStoragePoolDestroy           (virStoragePoolPtr pool);
int                     virStoragePoolDelete            (virStoragePoolPtr pool,
                                                         unsigned int flags);
int                     virStoragePoolRef               (virStoragePoolPtr pool);
int                     virStoragePoolFree              (virStoragePoolPtr pool);
int                     virStoragePoolRefresh           (virStoragePoolPtr pool,
                                                         unsigned int flags);

/*
 * StoragePool information
 */
const char*             virStoragePoolGetName           (virStoragePoolPtr pool);
int                     virStoragePoolGetUUID           (virStoragePoolPtr pool,
                                                         unsigned char *uuid);
int                     virStoragePoolGetUUIDString     (virStoragePoolPtr pool,
                                                         char *buf);

int                     virStoragePoolGetInfo           (virStoragePoolPtr vol,
                                                         virStoragePoolInfoPtr info);

char *                  virStoragePoolGetXMLDesc        (virStoragePoolPtr pool,
                                                         unsigned int flags);

int                     virStoragePoolGetAutostart      (virStoragePoolPtr pool,
                                                         int *autostart);
int                     virStoragePoolSetAutostart      (virStoragePoolPtr pool,
                                                         int autostart);

/*
 * List/lookup storage volumes within a pool
 */
int                     virStoragePoolNumOfVolumes      (virStoragePoolPtr pool);
int                     virStoragePoolListVolumes       (virStoragePoolPtr pool,
                                                         char **const names,
                                                         int maxnames);
int                     virStoragePoolListAllVolumes    (virStoragePoolPtr pool,
                                                         virStorageVolPtr **vols,
                                                         unsigned int flags);

virConnectPtr           virStorageVolGetConnect         (virStorageVolPtr vol);

/*
 * Lookup volumes based on various attributes
 */
virStorageVolPtr        virStorageVolLookupByName       (virStoragePoolPtr pool,
                                                         const char *name);
virStorageVolPtr        virStorageVolLookupByKey        (virConnectPtr conn,
                                                         const char *key);
virStorageVolPtr        virStorageVolLookupByPath       (virConnectPtr conn,
                                                         const char *path);


const char*             virStorageVolGetName            (virStorageVolPtr vol);
const char*             virStorageVolGetKey             (virStorageVolPtr vol);

typedef enum {
    VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA = 1 << 0,
    VIR_STORAGE_VOL_CREATE_REFLINK = 1 << 1, /* perform a btrfs lightweight copy */
} virStorageVolCreateFlags;

virStorageVolPtr        virStorageVolCreateXML          (virStoragePoolPtr pool,
                                                         const char *xmldesc,
                                                         unsigned int flags);
virStorageVolPtr        virStorageVolCreateXMLFrom      (virStoragePoolPtr pool,
                                                         const char *xmldesc,
                                                         virStorageVolPtr clonevol,
                                                         unsigned int flags);

typedef enum {
    VIR_STORAGE_VOL_DOWNLOAD_SPARSE_STREAM = 1 << 0, /* Use sparse stream */
} virStorageVolDownloadFlags;

int                     virStorageVolDownload           (virStorageVolPtr vol,
                                                         virStreamPtr stream,
                                                         unsigned long long offset,
                                                         unsigned long long length,
                                                         unsigned int flags);
typedef enum {
    VIR_STORAGE_VOL_UPLOAD_SPARSE_STREAM = 1 << 0,  /* Use sparse stream */
} virStorageVolUploadFlags;

int                     virStorageVolUpload             (virStorageVolPtr vol,
                                                         virStreamPtr stream,
                                                         unsigned long long offset,
                                                         unsigned long long length,
                                                         unsigned int flags);
int                     virStorageVolDelete             (virStorageVolPtr vol,
                                                         unsigned int flags);
int                     virStorageVolWipe               (virStorageVolPtr vol,
                                                         unsigned int flags);
int                     virStorageVolWipePattern        (virStorageVolPtr vol,
                                                         unsigned int algorithm,
                                                         unsigned int flags);
int                     virStorageVolRef                (virStorageVolPtr vol);
int                     virStorageVolFree               (virStorageVolPtr vol);

int                     virStorageVolGetInfo            (virStorageVolPtr vol,
                                                         virStorageVolInfoPtr info);
int                     virStorageVolGetInfoFlags       (virStorageVolPtr vol,
                                                         virStorageVolInfoPtr info,
                                                         unsigned int flags);
char *                  virStorageVolGetXMLDesc         (virStorageVolPtr pool,
                                                         unsigned int flags);

char *                  virStorageVolGetPath            (virStorageVolPtr vol);

typedef enum {
    VIR_STORAGE_VOL_RESIZE_ALLOCATE = 1 << 0, /* force allocation of new size */
    VIR_STORAGE_VOL_RESIZE_DELTA    = 1 << 1, /* size is relative to current */
    VIR_STORAGE_VOL_RESIZE_SHRINK   = 1 << 2, /* allow decrease in capacity */
} virStorageVolResizeFlags;

int                     virStorageVolResize             (virStorageVolPtr vol,
                                                         unsigned long long capacity,
                                                         unsigned int flags);

int virStoragePoolIsActive(virStoragePoolPtr pool);
int virStoragePoolIsPersistent(virStoragePoolPtr pool);

/**
 * VIR_STORAGE_POOL_EVENT_CALLBACK:
 *
 * Used to cast the event specific callback into the generic one
 * for use for virConnectStoragePoolEventRegisterAny()
 */
# define VIR_STORAGE_POOL_EVENT_CALLBACK(cb)((virConnectStoragePoolEventGenericCallback)(cb))

/**
 * virStoragePoolEventID:
 *
 * An enumeration of supported eventId parameters for
 * virConnectStoragePoolEventRegisterAny(). Each event id determines which
 * signature of callback function will be used.
 */
typedef enum {
    VIR_STORAGE_POOL_EVENT_ID_LIFECYCLE = 0, /* virConnectStoragePoolEventLifecycleCallback */
    VIR_STORAGE_POOL_EVENT_ID_REFRESH = 1, /* virConnectStoragePoolEventGenericCallback */

# ifdef VIR_ENUM_SENTINELS
    VIR_STORAGE_POOL_EVENT_ID_LAST
    /*
     * NB: this enum value will increase over time as new events are
     * added to the libvirt API. It reflects the last event ID supported
     * by this version of the libvirt API.
     */
# endif
} virStoragePoolEventID;

/**
 * virConnectStoragePoolEventGenericCallback:
 * @conn: the connection pointer
 * @pool: the pool pointer
 * @opaque: application specified data
 *
 * A generic storage pool event callback handler, for use with
 * virConnectStoragePoolEventRegisterAny(). Specific events usually
 * have a customization with extra parameters, often with @opaque being
 * passed in a different parameter position; use
 * VIR_STORAGE_POOL_EVENT_CALLBACK() when registering an appropriate handler.
 */
typedef void (*virConnectStoragePoolEventGenericCallback)(virConnectPtr conn,
                                                          virStoragePoolPtr pool,
                                                          void *opaque);

/* Use VIR_STORAGE_POOL_EVENT_CALLBACK() to cast the 'cb' parameter  */
int virConnectStoragePoolEventRegisterAny(virConnectPtr conn,
                                          virStoragePoolPtr pool, /* optional, to filter */
                                          int eventID,
                                          virConnectStoragePoolEventGenericCallback cb,
                                          void *opaque,
                                          virFreeCallback freecb);

int virConnectStoragePoolEventDeregisterAny(virConnectPtr conn,
                                            int callbackID);

/**
 * virStoragePoolEventLifecycleType:
 *
 * a virStoragePoolEventLifecycleType is emitted during storage pool
 * lifecycle events
 */
typedef enum {
    VIR_STORAGE_POOL_EVENT_DEFINED = 0,
    VIR_STORAGE_POOL_EVENT_UNDEFINED = 1,
    VIR_STORAGE_POOL_EVENT_STARTED = 2,
    VIR_STORAGE_POOL_EVENT_STOPPED = 3,

# ifdef VIR_ENUM_SENTINELS
    VIR_STORAGE_POOL_EVENT_LAST
# endif
} virStoragePoolEventLifecycleType;

/**
 * virConnectStoragePoolEventLifecycleCallback:
 * @conn: connection object
 * @pool: pool on which the event occurred
 * @event: The specific virStoragePoolEventLifeCycleType which occurred
 * @detail: contains some details on the reason of the event.
 * @opaque: application specified data
 *
 * This callback is called when a pool lifecycle action is performed, like start
 * or stop.
 *
 * The callback signature to use when registering for an event of type
 * VIR_STORAGE_POOL_EVENT_ID_LIFECYCLE with
 * virConnectStoragePoolEventRegisterAny()
 */
typedef void (*virConnectStoragePoolEventLifecycleCallback)(virConnectPtr conn,
                                                            virStoragePoolPtr pool,
                                                            int event,
                                                            int detail,
                                                            void *opaque);

#endif /* __VIR_LIBVIRT_STORAGE_H__ */
