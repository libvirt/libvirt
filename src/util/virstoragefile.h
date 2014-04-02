/*
 * virstoragefile.h: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2009, 2012-2014 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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

#ifndef __VIR_STORAGE_FILE_H__
# define __VIR_STORAGE_FILE_H__

# include "virbitmap.h"
# include "virseclabel.h"
# include "virstorageencryption.h"
# include "virutil.h"

/* Minimum header size required to probe all known formats with
 * virStorageFileProbeFormat, or obtain metadata from a known format.
 * Rounded to multiple of 512 (ISO has a 5-byte magic at offset
 * 32769).  Some formats can be probed with fewer bytes.  Although
 * some formats theoretically permit metadata that can rely on offsets
 * beyond this size, in practice that doesn't matter.  */
# define VIR_STORAGE_MAX_HEADER 0x8200


/* Types of disk backends (host resource).  Comparable to the public
 * virStorageVolType, except we have an undetermined state, don't have
 * a netdir type, and add a volume type for reference through a
 * storage pool.  */
enum virStorageType {
    VIR_STORAGE_TYPE_NONE,
    VIR_STORAGE_TYPE_FILE,
    VIR_STORAGE_TYPE_BLOCK,
    VIR_STORAGE_TYPE_DIR,
    VIR_STORAGE_TYPE_NETWORK,
    VIR_STORAGE_TYPE_VOLUME,

    VIR_STORAGE_TYPE_LAST
};

VIR_ENUM_DECL(virStorage)


enum virStorageFileFormat {
    VIR_STORAGE_FILE_AUTO_SAFE = -2,
    VIR_STORAGE_FILE_AUTO = -1,
    VIR_STORAGE_FILE_NONE = 0,
    VIR_STORAGE_FILE_RAW,
    VIR_STORAGE_FILE_DIR,
    VIR_STORAGE_FILE_BOCHS,
    VIR_STORAGE_FILE_CLOOP,
    VIR_STORAGE_FILE_COW,
    VIR_STORAGE_FILE_DMG,
    VIR_STORAGE_FILE_ISO,
    VIR_STORAGE_FILE_QCOW,
    VIR_STORAGE_FILE_QCOW2,
    VIR_STORAGE_FILE_QED,
    VIR_STORAGE_FILE_VMDK,
    VIR_STORAGE_FILE_VPC,
    VIR_STORAGE_FILE_FAT,
    VIR_STORAGE_FILE_VHD,
    VIR_STORAGE_FILE_VDI,

    VIR_STORAGE_FILE_LAST,
};

VIR_ENUM_DECL(virStorageFileFormat);

enum virStorageFileFeature {
    VIR_STORAGE_FILE_FEATURE_LAZY_REFCOUNTS = 0,

    VIR_STORAGE_FILE_FEATURE_LAST
};

VIR_ENUM_DECL(virStorageFileFeature);

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
    struct timespec btime; /* birth time unknown if btime.tv_nsec == -1 */
    struct timespec ctime;
    struct timespec mtime;
};


typedef struct _virStorageFileMetadata virStorageFileMetadata;
typedef virStorageFileMetadata *virStorageFileMetadataPtr;
struct _virStorageFileMetadata {
    char *backingStore; /* Canonical name (absolute file, or protocol) */
    char *backingStoreRaw; /* If file, original name, possibly relative */
    char *directory; /* The directory containing basename of backingStoreRaw */
    int backingStoreFormat; /* enum virStorageFileFormat */
    bool backingStoreIsFile;
    virStorageFileMetadataPtr backingMeta;

    virStorageEncryptionPtr encryption;
    unsigned long long capacity;
    virBitmapPtr features; /* bits described by enum virStorageFileFeature */
    char *compat;
};


/* Information related to network storage */
enum virStorageNetProtocol {
    VIR_STORAGE_NET_PROTOCOL_NBD,
    VIR_STORAGE_NET_PROTOCOL_RBD,
    VIR_STORAGE_NET_PROTOCOL_SHEEPDOG,
    VIR_STORAGE_NET_PROTOCOL_GLUSTER,
    VIR_STORAGE_NET_PROTOCOL_ISCSI,
    VIR_STORAGE_NET_PROTOCOL_HTTP,
    VIR_STORAGE_NET_PROTOCOL_HTTPS,
    VIR_STORAGE_NET_PROTOCOL_FTP,
    VIR_STORAGE_NET_PROTOCOL_FTPS,
    VIR_STORAGE_NET_PROTOCOL_TFTP,

    VIR_STORAGE_NET_PROTOCOL_LAST
};

VIR_ENUM_DECL(virStorageNetProtocol)


enum virStorageNetHostTransport {
    VIR_STORAGE_NET_HOST_TRANS_TCP,
    VIR_STORAGE_NET_HOST_TRANS_UNIX,
    VIR_STORAGE_NET_HOST_TRANS_RDMA,

    VIR_STORAGE_NET_HOST_TRANS_LAST
};

VIR_ENUM_DECL(virStorageNetHostTransport)

typedef struct _virStorageNetHostDef virStorageNetHostDef;
typedef virStorageNetHostDef *virStorageNetHostDefPtr;
struct _virStorageNetHostDef {
    char *name;
    char *port;
    int transport; /* enum virStorageNetHostTransport */
    char *socket;  /* path to unix socket */
};

/* Information for a storage volume from a virStoragePool */

/*
 * Used for volume "type" disk to indicate how to represent
 * the disk source if the specified "pool" is of iscsi type.
 */
enum virStorageSourcePoolMode {
    VIR_STORAGE_SOURCE_POOL_MODE_DEFAULT = 0,

    /* Use the path as it shows up on host, e.g.
     * /dev/disk/by-path/ip-$ip-iscsi-$iqn:iscsi.iscsi-pool0-lun-1
     */
    VIR_STORAGE_SOURCE_POOL_MODE_HOST,

    /* Use the URI from the storage pool source element host attribute. E.g.
     * file=iscsi://demo.org:6000/iqn.1992-01.com.example/1.
     */
    VIR_STORAGE_SOURCE_POOL_MODE_DIRECT,

    VIR_STORAGE_SOURCE_POOL_MODE_LAST
};

VIR_ENUM_DECL(virStorageSourcePoolMode)

typedef struct _virStorageSourcePoolDef virStorageSourcePoolDef;
struct _virStorageSourcePoolDef {
    char *pool; /* pool name */
    char *volume; /* volume name */
    int voltype; /* enum virStorageVolType, internal only */
    int pooltype; /* enum virStoragePoolType, internal only */
    int actualtype; /* enum virStorageType, internal only */
    int mode; /* enum virStorageSourcePoolMode */
};
typedef virStorageSourcePoolDef *virStorageSourcePoolDefPtr;


enum virStorageSecretType {
    VIR_STORAGE_SECRET_TYPE_NONE,
    VIR_STORAGE_SECRET_TYPE_UUID,
    VIR_STORAGE_SECRET_TYPE_USAGE,

    VIR_STORAGE_SECRET_TYPE_LAST
};


typedef struct _virStorageSource virStorageSource;
typedef virStorageSource *virStorageSourcePtr;

/* Stores information related to a host resource.  In the case of
 * backing chains, multiple source disks join to form a single guest
 * view.  */
struct _virStorageSource {
    int type; /* enum virStorageType */
    char *path;
    int protocol; /* enum virStorageNetProtocol */
    size_t nhosts;
    virStorageNetHostDefPtr hosts;
    virStorageSourcePoolDefPtr srcpool;
    struct {
        char *username;
        int secretType; /* enum virStorageSecretType */
        union {
            unsigned char uuid[VIR_UUID_BUFLEN];
            char *usage;
        } secret;
    } auth;
    virStorageEncryptionPtr encryption;

    char *driverName;
    int format; /* enum virStorageFileFormat */
    virBitmapPtr features;
    char *compat;

    virStoragePermsPtr perms;
    virStorageTimestampsPtr timestamps;
    unsigned long long allocation; /* in bytes, 0 if unknown */
    unsigned long long capacity; /* in bytes, 0 if unknown */
    size_t nseclabels;
    virSecurityDeviceLabelDefPtr *seclabels;
};


# ifndef DEV_BSIZE
#  define DEV_BSIZE 512
# endif

int virStorageFileProbeFormat(const char *path, uid_t uid, gid_t gid);
int virStorageFileProbeFormatFromBuf(const char *path, char *buf,
                                     size_t buflen);

virStorageFileMetadataPtr virStorageFileGetMetadata(const char *path,
                                                    int format,
                                                    uid_t uid, gid_t gid,
                                                    bool allow_probe);
virStorageFileMetadataPtr virStorageFileGetMetadataFromFD(const char *path,
                                                          int fd,
                                                          int format);
virStorageFileMetadataPtr virStorageFileGetMetadataFromBuf(const char *path,
                                                           char *buf,
                                                           size_t len,
                                                           int format);
int virStorageFileChainGetBroken(virStorageFileMetadataPtr chain,
                                 char **broken_file);

const char *virStorageFileChainLookup(virStorageFileMetadataPtr chain,
                                      const char *start,
                                      const char *name,
                                      virStorageFileMetadataPtr *meta,
                                      const char **parent)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virStorageFileFreeMetadata(virStorageFileMetadataPtr meta);

int virStorageFileResize(const char *path,
                         unsigned long long capacity,
                         unsigned long long orig_capacity,
                         bool pre_allocate);

int virStorageFileIsClusterFS(const char *path);

int virStorageFileGetLVMKey(const char *path,
                            char **key);
int virStorageFileGetSCSIKey(const char *path,
                             char **key);

void virStorageNetHostDefClear(virStorageNetHostDefPtr def);
void virStorageNetHostDefFree(size_t nhosts, virStorageNetHostDefPtr hosts);
virStorageNetHostDefPtr virStorageNetHostDefCopy(size_t nhosts,
                                                 virStorageNetHostDefPtr hosts);

void virStorageSourceAuthClear(virStorageSourcePtr def);
void virStorageSourcePoolDefFree(virStorageSourcePoolDefPtr def);
void virStorageSourceClear(virStorageSourcePtr def);

#endif /* __VIR_STORAGE_FILE_H__ */
