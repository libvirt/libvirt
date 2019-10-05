/*
 * virstoragefile.h: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2009, 2012-2016 Red Hat, Inc.
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
 */

#pragma once

#include <sys/stat.h>

#include "virbitmap.h"
#include "virobject.h"
#include "virseclabel.h"
#include "virstorageencryption.h"
#include "virutil.h"
#include "virsecret.h"
#include "virautoclean.h"
#include "virenum.h"

/* Minimum header size required to probe all known formats with
 * virStorageFileProbeFormat, or obtain metadata from a known format.
 * Rounded to multiple of 512 (ISO has a 5-byte magic at offset
 * 32769).  Some formats can be probed with fewer bytes.  Although
 * some formats theoretically permit metadata that can rely on offsets
 * beyond this size, in practice that doesn't matter.  */
#define VIR_STORAGE_MAX_HEADER 0x8200


/* Types of disk backends (host resource).  Comparable to the public
 * virStorageVolType, except we have an undetermined state, don't have
 * a netdir type, and add a volume type for reference through a
 * storage pool.  */
typedef enum {
    VIR_STORAGE_TYPE_NONE,
    VIR_STORAGE_TYPE_FILE,
    VIR_STORAGE_TYPE_BLOCK,
    VIR_STORAGE_TYPE_DIR,
    VIR_STORAGE_TYPE_NETWORK,
    VIR_STORAGE_TYPE_VOLUME,

    VIR_STORAGE_TYPE_LAST
} virStorageType;

VIR_ENUM_DECL(virStorage);


typedef enum {
    VIR_STORAGE_FILE_AUTO_SAFE = -2,
    VIR_STORAGE_FILE_AUTO = -1,
    VIR_STORAGE_FILE_NONE = 0,
    VIR_STORAGE_FILE_RAW,
    VIR_STORAGE_FILE_DIR,
    VIR_STORAGE_FILE_BOCHS,
    VIR_STORAGE_FILE_CLOOP,
    VIR_STORAGE_FILE_DMG,
    VIR_STORAGE_FILE_ISO,
    VIR_STORAGE_FILE_VPC,
    VIR_STORAGE_FILE_VDI,

    /* Not direct file formats, but used for various drivers */
    VIR_STORAGE_FILE_FAT,
    VIR_STORAGE_FILE_VHD,
    VIR_STORAGE_FILE_PLOOP,

    /* Not a format, but a marker: all formats below this point have
     * libvirt support for following a backing chain */
    VIR_STORAGE_FILE_BACKING,

    VIR_STORAGE_FILE_COW = VIR_STORAGE_FILE_BACKING,
    VIR_STORAGE_FILE_QCOW,
    VIR_STORAGE_FILE_QCOW2,
    VIR_STORAGE_FILE_QED,
    VIR_STORAGE_FILE_VMDK,

    VIR_STORAGE_FILE_LAST,
} virStorageFileFormat;

VIR_ENUM_DECL(virStorageFileFormat);

typedef enum {
    VIR_STORAGE_FILE_FEATURE_LAZY_REFCOUNTS = 0,

    VIR_STORAGE_FILE_FEATURE_LAST
} virStorageFileFeature;

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


/* Information related to network storage */
typedef enum {
    VIR_STORAGE_NET_PROTOCOL_NONE,
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
    VIR_STORAGE_NET_PROTOCOL_SSH,
    VIR_STORAGE_NET_PROTOCOL_VXHS,

    VIR_STORAGE_NET_PROTOCOL_LAST
} virStorageNetProtocol;

VIR_ENUM_DECL(virStorageNetProtocol);


typedef enum {
    VIR_STORAGE_NET_HOST_TRANS_TCP,
    VIR_STORAGE_NET_HOST_TRANS_UNIX,
    VIR_STORAGE_NET_HOST_TRANS_RDMA,

    VIR_STORAGE_NET_HOST_TRANS_LAST
} virStorageNetHostTransport;

VIR_ENUM_DECL(virStorageNetHostTransport);

typedef struct _virStorageNetHostDef virStorageNetHostDef;
typedef virStorageNetHostDef *virStorageNetHostDefPtr;
struct _virStorageNetHostDef {
    char *name;
    unsigned int port;
    int transport; /* virStorageNetHostTransport */
    char *socket;  /* path to unix socket */
};

/* Information for a storage volume from a virStoragePool */

/*
 * Used for volume "type" disk to indicate how to represent
 * the disk source if the specified "pool" is of iscsi type.
 */
typedef enum {
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
} virStorageSourcePoolMode;

VIR_ENUM_DECL(virStorageSourcePoolMode);

typedef struct _virStorageSourcePoolDef virStorageSourcePoolDef;
struct _virStorageSourcePoolDef {
    char *pool; /* pool name */
    char *volume; /* volume name */
    int voltype; /* virStorageVolType, internal only */
    int pooltype; /* virStoragePoolType from storage_conf.h, internal only */
    int actualtype; /* virStorageType, internal only */
    int mode; /* virStorageSourcePoolMode, currently makes sense only for iscsi pool */
};
typedef virStorageSourcePoolDef *virStorageSourcePoolDefPtr;


typedef enum {
    VIR_STORAGE_AUTH_TYPE_NONE,
    VIR_STORAGE_AUTH_TYPE_CHAP,
    VIR_STORAGE_AUTH_TYPE_CEPHX,

    VIR_STORAGE_AUTH_TYPE_LAST,
} virStorageAuthType;
VIR_ENUM_DECL(virStorageAuth);

typedef struct _virStorageAuthDef virStorageAuthDef;
typedef virStorageAuthDef *virStorageAuthDefPtr;
struct _virStorageAuthDef {
    char *username;
    char *secrettype; /* <secret type='%s' for disk source */
    int authType;     /* virStorageAuthType */
    virSecretLookupTypeDef seclookupdef;
};

typedef struct _virStoragePRDef virStoragePRDef;
typedef virStoragePRDef *virStoragePRDefPtr;
struct _virStoragePRDef {
    int managed; /* enum virTristateBool */
    char *path;

    /* manager object alias */
    char *mgralias;
};

typedef struct _virStorageSourceInitiatorDef virStorageSourceInitiatorDef;
typedef virStorageSourceInitiatorDef *virStorageSourceInitiatorDefPtr;
struct _virStorageSourceInitiatorDef {
    char *iqn; /* Initiator IQN */
};

typedef struct _virStorageDriverData virStorageDriverData;
typedef virStorageDriverData *virStorageDriverDataPtr;

typedef struct _virStorageSource virStorageSource;
typedef virStorageSource *virStorageSourcePtr;

/* Stores information related to a host resource.  In the case of backing
 * chains, multiple source disks join to form a single guest view.
 *
 * IMPORTANT: When adding fields to this struct it's also necessary to add
 * appropriate code to the virStorageSourceCopy deep copy function */
struct _virStorageSource {
    virObject parent;

    unsigned int id; /* backing chain identifier, 0 is unset */
    int type; /* virStorageType */
    char *path;
    int protocol; /* virStorageNetProtocol */
    char *volume; /* volume name for remote storage */
    char *snapshot; /* for storage systems supporting internal snapshots */
    char *configFile; /* some storage systems use config file as part of
                         the source definition */
    size_t nhosts;
    virStorageNetHostDefPtr hosts;
    virStorageSourcePoolDefPtr srcpool;
    virStorageAuthDefPtr auth;
    bool authInherited;
    virStorageEncryptionPtr encryption;
    bool encryptionInherited;
    virStoragePRDefPtr pr;

    virStorageSourceInitiatorDef initiator;

    virObjectPtr privateData;

    int format; /* virStorageFileFormat in domain backing chains, but
                 * pool-specific enum for storage volumes */
    virBitmapPtr features;
    char *compat;
    bool nocow;
    bool sparse;

    virStoragePermsPtr perms;
    virStorageTimestampsPtr timestamps;
    unsigned long long capacity; /* in bytes, 0 if unknown */
    unsigned long long allocation; /* in bytes, 0 if unknown */
    unsigned long long physical; /* in bytes, 0 if unknown */
    bool has_allocation; /* Set to true when provided in XML */

    size_t nseclabels;
    virSecurityDeviceLabelDefPtr *seclabels;

    /* Don't ever write to the image */
    bool readonly;

    /* image is shared across hosts */
    bool shared;

    /* backing chain of the storage source */
    virStorageSourcePtr backingStore;

    /* metadata for storage driver access to remote and local volumes */
    virStorageDriverDataPtr drv;

    /* metadata about storage image which need separate fields */
    /* Relative name by which this image was opened from its parent, or NULL
     * if this image was opened by absolute name */
    char *relPath;
    /* Name of the child backing store recorded in metadata of the
     * current file.  */
    char *backingStoreRaw;

    /* metadata that allows identifying given storage source */
    char *nodeformat;  /* name of the format handler object */
    char *nodestorage; /* name of the storage object */

    /* An optional setting to enable usage of TLS for the storage source */
    int haveTLS; /* enum virTristateBool */

    /* Indication whether the haveTLS value was altered due to qemu.conf
     * setting when haveTLS is missing from the domain config file */
    bool tlsFromConfig;

    /* If TLS is used, then mgmt of the TLS credentials occurs via an
     * object that is generated using a specific alias for a specific
     * certificate directory with listen and verify bools. */
    char *tlsAlias;
    char *tlsCertdir;

    bool detected; /* true if this entry was not provided by the user */

    unsigned int debugLevel;
    bool debug;

    /* Libvirt currently stores the following properties in virDomainDiskDef.
     * These instances are currently just copies from the parent definition and
     * are not mapped back to the XML */
    int iomode; /* enum virDomainDiskIo */
    int cachemode; /* enum virDomainDiskCache */
    int discard; /* enum virDomainDiskDiscard */
    int detect_zeroes; /* enum virDomainDiskDetectZeroes */

    bool floppyimg; /* set to true if the storage source is going to be used
                       as a source for floppy drive */

    bool hostcdrom; /* backing device is a cdrom */
};


#ifndef DEV_BSIZE
# define DEV_BSIZE 512
#endif

int virStorageFileProbeFormat(const char *path, uid_t uid, gid_t gid);

virStorageSourcePtr virStorageFileGetMetadataFromFD(const char *path,
                                                    int fd,
                                                    int format,
                                                    int *backingFormat);
virStorageSourcePtr virStorageFileGetMetadataFromBuf(const char *path,
                                                     char *buf,
                                                     size_t len,
                                                     int format,
                                                     int *backingFormat)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int virStorageFileChainGetBroken(virStorageSourcePtr chain,
                                 char **broken_file);

int virStorageFileParseChainIndex(const char *diskTarget,
                                  const char *name,
                                  unsigned int *chainIndex)
    ATTRIBUTE_NONNULL(3);

int virStorageFileParseBackingStoreStr(const char *str,
                                       char **target,
                                       unsigned int *chainIndex)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);

virStorageSourcePtr virStorageFileChainLookup(virStorageSourcePtr chain,
                                              virStorageSourcePtr startFrom,
                                              const char *name,
                                              unsigned int idx,
                                              virStorageSourcePtr *parent)
    ATTRIBUTE_NONNULL(1);

int virStorageFileResize(const char *path,
                         unsigned long long capacity,
                         bool pre_allocate);

int virStorageFileIsClusterFS(const char *path);
bool virStorageIsFile(const char *path);
bool virStorageIsRelative(const char *backing);

int virStorageFileGetLVMKey(const char *path,
                            char **key);
int virStorageFileGetSCSIKey(const char *path,
                             char **key,
                             bool ignoreError);
int virStorageFileGetNPIVKey(const char *path,
                             char **key);

void virStorageAuthDefFree(virStorageAuthDefPtr def);
virStorageAuthDefPtr virStorageAuthDefCopy(const virStorageAuthDef *src);
virStorageAuthDefPtr virStorageAuthDefParse(xmlNodePtr node,
                                            xmlXPathContextPtr ctxt);
void virStorageAuthDefFormat(virBufferPtr buf, virStorageAuthDefPtr authdef);

void virStoragePRDefFree(virStoragePRDefPtr prd);
virStoragePRDefPtr virStoragePRDefParseXML(xmlXPathContextPtr ctxt);
void virStoragePRDefFormat(virBufferPtr buf,
                           virStoragePRDefPtr prd,
                           bool migratable);
bool virStoragePRDefIsEqual(virStoragePRDefPtr a,
                            virStoragePRDefPtr b);
bool virStoragePRDefIsManaged(virStoragePRDefPtr prd);

bool
virStorageSourceChainHasManagedPR(virStorageSourcePtr src);

virSecurityDeviceLabelDefPtr
virStorageSourceGetSecurityLabelDef(virStorageSourcePtr src,
                                    const char *model);

void virStorageNetHostDefClear(virStorageNetHostDefPtr def);
void virStorageNetHostDefFree(size_t nhosts, virStorageNetHostDefPtr hosts);
virStorageNetHostDefPtr virStorageNetHostDefCopy(size_t nhosts,
                                                 virStorageNetHostDefPtr hosts);

int virStorageSourceInitChainElement(virStorageSourcePtr newelem,
                                     virStorageSourcePtr old,
                                     bool force);
void virStorageSourcePoolDefFree(virStorageSourcePoolDefPtr def);
void virStorageSourceClear(virStorageSourcePtr def);
int virStorageSourceGetActualType(const virStorageSource *def);
bool virStorageSourceIsLocalStorage(const virStorageSource *src);
bool virStorageSourceIsEmpty(virStorageSourcePtr src);
bool virStorageSourceIsBlockLocal(const virStorageSource *src);
virStorageSourcePtr virStorageSourceNew(void);
void virStorageSourceBackingStoreClear(virStorageSourcePtr def);
int virStorageSourceUpdatePhysicalSize(virStorageSourcePtr src,
                                       int fd, struct stat const *sb);
int virStorageSourceUpdateBackingSizes(virStorageSourcePtr src,
                                       int fd, struct stat const *sb);
int virStorageSourceUpdateCapacity(virStorageSourcePtr src,
                                   char *buf, ssize_t len,
                                   bool probe);

int virStorageSourceNewFromBacking(virStorageSourcePtr parent,
                                   virStorageSourcePtr *backing);

virStorageSourcePtr virStorageSourceCopy(const virStorageSource *src,
                                         bool backingChain)
    ATTRIBUTE_NONNULL(1);
bool virStorageSourceIsSameLocation(virStorageSourcePtr a,
                                    virStorageSourcePtr b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virStorageSourceParseRBDColonString(const char *rbdstr,
                                        virStorageSourcePtr src)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

typedef int
(*virStorageFileSimplifyPathReadlinkCallback)(const char *path,
                                              char **link,
                                              void *data);
char *virStorageFileCanonicalizePath(const char *path,
                                     virStorageFileSimplifyPathReadlinkCallback cb,
                                     void *cbdata);

int virStorageFileGetRelativeBackingPath(virStorageSourcePtr from,
                                         virStorageSourcePtr to,
                                         char **relpath)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int virStorageFileCheckCompat(const char *compat);

int virStorageSourceNewFromBackingAbsolute(const char *path,
                                           virStorageSourcePtr *src);

bool virStorageSourceIsRelative(virStorageSourcePtr src);

virStorageSourcePtr
virStorageSourceFindByNodeName(virStorageSourcePtr top,
                               const char *nodeName,
                               unsigned int *index)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void
virStorageSourceNetworkAssignDefaultPorts(virStorageSourcePtr src)
    ATTRIBUTE_NONNULL(1);

bool
virStorageSourceIsBacking(const virStorageSource *src);
bool
virStorageSourceHasBacking(const virStorageSource *src);


int
virStorageSourcePrivateDataParseRelPath(xmlXPathContextPtr ctxt,
                                        virStorageSourcePtr src);
int
virStorageSourcePrivateDataFormatRelPath(virStorageSourcePtr src,
                                         virBufferPtr buf);

void
virStorageSourceInitiatorParseXML(xmlXPathContextPtr ctxt,
                                  virStorageSourceInitiatorDefPtr initiator);

void
virStorageSourceInitiatorFormatXML(virStorageSourceInitiatorDefPtr initiator,
                                   virBufferPtr buf);

int
virStorageSourceInitiatorCopy(virStorageSourceInitiatorDefPtr dest,
                              const virStorageSourceInitiatorDef *src);

void
virStorageSourceInitiatorClear(virStorageSourceInitiatorDefPtr initiator);

int virStorageFileInit(virStorageSourcePtr src);
int virStorageFileInitAs(virStorageSourcePtr src,
                         uid_t uid, gid_t gid);
void virStorageFileDeinit(virStorageSourcePtr src);

int virStorageFileCreate(virStorageSourcePtr src);
int virStorageFileUnlink(virStorageSourcePtr src);
int virStorageFileStat(virStorageSourcePtr src,
                       struct stat *stat);
ssize_t virStorageFileRead(virStorageSourcePtr src,
                           size_t offset,
                           size_t len,
                           char **buf);
const char *virStorageFileGetUniqueIdentifier(virStorageSourcePtr src);
int virStorageFileAccess(virStorageSourcePtr src, int mode);
int virStorageFileChown(const virStorageSource *src, uid_t uid, gid_t gid);

int virStorageFileSupportsSecurityDriver(const virStorageSource *src);
int virStorageFileSupportsAccess(const virStorageSource *src);
int virStorageFileSupportsCreate(const virStorageSource *src);
int virStorageFileSupportsBackingChainTraversal(const virStorageSource *src);

int virStorageFileGetMetadata(virStorageSourcePtr src,
                              uid_t uid, gid_t gid,
                              bool report_broken)
    ATTRIBUTE_NONNULL(1);

int virStorageFileGetBackingStoreStr(virStorageSourcePtr src,
                                     char **backing)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virStorageFileReportBrokenChain(int errcode,
                                     virStorageSourcePtr src,
                                     virStorageSourcePtr parent);

VIR_DEFINE_AUTOPTR_FUNC(virStorageAuthDef, virStorageAuthDefFree);
