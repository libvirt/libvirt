/*
 * storage_source_conf.h: file utility functions for FS storage backend
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

#include "storage_encryption_conf.h"
#include "virbitmap.h"
#include "virconftypes.h"
#include "virenum.h"
#include "virobject.h"
#include "virpci.h"
#include "virseclabel.h"
#include "virsecret.h"

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
    VIR_STORAGE_TYPE_NVME,
    VIR_STORAGE_TYPE_VHOST_USER,
    VIR_STORAGE_TYPE_VHOST_VDPA,

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
    VIR_STORAGE_FILE_FEATURE_EXTENDED_L2,

    VIR_STORAGE_FILE_FEATURE_LAST
} virStorageFileFeature;

VIR_ENUM_DECL(virStorageFileFeature);


typedef struct _virStoragePerms virStoragePerms;
struct _virStoragePerms {
    mode_t mode;
    uid_t uid;
    gid_t gid;
    char *label;
};


typedef struct _virStorageTimestamps virStorageTimestamps;
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
    VIR_STORAGE_NET_PROTOCOL_NFS,

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
struct _virStorageNetHostDef {
    char *name;
    unsigned int port;
    virStorageNetHostTransport transport;
    char *socket;  /* path to unix socket */
};


typedef struct _virStorageNetCookieDef virStorageNetCookieDef;
struct _virStorageNetCookieDef {
    char *name;
    char *value;
};


void
virStorageNetCookieDefFree(virStorageNetCookieDef *def);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virStorageNetCookieDef, virStorageNetCookieDefFree);


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
    virStorageType actualtype; /* internal only */
    virStorageSourcePoolMode mode; /* currently makes sense only for iscsi pool */
};


typedef enum {
    VIR_STORAGE_AUTH_TYPE_NONE,
    VIR_STORAGE_AUTH_TYPE_CHAP,
    VIR_STORAGE_AUTH_TYPE_CEPHX,

    VIR_STORAGE_AUTH_TYPE_LAST,
} virStorageAuthType;

VIR_ENUM_DECL(virStorageAuth);


typedef struct _virStorageAuthDef virStorageAuthDef;
struct _virStorageAuthDef {
    char *username;
    char *secrettype; /* <secret type='%s' for disk source */
    int authType;     /* virStorageAuthType */
    virSecretLookupTypeDef seclookupdef;
};


typedef struct _virStoragePRDef virStoragePRDef;
struct _virStoragePRDef {
    virTristateBool managed;
    char *path;

    /* manager object alias */
    char *mgralias;
};


typedef struct _virStorageSourceInitiatorDef virStorageSourceInitiatorDef;
struct _virStorageSourceInitiatorDef {
    char *iqn; /* Initiator IQN */
};


typedef struct _virStorageSourceNVMeDef virStorageSourceNVMeDef;
struct _virStorageSourceNVMeDef {
    unsigned long long namespc;
    virTristateBool managed;
    virPCIDeviceAddress pciAddr;

    /* Don't forget to update virStorageSourceNVMeDefCopy */
};


typedef struct _virStorageSourceSlice virStorageSourceSlice;
struct _virStorageSourceSlice {
    unsigned long long offset;
    unsigned long long size;
    char *nodename;
};


struct _virStorageSourceFDTuple {
    GObject parent;
    int *fds;
    size_t nfds;
    int *testfds; /* populated by tests to ensure stable FDs */

    bool writable;
    bool tryRestoreLabel;

    /* connection this FD tuple is associated with for auto-closing */
    virConnect *conn;

    /* original selinux label when we relabel the image */
    char *selinuxLabel;
};
G_DECLARE_FINAL_TYPE(virStorageSourceFDTuple, vir_storage_source_fd_tuple, VIR, STORAGE_SOURCE_FD_TUPLE, GObject);

virStorageSourceFDTuple *
virStorageSourceFDTupleNew(void);


typedef struct _virStorageSource virStorageSource;

/* Stores information related to a host resource.  In the case of backing
 * chains, multiple source disks join to form a single guest view.
 *
 * IMPORTANT: When adding fields to this struct it's also necessary to add
 * appropriate code to the virStorageSourceCopy deep copy function */
struct _virStorageSource {
    virObject parent;

    unsigned int id; /* backing chain identifier, 0 is unset */
    virStorageType type;
    char *path;
    char *fdgroup; /* name of group of file descriptors the user wishes to use instead of 'path' */
    int protocol; /* virStorageNetProtocol */
    char *volume; /* volume name for remote storage */
    char *snapshot; /* for storage systems supporting internal snapshots */
    char *configFile; /* some storage systems use config file as part of
                         the source definition */
    char *query; /* query string for HTTP based protocols */
    char *vdpadev;
    size_t nhosts;
    virStorageNetHostDef *hosts;
    size_t ncookies;
    virStorageNetCookieDef **cookies;
    virStorageSourcePoolDef *srcpool;
    virStorageAuthDef *auth;
    virStorageEncryption *encryption;
    virStoragePRDef *pr;
    virTristateBool sslverify;
    /* both values below have 0 as default value */
    unsigned long long readahead; /* size of the readahead buffer in bytes */
    unsigned long long timeout; /* connection timeout in seconds */

    /* NBD QEMU reconnect-delay option,
     * 0 as default value */
    unsigned int reconnectDelay;

    virStorageSourceNVMeDef *nvme; /* type == VIR_STORAGE_TYPE_NVME */

    virDomainChrSourceDef *vhostuser; /* type == VIR_STORAGE_TYPE_VHOST_USER */

    virStorageSourceInitiatorDef initiator;

    virObject *privateData;

    int format; /* virStorageFileFormat in domain backing chains, but
                 * pool-specific enum for storage volumes */
    virBitmap *features;
    char *compat;
    bool nocow;
    bool sparse;

    virStorageSourceSlice *sliceStorage;

    virStoragePerms *perms;
    virStorageTimestamps *timestamps;
    unsigned long long capacity; /* in bytes, 0 if unknown */
    unsigned long long allocation; /* in bytes, 0 if unknown */
    unsigned long long physical; /* in bytes, 0 if unknown */
    unsigned long long clusterSize; /* in bytes, 0 if unknown */
    bool has_allocation; /* Set to true when provided in XML */

    unsigned long long metadataCacheMaxSize; /* size of the metadata cache in bytes */

    size_t nseclabels;
    virSecurityDeviceLabelDef **seclabels;

    /* Don't ever write to the image */
    bool readonly;

    /* image is shared across hosts */
    bool shared;

    /* backing chain of the storage source */
    virStorageSource *backingStore;

    /* metadata for storage driver access to remote and local volumes */
    void *drv;

    /* metadata about storage image which need separate fields */
    /* Relative name by which this image was opened from its parent, or NULL
     * if this image was opened by absolute name */
    char *relPath;
    /* Name of the child backing store recorded in metadata of the
     * current file.  */
    char *backingStoreRaw;
    virStorageFileFormat backingStoreRawFormat;

    /* metadata that allows identifying given storage source */
    char *nodenameformat;  /* name of the format handler object */
    char *nodenamestorage; /* name of the storage object */

    /* An optional setting to enable usage of TLS for the storage source */
    virTristateBool haveTLS;

    /* Indication whether the haveTLS value was altered due to qemu.conf
     * setting when haveTLS is missing from the domain config file */
    bool tlsFromConfig;

    /* If TLS is used, then mgmt of the TLS credentials occurs via an
     * object that is generated using a specific alias for a specific
     * certificate directory with listen and verify bools. */
    char *tlsAlias;
    char *tlsCertdir;

    /* TLS hostname override */
    char *tlsHostname;

    bool detected; /* true if this entry was not provided by the user */

    unsigned int debugLevel;
    bool debug;

    /* Libvirt currently stores the following properties in virDomainDiskDef.
     * These instances are currently just copies from the parent definition and
     * are not mapped back to the XML */
    virDomainDiskIo iomode;
    virDomainDiskCache cachemode;
    virDomainDiskDiscard discard;
    virDomainDiskDetectZeroes detect_zeroes;
    virTristateSwitch discard_no_unref;

    bool floppyimg; /* set to true if the storage source is going to be used
                       as a source for floppy drive */

    bool hostcdrom; /* backing device is a cdrom */

    /* ssh variables */
    char *ssh_user;
    bool ssh_host_key_check_disabled;
    char *ssh_known_hosts_file;
    char *ssh_keyfile;
    char *ssh_agent;

    /* nfs_user and nfs_group store the strings passed in by the user for NFS params.
     * nfs_uid and nfs_gid represent the converted/looked up ID numbers which are used
     * during run time, and are not based on the configuration */
    char *nfs_user;
    char *nfs_group;
    uid_t nfs_uid;
    gid_t nfs_gid;

    /* We need a flag to remember that the threshold event for this source was
     * registered with a full index (vda[3]) so that we can properly report just
     * one event for it */
    bool thresholdEventWithIndex;

    virStorageSourceFDTuple *fdtuple;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virStorageSource, virObjectUnref);

void
virStorageAuthDefFree(virStorageAuthDef *def);

virStorageAuthDef *
virStorageAuthDefCopy(const virStorageAuthDef *src);

virStorageAuthDef *
virStorageAuthDefParse(xmlNodePtr node,
                       xmlXPathContextPtr ctxt);

void
virStorageAuthDefFormat(virBuffer *buf,
                        virStorageAuthDef *authdef);

void
virStoragePRDefFree(virStoragePRDef *prd);

virStoragePRDef *
virStoragePRDefParseXML(xmlXPathContextPtr ctxt);

void
virStoragePRDefFormat(virBuffer *buf,
                      virStoragePRDef *prd,
                      bool migratable);

bool
virStoragePRDefIsEqual(virStoragePRDef *a,
                       virStoragePRDef *b);

bool
virStoragePRDefIsManaged(virStoragePRDef *prd);

bool
virStorageSourceChainHasManagedPR(virStorageSource *src);

void
virStorageSourceNVMeDefFree(virStorageSourceNVMeDef *def);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virStorageSourceNVMeDef, virStorageSourceNVMeDefFree);

bool
virStorageSourceChainHasNVMe(const virStorageSource *src);

virSecurityDeviceLabelDef *
virStorageSourceGetSecurityLabelDef(virStorageSource *src,
                                    const char *model);

void
virStorageNetHostDefClear(virStorageNetHostDef *def);

void
virStorageNetHostDefFree(size_t nhosts,
                         virStorageNetHostDef *hosts);

virStorageNetHostDef *
virStorageNetHostDefCopy(size_t nhosts,
                         virStorageNetHostDef *hosts);

int
virStorageSourceInitChainElement(virStorageSource *newelem,
                                 virStorageSource *old,
                                 bool force);

void
virStorageSourcePoolDefFree(virStorageSourcePoolDef *def);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virStorageSourcePoolDef, virStorageSourcePoolDefFree);

void
virStorageSourceClear(virStorageSource *def);

virStorageType
virStorageSourceGetActualType(const virStorageSource *def);

bool
virStorageSourceIsLocalStorage(const virStorageSource *src);

bool
virStorageSourceIsFD(const virStorageSource *src);

bool
virStorageSourceIsEmpty(virStorageSource *src);

bool
virStorageSourceIsBlockLocal(const virStorageSource *src);

virStorageSource *
virStorageSourceNew(void);

void
virStorageSourceBackingStoreClear(virStorageSource *def);

int
virStorageSourceNetCookiesValidate(virStorageSource *src);

virStorageSource *
virStorageSourceCopy(const virStorageSource *src,
                     bool backingChain)
    ATTRIBUTE_NONNULL(1);

bool
virStorageSourceIsSameLocation(virStorageSource *a,
                               virStorageSource *b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool
virStorageSourceIsRelative(virStorageSource *src);

void
virStorageSourceNetworkAssignDefaultPorts(virStorageSource *src)
    ATTRIBUTE_NONNULL(1);

bool
virStorageSourceIsBacking(const virStorageSource *src);

bool
virStorageSourceHasBacking(const virStorageSource *src);

int
virStorageSourcePrivateDataParseRelPath(xmlXPathContextPtr ctxt,
                                        virStorageSource *src);

int
virStorageSourcePrivateDataFormatRelPath(virStorageSource *src,
                                         virBuffer *buf);

void
virStorageSourceInitiatorParseXML(xmlXPathContextPtr ctxt,
                                  virStorageSourceInitiatorDef *initiator);

void
virStorageSourceInitiatorFormatXML(virStorageSourceInitiatorDef *initiator,
                                   virBuffer *buf);

int
virStorageSourceInitiatorCopy(virStorageSourceInitiatorDef *dest,
                              const virStorageSourceInitiatorDef *src);

void
virStorageSourceInitiatorClear(virStorageSourceInitiatorDef *initiator);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virStorageAuthDef, virStorageAuthDefFree);
