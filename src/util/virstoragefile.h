/*
 * virstoragefile.h: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2009, 2012-2013 Red Hat, Inc.
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
# include "virutil.h"

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

typedef struct _virStorageFileMetadata virStorageFileMetadata;
typedef virStorageFileMetadata *virStorageFileMetadataPtr;
struct _virStorageFileMetadata {
    char *backingStore; /* Canonical name (absolute file, or protocol) */
    char *backingStoreRaw; /* If file, original name, possibly relative */
    char *directory; /* The directory containing basename of backingStoreRaw */
    int backingStoreFormat; /* enum virStorageFileFormat */
    bool backingStoreIsFile;
    virStorageFileMetadataPtr backingMeta;
    unsigned long long capacity;
    bool encrypted;
    virBitmapPtr features; /* bits described by enum virStorageFileFeature */
    char *compat;
};

# ifndef DEV_BSIZE
#  define DEV_BSIZE 512
# endif

int virStorageFileProbeFormat(const char *path, uid_t uid, gid_t gid);
int virStorageFileProbeFormatFromFD(const char *path,
                                    int fd);

virStorageFileMetadataPtr virStorageFileGetMetadata(const char *path,
                                                    int format,
                                                    uid_t uid, gid_t gid,
                                                    bool allow_probe);
virStorageFileMetadataPtr virStorageFileGetMetadataFromFD(const char *path,
                                                          int fd,
                                                          int format);

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

enum {
    VIR_STORAGE_FILE_SHFS_NFS = (1 << 0),
    VIR_STORAGE_FILE_SHFS_GFS2 = (1 << 1),
    VIR_STORAGE_FILE_SHFS_OCFS = (1 << 2),
    VIR_STORAGE_FILE_SHFS_AFS = (1 << 3),
};

int virStorageFileIsSharedFS(const char *path);
int virStorageFileIsClusterFS(const char *path);
int virStorageFileIsSharedFSType(const char *path,
                                 int fstypes);

int virStorageFileGetLVMKey(const char *path,
                            char **key);
int virStorageFileGetSCSIKey(const char *path,
                             char **key);

#endif /* __VIR_STORAGE_FILE_H__ */
