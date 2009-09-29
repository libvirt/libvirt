/*
 * storage_file.c: file utility functions for FS storage backend
 *
 * Copyright (C) 2007-2009 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_STORAGE_FILE_H__
#define __VIR_STORAGE_FILE_H__

#include "util.h"
#include <stdbool.h>

enum virStorageFileFormat {
    VIR_STORAGE_FILE_RAW = 0,
    VIR_STORAGE_FILE_DIR,
    VIR_STORAGE_FILE_BOCHS,
    VIR_STORAGE_FILE_CLOOP,
    VIR_STORAGE_FILE_COW,
    VIR_STORAGE_FILE_DMG,
    VIR_STORAGE_FILE_ISO,
    VIR_STORAGE_FILE_QCOW,
    VIR_STORAGE_FILE_QCOW2,
    VIR_STORAGE_FILE_VMDK,
    VIR_STORAGE_FILE_VPC,
    VIR_STORAGE_FILE_LAST,
};

VIR_ENUM_DECL(virStorageFileFormat);

typedef struct _virStorageFileMetadata {
    int format;
    char *backingStore;
    unsigned long long capacity;
    bool encrypted;
} virStorageFileMetadata;

int virStorageFileGetMetadata(virConnectPtr conn,
                              const char *path,
                              virStorageFileMetadata *meta);
int virStorageFileGetMetadataFromFD(virConnectPtr conn,
                                    const char *path,
                                    int fd,
                                    virStorageFileMetadata *meta);

#endif /* __VIR_STORAGE_FILE_H__ */
