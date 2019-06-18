/*
 * virstoragefilebackend.h: internal storage source backend contract
 *
 * Copyright (C) 2007-2018 Red Hat, Inc.
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

#include "virstoragefile.h"

/* ------- virStorageFile backends ------------ */
typedef struct _virStorageFileBackend virStorageFileBackend;
typedef virStorageFileBackend *virStorageFileBackendPtr;

struct _virStorageDriverData {
    virStorageFileBackendPtr backend;
    void *priv;

    uid_t uid;
    gid_t gid;
};

typedef int
(*virStorageFileBackendInit)(virStorageSourcePtr src);

typedef void
(*virStorageFileBackendDeinit)(virStorageSourcePtr src);

typedef int
(*virStorageFileBackendCreate)(virStorageSourcePtr src);

typedef int
(*virStorageFileBackendUnlink)(virStorageSourcePtr src);

typedef int
(*virStorageFileBackendStat)(virStorageSourcePtr src,
                             struct stat *st);

typedef ssize_t
(*virStorageFileBackendRead)(virStorageSourcePtr src,
                             size_t offset,
                             size_t len,
                             char **buf);

typedef const char *
(*virStorageFileBackendGetUniqueIdentifier)(virStorageSourcePtr src);

typedef int
(*virStorageFileBackendAccess)(virStorageSourcePtr src,
                               int mode);

typedef int
(*virStorageFileBackendChown)(const virStorageSource *src,
                              uid_t uid,
                              gid_t gid);

int virStorageFileBackendForType(int type,
                                 int protocol,
                                 bool required,
                                 virStorageFileBackendPtr *backend);

struct _virStorageFileBackend {
    int type;
    int protocol;

    /* All storage file callbacks may be omitted if not implemented */

    /* The following group of callbacks is expected to set a libvirt
     * error on failure. */
    virStorageFileBackendInit backendInit;
    virStorageFileBackendDeinit backendDeinit;
    virStorageFileBackendRead storageFileRead;
    virStorageFileBackendGetUniqueIdentifier storageFileGetUniqueIdentifier;

    /* The following group of callbacks is expected to set errno
     * and return -1 on error. No libvirt error shall be reported */
    virStorageFileBackendCreate storageFileCreate;
    virStorageFileBackendUnlink storageFileUnlink;
    virStorageFileBackendStat   storageFileStat;
    virStorageFileBackendAccess storageFileAccess;
    virStorageFileBackendChown  storageFileChown;
};

int virStorageFileBackendRegister(virStorageFileBackendPtr backend);
