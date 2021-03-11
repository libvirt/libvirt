/*
 * storage_file_backend.h: internal storage source backend contract
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

#include "storage_source_conf.h"

/* ------- virStorageFile backends ------------ */
typedef struct _virStorageFileBackend virStorageFileBackend;

typedef struct _virStorageDriverData virStorageDriverData;
struct _virStorageDriverData {
    virStorageFileBackend *backend;
    void *priv;

    uid_t uid;
    gid_t gid;
};

typedef int
(*virStorageFileBackendInit)(virStorageSource *src);

typedef void
(*virStorageFileBackendDeinit)(virStorageSource *src);

typedef int
(*virStorageFileBackendCreate)(virStorageSource *src);

typedef int
(*virStorageFileBackendUnlink)(virStorageSource *src);

typedef int
(*virStorageFileBackendStat)(virStorageSource *src,
                             struct stat *st);

typedef ssize_t
(*virStorageFileBackendRead)(virStorageSource *src,
                             size_t offset,
                             size_t len,
                             char **buf);

typedef int
(*virStorageFileBackendAccess)(virStorageSource *src,
                               int mode);

typedef int
(*virStorageFileBackendChown)(const virStorageSource *src,
                              uid_t uid,
                              gid_t gid);

int virStorageFileBackendForType(int type,
                                 int protocol,
                                 bool required,
                                 virStorageFileBackend **backend);

struct _virStorageFileBackend {
    int type;
    int protocol;

    /* All storage file callbacks may be omitted if not implemented */

    /* The following group of callbacks is expected to set a libvirt
     * error on failure. */
    virStorageFileBackendInit backendInit;
    virStorageFileBackendDeinit backendDeinit;
    virStorageFileBackendRead storageFileRead;

    /* The following group of callbacks is expected to set errno
     * and return -1 on error. No libvirt error shall be reported */
    virStorageFileBackendCreate storageFileCreate;
    virStorageFileBackendUnlink storageFileUnlink;
    virStorageFileBackendStat   storageFileStat;
    virStorageFileBackendAccess storageFileAccess;
    virStorageFileBackendChown  storageFileChown;
};

int virStorageFileBackendRegister(virStorageFileBackend *backend);
