/*
 * storage_driver.h: core driver for storage APIs
 *
 * Copyright (C) 2006-2008, 2014 Red Hat, Inc.
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

#ifndef __VIR_STORAGE_DRIVER_H__
# define __VIR_STORAGE_DRIVER_H__

# include "storage_conf.h"
# include "conf/domain_conf.h"
# include "conf/snapshot_conf.h"

typedef struct _virStorageFileBackend virStorageFileBackend;
typedef virStorageFileBackend *virStorageFileBackendPtr;

typedef struct _virStorageFile virStorageFile;
typedef virStorageFile *virStorageFilePtr;
struct _virStorageFile {
    virStorageFileBackendPtr backend;
    void *priv;

    char *path;
    int type;
    int protocol;

    size_t nhosts;
    virDomainDiskHostDefPtr hosts;
};

virStorageFilePtr
virStorageFileInitFromDiskDef(virDomainDiskDefPtr disk);
virStorageFilePtr
virStorageFileInitFromSnapshotDef(virDomainSnapshotDiskDefPtr disk);
void virStorageFileFree(virStorageFilePtr file);

int virStorageFileCreate(virStorageFilePtr file);
int virStorageFileUnlink(virStorageFilePtr file);
int virStorageFileStat(virStorageFilePtr file,
                       struct stat *stat);

int storageRegister(void);

#endif /* __VIR_STORAGE_DRIVER_H__ */
