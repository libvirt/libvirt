/*
 * storage_file_backend_fs.c: storage file code for FS and directory handling
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

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "virerror.h"
#include "storage_file_backend.h"
#include "storage_file_backend_fs.h"
#include "virfile.h"
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_fs");


static void
virStorageFileBackendFileDeinit(virStorageSource *src)
{
    VIR_DEBUG("deinitializing FS storage file %p (%s:%s)", src,
              virStorageTypeToString(virStorageSourceGetActualType(src)),
              src->path);
}


static int
virStorageFileBackendFileInit(virStorageSource *src)
{
    virStorageDriverData *drv = src->drv;

    VIR_DEBUG("initializing FS storage file %p (%s:%s)[%u:%u]", src,
              virStorageTypeToString(virStorageSourceGetActualType(src)),
              src->path,
              (unsigned int)drv->uid, (unsigned int)drv->gid);

    return 0;
}


static int
virStorageFileBackendFileCreate(virStorageSource *src)
{
    virStorageDriverData *drv = src->drv;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virFileOpenAs(src->path, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR,
                            drv->uid, drv->gid, 0)) < 0) {
        errno = -fd;
        return -1;
    }

    return 0;
}


static int
virStorageFileBackendFileUnlink(virStorageSource *src)
{
    return unlink(src->path);
}


static int
virStorageFileBackendFileStat(virStorageSource *src,
                              struct stat *st)
{
    return stat(src->path, st);
}


static ssize_t
virStorageFileBackendFileRead(virStorageSource *src,
                              size_t offset,
                              size_t len,
                              char **buf)
{
    virStorageDriverData *drv = src->drv;
    ssize_t ret = -1;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virFileOpenAs(src->path, O_RDONLY, 0,
                            drv->uid, drv->gid, 0)) < 0) {
        virReportSystemError(-fd, _("Failed to open file '%1$s'"),
                             src->path);
        return -1;
    }

    if (offset > 0) {
        if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
            virReportSystemError(errno, _("cannot seek into '%1$s'"), src->path);
            return -1;
        }
    }

    if ((ret = virFileReadHeaderFD(fd, len, buf)) < 0) {
        virReportSystemError(errno, _("cannot read header '%1$s'"), src->path);
        return -1;
    }

    return ret;
}


static int
virStorageFileBackendFileAccess(virStorageSource *src,
                                int mode)
{
    virStorageDriverData *drv = src->drv;

    return virFileAccessibleAs(src->path, mode,
                               drv->uid, drv->gid);
}


static int
virStorageFileBackendFileChown(const virStorageSource *src,
                               uid_t uid,
                               gid_t gid)
{
    return chown(src->path, uid, gid);
}


virStorageFileBackend virStorageFileBackendFile = {
    .type = VIR_STORAGE_TYPE_FILE,

    .backendInit = virStorageFileBackendFileInit,
    .backendDeinit = virStorageFileBackendFileDeinit,

    .storageFileCreate = virStorageFileBackendFileCreate,
    .storageFileUnlink = virStorageFileBackendFileUnlink,
    .storageFileStat = virStorageFileBackendFileStat,
    .storageFileRead = virStorageFileBackendFileRead,
    .storageFileAccess = virStorageFileBackendFileAccess,
    .storageFileChown = virStorageFileBackendFileChown,
};


virStorageFileBackend virStorageFileBackendBlock = {
    .type = VIR_STORAGE_TYPE_BLOCK,

    .backendInit = virStorageFileBackendFileInit,
    .backendDeinit = virStorageFileBackendFileDeinit,

    .storageFileStat = virStorageFileBackendFileStat,
    .storageFileRead = virStorageFileBackendFileRead,
    .storageFileAccess = virStorageFileBackendFileAccess,
    .storageFileChown = virStorageFileBackendFileChown,
};


virStorageFileBackend virStorageFileBackendDir = {
    .type = VIR_STORAGE_TYPE_DIR,

    .backendInit = virStorageFileBackendFileInit,
    .backendDeinit = virStorageFileBackendFileDeinit,

    .storageFileAccess = virStorageFileBackendFileAccess,
    .storageFileChown = virStorageFileBackendFileChown,
};


int
virStorageFileFsRegister(void)
{
    if (virStorageFileBackendRegister(&virStorageFileBackendFile) < 0)
        return -1;

    if (virStorageFileBackendRegister(&virStorageFileBackendBlock) < 0)
        return -1;

    if (virStorageFileBackendRegister(&virStorageFileBackendDir) < 0)
        return -1;

    return 0;
}
