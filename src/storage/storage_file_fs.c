/*
 * storage_file_fs.c: storage file code for FS and directory handling
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
#include "storage_file_fs.h"
#include "storage_util.h"
#include "virstoragefilebackend.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_fs");


typedef struct _virStorageFileBackendFsPriv virStorageFileBackendFsPriv;
typedef virStorageFileBackendFsPriv *virStorageFileBackendFsPrivPtr;

struct _virStorageFileBackendFsPriv {
    char *canonpath; /* unique file identifier (canonical path) */
};


static void
virStorageFileBackendFileDeinit(virStorageSourcePtr src)
{
    VIR_DEBUG("deinitializing FS storage file %p (%s:%s)", src,
              virStorageTypeToString(virStorageSourceGetActualType(src)),
              src->path);

    virStorageFileBackendFsPrivPtr priv = src->drv->priv;

    VIR_FREE(priv->canonpath);
    VIR_FREE(priv);
}


static int
virStorageFileBackendFileInit(virStorageSourcePtr src)
{
    virStorageFileBackendFsPrivPtr priv = NULL;

    VIR_DEBUG("initializing FS storage file %p (%s:%s)[%u:%u]", src,
              virStorageTypeToString(virStorageSourceGetActualType(src)),
              src->path,
              (unsigned int)src->drv->uid, (unsigned int)src->drv->gid);

    if (VIR_ALLOC(priv) < 0)
        return -1;

    src->drv->priv = priv;

    return 0;
}


static int
virStorageFileBackendFileCreate(virStorageSourcePtr src)
{
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virFileOpenAs(src->path, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR,
                            src->drv->uid, src->drv->gid, 0)) < 0) {
        errno = -fd;
        return -1;
    }

    return 0;
}


static int
virStorageFileBackendFileUnlink(virStorageSourcePtr src)
{
    return unlink(src->path);
}


static int
virStorageFileBackendFileStat(virStorageSourcePtr src,
                              struct stat *st)
{
    return stat(src->path, st);
}


static ssize_t
virStorageFileBackendFileRead(virStorageSourcePtr src,
                              size_t offset,
                              size_t len,
                              char **buf)
{
    ssize_t ret = -1;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virFileOpenAs(src->path, O_RDONLY, 0,
                            src->drv->uid, src->drv->gid, 0)) < 0) {
        virReportSystemError(-fd, _("Failed to open file '%s'"),
                             src->path);
        return -1;
    }

    if (offset > 0) {
        if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
            virReportSystemError(errno, _("cannot seek into '%s'"), src->path);
            return -1;
        }
    }

    if ((ret = virFileReadHeaderFD(fd, len, buf)) < 0) {
        virReportSystemError(errno, _("cannot read header '%s'"), src->path);
        return -1;
    }

    return ret;
}


static const char *
virStorageFileBackendFileGetUniqueIdentifier(virStorageSourcePtr src)
{
    virStorageFileBackendFsPrivPtr priv = src->drv->priv;

    if (!priv->canonpath) {
        if (!(priv->canonpath = virFileCanonicalizePath(src->path))) {
            virReportSystemError(errno, _("can't canonicalize path '%s'"),
                                 src->path);
            return NULL;
        }
    }

    return priv->canonpath;
}


static int
virStorageFileBackendFileAccess(virStorageSourcePtr src,
                                int mode)
{
    return virFileAccessibleAs(src->path, mode,
                               src->drv->uid, src->drv->gid);
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

    .storageFileGetUniqueIdentifier = virStorageFileBackendFileGetUniqueIdentifier,
};


virStorageFileBackend virStorageFileBackendBlock = {
    .type = VIR_STORAGE_TYPE_BLOCK,

    .backendInit = virStorageFileBackendFileInit,
    .backendDeinit = virStorageFileBackendFileDeinit,

    .storageFileStat = virStorageFileBackendFileStat,
    .storageFileRead = virStorageFileBackendFileRead,
    .storageFileAccess = virStorageFileBackendFileAccess,
    .storageFileChown = virStorageFileBackendFileChown,

    .storageFileGetUniqueIdentifier = virStorageFileBackendFileGetUniqueIdentifier,
};


virStorageFileBackend virStorageFileBackendDir = {
    .type = VIR_STORAGE_TYPE_DIR,

    .backendInit = virStorageFileBackendFileInit,
    .backendDeinit = virStorageFileBackendFileDeinit,

    .storageFileAccess = virStorageFileBackendFileAccess,
    .storageFileChown = virStorageFileBackendFileChown,

    .storageFileGetUniqueIdentifier = virStorageFileBackendFileGetUniqueIdentifier,
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
