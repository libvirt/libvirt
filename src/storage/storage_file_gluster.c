/*
 * storage_file_gluster.c: storage file backend for Gluster handling
 *
 * Copyright (C) 2013-2018 Red Hat, Inc.
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
 */

#include <config.h>

#include <glusterfs/api/glfs.h>

#include "storage_file_gluster.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virstoragefilebackend.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_file_gluster");


typedef struct _virStorageFileBackendGlusterPriv virStorageFileBackendGlusterPriv;
typedef virStorageFileBackendGlusterPriv *virStorageFileBackendGlusterPrivPtr;

struct _virStorageFileBackendGlusterPriv {
    glfs_t *vol;
    char *canonpath;
};

static void
virStorageFileBackendGlusterDeinit(virStorageSourcePtr src)
{
    virStorageFileBackendGlusterPrivPtr priv = src->drv->priv;

    VIR_DEBUG("deinitializing gluster storage file %p (gluster://%s:%u/%s%s)",
              src, src->hosts->name, src->hosts->port, src->volume, src->path);

    if (priv->vol)
        glfs_fini(priv->vol);
    VIR_FREE(priv->canonpath);

    VIR_FREE(priv);
    src->drv->priv = NULL;
}

static int
virStorageFileBackendGlusterInitServer(virStorageFileBackendGlusterPrivPtr priv,
                                       virStorageNetHostDefPtr host)
{
    const char *transport = virStorageNetHostTransportTypeToString(host->transport);
    const char *hoststr = NULL;
    int port = 0;

    switch ((virStorageNetHostTransport) host->transport) {
    case VIR_STORAGE_NET_HOST_TRANS_RDMA:
    case VIR_STORAGE_NET_HOST_TRANS_TCP:
        hoststr = host->name;
        port = host->port;
        break;

    case VIR_STORAGE_NET_HOST_TRANS_UNIX:
        hoststr = host->socket;
        break;

    case VIR_STORAGE_NET_HOST_TRANS_LAST:
        break;
    }

    VIR_DEBUG("adding gluster host for %p: transport=%s host=%s port=%d",
              priv, transport, hoststr, port);

    if (glfs_set_volfile_server(priv->vol, transport, hoststr, port) < 0) {
        virReportSystemError(errno,
                             _("failed to set gluster volfile server '%s'"),
                             hoststr);
        return -1;
    }

    return 0;
}


static int
virStorageFileBackendGlusterInit(virStorageSourcePtr src)
{
    virStorageFileBackendGlusterPrivPtr priv = NULL;
    size_t i;

    if (!src->volume) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing gluster volume name for path '%s'"),
                       src->path);
        return -1;
    }

    if (VIR_ALLOC(priv) < 0)
        return -1;

    VIR_DEBUG("initializing gluster storage file %p "
              "(priv='%p' volume='%s' path='%s') as [%u:%u]",
              src, priv, src->volume, src->path,
              (unsigned int)src->drv->uid, (unsigned int)src->drv->gid);

    if (!(priv->vol = glfs_new(src->volume))) {
        virReportOOMError();
        goto error;
    }

    for (i = 0; i < src->nhosts; i++) {
        if (virStorageFileBackendGlusterInitServer(priv, src->hosts + i) < 0)
            goto error;
    }

    if (glfs_init(priv->vol) < 0) {
        virReportSystemError(errno,
                             _("failed to initialize gluster connection "
                               "(src=%p priv=%p)"), src, priv);
        goto error;
    }

    src->drv->priv = priv;

    return 0;

 error:
    if (priv->vol)
        glfs_fini(priv->vol);
    VIR_FREE(priv);

    return -1;
}


static int
virStorageFileBackendGlusterCreate(virStorageSourcePtr src)
{
    virStorageFileBackendGlusterPrivPtr priv = src->drv->priv;
    glfs_fd_t *fd = NULL;
    mode_t mode = S_IRUSR;

    if (!src->readonly)
        mode |= S_IWUSR;

    if (!(fd = glfs_creat(priv->vol, src->path,
                          O_CREAT | O_TRUNC | O_WRONLY, mode)))
        return -1;

    ignore_value(glfs_close(fd));
    return 0;
}


static int
virStorageFileBackendGlusterUnlink(virStorageSourcePtr src)
{
    virStorageFileBackendGlusterPrivPtr priv = src->drv->priv;

    return glfs_unlink(priv->vol, src->path);
}


static int
virStorageFileBackendGlusterStat(virStorageSourcePtr src,
                                 struct stat *st)
{
    virStorageFileBackendGlusterPrivPtr priv = src->drv->priv;

    return glfs_stat(priv->vol, src->path, st);
}


static ssize_t
virStorageFileBackendGlusterRead(virStorageSourcePtr src,
                                 size_t offset,
                                 size_t len,
                                 char **buf)
{
    virStorageFileBackendGlusterPrivPtr priv = src->drv->priv;
    glfs_fd_t *fd = NULL;
    ssize_t ret = -1;
    char *s;
    size_t nread = 0;

    *buf = NULL;

    if (!(fd = glfs_open(priv->vol, src->path, O_RDONLY))) {
        virReportSystemError(errno, _("Failed to open file '%s'"),
                             src->path);
        return -1;
    }

    if (offset > 0) {
        if (glfs_lseek(fd, offset, SEEK_SET) == (off_t) -1) {
            virReportSystemError(errno, _("cannot seek into '%s'"), src->path);
            goto cleanup;
        }
    }


    if (VIR_ALLOC_N(*buf, len) < 0)
        return -1;

    s = *buf;
    while (len) {
        ssize_t r = glfs_read(fd, s, len, 0);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            VIR_FREE(*buf);
            virReportSystemError(errno, _("unable to read '%s'"), src->path);
            return r;
        }
        if (r == 0)
            return nread;
        s += r;
        len -= r;
        nread += r;
    }

    ret = nread;

 cleanup:
    if (fd)
        glfs_close(fd);

    return ret;
}


static int
virStorageFileBackendGlusterAccess(virStorageSourcePtr src,
                                   int mode)
{
    virStorageFileBackendGlusterPrivPtr priv = src->drv->priv;

    return glfs_access(priv->vol, src->path, mode);
}

static int
virStorageFileBackendGlusterReadlinkCallback(const char *path,
                                             char **linkpath,
                                             void *data)
{
    virStorageFileBackendGlusterPrivPtr priv = data;
    size_t bufsiz = 0;
    ssize_t ret;
    struct stat st;
    g_autofree char *buf = NULL;

    *linkpath = NULL;

    if (glfs_stat(priv->vol, path, &st) < 0) {
        virReportSystemError(errno,
                             _("failed to stat gluster path '%s'"),
                             path);
        return -1;
    }

    if (!S_ISLNK(st.st_mode))
        return 1;

 realloc:
    if (VIR_EXPAND_N(buf, bufsiz, 256) < 0)
        return -1;

    if ((ret = glfs_readlink(priv->vol, path, buf, bufsiz)) < 0) {
        virReportSystemError(errno,
                             _("failed to read link of gluster file '%s'"),
                             path);
        return -1;
    }

    if (ret == bufsiz)
        goto realloc;

    buf[ret] = '\0';

    *linkpath = g_steal_pointer(&buf);

    return 0;
}


static const char *
virStorageFileBackendGlusterGetUniqueIdentifier(virStorageSourcePtr src)
{
    virStorageFileBackendGlusterPrivPtr priv = src->drv->priv;
    g_autofree char *filePath = NULL;

    if (priv->canonpath)
        return priv->canonpath;

    if (!(filePath = virStorageFileCanonicalizePath(src->path,
                                                    virStorageFileBackendGlusterReadlinkCallback,
                                                    priv)))
        return NULL;

    ignore_value(virAsprintf(&priv->canonpath, "gluster://%s:%u/%s/%s",
                             src->hosts->name,
                             src->hosts->port,
                             src->volume,
                             filePath));

    return priv->canonpath;
}


static int
virStorageFileBackendGlusterChown(const virStorageSource *src,
                                  uid_t uid,
                                  gid_t gid)
{
    virStorageFileBackendGlusterPrivPtr priv = src->drv->priv;

    return glfs_chown(priv->vol, src->path, uid, gid);
}


virStorageFileBackend virStorageFileBackendGluster = {
    .type = VIR_STORAGE_TYPE_NETWORK,
    .protocol = VIR_STORAGE_NET_PROTOCOL_GLUSTER,

    .backendInit = virStorageFileBackendGlusterInit,
    .backendDeinit = virStorageFileBackendGlusterDeinit,

    .storageFileCreate = virStorageFileBackendGlusterCreate,
    .storageFileUnlink = virStorageFileBackendGlusterUnlink,
    .storageFileStat = virStorageFileBackendGlusterStat,
    .storageFileRead = virStorageFileBackendGlusterRead,
    .storageFileAccess = virStorageFileBackendGlusterAccess,
    .storageFileChown = virStorageFileBackendGlusterChown,

    .storageFileGetUniqueIdentifier = virStorageFileBackendGlusterGetUniqueIdentifier,
};


int
virStorageFileGlusterRegister(void)
{
    if (virStorageFileBackendRegister(&virStorageFileBackendGluster) < 0)
        return -1;

    return 0;
}
