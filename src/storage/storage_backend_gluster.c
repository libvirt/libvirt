/*
 * storage_backend_gluster.c: storage backend for Gluster handling
 *
 * Copyright (C) 2013-2014 Red Hat, Inc.
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

#include "storage_backend_gluster.h"
#include "storage_conf.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virstoragefile.h"
#include "virstring.h"
#include "viruri.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_gluster");

struct _virStorageBackendGlusterState {
    glfs_t *vol;

    /* Accept the same URIs as qemu's block/gluster.c:
     * gluster[+transport]://[server[:port]]/vol/[dir/]image[?socket=...] */
    virURI *uri;

    char *volname; /* vol from URI, no '/' */
    char *dir; /* dir from URI, or "/"; always starts and ends in '/' */
};

typedef struct _virStorageBackendGlusterState virStorageBackendGlusterState;
typedef virStorageBackendGlusterState *virStorageBackendGlusterStatePtr;

static void
virStorageBackendGlusterClose(virStorageBackendGlusterStatePtr state)
{
    if (!state)
        return;

    /* Yuck - glusterfs-api-3.4.1 appears to always return -1 for
     * glfs_fini, with errno containing random data, so there's no way
     * to tell if it succeeded. 3.4.2 is supposed to fix this.*/
    if (state->vol && glfs_fini(state->vol) < 0)
        VIR_DEBUG("shutdown of gluster volume %s failed with errno %d",
                  state->volname, errno);

    virURIFree(state->uri);
    VIR_FREE(state->volname);
    VIR_FREE(state->dir);
    VIR_FREE(state);
}

static virStorageBackendGlusterStatePtr
virStorageBackendGlusterOpen(virStoragePoolObjPtr pool)
{
    virStorageBackendGlusterStatePtr ret = NULL;
    const char *name = pool->def->source.name;
    const char *dir = pool->def->source.dir;
    bool trailing_slash = true;

    /* Volume name must not contain '/'; optional path allows use of a
     * subdirectory within the volume name.  */
    if (strchr(name, '/')) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("gluster pool name '%s' must not contain /"),
                       name);
        return NULL;
    }
    if (dir) {
        if (*dir != '/') {
            virReportError(VIR_ERR_XML_ERROR,
                           _("gluster pool path '%s' must start with /"),
                           dir);
            return NULL;
        }
        if (strchr(dir, '\0')[-1] != '/')
            trailing_slash = false;
    }

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (VIR_STRDUP(ret->volname, name) < 0)
        goto error;
    if (virAsprintf(&ret->dir, "%s%s", dir ? dir : "/",
                    trailing_slash ? "" : "/") < 0)
        goto error;

    /* FIXME: Currently hard-coded to tcp transport; XML needs to be
     * extended to allow alternate transport */
    if (VIR_ALLOC(ret->uri) < 0)
        goto error;
    if (VIR_STRDUP(ret->uri->scheme, "gluster") < 0)
        goto error;
    if (VIR_STRDUP(ret->uri->server, pool->def->source.hosts[0].name) < 0)
        goto error;
    if (virAsprintf(&ret->uri->path, "/%s%s", ret->volname, ret->dir) < 0)
        goto error;
    ret->uri->port = pool->def->source.hosts[0].port;

    /* Actually connect to glfs */
    if (!(ret->vol = glfs_new(ret->volname))) {
        virReportOOMError();
        goto error;
    }

    if (glfs_set_volfile_server(ret->vol, "tcp",
                                ret->uri->server, ret->uri->port) < 0 ||
        glfs_init(ret->vol) < 0) {
        char *uri = virURIFormat(ret->uri);

        virReportSystemError(errno, _("failed to connect to %s"),
                             NULLSTR(uri));
        VIR_FREE(uri);
        goto error;
    }

    if (glfs_chdir(ret->vol, ret->dir) < 0) {
        virReportSystemError(errno,
                             _("failed to change to directory '%s' in '%s'"),
                             ret->dir, ret->volname);
        goto error;
    }

    return ret;

 error:
    virStorageBackendGlusterClose(ret);
    return NULL;
}


static ssize_t
virStorageBackendGlusterReadHeader(glfs_fd_t *fd,
                                   const char *name,
                                   ssize_t maxlen,
                                   char **buf)
{
    char *s;
    size_t nread = 0;

    if (VIR_ALLOC_N(*buf, maxlen) < 0)
        return -1;

    s = *buf;
    while (maxlen) {
        ssize_t r = glfs_read(fd, s, maxlen, 0);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0) {
            VIR_FREE(*buf);
            virReportSystemError(errno, _("unable to read '%s'"), name);
            return r;
        }
        if (r == 0)
            return nread;
        s += r;
        maxlen -= r;
        nread += r;
    }
    return nread;
}


static int
virStorageBackendGlusterSetMetadata(virStorageBackendGlusterStatePtr state,
                                    virStorageVolDefPtr vol,
                                    const char *name)
{
    int ret = -1;
    char *path = NULL;
    char *tmp;

    VIR_FREE(vol->key);
    VIR_FREE(vol->target.path);

    vol->type = VIR_STORAGE_VOL_NETWORK;
    vol->target.format = VIR_STORAGE_FILE_RAW;

    if (name) {
        VIR_FREE(vol->name);
        if (VIR_STRDUP(vol->name, name) < 0)
            goto cleanup;
    }

    if (virAsprintf(&path, "%s%s%s", state->volname, state->dir,
                    vol->name) < 0)
        goto cleanup;

    tmp = state->uri->path;
    if (virAsprintf(&state->uri->path, "/%s", path) < 0) {
        state->uri->path = tmp;
        goto cleanup;
    }
    if (!(vol->target.path = virURIFormat(state->uri))) {
        VIR_FREE(state->uri->path);
        state->uri->path = tmp;
        goto cleanup;
    }
    VIR_FREE(state->uri->path);
    state->uri->path = tmp;

    /* the path is unique enough to serve as a volume key */
    if (VIR_STRDUP(vol->key, vol->target.path) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(path);
    return ret;
}


/* Populate *volptr for the given name and stat information, or leave
 * it NULL if the entry should be skipped (such as ".").  Return 0 on
 * success, -1 on failure. */
static int
virStorageBackendGlusterRefreshVol(virStorageBackendGlusterStatePtr state,
                                   const char *name,
                                   struct stat *st,
                                   virStorageVolDefPtr *volptr)
{
    int ret = -1;
    virStorageVolDefPtr vol = NULL;
    glfs_fd_t *fd = NULL;
    virStorageSourcePtr meta = NULL;
    char *header = NULL;
    ssize_t len = VIR_STORAGE_MAX_HEADER;
    int backingFormat;

    *volptr = NULL;

    /* Silently skip '.' and '..'.  */
    if (STREQ(name, ".") || STREQ(name, ".."))
        return 0;

    /* Follow symlinks; silently skip broken links and loops.  */
    if (S_ISLNK(st->st_mode) && glfs_stat(state->vol, name, st) < 0) {
        if (errno == ENOENT || errno == ELOOP) {
            VIR_WARN("ignoring dangling symlink '%s'", name);
            ret = 0;
        } else {
            virReportSystemError(errno, _("cannot stat '%s'"), name);
        }
        return ret;
    }

    if (VIR_ALLOC(vol) < 0)
        goto cleanup;

    if (virStorageBackendUpdateVolTargetInfoFD(&vol->target, -1, st) < 0)
        goto cleanup;

    if (virStorageBackendGlusterSetMetadata(state, vol, name) < 0)
        goto cleanup;

    if (S_ISDIR(st->st_mode)) {
        vol->type = VIR_STORAGE_VOL_NETDIR;
        vol->target.format = VIR_STORAGE_FILE_DIR;
        *volptr = vol;
        vol = NULL;
        ret = 0;
        goto cleanup;
    }

    /* No need to worry about O_NONBLOCK - gluster doesn't allow creation
     * of fifos, so there's nothing it would protect us from. */
    if (!(fd = glfs_open(state->vol, name, O_RDONLY | O_NOCTTY))) {
        /* A dangling symlink now implies a TOCTTOU race; report it.  */
        virReportSystemError(errno, _("cannot open volume '%s'"), name);
        goto cleanup;
    }

    if ((len = virStorageBackendGlusterReadHeader(fd, name, len, &header)) < 0)
        goto cleanup;

    if (!(meta = virStorageFileGetMetadataFromBuf(name, header, len,
                                                  VIR_STORAGE_FILE_AUTO,
                                                  &backingFormat)))
        goto cleanup;

    if (meta->backingStoreRaw) {
        if (VIR_ALLOC(vol->target.backingStore) < 0)
            goto cleanup;

        vol->target.backingStore->path = meta->backingStoreRaw;

        if (backingFormat < 0)
            vol->target.backingStore->format = VIR_STORAGE_FILE_RAW;
        else
            vol->target.backingStore->format = backingFormat;
        meta->backingStoreRaw = NULL;
    }

    vol->target.format = meta->format;
    if (meta->capacity)
        vol->target.capacity = meta->capacity;
    if (meta->encryption) {
        vol->target.encryption = meta->encryption;
        meta->encryption = NULL;
    }
    vol->target.features = meta->features;
    meta->features = NULL;
    vol->target.compat = meta->compat;
    meta->compat = NULL;

    *volptr = vol;
    vol = NULL;
    ret = 0;
 cleanup:
    virStorageSourceFree(meta);
    virStorageVolDefFree(vol);
    if (fd)
        glfs_close(fd);
    VIR_FREE(header);
    return ret;
}

static int
virStorageBackendGlusterRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    virStoragePoolObjPtr pool)
{
    int ret = -1;
    virStorageBackendGlusterStatePtr state = NULL;
    struct {
        struct dirent ent;
        /* See comment below about readdir_r needing padding */
        char padding[MAX(1, 256 - (int) (sizeof(struct dirent)
                                         - offsetof(struct dirent, d_name)))];
    } de;
    struct dirent *ent;
    glfs_fd_t *dir = NULL;
    struct stat st;
    struct statvfs sb;

    if (!(state = virStorageBackendGlusterOpen(pool)))
        goto cleanup;

    /* Why oh why did glfs 3.4 decide to expose only readdir_r rather
     * than readdir?  POSIX admits that readdir_r is inherently a
     * flawed design, because systems are not required to define
     * NAME_MAX: http://austingroupbugs.net/view.php?id=696
     * http://womble.decadent.org.uk/readdir_r-advisory.html
     *
     * Fortunately, gluster appears to limit its underlying bricks to
     * only use file systems such as XFS that have a NAME_MAX of 255;
     * so we are currently guaranteed that if we provide 256 bytes of
     * tail padding, then we should have enough space to avoid buffer
     * overflow no matter whether the OS used d_name[], d_name[1], or
     * d_name[256] in its 'struct dirent'.
     * http://lists.gnu.org/archive/html/gluster-devel/2013-10/msg00083.html
     */

    if (!(dir = glfs_opendir(state->vol, state->dir))) {
        virReportSystemError(errno, _("cannot open path '%s' in '%s'"),
                             state->dir, state->volname);
        goto cleanup;
    }
    while (!(errno = glfs_readdirplus_r(dir, &st, &de.ent, &ent)) && ent) {
        virStorageVolDefPtr vol;
        int okay = virStorageBackendGlusterRefreshVol(state,
                                                      ent->d_name, &st,
                                                      &vol);

        if (okay < 0)
            goto cleanup;
        if (vol && VIR_APPEND_ELEMENT(pool->volumes.objs, pool->volumes.count,
                                      vol) < 0)
            goto cleanup;
    }
    if (errno) {
        virReportSystemError(errno, _("failed to read directory '%s' in '%s'"),
                             state->dir, state->volname);
        goto cleanup;
    }

    if (glfs_statvfs(state->vol, state->dir, &sb) < 0) {
        virReportSystemError(errno, _("cannot statvfs path '%s' in '%s'"),
                             state->dir, state->volname);
        goto cleanup;
    }

    pool->def->capacity = ((unsigned long long)sb.f_frsize *
                           (unsigned long long)sb.f_blocks);
    pool->def->available = ((unsigned long long)sb.f_bfree *
                            (unsigned long long)sb.f_frsize);
    pool->def->allocation = pool->def->capacity - pool->def->available;

    ret = 0;
 cleanup:
    if (dir)
        glfs_closedir(dir);
    virStorageBackendGlusterClose(state);
    if (ret < 0)
        virStoragePoolObjClearVols(pool);
    return ret;
}


static int
virStorageBackendGlusterVolDelete(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol,
                                  unsigned int flags)
{
    virStorageBackendGlusterStatePtr state = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    switch ((virStorageVolType) vol->type) {
    case VIR_STORAGE_VOL_FILE:
    case VIR_STORAGE_VOL_DIR:
    case VIR_STORAGE_VOL_BLOCK:
    case VIR_STORAGE_VOL_PLOOP:
    case VIR_STORAGE_VOL_LAST:
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("removing of '%s' volumes is not supported "
                         "by the gluster backend: %s"),
                       virStorageVolTypeToString(vol->type),
                       vol->target.path);
        goto cleanup;
        break;

    case VIR_STORAGE_VOL_NETWORK:
        if (!(state = virStorageBackendGlusterOpen(pool)))
            goto cleanup;

        if (glfs_unlink(state->vol, vol->name) < 0) {
            if (errno != ENOENT) {
                virReportSystemError(errno,
                                     _("cannot remove gluster volume file '%s'"),
                                     vol->target.path);
                goto cleanup;
            }
        }
        break;

    case VIR_STORAGE_VOL_NETDIR:
        if (!(state = virStorageBackendGlusterOpen(pool)))
            goto cleanup;

        if (glfs_rmdir(state->vol, vol->target.path) < 0) {
            if (errno != ENOENT) {
                virReportSystemError(errno,
                                     _("cannot remove gluster volume dir '%s'"),
                                     vol->target.path);
                goto cleanup;
            }
        }
        break;
    }

    ret = 0;

 cleanup:
    virStorageBackendGlusterClose(state);
    return ret;
}


static char *
virStorageBackendGlusterFindPoolSources(virConnectPtr conn ATTRIBUTE_UNUSED,
                                        const char *srcSpec,
                                        unsigned int flags)
{
    virStoragePoolSourceList list = { .type = VIR_STORAGE_POOL_GLUSTER,
                                      .nsources = 0,
                                      .sources = NULL
                                    };
    virStoragePoolSourcePtr source = NULL;
    char *ret = NULL;
    size_t i;

    virCheckFlags(0, NULL);

    if (!srcSpec) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("hostname must be specified for gluster sources"));
        return NULL;
    }

    if (!(source = virStoragePoolDefParseSourceString(srcSpec,
                                                      VIR_STORAGE_POOL_GLUSTER)))
        return NULL;

    if (source->nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        goto cleanup;
    }

    if (virStorageBackendFindGlusterPoolSources(source->hosts[0].name,
                                                0, /* currently ignored */
                                                &list) < 0)
        goto cleanup;

    if (!(ret = virStoragePoolSourceListFormat(&list)))
        goto cleanup;

 cleanup:
    for (i = 0; i < list.nsources; i++)
        virStoragePoolSourceClear(&list.sources[i]);
    VIR_FREE(list.sources);

    virStoragePoolSourceFree(source);
    return ret;
}


virStorageBackend virStorageBackendGluster = {
    .type = VIR_STORAGE_POOL_GLUSTER,

    .refreshPool = virStorageBackendGlusterRefreshPool,
    .findPoolSources = virStorageBackendGlusterFindPoolSources,

    .deleteVol = virStorageBackendGlusterVolDelete,
};


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

    VIR_DEBUG("deinitializing gluster storage file %p (gluster://%s:%s/%s%s)",
              src, src->hosts->name, src->hosts->port ? src->hosts->port : "0",
              src->volume, src->path);

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

        if (host->port &&
            virStrToLong_i(host->port, NULL, 10, &port) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to parse port number '%s'"),
                           host->port);
            return -1;
        }

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
virStorageFileBackendGlusterReadHeader(virStorageSourcePtr src,
                                       ssize_t max_len,
                                       char **buf)
{
    virStorageFileBackendGlusterPrivPtr priv = src->drv->priv;
    glfs_fd_t *fd = NULL;
    ssize_t ret = -1;

    *buf = NULL;

    if (!(fd = glfs_open(priv->vol, src->path, O_RDONLY))) {
        virReportSystemError(errno, _("Failed to open file '%s'"),
                             src->path);
        return -1;
    }

    ret = virStorageBackendGlusterReadHeader(fd, src->path, max_len, buf);

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
    char *buf = NULL;
    size_t bufsiz = 0;
    ssize_t ret;
    struct stat st;

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
        goto error;

    if ((ret = glfs_readlink(priv->vol, path, buf, bufsiz)) < 0) {
        virReportSystemError(errno,
                             _("failed to read link of gluster file '%s'"),
                             path);
        goto error;
    }

    if (ret == bufsiz)
        goto realloc;

    buf[ret] = '\0';

    *linkpath = buf;

    return 0;

 error:
    VIR_FREE(buf);
    return -1;
}


static const char *
virStorageFileBackendGlusterGetUniqueIdentifier(virStorageSourcePtr src)
{
    virStorageFileBackendGlusterPrivPtr priv = src->drv->priv;
    char *filePath = NULL;

    if (priv->canonpath)
        return priv->canonpath;

    if (!(filePath = virStorageFileCanonicalizePath(src->path,
                                                    virStorageFileBackendGlusterReadlinkCallback,
                                                    priv)))
        return NULL;

    ignore_value(virAsprintf(&priv->canonpath, "gluster://%s:%s/%s/%s",
                             src->hosts->name,
                             src->hosts->port,
                             src->volume,
                             filePath));

    VIR_FREE(filePath);

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
    .storageFileReadHeader = virStorageFileBackendGlusterReadHeader,
    .storageFileAccess = virStorageFileBackendGlusterAccess,
    .storageFileChown = virStorageFileBackendGlusterChown,

    .storageFileGetUniqueIdentifier = virStorageFileBackendGlusterGetUniqueIdentifier,


};
