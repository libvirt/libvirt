/*
 * storage_backend_fs.c: storage backend for FS and directory handling
 *
 * Copyright (C) 2007-2015 Red Hat, Inc.
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

#include <config.h>

#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

#include "virerror.h"
#include "storage_backend_fs.h"
#include "storage_conf.h"
#include "virstoragefile.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virxml.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_fs");

#define VIR_STORAGE_VOL_FS_OPEN_FLAGS    (VIR_STORAGE_VOL_OPEN_DEFAULT | \
                                          VIR_STORAGE_VOL_OPEN_DIR)
#define VIR_STORAGE_VOL_FS_PROBE_FLAGS   (VIR_STORAGE_VOL_FS_OPEN_FLAGS | \
                                          VIR_STORAGE_VOL_OPEN_NOERROR)

static int
virStorageBackendProbeTarget(virStorageSourcePtr target,
                             virStorageEncryptionPtr *encryption)
{
    int backingStoreFormat;
    int fd = -1;
    int ret = -1;
    int rc;
    virStorageSourcePtr meta = NULL;
    struct stat sb;

    if (encryption)
        *encryption = NULL;

    if ((rc = virStorageBackendVolOpen(target->path, &sb,
                                       VIR_STORAGE_VOL_FS_PROBE_FLAGS)) < 0)
        return rc; /* Take care to propagate rc, it is not always -1 */
    fd = rc;

    if (virStorageBackendUpdateVolTargetInfoFD(target, fd, &sb) < 0)
        goto cleanup;

    if (S_ISDIR(sb.st_mode)) {
        if (virStorageBackendIsPloopDir(target->path)) {
            if (virStorageBackendRedoPloopUpdate(target, &sb, &fd,
                                                 VIR_STORAGE_VOL_FS_PROBE_FLAGS) < 0)
                goto cleanup;
        } else {
            target->format = VIR_STORAGE_FILE_DIR;
            ret = 0;
            goto cleanup;
        }
    }

    if (!(meta = virStorageFileGetMetadataFromFD(target->path,
                                                 fd,
                                                 VIR_STORAGE_FILE_AUTO,
                                                 &backingStoreFormat)))
        goto cleanup;

    if (meta->backingStoreRaw) {
        if (!(target->backingStore = virStorageSourceNewFromBacking(meta)))
            goto cleanup;

        target->backingStore->format = backingStoreFormat;

        /* XXX: Remote storage doesn't play nicely with volumes backed by
         * remote storage. To avoid trouble, just fake the backing store is RAW
         * and put the string from the metadata as the path of the target. */
        if (!virStorageSourceIsLocalStorage(target->backingStore)) {
            virStorageSourceFree(target->backingStore);

            if (VIR_ALLOC(target->backingStore) < 0)
                goto cleanup;

            target->backingStore->type = VIR_STORAGE_TYPE_NETWORK;
            target->backingStore->path = meta->backingStoreRaw;
            meta->backingStoreRaw = NULL;
            target->backingStore->format = VIR_STORAGE_FILE_RAW;
        }

        if (target->backingStore->format == VIR_STORAGE_FILE_AUTO) {
            if ((rc = virStorageFileProbeFormat(target->backingStore->path,
                                                -1, -1)) < 0) {
                /* If the backing file is currently unavailable or is
                 * accessed via remote protocol only log an error, fake the
                 * format as RAW and continue. Returning -1 here would
                 * disable the whole storage pool, making it unavailable for
                 * even maintenance. */
                target->backingStore->format = VIR_STORAGE_FILE_RAW;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot probe backing volume format: %s"),
                               target->backingStore->path);
            } else {
                target->backingStore->format = rc;
            }
        }
    }

    target->format = meta->format;

    /* Default to success below this point */
    ret = 0;

    if (meta->capacity)
        target->capacity = meta->capacity;

    if (encryption && meta->encryption) {
        *encryption = meta->encryption;
        meta->encryption = NULL;

        /* XXX ideally we'd fill in secret UUID here
         * but we cannot guarantee 'conn' is non-NULL
         * at this point in time :-(  So we only fill
         * in secrets when someone first queries a vol
         */
    }

    virBitmapFree(target->features);
    target->features = meta->features;
    meta->features = NULL;

    if (meta->compat) {
        VIR_FREE(target->compat);
        target->compat = meta->compat;
        meta->compat = NULL;
    }

 cleanup:
    VIR_FORCE_CLOSE(fd);
    virStorageSourceFree(meta);
    return ret;

}

#if WITH_STORAGE_FS

# include <mntent.h>

struct _virNetfsDiscoverState {
    const char *host;
    virStoragePoolSourceList list;
};

typedef struct _virNetfsDiscoverState virNetfsDiscoverState;

static int
virStorageBackendFileSystemNetFindPoolSourcesFunc(char **const groups,
                                                  void *data)
{
    virNetfsDiscoverState *state = data;
    const char *name, *path;
    virStoragePoolSource *src = NULL;
    int ret = -1;

    path = groups[0];

    if (!(name = strrchr(path, '/'))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid netfs path (no /): %s"), path);
        goto cleanup;
    }
    name += 1;
    if (*name == '\0') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid netfs path (ends in /): %s"), path);
        goto cleanup;
    }

    if (!(src = virStoragePoolSourceListNewSource(&state->list)))
        goto cleanup;

    if (VIR_ALLOC_N(src->hosts, 1) < 0)
        goto cleanup;
    src->nhost = 1;

    if (VIR_STRDUP(src->hosts[0].name, state->host) < 0 ||
        VIR_STRDUP(src->dir, path) < 0)
        goto cleanup;
    src->format = VIR_STORAGE_POOL_NETFS_NFS;

    ret = 0;
 cleanup:
    return ret;
}


static int
virStorageBackendFileSystemNetFindNFSPoolSources(virNetfsDiscoverState *state)
{
    int ret = -1;

    /*
     *  # showmount --no-headers -e HOSTNAME
     *  /tmp   *
     *  /A dir demo1.foo.bar,demo2.foo.bar
     *
     * Extract directory name (including possible interior spaces ...).
     */

    const char *regexes[] = {
        "^(/.*\\S) +\\S+$"
    };
    int vars[] = {
        1
    };

    virCommandPtr cmd = NULL;

    cmd = virCommandNewArgList(SHOWMOUNT,
                               "--no-headers",
                               "--exports",
                               state->host,
                               NULL);

    if (virCommandRunRegex(cmd, 1, regexes, vars,
                           virStorageBackendFileSystemNetFindPoolSourcesFunc,
                           state, NULL, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virCommandFree(cmd);
    return ret;
}


static char *
virStorageBackendFileSystemNetFindPoolSources(virConnectPtr conn ATTRIBUTE_UNUSED,
                                              const char *srcSpec,
                                              unsigned int flags)
{
    virNetfsDiscoverState state = {
        .host = NULL,
        .list = {
            .type = VIR_STORAGE_POOL_NETFS,
            .nsources = 0,
            .sources = NULL
        }
    };
    virStoragePoolSourcePtr source = NULL;
    char *ret = NULL;
    size_t i;
    int retNFS = -1, retGluster = -1;

    virCheckFlags(0, NULL);

    if (!srcSpec) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("hostname must be specified for netfs sources"));
        return NULL;
    }

    if (!(source = virStoragePoolDefParseSourceString(srcSpec,
                                                      VIR_STORAGE_POOL_NETFS)))
        return NULL;

    if (source->nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        goto cleanup;
    }

    state.host = source->hosts[0].name;

    retNFS = virStorageBackendFileSystemNetFindNFSPoolSources(&state);

# ifdef GLUSTER_CLI
    retGluster =
        virStorageBackendFindGlusterPoolSources(state.host,
                                                VIR_STORAGE_POOL_NETFS_GLUSTERFS,
                                                &state.list);
# endif
    /* If both fail, then we won't return an empty list - return an error */
    if (retNFS < 0 && retGluster < 0)
        goto cleanup;

    if (!(ret = virStoragePoolSourceListFormat(&state.list)))
        goto cleanup;

 cleanup:
    for (i = 0; i < state.list.nsources; i++)
        virStoragePoolSourceClear(&state.list.sources[i]);
    VIR_FREE(state.list.sources);

    virStoragePoolSourceFree(source);
    return ret;
}

/**
 * @pool storage pool to check FS types
 *
 * Determine if storage pool FS types are properly set up
 *
 * Return 0 if everything's OK, -1 on error
 */
static int
virStorageBackendFileSystemIsValid(virStoragePoolObjPtr pool)
{
    if (pool->def->type == VIR_STORAGE_POOL_NETFS) {
        if (pool->def->source.nhost != 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("expected exactly 1 host for the storage pool"));
            return -1;
        }
        if (pool->def->source.hosts[0].name == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing source host"));
            return -1;
        }
        if (pool->def->source.dir == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing source path"));
            return -1;
        }
    } else {
        if (pool->def->source.ndevice != 1) {
            if (pool->def->source.ndevice == 0)
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("missing source device"));
            else
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("expected exactly 1 device for the "
                                 "storage pool"));
            return -1;
        }
    }
    return 0;
}


/**
 * virStorageBackendFileSystemGetPoolSource
 * @pool: storage pool object pointer
 *
 * Allocate/return a string representing the FS storage pool source.
 * It is up to the caller to VIR_FREE the allocated string
 */
static char *
virStorageBackendFileSystemGetPoolSource(virStoragePoolObjPtr pool)
{
    char *src = NULL;

    if (pool->def->type == VIR_STORAGE_POOL_NETFS) {
        if (pool->def->source.format == VIR_STORAGE_POOL_NETFS_CIFS) {
            if (virAsprintf(&src, "//%s/%s",
                            pool->def->source.hosts[0].name,
                            pool->def->source.dir) < 0)
                return NULL;
        } else {
            if (virAsprintf(&src, "%s:%s",
                            pool->def->source.hosts[0].name,
                            pool->def->source.dir) < 0)
                return NULL;
        }
    } else {
        if (VIR_STRDUP(src, pool->def->source.devices[0].path) < 0)
            return NULL;
    }
    return src;
}


/**
 * @pool storage pool to check for status
 *
 * Determine if a storage pool is already mounted
 *
 * Return 0 if not mounted, 1 if mounted, -1 on error
 */
static int
virStorageBackendFileSystemIsMounted(virStoragePoolObjPtr pool)
{
    int ret = -1;
    char *src = NULL;
    FILE *mtab;
    struct mntent ent;
    char buf[1024];

    if ((mtab = fopen(_PATH_MOUNTED, "r")) == NULL) {
        virReportSystemError(errno,
                             _("cannot read mount list '%s'"),
                             _PATH_MOUNTED);
        goto cleanup;
    }

    while ((getmntent_r(mtab, &ent, buf, sizeof(buf))) != NULL) {
        if (!(src = virStorageBackendFileSystemGetPoolSource(pool)))
            goto cleanup;

        if (STREQ(ent.mnt_dir, pool->def->target.path) &&
            STREQ(ent.mnt_fsname, src)) {
            ret = 1;
            goto cleanup;
        }

        VIR_FREE(src);
    }

    ret = 0;

 cleanup:
    VIR_FORCE_FCLOSE(mtab);
    VIR_FREE(src);
    return ret;
}

/**
 * @pool storage pool to mount
 *
 * Ensure that a FS storage pool is mounted on its target location.
 * If already mounted, this is a no-op
 *
 * Returns 0 if successfully mounted, -1 on error
 */
static int
virStorageBackendFileSystemMount(virStoragePoolObjPtr pool)
{
    char *src = NULL;
    /* 'mount -t auto' doesn't seem to auto determine nfs (or cifs),
     *  while plain 'mount' does. We have to craft separate argvs to
     *  accommodate this */
    bool netauto = (pool->def->type == VIR_STORAGE_POOL_NETFS &&
                    pool->def->source.format == VIR_STORAGE_POOL_NETFS_AUTO);
    bool glusterfs = (pool->def->type == VIR_STORAGE_POOL_NETFS &&
                      pool->def->source.format == VIR_STORAGE_POOL_NETFS_GLUSTERFS);
    bool cifsfs = (pool->def->type == VIR_STORAGE_POOL_NETFS &&
                   pool->def->source.format == VIR_STORAGE_POOL_NETFS_CIFS);
    virCommandPtr cmd = NULL;
    int ret = -1;
    int rc;

    if (virStorageBackendFileSystemIsValid(pool) < 0)
        return -1;

    /* Short-circuit if already mounted */
    if ((rc = virStorageBackendFileSystemIsMounted(pool)) != 0) {
        if (rc == 1) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Target '%s' is already mounted"),
                           pool->def->target.path);
        }
        return -1;
    }

    if (!(src = virStorageBackendFileSystemGetPoolSource(pool)))
        return -1;

    if (netauto)
        cmd = virCommandNewArgList(MOUNT,
                                   src,
                                   pool->def->target.path,
                                   NULL);
    else if (glusterfs)
        cmd = virCommandNewArgList(MOUNT,
                                   "-t",
                                   virStoragePoolFormatFileSystemNetTypeToString(pool->def->source.format),
                                   src,
                                   "-o",
                                   "direct-io-mode=1",
                                   pool->def->target.path,
                                   NULL);
    else if (cifsfs)
        cmd = virCommandNewArgList(MOUNT,
                                   "-t",
                                   virStoragePoolFormatFileSystemNetTypeToString(pool->def->source.format),
                                   src,
                                   pool->def->target.path,
                                   "-o",
                                   "guest",
                                   NULL);
    else
        cmd = virCommandNewArgList(MOUNT,
                                   "-t",
                                   (pool->def->type == VIR_STORAGE_POOL_FS ?
                                    virStoragePoolFormatFileSystemTypeToString(pool->def->source.format) :
                                    virStoragePoolFormatFileSystemNetTypeToString(pool->def->source.format)),
                                   src,
                                   pool->def->target.path,
                                   NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    VIR_FREE(src);
    return ret;
}

/**
 * @pool storage pool to unmount
 *
 * Ensure that a FS storage pool is not mounted on its target location.
 * If already unmounted, this is a no-op.
 *
 * Returns 0 if successfully unmounted, -1 on error
 */
static int
virStorageBackendFileSystemUnmount(virStoragePoolObjPtr pool)
{
    virCommandPtr cmd = NULL;
    int ret = -1;
    int rc;

    if (virStorageBackendFileSystemIsValid(pool) < 0)
        return -1;

    /* Short-circuit if already unmounted */
    if ((rc = virStorageBackendFileSystemIsMounted(pool)) != 1)
        return rc;

    cmd = virCommandNewArgList(UMOUNT,
                               pool->def->target.path,
                               NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}
#endif /* WITH_STORAGE_FS */


static int
virStorageBackendFileSystemCheck(virStoragePoolObjPtr pool,
                                 bool *isActive)
{
    if (pool->def->type == VIR_STORAGE_POOL_DIR) {
        *isActive = virFileExists(pool->def->target.path);
#if WITH_STORAGE_FS
    } else {
        int ret;
        *isActive = false;

        if (virStorageBackendFileSystemIsValid(pool) < 0)
            return -1;

        if ((ret = virStorageBackendFileSystemIsMounted(pool)) != 0) {
            if (ret < 0)
                return -1;
            *isActive = true;
        }
#endif /* WITH_STORAGE_FS */
    }

    return 0;
}

#if WITH_STORAGE_FS
/**
 * @conn connection to report errors against
 * @pool storage pool to start
 *
 * Starts a directory or FS based storage pool.  The underlying source
 * device will be mounted for FS based pools.
 *
 * Returns 0 on success, -1 on error
 */
static int
virStorageBackendFileSystemStart(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool)
{
    if (pool->def->type != VIR_STORAGE_POOL_DIR &&
        virStorageBackendFileSystemMount(pool) < 0)
        return -1;

    return 0;
}
#endif /* WITH_STORAGE_FS */


/* some platforms don't support mkfs */
#ifdef MKFS
static int
virStorageBackendExecuteMKFS(const char *device,
                             const char *format)
{
    int ret = 0;
    virCommandPtr cmd = NULL;

    cmd = virCommandNewArgList(MKFS, "-t", format, NULL);

    /* use the force, otherwise mkfs.xfs won't overwrite existing fs.
     * Similarly mkfs.ext2, mkfs.ext3, and mkfs.ext4 require supplying -F
     * and mkfs.vfat uses -I */
    if (STREQ(format, "xfs"))
        virCommandAddArg(cmd, "-f");
    else if (STREQ(format, "ext2") ||
             STREQ(format, "ext3") ||
             STREQ(format, "ext4"))
        virCommandAddArg(cmd, "-F");
    else if (STREQ(format, "vfat"))
        virCommandAddArg(cmd, "-I");

    virCommandAddArg(cmd, device);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportSystemError(errno,
                             _("Failed to make filesystem of "
                               "type '%s' on device '%s'"),
                             format, device);
        ret = -1;
    }

    virCommandFree(cmd);
    return ret;
}
#else /* #ifdef MKFS */
static int
virStorageBackendExecuteMKFS(const char *device ATTRIBUTE_UNUSED,
                             const char *format ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("mkfs is not supported on this platform: "
                     "Failed to make filesystem of "
                     "type '%s' on device '%s'"),
                   format, device);
    return -1;
}
#endif /* #ifdef MKFS */

static int
virStorageBackendMakeFileSystem(virStoragePoolObjPtr pool,
                                unsigned int flags)
{
    const char *device = NULL, *format = NULL;
    bool ok_to_mkfs = false;
    int ret = -1;

    if (pool->def->source.devices == NULL) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("No source device specified when formatting pool '%s'"),
                       pool->def->name);
        goto error;
    }

    device = pool->def->source.devices[0].path;
    format = virStoragePoolFormatFileSystemTypeToString(pool->def->source.format);
    VIR_DEBUG("source device: '%s' format: '%s'", device, format);

    if (!virFileExists(device)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Source device does not exist when formatting pool '%s'"),
                       pool->def->name);
        goto error;
    }

    if (flags & VIR_STORAGE_POOL_BUILD_OVERWRITE) {
        ok_to_mkfs = true;
    } else if (flags & VIR_STORAGE_POOL_BUILD_NO_OVERWRITE &&
               virStorageBackendDeviceIsEmpty(device, format, true)) {
        ok_to_mkfs = true;
    }

    if (ok_to_mkfs)
        ret = virStorageBackendExecuteMKFS(device, format);

 error:
    return ret;
}


/**
 * @conn connection to report errors against
 * @pool storage pool to build
 * @flags controls the pool formatting behaviour
 *
 * Build a directory or FS based storage pool.
 *
 * If no flag is set, it only makes the directory.
 *
 * If VIR_STORAGE_POOL_BUILD_NO_OVERWRITE set, it probes to determine if
 * any filesystem already exists on the target device, returning an error
 * if one exists. If no filesystem already exists, use mkfs to format the
 * target device.
 *
 * If VIR_STORAGE_POOL_BUILD_OVERWRITE is set, mkfs is always executed and
 * any existing data on the target device is overwritten unconditionally.
 *
 * The underlying source device is mounted for FS based pools.
 *
 * Returns 0 on success, -1 on error
 */
static int
virStorageBackendFileSystemBuild(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool,
                                 unsigned int flags)
{
    int ret = -1;
    char *parent = NULL;
    char *p = NULL;
    mode_t mode;
    bool needs_create_as_uid;
    unsigned int dir_create_flags;

    virCheckFlags(VIR_STORAGE_POOL_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_BUILD_NO_OVERWRITE, ret);

    VIR_EXCLUSIVE_FLAGS_GOTO(VIR_STORAGE_POOL_BUILD_OVERWRITE,
                             VIR_STORAGE_POOL_BUILD_NO_OVERWRITE,
                             error);

    if (VIR_STRDUP(parent, pool->def->target.path) < 0)
        goto error;
    if (!(p = strrchr(parent, '/'))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("path '%s' is not absolute"),
                       pool->def->target.path);
        goto error;
    }

    if (p != parent) {
        /* assure all directories in the path prior to the final dir
         * exist, with default uid/gid/mode. */
        *p = '\0';
        if (virFileMakePath(parent) < 0) {
            virReportSystemError(errno, _("cannot create path '%s'"),
                                 parent);
            goto error;
        }
    }

    dir_create_flags = VIR_DIR_CREATE_ALLOW_EXIST;
    needs_create_as_uid = (pool->def->type == VIR_STORAGE_POOL_NETFS);
    mode = pool->def->target.perms.mode;

    if (mode == (mode_t) -1 &&
        (needs_create_as_uid || !virFileExists(pool->def->target.path)))
        mode = VIR_STORAGE_DEFAULT_POOL_PERM_MODE;
    if (needs_create_as_uid)
        dir_create_flags |= VIR_DIR_CREATE_AS_UID;

    /* Now create the final dir in the path with the uid/gid/mode
     * requested in the config. If the dir already exists, just set
     * the perms. */
    if (virDirCreate(pool->def->target.path,
                     mode,
                     pool->def->target.perms.uid,
                     pool->def->target.perms.gid,
                     dir_create_flags) < 0)
        goto error;

    if (flags != 0) {
        ret = virStorageBackendMakeFileSystem(pool, flags);
    } else {
        ret = 0;
    }

 error:
    VIR_FREE(parent);
    return ret;
}


/**
 * Iterate over the pool's directory and enumerate all disk images
 * within it. This is non-recursive.
 */
static int
virStorageBackendFileSystemRefresh(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   virStoragePoolObjPtr pool)
{
    DIR *dir;
    struct dirent *ent;
    struct statvfs sb;
    struct stat statbuf;
    virStorageVolDefPtr vol = NULL;
    virStorageSourcePtr target = NULL;
    int direrr;
    int fd = -1, ret = -1;

    if (virDirOpen(&dir, pool->def->target.path) < 0)
        goto cleanup;

    while ((direrr = virDirRead(dir, &ent, pool->def->target.path)) > 0) {
        int err;

        if (virStringHasControlChars(ent->d_name)) {
            VIR_WARN("Ignoring file with control characters under '%s'",
                     pool->def->target.path);
            continue;
        }

        if (VIR_ALLOC(vol) < 0)
            goto cleanup;

        if (VIR_STRDUP(vol->name, ent->d_name) < 0)
            goto cleanup;

        vol->type = VIR_STORAGE_VOL_FILE;
        vol->target.format = VIR_STORAGE_FILE_RAW; /* Real value is filled in during probe */
        if (virAsprintf(&vol->target.path, "%s/%s",
                        pool->def->target.path,
                        vol->name) == -1)
            goto cleanup;

        if (VIR_STRDUP(vol->key, vol->target.path) < 0)
            goto cleanup;

        if ((err = virStorageBackendProbeTarget(&vol->target,
                                                &vol->target.encryption)) < 0) {
            if (err == -2) {
                /* Silently ignore non-regular files,
                 * eg 'lost+found', dangling symbolic link */
                virStorageVolDefFree(vol);
                vol = NULL;
                continue;
            } else if (err == -3) {
                /* The backing file is currently unavailable, its format is not
                 * explicitly specified, the probe to auto detect the format
                 * failed: continue with faked RAW format, since AUTO will
                 * break virStorageVolTargetDefFormat() generating the line
                 * <format type='...'/>. */
            } else {
                goto cleanup;
            }
        }

        /* directory based volume */
        if (vol->target.format == VIR_STORAGE_FILE_DIR)
            vol->type = VIR_STORAGE_VOL_DIR;

        if (vol->target.format == VIR_STORAGE_FILE_PLOOP)
            vol->type = VIR_STORAGE_VOL_PLOOP;

        if (vol->target.backingStore) {
            ignore_value(virStorageBackendUpdateVolTargetInfo(vol->target.backingStore,
                                                              false,
                                                              VIR_STORAGE_VOL_OPEN_DEFAULT, 0));
            /* If this failed, the backing file is currently unavailable,
             * the capacity, allocation, owner, group and mode are unknown.
             * An error message was raised, but we just continue. */
        }

        if (VIR_APPEND_ELEMENT(pool->volumes.objs, pool->volumes.count, vol) < 0)
            goto cleanup;
    }
    if (direrr < 0)
        goto cleanup;
    VIR_DIR_CLOSE(dir);
    vol = NULL;

    if (VIR_ALLOC(target))
        goto cleanup;

    if ((fd = open(pool->def->target.path, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("cannot open path '%s'"),
                             pool->def->target.path);
        goto cleanup;
    }

    if (fstat(fd, &statbuf) < 0) {
        virReportSystemError(errno,
                             _("cannot stat path '%s'"),
                             pool->def->target.path);
        goto cleanup;
    }

    if (virStorageBackendUpdateVolTargetInfoFD(target, fd, &statbuf) < 0)
        goto cleanup;

    /* VolTargetInfoFD doesn't update capacity correctly for the pool case */
    if (statvfs(pool->def->target.path, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot statvfs path '%s'"),
                             pool->def->target.path);
        goto cleanup;
    }

    pool->def->capacity = ((unsigned long long)sb.f_frsize *
                           (unsigned long long)sb.f_blocks);
    pool->def->available = ((unsigned long long)sb.f_bfree *
                            (unsigned long long)sb.f_frsize);
    pool->def->allocation = pool->def->capacity - pool->def->available;

    pool->def->target.perms.mode = target->perms->mode;
    pool->def->target.perms.uid = target->perms->uid;
    pool->def->target.perms.gid = target->perms->gid;
    VIR_FREE(pool->def->target.perms.label);
    if (VIR_STRDUP(pool->def->target.perms.label, target->perms->label) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_DIR_CLOSE(dir);
    VIR_FORCE_CLOSE(fd);
    virStorageVolDefFree(vol);
    virStorageSourceFree(target);
    if (ret < 0)
        virStoragePoolObjClearVols(pool);
    return ret;
}


/**
 * @conn connection to report errors against
 * @pool storage pool to stop
 *
 * Stops a file storage pool.  The underlying source device is unmounted
 * for FS based pools.  Any cached data about volumes is released.
 *
 * Returns 0 on success, -1 on error.
 */
#if WITH_STORAGE_FS
static int
virStorageBackendFileSystemStop(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virStoragePoolObjPtr pool)
{
    if (virStorageBackendFileSystemUnmount(pool) < 0)
        return -1;

    return 0;
}
#endif /* WITH_STORAGE_FS */


/**
 * @conn connection to report errors against
 * @pool storage pool to delete
 *
 * Delete a directory based storage pool
 *
 * Returns 0 on success, -1 on error
 */
static int
virStorageBackendFileSystemDelete(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool,
                                  unsigned int flags)
{
    virCheckFlags(0, -1);

    /* XXX delete all vols first ? */

    if (rmdir(pool->def->target.path) < 0) {
        virReportSystemError(errno,
                             _("failed to remove pool '%s'"),
                             pool->def->target.path);
        return -1;
    }

    return 0;
}


/**
 * Set up a volume definition to be added to a pool's volume list, but
 * don't do any file creation or allocation. By separating the two processes,
 * we allow allocation progress reporting (by polling the volume's 'info'
 * function), and can drop the parent pool lock during the (slow) allocation.
 */
static int
virStorageBackendFileSystemVolCreate(virConnectPtr conn ATTRIBUTE_UNUSED,
                                     virStoragePoolObjPtr pool,
                                     virStorageVolDefPtr vol)
{

    if (vol->target.format == VIR_STORAGE_FILE_DIR)
        vol->type = VIR_STORAGE_VOL_DIR;
    else if (vol->target.format == VIR_STORAGE_FILE_PLOOP)
        vol->type = VIR_STORAGE_VOL_PLOOP;
    else
        vol->type = VIR_STORAGE_VOL_FILE;

    /* Volumes within a directory pools are not recursive; do not
     * allow escape to ../ or a subdir */
    if (strchr(vol->name, '/')) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume name '%s' cannot contain '/'"), vol->name);
        return -1;
    }

    VIR_FREE(vol->target.path);
    if (virAsprintf(&vol->target.path, "%s/%s",
                    pool->def->target.path,
                    vol->name) == -1)
        return -1;

    if (virFileExists(vol->target.path)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("volume target path '%s' already exists"),
                       vol->target.path);
        return -1;
    }

    VIR_FREE(vol->key);
    return VIR_STRDUP(vol->key, vol->target.path);
}

static int createFileDir(virConnectPtr conn ATTRIBUTE_UNUSED,
                         virStoragePoolObjPtr pool,
                         virStorageVolDefPtr vol,
                         virStorageVolDefPtr inputvol,
                         unsigned int flags)
{
    int err;

    virCheckFlags(0, -1);

    if (inputvol) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("cannot copy from volume to a directory volume"));
        return -1;
    }

    if (vol->target.backingStore) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("backing storage not supported for directories volumes"));
        return -1;
    }


    if ((err = virDirCreate(vol->target.path,
                            (vol->target.perms->mode == (mode_t) -1 ?
                             VIR_STORAGE_DEFAULT_VOL_PERM_MODE :
                             vol->target.perms->mode),
                            vol->target.perms->uid,
                            vol->target.perms->gid,
                            (pool->def->type == VIR_STORAGE_POOL_NETFS
                             ? VIR_DIR_CREATE_AS_UID : 0))) < 0) {
        return -1;
    }

    return 0;
}

static int
_virStorageBackendFileSystemVolBuild(virConnectPtr conn,
                                     virStoragePoolObjPtr pool,
                                     virStorageVolDefPtr vol,
                                     virStorageVolDefPtr inputvol,
                                     unsigned int flags)
{
    virStorageBackendBuildVolFrom create_func;

    if (inputvol) {
        if (vol->target.encryption != NULL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("storage pool does not support "
                                   "building encrypted volumes from "
                                   "other volumes"));
            return -1;
        }
        create_func = virStorageBackendGetBuildVolFromFunction(vol,
                                                               inputvol);
        if (!create_func)
            return -1;
    } else if (vol->target.format == VIR_STORAGE_FILE_RAW &&
               vol->target.encryption == NULL) {
        create_func = virStorageBackendCreateRaw;
    } else if (vol->target.format == VIR_STORAGE_FILE_DIR) {
        create_func = createFileDir;
    } else if (vol->target.format == VIR_STORAGE_FILE_PLOOP) {
        create_func = virStorageBackendCreatePloop;
    } else {
        create_func = virStorageBackendCreateQemuImg;
    }

    if (create_func(conn, pool, vol, inputvol, flags) < 0)
        return -1;
    return 0;
}

/**
 * Allocate a new file as a volume. This is either done directly
 * for raw/sparse files, or by calling qemu-img for
 * special kinds of files
 */
static int
virStorageBackendFileSystemVolBuild(virConnectPtr conn,
                                    virStoragePoolObjPtr pool,
                                    virStorageVolDefPtr vol,
                                    unsigned int flags)
{
    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA |
                  VIR_STORAGE_VOL_CREATE_REFLINK,
                  -1);

    return _virStorageBackendFileSystemVolBuild(conn, pool, vol, NULL, flags);
}

/*
 * Create a storage vol using 'inputvol' as input
 */
static int
virStorageBackendFileSystemVolBuildFrom(virConnectPtr conn,
                                        virStoragePoolObjPtr pool,
                                        virStorageVolDefPtr vol,
                                        virStorageVolDefPtr inputvol,
                                        unsigned int flags)
{
    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA |
                  VIR_STORAGE_VOL_CREATE_REFLINK,
                  -1);

    return _virStorageBackendFileSystemVolBuild(conn, pool, vol, inputvol, flags);
}

/**
 * Remove a volume - no support for BLOCK and NETWORK yet
 */
static int
virStorageBackendFileSystemVolDelete(virConnectPtr conn ATTRIBUTE_UNUSED,
                                     virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                     virStorageVolDefPtr vol,
                                     unsigned int flags)
{
    virCheckFlags(0, -1);

    switch ((virStorageVolType) vol->type) {
    case VIR_STORAGE_VOL_FILE:
    case VIR_STORAGE_VOL_DIR:
        if (virFileRemove(vol->target.path, vol->target.perms->uid,
                          vol->target.perms->gid) < 0) {
            /* Silently ignore failures where the vol has already gone away */
            if (errno != ENOENT) {
                if (vol->type == VIR_STORAGE_VOL_FILE)
                    virReportSystemError(errno,
                                         _("cannot unlink file '%s'"),
                                         vol->target.path);
                else
                    virReportSystemError(errno,
                                         _("cannot remove directory '%s'"),
                                         vol->target.path);
                return -1;
            }
        }
        break;
    case VIR_STORAGE_VOL_PLOOP:
        if (virFileDeleteTree(vol->target.path) < 0)
            return -1;
        break;
    case VIR_STORAGE_VOL_BLOCK:
    case VIR_STORAGE_VOL_NETWORK:
    case VIR_STORAGE_VOL_NETDIR:
    case VIR_STORAGE_VOL_LAST:
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("removing block or network volumes is not supported: %s"),
                       vol->target.path);
        return -1;
    }
    return 0;
}


/* virStorageBackendFileSystemLoadDefaultSecrets:
 * @conn: Connection pointer to fetch secret
 * @vol: volume being refreshed
 *
 * If the volume had a secret generated, we need to regenerate the
 * encryption secret information
 *
 * Returns 0 if no secret or secret setup was successful,
 * -1 on failures w/ error message set
 */
static int
virStorageBackendFileSystemLoadDefaultSecrets(virConnectPtr conn,
                                              virStorageVolDefPtr vol)
{
    virSecretPtr sec;
    virStorageEncryptionSecretPtr encsec = NULL;

    if (!vol->target.encryption || vol->target.encryption->nsecrets != 0)
        return 0;

    /* The encryption secret for qcow2 and luks volumes use the path
     * to the volume, so look for a secret with the path. If not found,
     * then we cannot generate the secret after a refresh (or restart).
     * This may be the case if someone didn't follow instructions and created
     * a usage string that although matched with the secret usage string,
     * didn't contain the path to the volume. We won't error in that case,
     * but we also cannot find the secret. */
    if (!(sec = virSecretLookupByUsage(conn, VIR_SECRET_USAGE_TYPE_VOLUME,
                                       vol->target.path)))
        return 0;

    if (VIR_ALLOC_N(vol->target.encryption->secrets, 1) < 0 ||
        VIR_ALLOC(encsec) < 0) {
        VIR_FREE(vol->target.encryption->secrets);
        virObjectUnref(sec);
        return -1;
    }

    vol->target.encryption->nsecrets = 1;
    vol->target.encryption->secrets[0] = encsec;

    encsec->type = VIR_STORAGE_ENCRYPTION_SECRET_TYPE_PASSPHRASE;
    encsec->seclookupdef.type = VIR_SECRET_LOOKUP_TYPE_UUID;
    virSecretGetUUID(sec, encsec->seclookupdef.u.uuid);
    virObjectUnref(sec);

    return 0;
}


/**
 * Update info about a volume's capacity/allocation
 */
static int
virStorageBackendFileSystemVolRefresh(virConnectPtr conn,
                                      virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                      virStorageVolDefPtr vol)
{
    int ret;

    /* Refresh allocation / capacity / permissions info in case its changed */
    if ((ret = virStorageBackendUpdateVolInfo(vol, false,
                                              VIR_STORAGE_VOL_FS_OPEN_FLAGS,
                                              0)) < 0)
        return ret;

    /* Load any secrets if possible */
    return virStorageBackendFileSystemLoadDefaultSecrets(conn, vol);
}

static int
virStorageBackendFilesystemResizeQemuImg(const char *path,
                                         unsigned long long capacity)
{
    int ret = -1;
    char *img_tool;
    virCommandPtr cmd = NULL;

    img_tool = virFindFileInPath("qemu-img");
    if (!img_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to find qemu-img"));
        return -1;
    }

    /* Round capacity as qemu-img resize errors out on sizes which are not
     * a multiple of 512 */
    capacity = VIR_ROUND_UP(capacity, 512);

    cmd = virCommandNew(img_tool);
    virCommandAddArgList(cmd, "resize", path, NULL);
    virCommandAddArgFormat(cmd, "%llu", capacity);

    ret = virCommandRun(cmd, NULL);

    VIR_FREE(img_tool);
    virCommandFree(cmd);

    return ret;
}

/**
 * Resize a volume
 */
static int
virStorageBackendFileSystemVolResize(virConnectPtr conn ATTRIBUTE_UNUSED,
                                     virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                     virStorageVolDefPtr vol,
                                     unsigned long long capacity,
                                     unsigned int flags)
{
    virCheckFlags(VIR_STORAGE_VOL_RESIZE_ALLOCATE |
                  VIR_STORAGE_VOL_RESIZE_SHRINK, -1);

    bool pre_allocate = flags & VIR_STORAGE_VOL_RESIZE_ALLOCATE;

    if (vol->target.format == VIR_STORAGE_FILE_RAW) {
        return virStorageFileResize(vol->target.path, capacity,
                                    vol->target.allocation, pre_allocate);
    } else if (vol->target.format == VIR_STORAGE_FILE_PLOOP) {
        return virStoragePloopResize(vol, capacity);
    } else {
        if (pre_allocate) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("preallocate is only supported for raw "
                             "type volume"));
            return -1;
        }

        return virStorageBackendFilesystemResizeQemuImg(vol->target.path,
                                                        capacity);
    }
}


virStorageBackend virStorageBackendDirectory = {
    .type = VIR_STORAGE_POOL_DIR,

    .buildPool = virStorageBackendFileSystemBuild,
    .checkPool = virStorageBackendFileSystemCheck,
    .refreshPool = virStorageBackendFileSystemRefresh,
    .deletePool = virStorageBackendFileSystemDelete,
    .buildVol = virStorageBackendFileSystemVolBuild,
    .buildVolFrom = virStorageBackendFileSystemVolBuildFrom,
    .createVol = virStorageBackendFileSystemVolCreate,
    .refreshVol = virStorageBackendFileSystemVolRefresh,
    .deleteVol = virStorageBackendFileSystemVolDelete,
    .resizeVol = virStorageBackendFileSystemVolResize,
    .uploadVol = virStorageBackendVolUploadLocal,
    .downloadVol = virStorageBackendVolDownloadLocal,
    .wipeVol = virStorageBackendVolWipeLocal,
};

#if WITH_STORAGE_FS
virStorageBackend virStorageBackendFileSystem = {
    .type = VIR_STORAGE_POOL_FS,

    .buildPool = virStorageBackendFileSystemBuild,
    .checkPool = virStorageBackendFileSystemCheck,
    .startPool = virStorageBackendFileSystemStart,
    .refreshPool = virStorageBackendFileSystemRefresh,
    .stopPool = virStorageBackendFileSystemStop,
    .deletePool = virStorageBackendFileSystemDelete,
    .buildVol = virStorageBackendFileSystemVolBuild,
    .buildVolFrom = virStorageBackendFileSystemVolBuildFrom,
    .createVol = virStorageBackendFileSystemVolCreate,
    .refreshVol = virStorageBackendFileSystemVolRefresh,
    .deleteVol = virStorageBackendFileSystemVolDelete,
    .resizeVol = virStorageBackendFileSystemVolResize,
    .uploadVol = virStorageBackendVolUploadLocal,
    .downloadVol = virStorageBackendVolDownloadLocal,
    .wipeVol = virStorageBackendVolWipeLocal,
};
virStorageBackend virStorageBackendNetFileSystem = {
    .type = VIR_STORAGE_POOL_NETFS,

    .buildPool = virStorageBackendFileSystemBuild,
    .checkPool = virStorageBackendFileSystemCheck,
    .startPool = virStorageBackendFileSystemStart,
    .findPoolSources = virStorageBackendFileSystemNetFindPoolSources,
    .refreshPool = virStorageBackendFileSystemRefresh,
    .stopPool = virStorageBackendFileSystemStop,
    .deletePool = virStorageBackendFileSystemDelete,
    .buildVol = virStorageBackendFileSystemVolBuild,
    .buildVolFrom = virStorageBackendFileSystemVolBuildFrom,
    .createVol = virStorageBackendFileSystemVolCreate,
    .refreshVol = virStorageBackendFileSystemVolRefresh,
    .deleteVol = virStorageBackendFileSystemVolDelete,
    .resizeVol = virStorageBackendFileSystemVolResize,
    .uploadVol = virStorageBackendVolUploadLocal,
    .downloadVol = virStorageBackendVolDownloadLocal,
    .wipeVol = virStorageBackendVolWipeLocal,
};


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
    int fd = -1;
    mode_t mode = S_IRUSR;

    if (!src->readonly)
        mode |= S_IWUSR;

    if ((fd = virFileOpenAs(src->path, O_WRONLY | O_TRUNC | O_CREAT, mode,
                            src->drv->uid, src->drv->gid, 0)) < 0) {
        errno = -fd;
        return -1;
    }

    VIR_FORCE_CLOSE(fd);
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
virStorageFileBackendFileReadHeader(virStorageSourcePtr src,
                                    ssize_t max_len,
                                    char **buf)
{
    int fd = -1;
    ssize_t ret = -1;

    if ((fd = virFileOpenAs(src->path, O_RDONLY, 0,
                            src->drv->uid, src->drv->gid, 0)) < 0) {
        virReportSystemError(-fd, _("Failed to open file '%s'"),
                             src->path);
        return -1;
    }

    if ((ret = virFileReadHeaderFD(fd, max_len, buf)) < 0) {
        virReportSystemError(errno,
                             _("cannot read header '%s'"), src->path);
        goto cleanup;
    }

 cleanup:
    VIR_FORCE_CLOSE(fd);

    return ret;
}


static const char *
virStorageFileBackendFileGetUniqueIdentifier(virStorageSourcePtr src)
{
    virStorageFileBackendFsPrivPtr priv = src->drv->priv;

    if (!priv->canonpath) {
        if (!(priv->canonpath = canonicalize_file_name(src->path))) {
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
    .storageFileReadHeader = virStorageFileBackendFileReadHeader,
    .storageFileAccess = virStorageFileBackendFileAccess,
    .storageFileChown = virStorageFileBackendFileChown,

    .storageFileGetUniqueIdentifier = virStorageFileBackendFileGetUniqueIdentifier,
};


virStorageFileBackend virStorageFileBackendBlock = {
    .type = VIR_STORAGE_TYPE_BLOCK,

    .backendInit = virStorageFileBackendFileInit,
    .backendDeinit = virStorageFileBackendFileDeinit,

    .storageFileStat = virStorageFileBackendFileStat,
    .storageFileReadHeader = virStorageFileBackendFileReadHeader,
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

#endif /* WITH_STORAGE_FS */
