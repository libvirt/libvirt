/*
 * storage_backend_fs.c: storage backend for FS and directory handling
 *
 * Copyright (C) 2007-2013 Red Hat, Inc.
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

#if WITH_BLKID
# include <blkid/blkid.h>
#endif

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

#define VIR_STORAGE_VOL_FS_OPEN_FLAGS       (VIR_STORAGE_VOL_OPEN_DEFAULT   |\
                                             VIR_STORAGE_VOL_OPEN_DIR)
#define VIR_STORAGE_VOL_FS_REFRESH_FLAGS    (VIR_STORAGE_VOL_FS_OPEN_FLAGS  &\
                                             ~VIR_STORAGE_VOL_OPEN_ERROR)

static int ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
virStorageBackendProbeTarget(virStorageVolTargetPtr target,
                             char **backingStore,
                             int *backingStoreFormat,
                             unsigned long long *allocation,
                             unsigned long long *capacity,
                             virStorageEncryptionPtr *encryption)
{
    int fd = -1;
    int ret = -1;
    virStorageFileMetadata *meta = NULL;
    struct stat sb;
    char *header = NULL;
    ssize_t len = VIR_STORAGE_MAX_HEADER;

    *backingStore = NULL;
    *backingStoreFormat = VIR_STORAGE_FILE_AUTO;
    if (encryption)
        *encryption = NULL;

    if ((ret = virStorageBackendVolOpenCheckMode(target->path, &sb,
                                        VIR_STORAGE_VOL_FS_REFRESH_FLAGS)) < 0)
        goto error; /* Take care to propagate ret, it is not always -1 */
    fd = ret;

    if ((ret = virStorageBackendUpdateVolTargetInfoFD(target, fd, &sb,
                                                      allocation,
                                                      capacity)) < 0) {
        goto error;
    }

    if (S_ISDIR(sb.st_mode)) {
        target->format = VIR_STORAGE_FILE_DIR;
    } else {
        if ((len = virFileReadHeaderFD(fd, len, &header)) < 0) {
            virReportSystemError(errno, _("cannot read header '%s'"),
                                 target->path);
            goto error;
        }

        target->format = virStorageFileProbeFormatFromBuf(target->path,
                                                          header, len);
        if (target->format < 0) {
            ret = -1;
            goto error;
        }

        if (!(meta = virStorageFileGetMetadataFromBuf(target->path,
                                                      header, len,
                                                      target->format))) {
            ret = -1;
            goto error;
        }
    }

    VIR_FORCE_CLOSE(fd);

    if (meta && meta->backingStore) {
        *backingStore = meta->backingStore;
        meta->backingStore = NULL;
        if (meta->backingStoreFormat == VIR_STORAGE_FILE_AUTO &&
            meta->backingStoreIsFile) {
            if ((ret = virStorageFileProbeFormat(*backingStore, -1, -1)) < 0) {
                /* If the backing file is currently unavailable, only log an error,
                 * but continue. Returning -1 here would disable the whole storage
                 * pool, making it unavailable for even maintenance. */
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot probe backing volume format: %s"),
                               *backingStore);
                ret = -3;
            } else {
                *backingStoreFormat = ret;
                ret = 0;
            }
        } else {
            *backingStoreFormat = meta->backingStoreFormat;
            ret = 0;
        }
    } else {
        ret = 0;
    }

    if (capacity && meta && meta->capacity)
        *capacity = meta->capacity;

    if (encryption && meta && meta->encrypted) {
        if (VIR_ALLOC(*encryption) < 0)
            goto cleanup;

        switch (target->format) {
        case VIR_STORAGE_FILE_QCOW:
        case VIR_STORAGE_FILE_QCOW2:
            (*encryption)->format = VIR_STORAGE_ENCRYPTION_FORMAT_QCOW;
            break;
        default:
            break;
        }

        /* XXX ideally we'd fill in secret UUID here
         * but we cannot guarantee 'conn' is non-NULL
         * at this point in time :-(  So we only fill
         * in secrets when someone first queries a vol
         */
    }

    virBitmapFree(target->features);
    if (meta) {
        target->features = meta->features;
        meta->features = NULL;
    }

    if (meta && meta->compat) {
        VIR_FREE(target->compat);
        target->compat = meta->compat;
        meta->compat = NULL;
    }

    goto cleanup;

error:
    VIR_FORCE_CLOSE(fd);

cleanup:
    virStorageFileFreeMetadata(meta);
    VIR_FREE(header);
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
virStorageBackendFileSystemNetFindPoolSourcesFunc(virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                                  char **const groups,
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


static char *
virStorageBackendFileSystemNetFindPoolSources(virConnectPtr conn ATTRIBUTE_UNUSED,
                                              const char *srcSpec,
                                              unsigned int flags)
{
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
    virNetfsDiscoverState state = {
        .host = NULL,
        .list = {
            .type = VIR_STORAGE_POOL_NETFS,
            .nsources = 0,
            .sources = NULL
        }
    };
    virStoragePoolSourcePtr source = NULL;
    char *retval = NULL;
    size_t i;
    virCommandPtr cmd = NULL;

    virCheckFlags(0, NULL);

    if (!srcSpec) {
        virReportError(VIR_ERR_INVALID_ARG,
                       "%s", _("hostname must be specified for netfs sources"));
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

    cmd = virCommandNewArgList(SHOWMOUNT,
                               "--no-headers",
                               "--exports",
                               source->hosts[0].name,
                               NULL);

    if (virStorageBackendRunProgRegex(NULL, cmd, 1, regexes, vars,
                            virStorageBackendFileSystemNetFindPoolSourcesFunc,
                            &state, NULL) < 0)
        goto cleanup;

    retval = virStoragePoolSourceListFormat(&state.list);
    if (retval == NULL)
        goto cleanup;

 cleanup:
    for (i = 0; i < state.list.nsources; i++)
        virStoragePoolSourceClear(&state.list.sources[i]);
    VIR_FREE(state.list.sources);

    virStoragePoolSourceFree(source);
    virCommandFree(cmd);
    return retval;
}


/**
 * @conn connection to report errors against
 * @pool storage pool to check for status
 *
 * Determine if a storage pool is already mounted
 *
 * Return 0 if not mounted, 1 if mounted, -1 on error
 */
static int
virStorageBackendFileSystemIsMounted(virStoragePoolObjPtr pool) {
    FILE *mtab;
    struct mntent ent;
    char buf[1024];

    if ((mtab = fopen(_PATH_MOUNTED, "r")) == NULL) {
        virReportSystemError(errno,
                             _("cannot read mount list '%s'"),
                             _PATH_MOUNTED);
        return -1;
    }

    while ((getmntent_r(mtab, &ent, buf, sizeof(buf))) != NULL) {
        if (STREQ(ent.mnt_dir, pool->def->target.path)) {
            VIR_FORCE_FCLOSE(mtab);
            return 1;
        }
    }

    VIR_FORCE_FCLOSE(mtab);
    return 0;
}

/**
 * @conn connection to report errors against
 * @pool storage pool to mount
 *
 * Ensure that a FS storage pool is mounted on its target location.
 * If already mounted, this is a no-op
 *
 * Returns 0 if successfully mounted, -1 on error
 */
static int
virStorageBackendFileSystemMount(virStoragePoolObjPtr pool) {
    char *src = NULL;
    /* 'mount -t auto' doesn't seem to auto determine nfs (or cifs),
     *  while plain 'mount' does. We have to craft separate argvs to
     *  accommodate this */
    bool netauto = (pool->def->type == VIR_STORAGE_POOL_NETFS &&
                    pool->def->source.format == VIR_STORAGE_POOL_NETFS_AUTO);
    bool glusterfs = (pool->def->type == VIR_STORAGE_POOL_NETFS &&
                      pool->def->source.format == VIR_STORAGE_POOL_NETFS_GLUSTERFS);
    virCommandPtr cmd = NULL;
    int ret = -1;
    int rc;

    if (pool->def->type == VIR_STORAGE_POOL_NETFS) {
        if (pool->def->source.nhost != 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Expected exactly 1 host for the storage pool"));
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
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing source device"));
            return -1;
        }
    }

    /* Short-circuit if already mounted */
    if ((rc = virStorageBackendFileSystemIsMounted(pool)) != 0) {
        if (rc == 1) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Target '%s' is already mounted"),
                           pool->def->target.path);
        }
        return -1;
    }

    if (pool->def->type == VIR_STORAGE_POOL_NETFS) {
        if (virAsprintf(&src, "%s:%s",
                        pool->def->source.hosts[0].name,
                        pool->def->source.dir) == -1)
            return -1;

    } else {
        if (VIR_STRDUP(src, pool->def->source.devices[0].path) < 0)
            return -1;
    }

    if (netauto)
        cmd = virCommandNewArgList(MOUNT,
                                   src,
                                   pool->def->target.path,
                                   NULL);
    else if (glusterfs)
        cmd = virCommandNewArgList(MOUNT,
                                   "-t",
                                   (pool->def->type == VIR_STORAGE_POOL_FS ?
                                    virStoragePoolFormatFileSystemTypeToString(pool->def->source.format) :
                                    virStoragePoolFormatFileSystemNetTypeToString(pool->def->source.format)),
                                   src,
                                   "-o",
                                   "direct-io-mode=1",
                                   pool->def->target.path,
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
 * @conn connection to report errors against
 * @pool storage pool to unmount
 *
 * Ensure that a FS storage pool is not mounted on its target location.
 * If already unmounted, this is a no-op
 *
 * Returns 0 if successfully unmounted, -1 on error
 */
static int
virStorageBackendFileSystemUnmount(virStoragePoolObjPtr pool) {
    virCommandPtr cmd = NULL;
    int ret = -1;
    int rc;

    if (pool->def->type == VIR_STORAGE_POOL_NETFS) {
        if (pool->def->source.nhost != 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Expected exactly 1 host for the storage pool"));
            return -1;
        }
        if (pool->def->source.hosts[0].name == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing source host"));
            return -1;
        }
        if (pool->def->source.dir == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing source dir"));
            return -1;
        }
    } else {
        if (pool->def->source.ndevice != 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing source device"));
            return -1;
        }
    }

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
virStorageBackendFileSystemCheck(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool,
                                 bool *isActive)
{
    if (pool->def->type == VIR_STORAGE_POOL_DIR) {
        *isActive = virFileExists(pool->def->target.path);
#if WITH_STORAGE_FS
    } else {
        int ret;
        *isActive = false;
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
 * Starts a directory or FS based storage pool.
 *
 *  - If it is a FS based pool, mounts the unlying source device on the pool
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

#if WITH_BLKID
static virStoragePoolProbeResult
virStorageBackendFileSystemProbe(const char *device,
                                 const char *format) {

    virStoragePoolProbeResult ret = FILESYSTEM_PROBE_ERROR;
    blkid_probe probe = NULL;
    const char *fstype = NULL;
    char *names[2], *libblkid_format = NULL;

    VIR_DEBUG("Probing for existing filesystem of type %s on device %s",
              format, device);

    if (blkid_known_fstype(format) == 0) {
        virReportError(VIR_ERR_STORAGE_PROBE_FAILED,
                       _("Not capable of probing for "
                         "filesystem of type %s"),
                       format);
        goto error;
    }

    probe = blkid_new_probe_from_filename(device);
    if (probe == NULL) {
        virReportError(VIR_ERR_STORAGE_PROBE_FAILED,
                       _("Failed to create filesystem probe "
                         "for device %s"),
                       device);
        goto error;
    }

    if (VIR_STRDUP(libblkid_format, format) < 0)
        goto error;

    names[0] = libblkid_format;
    names[1] = NULL;

    blkid_probe_filter_superblocks_type(probe,
                                        BLKID_FLTR_ONLYIN,
                                        names);

    if (blkid_do_probe(probe) != 0) {
        VIR_INFO("No filesystem of type '%s' found on device '%s'",
                 format, device);
        ret = FILESYSTEM_PROBE_NOT_FOUND;
    } else if (blkid_probe_lookup_value(probe, "TYPE", &fstype, NULL) == 0) {
        virReportError(VIR_ERR_STORAGE_POOL_BUILT,
                       _("Existing filesystem of type '%s' found on "
                         "device '%s'"),
                       fstype, device);
        ret = FILESYSTEM_PROBE_FOUND;
    }

    if (blkid_do_probe(probe) != 1) {
        virReportError(VIR_ERR_STORAGE_PROBE_FAILED, "%s",
                       _("Found additional probes to run, "
                         "filesystem probing may be incorrect"));
        ret = FILESYSTEM_PROBE_ERROR;
    }

error:
    VIR_FREE(libblkid_format);

    if (probe != NULL) {
        blkid_free_probe(probe);
    }

    return ret;
}

#else /* #if WITH_BLKID */

static virStoragePoolProbeResult
virStorageBackendFileSystemProbe(const char *device ATTRIBUTE_UNUSED,
                                 const char *format ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("probing for filesystems is unsupported "
                     "by this build"));

    return FILESYSTEM_PROBE_ERROR;
}

#endif /* #if WITH_BLKID */

/* some platforms don't support mkfs */
#ifdef MKFS
static int
virStorageBackendExecuteMKFS(const char *device,
                             const char *format)
{
    int ret = 0;
    virCommandPtr cmd = NULL;

    cmd = virCommandNewArgList(MKFS,
                               "-t",
                               format,
                               device,
                               NULL);

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
               virStorageBackendFileSystemProbe(device, format) ==
               FILESYSTEM_PROBE_NOT_FOUND) {
        ok_to_mkfs = true;
    }

    if (ok_to_mkfs) {
        ret = virStorageBackendExecuteMKFS(device, format);
    }

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
 * If no flag is set, it only makes the directory; If
 * VIR_STORAGE_POOL_BUILD_NO_OVERWRITE set, it probes to determine if
 * filesystem already exists on the target device, renurning an error
 * if exists, or using mkfs to format the target device if not; If
 * VIR_STORAGE_POOL_BUILD_OVERWRITE is set, mkfs is always executed,
 * any existed data on the target device is overwritten unconditionally.
 *
 *  - If it is a FS based pool, mounts the unlying source device on the pool
 *
 * Returns 0 on success, -1 on error
 */
static int
virStorageBackendFileSystemBuild(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool,
                                 unsigned int flags)
{
    int err, ret = -1;
    char *parent = NULL;
    char *p = NULL;

    virCheckFlags(VIR_STORAGE_POOL_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_BUILD_NO_OVERWRITE, ret);

    if (flags == (VIR_STORAGE_POOL_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_BUILD_NO_OVERWRITE)) {

        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Overwrite and no overwrite flags"
                         " are mutually exclusive"));
        goto error;
    }

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

    /* Now create the final dir in the path with the uid/gid/mode
     * requested in the config. If the dir already exists, just set
     * the perms. */
    if ((err = virDirCreate(pool->def->target.path,
                            pool->def->target.perms.mode,
                            pool->def->target.perms.uid,
                            pool->def->target.perms.gid,
                            VIR_DIR_CREATE_FORCE_PERMS |
                            VIR_DIR_CREATE_ALLOW_EXIST |
                            (pool->def->type == VIR_STORAGE_POOL_NETFS
                            ? VIR_DIR_CREATE_AS_UID : 0)) < 0)) {
        virReportSystemError(-err, _("cannot create path '%s'"),
                             pool->def->target.path);
        goto error;
    }

    /* Reflect the actual uid and gid to the config. */
    if (pool->def->target.perms.uid == (uid_t) -1)
        pool->def->target.perms.uid = geteuid();
    if (pool->def->target.perms.gid == (gid_t) -1)
        pool->def->target.perms.gid = getegid();

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
    virStorageVolDefPtr vol = NULL;

    if (!(dir = opendir(pool->def->target.path))) {
        virReportSystemError(errno,
                             _("cannot open path '%s'"),
                             pool->def->target.path);
        goto cleanup;
    }

    while ((ent = readdir(dir)) != NULL) {
        int ret;
        char *backingStore;
        int backingStoreFormat;

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

        if ((ret = virStorageBackendProbeTarget(&vol->target,
                                                &backingStore,
                                                &backingStoreFormat,
                                                &vol->allocation,
                                                &vol->capacity,
                                                &vol->target.encryption)) < 0) {
            if (ret == -2) {
                /* Silently ignore non-regular files,
                 * eg '.' '..', 'lost+found', dangling symbolic link */
                virStorageVolDefFree(vol);
                vol = NULL;
                continue;
            } else if (ret == -3) {
                /* The backing file is currently unavailable, its format is not
                 * explicitly specified, the probe to auto detect the format
                 * failed: continue with faked RAW format, since AUTO will
                 * break virStorageVolTargetDefFormat() generating the line
                 * <format type='...'/>. */
                backingStoreFormat = VIR_STORAGE_FILE_RAW;
            } else
                goto cleanup;
        }

        /* directory based volume */
        if (vol->target.format == VIR_STORAGE_FILE_DIR)
            vol->type = VIR_STORAGE_VOL_DIR;

        if (backingStore != NULL) {
            vol->backingStore.path = backingStore;
            vol->backingStore.format = backingStoreFormat;

            if (virStorageBackendUpdateVolTargetInfo(&vol->backingStore,
                                        NULL, NULL,
                                        VIR_STORAGE_VOL_OPEN_DEFAULT) < 0) {
                /* The backing file is currently unavailable, the capacity,
                 * allocation, owner, group and mode are unknown. Just log the
                 * error and continue.
                 * Unfortunately virStorageBackendProbeTarget() might already
                 * have logged a similar message for the same problem, but only
                 * if AUTO format detection was used. */
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot probe backing volume info: %s"),
                               vol->backingStore.path);
            }
        }


        if (VIR_REALLOC_N(pool->volumes.objs,
                          pool->volumes.count+1) < 0)
            goto cleanup;
        pool->volumes.objs[pool->volumes.count++] = vol;
        vol = NULL;
    }
    closedir(dir);


    if (statvfs(pool->def->target.path, &sb) < 0) {
        virReportSystemError(errno,
                             _("cannot statvfs path '%s'"),
                             pool->def->target.path);
        return -1;
    }
    pool->def->capacity = ((unsigned long long)sb.f_frsize *
                           (unsigned long long)sb.f_blocks);
    pool->def->available = ((unsigned long long)sb.f_bfree *
                            (unsigned long long)sb.f_frsize);
    pool->def->allocation = pool->def->capacity - pool->def->available;

    return 0;

 cleanup:
    if (dir)
        closedir(dir);
    virStorageVolDefFree(vol);
    virStoragePoolObjClearVols(pool);
    return -1;
}


/**
 * @conn connection to report errors against
 * @pool storage pool to start
 *
 * Stops a FS based storage pool.
 *
 *  - If it is a FS based pool, unmounts the unlying source device on the pool
 *  - Releases all cached data about volumes
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
 * @pool storage pool to build
 *
 * Build a directory or FS based storage pool.
 *
 *  - If it is a FS based pool, mounts the unlying source device on the pool
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

    vol->type = VIR_STORAGE_VOL_FILE;

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

    if ((err = virDirCreate(vol->target.path, vol->target.perms.mode,
                            vol->target.perms.uid,
                            vol->target.perms.gid,
                            VIR_DIR_CREATE_FORCE_PERMS |
                            (pool->def->type == VIR_STORAGE_POOL_NETFS
                             ? VIR_DIR_CREATE_AS_UID : 0))) < 0) {
        virReportSystemError(-err, _("cannot create path '%s'"),
                             vol->target.path);
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
    int tool_type;

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
    } else if (vol->target.format == VIR_STORAGE_FILE_RAW) {
        create_func = virStorageBackendCreateRaw;
    } else if (vol->target.format == VIR_STORAGE_FILE_DIR) {
        create_func = createFileDir;
    } else if ((tool_type = virStorageBackendFindFSImageTool(NULL)) != -1) {
        create_func = virStorageBackendFSImageToolTypeToFunc(tool_type);

        if (!create_func)
            return -1;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("creation of non-raw images "
                               "is not supported without qemu-img"));
        return -1;
    }

    if (create_func(conn, pool, vol, inputvol, flags) < 0)
        return -1;
    return 0;
}

/**
 * Allocate a new file as a volume. This is either done directly
 * for raw/sparse files, or by calling qemu-img/qcow-create for
 * special kinds of files
 */
static int
virStorageBackendFileSystemVolBuild(virConnectPtr conn,
                                    virStoragePoolObjPtr pool,
                                    virStorageVolDefPtr vol,
                                    unsigned int flags)
{
    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, -1);

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
    virCheckFlags(VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA, -1);

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
        if (unlink(vol->target.path) < 0) {
            /* Silently ignore failures where the vol has already gone away */
            if (errno != ENOENT) {
                virReportSystemError(errno,
                                     _("cannot unlink file '%s'"),
                                     vol->target.path);
                return -1;
            }
        }
        break;
    case VIR_STORAGE_VOL_DIR:
        if (rmdir(vol->target.path) < 0) {
            virReportSystemError(errno,
                                 _("cannot remove directory '%s'"),
                                 vol->target.path);
            return -1;
        }
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


/**
 * Update info about a volume's capacity/allocation
 */
static int
virStorageBackendFileSystemVolRefresh(virConnectPtr conn,
                                      virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                      virStorageVolDefPtr vol)
{
    int ret;

    /* Refresh allocation / permissions info in case its changed */
    ret = virStorageBackendUpdateVolInfoFlags(vol, 0,
                                              VIR_STORAGE_VOL_FS_OPEN_FLAGS);
    if (ret < 0)
        return ret;

    /* Load any secrets if posible */
    if (vol->target.encryption &&
        vol->target.encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_QCOW &&
        vol->target.encryption->nsecrets == 0) {
        virSecretPtr sec;
        virStorageEncryptionSecretPtr encsec = NULL;

        sec = virSecretLookupByUsage(conn,
                                     VIR_SECRET_USAGE_TYPE_VOLUME,
                                     vol->target.path);
        if (sec) {
            if (VIR_ALLOC_N(vol->target.encryption->secrets, 1) < 0 ||
                VIR_ALLOC(encsec) < 0) {
                VIR_FREE(vol->target.encryption->secrets);
                virSecretFree(sec);
                return -1;
            }

            vol->target.encryption->nsecrets = 1;
            vol->target.encryption->secrets[0] = encsec;

            encsec->type = VIR_STORAGE_ENCRYPTION_SECRET_TYPE_PASSPHRASE;
            virSecretGetUUID(sec, encsec->uuid);
            virSecretFree(sec);
        }
    }

    return 0;
}

static int
virStorageBackendFilesystemResizeQemuImg(const char *path,
                                         unsigned long long capacity)
{
    int ret = -1;
    char *img_tool;
    virCommandPtr cmd = NULL;

    /* KVM is usually ahead of qemu on features, so try that first */
    img_tool = virFindFileInPath("kvm-img");
    if (!img_tool)
        img_tool = virFindFileInPath("qemu-img");

    if (!img_tool) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unable to find kvm-img or qemu-img"));
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
    virCheckFlags(VIR_STORAGE_VOL_RESIZE_ALLOCATE, -1);

    bool pre_allocate = flags & VIR_STORAGE_VOL_RESIZE_ALLOCATE;

    if (vol->target.format == VIR_STORAGE_FILE_RAW) {
        return virStorageFileResize(vol->target.path, capacity,
                                    vol->capacity, pre_allocate);
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
};
#endif /* WITH_STORAGE_FS */
