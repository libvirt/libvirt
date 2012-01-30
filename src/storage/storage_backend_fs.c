/*
 * storage_backend_fs.c: storage backend for FS and directory handling
 *
 * Copyright (C) 2007-2011 Red Hat, Inc.
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

#if HAVE_LIBBLKID
# include <blkid/blkid.h>
#endif

#include "virterror_internal.h"
#include "storage_backend_fs.h"
#include "storage_conf.h"
#include "storage_file.h"
#include "command.h"
#include "memory.h"
#include "xml.h"
#include "virfile.h"
#include "logging.h"

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
    virStorageFileMetadata *meta;

    if (VIR_ALLOC(meta) < 0) {
        virReportOOMError();
        return ret;
    }

    *backingStore = NULL;
    *backingStoreFormat = VIR_STORAGE_FILE_AUTO;
    if (encryption)
        *encryption = NULL;

    if ((ret = virStorageBackendVolOpenCheckMode(target->path,
                                        VIR_STORAGE_VOL_FS_REFRESH_FLAGS)) < 0)
        goto error; /* Take care to propagate ret, it is not always -1 */
    fd = ret;

    if ((ret = virStorageBackendUpdateVolTargetInfoFD(target, fd,
                                                      allocation,
                                                      capacity)) < 0) {
        goto error;
    }

    if ((target->format = virStorageFileProbeFormatFromFD(target->path, fd)) < 0) {
        ret = -1;
        goto error;
    }

    if (virStorageFileGetMetadataFromFD(target->path, fd,
                                        target->format,
                                        meta) < 0) {
        ret = -1;
        goto error;
    }

    VIR_FORCE_CLOSE(fd);

    if (meta->backingStore) {
        *backingStore = meta->backingStore;
        meta->backingStore = NULL;
        if (meta->backingStoreFormat == VIR_STORAGE_FILE_AUTO) {
            if ((ret = virStorageFileProbeFormat(*backingStore)) < 0) {
                /* If the backing file is currently unavailable, only log an error,
                 * but continue. Returning -1 here would disable the whole storage
                 * pool, making it unavailable for even maintenance. */
                virStorageReportError(VIR_ERR_INTERNAL_ERROR,
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

    if (capacity && meta->capacity)
        *capacity = meta->capacity;

    if (encryption != NULL && meta->encrypted) {
        if (VIR_ALLOC(*encryption) < 0) {
            virReportOOMError();
            goto cleanup;
        }

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

    virStorageFileFreeMetadata(meta);

    return ret;

error:
    VIR_FORCE_CLOSE(fd);

cleanup:
    virStorageFileFreeMetadata(meta);
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

    name = strrchr(path, '/');
    if (name == NULL) {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("invalid netfs path (no /): %s"), path);
        goto cleanup;
    }
    name += 1;
    if (*name == '\0') {
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              _("invalid netfs path (ends in /): %s"), path);
        goto cleanup;
    }

    if (!(src = virStoragePoolSourceListNewSource(&state->list)))
        goto cleanup;

    if (!(src->host.name = strdup(state->host)) ||
        !(src->dir = strdup(path))) {
        virReportOOMError();
        goto cleanup;
    }
    src->format = VIR_STORAGE_POOL_NETFS_NFS;

    src = NULL;
    ret = 0;
cleanup:
    virStoragePoolSourceFree(src);
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
    const char *prog[] = { SHOWMOUNT, "--no-headers", "--exports", NULL, NULL };
    virStoragePoolSourcePtr source = NULL;
    char *retval = NULL;
    unsigned int i;

    virCheckFlags(0, NULL);

    source = virStoragePoolDefParseSourceString(srcSpec,
                                                VIR_STORAGE_POOL_NETFS);
    if (!source)
        goto cleanup;

    state.host = source->host.name;
    prog[3] = source->host.name;

    if (virStorageBackendRunProgRegex(NULL, prog, 1, regexes, vars,
                            virStorageBackendFileSystemNetFindPoolSourcesFunc,
                            &state, NULL) < 0)
        goto cleanup;

    retval = virStoragePoolSourceListFormat(&state.list);
    if (retval == NULL) {
        virReportOOMError();
        goto cleanup;
    }

 cleanup:
    for (i = 0; i < state.list.nsources; i++)
        virStoragePoolSourceClear(&state.list.sources[i]);
    VIR_FREE(state.list.sources);

    virStoragePoolSourceFree(source);

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
    char *src;
    const char **mntargv;

    /* 'mount -t auto' doesn't seem to auto determine nfs (or cifs),
     *  while plain 'mount' does. We have to craft separate argvs to
     *  accommodate this */
    int netauto = (pool->def->type == VIR_STORAGE_POOL_NETFS &&
                   pool->def->source.format == VIR_STORAGE_POOL_NETFS_AUTO);
    int glusterfs = (pool->def->type == VIR_STORAGE_POOL_NETFS &&
                 pool->def->source.format == VIR_STORAGE_POOL_NETFS_GLUSTERFS);

    int source_index;

    const char *netfs_auto_argv[] = {
        MOUNT,
        NULL, /* source path */
        pool->def->target.path,
        NULL,
    };

    const char *fs_argv[] =  {
        MOUNT,
        "-t",
        pool->def->type == VIR_STORAGE_POOL_FS ?
        virStoragePoolFormatFileSystemTypeToString(pool->def->source.format) :
        virStoragePoolFormatFileSystemNetTypeToString(pool->def->source.format),
        NULL, /* Fill in shortly - careful not to add extra fields
                 before this */
        pool->def->target.path,
        NULL,
    };

    const char *glusterfs_argv[] = {
        MOUNT,
        "-t",
        pool->def->type == VIR_STORAGE_POOL_FS ?
        virStoragePoolFormatFileSystemTypeToString(pool->def->source.format) :
        virStoragePoolFormatFileSystemNetTypeToString(pool->def->source.format),
        NULL,
        "-o",
        "direct-io-mode=1",
        pool->def->target.path,
        NULL,
    };

    if (netauto) {
        mntargv = netfs_auto_argv;
        source_index = 1;
    } else if (glusterfs) {
        mntargv = glusterfs_argv;
        source_index = 3;
    } else {
        mntargv = fs_argv;
        source_index = 3;
    }

    int ret;

    if (pool->def->type == VIR_STORAGE_POOL_NETFS) {
        if (pool->def->source.host.name == NULL) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source host"));
            return -1;
        }
        if (pool->def->source.dir == NULL) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source path"));
            return -1;
        }
    } else {
        if (pool->def->source.ndevice != 1) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source device"));
            return -1;
        }
    }

    /* Short-circuit if already mounted */
    if ((ret = virStorageBackendFileSystemIsMounted(pool)) != 0) {
        if (ret < 0)
            return -1;
        else
            return 0;
    }

    if (pool->def->type == VIR_STORAGE_POOL_NETFS) {
        if (virAsprintf(&src, "%s:%s",
                        pool->def->source.host.name,
                        pool->def->source.dir) == -1) {
            virReportOOMError();
            return -1;
        }

    } else {
        if ((src = strdup(pool->def->source.devices[0].path)) == NULL) {
            virReportOOMError();
            return -1;
        }
    }
    mntargv[source_index] = src;

    if (virRun(mntargv, NULL) < 0) {
        VIR_FREE(src);
        return -1;
    }
    VIR_FREE(src);
    return 0;
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
    const char *mntargv[3];
    int ret;

    if (pool->def->type == VIR_STORAGE_POOL_NETFS) {
        if (pool->def->source.host.name == NULL) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source host"));
            return -1;
        }
        if (pool->def->source.dir == NULL) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source dir"));
            return -1;
        }
    } else {
        if (pool->def->source.ndevice != 1) {
            virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("missing source device"));
            return -1;
        }
    }

    /* Short-circuit if already unmounted */
    if ((ret = virStorageBackendFileSystemIsMounted(pool)) != 1) {
        if (ret < 0)
            return -1;
        else
            return 0;
    }

    mntargv[0] = UMOUNT;
    mntargv[1] = pool->def->target.path;
    mntargv[2] = NULL;

    if (virRun(mntargv, NULL) < 0) {
        return -1;
    }
    return 0;
}
#endif /* WITH_STORAGE_FS */


static int
virStorageBackendFileSystemCheck(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virStoragePoolObjPtr pool,
                                 bool *isActive)
{
    *isActive = false;
    if (pool->def->type == VIR_STORAGE_POOL_DIR) {
        if (access(pool->def->target.path, F_OK) == 0)
            *isActive = true;
#if WITH_STORAGE_FS
    } else {
        int ret;
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

#if HAVE_LIBBLKID
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
        virStorageReportError(VIR_ERR_STORAGE_PROBE_FAILED,
                              _("Not capable of probing for "
                                "filesystem of type %s"),
                              format);
        goto error;
    }

    probe = blkid_new_probe_from_filename(device);
    if (probe == NULL) {
        virStorageReportError(VIR_ERR_STORAGE_PROBE_FAILED,
                                  _("Failed to create filesystem probe "
                                  "for device %s"),
                                  device);
        goto error;
    }

    if ((libblkid_format = strdup(format)) == NULL) {
        virReportOOMError();
        goto error;
    }

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
        virStorageReportError(VIR_ERR_STORAGE_POOL_BUILT,
                              _("Existing filesystem of type '%s' found on "
                                "device '%s'"),
                              fstype, device);
        ret = FILESYSTEM_PROBE_FOUND;
    }

    if (blkid_do_probe(probe) != 1) {
        virStorageReportError(VIR_ERR_STORAGE_PROBE_FAILED,
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

#else /* #if HAVE_LIBBLKID */

static virStoragePoolProbeResult
virStorageBackendFileSystemProbe(const char *device ATTRIBUTE_UNUSED,
                                 const char *format ATTRIBUTE_UNUSED)
{
    virStorageReportError(VIR_ERR_OPERATION_INVALID,
                          _("probing for filesystems is unsupported "
                            "by this build"));

    return FILESYSTEM_PROBE_ERROR;
}

#endif /* #if HAVE_LIBBLKID */

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
    return ret;
}
#else /* #ifdef MKFS */
static int
virStorageBackendExecuteMKFS(const char *device ATTRIBUTE_UNUSED,
                             const char *format ATTRIBUTE_UNUSED)
{
    virStorageReportError(VIR_ERR_INTERNAL_ERROR,
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
        virStorageReportError(VIR_ERR_OPERATION_INVALID,
                              _("No source device specified when formatting pool '%s'"),
                              pool->def->name);
        goto error;
    }

    device = pool->def->source.devices[0].path;
    format = virStoragePoolFormatFileSystemTypeToString(pool->def->source.format);
    VIR_DEBUG("source device: '%s' format: '%s'", device, format);

    if (!virFileExists(device)) {
        virStorageReportError(VIR_ERR_OPERATION_INVALID,
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

        virStorageReportError(VIR_ERR_OPERATION_INVALID,
                              _("Overwrite and no overwrite flags"
                                " are mutually exclusive"));
        goto error;
    }

    if ((parent = strdup(pool->def->target.path)) == NULL) {
        virReportOOMError();
        goto error;
    }
    if (!(p = strrchr(parent, '/'))) {
        virStorageReportError(VIR_ERR_INVALID_ARG,
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

    struct stat st;

    if ((stat(pool->def->target.path, &st) < 0)
        || (pool->def->target.perms.uid != -1)) {

        uid_t uid = (pool->def->target.perms.uid == -1)
            ? getuid() : pool->def->target.perms.uid;
        gid_t gid = (pool->def->target.perms.gid == -1)
            ? getgid() : pool->def->target.perms.gid;

        if ((err = virDirCreate(pool->def->target.path,
                                pool->def->target.perms.mode,
                                uid, gid,
                                VIR_DIR_CREATE_FORCE_PERMS |
                                VIR_DIR_CREATE_ALLOW_EXIST |
                                (pool->def->type == VIR_STORAGE_POOL_NETFS
                                 ? VIR_DIR_CREATE_AS_UID : 0)) < 0)) {
            virReportSystemError(-err, _("cannot create path '%s'"),
                                 pool->def->target.path);
            goto error;
        }
    }

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
            goto no_memory;

        if ((vol->name = strdup(ent->d_name)) == NULL)
            goto no_memory;

        vol->type = VIR_STORAGE_VOL_FILE;
        vol->target.format = VIR_STORAGE_FILE_RAW; /* Real value is filled in during probe */
        if (virAsprintf(&vol->target.path, "%s/%s",
                        pool->def->target.path,
                        vol->name) == -1)
            goto no_memory;

        if ((vol->key = strdup(vol->target.path)) == NULL)
            goto no_memory;

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
                virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                                      _("cannot probe backing volume info: %s"),
                                      vol->backingStore.path);
            }
        }


        if (VIR_REALLOC_N(pool->volumes.objs,
                          pool->volumes.count+1) < 0)
            goto no_memory;
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
                            (unsigned long long)sb.f_bsize);
    pool->def->allocation = pool->def->capacity - pool->def->available;

    return 0;

no_memory:
    virReportOOMError();
    /* fallthrough */

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
 * Stops a directory or FS based storage pool.
 *
 *  - If it is a FS based pool, unmounts the unlying source device on the pool
 *  - Releases all cached data about volumes
 */
#if WITH_STORAGE_FS
static int
virStorageBackendFileSystemStop(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virStoragePoolObjPtr pool)
{
    if (pool->def->type != VIR_STORAGE_POOL_DIR &&
        virStorageBackendFileSystemUnmount(pool) < 0)
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
                    vol->name) == -1) {
        virReportOOMError();
        return -1;
    }

    VIR_FREE(vol->key);
    vol->key = strdup(vol->target.path);
    if (vol->key == NULL) {
        virReportOOMError();
        return -1;
    }

    return 0;
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
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s",
                              _("cannot copy from volume to a directory volume"));
        return -1;
    }

    uid_t uid = (vol->target.perms.uid == -1)
        ? getuid() : vol->target.perms.uid;
    gid_t gid = (vol->target.perms.gid == -1)
        ? getgid() : vol->target.perms.gid;

    if ((err = virDirCreate(vol->target.path, vol->target.perms.mode,
                            uid, gid,
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
                                     virStorageVolDefPtr inputvol)
{
    virStorageBackendBuildVolFrom create_func;
    int tool_type;

    if (inputvol) {
        if (vol->target.encryption != NULL) {
            virStorageReportError(VIR_ERR_CONFIG_UNSUPPORTED,
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
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("creation of non-raw images "
                                      "is not supported without qemu-img"));
        return -1;
    }

    if (create_func(conn, pool, vol, inputvol, 0) < 0)
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
                                    virStorageVolDefPtr vol) {
    return _virStorageBackendFileSystemVolBuild(conn, pool, vol, NULL);
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
    virCheckFlags(0, -1);

    return _virStorageBackendFileSystemVolBuild(conn, pool, vol, inputvol);
}

/**
 * Remove a volume - just unlinks for now
 */
static int
virStorageBackendFileSystemVolDelete(virConnectPtr conn ATTRIBUTE_UNUSED,
                                     virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                     virStorageVolDefPtr vol,
                                     unsigned int flags)
{
    virCheckFlags(0, -1);

    if (unlink(vol->target.path) < 0) {
        /* Silently ignore failures where the vol has already gone away */
        if (errno != ENOENT) {
            virReportSystemError(errno,
                                 _("cannot unlink file '%s'"),
                                 vol->target.path);
            return -1;
        }
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
                virReportOOMError();
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
        virStorageReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("unable to find kvm-img or qemu-img"));
        return -1;
    }

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
    virCheckFlags(0, -1);

    if (vol->target.format == VIR_STORAGE_FILE_RAW)
        return virStorageFileResize(vol->target.path, capacity);
    else
        return virStorageBackendFilesystemResizeQemuImg(vol->target.path,
                                                        capacity);
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
