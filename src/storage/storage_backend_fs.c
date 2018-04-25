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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include "virerror.h"
#include "storage_backend_fs.h"
#include "storage_util.h"
#include "storage_conf.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_fs");

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
virStorageBackendFileSystemNetFindPoolSources(const char *srcSpec,
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
    int retNFS = -1;
    int retGluster = 0;

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

    retGluster = virStorageBackendFindGlusterPoolSources(state.host,
                                                         VIR_STORAGE_POOL_NETFS,
                                                         &state.list, false);

    if (retGluster < 0)
        goto cleanup;

    /* If both fail, then we won't return an empty list - return an error */
    if (retNFS < 0 && retGluster == 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("no storage pools were found on host '%s'"),
                       state.host);
        goto cleanup;
    }

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
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);

    if (def->type == VIR_STORAGE_POOL_NETFS) {
        if (def->source.nhost != 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("expected exactly 1 host for the storage pool"));
            return -1;
        }
        if (def->source.hosts[0].name == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing source host"));
            return -1;
        }
        if (def->source.dir == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing source path"));
            return -1;
        }
    } else {
        if (def->source.ndevice != 1) {
            if (def->source.ndevice == 0)
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
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    char *src = NULL;

    if (def->type == VIR_STORAGE_POOL_NETFS) {
        if (def->source.format == VIR_STORAGE_POOL_NETFS_CIFS) {
            if (virAsprintf(&src, "//%s/%s",
                            def->source.hosts[0].name,
                            def->source.dir) < 0)
                return NULL;
        } else {
            if (virAsprintf(&src, "%s:%s",
                            def->source.hosts[0].name,
                            def->source.dir) < 0)
                return NULL;
        }
    } else {
        if (VIR_STRDUP(src, def->source.devices[0].path) < 0)
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
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    char *src = NULL;
    FILE *mtab;
    struct mntent ent;
    char buf[1024];
    int rc1, rc2;

    if ((mtab = fopen(_PATH_MOUNTED, "r")) == NULL) {
        virReportSystemError(errno,
                             _("cannot read mount list '%s'"),
                             _PATH_MOUNTED);
        goto cleanup;
    }

    while ((getmntent_r(mtab, &ent, buf, sizeof(buf))) != NULL) {
        if (!(src = virStorageBackendFileSystemGetPoolSource(pool)))
            goto cleanup;

        /* compare both mount destinations and sources to be sure the mounted
         * FS pool is really the one we're looking for
         */
        if ((rc1 = virFileComparePaths(ent.mnt_dir, def->target.path)) < 0 ||
            (rc2 = virFileComparePaths(ent.mnt_fsname, src)) < 0)
            goto cleanup;

        if (rc1 && rc2) {
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
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    char *src = NULL;
    /* 'mount -t auto' doesn't seem to auto determine nfs (or cifs),
     *  while plain 'mount' does. We have to craft separate argvs to
     *  accommodate this */
    bool netauto = (def->type == VIR_STORAGE_POOL_NETFS &&
                    def->source.format == VIR_STORAGE_POOL_NETFS_AUTO);
    bool glusterfs = (def->type == VIR_STORAGE_POOL_NETFS &&
                      def->source.format == VIR_STORAGE_POOL_NETFS_GLUSTERFS);
    bool cifsfs = (def->type == VIR_STORAGE_POOL_NETFS &&
                   def->source.format == VIR_STORAGE_POOL_NETFS_CIFS);
    virCommandPtr cmd = NULL;
    int ret = -1;
    int rc;

    if (virStorageBackendFileSystemIsValid(pool) < 0)
        return -1;

    if ((rc = virStorageBackendFileSystemIsMounted(pool)) < 0)
        return -1;

    /* Short-circuit if already mounted */
    if (rc == 1) {
        VIR_INFO("Target '%s' is already mounted", def->target.path);
        return 0;
    }

    if (!(src = virStorageBackendFileSystemGetPoolSource(pool)))
        return -1;

    if (netauto)
        cmd = virCommandNewArgList(MOUNT,
                                   src,
                                   def->target.path,
                                   NULL);
    else if (glusterfs)
        cmd = virCommandNewArgList(MOUNT,
                                   "-t",
                                   virStoragePoolFormatFileSystemNetTypeToString(def->source.format),
                                   src,
                                   "-o",
                                   "direct-io-mode=1",
                                   def->target.path,
                                   NULL);
    else if (cifsfs)
        cmd = virCommandNewArgList(MOUNT,
                                   "-t",
                                   virStoragePoolFormatFileSystemNetTypeToString(def->source.format),
                                   src,
                                   def->target.path,
                                   "-o",
                                   "guest",
                                   NULL);
    else
        cmd = virCommandNewArgList(MOUNT,
                                   "-t",
                                   (def->type == VIR_STORAGE_POOL_FS ?
                                    virStoragePoolFormatFileSystemTypeToString(def->source.format) :
                                    virStoragePoolFormatFileSystemNetTypeToString(def->source.format)),
                                   src,
                                   def->target.path,
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
 * @pool storage pool to start
 *
 * Starts a directory or FS based storage pool.  The underlying source
 * device will be mounted for FS based pools.
 *
 * Returns 0 on success, -1 on error
 */
static int
virStorageBackendFileSystemStart(virStoragePoolObjPtr pool)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);

    if (def->type != VIR_STORAGE_POOL_DIR &&
        virStorageBackendFileSystemMount(pool) < 0)
        return -1;

    return 0;
}


/**
 * @pool storage pool to unmount
 *
 * Stops a file storage pool.  The underlying source device is unmounted
 * for FS based pools.  Any cached data about volumes is released.
 *
 * Ensure that a FS storage pool is not mounted on its target location.
 * If already unmounted, this is a no-op.
 *
 * Returns 0 if successfully unmounted, -1 on error
 */
static int
virStorageBackendFileSystemStop(virStoragePoolObjPtr pool)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    virCommandPtr cmd = NULL;
    int ret = -1;
    int rc;

    if (virStorageBackendFileSystemIsValid(pool) < 0)
        return -1;

    /* Short-circuit if already unmounted */
    if ((rc = virStorageBackendFileSystemIsMounted(pool)) != 1)
        return rc;

    cmd = virCommandNewArgList(UMOUNT, def->target.path, NULL);
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
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);

    if (def->type == VIR_STORAGE_POOL_DIR) {
        *isActive = virFileExists(def->target.path);
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
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    const char *device = NULL, *format = NULL;
    bool ok_to_mkfs = false;
    int ret = -1;

    if (def->source.devices == NULL) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("No source device specified when formatting pool '%s'"),
                       def->name);
        goto error;
    }

    device = def->source.devices[0].path;
    format = virStoragePoolFormatFileSystemTypeToString(def->source.format);
    VIR_DEBUG("source device: '%s' format: '%s'", device, format);

    if (!virFileExists(device)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Source device does not exist when formatting pool '%s'"),
                       def->name);
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
virStorageBackendFileSystemBuild(virStoragePoolObjPtr pool,
                                 unsigned int flags)
{
    virCheckFlags(VIR_STORAGE_POOL_BUILD_OVERWRITE |
                  VIR_STORAGE_POOL_BUILD_NO_OVERWRITE, -1);

    VIR_EXCLUSIVE_FLAGS_RET(VIR_STORAGE_POOL_BUILD_OVERWRITE,
                            VIR_STORAGE_POOL_BUILD_NO_OVERWRITE,
                            -1);

    if (virStorageBackendBuildLocal(pool) < 0)
        return -1;

    if (flags != 0)
        return virStorageBackendMakeFileSystem(pool, flags);

    return 0;
}


virStorageBackend virStorageBackendDirectory = {
    .type = VIR_STORAGE_POOL_DIR,

    .buildPool = virStorageBackendFileSystemBuild,
    .checkPool = virStorageBackendFileSystemCheck,
    .refreshPool = virStorageBackendRefreshLocal,
    .deletePool = virStorageBackendDeleteLocal,
    .buildVol = virStorageBackendVolBuildLocal,
    .buildVolFrom = virStorageBackendVolBuildFromLocal,
    .createVol = virStorageBackendVolCreateLocal,
    .refreshVol = virStorageBackendVolRefreshLocal,
    .deleteVol = virStorageBackendVolDeleteLocal,
    .resizeVol = virStorageBackendVolResizeLocal,
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
    .refreshPool = virStorageBackendRefreshLocal,
    .stopPool = virStorageBackendFileSystemStop,
    .deletePool = virStorageBackendDeleteLocal,
    .buildVol = virStorageBackendVolBuildLocal,
    .buildVolFrom = virStorageBackendVolBuildFromLocal,
    .createVol = virStorageBackendVolCreateLocal,
    .refreshVol = virStorageBackendVolRefreshLocal,
    .deleteVol = virStorageBackendVolDeleteLocal,
    .resizeVol = virStorageBackendVolResizeLocal,
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
    .refreshPool = virStorageBackendRefreshLocal,
    .stopPool = virStorageBackendFileSystemStop,
    .deletePool = virStorageBackendDeleteLocal,
    .buildVol = virStorageBackendVolBuildLocal,
    .buildVolFrom = virStorageBackendVolBuildFromLocal,
    .createVol = virStorageBackendVolCreateLocal,
    .refreshVol = virStorageBackendVolRefreshLocal,
    .deleteVol = virStorageBackendVolDeleteLocal,
    .resizeVol = virStorageBackendVolResizeLocal,
    .uploadVol = virStorageBackendVolUploadLocal,
    .downloadVol = virStorageBackendVolDownloadLocal,
    .wipeVol = virStorageBackendVolWipeLocal,
};
#endif /* WITH_STORAGE_FS */


int
virStorageBackendFsRegister(void)
{
    if (virStorageBackendRegister(&virStorageBackendDirectory) < 0)
        return -1;

#if WITH_STORAGE_FS
    if (virStorageBackendRegister(&virStorageBackendFileSystem) < 0)
        return -1;

    if (virStorageBackendRegister(&virStorageBackendNetFileSystem) < 0)
        return -1;
#endif /* WITH_STORAGE_FS */

    return 0;
}
