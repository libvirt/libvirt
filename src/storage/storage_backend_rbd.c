/*
 * storage_backend_rbd.c: storage backend for RBD (RADOS Block Device) handling
 *
 * Copyright (C) 2013-2016 Red Hat, Inc.
 * Copyright (C) 2012 Wido den Hollander
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
 * Author: Wido den Hollander <wido@widodh.nl>
 */

#include <config.h>

#include <inttypes.h>
#include "datatypes.h"
#include "virerror.h"
#include "storage_backend_rbd.h"
#include "storage_conf.h"
#include "viralloc.h"
#include "virlog.h"
#include "base64.h"
#include "viruuid.h"
#include "virstring.h"
#include "virrandom.h"
#include "rados/librados.h"
#include "rbd/librbd.h"
#include "secret_util.h"
#include "storage_util.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_rbd");

struct _virStorageBackendRBDState {
    rados_t cluster;
    rados_ioctx_t ioctx;
    time_t starttime;
};

typedef struct _virStorageBackendRBDState virStorageBackendRBDState;
typedef virStorageBackendRBDState *virStorageBackendRBDStatePtr;

static int
virStorageBackendRBDRADOSConfSet(rados_t cluster,
                                 const char *option,
                                 const char *value)
{
    VIR_DEBUG("Setting RADOS option '%s' to '%s'",
              option, value);
    if (rados_conf_set(cluster, option, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to set RADOS option: %s"),
                       option);
        return -1;
    }

    return 0;
}

static int
virStorageBackendRBDOpenRADOSConn(virStorageBackendRBDStatePtr ptr,
                                  virConnectPtr conn,
                                  virStoragePoolSourcePtr source)
{
    int ret = -1;
    int r = 0;
    virStorageAuthDefPtr authdef = source->auth;
    unsigned char *secret_value = NULL;
    size_t secret_value_size = 0;
    char *rados_key = NULL;
    virBuffer mon_host = VIR_BUFFER_INITIALIZER;
    size_t i;
    char *mon_buff = NULL;
    const char *client_mount_timeout = "30";
    const char *mon_op_timeout = "30";
    const char *osd_op_timeout = "30";
    const char *rbd_default_format = "2";

    if (authdef) {
        VIR_DEBUG("Using cephx authorization, username: %s", authdef->username);

        if ((r = rados_create(&ptr->cluster, authdef->username)) < 0) {
            virReportSystemError(-r, "%s", _("failed to initialize RADOS"));
            goto cleanup;
        }

        if (!conn) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'ceph' authentication not supported "
                             "for autostarted pools"));
            return -1;
        }

        if (virSecretGetSecretString(conn, &authdef->seclookupdef,
                                     VIR_SECRET_USAGE_TYPE_CEPH,
                                     &secret_value, &secret_value_size) < 0)
            goto cleanup;

        if (!(rados_key = virStringEncodeBase64(secret_value, secret_value_size)))
            goto cleanup;

        if (virStorageBackendRBDRADOSConfSet(ptr->cluster,
                                             "key", rados_key) < 0)
            goto cleanup;

        if (virStorageBackendRBDRADOSConfSet(ptr->cluster,
                                             "auth_supported", "cephx") < 0)
            goto cleanup;
    } else {
        VIR_DEBUG("Not using cephx authorization");
        if (rados_create(&ptr->cluster, NULL) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to create the RADOS cluster"));
            goto cleanup;
        }
        if (virStorageBackendRBDRADOSConfSet(ptr->cluster,
                                             "auth_supported", "none") < 0)
            goto cleanup;
    }

    VIR_DEBUG("Found %zu RADOS cluster monitors in the pool configuration",
              source->nhost);

    for (i = 0; i < source->nhost; i++) {
        if (source->hosts[i].name != NULL &&
            !source->hosts[i].port) {
            virBufferAsprintf(&mon_host, "%s,",
                              source->hosts[i].name);
        } else if (source->hosts[i].name != NULL &&
            source->hosts[i].port) {
            virBufferAsprintf(&mon_host, "%s:%d,",
                              source->hosts[i].name,
                              source->hosts[i].port);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("received malformed monitor, check the XML definition"));
        }
    }

    if (virBufferCheckError(&mon_host) < 0)
        goto cleanup;

    mon_buff = virBufferContentAndReset(&mon_host);
    if (virStorageBackendRBDRADOSConfSet(ptr->cluster,
                                         "mon_host",
                                         mon_buff) < 0)
        goto cleanup;

    /*
     * Set timeout options for librados.
     * In case the Ceph cluster is down libvirt won't block forever.
     * Operations in librados will return -ETIMEDOUT when the timeout is reached.
     */
    if (virStorageBackendRBDRADOSConfSet(ptr->cluster,
                                         "client_mount_timeout",
                                         client_mount_timeout) < 0)
        goto cleanup;

    if (virStorageBackendRBDRADOSConfSet(ptr->cluster,
                                         "rados_mon_op_timeout",
                                         mon_op_timeout) < 0)
        goto cleanup;

    if (virStorageBackendRBDRADOSConfSet(ptr->cluster,
                                         "rados_osd_op_timeout",
                                         osd_op_timeout) < 0)
        goto cleanup;

    /*
     * Librbd supports creating RBD format 2 images. We no longer have to invoke
     * rbd_create3(), we can tell librbd to default to format 2.
     * This leaves us to simply use rbd_create() and use the default behavior of librbd
     */
    if (virStorageBackendRBDRADOSConfSet(ptr->cluster,
                                         "rbd_default_format",
                                         rbd_default_format) < 0)
        goto cleanup;

    ptr->starttime = time(0);
    if ((r = rados_connect(ptr->cluster)) < 0) {
        virReportSystemError(-r, _("failed to connect to the RADOS monitor on: %s"),
                             mon_buff);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_DISPOSE_N(secret_value, secret_value_size);
    VIR_DISPOSE_STRING(rados_key);

    virBufferFreeAndReset(&mon_host);
    VIR_FREE(mon_buff);
    return ret;
}

static int
virStorageBackendRBDOpenIoCTX(virStorageBackendRBDStatePtr ptr,
                              virStoragePoolObjPtr pool)
{
    int r = rados_ioctx_create(ptr->cluster, pool->def->source.name, &ptr->ioctx);
    if (r < 0) {
        virReportSystemError(-r, _("failed to create the RBD IoCTX. Does the pool '%s' exist?"),
                             pool->def->source.name);
    }
    return r;
}

static void
virStorageBackendRBDCloseRADOSConn(virStorageBackendRBDStatePtr ptr)
{
    if (ptr->ioctx != NULL) {
        VIR_DEBUG("Closing RADOS IoCTX");
        rados_ioctx_destroy(ptr->ioctx);
    }
    ptr->ioctx = NULL;

    if (ptr->cluster != NULL) {
        VIR_DEBUG("Closing RADOS connection");
        rados_shutdown(ptr->cluster);
    }
    ptr->cluster = NULL;

    VIR_DEBUG("RADOS connection existed for %ld seconds",
              time(0) - ptr->starttime);
}


static void
virStorageBackendRBDFreeState(virStorageBackendRBDStatePtr *ptr)
{
    if (!*ptr)
        return;

    virStorageBackendRBDCloseRADOSConn(*ptr);

    VIR_FREE(*ptr);
}


static virStorageBackendRBDStatePtr
virStorageBackendRBDNewState(virConnectPtr conn,
                             virStoragePoolObjPtr pool)
{
    virStorageBackendRBDStatePtr ptr;

    if (VIR_ALLOC(ptr) < 0)
        return NULL;

    if (virStorageBackendRBDOpenRADOSConn(ptr, conn, &pool->def->source) < 0)
        goto error;

    if (virStorageBackendRBDOpenIoCTX(ptr, pool) < 0)
        goto error;

    return ptr;

 error:
    virStorageBackendRBDFreeState(&ptr);
    return NULL;
}


static int
volStorageBackendRBDGetFeatures(rbd_image_t image,
                                const char *volname,
                                uint64_t *features)
{
    int r, ret = -1;

    if ((r = rbd_get_features(image, features)) < 0) {
        virReportSystemError(-r, _("failed to get the features of RBD image "
                                 "%s"), volname);
        goto cleanup;
    }
    ret = 0;

 cleanup:
    return ret;
}

#if LIBRBD_VERSION_CODE > 265
static bool
volStorageBackendRBDUseFastDiff(uint64_t features)
{
    return features & RBD_FEATURE_FAST_DIFF;
}

static int
virStorageBackendRBDRefreshVolInfoCb(uint64_t offset ATTRIBUTE_UNUSED,
                                     size_t len,
                                     int exists,
                                     void *arg)
{
    size_t *used_size = (size_t *)(arg);
    if (exists)
        (*used_size) += len;

    return 0;
}

static int
virStorageBackendRBDSetAllocation(virStorageVolDefPtr vol,
                                  rbd_image_t *image,
                                  rbd_image_info_t *info)
{
    int r, ret = -1;
    size_t allocation = 0;

    if ((r = rbd_diff_iterate2(image, NULL, 0, info->size, 0, 1,
                               &virStorageBackendRBDRefreshVolInfoCb,
                               &allocation)) < 0) {
        virReportSystemError(-r, _("failed to iterate RBD image '%s'"),
                             vol->name);
        goto cleanup;
    }

    VIR_DEBUG("Found %zu bytes allocated for RBD image %s",
              allocation, vol->name);

    vol->target.allocation = allocation;
    ret = 0;

 cleanup:
    return ret;
}

#else
static int
volStorageBackendRBDUseFastDiff(uint64_t features ATTRIBUTE_UNUSED)
{
    return false;
}

static int
virStorageBackendRBDSetAllocation(virStorageVolDefPtr vol ATTRIBUTE_UNUSED,
                                  rbd_image_t *image ATTRIBUTE_UNUSED,
                                  rbd_image_info_t *info ATTRIBUTE_UNUSED)
{
    return false;
}
#endif

static int
volStorageBackendRBDRefreshVolInfo(virStorageVolDefPtr vol,
                                   virStoragePoolObjPtr pool,
                                   virStorageBackendRBDStatePtr ptr)
{
    int ret = -1;
    int r = 0;
    rbd_image_t image = NULL;
    rbd_image_info_t info;
    uint64_t features;

    if ((r = rbd_open_read_only(ptr->ioctx, vol->name, &image, NULL)) < 0) {
        ret = -r;
        virReportSystemError(-r, _("failed to open the RBD image '%s'"),
                             vol->name);
        goto cleanup;
    }

    if ((r = rbd_stat(image, &info, sizeof(info))) < 0) {
        ret = -r;
        virReportSystemError(-r, _("failed to stat the RBD image '%s'"),
                             vol->name);
        goto cleanup;
    }

    if (volStorageBackendRBDGetFeatures(image, vol->name, &features) < 0)
        goto cleanup;

    vol->target.capacity = info.size;
    vol->type = VIR_STORAGE_VOL_NETWORK;
    vol->target.format = VIR_STORAGE_FILE_RAW;

    if (volStorageBackendRBDUseFastDiff(features)) {
        VIR_DEBUG("RBD image %s/%s has fast-diff feature enabled. "
                  "Querying for actual allocation",
                  pool->def->source.name, vol->name);

        if (virStorageBackendRBDSetAllocation(vol, image, &info) < 0)
            goto cleanup;
    } else {
        vol->target.allocation = info.obj_size * info.num_objs;
    }

    VIR_DEBUG("Refreshed RBD image %s/%s (capacity: %llu allocation: %llu "
                      "obj_size: %"PRIu64" num_objs: %"PRIu64")",
              pool->def->source.name, vol->name, vol->target.capacity,
              vol->target.allocation, info.obj_size, info.num_objs);

    VIR_FREE(vol->target.path);
    if (virAsprintf(&vol->target.path, "%s/%s",
                    pool->def->source.name,
                    vol->name) < 0)
        goto cleanup;

    VIR_FREE(vol->key);
    if (virAsprintf(&vol->key, "%s/%s",
                    pool->def->source.name,
                    vol->name) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (image)
        rbd_close(image);
    return ret;
}

static int
virStorageBackendRBDRefreshPool(virConnectPtr conn,
                                virStoragePoolObjPtr pool)
{
    size_t max_size = 1024;
    int ret = -1;
    int len = -1;
    int r = 0;
    char *name, *names = NULL;
    virStorageBackendRBDStatePtr ptr = NULL;
    struct rados_cluster_stat_t clusterstat;
    struct rados_pool_stat_t poolstat;

    if (!(ptr = virStorageBackendRBDNewState(conn, pool)))
        goto cleanup;

    if ((r = rados_cluster_stat(ptr->cluster, &clusterstat)) < 0) {
        virReportSystemError(-r, "%s", _("failed to stat the RADOS cluster"));
        goto cleanup;
    }

    if ((r = rados_ioctx_pool_stat(ptr->ioctx, &poolstat)) < 0) {
        virReportSystemError(-r, _("failed to stat the RADOS pool '%s'"),
                             pool->def->source.name);
        goto cleanup;
    }

    pool->def->capacity = clusterstat.kb * 1024;
    pool->def->available = clusterstat.kb_avail * 1024;
    pool->def->allocation = poolstat.num_bytes;

    VIR_DEBUG("Utilization of RBD pool %s: (kb: %"PRIu64" kb_avail: %"PRIu64
              " num_bytes: %"PRIu64")",
              pool->def->source.name, clusterstat.kb, clusterstat.kb_avail,
              poolstat.num_bytes);

    while (true) {
        if (VIR_ALLOC_N(names, max_size) < 0)
            goto cleanup;

        len = rbd_list(ptr->ioctx, names, &max_size);
        if (len >= 0)
            break;
        if (len != -ERANGE) {
            VIR_WARN("%s", "A problem occurred while listing RBD images");
            goto cleanup;
        }
        VIR_FREE(names);
    }

    for (name = names; name < names + max_size;) {
        virStorageVolDefPtr vol;

        if (STREQ(name, ""))
            break;

        if (VIR_ALLOC(vol) < 0)
            goto cleanup;

        if (VIR_STRDUP(vol->name, name) < 0) {
            VIR_FREE(vol);
            goto cleanup;
        }

        name += strlen(name) + 1;

        r = volStorageBackendRBDRefreshVolInfo(vol, pool, ptr);

        /* It could be that a volume has been deleted through a different route
         * then libvirt and that will cause a -ENOENT to be returned.
         *
         * Another possibility is that there is something wrong with the placement
         * group (PG) that RBD image's header is in and that causes -ETIMEDOUT
         * to be returned.
         *
         * Do not error out and simply ignore the volume
         */
        if (r < 0) {
            if (r == -ENOENT || r == -ETIMEDOUT)
                continue;

            virStorageVolDefFree(vol);
            goto cleanup;
        }

        if (virStoragePoolObjAddVol(pool, vol) < 0) {
            virStorageVolDefFree(vol);
            virStoragePoolObjClearVols(pool);
            goto cleanup;
        }
    }

    VIR_DEBUG("Found %zu images in RBD pool %s",
              virStoragePoolObjGetVolumesCount(pool), pool->def->source.name);

    ret = 0;

 cleanup:
    VIR_FREE(names);
    virStorageBackendRBDFreeState(&ptr);
    return ret;
}

static int
virStorageBackendRBDCleanupSnapshots(rados_ioctx_t ioctx,
                                     virStoragePoolSourcePtr source,
                                     virStorageVolDefPtr vol)
{
    int ret = -1;
    int r = 0;
    int max_snaps = 128;
    int snap_count, protected;
    size_t i;
    rbd_snap_info_t *snaps = NULL;
    rbd_image_t image = NULL;

    if ((r = rbd_open(ioctx, vol->name, &image, NULL)) < 0) {
       virReportSystemError(-r, _("failed to open the RBD image '%s'"),
                            vol->name);
       goto cleanup;
    }

    do {
        if (VIR_ALLOC_N(snaps, max_snaps))
            goto cleanup;

        snap_count = rbd_snap_list(image, snaps, &max_snaps);
        if (snap_count <= 0)
            VIR_FREE(snaps);

    } while (snap_count == -ERANGE);

    VIR_DEBUG("Found %d snapshots for volume %s/%s", snap_count,
              source->name, vol->name);

    for (i = 0; i < snap_count; i++) {
        if ((r = rbd_snap_is_protected(image, snaps[i].name, &protected)) < 0) {
            virReportSystemError(-r, _("failed to verify if snapshot '%s/%s@%s' is protected"),
                                 source->name, vol->name,
                                 snaps[i].name);
            goto cleanup;
        }

        if (protected == 1) {
            VIR_DEBUG("Snapshot %s/%s@%s is protected needs to be "
                      "unprotected", source->name, vol->name,
                      snaps[i].name);

            if ((r = rbd_snap_unprotect(image, snaps[i].name)) < 0) {
                virReportSystemError(-r, _("failed to unprotect snapshot '%s/%s@%s'"),
                                     source->name, vol->name,
                                     snaps[i].name);
                goto cleanup;
            }
        }

        VIR_DEBUG("Removing snapshot %s/%s@%s", source->name,
                  vol->name, snaps[i].name);

        if ((r = rbd_snap_remove(image, snaps[i].name)) < 0) {
            virReportSystemError(-r, _("failed to remove snapshot '%s/%s@%s'"),
                                 source->name, vol->name,
                                 snaps[i].name);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    if (snaps)
        rbd_snap_list_end(snaps);

    VIR_FREE(snaps);

    if (image)
        rbd_close(image);

    return ret;
}

static int
virStorageBackendRBDDeleteVol(virConnectPtr conn,
                              virStoragePoolObjPtr pool,
                              virStorageVolDefPtr vol,
                              unsigned int flags)
{
    int ret = -1;
    int r = 0;
    virStorageBackendRBDStatePtr ptr = NULL;

    virCheckFlags(VIR_STORAGE_VOL_DELETE_ZEROED |
                  VIR_STORAGE_VOL_DELETE_WITH_SNAPSHOTS, -1);

    VIR_DEBUG("Removing RBD image %s/%s", pool->def->source.name, vol->name);

    if (flags & VIR_STORAGE_VOL_DELETE_ZEROED)
        VIR_WARN("%s", "This storage backend does not support zeroed removal of volumes");

    if (!(ptr = virStorageBackendRBDNewState(conn, pool)))
        goto cleanup;

    if (flags & VIR_STORAGE_VOL_DELETE_WITH_SNAPSHOTS) {
        if (virStorageBackendRBDCleanupSnapshots(ptr->ioctx, &pool->def->source,
                                                 vol) < 0)
            goto cleanup;
    }

    VIR_DEBUG("Removing volume %s/%s", pool->def->source.name, vol->name);

    r = rbd_remove(ptr->ioctx, vol->name);
    if (r < 0 && (-r) != ENOENT) {
        virReportSystemError(-r, _("failed to remove volume '%s/%s'"),
                             pool->def->source.name, vol->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virStorageBackendRBDFreeState(&ptr);
    return ret;
}


static int
virStorageBackendRBDCreateVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                              virStoragePoolObjPtr pool,
                              virStorageVolDefPtr vol)
{
    vol->type = VIR_STORAGE_VOL_NETWORK;

    if (vol->target.format != VIR_STORAGE_FILE_RAW) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only RAW volumes are supported by this storage pool"));
        return -1;
    }

    VIR_FREE(vol->target.path);
    if (virAsprintf(&vol->target.path, "%s/%s",
                    pool->def->source.name,
                    vol->name) < 0)
        return -1;

    VIR_FREE(vol->key);
    if (virAsprintf(&vol->key, "%s/%s",
                    pool->def->source.name,
                    vol->name) < 0)
        return -1;

    return 0;
}

static int virStorageBackendRBDCreateImage(rados_ioctx_t io,
                                           char *name, long capacity)
{
    int order = 0;
    return rbd_create(io, name, capacity, &order);
}

static int
virStorageBackendRBDBuildVol(virConnectPtr conn,
                             virStoragePoolObjPtr pool,
                             virStorageVolDefPtr vol,
                             unsigned int flags)
{
    virStorageBackendRBDStatePtr ptr = NULL;
    int ret = -1;
    int r = 0;

    VIR_DEBUG("Creating RBD image %s/%s with size %llu",
              pool->def->source.name,
              vol->name, vol->target.capacity);

    virCheckFlags(0, -1);

    if (!vol->target.capacity) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("volume capacity required for this storage pool"));
        goto cleanup;
    }

    if (vol->target.format != VIR_STORAGE_FILE_RAW) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("only RAW volumes are supported by this storage pool"));
        goto cleanup;
    }

    if (vol->target.encryption != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("storage pool does not support encrypted volumes"));
        goto cleanup;
    }

    if (!(ptr = virStorageBackendRBDNewState(conn, pool)))
        goto cleanup;

    if ((r = virStorageBackendRBDCreateImage(ptr->ioctx, vol->name,
                                             vol->target.capacity)) < 0) {
        virReportSystemError(-r, _("failed to create volume '%s/%s'"),
                             pool->def->source.name,
                             vol->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virStorageBackendRBDFreeState(&ptr);
    return ret;
}

static int
virStorageBackendRBDImageInfo(rbd_image_t image,
                              char *volname,
                              uint64_t *features,
                              uint64_t *stripe_unit,
                              uint64_t *stripe_count)
{
    int ret = -1;
    int r = 0;
    uint8_t oldformat;

    if ((r = rbd_get_old_format(image, &oldformat)) < 0) {
        virReportSystemError(-r, _("failed to get the format of RBD image %s"),
                             volname);
        goto cleanup;
    }

    if (oldformat != 0) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("RBD image %s is old format. Does not support "
                         "extended features and striping"),
                       volname);
        goto cleanup;
    }

    if (volStorageBackendRBDGetFeatures(image, volname, features) < 0)
        goto cleanup;

    if ((r = rbd_get_stripe_unit(image, stripe_unit)) < 0) {
        virReportSystemError(-r, _("failed to get the stripe unit of RBD image %s"),
                             volname);
        goto cleanup;
    }

    if ((r = rbd_get_stripe_count(image, stripe_count)) < 0) {
        virReportSystemError(-r, _("failed to get the stripe count of RBD image %s"),
                             volname);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}

/* Callback function for rbd_diff_iterate() */
static int
virStorageBackendRBDIterateCb(uint64_t offset ATTRIBUTE_UNUSED,
                              size_t length ATTRIBUTE_UNUSED,
                              int exists ATTRIBUTE_UNUSED,
                              void *arg)
{
    /*
     * Just set that there is a diff for this snapshot, we do not care where
     *
     * When it returns a negative number the rbd_diff_iterate() function will stop
     *
     * That's why we return -1, meaning that there is a difference and we can stop
     * searching any further.
     */
    *(int*) arg = 1;
    return -1;
}

static int
virStorageBackendRBDSnapshotFindNoDiff(rbd_image_t image,
                                       char *imgname,
                                       virBufferPtr snapname)
{
    int r = -1;
    int ret = -1;
    int snap_count;
    int max_snaps = 128;
    size_t i;
    int diff;
    rbd_snap_info_t *snaps = NULL;
    rbd_image_info_t info;

    if ((r = rbd_stat(image, &info, sizeof(info))) < 0) {
        virReportSystemError(-r, _("failed to stat the RBD image %s"),
                             imgname);
        goto cleanup;
    }

    do {
        if (VIR_ALLOC_N(snaps, max_snaps))
            goto cleanup;

        snap_count = rbd_snap_list(image, snaps, &max_snaps);
        if (snap_count <= 0)
            VIR_FREE(snaps);

    } while (snap_count == -ERANGE);

    if (snap_count <= 0) {
        if (snap_count == 0)
            ret = 0;
        goto cleanup;
    }

    VIR_DEBUG("Found %d snapshots for RBD image %s", snap_count, imgname);

    for (i = 0; i < snap_count; i++) {
        VIR_DEBUG("Querying diff for RBD snapshot %s@%s", imgname,
                  snaps[i].name);

        /* The callback will set diff to non-zero if there is a diff */
        diff = 0;

/*
 * rbd_diff_iterate2() is available in versions above Ceph 0.94 (Hammer)
 * It uses a object map inside Ceph which is faster than rbd_diff_iterate()
 * which iterates all objects.
 * LIBRBD_VERSION_CODE for Ceph 0.94 is 265. In 266 and upwards diff_iterate2
 * is available
 */
#if LIBRBD_VERSION_CODE > 265
        r = rbd_diff_iterate2(image, snaps[i].name, 0, info.size, 0, 1,
                              virStorageBackendRBDIterateCb, (void *)&diff);
#else
        r = rbd_diff_iterate(image, snaps[i].name, 0, info.size,
                             virStorageBackendRBDIterateCb, (void *)&diff);
#endif

        if (r < 0) {
            virReportSystemError(-r, _("failed to iterate RBD snapshot %s@%s"),
                                 imgname, snaps[i].name);
            goto cleanup;
        }

        /* If diff is still set to zero we found a snapshot without deltas */
        if (diff == 0) {
            VIR_DEBUG("RBD snapshot %s@%s has no delta", imgname,
                      snaps[i].name);
            virBufferAsprintf(snapname, "%s", snaps[i].name);
            ret = 0;
            goto cleanup;
        }

        VIR_DEBUG("RBD snapshot %s@%s has deltas. Continuing search.",
                  imgname, snaps[i].name);
    }

    ret = 0;

 cleanup:
    if (snaps)
        rbd_snap_list_end(snaps);

    VIR_FREE(snaps);

    return ret;
}

static int
virStorageBackendRBDSnapshotCreate(rbd_image_t image,
                                   char *imgname,
                                   char *snapname)
{
    int ret = -1;
    int r = -1;

    VIR_DEBUG("Creating RBD snapshot %s@%s", imgname, snapname);

    if ((r = rbd_snap_create(image, snapname)) < 0) {
        virReportSystemError(-r, _("failed to create RBD snapshot %s@%s"),
                                   imgname, snapname);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}

static int
virStorageBackendRBDSnapshotProtect(rbd_image_t image,
                                    char *imgname,
                                    char *snapname)
{
    int r = -1;
    int ret = -1;
    int protected;

    VIR_DEBUG("Querying if RBD snapshot %s@%s is protected", imgname, snapname);

    if ((r = rbd_snap_is_protected(image, snapname, &protected)) < 0) {
        virReportSystemError(-r, _("failed to verify if RBD snapshot %s@%s "
                                   "is protected"), imgname, snapname);
        goto cleanup;
    }

    if (protected == 0) {
        VIR_DEBUG("RBD Snapshot %s@%s is not protected, protecting",
                  imgname, snapname);

        if ((r = rbd_snap_protect(image, snapname)) < 0) {
            virReportSystemError(-r, _("failed to protect RBD snapshot %s@%s"),
                                       imgname, snapname);
            goto cleanup;
        }
    } else {
        VIR_DEBUG("RBD Snapshot %s@%s is already protected", imgname, snapname);
    }

    ret = 0;

 cleanup:
    return ret;
}

static int
virStorageBackendRBDCloneImage(rados_ioctx_t io,
                               char *origvol,
                               char *newvol)
{
    int r = -1;
    int ret = -1;
    int order = 0;
    uint64_t features;
    uint64_t stripe_count;
    uint64_t stripe_unit;
    virBuffer snapname = VIR_BUFFER_INITIALIZER;
    char *snapname_buff = NULL;
    rbd_image_t image = NULL;

    if ((r = rbd_open(io, origvol, &image, NULL)) < 0) {
        virReportSystemError(-r, _("failed to open the RBD image %s"),
                             origvol);
        goto cleanup;
    }

    if ((virStorageBackendRBDImageInfo(image, origvol, &features, &stripe_unit,
                                       &stripe_count)) < 0)
        goto cleanup;

    /*
     * First we attempt to find a snapshot which has no differences between
     * the current state of the RBD image.
     *
     * This prevents us from creating a new snapshot for every clone operation
     * while it could be that the original volume has not changed
     */
    if (virStorageBackendRBDSnapshotFindNoDiff(image, origvol, &snapname) < 0)
        goto cleanup;

    /*
     * the virBuffer snapname will contain a snapshot's name if one without
     * deltas has been found.
     *
     * If it's NULL we have to create a new snapshot and clone from there
     */
    snapname_buff = virBufferContentAndReset(&snapname);

    if (snapname_buff == NULL) {
        VIR_DEBUG("No RBD snapshot with zero delta could be found for image %s",
                  origvol);

        virBufferAsprintf(&snapname, "libvirt-%d", (int)virRandomInt(65534));

        if (virBufferCheckError(&snapname) < 0)
            goto cleanup;

        snapname_buff = virBufferContentAndReset(&snapname);

        if (virStorageBackendRBDSnapshotCreate(image, origvol, snapname_buff) < 0)
            goto cleanup;

    }

    VIR_DEBUG("Using snapshot name %s for cloning RBD image %s to %s",
              snapname_buff, origvol, newvol);

    /*
     * RBD snapshots have to be 'protected' before they can be used
     * as a parent snapshot for a child image
     */
    if ((r = virStorageBackendRBDSnapshotProtect(image, origvol, snapname_buff)) < 0)
        goto cleanup;

    VIR_DEBUG("Performing RBD clone from %s to %s", origvol, newvol);

    if ((r = rbd_clone2(io, origvol, snapname_buff, io, newvol, features,
                        &order, stripe_unit, stripe_count)) < 0) {
        virReportSystemError(-r, _("failed to clone RBD volume %s to %s"),
                             origvol, newvol);
        goto cleanup;
    }

    VIR_DEBUG("Cloned RBD image %s to %s", origvol, newvol);

    ret = 0;

 cleanup:
    virBufferFreeAndReset(&snapname);
    VIR_FREE(snapname_buff);

    if (image)
        rbd_close(image);

    return ret;
}

static int
virStorageBackendRBDBuildVolFrom(virConnectPtr conn,
                                 virStoragePoolObjPtr pool,
                                 virStorageVolDefPtr newvol,
                                 virStorageVolDefPtr origvol,
                                 unsigned int flags)
{
    virStorageBackendRBDStatePtr ptr = NULL;
    int ret = -1;

    VIR_DEBUG("Creating clone of RBD image %s/%s with name %s",
              pool->def->source.name, origvol->name, newvol->name);

    virCheckFlags(0, -1);

    if (!(ptr = virStorageBackendRBDNewState(conn, pool)))
        goto cleanup;

    if ((virStorageBackendRBDCloneImage(ptr->ioctx, origvol->name,
                                        newvol->name)) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virStorageBackendRBDFreeState(&ptr);
    return ret;
}

static int
virStorageBackendRBDRefreshVol(virConnectPtr conn,
                               virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                               virStorageVolDefPtr vol)
{
    virStorageBackendRBDStatePtr ptr = NULL;
    int ret = -1;

    if (!(ptr = virStorageBackendRBDNewState(conn, pool)))
        goto cleanup;

    if (volStorageBackendRBDRefreshVolInfo(vol, pool, ptr) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virStorageBackendRBDFreeState(&ptr);
    return ret;
}

static int
virStorageBackendRBDResizeVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                              virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                              virStorageVolDefPtr vol,
                              unsigned long long capacity,
                              unsigned int flags)
{
    virStorageBackendRBDStatePtr ptr = NULL;
    rbd_image_t image = NULL;
    int ret = -1;
    int r = 0;

    virCheckFlags(0, -1);

    if (!(ptr = virStorageBackendRBDNewState(conn, pool)))
        goto cleanup;

    if ((r = rbd_open(ptr->ioctx, vol->name, &image, NULL)) < 0) {
       virReportSystemError(-r, _("failed to open the RBD image '%s'"),
                            vol->name);
       goto cleanup;
    }

    if ((r = rbd_resize(image, capacity)) < 0) {
        virReportSystemError(-r, _("failed to resize the RBD image '%s'"),
                             vol->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (image != NULL)
       rbd_close(image);
    virStorageBackendRBDFreeState(&ptr);
    return ret;
}

static int
virStorageBackendRBDVolWipeZero(rbd_image_t image,
                                char *imgname,
                                rbd_image_info_t *info,
                                uint64_t stripe_count)
{
    int r = -1;
    int ret = -1;
    unsigned long long offset = 0;
    unsigned long long length;
    char *writebuf;

    if (VIR_ALLOC_N(writebuf, info->obj_size * stripe_count) < 0)
        goto cleanup;

    while (offset < info->size) {
        length = MIN((info->size - offset), (info->obj_size * stripe_count));

        if ((r = rbd_write(image, offset, length, writebuf)) < 0) {
            virReportSystemError(-r, _("writing %llu bytes failed on "
                                       "RBD image %s at offset %llu"),
                                       length, imgname, offset);
            goto cleanup;
        }

        VIR_DEBUG("Wrote %llu bytes to RBD image %s at offset %llu",
                  length, imgname, offset);

        offset += length;
    }

    ret = 0;

 cleanup:
    VIR_FREE(writebuf);

    return ret;
}

static int
virStorageBackendRBDVolWipeDiscard(rbd_image_t image,
                                   char *imgname,
                                   rbd_image_info_t *info,
                                   uint64_t stripe_count)
{
    int r = -1;
    int ret = -1;
    unsigned long long offset = 0;
    unsigned long long length;

    VIR_DEBUG("Wiping RBD %s volume using discard)", imgname);

    while (offset < info->size) {
        length = MIN((info->size - offset), (info->obj_size * stripe_count));

        if ((r = rbd_discard(image, offset, length)) < 0) {
            virReportSystemError(-r, _("discarding %llu bytes failed on "
                                       "RBD image %s at offset %llu"),
                                     length, imgname, offset);
            goto cleanup;
        }

        VIR_DEBUG("Discarded %llu bytes of RBD image %s at offset %llu",
                  length, imgname, offset);

        offset += length;
    }

    ret = 0;

 cleanup:
    return ret;
}

static int
virStorageBackendRBDVolWipe(virConnectPtr conn,
                            virStoragePoolObjPtr pool,
                            virStorageVolDefPtr vol,
                            unsigned int algorithm,
                            unsigned int flags)
{
    virStorageBackendRBDStatePtr ptr = NULL;
    rbd_image_t image = NULL;
    rbd_image_info_t info;
    uint64_t stripe_count;
    int r = -1;
    int ret = -1;

    virCheckFlags(0, -1);

    VIR_DEBUG("Wiping RBD image %s/%s", pool->def->source.name, vol->name);

    if (!(ptr = virStorageBackendRBDNewState(conn, pool)))
        goto cleanup;

    if ((r = rbd_open(ptr->ioctx, vol->name, &image, NULL)) < 0) {
        virReportSystemError(-r, _("failed to open the RBD image %s"),
                             vol->name);
        goto cleanup;
    }

    if ((r = rbd_stat(image, &info, sizeof(info))) < 0) {
        virReportSystemError(-r, _("failed to stat the RBD image %s"),
                             vol->name);
        goto cleanup;
    }

    if ((r = rbd_get_stripe_count(image, &stripe_count)) < 0) {
        virReportSystemError(-r, _("failed to get stripe count of RBD image %s"),
                             vol->name);
        goto cleanup;
    }

    VIR_DEBUG("Need to wipe %"PRIu64" bytes from RBD image %s/%s",
              info.size, pool->def->source.name, vol->name);

    switch ((virStorageVolWipeAlgorithm) algorithm) {
    case VIR_STORAGE_VOL_WIPE_ALG_ZERO:
        r = virStorageBackendRBDVolWipeZero(image, vol->name,
                                            &info, stripe_count);
            break;
    case VIR_STORAGE_VOL_WIPE_ALG_TRIM:
        r = virStorageBackendRBDVolWipeDiscard(image, vol->name,
                                               &info, stripe_count);
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_NNSA:
    case VIR_STORAGE_VOL_WIPE_ALG_DOD:
    case VIR_STORAGE_VOL_WIPE_ALG_BSI:
    case VIR_STORAGE_VOL_WIPE_ALG_GUTMANN:
    case VIR_STORAGE_VOL_WIPE_ALG_SCHNEIER:
    case VIR_STORAGE_VOL_WIPE_ALG_PFITZNER7:
    case VIR_STORAGE_VOL_WIPE_ALG_PFITZNER33:
    case VIR_STORAGE_VOL_WIPE_ALG_RANDOM:
    case VIR_STORAGE_VOL_WIPE_ALG_LAST:
        virReportError(VIR_ERR_INVALID_ARG, _("unsupported algorithm %d"),
                       algorithm);
        goto cleanup;
    }

    if (r < 0) {
        virReportSystemError(-r, _("failed to wipe RBD image %s"),
                             vol->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (image)
        rbd_close(image);

    virStorageBackendRBDFreeState(&ptr);

    return ret;
}

virStorageBackend virStorageBackendRBD = {
    .type = VIR_STORAGE_POOL_RBD,

    .refreshPool = virStorageBackendRBDRefreshPool,
    .createVol = virStorageBackendRBDCreateVol,
    .buildVol = virStorageBackendRBDBuildVol,
    .buildVolFrom = virStorageBackendRBDBuildVolFrom,
    .refreshVol = virStorageBackendRBDRefreshVol,
    .deleteVol = virStorageBackendRBDDeleteVol,
    .resizeVol = virStorageBackendRBDResizeVol,
    .wipeVol = virStorageBackendRBDVolWipe
};


int
virStorageBackendRBDRegister(void)
{
    return virStorageBackendRegister(&virStorageBackendRBD);
}
