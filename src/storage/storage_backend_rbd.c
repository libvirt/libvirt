/*
 * storage_backend_rbd.c: storage backend for RBD (RADOS Block Device) handling
 *
 * Copyright (C) 2013 Red Hat, Inc.
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

#include "datatypes.h"
#include "virerror.h"
#include "storage_backend_rbd.h"
#include "storage_conf.h"
#include "viralloc.h"
#include "virlog.h"
#include "base64.h"
#include "viruuid.h"
#include "virstring.h"
#include "rados/librados.h"
#include "rbd/librbd.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

struct _virStorageBackendRBDState {
    rados_t cluster;
    rados_ioctx_t ioctx;
    time_t starttime;
};

typedef struct _virStorageBackendRBDState virStorageBackendRBDState;
typedef virStorageBackendRBDState *virStorageBackendRBDStatePtr;

static int virStorageBackendRBDOpenRADOSConn(virStorageBackendRBDStatePtr ptr,
                                             virConnectPtr conn,
                                             virStoragePoolObjPtr pool)
{
    int ret = -1;
    unsigned char *secret_value = NULL;
    size_t secret_value_size;
    char *rados_key = NULL;
    virBuffer mon_host = VIR_BUFFER_INITIALIZER;
    virSecretPtr secret = NULL;
    char secretUuid[VIR_UUID_STRING_BUFLEN];
    size_t i;
    char *mon_buff = NULL;

    VIR_DEBUG("Found Cephx username: %s",
              pool->def->source.auth.cephx.username);

    if (pool->def->source.auth.cephx.username != NULL) {
        VIR_DEBUG("Using cephx authorization");
        if (rados_create(&ptr->cluster,
            pool->def->source.auth.cephx.username) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to initialize RADOS"));
            goto cleanup;
        }

        if (!conn) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'ceph' authentication not supported "
                             "for autostarted pools"));
            return -1;
        }

        if (pool->def->source.auth.cephx.secret.uuidUsable) {
            virUUIDFormat(pool->def->source.auth.cephx.secret.uuid, secretUuid);
            VIR_DEBUG("Looking up secret by UUID: %s", secretUuid);
            secret = virSecretLookupByUUIDString(conn, secretUuid);
        } else if (pool->def->source.auth.cephx.secret.usage != NULL) {
            VIR_DEBUG("Looking up secret by usage: %s",
                      pool->def->source.auth.cephx.secret.usage);
            secret = virSecretLookupByUsage(conn, VIR_SECRET_USAGE_TYPE_CEPH,
                                            pool->def->source.auth.cephx.secret.usage);
        }

        if (secret == NULL) {
            if (pool->def->source.auth.cephx.secret.uuidUsable) {
                virReportError(VIR_ERR_NO_SECRET,
                               _("no secret matches uuid '%s'"),
                                 secretUuid);
            } else {
                virReportError(VIR_ERR_NO_SECRET,
                               _("no secret matches usage value '%s'"),
                                 pool->def->source.auth.cephx.secret.usage);
            }
            goto cleanup;
        }

        secret_value = conn->secretDriver->secretGetValue(secret, &secret_value_size, 0,
                                                          VIR_SECRET_GET_VALUE_INTERNAL_CALL);

        if (!secret_value) {
            if (pool->def->source.auth.cephx.secret.uuidUsable) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("could not get the value of the secret "
                                 "for username '%s' using uuid '%s'"),
                               pool->def->source.auth.cephx.username,
                               secretUuid);
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("could not get the value of the secret "
                                 "for username '%s' using usage value '%s'"),
                               pool->def->source.auth.cephx.username,
                               pool->def->source.auth.cephx.secret.usage);
            }
            goto cleanup;
        }

        base64_encode_alloc((char *)secret_value,
                            secret_value_size, &rados_key);
        memset(secret_value, 0, secret_value_size);

        if (rados_key == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to decode the RADOS key"));
            goto cleanup;
        }

        VIR_DEBUG("Found cephx key: %s", rados_key);
        if (rados_conf_set(ptr->cluster, "key", rados_key) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to set RADOS option: %s"),
                           "rados_key");
            goto cleanup;
        }

        memset(rados_key, 0, strlen(rados_key));

        if (rados_conf_set(ptr->cluster, "auth_supported", "cephx") < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to set RADOS option: %s"),
                           "auth_supported");
            goto cleanup;
        }
    } else {
        VIR_DEBUG("Not using cephx authorization");
        if (rados_create(&ptr->cluster, NULL) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("failed to create the RADOS cluster"));
            goto cleanup;
        }
        if (rados_conf_set(ptr->cluster, "auth_supported", "none") < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to set RADOS option: %s"),
                           "auth_supported");
            goto cleanup;
        }
    }

    VIR_DEBUG("Found %zu RADOS cluster monitors in the pool configuration",
              pool->def->source.nhost);

    for (i = 0; i < pool->def->source.nhost; i++) {
        if (pool->def->source.hosts[i].name != NULL &&
            !pool->def->source.hosts[i].port) {
            virBufferAsprintf(&mon_host, "%s:6789,",
                              pool->def->source.hosts[i].name);
        } else if (pool->def->source.hosts[i].name != NULL &&
            pool->def->source.hosts[i].port) {
            virBufferAsprintf(&mon_host, "%s:%d,",
                              pool->def->source.hosts[i].name,
                              pool->def->source.hosts[i].port);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("received malformed monitor, check the XML definition"));
        }
    }

    if (virBufferError(&mon_host)) {
       virReportOOMError();
       goto cleanup;
    }

    mon_buff = virBufferContentAndReset(&mon_host);
    VIR_DEBUG("RADOS mon_host has been set to: %s", mon_buff);
    if (rados_conf_set(ptr->cluster, "mon_host", mon_buff) < 0) {
       virReportError(VIR_ERR_INTERNAL_ERROR,
                      _("failed to set RADOS option: %s"),
                      "mon_host");
        goto cleanup;
    }

    ptr->starttime = time(0);
    if (rados_connect(ptr->cluster) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to connect to the RADOS monitor on: %s"),
                       mon_buff);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(secret_value);
    VIR_FREE(rados_key);

    if (secret != NULL)
        virSecretFree(secret);

    virBufferFreeAndReset(&mon_host);
    VIR_FREE(mon_buff);
    return ret;
}

static int virStorageBackendRBDCloseRADOSConn(virStorageBackendRBDStatePtr ptr)
{
    int ret = 0;

    if (ptr->ioctx != NULL) {
        VIR_DEBUG("Closing RADOS IoCTX");
        rados_ioctx_destroy(ptr->ioctx);
        ret = -1;
    }
    ptr->ioctx = NULL;

    if (ptr->cluster != NULL) {
        VIR_DEBUG("Closing RADOS connection");
        rados_shutdown(ptr->cluster);
        ret = -2;
    }
    ptr->cluster = NULL;

    time_t runtime = time(0) - ptr->starttime;
    VIR_DEBUG("RADOS connection existed for %ld seconds", runtime);

    return ret;
}

static int volStorageBackendRBDRefreshVolInfo(virStorageVolDefPtr vol,
                                              virStoragePoolObjPtr pool,
                                              virStorageBackendRBDStatePtr ptr)
{
    int ret = -1;
    rbd_image_t image;
    if (rbd_open(ptr->ioctx, vol->name, &image, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to open the RBD image '%s'"),
                       vol->name);
        return ret;
    }

    rbd_image_info_t info;
    if (rbd_stat(image, &info, sizeof(info)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to stat the RBD image"));
        goto cleanup;
    }

    VIR_DEBUG("Refreshed RBD image %s/%s (size: %llu obj_size: %llu num_objs: %llu)",
              pool->def->source.name, vol->name, (unsigned long long)info.size,
              (unsigned long long)info.obj_size,
              (unsigned long long)info.num_objs);

    vol->capacity = info.size;
    vol->allocation = info.obj_size * info.num_objs;
    vol->type = VIR_STORAGE_VOL_NETWORK;

    VIR_FREE(vol->target.path);
    if (virAsprintf(&vol->target.path, "%s/%s",
                    pool->def->source.name,
                    vol->name) == -1)
        goto cleanup;

    VIR_FREE(vol->key);
    if (virAsprintf(&vol->key, "%s/%s",
                    pool->def->source.name,
                    vol->name) == -1)
        goto cleanup;

    ret = 0;

cleanup:
    rbd_close(image);
    return ret;
}

static int virStorageBackendRBDRefreshPool(virConnectPtr conn,
                                           virStoragePoolObjPtr pool)
{
    size_t max_size = 1024;
    int ret = -1;
    int len = -1;
    char *name, *names = NULL;
    virStorageBackendRBDState ptr;
    ptr.cluster = NULL;
    ptr.ioctx = NULL;

    if (virStorageBackendRBDOpenRADOSConn(&ptr, conn, pool) < 0) {
        goto cleanup;
    }

    if (rados_ioctx_create(ptr.cluster,
        pool->def->source.name, &ptr.ioctx) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create the RBD IoCTX. Does the pool '%s' exist?"),
                       pool->def->source.name);
        goto cleanup;
    }

    struct rados_cluster_stat_t stat;
    if (rados_cluster_stat(ptr.cluster, &stat) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to stat the RADOS cluster"));
        goto cleanup;
    }

    struct rados_pool_stat_t poolstat;
    if (rados_ioctx_pool_stat(ptr.ioctx, &poolstat) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to stat the RADOS pool '%s'"),
                       pool->def->source.name);
        goto cleanup;
    }

    pool->def->capacity = stat.kb * 1024;
    pool->def->available = stat.kb_avail * 1024;
    pool->def->allocation = poolstat.num_bytes;

    VIR_DEBUG("Utilization of RBD pool %s: (kb: %llu kb_avail: %llu num_bytes: %llu)",
              pool->def->source.name, (unsigned long long)stat.kb,
              (unsigned long long)stat.kb_avail,
              (unsigned long long)poolstat.num_bytes);

    while (true) {
        if (VIR_ALLOC_N(names, max_size) < 0)
            goto cleanup;

        len = rbd_list(ptr.ioctx, names, &max_size);
        if (len >= 0)
            break;
        if (len != -ERANGE) {
            VIR_WARN("%s", _("A problem occurred while listing RBD images"));
            goto cleanup;
        }
        VIR_FREE(names);
    }

    for (name = names; name < names + max_size;) {
        virStorageVolDefPtr vol;

        if (VIR_REALLOC_N(pool->volumes.objs, pool->volumes.count + 1) < 0) {
            virStoragePoolObjClearVols(pool);
            goto cleanup;
        }

        if (STREQ(name, ""))
            break;

        if (VIR_ALLOC(vol) < 0)
            goto cleanup;

        if (VIR_STRDUP(vol->name, name) < 0) {
            VIR_FREE(vol);
            goto cleanup;
        }

        name += strlen(name) + 1;

        if (volStorageBackendRBDRefreshVolInfo(vol, pool, &ptr) < 0) {
            virStorageVolDefFree(vol);
            goto cleanup;
        }

        pool->volumes.objs[pool->volumes.count++] = vol;
    }

    VIR_DEBUG("Found %zu images in RBD pool %s",
              pool->volumes.count, pool->def->source.name);

    ret = 0;

cleanup:
    VIR_FREE(names);
    virStorageBackendRBDCloseRADOSConn(&ptr);
    return ret;
}

static int virStorageBackendRBDDeleteVol(virConnectPtr conn,
                                         virStoragePoolObjPtr pool,
                                         virStorageVolDefPtr vol,
                                         unsigned int flags)
{
    int ret = -1;
    virStorageBackendRBDState ptr;
    ptr.cluster = NULL;
    ptr.ioctx = NULL;

    VIR_DEBUG("Removing RBD image %s/%s", pool->def->source.name, vol->name);

    if (flags & VIR_STORAGE_VOL_DELETE_ZEROED) {
        VIR_WARN("%s", _("This storage backend does not supported zeroed removal of volumes"));
    }

    if (virStorageBackendRBDOpenRADOSConn(&ptr, conn, pool) < 0) {
        goto cleanup;
    }

    if (rados_ioctx_create(ptr.cluster,
        pool->def->source.name, &ptr.ioctx) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create the RBD IoCTX. Does the pool '%s' exist?"),
                       pool->def->source.name);
        goto cleanup;
    }

    if (rbd_remove(ptr.ioctx, vol->name) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to remove volume '%s/%s'"),
                       pool->def->source.name,
                       vol->name);
        goto cleanup;
    }

    ret = 0;

cleanup:
    virStorageBackendRBDCloseRADOSConn(&ptr);
    return ret;
}

static int virStorageBackendRBDCreateVol(virConnectPtr conn,
                                         virStoragePoolObjPtr pool,
                                         virStorageVolDefPtr vol)
{
    virStorageBackendRBDState ptr;
    ptr.cluster = NULL;
    ptr.ioctx = NULL;
    int order = 0;
    int ret = -1;

    VIR_DEBUG("Creating RBD image %s/%s with size %llu",
              pool->def->source.name,
              vol->name, vol->capacity);

    if (virStorageBackendRBDOpenRADOSConn(&ptr, conn, pool) < 0) {
        goto cleanup;
    }

    if (rados_ioctx_create(ptr.cluster,
                           pool->def->source.name, &ptr.ioctx) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create the RBD IoCTX. Does the pool '%s' exist?"),
                       pool->def->source.name);
        goto cleanup;
    }

    if (vol->target.encryption != NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("storage pool does not support encrypted volumes"));
        goto cleanup;
    }

    if (rbd_create(ptr.ioctx, vol->name, vol->capacity, &order) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create volume '%s/%s'"),
                       pool->def->source.name,
                       vol->name);
        goto cleanup;
    }

    if (volStorageBackendRBDRefreshVolInfo(vol, pool, &ptr) < 0) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    virStorageBackendRBDCloseRADOSConn(&ptr);
    return ret;
}

static int virStorageBackendRBDRefreshVol(virConnectPtr conn,
                                          virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                          virStorageVolDefPtr vol)
{
    virStorageBackendRBDState ptr;
    ptr.cluster = NULL;
    ptr.ioctx = NULL;
    int ret = -1;

    if (virStorageBackendRBDOpenRADOSConn(&ptr, conn, pool) < 0) {
        goto cleanup;
    }

    if (rados_ioctx_create(ptr.cluster,
        pool->def->source.name, &ptr.ioctx) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create the RBD IoCTX. Does the pool '%s' exist?"),
                       pool->def->source.name);
        goto cleanup;
    }

    if (volStorageBackendRBDRefreshVolInfo(vol, pool, &ptr) < 0) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    virStorageBackendRBDCloseRADOSConn(&ptr);
    return ret;
}

static int virStorageBackendRBDResizeVol(virConnectPtr conn ATTRIBUTE_UNUSED,
                                     virStoragePoolObjPtr pool ATTRIBUTE_UNUSED,
                                     virStorageVolDefPtr vol,
                                     unsigned long long capacity,
                                     unsigned int flags)
{
    virStorageBackendRBDState ptr;
    ptr.cluster = NULL;
    ptr.ioctx = NULL;
    rbd_image_t image = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (virStorageBackendRBDOpenRADOSConn(&ptr, conn, pool) < 0) {
        goto cleanup;
    }

    if (rados_ioctx_create(ptr.cluster,
        pool->def->source.name, &ptr.ioctx) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to create the RBD IoCTX. Does the pool '%s' exist?"),
                       pool->def->source.name);
        goto cleanup;
    }

    if (rbd_open(ptr.ioctx, vol->name, &image, NULL) < 0) {
       virReportError(VIR_ERR_INTERNAL_ERROR,
                      _("failed to open the RBD image '%s'"),
                      vol->name);
       goto cleanup;
    }

    if (rbd_resize(image, capacity) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to resize the RBD image '%s'"),
                       vol->name);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (image != NULL)
       rbd_close(image);
    virStorageBackendRBDCloseRADOSConn(&ptr);
    return ret;
}

virStorageBackend virStorageBackendRBD = {
    .type = VIR_STORAGE_POOL_RBD,

    .refreshPool = virStorageBackendRBDRefreshPool,
    .createVol = virStorageBackendRBDCreateVol,
    .refreshVol = virStorageBackendRBDRefreshVol,
    .deleteVol = virStorageBackendRBDDeleteVol,
    .resizeVol = virStorageBackendRBDResizeVol,
};
