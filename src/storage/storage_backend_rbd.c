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
 */

#include <config.h>

#include <inttypes.h>
#include "datatypes.h"
#include "virerror.h"
#include "storage_backend_rbd.h"
#include "storage_conf.h"
#include "viralloc.h"
#include "viridentity.h"
#include "virlog.h"
#include "viruuid.h"
#include "virrandom.h"
#include "rados/librados.h"
#include "rbd/librbd.h"
#include "virsecret.h"
#include "storage_util.h"
#include "virsecureerase.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_rbd");

struct _virStorageBackendRBDState {
    rados_t cluster;
    rados_ioctx_t ioctx;
    time_t starttime;
};

typedef struct _virStorageBackendRBDState virStorageBackendRBDState;

typedef struct _virStoragePoolRBDConfigOptionsDef virStoragePoolRBDConfigOptionsDef;
struct _virStoragePoolRBDConfigOptionsDef {
    size_t noptions;
    char **names;
    char **values;
};

static void
virStoragePoolDefRBDNamespaceFree(void *nsdata)
{
    virStoragePoolRBDConfigOptionsDef *cmdopts = nsdata;
    size_t i;

    if (!cmdopts)
        return;

    for (i = 0; i < cmdopts->noptions; i++) {
        g_free(cmdopts->names[i]);
        g_free(cmdopts->values[i]);
    }
    g_free(cmdopts->names);
    g_free(cmdopts->values);

    g_free(cmdopts);
}


static int
virStoragePoolDefRBDNamespaceParse(xmlXPathContextPtr ctxt,
                                   void **data)
{
    virStoragePoolRBDConfigOptionsDef *cmdopts = NULL;
    int nnodes;
    size_t i;
    int ret = -1;
    g_autofree xmlNodePtr *nodes = NULL;

    nnodes = virXPathNodeSet("./rbd:config_opts/rbd:option", ctxt, &nodes);
    if (nnodes < 0)
        return -1;

    if (nnodes == 0)
        return 0;

    cmdopts = g_new0(virStoragePoolRBDConfigOptionsDef, 1);

    cmdopts->names = g_new0(char *, nnodes);
    cmdopts->values = g_new0(char *, nnodes);

    for (i = 0; i < nnodes; i++) {
        if (!(cmdopts->names[cmdopts->noptions] =
              virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("no rbd option name specified"));
            goto cleanup;
        }
        if (*cmdopts->names[cmdopts->noptions] == '\0') {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("empty rbd option name specified"));
            goto cleanup;
        }
        if (!(cmdopts->values[cmdopts->noptions] =
              virXMLPropString(nodes[i], "value"))) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("no rbd option value specified for name '%1$s'"),
                           cmdopts->names[cmdopts->noptions]);
            goto cleanup;
        }
        if (*cmdopts->values[cmdopts->noptions] == '\0') {
            virReportError(VIR_ERR_XML_ERROR,
                           _("empty rbd option value specified for name '%1$s'"),
                           cmdopts->names[cmdopts->noptions]);
            goto cleanup;
        }
        cmdopts->noptions++;
    }

    *data = g_steal_pointer(&cmdopts);
    ret = 0;

 cleanup:
    virStoragePoolDefRBDNamespaceFree(cmdopts);
    return ret;
}


static int
virStoragePoolDefRBDNamespaceFormatXML(virBuffer *buf,
                                       void *nsdata)
{
    size_t i;
    virStoragePoolRBDConfigOptionsDef *def = nsdata;

    if (!def)
        return 0;

    virBufferAddLit(buf, "<rbd:config_opts>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < def->noptions; i++) {
        virBufferEscapeString(buf, "<rbd:option name='%s' ", def->names[i]);
        virBufferEscapeString(buf, "value='%s'/>\n", def->values[i]);
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</rbd:config_opts>\n");

    return 0;
}


static int
virStorageBackendRBDRADOSConfSetQuiet(rados_t cluster,
                                      const char *option,
                                      const char *value)
{
    if (rados_conf_set(cluster, option, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to set RADOS option: %1$s"),
                       option);
        return -1;
    }

    return 0;
}


static int
virStorageBackendRBDRADOSConfSet(rados_t cluster,
                                 const char *option,
                                 const char *value)
{
    VIR_DEBUG("Setting RADOS option '%s' to '%s'",
              option, value);

    return virStorageBackendRBDRADOSConfSetQuiet(cluster, option, value);
}


static int
virStorageBackendRBDOpenRADOSConn(virStorageBackendRBDState *ptr,
                                  virStoragePoolDef *def)
{
    int ret = -1;
    virStoragePoolSource *source = &def->source;
    virStorageAuthDef *authdef = source->auth;
    g_autofree unsigned char *secret_value = NULL;
    size_t secret_value_size = 0;
    g_auto(virBuffer) mon_host = VIR_BUFFER_INITIALIZER;
    size_t i;
    const char *client_mount_timeout = "30";
    const char *mon_op_timeout = "30";
    const char *osd_op_timeout = "30";
    const char *rbd_default_format = "2";
    virConnectPtr conn = NULL;
    g_autofree char *mon_buff = NULL;

    if (authdef) {
        VIR_IDENTITY_AUTORESTORE virIdentity *oldident = NULL;
        g_autofree char *rados_key = NULL;
        int rc;

        VIR_DEBUG("Using cephx authorization, username: %s", authdef->username);

        if (rados_create(&ptr->cluster, authdef->username) < 0) {
            virReportSystemError(errno, "%s", _("failed to initialize RADOS"));
            goto cleanup;
        }

        if (!(oldident = virIdentityElevateCurrent()))
            goto cleanup;

        conn = virGetConnectSecret();
        if (!conn)
            return -1;

        if (virSecretGetSecretString(conn, &authdef->seclookupdef,
                                     VIR_SECRET_USAGE_TYPE_CEPH,
                                     &secret_value, &secret_value_size) < 0)
            goto cleanup;

        rados_key = g_base64_encode(secret_value, secret_value_size);
        virSecureErase(secret_value, secret_value_size);

        VIR_DEBUG("Setting RADOS option 'key'");
        rc = virStorageBackendRBDRADOSConfSetQuiet(ptr->cluster, "key", rados_key);
        virSecureEraseString(rados_key);

        if (rc < 0)
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

    /* combine host and port into portal */
    for (i = 0; i < source->nhost; i++) {
        if (source->hosts[i].name != NULL &&
            !source->hosts[i].port) {
            virBufferAsprintf(&mon_host, "%s,",
                              source->hosts[i].name);
        } else if (source->hosts[i].name != NULL &&
            source->hosts[i].port) {
            const char *incFormat;
            if (virSocketAddrNumericFamily(source->hosts[i].name) == AF_INET6) {
                /* IPv6 address must be escaped in brackets on the cmd line */
                incFormat = "[%s]:%d,";
            } else {
                /* listenAddress is a hostname or IPv4 */
                incFormat = "%s:%d,";
            }
            virBufferAsprintf(&mon_host, incFormat,
                              source->hosts[i].name,
                              source->hosts[i].port);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("received malformed monitor, check the XML definition"));
        }
    }

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

    if (def->namespaceData) {
        virStoragePoolRBDConfigOptionsDef *cmdopts = def->namespaceData;
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        for (i = 0; i < cmdopts->noptions; i++) {
            if (virStorageBackendRBDRADOSConfSet(ptr->cluster,
                                                 cmdopts->names[i],
                                                 cmdopts->values[i]) < 0)
                goto cleanup;
        }

        virUUIDFormat(def->uuid, uuidstr);
        VIR_WARN("Storage Pool name='%s' uuid='%s' is tainted by custom "
                 "config_opts from XML", def->name, uuidstr);
    }

    ptr->starttime = time(0);
    if (rados_connect(ptr->cluster) < 0) {
        virReportSystemError(errno, _("failed to connect to the RADOS monitor on: %1$s"),
                             mon_buff);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virObjectUnref(conn);
    return ret;
}

static int
virStorageBackendRBDOpenIoCTX(virStorageBackendRBDState *ptr,
                              virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    int rc = rados_ioctx_create(ptr->cluster, def->source.name, &ptr->ioctx);
    if (rc < 0) {
        virReportSystemError(errno, _("failed to create the RBD IoCTX. Does the pool '%1$s' exist?"),
                             def->source.name);
    }
    return rc;
}

static void
virStorageBackendRBDCloseRADOSConn(virStorageBackendRBDState *ptr)
{
    if (ptr->ioctx != NULL) {
        VIR_DEBUG("Closing RADOS IoCTX");
        g_clear_pointer(&ptr->ioctx, rados_ioctx_destroy);
    }

    if (ptr->cluster != NULL) {
        VIR_DEBUG("Closing RADOS connection");
        g_clear_pointer(&ptr->cluster, rados_shutdown);
    }

    VIR_DEBUG("RADOS connection existed for %ld seconds",
              time(0) - ptr->starttime);
}


static void
virStorageBackendRBDFreeState(virStorageBackendRBDState **ptr)
{
    if (!*ptr)
        return;

    virStorageBackendRBDCloseRADOSConn(*ptr);

    VIR_FREE(*ptr);
}


static virStorageBackendRBDState *
virStorageBackendRBDNewState(virStoragePoolObj *pool)
{
    virStorageBackendRBDState *ptr;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);

    ptr = g_new0(virStorageBackendRBDState, 1);

    if (virStorageBackendRBDOpenRADOSConn(ptr, def) < 0)
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
    int rc;

    if ((rc = rbd_get_features(image, features)) < 0) {
        virReportSystemError(errno,
                             _("failed to get the features of RBD image %1$s"),
                             volname);
        return rc;
    }

    return 0;
}

#if LIBRBD_VERSION_CODE > 265
static int
volStorageBackendRBDGetFlags(rbd_image_t image,
                             const char *volname,
                             uint64_t *flags)
{
    int rc;

    if ((rc = rbd_get_flags(image, flags)) < 0) {
        virReportSystemError(errno,
                             _("failed to get the flags of RBD image %1$s"),
                             volname);
        return rc;
    }

    return 0;
}

static bool
volStorageBackendRBDUseFastDiff(uint64_t features, uint64_t flags)
{
    return (((features & RBD_FEATURE_FAST_DIFF) != 0ULL) &&
            ((flags & RBD_FLAG_FAST_DIFF_INVALID) == 0ULL));
}

static int
virStorageBackendRBDRefreshVolInfoCb(uint64_t offset G_GNUC_UNUSED,
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
virStorageBackendRBDSetAllocation(virStorageVolDef *vol,
                                  rbd_image_t *image,
                                  rbd_image_info_t *info)
{
    int rc;
    size_t allocation = 0;

    if ((rc = rbd_diff_iterate2(image, NULL, 0, info->size, 0, 1,
                               &virStorageBackendRBDRefreshVolInfoCb,
                               &allocation)) < 0) {
        virReportSystemError(errno, _("failed to iterate RBD image '%1$s'"),
                             vol->name);
        return rc;
    }

    VIR_DEBUG("Found %zu bytes allocated for RBD image %s",
              allocation, vol->name);

    vol->target.allocation = allocation;

    return 0;
}

#else
static int
volStorageBackendRBDGetFlags(rbd_image_t image G_GNUC_UNUSED,
                             const char *volname G_GNUC_UNUSED,
                             uint64_t *flags)
{
    *flags = 0;
    return 0;
}

static int
volStorageBackendRBDUseFastDiff(uint64_t features G_GNUC_UNUSED,
                                uint64_t feature_flags G_GNUC_UNUSED)
{
    return false;
}

static int
virStorageBackendRBDSetAllocation(virStorageVolDef *vol G_GNUC_UNUSED,
                                  rbd_image_t *image G_GNUC_UNUSED,
                                  rbd_image_info_t *info G_GNUC_UNUSED)
{
    return false;
}
#endif

static int
volStorageBackendRBDRefreshVolInfo(virStorageVolDef *vol,
                                   virStoragePoolObj *pool,
                                   virStorageBackendRBDState *ptr)
{
    int ret = -1;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    rbd_image_t image = NULL;
    rbd_image_info_t info;
    uint64_t features;
    uint64_t flags;

    if ((ret = rbd_open_read_only(ptr->ioctx, vol->name, &image, NULL)) < 0) {
        virReportSystemError(errno, _("failed to open the RBD image '%1$s'"),
                             vol->name);
        goto cleanup;
    }

    if ((ret = rbd_stat(image, &info, sizeof(info))) < 0) {
        virReportSystemError(errno, _("failed to stat the RBD image '%1$s'"),
                             vol->name);
        goto cleanup;
    }

    if ((ret = volStorageBackendRBDGetFeatures(image, vol->name, &features)) < 0)
        goto cleanup;

    if ((ret = volStorageBackendRBDGetFlags(image, vol->name, &flags)) < 0)
        goto cleanup;

    vol->target.capacity = info.size;
    vol->type = VIR_STORAGE_VOL_NETWORK;
    vol->target.format = VIR_STORAGE_FILE_RAW;

    if (def->refresh &&
        def->refresh->volume.allocation == VIR_STORAGE_VOL_DEF_REFRESH_ALLOCATION_DEFAULT &&
        volStorageBackendRBDUseFastDiff(features, flags)) {
        VIR_DEBUG("RBD image %s/%s has fast-diff feature enabled. "
                  "Querying for actual allocation",
                  def->source.name, vol->name);

        if ((ret = virStorageBackendRBDSetAllocation(vol, image, &info)) < 0)
            goto cleanup;
    } else {
        vol->target.allocation = info.obj_size * info.num_objs;
    }

    VIR_DEBUG("Refreshed RBD image %s/%s (capacity: %llu allocation: %llu "
                      "obj_size: %"PRIu64" num_objs: %"PRIu64")",
              def->source.name, vol->name, vol->target.capacity,
              vol->target.allocation, info.obj_size, info.num_objs);

    VIR_FREE(vol->target.path);
    vol->target.path = g_strdup_printf("%s/%s", def->source.name, vol->name);

    VIR_FREE(vol->key);
    vol->key = g_strdup_printf("%s/%s", def->source.name, vol->name);

 cleanup:
    if (image)
        rbd_close(image);
    return ret;
}


#ifdef WITH_RBD_LIST2
static char **
virStorageBackendRBDGetVolNames(virStorageBackendRBDState *ptr)
{
    char **names = NULL;
    int rc;
    g_autofree rbd_image_spec_t *images = NULL;
    size_t nimages = 16;
    size_t i;

    while (true) {
        VIR_REALLOC_N(images, nimages);

        rc = rbd_list2(ptr->ioctx, images, &nimages);
        if (rc >= 0)
            break;
        if (rc != -ERANGE) {
            virReportSystemError(errno, "%s", _("Unable to list RBD images"));
            return NULL;
        }
    }

    names = g_new0(char *, nimages + 1);

    for (i = 0; i < nimages; i++)
        names[i] = g_strdup(images[i].name);

    rbd_image_spec_list_cleanup(images, nimages);

    return names;
}

#else /* ! WITH_RBD_LIST2 */

static char **
virStorageBackendRBDGetVolNames(virStorageBackendRBDState *ptr)
{
    g_auto(GStrv) names = NULL;
    size_t nnames = 0;
    int rc;
    size_t max_size = 1024;
    g_autofree char *namebuf = NULL;
    const char *name;

    while (true) {
        namebuf = g_new0(char, max_size);

        rc = rbd_list(ptr->ioctx, namebuf, &max_size);
        if (rc >= 0)
            break;
        if (rc != -ERANGE) {
            virReportSystemError(errno, "%s", _("Unable to list RBD images"));
            return NULL;
        }
        VIR_FREE(namebuf);
    }

    for (name = namebuf; name < namebuf + max_size;) {
        g_autofree char *namedup = NULL;

        if (STREQ(name, ""))
            break;

        namedup = g_strdup(name);

        VIR_APPEND_ELEMENT(names, nnames, namedup);

        name += strlen(name) + 1;
    }

    VIR_EXPAND_N(names, nnames, 1);

    return g_steal_pointer(&names);
}
#endif /* ! WITH_RBD_LIST2 */


static int
virStorageBackendRBDRefreshPool(virStoragePoolObj *pool)
{
    int rc, ret = -1;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendRBDState *ptr = NULL;
    struct rados_cluster_stat_t clusterstat;
    struct rados_pool_stat_t poolstat;
    g_auto(GStrv) names = NULL;
    size_t i;

    if (!(ptr = virStorageBackendRBDNewState(pool)))
        goto cleanup;

    if (rados_cluster_stat(ptr->cluster, &clusterstat) < 0) {
        virReportSystemError(errno, "%s", _("failed to stat the RADOS cluster"));
        goto cleanup;
    }

    if (rados_ioctx_pool_stat(ptr->ioctx, &poolstat) < 0) {
        virReportSystemError(errno, _("failed to stat the RADOS pool '%1$s'"),
                             def->source.name);
        goto cleanup;
    }

    def->capacity = clusterstat.kb * 1024;
    def->available = clusterstat.kb_avail * 1024;
    def->allocation = poolstat.num_bytes;

    VIR_DEBUG("Utilization of RBD pool %s: (kb: %"PRIu64" kb_avail: %"PRIu64
              " num_bytes: %"PRIu64")",
              def->source.name, clusterstat.kb, clusterstat.kb_avail,
              poolstat.num_bytes);

    if (!(names = virStorageBackendRBDGetVolNames(ptr)))
        goto cleanup;

    for (i = 0; names[i] != NULL; i++) {
        g_autoptr(virStorageVolDef) vol = NULL;

        vol = g_new0(virStorageVolDef, 1);

        vol->name = g_steal_pointer(&names[i]);

        rc = volStorageBackendRBDRefreshVolInfo(vol, pool, ptr);

        /* It could be that a volume has been deleted through a different route
         * then libvirt and that will cause a -ENOENT to be returned.
         *
         * Another possibility is that there is something wrong with the placement
         * group (PG) that RBD image's header is in and that causes -ETIMEDOUT
         * to be returned.
         *
         * Do not error out and simply ignore the volume
         */
        if (rc < 0) {
            if (rc == -ENOENT || rc == -ETIMEDOUT)
                continue;

            goto cleanup;
        }

        if (virStoragePoolObjAddVol(pool, vol) < 0)
            goto cleanup;
        vol = NULL;
    }

    VIR_DEBUG("Found %zu images in RBD pool %s",
              virStoragePoolObjGetVolumesCount(pool), def->source.name);

    ret = 0;

 cleanup:
    virStorageBackendRBDFreeState(&ptr);
    return ret;
}

static int
virStorageBackendRBDCleanupSnapshots(rados_ioctx_t ioctx,
                                     virStoragePoolSource *source,
                                     virStorageVolDef *vol)
{
    int ret = -1;
    int max_snaps = 128;
    int snap_count, protected;
    size_t i;
    rbd_image_t image = NULL;
    g_autofree rbd_snap_info_t *snaps = NULL;

    if (rbd_open(ioctx, vol->name, &image, NULL) < 0) {
       virReportSystemError(errno, _("failed to open the RBD image '%1$s'"),
                            vol->name);
       goto cleanup;
    }

    do {
        snaps = g_new0(rbd_snap_info_t, max_snaps);

        snap_count = rbd_snap_list(image, snaps, &max_snaps);
        if (snap_count <= 0)
            VIR_FREE(snaps);

    } while (snap_count == -ERANGE);

    VIR_DEBUG("Found %d snapshots for volume %s/%s", snap_count,
              source->name, vol->name);

    for (i = 0; i < snap_count; i++) {
        if (rbd_snap_is_protected(image, snaps[i].name, &protected) < 0) {
            virReportSystemError(errno, _("failed to verify if snapshot '%1$s/%2$s@%3$s' is protected"),
                                 source->name, vol->name,
                                 snaps[i].name);
            goto cleanup;
        }

        if (protected == 1) {
            VIR_DEBUG("Snapshot %s/%s@%s is protected needs to be "
                      "unprotected", source->name, vol->name,
                      snaps[i].name);

            if (rbd_snap_unprotect(image, snaps[i].name) < 0) {
                virReportSystemError(errno, _("failed to unprotect snapshot '%1$s/%2$s@%3$s'"),
                                     source->name, vol->name,
                                     snaps[i].name);
                goto cleanup;
            }
        }

        VIR_DEBUG("Removing snapshot %s/%s@%s", source->name,
                  vol->name, snaps[i].name);

        if (rbd_snap_remove(image, snaps[i].name) < 0) {
            virReportSystemError(errno, _("failed to remove snapshot '%1$s/%2$s@%3$s'"),
                                 source->name, vol->name,
                                 snaps[i].name);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    if (snaps)
        rbd_snap_list_end(snaps);

    if (image)
        rbd_close(image);

    return ret;
}

static int
virStorageBackendRBDDeleteVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol,
                              unsigned int flags)
{
    int rc, ret = -1;
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendRBDState *ptr = NULL;

    virCheckFlags(VIR_STORAGE_VOL_DELETE_ZEROED |
                  VIR_STORAGE_VOL_DELETE_WITH_SNAPSHOTS, -1);

    VIR_DEBUG("Removing RBD image %s/%s", def->source.name, vol->name);

    if (flags & VIR_STORAGE_VOL_DELETE_ZEROED)
        VIR_WARN("%s", "This storage backend does not support zeroed removal of volumes");

    if (!(ptr = virStorageBackendRBDNewState(pool)))
        goto cleanup;

    if (flags & VIR_STORAGE_VOL_DELETE_WITH_SNAPSHOTS) {
        if (virStorageBackendRBDCleanupSnapshots(ptr->ioctx, &def->source,
                                                 vol) < 0)
            goto cleanup;
    }

    VIR_DEBUG("Removing volume %s/%s", def->source.name, vol->name);

    rc = rbd_remove(ptr->ioctx, vol->name);
    if (rc < 0 && (-rc) != ENOENT) {
        virReportSystemError(errno, _("failed to remove volume '%1$s/%2$s'"),
                             def->source.name, vol->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virStorageBackendRBDFreeState(&ptr);
    return ret;
}


static int
virStorageBackendRBDCreateVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);

    vol->type = VIR_STORAGE_VOL_NETWORK;

    if (vol->target.format != VIR_STORAGE_FILE_RAW) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only RAW volumes are supported by this storage pool"));
        return -1;
    }

    VIR_FREE(vol->target.path);
    vol->target.path = g_strdup_printf("%s/%s", def->source.name, vol->name);

    VIR_FREE(vol->key);
    vol->key = g_strdup_printf("%s/%s", def->source.name, vol->name);

    return 0;
}

static int virStorageBackendRBDCreateImage(rados_ioctx_t io,
                                           char *name, long capacity)
{
    int order = 0;
    return rbd_create(io, name, capacity, &order);
}

static int
virStorageBackendRBDBuildVol(virStoragePoolObj *pool,
                             virStorageVolDef *vol,
                             unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendRBDState *ptr = NULL;
    int ret = -1;

    VIR_DEBUG("Creating RBD image %s/%s with size %llu",
              def->source.name, vol->name, vol->target.capacity);

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

    if (!(ptr = virStorageBackendRBDNewState(pool)))
        goto cleanup;

    if (virStorageBackendRBDCreateImage(ptr->ioctx, vol->name,
                                       vol->target.capacity) < 0) {
        virReportSystemError(errno, _("failed to create volume '%1$s/%2$s'"),
                             def->source.name, vol->name);
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
    uint8_t oldformat;

    if (rbd_get_old_format(image, &oldformat) < 0) {
        virReportSystemError(errno, _("failed to get the format of RBD image %1$s"),
                             volname);
        return -1;
    }

    if (oldformat != 0) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("RBD image %1$s is old format. Does not support extended features and striping"),
                       volname);
        return -1;
    }

    if (volStorageBackendRBDGetFeatures(image, volname, features) < 0)
        return -1;

    if (rbd_get_stripe_unit(image, stripe_unit) < 0) {
        virReportSystemError(errno, _("failed to get the stripe unit of RBD image %1$s"),
                             volname);
        return -1;
    }

    if (rbd_get_stripe_count(image, stripe_count) < 0) {
        virReportSystemError(errno, _("failed to get the stripe count of RBD image %1$s"),
                             volname);
        return -1;
    }

    return 0;
}

/* Callback function for rbd_diff_iterate() */
static int
virStorageBackendRBDIterateCb(uint64_t offset G_GNUC_UNUSED,
                              size_t length G_GNUC_UNUSED,
                              int exists G_GNUC_UNUSED,
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
                                       virBuffer *snapname)
{
    int ret = -1;
    int snap_count;
    int max_snaps = 128;
    size_t i;
    int diff;
    rbd_image_info_t info;
    g_autofree rbd_snap_info_t *snaps = NULL;

    if (rbd_stat(image, &info, sizeof(info)) < 0) {
        virReportSystemError(errno, _("failed to stat the RBD image %1$s"),
                             imgname);
        goto cleanup;
    }

    do {
        snaps = g_new0(rbd_snap_info_t, max_snaps);

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
        if (rbd_diff_iterate2(image, snaps[i].name, 0, info.size, 0, 1,
                             virStorageBackendRBDIterateCb, (void *)&diff) < 0) {
#else
        if (rbd_diff_iterate(image, snaps[i].name, 0, info.size,
                            virStorageBackendRBDIterateCb, (void *)&diff) < 0) {
#endif
            virReportSystemError(errno, _("failed to iterate RBD snapshot %1$s@%2$s"),
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

    return ret;
}

static int
virStorageBackendRBDSnapshotCreate(rbd_image_t image,
                                   char *imgname,
                                   char *snapname)
{
    VIR_DEBUG("Creating RBD snapshot %s@%s", imgname, snapname);

    if (rbd_snap_create(image, snapname) < 0) {
        virReportSystemError(errno, _("failed to create RBD snapshot %1$s@%2$s"),
                                   imgname, snapname);
        return -1;
    }

    return 0;
}

static int
virStorageBackendRBDSnapshotProtect(rbd_image_t image,
                                    char *imgname,
                                    char *snapname)
{
    int protected;

    VIR_DEBUG("Querying if RBD snapshot %s@%s is protected", imgname, snapname);

    if (rbd_snap_is_protected(image, snapname, &protected) < 0) {
        virReportSystemError(errno,
                             _("failed to verify if RBD snapshot %1$s@%2$s is protected"),
                             imgname, snapname);
        return -1;
    }

    if (protected == 0) {
        VIR_DEBUG("RBD Snapshot %s@%s is not protected, protecting",
                  imgname, snapname);

        if (rbd_snap_protect(image, snapname) < 0) {
            virReportSystemError(errno, _("failed to protect RBD snapshot %1$s@%2$s"),
                                       imgname, snapname);
            return -1;
        }
    } else {
        VIR_DEBUG("RBD Snapshot %s@%s is already protected", imgname, snapname);
    }

    return 0;
}

static int
virStorageBackendRBDCloneImage(rados_ioctx_t io,
                               char *origvol,
                               char *newvol)
{
    int ret = -1;
    int order = 0;
    uint64_t features;
    uint64_t stripe_count;
    uint64_t stripe_unit;
    g_auto(virBuffer) snapname = VIR_BUFFER_INITIALIZER;
    rbd_image_t image = NULL;
    g_autofree char *snapname_buff = NULL;

    if (rbd_open(io, origvol, &image, NULL) < 0) {
        virReportSystemError(errno, _("failed to open the RBD image %1$s"),
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
    if (virStorageBackendRBDSnapshotProtect(image, origvol, snapname_buff) < 0)
        goto cleanup;

    VIR_DEBUG("Performing RBD clone from %s to %s", origvol, newvol);

    if (rbd_clone2(io, origvol, snapname_buff, io, newvol, features,
                   &order, stripe_unit, stripe_count) < 0) {
        virReportSystemError(errno, _("failed to clone RBD volume %1$s to %2$s"),
                             origvol, newvol);
        goto cleanup;
    }

    VIR_DEBUG("Cloned RBD image %s to %s", origvol, newvol);

    ret = 0;

 cleanup:
    if (image)
        rbd_close(image);

    return ret;
}

static int
virStorageBackendRBDBuildVolFrom(virStoragePoolObj *pool,
                                 virStorageVolDef *newvol,
                                 virStorageVolDef *origvol,
                                 unsigned int flags)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    virStorageBackendRBDState *ptr = NULL;
    int ret = -1;

    VIR_DEBUG("Creating clone of RBD image %s/%s with name %s",
              def->source.name, origvol->name, newvol->name);

    virCheckFlags(0, -1);

    if (!(ptr = virStorageBackendRBDNewState(pool)))
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
virStorageBackendRBDRefreshVol(virStoragePoolObj *pool,
                               virStorageVolDef *vol)
{
    virStorageBackendRBDState *ptr = NULL;
    int ret = -1;

    if (!(ptr = virStorageBackendRBDNewState(pool)))
        goto cleanup;

    if (volStorageBackendRBDRefreshVolInfo(vol, pool, ptr) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virStorageBackendRBDFreeState(&ptr);
    return ret;
}

static int
virStorageBackendRBDResizeVol(virStoragePoolObj *pool,
                              virStorageVolDef *vol,
                              unsigned long long capacity,
                              unsigned int flags)
{
    virStorageBackendRBDState *ptr = NULL;
    rbd_image_t image = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    if (!(ptr = virStorageBackendRBDNewState(pool)))
        goto cleanup;

    if (rbd_open(ptr->ioctx, vol->name, &image, NULL) < 0) {
       virReportSystemError(errno, _("failed to open the RBD image '%1$s'"),
                            vol->name);
       goto cleanup;
    }

    if (rbd_resize(image, capacity) < 0) {
        virReportSystemError(errno, _("failed to resize the RBD image '%1$s'"),
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
    unsigned long long offset = 0;
    unsigned long long length;
    g_autofree char *writebuf = NULL;

    writebuf = g_new0(char, info->obj_size * stripe_count);

    while (offset < info->size) {
        length = MIN((info->size - offset), (info->obj_size * stripe_count));

        if (rbd_write(image, offset, length, writebuf) < 0) {
            virReportSystemError(errno, _("writing %1$llu bytes failed on RBD image %2$s at offset %3$llu"),
                                 length, imgname, offset);
            return -1;
        }

        VIR_DEBUG("Wrote %llu bytes to RBD image %s at offset %llu",
                  length, imgname, offset);

        offset += length;
    }

    return 0;
}

static int
virStorageBackendRBDVolWipeDiscard(rbd_image_t image,
                                   char *imgname,
                                   rbd_image_info_t *info,
                                   uint64_t stripe_count)
{
    unsigned long long offset = 0;
    unsigned long long length;

    VIR_DEBUG("Wiping RBD %s volume using discard)", imgname);

    while (offset < info->size) {
        length = MIN((info->size - offset), (info->obj_size * stripe_count));

        if (rbd_discard(image, offset, length) < 0) {
            virReportSystemError(errno, _("discarding %1$llu bytes failed on RBD image %2$s at offset %3$llu"),
                                 length, imgname, offset);
            return -1;
        }

        VIR_DEBUG("Discarded %llu bytes of RBD image %s at offset %llu",
                  length, imgname, offset);

        offset += length;
    }

    return 0;
}

static int
virStorageBackendRBDVolWipe(virStoragePoolObj *pool,
                            virStorageVolDef *vol,
                            unsigned int algorithm,
                            unsigned int flags)
{
    virStorageBackendRBDState *ptr = NULL;
    virStoragePoolDef *def;
    rbd_image_t image = NULL;
    rbd_image_info_t info;
    uint64_t stripe_count;
    int rc = 0;
    int ret = -1;

    virCheckFlags(0, -1);

    virObjectLock(pool);
    def = virStoragePoolObjGetDef(pool);
    VIR_DEBUG("Wiping RBD image %s/%s", def->source.name, vol->name);
    ptr = virStorageBackendRBDNewState(pool);
    virObjectUnlock(pool);

    if (!ptr)
        goto cleanup;

    if (rbd_open(ptr->ioctx, vol->name, &image, NULL) < 0) {
        virReportSystemError(errno, _("failed to open the RBD image %1$s"),
                             vol->name);
        goto cleanup;
    }

    if (rbd_stat(image, &info, sizeof(info)) < 0) {
        virReportSystemError(errno, _("failed to stat the RBD image %1$s"),
                             vol->name);
        goto cleanup;
    }

    if (rbd_get_stripe_count(image, &stripe_count) < 0) {
        virReportSystemError(errno, _("failed to get stripe count of RBD image %1$s"),
                             vol->name);
        goto cleanup;
    }

    VIR_DEBUG("Need to wipe %"PRIu64" bytes from RBD image %s/%s",
              info.size, def->source.name, vol->name);

    switch ((virStorageVolWipeAlgorithm) algorithm) {
    case VIR_STORAGE_VOL_WIPE_ALG_ZERO:
        rc = virStorageBackendRBDVolWipeZero(image, vol->name,
                                            &info, stripe_count);
            break;
    case VIR_STORAGE_VOL_WIPE_ALG_TRIM:
        rc = virStorageBackendRBDVolWipeDiscard(image, vol->name,
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
        virReportError(VIR_ERR_INVALID_ARG, _("unsupported algorithm %1$d"),
                       algorithm);
        goto cleanup;
    }

    if (rc < 0) {
        virReportSystemError(errno, _("failed to wipe RBD image %1$s"),
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


static virXMLNamespace virStoragePoolRBDXMLNamespace = {
    .parse = virStoragePoolDefRBDNamespaceParse,
    .free = virStoragePoolDefRBDNamespaceFree,
    .format = virStoragePoolDefRBDNamespaceFormatXML,
    .prefix = "rbd",
    .uri = "http://libvirt.org/schemas/storagepool/rbd/1.0",
};


int
virStorageBackendRBDRegister(void)
{
    if (virStorageBackendRegister(&virStorageBackendRBD) < 0)
        return -1;

    return virStorageBackendNamespaceInit(VIR_STORAGE_POOL_RBD,
                                          &virStoragePoolRBDXMLNamespace);
}
