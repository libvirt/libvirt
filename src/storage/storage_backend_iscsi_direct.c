/*
 * storage_backend_iscsi_direct.c: storage backend for iSCSI using libiscsi
 *
 * Copyright (C) 2018 Clementine Hayat.
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

#include <iscsi/iscsi.h>
#include <iscsi/scsi-lowlevel.h>

#include "datatypes.h"
#include "secret_util.h"
#include "storage_backend_iscsi_direct.h"
#include "storage_util.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virobject.h"
#include "virstring.h"
#include "virtime.h"
#include "viruuid.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

#define ISCSI_DEFAULT_TARGET_PORT 3260
#define VIR_ISCSI_TEST_UNIT_TIMEOUT 30 * 1000
#define BLOCK_PER_PACKET 128
#define VOL_NAME_PREFIX "unit:0:0:"

VIR_LOG_INIT("storage.storage_backend_iscsi_direct");

static struct iscsi_context *
virISCSIDirectCreateContext(const char* initiator_iqn)
{
    struct iscsi_context *iscsi = NULL;

    iscsi = iscsi_create_context(initiator_iqn);
    if (!iscsi)
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to create iscsi context for %s"),
                       initiator_iqn);
    return iscsi;
}

static char *
virStorageBackendISCSIDirectPortal(virStoragePoolSourcePtr source)
{
    char *portal = NULL;

    if (source->nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        return NULL;
    }
    if (source->hosts[0].port == 0) {
        ignore_value(virAsprintf(&portal, "%s:%d",
                                 source->hosts[0].name,
                                 ISCSI_DEFAULT_TARGET_PORT));
    } else if (strchr(source->hosts[0].name, ':')) {
        ignore_value(virAsprintf(&portal, "[%s]:%d",
                                 source->hosts[0].name,
                                 source->hosts[0].port));
    } else {
        ignore_value(virAsprintf(&portal, "%s:%d",
                                 source->hosts[0].name,
                                 source->hosts[0].port));
    }
    return portal;
}

static int
virStorageBackendISCSIDirectSetAuth(struct iscsi_context *iscsi,
                                    virStoragePoolSourcePtr source)
{
    unsigned char *secret_value = NULL;
    size_t secret_size;
    virStorageAuthDefPtr authdef = source->auth;
    int ret = -1;
    virConnectPtr conn = NULL;

    if (!authdef || authdef->authType == VIR_STORAGE_AUTH_TYPE_NONE)
        return 0;

    VIR_DEBUG("username='%s' authType=%d seclookupdef.type=%d",
              authdef->username, authdef->authType, authdef->seclookupdef.type);

    if (authdef->authType != VIR_STORAGE_AUTH_TYPE_CHAP) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("iscsi-direct pool only supports 'chap' auth type"));
        return ret;
    }

    if (!(conn = virGetConnectSecret()))
        return ret;

    if (virSecretGetSecretString(conn, &authdef->seclookupdef,
                                 VIR_SECRET_USAGE_TYPE_ISCSI,
                                 &secret_value, &secret_size) < 0)
        goto cleanup;

    if (VIR_REALLOC_N(secret_value, secret_size + 1) < 0)
        goto cleanup;

    secret_value[secret_size] = '\0';

    if (iscsi_set_initiator_username_pwd(iscsi,
                                         authdef->username,
                                         (const char *)secret_value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to set credential: %s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_DISPOSE_N(secret_value, secret_size);
    virObjectUnref(conn);
    return ret;
}

static int
virISCSIDirectSetContext(struct iscsi_context *iscsi,
                         const char *target_name,
                         enum iscsi_session_type session)
{
    if (iscsi_init_transport(iscsi, TCP_TRANSPORT) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to init transport: %s"),
                       iscsi_get_error(iscsi));
        return -1;
    }
    if (session == ISCSI_SESSION_NORMAL) {
        if (iscsi_set_targetname(iscsi, target_name) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to set target name: %s"),
                           iscsi_get_error(iscsi));
            return -1;
        }
    }
    if (iscsi_set_session_type(iscsi, session) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to set session type: %s"),
                       iscsi_get_error(iscsi));
        return -1;
    }
    return 0;
}

static int
virISCSIDirectConnect(struct iscsi_context *iscsi,
                      const char *portal)
{
    if (iscsi_connect_sync(iscsi, portal) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to connect: %s"),
                       iscsi_get_error(iscsi));
        return -1;
    }
    if (iscsi_login_sync(iscsi) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to login: %s"),
                       iscsi_get_error(iscsi));
        return -1;
    }
    return 0;
}

static int
virISCSIDirectTestUnitReady(struct iscsi_context *iscsi,
                            int lun)
{
    struct scsi_task *task = NULL;
    int ret = -1;
    virTimeBackOffVar timebackoff;

    if (virTimeBackOffStart(&timebackoff, 1,
                            VIR_ISCSI_TEST_UNIT_TIMEOUT) < 0)
        goto cleanup;

    do {
        if (!(task = iscsi_testunitready_sync(iscsi, lun))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed testunitready: %s"),
                           iscsi_get_error(iscsi));
            goto cleanup;
        }

        if (task->status != SCSI_STATUS_CHECK_CONDITION ||
            task->sense.key != SCSI_SENSE_UNIT_ATTENTION ||
            task->sense.ascq != SCSI_SENSE_ASCQ_BUS_RESET)
            break;

        scsi_free_scsi_task(task);
    } while (virTimeBackOffWait(&timebackoff));

    if (task->status != SCSI_STATUS_GOOD) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed testunitready: %s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    scsi_free_scsi_task(task);
    return ret;
}

static int
virISCSIDirectSetVolumeAttributes(virStoragePoolObjPtr pool,
                                  virStorageVolDefPtr vol,
                                  int lun,
                                  char *portal)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);

    if (virAsprintf(&vol->name, "%s%u", VOL_NAME_PREFIX, lun) < 0)
        return -1;
    if (virAsprintf(&vol->key, "ip-%s-iscsi-%s-lun-%u", portal,
                    def->source.devices[0].path, lun) < 0)
        return -1;
    if (virAsprintf(&vol->target.path, "ip-%s-iscsi-%s-lun-%u", portal,
                    def->source.devices[0].path, lun) < 0)
        return -1;
    return 0;
}

static int
virISCSIDirectGetVolumeCapacity(struct iscsi_context *iscsi,
                                int lun,
                                uint32_t *block_size,
                                uint64_t *nb_block)
{
    struct scsi_task *task = NULL;
    struct scsi_inquiry_standard *inq = NULL;
    int ret = -1;

    if (!(task = iscsi_inquiry_sync(iscsi, lun, 0, 0, 64)) ||
        task->status != SCSI_STATUS_GOOD) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to send inquiry command: %s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }

    if (!(inq = scsi_datain_unmarshall(task))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to unmarshall reply: %s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }

    if (inq->device_type == SCSI_INQUIRY_PERIPHERAL_DEVICE_TYPE_DIRECT_ACCESS) {
        struct scsi_readcapacity16 *rc16 = NULL;

        scsi_free_scsi_task(task);
        task = NULL;

        if (!(task = iscsi_readcapacity16_sync(iscsi, lun)) ||
            task->status != SCSI_STATUS_GOOD) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to get capacity of lun: %s"),
                           iscsi_get_error(iscsi));
            goto cleanup;
        }

        if (!(rc16 = scsi_datain_unmarshall(task))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to unmarshall reply: %s"),
                           iscsi_get_error(iscsi));
            goto cleanup;
        }

        *block_size  = rc16->block_length;
        *nb_block = rc16->returned_lba;

    }

    ret = 0;
 cleanup:
    scsi_free_scsi_task(task);
    return ret;
}

static int
virISCSIDirectRefreshVol(virStoragePoolObjPtr pool,
                         struct iscsi_context *iscsi,
                         int lun,
                         char *portal)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    uint32_t block_size;
    uint64_t nb_block;
    g_autoptr(virStorageVolDef) vol = NULL;

    if (virISCSIDirectTestUnitReady(iscsi, lun) < 0)
        return -1;

    if (VIR_ALLOC(vol) < 0)
        return -1;

    vol->type = VIR_STORAGE_VOL_NETWORK;

    if (virISCSIDirectGetVolumeCapacity(iscsi, lun, &block_size, &nb_block) < 0)
        return -1;

    vol->target.capacity = block_size * nb_block;
    vol->target.allocation = block_size * nb_block;
    def->capacity += vol->target.capacity;
    def->allocation += vol->target.allocation;

    if (virISCSIDirectSetVolumeAttributes(pool, vol, lun, portal) < 0)
        return -1;

    if (virStoragePoolObjAddVol(pool, vol) < 0)
        return -1;
    vol = NULL;

    return 0;
}

static int
virISCSIDirectReportLuns(virStoragePoolObjPtr pool,
                         struct iscsi_context *iscsi,
                         char *portal)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    struct scsi_task *task = NULL;
    struct scsi_reportluns_list *list = NULL;
    int full_size;
    size_t i;
    int ret = -1;

    if (!(task = iscsi_reportluns_sync(iscsi, 0, 16))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to reportluns: %s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }

    full_size = scsi_datain_getfullsize(task);

    if (full_size > task->datain.size) {
        scsi_free_scsi_task(task);
        if (!(task = iscsi_reportluns_sync(iscsi, 0, full_size))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to reportluns: %s"),
                           iscsi_get_error(iscsi));
            goto cleanup;
        }
    }

    if (!(list = scsi_datain_unmarshall(task))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to unmarshall reportluns: %s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }

    def->capacity = 0;
    def->allocation = 0;
    for (i = 0; i < list->num; i++) {
        if (virISCSIDirectRefreshVol(pool, iscsi, list->luns[i], portal) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    scsi_free_scsi_task(task);
    return ret;
}

static int
virISCSIDirectDisconnect(struct iscsi_context *iscsi)
{
    if (iscsi_logout_sync(iscsi) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to logout: %s"),
                       iscsi_get_error(iscsi));
        return -1;
    }
    if (iscsi_disconnect(iscsi) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to disconnect: %s"),
                       iscsi_get_error(iscsi));
        return -1;
    }
    return 0;
}

static int
virISCSIDirectUpdateTargets(struct iscsi_context *iscsi,
                            size_t *ntargets,
                            char ***targets)
{
    int ret = -1;
    struct iscsi_discovery_address *addr;
    struct iscsi_discovery_address *tmp_addr;
    size_t tmp_ntargets = 0;
    char **tmp_targets = NULL;

    if (!(addr = iscsi_discovery_sync(iscsi))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to discover session: %s"),
                       iscsi_get_error(iscsi));
        return ret;
    }

    for (tmp_addr = addr; tmp_addr; tmp_addr = tmp_addr->next) {
        g_autofree char *target = NULL;

        if (VIR_STRDUP(target, tmp_addr->target_name) < 0)
            goto cleanup;

        if (VIR_APPEND_ELEMENT(tmp_targets, tmp_ntargets, target) < 0)
            goto cleanup;
    }

    VIR_STEAL_PTR(*targets, tmp_targets);
    *ntargets = tmp_ntargets;
    tmp_ntargets = 0;

    ret = 0;
 cleanup:
    iscsi_free_discovery_data(iscsi, addr);
    virStringListFreeCount(tmp_targets, tmp_ntargets);
    return ret;
}

static int
virISCSIDirectScanTargets(char *initiator_iqn,
                          char *portal,
                          size_t *ntargets,
                          char ***targets)
{
    struct iscsi_context *iscsi = NULL;
    int ret = -1;

    if (!(iscsi = virISCSIDirectCreateContext(initiator_iqn)))
        goto cleanup;
    if (virISCSIDirectSetContext(iscsi, NULL, ISCSI_SESSION_DISCOVERY) < 0)
        goto cleanup;
    if (virISCSIDirectConnect(iscsi, portal) < 0)
        goto cleanup;
    if (virISCSIDirectUpdateTargets(iscsi, ntargets, targets) < 0)
        goto disconnect;

    ret = 0;
 disconnect:
    virISCSIDirectDisconnect(iscsi);
 cleanup:
    iscsi_destroy_context(iscsi);
    return ret;
}

static int
virStorageBackendISCSIDirectCheckPool(virStoragePoolObjPtr pool,
                                      bool *isActive)
{
    *isActive = virStoragePoolObjIsActive(pool);
    return 0;
}

static char *
virStorageBackendISCSIDirectFindPoolSources(const char *srcSpec,
                                            unsigned int flags)
{
    size_t ntargets = 0;
    char **targets = NULL;
    char *ret = NULL;
    size_t i;
    virStoragePoolSourceList list = {
        .type = VIR_STORAGE_POOL_ISCSI_DIRECT,
        .nsources = 0,
        .sources = NULL
    };
    g_autofree char *portal = NULL;
    g_autoptr(virStoragePoolSource) source = NULL;

    virCheckFlags(0, NULL);

    if (!srcSpec) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("hostname must be specified for iscsi sources"));
        return NULL;
    }

    if (!(source = virStoragePoolDefParseSourceString(srcSpec, list.type)))
        return NULL;

    if (source->nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        goto cleanup;
    }

    if (!source->initiator.iqn) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("missing initiator IQN"));
        goto cleanup;
    }

    if (!(portal = virStorageBackendISCSIDirectPortal(source)))
        goto cleanup;

    if (virISCSIDirectScanTargets(source->initiator.iqn, portal, &ntargets, &targets) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(list.sources, ntargets) < 0)
        goto cleanup;

    for (i = 0; i < ntargets; i++) {
        if (VIR_ALLOC_N(list.sources[i].devices, 1) < 0 ||
            VIR_ALLOC_N(list.sources[i].hosts, 1) < 0)
            goto cleanup;
        list.sources[i].nhost = 1;
        list.sources[i].hosts[0] = source->hosts[0];
        list.sources[i].initiator = source->initiator;
        list.sources[i].ndevice = 1;
        list.sources[i].devices[0].path = targets[i];
        list.nsources++;
    }

    if (!(ret = virStoragePoolSourceListFormat(&list)))
        goto cleanup;

 cleanup:
    if (list.sources) {
        for (i = 0; i < ntargets; i++) {
            VIR_FREE(list.sources[i].hosts);
            VIR_FREE(list.sources[i].devices);
        }
        VIR_FREE(list.sources);
    }
    for (i = 0; i < ntargets; i++)
        VIR_FREE(targets[i]);
    VIR_FREE(targets);
    return ret;
}

static struct iscsi_context *
virStorageBackendISCSIDirectSetConnection(virStoragePoolObjPtr pool,
                                          char **portalRet)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    struct iscsi_context *iscsi = NULL;
    g_autofree char *portal = NULL;

    if (!(iscsi = virISCSIDirectCreateContext(def->source.initiator.iqn)))
        goto error;
    if (!(portal = virStorageBackendISCSIDirectPortal(&def->source)))
        goto error;
    if (virStorageBackendISCSIDirectSetAuth(iscsi, &def->source) < 0)
        goto error;
    if (virISCSIDirectSetContext(iscsi, def->source.devices[0].path, ISCSI_SESSION_NORMAL) < 0)
        goto error;
    if (virISCSIDirectConnect(iscsi, portal) < 0)
        goto error;

    if (portalRet)
        VIR_STEAL_PTR(*portalRet, portal);

 cleanup:
    return iscsi;

 error:
    iscsi_destroy_context(iscsi);
    iscsi = NULL;
    goto cleanup;
}

static int
virStorageBackendISCSIDirectRefreshPool(virStoragePoolObjPtr pool)
{
    struct iscsi_context *iscsi = NULL;
    int ret = -1;
    g_autofree char *portal = NULL;

    if (!(iscsi = virStorageBackendISCSIDirectSetConnection(pool, &portal)))
        return -1;
    ret = virISCSIDirectReportLuns(pool, iscsi, portal);
    virISCSIDirectDisconnect(iscsi);
    iscsi_destroy_context(iscsi);
    return ret;
}

static int
virStorageBackendISCSIDirectGetLun(virStorageVolDefPtr vol,
                                   int *lun)
{
    const char *name;

    if (!(name = STRSKIP(vol->name, VOL_NAME_PREFIX)) ||
        virStrToLong_i(name, NULL, 10, lun) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid volume name %s"), vol->name);
        return -1;
    }

    return 0;
}

static int
virStorageBackendISCSIDirectVolWipeZero(virStorageVolDefPtr vol,
                                        struct iscsi_context *iscsi)
{
    uint64_t lba = 0;
    uint32_t block_size;
    uint64_t nb_block;
    struct scsi_task *task = NULL;
    int lun = 0;
    int ret = -1;
    g_autofree unsigned char *data = NULL;

    if (virStorageBackendISCSIDirectGetLun(vol, &lun) < 0)
        return ret;
    if (virISCSIDirectTestUnitReady(iscsi, lun) < 0)
        return ret;
    if (virISCSIDirectGetVolumeCapacity(iscsi, lun, &block_size, &nb_block))
        return ret;
    if (VIR_ALLOC_N(data, block_size * BLOCK_PER_PACKET))
        return ret;

    while (lba < nb_block) {
        const uint64_t to_write = MIN(nb_block - lba + 1, BLOCK_PER_PACKET);

        task = iscsi_write16_sync(iscsi, lun, lba, data,
                                  block_size * to_write,
                                  block_size, 0, 0, 0, 0, 0);

        if (!task ||
            task->status != SCSI_STATUS_GOOD) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to write to LUN %d: %s"),
                           lun, iscsi_get_error(iscsi));
            scsi_free_scsi_task(task);
            return -1;
        }

        scsi_free_scsi_task(task);
        lba += to_write;
    }

    return 0;
}

static int
virStorageBackenISCSIDirectWipeVol(virStoragePoolObjPtr pool,
                                   virStorageVolDefPtr vol,
                                   unsigned int algorithm,
                                   unsigned int flags)
{
    struct iscsi_context *iscsi = NULL;
    int ret = -1;

    virCheckFlags(0, -1);

    virObjectLock(pool);
    iscsi = virStorageBackendISCSIDirectSetConnection(pool, NULL);
    virObjectUnlock(pool);

    if (!iscsi)
        return -1;

    switch ((virStorageVolWipeAlgorithm) algorithm) {
    case VIR_STORAGE_VOL_WIPE_ALG_ZERO:
        if (virStorageBackendISCSIDirectVolWipeZero(vol, iscsi) < 0)
            goto cleanup;
        break;
    case VIR_STORAGE_VOL_WIPE_ALG_TRIM:
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

    ret = 0;
 cleanup:
    virISCSIDirectDisconnect(iscsi);
    iscsi_destroy_context(iscsi);
    return ret;
}


virStorageBackend virStorageBackendISCSIDirect = {
    .type = VIR_STORAGE_POOL_ISCSI_DIRECT,

    .checkPool = virStorageBackendISCSIDirectCheckPool,
    .findPoolSources = virStorageBackendISCSIDirectFindPoolSources,
    .refreshPool = virStorageBackendISCSIDirectRefreshPool,
    .wipeVol = virStorageBackenISCSIDirectWipeVol,
};

int
virStorageBackendISCSIDirectRegister(void)
{
    return virStorageBackendRegister(&virStorageBackendISCSIDirect);
}
