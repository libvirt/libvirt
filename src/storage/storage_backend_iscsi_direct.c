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
#include "virsecret.h"
#include "storage_backend_iscsi_direct.h"
#include "storage_util.h"
#include "virerror.h"
#include "viridentity.h"
#include "virlog.h"
#include "virobject.h"
#include "virstring.h"
#include "virtime.h"
#include "virsecureerase.h"

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
                       _("Failed to create iscsi context for %1$s"),
                       initiator_iqn);
    return iscsi;
}

static char *
virStorageBackendISCSIDirectPortal(virStoragePoolSource *source)
{
    char *portal = NULL;

    if (source->nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        return NULL;
    }
    if (source->hosts[0].port == 0) {
        portal = g_strdup_printf("%s:%d",
                                 source->hosts[0].name,
                                 ISCSI_DEFAULT_TARGET_PORT);
    } else if (strchr(source->hosts[0].name, ':')) {
        portal = g_strdup_printf("[%s]:%d",
                                 source->hosts[0].name,
                                 source->hosts[0].port);
    } else {
        portal = g_strdup_printf("%s:%d",
                                 source->hosts[0].name,
                                 source->hosts[0].port);
    }
    return portal;
}

static int
virStorageBackendISCSIDirectSetAuth(struct iscsi_context *iscsi,
                                    virStoragePoolSource *source)
{
    g_autofree unsigned char *secret_value = NULL;
    size_t secret_size;
    g_autofree char *secret_str = NULL;
    virStorageAuthDef *authdef = source->auth;
    g_autoptr(virConnect) conn = NULL;
    VIR_IDENTITY_AUTORESTORE virIdentity *oldident = NULL;

    if (!authdef || authdef->authType == VIR_STORAGE_AUTH_TYPE_NONE)
        return 0;

    VIR_DEBUG("username='%s' authType=%d seclookupdef.type=%d",
              authdef->username, authdef->authType, authdef->seclookupdef.type);

    if (authdef->authType != VIR_STORAGE_AUTH_TYPE_CHAP) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("iscsi-direct pool only supports 'chap' auth type"));
        return -1;
    }

    if (!(oldident = virIdentityElevateCurrent()))
        return -1;

    if (!(conn = virGetConnectSecret()))
        return -1;

    if (virSecretGetSecretString(conn, &authdef->seclookupdef,
                                 VIR_SECRET_USAGE_TYPE_ISCSI,
                                 &secret_value, &secret_size) < 0)
        return -1;

    secret_str = g_strndup((char *)secret_value, secret_size);
    virSecureErase(secret_value, secret_size);

    if (iscsi_set_initiator_username_pwd(iscsi,
                                         authdef->username, secret_str) < 0) {
        virSecureErase(secret_str, secret_size);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to set credential: %1$s"),
                       iscsi_get_error(iscsi));
        return -1;
    }
    virSecureErase(secret_str, secret_size);

    return 0;
}

static int
virISCSIDirectSetContext(struct iscsi_context *iscsi,
                         const char *target_name,
                         enum iscsi_session_type session)
{
    if (iscsi_init_transport(iscsi, TCP_TRANSPORT) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to init transport: %1$s"),
                       iscsi_get_error(iscsi));
        return -1;
    }
    if (session == ISCSI_SESSION_NORMAL) {
        if (iscsi_set_targetname(iscsi, target_name) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to set target name: %1$s"),
                           iscsi_get_error(iscsi));
            return -1;
        }
    }
    if (iscsi_set_session_type(iscsi, session) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to set session type: %1$s"),
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
                       _("Failed to connect: %1$s"),
                       iscsi_get_error(iscsi));
        return -1;
    }
    if (iscsi_login_sync(iscsi) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to login: %1$s"),
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
                           _("Failed testunitready: %1$s"),
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
                       _("Failed testunitready: %1$s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    scsi_free_scsi_task(task);
    return ret;
}

static int
virISCSIDirectSetVolumeAttributes(virStoragePoolObj *pool,
                                  virStorageVolDef *vol,
                                  int lun,
                                  char *portal)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);

    vol->name = g_strdup_printf("%s%u", VOL_NAME_PREFIX, lun);
    vol->key = g_strdup_printf("ip-%s-iscsi-%s-lun-%u", portal,
                               def->source.devices[0].path, lun);
    vol->target.path = g_strdup_printf("ip-%s-iscsi-%s-lun-%u", portal,
                                       def->source.devices[0].path, lun);
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
                       _("Failed to send inquiry command: %1$s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }

    if (!(inq = scsi_datain_unmarshall(task))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to unmarshall reply: %1$s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }

    if (inq->device_type == SCSI_INQUIRY_PERIPHERAL_DEVICE_TYPE_DIRECT_ACCESS) {
        struct scsi_readcapacity16 *rc16 = NULL;

        g_clear_pointer(&task, scsi_free_scsi_task);

        if (!(task = iscsi_readcapacity16_sync(iscsi, lun)) ||
            task->status != SCSI_STATUS_GOOD) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to get capacity of lun: %1$s"),
                           iscsi_get_error(iscsi));
            goto cleanup;
        }

        if (!(rc16 = scsi_datain_unmarshall(task))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to unmarshall reply: %1$s"),
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
virISCSIDirectRefreshVol(virStoragePoolObj *pool,
                         struct iscsi_context *iscsi,
                         int lun,
                         char *portal)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    uint32_t block_size = 0;
    uint64_t nb_block = 0;
    g_autoptr(virStorageVolDef) vol = NULL;

    if (virISCSIDirectTestUnitReady(iscsi, lun) < 0)
        return -1;

    vol = g_new0(virStorageVolDef, 1);

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
virISCSIDirectReportLuns(virStoragePoolObj *pool,
                         struct iscsi_context *iscsi,
                         char *portal)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    struct scsi_task *task = NULL;
    struct scsi_reportluns_list *list = NULL;
    int full_size;
    size_t i;
    int ret = -1;

    if (!(task = iscsi_reportluns_sync(iscsi, 0, 16))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to reportluns: %1$s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }

    full_size = scsi_datain_getfullsize(task);

    if (full_size > task->datain.size) {
        scsi_free_scsi_task(task);
        if (!(task = iscsi_reportluns_sync(iscsi, 0, full_size))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to reportluns: %1$s"),
                           iscsi_get_error(iscsi));
            goto cleanup;
        }
    }

    if (!(list = scsi_datain_unmarshall(task))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to unmarshall reportluns: %1$s"),
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
    virErrorPtr orig_err;
    int ret = -1;

    virErrorPreserveLast(&orig_err);

    if (iscsi_logout_sync(iscsi) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to logout: %1$s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }
    if (iscsi_disconnect(iscsi) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to disconnect: %1$s"),
                       iscsi_get_error(iscsi));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virErrorRestore(&orig_err);
    return ret;
}

static int
virISCSIDirectUpdateTargets(struct iscsi_context *iscsi,
                            size_t *ntargets,
                            char ***targets)
{
    struct iscsi_discovery_address *addr;
    struct iscsi_discovery_address *tmp_addr;
    size_t i = 0;

    *ntargets = 0;

    if (!(addr = iscsi_discovery_sync(iscsi))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to discover session: %1$s"),
                       iscsi_get_error(iscsi));
        return -1;
    }

    for (tmp_addr = addr; tmp_addr; tmp_addr = tmp_addr->next)
        (*ntargets)++;

    *targets = g_new0(char *, *ntargets + 1);

    for (tmp_addr = addr; tmp_addr; tmp_addr = tmp_addr->next)
        *targets[i++] = g_strdup(tmp_addr->target_name);

    iscsi_free_discovery_data(iscsi, addr);

    return 0;
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
virStorageBackendISCSIDirectCheckPool(virStoragePoolObj *pool,
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
    g_auto(GStrv) targets = NULL;
    size_t i;
    g_autoptr(virStoragePoolSourceList) list = g_new0(virStoragePoolSourceList, 1);
    g_autofree char *portal = NULL;
    g_autoptr(virStoragePoolSource) source = NULL;

    virCheckFlags(0, NULL);

    list->type = VIR_STORAGE_POOL_ISCSI_DIRECT;

    if (!srcSpec) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("hostname must be specified for iscsi sources"));
        return NULL;
    }

    if (!(source = virStoragePoolDefParseSourceString(srcSpec, list->type)))
        return NULL;

    if (source->nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        return NULL;
    }

    if (!source->initiator.iqn) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("missing initiator IQN"));
        return NULL;
    }

    if (!(portal = virStorageBackendISCSIDirectPortal(source)))
        return NULL;

    if (virISCSIDirectScanTargets(source->initiator.iqn, portal, &ntargets, &targets) < 0)
        return NULL;

    list->sources = g_new0(virStoragePoolSource, ntargets);

    for (i = 0; i < ntargets; i++) {
        list->sources[i].hosts = g_new0(virStoragePoolSourceHost, 1);
        list->sources[i].nhost = 1;
        list->sources[i].hosts[0].name = g_strdup(source->hosts[0].name);
        list->sources[i].hosts[0].port = source->hosts[0].port;

        virStorageSourceInitiatorCopy(&list->sources[i].initiator,
                                      &source->initiator);

        list->sources[i].devices = g_new0(virStoragePoolSourceDevice, 1);
        list->sources[i].ndevice = 1;
        list->sources[i].devices[0].path = g_strdup(targets[i]);

        list->nsources++;
    }

    return virStoragePoolSourceListFormat(list);
}

static struct iscsi_context *
virStorageBackendISCSIDirectSetConnection(virStoragePoolObj *pool,
                                          char **portalRet)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
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
        *portalRet = g_steal_pointer(&portal);

    return iscsi;

 error:
    iscsi_destroy_context(iscsi);
    return NULL;
}

static int
virStorageBackendISCSIDirectRefreshPool(virStoragePoolObj *pool)
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
virStorageBackendISCSIDirectGetLun(virStorageVolDef *vol,
                                   int *lun)
{
    const char *name;

    if (!(name = STRSKIP(vol->name, VOL_NAME_PREFIX)) ||
        virStrToLong_i(name, NULL, 10, lun) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid volume name %1$s"), vol->name);
        return -1;
    }

    return 0;
}

static int
virStorageBackendISCSIDirectVolWipeZero(virStorageVolDef *vol,
                                        struct iscsi_context *iscsi)
{
    uint64_t lba = 0;
    uint32_t block_size = 0;
    uint64_t nb_block = 0;
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
    data = g_new0(unsigned char, block_size * BLOCK_PER_PACKET);

    while (lba < nb_block) {
        const uint64_t to_write = MIN(nb_block - lba + 1, BLOCK_PER_PACKET);

        task = iscsi_write16_sync(iscsi, lun, lba, data,
                                  block_size * to_write,
                                  block_size, 0, 0, 0, 0, 0);

        if (!task ||
            task->status != SCSI_STATUS_GOOD) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to write to LUN %1$d: %2$s"),
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
virStorageBackenISCSIDirectWipeVol(virStoragePoolObj *pool,
                                   virStorageVolDef *vol,
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
        virReportError(VIR_ERR_INVALID_ARG, _("unsupported algorithm %1$d"),
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
