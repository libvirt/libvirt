/*
 * storage_backend_iscsi.c: storage backend for iSCSI handling
 *
 * Copyright (C) 2007-2016 Red Hat, Inc.
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

#include <dirent.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "datatypes.h"
#include "driver.h"
#include "storage_backend_iscsi.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virerror.h"
#include "virfile.h"
#include "viriscsi.h"
#include "virlog.h"
#include "virobject.h"
#include "virstring.h"
#include "viruuid.h"
#include "secret_util.h"
#include "storage_util.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_iscsi");

#define ISCSI_DEFAULT_TARGET_PORT 3260

static char *
virStorageBackendISCSIPortal(virStoragePoolSourcePtr source)
{
    char *portal = NULL;

    if (source->nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        return NULL;
    }

    if (source->hosts[0].port == 0)
        source->hosts[0].port = ISCSI_DEFAULT_TARGET_PORT;

    if (strchr(source->hosts[0].name, ':')) {
        ignore_value(virAsprintf(&portal, "[%s]:%d,1",
                                 source->hosts[0].name,
                                 source->hosts[0].port));
    } else {
        ignore_value(virAsprintf(&portal, "%s:%d,1",
                                 source->hosts[0].name,
                                 source->hosts[0].port));
    }

    return portal;
}


static char *
virStorageBackendISCSISession(virStoragePoolObjPtr pool,
                              bool probe)
{
    return virISCSIGetSession(pool->def->source.devices[0].path, probe);
}


static int
virStorageBackendISCSIGetHostNumber(const char *sysfs_path,
                                    uint32_t *host)
{
    int ret = -1;
    DIR *sysdir = NULL;
    struct dirent *dirent = NULL;
    int direrr;

    VIR_DEBUG("Finding host number from '%s'", sysfs_path);

    virFileWaitForDevices();

    if (virDirOpen(&sysdir, sysfs_path) < 0)
        goto cleanup;

    while ((direrr = virDirRead(sysdir, &dirent, sysfs_path)) > 0) {
        if (STRPREFIX(dirent->d_name, "target")) {
            if (sscanf(dirent->d_name, "target%u:", host) == 1) {
                ret = 0;
                goto cleanup;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to parse target '%s'"), dirent->d_name);
                goto cleanup;
            }
        }
    }

    if (direrr == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to get host number for iSCSI session "
                         "with path '%s'"), sysfs_path);
        goto cleanup;
    }

 cleanup:
    VIR_DIR_CLOSE(sysdir);
    return ret;
}

static int
virStorageBackendISCSIFindLUs(virStoragePoolObjPtr pool,
                              const char *session)
{
    char *sysfs_path;
    int retval = -1;
    uint32_t host;

    if (virAsprintf(&sysfs_path,
                    "/sys/class/iscsi_session/session%s/device", session) < 0)
        goto cleanup;

    if (virStorageBackendISCSIGetHostNumber(sysfs_path, &host) < 0)
        goto cleanup;

    if (virStorageBackendSCSIFindLUs(pool, host) < 0)
        goto cleanup;

    retval = 0;

 cleanup:

    VIR_FREE(sysfs_path);

    return retval;
}


static char *
virStorageBackendISCSIFindPoolSources(virConnectPtr conn ATTRIBUTE_UNUSED,
                                      const char *srcSpec,
                                      unsigned int flags)
{
    virStoragePoolSourcePtr source = NULL;
    size_t ntargets = 0;
    char **targets = NULL;
    char *ret = NULL;
    size_t i;
    virStoragePoolSourceList list = {
        .type = VIR_STORAGE_POOL_ISCSI,
        .nsources = 0,
        .sources = NULL
    };
    char *portal = NULL;

    virCheckFlags(0, NULL);

    if (!srcSpec) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("hostname must be specified for iscsi sources"));
        return NULL;
    }

    if (!(source = virStoragePoolDefParseSourceString(srcSpec,
                                                      list.type)))
        return NULL;

    if (source->nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        goto cleanup;
    }

    if (!(portal = virStorageBackendISCSIPortal(source)))
        goto cleanup;

    if (virISCSIScanTargets(portal, &ntargets, &targets) < 0)
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
    VIR_FREE(portal);
    virStoragePoolSourceFree(source);
    return ret;
}

static int
virStorageBackendISCSICheckPool(virStoragePoolObjPtr pool,
                                bool *isActive)
{
    char *session = NULL;
    int ret = -1;

    *isActive = false;

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

    if (pool->def->source.ndevice != 1 ||
        pool->def->source.devices[0].path == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing source device"));
        return -1;
    }

    if ((session = virStorageBackendISCSISession(pool, true)) != NULL) {
        *isActive = true;
        VIR_FREE(session);
    }
    ret = 0;

    return ret;
}


static int
virStorageBackendISCSISetAuth(const char *portal,
                              virConnectPtr conn,
                              virStoragePoolSourcePtr source)
{
    unsigned char *secret_value = NULL;
    size_t secret_size;
    virStorageAuthDefPtr authdef = source->auth;
    int ret = -1;

    if (!authdef || authdef->authType == VIR_STORAGE_AUTH_TYPE_NONE)
        return 0;

    VIR_DEBUG("username='%s' authType=%d seclookupdef.type=%d",
              authdef->username, authdef->authType, authdef->seclookupdef.type);
    if (authdef->authType != VIR_STORAGE_AUTH_TYPE_CHAP) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("iscsi pool only supports 'chap' auth type"));
        return -1;
    }

    if (!conn) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("iscsi 'chap' authentication not supported "
                         "for autostarted pools"));
        return -1;
    }

    if (virSecretGetSecretString(conn, &authdef->seclookupdef,
                                 VIR_SECRET_USAGE_TYPE_ISCSI,
                                 &secret_value, &secret_size) < 0)
        goto cleanup;

    if (virISCSINodeUpdate(portal,
                           source->devices[0].path,
                           "node.session.auth.authmethod",
                           "CHAP") < 0 ||
        virISCSINodeUpdate(portal,
                           source->devices[0].path,
                           "node.session.auth.username",
                           authdef->username) < 0 ||
        virISCSINodeUpdate(portal,
                           source->devices[0].path,
                           "node.session.auth.password",
                           (const char *)secret_value) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_DISPOSE_N(secret_value, secret_size);
    return ret;
}

static int
virStorageBackendISCSIStartPool(virConnectPtr conn,
                                virStoragePoolObjPtr pool)
{
    char *portal = NULL;
    char *session = NULL;
    int ret = -1;

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

    if (pool->def->source.ndevice != 1 ||
        pool->def->source.devices[0].path == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing source device"));
        return -1;
    }

    if ((session = virStorageBackendISCSISession(pool, true)) == NULL) {
        if ((portal = virStorageBackendISCSIPortal(&pool->def->source)) == NULL)
            goto cleanup;

        /* Create a static node record for the IQN target. Must be done
         * in order for login to the target */
        if (virISCSINodeNew(portal, pool->def->source.devices[0].path) < 0)
            goto cleanup;

        if (virStorageBackendISCSISetAuth(portal, conn, &pool->def->source) < 0)
            goto cleanup;

        if (virISCSIConnectionLogin(portal,
                                    pool->def->source.initiator.iqn,
                                    pool->def->source.devices[0].path) < 0)
            goto cleanup;
    }
    ret = 0;

 cleanup:
    VIR_FREE(portal);
    VIR_FREE(session);
    return ret;
}

static int
virStorageBackendISCSIRefreshPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolObjPtr pool)
{
    char *session = NULL;

    pool->def->allocation = pool->def->capacity = pool->def->available = 0;

    if ((session = virStorageBackendISCSISession(pool, false)) == NULL)
        goto cleanup;
    if (virISCSIRescanLUNs(session) < 0)
        goto cleanup;
    if (virStorageBackendISCSIFindLUs(pool, session) < 0)
        goto cleanup;
    VIR_FREE(session);

    return 0;

 cleanup:
    VIR_FREE(session);
    return -1;
}


static int
virStorageBackendISCSIStopPool(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virStoragePoolObjPtr pool)
{
    char *portal;
    char *session;
    int ret = -1;

    if ((session = virStorageBackendISCSISession(pool, true)) == NULL)
        return 0;
    VIR_FREE(session);

    if ((portal = virStorageBackendISCSIPortal(&pool->def->source)) == NULL)
        return -1;

    if (virISCSIConnectionLogout(portal,
                                 pool->def->source.initiator.iqn,
                                 pool->def->source.devices[0].path) < 0)
        goto cleanup;
    ret = 0;

 cleanup:
    VIR_FREE(portal);
    return ret;
}

virStorageBackend virStorageBackendISCSI = {
    .type = VIR_STORAGE_POOL_ISCSI,

    .checkPool = virStorageBackendISCSICheckPool,
    .startPool = virStorageBackendISCSIStartPool,
    .refreshPool = virStorageBackendISCSIRefreshPool,
    .stopPool = virStorageBackendISCSIStopPool,
    .findPoolSources = virStorageBackendISCSIFindPoolSources,
    .uploadVol = virStorageBackendVolUploadLocal,
    .downloadVol = virStorageBackendVolDownloadLocal,
    .wipeVol = virStorageBackendVolWipeLocal,
};


int
virStorageBackendISCSIRegister(void)
{
    return virStorageBackendRegister(&virStorageBackendISCSI);
}
