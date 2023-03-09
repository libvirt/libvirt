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
 */

#include <config.h>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "datatypes.h"
#include "driver.h"
#include "storage_backend_iscsi.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "viriscsi.h"
#include "viridentity.h"
#include "virlog.h"
#include "virobject.h"
#include "virsecret.h"
#include "storage_util.h"
#include "virutil.h"
#include "virsecureerase.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("storage.storage_backend_iscsi");

#define ISCSI_DEFAULT_TARGET_PORT 3260

static char *
virStorageBackendISCSIPortal(virStoragePoolSource *source)
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
        portal = g_strdup_printf("[%s]:%d,1",
                                 source->hosts[0].name,
                                 source->hosts[0].port);
    } else {
        portal = g_strdup_printf("%s:%d,1",
                                 source->hosts[0].name,
                                 source->hosts[0].port);
    }

    return portal;
}


static char *
virStorageBackendISCSISession(virStoragePoolObj *pool,
                              bool probe)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    return virISCSIGetSession(def->source.devices[0].path, probe);
}


static int
virStorageBackendISCSIGetHostNumber(const char *sysfs_path,
                                    uint32_t *host)
{
    g_autoptr(DIR) sysdir = NULL;
    struct dirent *dirent = NULL;
    int direrr;

    VIR_DEBUG("Finding host number from '%s'", sysfs_path);

    virWaitForDevices();

    if (virDirOpen(&sysdir, sysfs_path) < 0)
        return -1;

    while ((direrr = virDirRead(sysdir, &dirent, sysfs_path)) > 0) {
        if (STRPREFIX(dirent->d_name, "target")) {
            if (sscanf(dirent->d_name, "target%u:", host) == 1) {
                return 0;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to parse target '%1$s'"), dirent->d_name);
                return -1;
            }
        }
    }

    if (direrr == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to get host number for iSCSI session with path '%1$s'"),
                       sysfs_path);
        return -1;
    }

    return -1;
}

static int
virStorageBackendISCSIFindLUs(virStoragePoolObj *pool,
                              const char *session)
{
    uint32_t host;
    g_autofree char *sysfs_path = NULL;

    sysfs_path = g_strdup_printf("/sys/class/iscsi_session/session%s/device",
                                 session);

    if (virStorageBackendISCSIGetHostNumber(sysfs_path, &host) < 0)
        return -1;

    if (virStorageBackendSCSIFindLUs(pool, host) < 0)
        return -1;

    return 0;
}


static char *
virStorageBackendISCSIFindPoolSources(const char *srcSpec,
                                      unsigned int flags)
{
    size_t ntargets = 0;
    char **targets = NULL;
    char *ret = NULL;
    size_t i;
    virStoragePoolSourceList list = {
        .type = VIR_STORAGE_POOL_ISCSI,
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

    if (virISCSIScanTargets(portal,
                            source->initiator.iqn,
                            false,
                            &ntargets, &targets) < 0)
        goto cleanup;

    list.sources = g_new0(virStoragePoolSource, ntargets);

    for (i = 0; i < ntargets; i++) {
        list.sources[i].devices = g_new0(virStoragePoolSourceDevice, 1);
        list.sources[i].hosts = g_new0(virStoragePoolSourceHost, 1);
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

static int
virStorageBackendISCSICheckPool(virStoragePoolObj *pool,
                                bool *isActive)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autofree char *session = NULL;

    *isActive = false;

    if (def->source.nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        return -1;
    }

    if (def->source.hosts[0].name == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing source host"));
        return -1;
    }

    if (def->source.ndevice != 1 ||
        def->source.devices[0].path == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing source device"));
        return -1;
    }

    if ((session = virStorageBackendISCSISession(pool, true)))
        *isActive = true;
    return 0;
}


static int
virStorageBackendISCSISetAuth(const char *portal,
                              virStoragePoolSource *source)
{
    g_autofree unsigned char *secret_value = NULL;
    size_t secret_size;
    g_autofree char *secret_str = NULL;
    virStorageAuthDef *authdef = source->auth;
    int ret = 0;
    g_autoptr(virConnect) conn = NULL;
    VIR_IDENTITY_AUTORESTORE virIdentity *oldident = NULL;

    if (!authdef || authdef->authType == VIR_STORAGE_AUTH_TYPE_NONE)
        return 0;

    VIR_DEBUG("username='%s' authType=%d seclookupdef.type=%d",
              authdef->username, authdef->authType, authdef->seclookupdef.type);
    if (authdef->authType != VIR_STORAGE_AUTH_TYPE_CHAP) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("iscsi pool only supports 'chap' auth type"));
        return -1;
    }

    if (!(oldident = virIdentityElevateCurrent()))
        return -1;

    conn = virGetConnectSecret();
    if (!conn)
        return -1;

    if (virSecretGetSecretString(conn, &authdef->seclookupdef,
                                 VIR_SECRET_USAGE_TYPE_ISCSI,
                                 &secret_value, &secret_size) < 0)
        return -1;

    secret_str = g_strndup((char *) secret_value, secret_size);
    virSecureErase(secret_value, secret_size);

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
                           secret_str) < 0)
        ret = -1;

    virSecureErase(secret_str, secret_size);
    return ret;
}

static int
virStorageBackendISCSIStartPool(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autofree char *portal = NULL;
    g_autofree char *session = NULL;

    if (def->source.nhost != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Expected exactly 1 host for the storage pool"));
        return -1;
    }

    if (def->source.hosts[0].name == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing source host"));
        return -1;
    }

    if (def->source.ndevice != 1 ||
        def->source.devices[0].path == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing source device"));
        return -1;
    }

    if ((session = virStorageBackendISCSISession(pool, true)) == NULL) {
        if ((portal = virStorageBackendISCSIPortal(&def->source)) == NULL)
            return -1;

        /* Create a static node record for the IQN target. Must be done
         * in order for login to the target */
        if (virISCSINodeNew(portal, def->source.devices[0].path) < 0)
            return -1;

        if (virStorageBackendISCSISetAuth(portal, &def->source) < 0)
            return -1;

        if (virISCSIConnectionLogin(portal,
                                    def->source.initiator.iqn,
                                    def->source.devices[0].path) < 0)
            return -1;
    }
    return 0;
}

static int
virStorageBackendISCSIRefreshPool(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autofree char *session = NULL;

    def->allocation = def->capacity = def->available = 0;

    if ((session = virStorageBackendISCSISession(pool, false)) == NULL)
        return -1;
    if (virISCSIRescanLUNs(session) < 0)
        return -1;
    if (virStorageBackendISCSIFindLUs(pool, session) < 0)
        return -1;

    return 0;
}


static int
virStorageBackendISCSIStopPool(virStoragePoolObj *pool)
{
    virStoragePoolDef *def = virStoragePoolObjGetDef(pool);
    g_autofree char *portal = NULL;
    g_autofree char *session = NULL;

    if ((session = virStorageBackendISCSISession(pool, true)) == NULL)
        return 0;

    if ((portal = virStorageBackendISCSIPortal(&def->source)) == NULL)
        return -1;

    if (virISCSIConnectionLogout(portal,
                                 def->source.initiator.iqn,
                                 def->source.devices[0].path) < 0)
        return -1;

    return 0;
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
