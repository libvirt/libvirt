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
#include <sys/wait.h>
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
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
    return virISCSIGetSession(def->source.devices[0].path, probe);
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

    virWaitForDevices();

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
    uint32_t host;
    g_autofree char *sysfs_path = NULL;

    if (virAsprintf(&sysfs_path,
                    "/sys/class/iscsi_session/session%s/device", session) < 0)
        return -1;

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

static int
virStorageBackendISCSICheckPool(virStoragePoolObjPtr pool,
                                bool *isActive)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
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
                       _("iscsi pool only supports 'chap' auth type"));
        return -1;
    }

    conn = virGetConnectSecret();
    if (!conn)
        return -1;

    if (virSecretGetSecretString(conn, &authdef->seclookupdef,
                                 VIR_SECRET_USAGE_TYPE_ISCSI,
                                 &secret_value, &secret_size) < 0)
        goto cleanup;

    if (VIR_REALLOC_N(secret_value, secret_size + 1) < 0)
        goto cleanup;

    secret_value[secret_size] = '\0';

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
    virObjectUnref(conn);
    return ret;
}

static int
virStorageBackendISCSIStartPool(virStoragePoolObjPtr pool)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
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
virStorageBackendISCSIRefreshPool(virStoragePoolObjPtr pool)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
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
virStorageBackendISCSIStopPool(virStoragePoolObjPtr pool)
{
    virStoragePoolDefPtr def = virStoragePoolObjGetDef(pool);
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
