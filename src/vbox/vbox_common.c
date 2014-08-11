/*
 * Copyright 2014, Taowei Luo (uaedante@gmail.com)
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

#include <unistd.h>

#include "internal.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "domain_event.h"
#include "virlog.h"
#include "viralloc.h"
#include "nodeinfo.h"

#include "vbox_common.h"
#include "vbox_uniformed_api.h"
#include "vbox_install_api.h"

/* Common codes for vbox driver. With the definitions in vbox_common.h,
 * it treats vbox structs as a void*. Though vboxUniformedAPI
 * it call vbox functions. This file is a high level implement about
 * the vbox driver.
 */

#define VIR_FROM_THIS VIR_FROM_VBOX

VIR_LOG_INIT("vbox.vbox_common");

#define VBOX_UTF16_FREE(arg)                                            \
    do {                                                                \
        if (arg) {                                                      \
            gVBoxAPI.UPFN.Utf16Free(data->pFuncs, arg);                 \
            (arg) = NULL;                                               \
        }                                                               \
    } while (0)

#define VBOX_UTF8_FREE(arg)                                             \
    do {                                                                \
        if (arg) {                                                      \
            gVBoxAPI.UPFN.Utf8Free(data->pFuncs, arg);                  \
            (arg) = NULL;                                               \
        }                                                               \
    } while (0)

#define VBOX_COM_UNALLOC_MEM(arg)                                       \
    do {                                                                \
        if (arg) {                                                      \
            gVBoxAPI.UPFN.ComUnallocMem(data->pFuncs, arg);             \
            (arg) = NULL;                                               \
        }                                                               \
    } while (0)

#define VBOX_UTF16_TO_UTF8(arg1, arg2)  gVBoxAPI.UPFN.Utf16ToUtf8(data->pFuncs, arg1, arg2)
#define VBOX_UTF8_TO_UTF16(arg1, arg2)  gVBoxAPI.UPFN.Utf8ToUtf16(data->pFuncs, arg1, arg2)

/* global vbox API, used for all common codes. */
static vboxUniformedAPI gVBoxAPI;

int vboxRegisterUniformedAPI(uint32_t uVersion)
{
    /* Install gVBoxAPI according to the vbox API version.
     * Return -1 for unsupported version.
     */
    if (uVersion >= 2001052 && uVersion < 2002051) {
        vbox22InstallUniformedAPI(&gVBoxAPI);
    } else if (uVersion >= 2002051 && uVersion < 3000051) {
        vbox30InstallUniformedAPI(&gVBoxAPI);
    } else if (uVersion >= 3000051 && uVersion < 3001051) {
        vbox31InstallUniformedAPI(&gVBoxAPI);
    } else if (uVersion >= 3001051 && uVersion < 3002051) {
        vbox32InstallUniformedAPI(&gVBoxAPI);
    } else if (uVersion >= 3002051 && uVersion < 4000051) {
        vbox40InstallUniformedAPI(&gVBoxAPI);
    } else if (uVersion >= 4000051 && uVersion < 4001051) {
        vbox41InstallUniformedAPI(&gVBoxAPI);
    } else if (uVersion >= 4001051 && uVersion < 4002020) {
        vbox42InstallUniformedAPI(&gVBoxAPI);
    } else if (uVersion >= 4002020 && uVersion < 4002051) {
        vbox42_20InstallUniformedAPI(&gVBoxAPI);
    } else if (uVersion >= 4002051 && uVersion < 4003004) {
        vbox43InstallUniformedAPI(&gVBoxAPI);
    } else if (uVersion >= 4003004 && uVersion < 4003051) {
        vbox43_4InstallUniformedAPI(&gVBoxAPI);
    } else {
        return -1;
    }
    return 0;
}

static virDomainDefParserConfig vboxDomainDefParserConfig = {
    .macPrefix = { 0x08, 0x00, 0x27 },
};

static virDomainXMLOptionPtr
vboxXMLConfInit(void)
{
    return virDomainXMLOptionNew(&vboxDomainDefParserConfig,
                                 NULL, NULL);
}

static int vboxInitialize(vboxGlobalData *data)
{
    if (gVBoxAPI.UPFN.Initialize(data) != 0)
        goto cleanup;

    if (gVBoxAPI.domainEventCallbacks && gVBoxAPI.initializeDomainEvent(data) != 0)
        goto cleanup;

    if (data->vboxObj == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("IVirtualBox object is null"));
        goto cleanup;
    }

    if (data->vboxSession == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("ISession object is null"));
        goto cleanup;
    }

    return 0;

 cleanup:
    return -1;
}

static virCapsPtr vboxCapsInit(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   false, false)) == NULL)
        goto no_memory;

    if (nodeCapsInitNUMA(caps) < 0)
        goto no_memory;

    if ((guest = virCapabilitiesAddGuest(caps,
                                         "hvm",
                                         caps->host.arch,
                                         NULL,
                                         NULL,
                                         0,
                                         NULL)) == NULL)
        goto no_memory;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "vbox",
                                      NULL,
                                      NULL,
                                      0,
                                      NULL) == NULL)
        goto no_memory;

    return caps;

 no_memory:
    virObjectUnref(caps);
    return NULL;
}

static int vboxExtractVersion(vboxGlobalData *data)
{
    int ret = -1;
    PRUnichar *versionUtf16 = NULL;
    char *vboxVersion = NULL;
    nsresult rc;

    if (data->version > 0)
        return 0;

    rc = gVBoxAPI.UIVirtualBox.GetVersion(data->vboxObj, &versionUtf16);
    if (NS_FAILED(rc))
        goto failed;

    VBOX_UTF16_TO_UTF8(versionUtf16, &vboxVersion);

    if (virParseVersionString(vboxVersion, &data->version, false) >= 0)
        ret = 0;

    VBOX_UTF8_FREE(vboxVersion);
    VBOX_COM_UNALLOC_MEM(versionUtf16);
 failed:
    if (ret != 0)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not extract VirtualBox version"));

    return ret;
}

static void vboxUninitialize(vboxGlobalData *data)
{
    if (!data)
        return;

    gVBoxAPI.UPFN.Uninitialize(data);

    virObjectUnref(data->caps);
    virObjectUnref(data->xmlopt);
    if (gVBoxAPI.domainEventCallbacks)
        virObjectEventStateFree(data->domainEvents);
    VIR_FREE(data);
}

virDrvOpenStatus vboxConnectOpen(virConnectPtr conn,
                                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                 unsigned int flags)
{
    vboxGlobalData *data = NULL;
    uid_t uid = geteuid();

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->uri == NULL &&
        !(conn->uri = virURIParse(uid ? "vbox:///session" : "vbox:///system")))
        return VIR_DRV_OPEN_ERROR;

    if (conn->uri->scheme == NULL ||
        STRNEQ(conn->uri->scheme, "vbox"))
        return VIR_DRV_OPEN_DECLINED;

    /* Leave for remote driver */
    if (conn->uri->server != NULL)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->uri->path == NULL || STREQ(conn->uri->path, "")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no VirtualBox driver path specified (try vbox:///session)"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (uid != 0) {
        if (STRNEQ(conn->uri->path, "/session")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown driver path '%s' specified (try vbox:///session)"), conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    } else { /* root */
        if (STRNEQ(conn->uri->path, "/system") &&
            STRNEQ(conn->uri->path, "/session")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown driver path '%s' specified (try vbox:///system)"), conn->uri->path);
            return VIR_DRV_OPEN_ERROR;
        }
    }

    if (VIR_ALLOC(data) < 0)
        return VIR_DRV_OPEN_ERROR;

    if (!(data->caps = vboxCapsInit()) ||
        vboxInitialize(data) < 0 ||
        vboxExtractVersion(data) < 0 ||
        !(data->xmlopt = vboxXMLConfInit())) {
        vboxUninitialize(data);
        return VIR_DRV_OPEN_ERROR;
    }

    if (gVBoxAPI.domainEventCallbacks) {
        if (!(data->domainEvents = virObjectEventStateNew())) {
            vboxUninitialize(data);
            return VIR_DRV_OPEN_ERROR;
        }

        data->conn = conn;
    }

    if (gVBoxAPI.hasStaticGlobalData)
        gVBoxAPI.registerGlobalData(data);

    conn->privateData = data;
    VIR_DEBUG("in vboxOpen");

    return VIR_DRV_OPEN_SUCCESS;
}

int vboxConnectClose(virConnectPtr conn)
{
    vboxGlobalData *data = conn->privateData;
    VIR_DEBUG("%s: in vboxClose", conn->driver->name);

    vboxUninitialize(data);
    conn->privateData = NULL;

    return 0;
}
