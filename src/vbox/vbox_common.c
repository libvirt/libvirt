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

#define RC_SUCCEEDED(rc) NS_SUCCEEDED(rc.resultCode)
#define RC_FAILED(rc) NS_FAILED(rc.resultCode)

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

#define VBOX_RELEASE(arg)                                                     \
    do {                                                                      \
        if (arg) {                                                            \
            gVBoxAPI.nsUISupports.Release((void *)arg);                        \
            (arg) = NULL;                                                     \
        }                                                                     \
    } while (0)

#define VBOX_OBJECT_CHECK(conn, type, value) \
vboxGlobalData *data = conn->privateData;\
type ret = value;\
if (!data->vboxObj) {\
    return ret;\
}

#define vboxIIDUnalloc(iid)                     gVBoxAPI.UIID.vboxIIDUnalloc(data, iid)
#define vboxIIDToUUID(iid, uuid)                gVBoxAPI.UIID.vboxIIDToUUID(data, iid, uuid)
#define vboxIIDFromUUID(iid, uuid)              gVBoxAPI.UIID.vboxIIDFromUUID(data, iid, uuid)
#define vboxIIDIsEqual(iid1, iid2)              gVBoxAPI.UIID.vboxIIDIsEqual(data, iid1, iid2)
#define DEBUGIID(msg, iid)                      gVBoxAPI.UIID.DEBUGIID(msg, iid)
#define vboxIIDFromArrayItem(iid, array, idx) \
    gVBoxAPI.UIID.vboxIIDFromArrayItem(data, iid, array, idx)

#define VBOX_IID_INITIALIZE(iid)                gVBoxAPI.UIID.vboxIIDInitialize(iid)

#define ARRAY_GET_MACHINES \
    (gVBoxAPI.UArray.handleGetMachines(data->vboxObj))


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

static int openSessionForMachine(vboxGlobalData *data, const unsigned char *dom_uuid, vboxIIDUnion *iid,
                                 IMachine **machine, bool checkflag)
{
    VBOX_IID_INITIALIZE(iid);
    vboxIIDFromUUID(iid, dom_uuid);
    if (!checkflag || gVBoxAPI.getMachineForSession) {
        /* Get machine for the call to VBOX_SESSION_OPEN_EXISTING */
        if (NS_FAILED(gVBoxAPI.UIVirtualBox.GetMachine(data->vboxObj, iid, machine))) {
            virReportError(VIR_ERR_NO_DOMAIN, "%s",
                           _("no domain with matching uuid"));
            return -1;
        }
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

int
vboxDomainSave(virDomainPtr dom, const char *path ATTRIBUTE_UNUSED)
{
    VBOX_OBJECT_CHECK(dom->conn, int, -1);
    IConsole *console    = NULL;
    vboxIIDUnion iid;
    IMachine *machine = NULL;
    IProgress *progress = NULL;
    resultCodeUnion resultCode;
    nsresult rc;

    /* VirtualBox currently doesn't support saving to a file
     * at a location other then the machine folder and thus
     * setting path to ATTRIBUTE_UNUSED for now, will change
     * this behaviour once get the VirtualBox API in right
     * shape to do this
     */

    /* Open a Session for the machine */
    if (openSessionForMachine(data, dom->uuid, &iid, &machine, true) < 0)
        goto cleanup;

    rc = gVBoxAPI.UISession.OpenExisting(data, &iid, machine);
    if (NS_FAILED(rc))
        goto cleanup;

    rc = gVBoxAPI.UISession.GetConsole(data->vboxSession, &console);
    if (NS_FAILED(rc) || !console)
        goto freeSession;

    rc = gVBoxAPI.UIConsole.SaveState(console, &progress);
    if (!progress)
        goto freeSession;

    gVBoxAPI.UIProgress.WaitForCompletion(progress, -1);
    gVBoxAPI.UIProgress.GetResultCode(progress, &resultCode);
    if (RC_SUCCEEDED(resultCode))
        ret = 0;

 freeSession:
    gVBoxAPI.UISession.Close(data->vboxSession);

 cleanup:
    DEBUGIID("UUID of machine being saved:", &iid);
    VBOX_RELEASE(machine);
    VBOX_RELEASE(console);
    VBOX_RELEASE(progress);
    vboxIIDUnalloc(&iid);
    return ret;
}

static void vboxDriverLock(vboxGlobalData *data)
{
    virMutexLock(&data->lock);
}

static void vboxDriverUnlock(vboxGlobalData *data)
{
    virMutexUnlock(&data->lock);
}

int vboxConnectGetVersion(virConnectPtr conn, unsigned long *version)
{
    vboxGlobalData *data = conn->privateData;
    VIR_DEBUG("%s: in vboxGetVersion", conn->driver->name);

    vboxDriverLock(data);
    *version = data->version;
    vboxDriverUnlock(data);

    return 0;
}

char *vboxConnectGetHostname(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return virGetHostname();
}

int vboxConnectIsSecure(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* Driver is using local, non-network based transport */
    return 1;
}

int vboxConnectIsEncrypted(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* No encryption is needed, or used on the local transport*/
    return 0;
}

int vboxConnectIsAlive(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    return 1;
}

int
vboxConnectGetMaxVcpus(virConnectPtr conn, const char *type ATTRIBUTE_UNUSED)
{
    VBOX_OBJECT_CHECK(conn, int, -1);
    PRUint32 maxCPUCount = 0;

    /* VirtualBox Supports only hvm and thus the type passed to it
     * has no meaning, setting it to ATTRIBUTE_UNUSED
     */
    ISystemProperties *systemProperties = NULL;

    gVBoxAPI.UIVirtualBox.GetSystemProperties(data->vboxObj, &systemProperties);
    if (!systemProperties)
        goto cleanup;
    gVBoxAPI.UISystemProperties.GetMaxGuestCPUCount(systemProperties, &maxCPUCount);

    if (maxCPUCount > 0)
        ret = maxCPUCount;

 cleanup:
    VBOX_RELEASE(systemProperties);
    return ret;
}

char *vboxConnectGetCapabilities(virConnectPtr conn)
{
    VBOX_OBJECT_CHECK(conn, char *, NULL);

    vboxDriverLock(data);
    ret = virCapabilitiesFormatXML(data->caps);
    vboxDriverUnlock(data);

    return ret;
}

int vboxConnectListDomains(virConnectPtr conn, int *ids, int nids)
{
    VBOX_OBJECT_CHECK(conn, int, -1);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    PRUint32 state;
    nsresult rc;
    size_t i, j;

    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of Domains, rc=%08x"),
                       (unsigned)rc);
        goto cleanup;
    }

    ret = 0;
    for (i = 0, j = 0; (i < machines.count) && (j < nids); ++i) {
        IMachine *machine = machines.items[i];

        if (machine) {
            PRBool isAccessible = PR_FALSE;
            gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
            if (isAccessible) {
                gVBoxAPI.UIMachine.GetState(machine, &state);
                if (gVBoxAPI.machineStateChecker.Online(state)) {
                    ret++;
                    ids[j++] = i + 1;
                }
            }
        }
    }

 cleanup:
    gVBoxAPI.UArray.vboxArrayRelease(&machines);
    return ret;
}

int vboxConnectNumOfDomains(virConnectPtr conn)
{
    VBOX_OBJECT_CHECK(conn, int, -1);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    PRUint32 state;
    nsresult rc;
    size_t i;

    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get number of Domains, rc=%08x"), (unsigned)rc);
        goto cleanup;
    }

    ret = 0;
    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];

        if (machine) {
            PRBool isAccessible = PR_FALSE;
            gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
            if (isAccessible) {
                gVBoxAPI.UIMachine.GetState(machine, &state);
                if (gVBoxAPI.machineStateChecker.Online(state))
                    ret++;
            }
        }
    }

 cleanup:
    gVBoxAPI.UArray.vboxArrayRelease(&machines);
    return ret;
}

virDomainPtr vboxDomainLookupByID(virConnectPtr conn, int id)
{
    VBOX_OBJECT_CHECK(conn, virDomainPtr, NULL);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    IMachine *machine;
    PRBool isAccessible = PR_FALSE;
    PRUnichar *machineNameUtf16 = NULL;
    char *machineNameUtf8  = NULL;
    vboxIIDUnion iid;
    unsigned char uuid[VIR_UUID_BUFLEN];
    PRUint32 state;
    nsresult rc;

    VBOX_IID_INITIALIZE(&iid);
    /* Internal vbox IDs start from 0, the public libvirt ID
     * starts from 1, so refuse id == 0, and adjust the rest*/
    if (id == 0) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching id %d"), id);
        return NULL;
    }
    id = id - 1;

    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return NULL;
    }

    if (id >= machines.count)
        goto cleanup;

    machine = machines.items[id];

    if (!machine)
        goto cleanup;

    isAccessible = PR_FALSE;
    gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
    if (!isAccessible)
        goto cleanup;

    gVBoxAPI.UIMachine.GetState(machine, &state);
    if (!gVBoxAPI.machineStateChecker.Online(state))
        goto cleanup;

    gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
    VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

    gVBoxAPI.UIMachine.GetId(machine, &iid);
    vboxIIDToUUID(&iid, uuid);
    vboxIIDUnalloc(&iid);

    /* get a new domain pointer from virGetDomain, if it fails
     * then no need to assign the id, else assign the id, cause
     * it is -1 by default. rest is taken care by virGetDomain
     * itself, so need not worry.
     */

    ret = virGetDomain(conn, machineNameUtf8, uuid);
    if (ret)
        ret->id = id + 1;

    /* Cleanup all the XPCOM allocated stuff here */
    VBOX_UTF8_FREE(machineNameUtf8);
    VBOX_UTF16_FREE(machineNameUtf16);

 cleanup:
    gVBoxAPI.UArray.vboxArrayRelease(&machines);
    return ret;
}

virDomainPtr vboxDomainLookupByUUID(virConnectPtr conn,
                                    const unsigned char *uuid)
{
    VBOX_OBJECT_CHECK(conn, virDomainPtr, NULL);
    vboxArray machines = VBOX_ARRAY_INITIALIZER;
    vboxIIDUnion iid;
    char *machineNameUtf8  = NULL;
    PRUnichar *machineNameUtf16 = NULL;
    unsigned char iid_as_uuid[VIR_UUID_BUFLEN];
    size_t i;
    bool matched = false;
    nsresult rc;

    VBOX_IID_INITIALIZE(&iid);
    rc = gVBoxAPI.UArray.vboxArrayGet(&machines, data->vboxObj, ARRAY_GET_MACHINES);
    if (NS_FAILED(rc)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get list of machines, rc=%08x"), (unsigned)rc);
        return NULL;
    }

    for (i = 0; i < machines.count; ++i) {
        IMachine *machine = machines.items[i];
        PRBool isAccessible = PR_FALSE;

        if (!machine)
            continue;

        gVBoxAPI.UIMachine.GetAccessible(machine, &isAccessible);
        if (!isAccessible)
            continue;

        rc = gVBoxAPI.UIMachine.GetId(machine, &iid);
        if (NS_FAILED(rc))
            continue;
        vboxIIDToUUID(&iid, iid_as_uuid);
        vboxIIDUnalloc(&iid);

        if (memcmp(uuid, iid_as_uuid, VIR_UUID_BUFLEN) == 0) {

            PRUint32 state;

            matched = true;

            gVBoxAPI.UIMachine.GetName(machine, &machineNameUtf16);
            VBOX_UTF16_TO_UTF8(machineNameUtf16, &machineNameUtf8);

            gVBoxAPI.UIMachine.GetState(machine, &state);

            /* get a new domain pointer from virGetDomain, if it fails
             * then no need to assign the id, else assign the id, cause
             * it is -1 by default. rest is taken care by virGetDomain
             * itself, so need not worry.
             */

            ret = virGetDomain(conn, machineNameUtf8, iid_as_uuid);
            if (ret &&
                gVBoxAPI.machineStateChecker.Online(state))
                ret->id = i + 1;
         }

         if (matched)
             break;
    }

    /* Do the cleanup and take care you dont leak any memory */
    VBOX_UTF8_FREE(machineNameUtf8);
    VBOX_COM_UNALLOC_MEM(machineNameUtf16);
    gVBoxAPI.UArray.vboxArrayRelease(&machines);

    return ret;
}
