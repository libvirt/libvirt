/*
 * Copyright (C) 2014 Taowei Luo (uaedante@gmail.com)
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2008-2009 Sun Microsystems, Inc.
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

#include "internal.h"
#include "datatypes.h"
#include "domain_conf.h"
#include "domain_event.h"
#include "virlog.h"
#include "virstring.h"

#include "vbox_common.h"
#include "vbox_uniformed_api.h"

#define VIR_FROM_THIS VIR_FROM_VBOX

VIR_LOG_INIT("vbox.vbox_network");

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

#define VBOX_UTF16_TO_UTF8(arg1, arg2)  gVBoxAPI.UPFN.Utf16ToUtf8(data->pFuncs, arg1, arg2)
#define VBOX_UTF8_TO_UTF16(arg1, arg2)  gVBoxAPI.UPFN.Utf8ToUtf16(data->pFuncs, arg1, arg2)

#define VBOX_RELEASE(arg)                                                     \
    do {                                                                      \
        if (arg) {                                                            \
            gVBoxAPI.nsUISupports.Release((void *)arg);                       \
            (arg) = NULL;                                                     \
        }                                                                     \
    } while (0)

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

static vboxUniformedAPI gVBoxAPI;

/**
 * The Network Functions here on
 */

virDrvOpenStatus vboxNetworkOpen(virConnectPtr conn,
                                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                 unsigned int flags)
{
    vboxGlobalData *data = conn->privateData;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (STRNEQ(conn->driver->name, "VBOX"))
        goto cleanup;

    if (!data->pFuncs || !data->vboxObj || !data->vboxSession)
        goto cleanup;

    VIR_DEBUG("network initialized");
    /* conn->networkPrivateData = some network specific data */
    return VIR_DRV_OPEN_SUCCESS;

 cleanup:
    return VIR_DRV_OPEN_DECLINED;
}

int vboxNetworkClose(virConnectPtr conn)
{
    VIR_DEBUG("network uninitialized");
    conn->networkPrivateData = NULL;
    return 0;
}

int vboxConnectNumOfNetworks(virConnectPtr conn)
{
    vboxGlobalData *data = conn->privateData;
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    IHost *host = NULL;
    size_t i = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    gVBoxAPI.UArray.vboxArrayGet(&networkInterfaces, host,
                                 gVBoxAPI.UArray.handleHostGetNetworkInterfaces(host));

    ret = 0;
    for (i = 0; i < networkInterfaces.count; i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];
        PRUint32 status = HostNetworkInterfaceStatus_Unknown;
        PRUint32 interfaceType = 0;

        if (!networkInterface)
            continue;

        gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);
        if (interfaceType != HostNetworkInterfaceType_HostOnly)
            continue;

        gVBoxAPI.UIHNInterface.GetStatus(networkInterface, &status);

        if (status == HostNetworkInterfaceStatus_Up)
            ret++;
    }

    gVBoxAPI.UArray.vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    VIR_DEBUG("numActive: %d", ret);
    return ret;
}

int vboxConnectListNetworks(virConnectPtr conn, char **const names, int nnames)
{
    vboxGlobalData *data = conn->privateData;
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    IHost *host = NULL;
    size_t i = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    gVBoxAPI.UArray.vboxArrayGet(&networkInterfaces, host,
                                 gVBoxAPI.UArray.handleHostGetNetworkInterfaces(host));

    ret = 0;
    for (i = 0; (ret < nnames) && (i < networkInterfaces.count); i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];
        char *nameUtf8 = NULL;
        PRUnichar *nameUtf16 = NULL;
        PRUint32 interfaceType = 0;
        PRUint32 status = HostNetworkInterfaceStatus_Unknown;

        if (!networkInterface)
            continue;

        gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType != HostNetworkInterfaceType_HostOnly)
            continue;

        gVBoxAPI.UIHNInterface.GetStatus(networkInterface, &status);

        if (status != HostNetworkInterfaceStatus_Up)
            continue;

        gVBoxAPI.UIHNInterface.GetName(networkInterface, &nameUtf16);
        VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

        VIR_DEBUG("nnames[%d]: %s", ret, nameUtf8);
        if (VIR_STRDUP(names[ret], nameUtf8) >= 0)
            ret++;

        VBOX_UTF8_FREE(nameUtf8);
        VBOX_UTF16_FREE(nameUtf16);
    }

    gVBoxAPI.UArray.vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    return ret;
}

int vboxConnectNumOfDefinedNetworks(virConnectPtr conn)
{
    vboxGlobalData *data = conn->privateData;
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    IHost *host = NULL;
    size_t i = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    gVBoxAPI.UArray.vboxArrayGet(&networkInterfaces, host,
                                 gVBoxAPI.UArray.handleHostGetNetworkInterfaces(host));

    ret = 0;
    for (i = 0; i < networkInterfaces.count; i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];
        PRUint32 status = HostNetworkInterfaceStatus_Unknown;
        PRUint32 interfaceType = 0;

        if (!networkInterface)
            continue;

        gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);
        if (interfaceType != HostNetworkInterfaceType_HostOnly)
            continue;

        gVBoxAPI.UIHNInterface.GetStatus(networkInterface, &status);

        if (status == HostNetworkInterfaceStatus_Down)
            ret++;
    }

    gVBoxAPI.UArray.vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    VIR_DEBUG("numActive: %d", ret);
    return ret;
}

int vboxConnectListDefinedNetworks(virConnectPtr conn, char **const names, int nnames)
{
    vboxGlobalData *data = conn->privateData;
    vboxArray networkInterfaces = VBOX_ARRAY_INITIALIZER;
    IHost *host = NULL;
    size_t i = 0;
    int ret = -1;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    gVBoxAPI.UArray.vboxArrayGet(&networkInterfaces, host,
                                 gVBoxAPI.UArray.handleHostGetNetworkInterfaces(host));

    ret = 0;
    for (i = 0; (ret < nnames) && (i < networkInterfaces.count); i++) {
        IHostNetworkInterface *networkInterface = networkInterfaces.items[i];
        PRUint32 interfaceType = 0;
        char *nameUtf8 = NULL;
        PRUnichar *nameUtf16 = NULL;
        PRUint32 status = HostNetworkInterfaceStatus_Unknown;

        if (!networkInterface)
            continue;

        gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);

        if (interfaceType != HostNetworkInterfaceType_HostOnly)
            continue;

        gVBoxAPI.UIHNInterface.GetStatus(networkInterface, &status);

        if (status != HostNetworkInterfaceStatus_Down)
            continue;

        gVBoxAPI.UIHNInterface.GetName(networkInterface, &nameUtf16);
        VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

        VIR_DEBUG("nnames[%d]: %s", ret, nameUtf8);
        if (VIR_STRDUP(names[ret], nameUtf8) >= 0)
            ret++;

        VBOX_UTF8_FREE(nameUtf8);
        VBOX_UTF16_FREE(nameUtf16);
    }

    gVBoxAPI.UArray.vboxArrayRelease(&networkInterfaces);

    VBOX_RELEASE(host);

    return ret;
}

virNetworkPtr vboxNetworkLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    vboxGlobalData *data = conn->privateData;
    PRUint32 interfaceType = 0;
    char *nameUtf8 = NULL;
    PRUnichar *nameUtf16 = NULL;
    IHostNetworkInterface *networkInterface = NULL;
    vboxIIDUnion iid;
    IHost *host = NULL;
    virNetworkPtr ret = NULL;

    if (!data->vboxObj)
        return ret;

    gVBoxAPI.UIVirtualBox.GetHost(data->vboxObj, &host);
    if (!host)
        return ret;

    VBOX_IID_INITIALIZE(&iid);
    vboxIIDFromUUID(&iid, uuid);

    /* TODO: "internal" networks are just strings and
     * thus can't do much with them
     */

    gVBoxAPI.UIHost.FindHostNetworkInterfaceById(host, &iid,
                                                 &networkInterface);
    if (!networkInterface)
        goto cleanup;

    gVBoxAPI.UIHNInterface.GetInterfaceType(networkInterface, &interfaceType);

    if (interfaceType != HostNetworkInterfaceType_HostOnly)
        goto cleanup;

    gVBoxAPI.UIHNInterface.GetName(networkInterface, &nameUtf16);
    VBOX_UTF16_TO_UTF8(nameUtf16, &nameUtf8);

    ret = virGetNetwork(conn, nameUtf8, uuid);

    VIR_DEBUG("Network Name: %s", nameUtf8);
    DEBUGIID("Network UUID", &iid);
    VBOX_UTF8_FREE(nameUtf8);
    VBOX_UTF16_FREE(nameUtf16);

 cleanup:
    VBOX_RELEASE(networkInterface);
    VBOX_RELEASE(host);
    vboxIIDUnalloc(&iid);
    return ret;
}
