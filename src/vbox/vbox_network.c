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

#include "vbox_common.h"
#include "vbox_uniformed_api.h"

#define VIR_FROM_THIS VIR_FROM_VBOX

VIR_LOG_INIT("vbox.vbox_network");

#define VBOX_RELEASE(arg)                                                     \
    do {                                                                      \
        if (arg) {                                                            \
            gVBoxAPI.nsUISupports.Release((void *)arg);                       \
            (arg) = NULL;                                                     \
        }                                                                     \
    } while (0)

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
