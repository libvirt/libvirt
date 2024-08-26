/*
 * Copyright Microsoft Corp. 2023
 *
 * ch_interface.c: methods to connect guest interfaces to appropriate host
 * backends
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

#include "domain_conf.h"
#include "domain_interface.h"
#include "virebtables.h"
#include "viralloc.h"
#include "ch_interface.h"
#include "virjson.h"
#include "virlog.h"
#include "datatypes.h"

#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_interface");


static int
virCHInterfaceUpdateNicindexes(virDomainNetDef *net,
                               int **nicindexes,
                               size_t *nnicindexes)
{
    int nicindex = 0;

    if (!nicindexes || !nnicindexes || !net->ifname)
        return 0;

    if (virNetDevGetIndex(net->ifname, &nicindex) < 0)
        return -1;

    VIR_APPEND_ELEMENT(*nicindexes, *nnicindexes, nicindex);

    return 0;
}


/**
 * virCHConnetNetworkInterfaces:
 * @driver: pointer to ch driver object
 * @vm: pointer to domain definition
 * @net: pointer to a guest net
 * @tapfds: returned array of tap FDs
 * @nicindexes: returned array list of network interface indexes
 * @nnicindexes: returned number of network interfaces
 *
 *
 * Returns 0 on success, -1 on error.
 */
int
virCHConnetNetworkInterfaces(virCHDriver *driver,
                             virDomainDef *vm,
                             virDomainNetDef *net,
                             int *tapfds,
                             int **nicindexes,
                             size_t *nnicindexes)
{
    virDomainNetType actualType = virDomainNetGetActualType(net);
    g_autoptr(virCHDriverConfig) cfg = virCHDriverGetConfig(driver);
    g_autoptr(virConnect) conn = NULL;
    size_t tapfdSize = net->driver.virtio.queues;

    /* If appropriate, grab a physical device from the configured
     * network's pool of devices, or resolve bridge device name
     * to the one defined in the network definition.
     */
    if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        if (!(conn = virGetConnectNetwork()))
            return -1;
        if (virDomainNetAllocateActualDevice(conn, vm, net) < 0)
            return -1;
    }

    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (virDomainInterfaceEthernetConnect(vm, net,
                                              driver->ebtables, false,
                                              driver->privileged, tapfds,
                                              net->driver.virtio.queues) < 0)
            return -1;

        if (virCHInterfaceUpdateNicindexes(net, nicindexes, nnicindexes) < 0)
            return -1;
        break;
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        if (virDomainInterfaceBridgeConnect(vm, net,
                                            tapfds,
                                            &tapfdSize,
                                            driver->privileged,
                                            driver->ebtables,
                                            false,
                                            NULL) < 0)
            return -1;

        if (virCHInterfaceUpdateNicindexes(net, nicindexes, nnicindexes) < 0)
            return -1;
        break;
    case VIR_DOMAIN_NET_TYPE_DIRECT:
        if (virCHInterfaceUpdateNicindexes(net, nicindexes, nnicindexes) < 0)
            return -1;
        break;
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported Network type %1$d"), actualType);
        return -1;
    }

    return 0;
}
