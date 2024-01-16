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


#define VIR_FROM_THIS VIR_FROM_CH

VIR_LOG_INIT("ch.ch_interface");

/**
 * virCHConnetNetworkInterfaces:
 * @driver: pointer to ch driver object
 * @vm: pointer to domain definition
 * @net: pointer to a guest net
 * @nicindexes: returned array of FDs of guest interfaces
 * @nnicindexes: returned number of guest interfaces
 *
 *
 * Returns 0 on success, -1 on error.
 */
int
virCHConnetNetworkInterfaces(virCHDriver *driver,
                             virDomainDef *vm,
                             virDomainNetDef *net,
                             int *tapfds, int **nicindexes, size_t *nnicindexes)
{
    virDomainNetType actualType = virDomainNetGetActualType(net);


    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_ETHERNET:

        if (virDomainInterfaceEthernetConnect(vm, net,
                                              driver->ebtables, false,
                                              driver->privileged, tapfds,
                                              net->driver.virtio.queues) < 0)
            return -1;

        G_GNUC_FALLTHROUGH;
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
        if (nicindexes && nnicindexes && net->ifname) {
            int nicindex = 0;

            if (virNetDevGetIndex(net->ifname, &nicindex) < 0)
                return -1;

            VIR_APPEND_ELEMENT(*nicindexes, *nnicindexes, nicindex);
        }

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
