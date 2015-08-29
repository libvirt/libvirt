/*
 * qemu_interface.c: QEMU interface management
 *
 * Copyright IBM Corp. 2014
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
 * Authors:
 *     Matthew J. Rosato <mjrosato@linux.vnet.ibm.com>
 */

#include <config.h>

#include "network_conf.h"
#include "qemu_interface.h"
#include "virnetdev.h"
#include "virnetdevtap.h"
#include "virnetdevmacvlan.h"
#include "virnetdevbridge.h"
#include "virnetdevvportprofile.h"

/**
 * qemuInterfaceStartDevice:
 * @net: net device to start
 *
 * Based upon the type of device provided, perform the appropriate
 * work to completely activate the device and make it reachable from
 * the rest of the network.
 */
int
qemuInterfaceStartDevice(virDomainNetDefPtr net)
{
    int ret = -1;
    virDomainNetType actualType = virDomainNetGetActualType(net);

    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        if (virDomainNetGetActualBridgeMACTableManager(net)
            == VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_LIBVIRT) {
            /* libvirt is managing the FDB of the bridge this device
             * is attaching to, so we have turned off learning and
             * unicast_flood on the device to prevent the kernel from
             * adding any FDB entries for it. This means we need to
             * add an fdb entry ourselves, using the MAC address from
             * the interface config.
             */
            if (virNetDevBridgeFDBAdd(&net->mac, net->ifname,
                                      VIR_NETDEVBRIDGE_FDB_FLAG_MASTER |
                                      VIR_NETDEVBRIDGE_FDB_FLAG_TEMP) < 0)
                goto cleanup;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_DIRECT: {
        const char *physdev = virDomainNetGetActualDirectDev(net);
        bool isOnline = true;

        /* set the physdev online if necessary. It may already be up,
         * in which case we shouldn't re-up it just in case that causes
         * some sort of "blip" in the physdev's status.
         */
        if (physdev && virNetDevGetOnline(physdev, &isOnline) < 0)
            goto cleanup;
        if (!isOnline && virNetDevSetOnline(physdev, true) < 0)
            goto cleanup;

        /* macvtap devices share their MAC address with the guest
         * domain, and if they are set online prior to the domain CPUs
         * being started, the host may send out traffic from this
         * device that could confuse other entities on the network (in
         * particular, if this new domain is the destination of a
         * migration, and the source domain is still running, another
         * host may mistakenly direct traffic for the guest to the
         * destination domain rather than source domain). To prevent
         * this, we create the macvtap device with IFF_UP false
         * (i.e. "offline") then wait to bring it online until just as
         * we are starting the domain CPUs.
         */
        if (virNetDevSetOnline(net->ifname, true) < 0)
            goto cleanup;
        break;
    }

    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_LAST:
        /* these types all require no action */
        break;
    }

    ret = 0;
 cleanup:
    return ret;
}

/**
 * qemuInterfaceStartDevices:
 * @def: domain definition
 *
 * Set all ifaces associated with this domain to the online state.
 */
int
qemuInterfaceStartDevices(virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        if (qemuInterfaceStartDevice(def->nets[i]) < 0)
            return -1;
    }
    return 0;
}


/**
 * qemuInterfaceStopDevice:
 * @net: net device to stop
 *
 * Based upon the type of device provided, perform the appropriate
 * work to deactivate the device so that packets aren't forwarded to
 * it from the rest of the network.
 */
int
qemuInterfaceStopDevice(virDomainNetDefPtr net)
{
    int ret = -1;
    virDomainNetType actualType = virDomainNetGetActualType(net);

    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        if (virDomainNetGetActualBridgeMACTableManager(net)
            == VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_LIBVIRT) {
            /* remove the FDB entries that were added during
             * qemuInterfaceStartDevices()
             */
            if (virNetDevBridgeFDBDel(&net->mac, net->ifname,
                                      VIR_NETDEVBRIDGE_FDB_FLAG_MASTER |
                                      VIR_NETDEVBRIDGE_FDB_FLAG_TEMP) < 0)
                goto cleanup;
        }
        break;

    case VIR_DOMAIN_NET_TYPE_DIRECT: {
        const char *physdev = virDomainNetGetActualDirectDev(net);

        /* macvtap interfaces need to be marked !IFF_UP (ie "down") to
         * prevent any host-generated traffic sent from this interface
         * from putting bad info into the arp caches of other machines
         * on this network.
         */
        if (virNetDevSetOnline(net->ifname, false) < 0)
            goto cleanup;

        /* also mark the physdev down for passthrough macvtap, as the
         * physdev has the same MAC address as the macvtap device.
         */
        if (virDomainNetGetActualDirectMode(net) ==
            VIR_NETDEV_MACVLAN_MODE_PASSTHRU &&
            physdev && virNetDevSetOnline(physdev, false) < 0)
            goto cleanup;
        break;
    }

    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_LAST:
        /* these types all require no action */
        break;
    }

    ret = 0;
 cleanup:
    return ret;
}

/**
 * qemuInterfaceStopDevices:
 * @def: domain definition
 *
 * Make all interfaces associated with this domain inaccessible from
 * the rest of the network.
 */
int
qemuInterfaceStopDevices(virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        if (qemuInterfaceStopDevice(def->nets[i]) < 0)
            return -1;
    }
    return 0;
}
