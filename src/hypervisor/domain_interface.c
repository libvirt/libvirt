/*
 * Copyright (C) 2015-2016 Red Hat, Inc.
 * Copyright IBM Corp. 2014
 *
 * domain_interface.c: methods to manage guest/domain interfaces
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

#include "datatypes.h"
#include "domain_audit.h"
#include "domain_conf.h"
#include "domain_driver.h"
#include "domain_interface.h"
#include "domain_nwfilter.h"
#include "network_conf.h"
#include "viralloc.h"
#include "virconftypes.h"
#include "virebtables.h"
#include "virfile.h"
#include "virlog.h"
#include "virmacaddr.h"
#include "virnetdevbridge.h"
#include "virnetdevmidonet.h"
#include "virnetdevopenvswitch.h"
#include "virnetdevtap.h"


#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("domain.interface");

bool
virDomainInterfaceIsVnetCompatModel(const virDomainNetDef *net)
{
    return (virDomainNetIsVirtioModel(net) ||
            net->model == VIR_DOMAIN_NET_MODEL_E1000E ||
            net->model == VIR_DOMAIN_NET_MODEL_IGB ||
            net->model == VIR_DOMAIN_NET_MODEL_VMXNET3);
}

/* virDomainInterfaceEthernetConnect:
 * @def: the definition of the VM
 * @net: a net definition in the VM
 * @ebtables: ebtales context
 * @macFilter: whether driver support mac Filtering
 * @privileged: whether running as privileged user
 * @tapfd: returned array of file descriptors for the domain interface
 * @tapfdsize: returned number of file descriptors in @tapfd
 *
 * Called *only* called if actualType is VIR_DOMAIN_NET_TYPE_ETHERNET
 * (i.e. if the connection is made with a tap device)
 */
int
virDomainInterfaceEthernetConnect(virDomainDef *def,
                                  virDomainNetDef *net,
                                  ebtablesContext *ebtables,
                                  bool macFilter,
                                  bool privileged,
                                  int *tapfd,
                                  size_t tapfdSize)
{
    virMacAddr tapmac;
    int ret = -1;
    unsigned int tap_create_flags = VIR_NETDEV_TAP_CREATE_IFUP;
    bool template_ifname = false;
    const char *tunpath = "/dev/net/tun";
    const char *auditdev = tunpath;

    if (net->backend.tap) {
        tunpath = net->backend.tap;
        if (!privileged) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("cannot use custom tap device in session mode"));
            goto cleanup;
        }
    }

    if (virDomainInterfaceIsVnetCompatModel(net))
        tap_create_flags |= VIR_NETDEV_TAP_CREATE_VNET_HDR;

    if (net->managed_tap == VIR_TRISTATE_BOOL_NO) {
        if (!net->ifname) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("target dev must be supplied when managed='no'"));
            goto cleanup;
        }
        if (virNetDevExists(net->ifname) != 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("target managed='no' but specified dev doesn't exist"));
            goto cleanup;
        }

        tap_create_flags |= VIR_NETDEV_TAP_CREATE_ALLOW_EXISTING;

        if (virNetDevMacVLanIsMacvtap(net->ifname)) {
            auditdev = net->ifname;
            if (virNetDevMacVLanTapOpen(net->ifname, tapfd, tapfdSize) < 0)
                goto cleanup;
            if (virNetDevMacVLanTapSetup(tapfd, tapfdSize,
                                         virDomainInterfaceIsVnetCompatModel(net)) < 0) {
                goto cleanup;
            }
        } else {
            if (virNetDevTapCreate(&net->ifname, tunpath, tapfd, tapfdSize,
                                   tap_create_flags) < 0)
                goto cleanup;
        }
    } else {

        if (!net->ifname)
            template_ifname = true;

        if (virNetDevTapCreate(&net->ifname, tunpath, tapfd, tapfdSize,
                               tap_create_flags) < 0) {
            goto cleanup;
        }

        /* The tap device's MAC address cannot match the MAC address
         * used by the guest. This results in "received packet on
         * vnetX with own address as source address" error logs from
         * the kernel.
         */
        virMacAddrSet(&tapmac, &net->mac);
        if (tapmac.addr[0] == 0xFE)
            tapmac.addr[0] = 0xFA;
        else
            tapmac.addr[0] = 0xFE;

        if (virNetDevSetMAC(net->ifname, &tapmac) < 0)
            goto cleanup;

        if (virNetDevSetOnline(net->ifname, true) < 0)
            goto cleanup;
    }

    if (net->script &&
        virNetDevRunEthernetScript(net->ifname, net->script) < 0)
        goto cleanup;

    if (macFilter &&
        ebtablesAddForwardAllowIn(ebtables,
                                  net->ifname,
                                  &net->mac) < 0)
        goto cleanup;

    if (net->filter &&
        virDomainConfNWFilterInstantiate(def->name, def->uuid, net, false) < 0) {
        goto cleanup;
    }

    virDomainAuditNetDevice(def, net, auditdev, true);

    ret = 0;

 cleanup:
    if (ret < 0) {
        size_t i;

        virDomainAuditNetDevice(def, net, auditdev, false);
        for (i = 0; i < tapfdSize && tapfd[i] >= 0; i++)
            VIR_FORCE_CLOSE(tapfd[i]);
        if (template_ifname)
            VIR_FREE(net->ifname);
    }

    return ret;
}

/**
 * virDomainInterfaceStartDevice:
 * @net: net device to start
 *
 * Based upon the type of device provided, perform the appropriate
 * work to completely activate the device and make it reachable from
 * the rest of the network.
 */
int
virDomainInterfaceStartDevice(virDomainNetDef *net)
{
    virDomainNetType actualType = virDomainNetGetActualType(net);

    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        if (virDomainNetGetActualBridgeMACTableManager(net) ==
                VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_LIBVIRT) {
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
                return -1;
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
            return -1;
        if (!isOnline && virNetDevSetOnline(physdev, true) < 0)
            return -1;

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
            return -1;
        break;
    }

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (virNetDevIPInfoAddToDev(net->ifname, &net->hostIP) < 0)
            return -1;

        break;

    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
        /* these types all require no action */
        break;
    }

    return 0;
}

/**
 * virDomainInterfaceStartDevices:
 * @def: domain definition
 *
 * Set all ifaces associated with this domain to the online state.
 */
int
virDomainInterfaceStartDevices(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        if (virDomainInterfaceStartDevice(def->nets[i]) < 0)
            return -1;
    }
    return 0;
}

/**
 * virDomainInterfaceStopDevice:
 * @net: net device to stop
 *
 * Based upon the type of device provided, perform the appropriate
 * work to deactivate the device so that packets aren't forwarded to
 * it from the rest of the network.
 */
int
virDomainInterfaceStopDevice(virDomainNetDef *net)
{
    virDomainNetType actualType = virDomainNetGetActualType(net);

    switch (actualType) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
        if (virDomainNetGetActualBridgeMACTableManager(net) ==
                VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_LIBVIRT) {
            /* remove the FDB entries that were added during
             * virDomainInterfaceStartDevices()
             */
            if (virNetDevBridgeFDBDel(&net->mac, net->ifname,
                                      VIR_NETDEVBRIDGE_FDB_FLAG_MASTER |
                                      VIR_NETDEVBRIDGE_FDB_FLAG_TEMP) < 0)
                return -1;
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
            return -1;

        /* also mark the physdev down for passthrough macvtap, as the
         * physdev has the same MAC address as the macvtap device.
         */
        if (virDomainNetGetActualDirectMode(net) ==
                VIR_NETDEV_MACVLAN_MODE_PASSTHRU &&
                physdev && virNetDevSetOnline(physdev, false) < 0)
            return -1;
        break;
    }

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
        /* these types all require no action */
        break;
    }

    return 0;
}

/**
 * virDomainInterfaceStopDevices:
 * @def: domain definition
 *
 * Make all interfaces associated with this domain inaccessible from
 * the rest of the network.
 */
int
virDomainInterfaceStopDevices(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        if (virDomainInterfaceStopDevice(def->nets[i]) < 0)
            return -1;
    }
    return 0;
}

/**
 * virDomainInterfaceDeleteDevice:
 * @def: domain definition
 * @net: a net definition in the VM
 * @priv_net_created: whether private network created
 * @stateDir: driver's stateDir
 *
 * Disconnect and delete domain interfaces.
 */

void
virDomainInterfaceDeleteDevice(virDomainDef *def,
                               virDomainNetDef *net,
                               bool priv_net_created,
                               char *stateDir)
{
    const virNetDevVPortProfile *vport = NULL;
    g_autoptr(virConnect) conn = NULL;

    vport = virDomainNetGetActualVirtPortProfile(net);
    switch (virDomainNetGetActualType(net)) {
    case VIR_DOMAIN_NET_TYPE_DIRECT:
        if (priv_net_created) {
            virNetDevMacVLanDeleteWithVPortProfile(net->ifname, &net->mac,
                                                   virDomainNetGetActualDirectDev(net),
                                                   virDomainNetGetActualDirectMode(net),
                                                   virDomainNetGetActualVirtPortProfile(net),
                                                   stateDir);
        }
        break;
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        if (net->managed_tap != VIR_TRISTATE_BOOL_NO && net->ifname) {
            ignore_value(virNetDevTapDelete(net->ifname, net->backend.tap));
            VIR_FREE(net->ifname);
        }
        break;
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
#ifdef VIR_NETDEV_TAP_REQUIRE_MANUAL_CLEANUP
        if (!(vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH))
            ignore_value(virNetDevTapDelete(net->ifname, net->backend.tap));
#endif
        break;
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
        /* No special cleanup procedure for these types. */
        break;
    }
    /* release the physical device (or any other resources used by
        * this interface in the network driver
        */
    if (vport) {
        if (vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_MIDONET) {
            ignore_value(virNetDevMidonetUnbindPort(vport));
        } else if (vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
            ignore_value(virNetDevOpenvswitchRemovePort(
                                virDomainNetGetActualBridgeName(net),
                                net->ifname));
        }
    }

    /* kick the device out of the hostdev list too */
    virDomainNetRemoveHostdev(def, net);
    if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        if (conn || (conn = virGetConnectNetwork()))
            virDomainNetReleaseActualDevice(conn, net);
        else
            VIR_WARN("Unable to release network device '%s'", NULLSTR(net->ifname));
    }

}
