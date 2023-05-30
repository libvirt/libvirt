/*
 * qemu_interface.c: QEMU interface management
 *
 * Copyright (C) 2015-2016 Red Hat, Inc.
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
 */

#include <config.h>

#include "network_conf.h"
#include "domain_audit.h"
#include "domain_nwfilter.h"
#include "qemu_interface.h"
#include "viralloc.h"
#include "virlog.h"
#include "virnetdev.h"
#include "virnetdevtap.h"
#include "virnetdevmacvlan.h"
#include "virnetdevbridge.h"
#include "virnetdevvportprofile.h"
#include "virsocket.h"

#include <sys/stat.h>
#include <fcntl.h>

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_interface");

/**
 * qemuInterfaceStartDevice:
 * @net: net device to start
 *
 * Based upon the type of device provided, perform the appropriate
 * work to completely activate the device and make it reachable from
 * the rest of the network.
 */
int
qemuInterfaceStartDevice(virDomainNetDef *net)
{
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
 * qemuInterfaceStartDevices:
 * @def: domain definition
 *
 * Set all ifaces associated with this domain to the online state.
 */
int
qemuInterfaceStartDevices(virDomainDef *def)
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
qemuInterfaceStopDevice(virDomainNetDef *net)
{
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
 * qemuInterfaceStopDevices:
 * @def: domain definition
 *
 * Make all interfaces associated with this domain inaccessible from
 * the rest of the network.
 */
int
qemuInterfaceStopDevices(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        if (qemuInterfaceStopDevice(def->nets[i]) < 0)
            return -1;
    }
    return 0;
}


static bool
qemuInterfaceIsVnetCompatModel(const virDomainNetDef *net)
{
    return (virDomainNetIsVirtioModel(net) ||
            net->model == VIR_DOMAIN_NET_MODEL_E1000E ||
            net->model == VIR_DOMAIN_NET_MODEL_IGB ||
            net->model == VIR_DOMAIN_NET_MODEL_VMXNET3);
}


/**
 * qemuInterfaceDirectConnect:
 * @def: the definition of the VM (needed by 802.1Qbh and audit)
 * @driver: pointer to the driver instance
 * @net: pointer to the VM's interface description with direct device type
 * @tapfd: array of file descriptor return value for the new device
 * @tapfdSize: number of file descriptors in @tapfd
 * @vmop: VM operation type
 *
 * Returns 0 on success or -1 in case of error.
 */
int
qemuInterfaceDirectConnect(virDomainDef *def,
                           virQEMUDriver *driver,
                           virDomainNetDef *net,
                           int *tapfd,
                           size_t tapfdSize,
                           virNetDevVPortProfileOp vmop)
{
    int ret = -1;
    char *res_ifname = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    unsigned int macvlan_create_flags = VIR_NETDEV_MACVLAN_CREATE_WITH_TAP;
    qemuDomainNetworkPrivate *netpriv = QEMU_DOMAIN_NETWORK_PRIVATE(net);

    if (qemuInterfaceIsVnetCompatModel(net))
        macvlan_create_flags |= VIR_NETDEV_MACVLAN_VNET_HDR;

    if (virNetDevMacVLanCreateWithVPortProfile(net->ifname,
                                               &net->mac,
                                               virDomainNetGetActualDirectDev(net),
                                               virDomainNetGetActualDirectMode(net),
                                               virDomainNetGetActualVlan(net),
                                               def->uuid,
                                               virDomainNetGetActualVirtPortProfile(net),
                                               &res_ifname,
                                               vmop, cfg->stateDir,
                                               tapfd, tapfdSize,
                                               macvlan_create_flags) < 0)
        goto cleanup;

    netpriv->created = true;

    virDomainAuditNetDevice(def, net, res_ifname, true);
    VIR_FREE(net->ifname);
    net->ifname = res_ifname;
    ret = 0;

 cleanup:
    if (ret < 0) {
        while (tapfdSize--)
            VIR_FORCE_CLOSE(tapfd[tapfdSize]);
    }
    return ret;
}


/**
 * qemuCreateInBridgePortWithHelper:
 * @cfg: the configuration object in which the helper name is looked up
 * @brname: the bridge name
 * @ifname: the returned interface name
 * @macaddr: the returned MAC address
 * @tapfd: file descriptor return value for the new tap device
 * @flags: OR of virNetDevTapCreateFlags:

 *   VIR_NETDEV_TAP_CREATE_VNET_HDR
 *     - Enable IFF_VNET_HDR on the tap device
 *
 * This function creates a new tap device on a bridge using an external
 * helper.  The final name for the bridge will be stored in @ifname.
 *
 * Returns 0 in case of success or -1 on failure
 */
static int
qemuCreateInBridgePortWithHelper(virQEMUDriverConfig *cfg,
                                 const char *brname,
                                 char **ifname,
                                 int *tapfd,
                                 unsigned int flags)
{
    const char *const bridgeHelperDirs[] = {
        "/usr/libexec",
        "/usr/lib/qemu",
        "/usr/lib",
        NULL,
    };
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *bridgeHelperPath = NULL;
    char *errbuf = NULL, *cmdstr = NULL;
    int pair[2] = { -1, -1 };

    if ((flags & ~VIR_NETDEV_TAP_CREATE_VNET_HDR) != VIR_NETDEV_TAP_CREATE_IFUP)
        return -1;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
        virReportSystemError(errno, "%s", _("failed to create socket"));
        return -1;
    }

    bridgeHelperPath = virFindFileInPathFull(cfg->bridgeHelperName, bridgeHelperDirs);

    if (!bridgeHelperPath) {
        virReportSystemError(errno, _("'%1$s' is not a suitable bridge helper"),
                             cfg->bridgeHelperName);
        return -1;
    }

    VIR_DEBUG("Using qemu-bridge-helper: %s", bridgeHelperPath);

    cmd = virCommandNew(bridgeHelperPath);
    if (flags & VIR_NETDEV_TAP_CREATE_VNET_HDR)
        virCommandAddArgFormat(cmd, "--use-vnet");
    virCommandAddArgFormat(cmd, "--br=%s", brname);
    virCommandAddArgFormat(cmd, "--fd=%d", pair[1]);
    virCommandSetErrorBuffer(cmd, &errbuf);
    virCommandDoAsyncIO(cmd);
    virCommandPassFD(cmd, pair[1],
                     VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    virCommandClearCaps(cmd);
#ifdef CAP_NET_ADMIN
    virCommandAllowCap(cmd, CAP_NET_ADMIN);
#endif
    if (virCommandRunAsync(cmd, NULL) < 0) {
        *tapfd = -1;
        goto cleanup;
    }

    do {
        *tapfd = virSocketRecvFD(pair[0], 0);
    } while (*tapfd < 0 && errno == EINTR);

    if (*tapfd < 0) {
        char *errstr = NULL;

        if (!(cmdstr = virCommandToString(cmd, false)))
            goto cleanup;
        virCommandAbort(cmd);

        if (errbuf && *errbuf)
            errstr = g_strdup_printf("stderr=%s", errbuf);

        virReportSystemError(errno,
                             _("%1$s: failed to communicate with bridge helper: %2$s"),
                             cmdstr,
                             NULLSTR_EMPTY(errstr));
        VIR_FREE(errstr);
        goto cleanup;
    }

    if (virNetDevTapGetName(*tapfd, ifname) < 0 ||
        virCommandWait(cmd, NULL) < 0) {
        VIR_FORCE_CLOSE(*tapfd);
        *tapfd = -1;
    }

 cleanup:
    VIR_FREE(cmdstr);
    VIR_FREE(errbuf);
    VIR_FORCE_CLOSE(pair[0]);
    return *tapfd < 0 ? -1 : 0;
}


/* qemuInterfaceEthernetConnect:
 * @def: the definition of the VM
 * @driver: qemu driver data
 * @net: pointer to the VM's interface description
 * @tapfd: array of file descriptor return value for the new device
 * @tapfdsize: number of file descriptors in @tapfd
 *
 * Called *only* called if actualType is VIR_DOMAIN_NET_TYPE_ETHERNET
 * (i.e. if the connection is made with a tap device)
 */
int
qemuInterfaceEthernetConnect(virDomainDef *def,
                           virQEMUDriver *driver,
                           virDomainNetDef *net,
                           int *tapfd,
                           size_t tapfdSize)
{
    virMacAddr tapmac;
    int ret = -1;
    unsigned int tap_create_flags = VIR_NETDEV_TAP_CREATE_IFUP;
    bool template_ifname = false;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    const char *tunpath = "/dev/net/tun";
    const char *auditdev = tunpath;

    if (net->backend.tap) {
        tunpath = net->backend.tap;
        if (!driver->privileged) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("cannot use custom tap device in session mode"));
            goto cleanup;
        }
    }

    if (qemuInterfaceIsVnetCompatModel(net))
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
                                         qemuInterfaceIsVnetCompatModel(net)) < 0) {
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

    if (cfg->macFilter &&
        ebtablesAddForwardAllowIn(driver->ebtables,
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


/* qemuInterfaceBridgeConnect:
 * @def: the definition of the VM
 * @driver: qemu driver data
 * @net: pointer to the VM's interface description
 * @tapfd: array of file descriptor return value for the new device
 * @tapfdsize: number of file descriptors in @tapfd
 *
 * Called *only* called if actualType is VIR_DOMAIN_NET_TYPE_NETWORK or
 * VIR_DOMAIN_NET_TYPE_BRIDGE (i.e. if the connection is made with a tap
 * device connecting to a bridge device)
 */
int
qemuInterfaceBridgeConnect(virDomainDef *def,
                           virQEMUDriver *driver,
                           virDomainNetDef *net,
                           int *tapfd,
                           size_t *tapfdSize)
{
    const char *brname;
    int ret = -1;
    unsigned int tap_create_flags = VIR_NETDEV_TAP_CREATE_IFUP;
    bool template_ifname = false;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    const char *tunpath = "/dev/net/tun";

    if (net->backend.tap) {
        tunpath = net->backend.tap;
        if (!driver->privileged) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("cannot use custom tap device in session mode"));
            goto cleanup;
        }
    }

    if (!(brname = virDomainNetGetActualBridgeName(net))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Missing bridge name"));
        goto cleanup;
    }

    if (!net->ifname)
        template_ifname = true;

    if (qemuInterfaceIsVnetCompatModel(net))
        tap_create_flags |= VIR_NETDEV_TAP_CREATE_VNET_HDR;

    if (driver->privileged) {
        if (virNetDevTapCreateInBridgePort(brname, &net->ifname, &net->mac,
                                           def->uuid, tunpath, tapfd, *tapfdSize,
                                           virDomainNetGetActualVirtPortProfile(net),
                                           virDomainNetGetActualVlan(net),
                                           virDomainNetGetActualPortOptionsIsolated(net),
                                           net->coalesce, 0, NULL,
                                           tap_create_flags) < 0) {
            virDomainAuditNetDevice(def, net, tunpath, false);
            goto cleanup;
        }
        if (virDomainNetGetActualBridgeMACTableManager(net)
            == VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_LIBVIRT) {
            /* libvirt is managing the FDB of the bridge this device
             * is attaching to, so we need to turn off learning and
             * unicast_flood on the device to prevent the kernel from
             * adding any FDB entries for it. We will add an fdb
             * entry ourselves (during qemuInterfaceStartDevices(),
             * using the MAC address from the interface config.
             */
            if (virNetDevBridgePortSetLearning(brname, net->ifname, false) < 0)
                goto cleanup;
            if (virNetDevBridgePortSetUnicastFlood(brname, net->ifname, false) < 0)
                goto cleanup;
        }
    } else {
        if (qemuCreateInBridgePortWithHelper(cfg, brname,
                                             &net->ifname,
                                             tapfd, tap_create_flags) < 0) {
            virDomainAuditNetDevice(def, net, tunpath, false);
            goto cleanup;
        }
        /* qemuCreateInBridgePortWithHelper can only create a single FD */
        if (*tapfdSize > 1) {
            VIR_WARN("Ignoring multiqueue network request");
            *tapfdSize = 1;
        }
    }

    virDomainAuditNetDevice(def, net, tunpath, true);

    if (cfg->macFilter &&
        ebtablesAddForwardAllowIn(driver->ebtables,
                                  net->ifname,
                                  &net->mac) < 0)
        goto cleanup;

    if (net->filter &&
        virDomainConfNWFilterInstantiate(def->name, def->uuid, net, false) < 0) {
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (ret < 0) {
        size_t i;
        for (i = 0; i < *tapfdSize && tapfd[i] >= 0; i++)
            VIR_FORCE_CLOSE(tapfd[i]);
        if (template_ifname)
            VIR_FREE(net->ifname);
    }

    return ret;
}


/*
 * Returns: -1 on error, 0 on success. Populates net->privateData->slirp if
 * the slirp helper is needed.
 */
int
qemuInterfacePrepareSlirp(virQEMUDriver *driver,
                          virDomainNetDef *net)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(qemuSlirp) slirp = NULL;
    size_t i;

    if (!cfg->slirpHelperName ||
        !virFileExists(cfg->slirpHelperName))
        return 0; /* fallback to builtin slirp impl */

    if (!(slirp = qemuSlirpNewForHelper(cfg->slirpHelperName)))
        return -1;

    for (i = 0; i < net->guestIP.nips; i++) {
        const virNetDevIPAddr *ip = net->guestIP.ips[i];

        if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET) &&
            !qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_IPV4))
            return 0;

        if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET6) &&
            !qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_IPV6))
            return 0;
    }

    QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp = g_steal_pointer(&slirp);
    return 0;
}


/**
 * qemuInterfaceOpenVhostNet:
 * @vm: domain object
 * @net: network definition
 *
 * Open vhost-net, multiple times - if requested.
 *
 * Returns: 0 on success
 *         -1 on failure
 */
int
qemuInterfaceOpenVhostNet(virDomainObj *vm,
                          virDomainNetDef *net)
{
    qemuDomainNetworkPrivate *netpriv = QEMU_DOMAIN_NETWORK_PRIVATE(net);
    size_t i;
    const char *vhostnet_path = net->backend.vhost;
    size_t vhostfdSize = net->driver.virtio.queues;

    if (!vhostfdSize)
        vhostfdSize = 1;

    if (!vhostnet_path)
        vhostnet_path = "/dev/vhost-net";

    /* If running a plain QEMU guest, or
     * if the config says explicitly to not use vhost, return now */
    if (vm->def->virtType != VIR_DOMAIN_VIRT_KVM ||
        net->driver.virtio.name == VIR_DOMAIN_NET_DRIVER_TYPE_QEMU)
        return 0;

    /* If qemu doesn't support vhost-net mode (including the -netdev and
     * -device command options), don't try to open the device.
     */
    if (!qemuDomainSupportsNicdev(vm->def, net)) {
        if (net->driver.virtio.name == VIR_DOMAIN_NET_DRIVER_TYPE_VHOST) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vhost-net is not supported with this QEMU binary"));
            return -1;
        }
        return 0;
    }

    /* If the nic model isn't virtio, don't try to open. */
    if (!virDomainNetIsVirtioModel(net)) {
        if (net->driver.virtio.name == VIR_DOMAIN_NET_DRIVER_TYPE_VHOST) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vhost-net is only supported for virtio network interfaces"));
            return -1;
        }
        return 0;
    }

    for (i = 0; i < vhostfdSize; i++) {
        VIR_AUTOCLOSE fd = open(vhostnet_path, O_RDWR);
        g_autofree char *name = g_strdup_printf("vhostfd-%s%zu", net->info.alias, i);

        /* If the config says explicitly to use vhost and we couldn't open it,
         * report an error.
         */
        if (fd < 0) {
            virDomainAuditNetDevice(vm->def, net, vhostnet_path, false);
            if (net->driver.virtio.name == VIR_DOMAIN_NET_DRIVER_TYPE_VHOST) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("vhost-net was requested for an interface, but is unavailable"));
                return -1;
            }
            VIR_WARN("Unable to open vhost-net. Opened so far %zu, requested %zu",
                     i, vhostfdSize);
            break;
        }

        netpriv->vhostfds = g_slist_prepend(netpriv->vhostfds, qemuFDPassDirectNew(name, &fd));
    }

    netpriv->vhostfds = g_slist_reverse(netpriv->vhostfds);
    virDomainAuditNetDevice(vm->def, net, vhostnet_path, vhostfdSize);
    return 0;
}
