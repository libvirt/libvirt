/*
 * Copyright (C) 2007-2014 Red Hat, Inc.
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

#include "virmacaddr.h"
#include "virnetdevtap.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virnetdevmidonet.h"
#include "virnetdevopenvswitch.h"
#include "virerror.h"
#include "virfile.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"

#include <unistd.h>
#include <sys/types.h>
#ifndef WIN32
# include <sys/ioctl.h>
#endif
#ifdef WITH_NET_IF_H
# include <net/if.h>
#endif
#include <fcntl.h>
#ifdef __linux__
# include <linux/if_tun.h>    /* IFF_TUN, IFF_NO_PI */
#elif defined(__FreeBSD__)
# include <net/if_mib.h>
# include <sys/sysctl.h>
#endif
#if defined(WITH_GETIFADDRS) && defined(AF_LINK)
# include <ifaddrs.h>
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.netdevtap");

/**
 * virNetDevTapGetName:
 * @tapfd: a tun/tap file descriptor
 * @ifname: a pointer that will receive the interface name
 *
 * Retrieve the interface name given a file descriptor for a tun/tap
 * interface.
 *
 * Returns 0 if the interface name is successfully queried, -1 otherwise
 */
int
virNetDevTapGetName(int tapfd G_GNUC_UNUSED, char **ifname G_GNUC_UNUSED)
{
#ifdef TUNGETIFF
    struct ifreq ifr;

    if (ioctl(tapfd, TUNGETIFF, &ifr) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to query tap interface name"));
        return -1;
    }

    *ifname = g_strdup(ifr.ifr_name);
    return 0;
#else
    return -1;
#endif
}

/**
 * virNetDevTapGetRealDeviceName:
 * @ifname: the interface name
 *
 * Lookup real interface name (i.e. name of the device entry in /dev),
 * because e.g. on FreeBSD if we rename tap device to vnetN its device
 * entry still remains unchanged (/dev/tapX), but bhyve needs a name
 * that matches /dev entry.
 *
 * Returns the proper interface name or NULL if no corresponding interface
 * found.
 */
char*
virNetDevTapGetRealDeviceName(char *ifname G_GNUC_UNUSED)
{
#ifdef IFDATA_DRIVERNAME
    int ifindex = 0;
    int name[6];
    size_t len = 0;
    char *ret = NULL;

    if ((ifindex = if_nametoindex(ifname)) == 0) {
        virReportSystemError(errno,
                             _("Unable to get interface index for '%1$s'"),
                             ifname);
        return NULL;
    }

    name[0] = CTL_NET;
    name[1] = PF_LINK;
    name[2] = NETLINK_GENERIC;
    name[3] = IFMIB_IFDATA;
    name[4] = ifindex;
    name[5] = IFDATA_DRIVERNAME;

    if (sysctl(name, 6, NULL, &len, 0, 0) < 0) {
        virReportSystemError(errno,
                             _("Unable to get driver name for '%1$s'"),
                             ifname);
        return NULL;
    }

    ret = g_new0(char, len);

    if (sysctl(name, 6, ret, &len, 0, 0) < 0) {
        virReportSystemError(errno,
                             _("Unable to get driver name for '%1$s'"),
                             ifname);
        VIR_FREE(ret);
        return NULL;
    }

    return ret;
#else
    return NULL;
#endif
}


#ifdef TUNSETIFF
/**
 * virNetDevTapCreate:
 * @ifname: the interface name
 * @tunpath: path to the tun device (if NULL, /dev/net/tun is used)
 * @tapfds: array of file descriptors return value for the new tap device
 * @tapfdSize: number of file descriptors in @tapfd
 * @flags: OR of virNetDevTapCreateFlags. Only the following flags are
 *         recognized:
 *
 *   VIR_NETDEV_TAP_CREATE_VNET_HDR
 *     - Enable IFF_VNET_HDR on the tap device
 *   VIR_NETDEV_TAP_CREATE_PERSIST
 *     - The device will persist after the file descriptor is closed
 *   VIR_NETDEV_TAP_CREATE_ALLOW_EXISTING
 *     - The device creation does not fail if @ifname already exists
 *
 * Creates a tap interface. The caller must use virNetDevTapDelete to
 * remove a persistent TAP device when it is no longer needed. In case
 * @tapfdSize is greater than one, multiqueue extension is requested
 * from kernel.
 *
 * Returns 0 in case of success or -1 on failure.
 */
int virNetDevTapCreate(char **ifname,
                       const char *tunpath,
                       int *tapfd,
                       size_t tapfdSize,
                       unsigned int flags)
{
    size_t i = 0;
    int rc;
    int ret = -1;
    int fd = -1;

    /* if ifname is empty, then auto-generate a name for the new
     * device (the kernel could do this for us, but has a bad habit of
     * immediately re-using names that have just been released, which
     * can lead to race conditions).  if ifname is just a
     * user-provided name, virNetDevGenerateName leaves it
     * unchanged. */
    rc = virNetDevGenerateName(ifname, VIR_NET_DEV_GEN_NAME_VNET);
    if (rc < 0)
        return -1;

    if (rc > 0 &&
        !(flags & VIR_NETDEV_TAP_CREATE_ALLOW_EXISTING)) {
        rc = virNetDevExists(*ifname);

        if (rc < 0) {
            return -1;
        } else if (rc > 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("The %1$s interface already exists"),
                           *ifname);
            return -1;
        }
    }

    if (!tunpath)
        tunpath = "/dev/net/tun";

    for (i = 0; i < tapfdSize; i++) {
        struct ifreq ifr = { 0 };

        if ((fd = open(tunpath, O_RDWR)) < 0) {
            virReportSystemError(errno,
                                 _("Unable to open %1$s, is tun module loaded?"),
                                 tunpath);
            goto cleanup;
        }

        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        /* If tapfdSize is greater than one, request multiqueue */
        if (tapfdSize > 1)
            ifr.ifr_flags |= IFF_MULTI_QUEUE;

        if (flags &  VIR_NETDEV_TAP_CREATE_VNET_HDR)
            ifr.ifr_flags |= IFF_VNET_HDR;

        if (virStrcpyStatic(ifr.ifr_name, *ifname) < 0) {
            virReportSystemError(ERANGE,
                                 _("Network interface name '%1$s' is too long"),
                                 *ifname);
            goto cleanup;

        }

        if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
            virReportSystemError(errno,
                                 _("Unable to create tap device %1$s"),
                                 NULLSTR(*ifname));
            goto cleanup;
        }

        if (i == 0) {
            /* In case we are looping more than once, set other
             * TAPs to have the same name */
            VIR_FREE(*ifname);
            *ifname = g_strdup(ifr.ifr_name);
        }

        if ((flags & VIR_NETDEV_TAP_CREATE_PERSIST) &&
            ioctl(fd, TUNSETPERSIST, 1) < 0) {
            virReportSystemError(errno,
                                 _("Unable to set tap device %1$s to persistent"),
                                 NULLSTR(*ifname));
            goto cleanup;
        }
        tapfd[i] = fd;
    }

    VIR_INFO("created device: '%s'", *ifname);
    ret = 0;

 cleanup:
    if (ret < 0) {
        VIR_FORCE_CLOSE(fd);
        while (i--)
            VIR_FORCE_CLOSE(tapfd[i]);
    }

    return ret;
}


int virNetDevTapDelete(const char *ifname,
                       const char *tunpath)
{
    struct ifreq try = { 0 };
    int fd;
    int ret = -1;

    if (!tunpath)
        tunpath = "/dev/net/tun";

    if ((fd = open(tunpath, O_RDWR)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open %1$s, is tun module loaded?"),
                             tunpath);
        return -1;
    }

    try.ifr_flags = IFF_TAP|IFF_NO_PI;

    if (virStrcpyStatic(try.ifr_name, ifname) < 0) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%1$s' is too long"),
                             ifname);
        goto cleanup;
    }

    if (ioctl(fd, TUNSETIFF, &try) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to associate TAP device"));
        goto cleanup;
    }

    if (ioctl(fd, TUNSETPERSIST, 0) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to make TAP device non-persistent"));
        goto cleanup;
    }

    VIR_INFO("delete device: '%s'", ifname);
    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#elif defined(SIOCIFCREATE2) && defined(SIOCIFDESTROY) && defined(IF_MAXUNIT)
int virNetDevTapCreate(char **ifname,
                       const char *tunpath G_GNUC_UNUSED,
                       int *tapfd,
                       size_t tapfdSize,
                       unsigned int flags G_GNUC_UNUSED)
{
    int s;
    struct ifreq ifr;
    int ret = -1;

    if (tapfdSize > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Multiqueue devices are not supported on this system"));
        goto cleanup;
    }

    /* auto-generate an unused name for the new device (this
     * is NOP if a name has been provided)
     */
    if (virNetDevGenerateName(ifname, VIR_NET_DEV_GEN_NAME_VNET) < 0)
        return -1;

    /* As FreeBSD determines interface type by name,
     * we have to create 'tap' interface first and
     * then rename it to 'vnet'
     */
    if ((s = virNetDevSetupControl("tap", &ifr)) < 0)
        return -1;

    if (ioctl(s, SIOCIFCREATE2, &ifr) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create tap device"));
        goto cleanup;
    }

    if (tapfd) {
        g_autofree char *dev_path = NULL;
        dev_path = g_strdup_printf("/dev/%s", ifr.ifr_name);

        if ((*tapfd = open(dev_path, O_RDWR)) < 0) {
            virReportSystemError(errno,
                                 _("Unable to open %1$s"),
                                 dev_path);
            goto cleanup;
        }
    }

    if (virNetDevSetName(ifr.ifr_name, *ifname) == -1)
        goto cleanup;


    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(s);

    return ret;
}

int virNetDevTapDelete(const char *ifname,
                       const char *tunpath G_GNUC_UNUSED)
{
    int s;
    struct ifreq ifr;
    int ret = -1;

    if ((s = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(s, SIOCIFDESTROY, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to remove tap device %1$s"),
                             ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(s);
    return ret;
}

#else
int virNetDevTapCreate(char **ifname G_GNUC_UNUSED,
                       const char *tunpath G_GNUC_UNUSED,
                       int *tapfd G_GNUC_UNUSED,
                       size_t tapfdSize G_GNUC_UNUSED,
                       unsigned int flags G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to create TAP devices on this platform"));
    return -1;
}
int virNetDevTapDelete(const char *ifname G_GNUC_UNUSED,
                       const char *tunpath G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to delete TAP devices on this platform"));
    return -1;
}
#endif


/**
 * virNetDevTapAttachBridge:
 * @tapname: the tap interface name (or name template)
 * @brname: the bridge name
 * @macaddr: desired MAC address
 * @virtPortProfile: bridge/port specific configuration
 * @virtVlan: vlan tag info
 * @mtu: requested MTU for port (or 0 for "default")
 * @actualMTU: MTU actually set for port (after accounting for bridge's MTU)
 *
 * This attaches an existing tap device (@tapname) to a bridge
 * (@brname).
 *
 * Returns 0 in case of success or -1 on failure
 */
int
virNetDevTapAttachBridge(const char *tapname,
                         const char *brname,
                         const virMacAddr *macaddr,
                         const unsigned char *vmuuid,
                         const virNetDevVPortProfile *virtPortProfile,
                         const virNetDevVlan *virtVlan,
                         virTristateBool isolatedPort,
                         unsigned int mtu,
                         unsigned int *actualMTU)
{
    /* If an MTU is specified for the new device, set it before
     * attaching the device to the bridge, as it may affect the MTU of
     * the bridge (in particular if it is the first device attached to
     * the bridge, or if it is smaller than the current MTU of the
     * bridge). If MTU isn't specified for the new device (i.e. 0),
     * we need to set the interface MTU to the current MTU of the
     * bridge (to avoid inadvertently changing the bridge's MTU).
     */
    if (mtu > 0) {
        if (virNetDevSetMTU(tapname, mtu) < 0)
            return -1;
    } else {
        if (virNetDevSetMTUFromDevice(tapname, brname) < 0)
            return -1;
    }
    if (actualMTU) {
        int retMTU = virNetDevGetMTU(tapname);

        if (retMTU < 0)
            return -1;

        *actualMTU = retMTU;
    }


    if (virtPortProfile) {
        if (virtPortProfile->virtPortType == VIR_NETDEV_VPORT_PROFILE_MIDONET) {
            if (virNetDevMidonetBindPort(tapname, virtPortProfile) < 0)
                return -1;
        } else if (virtPortProfile->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
            if (virNetDevOpenvswitchAddPort(brname, tapname, macaddr, vmuuid,
                                            virtPortProfile, virtVlan) < 0)
                return -1;
        }
    } else {
        if (virNetDevBridgeAddPort(brname, tapname) < 0)
            return -1;

        if (isolatedPort == VIR_TRISTATE_BOOL_YES &&
            virNetDevBridgePortSetIsolated(brname, tapname, true) < 0) {
            virErrorPtr err;

            virErrorPreserveLast(&err);
            ignore_value(virNetDevBridgeRemovePort(brname, tapname));
            virErrorRestore(&err);
            return -1;
        }
    }

    return 0;
}


/**
 * virNetDevTapReattachBridge:
 * @tapname: the tap interface name (or name template)
 * @brname: the bridge name
 * @macaddr: desired MAC address
 * @virtPortProfile: bridge/port specific configuration
 * @virtVlan: vlan tag info
 * @mtu: requested MTU for port (or 0 for "default")
 * @actualMTU: MTU actually set for port (after accounting for bridge's MTU)
 *
 * Ensures that the tap device (@tapname) is connected to the bridge
 * (@brname), potentially removing it from any existing bridge that
 * does not match.
 *
 * Returns 0 in case of success or -1 on failure
 */
int
virNetDevTapReattachBridge(const char *tapname,
                           const char *brname,
                           const virMacAddr *macaddr,
                           const unsigned char *vmuuid,
                           const virNetDevVPortProfile *virtPortProfile,
                           const virNetDevVlan *virtVlan,
                           virTristateBool isolatedPort,
                           unsigned int mtu,
                           unsigned int *actualMTU)
{
    bool useOVS = false;
    g_autofree char *master = NULL;

    if (virNetDevGetMaster(tapname, &master) < 0)
        return -1;

    /* IFLA_MASTER for a tap on an OVS switch is always "ovs-system" */
    if (STREQ_NULLABLE(master, "ovs-system")) {
        useOVS = true;
        if (virNetDevOpenvswitchInterfaceGetMaster(tapname, &master) < 0)
            return -1;
    }

    /* Nothing more todo if we're on the right bridge already */
    if (STREQ_NULLABLE(brname, master))
        return 0;

    /* disconnect from current (incorrect) bridge, if any  */
    if (master) {
        int ret;
        VIR_INFO("Removing %s from %s", tapname, master);
        if (useOVS)
            ret = virNetDevOpenvswitchRemovePort(master, tapname);
        else
            ret = virNetDevBridgeRemovePort(master, tapname);
        if (ret < 0)
            return -1;
    }

    VIR_INFO("Attaching %s to %s", tapname, brname);
    if (virNetDevTapAttachBridge(tapname, brname,
                                 macaddr, vmuuid,
                                 virtPortProfile,
                                 virtVlan,
                                 isolatedPort,
                                 mtu, actualMTU) < 0)
        return -1;

    return 0;
}


/**
 * virNetDevTapCreateInBridgePort:
 * @brname: the bridge name
 * @ifname: the interface name (or name template)
 * @macaddr: desired MAC address
 * @tunpath: path to the tun device (if NULL, /dev/net/tun is used)
 * @tapfd: array of file descriptor return value for the new tap device
 * @tapfdSize: number of file descriptors in @tapfd
 * @virtPortProfile: bridge/port specific configuration
 * @coalesce: optional coalesce parameters
 * @mtu: requested MTU for port (or 0 for "default")
 * @actualMTU: MTU actually set for port (after accounting for bridge's MTU)
 * @flags: OR of virNetDevTapCreateFlags:

 *   VIR_NETDEV_TAP_CREATE_IFUP
 *     - Bring the interface up
 *   VIR_NETDEV_TAP_CREATE_VNET_HDR
 *     - Enable IFF_VNET_HDR on the tap device
 *   VIR_NETDEV_TAP_CREATE_USE_MAC_FOR_BRIDGE
 *     - Set this interface's MAC as the bridge's MAC address
 *   VIR_NETDEV_TAP_CREATE_PERSIST
 *     - The device will persist after the file descriptor is closed
 *
 * This function creates a new tap device on a bridge. @ifname can be either
 * a fixed name or a name template with '%d' for dynamic name allocation.
 * in either case the final name for the bridge will be stored in @ifname.
 * If the @tapfd parameter is supplied, the open tap device file descriptor
 * will be returned, otherwise the TAP device will be closed. The caller must
 * use virNetDevTapDelete to remove a persistent TAP device when it is no
 * longer needed.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevTapCreateInBridgePort(const char *brname,
                                   char **ifname,
                                   const virMacAddr *macaddr,
                                   const unsigned char *vmuuid,
                                   const char *tunpath,
                                   int *tapfd,
                                   size_t tapfdSize,
                                   const virNetDevVPortProfile *virtPortProfile,
                                   const virNetDevVlan *virtVlan,
                                   virTristateBool isolatedPort,
                                   virNetDevCoalesce *coalesce,
                                   unsigned int mtu,
                                   unsigned int *actualMTU,
                                   unsigned int flags)
{
    virMacAddr tapmac;
    size_t i;

    if (virNetDevTapCreate(ifname, tunpath, tapfd, tapfdSize, flags) < 0)
        return -1;

    /* We need to set the interface MAC before adding it
     * to the bridge, because the bridge assumes the lowest
     * MAC of all enslaved interfaces & we don't want it
     * seeing the kernel allocate random MAC for the TAP
     * device before we set our static MAC.
     */
    virMacAddrSet(&tapmac, macaddr);
    if (!(flags & VIR_NETDEV_TAP_CREATE_USE_MAC_FOR_BRIDGE)) {
        /* The tap device's MAC address cannot match the MAC address
         * used by the guest. This results in "received packet on
         * vnetX with own address as source address" error logs from
         * the kernel. Making the tap address as high as possible
         * discourages the bridge from using this tap's MAC as its own
         * (a Linux host bridge will take on the lowest numbered MAC
         * of all devices attached to it).
         */
        if (tapmac.addr[0] == 0xFE)
            tapmac.addr[0] = 0xFA;
        else
            tapmac.addr[0] = 0xFE;
    }

    if (virNetDevSetMAC(*ifname, &tapmac) < 0)
        goto error;

    if (virNetDevTapAttachBridge(*ifname, brname, macaddr, vmuuid,
                                 virtPortProfile, virtVlan,
                                 isolatedPort, mtu, actualMTU) < 0) {
        goto error;
    }

    if (virNetDevSetOnline(*ifname, !!(flags & VIR_NETDEV_TAP_CREATE_IFUP)) < 0)
        goto error;

    if (virNetDevSetCoalesce(*ifname, coalesce, false) < 0)
        goto error;

    return 0;

 error:
    for (i = 0; i < tapfdSize && tapfd[i] >= 0; i++)
        VIR_FORCE_CLOSE(tapfd[i]);

    return -1;
}

/*-------------------- interface stats --------------------*/

/**
 * virNetDevTapInterfaceStats:
 * @ifname: interface
 * @stats: where to store statistics
 * @swapped: whether to swap RX/TX fields
 *
 * Fetch RX/TX statistics for given named interface (@ifname) and
 * store them at @stats. The returned statistics are always from
 * domain POV. Because in some cases this means swapping RX/TX in
 * the stats and in others this means no swapping (consider TAP
 * vs macvtap) caller might choose if the returned stats should
 * be @swapped or not.
 *
 * Returns 0 on success, -1 otherwise (with error reported).
 */
#ifdef __linux__
int
virNetDevTapInterfaceStats(const char *ifname,
                           virDomainInterfaceStatsPtr stats,
                           bool swapped)
{
    int ifname_len;
    FILE *fp;
    char line[256], *colon;

    if (!ifname) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Interface name not provided"));
        return -1;
    }

    fp = fopen("/proc/net/dev", "r");
    if (!fp) {
        virReportSystemError(errno, "%s",
                             _("Could not open /proc/net/dev"));
        return -1;
    }

    ifname_len = strlen(ifname);

    while (fgets(line, sizeof(line), fp)) {
        long long dummy;
        long long rx_bytes;
        long long rx_packets;
        long long rx_errs;
        long long rx_drop;
        long long tx_bytes;
        long long tx_packets;
        long long tx_errs;
        long long tx_drop;

        /* The line looks like:
         *   "   eth0:..."
         * Split it at the colon.
         */
        colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        if (colon-ifname_len >= line &&
            STREQ(colon-ifname_len, ifname)) {
            if (sscanf(colon+1,
                       "%lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
                       &rx_bytes, &rx_packets, &rx_errs, &rx_drop,
                       &dummy, &dummy, &dummy, &dummy,
                       &tx_bytes, &tx_packets, &tx_errs, &tx_drop,
                       &dummy, &dummy, &dummy, &dummy) != 16)
                continue;

            if (swapped) {
                stats->rx_bytes = tx_bytes;
                stats->rx_packets = tx_packets;
                stats->rx_errs = tx_errs;
                stats->rx_drop = tx_drop;
                stats->tx_bytes = rx_bytes;
                stats->tx_packets = rx_packets;
                stats->tx_errs = rx_errs;
                stats->tx_drop = rx_drop;
            } else {
                stats->rx_bytes = rx_bytes;
                stats->rx_packets = rx_packets;
                stats->rx_errs = rx_errs;
                stats->rx_drop = rx_drop;
                stats->tx_bytes = tx_bytes;
                stats->tx_packets = tx_packets;
                stats->tx_errs = tx_errs;
                stats->tx_drop = tx_drop;
            }

            VIR_FORCE_FCLOSE(fp);
            return 0;
        }
    }
    VIR_FORCE_FCLOSE(fp);

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("/proc/net/dev: Interface not found"));
    return -1;
}
#elif defined(WITH_GETIFADDRS) && defined(AF_LINK)
int
virNetDevTapInterfaceStats(const char *ifname,
                           virDomainInterfaceStatsPtr stats,
                           bool swapped)
{
    struct ifaddrs *ifap, *ifa;
    struct if_data *ifd;
    int ret = -1;

    if (!ifname) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Interface name not provided"));
        return -1;
    }

    if (getifaddrs(&ifap) < 0) {
        virReportSystemError(errno, "%s",
                             _("Could not get interface list"));
        return -1;
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family != AF_LINK)
            continue;

        if (STREQ(ifa->ifa_name, ifname)) {
            ifd = (struct if_data *)ifa->ifa_data;
            if (swapped) {
                stats->tx_bytes = ifd->ifi_ibytes;
                stats->tx_packets = ifd->ifi_ipackets;
                stats->tx_errs = ifd->ifi_ierrors;
                stats->tx_drop = ifd->ifi_iqdrops;
                stats->rx_bytes = ifd->ifi_obytes;
                stats->rx_packets = ifd->ifi_opackets;
                stats->rx_errs = ifd->ifi_oerrors;
# ifndef __APPLE__
                stats->rx_drop = ifd->ifi_oqdrops;
# else
                stats->rx_drop = 0;
# endif
            } else {
                stats->tx_bytes = ifd->ifi_obytes;
                stats->tx_packets = ifd->ifi_opackets;
                stats->tx_errs = ifd->ifi_oerrors;
# ifndef __APPLE__
                stats->tx_drop = ifd->ifi_oqdrops;
# else
                stats->tx_drop = 0;
# endif
                stats->rx_bytes = ifd->ifi_ibytes;
                stats->rx_packets = ifd->ifi_ipackets;
                stats->rx_errs = ifd->ifi_ierrors;
                stats->rx_drop = ifd->ifi_iqdrops;
            }

            ret = 0;
            break;
        }
    }

    if (ret < 0)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Interface not found"));

    freeifaddrs(ifap);
    return ret;
}
#else
int
virNetDevTapInterfaceStats(const char *ifname G_GNUC_UNUSED,
                           virDomainInterfaceStatsPtr stats G_GNUC_UNUSED,
                           bool swapped G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                   _("interface stats not implemented on this platform"));
    return -1;
}

#endif /* __linux__ */
