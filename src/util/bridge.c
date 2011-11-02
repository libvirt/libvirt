/*
 * Copyright (C) 2007, 2009, 2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 */

#include <config.h>

#if defined(WITH_BRIDGE)

# include "bridge.h"
# include "virfile.h"

# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <unistd.h>
# include <fcntl.h>
# include <errno.h>
# include <arpa/inet.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <sys/ioctl.h>
# include <paths.h>
# include <sys/wait.h>

# include <linux/param.h>     /* HZ                 */
# include <linux/sockios.h>   /* SIOCBRADDBR etc.   */
# include <linux/if_bridge.h> /* SYSFS_BRIDGE_ATTR  */
# include <linux/if_tun.h>    /* IFF_TUN, IFF_NO_PI */
# include <net/if_arp.h>    /* ARPHRD_ETHER */

# include "internal.h"
# include "command.h"
# include "memory.h"
# include "util.h"
# include "logging.h"
# include "network.h"
# include "virterror_internal.h"

# define JIFFIES_TO_MS(j) (((j)*1000)/HZ)
# define MS_TO_JIFFIES(ms) (((ms)*HZ)/1000)

# define VIR_FROM_THIS VIR_FROM_NONE

static int virNetDevSetupControlFull(const char *ifname,
                                     struct ifreq *ifr,
                                     int domain,
                                     int type)
{
    int fd;

    if (ifname && ifr) {
        memset(ifr, 0, sizeof(*ifr));

        if (virStrcpyStatic(ifr->ifr_name, ifname) == NULL) {
            virReportSystemError(ERANGE,
                                 _("Network interface name '%s' is too long"),
                                 ifname);
            return -1;
        }
    }

    if ((fd = socket(domain, type, 0)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot open network interface control socket"));
        return -1;
    }

    if (virSetInherit(fd, false) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot set close-on-exec flag for socket"));
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

    return fd;
}


static int virNetDevSetupControl(const char *ifname,
                                 struct ifreq *ifr)
{
    return virNetDevSetupControlFull(ifname, ifr, AF_PACKET, SOCK_DGRAM);
}


/**
 * virNetDevBridgeCreate:
 * @brname: the bridge name
 *
 * This function register a new bridge
 *
 * Returns 0 in case of success or -1 on failure
 */
# ifdef SIOCBRADDBR
int virNetDevBridgeCreate(const char *brname)
{
    int fd = -1;
    int ret = -1;

    if ((fd = virNetDevSetupControl(NULL, NULL)) < 0)
        return -1;

    if (ioctl(fd, SIOCBRADDBR, brname) < 0) {
        virReportSystemError(errno,
                             _("Unable to create bridge %s"), brname);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
# else
int virNetDevBridgeCreate(const char *brname)
{
    virReportSystemError(ENOSYS,
                         _("Unable to create bridge %s"), brname);
    return -1;
}
# endif

# ifdef SIOCBRDELBR
/**
 * virNetDevExists:
 * @ifname
 *
 * Check if the network device @ifname exists
 *
 * Returns 1 if it exists, 0 if it does not, -1 on error
 */
int virNetDevExists(const char *ifname)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {
        if (errno == ENODEV)
            ret = 0;
        else
            virReportSystemError(errno,
                                 _("Unable to check interface flags for %s"), ifname);
        goto cleanup;
    }

    ret = 1;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
# else
int virNetDevExists(const char *ifname)
{
    virReportSystemError(ENOSYS,
                         _("Unable to check interface %s"), ifname);
    return -1;
}
# endif

/**
 * virNetDevBridgeDelete:
 * @brname: the bridge name
 *
 * Remove a bridge from the layer.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
# ifdef SIOCBRDELBR
int virNetDevBridgeDelete(const char *brname)
{
    int fd = -1;
    int ret = -1;

    if ((fd = virNetDevSetupControl(NULL, NULL)) < 0)
        return -1;

    if (ioctl(fd, SIOCBRDELBR, brname) < 0) {
        virReportSystemError(errno,
                             _("Unable to delete bridge %s"), brname);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
# else
int virNetDevBridgeDelete(const char *brname ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to delete bridge %s"), brname);
    return -1;
}
# endif

/**
 * virNetDevBridgeAddPort:
 * @brname: the bridge name
 * @ifname: the network interface name
 *
 * Adds an interface to a bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
# ifdef SIOCBRADDIF
int virNetDevBridgeAddPort(const char *brname,
                           const char *ifname)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        return -1;

    if (!(ifr.ifr_ifindex = if_nametoindex(ifname))) {
        virReportSystemError(ENODEV,
                             _("Unable to get interface index for %s"), ifname);
        goto cleanup;
    }

    if (ioctl(fd, SIOCBRADDIF, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to add bridge %s port %s"), brname, ifname);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
# else
int virNetDevBridgeAddPort(const char *brname,
                           const char *ifname)
{
    virReportSystemError(ENOSYS,
                         _("Unable to add bridge %s port %s"), brname, ifname);
    return -1;
}
# endif

/**
 * virNetDevBridgeRemovePort:
 * @brname: the bridge name
 * @ifname: the network interface name
 *
 * Removes an interface from a bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
# ifdef SIOCBRDELIF
int virNetDevBridgeRemovePort(const char *brname,
                              const char *ifname)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(brname, &ifr)) < 0)
        return -1;

    if (!(ifr.ifr_ifindex = if_nametoindex(ifname))) {
        virReportSystemError(ENODEV,
                             _("Unable to get interface index for %s"), ifname);

        goto cleanup;
    }

    if (ioctl(fd, SIOCBRDELIF, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to remove bridge %s port %s"), brname, ifname);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
# else
int virNetDevBridgeRemovePort(const char *brname,
                              const char *ifname)
{
    virReportSystemError(errno,
                         _("Unable to remove bridge %s port %s"), brname, ifname);
    return -1;
}
# endif

/**
 * virNetDevSetMAC:
 * @ifname: interface name to set MTU for
 * @macaddr: MAC address (VIR_MAC_BUFLEN in size)
 *
 * This function sets the @macaddr for a given interface @ifname. This
 * gets rid of the kernel's automatically assigned random MAC.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevSetMAC(const char *ifname,
                    const unsigned char *macaddr)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    /* To fill ifr.ifr_hdaddr.sa_family field */
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot get interface MAC on '%s'"),
                             ifname);
        goto cleanup;
    }

    memcpy(ifr.ifr_hwaddr.sa_data, macaddr, VIR_MAC_BUFLEN);

    if (ioctl(fd, SIOCSIFHWADDR, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot set interface MAC on '%s'"),
                             ifname);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

/**
 * virNetDevGetMTU:
 * @ifname: interface name get MTU for
 *
 * This function gets the @mtu value set for a given interface @ifname.
 *
 * Returns the MTU value in case of success, or -1 on failure.
 */
int virNetDevGetMTU(const char *ifname)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot get interface MTU on '%s'"),
                             ifname);
        goto cleanup;
    }

    ret = ifr.ifr_mtu;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

/**
 * virNetDevSetMTU:
 * @ifname: interface name to set MTU for
 * @mtu: MTU value
 *
 * This function sets the @mtu for a given interface @ifname.  Typically
 * used on a tap device to set up for Jumbo Frames.
 *
 * Returns 0 in case of success, or -1 on failure
 */
int virNetDevSetMTU(const char *ifname, int mtu)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    ifr.ifr_mtu = mtu;

    if (ioctl(fd, SIOCSIFMTU, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot set interface MTU on '%s'"),
                             ifname);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

/**
 * virNetDevSetMTUFromDevice:
 * @ifname: name of the interface whose MTU we want to set
 * @otherifname: name of the interface whose MTU we want to copy
 *
 * Sets the interface mtu to the same MTU as another interface
 *
 * Returns 0 in case of success, or -1 on failure
 */
int virNetDevSetMTUFromDevice(const char *ifname,
                              const char *otherifname)
{
    int mtu = virNetDevGetMTU(otherifname);

    if (mtu < 0)
        return -1;

    return virNetDevSetMTU(ifname, mtu);
}

/**
 * virNetDevProbeVnetHdr:
 * @tapfd: a tun/tap file descriptor
 *
 * Check whether it is safe to enable the IFF_VNET_HDR flag on the
 * tap interface.
 *
 * Setting IFF_VNET_HDR enables QEMU's virtio_net driver to allow
 * guests to pass larger (GSO) packets, with partial checksums, to
 * the host. This greatly increases the achievable throughput.
 *
 * It is only useful to enable this when we're setting up a virtio
 * interface. And it is only *safe* to enable it when we know for
 * sure that a) qemu has support for IFF_VNET_HDR and b) the running
 * kernel implements the TUNGETIFF ioctl(), which qemu needs to query
 * the supplied tapfd.
 *
 * Returns 1 if VnetHdr is supported, 0 if not supported
 */
# ifdef IFF_VNET_HDR
static int
virNetDevProbeVnetHdr(int tapfd)
{
#  if defined(IFF_VNET_HDR) && defined(TUNGETFEATURES) && defined(TUNGETIFF)
    unsigned int features;
    struct ifreq dummy;

    if (ioctl(tapfd, TUNGETFEATURES, &features) != 0) {
        VIR_INFO("Not enabling IFF_VNET_HDR; "
                 "TUNGETFEATURES ioctl() not implemented");
        return 0;
    }

    if (!(features & IFF_VNET_HDR)) {
        VIR_INFO("Not enabling IFF_VNET_HDR; "
                 "TUNGETFEATURES ioctl() reports no IFF_VNET_HDR");
        return 0;
    }

    /* The kernel will always return -1 at this point.
     * If TUNGETIFF is not implemented then errno == EBADFD.
     */
    if (ioctl(tapfd, TUNGETIFF, &dummy) != -1 || errno != EBADFD) {
        VIR_INFO("Not enabling IFF_VNET_HDR; "
                 "TUNGETIFF ioctl() not implemented");
        return 0;
    }

    VIR_INFO("Enabling IFF_VNET_HDR");

    return 1;
#  else
    (void) tapfd;
    VIR_INFO("Not enabling IFF_VNET_HDR; disabled at build time");
    return 0;
#  endif
}
# endif

/**
 * brAddTap:
 * @brname: the bridge name
 * @ifname: the interface name (or name template)
 * @macaddr: desired MAC address (VIR_MAC_BUFLEN long)
 * @vnet_hdr: whether to try enabling IFF_VNET_HDR
 * @tapfd: file descriptor return value for the new tap device
 *
 * This function creates a new tap device on a bridge. @ifname can be either
 * a fixed name or a name template with '%d' for dynamic name allocation.
 * in either case the final name for the bridge will be stored in @ifname.
 * If the @tapfd parameter is supplied, the open tap device file
 * descriptor will be returned, otherwise the TAP device will be made
 * persistent and closed. The caller must use brDeleteTap to remove
 * a persistent TAP devices when it is no longer needed.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevTapCreateInBridgePort(const char *brname,
                                   char **ifname,
                                   const unsigned char *macaddr,
                                   int vnet_hdr,
                                   bool up,
                                   int *tapfd)
{
    if (virNetDevTapCreate(ifname, vnet_hdr, tapfd) < 0)
        return -1;

    /* We need to set the interface MAC before adding it
     * to the bridge, because the bridge assumes the lowest
     * MAC of all enslaved interfaces & we don't want it
     * seeing the kernel allocate random MAC for the TAP
     * device before we set our static MAC.
     */
    if (virNetDevSetMAC(*ifname, macaddr) < 0)
        goto error;

    /* We need to set the interface MTU before adding it
     * to the bridge, because the bridge will have its
     * MTU adjusted automatically when we add the new interface.
     */
    if (virNetDevSetMTUFromDevice(*ifname, brname) < 0)
        goto error;

    if (virNetDevBridgeAddPort(brname, *ifname) < 0)
        goto error;

    if (virNetDevSetOnline(*ifname, up) < 0)
        goto error;

    return 0;

error:
    if (tapfd)
        VIR_FORCE_CLOSE(*tapfd);
    return -1;
}

int virNetDevTapDelete(const char *ifname)
{
    struct ifreq try;
    int fd;
    int ret = -1;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to open /dev/net/tun, is tun module loaded?"));
        return -1;
    }

    memset(&try, 0, sizeof(struct ifreq));
    try.ifr_flags = IFF_TAP|IFF_NO_PI;

    if (virStrcpyStatic(try.ifr_name, ifname) == NULL) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%s' is too long"),
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

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


/**
 * virNetDevSetOnline:
 * @ifname: the interface name
 * @online: true for up, false for down
 *
 * Function to control if an interface is activated (up, true) or not (down, false)
 *
 * Returns 0 in case of success or -1 on error.
 */
int virNetDevSetOnline(const char *ifname,
                       bool online)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;
    int ifflags;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot get interface flags on '%s'"),
                             ifname);
        goto cleanup;
    }

    if (online)
        ifflags = ifr.ifr_flags | IFF_UP;
    else
        ifflags = ifr.ifr_flags & ~IFF_UP;

    if (ifr.ifr_flags != ifflags) {
        ifr.ifr_flags = ifflags;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
            virReportSystemError(errno,
                                 _("Cannot set interface flags on '%s'"),
                                 ifname);
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

/**
 * virNetDevIsOnline:
 * @ifname: the interface name
 * @online: where to store the status
 *
 * Function to query if an interface is activated (true) or not (false)
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
int virNetDevIsOnline(const char *ifname,
                      bool *online)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot get interface flags on '%s'"),
                             ifname);
        goto cleanup;
    }

    *online = (ifr.ifr_flags & IFF_UP) ? true : false;
    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

/**
 * virNetDevSetIPv4Address:
 * @ifname: the interface name
 * @addr: the IP address (IPv4 or IPv6)
 * @prefix: number of 1 bits in the netmask
 *
 * Add an IP address to an interface. This function *does not* remove
 * any previously added IP addresses - that must be done separately with
 * brDelInetAddress.
 *
 * Returns 0 in case of success or -1 in case of error.
 */

int virNetDevSetIPv4Address(const char *ifname,
                            virSocketAddr *addr,
                            unsigned int prefix)
{
    virCommandPtr cmd = NULL;
    char *addrstr = NULL, *bcaststr = NULL;
    virSocketAddr broadcast;
    int ret = -1;

    if (!(addrstr = virSocketFormatAddr(addr)))
        goto cleanup;
    /* format up a broadcast address if this is IPv4 */
    if ((VIR_SOCKET_IS_FAMILY(addr, AF_INET)) &&
        ((virSocketAddrBroadcastByPrefix(addr, prefix, &broadcast) < 0) ||
         !(bcaststr = virSocketFormatAddr(&broadcast)))) {
        goto cleanup;
    }
    cmd = virCommandNew(IP_PATH);
    virCommandAddArgList(cmd, "addr", "add", NULL);
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    if (bcaststr)
        virCommandAddArgList(cmd, "broadcast", bcaststr, NULL);
    virCommandAddArgList(cmd, "dev", ifname, NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(addrstr);
    VIR_FREE(bcaststr);
    virCommandFree(cmd);
    return ret;
}

/**
 * virNetDevClearIPv4Address:
 * @ifname: the interface name
 * @addr: the IP address (IPv4 or IPv6)
 * @prefix: number of 1 bits in the netmask
 *
 * Delete an IP address from an interface.
 *
 * Returns 0 in case of success or -1 in case of error.
 */

int virNetDevClearIPv4Address(const char *ifname,
                              virSocketAddr *addr,
                              unsigned int prefix)
{
    virCommandPtr cmd = NULL;
    char *addrstr;
    int ret = -1;

    if (!(addrstr = virSocketFormatAddr(addr)))
        goto cleanup;
    cmd = virCommandNew(IP_PATH);
    virCommandAddArgList(cmd, "addr", "del", NULL);
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    virCommandAddArgList(cmd, "dev", ifname, NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(addrstr);
    virCommandFree(cmd);
    return ret;
}

/**
 * virNetDevBridgeSetSTPDelay:
 * @brname: the bridge name
 * @delay: delay in seconds
 *
 * Set the bridge forward delay
 *
 * Returns 0 in case of success or -1 on failure
 */

int virNetDevBridgeSetSTPDelay(const char *brname,
                               int delay)
{
    virCommandPtr cmd;
    int ret = -1;

    cmd = virCommandNew(BRCTL);
    virCommandAddArgList(cmd, "setfd", brname, NULL);
    virCommandAddArgFormat(cmd, "%d", delay);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    virCommandFree(cmd);
    return ret;
}

/**
 * virNetDevBridgeSetSTP:
 * @brname: the bridge name
 * @enable: 1 to enable, 0 to disable
 *
 * Control whether the bridge participates in the spanning tree protocol,
 * in general don't disable it without good reasons.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevBridgeSetSTP(const char *brname,
                          bool enable)
{
    virCommandPtr cmd;
    int ret = -1;

    cmd = virCommandNew(BRCTL);
    virCommandAddArgList(cmd, "stp", brname,
                         enable ? "on" : "off",
                         NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    virCommandFree(cmd);
    return ret;
}

/**
 * brCreateTap:
 * @ifname: the interface name
 * @vnet_hr: whether to try enabling IFF_VNET_HDR
 * @tapfd: file descriptor return value for the new tap device
 *
 * Creates a tap interface.
 * If the @tapfd parameter is supplied, the open tap device file
 * descriptor will be returned, otherwise the TAP device will be made
 * persistent and closed. The caller must use brDeleteTap to remove
 * a persistent TAP devices when it is no longer needed.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */

int virNetDevTapCreate(char **ifname,
                       int vnet_hdr ATTRIBUTE_UNUSED,
                       int *tapfd)
{
    int fd;
    struct ifreq ifr;
    int ret = -1;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to open /dev/net/tun, is tun module loaded?"));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP|IFF_NO_PI;

# ifdef IFF_VNET_HDR
    if (vnet_hdr && virNetDevProbeVnetHdr(fd))
        ifr.ifr_flags |= IFF_VNET_HDR;
# endif

    if (virStrcpyStatic(ifr.ifr_name, *ifname) == NULL) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%s' is too long"),
                             *ifname);
        goto cleanup;

    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to create tap device %s"),
                             NULLSTR(*ifname));
        goto cleanup;
    }

    if (!tapfd &&
        (errno = ioctl(fd, TUNSETPERSIST, 1))) {
        virReportSystemError(errno,
                             _("Unable to set tap device %s to persistent"),
                             NULLSTR(*ifname));
        goto cleanup;
    }

    VIR_FREE(*ifname);
    if (!(*ifname = strdup(ifr.ifr_name))) {
        virReportOOMError();
        goto cleanup;
    }
    if (tapfd)
        *tapfd = fd;
    else
        VIR_FORCE_CLOSE(fd);

    ret = 0;

cleanup:
    if (ret < 0)
        VIR_FORCE_CLOSE(fd);

    return ret;
}

#endif /* WITH_BRIDGE */
