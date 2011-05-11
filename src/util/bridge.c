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
# include "files.h"

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

# define JIFFIES_TO_MS(j) (((j)*1000)/HZ)
# define MS_TO_JIFFIES(ms) (((ms)*HZ)/1000)

struct _brControl {
    int fd;
};

/**
 * brInit:
 * @ctlp: pointer to bridge control return value
 *
 * Initialize a new bridge layer. In case of success
 * @ctlp will contain a pointer to the new bridge structure.
 *
 * Returns 0 in case of success, an error code otherwise.
 */
int
brInit(brControl **ctlp)
{
    int fd;
    int flags;

    if (!ctlp || *ctlp)
        return EINVAL;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return errno;

    if ((flags = fcntl(fd, F_GETFD)) < 0 ||
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        int err = errno;
        VIR_FORCE_CLOSE(fd);
        return err;
    }

    if (VIR_ALLOC(*ctlp) < 0) {
        VIR_FORCE_CLOSE(fd);
        return ENOMEM;
    }

    (*ctlp)->fd = fd;

    return 0;
}

/**
 * brShutdown:
 * @ctl: pointer to a bridge control
 *
 * Shutdown the bridge layer and deallocate the associated structures
 */
void
brShutdown(brControl *ctl)
{
    if (!ctl)
        return;

    VIR_FORCE_CLOSE(ctl->fd);

    VIR_FREE(ctl);
}

/**
 * brAddBridge:
 * @ctl: bridge control pointer
 * @name: the bridge name
 *
 * This function register a new bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
# ifdef SIOCBRADDBR
int
brAddBridge(brControl *ctl,
            const char *name)
{
    if (!ctl || !ctl->fd || !name)
        return EINVAL;

    if (ioctl(ctl->fd, SIOCBRADDBR, name) == 0)
        return 0;

    return errno;
}
# else
int brAddBridge (brControl *ctl ATTRIBUTE_UNUSED,
                 const char *name ATTRIBUTE_UNUSED)
{
    return EINVAL;
}
# endif

# ifdef SIOCBRDELBR
int
brHasBridge(brControl *ctl,
            const char *name)
{
    struct ifreq ifr;

    if (!ctl || !name) {
        errno = EINVAL;
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));

    if (virStrcpyStatic(ifr.ifr_name, name) == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (ioctl(ctl->fd, SIOCGIFFLAGS, &ifr))
        return -1;

    return 0;
}
# else
int
brHasBridge(brControl *ctl ATTRIBUTE_UNUSED,
            const char *name ATTRIBUTE_UNUSED)
{
    return EINVAL;
}
# endif

/**
 * brDeleteBridge:
 * @ctl: bridge control pointer
 * @name: the bridge name
 *
 * Remove a bridge from the layer.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
# ifdef SIOCBRDELBR
int
brDeleteBridge(brControl *ctl,
               const char *name)
{
    if (!ctl || !ctl->fd || !name)
        return EINVAL;

    return ioctl(ctl->fd, SIOCBRDELBR, name) == 0 ? 0 : errno;
}
# else
int
brDeleteBridge(brControl *ctl ATTRIBUTE_UNUSED,
               const char *name ATTRIBUTE_UNUSED)
{
    return EINVAL;
}
# endif

# if defined(SIOCBRADDIF) && defined(SIOCBRDELIF)
static int
brAddDelInterface(brControl *ctl,
                  int cmd,
                  const char *bridge,
                  const char *iface)
{
    struct ifreq ifr;

    if (!ctl || !ctl->fd || !bridge || !iface)
        return EINVAL;

    memset(&ifr, 0, sizeof(struct ifreq));

    if (virStrcpyStatic(ifr.ifr_name, bridge) == NULL)
        return EINVAL;

    if (!(ifr.ifr_ifindex = if_nametoindex(iface)))
        return ENODEV;

    return ioctl(ctl->fd, cmd, &ifr) == 0 ? 0 : errno;
}
# endif

/**
 * brAddInterface:
 * @ctl: bridge control pointer
 * @bridge: the bridge name
 * @iface: the network interface name
 *
 * Adds an interface to a bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
# ifdef SIOCBRADDIF
int
brAddInterface(brControl *ctl,
               const char *bridge,
               const char *iface)
{
    return brAddDelInterface(ctl, SIOCBRADDIF, bridge, iface);
}
# else
int
brAddInterface(brControl *ctl ATTRIBUTE_UNUSED,
               const char *bridge ATTRIBUTE_UNUSED,
               const char *iface ATTRIBUTE_UNUSED)
{
    return EINVAL;
}
# endif

/**
 * brDeleteInterface:
 * @ctl: bridge control pointer
 * @bridge: the bridge name
 * @iface: the network interface name
 *
 * Removes an interface from a bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
# ifdef SIOCBRDELIF
int
brDeleteInterface(brControl *ctl,
                  const char *bridge,
                  const char *iface)
{
    return brAddDelInterface(ctl, SIOCBRDELIF, bridge, iface);
}
# else
int
brDeleteInterface(brControl *ctl ATTRIBUTE_UNUSED,
                  const char *bridge ATTRIBUTE_UNUSED,
                  const char *iface ATTRIBUTE_UNUSED)
{
    return EINVAL;
}
# endif

/**
 * ifSetInterfaceMac:
 * @ctl: bridge control pointer
 * @ifname: interface name to set MTU for
 * @macaddr: MAC address (VIR_MAC_BUFLEN in size)
 *
 * This function sets the @macaddr for a given interface @ifname. This
 * gets rid of the kernel's automatically assigned random MAC.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
static int ifSetInterfaceMac(brControl *ctl, const char *ifname,
                             const unsigned char *macaddr)
{
    struct ifreq ifr;

    if (!ctl || !ifname)
        return EINVAL;

    memset(&ifr, 0, sizeof(struct ifreq));
    if (virStrcpyStatic(ifr.ifr_name, ifname) == NULL)
        return EINVAL;

    /* To fill ifr.ifr_hdaddr.sa_family field */
    if (ioctl(ctl->fd, SIOCGIFHWADDR, &ifr) != 0)
        return errno;

    memcpy(ifr.ifr_hwaddr.sa_data, macaddr, VIR_MAC_BUFLEN);

    return ioctl(ctl->fd, SIOCSIFHWADDR, &ifr) == 0 ? 0 : errno;
}

/**
 * ifGetMtu
 * @ctl: bridge control pointer
 * @ifname: interface name get MTU for
 *
 * This function gets the @mtu value set for a given interface @ifname.
 *
 * Returns the MTU value in case of success.
 * On error, returns -1 and sets errno accordingly
 */
static int ifGetMtu(brControl *ctl, const char *ifname)
{
    struct ifreq ifr;

    if (!ctl || !ifname) {
        errno = EINVAL;
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));

    if (virStrcpyStatic(ifr.ifr_name, ifname) == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (ioctl(ctl->fd, SIOCGIFMTU, &ifr))
        return -1;

    return ifr.ifr_mtu;

}

/**
 * ifSetMtu:
 * @ctl: bridge control pointer
 * @ifname: interface name to set MTU for
 * @mtu: MTU value
 *
 * This function sets the @mtu for a given interface @ifname.  Typically
 * used on a tap device to set up for Jumbo Frames.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
static int ifSetMtu(brControl *ctl, const char *ifname, int mtu)
{
    struct ifreq ifr;

    if (!ctl || !ifname)
        return EINVAL;

    memset(&ifr, 0, sizeof(struct ifreq));

    if (virStrcpyStatic(ifr.ifr_name, ifname) == NULL)
        return EINVAL;
    ifr.ifr_mtu = mtu;

    return ioctl(ctl->fd, SIOCSIFMTU, &ifr) == 0 ? 0 : errno;
}

/**
 * brSetInterfaceMtu
 * @ctl: bridge control pointer
 * @bridge: name of the bridge interface
 * @ifname: name of the interface whose MTU we want to set
 *
 * Sets the interface mtu to the same MTU of the bridge
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
static int brSetInterfaceMtu(brControl *ctl,
                             const char *bridge,
                             const char *ifname)
{
    int mtu = ifGetMtu(ctl, bridge);

    if (mtu < 0)
        return errno;

    return ifSetMtu(ctl, ifname, mtu);
}

/**
 * brProbeVnetHdr:
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
 * Returns 0 in case of success or an errno code in case of failure.
 */
# ifdef IFF_VNET_HDR
static int
brProbeVnetHdr(int tapfd)
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
 * @ctl: bridge control pointer
 * @bridge: the bridge name
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
 * Returns 0 in case of success or an errno code in case of failure.
 */
int
brAddTap(brControl *ctl,
         const char *bridge,
         char **ifname,
         const unsigned char *macaddr,
         int vnet_hdr,
         bool up,
         int *tapfd)
{
    int fd;
    struct ifreq ifr;

    if (!ctl || !ctl->fd || !bridge || !ifname)
        return EINVAL;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
      return errno;

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TAP|IFF_NO_PI;

# ifdef IFF_VNET_HDR
    if (vnet_hdr && brProbeVnetHdr(fd))
        ifr.ifr_flags |= IFF_VNET_HDR;
# else
    (void) vnet_hdr;
# endif

    if (virStrcpyStatic(ifr.ifr_name, *ifname) == NULL) {
        errno = EINVAL;
        goto error;
    }

    if (ioctl(fd, TUNSETIFF, &ifr) < 0)
        goto error;

    /* We need to set the interface MAC before adding it
     * to the bridge, because the bridge assumes the lowest
     * MAC of all enslaved interfaces & we don't want it
     * seeing the kernel allocate random MAC for the TAP
     * device before we set our static MAC.
     */
    if ((errno = ifSetInterfaceMac(ctl, ifr.ifr_name, macaddr)))
        goto error;
    /* We need to set the interface MTU before adding it
     * to the bridge, because the bridge will have its
     * MTU adjusted automatically when we add the new interface.
     */
    if ((errno = brSetInterfaceMtu(ctl, bridge, ifr.ifr_name)))
        goto error;
    if ((errno = brAddInterface(ctl, bridge, ifr.ifr_name)))
        goto error;
    if (up && ((errno = brSetInterfaceUp(ctl, ifr.ifr_name, 1))))
        goto error;
    if (!tapfd &&
        (errno = ioctl(fd, TUNSETPERSIST, 1)))
        goto error;
    VIR_FREE(*ifname);
    if (!(*ifname = strdup(ifr.ifr_name)))
        goto error;
    if (tapfd)
        *tapfd = fd;
    else
        VIR_FORCE_CLOSE(fd);
    return 0;

 error:
    VIR_FORCE_CLOSE(fd);

    return errno;
}

int brDeleteTap(brControl *ctl,
                const char *ifname)
{
    struct ifreq try;
    int fd;

    if (!ctl || !ctl->fd || !ifname)
        return EINVAL;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
        return errno;

    memset(&try, 0, sizeof(struct ifreq));
    try.ifr_flags = IFF_TAP|IFF_NO_PI;

    if (virStrcpyStatic(try.ifr_name, ifname) == NULL) {
        errno = EINVAL;
        goto error;
    }

    if (ioctl(fd, TUNSETIFF, &try) == 0) {
        if ((errno = ioctl(fd, TUNSETPERSIST, 0)))
            goto error;
    }

 error:
    VIR_FORCE_CLOSE(fd);

    return errno;
}


/**
 * brSetInterfaceUp:
 * @ctl: bridge control pointer
 * @ifname: the interface name
 * @up: 1 for up, 0 for down
 *
 * Function to control if an interface is activated (up, 1) or not (down, 0)
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
int
brSetInterfaceUp(brControl *ctl,
                 const char *ifname,
                 int up)
{
    struct ifreq ifr;
    int flags;

    if (!ctl || !ifname)
        return EINVAL;

    memset(&ifr, 0, sizeof(struct ifreq));

    if (virStrcpyStatic(ifr.ifr_name, ifname) == NULL)
        return EINVAL;

    if (ioctl(ctl->fd, SIOCGIFFLAGS, &ifr) < 0)
        return errno;

    flags = up ? (ifr.ifr_flags | IFF_UP) : (ifr.ifr_flags & ~IFF_UP);

    if (ifr.ifr_flags != flags) {
        ifr.ifr_flags = flags;

        if (ioctl(ctl->fd, SIOCSIFFLAGS, &ifr) < 0)
            return errno;
    }

    return 0;
}

/**
 * brGetInterfaceUp:
 * @ctl: bridge control pointer
 * @ifname: the interface name
 * @up: where to store the status
 *
 * Function to query if an interface is activated (1) or not (0)
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
int
brGetInterfaceUp(brControl *ctl,
                 const char *ifname,
                 int *up)
{
    struct ifreq ifr;

    if (!ctl || !ifname || !up)
        return EINVAL;

    memset(&ifr, 0, sizeof(struct ifreq));

    if (virStrcpyStatic(ifr.ifr_name, ifname) == NULL)
        return EINVAL;

    if (ioctl(ctl->fd, SIOCGIFFLAGS, &ifr) < 0)
        return errno;

    *up = (ifr.ifr_flags & IFF_UP) ? 1 : 0;

    return 0;
}

/**
 * brAddInetAddress:
 * @ctl: bridge control pointer
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

int
brAddInetAddress(brControl *ctl ATTRIBUTE_UNUSED,
                 const char *ifname,
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
 * brDelInetAddress:
 * @ctl: bridge control pointer
 * @ifname: the interface name
 * @addr: the IP address (IPv4 or IPv6)
 * @prefix: number of 1 bits in the netmask
 *
 * Delete an IP address from an interface.
 *
 * Returns 0 in case of success or -1 in case of error.
 */

int
brDelInetAddress(brControl *ctl ATTRIBUTE_UNUSED,
                 const char *ifname,
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
 * brSetForwardDelay:
 * @ctl: bridge control pointer
 * @bridge: the bridge name
 * @delay: delay in seconds
 *
 * Set the bridge forward delay
 *
 * Returns 0 in case of success or -1 on failure
 */

int
brSetForwardDelay(brControl *ctl ATTRIBUTE_UNUSED,
                  const char *bridge,
                  int delay)
{
    virCommandPtr cmd;
    int ret = -1;

    cmd = virCommandNew(BRCTL);
    virCommandAddArgList(cmd, "setfd", bridge, NULL);
    virCommandAddArgFormat(cmd, "%d", delay);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    virCommandFree(cmd);
    return ret;
}

/**
 * brSetEnableSTP:
 * @ctl: bridge control pointer
 * @bridge: the bridge name
 * @enable: 1 to enable, 0 to disable
 *
 * Control whether the bridge participates in the spanning tree protocol,
 * in general don't disable it without good reasons.
 *
 * Returns 0 in case of success or -1 on failure
 */
int
brSetEnableSTP(brControl *ctl ATTRIBUTE_UNUSED,
               const char *bridge,
               int enable)
{
    virCommandPtr cmd;
    int ret = -1;

    cmd = virCommandNew(BRCTL);
    virCommandAddArgList(cmd, "stp", bridge,
                         enable ? "on" : "off",
                         NULL);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    virCommandFree(cmd);
    return ret;
}

#endif /* WITH_BRIDGE */
