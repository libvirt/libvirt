/*
 * Copyright (C) 2007-2012 Red Hat, Inc.
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
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virmacaddr.h"
#include "virnetdevtap.h"
#include "virnetdev.h"
#include "virnetdevbridge.h"
#include "virnetdevopenvswitch.h"
#include "virterror_internal.h"
#include "virfile.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"
#include "util.h"

#include <sys/ioctl.h>
#ifdef HAVE_NET_IF_H
# include <net/if.h>
#endif
#include <fcntl.h>
#ifdef __linux__
# include <linux/if_tun.h>    /* IFF_TUN, IFF_NO_PI */
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

#define virNetDevTapError(code, ...)                    \
    virReportErrorHelper(VIR_FROM_NONE, code, __FILE__, \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

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
#ifdef IFF_VNET_HDR
static int
virNetDevProbeVnetHdr(int tapfd)
{
# if defined(IFF_VNET_HDR) && defined(TUNGETFEATURES) && defined(TUNGETIFF)
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
# else
    (void) tapfd;
    VIR_INFO("Not enabling IFF_VNET_HDR; disabled at build time");
    return 0;
# endif
}
#endif


#ifdef TUNSETIFF
/**
 * virNetDevTapCreate:
 * @ifname: the interface name
 * @tapfd: file descriptor return value for the new tap device
 * @flags: OR of virNetDevTapCreateFlags. Only one flag is recognized:
 *
 *   VIR_NETDEV_TAP_CREATE_VNET_HDR
 *     - Enable IFF_VNET_HDR on the tap device
 *
 * Creates a tap interface.
 * If the @tapfd parameter is supplied, the open tap device file
 * descriptor will be returned, otherwise the TAP device will be made
 * persistent and closed. The caller must use virNetDevTapDelete to
 * remove a persistent TAP devices when it is no longer needed.
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
int virNetDevTapCreate(char **ifname,
                       int *tapfd,
                       unsigned int flags ATTRIBUTE_UNUSED)
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
    if ((flags &  VIR_NETDEV_TAP_CREATE_VNET_HDR) &&
        virNetDevProbeVnetHdr(fd))
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
#else /* ! TUNSETIFF */
int virNetDevTapCreate(char **ifname ATTRIBUTE_UNUSED,
                       int *tapfd ATTRIBUTE_UNUSED,
                       unsigned int flags ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to create TAP devices on this platform"));
    return -1;
}
int virNetDevTapDelete(const char *ifname ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to delete TAP devices on this platform"));
    return -1;
}
#endif /* ! TUNSETIFF */


/**
 * virNetDevTapCreateInBridgePort:
 * @brname: the bridge name
 * @ifname: the interface name (or name template)
 * @macaddr: desired MAC address (VIR_MAC_BUFLEN long)
 * @tapfd: file descriptor return value for the new tap device
 * @virtPortProfile: bridge/port specific configuration
 * @flags: OR of virNetDevTapCreateFlags:

 *   VIR_NETDEV_TAP_CREATE_IFUP
 *     - Bring the interface up
 *   VIR_NETDEV_TAP_CREATE_VNET_HDR
 *     - Enable IFF_VNET_HDR on the tap device
 *   VIR_NETDEV_TAP_CREATE_USE_MAC_FOR_BRIDGE
 *     - Set this interface's MAC as the bridge's MAC address
 *
 * This function creates a new tap device on a bridge. @ifname can be either
 * a fixed name or a name template with '%d' for dynamic name allocation.
 * in either case the final name for the bridge will be stored in @ifname.
 * If the @tapfd parameter is supplied, the open tap device file
 * descriptor will be returned, otherwise the TAP device will be made
 * persistent and closed. The caller must use virNetDevTapDelete to remove
 * a persistent TAP devices when it is no longer needed.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevTapCreateInBridgePort(const char *brname,
                                   char **ifname,
                                   const unsigned char *macaddr,
                                   const unsigned char *vmuuid,
                                   int *tapfd,
                                   virNetDevVPortProfilePtr virtPortProfile,
                                   unsigned int flags)
{
    unsigned char tapmac[VIR_MAC_BUFLEN];

    if (virNetDevTapCreate(ifname, tapfd, flags) < 0)
        return -1;

    /* We need to set the interface MAC before adding it
     * to the bridge, because the bridge assumes the lowest
     * MAC of all enslaved interfaces & we don't want it
     * seeing the kernel allocate random MAC for the TAP
     * device before we set our static MAC.
     */
    memcpy(tapmac, macaddr, VIR_MAC_BUFLEN);
    if (!(flags & VIR_NETDEV_TAP_CREATE_USE_MAC_FOR_BRIDGE)) {
        if (macaddr[0] == 0xFE) {
            /* For normal use, the tap device's MAC address cannot
             * match the MAC address used by the guest. This results
             * in "received packet on vnetX with own address as source
             * address" error logs from the kernel.
             */
            virNetDevTapError(VIR_ERR_CONFIG_UNSUPPORTED,
                              "Unable to use MAC address starting with "
                              "reserved value 0xFE - '%02X:%02X:%02X:%02X:%02X:%02X' - ",
                              macaddr[0], macaddr[1], macaddr[2],
                              macaddr[3], macaddr[4], macaddr[5]);
            goto error;
        }
        tapmac[0] = 0xFE; /* Discourage bridge from using TAP dev MAC */
    }

    if (virNetDevSetMAC(*ifname, tapmac) < 0)
        goto error;

    /* We need to set the interface MTU before adding it
     * to the bridge, because the bridge will have its
     * MTU adjusted automatically when we add the new interface.
     */
    if (virNetDevSetMTUFromDevice(*ifname, brname) < 0)
        goto error;

    if (virtPortProfile) {
        if (virNetDevOpenvswitchAddPort(brname, *ifname, macaddr, vmuuid,
                                        virtPortProfile) < 0) {
            goto error;
        }
    } else {
        if (virNetDevBridgeAddPort(brname, *ifname) < 0)
            goto error;
    }

    if (virNetDevSetOnline(*ifname, !!(flags & VIR_NETDEV_TAP_CREATE_IFUP)) < 0)
        goto error;

    return 0;

 error:
    VIR_FORCE_CLOSE(*tapfd);

    return errno;
}
