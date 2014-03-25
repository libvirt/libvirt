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
 *
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virnetdev.h"
#include "virmacaddr.h"
#include "virfile.h"
#include "virerror.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virpci.h"
#include "virlog.h"
#include "virstring.h"
#include "virutil.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>

#ifdef __linux__
# include <linux/sockios.h>
# include <linux/if_vlan.h>
# define VIR_NETDEV_FAMILY AF_PACKET
#elif defined(HAVE_STRUCT_IFREQ) && defined(AF_LOCAL)
# define VIR_NETDEV_FAMILY AF_LOCAL
#else
# undef HAVE_STRUCT_IFREQ
#endif

#if HAVE_DECL_LINK_ADDR
# include <sys/sockio.h>
# include <net/if_dl.h>
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.netdev");

#if defined(HAVE_STRUCT_IFREQ)
static int virNetDevSetupControlFull(const char *ifname,
                                     struct ifreq *ifr,
                                     int domain,
                                     int type)
{
    int fd;

    if (ifr && ifname) {
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


int
virNetDevSetupControl(const char *ifname,
                      struct ifreq *ifr)
{
    return virNetDevSetupControlFull(ifname, ifr, VIR_NETDEV_FAMILY, SOCK_DGRAM);
}
#else /* !HAVE_STRUCT_IFREQ */
int
virNetDevSetupControl(const char *ifname ATTRIBUTE_UNUSED,
                      void *ifr ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Network device configuration is not supported "
                           "on this platform"));
    return -1;
}
#endif /* HAVE_STRUCT_IFREQ */


#if defined(SIOCGIFFLAGS) && defined(HAVE_STRUCT_IFREQ)
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
        if (errno == ENODEV || errno == ENXIO)
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
#else
int virNetDevExists(const char *ifname)
{
    virReportSystemError(ENOSYS,
                         _("Unable to check interface %s"), ifname);
    return -1;
}
#endif


#if defined(SIOCGIFHWADDR) && defined(SIOCSIFHWADDR) && \
    defined(HAVE_STRUCT_IFREQ)
/**
 * virNetDevSetMAC:
 * @ifname: interface name to set MTU for
 * @macaddr: MAC address
 *
 * This function sets the @macaddr for a given interface @ifname. This
 * gets rid of the kernel's automatically assigned random MAC.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevSetMAC(const char *ifname,
                    const virMacAddr *macaddr)
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

    virMacAddrGetRaw(macaddr, (unsigned char *)ifr.ifr_hwaddr.sa_data);

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
#elif defined(SIOCSIFLLADDR) && defined(HAVE_STRUCT_IFREQ) && \
    HAVE_DECL_LINK_ADDR
int virNetDevSetMAC(const char *ifname,
                    const virMacAddr *macaddr)
{
        struct ifreq ifr;
        struct sockaddr_dl sdl;
        char mac[VIR_MAC_STRING_BUFLEN + 1] = ":";
        int s;
        int ret = -1;

        if ((s = virNetDevSetupControl(ifname, &ifr)) < 0)
            return -1;

        virMacAddrFormat(macaddr, mac + 1);
        sdl.sdl_len = sizeof(sdl);
        link_addr(mac, &sdl);

        memcpy(ifr.ifr_addr.sa_data, sdl.sdl_data, VIR_MAC_BUFLEN);
        ifr.ifr_addr.sa_len = VIR_MAC_BUFLEN;

        if (ioctl(s, SIOCSIFLLADDR, &ifr) < 0) {
            virReportSystemError(errno,
                                 _("Cannot set interface MAC on '%s'"),
                                 ifname);
            goto cleanup;
        }

        ret = 0;
 cleanup:
        VIR_FORCE_CLOSE(s);

        return ret;
}
#else
int virNetDevSetMAC(const char *ifname,
                    const virMacAddr *macaddr ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot set interface MAC on '%s'"),
                         ifname);
    return -1;
}
#endif


#if defined(SIOCGIFHWADDR) && defined(HAVE_STRUCT_IFREQ)
/**
 * virNetDevGetMAC:
 * @ifname: interface name to set MTU for
 * @macaddr: MAC address
 *
 * This function gets the @macaddr for a given interface @ifname.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevGetMAC(const char *ifname,
                    virMacAddrPtr macaddr)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot get interface MAC on '%s'"),
                             ifname);
        goto cleanup;
    }

    virMacAddrSetRaw(macaddr, (unsigned char *)ifr.ifr_hwaddr.sa_data);

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#else
int virNetDevGetMAC(const char *ifname,
                    virMacAddrPtr macaddr ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot get interface MAC on '%s'"),
                         ifname);
    return -1;
}
#endif



/**
 * virNetDevReplaceMacAddress:
 * @macaddress: new MAC address for interface
 * @linkdev: name of interface
 * @stateDir: directory to store old MAC address
 *
 * Returns 0 on success, -1 on failure
 *
 */
int
virNetDevReplaceMacAddress(const char *linkdev,
                           const virMacAddr *macaddress,
                           const char *stateDir)
{
    virMacAddr oldmac;
    char *path = NULL;
    char macstr[VIR_MAC_STRING_BUFLEN];

    if (virNetDevGetMAC(linkdev, &oldmac) < 0)
        return -1;


    if (virAsprintf(&path, "%s/%s",
                    stateDir,
                    linkdev) < 0)
        return -1;
    virMacAddrFormat(&oldmac, macstr);
    if (virFileWriteStr(path, macstr, O_CREAT|O_TRUNC|O_WRONLY) < 0) {
        virReportSystemError(errno, _("Unable to preserve mac for %s"),
                             linkdev);
        return -1;
    }

    if (virNetDevSetMAC(linkdev, macaddress) < 0)
        return -1;

    return 0;
}

/**
 * virNetDevRestoreMacAddress:
 * @linkdev: name of interface
 * @stateDir: directory containing old MAC address
 *
 * Returns 0 on success, -errno on failure.
 *
 */
int
virNetDevRestoreMacAddress(const char *linkdev,
                           const char *stateDir)
{
    int rc;
    char *oldmacname = NULL;
    char *macstr = NULL;
    char *path = NULL;
    virMacAddr oldmac;

    if (virAsprintf(&path, "%s/%s",
                    stateDir,
                    linkdev) < 0)
        return -1;

    if (virFileReadAll(path, VIR_MAC_STRING_BUFLEN, &macstr) < 0)
        return -1;

    if (virMacAddrParse(macstr, &oldmac) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse MAC address from '%s'"),
                       oldmacname);
        VIR_FREE(macstr);
        return -1;
    }

    /*reset mac and remove file-ignore results*/
    rc = virNetDevSetMAC(linkdev, &oldmac);
    ignore_value(unlink(path));
    VIR_FREE(macstr);

    return rc;
}


#if defined(SIOCGIFMTU) && defined(HAVE_STRUCT_IFREQ)
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
#else
int virNetDevGetMTU(const char *ifname)
{
    virReportSystemError(ENOSYS,
                         _("Cannot get interface MTU on '%s'"),
                         ifname);
    return -1;
}
#endif


#if defined(SIOCSIFMTU) && defined(HAVE_STRUCT_IFREQ)
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
#else
int virNetDevSetMTU(const char *ifname, int mtu ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot set interface MTU on '%s'"),
                         ifname);
    return -1;
}
#endif


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
 * virNetDevSetNamespace:
 * @ifname: name of device
 * @pidInNs: PID of process in target net namespace
 *
 * Moves the given device into the target net namespace specified by the given
 * pid using this command:
 *     ip link set @iface netns @pidInNs
 *
 * Returns 0 on success or -1 in case of error
 */
int virNetDevSetNamespace(const char *ifname, pid_t pidInNs)
{
    int rc;
    char *pid = NULL;
    const char *argv[] = {
        "ip", "link", "set", ifname, "netns", NULL, NULL
    };

    if (virAsprintf(&pid, "%lld", (long long) pidInNs) == -1)
        return -1;

    argv[5] = pid;
    rc = virRun(argv, NULL);

    VIR_FREE(pid);
    return rc;
}

#if defined(SIOCSIFNAME) && defined(HAVE_STRUCT_IFREQ)
/**
 * virNetDevSetName:
 * @ifname: name of device
 * @newifname: new name of @ifname
 *
 * Changes the name of the given device.
 *
 * Returns 0 on success, -1 on error
 */
int virNetDevSetName(const char* ifname, const char *newifname)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

# ifdef HAVE_STRUCT_IFREQ_IFR_NEWNAME
    if (virStrcpyStatic(ifr.ifr_newname, newifname) == NULL) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%s' is too long"),
                             newifname);
        goto cleanup;
    }
# else
    ifr.ifr_data = (caddr_t)newifname;
# endif

    if (ioctl(fd, SIOCSIFNAME, &ifr)) {
        virReportSystemError(errno,
                             _("Unable to rename '%s' to '%s'"),
                             ifname, newifname);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#else
int virNetDevSetName(const char* ifname, const char *newifname)
{
    virReportSystemError(ENOSYS,
                         _("Cannot rename interface '%s' to '%s' on this platform"),
                         ifname, newifname);
    return -1;
}
#endif


#if defined(SIOCSIFFLAGS) && defined(HAVE_STRUCT_IFREQ)
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
#else
int virNetDevSetOnline(const char *ifname,
                       bool online ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot set interface flags on '%s'"),
                         ifname);
    return -1;
}
#endif


#if defined(SIOCGIFFLAGS) && defined(HAVE_STRUCT_IFREQ)
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
#else
int virNetDevIsOnline(const char *ifname,
                      bool *online ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot get interface flags on '%s'"),
                         ifname);
    return -1;
}
#endif


/**
 * virNetDevGetIndex:
 * @ifname : Name of the interface whose index is to be found
 * @ifindex: Pointer to int where the index will be written into
 *
 * Get the index of an interface given its name.
 *
 * Returns 0 on success, -1 on failure
 */
#if defined(SIOCGIFINDEX) && defined(HAVE_STRUCT_IFREQ)
int virNetDevGetIndex(const char *ifname, int *ifindex)
{
    int ret = -1;
    struct ifreq ifreq;
    int fd = socket(VIR_NETDEV_FAMILY, SOCK_DGRAM, 0);

    if (fd < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to open control socket"));
        return -1;
    }

    memset(&ifreq, 0, sizeof(ifreq));

    if (virStrncpy(ifreq.ifr_name, ifname, strlen(ifname),
                   sizeof(ifreq.ifr_name)) == NULL) {
        virReportSystemError(ERANGE,
                             _("invalid interface name %s"),
                             ifname);
        goto cleanup;
    }

    if (ioctl(fd, SIOCGIFINDEX, &ifreq) < 0) {
        virReportSystemError(errno,
                             _("Unable to get index for interface %s"), ifname);
        goto cleanup;
    }

# ifdef HAVE_STRUCT_IFREQ_IFR_INDEX
    *ifindex = ifreq.ifr_index;
# else
    *ifindex = ifreq.ifr_ifindex;
# endif
    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#else /* ! SIOCGIFINDEX */
int virNetDevGetIndex(const char *ifname ATTRIBUTE_UNUSED,
                      int *ifindex ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get interface index on this platform"));
    return -1;
}
#endif /* ! SIOCGIFINDEX */


#if defined(SIOCGIFVLAN) && defined(HAVE_STRUCT_IFREQ) && HAVE_DECL_GET_VLAN_VID_CMD
int virNetDevGetVLanID(const char *ifname, int *vlanid)
{
    struct vlan_ioctl_args vlanargs = {
      .cmd = GET_VLAN_VID_CMD,
    };
    int ret = -1;
    int fd = socket(PF_PACKET, SOCK_DGRAM, 0);

    if (fd < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to open control socket"));
        return -1;
    }

    if (virStrcpyStatic(vlanargs.device1, ifname) == NULL) {
        virReportSystemError(ERANGE,
                             _("invalid interface name %s"),
                             ifname);
        goto cleanup;
    }

    if (ioctl(fd, SIOCGIFVLAN, &vlanargs) != 0) {
        virReportSystemError(errno,
                             _("Unable to get VLAN for interface %s"), ifname);
        goto cleanup;
    }

    *vlanid = vlanargs.u.VID;
    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);

    return ret;
}
#else /* ! SIOCGIFVLAN */
int virNetDevGetVLanID(const char *ifname ATTRIBUTE_UNUSED,
                       int *vlanid ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get VLAN on this platform"));
    return -1;
}
#endif /* ! SIOCGIFVLAN */



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

    if (!(addrstr = virSocketAddrFormat(addr)))
        goto cleanup;
    /* format up a broadcast address if this is IPv4 */
    if ((VIR_SOCKET_ADDR_IS_FAMILY(addr, AF_INET)) &&
        ((virSocketAddrBroadcastByPrefix(addr, prefix, &broadcast) < 0) ||
         !(bcaststr = virSocketAddrFormat(&broadcast)))) {
        goto cleanup;
    }
#ifdef IFCONFIG_PATH
    cmd = virCommandNew(IFCONFIG_PATH);
    virCommandAddArg(cmd, ifname);
    if (VIR_SOCKET_ADDR_IS_FAMILY(addr, AF_INET6))
        virCommandAddArg(cmd, "inet6");
    else
        virCommandAddArg(cmd, "inet");
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    if (bcaststr)
        virCommandAddArgList(cmd, "broadcast", bcaststr, NULL);
    virCommandAddArg(cmd, "alias");
#else
    cmd = virCommandNew(IP_PATH);
    virCommandAddArgList(cmd, "addr", "add", NULL);
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    if (bcaststr)
        virCommandAddArgList(cmd, "broadcast", bcaststr, NULL);
    virCommandAddArgList(cmd, "dev", ifname, NULL);
#endif

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
 * virNetDevAddRoute:
 * @ifname: the interface name
 * @addr: the IP network address (IPv4 or IPv6)
 * @prefix: number of 1 bits in the netmask
 * @gateway: via address for route (same as @addr)
 *
 * Add a route for a network IP address to an interface. This function
 * *does not* remove any previously added IP static routes.
 *
 * Returns 0 in case of success or -1 in case of error.
 */

int
virNetDevAddRoute(const char *ifname,
                  virSocketAddrPtr addr,
                  unsigned int prefix,
                  virSocketAddrPtr gateway,
                  unsigned int metric)
{
    virCommandPtr cmd = NULL;
    char *addrstr = NULL, *gatewaystr = NULL;
    int ret = -1;

    if (!(addrstr = virSocketAddrFormat(addr)))
        goto cleanup;
    if (!(gatewaystr = virSocketAddrFormat(gateway)))
        goto cleanup;
    cmd = virCommandNew(IP_PATH);
    virCommandAddArgList(cmd, "route", "add", NULL);
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    virCommandAddArgList(cmd, "via", gatewaystr, "dev", ifname,
                              "proto", "static", "metric", NULL);
    virCommandAddArgFormat(cmd, "%u", metric);

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(addrstr);
    VIR_FREE(gatewaystr);
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

    if (!(addrstr = virSocketAddrFormat(addr)))
        goto cleanup;
#ifdef IFCONFIG_PATH
    cmd = virCommandNew(IFCONFIG_PATH);
    virCommandAddArg(cmd, ifname);
    if (VIR_SOCKET_ADDR_IS_FAMILY(addr, AF_INET6))
        virCommandAddArg(cmd, "inet6");
    else
        virCommandAddArg(cmd, "inet");
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    virCommandAddArg(cmd, "-alias");
#else
    cmd = virCommandNew(IP_PATH);
    virCommandAddArgList(cmd, "addr", "del", NULL);
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    virCommandAddArgList(cmd, "dev", ifname, NULL);
#endif

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(addrstr);
    virCommandFree(cmd);
    return ret;
}


/**
 * virNetDevGetIPv4Address:
 * @ifname: name of the interface whose IP address we want
 * @addr: filled with the IPv4 address
 *
 * This function gets the IPv4 address for the interface @ifname
 * and stores it in @addr
 *
 * Returns 0 on success, -errno on failure.
 */
#if defined(SIOCGIFADDR) && defined(HAVE_STRUCT_IFREQ)
int virNetDevGetIPv4Address(const char *ifname,
                            virSocketAddrPtr addr)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    memset(addr, 0, sizeof(*addr));
    addr->data.stor.ss_family = AF_UNSPEC;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFADDR, (char *)&ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to get IPv4 address for interface %s"), ifname);
        goto cleanup;
    }

    addr->data.stor.ss_family = AF_INET;
    addr->len = sizeof(addr->data.inet4);
    memcpy(&addr->data.inet4, &ifr.ifr_addr, addr->len);
    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

#else /* ! SIOCGIFADDR */

int virNetDevGetIPv4Address(const char *ifname ATTRIBUTE_UNUSED,
                            virSocketAddrPtr addr ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get IPv4 address on this platform"));
    return -1;
}

#endif /* ! SIOCGIFADDR */


/**
 * virNetDevValidateConfig:
 * @ifname: Name of the interface
 * @macaddr: expected MAC address of the interface; not checked if NULL
 * @ifindex: expected index of the interface; not checked if '-1'
 *
 * Determine whether a given interface is still available. If so,
 * it must have the given MAC address and if an interface index is
 * passed, it must also match the interface index.
 *
 * Returns 1 if the config matches, 0 if the config does not match, or interface does not exist, -1 on error
 */
#if defined(SIOCGIFHWADDR) && defined(HAVE_STRUCT_IFREQ)
int virNetDevValidateConfig(const char *ifname,
                            const virMacAddr *macaddr, int ifindex)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;
    int idx;
    int rc;

    if ((rc = virNetDevExists(ifname)) < 0)
        return -1;
    if (rc == 0) {
        ret = 0;
        goto cleanup;
    }

    if (macaddr != NULL) {
        if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
            return -1;

        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            if (errno == ENODEV) {
                ret = 0;
                goto cleanup;
            }
            virReportSystemError(errno,
                                 _("could not get MAC address of interface %s"),
                                 ifname);
            goto cleanup;
        }

        if (virMacAddrCmpRaw(macaddr,
                             (unsigned char *)ifr.ifr_hwaddr.sa_data) != 0) {
            ret = 0;
            goto cleanup;
        }
    }

    if (ifindex != -1) {
        if (virNetDevGetIndex(ifname, &idx) < 0)
            goto cleanup;
        else if (idx != ifindex) {
            ret = 0;
            goto cleanup;
        }
    }

    ret = 1;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#else
int virNetDevValidateConfig(const char *ifname ATTRIBUTE_UNUSED,
                            const virMacAddr *macaddr ATTRIBUTE_UNUSED,
                            int ifindex ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to check interface config on this platform"));
    return -1;
}
#endif


#ifdef __linux__
# define NET_SYSFS "/sys/class/net/"

static int
virNetDevSysfsFile(char **pf_sysfs_device_link, const char *ifname,
               const char *file)
{

    if (virAsprintf(pf_sysfs_device_link, NET_SYSFS "%s/%s", ifname, file) < 0)
        return -1;
    return 0;
}

static int
virNetDevSysfsDeviceFile(char **pf_sysfs_device_link, const char *ifname,
                     const char *file)
{

    if (virAsprintf(pf_sysfs_device_link, NET_SYSFS "%s/device/%s", ifname,
                    file) < 0)
        return -1;
    return 0;
}

/**
 * virNetDevGetVirtualFunctions:
 *
 * @pfname : name of the physical function interface name
 * @vfname: array that will hold the interface names of the virtual_functions
 * @n_vfname: pointer to the number of virtual functions
 *
 * Returns 0 on success and -1 on failure
 */

int
virNetDevGetVirtualFunctions(const char *pfname,
                             char ***vfname,
                             virPCIDeviceAddressPtr **virt_fns,
                             size_t *n_vfname)
{
    int ret = -1;
    size_t i;
    char *pf_sysfs_device_link = NULL;
    char *pci_sysfs_device_link = NULL;
    char *pciConfigAddr = NULL;

    *virt_fns = NULL;
    *n_vfname = 0;

    if (virNetDevSysfsFile(&pf_sysfs_device_link, pfname, "device") < 0)
        return ret;

    if (virPCIGetVirtualFunctions(pf_sysfs_device_link, virt_fns,
                                  n_vfname) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(*vfname, *n_vfname) < 0)
        goto cleanup;

    for (i = 0; i < *n_vfname; i++)
    {
        if (virPCIGetAddrString((*virt_fns)[i]->domain,
                                (*virt_fns)[i]->bus,
                                (*virt_fns)[i]->slot,
                                (*virt_fns)[i]->function,
                                &pciConfigAddr) < 0) {
            virReportSystemError(ENOSYS, "%s",
                                 _("Failed to get PCI Config Address String"));
            goto cleanup;
        }
        if (virPCIGetSysfsFile(pciConfigAddr, &pci_sysfs_device_link) < 0) {
            virReportSystemError(ENOSYS, "%s",
                                 _("Failed to get PCI SYSFS file"));
            goto cleanup;
        }

        if (virPCIGetNetName(pci_sysfs_device_link, &((*vfname)[i])) < 0) {
            VIR_INFO("VF does not have an interface name");
        }
    }

    ret = 0;

 cleanup:
    if (ret < 0) {
        VIR_FREE(*vfname);
        VIR_FREE(*virt_fns);
    }
    VIR_FREE(pf_sysfs_device_link);
    VIR_FREE(pci_sysfs_device_link);
    VIR_FREE(pciConfigAddr);
    return ret;
}

/**
 * virNetDevIsVirtualFunction:
 * @ifname : name of the interface
 *
 * Checks if an interface is a SRIOV virtual function.
 *
 * Returns 1 if interface is SRIOV virtual function, 0 if not and -1 if error
 *
 */
int
virNetDevIsVirtualFunction(const char *ifname)
{
    char *if_sysfs_device_link = NULL;
    int ret = -1;

    if (virNetDevSysfsFile(&if_sysfs_device_link, ifname, "device") < 0)
        return ret;

    ret = virPCIIsVirtualFunction(if_sysfs_device_link);

    VIR_FREE(if_sysfs_device_link);

    return ret;
}

/**
 * virNetDevGetVirtualFunctionIndex
 *
 * @pfname : name of the physical function interface name
 * @vfname : name of the virtual function interface name
 * @vf_index : Pointer to int. Contains vf index of interface upon successful
 *             return
 *
 * Returns 0 on success, -1 on failure
 *
 */
int
virNetDevGetVirtualFunctionIndex(const char *pfname, const char *vfname,
                                 int *vf_index)
{
    char *pf_sysfs_device_link = NULL, *vf_sysfs_device_link = NULL;
    int ret = -1;

    if (virNetDevSysfsFile(&pf_sysfs_device_link, pfname, "device") < 0)
        return ret;

    if (virNetDevSysfsFile(&vf_sysfs_device_link, vfname, "device") < 0) {
        VIR_FREE(pf_sysfs_device_link);
        return ret;
    }

    ret = virPCIGetVirtualFunctionIndex(pf_sysfs_device_link,
                                        vf_sysfs_device_link,
                                        vf_index);

    VIR_FREE(pf_sysfs_device_link);
    VIR_FREE(vf_sysfs_device_link);

    return ret;
}

/**
 * virNetDevGetPhysicalFunction
 *
 * @ifname : name of the physical function interface name
 * @pfname : Contains sriov physical function for interface ifname
 *           upon successful return
 *
 * Returns 0 on success, -1 on failure
 *
 */
int
virNetDevGetPhysicalFunction(const char *ifname, char **pfname)
{
    char *physfn_sysfs_path = NULL;
    int ret = -1;

    if (virNetDevSysfsDeviceFile(&physfn_sysfs_path, ifname, "physfn") < 0)
        return ret;

    ret = virPCIGetNetName(physfn_sysfs_path, pfname);

    VIR_FREE(physfn_sysfs_path);

    return ret;
}

/**
 * virNetDevGetVirtualFunctionInfo:
 * @vfname: name of the virtual function interface
 * @pfname: name of the physical function
 * @vf: vf index
 *
 * Returns 0 on success, -errno on failure.
 *
 */
int
virNetDevGetVirtualFunctionInfo(const char *vfname, char **pfname,
                                int *vf)
{
    char *pf_sysfs_path = NULL, *vf_sysfs_path = NULL;
    int ret = -1;

    *pfname = NULL;

    if (virNetDevGetPhysicalFunction(vfname, pfname) < 0)
        return ret;

    if (virNetDevSysfsFile(&pf_sysfs_path, *pfname, "device") < 0)
        goto cleanup;

    if (virNetDevSysfsFile(&vf_sysfs_path, vfname, "device") < 0)
        goto cleanup;

    ret = virPCIGetVirtualFunctionIndex(pf_sysfs_path, vf_sysfs_path, vf);

 cleanup:
    if (ret < 0)
        VIR_FREE(*pfname);

    VIR_FREE(vf_sysfs_path);
    VIR_FREE(pf_sysfs_path);

    return ret;
}

#else /* !__linux__ */
int
virNetDevGetVirtualFunctions(const char *pfname ATTRIBUTE_UNUSED,
                             char ***vfname ATTRIBUTE_UNUSED,
                             virPCIDeviceAddressPtr **virt_fns ATTRIBUTE_UNUSED,
                             size_t *n_vfname ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get virtual functions on this platform"));
    return -1;
}

int
virNetDevIsVirtualFunction(const char *ifname ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to check virtual function status on this platform"));
    return -1;
}

int
virNetDevGetVirtualFunctionIndex(const char *pfname ATTRIBUTE_UNUSED,
                             const char *vfname ATTRIBUTE_UNUSED,
                             int *vf_index ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get virtual function index on this platform"));
    return -1;
}

int
virNetDevGetPhysicalFunction(const char *ifname ATTRIBUTE_UNUSED,
                             char **pfname ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get physical function status on this platform"));
    return -1;
}

int
virNetDevGetVirtualFunctionInfo(const char *vfname ATTRIBUTE_UNUSED,
                                char **pfname ATTRIBUTE_UNUSED,
                                int *vf ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get virtual function info on this platform"));
    return -1;
}
#endif /* !__linux__ */
#if defined(__linux__) && defined(HAVE_LIBNL) && defined(IFLA_VF_MAX)

static struct nla_policy ifla_vf_policy[IFLA_VF_MAX+1] = {
    [IFLA_VF_MAC]       = { .type = NLA_UNSPEC,
                            .maxlen = sizeof(struct ifla_vf_mac) },
    [IFLA_VF_VLAN]      = { .type = NLA_UNSPEC,
                            .maxlen = sizeof(struct ifla_vf_vlan) },
};

/**
 * virNetDevLinkDump:
 *
 * @ifname: The name of the interface; only use if ifindex < 0
 * @ifindex: The interface index; may be < 0 if ifname is given
 * @nlattr: pointer to a pointer of netlink attributes that will contain
 *          the results
 * @src_pid: pid used for nl_pid of the local end of the netlink message
 *           (0 == "use getpid()")
 * @dst_pid: pid of destination nl_pid if the kernel
 *           is not the target of the netlink message but it is to be
 *           sent to another process (0 if sending to the kernel)
 *
 * Get information about an interface given its name or index.
 *
 * Returns 0 on success, -1 on fatal error.
 */
int
virNetDevLinkDump(const char *ifname, int ifindex,
                  struct nlattr **tb,
                  uint32_t src_pid, uint32_t dst_pid)
{
    int rc = -1;
    struct nlmsghdr *resp = NULL;
    struct nlmsgerr *err;
    struct ifinfomsg ifinfo = {
        .ifi_family = AF_UNSPEC,
        .ifi_index  = ifindex
    };
    unsigned int recvbuflen;
    struct nl_msg *nl_msg;

    if (ifname && ifindex <= 0 && virNetDevGetIndex(ifname, &ifindex) < 0)
        return -1;

    ifinfo.ifi_index = ifindex;

    nl_msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST);
    if (!nl_msg) {
        virReportOOMError();
        return -1;
    }

    if (nlmsg_append(nl_msg,  &ifinfo, sizeof(ifinfo), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;

    if (ifname) {
        if (nla_put(nl_msg, IFLA_IFNAME, strlen(ifname)+1, ifname) < 0)
            goto buffer_too_small;
    }

# ifdef RTEXT_FILTER_VF
    /* if this filter exists in the kernel's netlink implementation,
     * we need to set it, otherwise the response message will not
     * contain the IFLA_VFINFO_LIST that we're looking for.
     */
    {
        uint32_t ifla_ext_mask = RTEXT_FILTER_VF;

        if (nla_put(nl_msg, IFLA_EXT_MASK,
                    sizeof(ifla_ext_mask), &ifla_ext_mask) < 0) {
            goto buffer_too_small;
        }
    }
# endif

    if (virNetlinkCommand(nl_msg, &resp, &recvbuflen,
                          src_pid, dst_pid, NETLINK_ROUTE, 0) < 0)
        goto cleanup;

    if (recvbuflen < NLMSG_LENGTH(0) || resp == NULL)
        goto malformed_resp;

    switch (resp->nlmsg_type) {
    case NLMSG_ERROR:
        err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            goto malformed_resp;

        if (err->error) {
            virReportSystemError(-err->error,
                                 _("error dumping %s (%d) interface"),
                                 ifname, ifindex);
            goto cleanup;
        }
        break;

    case GENL_ID_CTRL:
    case NLMSG_DONE:
        rc = nlmsg_parse(resp, sizeof(struct ifinfomsg),
                         tb, IFLA_MAX, NULL);
        if (rc < 0)
            goto malformed_resp;
        break;

    default:
        goto malformed_resp;
    }
    rc = 0;
 cleanup:
    nlmsg_free(nl_msg);
    VIR_FREE(resp);
    return rc;

 malformed_resp:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("malformed netlink response message"));
    goto cleanup;

 buffer_too_small:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("allocated netlink buffer is too small"));
    goto cleanup;
}

static int
virNetDevSetVfConfig(const char *ifname, int ifindex, int vf,
                     bool nltarget_kernel, const virMacAddr *macaddr,
                     int vlanid, uint32_t (*getPidFunc)(void))
{
    int rc = -1;
    struct nlmsghdr *resp = NULL;
    struct nlmsgerr *err;
    unsigned int recvbuflen = 0;
    uint32_t pid = 0;
    struct nl_msg *nl_msg;
    struct nlattr *vfinfolist, *vfinfo;
    struct ifinfomsg ifinfo = {
        .ifi_family = AF_UNSPEC,
        .ifi_index  = ifindex
    };

    if (!macaddr && vlanid < 0)
        return -1;

    nl_msg = nlmsg_alloc_simple(RTM_SETLINK, NLM_F_REQUEST);
    if (!nl_msg) {
        virReportOOMError();
        return rc;
    }

    if (nlmsg_append(nl_msg,  &ifinfo, sizeof(ifinfo), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;

    if (ifname &&
        nla_put(nl_msg, IFLA_IFNAME, strlen(ifname)+1, ifname) < 0)
        goto buffer_too_small;


    if (!(vfinfolist = nla_nest_start(nl_msg, IFLA_VFINFO_LIST)))
        goto buffer_too_small;

    if (!(vfinfo = nla_nest_start(nl_msg, IFLA_VF_INFO)))
        goto buffer_too_small;

    if (macaddr) {
        struct ifla_vf_mac ifla_vf_mac = {
             .vf = vf,
             .mac = { 0, },
        };

        virMacAddrGetRaw(macaddr, ifla_vf_mac.mac);

        if (nla_put(nl_msg, IFLA_VF_MAC, sizeof(ifla_vf_mac),
                    &ifla_vf_mac) < 0)
            goto buffer_too_small;
    }

    if (vlanid >= 0) {
        struct ifla_vf_vlan ifla_vf_vlan = {
             .vf = vf,
             .vlan = vlanid,
             .qos = 0,
        };

        if (nla_put(nl_msg, IFLA_VF_VLAN, sizeof(ifla_vf_vlan),
                    &ifla_vf_vlan) < 0)
            goto buffer_too_small;
    }

    nla_nest_end(nl_msg, vfinfo);
    nla_nest_end(nl_msg, vfinfolist);

    if (!nltarget_kernel) {
        pid = getPidFunc();
        if (pid == 0) {
            rc = -1;
            goto cleanup;
        }
    }

    if (virNetlinkCommand(nl_msg, &resp, &recvbuflen, 0, pid,
                          NETLINK_ROUTE, 0) < 0)
        goto cleanup;

    if (recvbuflen < NLMSG_LENGTH(0) || resp == NULL)
        goto malformed_resp;

    switch (resp->nlmsg_type) {
    case NLMSG_ERROR:
        err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            goto malformed_resp;

        if (err->error) {
            virReportSystemError(-err->error,
                _("error during set %s of ifindex %d"),
                (macaddr ? (vlanid >= 0 ? "mac/vlan" : "mac") : "vlanid"),
                ifindex);
            goto cleanup;
        }
        break;

    case NLMSG_DONE:
        break;

    default:
        goto malformed_resp;
    }

    rc = 0;
 cleanup:
    nlmsg_free(nl_msg);
    VIR_FREE(resp);
    return rc;

 malformed_resp:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("malformed netlink response message"));
    goto cleanup;

 buffer_too_small:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("allocated netlink buffer is too small"));
    goto cleanup;
}

static int
virNetDevParseVfConfig(struct nlattr **tb, int32_t vf, virMacAddrPtr mac,
                       int *vlanid)
{
    int rc = -1;
    struct ifla_vf_mac *vf_mac;
    struct ifla_vf_vlan *vf_vlan;
    struct nlattr *tb_vf_info = {NULL, };
    struct nlattr *tb_vf[IFLA_VF_MAX+1];
    int rem;

    if (!tb[IFLA_VFINFO_LIST]) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing IFLA_VF_INFO in netlink response"));
        goto cleanup;
    }

    nla_for_each_nested(tb_vf_info, tb[IFLA_VFINFO_LIST], rem) {
        if (nla_type(tb_vf_info) != IFLA_VF_INFO)
            continue;

        if (nla_parse_nested(tb_vf, IFLA_VF_MAX, tb_vf_info,
                             ifla_vf_policy)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("error parsing IFLA_VF_INFO"));
            goto cleanup;
        }

        if (tb[IFLA_VF_MAC]) {
            vf_mac = RTA_DATA(tb_vf[IFLA_VF_MAC]);
            if (vf_mac && vf_mac->vf == vf)  {
                virMacAddrSetRaw(mac, vf_mac->mac);
                rc = 0;
            }
        }

        if (tb[IFLA_VF_VLAN]) {
            vf_vlan = RTA_DATA(tb_vf[IFLA_VF_VLAN]);
            if (vf_vlan && vf_vlan->vf == vf)  {
                *vlanid = vf_vlan->vlan;
                rc = 0;
            }
        }

        if (rc == 0)
            break;
    }
    if (rc < 0)
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("couldn't find IFLA_VF_INFO for VF %d "
                         "in netlink response"), vf);
 cleanup:
    return rc;
}

static int
virNetDevGetVfConfig(const char *ifname, int vf, virMacAddrPtr mac,
                     int *vlanid)
{
    int rc = -1;
    struct nlattr *tb[IFLA_MAX + 1] = {NULL, };
    int ifindex = -1;

    rc = virNetDevLinkDump(ifname, ifindex, tb, 0, 0);
    if (rc < 0)
        return rc;

    rc = virNetDevParseVfConfig(tb, vf, mac, vlanid);

    return rc;
}

static int
virNetDevReplaceVfConfig(const char *pflinkdev, int vf,
                         const virMacAddr *macaddress,
                         int vlanid,
                         const char *stateDir)
{
    int ret = -1;
    virMacAddr oldmac;
    int oldvlanid = -1;
    char *path = NULL;
    char macstr[VIR_MAC_STRING_BUFLEN];
    char *fileData = NULL;
    int ifindex = -1;

    if (virNetDevGetVfConfig(pflinkdev, vf, &oldmac, &oldvlanid) < 0)
        goto cleanup;

    if (virAsprintf(&path, "%s/%s_vf%d",
                    stateDir, pflinkdev, vf) < 0)
        goto cleanup;

    if (virAsprintf(&fileData, "%s\n%d\n",
                    virMacAddrFormat(&oldmac, macstr), oldvlanid) < 0)
        goto cleanup;
    if (virFileWriteStr(path, fileData, O_CREAT|O_TRUNC|O_WRONLY) < 0) {
        virReportSystemError(errno, _("Unable to preserve mac/vlan tag "
                                      "for pf = %s, vf = %d"), pflinkdev, vf);
        goto cleanup;
    }

    ret = virNetDevSetVfConfig(pflinkdev, ifindex, vf, true,
                                macaddress, vlanid, NULL);

 cleanup:
    VIR_FREE(path);
    VIR_FREE(fileData);
    return ret;
}

static int
virNetDevRestoreVfConfig(const char *pflinkdev, int vf,
                         const char *stateDir)
{
    int rc = -1;
    char *path = NULL;
    char *fileData = NULL;
    char *vlan = NULL;
    virMacAddr oldmac;
    int vlanid = -1;
    int ifindex = -1;

    if (virAsprintf(&path, "%s/%s_vf%d",
                    stateDir, pflinkdev, vf) < 0)
        return rc;

    if (virFileReadAll(path, 128, &fileData) < 0) {
        goto cleanup;
    }

    if ((vlan = strchr(fileData, '\n'))) {
        char *endptr;

        *vlan++ = 0; /* NULL terminate the mac address */
        if (*vlan) {
            if ((virStrToLong_i(vlan, &endptr, 10, &vlanid) < 0) ||
                (endptr && *endptr != '\n' && *endptr != 0)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Cannot parse vlan tag from '%s'"),
                               vlan);
                goto cleanup;
            }
        }
    }

    if (virMacAddrParse(fileData, &oldmac) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse MAC address from '%s'"),
                       fileData);
        goto cleanup;
    }

    /*reset mac and remove file-ignore results*/
    rc = virNetDevSetVfConfig(pflinkdev, ifindex, vf, true,
                              &oldmac, vlanid, NULL);
    ignore_value(unlink(path));

 cleanup:
    VIR_FREE(path);
    VIR_FREE(fileData);

    return rc;
}

/**
 * virNetDevReplaceNetConfig:
 * @linkdev: name of the interface
 * @vf: vf index if linkdev is a pf
 * @macaddress: new MAC address for interface
 * @vlanid: new vlanid
 * @stateDir: directory to store old net config
 *
 * Returns 0 on success, -1 on failure
 *
 */
int
virNetDevReplaceNetConfig(const char *linkdev, int vf,
                          const virMacAddr *macaddress, int vlanid,
                          const char *stateDir)
{
    if (vf == -1)
        return virNetDevReplaceMacAddress(linkdev, macaddress, stateDir);
    else
        return virNetDevReplaceVfConfig(linkdev, vf, macaddress, vlanid,
                                        stateDir);
}

/**
 * virNetDevRestoreNetConfig:
 * @linkdev: name of the interface
 * @vf: vf index if linkdev is a pf
 * @stateDir: directory containing old net config
 *
 * Returns 0 on success, -errno on failure.
 *
 */
int
virNetDevRestoreNetConfig(const char *linkdev, int vf, const char *stateDir)
{
    if (vf == -1)
        return virNetDevRestoreMacAddress(linkdev, stateDir);
    else
        return virNetDevRestoreVfConfig(linkdev, vf, stateDir);
}

#else /* defined(__linux__) && defined(HAVE_LIBNL) */

int
virNetDevLinkDump(const char *ifname ATTRIBUTE_UNUSED,
                  int ifindex ATTRIBUTE_UNUSED,
                  struct nlattr **tb ATTRIBUTE_UNUSED,
                  uint32_t src_pid ATTRIBUTE_UNUSED,
                  uint32_t dst_pid ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to dump link info on this platform"));
    return -1;
}

int
virNetDevReplaceNetConfig(const char *linkdev ATTRIBUTE_UNUSED,
                          int vf ATTRIBUTE_UNUSED,
                          const virMacAddr *macaddress ATTRIBUTE_UNUSED,
                          int vlanid ATTRIBUTE_UNUSED,
                          const char *stateDir ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to replace net config on this platform"));
    return -1;

}

int
virNetDevRestoreNetConfig(const char *linkdev ATTRIBUTE_UNUSED,
                          int vf ATTRIBUTE_UNUSED,
                          const char *stateDir ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to restore net config on this platform"));
    return -1;
}

#endif /* defined(__linux__) && defined(HAVE_LIBNL) */
