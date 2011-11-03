/*
 * Copyright (C) 2007-2011 Red Hat, Inc.
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

#include "virnetdev.h"
#include "virfile.h"
#include "virterror_internal.h"
#include "command.h"
#include "memory.h"

#include <sys/ioctl.h>
#ifdef HAVE_NET_IF_H
# include <net/if.h>
#endif
#include <fcntl.h>

#ifdef __linux__
# include <linux/sockios.h>
# include <linux/if_vlan.h>
#endif

#define VIR_FROM_THIS VIR_FROM_NONE
#define virNetDevError(code, ...)                                      \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,                \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#ifdef HAVE_NET_IF_H
static int virNetDevSetupControlFull(const char *ifname,
                                     struct ifreq *ifr,
                                     int domain,
                                     int type)
{
    int fd;

    memset(ifr, 0, sizeof(*ifr));

    if (virStrcpyStatic(ifr->ifr_name, ifname) == NULL) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%s' is too long"),
                             ifname);
        return -1;
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
#endif


#ifdef SIOCGIFFLAGS
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
#else
int virNetDevExists(const char *ifname)
{
    virReportSystemError(ENOSYS,
                         _("Unable to check interface %s"), ifname);
    return -1;
}
#endif


#ifdef SIOCGIFHWADDR
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
#else
int virNetDevSetMAC(const char *ifname,
                    const unsigned char *macaddr ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot set interface MAC on '%s'"),
                         ifname);
    return -1;
}
#endif


#ifdef SIOCGIFHWADDR
/**
 * virNetDevGetMAC:
 * @ifname: interface name to set MTU for
 * @macaddr: MAC address (VIR_MAC_BUFLEN in size)
 *
 * This function gets the @macaddr for a given interface @ifname.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevGetMAC(const char *ifname,
                    unsigned char *macaddr)
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

    memcpy(macaddr, ifr.ifr_hwaddr.sa_data, VIR_MAC_BUFLEN);

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#else
int virNetDevGetMAC(const char *ifname,
                    unsigned char *macaddr ATTRIBUTE_UNUSED)
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
                           const unsigned char *macaddress,
                           const char *stateDir)
{
    unsigned char oldmac[6];
    char *path = NULL;
    char macstr[VIR_MAC_STRING_BUFLEN];

    if (virNetDevGetMAC(linkdev, oldmac) < 0)
        return -1;


    if (virAsprintf(&path, "%s/%s",
                    stateDir,
                    linkdev) < 0) {
        virReportOOMError();
        return -1;
    }
    virFormatMacAddr(oldmac, macstr);
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
    unsigned char oldmac[6];

    if (virAsprintf(&path, "%s/%s",
                    stateDir,
                    linkdev) < 0) {
        virReportOOMError();
        return -1;
    }

    if (virFileReadAll(path, VIR_MAC_STRING_BUFLEN, &macstr) < 0)
        return -1;

    if (virParseMacAddr(macstr, &oldmac[0]) != 0) {
        virNetDevError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse MAC address from '%s'"),
                       oldmacname);
        VIR_FREE(macstr);
        return -1;
    }

    /*reset mac and remove file-ignore results*/
    rc = virNetDevSetMAC(linkdev, oldmac);
    ignore_value(unlink(path));
    VIR_FREE(macstr);

    return rc;
}


#ifdef SIOCGIFMTU
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


#ifdef SIOCSIFMTU
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
int virNetDevSetNamespace(const char *ifname, int pidInNs)
{
    int rc;
    char *pid = NULL;
    const char *argv[] = {
        "ip", "link", "set", ifname, "netns", NULL, NULL
    };

    if (virAsprintf(&pid, "%d", pidInNs) == -1) {
        virReportOOMError();
        return -1;
    }

    argv[5] = pid;
    rc = virRun(argv, NULL);

    VIR_FREE(pid);
    return rc;
}

#ifdef SIOCSIFNAME
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

    if (virStrcpyStatic(ifr.ifr_newname, newifname) == NULL) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%s' is too long"),
                             newifname);
        goto cleanup;
    }

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


#ifdef SIOCSIFFLAGS
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


#ifdef SIOCGIFFLAGS
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
#ifdef __linux__
int virNetDevGetIndex(const char *ifname, int *ifindex)
{
    int ret = -1;
    struct ifreq ifreq;
    int fd = socket(PF_PACKET, SOCK_DGRAM, 0);

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

    *ifindex = ifreq.ifr_ifindex;
    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#else /* ! __linux__ */
int virNetDevGetIndex(const char *ifname ATTRIBUTE_UNUSED,
                      int *ifindex ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get interface index on this platform"));
    return -1;
}
#endif /* ! __linux__ */


#ifdef __linux__
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
#else /* ! __linux__ */
int virNetDevGetVLanID(const char *ifname ATTRIBUTE_UNUSED,
                       int *vlanid ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get VLAN on this platform"));
    return -1;
}
#endif /* ! __linux__ */



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

    if (!(addrstr = virSocketAddrFormat(addr)))
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
