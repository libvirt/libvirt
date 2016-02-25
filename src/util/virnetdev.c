/*
 * Copyright (C) 2007-2015 Red Hat, Inc.
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

#if HAVE_GETIFADDRS
# include <ifaddrs.h>
#endif

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

#if defined(SIOCETHTOOL) && defined(HAVE_STRUCT_IFREQ)
# include <linux/types.h>
# include <linux/ethtool.h>
#endif

#if HAVE_DECL_LINK_ADDR
# include <sys/sockio.h>
# include <net/if_dl.h>
#endif

#ifndef IFNAMSIZ
# define IFNAMSIZ 16
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.netdev");

#define PROC_NET_DEV_MCAST "/proc/net/dev_mcast"
#define MAX_MCAST_SIZE 50*14336
#define VIR_MCAST_NAME_LEN (IFNAMSIZ + 1)
#define VIR_MCAST_TOKEN_DELIMS " \n"
#define VIR_MCAST_ADDR_LEN (VIR_MAC_HEXLEN + 1)

#if defined(SIOCSIFFLAGS) && defined(HAVE_STRUCT_IFREQ)
# define VIR_IFF_UP IFF_UP
# define VIR_IFF_PROMISC IFF_PROMISC
# define VIR_IFF_MULTICAST IFF_MULTICAST
# define VIR_IFF_ALLMULTI IFF_ALLMULTI
#else
# define VIR_IFF_UP 0
# define VIR_IFF_PROMISC 0
# define VIR_IFF_MULTICAST 0
# define VIR_IFF_ALLMULTI 0
#endif

#define RESOURCE_FILE_LEN 4096
#if HAVE_DECL_ETHTOOL_GFEATURES
# define TX_UDP_TNL 25
# define GFEATURES_SIZE 2
# define FEATURE_WORD(blocks, index, field)  ((blocks)[(index) / 32U].field)
# define FEATURE_FIELD_FLAG(index)      (1U << (index) % 32U)
# define FEATURE_BIT_IS_SET(blocks, index, field)        \
    (FEATURE_WORD(blocks, index, field) & FEATURE_FIELD_FLAG(index))
#endif
#define VIR_DAD_WAIT_TIMEOUT 20 /* seconds */

typedef enum {
    VIR_MCAST_TYPE_INDEX_TOKEN,
    VIR_MCAST_TYPE_NAME_TOKEN,
    VIR_MCAST_TYPE_USERS_TOKEN,
    VIR_MCAST_TYPE_GLOBAL_TOKEN,
    VIR_MCAST_TYPE_ADDR_TOKEN,

    VIR_MCAST_TYPE_LAST
} virMCastType;

typedef struct _virNetDevMcastEntry virNetDevMcastEntry;
typedef virNetDevMcastEntry *virNetDevMcastEntryPtr;
struct _virNetDevMcastEntry  {
        int idx;
        char name[VIR_MCAST_NAME_LEN];
        int users;
        bool global;
        virMacAddr macaddr;
};

typedef struct _virNetDevMcastList virNetDevMcastList;
typedef virNetDevMcastList *virNetDevMcastListPtr;
struct _virNetDevMcastList {
    size_t nentries;
    virNetDevMcastEntryPtr *entries;
};

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
        char macstr[VIR_MAC_STRING_BUFLEN];

        virReportSystemError(errno,
                             _("Cannot set interface MAC to %s on '%s'"),
                             virMacAddrFormat(macaddr, macstr), ifname);
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
                                 _("Cannot set interface MAC to %s on '%s'"),
                                 mac + 1, ifname);
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
    int ret = -1;

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
        goto cleanup;
    }

    if (virNetDevSetMAC(linkdev, macaddress) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(path);
    return ret;
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
    int rc = -1;
    char *oldmacname = NULL;
    char *macstr = NULL;
    char *path = NULL;
    virMacAddr oldmac;

    if (virAsprintf(&path, "%s/%s",
                    stateDir,
                    linkdev) < 0)
        return -1;

    if (virFileReadAll(path, VIR_MAC_STRING_BUFLEN, &macstr) < 0)
        goto cleanup;

    if (virMacAddrParse(macstr, &oldmac) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse MAC address from '%s'"),
                       oldmacname);
        goto cleanup;
    }

    /*reset mac and remove file-ignore results*/
    rc = virNetDevSetMAC(linkdev, &oldmac);
    ignore_value(unlink(path));

 cleanup:
    VIR_FREE(macstr);
    VIR_FREE(path);
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
    int ret = -1;
    char *pid = NULL;
    char *phy = NULL;
    char *phy_path = NULL;
    int len;

    if (virAsprintf(&pid, "%lld", (long long) pidInNs) == -1)
        return -1;

    /* The 802.11 wireless devices only move together with their PHY. */
    if (virNetDevSysfsFile(&phy_path, ifname, "phy80211/name") < 0)
        goto cleanup;

    if ((len = virFileReadAllQuiet(phy_path, 1024, &phy)) <= 0) {
        /* Not a wireless device. */
        const char *argv[] = {
            "ip", "link", "set", ifname, "netns", NULL, NULL
        };

        argv[5] = pid;
        if (virRun(argv, NULL) < 0)
            goto cleanup;

    } else {
        const char *argv[] = {
            "iw", "phy", NULL, "set", "netns", NULL, NULL
        };

        /* Remove a line break. */
        phy[len - 1] = '\0';

        argv[2] = phy;
        argv[5] = pid;
        if (virRun(argv, NULL) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(phy_path);
    VIR_FREE(phy);
    VIR_FREE(pid);
    return ret;
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
static int
virNetDevSetIFFlag(const char *ifname, int flag, bool val)
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

    if (val)
        ifflags = ifr.ifr_flags | flag;
    else
        ifflags = ifr.ifr_flags & ~flag;

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
static int
virNetDevSetIFFlag(const char *ifname,
                   int flag ATTRIBUTE_UNUSED,
                   bool val ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot set interface flags on '%s'"),
                         ifname);
    return -1;
}
#endif



/**
 * virNetDevSetOnline:
 * @ifname: the interface name
 * @online: true for up, false for down
 *
 * Function to control if an interface is activated (up, true) or not (down, false)
 *
 * Returns 0 in case of success or -1 on error.
 */
int
virNetDevSetOnline(const char *ifname,
                   bool online)
{

    return virNetDevSetIFFlag(ifname, VIR_IFF_UP, online);
}

/**
 * virNetDevSetPromiscuous:
 * @ifname: the interface name
 * @promiscuous: true for receive all packets, false for do not receive
 *               all packets
 *
 * Function to control if an interface is to receive all
 * packets (receive all, true) or not (do not receive all, false)
 *
 * Returns 0 in case of success or -1 on error.
 */
int
virNetDevSetPromiscuous(const char *ifname,
                        bool promiscuous)
{
    return virNetDevSetIFFlag(ifname, VIR_IFF_PROMISC, promiscuous);
}

/**
 * virNetDevSetRcvMulti:
 * @ifname: the interface name
 * @:receive true for receive multicast packets, false for do not receive
 *           multicast packets
 *
 * Function to control if an interface is to receive multicast
 * packets in which it is interested (receive, true)
 * or not (do not receive, false)
 *
 * Returns 0 in case of success or -1 on error.
 */
int
virNetDevSetRcvMulti(const char *ifname,
                     bool receive)
{
    return virNetDevSetIFFlag(ifname, VIR_IFF_MULTICAST, receive);
}

/**
 * virNetDevSetRcvAllMulti:
 * @ifname: the interface name
 * @:receive true for receive all packets, false for do not receive all packets
 *
 * Function to control if an interface is to receive all multicast
 * packets (receive, true) or not (do not receive, false)
 *
 * Returns 0 in case of success or -1 on error.
 */
int
virNetDevSetRcvAllMulti(const char *ifname,
                        bool receive)
{
    return virNetDevSetIFFlag(ifname, VIR_IFF_ALLMULTI, receive);
}


#if defined(SIOCGIFFLAGS) && defined(HAVE_STRUCT_IFREQ)
static int
virNetDevGetIFFlag(const char *ifname, int flag, bool *val)
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

    *val = (ifr.ifr_flags & flag) ? true : false;
    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#else
static int
virNetDevGetIFFlag(const char *ifname,
                   int flag ATTRIBUTE_UNUSED,
                   bool *val ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot get interface flags on '%s'"),
                         ifname);
    return -1;
}
#endif


/**
 * virNetDevGetOnline:
 * @ifname: the interface name
 * @online: where to store the status
 *
 * Function to query if an interface is activated (true) or not (false)
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
int
virNetDevGetOnline(const char *ifname,
                   bool *online)
{
    return virNetDevGetIFFlag(ifname, VIR_IFF_UP, online);
}

/**
 * virNetDevIsPromiscuous:
 * @ifname: the interface name
 * @promiscuous: where to store the status
 *
 * Function to query if an interface is receiving all packets (true) or
 * not (false)
 *
 * Returns 0 in case of success or an errno code in case of failure.
 */
int
virNetDevGetPromiscuous(const char *ifname,
                        bool *promiscuous)
{
    return virNetDevGetIFFlag(ifname, VIR_IFF_PROMISC, promiscuous);
}

/**
 * virNetDevIsRcvMulti:
 * @ifname: the interface name
 * @receive where to store the status
 *
 * Function to query whether an interface is receiving multicast packets (true)
 * in which it is interested, or not (false)
 *
 * Returns 0 in case of success or -1 on error.
 */
int
virNetDevGetRcvMulti(const char *ifname,
                     bool *receive)
{
    return virNetDevGetIFFlag(ifname, VIR_IFF_MULTICAST, receive);
}

/**
 * virNetDevIsRcvAllMulti:
 * @ifname: the interface name
 * @:receive where to store the status
 *
 * Function to query whether an interface is receiving all multicast
 * packets (receiving, true) or not (is not receiving, false)
 *
 * Returns 0 in case of success or -1 on error.
 */
int
virNetDevGetRcvAllMulti(const char *ifname,
                        bool *receive)
{
    return virNetDevGetIFFlag(ifname, VIR_IFF_ALLMULTI, receive);
}


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


#if defined(__linux__) && defined(HAVE_LIBNL)

static int
virNetDevGetIPAddressBinary(virSocketAddr *addr, void **data, size_t *len)
{
    if (!addr)
        return -1;

    switch (VIR_SOCKET_ADDR_FAMILY(addr)) {
    case AF_INET:
        *data = &addr->data.inet4.sin_addr;
        *len = sizeof(struct in_addr);
        break;
    case AF_INET6:
        *data = &addr->data.inet6.sin6_addr;
        *len = sizeof(struct in6_addr);
        break;
    default:
        return -1;
    }
    return 0;
}

static struct nl_msg *
virNetDevCreateNetlinkAddressMessage(int messageType,
                                     const char *ifname,
                                     virSocketAddr *addr,
                                     unsigned int prefix,
                                     virSocketAddr *broadcast)
{
    struct nl_msg *nlmsg = NULL;
    struct ifaddrmsg ifa;
    unsigned int ifindex;
    void *addrData = NULL;
    void *broadcastData = NULL;
    size_t addrDataLen;

    if (virNetDevGetIPAddressBinary(addr, &addrData, &addrDataLen) < 0)
        return NULL;

    if (broadcast && virNetDevGetIPAddressBinary(broadcast, &broadcastData,
                                                 &addrDataLen) < 0)
        return NULL;

    /* Get the interface index */
    if ((ifindex = if_nametoindex(ifname)) == 0)
        return NULL;

    if (!(nlmsg = nlmsg_alloc_simple(messageType,
                                     NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL))) {
        virReportOOMError();
        return NULL;
    }

    memset(&ifa, 0, sizeof(ifa));

    ifa.ifa_prefixlen = prefix;
    ifa.ifa_family = VIR_SOCKET_ADDR_FAMILY(addr);
    ifa.ifa_index = ifindex;
    ifa.ifa_scope = 0;

    if (nlmsg_append(nlmsg, &ifa, sizeof(ifa), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;

    if (nla_put(nlmsg, IFA_LOCAL, addrDataLen, addrData) < 0)
        goto buffer_too_small;

    if (nla_put(nlmsg, IFA_ADDRESS, addrDataLen, addrData) < 0)
        goto buffer_too_small;

    if (broadcastData &&
        nla_put(nlmsg, IFA_BROADCAST, addrDataLen, broadcastData) < 0)
        goto buffer_too_small;

    return nlmsg;

 buffer_too_small:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("allocated netlink buffer is too small"));
    nlmsg_free(nlmsg);
    return NULL;
}

/**
 * virNetDevSetIPAddress:
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
int virNetDevSetIPAddress(const char *ifname,
                          virSocketAddr *addr,
                          unsigned int prefix)
{
    virSocketAddr *broadcast = NULL;
    int ret = -1;
    struct nl_msg *nlmsg = NULL;
    struct nlmsghdr *resp = NULL;
    unsigned int recvbuflen;


    /* The caller needs to provide a correct address */
    if (VIR_SOCKET_ADDR_FAMILY(addr) == AF_INET) {
        /* compute a broadcast address if this is IPv4 */
        if (VIR_ALLOC(broadcast) < 0)
            return -1;

        if (virSocketAddrBroadcastByPrefix(addr, prefix, broadcast) < 0)
            goto cleanup;
    }

    if (!(nlmsg = virNetDevCreateNetlinkAddressMessage(RTM_NEWADDR, ifname,
                                                       addr, prefix,
                                                       broadcast)))
        goto cleanup;

    if (virNetlinkCommand(nlmsg, &resp, &recvbuflen, 0, 0,
                          NETLINK_ROUTE, 0) < 0)
        goto cleanup;


    if (virNetlinkGetErrorCode(resp, recvbuflen) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Error adding IP address to %s"), ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    nlmsg_free(nlmsg);
    VIR_FREE(resp);
    VIR_FREE(broadcast);
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
    int ret = -1;
    struct nl_msg *nlmsg = NULL;
    struct nlmsghdr *resp = NULL;
    unsigned int recvbuflen;
    unsigned int ifindex;
    struct rtmsg rtmsg;
    void *gatewayData = NULL;
    void *addrData = NULL;
    size_t addrDataLen;
    int errCode;
    virSocketAddr defaultAddr;
    virSocketAddrPtr actualAddr;
    char *toStr = NULL;
    char *viaStr = NULL;

    actualAddr = addr;

    /* If we have no valid network address, then use the default one */
    if (!addr || !VIR_SOCKET_ADDR_VALID(addr)) {
        VIR_DEBUG("computing default address");
        int family = VIR_SOCKET_ADDR_FAMILY(gateway);
        if (family == AF_INET) {
            if (virSocketAddrParseIPv4(&defaultAddr, VIR_SOCKET_ADDR_IPV4_ALL) < 0)
                goto cleanup;
        } else {
            if (virSocketAddrParseIPv6(&defaultAddr, VIR_SOCKET_ADDR_IPV6_ALL) < 0)
                goto cleanup;
        }

        actualAddr = &defaultAddr;
    }

    toStr = virSocketAddrFormat(actualAddr);
    viaStr = virSocketAddrFormat(gateway);
    VIR_DEBUG("Adding route %s/%d via %s", toStr, prefix, viaStr);

    if (virNetDevGetIPAddressBinary(actualAddr, &addrData, &addrDataLen) < 0 ||
        virNetDevGetIPAddressBinary(gateway, &gatewayData, &addrDataLen) < 0)
        goto cleanup;

    /* Get the interface index */
    if ((ifindex = if_nametoindex(ifname)) == 0)
        goto cleanup;

    if (!(nlmsg = nlmsg_alloc_simple(RTM_NEWROUTE,
                                     NLM_F_REQUEST | NLM_F_CREATE |
                                     NLM_F_EXCL))) {
        virReportOOMError();
        goto cleanup;
    }

    memset(&rtmsg, 0, sizeof(rtmsg));

    rtmsg.rtm_family = VIR_SOCKET_ADDR_FAMILY(gateway);
    rtmsg.rtm_table = RT_TABLE_MAIN;
    rtmsg.rtm_scope = RT_SCOPE_UNIVERSE;
    rtmsg.rtm_protocol = RTPROT_BOOT;
    rtmsg.rtm_type = RTN_UNICAST;
    rtmsg.rtm_dst_len = prefix;

    if (nlmsg_append(nlmsg, &rtmsg, sizeof(rtmsg), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;

    if (prefix > 0 && nla_put(nlmsg, RTA_DST, addrDataLen, addrData) < 0)
        goto buffer_too_small;

    if (nla_put(nlmsg, RTA_GATEWAY, addrDataLen, gatewayData) < 0)
        goto buffer_too_small;

    if (nla_put_u32(nlmsg, RTA_OIF, ifindex) < 0)
        goto buffer_too_small;

    if (metric > 0 && nla_put_u32(nlmsg, RTA_PRIORITY, metric) < 0)
        goto buffer_too_small;

    if (virNetlinkCommand(nlmsg, &resp, &recvbuflen, 0, 0,
                          NETLINK_ROUTE, 0) < 0)
        goto cleanup;

    if ((errCode = virNetlinkGetErrorCode(resp, recvbuflen)) < 0) {
        virReportSystemError(errCode, _("Error adding route to %s"), ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(toStr);
    VIR_FREE(viaStr);
    nlmsg_free(nlmsg);
    return ret;

 buffer_too_small:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("allocated netlink buffer is too small"));
    goto cleanup;
}

/**
 * virNetDevClearIPAddress:
 * @ifname: the interface name
 * @addr: the IP address (IPv4 or IPv6)
 * @prefix: number of 1 bits in the netmask
 *
 * Delete an IP address from an interface.
 *
 * Returns 0 in case of success or -1 in case of error.
 */
int virNetDevClearIPAddress(const char *ifname,
                            virSocketAddr *addr,
                            unsigned int prefix)
{
    int ret = -1;
    struct nl_msg *nlmsg = NULL;
    struct nlmsghdr *resp = NULL;
    unsigned int recvbuflen;

    if (!(nlmsg = virNetDevCreateNetlinkAddressMessage(RTM_DELADDR, ifname,
                                                       addr, prefix,
                                                       NULL)))
        goto cleanup;

    if (virNetlinkCommand(nlmsg, &resp, &recvbuflen, 0, 0,
                          NETLINK_ROUTE, 0) < 0)
        goto cleanup;

    if (virNetlinkGetErrorCode(resp, recvbuflen) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Error removing IP address from %s"), ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    nlmsg_free(nlmsg);
    VIR_FREE(resp);
    return ret;
}

/* return true if there is a known address with 'tentative' flag set */
static bool
virNetDevParseDadStatus(struct nlmsghdr *nlh, int len,
                        virSocketAddrPtr *addrs, size_t count)
{
    struct ifaddrmsg *ifaddrmsg_ptr;
    unsigned int ifaddrmsg_len;
    struct rtattr *rtattr_ptr;
    size_t i;
    struct in6_addr *addr;

    VIR_WARNINGS_NO_CAST_ALIGN
    for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
    VIR_WARNINGS_RESET
        if (NLMSG_PAYLOAD(nlh, 0) < sizeof(struct ifaddrmsg)) {
            /* Message without payload is the last one. */
            break;
        }

        ifaddrmsg_ptr = (struct ifaddrmsg *)NLMSG_DATA(nlh);
        if (!(ifaddrmsg_ptr->ifa_flags & IFA_F_TENTATIVE)) {
            /* Not tentative: we are not interested in this entry. */
            continue;
        }

        ifaddrmsg_len = IFA_PAYLOAD(nlh);
        VIR_WARNINGS_NO_CAST_ALIGN
        rtattr_ptr = (struct rtattr *) IFA_RTA(ifaddrmsg_ptr);
        for (; RTA_OK(rtattr_ptr, ifaddrmsg_len);
            rtattr_ptr = RTA_NEXT(rtattr_ptr, ifaddrmsg_len)) {
            VIR_WARNINGS_RESET
            if (RTA_PAYLOAD(rtattr_ptr) != sizeof(struct in6_addr)) {
                /* No address: ignore. */
                continue;
            }

            /* We check only known addresses. */
            for (i = 0; i < count; i++) {
                addr = &addrs[i]->data.inet6.sin6_addr;
                if (!memcmp(addr, RTA_DATA(rtattr_ptr),
                            sizeof(struct in6_addr))) {
                    /* We found matching tentative address. */
                    return true;
                }
            }
        }
    }
    return false;
}

/* return after DAD finishes for all known IPv6 addresses or an error */
int
virNetDevWaitDadFinish(virSocketAddrPtr *addrs, size_t count)
{
    struct nl_msg *nlmsg = NULL;
    struct ifaddrmsg ifa;
    struct nlmsghdr *resp = NULL;
    unsigned int recvbuflen;
    int ret = -1;
    bool dad = true;
    time_t max_time = time(NULL) + VIR_DAD_WAIT_TIMEOUT;

    if (!(nlmsg = nlmsg_alloc_simple(RTM_GETADDR,
                                     NLM_F_REQUEST | NLM_F_DUMP))) {
        virReportOOMError();
        return -1;
    }

    memset(&ifa, 0, sizeof(ifa));
    /* DAD is for IPv6 adresses only. */
    ifa.ifa_family = AF_INET6;
    if (nlmsg_append(nlmsg, &ifa, sizeof(ifa), NLMSG_ALIGNTO) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("allocated netlink buffer is too small"));
        goto cleanup;
    }

    /* Periodically query netlink until DAD finishes on all known addresses. */
    while (dad && time(NULL) < max_time) {
        if (virNetlinkCommand(nlmsg, &resp, &recvbuflen, 0, 0,
                              NETLINK_ROUTE, 0) < 0)
            goto cleanup;

        if (virNetlinkGetErrorCode(resp, recvbuflen) < 0) {
            virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                           _("error reading DAD state information"));
            goto cleanup;
        }

        /* Parse response. */
        dad = virNetDevParseDadStatus(resp, recvbuflen, addrs, count);
        if (dad)
            usleep(1000 * 10);

        VIR_FREE(resp);
    }
    /* Check timeout. */
    if (dad) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Duplicate Address Detection "
                         "not finished in %d seconds"), VIR_DAD_WAIT_TIMEOUT);
    } else {
        ret = 0;
    }

 cleanup:
    VIR_FREE(resp);
    nlmsg_free(nlmsg);
    return ret;
}

#else /* defined(__linux__) && defined(HAVE_LIBNL) */

int virNetDevSetIPAddress(const char *ifname,
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
# ifdef IFCONFIG_PATH
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
# else
    cmd = virCommandNew(IP_PATH);
    virCommandAddArgList(cmd, "addr", "add", NULL);
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    if (bcaststr)
        virCommandAddArgList(cmd, "broadcast", bcaststr, NULL);
    virCommandAddArgList(cmd, "dev", ifname, NULL);
# endif

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(addrstr);
    VIR_FREE(bcaststr);
    virCommandFree(cmd);
    return ret;
}

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

int virNetDevClearIPAddress(const char *ifname,
                            virSocketAddr *addr,
                            unsigned int prefix)
{
    virCommandPtr cmd = NULL;
    char *addrstr;
    int ret = -1;

    if (!(addrstr = virSocketAddrFormat(addr)))
        goto cleanup;
# ifdef IFCONFIG_PATH
    cmd = virCommandNew(IFCONFIG_PATH);
    virCommandAddArg(cmd, ifname);
    if (VIR_SOCKET_ADDR_IS_FAMILY(addr, AF_INET6))
        virCommandAddArg(cmd, "inet6");
    else
        virCommandAddArg(cmd, "inet");
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    virCommandAddArg(cmd, "-alias");
# else
    cmd = virCommandNew(IP_PATH);
    virCommandAddArgList(cmd, "addr", "del", NULL);
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    virCommandAddArgList(cmd, "dev", ifname, NULL);
# endif

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(addrstr);
    virCommandFree(cmd);
    return ret;
}

/* return after DAD finishes for all known IPv6 addresses or an error */
int
virNetDevWaitDadFinish(virSocketAddrPtr *addrs ATTRIBUTE_UNUSED,
                       size_t count ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to wait for IPv6 DAD on this platform"));
    return -1;
}

#endif /* defined(__linux__) && defined(HAVE_LIBNL) */

/**
 * virNetDevGetIPv4AddressIoctl:
 * @ifname: name of the interface whose IP address we want
 * @addr: filled with the IPv4 address
 *
 * This function gets the IPv4 address for the interface @ifname
 * and stores it in @addr
 *
 * Returns 0 on success, -errno on failure.
 */
#if defined(SIOCGIFADDR) && defined(HAVE_STRUCT_IFREQ)
static int
virNetDevGetIPv4AddressIoctl(const char *ifname,
                             virSocketAddrPtr addr)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFADDR, (char *)&ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to get IPv4 address for interface %s via ioctl"),
                             ifname);
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

static int
virNetDevGetIPv4AddressIoctl(const char *ifname ATTRIBUTE_UNUSED,
                             virSocketAddrPtr addr ATTRIBUTE_UNUSED)
{
    return -2;
}

#endif /* ! SIOCGIFADDR */

/**
 * virNetDevGetifaddrsAddress:
 * @ifname: name of the interface whose IP address we want
 * @addr: filled with the IP address
 *
 * This function gets the IP address for the interface @ifname
 * and stores it in @addr
 *
 * Returns 0 on success, -1 on failure, -2 on unsupported.
 */
#if HAVE_GETIFADDRS
static int
virNetDevGetifaddrsAddress(const char *ifname,
                           virSocketAddrPtr addr)
{
    struct ifaddrs *ifap, *ifa;
    int ret = -1;

    if (getifaddrs(&ifap) < 0) {
        virReportSystemError(errno,
                             _("Could not get interface list for '%s'"),
                             ifname);
        return -1;
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        int family = ifa->ifa_addr->sa_family;

        if (STRNEQ_NULLABLE(ifa->ifa_name, ifname))
            continue;
        if (family != AF_INET6 && family != AF_INET)
            continue;

        if (family == AF_INET6) {
            addr->len = sizeof(addr->data.inet6);
            memcpy(&addr->data.inet6, ifa->ifa_addr, addr->len);
        } else {
            addr->len = sizeof(addr->data.inet4);
            memcpy(&addr->data.inet4, ifa->ifa_addr, addr->len);
        }
        addr->data.stor.ss_family = family;
        ret = 0;
        goto cleanup;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("no IP address found for interface '%s'"),
                   ifname);
 cleanup:
    freeifaddrs(ifap);
    return ret;
}

#else  /* ! HAVE_GETIFADDRS */

static int
virNetDevGetifaddrsAddress(const char *ifname ATTRIBUTE_UNUSED,
                           virSocketAddrPtr addr ATTRIBUTE_UNUSED)
{
    return -2;
}

#endif

/**
 * virNetDevGetIPAddress:
 * @ifname: name of the interface whose IP address we want
 * @addr: filled with the IPv4 address
 *
 * This function gets the IPv4 address for the interface @ifname
 * and stores it in @addr
 *
 * Returns 0 on success, -errno on failure.
 */
int
virNetDevGetIPAddress(const char *ifname,
                      virSocketAddrPtr addr)
{
    int ret;

    memset(addr, 0, sizeof(*addr));
    addr->data.stor.ss_family = AF_UNSPEC;

    if ((ret = virNetDevGetifaddrsAddress(ifname, addr)) != -2)
        return ret;

    if ((ret = virNetDevGetIPv4AddressIoctl(ifname, addr)) != -2)
        return ret;

    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get IP address on this platform"));
    return -1;
}

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
        if (idx != ifindex) {
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

int
virNetDevSysfsFile(char **pf_sysfs_device_link, const char *ifname,
                   const char *file)
{

    if (virAsprintf(pf_sysfs_device_link, SYSFS_NET_DIR "%s/%s", ifname, file) < 0)
        return -1;
    return 0;
}

static int
virNetDevSysfsDeviceFile(char **pf_sysfs_device_link, const char *ifname,
                     const char *file)
{

    if (virAsprintf(pf_sysfs_device_link, SYSFS_NET_DIR "%s/device/%s", ifname,
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
                             size_t *n_vfname,
                             unsigned int *max_vfs)
{
    int ret = -1;
    size_t i;
    char *pf_sysfs_device_link = NULL;
    char *pci_sysfs_device_link = NULL;
    char *pciConfigAddr = NULL;

    *virt_fns = NULL;
    *n_vfname = 0;
    *max_vfs = 0;

    if (virNetDevSysfsFile(&pf_sysfs_device_link, pfname, "device") < 0)
        return ret;

    if (virPCIGetVirtualFunctions(pf_sysfs_device_link, virt_fns,
                                  n_vfname, max_vfs) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(*vfname, *n_vfname) < 0)
        goto cleanup;

    for (i = 0; i < *n_vfname; i++) {
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

        if (virPCIGetNetName(pci_sysfs_device_link, &((*vfname)[i])) < 0)
            VIR_INFO("VF does not have an interface name");
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
                             size_t *n_vfname ATTRIBUTE_UNUSED,
                             unsigned int *max_vfs ATTRIBUTE_UNUSED)
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

int
virNetDevSysfsFile(char **pf_sysfs_device_link ATTRIBUTE_UNUSED,
                   const char *ifname ATTRIBUTE_UNUSED,
                   const char *file ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get sysfs info on this platform"));
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
 * @ifname:  The name of the interface; only use if ifindex <= 0
 * @ifindex: The interface index; may be <= 0 if ifname is given
 * @data:    Gets a pointer to the raw data from netlink.
             MUST BE FREED BY CALLER!
 * @nlattr:  Pointer to a pointer of netlink attributes that will contain
 *           the results
 * @src_pid: pid used for nl_pid of the local end of the netlink message
 *           (0 == "use getpid()")
 * @dst_pid: pid of destination nl_pid if the kernel
 *           is not the target of the netlink message but it is to be
 *           sent to another process (0 if sending to the kernel)
 *
 * Get information from netlink about an interface given its name or index.
 *
 * Returns 0 on success, -1 on fatal error.
 */
int
virNetDevLinkDump(const char *ifname, int ifindex,
                  void **nlData, struct nlattr **tb,
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
    if (rc < 0)
       VIR_FREE(resp);
    *nlData = resp;
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
            char macstr[VIR_MAC_STRING_BUFLEN];

            virReportSystemError(-err->error,
                                 _("Cannot set interface MAC/vlanid to %s/%d "
                                   "for ifname %s ifindex %d vf %d"),
                                 (macaddr
                                  ? virMacAddrFormat(macaddr, macstr)
                                  : "(unchanged)"),
                                 vlanid,
                                 ifname ? ifname : "(unspecified)",
                                 ifindex, vf);
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
    void *nlData = NULL;
    struct nlattr *tb[IFLA_MAX + 1] = {NULL, };
    int ifindex = -1;

    rc = virNetDevLinkDump(ifname, ifindex, &nlData, tb, 0, 0);
    if (rc < 0)
        goto cleanup;

    rc = virNetDevParseVfConfig(tb, vf, mac, vlanid);

 cleanup:
    VIR_FREE(nlData);
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
    bool pfIsOnline;

    /* Assure that PF is online prior to twiddling with the VF.  It
     * *should* be, but if the PF isn't online the changes made to the
     * VF via the PF won't take effect, yet there will be no error
     * reported. In the case that it isn't online, fail and report the
     * error, since setting an unconfigured interface online
     * automatically turns on IPv6 autoconfig, which may not be what
     * the admin expects, so we want them to explicitly enable the PF
     * in the host system network config.
     */
    if (virNetDevGetOnline(pflinkdev, &pfIsOnline) < 0)
       goto cleanup;
    if (!pfIsOnline) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to configure VF %d of PF '%s' "
                         "because the PF is not online. Please "
                         "change host network config to put the "
                         "PF online."),
                       vf, pflinkdev);
        goto cleanup;
    }

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
virNetDevRestoreVfConfig(const char *pflinkdev,
                         int vf, const char *vflinkdev,
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

    if (vflinkdev && !virFileExists(path)) {
        /* this VF's config may have been stored with
         * virNetDevReplaceMacAddress while running an older version
         * of libvirt. If so, the ${pf}_vf${id} file won't exist. In
         * that case, try to restore using the older method with the
         * VF's name directly.
         */
        rc = virNetDevRestoreMacAddress(vflinkdev, stateDir);
        goto cleanup;
    }

    if (virFileReadAll(path, 128, &fileData) < 0)
        goto cleanup;

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
    int ret = -1;
    char *pfdevname = NULL;

    if (vf == -1 && virNetDevIsVirtualFunction(linkdev) == 1) {
        /* If this really *is* a VF and the caller just didn't know
         * it, we should set the MAC address via PF+vf# instead of
         * setting directly via VF, because the latter will be
         * rejected any time after the former has been done.
         */
        if (virNetDevGetPhysicalFunction(linkdev, &pfdevname) < 0)
            goto cleanup;
        if (virNetDevGetVirtualFunctionIndex(pfdevname, linkdev, &vf) < 0)
            goto cleanup;
        linkdev = pfdevname;
    }

    if (vf == -1)
        ret = virNetDevReplaceMacAddress(linkdev, macaddress, stateDir);
    else
        ret = virNetDevReplaceVfConfig(linkdev, vf, macaddress, vlanid,
                                       stateDir);

 cleanup:
    VIR_FREE(pfdevname);
    return ret;
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
    int ret = -1;
    char *pfdevname = NULL;
    const char *vfdevname = NULL;

    if (vf == -1 && virNetDevIsVirtualFunction(linkdev) == 1) {
        /* If this really *is* a VF and the caller just didn't know
         * it, we should set the MAC address via PF+vf# instead of
         * setting directly via VF, because the latter will be
         * rejected any time after the former has been done.
         */
        if (virNetDevGetPhysicalFunction(linkdev, &pfdevname) < 0)
            goto cleanup;
        if (virNetDevGetVirtualFunctionIndex(pfdevname, linkdev, &vf) < 0)
            goto cleanup;
        vfdevname = linkdev;
        linkdev = pfdevname;
    }

    if (vf == -1)
        ret = virNetDevRestoreMacAddress(linkdev, stateDir);
    else
        ret = virNetDevRestoreVfConfig(linkdev, vf, vfdevname, stateDir);

 cleanup:
    VIR_FREE(pfdevname);
    return ret;
}

#else /* defined(__linux__) && defined(HAVE_LIBNL) */

int
virNetDevLinkDump(const char *ifname ATTRIBUTE_UNUSED,
                  int ifindex ATTRIBUTE_UNUSED,
                  void **nlData ATTRIBUTE_UNUSED,
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

#ifdef __linux__
int
virNetDevGetLinkInfo(const char *ifname,
                     virInterfaceLinkPtr lnk)
{
    int ret = -1;
    char *path = NULL;
    char *buf = NULL;
    char *tmp;
    int tmp_state;
    unsigned int tmp_speed;

    if (virNetDevSysfsFile(&path, ifname, "operstate") < 0)
        goto cleanup;

    if (virFileReadAll(path, 1024, &buf) < 0) {
        virReportSystemError(errno,
                             _("unable to read: %s"),
                             path);
        goto cleanup;
    }

    if (!(tmp = strchr(buf, '\n'))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse: %s"),
                       buf);
        goto cleanup;
    }

    *tmp = '\0';

    /* We shouldn't allow 0 here, because
     * virInterfaceState enum starts from 1. */
    if ((tmp_state = virInterfaceStateTypeFromString(buf)) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse: %s"),
                       buf);
        goto cleanup;
    }

    lnk->state = tmp_state;

    /* Shortcut to avoid some kernel issues. If link is not up several drivers
     * report several misleading values. While igb reports 65535, realtek goes
     * with 10. To avoid muddying XML with insane values, don't report link
     * speed if that's the case. */
    if (lnk->state != VIR_INTERFACE_STATE_UP) {
        lnk->speed = 0;
        ret = 0;
        goto cleanup;
    }

    VIR_FREE(path);
    VIR_FREE(buf);

    if (virNetDevSysfsFile(&path, ifname, "speed") < 0)
        goto cleanup;

    if (virFileReadAllQuiet(path, 1024, &buf) < 0) {
        /* Some devices doesn't report speed, in which case we get EINVAL */
        if (errno == EINVAL) {
            ret = 0;
            goto cleanup;
        }
        virReportSystemError(errno,
                             _("unable to read: %s"),
                             path);
        goto cleanup;
    }

    if (virStrToLong_ui(buf, &tmp, 10, &tmp_speed) < 0 ||
        *tmp != '\n') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse: %s"),
                       buf);
        goto cleanup;
    }

    lnk->speed = tmp_speed;

    ret = 0;
 cleanup:
    VIR_FREE(buf);
    VIR_FREE(path);
    return ret;
}

#else

int
virNetDevGetLinkInfo(const char *ifname,
                     virInterfaceLinkPtr lnk)
{
    /* Port me */
    VIR_DEBUG("Getting link info on %s is not implemented on this platform",
              ifname);
    lnk->speed = lnk->state = 0;
    return 0;
}
#endif /* defined(__linux__) */


#if defined(SIOCADDMULTI) && defined(HAVE_STRUCT_IFREQ) && \
    defined(HAVE_STRUCT_IFREQ_IFR_HWADDR)
/**
 * virNetDevAddMulti:
 * @ifname: interface name to which to add multicast MAC address
 * @macaddr: MAC address
 *
 * This function adds the @macaddr to the multicast list for a given interface
 * @ifname.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevAddMulti(const char *ifname,
                      virMacAddrPtr macaddr)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
    virMacAddrGetRaw(macaddr, (unsigned char *)ifr.ifr_hwaddr.sa_data);

    if (ioctl(fd, SIOCADDMULTI, &ifr) < 0) {
        char macstr[VIR_MAC_STRING_BUFLEN];
        virReportSystemError(errno,
                             _("Cannot add multicast MAC %s on '%s' interface"),
                             virMacAddrFormat(macaddr, macstr), ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#else
int virNetDevAddMulti(const char *ifname ATTRIBUTE_UNUSED,
                      virMacAddrPtr macaddr ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to add address to interface "
                           "multicast list on this platform"));
    return -1;
}
#endif

#if defined(SIOCDELMULTI) && defined(HAVE_STRUCT_IFREQ) && \
    defined(HAVE_STRUCT_IFREQ_IFR_HWADDR)
/**
 * virNetDevDelMulti:
 * @ifname: interface name from which to delete the multicast MAC address
 * @macaddr: MAC address
 *
 * This function deletes the @macaddr from the multicast list for a given
 * interface @ifname.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevDelMulti(const char *ifname,
                      virMacAddrPtr macaddr)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
    virMacAddrGetRaw(macaddr, (unsigned char *)ifr.ifr_hwaddr.sa_data);

    if (ioctl(fd, SIOCDELMULTI, &ifr) < 0) {
        char macstr[VIR_MAC_STRING_BUFLEN];
        virReportSystemError(errno,
                             _("Cannot add multicast MAC %s on '%s' interface"),
                             virMacAddrFormat(macaddr, macstr), ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}
#else
int virNetDevDelMulti(const char *ifname ATTRIBUTE_UNUSED,
                      virMacAddrPtr macaddr ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to delete address from interface "
                           "multicast list on this platform"));
    return -1;
}
#endif

static int virNetDevParseMcast(char *buf, virNetDevMcastEntryPtr mcast)
{
    int ifindex;
    int num;
    char *next;
    char *token;
    char *saveptr;
    char *endptr;

    for (ifindex = VIR_MCAST_TYPE_INDEX_TOKEN, next = buf; ifindex < VIR_MCAST_TYPE_LAST; ifindex++,
         next = NULL) {
        token = strtok_r(next, VIR_MCAST_TOKEN_DELIMS, &saveptr);

        if (token == NULL) {
            virReportSystemError(EINVAL,
                                 _("failed to parse multicast address from '%s'"),
                                 buf);
            return -1;
        }

        switch ((virMCastType)ifindex) {
            case VIR_MCAST_TYPE_INDEX_TOKEN:
                if (virStrToLong_i(token, &endptr, 10, &num) < 0) {
                    virReportSystemError(EINVAL,
                                         _("Failed to parse interface index from '%s'"),
                                         buf);
                    return -1;

                }
                mcast->idx = num;
                break;
            case VIR_MCAST_TYPE_NAME_TOKEN:
                if (virStrncpy(mcast->name, token, strlen(token),
                    VIR_MCAST_NAME_LEN) == NULL) {
                    virReportSystemError(EINVAL,
                                         _("Failed to parse network device name from '%s'"),
                                         buf);
                    return -1;
                }
                break;
            case VIR_MCAST_TYPE_USERS_TOKEN:
                if (virStrToLong_i(token, &endptr, 10, &num) < 0) {
                    virReportSystemError(EINVAL,
                                         _("Failed to parse users from '%s'"),
                                         buf);
                    return -1;

                }
                mcast->users = num;
                break;
            case VIR_MCAST_TYPE_GLOBAL_TOKEN:
                if (virStrToLong_i(token, &endptr, 10, &num) < 0) {
                    virReportSystemError(EINVAL,
                                         _("Failed to parse users from '%s'"),
                                         buf);
                    return -1;

                }
                mcast->global = num;
                break;
            case VIR_MCAST_TYPE_ADDR_TOKEN:
                if (virMacAddrParseHex((const char*)token,
                    &mcast->macaddr) < 0) {
                    virReportSystemError(EINVAL,
                                         _("Failed to parse MAC address from '%s'"),
                                         buf);
                }
                break;

            /* coverity[dead_error_begin] */
            case VIR_MCAST_TYPE_LAST:
                break;
        }
    }
    return 0;
}


static void virNetDevMcastListClear(virNetDevMcastListPtr mcast)
{
    size_t i;

    for (i = 0; i < mcast->nentries; i++)
       VIR_FREE(mcast->entries[i]);
    VIR_FREE(mcast->entries);
    mcast->nentries = 0;
}


static int virNetDevGetMcastList(const char *ifname,
                                 virNetDevMcastListPtr mcast)
{
    char *cur = NULL;
    char *buf = NULL;
    char *next = NULL;
    int ret = -1, len;
    virNetDevMcastEntryPtr entry = NULL;

    mcast->entries = NULL;
    mcast->nentries = 0;

    /* Read entire multicast table into memory */
    if ((len = virFileReadAll(PROC_NET_DEV_MCAST, MAX_MCAST_SIZE, &buf)) <= 0)
        goto cleanup;

    cur = buf;
    while (cur) {
        if (!entry && VIR_ALLOC(entry) < 0)
                goto cleanup;

        next = strchr(cur, '\n');
        if (next)
            next++;
        if (virNetDevParseMcast(cur, entry))
            goto cleanup;

        /* Only return global multicast MAC addresses for
         * specified interface */
        if (entry->global && STREQ(ifname, entry->name)) {
            if (VIR_APPEND_ELEMENT(mcast->entries, mcast->nentries, entry))
                 goto cleanup;
        } else {
            memset(entry, 0, sizeof(virNetDevMcastEntry));
        }
        cur = next && ((next - buf) < len) ? next : NULL;
    }

    ret = 0;
 cleanup:
    VIR_FREE(buf);
    VIR_FREE(entry);

    return ret;
}


VIR_ENUM_IMPL(virNetDevRxFilterMode,
              VIR_NETDEV_RX_FILTER_MODE_LAST,
              "none",
              "normal",
              "all");


static int virNetDevGetMulticastTable(const char *ifname,
                                      virNetDevRxFilterPtr filter)
{
    size_t i;
    int ret = -1;
    virNetDevMcastList mcast;
    filter->multicast.nTable = 0;
    filter->multicast.table = NULL;

    if (virNetDevGetMcastList(ifname, &mcast) < 0)
        goto cleanup;

    if (mcast.nentries > 0) {
        if (VIR_ALLOC_N(filter->multicast.table, mcast.nentries) < 0)
            goto cleanup;

        for (i = 0; i < mcast.nentries; i++) {
            virMacAddrSet(&filter->multicast.table[i],
                          &mcast.entries[i]->macaddr);
        }

        filter->multicast.nTable = mcast.nentries;
    }

    ret = 0;

 cleanup:
    virNetDevMcastListClear(&mcast);
    return ret;
}


virNetDevRxFilterPtr
virNetDevRxFilterNew(void)
{
    virNetDevRxFilterPtr filter;

    if (VIR_ALLOC(filter) < 0)
        return NULL;
    return filter;
}


void
virNetDevRxFilterFree(virNetDevRxFilterPtr filter)
{
    if (filter) {
        VIR_FREE(filter->name);
        VIR_FREE(filter->unicast.table);
        VIR_FREE(filter->multicast.table);
        VIR_FREE(filter->vlan.table);
        VIR_FREE(filter);
    }
}


/**
 * virNetDevGetRxFilter:
 * This function supplies the RX filter list for a given device interface
 *
 * @ifname: Name of the interface
 * @filter: The RX filter list
 *
 * Returns 0 or -1 on failure.
 */
int virNetDevGetRxFilter(const char *ifname,
                         virNetDevRxFilterPtr *filter)
{
    int ret = -1;
    bool receive = false;
    virNetDevRxFilterPtr fil = virNetDevRxFilterNew();

    if (!fil)
        goto cleanup;

    if (virNetDevGetMAC(ifname, &fil->mac))
        goto cleanup;

    if (virNetDevGetMulticastTable(ifname, fil))
        goto cleanup;

    if (virNetDevGetPromiscuous(ifname, &fil->promiscuous))
        goto cleanup;

    if (virNetDevGetRcvAllMulti(ifname, &receive))
        goto cleanup;

    if (receive) {
        fil->multicast.mode = VIR_NETDEV_RX_FILTER_MODE_ALL;
    } else {
        if (virNetDevGetRcvMulti(ifname, &receive))
            goto cleanup;

        if (receive)
            fil->multicast.mode = VIR_NETDEV_RX_FILTER_MODE_NORMAL;
        else
            fil->multicast.mode = VIR_NETDEV_RX_FILTER_MODE_NONE;
    }

    ret = 0;
 cleanup:
    if (ret < 0) {
        virNetDevRxFilterFree(fil);
        fil = NULL;
    }

    *filter = fil;
    return ret;
}

#if defined(SIOCETHTOOL) && defined(HAVE_STRUCT_IFREQ)

/**
 * virNetDevRDMAFeature
 * This function checks for the availability of RDMA feature
 * and add it to bitmap
 *
 * @ifname: name of the interface
 * @out: add RDMA feature if exist to bitmap
 *
 * Returns 0 on success, -1 on failure.
 */
static int
virNetDevRDMAFeature(const char *ifname,
                     virBitmapPtr *out)
{
    char *eth_devpath = NULL;
    char *ib_devpath = NULL;
    char *eth_res_buf = NULL;
    char *ib_res_buf = NULL;
    DIR *dirp = NULL;
    struct dirent *dp;
    int ret = -1;

    if (!virFileExists(SYSFS_INFINIBAND_DIR))
        return 0;

    if (!(dirp = opendir(SYSFS_INFINIBAND_DIR))) {
        virReportSystemError(errno,
                             _("Failed to opendir path '%s'"),
                             SYSFS_INFINIBAND_DIR);
        return -1;
    }

    if (virAsprintf(&eth_devpath, SYSFS_NET_DIR "%s/device/resource", ifname) < 0)
        goto cleanup;
    if (!virFileExists(eth_devpath))
        goto cleanup;
    if (virFileReadAll(eth_devpath, RESOURCE_FILE_LEN, &eth_res_buf) < 0)
        goto cleanup;

    while (virDirRead(dirp, &dp, SYSFS_INFINIBAND_DIR) > 0) {
        if (dp->d_name[0] == '.')
            continue;
        if (virAsprintf(&ib_devpath, SYSFS_INFINIBAND_DIR "%s/device/resource",
                        dp->d_name) < 0)
            continue;
        if (virFileReadAll(ib_devpath, RESOURCE_FILE_LEN, &ib_res_buf) > 0 &&
            STREQ(eth_res_buf, ib_res_buf)) {
            ignore_value(virBitmapSetBit(*out, VIR_NET_DEV_FEAT_RDMA));
            break;
        }
        VIR_FREE(ib_devpath);
        VIR_FREE(ib_res_buf);
    }
    ret = 0;

 cleanup:
    closedir(dirp);
    VIR_FREE(eth_devpath);
    VIR_FREE(ib_devpath);
    VIR_FREE(eth_res_buf);
    VIR_FREE(ib_res_buf);
    return ret;
}


/**
 * virNetDevSendEthtoolIoctl
 * This function sends ethtool ioctl request
 *
 * @ifname: name of the interface
 * @cmd: reference to an ethtool command structure
 *
 * Returns 0 on success, -1 on failure.
 */
static int
virNetDevSendEthtoolIoctl(const char *ifname, void *cmd)
{
    int ret = -1;
    int fd = -1;
    struct ifreq ifr;

    /* Ultimately uses AF_PACKET for socket which requires privileged
     * daemon support.
     */
    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return ret;

    ifr.ifr_data = cmd;
    ret = ioctl(fd, SIOCETHTOOL, &ifr);
    if (ret != 0) {
        switch (errno) {
            case EINVAL: /* kernel doesn't support SIOCETHTOOL */
                VIR_DEBUG("ethtool ioctl: invalid request");
                break;
            case EOPNOTSUPP: /* kernel doesn't support specific feature */
                VIR_DEBUG("ethtool ioctl: request not supported");
                break;
            default:
                virReportSystemError(errno, "%s", _("ethtool ioctl error"));
                goto cleanup;
        }
    }

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


/**
* virNetDevFeatureAvailable
* This function checks for the availability of a network device feature
*
* @ifname: name of the interface
* @cmd: reference to an ethtool command structure
*
* Returns 0 if not found, 1 on success, and -1 on failure.
*/
static int
virNetDevFeatureAvailable(const char *ifname, struct ethtool_value *cmd)
{
    int ret = -1;

    cmd = (void*)cmd;
    if (!virNetDevSendEthtoolIoctl(ifname, cmd))
        ret = cmd->data > 0 ? 1 : 0;
    return ret;
}


# if HAVE_DECL_ETHTOOL_GFEATURES
/**
 * virNetDevGFeatureAvailable
 * This function checks for the availability of a network device gfeature
 *
 * @ifname: name of the interface
 * @cmd: reference to a gfeatures ethtool command structure
 *
 * Returns 0 if not found, 1 on success, and -1 on failure.
 */
static int
virNetDevGFeatureAvailable(const char *ifname, struct ethtool_gfeatures *cmd)
{
    int ret = -1;

    cmd = (void*)cmd;
    if (!virNetDevSendEthtoolIoctl(ifname, cmd))
        ret = FEATURE_BIT_IS_SET(cmd->features, TX_UDP_TNL, active);
    return ret;
}
# endif


/**
 * virNetDevGetFeatures:
 * This function gets the nic offloads features available for ifname
 *
 * @ifname: name of the interface
 * @out: bitmap of the available virNetDevFeature feature bits
 *
 * Returns 0 on success or if called from session mode, -1 on failure.
 * If called from session mode, an empty bitmap is returned.
 */
int
virNetDevGetFeatures(const char *ifname,
                     virBitmapPtr *out)
{
    size_t i = -1;
    struct ethtool_value cmd = { 0 };
# if HAVE_DECL_ETHTOOL_GFEATURES
    struct ethtool_gfeatures *g_cmd;
# endif
    struct elem{
        const int cmd;
        const virNetDevFeature feat;
    };
    /* legacy ethtool getters */
    struct elem cmds[] = {
        {ETHTOOL_GRXCSUM, VIR_NET_DEV_FEAT_GRXCSUM},
        {ETHTOOL_GTXCSUM, VIR_NET_DEV_FEAT_GTXCSUM},
        {ETHTOOL_GSG, VIR_NET_DEV_FEAT_GSG},
        {ETHTOOL_GTSO, VIR_NET_DEV_FEAT_GTSO},
# if HAVE_DECL_ETHTOOL_GGSO
        {ETHTOOL_GGSO, VIR_NET_DEV_FEAT_GGSO},
# endif
# if HAVE_DECL_ETHTOOL_GGRO
        {ETHTOOL_GGRO, VIR_NET_DEV_FEAT_GGRO},
# endif
    };

    if (!(*out = virBitmapNew(VIR_NET_DEV_FEAT_LAST)))
        return -1;

    /* Only fetch features if we're privileged, but no need to fail */
    if (geteuid() != 0) {
        VIR_DEBUG("ETHTOOL feature bits not available in session mode");
        return 0;
    }

    for (i = 0; i < ARRAY_CARDINALITY(cmds); i++) {
        cmd.cmd = cmds[i].cmd;
        if (virNetDevFeatureAvailable(ifname, &cmd) == 1)
            ignore_value(virBitmapSetBit(*out, cmds[i].feat));
    }

# if HAVE_DECL_ETHTOOL_GFLAGS
    size_t j = -1;
    /* ethtool masks */
    struct elem flags[] = {
#  if HAVE_DECL_ETH_FLAG_LRO
        {ETH_FLAG_LRO, VIR_NET_DEV_FEAT_LRO},
#  endif
#  if HAVE_DECL_ETH_FLAG_TXVLAN
        {ETH_FLAG_RXVLAN, VIR_NET_DEV_FEAT_RXVLAN},
        {ETH_FLAG_TXVLAN, VIR_NET_DEV_FEAT_TXVLAN},
#  endif
#  if HAVE_DECL_ETH_FLAG_NTUBLE
        {ETH_FLAG_NTUPLE, VIR_NET_DEV_FEAT_NTUPLE},
#  endif
#  if HAVE_DECL_ETH_FLAG_RXHASH
        {ETH_FLAG_RXHASH, VIR_NET_DEV_FEAT_RXHASH},
#  endif
    };

    cmd.cmd = ETHTOOL_GFLAGS;
    if (virNetDevFeatureAvailable(ifname, &cmd) == 1) {
        for (j = 0; j < ARRAY_CARDINALITY(flags); j++) {
            if (cmd.data & flags[j].cmd)
                ignore_value(virBitmapSetBit(*out, flags[j].feat));
        }
    }
# endif

# if HAVE_DECL_ETHTOOL_GFEATURES
    if (VIR_ALLOC_VAR(g_cmd,
                      struct ethtool_get_features_block, GFEATURES_SIZE) < 0)
        return -1;
    g_cmd->cmd = ETHTOOL_GFEATURES;
    g_cmd->size = GFEATURES_SIZE;
    if (virNetDevGFeatureAvailable(ifname, g_cmd) == 1)
        ignore_value(virBitmapSetBit(*out, VIR_NET_DEV_FEAT_TXUDPTNL));
    VIR_FREE(g_cmd);
# endif

    if (virNetDevRDMAFeature(ifname, out) < 0)
        return -1;
    return 0;
}
#else
int
virNetDevGetFeatures(const char *ifname ATTRIBUTE_UNUSED,
                     virBitmapPtr *out ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("Getting network device features on %s is not implemented on this platform",
              ifname);
    return 0;
}
#endif
