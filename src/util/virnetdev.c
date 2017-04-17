/*
 * Copyright (C) 2007-2016 Red Hat, Inc.
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
#include "virnetlink.h"
#include "virmacaddr.h"
#include "virfile.h"
#include "virerror.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virpci.h"
#include "virlog.h"
#include "virstring.h"
#include "virutil.h"
#include "virjson.h"

#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>

#ifdef __linux__
# include <linux/sockios.h>
# include <linux/if_vlan.h>
# define VIR_NETDEV_FAMILY AF_UNIX
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
 * virNetDevSetMACInternal:
 * @ifname: interface name to set MTU for
 * @macaddr: MAC address
 * @quiet: true if a failure to set MAC address with
 *         errno == EADDRNOTAVAIL || errno == EPERM
 *         should be silent (still returns error, but without log)
 *
 * This function sets the @macaddr for a given interface @ifname.
 *
 * Returns 0 in case of success or -1 on failure
 */
static int
virNetDevSetMACInternal(const char *ifname,
                        const virMacAddr *macaddr,
                        bool quiet)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;
    char macstr[VIR_MAC_STRING_BUFLEN];

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

        if (quiet &&
            (errno == EADDRNOTAVAIL || errno == EPERM))
            goto cleanup;

        virReportSystemError(errno,
                             _("Cannot set interface MAC to %s on '%s'"),
                             virMacAddrFormat(macaddr, macstr), ifname);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_DEBUG("SIOCSIFHWADDR %s MAC=%s - %s",
              ifname, virMacAddrFormat(macaddr, macstr),
              ret < 0 ? "Fail" : "Success");

    VIR_FORCE_CLOSE(fd);
    return ret;
}


#elif defined(SIOCSIFLLADDR) && defined(HAVE_STRUCT_IFREQ) &&   \
    HAVE_DECL_LINK_ADDR


static int
virNetDevSetMACInternal(const char *ifname,
                        const virMacAddr *macaddr,
                        bool quiet)
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
            if (quiet &&
                (errno == EADDRNOTAVAIL || errno == EPERM))
                goto cleanup;

            virReportSystemError(errno,
                                 _("Cannot set interface MAC to %s on '%s'"),
                                 mac + 1, ifname);
            goto cleanup;
        }

        ret = 0;
 cleanup:
        VIR_DEBUG("SIOCSIFLLADDR %s MAC=%s - %s", ifname, mac + 1,
                  ret < 0 ? "Fail" : "Success");

        VIR_FORCE_CLOSE(s);

        return ret;
}


#else


static int
virNetDevSetMACInternal(const char *ifname,
                        const virMacAddr *macaddr ATTRIBUTE_UNUSED,
                        bool quiet ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot set interface MAC on '%s'"),
                         ifname);
    return -1;
}


#endif


int
virNetDevSetMAC(const char *ifname,
                const virMacAddr *macaddr)
{
    return virNetDevSetMACInternal(ifname, macaddr, false);
}


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

#if defined(HAVE_IF_INDEXTONAME)
char *virNetDevGetName(int ifindex)
{
    char name[IFNAMSIZ];
    char *ifname = NULL;

    memset(&name, 0, sizeof(name));

    if (!if_indextoname(ifindex, name)) {
        virReportSystemError(errno,
                             _("Failed to convert interface index %d to a name"),
                             ifindex);
        goto cleanup;
    }

   ignore_value(VIR_STRDUP(ifname, name));

 cleanup:
     return ifname;
}
#else
char *virNetDevGetName(int ifindex)
{
    virReportSystemError(ENOSYS,
                         _("Cannot get interface name for index '%i'"),
                         ifindex);
    return NULL;
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


#if defined(__linux__) && defined(HAVE_LIBNL)
/**
 * virNetDevGetMaster:
 * @ifname: name of interface we're interested in
 * @master: used to return a string containing the name of @ifname's "master"
 *          (this is the bridge or bond device that this device is attached to)
 *
 * Returns 0 on success, -1 on failure (if @ifname has no master
 * @master will be NULL, but return value will still be 0 (success)).
 */
int
virNetDevGetMaster(const char *ifname, char **master)
{
    int ret = -1;
    void *nlData = NULL;
    struct nlattr *tb[IFLA_MAX + 1] = {NULL, };

    *master = NULL;

    if (virNetlinkDumpLink(ifname, -1, &nlData, tb, 0, 0) < 0)
        goto cleanup;

    if (tb[IFLA_MASTER]) {
        if (!(*master = virNetDevGetName(*(int *)RTA_DATA(tb[IFLA_MASTER]))))
            goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(nlData);
    return ret;
}


#else


int
virNetDevGetMaster(const char *ifname ATTRIBUTE_UNUSED,
                   char **master ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Unable to get device master from netlink on this platform"));
    return -1;
}


#endif /* defined(__linux__) && defined(HAVE_LIBNL) */


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


static virPCIDevicePtr
virNetDevGetPCIDevice(const char *devName)
{
    char *vfSysfsDevicePath = NULL;
    virPCIDeviceAddressPtr vfPCIAddr = NULL;
    virPCIDevicePtr vfPCIDevice = NULL;

    if (virNetDevSysfsFile(&vfSysfsDevicePath, devName, "device") < 0)
        goto cleanup;

    vfPCIAddr = virPCIGetDeviceAddressFromSysfsLink(vfSysfsDevicePath);
    if (!vfPCIAddr)
        goto cleanup;

    vfPCIDevice = virPCIDeviceNew(vfPCIAddr->domain, vfPCIAddr->bus,
                                  vfPCIAddr->slot, vfPCIAddr->function);

 cleanup:
    VIR_FREE(vfSysfsDevicePath);
    VIR_FREE(vfPCIAddr);

    return vfPCIDevice;
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
            goto cleanup;

        if (!(*vfname)[i])
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

    if (virPCIGetNetName(physfn_sysfs_path, pfname) < 0)
        goto cleanup;

    if (!*pfname) {
        /* this shouldn't be possible. A VF can't exist unless its
         * PF device is bound to a network driver
         */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("The PF device for VF %s has no network device name"),
                       ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(physfn_sysfs_path);
    return ret;
}


/**
 * virNetDevPFGetVF:
 *
 * @pfname: netdev name of the physical function (PF)
 * @vf: virtual function (VF) number for the device of interest
 * @vfname: name of the physical function interface name
 *
 * Finds the netdev name of VF# @vf of SRIOV PF @pfname, and puts it
 * in @vfname. The caller must free @vfname when it's finished with
 * it.
 *
 * Returns 0 on success, -1 on failure
 *
 * NB: if the VF has no netdev name, that is *not* considered an
 * error; *vfname simply gets a NULL and the return value is 0
 * (success).
 */
int
virNetDevPFGetVF(const char *pfname, int vf, char **vfname)
{
    char *virtfnName = NULL;
    char *virtfnSysfsPath = NULL;
    int ret = -1;

    if (virAsprintf(&virtfnName, "virtfn%d", vf) < 0)
        goto cleanup;

    /* this provides the path to the VF's directory in sysfs,
     * e.g. "/sys/class/net/enp2s0f0/virtfn3"
     */
    if (virNetDevSysfsDeviceFile(&virtfnSysfsPath, pfname, virtfnName) < 0)
        goto cleanup;

    /* and this gets the netdev name associated with it, which is a
     * directory entry in [virtfnSysfsPath]/net,
     * e.g. "/sys/class/net/enp2s0f0/virtfn3/net/enp2s11f4" - in this
     * example the VF for enp2s0f0 vf#3 is "enp2s11f4". (If the VF
     * isn't bound to a netdev driver, it won't have a netdev name,
     * and vfname will be NULL).
     */
    ret = virPCIGetNetName(virtfnSysfsPath, vfname);

 cleanup:
    VIR_FREE(virtfnName);
    VIR_FREE(virtfnSysfsPath);

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
virNetDevPFGetVF(const char *pfname ATTRIBUTE_UNUSED,
                 int vf ATTRIBUTE_UNUSED,
                 char **vfname ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get virtual function name on this platform"));
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


static virMacAddr zeroMAC = { .addr = { 0, 0, 0, 0, 0, 0 } };

/* if a net driver doesn't allow setting MAC to all 0, try setting
 * to this (the only bit that is set is the "locally administered" bit")
 */
static virMacAddr altZeroMAC = { .addr = { 2, 0, 0, 0, 0, 0 } };


static struct nla_policy ifla_vf_policy[IFLA_VF_MAX+1] = {
    [IFLA_VF_MAC]       = { .type = NLA_UNSPEC,
                            .maxlen = sizeof(struct ifla_vf_mac) },
    [IFLA_VF_VLAN]      = { .type = NLA_UNSPEC,
                            .maxlen = sizeof(struct ifla_vf_vlan) },
};


static int
virNetDevSetVfConfig(const char *ifname, int vf,
                     const virMacAddr *macaddr, int vlanid,
                     bool *allowRetry)
{
    int rc = -1;
    char macstr[VIR_MAC_STRING_BUFLEN];
    struct nlmsghdr *resp = NULL;
    struct nlmsgerr *err;
    unsigned int recvbuflen = 0;
    struct nl_msg *nl_msg;
    struct nlattr *vfinfolist, *vfinfo;
    struct ifinfomsg ifinfo = {
        .ifi_family = AF_UNSPEC,
        .ifi_index  = -1,
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

    if (virNetlinkCommand(nl_msg, &resp, &recvbuflen, 0, 0,
                          NETLINK_ROUTE, 0) < 0)
        goto cleanup;

    if (recvbuflen < NLMSG_LENGTH(0) || resp == NULL)
        goto malformed_resp;

    switch (resp->nlmsg_type) {
    case NLMSG_ERROR:
        err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (resp->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
            goto malformed_resp;

        /* if allowRetry is true and the error was EINVAL, then
         * silently return a failure so the caller can retry with a
         * different MAC address
         */
        if (err->error == -EINVAL && *allowRetry &&
            macaddr && !virMacAddrCmp(macaddr, &zeroMAC)) {
            goto cleanup;
        } else if (err->error) {
            /* other errors are permanent */
            virReportSystemError(-err->error,
                                 _("Cannot set interface MAC/vlanid to %s/%d "
                                   "for ifname %s vf %d"),
                                 (macaddr
                                  ? virMacAddrFormat(macaddr, macstr)
                                  : "(unchanged)"),
                                 vlanid,
                                 ifname ? ifname : "(unspecified)",
                                 vf);
            *allowRetry = false; /* no use retrying */
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
    VIR_DEBUG("RTM_SETLINK %s vf %d MAC=%s vlanid=%d - %s",
              ifname, vf,
              macaddr ? virMacAddrFormat(macaddr, macstr) : "(unchanged)",
              vlanid, rc < 0 ? "Fail" : "Success");

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

        if (mac && tb[IFLA_VF_MAC]) {
            vf_mac = RTA_DATA(tb_vf[IFLA_VF_MAC]);
            if (vf_mac && vf_mac->vf == vf)  {
                virMacAddrSetRaw(mac, vf_mac->mac);
                rc = 0;
            }
        }

        if (vlanid && tb[IFLA_VF_VLAN]) {
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

    rc = virNetlinkDumpLink(ifname, ifindex, &nlData, tb, 0, 0);
    if (rc < 0)
        goto cleanup;

    rc = virNetDevParseVfConfig(tb, vf, mac, vlanid);

 cleanup:
    VIR_FREE(nlData);
    return rc;
}


# define VIR_NETDEV_KEYNAME_ADMIN_MAC "adminMac"
# define VIR_NETDEV_KEYNAME_VLAN_TAG "vlanTag"
# define VIR_NETDEV_KEYNAME_MAC "mac"

/**
 * virNetDevSaveNetConfig:
 * @linkdev: name of the interface
 * @vf: vf index if linkdev is a pf
 * @stateDir: directory to store old net config
 * @saveVlan: false if we shouldn't attempt to save vlan tag info
 *            (eg for interfaces using 802.1Qbg, since it handles
 *            vlan tags internally)
 *
 * Save current MAC address and (if linkdev itself is a VF, or if @vf
 * >= 0) the "admin MAC address" and vlan tag the device described by
 * @linkdev:@vf to @stateDir. (the "admin MAC address" is stored in
 * the PF, and is what the VF MAC will be initialized to the next time
 * its driver is reloaded (either on host or guest).
 *
 * File Format:
 *
 * The file is in json format and will contain 1 or more of the
 * following values:
 *
 *      "mac"      - VF MAC address (or missing if VF has no host net driver)
 *      "vlanTag"  - a single vlan tag id
 *      "adminMac" - admin MAC address (stored in the PF)
 *
 * For example:
 *
 *    {"mac": "9A:11:22:33:44:55",
 *     "vlanTag": "42",
 *     "adminMac": "00:00:00:00:00:00"
 *    }
 *
 * File Name:
 *
 * If the device is a VF and we're allowed to save vlan tag info, the
 * file will be named ${pfDevName_vf#{vf} (e.g. "enp2s0f0_vf5") and
 * will contain at least "adminMac" and "vlanTag" (if the device was bound
 * to a net driver on the host prior to use, it will also have "mac"..
 * If the device isn't a VF, or we're not allowed to save vlan tag
 * info, the file will be named ${linkdev} (e.g. "enp3s0f0") and will
 * contain just linkdev's MAC address.
 *
 * Returns 0 on success, -1 on failure
 *
 */
int
virNetDevSaveNetConfig(const char *linkdev, int vf,
                       const char *stateDir,
                       bool saveVlan)
{
    int ret = -1;
    const char *pfDevName = NULL;
    char *pfDevOrig = NULL;
    char *vfDevOrig = NULL;
    virMacAddr oldMAC;
    char MACStr[VIR_MAC_STRING_BUFLEN];
    int oldVlanTag = -1;
    char *filePath = NULL;
    char *fileStr = NULL;
    virJSONValuePtr configJSON = NULL;

    if (vf >= 0) {
        /* linkdev is the PF */
        pfDevName = linkdev;

        /* linkdev should get the VF's netdev name (or NULL if none) */
        if (virNetDevPFGetVF(pfDevName, vf, &vfDevOrig) < 0)
            goto cleanup;

        linkdev = vfDevOrig;

    } else if (saveVlan && virNetDevIsVirtualFunction(linkdev) == 1) {
        /* when vf is -1, linkdev might be a standard netdevice (not
         * SRIOV), or it might be an SRIOV VF. If it's a VF, normalize
         * it to PF + VFname
         */

        if (virNetDevGetPhysicalFunction(linkdev, &pfDevOrig) < 0)
            goto cleanup;

        pfDevName = pfDevOrig;

        if (virNetDevGetVirtualFunctionIndex(pfDevName, linkdev, &vf) < 0)
            goto cleanup;
    }

    if (!(configJSON = virJSONValueNewObject()))
        goto cleanup;

    /* if there is a PF, it's now in pfDevName, and linkdev is either
     * the VF's name, or NULL (if the VF isn't bound to a net driver
     * on the host)
     */

    if (pfDevName) {
        if (virAsprintf(&filePath, "%s/%s_vf%d", stateDir, pfDevName, vf) < 0)
            goto cleanup;

        /* get admin MAC and vlan tag */
        if (virNetDevGetVfConfig(pfDevName, vf, &oldMAC,
                                 saveVlan ? &oldVlanTag : NULL) < 0) {
            goto cleanup;
        }

        if (virJSONValueObjectAppendString(configJSON,
                                           VIR_NETDEV_KEYNAME_ADMIN_MAC,
                                           virMacAddrFormat(&oldMAC, MACStr)) < 0 ||
            virJSONValueObjectAppendNumberInt(configJSON,
                                              VIR_NETDEV_KEYNAME_VLAN_TAG,
                                              oldVlanTag) < 0) {
            goto cleanup;
        }

    } else {
        if (virAsprintf(&filePath, "%s/%s", stateDir, linkdev) < 0)
            goto cleanup;
    }

    if (linkdev) {
        if (virNetDevGetMAC(linkdev, &oldMAC) < 0)
            goto cleanup;

        /* for interfaces with no pfDevName (i.e. not a VF, this will
         * be the only value in the file.
         */
        if (virJSONValueObjectAppendString(configJSON, VIR_NETDEV_KEYNAME_MAC,
                                           virMacAddrFormat(&oldMAC, MACStr)) < 0)
           goto cleanup;
    }

    if (!(fileStr = virJSONValueToString(configJSON, true)))
        goto cleanup;

    if (virFileWriteStr(filePath, fileStr, O_CREAT|O_TRUNC|O_WRONLY) < 0) {
        virReportSystemError(errno, _("Unable to preserve mac/vlan tag "
                                      "for device = %s, vf = %d"), linkdev, vf);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(pfDevOrig);
    VIR_FREE(vfDevOrig);
    VIR_FREE(filePath);
    VIR_FREE(fileStr);
    virJSONValueFree(configJSON);
    return ret;
}


/**
 * virNetDevReadNetConfig:
 * @linkdev: name of the interface
 * @vf: vf index if linkdev is a pf
 * @stateDir: directory where net config is stored
 * @adminMAC: returns admin MAC to store in the PF (if this is a VF)
 * @MAC: returns MAC to set on device immediately
 *
 * Read saved MAC address and (if linkdev itself is a VF, or if @vf >=
 * 0) "admin MAC address" and vlan tag of the device described by
 * @linkdev:@vf from a file in @stateDir. (see virNetDevSaveNetConfig
 * for details of file name and format).
 *
 * Returns 0 on success, -1 on failure.
 *
 * The caller MUST free adminMAC, vlan, and MAC when it is finished
 * with them (they will be NULL if they weren't found in the file)
 *
 */
int
virNetDevReadNetConfig(const char *linkdev, int vf,
                       const char *stateDir,
                       virMacAddrPtr *adminMAC,
                       virNetDevVlanPtr *vlan,
                       virMacAddrPtr *MAC)
{
    int ret = -1;
    const char *pfDevName = NULL;
    char *pfDevOrig = NULL;
    char *vfDevOrig = NULL;
    char *filePath = NULL;
    char *fileStr = NULL;
    virJSONValuePtr configJSON = NULL;
    const char *MACStr = NULL;
    const char *adminMACStr = NULL;
    int vlanTag = -1;

    *adminMAC = NULL;
    *vlan = NULL;
    *MAC = NULL;

    if (vf >= 0) {
        /* linkdev is the PF */
        pfDevName = linkdev;

        /* linkdev should get the VF's netdev name (or NULL if none) */
        if (virNetDevPFGetVF(pfDevName, vf, &vfDevOrig) < 0)
            goto cleanup;

        linkdev = vfDevOrig;

    } else if (virNetDevIsVirtualFunction(linkdev) == 1) {
        /* when vf is -1, linkdev might be a standard netdevice (not
         * SRIOV), or it might be an SRIOV VF. If it's a VF, normalize
         * it to PF + VFname
         */

        if (virNetDevGetPhysicalFunction(linkdev, &pfDevOrig) < 0)
            goto cleanup;

        pfDevName = pfDevOrig;

        if (virNetDevGetVirtualFunctionIndex(pfDevName, linkdev, &vf) < 0)
            goto cleanup;
    }

    /* if there is a PF, it's now in pfDevName, and linkdev is either
     * the VF's name, or NULL (if the VF isn't bound to a net driver
     * on the host)
     */

    if (pfDevName) {
        if (virAsprintf(&filePath, "%s/%s_vf%d", stateDir, pfDevName, vf) < 0)
            goto cleanup;

        if (linkdev && !virFileExists(filePath)) {
            /* the device may have been stored in a file named for the
             * VF due to saveVlan == false (or an older version of
             * libvirt), so reset filePath so we'll try the other
             * filename before failing.
             */
            VIR_FREE(filePath);
            pfDevName = NULL;
        }
    }

    if (!pfDevName) {
        if (virAsprintf(&filePath, "%s/%s", stateDir, linkdev) < 0)
            goto cleanup;
    }

    if (virFileReadAll(filePath, 128, &fileStr) < 0)
        goto cleanup;

    if (strchr("0123456789abcdefABCDEF", fileStr[0])) {
        const char *vlanStr = NULL;

        /* old version of file - just two lines of text. Line 1 is the
         * MAC address (or if line 2 is present, line 1 is adminMAC),
         * and line 2 (if present) is the vlan tag
         */

        if ((vlanStr = strchr(fileStr, '\n'))) {
            char *endptr;

            /* if there are 2 lines, the first is adminMAC */
            adminMACStr = fileStr;
            vlanStr++;

            if ((virStrToLong_i(vlanStr, &endptr, 10, &vlanTag) < 0) ||
                (endptr && *endptr != '\n' && *endptr != 0)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse vlan tag '%s' from file '%s'"),
                               vlanStr, filePath);
                goto cleanup;
            }
        } else {
            /* if there is only one line, it is MAC */
            MACStr = fileStr;
        }
    } else {
        /* if it doesn't start with a hex digit, it is a modern
         * version of the config file - JSON format as described in
         * preamble to virNetDevSaveNetConfig()
         */
        if (!(configJSON = virJSONValueFromString(fileStr))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid json in net device saved "
                             "config file '%s': '%.60s'"),
                           filePath, fileStr);
            goto cleanup;
        }

        MACStr = virJSONValueObjectGetString(configJSON,
                                             VIR_NETDEV_KEYNAME_MAC);
        adminMACStr = virJSONValueObjectGetString(configJSON,
                                                  VIR_NETDEV_KEYNAME_ADMIN_MAC);
        ignore_value(virJSONValueObjectGetNumberInt(configJSON,
                                                    VIR_NETDEV_KEYNAME_VLAN_TAG,
                                                    &vlanTag));

        if (!(MACStr || adminMACStr)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("network device saved config file '%s' "
                             "has unexpected contents, missing both "
                             "'MAC' and 'adminMAC': '%.60s'"),
                           filePath, fileStr);
            goto cleanup;
        }
    }

    if (MACStr) {
        if (VIR_ALLOC(*MAC) < 0)
            goto cleanup;

        if (virMacAddrParse(MACStr, *MAC) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse MAC address '%s' from file '%s'"),
                           MACStr, filePath);
            goto cleanup;
        }
    }

    if (adminMACStr) {
        if (VIR_ALLOC(*adminMAC) < 0)
            goto cleanup;

        if (virMacAddrParse(adminMACStr, *adminMAC) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse MAC address '%s' from file '%s'"),
                           adminMACStr, filePath);
            goto cleanup;
        }
    }

    if (vlanTag != -1) {
        /* construct a simple virNetDevVlan object with a single tag */
        if (VIR_ALLOC(*vlan) < 0)
            goto cleanup;
        if (VIR_ALLOC((*vlan)->tag) < 0)
            goto cleanup;
        (*vlan)->nTags = 1;
        (*vlan)->tag[0] = vlanTag;
    }

    /* we won't need the file again */
    ignore_value(unlink(filePath));

    ret = 0;
 cleanup:
    if (ret < 0) {
        VIR_FREE(*adminMAC);
        VIR_FREE(*MAC);
        VIR_FREE(*vlan);
    }

    VIR_FREE(pfDevOrig);
    VIR_FREE(vfDevOrig);
    VIR_FREE(filePath);
    VIR_FREE(fileStr);
    virJSONValueFree(configJSON);
    return ret;
}


/**
 * virNetDevSetNetConfig:
 * @linkdev: name of the interface
 * @vf: vf index if linkdev is a PF
 * @adminMAC: new admin MAC address (will be stored in PF and
 *            used for next initialization of VF driver)
 * @vlan: new vlan tag info (or NULL)
 * @MAC: new MAC address to set on the device immediately
 * @setVlan: true to enable setting vlan tag (even if @vlan is NULL,
 *           the interface vlan tag will be set to 0).
 *
 *
 * Set new MAC address and (optionally) admin MAC and vlan tag of
 * @linkdev VF# @vf.
 *
 * Returns 0 on success, -1 on failure
 *
 */
int
virNetDevSetNetConfig(const char *linkdev, int vf,
                      const virMacAddr *adminMAC,
                      virNetDevVlanPtr vlan,
                      const virMacAddr *MAC,
                      bool setVlan)
{
    int ret = -1;
    char MACStr[VIR_MAC_STRING_BUFLEN];
    const char *pfDevName = NULL;
    char *pfDevOrig = NULL;
    char *vfDevOrig = NULL;
    int vlanTag = -1;
    virPCIDevicePtr vfPCIDevice = NULL;

    if (vf >= 0) {
        /* linkdev is the PF */
        pfDevName = linkdev;

        /* linkdev should get the VF's netdev name (or NULL if none) */
        if (virNetDevPFGetVF(pfDevName, vf, &vfDevOrig) < 0)
            goto cleanup;

        linkdev = vfDevOrig;

    } else if (virNetDevIsVirtualFunction(linkdev) == 1) {
        /* when vf is -1, linkdev might be a standard netdevice (not
         * SRIOV), or it might be an SRIOV VF. If it's a VF, normalize
         * it to PF + VFname
         */

        if (virNetDevGetPhysicalFunction(linkdev, &pfDevOrig) < 0)
            goto cleanup;

        pfDevName = pfDevOrig;

        if (virNetDevGetVirtualFunctionIndex(pfDevName, linkdev, &vf) < 0)
            goto cleanup;
    }


    if (!pfDevName) {
        /* if it's not SRIOV, then we can't set the admin MAC address
         * or vlan tag
         */
        if (adminMAC) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("admin MAC can only be set for SR-IOV VFs, but "
                             "%s is not a VF"), linkdev);
            goto cleanup;
        }

        if (vlan) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("vlan can only be set for SR-IOV VFs, but "
                             "%s is not a VF"), linkdev);
            goto cleanup;
        }

    } else {
        bool pfIsOnline;

        /* Assure that PF is online before trying to use it to set
         * anything up for this VF. It *should* be online already,
         * but if it isn't online the changes made to the VF via the
         * PF won't take effect, yet there will be no error
         * reported. In the case that the PF isn't online, we need to
         * fail and report the error, rather than automatically
         * setting it online, since setting an unconfigured interface
         * online automatically turns on IPv6 autoconfig, which may
         * not be what the admin expects, so we require them to
         * explicitly enable the PF in the host system network config.
         */
        if (virNetDevGetOnline(pfDevName, &pfIsOnline) < 0)
            goto cleanup;

        if (!pfIsOnline) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to configure VF %d of PF '%s' "
                             "because the PF is not online. Please "
                             "change host network config to put the "
                             "PF online."),
                           vf, pfDevName);
            goto cleanup;
        }

        if (vlan) {
            if (vlan->nTags != 1 || vlan->trunk) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("vlan trunking is not supported "
                                 "by SR-IOV network devices"));
                goto cleanup;
            }

            if (!setVlan) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("vlan tag set for interface %s but "
                                 "caller requested it not be set"));
                goto cleanup;
            }

            vlanTag = vlan->tag[0];

        } else if (setVlan) {
            vlanTag = 0; /* assure any existing vlan tag is reset */
        }
    }

    if (MAC) {
        int setMACrc;

        if (!linkdev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("VF %d of PF '%s' is not bound to a net driver, "
                             "so its MAC address cannot be set to %s"),
                           vf, pfDevName, virMacAddrFormat(MAC, MACStr));
            goto cleanup;
        }

        setMACrc = virNetDevSetMACInternal(linkdev, MAC, !!pfDevOrig);
        if (setMACrc < 0) {
            bool allowRetry = false;
            int retries = 100;

            /* if pfDevOrig == NULL, this isn't a VF, so we've failed */
            if (!pfDevOrig ||
                (errno != EADDRNOTAVAIL && errno != EPERM))
                goto cleanup;

            /* Otherwise this is a VF, and virNetDevSetMAC failed with
             * EADDRNOTAVAIL/EPERM, which could be due to the
             * "administratively set" flag being set in the PF for
             * this VF.  When this happens, we can attempt to use an
             * alternate method to set the VF MAC: first set it into
             * the admin MAC for this VF in the PF, then unbind/rebind
             * the VF from its net driver. This causes the VF's MAC to
             * be initialized to whatever was stored in the admin MAC.
             */

            if (virNetDevSetVfConfig(pfDevName, vf,
                                     MAC, vlanTag, &allowRetry) < 0) {
                goto cleanup;
            }

            /* admin MAC is set, now we need to construct a virPCIDevice
             * object so we can call virPCIDeviceRebind()
             */
            if (!(vfPCIDevice = virNetDevGetPCIDevice(linkdev)))
                goto cleanup;

            /* Rebind the device. This should set the proper MAC address */
            if (virPCIDeviceRebind(vfPCIDevice) < 0)
                goto cleanup;

            /* Wait until virNetDevGetIndex for the VF netdev returns success.
             * This indicates that the device is ready to be used. If we don't
             * wait, then upcoming operations on the VF may fail.
             */
            while (retries-- > 0 && !virNetDevExists(linkdev))
               usleep(1000);
        }

        if (pfDevOrig && setMACrc == 0) {
            /* if pfDevOrig is set, it that the caller was *really*
             * only interested in setting the MAC of the VF itself,
             * *not* the admin MAC via the PF. In those cases, the
             * adminMAC was only provided in case we need to set the
             * VF's MAC by temporarily unbinding/rebinding the VF's
             * net driver with the admin MAC set to the desired MAC,
             * and then want to restore the admin MAC to its original
             * setting when we're finished. We would only need to do
             * that if the virNetDevSetMAC() above had failed; since
             * setMACrc == 0, we know it didn't fail and we don't need
             * to set the adminMAC, so we are NULLing it out here to
             * avoid that below.

             * (NB: since setting the admin MAC sets the
             * "administratively set" flag for the VF in the PF's
             * driver, which prevents any future changes to the VF's
             * MAC address, we want to avoid setting the admin MAC as
             * much as possible.)
             */
            adminMAC = NULL;
        }
    }

    if (adminMAC || vlanTag >= 0) {
        /* Set vlanTag and admin MAC using an RTM_SETLINK request sent to
         * PFdevname+VF#, if mac != NULL this will set the "admin MAC" via
         * the PF, *not* the actual VF MAC - the admin MAC only takes
         * effect the next time the VF's driver is initialized (either in
         * guest or host). if there is a vlanTag to set, it will take
         * effect immediately though.
         */
        bool allowRetry = true;

        if (virNetDevSetVfConfig(pfDevName, vf,
                                 adminMAC, vlanTag, &allowRetry) < 0) {
            /* allowRetry will still be true if the failure was due to
             * trying to set the MAC address to all 0. In that case,
             * we can retry with "altZeroMAC", which is just an all-0 MAC
             * with the "locally administered" bit set.
             */
            if (!allowRetry)
                goto cleanup;

            allowRetry = false;
            if (virNetDevSetVfConfig(pfDevName, vf,
                                     &altZeroMAC, vlanTag, &allowRetry) < 0) {
                goto cleanup;
            }
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(pfDevOrig);
    VIR_FREE(vfDevOrig);
    virPCIDeviceFree(vfPCIDevice);
    return ret;
}


#else /* defined(__linux__) && defined(HAVE_LIBNL)  && defined(IFLA_VF_MAX) */


int
virNetDevSaveNetConfig(const char *linkdev ATTRIBUTE_UNUSED,
                       int vf ATTRIBUTE_UNUSED,
                       const char *stateDir ATTRIBUTE_UNUSED,
                       bool saveVlan ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to save net device config on this platform"));
    return -1;
}


int
virNetDevReadNetConfig(const char *linkdev ATTRIBUTE_UNUSED,
                       int vf ATTRIBUTE_UNUSED,
                       const char *stateDir ATTRIBUTE_UNUSED,
                       virMacAddrPtr *adminMAC ATTRIBUTE_UNUSED,
                       virNetDevVlanPtr *vlan ATTRIBUTE_UNUSED,
                       virMacAddrPtr *MAC ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to read net device config on this platform"));
    return -1;
}


int
virNetDevSetNetConfig(const char *linkdev ATTRIBUTE_UNUSED,
                      int vf ATTRIBUTE_UNUSED,
                      const virMacAddr *adminMAC ATTRIBUTE_UNUSED,
                      virNetDevVlanPtr vlan ATTRIBUTE_UNUSED,
                      const virMacAddr *MAC ATTRIBUTE_UNUSED,
                      bool setVlan ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to set net device config on this platform"));
    return -1;
}


#endif /* defined(__linux__) && defined(HAVE_LIBNL) && defined(IFLA_VF_MAX) */

VIR_ENUM_IMPL(virNetDevIfState,
              VIR_NETDEV_IF_STATE_LAST,
              "" /* value of zero means no state */,
              "unknown", "notpresent",
              "down", "lowerlayerdown",
              "testing", "dormant", "up")

VIR_ENUM_IMPL(virNetDevFeature,
              VIR_NET_DEV_FEAT_LAST,
              "rx",
              "tx",
              "sg",
              "tso",
              "gso",
              "gro",
              "lro",
              "rxvlan",
              "txvlan",
              "ntuple",
              "rxhash",
              "rdma",
              "txudptnl")

#ifdef __linux__
int
virNetDevGetLinkInfo(const char *ifname,
                     virNetDevIfLinkPtr lnk)
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
    if ((tmp_state = virNetDevIfStateTypeFromString(buf)) <= 0) {
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
    if (lnk->state != VIR_NETDEV_IF_STATE_UP) {
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
                     virNetDevIfLinkPtr lnk)
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

    if (virDirOpen(&dirp, SYSFS_INFINIBAND_DIR) < 0)
        return -1;

    if (virAsprintf(&eth_devpath, SYSFS_NET_DIR "%s/device/resource", ifname) < 0)
        goto cleanup;
    if (!virFileExists(eth_devpath))
        goto cleanup;
    if (virFileReadAll(eth_devpath, RESOURCE_FILE_LEN, &eth_res_buf) < 0)
        goto cleanup;

    while (virDirRead(dirp, &dp, SYSFS_INFINIBAND_DIR) > 0) {
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
    VIR_DIR_CLOSE(dirp);
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
 * @fd: socket to operate on
 * @ifr: struct ifreq with the command
 *
 * Returns 0 on success, -1 on failure.
 */
static int
virNetDevSendEthtoolIoctl(int fd, struct ifreq *ifr)
{
    int ret = -1;

    ret = ioctl(fd, SIOCETHTOOL, ifr);
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
            break;
        }
    }

    return ret;
}

struct virNetDevEthtoolFeatureCmd {
    const int cmd;
    const virNetDevFeature feat;
};


/**
 * virNetDevFeatureAvailable
 * This function checks for the availability of a network device feature
 *
 * @fd: socket to operate on
 * @ifr: struct ifreq with the command
 * @cmd: reference to an ethtool command structure
 *
 * Returns true if the feature is available, false otherwise.
 */
static bool
virNetDevFeatureAvailable(int fd, struct ifreq *ifr, struct ethtool_value *cmd)
{
    ifr->ifr_data = (void*)cmd;
    if (virNetDevSendEthtoolIoctl(fd, ifr) == 0 &&
        cmd->data > 0)
        return true;
    return false;
}


static void
virNetDevGetEthtoolFeatures(virBitmapPtr bitmap,
                            int fd,
                            struct ifreq *ifr)
{
    size_t i;
    struct ethtool_value cmd = { 0 };

    /* legacy ethtool getters */
    struct virNetDevEthtoolFeatureCmd ethtool_cmds[] = {
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

# if HAVE_DECL_ETHTOOL_GFLAGS
    /* ethtool masks */
    struct virNetDevEthtoolFeatureCmd flags[] = {
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
# endif

    for (i = 0; i < ARRAY_CARDINALITY(ethtool_cmds); i++) {
        cmd.cmd = ethtool_cmds[i].cmd;
        if (virNetDevFeatureAvailable(fd, ifr, &cmd))
            ignore_value(virBitmapSetBit(bitmap, ethtool_cmds[i].feat));
    }

# if HAVE_DECL_ETHTOOL_GFLAGS
    cmd.cmd = ETHTOOL_GFLAGS;
    if (virNetDevFeatureAvailable(fd, ifr, &cmd)) {
        for (i = 0; i < ARRAY_CARDINALITY(flags); i++) {
            if (cmd.data & flags[i].cmd)
                ignore_value(virBitmapSetBit(bitmap, flags[i].feat));
        }
    }
# endif
}


# if HAVE_DECL_ETHTOOL_GFEATURES
/**
 * virNetDevGFeatureAvailable
 * This function checks for the availability of a network device gfeature
 *
 * @fd: socket to operate on
 * @ifr: struct ifreq with the command
 * @cmd: reference to an ethtool command structure
 *
 * Returns true if the feature is available, false otherwise.
 */
static bool
virNetDevGFeatureAvailable(int fd,
                           struct ifreq *ifr,
                           struct ethtool_gfeatures *cmd)
{
    ifr->ifr_data = (void*)cmd;
    if (virNetDevSendEthtoolIoctl(fd, ifr) == 0)
        return !!FEATURE_BIT_IS_SET(cmd->features, TX_UDP_TNL, active);
    return false;
}


static int
virNetDevGetEthtoolGFeatures(virBitmapPtr bitmap,
                             int fd,
                             struct ifreq *ifr)
{
    struct ethtool_gfeatures *g_cmd;

    if (VIR_ALLOC_VAR(g_cmd,
                      struct ethtool_get_features_block, GFEATURES_SIZE) < 0)
        return -1;

    g_cmd->cmd = ETHTOOL_GFEATURES;
    g_cmd->size = GFEATURES_SIZE;
    if (virNetDevGFeatureAvailable(fd, ifr, g_cmd))
        ignore_value(virBitmapSetBit(bitmap, VIR_NET_DEV_FEAT_TXUDPTNL));
    VIR_FREE(g_cmd);
    return 0;
}
# else
static int
virNetDevGetEthtoolGFeatures(virBitmapPtr bitmap ATTRIBUTE_UNUSED,
                             int fd ATTRIBUTE_UNUSED,
                             struct ifreq *ifr ATTRIBUTE_UNUSED)
{
    return 0;
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
    struct ifreq ifr;
    int ret = -1;
    int fd = -1;

    if (!(*out = virBitmapNew(VIR_NET_DEV_FEAT_LAST)))
        return -1;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        goto cleanup;

    virNetDevGetEthtoolFeatures(*out, fd, &ifr);

    if (virNetDevGetEthtoolGFeatures(*out, fd, &ifr) < 0)
        goto cleanup;

    if (virNetDevRDMAFeature(ifname, out) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
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


/**
 * virNetDevRunEthernetScript:
 * @ifname: the interface name
 * @script: the script name
 *
 * This function executes script for new tap device created by libvirt.
 * Returns 0 in case of success or -1 on failure
 */
int
virNetDevRunEthernetScript(const char *ifname, const char *script)
{
    virCommandPtr cmd;
    int ret;

    /* Not a bug! Previously we did accept script="" as a NO-OP. */
    if (STREQ(script, ""))
        return 0;

    cmd = virCommandNew(script);
    virCommandAddArgFormat(cmd, "%s", ifname);
    virCommandClearCaps(cmd);
#ifdef CAP_NET_ADMIN
    virCommandAllowCap(cmd, CAP_NET_ADMIN);
#endif
    virCommandAddEnvPassCommon(cmd);

    ret = virCommandRun(cmd, NULL);

    virCommandFree(cmd);
    return ret;
}
