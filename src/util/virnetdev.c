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
 */

#include <config.h>
#include <math.h>

#define LIBVIRT_VIRNETDEVPRIV_H_ALLOW

#include "virnetdevpriv.h"
#include "viralloc.h"
#include "virnetlink.h"
#include "virmacaddr.h"
#include "virfile.h"
#include "virerror.h"
#include "vircommand.h"
#include "virpci.h"
#include "virlog.h"
#include "virstring.h"
#include "virutil.h"
#include "virjson.h"

#ifndef WIN32
# include <sys/ioctl.h>
#endif
#include <fcntl.h>

#ifdef __linux__
# include <linux/sockios.h>
# include <linux/if_vlan.h>
# include <linux/types.h>
# include <linux/ethtool.h>
# include <linux/devlink.h>
# define VIR_NETDEV_FAMILY AF_UNIX
#elif defined(WITH_STRUCT_IFREQ) && defined(AF_LOCAL)
# define VIR_NETDEV_FAMILY AF_LOCAL
#else
# undef WITH_STRUCT_IFREQ
#endif

#if WITH_DECL_LINK_ADDR
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

#if defined(SIOCSIFFLAGS) && defined(WITH_STRUCT_IFREQ)
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
#ifdef __linux__
# define TX_UDP_TNL 25
# define GFEATURES_SIZE 2
# define FEATURE_WORD(blocks, index, field)  ((blocks)[(index) / 32U].field)
# define FEATURE_FIELD_FLAG(index)      (1U << (index) % 32U)
# define FEATURE_BIT_IS_SET(blocks, index, field) \
    (FEATURE_WORD(blocks, index, field) & FEATURE_FIELD_FLAG(index))
#endif


static virNetDevGenName
virNetDevGenNames[VIR_NET_DEV_GEN_NAME_LAST] = {
    {-1, VIR_NET_GENERATED_VNET_PREFIX, VIR_MUTEX_INITIALIZER},
    {-1, VIR_NET_GENERATED_MACVTAP_PREFIX, VIR_MUTEX_INITIALIZER},
    {-1, VIR_NET_GENERATED_MACVLAN_PREFIX, VIR_MUTEX_INITIALIZER},
};

typedef enum {
    VIR_MCAST_TYPE_INDEX_TOKEN,
    VIR_MCAST_TYPE_NAME_TOKEN,
    VIR_MCAST_TYPE_USERS_TOKEN,
    VIR_MCAST_TYPE_GLOBAL_TOKEN,
    VIR_MCAST_TYPE_ADDR_TOKEN,

    VIR_MCAST_TYPE_LAST
} virMCastType;

typedef struct _virNetDevMcastEntry virNetDevMcastEntry;
struct _virNetDevMcastEntry  {
        int idx;
        char name[VIR_MCAST_NAME_LEN];
        int users;
        bool global;
        virMacAddr macaddr;
};

static void
virNetDevMcastEntryFree(virNetDevMcastEntry *entry)
{
    g_free(entry);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNetDevMcastEntry, virNetDevMcastEntryFree);

typedef struct _virNetDevMcastList virNetDevMcastList;
struct _virNetDevMcastList {
    size_t nentries;
    virNetDevMcastEntry **entries;
};

#if defined(WITH_STRUCT_IFREQ)
static int virNetDevSetupControlFull(const char *ifname,
                                     struct ifreq *ifr,
                                     int domain,
                                     int type)
{
    int fd;

    if (ifr && ifname) {
        memset(ifr, 0, sizeof(*ifr));

        if (virStrcpyStatic(ifr->ifr_name, ifname) < 0) {
            virReportSystemError(ERANGE,
                                 _("Network interface name '%1$s' is too long"),
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
#else /* !WITH_STRUCT_IFREQ */
int
virNetDevSetupControl(const char *ifname G_GNUC_UNUSED,
                      void *ifr G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Network device configuration is not supported on this platform"));
    return -1;
}
#endif /* WITH_STRUCT_IFREQ */


#if defined(SIOCGIFFLAGS) && defined(WITH_STRUCT_IFREQ)
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
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {
        if (errno == ENODEV || errno == ENXIO)
            return 0;

        virReportSystemError(errno, _("Unable to check interface flags for %1$s"),
                             ifname);
        return -1;
    }

    return 1;
}
#else
int virNetDevExists(const char *ifname)
{
    virReportSystemError(ENOSYS,
                         _("Unable to check interface %1$s"), ifname);
    return -1;
}
#endif


#if defined(SIOCGIFHWADDR) && defined(SIOCSIFHWADDR) && \
    defined(WITH_STRUCT_IFREQ)
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
    struct ifreq ifr;
    char macstr[VIR_MAC_STRING_BUFLEN];
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    /* To fill ifr.ifr_hdaddr.sa_family field */
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        virReportSystemError(errno, _("Cannot get interface MAC on '%1$s'"),
                             ifname);

        VIR_DEBUG("SIOCSIFHWADDR %s get MAC - Fail", ifname);
        return -1;
    }

    virMacAddrGetRaw(macaddr, (unsigned char *)ifr.ifr_hwaddr.sa_data);

    if (ioctl(fd, SIOCSIFHWADDR, &ifr) < 0) {

        if (quiet &&
            (errno == EADDRNOTAVAIL || errno == EPERM)) {
            VIR_DEBUG("SIOCSIFHWADDR %s MAC=%s - Fail",
                      ifname, virMacAddrFormat(macaddr, macstr));
            return -1;
        }

        virReportSystemError(errno,
                             _("Cannot set interface MAC to %1$s on '%2$s'"),
                             virMacAddrFormat(macaddr, macstr), ifname);
        return -1;
    }

    VIR_DEBUG("SIOCSIFHWADDR %s MAC=%s - Success",
              ifname, virMacAddrFormat(macaddr, macstr));

    return 0;
}


#elif defined(SIOCSIFLLADDR) && defined(WITH_STRUCT_IFREQ) && \
    WITH_DECL_LINK_ADDR


static int
virNetDevSetMACInternal(const char *ifname,
                        const virMacAddr *macaddr,
                        bool quiet)
{
    struct ifreq ifr;
    struct sockaddr_dl sdl;
    char mac[VIR_MAC_STRING_BUFLEN + 1] = ":";
    VIR_AUTOCLOSE s = -1;

    if ((s = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    virMacAddrFormat(macaddr, mac + 1);
    sdl.sdl_len = sizeof(sdl);
    link_addr(mac, &sdl);

    memcpy(ifr.ifr_addr.sa_data, sdl.sdl_data, VIR_MAC_BUFLEN);
    ifr.ifr_addr.sa_len = VIR_MAC_BUFLEN;

    if (ioctl(s, SIOCSIFLLADDR, &ifr) < 0) {
        if (quiet &&
            (errno == EADDRNOTAVAIL || errno == EPERM)) {
            VIR_DEBUG("SIOCSIFLLADDR %s MAC=%s - Fail", ifname, mac + 1);
            return -1;
        }

        virReportSystemError(errno,
                             _("Cannot set interface MAC to %1$s on '%2$s'"),
                             mac + 1, ifname);
        return -1;
    }

    VIR_DEBUG("SIOCSIFLLADDR %s MAC=%s - Success", ifname, mac + 1);
    return 0;
}


#else


static int
virNetDevSetMACInternal(const char *ifname,
                        const virMacAddr *macaddr G_GNUC_UNUSED,
                        bool quiet G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot set interface MAC on '%1$s'"),
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


#if defined(SIOCGIFHWADDR) && defined(WITH_STRUCT_IFREQ)
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
                    virMacAddr *macaddr)
{
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot get interface MAC on '%1$s'"),
                             ifname);
        return -1;
    }

    virMacAddrSetRaw(macaddr, (unsigned char *)ifr.ifr_hwaddr.sa_data);

    return 0;
}
#else
int virNetDevGetMAC(const char *ifname,
                    virMacAddr *macaddr G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot get interface MAC on '%1$s'"),
                         ifname);
    return -1;
}
#endif


#if defined(SIOCGIFMTU) && defined(WITH_STRUCT_IFREQ)
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
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot get interface MTU on '%1$s'"),
                             ifname);
        return -1;
    }

    return ifr.ifr_mtu;
}
#else
int virNetDevGetMTU(const char *ifname)
{
    virReportSystemError(ENOSYS,
                         _("Cannot get interface MTU on '%1$s'"),
                         ifname);
    return -1;
}
#endif


#if defined(SIOCSIFMTU) && defined(WITH_STRUCT_IFREQ)
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
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    ifr.ifr_mtu = mtu;

    if (ioctl(fd, SIOCSIFMTU, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot set interface MTU on '%1$s'"),
                             ifname);
        return -1;
    }

    return 0;
}
#else
int virNetDevSetMTU(const char *ifname, int mtu G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot set interface MTU on '%1$s'"),
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
    g_autofree char *pid = NULL;
    g_autofree char *phy = NULL;
    g_autofree char *phy_path = NULL;
    g_autoptr(virCommand) cmd = NULL;
    int len;

    pid = g_strdup_printf("%lld", (long long) pidInNs);

    /* The 802.11 wireless devices only move together with their PHY. */
    if (virNetDevSysfsFile(&phy_path, ifname, "phy80211/name") < 0)
        return -1;

    if ((len = virFileReadAllQuiet(phy_path, 1024, &phy)) <= 0) {
        /* Not a wireless device. */
        cmd = virCommandNewArgList("ip", "link",
                                   "set", ifname, "netns", pid, NULL);
    } else {
        /* Remove a line break. */
        phy[len - 1] = '\0';

        cmd = virCommandNewArgList("iw", "phy", phy,
                                   "set", "netns", pid, NULL);
    }

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    return 0;
}

#if defined(SIOCSIFNAME) && defined(WITH_STRUCT_IFREQ)
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
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

# ifdef WITH_STRUCT_IFREQ_IFR_NEWNAME
    if (virStrcpyStatic(ifr.ifr_newname, newifname) < 0) {
        virReportSystemError(ERANGE,
                             _("Network interface name '%1$s' is too long"),
                             newifname);
        return -1;
    }
# else
    ifr.ifr_data = (caddr_t)newifname;
# endif

    if (ioctl(fd, SIOCSIFNAME, &ifr)) {
        virReportSystemError(errno,
                             _("Unable to rename '%1$s' to '%2$s'"),
                             ifname, newifname);
        return -1;
    }

    return 0;
}
#else
int virNetDevSetName(const char* ifname, const char *newifname)
{
    virReportSystemError(ENOSYS,
                         _("Cannot rename interface '%1$s' to '%2$s' on this platform"),
                         ifname, newifname);
    return -1;
}
#endif


#if defined(SIOCSIFFLAGS) && defined(WITH_STRUCT_IFREQ)
static int
virNetDevSetIFFlag(const char *ifname, int flag, bool val)
{
    struct ifreq ifr;
    int ifflags;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot get interface flags on '%1$s'"),
                             ifname);
        return -1;
    }

    if (val)
        ifflags = ifr.ifr_flags | flag;
    else
        ifflags = ifr.ifr_flags & ~flag;

    if (ifr.ifr_flags != ifflags) {
        ifr.ifr_flags = ifflags;
        if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
            virReportSystemError(errno,
                                 _("Cannot set interface flags on '%1$s'"),
                                 ifname);
            return -1;
        }
    }

    return 0;
}
#else
static int
virNetDevSetIFFlag(const char *ifname,
                   int flag G_GNUC_UNUSED,
                   bool val G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot set interface flags on '%1$s'"),
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


#if defined(SIOCGIFFLAGS) && defined(WITH_STRUCT_IFREQ)
static int
virNetDevGetIFFlag(const char *ifname, int flag, bool *val)
{
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot get interface flags on '%1$s'"),
                             ifname);
        return -1;
    }

    *val = (ifr.ifr_flags & flag) ? true : false;
    return 0;
}
#else
static int
virNetDevGetIFFlag(const char *ifname,
                   int flag G_GNUC_UNUSED,
                   bool *val G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot get interface flags on '%1$s'"),
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

#if defined(WITH_IF_INDEXTONAME)
char *virNetDevGetName(int ifindex)
{
    char name[IFNAMSIZ] = { 0 };

    if (!if_indextoname(ifindex, name)) {
        virReportSystemError(errno,
                             _("Failed to convert interface index %1$d to a name"),
                             ifindex);
        return NULL;
    }

    return g_strdup(name);
}
#else
char *virNetDevGetName(int ifindex)
{
    virReportSystemError(ENOSYS,
                         _("Cannot get interface name for index '%1$i'"),
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
#if defined(SIOCGIFINDEX) && defined(WITH_STRUCT_IFREQ)
int virNetDevGetIndex(const char *ifname, int *ifindex)
{
    struct ifreq ifreq = { 0 };
    VIR_AUTOCLOSE fd = socket(VIR_NETDEV_FAMILY, SOCK_DGRAM, 0);

    if (fd < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to open control socket"));
        return -1;
    }

    if (virStrcpyStatic(ifreq.ifr_name, ifname) < 0) {
        virReportSystemError(ERANGE,
                             _("invalid interface name %1$s"),
                             ifname);
        return -1;
    }

    if (ioctl(fd, SIOCGIFINDEX, &ifreq) < 0) {
        virReportSystemError(errno,
                             _("Unable to get index for interface %1$s"), ifname);
        return -1;
    }

# ifdef WITH_STRUCT_IFREQ_IFR_INDEX
    *ifindex = ifreq.ifr_index;
# else
    *ifindex = ifreq.ifr_ifindex;
# endif
    return 0;
}
#else /* ! SIOCGIFINDEX */
int virNetDevGetIndex(const char *ifname G_GNUC_UNUSED,
                      int *ifindex G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get interface index on this platform"));
    return -1;
}
#endif /* ! SIOCGIFINDEX */


#if defined(WITH_LIBNL)
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
    g_autofree void *nlData = NULL;
    struct nlattr *tb[IFLA_MAX + 1] = {NULL, };

    *master = NULL;

    if (virNetlinkDumpLink(ifname, -1, &nlData, tb, 0, 0) < 0)
        return -1;

    if (tb[IFLA_MASTER]) {
        if (!(*master = virNetDevGetName(*(int *)RTA_DATA(tb[IFLA_MASTER]))))
            return -1;
    }

    VIR_DEBUG("IFLA_MASTER for %s is %s", ifname, *master ? *master : "(none)");
    return 0;
}

#elif defined(__linux__)

/* libnl isn't available, so we can't use netlink.
 * Fall back to using sysfs
 */
int
virNetDevGetMaster(const char *ifname, char **master)
{
    g_autofree char *path = NULL;
    g_autofree char *canonical = NULL;

    if (virNetDevSysfsFile(&path, ifname, "master") < 0)
        return -1;

    if (!(canonical = virFileCanonicalizePath(path)))
        return -1;

    *master = g_path_get_basename(canonical);

    VIR_DEBUG("IFLA_MASTER for %s is %s", ifname, *master ? *master : "(none)");
    return 0;
}

#else

int
virNetDevGetMaster(const char *ifname G_GNUC_UNUSED,
                   char **master G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Unable to get device master from netlink on this platform"));
    return -1;
}


#endif /* defined(WITH_LIBNL) */


#if __linux__
int virNetDevGetVLanID(const char *ifname, int *vlanid)
{
    struct vlan_ioctl_args vlanargs = {
      .cmd = GET_VLAN_VID_CMD,
    };
    VIR_AUTOCLOSE fd = socket(PF_PACKET, SOCK_DGRAM, 0);

    if (fd < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to open control socket"));
        return -1;
    }

    if (virStrcpyStatic(vlanargs.device1, ifname) < 0) {
        virReportSystemError(ERANGE,
                             _("invalid interface name %1$s"),
                             ifname);
        return -1;
    }

    if (ioctl(fd, SIOCGIFVLAN, &vlanargs) != 0) {
        virReportSystemError(errno,
                             _("Unable to get VLAN for interface %1$s"), ifname);
        return -1;
    }

    *vlanid = vlanargs.u.VID;
    return 0;
}
#else /* ! __linux__ */
int virNetDevGetVLanID(const char *ifname G_GNUC_UNUSED,
                       int *vlanid G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get VLAN on this platform"));
    return -1;
}
#endif /* ! __linux__ */


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
#if defined(SIOCGIFHWADDR) && defined(WITH_STRUCT_IFREQ)
int virNetDevValidateConfig(const char *ifname,
                            const virMacAddr *macaddr, int ifindex)
{
    struct ifreq ifr;
    int idx;
    int rc;
    VIR_AUTOCLOSE fd = -1;

    if ((rc = virNetDevExists(ifname)) < 0)
        return -1;
    if (rc == 0)
        return 0;

    if (macaddr != NULL) {
        if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
            return -1;

        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            if (errno == ENODEV)
                return 0;

            virReportSystemError(errno,
                                 _("could not get MAC address of interface %1$s"),
                                 ifname);
            return -1;
        }

        if (virMacAddrCmpRaw(macaddr,
                             (unsigned char *)ifr.ifr_hwaddr.sa_data) != 0)
            return 0;
    }

    if (ifindex != -1) {
        if (virNetDevGetIndex(ifname, &idx) < 0)
            return -1;
        if (idx != ifindex)
            return 0;
    }

    return 1;
}
#else
int virNetDevValidateConfig(const char *ifname G_GNUC_UNUSED,
                            const virMacAddr *macaddr G_GNUC_UNUSED,
                            int ifindex G_GNUC_UNUSED)
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
    *pf_sysfs_device_link = g_strdup_printf(SYSFS_NET_DIR "%s/%s", ifname, file);
    return 0;
}

static int
virNetDevSysfsDeviceFile(char **pf_sysfs_device_link, const char *ifname,
                         const char *file)
{
    *pf_sysfs_device_link = g_strdup_printf(SYSFS_NET_DIR "%s/device/%s", ifname,
                                            file);
    return 0;
}


# if defined(WITH_LIBNL)

/**
 * Determine if the device path specified in devpath is a PCI Device
 * by resolving the 'subsystem'-link in devpath and looking for
 * 'pci' in the last component. For more information see the rules
 * for accessing sysfs in the kernel docs
 *
 * https://www.kernel.org/doc/html/latest/admin-guide/sysfs-rules.html
 *
 * Returns true if devpath's subsystem is pci, false otherwise.
 */
static bool
virNetDevIsPCIDevice(const char *devpath)
{
    g_autofree char *subsys_link = NULL;
    g_autofree char *abs_path = NULL;
    g_autofree char *subsys = NULL;

    subsys_link = g_strdup_printf("%s/subsystem", devpath);

    if (!virFileExists(subsys_link))
        return false;

    if (virFileResolveLink(subsys_link, &abs_path) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to resolve device subsystem symlink %1$s"),
                       subsys_link);
        return false;
    }

    subsys = g_path_get_basename(abs_path);
    return STRPREFIX(subsys, "pci");
}


static virPCIDevice *
virNetDevGetPCIDevice(const char *devName)
{
    g_autofree char *vfSysfsDevicePath = NULL;
    g_autoptr(virPCIDeviceAddress) vfPCIAddr = NULL;

    if (virNetDevSysfsFile(&vfSysfsDevicePath, devName, "device") < 0)
        return NULL;

    if (!virNetDevIsPCIDevice(vfSysfsDevicePath))
        return NULL;

    vfPCIAddr = virPCIGetDeviceAddressFromSysfsLink(vfSysfsDevicePath);
    if (!vfPCIAddr)
        return NULL;

    return virPCIDeviceNew(vfPCIAddr);
}
# endif


/* A wrapper to get content of file from ifname SYSFS_NET_DIR
 */
static int
virNetDevGetSysfsFileValue(const char *ifname,
                           const char *fileName,
                           char **sysfsFileData)
{
    g_autofree char *sysfsFile = NULL;

    *sysfsFileData = NULL;

    if (virNetDevSysfsFile(&sysfsFile, ifname, fileName) < 0)
        return -1;

    /* a failure to read just means the driver doesn't support
     * <fileName>, so set success now and ignore the return from
     * virFileReadAllQuiet().
     */

    ignore_value(virFileReadAllQuiet(sysfsFile, 1024, sysfsFileData));
    return 0;
}

/**
 * virNetDevGetPhysPortID:
 *
 * @ifname: name of a netdev
 *
 * @physPortID: pointer to char* that will receive @ifname's
 *              phys_port_id from sysfs (null terminated
 *              string). Could be NULL if @ifname's net driver doesn't
 *              support phys_port_id (most netdev drivers
 *              don't). Caller is responsible for freeing the string
 *              when finished.
 *
 * Returns 0 on success or -1 on failure.
 */
int
virNetDevGetPhysPortID(const char *ifname,
                       char **physPortID)
{
    return virNetDevGetSysfsFileValue(ifname, "phys_port_id", physPortID);
}


/**
 * virNetDevGetPhysPortName:
 *
 * @ifname: name of a netdev
 *
 * @physPortName: pointer to char* that will receive @ifname's
 *                phys_port_name from sysfs (null terminated
 *                string). Could be NULL if @ifname's net driver doesn't
 *                support phys_port_name (most netdev drivers
 *                don't). Caller is responsible for freeing the string
 *                when finished.
 *
 * Returns 0 on success or -1 on failure.
 */
int
virNetDevGetPhysPortName(const char *ifname,
                         char **physPortName)
{
    return virNetDevGetSysfsFileValue(ifname, "phys_port_name", physPortName);
}


/**
 * virNetDevGetVirtualFunctions:
 * @pfname : name of the physical function interface name
 * @vfs: Filled with struct describing the virtual functions of @pfname
 *
 * Returns 0 on success and -1 on failure
 */
int
virNetDevGetVirtualFunctions(const char *pfname,
                             virPCIVirtualFunctionList **vfs)
{
    g_autofree char *pf_sysfs_device_link = NULL;

    if (virNetDevSysfsFile(&pf_sysfs_device_link, pfname, "device") < 0)
        return -1;

    if (virPCIGetVirtualFunctionsFull(pf_sysfs_device_link, vfs, pfname) < 0)
        return -1;

    return 0;
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
    g_autofree char *if_sysfs_device_link = NULL;

    if (virNetDevSysfsFile(&if_sysfs_device_link, ifname, "device") < 0)
        return -1;

    return virPCIIsVirtualFunction(if_sysfs_device_link);
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
    g_autofree char *pf_sysfs_device_link = NULL;
    g_autofree char *vf_sysfs_device_link = NULL;

    if (virNetDevSysfsFile(&pf_sysfs_device_link, pfname, "device") < 0)
        return -1;

    if (virNetDevSysfsFile(&vf_sysfs_device_link, vfname, "device") < 0)
        return -1;

    return virPCIGetVirtualFunctionIndex(pf_sysfs_device_link,
                                         vf_sysfs_device_link,
                                         vf_index);
}

/**
 * virNetDevGetPhysicalFunction
 *
 * @ifname : name of the physical function interface name
 * @pfname : Contains sriov physical function for interface ifname
 *           upon successful return (might be NULL if the PF has no
 *           associated netdev. This is *not* an error)
 *
 * Returns 0 on success, -1 on failure
 *
 */
int
virNetDevGetPhysicalFunction(const char *ifname, char **pfname)
{
    g_autofree char *physfn_sysfs_path = NULL;

    if (virNetDevSysfsDeviceFile(&physfn_sysfs_path, ifname, "physfn") < 0)
        return -1;

    if (virPCIGetNetName(physfn_sysfs_path, 0, ifname, pfname) < 0)
        return -1;

    return 0;
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
    g_autofree char *virtfnName = NULL;
    g_autofree char *virtfnSysfsPath = NULL;

    virtfnName = g_strdup_printf("virtfn%d", vf);

    /* this provides the path to the VF's directory in sysfs,
     * e.g. "/sys/class/net/enp2s0f0/virtfn3"
     */
    if (virNetDevSysfsDeviceFile(&virtfnSysfsPath, pfname, virtfnName) < 0)
        return -1;

    /* and this gets the netdev name associated with it, which is a
     * directory entry in [virtfnSysfsPath]/net,
     * e.g. "/sys/class/net/enp2s0f0/virtfn3/net/enp2s11f4" - in this
     * example the VF for enp2s0f0 vf#3 is "enp2s11f4". (If the VF
     * isn't bound to a netdev driver, it won't have a netdev name,
     * and vfname will be NULL).
     */
    return virPCIGetNetName(virtfnSysfsPath, 0, pfname, vfname);
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
    int ret = -1;

    if (virNetDevGetPhysicalFunction(vfname, pfname) < 0)
        return -1;

    if (!*pfname) {
        /* The SRIOV standard does not require VF netdevs to have the
         * netdev assigned to a PF, but our method of retrieving
         * VFINFO does.
         */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("The PF device for VF %1$s has no network device name, cannot get virtual function info"),
                       vfname);
        return -1;
    }

    if (virNetDevGetVirtualFunctionIndex(*pfname, vfname, vf) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0)
        VIR_FREE(*pfname);
    return ret;
}

#else /* !__linux__ */
int
virNetDevGetPhysPortID(const char *ifname G_GNUC_UNUSED,
                       char **physPortID)
{
    /* this actually should never be called, and is just here to
     * satisfy the linker.
     */
    *physPortID = NULL;
    return 0;
}

int
virNetDevGetPhysPortName(const char *ifname G_GNUC_UNUSED,
                       char **physPortName)
{
    /* this actually should never be called, and is just here to
     * satisfy the linker.
     */
    *physPortName = NULL;
    return 0;
}

int
virNetDevGetVirtualFunctions(const char *pfname G_GNUC_UNUSED,
                             virPCIVirtualFunctionList **vfs G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get virtual functions on this platform"));
    return -1;
}

int
virNetDevIsVirtualFunction(const char *ifname G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to check virtual function status on this platform"));
    return -1;
}

int
virNetDevGetVirtualFunctionIndex(const char *pfname G_GNUC_UNUSED,
                                 const char *vfname G_GNUC_UNUSED,
                                 int *vf_index G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get virtual function index on this platform"));
    return -1;
}

int
virNetDevGetPhysicalFunction(const char *ifname G_GNUC_UNUSED,
                             char **pfname G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get physical function status on this platform"));
    return -1;
}

int
virNetDevPFGetVF(const char *pfname G_GNUC_UNUSED,
                 int vf G_GNUC_UNUSED,
                 char **vfname G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get virtual function name on this platform"));
    return -1;
}

int
virNetDevGetVirtualFunctionInfo(const char *vfname G_GNUC_UNUSED,
                                char **pfname G_GNUC_UNUSED,
                                int *vf G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get virtual function info on this platform"));
    return -1;
}

int
virNetDevSysfsFile(char **pf_sysfs_device_link G_GNUC_UNUSED,
                   const char *ifname G_GNUC_UNUSED,
                   const char *file G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get sysfs info on this platform"));
    return -1;
}


#endif /* !__linux__ */
#if defined(WITH_LIBNL)


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
    [IFLA_VF_STATS]     = { .type = NLA_NESTED },
};


static struct nla_policy ifla_vfstats_policy[IFLA_VF_STATS_MAX+1] = {
    [IFLA_VF_STATS_RX_PACKETS]  = { .type = NLA_U64 },
    [IFLA_VF_STATS_TX_PACKETS]  = { .type = NLA_U64 },
    [IFLA_VF_STATS_RX_BYTES]    = { .type = NLA_U64 },
    [IFLA_VF_STATS_TX_BYTES]    = { .type = NLA_U64 },
    [IFLA_VF_STATS_BROADCAST]   = { .type = NLA_U64 },
    [IFLA_VF_STATS_MULTICAST]   = { .type = NLA_U64 },
};

int
virNetDevSendVfSetLinkRequest(const char *ifname,
                              int vfInfoType,
                              const void *payload,
                              const size_t payloadLen)
{
    int rc = -1;
    g_autofree struct nlmsghdr *resp = NULL;
    struct nlmsgerr *err = NULL;
    unsigned int recvbuflen = 0;
    struct nl_msg *nl_msg;
    struct nlattr *vfinfolist, *vfinfo;
    struct ifinfomsg ifinfo = {
        .ifi_family = AF_UNSPEC,
        .ifi_index  = -1,
    };

    nl_msg = virNetlinkMsgNew(RTM_SETLINK, NLM_F_REQUEST);

    if (nlmsg_append(nl_msg,  &ifinfo, sizeof(ifinfo), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;

    if (ifname &&
        nla_put(nl_msg, IFLA_IFNAME, strlen(ifname)+1, ifname) < 0)
        goto buffer_too_small;

    if (!(vfinfolist = nla_nest_start(nl_msg, IFLA_VFINFO_LIST)))
        goto buffer_too_small;

    if (!(vfinfo = nla_nest_start(nl_msg, IFLA_VF_INFO)))
        goto buffer_too_small;

    if (nla_put(nl_msg, vfInfoType, payloadLen, payload) < 0)
        goto buffer_too_small;

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
        rc = err->error;
        break;
    case NLMSG_DONE:
        rc = 0;
        break;
    default:
        goto malformed_resp;
    }

 cleanup:
    nlmsg_free(nl_msg);
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

int
virNetDevSetVfVlan(const char *ifname,
                   int vf,
                   const int *vlanid)
{
    int ret = -1;
    struct ifla_vf_vlan ifla_vf_vlan = {
        .vf = vf,
        .vlan = 0,
        .qos = 0,
    };

    /* If vlanid is NULL, assume it needs to be cleared. */
    if (vlanid) {
        /* VLAN ids 0 and 4095 are reserved per 802.1Q but are valid values. */
        if ((*vlanid < 0 || *vlanid > 4095)) {
            virReportError(ERANGE, _("vlanid out of range: %1$d"), *vlanid);
            return -ERANGE;
        }
        ifla_vf_vlan.vlan = *vlanid;
    }

    ret = virNetDevSendVfSetLinkRequest(ifname, IFLA_VF_VLAN,
                                        &ifla_vf_vlan, sizeof(ifla_vf_vlan));

    /* If vlanid is NULL - we are attempting to implicitly clear an existing
     * VLAN id.  An EPERM received at this stage is an indicator that the
     * embedded switch is not exposed to this host and the network driver is
     * not able to set a VLAN for a VF, whereas the Libvirt client has not
     * explicitly configured a VLAN or requested it to be cleared via VLAN id
     * 0. */
    if (ret == -EPERM && vlanid == NULL) {
        ret = 0;
    } else if (ret < 0) {
        virReportSystemError(-ret,
                             _("Cannot set interface vlanid to %1$d for ifname %2$s vf %3$d"),
                             ifla_vf_vlan.vlan, ifname ? ifname : "(unspecified)", vf);
    }

    VIR_DEBUG("RTM_SETLINK %s vf %d vlanid=%d - %s",
              ifname, vf, ifla_vf_vlan.vlan, ret < 0 ? "Fail" : "Success");
    return ret;
}

int
virNetDevSetVfMac(const char *ifname, int vf,
                  const virMacAddr *macaddr,
                  bool *allowRetry)
{
    int ret = -1;
    char macstr[VIR_MAC_STRING_BUFLEN];
    struct ifla_vf_mac ifla_vf_mac = {
        .vf = vf,
        .mac = { 0, },
    };

    if (macaddr == NULL || allowRetry == NULL) {
        virReportError(EINVAL,
                       _("Invalid parameters macaddr=%1$p allowRetry=%2$p"),
                       macaddr, allowRetry);
        return -EINVAL;
    }

    virMacAddrGetRaw(macaddr, ifla_vf_mac.mac);

    ret = virNetDevSendVfSetLinkRequest(ifname, IFLA_VF_MAC,
                                        &ifla_vf_mac, sizeof(ifla_vf_mac));
    if (ret == -EINVAL && *allowRetry && !virMacAddrCmp(macaddr, &zeroMAC)) {
        /* if allowRetry is true and the error was EINVAL, then
         * silently return a failure so the caller can retry with a
         * different MAC address. */
    } else if (ret < 0) {
        /* other errors are permanent */
        virReportSystemError(-ret,
                             _("Cannot set interface MAC to %1$s for ifname %2$s vf %3$d"),
                             macaddr ? virMacAddrFormat(macaddr, macstr) : "(unchanged)",
                             ifname ? ifname : "(unspecified)",
                             vf);
        *allowRetry = false; /* don't use retrying */
    }

    VIR_DEBUG("RTM_SETLINK %s vf %d MAC=%s - %s",
              ifname, vf,
              macaddr ? virMacAddrFormat(macaddr, macstr) : "(unchanged)",
              ret < 0 ? "Fail" : "Success");
    return ret;
}

int
virNetDevSetVfConfig(const char *ifname,
                     int vf,
                     const virMacAddr *macaddr,
                     const int *vlanid,
                     bool *allowRetry)
{
    int ret = -1;

    if (macaddr &&
        (ret = virNetDevSetVfMac(ifname, vf, macaddr, allowRetry)) < 0)
        return ret;
    if ((ret = virNetDevSetVfVlan(ifname, vf, vlanid)) < 0)
        return ret;
    return ret;
}

/**
 * virNetDevParseVfInfo:
 * Get the VF interface information from kernel by netlink, To make netlink
 * parsing logic easy to maintain, extending this function to get some new
 * data is better than add a new function.
 */
static int
virNetDevParseVfInfo(struct nlattr **tb, int32_t vf, virMacAddr *mac,
                     int *vlanid, virDomainInterfaceStatsPtr stats)
{
    int rc = -1;
    struct ifla_vf_mac *vf_mac;
    struct ifla_vf_vlan *vf_vlan;
    struct nlattr *tb_vf_info = {NULL, };
    struct nlattr *tb_vf[IFLA_VF_MAX+1];
    struct nlattr *tb_vf_stats[IFLA_VF_STATS_MAX+1];
    int rem;

    if (!tb[IFLA_VFINFO_LIST]) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing IFLA_VF_INFO in netlink response"));
        return rc;
    }

    nla_for_each_nested(tb_vf_info, tb[IFLA_VFINFO_LIST], rem) {
        if (nla_type(tb_vf_info) != IFLA_VF_INFO)
            continue;

        if (nla_parse_nested(tb_vf, IFLA_VF_MAX, tb_vf_info,
                             ifla_vf_policy)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("error parsing IFLA_VF_INFO"));
            return rc;
        }

        if (mac && tb_vf[IFLA_VF_MAC]) {
            vf_mac = RTA_DATA(tb_vf[IFLA_VF_MAC]);
            if (vf_mac && vf_mac->vf == vf)  {
                virMacAddrSetRaw(mac, vf_mac->mac);
                rc = 0;
            }
        }

        if (vlanid && tb_vf[IFLA_VF_VLAN]) {
            vf_vlan = RTA_DATA(tb_vf[IFLA_VF_VLAN]);
            if (vf_vlan && vf_vlan->vf == vf)  {
                *vlanid = vf_vlan->vlan;
                rc = 0;
            }
        }

        if (stats && tb_vf[IFLA_VF_STATS] && tb_vf[IFLA_VF_MAC]) {
            vf_mac = RTA_DATA(tb_vf[IFLA_VF_MAC]);
            if (vf_mac && vf_mac->vf == vf)  {
                rc = nla_parse_nested(tb_vf_stats, IFLA_VF_STATS_MAX,
                                      tb_vf[IFLA_VF_STATS],
                                      ifla_vfstats_policy);
                if (rc < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("error parsing IFLA_VF_STATS"));
                     return rc;
                }

                stats->rx_bytes = nla_get_u64(tb_vf_stats[IFLA_VF_STATS_RX_BYTES]);
                stats->tx_bytes = nla_get_u64(tb_vf_stats[IFLA_VF_STATS_TX_BYTES]);
                stats->rx_packets = nla_get_u64(tb_vf_stats[IFLA_VF_STATS_RX_PACKETS]);
                stats->tx_packets = nla_get_u64(tb_vf_stats[IFLA_VF_STATS_TX_PACKETS]);
                rc = 0;
            }
        }

        if (rc == 0)
            break;
    }
    if (rc < 0)
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("couldn't find IFLA_VF_INFO for VF %1$d in netlink response"),
                       vf);
    return rc;
}

static int
virNetDevGetVfConfig(const char *ifname, int vf, virMacAddr *mac,
                     int *vlanid)
{
    g_autofree void *nlData = NULL;
    struct nlattr *tb[IFLA_MAX + 1] = {NULL, };
    int ifindex = -1;

    if (virNetlinkDumpLink(ifname, ifindex, &nlData, tb, 0, 0) < 0)
        return -1;

    return virNetDevParseVfInfo(tb, vf, mac, vlanid, NULL);
}


/**
 * virNetDevVFInterfaceStats:
 * @vfAddr: PCI address of a VF
 * @stats: returns stats of the VF interface
 *
 * Get the VF interface from kernel by netlink.
 * Returns 0 on success, -1 on failure.
 */
int
virNetDevVFInterfaceStats(virPCIDeviceAddress *vfAddr,
                          virDomainInterfaceStatsPtr stats)
{
    g_autofree void *nlData = NULL;
    struct nlattr *tb[IFLA_MAX + 1] = {NULL, };
    g_autofree char *vfSysfsPath = NULL;
    g_autofree char *pfname = NULL;
    int vf = -1;

    if (virPCIDeviceAddressGetSysfsFile(vfAddr, &vfSysfsPath) < 0)
        return -1;

    if (!virPCIIsVirtualFunction(vfSysfsPath)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("'%1$s' is not a VF device"), vfSysfsPath);
       return -1;
    }

    if (virPCIGetVirtualFunctionInfo(vfSysfsPath, -1, &pfname, &vf) < 0)
        return -1;

    if (virNetlinkDumpLink(pfname, -1, &nlData, tb, 0, 0) < 0)
        return -1;

    return virNetDevParseVfInfo(tb, vf, NULL, NULL, stats);
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
    const char *pfDevName = NULL;
    g_autofree char *pfDevOrig = NULL;
    g_autofree char *vfDevOrig = NULL;
    virMacAddr oldMAC;
    char MACStr[VIR_MAC_STRING_BUFLEN];
    int oldVlanTag = -1;
    g_autofree char *filePath = NULL;
    g_autofree char *fileStr = NULL;
    g_autoptr(virJSONValue) configJSON = NULL;

    if (vf >= 0) {
        /* linkdev is the PF */
        pfDevName = linkdev;

        /* linkdev should get the VF's netdev name (or NULL if none) */
        if (virNetDevPFGetVF(pfDevName, vf, &vfDevOrig) < 0)
            return -1;

        linkdev = vfDevOrig;
        saveVlan = true;

    } else if (virNetDevIsVirtualFunction(linkdev) == 1) {
        /* when vf is -1, linkdev might be a standard netdevice (not
         * SRIOV), or it might be an SRIOV VF. If it's a VF, normalize
         * it to PF + VFname
         */

        if (virNetDevGetVirtualFunctionInfo(linkdev, &pfDevOrig, &vf) < 0)
            return -1;
        pfDevName = pfDevOrig;
    }

    if (pfDevName) {
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
            return -1;

        if (!pfIsOnline) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to configure VF %1$d of PF '%2$s' because the PF is not online. Please change host network config to put the PF online."),
                           vf, pfDevName);
            return -1;
        }
    }

    configJSON = virJSONValueNewObject();

    /* if there is a PF, it's now in pfDevName, and linkdev is either
     * the VF's name, or NULL (if the VF isn't bound to a net driver
     * on the host)
     */

    if (pfDevName && saveVlan) {
        filePath = g_strdup_printf("%s/%s_vf%d", stateDir, pfDevName, vf);

        /* get admin MAC and vlan tag */
        if (virNetDevGetVfConfig(pfDevName, vf, &oldMAC, &oldVlanTag) < 0)
            return -1;

        if (virJSONValueObjectAppendString(configJSON,
                                           VIR_NETDEV_KEYNAME_ADMIN_MAC,
                                           virMacAddrFormat(&oldMAC, MACStr)) < 0 ||
            virJSONValueObjectAppendNumberInt(configJSON,
                                              VIR_NETDEV_KEYNAME_VLAN_TAG,
                                              oldVlanTag) < 0) {
            return -1;
        }

    } else {
        filePath = g_strdup_printf("%s/%s", stateDir, linkdev);
    }

    if (linkdev) {
        if (virNetDevGetMAC(linkdev, &oldMAC) < 0)
            return -1;

        /* for interfaces with no pfDevName (i.e. not a VF, this will
         * be the only value in the file.
         */
        if (virJSONValueObjectAppendString(configJSON, VIR_NETDEV_KEYNAME_MAC,
                                           virMacAddrFormat(&oldMAC, MACStr)) < 0)
           return -1;
    }

    if (!(fileStr = virJSONValueToString(configJSON, true)))
        return -1;

    if (virFileWriteStr(filePath, fileStr, 0600) < 0) {
        virReportSystemError(errno,
                             _("Unable to preserve mac/vlan tag for device = %1$s, vf = %2$d"),
                             linkdev, vf);
        return -1;
    }

    return 0;
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
 * Returns 0 on success, -1 on failure. It is *NOT* considered failure
 * if no file is found to read. In that case, adminMAC, vlan, and MAC
 * are set to NULL, and success is returned.
 *
 * The caller MUST free adminMAC, vlan, and MAC when it is finished
 * with them (they will be NULL if they weren't found in the file)
 *
 */
int
virNetDevReadNetConfig(const char *linkdev, int vf,
                       const char *stateDir,
                       virMacAddr **adminMAC,
                       virNetDevVlan **vlan,
                       virMacAddr **MAC)
{
    int ret = -1;
    const char *pfDevName = NULL;
    g_autofree char *pfDevOrig = NULL;
    g_autofree char *vfDevOrig = NULL;
    g_autofree char *filePath = NULL;
    g_autofree char *fileStr = NULL;
    g_autoptr(virJSONValue) configJSON = NULL;
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

        if (virNetDevGetVirtualFunctionInfo(linkdev, &pfDevOrig, &vf) < 0)
            goto cleanup;
        pfDevName = pfDevOrig;
    }

    /* if there is a PF, it's now in pfDevName, and linkdev is either
     * the VF's name, or NULL (if the VF isn't bound to a net driver
     * on the host)
     */

    if (pfDevName) {
        filePath = g_strdup_printf("%s/%s_vf%d", stateDir, pfDevName, vf);

        if (linkdev && !virFileExists(filePath)) {
            /* the device may have been stored in a file named for the
             * VF due to saveVlan == false (or an older version of
             * libvirt), so reset filePath and pfDevName so we'll try
             * the other filename.
             */
            VIR_FREE(filePath);
            pfDevName = NULL;
        }
    }

    if (!pfDevName)
        filePath = g_strdup_printf("%s/%s", stateDir, linkdev);

    if (!virFileExists(filePath)) {
        /* having no file to read is not necessarily an error, so we
         * just return success, but with MAC, adminMAC, and vlan set to NULL
         */
        ret = 0;
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
                               _("cannot parse vlan tag '%1$s' from file '%2$s'"),
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
                           _("invalid json in net device saved config file '%1$s': '%2$.60s'"),
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
                           _("network device saved config file '%1$s' has unexpected contents, missing both 'MAC' and 'adminMAC': '%2$.60s'"),
                           filePath, fileStr);
            goto cleanup;
        }
    }

    if (MACStr) {
        *MAC = g_new0(virMacAddr, 1);

        if (virMacAddrParse(MACStr, *MAC) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse MAC address '%1$s' from file '%2$s'"),
                           MACStr, filePath);
            goto cleanup;
        }
    }

    if (adminMACStr) {
        *adminMAC = g_new0(virMacAddr, 1);

        if (virMacAddrParse(adminMACStr, *adminMAC) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse MAC address '%1$s' from file '%2$s'"),
                           adminMACStr, filePath);
            goto cleanup;
        }
    }

    if (vlanTag != -1) {
        /* construct a simple virNetDevVlan object with a single tag */
        *vlan = g_new0(virNetDevVlan, 1);
        (*vlan)->tag = g_new0(unsigned int, 1);
        (*vlan)->nTags = 1;
        (*vlan)->tag[0] = vlanTag;
    }

    /* we won't need the file again */
    unlink(filePath);

    ret = 0;
 cleanup:
    if (ret < 0) {
        VIR_FREE(*adminMAC);
        VIR_FREE(*MAC);
        VIR_FREE(*vlan);
    }

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
                      const virNetDevVlan *vlan,
                      const virMacAddr *MAC,
                      bool setVlan)
{
    char MACStr[VIR_MAC_STRING_BUFLEN];
    const char *pfDevName = NULL;
    g_autofree char *pfDevOrig = NULL;
    g_autofree char *vfDevOrig = NULL;
    g_autofree int *vlanTag = NULL;
    g_autoptr(virPCIDevice) vfPCIDevice = NULL;

    if (vf >= 0) {
        /* linkdev is the PF */
        pfDevName = linkdev;

        /* linkdev should get the VF's netdev name (or NULL if none) */
        if (virNetDevPFGetVF(pfDevName, vf, &vfDevOrig) < 0)
            return -1;

        linkdev = vfDevOrig;

    } else if (virNetDevIsVirtualFunction(linkdev) == 1) {
        /* when vf is -1, linkdev might be a standard netdevice (not
         * SRIOV), or it might be an SRIOV VF. If it's a VF, normalize
         * it to PF + VFname
         */

        if (virNetDevGetVirtualFunctionInfo(linkdev, &pfDevOrig, &vf))
            return -1;
        pfDevName = pfDevOrig;
    }


    if (!pfDevName) {
        /* if it's not SRIOV, then we can't set the admin MAC address
         * or vlan tag
         */
        if (adminMAC) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("admin MAC can only be set for SR-IOV VFs, but %1$s is not a VF"),
                           linkdev);
            return -1;
        }

        if (vlan) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("vlan can only be set for SR-IOV VFs, but %1$s is not a VF"),
                           linkdev);
            return -1;
        }

    } else {
        if (vlan) {
            if (vlan->nTags != 1 || vlan->trunk) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("vlan trunking is not supported by SR-IOV network devices"));
                return -1;
            }

            if (!setVlan) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("vlan tag set for interface %1$s but caller requested it not be set"));
                return -1;
            }

            vlanTag = g_new0(int, 1);
            *vlanTag = vlan->tag[0];

        } else if (setVlan) {
            vlanTag = g_new0(int, 1);
            /* Assure any existing vlan tag is reset. */
            *vlanTag = 0;
        } else {
            /* Indicate that setting a VLAN has not been explicitly requested.
             * This allows selected errors in clearing a VF VLAN to be ignored. */
            vlanTag = NULL;
        }
    }

    if (MAC) {
        int setMACrc;

        if (!linkdev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("VF %1$d of PF '%2$s' is not bound to a net driver, so its MAC address cannot be set to %3$s"),
                           vf, pfDevName, virMacAddrFormat(MAC, MACStr));
            return -1;
        }

        setMACrc = virNetDevSetMACInternal(linkdev, MAC, !!pfDevOrig);
        if (setMACrc < 0) {
            bool allowRetry = false;
            int retries = 100;

            /* if pfDevOrig == NULL, this isn't a VF, so we've failed */
            if (!pfDevOrig ||
                (errno != EADDRNOTAVAIL && errno != EPERM))
                return -1;

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
                return -1;
            }

            /* admin MAC is set, now we need to construct a virPCIDevice
             * object so we can call virPCIDeviceRebind()
             */
            if (!(vfPCIDevice = virNetDevGetPCIDevice(linkdev)))
                return -1;

            /* Rebind the device. This should set the proper MAC address */
            if (virPCIDeviceRebind(vfPCIDevice) < 0)
                return -1;

            /* Wait until virNetDevGetIndex for the VF netdev returns success.
             * This indicates that the device is ready to be used. If we don't
             * wait, then upcoming operations on the VF may fail.
             */
            while (retries-- > 0 && !virNetDevExists(linkdev))
               g_usleep(1000);
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

    if (adminMAC || vlanTag) {
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
                return -1;

            allowRetry = false;
            if (virNetDevSetVfConfig(pfDevName, vf,
                                     &altZeroMAC, vlanTag, &allowRetry) < 0) {
                return -1;
            }
        }
    }

    return 0;
}


#else /* defined(WITH_LIBNL) */


int
virNetDevSaveNetConfig(const char *linkdev G_GNUC_UNUSED,
                       int vf G_GNUC_UNUSED,
                       const char *stateDir G_GNUC_UNUSED,
                       bool saveVlan G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to save net device config on this platform"));
    return -1;
}


int
virNetDevReadNetConfig(const char *linkdev G_GNUC_UNUSED,
                       int vf G_GNUC_UNUSED,
                       const char *stateDir G_GNUC_UNUSED,
                       virMacAddr **adminMAC G_GNUC_UNUSED,
                       virNetDevVlan **vlan G_GNUC_UNUSED,
                       virMacAddr **MAC G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to read net device config on this platform"));
    return -1;
}


int
virNetDevSetNetConfig(const char *linkdev G_GNUC_UNUSED,
                      int vf G_GNUC_UNUSED,
                      const virMacAddr *adminMAC G_GNUC_UNUSED,
                      const virNetDevVlan *vlan G_GNUC_UNUSED,
                      const virMacAddr *MAC G_GNUC_UNUSED,
                      bool setVlan G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to set net device config on this platform"));
    return -1;
}


int
virNetDevVFInterfaceStats(virPCIDeviceAddress *vfAddr G_GNUC_UNUSED,
                          virDomainInterfaceStatsPtr stats G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to get VF net device stats on this platform"));
    return -1;
}

int
virNetDevSendVfSetLinkRequest(const char *ifname G_GNUC_UNUSED,
                              int vfInfoType G_GNUC_UNUSED,
                              const void *payload G_GNUC_UNUSED,
                              const size_t payloadLen G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to send a VF SETLINK request on this platform"));
    return -ENOSYS;
}

int
virNetDevSetVfVlan(const char *ifname G_GNUC_UNUSED,
                   int vf G_GNUC_UNUSED,
                   const int *vlanid G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to set a VF VLAN on this platform"));
    return -ENOSYS;
}

int
virNetDevSetVfMac(const char *ifname G_GNUC_UNUSED,
                  int vf G_GNUC_UNUSED,
                  const virMacAddr *macaddr G_GNUC_UNUSED,
                  bool *allowRetry G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to set a VF MAC on this platform"));
    return -ENOSYS;
}

int
virNetDevSetVfConfig(const char *ifname G_GNUC_UNUSED,
                     int vf G_GNUC_UNUSED,
                     const virMacAddr *macaddr G_GNUC_UNUSED,
                     const int *vlanid G_GNUC_UNUSED,
                     bool *allowRetry G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to set a VF config on this platform"));
    return -ENOSYS;
}


#endif /* defined(WITH_LIBNL) */

VIR_ENUM_IMPL(virNetDevIfState,
              VIR_NETDEV_IF_STATE_LAST,
              "" /* value of zero means no state */,
              "unknown", "notpresent",
              "down", "lowerlayerdown",
              "testing", "dormant", "up",
);

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
              "txudptnl",
              "switchdev",
);

#ifdef __linux__
int
virNetDevGetLinkInfo(const char *ifname,
                     virNetDevIfLink *lnk)
{
    g_autofree char *path = NULL;
    g_autofree char *buf = NULL;
    char *tmp;
    int tmp_state;
    unsigned int tmp_speed;

    if (virNetDevSysfsFile(&path, ifname, "operstate") < 0)
        return -1;

    /* The device may have been removed or moved by the time we got here.
     * Obviously attempting to get LinkInfo on a no longer existing device
     * is useless, so stop processing. If we got here via the udev monitor
     * a remove or move event will follow and we will be able to get valid
     * LinkInfo at that time */
    if (!virFileExists(path)) {
        VIR_INFO("The interface '%s' was removed before we could query it.",
                 ifname);
        return -1;
    }

    if (virFileReadAll(path, 1024, &buf) < 0) {
        virReportSystemError(errno,
                             _("unable to read: %1$s"),
                             path);
        return -1;
    }

    if (!(tmp = strchr(buf, '\n'))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse: %1$s"),
                       buf);
        return -1;
    }

    *tmp = '\0';

    /* We shouldn't allow 0 here, because
     * virInterfaceState enum starts from 1. */
    if ((tmp_state = virNetDevIfStateTypeFromString(buf)) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse: %1$s"),
                       buf);
        return -1;
    }

    lnk->state = tmp_state;

    /* Shortcut to avoid some kernel issues. If link is not up several drivers
     * report several misleading values. While igb reports 65535, realtek goes
     * with 10. To avoid muddying XML with insane values, don't report link
     * speed if that's the case. */
    if (lnk->state != VIR_NETDEV_IF_STATE_UP) {
        lnk->speed = 0;
        return 0;
    }

    VIR_FREE(path);
    VIR_FREE(buf);

    if (virNetDevSysfsFile(&path, ifname, "speed") < 0)
        return -1;

    if (virFileReadAllQuiet(path, 1024, &buf) < 0) {
        /* Some devices doesn't report speed, in which case we get EINVAL */
        if (errno == EINVAL)
            return 0;
        virReportSystemError(errno,
                             _("unable to read: %1$s"),
                             path);
        return -1;
    }

    if (virStrToLong_ui(buf, &tmp, 10, &tmp_speed) < 0 ||
        *tmp != '\n') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse: %1$s"),
                       buf);
        return -1;
    }

    lnk->speed = tmp_speed;

    return 0;
}

#else

int
virNetDevGetLinkInfo(const char *ifname,
                     virNetDevIfLink *lnk)
{
    /* Port me */
    VIR_DEBUG("Getting link info on %s is not implemented on this platform",
              ifname);
    lnk->speed = lnk->state = 0;
    return 0;
}
#endif /* defined(__linux__) */


#if defined(SIOCADDMULTI) && defined(WITH_STRUCT_IFREQ) && \
    defined(WITH_STRUCT_IFREQ_IFR_HWADDR)
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
                      virMacAddr *macaddr)
{
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
    virMacAddrGetRaw(macaddr, (unsigned char *)ifr.ifr_hwaddr.sa_data);

    if (ioctl(fd, SIOCADDMULTI, &ifr) < 0) {
        char macstr[VIR_MAC_STRING_BUFLEN];
        virReportSystemError(errno,
                             _("Cannot add multicast MAC %1$s on '%2$s' interface"),
                             virMacAddrFormat(macaddr, macstr), ifname);
        return -1;
    }

    return 0;
}
#else
int virNetDevAddMulti(const char *ifname G_GNUC_UNUSED,
                      virMacAddr *macaddr G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to add address to interface multicast list on this platform"));
    return -1;
}
#endif

#if defined(SIOCDELMULTI) && defined(WITH_STRUCT_IFREQ) && \
    defined(WITH_STRUCT_IFREQ_IFR_HWADDR)
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
                      virMacAddr *macaddr)
{
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    ifr.ifr_hwaddr.sa_family = AF_UNSPEC;
    virMacAddrGetRaw(macaddr, (unsigned char *)ifr.ifr_hwaddr.sa_data);

    if (ioctl(fd, SIOCDELMULTI, &ifr) < 0) {
        char macstr[VIR_MAC_STRING_BUFLEN];
        virReportSystemError(errno,
                             _("Cannot add multicast MAC %1$s on '%2$s' interface"),
                             virMacAddrFormat(macaddr, macstr), ifname);
        return -1;
    }

    return 0;
}
#else
int virNetDevDelMulti(const char *ifname G_GNUC_UNUSED,
                      virMacAddr *macaddr G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to delete address from interface multicast list on this platform"));
    return -1;
}
#endif

static int virNetDevParseMcast(char *buf, virNetDevMcastEntry *mcast)
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
                                 _("failed to parse multicast address from '%1$s'"),
                                 buf);
            return -1;
        }

        switch ((virMCastType)ifindex) {
            case VIR_MCAST_TYPE_INDEX_TOKEN:
                if (virStrToLong_i(token, &endptr, 10, &num) < 0) {
                    virReportSystemError(EINVAL,
                                         _("Failed to parse interface index from '%1$s'"),
                                         buf);
                    return -1;

                }
                mcast->idx = num;
                break;
            case VIR_MCAST_TYPE_NAME_TOKEN:
                if (virStrcpy(mcast->name, token, VIR_MCAST_NAME_LEN) < 0) {
                    virReportSystemError(EINVAL,
                                         _("Failed to parse network device name from '%1$s'"),
                                         buf);
                    return -1;
                }
                break;
            case VIR_MCAST_TYPE_USERS_TOKEN:
                if (virStrToLong_i(token, &endptr, 10, &num) < 0) {
                    virReportSystemError(EINVAL,
                                         _("Failed to parse users from '%1$s'"),
                                         buf);
                    return -1;

                }
                mcast->users = num;
                break;
            case VIR_MCAST_TYPE_GLOBAL_TOKEN:
                if (virStrToLong_i(token, &endptr, 10, &num) < 0) {
                    virReportSystemError(EINVAL,
                                         _("Failed to parse users from '%1$s'"),
                                         buf);
                    return -1;

                }
                mcast->global = num;
                break;
            case VIR_MCAST_TYPE_ADDR_TOKEN:
                if (virMacAddrParseHex((const char*)token,
                                       &mcast->macaddr) < 0) {
                    virReportSystemError(EINVAL,
                                         _("Failed to parse MAC address from '%1$s'"),
                                         buf);
                }
                break;

            case VIR_MCAST_TYPE_LAST:
                break;
        }
    }
    return 0;
}


static void virNetDevMcastListClear(virNetDevMcastList *mcast)
{
    size_t i;

    for (i = 0; i < mcast->nentries; i++)
       VIR_FREE(mcast->entries[i]);
    VIR_FREE(mcast->entries);
    mcast->nentries = 0;
}


static int virNetDevGetMcastList(const char *ifname,
                                 virNetDevMcastList *mcast)
{
    char *cur = NULL;
    g_autofree char *buf = NULL;
    char *next = NULL;
    int len;
    g_autoptr(virNetDevMcastEntry) entry = NULL;

    mcast->entries = NULL;
    mcast->nentries = 0;

    /* Read entire multicast table into memory */
    if ((len = virFileReadAll(PROC_NET_DEV_MCAST, MAX_MCAST_SIZE, &buf)) <= 0)
        return -1;

    cur = buf;
    while (cur) {
        if (!entry)
            entry = g_new0(virNetDevMcastEntry, 1);

        next = strchr(cur, '\n');
        if (next)
            next++;
        if (virNetDevParseMcast(cur, entry))
            return -1;

        /* Only return global multicast MAC addresses for
         * specified interface */
        if (entry->global && STREQ(ifname, entry->name)) {
            VIR_APPEND_ELEMENT(mcast->entries, mcast->nentries, entry);
        } else {
            memset(entry, 0, sizeof(virNetDevMcastEntry));
        }
        cur = next && ((next - buf) < len) ? next : NULL;
    }

    return 0;
}


VIR_ENUM_IMPL(virNetDevRxFilterMode,
              VIR_NETDEV_RX_FILTER_MODE_LAST,
              "none",
              "normal",
              "all",
);


static int virNetDevGetMulticastTable(const char *ifname,
                                      virNetDevRxFilter *filter)
{
    size_t i;
    int ret = -1;
    virNetDevMcastList mcast;
    filter->multicast.nTable = 0;
    filter->multicast.table = NULL;

    if (virNetDevGetMcastList(ifname, &mcast) < 0)
        goto cleanup;

    if (mcast.nentries > 0) {
        filter->multicast.table = g_new0(virMacAddr, mcast.nentries);

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


virNetDevRxFilter *
virNetDevRxFilterNew(void)
{
    return g_new0(virNetDevRxFilter, 1);
}


void
virNetDevRxFilterFree(virNetDevRxFilter *filter)
{
    if (filter) {
        g_free(filter->name);
        g_free(filter->unicast.table);
        g_free(filter->multicast.table);
        g_free(filter->vlan.table);
        g_free(filter);
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
                         virNetDevRxFilter **filter)
{
    int ret = -1;
    bool receive = false;
    virNetDevRxFilter *fil = virNetDevRxFilterNew();

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
        g_clear_pointer(&fil, virNetDevRxFilterFree);
    }

    *filter = fil;
    return ret;
}

#if __linux__

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
                     virBitmap **out)
{
    g_autofree char *eth_devpath = NULL;
    g_autofree char *eth_res_buf = NULL;
    g_autoptr(DIR) dirp = NULL;
    struct dirent *dp;

    if (!virFileExists(SYSFS_INFINIBAND_DIR))
        return 0;

    if (virDirOpen(&dirp, SYSFS_INFINIBAND_DIR) < 0)
        return -1;

    eth_devpath = g_strdup_printf(SYSFS_NET_DIR "%s/device/resource", ifname);

    /* If /sys/class/net/<ifname>/device/resource doesn't exist it is not a PCI
     * device and therefore it will not have RDMA. */
    if (!virFileExists(eth_devpath)) {
        return 0;
    }

    if (virFileReadAll(eth_devpath, RESOURCE_FILE_LEN, &eth_res_buf) < 0)
        return -1;

    while (virDirRead(dirp, &dp, SYSFS_INFINIBAND_DIR) > 0) {
        g_autofree char *ib_res_buf = NULL;
        g_autofree char *ib_devpath = g_strdup_printf(SYSFS_INFINIBAND_DIR "%s/device/resource",
                                                      dp->d_name);

        if (virFileReadAll(ib_devpath, RESOURCE_FILE_LEN, &ib_res_buf) > 0 &&
            STREQ(eth_res_buf, ib_res_buf)) {
            ignore_value(virBitmapSetBit(*out, VIR_NET_DEV_FEAT_RDMA));
            break;
        }
    }

    return 0;
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
virNetDevSendEthtoolIoctl(const char *ifname, int fd, struct ifreq *ifr)
{
    int ret = -1;

    ret = ioctl(fd, SIOCETHTOOL, ifr);
    if (ret != 0) {
        switch (errno) {
        case EINVAL: /* kernel doesn't support SIOCETHTOOL */
            VIR_DEBUG("ethtool ioctl: invalid request on %s", ifname);
            break;
        case EOPNOTSUPP: /* kernel doesn't support specific feature */
            VIR_DEBUG("ethtool ioctl: request not supported on %s", ifname);
            break;
        default:
            virReportSystemError(errno, _("ethtool ioctl error on %1$s"), ifname);
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
virNetDevFeatureAvailable(const char *ifname, int fd, struct ifreq *ifr, struct ethtool_value *cmd)
{
    ifr->ifr_data = (void*)cmd;
    if (virNetDevSendEthtoolIoctl(ifname, fd, ifr) == 0 &&
        cmd->data > 0)
        return true;
    return false;
}


static void
virNetDevGetEthtoolFeatures(const char *ifname,
                            virBitmap *bitmap,
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
        {ETHTOOL_GGSO, VIR_NET_DEV_FEAT_GGSO},
        {ETHTOOL_GGRO, VIR_NET_DEV_FEAT_GGRO},
    };

    /* ethtool masks */
    struct virNetDevEthtoolFeatureCmd flags[] = {
        {ETH_FLAG_LRO, VIR_NET_DEV_FEAT_LRO},
        {ETH_FLAG_RXVLAN, VIR_NET_DEV_FEAT_RXVLAN},
        {ETH_FLAG_TXVLAN, VIR_NET_DEV_FEAT_TXVLAN},
        {ETH_FLAG_NTUPLE, VIR_NET_DEV_FEAT_NTUPLE},
        {ETH_FLAG_RXHASH, VIR_NET_DEV_FEAT_RXHASH},
    };

    for (i = 0; i < G_N_ELEMENTS(ethtool_cmds); i++) {
        cmd.cmd = ethtool_cmds[i].cmd;
        if (virNetDevFeatureAvailable(ifname, fd, ifr, &cmd))
            ignore_value(virBitmapSetBit(bitmap, ethtool_cmds[i].feat));
    }

    cmd.cmd = ETHTOOL_GFLAGS;
    if (virNetDevFeatureAvailable(ifname, fd, ifr, &cmd)) {
        for (i = 0; i < G_N_ELEMENTS(flags); i++) {
            if (cmd.data & flags[i].cmd)
                ignore_value(virBitmapSetBit(bitmap, flags[i].feat));
        }
    }
}


# if defined(WITH_LIBNL)

/**
 * virNetDevGetFamilyId:
 * This function supplies the devlink family id
 *
 * @family_name: the name of the family to query
 * @family_id: family ID
 *
 * Returns: 0 if no family was found,
 *          1 if family was found (@family_id is set),
 *         -1 otherwise
 */
static int
virNetDevGetFamilyId(const char *family_name,
                     uint32_t *family_id)
{
    struct nl_msg *nl_msg = NULL;
    g_autofree struct nlmsghdr *resp = NULL;
    struct genlmsghdr gmsgh = {
        .cmd = CTRL_CMD_GETFAMILY,
        .version = DEVLINK_GENL_VERSION,
        .reserved = 0,
    };
    struct nlattr *tb[CTRL_ATTR_MAX + 1] = {NULL, };
    unsigned int recvbuflen;
    int ret = -1;

    nl_msg = virNetlinkMsgNew(GENL_ID_CTRL, NLM_F_REQUEST | NLM_F_ACK);

    if (nlmsg_append(nl_msg, &gmsgh, sizeof(gmsgh), NLMSG_ALIGNTO) < 0)
        goto cleanup;

    if (nla_put_string(nl_msg, CTRL_ATTR_FAMILY_NAME, family_name) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("allocated netlink buffer is too small"));
        goto cleanup;
    }

    if (virNetlinkCommand(nl_msg, &resp, &recvbuflen, 0, 0, NETLINK_GENERIC, 0) < 0)
        goto cleanup;

    if (nlmsg_parse(resp, sizeof(struct nlmsghdr), tb, CTRL_ATTR_MAX, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed netlink response message"));
        goto cleanup;
    }

    if (tb[CTRL_ATTR_FAMILY_ID] == NULL) {
        ret = 0;
        goto cleanup;
    }

    *family_id = *(uint32_t *)RTA_DATA(tb[CTRL_ATTR_FAMILY_ID]);
    ret = 1;

 cleanup:
    nlmsg_free(nl_msg);
    return ret;
}


/**
 * virNetDevSwitchdevFeature
 * This function checks for the availability of Switchdev feature
 * and add it to bitmap
 *
 * @ifname: name of the interface
 * @out: add Switchdev feature if exist to bitmap
 *
 * Returns 0 on success, -1 on failure.
 */
static int
virNetDevSwitchdevFeature(const char *ifname,
                          virBitmap **out)
{
    struct nl_msg *nl_msg = NULL;
    g_autofree struct nlmsghdr *resp = NULL;
    unsigned int recvbuflen;
    g_autofree struct nlattr **tb = g_new0(struct nlattr *, DEVLINK_ATTR_MAX + 1);
    g_autoptr(virPCIDevice) pci_device_ptr = NULL;
    struct genlmsghdr gmsgh = {
        .cmd = DEVLINK_CMD_ESWITCH_GET,
        .version = DEVLINK_GENL_VERSION,
        .reserved = 0,
    };
    const char *pci_name;
    g_autofree char *pfname = NULL;
    int is_vf = -1;
    int ret = -1;
    uint32_t family_id;
    int rv;

    if ((is_vf = virNetDevIsVirtualFunction(ifname)) < 0)
        return ret;

    if (is_vf == 1 && virNetDevGetPhysicalFunction(ifname, &pfname) < 0)
        return ret;

    pci_device_ptr = pfname ? virNetDevGetPCIDevice(pfname) :
                              virNetDevGetPCIDevice(ifname);
    /* No PCI device, then no feature bit to check/add */
    if (pci_device_ptr == NULL)
        return 0;

    if ((rv = virNetDevGetFamilyId(DEVLINK_GENL_NAME, &family_id)) <= 0)
        return rv;

    nl_msg = virNetlinkMsgNew(family_id, NLM_F_REQUEST | NLM_F_ACK);

    if (nlmsg_append(nl_msg, &gmsgh, sizeof(gmsgh), NLMSG_ALIGNTO) < 0)
        goto cleanup;

    pci_name = virPCIDeviceGetName(pci_device_ptr);

    if (nla_put(nl_msg, DEVLINK_ATTR_BUS_NAME, strlen("pci")+1, "pci") < 0 ||
        nla_put(nl_msg, DEVLINK_ATTR_DEV_NAME, strlen(pci_name)+1, pci_name) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("allocated netlink buffer is too small"));
        goto cleanup;
    }

    if (virNetlinkCommand(nl_msg, &resp, &recvbuflen, 0, 0, NETLINK_GENERIC, 0) < 0)
        goto cleanup;

    if (nlmsg_parse(resp, sizeof(struct genlmsghdr), tb, DEVLINK_ATTR_MAX, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed netlink response message"));
        goto cleanup;
    }

    if (tb[DEVLINK_ATTR_ESWITCH_MODE] &&
        *(int *)RTA_DATA(tb[DEVLINK_ATTR_ESWITCH_MODE]) == DEVLINK_ESWITCH_MODE_SWITCHDEV) {
        ignore_value(virBitmapSetBit(*out, VIR_NET_DEV_FEAT_SWITCHDEV));
    }

    ret = 0;

 cleanup:
    nlmsg_free(nl_msg);
    return ret;
}
# else
static int
virNetDevSwitchdevFeature(const char *ifname G_GNUC_UNUSED,
                          virBitmap **out G_GNUC_UNUSED)
{
    return 0;
}
# endif


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
virNetDevGFeatureAvailable(const char *ifname,
                           int fd,
                           struct ifreq *ifr,
                           struct ethtool_gfeatures *cmd)
{
    ifr->ifr_data = (void*)cmd;
    if (virNetDevSendEthtoolIoctl(ifname, fd, ifr) == 0)
        return !!FEATURE_BIT_IS_SET(cmd->features, TX_UDP_TNL, active);
    return false;
}


static int
virNetDevGetEthtoolGFeatures(const char *ifname,
                             virBitmap *bitmap,
                             int fd,
                             struct ifreq *ifr)
{
    g_autofree struct ethtool_gfeatures *g_cmd = NULL;

    g_cmd = g_malloc0(sizeof(struct ethtool_gfeatures) +
                      sizeof(struct ethtool_get_features_block) * GFEATURES_SIZE);

    g_cmd->cmd = ETHTOOL_GFEATURES;
    g_cmd->size = GFEATURES_SIZE;
    if (virNetDevGFeatureAvailable(ifname, fd, ifr, g_cmd))
        ignore_value(virBitmapSetBit(bitmap, VIR_NET_DEV_FEAT_TXUDPTNL));
    return 0;
}


/**
 * virNetDevSetCoalesce:
 * @ifname: interface name to modify
 * @coalesce: Coalesce settings to set or update
 * @update: Whether this is an update for existing settings or not
 *
 * This function sets the various coalesce settings for a given interface
 * @ifname and updates them back into @coalesce.
 *
 * Returns 0 in case of success or -1 on failure
 */
int virNetDevSetCoalesce(const char *ifname,
                         virNetDevCoalesce *coalesce,
                         bool update)
{
    struct ifreq ifr;
    struct ethtool_coalesce coal = {0};
    VIR_AUTOCLOSE fd = -1;

    if (!coalesce && !update)
        return 0;

    if (coalesce) {
        coal = (struct ethtool_coalesce) {
            .rx_max_coalesced_frames = coalesce->rx_max_coalesced_frames,
            .rx_coalesce_usecs_irq = coalesce->rx_coalesce_usecs_irq,
            .rx_max_coalesced_frames_irq = coalesce->rx_max_coalesced_frames_irq,
            .tx_coalesce_usecs = coalesce->tx_coalesce_usecs,
            .tx_max_coalesced_frames = coalesce->tx_max_coalesced_frames,
            .tx_coalesce_usecs_irq = coalesce->tx_coalesce_usecs_irq,
            .tx_max_coalesced_frames_irq = coalesce->tx_max_coalesced_frames_irq,
            .stats_block_coalesce_usecs = coalesce->stats_block_coalesce_usecs,
            .use_adaptive_rx_coalesce = coalesce->use_adaptive_rx_coalesce,
            .use_adaptive_tx_coalesce = coalesce->use_adaptive_tx_coalesce,
            .pkt_rate_low = coalesce->pkt_rate_low,
            .rx_coalesce_usecs_low = coalesce->rx_coalesce_usecs_low,
            .rx_max_coalesced_frames_low = coalesce->rx_max_coalesced_frames_low,
            .tx_coalesce_usecs_low = coalesce->tx_coalesce_usecs_low,
            .tx_max_coalesced_frames_low = coalesce->tx_max_coalesced_frames_low,
            .pkt_rate_high = coalesce->pkt_rate_high,
            .rx_coalesce_usecs_high = coalesce->rx_coalesce_usecs_high,
            .rx_max_coalesced_frames_high = coalesce->rx_max_coalesced_frames_high,
            .tx_coalesce_usecs_high = coalesce->tx_coalesce_usecs_high,
            .tx_max_coalesced_frames_high = coalesce->tx_max_coalesced_frames_high,
            .rate_sample_interval = coalesce->rate_sample_interval,
        };
    }

    coal.cmd = ETHTOOL_SCOALESCE;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    ifr.ifr_data = (void *) &coal;

    if (virNetDevSendEthtoolIoctl(ifname, fd, &ifr) < 0) {
        virReportSystemError(errno,
                             _("Cannot set coalesce info on '%1$s'"),
                             ifname);
        return -1;
    }

    if (coalesce) {
        coal = (struct ethtool_coalesce) {
            .cmd = ETHTOOL_GCOALESCE,
        };

        /* Don't fail if the update itself fails */
        if (virNetDevSendEthtoolIoctl(ifname, fd, &ifr) == 0) {
            coalesce->rx_max_coalesced_frames = coal.rx_max_coalesced_frames;
            coalesce->rx_coalesce_usecs_irq = coal.rx_coalesce_usecs_irq;
            coalesce->rx_max_coalesced_frames_irq = coal.rx_max_coalesced_frames_irq;
            coalesce->tx_coalesce_usecs = coal.tx_coalesce_usecs;
            coalesce->tx_max_coalesced_frames = coal.tx_max_coalesced_frames;
            coalesce->tx_coalesce_usecs_irq = coal.tx_coalesce_usecs_irq;
            coalesce->tx_max_coalesced_frames_irq = coal.tx_max_coalesced_frames_irq;
            coalesce->stats_block_coalesce_usecs = coal.stats_block_coalesce_usecs;
            coalesce->use_adaptive_rx_coalesce = coal.use_adaptive_rx_coalesce;
            coalesce->use_adaptive_tx_coalesce = coal.use_adaptive_tx_coalesce;
            coalesce->pkt_rate_low = coal.pkt_rate_low;
            coalesce->rx_coalesce_usecs_low = coal.rx_coalesce_usecs_low;
            coalesce->rx_max_coalesced_frames_low = coal.rx_max_coalesced_frames_low;
            coalesce->tx_coalesce_usecs_low = coal.tx_coalesce_usecs_low;
            coalesce->tx_max_coalesced_frames_low = coal.tx_max_coalesced_frames_low;
            coalesce->pkt_rate_high = coal.pkt_rate_high;
            coalesce->rx_coalesce_usecs_high = coal.rx_coalesce_usecs_high;
            coalesce->rx_max_coalesced_frames_high = coal.rx_max_coalesced_frames_high;
            coalesce->tx_coalesce_usecs_high = coal.tx_coalesce_usecs_high;
            coalesce->tx_max_coalesced_frames_high = coal.tx_max_coalesced_frames_high;
            coalesce->rate_sample_interval = coal.rate_sample_interval;
        }
    }

    return 0;
}


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
                     virBitmap **out)
{
    struct ifreq ifr;
    VIR_AUTOCLOSE fd = -1;

    *out = virBitmapNew(VIR_NET_DEV_FEAT_LAST);

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    virNetDevGetEthtoolFeatures(ifname, *out, fd, &ifr);

    if (virNetDevGetEthtoolGFeatures(ifname, *out, fd, &ifr) < 0)
        return -1;

    if (virNetDevRDMAFeature(ifname, out) < 0)
        return -1;

    if (virNetDevSwitchdevFeature(ifname, out) < 0)
        return -1;

    return 0;
}
#else
int
virNetDevGetFeatures(const char *ifname G_GNUC_UNUSED,
                     virBitmap **out G_GNUC_UNUSED)
{
    VIR_DEBUG("Getting network device features on %s is not implemented on this platform",
              ifname);
    return 0;
}

int virNetDevSetCoalesce(const char *ifname,
                         virNetDevCoalesce *coalesce,
                         bool update)
{
    if (!coalesce && !update)
        return 0;

    virReportSystemError(ENOSYS,
                         _("Cannot set coalesce info on interface '%1$s'"),
                         ifname);
    return -1;
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
    g_autoptr(virCommand) cmd = NULL;

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

    return virCommandRun(cmd, NULL);
}


/**
 * virNetDevReserveName:
 * @name: name of an existing network device
 *
 * Reserve a network device name, so that any new network device
 * created with an autogenerated name will use a number higher
 * than the number in the given device name.
 *
 * Returns nothing.
 */
void
virNetDevReserveName(const char *name)
{
    unsigned int id;
    const char *idstr = NULL;
    virNetDevGenNameType type;

    if (!name)
        return;

    if (STRPREFIX(name, VIR_NET_GENERATED_VNET_PREFIX))
        type = VIR_NET_DEV_GEN_NAME_VNET;
    else if (STRPREFIX(name, VIR_NET_GENERATED_MACVTAP_PREFIX))
        type = VIR_NET_DEV_GEN_NAME_MACVTAP;
    else if (STRPREFIX(name, VIR_NET_GENERATED_MACVLAN_PREFIX))
        type = VIR_NET_DEV_GEN_NAME_MACVLAN;
    else
        return;

    VIR_INFO("marking device in use: '%s'", name);

    idstr = name + strlen(virNetDevGenNames[type].prefix);

    if (virStrToLong_ui(idstr, NULL, 10, &id) >= 0) {
        VIR_LOCK_GUARD lock = virLockGuardLock(&virNetDevGenNames[type].mutex);

        if (virNetDevGenNames[type].lastID < (int)id)
            virNetDevGenNames[type].lastID = id;
    }
}


/**
 * virNetDevGenerateName:
 * @ifname: pointer to pointer to string which can be a template,
 *          NULL or user-provided name.
 * @type: type of the network device
 *
 * generate a new (currently unused) name for a new network device based
 * on @ifname. If string pointed by @ifname is a template, replace %d
 * with the reserved id; if that string is NULL, just generate a new
 * name. Keep trying new values until one is found that doesn't already
 * exist, or we've tried 10000 different names. Once a usable name is
 * found, replace the template with the actual name.
 *
 * Note: if string pointed by @ifname is NOT a template or NULL, leave
 * it unchanged and return it directly.
 *
 * Returns: 1 if @ifname already contains a valid name,
 *          0 on success (@ifname was generated),
 *         -1 on failure.
 */
int
virNetDevGenerateName(char **ifname, virNetDevGenNameType type)
{
    const char *prefix = virNetDevGenNames[type].prefix;
    double maxIDd = pow(10, IFNAMSIZ - 1 - strlen(prefix));
    int maxID = INT_MAX;
    int attempts = 0;

    /* The @ifname is not a template, leave it unchanged. */
    if (*ifname &&
        (strchr(*ifname, '%') != strrchr(*ifname, '%') ||
         strstr(*ifname, "%d") == NULL)) {
        return 1;
    }

    if (maxIDd <= (double)INT_MAX)
        maxID = (int)maxIDd;

    do {
        g_autofree char *try = NULL;
        int id = 0;

        VIR_WITH_MUTEX_LOCK_GUARD(&virNetDevGenNames[type].mutex) {
            id = ++virNetDevGenNames[type].lastID;

            /* reset before overflow */
            if (virNetDevGenNames[type].lastID >= maxID)
                virNetDevGenNames[type].lastID = -1;
        }

        if (*ifname)
            try = g_strdup_printf(*ifname, id);
        else
            try = g_strdup_printf("%s%d", prefix, id);

        if (!virNetDevExists(try)) {
            g_free(*ifname);
            *ifname = g_steal_pointer(&try);
            return 0;
        }
    } while (++attempts < 10000);

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("no unused %1$s names available"),
                   prefix);
    return -1;
}
