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

#include "virnetdevip.h"
#include "virnetdev.h"
#include "virnetlink.h"
#include "virfile.h"
#include "virerror.h"
#include "virlog.h"
#include "virstring.h"
#include "vircommand.h"
#include "viralloc.h"

#if WITH_GETIFADDRS
# include <ifaddrs.h>
#endif

#ifndef WIN32
# include <sys/ioctl.h>
#endif
#ifdef WITH_NET_IF_H
# include <net/if.h>
#endif
#include <fcntl.h>

#ifdef __linux__
# include <linux/sockios.h>
# include <linux/if_vlan.h>
# include <linux/ipv6_route.h>
#endif

#define PROC_NET_IPV6_ROUTE "/proc/net/ipv6_route"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.netdevip");

#if defined(WITH_LIBNL)

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
                                     virSocketAddr *broadcast,
                                     virSocketAddr *peer)
{
    struct nl_msg *nlmsg = NULL;
    struct ifaddrmsg ifa = { 0 };
    unsigned int ifindex;
    void *addrData = NULL;
    void *peerData = NULL;
    void *broadcastData = NULL;
    size_t addrDataLen;

    if (virNetDevGetIPAddressBinary(addr, &addrData, &addrDataLen) < 0)
        return NULL;

    if (peer && VIR_SOCKET_ADDR_VALID(peer)) {
        if (virNetDevGetIPAddressBinary(peer, &peerData, &addrDataLen) < 0)
            return NULL;
    } else if (broadcast) {
        if (virNetDevGetIPAddressBinary(broadcast, &broadcastData,
                                        &addrDataLen) < 0)
            return NULL;
    }

    /* Get the interface index */
    if ((ifindex = if_nametoindex(ifname)) == 0)
        return NULL;

    nlmsg = virNetlinkMsgNew(messageType,
                             NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);

    ifa.ifa_prefixlen = prefix;
    ifa.ifa_family = VIR_SOCKET_ADDR_FAMILY(addr);
    ifa.ifa_index = ifindex;
    ifa.ifa_scope = 0;

    if (nlmsg_append(nlmsg, &ifa, sizeof(ifa), NLMSG_ALIGNTO) < 0)
        goto buffer_too_small;

    if (nla_put(nlmsg, IFA_LOCAL, addrDataLen, addrData) < 0)
        goto buffer_too_small;

    if (peerData) {
        if (nla_put(nlmsg, IFA_ADDRESS, addrDataLen, peerData) < 0)
            goto buffer_too_small;
    }

    if (broadcastData) {
        if (nla_put(nlmsg, IFA_BROADCAST, addrDataLen, broadcastData) < 0)
            goto buffer_too_small;
    }

    return nlmsg;

 buffer_too_small:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("allocated netlink buffer is too small"));
    nlmsg_free(nlmsg);
    return NULL;
}

/**
 * virNetDevIPAddrAdd:
 * @ifname: the interface name
 * @addr: the IP address (IPv4 or IPv6)
 * @peer: The IP address of peer (IPv4 or IPv6)
 * @prefix: number of 1 bits in the netmask
 *
 * Add an IP address to an interface. This function *does not* remove
 * any previously added IP addresses - that must be done separately with
 * virNetDevIPAddrClear.
 *
 * Returns 0 in case of success or -1 in case of error.
 */
int
virNetDevIPAddrAdd(const char *ifname,
                   virSocketAddr *addr,
                   virSocketAddr *peer,
                   unsigned int prefix)
{
    unsigned int recvbuflen;
    g_autoptr(virNetlinkMsg) nlmsg = NULL;
    g_autoptr(virSocketAddr) broadcast = NULL;
    g_autofree struct nlmsghdr *resp = NULL;
    g_autofree char *ipStr = NULL;
    g_autofree char *peerStr = NULL;
    g_autofree char *bcastStr = NULL;

    ipStr = virSocketAddrFormat(addr);
    if (peer && VIR_SOCKET_ADDR_VALID(peer))
       peerStr = virSocketAddrFormat(peer);

    /* The caller needs to provide a correct address */
    if (VIR_SOCKET_ADDR_FAMILY(addr) == AF_INET &&
        !(peer && VIR_SOCKET_ADDR_VALID(peer))) {
        /* compute a broadcast address if this is IPv4 */
        broadcast = g_new0(virSocketAddr, 1);

        if (virSocketAddrBroadcastByPrefix(addr, prefix, broadcast) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to determine broadcast address for '%1$s/%2$d'"),
                           ipStr, prefix);
            return -1;
        }
        bcastStr = virSocketAddrFormat(broadcast);
    }

    VIR_DEBUG("Adding IP address %s/%d%s%s%s%s to %s",
              NULLSTR(ipStr), prefix,
              peerStr ? " peer " : "", peerStr ? peerStr : "",
              bcastStr ? " bcast " : "", bcastStr ? bcastStr : "",
              ifname);

    if (!(nlmsg = virNetDevCreateNetlinkAddressMessage(RTM_NEWADDR, ifname,
                                                       addr, prefix,
                                                       broadcast, peer)))
        return -1;

    if (virNetlinkCommand(nlmsg, &resp, &recvbuflen,
                          0, 0, NETLINK_ROUTE, 0) < 0)
        return -1;


    if (virNetlinkGetErrorCode(resp, recvbuflen) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Failed to add IP address %1$s/%2$d%3$s%4$s%5$s%6$s to %7$s"),
                       ipStr, prefix,
                       peerStr ? " peer " : "", peerStr ? peerStr : "",
                       bcastStr ? " bcast " : "", bcastStr ? bcastStr : "",
                       ifname);
        return -1;
    }

    return 0;
}


/**
 * virNetDevIPAddrDel:
 * @ifname: the interface name
 * @addr: the IP address (IPv4 or IPv6)
 * @prefix: number of 1 bits in the netmask
 *
 * Delete an IP address from an interface.
 *
 * Returns 0 in case of success or -1 in case of error.
 */
int
virNetDevIPAddrDel(const char *ifname,
                   virSocketAddr *addr,
                   unsigned int prefix)
{
    unsigned int recvbuflen;
    g_autoptr(virNetlinkMsg) nlmsg = NULL;
    g_autofree struct nlmsghdr *resp = NULL;

    if (!(nlmsg = virNetDevCreateNetlinkAddressMessage(RTM_DELADDR, ifname,
                                                       addr, prefix,
                                                       NULL, NULL)))
        return -1;

    if (virNetlinkCommand(nlmsg, &resp, &recvbuflen, 0, 0,
                          NETLINK_ROUTE, 0) < 0)
        return -1;

    if (virNetlinkGetErrorCode(resp, recvbuflen) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Error removing IP address from %1$s"), ifname);
        return -1;
    }

    return 0;
}


/**
 * virNetDevIPRouteAdd:
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
virNetDevIPRouteAdd(const char *ifname,
                    virSocketAddr *addr,
                    unsigned int prefix,
                    virSocketAddr *gateway,
                    unsigned int metric)
{
    unsigned int recvbuflen;
    unsigned int ifindex;
    struct rtmsg rtmsg = { 0 };
    void *gatewayData = NULL;
    void *addrData = NULL;
    size_t addrDataLen;
    int errCode;
    virSocketAddr defaultAddr;
    virSocketAddr *actualAddr;
    g_autoptr(virNetlinkMsg) nlmsg = NULL;
    g_autofree char *toStr = NULL;
    g_autofree char *viaStr = NULL;
    g_autofree struct nlmsghdr *resp = NULL;

    actualAddr = addr;

    /* If we have no valid network address, then use the default one */
    if (!addr || !VIR_SOCKET_ADDR_VALID(addr)) {
        int family = VIR_SOCKET_ADDR_FAMILY(gateway);

        VIR_DEBUG("computing default address");

        if (family == AF_INET) {
            if (virSocketAddrParseIPv4(&defaultAddr, VIR_SOCKET_ADDR_IPV4_ALL) < 0)
                return -1;
        } else {
            if (virSocketAddrParseIPv6(&defaultAddr, VIR_SOCKET_ADDR_IPV6_ALL) < 0)
                return -1;
        }

        actualAddr = &defaultAddr;
    }

    toStr = virSocketAddrFormat(actualAddr);
    viaStr = virSocketAddrFormat(gateway);
    VIR_DEBUG("Adding route %s/%d via %s", toStr, prefix, viaStr);

    if (virNetDevGetIPAddressBinary(actualAddr, &addrData, &addrDataLen) < 0 ||
        virNetDevGetIPAddressBinary(gateway, &gatewayData, &addrDataLen) < 0)
        return -1;

    /* Get the interface index */
    if ((ifindex = if_nametoindex(ifname)) == 0)
        return -1;

    nlmsg = virNetlinkMsgNew(RTM_NEWROUTE,
                             NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL);

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
        return -1;

    if ((errCode = virNetlinkGetErrorCode(resp, recvbuflen)) < 0) {
        virReportSystemError(errCode, _("Error adding route to %1$s"), ifname);
        return -1;
    }

    return 0;

 buffer_too_small:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("allocated netlink buffer is too small"));
    return -1;
}


#else /* defined(WITH_LIBNL) */


int
virNetDevIPAddrAdd(const char *ifname,
                   virSocketAddr *addr,
                   virSocketAddr *peer,
                   unsigned int prefix)
{
    virSocketAddr broadcast;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *addrstr = NULL;
    g_autofree char *bcaststr = NULL;
    g_autofree char *peerstr = NULL;

    if (!(addrstr = virSocketAddrFormat(addr)))
        return -1;

    if (peer && VIR_SOCKET_ADDR_VALID(peer) && !(peerstr = virSocketAddrFormat(peer)))
        return -1;

    /* format up a broadcast address if this is IPv4 */
    if (!peerstr &&
        ((VIR_SOCKET_ADDR_IS_FAMILY(addr, AF_INET)) &&
         ((virSocketAddrBroadcastByPrefix(addr, prefix, &broadcast) < 0) ||
          !(bcaststr = virSocketAddrFormat(&broadcast))))) {
        return -1;
    }

# ifdef IFCONFIG
    cmd = virCommandNew(IFCONFIG);
    virCommandAddArg(cmd, ifname);
    if (VIR_SOCKET_ADDR_IS_FAMILY(addr, AF_INET6))
        virCommandAddArg(cmd, "inet6");
    else
        virCommandAddArg(cmd, "inet");
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    if (peerstr)
        virCommandAddArgList(cmd, "pointopoint", peerstr, NULL);
    if (bcaststr)
        virCommandAddArgList(cmd, "broadcast", bcaststr, NULL);
    virCommandAddArg(cmd, "alias");
# else
    cmd = virCommandNew(IP);
    virCommandAddArgList(cmd, "addr", "add", NULL);
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    if (peerstr)
        virCommandAddArgList(cmd, "peer", peerstr, NULL);
    if (bcaststr)
        virCommandAddArgList(cmd, "broadcast", bcaststr, NULL);
    virCommandAddArgList(cmd, "dev", ifname, NULL);
# endif

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    return 0;
}


int
virNetDevIPAddrDel(const char *ifname,
                   virSocketAddr *addr,
                   unsigned int prefix)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *addrstr = NULL;

    if (!(addrstr = virSocketAddrFormat(addr)))
        return -1;
# ifdef IFCONFIG
    cmd = virCommandNew(IFCONFIG);
    virCommandAddArg(cmd, ifname);
    if (VIR_SOCKET_ADDR_IS_FAMILY(addr, AF_INET6))
        virCommandAddArg(cmd, "inet6");
    else
        virCommandAddArg(cmd, "inet");
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    virCommandAddArg(cmd, "-alias");
# else
    cmd = virCommandNew(IP);
    virCommandAddArgList(cmd, "addr", "del", NULL);
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    virCommandAddArgList(cmd, "dev", ifname, NULL);
# endif

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    return 0;
}


int
virNetDevIPRouteAdd(const char *ifname,
                    virSocketAddr *addr,
                    unsigned int prefix,
                    virSocketAddr *gateway,
                    unsigned int metric)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *addrstr = NULL;
    g_autofree char *gatewaystr = NULL;

    if (!(addrstr = virSocketAddrFormat(addr)))
        return -1;
    if (!(gatewaystr = virSocketAddrFormat(gateway)))
        return -1;
    cmd = virCommandNew(IP);
    virCommandAddArgList(cmd, "route", "add", NULL);
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    virCommandAddArgList(cmd, "via", gatewaystr, "dev", ifname,
                         "proto", "static", "metric", NULL);
    virCommandAddArgFormat(cmd, "%u", metric);

    if (virCommandRun(cmd, NULL) < 0)
        return -1;

    return 0;
}

#endif /* defined(HAVE_LIBNL) */


#if defined(__linux__)

static int
virNetDevIPGetAcceptRA(const char *ifname)
{
    g_autofree char *path = NULL;
    g_autofree char *buf = NULL;
    char *suffix;
    int accept_ra = -1;

    path = g_strdup_printf("/proc/sys/net/ipv6/conf/%s/accept_ra",
                           ifname ? ifname : "all");

    if ((virFileReadAll(path, 512, &buf) < 0) ||
        (virStrToLong_i(buf, &suffix, 10, &accept_ra) < 0))
        return -1;

    return accept_ra;
}

/**
 * virNetDevIPCheckIPv6Forwarding
 *
 * This function checks if IPv6 routes have the RTF_ADDRCONF flag set,
 * indicating they have been created by the kernel's RA configuration
 * handling.  These routes are subject to being flushed when ipv6
 * forwarding is enabled unless accept_ra is explicitly set to "2".
 * This will most likely result in ipv6 networking being broken.
 *
 * Returns: true if it is safe to enable forwarding, or false if
 *          breakable routes are found.
 *
 **/
bool
virNetDevIPCheckIPv6Forwarding(void)
{
    int len;
    char *cur;
    g_autofree char *buf = NULL;
    /* lines are 150 chars */
    enum {MAX_ROUTE_SIZE = 150*1000000};

    /* This is /proc/sys/net/ipv6/conf/all/accept_ra */
    int all_accept_ra = virNetDevIPGetAcceptRA(NULL);

    /* Read ipv6 routes */
    if ((len = virFileReadAll(PROC_NET_IPV6_ROUTE,
                              MAX_ROUTE_SIZE, &buf)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to read %1$s for ipv6 forwarding checks"),
                       PROC_NET_IPV6_ROUTE);
        return false;
    }

    /* Dropping the last character to stop the loop */
    if (len > 0)
        buf[len-1] = '\0';

    cur = buf;
    while (cur) {
        char route[33], flags[9], iface[9];
        unsigned int flags_val;
        char *iface_val;
        int num;
        char *nl = strchr(cur, '\n');

        if (nl)
            *nl++ = '\0';

        num = sscanf(cur, "%32s %*s %*s %*s %*s %*s %*s %*s %8s %8s",
                     route, flags, iface);

        cur = nl;
        if (num != 3) {
            VIR_DEBUG("Failed to parse route line: %s", cur);
            continue;
        }

        if (virStrToLong_ui(flags, NULL, 16, &flags_val)) {
            VIR_DEBUG("Failed to parse flags: %s", flags);
            continue;
        }

        /* This is right justified, strip leading spaces */
        iface_val = &iface[0];
        while (*iface_val && g_ascii_isspace(*iface_val))
            iface_val++;

        VIR_DEBUG("%s iface %s flags %s : RTF_ADDRCONF %sset",
                  route, iface_val, flags,
                  (flags_val & RTF_ADDRCONF ? "" : "not "));

        if (flags_val & RTF_ADDRCONF) {
            int ret = virNetDevIPGetAcceptRA(iface_val);
            VIR_DEBUG("%s reports accept_ra of %d",
                      iface_val, ret);
            /* If the interface for this autoconfigured route
             * has accept_ra == 1, or it is default and the "all"
             * value of accept_ra == 1, it will be subject to
             * flushing if forwarding is enabled.
             */
            if (ret == 1 || (ret == 0 && all_accept_ra == 1)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Check the host setup: interface %1$s has kernel autoconfigured IPv6 routes and enabling forwarding without accept_ra set to 2 will cause the kernel to flush them, breaking networking."),
                               iface_val);
                return false;
            }
        }
    }
    return true;
}
#else

bool
virNetDevIPCheckIPv6Forwarding(void)
{
    VIR_DEBUG("No checks for IPv6 forwarding issues on non-Linux systems");
    return true;
}

#endif /* defined(__linux__) */


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
#if defined(SIOCGIFADDR) && defined(WITH_STRUCT_IFREQ)
static int
virNetDevGetIPv4AddressIoctl(const char *ifname,
                             virSocketAddr *addr)
{
    int fd = -1;
    int ret = -1;
    struct ifreq ifr;

    if ((fd = virNetDevSetupControl(ifname, &ifr)) < 0)
        return -1;

    if (ioctl(fd, SIOCGIFADDR, (char *)&ifr) < 0) {
        virReportSystemError(errno,
                             _("Unable to get IPv4 address for interface %1$s via ioctl"),
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
virNetDevGetIPv4AddressIoctl(const char *ifname G_GNUC_UNUSED,
                             virSocketAddr *addr G_GNUC_UNUSED)
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
#if WITH_GETIFADDRS
static int
virNetDevGetifaddrsAddress(const char *ifname,
                           virSocketAddr *addr)
{
    struct ifaddrs *ifap, *ifa;
    int ret = -1;

    if (getifaddrs(&ifap) < 0) {
        virReportSystemError(errno,
                             _("Could not get interface list for '%1$s'"),
                             ifname);
        return -1;
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (STRNEQ_NULLABLE(ifa->ifa_name, ifname))
            continue;

        if (!ifa->ifa_addr)
            continue;

        switch (ifa->ifa_addr->sa_family) {
        case AF_INET6:
            addr->len = sizeof(addr->data.inet6);
            memcpy(&addr->data.inet6, ifa->ifa_addr, addr->len);
            break;
        case AF_INET:
            addr->len = sizeof(addr->data.inet4);
            memcpy(&addr->data.inet4, ifa->ifa_addr, addr->len);
            break;
        default:
            continue;
        }
        addr->data.stor.ss_family = ifa->ifa_addr->sa_family;
        ret = 0;
        goto cleanup;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("no IP address found for interface '%1$s'"),
                   ifname);
 cleanup:
    freeifaddrs(ifap);
    return ret;
}

#else  /* ! WITH_GETIFADDRS */

static int
virNetDevGetifaddrsAddress(const char *ifname G_GNUC_UNUSED,
                           virSocketAddr *addr G_GNUC_UNUSED)
{
    return -2;
}

#endif

/**
 * virNetDevIPIPAddrGet:
 * @ifname: name of the interface whose IP address we want
 * @addr: filled with the IPv4 address
 *
 * This function gets the IPv4 address for the interface @ifname
 * and stores it in @addr
 *
 * Returns 0 on success, -errno on failure.
 */
int
virNetDevIPAddrGet(const char *ifname,
                   virSocketAddr *addr)
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

/* manipulating the virNetDevIPRoute object */
void
virNetDevIPRouteFree(virNetDevIPRoute *def)
{
    if (!def)
        return;
    g_free(def->family);
    g_free(def);
}

virSocketAddr *
virNetDevIPRouteGetAddress(virNetDevIPRoute *def)
{
    if (def)
        return &def->address;

    return NULL;
}

int
virNetDevIPRouteGetPrefix(virNetDevIPRoute *def)
{
    int prefix = 0;
    virSocketAddr zero;

    if (!def)
        return -1;

    /* this creates an all-0 address of the appropriate family */
    ignore_value(virSocketAddrParse(&zero,
                                    (VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET)
                                     ? VIR_SOCKET_ADDR_IPV4_ALL
                                     : VIR_SOCKET_ADDR_IPV6_ALL),
                                    VIR_SOCKET_ADDR_FAMILY(&def->address)));

    if (virSocketAddrEqual(&def->address, &zero)) {
        if (def->has_prefix && def->prefix == 0)
            prefix = 0;
        else if ((VIR_SOCKET_ADDR_IS_FAMILY(&def->netmask, AF_INET) &&
                  virSocketAddrEqual(&def->netmask, &zero)))
            prefix = 0;
        else
            prefix = virSocketAddrGetIPPrefix(&def->address, &def->netmask,
                                              def->prefix);
    } else {
        prefix = virSocketAddrGetIPPrefix(&def->address, &def->netmask,
                                          def->prefix);
    }

    return prefix;
}

unsigned int
virNetDevIPRouteGetMetric(virNetDevIPRoute *def)
{
    if (def && def->has_metric && def->metric > 0)
        return def->metric;

    return 1;
}

virSocketAddr *
virNetDevIPRouteGetGateway(virNetDevIPRoute *def)
{
    if (def)
        return &def->gateway;
    return NULL;
}

/* manipulating the virNetDevIPInfo object */

void
virNetDevIPInfoClear(virNetDevIPInfo *ip)
{
    size_t i;

    for (i = 0; i < ip->nips; i++)
        VIR_FREE(ip->ips[i]);
    VIR_FREE(ip->ips);
    ip->nips = 0;

    for (i = 0; i < ip->nroutes; i++)
        virNetDevIPRouteFree(ip->routes[i]);
    VIR_FREE(ip->routes);
    ip->nroutes = 0;
}


/**
 * virNetDevIPInfoAddToDev:
 * @ifname: name of device to operate on
 * @ipInfo: list of routes and IP addresses to add to this device
 *
 * All IP routes and IP addresses in ipInfo are added to the named device.
 *
 * Returns: 0 on success, -1 (and error reported) on failure.
 */
int
virNetDevIPInfoAddToDev(const char *ifname,
                        virNetDevIPInfo const *ipInfo)
{
    size_t i;
    int prefix;
    g_autofree char *ipStr = NULL;

    /* add all IP addresses */
    for (i = 0; i < ipInfo->nips; i++) {
        virNetDevIPAddr *ip = ipInfo->ips[i];

        if ((prefix = virSocketAddrGetIPPrefix(&ip->address,
                                               NULL, ip->prefix)) < 0) {
            ipStr = virSocketAddrFormat(&ip->address);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to determine prefix for IP address '%1$s'"),
                           NULLSTR(ipStr));
            return -1;
        }
        if (virNetDevIPAddrAdd(ifname, &ip->address, &ip->peer, prefix) < 0)
            return -1;
    }

    /* add all routes */
    for (i = 0; i < ipInfo->nroutes; i++) {
        virNetDevIPRoute *route = ipInfo->routes[i];

        if ((prefix = virNetDevIPRouteGetPrefix(route)) < 0) {
            ipStr = virSocketAddrFormat(&route->address);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to determine prefix for route with destination '%1$s'"),
                           NULLSTR(ipStr));
            return -1;
        }
        if (virNetDevIPRouteAdd(ifname, &route->address, prefix,
                                &route->gateway,
                                virNetDevIPRouteGetMetric(route)) < 0)
            return -1;
    }

    return 0;
}

void
virNetDevIPAddrFree(virNetDevIPAddr *ip)
{
    g_free(ip);
}
