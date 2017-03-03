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

#include "virnetdevip.h"
#include "virnetdev.h"
#include "virnetlink.h"
#include "virfile.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virutil.h"
#include "vircommand.h"

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

#define VIR_DAD_WAIT_TIMEOUT 20 /* seconds */

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.netdevip");

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
                                     virSocketAddr *broadcast,
                                     virSocketAddr *peer)
{
    struct nl_msg *nlmsg = NULL;
    struct ifaddrmsg ifa;
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
    virSocketAddr *broadcast = NULL;
    int ret = -1;
    struct nl_msg *nlmsg = NULL;
    struct nlmsghdr *resp = NULL;
    unsigned int recvbuflen;
    char *ipStr = NULL;
    char *peerStr = NULL;
    char *bcastStr = NULL;

    ipStr = virSocketAddrFormat(addr);
    if (peer && VIR_SOCKET_ADDR_VALID(peer))
       peerStr = virSocketAddrFormat(peer);

    /* The caller needs to provide a correct address */
    if (VIR_SOCKET_ADDR_FAMILY(addr) == AF_INET &&
        !(peer && VIR_SOCKET_ADDR_VALID(peer))) {
        /* compute a broadcast address if this is IPv4 */
        if (VIR_ALLOC(broadcast) < 0)
            goto cleanup;

        if (virSocketAddrBroadcastByPrefix(addr, prefix, broadcast) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to determine broadcast address for '%s/%d'"),
                       ipStr, prefix);
            goto cleanup;
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
        goto cleanup;

    if (virNetlinkCommand(nlmsg, &resp, &recvbuflen,
                          0, 0, NETLINK_ROUTE, 0) < 0)
        goto cleanup;


    if (virNetlinkGetErrorCode(resp, recvbuflen) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Failed to add IP address %s/%d%s%s%s%s to %s"),
                       ipStr, prefix,
                       peerStr ? " peer " : "", peerStr ? peerStr : "",
                       bcastStr ? " bcast " : "", bcastStr ? bcastStr : "",
                       ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(ipStr);
    VIR_FREE(peerStr);
    VIR_FREE(bcastStr);
    nlmsg_free(nlmsg);
    VIR_FREE(resp);
    VIR_FREE(broadcast);
    return ret;
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
    int ret = -1;
    struct nl_msg *nlmsg = NULL;
    struct nlmsghdr *resp = NULL;
    unsigned int recvbuflen;

    if (!(nlmsg = virNetDevCreateNetlinkAddressMessage(RTM_DELADDR, ifname,
                                                       addr, prefix,
                                                       NULL, NULL)))
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


/* return true if there is a known address with 'tentative' flag set */
static bool
virNetDevIPParseDadStatus(struct nlmsghdr *nlh, int len,
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
virNetDevIPWaitDadFinish(virSocketAddrPtr *addrs, size_t count)
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
        dad = virNetDevIPParseDadStatus(resp, recvbuflen, addrs, count);
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

static int
virNetDevIPGetAcceptRA(const char *ifname)
{
    char *path = NULL;
    char *buf = NULL;
    char *suffix;
    int accept_ra = -1;

    if (virAsprintf(&path, "/proc/sys/net/ipv6/conf/%s/accept_ra",
                    ifname ? ifname : "all") < 0)
        goto cleanup;

    if ((virFileReadAll(path, 512, &buf) < 0) ||
        (virStrToLong_i(buf, &suffix, 10, &accept_ra) < 0))
        goto cleanup;

 cleanup:
    VIR_FREE(path);
    VIR_FREE(buf);

    return accept_ra;
}

struct virNetDevIPCheckIPv6ForwardingData {
    bool hasRARoutes;

    /* Devices with conflicting accept_ra */
    char **devices;
    size_t ndevices;
};

static int
virNetDevIPCheckIPv6ForwardingCallback(const struct nlmsghdr *resp,
                                       void *opaque)
{
    struct rtmsg *rtmsg = NLMSG_DATA(resp);
    int accept_ra = -1;
    struct rtattr *rta;
    char *ifname = NULL;
    struct virNetDevIPCheckIPv6ForwardingData *data = opaque;
    int ret = 0;
    int len = RTM_PAYLOAD(resp);
    int oif = -1;

    /* Ignore messages other than route ones */
    if (resp->nlmsg_type != RTM_NEWROUTE)
        return ret;

    /* Extract a few attributes */
    for (rta = RTM_RTA(rtmsg); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        switch (rta->rta_type) {
        case RTA_OIF:
            oif = *(int *)RTA_DATA(rta);

            if (!(ifname = virNetDevGetName(oif)))
                goto error;
            break;
        }
    }

    /* No need to do anything else for non RA routes */
    if (rtmsg->rtm_protocol != RTPROT_RA)
        goto cleanup;

    data->hasRARoutes = true;

    /* Check the accept_ra value for the interface */
    accept_ra = virNetDevIPGetAcceptRA(ifname);
    VIR_DEBUG("Checking route for device %s, accept_ra: %d", ifname, accept_ra);

    if (accept_ra != 2 && VIR_APPEND_ELEMENT(data->devices, data->ndevices, ifname) < 0)
        goto error;

 cleanup:
    VIR_FREE(ifname);
    return ret;

 error:
    ret = -1;
    goto cleanup;
}

bool
virNetDevIPCheckIPv6Forwarding(void)
{
    struct nl_msg *nlmsg = NULL;
    bool valid = false;
    struct rtgenmsg genmsg;
    size_t i;
    struct virNetDevIPCheckIPv6ForwardingData data = {
        .hasRARoutes = false,
        .devices = NULL,
        .ndevices = 0
    };


    /* Prepare the request message */
    if (!(nlmsg = nlmsg_alloc_simple(RTM_GETROUTE,
                                     NLM_F_REQUEST | NLM_F_DUMP))) {
        virReportOOMError();
        goto cleanup;
    }

    memset(&genmsg, 0, sizeof(genmsg));
    genmsg.rtgen_family = AF_INET6;

    if (nlmsg_append(nlmsg, &genmsg, sizeof(genmsg), NLMSG_ALIGNTO) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("allocated netlink buffer is too small"));
        goto cleanup;
    }

    /* Send the request and loop over the responses */
    if (virNetlinkDumpCommand(nlmsg, virNetDevIPCheckIPv6ForwardingCallback,
                              0, 0, NETLINK_ROUTE, 0, &data) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to loop over IPv6 routes"));
        goto cleanup;
    }

    valid = !data.hasRARoutes || data.ndevices == 0;

    /* Check the global accept_ra if at least one isn't set on a
       per-device basis */
    if (!valid && data.hasRARoutes) {
        int accept_ra = virNetDevIPGetAcceptRA(NULL);
        valid = accept_ra == 2;
        VIR_DEBUG("Checked global accept_ra: %d", accept_ra);
    }

    if (!valid) {
        virBuffer buf = VIR_BUFFER_INITIALIZER;
        for (i = 0; i < data.ndevices; i++) {
            virBufferAdd(&buf, data.devices[i], -1);
            if (i < data.ndevices - 1)
                virBufferAddLit(&buf, ", ");
        }

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Check the host setup: enabling IPv6 forwarding with "
                         "RA routes without accept_ra set to 2 is likely to cause "
                         "routes loss. Interfaces to look at: %s"),
                       virBufferCurrentContent(&buf));
        virBufferFreeAndReset(&buf);
    }

 cleanup:
    nlmsg_free(nlmsg);
    for (i = 0; i < data.ndevices; i++)
        VIR_FREE(data.devices[i]);
    return valid;
}

#else /* defined(__linux__) && defined(HAVE_LIBNL) */


int
virNetDevIPAddrAdd(const char *ifname,
                   virSocketAddr *addr,
                   virSocketAddr *peer,
                   unsigned int prefix)
{
    virCommandPtr cmd = NULL;
    char *addrstr = NULL, *bcaststr = NULL, *peerstr = NULL;
    virSocketAddr broadcast;
    int ret = -1;

    if (!(addrstr = virSocketAddrFormat(addr)))
        goto cleanup;

    if (peer && VIR_SOCKET_ADDR_VALID(peer) && !(peerstr = virSocketAddrFormat(peer)))
        goto cleanup;

    /* format up a broadcast address if this is IPv4 */
    if (!peerstr && ((VIR_SOCKET_ADDR_IS_FAMILY(addr, AF_INET)) &&
        ((virSocketAddrBroadcastByPrefix(addr, prefix, &broadcast) < 0) ||
         !(bcaststr = virSocketAddrFormat(&broadcast))))) {
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
    if (peerstr)
        virCommandAddArgList(cmd, "pointopoint", peerstr, NULL);
    if (bcaststr)
        virCommandAddArgList(cmd, "broadcast", bcaststr, NULL);
    virCommandAddArg(cmd, "alias");
# else
    cmd = virCommandNew(IP_PATH);
    virCommandAddArgList(cmd, "addr", "add", NULL);
    virCommandAddArgFormat(cmd, "%s/%u", addrstr, prefix);
    if (peerstr)
        virCommandAddArgList(cmd, "peer", peerstr, NULL);
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
    VIR_FREE(peerstr);
    virCommandFree(cmd);
    return ret;
}


int
virNetDevIPAddrDel(const char *ifname,
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


int
virNetDevIPRouteAdd(const char *ifname,
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


/* return after DAD finishes for all known IPv6 addresses or an error */
int
virNetDevIPWaitDadFinish(virSocketAddrPtr *addrs ATTRIBUTE_UNUSED,
                         size_t count ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to wait for IPv6 DAD on this platform"));
    return -1;
}

bool
virNetDevIPCheckIPv6Forwarding(void)
{
    VIR_WARN("built without libnl: unable to check if IPv6 forwarding can be safely enabled");
    return true;
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

/* manipulating the virNetDevIPRoute object */
void
virNetDevIPRouteFree(virNetDevIPRoutePtr def)
{
    if (!def)
        return;
    VIR_FREE(def->family);
    VIR_FREE(def);
}

virSocketAddrPtr
virNetDevIPRouteGetAddress(virNetDevIPRoutePtr def)
{
    if (def)
        return &def->address;

    return NULL;
}

int
virNetDevIPRouteGetPrefix(virNetDevIPRoutePtr def)
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
virNetDevIPRouteGetMetric(virNetDevIPRoutePtr def)
{
    if (def && def->has_metric && def->metric > 0)
        return def->metric;

    return 1;
}

virSocketAddrPtr
virNetDevIPRouteGetGateway(virNetDevIPRoutePtr def)
{
    if (def)
        return &def->gateway;
    return NULL;
}

/* manipulating the virNetDevIPInfo object */

void
virNetDevIPInfoClear(virNetDevIPInfoPtr ip)
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
    int ret = -1;
    size_t i;
    int prefix;

    /* add all IP addresses */
    for (i = 0; i < ipInfo->nips; i++) {
        virNetDevIPAddrPtr ip = ipInfo->ips[i];

        if ((prefix = virSocketAddrGetIPPrefix(&ip->address,
                                               NULL, ip->prefix)) < 0) {
            char *ipStr = virSocketAddrFormat(&ip->address);

            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to determine prefix for IP address '%s'"),
                           NULLSTR(ipStr));
            VIR_FREE(ipStr);
            goto cleanup;
        }
        if (virNetDevIPAddrAdd(ifname, &ip->address, &ip->peer, prefix) < 0)
            goto cleanup;
    }

    /* add all routes */
    for (i = 0; i < ipInfo->nroutes; i++) {
        virNetDevIPRoutePtr route = ipInfo->routes[i];

        if ((prefix = virNetDevIPRouteGetPrefix(route)) < 0) {
            char *ipStr = virSocketAddrFormat(&route->address);

            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to determine prefix for route with destination '%s'"),
                           NULLSTR(ipStr));
            VIR_FREE(ipStr);
            goto cleanup;
        }
        if (virNetDevIPRouteAdd(ifname, &route->address, prefix,
                                &route->gateway,
                                virNetDevIPRouteGetMetric(route)) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}
