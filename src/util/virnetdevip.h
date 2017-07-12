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

#ifndef __VIR_NETDEVIP_H__
# define __VIR_NETDEVIP_H__

# include "virsocketaddr.h"

typedef struct _virNetDevIPAddr virNetDevIPAddr;
typedef virNetDevIPAddr *virNetDevIPAddrPtr;
struct _virNetDevIPAddr {
    virSocketAddr address; /* ipv4 or ipv6 address */
    virSocketAddr peer;    /* ipv4 or ipv6 address of peer */
    unsigned int prefix;   /* number of 1 bits in the netmask */
};

typedef struct _virNetDevIPRoute virNetDevIPRoute;
typedef virNetDevIPRoute *virNetDevIPRoutePtr;
struct _virNetDevIPRoute {
    char *family;               /* ipv4 or ipv6 - default is ipv4 */
    virSocketAddr address;      /* Routed Network IP address */

    /* One or the other of the following two will be used for a given
     * Network address, but never both. The parser guarantees this.
     * The virSocketAddrGetIPPrefix() can be used to get a
     * valid prefix.
     */
    virSocketAddr netmask;      /* ipv4 - either netmask or prefix specified */
    unsigned int prefix;        /* ipv6 - only prefix allowed */
    bool has_prefix;            /* prefix= was specified */
    unsigned int metric;        /* value for metric (defaults to 1) */
    bool has_metric;            /* metric= was specified */
    virSocketAddr gateway;      /* gateway IP address for ip-route */
};

/* A full set of all IP config info for a network device */
typedef struct _virNetDevIPInfo virNetDevIPInfo;
typedef virNetDevIPInfo *virNetDevIPInfoPtr;
 struct _virNetDevIPInfo {
    size_t nips;
    virNetDevIPAddrPtr *ips;
    size_t nroutes;
    virNetDevIPRoutePtr *routes;
};

/* manipulating/querying the netdev */
int virNetDevIPAddrAdd(const char *ifname,
                       virSocketAddr *addr,
                       virSocketAddr *peer,
                       unsigned int prefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NOINLINE;
int virNetDevIPRouteAdd(const char *ifname,
                        virSocketAddrPtr addr,
                        unsigned int prefix,
                        virSocketAddrPtr gateway,
                        unsigned int metric)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_RETURN_CHECK;
int virNetDevIPAddrDel(const char *ifname,
                       virSocketAddr *addr,
                       unsigned int prefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevIPAddrGet(const char *ifname, virSocketAddrPtr addr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevIPWaitDadFinish(virSocketAddrPtr *addrs, size_t count)
    ATTRIBUTE_NONNULL(1);
bool virNetDevIPCheckIPv6Forwarding(void);

/* virNetDevIPRoute object */
void virNetDevIPRouteFree(virNetDevIPRoutePtr def);
virSocketAddrPtr virNetDevIPRouteGetAddress(virNetDevIPRoutePtr def);
int virNetDevIPRouteGetPrefix(virNetDevIPRoutePtr def);
unsigned int virNetDevIPRouteGetMetric(virNetDevIPRoutePtr def);
virSocketAddrPtr virNetDevIPRouteGetGateway(virNetDevIPRoutePtr def);

/* virNetDevIPInfo object */
void virNetDevIPInfoClear(virNetDevIPInfoPtr ip);
int virNetDevIPInfoAddToDev(const char *ifname,
                            virNetDevIPInfo const *ipInfo);

#endif /* __VIR_NETDEVIP_H__ */
