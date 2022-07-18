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

#pragma once

#include "virsocketaddr.h"

typedef struct _virNetDevIPAddr virNetDevIPAddr;
struct _virNetDevIPAddr {
    virSocketAddr address; /* ipv4 or ipv6 address */
    virSocketAddr peer;    /* ipv4 or ipv6 address of peer */
    unsigned int prefix;   /* number of 1 bits in the netmask */
};

typedef struct _virNetDevIPRoute virNetDevIPRoute;
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
 struct _virNetDevIPInfo {
    size_t nips;
    virNetDevIPAddr **ips;
    size_t nroutes;
    virNetDevIPRoute **routes;
};

/* manipulating/querying the netdev */
int virNetDevIPAddrAdd(const char *ifname,
                       virSocketAddr *addr,
                       virSocketAddr *peer,
                       unsigned int prefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT G_NO_INLINE;
int virNetDevIPRouteAdd(const char *ifname,
                        virSocketAddr *addr,
                        unsigned int prefix,
                        virSocketAddr *gateway,
                        unsigned int metric)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4)
    G_GNUC_WARN_UNUSED_RESULT;
int virNetDevIPAddrDel(const char *ifname,
                       virSocketAddr *addr,
                       unsigned int prefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
int virNetDevIPAddrGet(const char *ifname, virSocketAddr *addr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
bool virNetDevIPCheckIPv6Forwarding(void);
void virNetDevIPAddrFree(virNetDevIPAddr *ip);

/* virNetDevIPRoute object */
void virNetDevIPRouteFree(virNetDevIPRoute *def);
virSocketAddr *virNetDevIPRouteGetAddress(virNetDevIPRoute *def);
int virNetDevIPRouteGetPrefix(virNetDevIPRoute *def);
unsigned int virNetDevIPRouteGetMetric(virNetDevIPRoute *def);
virSocketAddr *virNetDevIPRouteGetGateway(virNetDevIPRoute *def);

/* virNetDevIPInfo object */
void virNetDevIPInfoClear(virNetDevIPInfo *ip);
int virNetDevIPInfoAddToDev(const char *ifname,
                            virNetDevIPInfo const *ipInfo);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNetDevIPAddr, virNetDevIPAddrFree);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNetDevIPRoute, virNetDevIPRouteFree);
