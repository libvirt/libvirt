/*
 * Copyright (C) 2009-2013, 2015 Red Hat, Inc.
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

#include "virsocket.h"

#define VIR_LOOPBACK_IPV4_ADDR "127.0.0.1"

typedef struct {
    union {
        struct sockaddr sa;
        struct sockaddr_storage stor;
        struct sockaddr_in inet4;
        struct sockaddr_in6 inet6;
#ifndef WIN32
        struct sockaddr_un un;
#endif
    } data;
    socklen_t len;
} virSocketAddr;

#define VIR_SOCKET_ADDR_VALID(s) \
    ((s)->data.sa.sa_family != AF_UNSPEC)

#define VIR_SOCKET_ADDR_IS_FAMILY(s, f) \
    ((s)->data.sa.sa_family == f)

#define VIR_SOCKET_ADDR_FAMILY(s) \
    ((s)->data.sa.sa_family)

#define VIR_SOCKET_ADDR_IPV4_ALL "0.0.0.0"
#define VIR_SOCKET_ADDR_IPV6_ALL "::"

#define VIR_SOCKET_ADDR_IPV4_ARPA "in-addr.arpa"
#define VIR_SOCKET_ADDR_IPV6_ARPA "ip6.arpa"

typedef struct _virSocketAddrRange virSocketAddrRange;
struct _virSocketAddrRange {
    virSocketAddr start;
    virSocketAddr end;
};

typedef struct _virPortRange virPortRange;
struct _virPortRange {
    unsigned int start;
    unsigned int end;
};

int virSocketAddrParse(virSocketAddr *addr,
                       const char *val,
                       int family);

int virSocketAddrParseAny(virSocketAddr *addr,
                          const char *val,
                          int family,
                          bool reportError);

int virSocketAddrParseIPv4(virSocketAddr *addr,
                           const char *val);

int virSocketAddrParseIPv6(virSocketAddr *addr,
                           const char *val);

int virSocketAddrResolveService(const char *service);

void virSocketAddrSetIPv4AddrNetOrder(virSocketAddr *addr, uint32_t val);
void virSocketAddrSetIPv4Addr(virSocketAddr *addr, uint32_t val);
void virSocketAddrSetIPv6AddrNetOrder(virSocketAddr *addr, uint32_t val[4]);
void virSocketAddrSetIPv6Addr(virSocketAddr *addr, uint32_t val[4]);

char *virSocketAddrFormat(const virSocketAddr *addr);
char *virSocketAddrFormatFull(const virSocketAddr *addr,
                              bool withService,
                              const char *separator);
char *virSocketAddrFormatWithPrefix(virSocketAddr *addr,
                                    unsigned int prefix,
                                    bool masked);

char *virSocketAddrGetPath(virSocketAddr *addr);

int virSocketAddrSetPort(virSocketAddr *addr, int port);

int virSocketAddrGetPort(virSocketAddr *addr);

int virSocketAddrGetRange(virSocketAddr *start,
                          virSocketAddr *end,
                          virSocketAddr *network,
                          int prefix);

int virSocketAddrIsNetmask(virSocketAddr *netmask);

int virSocketAddrCheckNetmask(virSocketAddr *addr1,
                              virSocketAddr *addr2,
                              virSocketAddr *netmask);
int virSocketAddrMask(const virSocketAddr *addr,
                      const virSocketAddr *netmask,
                      virSocketAddr *network);
int virSocketAddrMaskByPrefix(const virSocketAddr *addr,
                              unsigned int prefix,
                              virSocketAddr *network);
int virSocketAddrBroadcast(const virSocketAddr *addr,
                           const virSocketAddr *netmask,
                           virSocketAddr *broadcast);
int virSocketAddrBroadcastByPrefix(const virSocketAddr *addr,
                                   unsigned int prefix,
                                   virSocketAddr *broadcast);

int virSocketAddrGetNumNetmaskBits(const virSocketAddr *netmask);
int virSocketAddrPrefixToNetmask(unsigned int prefix,
                                 virSocketAddr *netmask,
                                 int family);
int virSocketAddrGetIPPrefix(const virSocketAddr *address,
                             const virSocketAddr *netmask,
                             int prefix);
bool virSocketAddrEqual(const virSocketAddr *s1,
                        const virSocketAddr *s2);
bool virSocketAddrIsPrivate(const virSocketAddr *addr);

bool virSocketAddrIsWildcard(const virSocketAddr *addr);

int virSocketAddrNumericFamily(const char *address);

bool virSocketAddrIsNumericLocalhost(const char *addr);

int virSocketAddrPTRDomain(const virSocketAddr *addr,
                           unsigned int prefix,
                           char **ptr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);

void virSocketAddrFree(virSocketAddr *addr);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSocketAddr, virSocketAddrFree);
