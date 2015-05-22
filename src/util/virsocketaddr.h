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
 *
 * Authors:
 *     Daniel Veillard <veillard@redhat.com>
 *     Laine Stump <laine@laine.org>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_SOCKETADDR_H__
# define __VIR_SOCKETADDR_H__

# include "internal.h"

# include <netinet/in.h>
# include <sys/socket.h>
# ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
# endif

typedef struct {
    union {
        struct sockaddr sa;
        struct sockaddr_storage stor;
        struct sockaddr_in inet4;
        struct sockaddr_in6 inet6;
# ifdef HAVE_SYS_UN_H
        struct sockaddr_un un;
# endif
    } data;
    socklen_t len;
} virSocketAddr;

# define VIR_SOCKET_ADDR_VALID(s)               \
    ((s)->data.sa.sa_family != AF_UNSPEC)

# define VIR_SOCKET_ADDR_IS_FAMILY(s, f)        \
    ((s)->data.sa.sa_family == f)

# define VIR_SOCKET_ADDR_FAMILY(s)              \
    ((s)->data.sa.sa_family)

# define VIR_SOCKET_ADDR_DEFAULT_PREFIX 24
# define VIR_SOCKET_ADDR_IPV4_ALL "0.0.0.0"
# define VIR_SOCKET_ADDR_IPV6_ALL "::"

typedef virSocketAddr *virSocketAddrPtr;

typedef struct _virSocketAddrRange virSocketAddrRange;
typedef virSocketAddrRange *virSocketAddrRangePtr;
struct _virSocketAddrRange {
    virSocketAddr start;
    virSocketAddr end;
};

typedef struct _virPortRange virPortRange;
typedef virPortRange *virPortRangePtr;
struct _virPortRange {
    unsigned int start;
    unsigned int end;
};

int virSocketAddrParse(virSocketAddrPtr addr,
                       const char *val,
                       int family);

int virSocketAddrParseIPv4(virSocketAddrPtr addr,
                           const char *val);

int virSocketAddrParseIPv6(virSocketAddrPtr addr,
                           const char *val);

void virSocketAddrSetIPv4Addr(virSocketAddrPtr s, uint32_t addr);

char *virSocketAddrFormat(const virSocketAddr *addr);
char *virSocketAddrFormatFull(const virSocketAddr *addr,
                              bool withService,
                              const char *separator);

int virSocketAddrSetPort(virSocketAddrPtr addr, int port);

int virSocketAddrGetPort(virSocketAddrPtr addr);

int virSocketAddrGetRange(virSocketAddrPtr start,
                          virSocketAddrPtr end,
                          virSocketAddrPtr network,
                          int prefix);

int virSocketAddrIsNetmask(virSocketAddrPtr netmask);

int virSocketAddrCheckNetmask(virSocketAddrPtr addr1,
                              virSocketAddrPtr addr2,
                              virSocketAddrPtr netmask);
int virSocketAddrMask(const virSocketAddr *addr,
                      const virSocketAddr *netmask,
                      virSocketAddrPtr network);
int virSocketAddrMaskByPrefix(const virSocketAddr *addr,
                              unsigned int prefix,
                              virSocketAddrPtr network);
int virSocketAddrBroadcast(const virSocketAddr *addr,
                           const virSocketAddr *netmask,
                           virSocketAddrPtr broadcast);
int virSocketAddrBroadcastByPrefix(const virSocketAddr *addr,
                                   unsigned int prefix,
                                   virSocketAddrPtr broadcast);

int virSocketAddrGetNumNetmaskBits(const virSocketAddr *netmask);
int virSocketAddrPrefixToNetmask(unsigned int prefix,
                                 virSocketAddrPtr netmask,
                                 int family);
int virSocketAddrGetIpPrefix(const virSocketAddr *address,
                             const virSocketAddr *netmask,
                             int prefix);
bool virSocketAddrEqual(const virSocketAddr *s1,
                        const virSocketAddr *s2);
bool virSocketAddrIsPrivate(const virSocketAddr *addr);

bool virSocketAddrIsWildcard(const virSocketAddr *addr);

int virSocketAddrNumericFamily(const char *address);

bool virSocketAddrIsNumericLocalhost(const char *addr);
#endif /* __VIR_SOCKETADDR_H__ */
