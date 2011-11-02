/*
 * Copyright (C) 2009-2011 Red Hat, Inc.
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

typedef virSocketAddr *virSocketAddrPtr;

int virSocketAddrParse(virSocketAddrPtr addr,
                       const char *val,
                       int family);

int virSocketAddrParseIPv4(virSocketAddrPtr addr,
                           const char *val);

int virSocketAddrParseIPv6(virSocketAddrPtr addr,
                           const char *val);

char * virSocketAddrFormat(virSocketAddrPtr addr);
char * virSocketAddrFormatFull(virSocketAddrPtr addr,
                               bool withService,
                               const char *separator);

int virSocketAddrSetPort(virSocketAddrPtr addr, int port);

int virSocketAddrGetPort(virSocketAddrPtr addr);

int virSocketAddrGetRange(virSocketAddrPtr start,
                          virSocketAddrPtr end);

int virSocketAddrIsNetmask(virSocketAddrPtr netmask);

int virSocketAddrCheckNetmask(virSocketAddrPtr addr1,
                              virSocketAddrPtr addr2,
                              virSocketAddrPtr netmask);
int virSocketAddrMask(const virSocketAddrPtr addr,
                      const virSocketAddrPtr netmask,
                      virSocketAddrPtr       network);
int virSocketAddrMaskByPrefix(const virSocketAddrPtr addr,
                              unsigned int           prefix,
                              virSocketAddrPtr       network);
int virSocketAddrBroadcast(const virSocketAddrPtr addr,
                           const virSocketAddrPtr netmask,
                           virSocketAddrPtr       broadcast);
int virSocketAddrBroadcastByPrefix(const virSocketAddrPtr addr,
                                   unsigned int           prefix,
                                   virSocketAddrPtr       broadcast);

int virSocketAddrGetNumNetmaskBits(const virSocketAddrPtr netmask);
int virSocketAddrPrefixToNetmask(unsigned int prefix,
                                 virSocketAddrPtr netmask,
                                 int family);

#endif /* __VIR_SOCKETADDR_H__ */
