/*
 * network.h: network helper APIs for libvirt
 *
 * Copyright (C) 2009-2009 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_NETWORK_H__
# define __VIR_NETWORK_H__

# include "internal.h"

# include <sys/types.h>
# include <sys/socket.h>
# ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
# endif
# include <netdb.h>
# include <stdbool.h>

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

# define VIR_SOCKET_HAS_ADDR(s)                 \
    ((s)->data.sa.sa_family != AF_UNSPEC)

# define VIR_SOCKET_IS_FAMILY(s, f)             \
    ((s)->data.sa.sa_family == f)

typedef virSocketAddr *virSocketAddrPtr;

int virSocketParseAddr    (const char *val,
                           virSocketAddrPtr addr,
                           int hint);

int virSocketParseIpv4Addr(const char *val,
                           virSocketAddrPtr addr);

int virSocketParseIpv6Addr(const char *val,
                           virSocketAddrPtr addr);

char * virSocketFormatAddr(virSocketAddrPtr addr);
char * virSocketFormatAddrFull(virSocketAddrPtr addr,
                               bool withService,
                               const char *separator);

int virSocketSetPort(virSocketAddrPtr addr, int port);

int virSocketGetPort(virSocketAddrPtr addr);

int virSocketGetRange     (virSocketAddrPtr start,
                           virSocketAddrPtr end);

int virSocketAddrIsNetmask(virSocketAddrPtr netmask);

int virSocketCheckNetmask (virSocketAddrPtr addr1,
                           virSocketAddrPtr addr2,
                           virSocketAddrPtr netmask);

int virSocketGetNumNetmaskBits(const virSocketAddrPtr netmask);

#endif /* __VIR_NETWORK_H__ */
