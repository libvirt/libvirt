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
#define __VIR_NETWORK_H__

#include "internal.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

typedef union {
    struct sockaddr_storage stor;
    struct sockaddr_in inet4;
    struct sockaddr_in6 inet6;
} virSocketAddr;
typedef virSocketAddr *virSocketAddrPtr;

int virSocketParseAddr    (const char *val,
                           virSocketAddrPtr addr,
                           int hint);

int virSocketParseIpv4Addr(const char *val,
                           virSocketAddrPtr addr);

int virSocketParseIpv6Addr(const char *val,
                           virSocketAddrPtr addr);

char * virSocketFormatAddr(virSocketAddrPtr addr);

int virSocketSetPort(virSocketAddrPtr addr, int port);

int virSocketGetPort(virSocketAddrPtr addr);

int virSocketAddrInNetwork(virSocketAddrPtr addr1,
                           virSocketAddrPtr addr2,
                           virSocketAddrPtr netmask);

int virSocketGetRange     (virSocketAddrPtr start,
                           virSocketAddrPtr end);

int virSocketAddrIsNetmask(virSocketAddrPtr netmask);

int virSocketCheckNetmask (virSocketAddrPtr addr1,
                           virSocketAddrPtr addr2,
                           virSocketAddrPtr netmask);
#endif /* __VIR_NETWORK_H__ */
