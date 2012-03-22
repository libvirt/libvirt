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

#include <config.h>

#include "virsocketaddr.h"
#include "virterror_internal.h"
#include "util.h"

#include <netdb.h>

#define VIR_FROM_THIS VIR_FROM_NONE
#define virSocketError(code, ...)                                       \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

/*
 * Helpers to extract the IP arrays from the virSocketAddrPtr
 * That part is the less portable of the module
 */
typedef unsigned char virSocketAddrIPv4[4];
typedef virSocketAddrIPv4 *virSocketAddrIPv4Ptr;
typedef unsigned short virSocketAddrIPv6[8];
typedef virSocketAddrIPv6 *virSocketAddrIPv6Ptr;

static int virSocketAddrGetIPv4Addr(virSocketAddrPtr addr, virSocketAddrIPv4Ptr tab) {
    unsigned long val;
    int i;

    if ((addr == NULL) || (tab == NULL) || (addr->data.stor.ss_family != AF_INET))
        return -1;

    val = ntohl(addr->data.inet4.sin_addr.s_addr);

    for (i = 0;i < 4;i++) {
        (*tab)[3 - i] = val & 0xFF;
        val >>= 8;
    }

    return 0;
}

static int virSocketAddrGetIPv6Addr(virSocketAddrPtr addr, virSocketAddrIPv6Ptr tab) {
    int i;

    if ((addr == NULL) || (tab == NULL) || (addr->data.stor.ss_family != AF_INET6))
        return -1;

    for (i = 0;i < 8;i++) {
        (*tab)[i] = ((addr->data.inet6.sin6_addr.s6_addr[2 * i] << 8) |
                     addr->data.inet6.sin6_addr.s6_addr[2 * i + 1]);
    }

    return 0;
}

/**
 * virSocketAddrParse:
 * @val: a numeric network address IPv4 or IPv6
 * @addr: where to store the return value, optional.
 * @family: address family to pass down to getaddrinfo
 *
 * Mostly a wrapper for getaddrinfo() extracting the address storage
 * from the numeric string like 1.2.3.4 or 2001:db8:85a3:0:0:8a2e:370:7334
 *
 * Returns the length of the network address or -1 in case of error.
 */
int virSocketAddrParse(virSocketAddrPtr addr, const char *val, int family) {
    int len;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int err;

    if (val == NULL) {
        virSocketError(VIR_ERR_INVALID_ARG, "%s", _("Missing address"));
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_flags = AI_NUMERICHOST;
    if ((err = getaddrinfo(val, NULL, &hints, &res)) != 0) {
        virSocketError(VIR_ERR_SYSTEM_ERROR,
                       _("Cannot parse socket address '%s': %s"),
                       val, gai_strerror(err));
        return -1;
    }

    if (res == NULL) {
        virSocketError(VIR_ERR_SYSTEM_ERROR,
                       _("No socket addresses found for '%s'"),
                       val);
        return -1;
    }

    len = res->ai_addrlen;
    if (addr != NULL) {
        memcpy(&addr->data.stor, res->ai_addr, len);
        addr->len = res->ai_addrlen;
    }

    freeaddrinfo(res);
    return len;
}

/*
 * virSocketAddrParseIPv4:
 * @val: an IPv4 numeric address
 * @addr: the location to store the result
 *
 * Extract the address storage from an IPv4 numeric address
 *
 * Returns the length of the network address or -1 in case of error.
 */
int
virSocketAddrParseIPv4(virSocketAddrPtr addr, const char *val) {
    return virSocketAddrParse(addr, val, AF_INET);
}

/*
 * virSocketAddrParseIPv6:
 * @val: an IPv6 numeric address
 * @addr: the location to store the result
 *
 * Extract the address storage from an IPv6 numeric address
 *
 * Returns the length of the network address or -1 in case of error.
 */
int
virSocketAddrParseIPv6(virSocketAddrPtr addr, const char *val) {
    return virSocketAddrParse(addr, val, AF_INET6);
}

/*
 * virSocketAddrFormat:
 * @addr: an initialized virSocketAddrPtr
 *
 * Returns a string representation of the given address
 * Returns NULL on any error
 * Caller must free the returned string
 */
char *
virSocketAddrFormat(virSocketAddrPtr addr) {
    return virSocketAddrFormatFull(addr, false, NULL);
}


/*
 * virSocketAddrFormatFull:
 * @addr: an initialized virSocketAddrPtr
 * @withService: if true, then service info is appended
 * @separator: separator between hostname & service.
 *
 * Returns a string representation of the given address
 * Returns NULL on any error
 * Caller must free the returned string
 */
char *
virSocketAddrFormatFull(virSocketAddrPtr addr,
                        bool withService,
                        const char *separator)
{
    char host[NI_MAXHOST], port[NI_MAXSERV];
    char *addrstr;
    int err;

    if (addr == NULL) {
        virSocketError(VIR_ERR_INVALID_ARG, "%s", _("Missing address"));
        return NULL;
    }

    /* Short-circuit since getnameinfo doesn't work
     * nicely for UNIX sockets */
    if (addr->data.sa.sa_family == AF_UNIX) {
        if (withService) {
            if (virAsprintf(&addrstr, "127.0.0.1%s0",
                            separator ? separator : ":") < 0)
                goto no_memory;
        } else {
            if (!(addrstr = strdup("127.0.0.1")))
                goto no_memory;
        }
        return addrstr;
    }

    if ((err = getnameinfo(&addr->data.sa,
                           addr->len,
                           host, sizeof(host),
                           port, sizeof(port),
                           NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        virSocketError(VIR_ERR_SYSTEM_ERROR,
                       _("Cannot convert socket address to string: %s"),
                       gai_strerror(err));
        return NULL;
    }

    if (withService) {
        if (virAsprintf(&addrstr, "%s%s%s", host, separator, port) == -1)
            goto no_memory;
    } else {
        if (!(addrstr = strdup(host)))
            goto no_memory;
    }

    return addrstr;

no_memory:
    virReportOOMError();
    return NULL;
}


/*
 * virSocketAddrSetPort:
 * @addr: an initialized virSocketAddrPtr
 * @port: the port number to set
 *
 * Set the transport layer port of the given virtSocketAddr
 *
 * Returns 0 on success, -1 on failure
 */
int
virSocketAddrSetPort(virSocketAddrPtr addr, int port) {
    if (addr == NULL)
        return -1;

    port = htons(port);

    if(addr->data.stor.ss_family == AF_INET) {
        addr->data.inet4.sin_port = port;
    }

    else if(addr->data.stor.ss_family == AF_INET6) {
        addr->data.inet6.sin6_port = port;
    }

    else {
        return -1;
    }

    return 0;
}

/*
 * virSocketGetPort:
 * @addr: an initialized virSocketAddrPtr
 *
 * Returns the transport layer port of the given virtSocketAddr
 * Returns -1 if @addr is invalid
 */
int
virSocketAddrGetPort(virSocketAddrPtr addr) {
    if (addr == NULL)
        return -1;

    if(addr->data.stor.ss_family == AF_INET) {
        return ntohs(addr->data.inet4.sin_port);
    }

    else if(addr->data.stor.ss_family == AF_INET6) {
        return ntohs(addr->data.inet6.sin6_port);
    }

    return -1;
}

/**
 * virSocketAddrIsNetmask:
 * @netmask: the netmask address
 *
 * Check that @netmask is a proper network mask
 *
 * Returns 0 in case of success and -1 in case of error
 */
int virSocketAddrIsNetmask(virSocketAddrPtr netmask) {
    int n = virSocketAddrGetNumNetmaskBits(netmask);
    if (n < 0)
        return -1;
    return 0;
}

/**
 * virSocketAddrMask:
 * @addr: address that needs to be masked
 * @netmask: the netmask address
 * @network: where to store the result, can be same as @addr
 *
 * Mask off the host bits of @addr according to @netmask, turning it
 * into a network address.
 *
 * Returns 0 in case of success, or -1 on error.
 */
int
virSocketAddrMask(const virSocketAddrPtr addr,
                  const virSocketAddrPtr netmask,
                  virSocketAddrPtr       network)
{
    if (addr->data.stor.ss_family != netmask->data.stor.ss_family) {
        network->data.stor.ss_family = AF_UNSPEC;
        return -1;
    }

    if (addr->data.stor.ss_family == AF_INET) {
        network->data.inet4.sin_addr.s_addr
            = (addr->data.inet4.sin_addr.s_addr
               & netmask->data.inet4.sin_addr.s_addr);
        network->data.inet4.sin_port = 0;
        network->data.stor.ss_family = AF_INET;
        network->len = addr->len;
        return 0;
    }
    if (addr->data.stor.ss_family == AF_INET6) {
        int ii;
        for (ii = 0; ii < 16; ii++) {
            network->data.inet6.sin6_addr.s6_addr[ii]
                = (addr->data.inet6.sin6_addr.s6_addr[ii]
                   & netmask->data.inet6.sin6_addr.s6_addr[ii]);
        }
        network->data.inet6.sin6_port = 0;
        network->data.stor.ss_family = AF_INET6;
        network->len = addr->len;
        return 0;
    }
    network->data.stor.ss_family = AF_UNSPEC;
    return -1;
}

/**
 * virSocketAddrMaskByPrefix:
 * @addr: address that needs to be masked
 * @prefix: prefix (# of 1 bits) of netmask to apply
 * @network: where to store the result, can be same as @addr
 *
 * Mask off the host bits of @addr according to @prefix, turning it
 * into a network address.
 *
 * Returns 0 in case of success, or -1 on error.
 */
int
virSocketAddrMaskByPrefix(const virSocketAddrPtr addr,
                          unsigned int           prefix,
                          virSocketAddrPtr       network)
{
    virSocketAddr netmask;

    if (virSocketAddrPrefixToNetmask(prefix, &netmask,
                                     addr->data.stor.ss_family) < 0) {
        network->data.stor.ss_family = AF_UNSPEC;
        return -1;
    }

    return virSocketAddrMask(addr, &netmask, network);
}

/**
 * virSocketAddrBroadcast:
 * @addr: address that needs to be turned into broadcast address (IPv4 only)
 * @netmask: the netmask address
 * @broadcast: virSocketAddr to recieve the broadcast address
 *
 * Mask ON the host bits of @addr according to @netmask, turning it
 * into a broadcast address.
 *
 * Returns 0 in case of success, or -1 on error.
 */
int
virSocketAddrBroadcast(const virSocketAddrPtr addr,
                       const virSocketAddrPtr netmask,
                       virSocketAddrPtr       broadcast)
{
    if ((addr->data.stor.ss_family != AF_INET) ||
        (netmask->data.stor.ss_family != AF_INET)) {
        broadcast->data.stor.ss_family = AF_UNSPEC;
        return -1;
    }

    broadcast->data.stor.ss_family = AF_INET;
    broadcast->len = addr->len;
    broadcast->data.inet4.sin_addr.s_addr
        = (addr->data.inet4.sin_addr.s_addr
           | ~netmask->data.inet4.sin_addr.s_addr);
    return 0;
}

/**
 * virSocketAddrBroadcastByPrefix:
 * @addr: address that needs to be turned into broadcast address (IPv4 only)
 * @prefix: prefix (# of 1 bits) of netmask to apply
 * @broadcast: virSocketAddr to recieve the broadcast address
 *
 * Mask off the host bits of @addr according to @prefix, turning it
 * into a network address.
 *
 * Returns 0 in case of success, or -1 on error.
 */
int
virSocketAddrBroadcastByPrefix(const virSocketAddrPtr addr,
                               unsigned int           prefix,
                               virSocketAddrPtr       broadcast)
{
    virSocketAddr netmask;

    if (virSocketAddrPrefixToNetmask(prefix, &netmask,
                                     addr->data.stor.ss_family) < 0)
        return -1;

    return virSocketAddrBroadcast(addr, &netmask, broadcast);
}

/**
 * virSocketCheckNetmask:
 * @addr1: a first network address
 * @addr2: a second network address
 * @netmask: the netmask address
 *
 * Check that @addr1 and @addr2 pertain to the same @netmask address
 * range and returns the size of the range
 *
 * Returns 1 in case of success and 0 in case of failure and
 *         -1 in case of error
 */
int virSocketAddrCheckNetmask(virSocketAddrPtr addr1, virSocketAddrPtr addr2,
                              virSocketAddrPtr netmask) {
    int i;

    if ((addr1 == NULL) || (addr2 == NULL) || (netmask == NULL))
        return -1;
    if ((addr1->data.stor.ss_family != addr2->data.stor.ss_family) ||
        (addr1->data.stor.ss_family != netmask->data.stor.ss_family))
        return -1;

    if (virSocketAddrIsNetmask(netmask) != 0)
        return -1;

    if (addr1->data.stor.ss_family == AF_INET) {
        virSocketAddrIPv4 t1, t2, tm;

        if ((virSocketAddrGetIPv4Addr(addr1, &t1) < 0) ||
            (virSocketAddrGetIPv4Addr(addr2, &t2) < 0) ||
            (virSocketAddrGetIPv4Addr(netmask, &tm) < 0))
            return -1;

        for (i = 0;i < 4;i++) {
            if ((t1[i] & tm[i]) != (t2[i] & tm[i]))
                return 0;
        }

    } else if (addr1->data.stor.ss_family == AF_INET6) {
        virSocketAddrIPv6 t1, t2, tm;

        if ((virSocketAddrGetIPv6Addr(addr1, &t1) < 0) ||
            (virSocketAddrGetIPv6Addr(addr2, &t2) < 0) ||
            (virSocketAddrGetIPv6Addr(netmask, &tm) < 0))
            return -1;

        for (i = 0;i < 8;i++) {
            if ((t1[i] & tm[i]) != (t2[i] & tm[i]))
                return 0;
        }

    } else {
        return -1;
    }
    return 1;
}

/**
 * virSocketGetRange:
 * @start: start of an IP range
 * @end: end of an IP range
 *
 * Check the order of the 2 addresses and compute the range, this
 * will return 1 for identical addresses. Errors can come from incompatible
 * addresses type, excessive range (>= 2^^16) where the two addresses are
 * unrelated or inverted start and end.
 *
 * Returns the size of the range or -1 in case of failure
 */
int virSocketAddrGetRange(virSocketAddrPtr start, virSocketAddrPtr end) {
    int ret = 0, i;

    if ((start == NULL) || (end == NULL))
        return -1;
    if (start->data.stor.ss_family != end->data.stor.ss_family)
        return -1;

    if (start->data.stor.ss_family == AF_INET) {
        virSocketAddrIPv4 t1, t2;

        if ((virSocketAddrGetIPv4Addr(start, &t1) < 0) ||
            (virSocketAddrGetIPv4Addr(end, &t2) < 0))
            return -1;

        for (i = 0;i < 2;i++) {
            if (t1[i] != t2[i])
                return -1;
        }
        ret = (t2[2] - t1[2]) * 256 + (t2[3] - t1[3]);
        if (ret < 0)
            return -1;
        ret++;
    } else if (start->data.stor.ss_family == AF_INET6) {
        virSocketAddrIPv6 t1, t2;

        if ((virSocketAddrGetIPv6Addr(start, &t1) < 0) ||
            (virSocketAddrGetIPv6Addr(end, &t2) < 0))
            return -1;

        for (i = 0;i < 7;i++) {
            if (t1[i] != t2[i])
                return -1;
        }
        ret = t2[7] - t1[7];
        if (ret < 0)
            return -1;
        ret++;
    } else {
        return -1;
    }
    return ret;
}


/**
 * virSocketAddrGetNumNetmaskBits
 * @netmask: the presumed netmask
 *
 * Get the number of netmask bits in a netmask.
 *
 * Returns the number of bits in the netmask or -1 if an error occurred
 * or the netmask is invalid.
 */
int virSocketAddrGetNumNetmaskBits(const virSocketAddrPtr netmask)
{
    int i, j;
    int c = 0;

    if (netmask->data.stor.ss_family == AF_INET) {
        virSocketAddrIPv4 tm;
        uint8_t bit;

        if (virSocketAddrGetIPv4Addr(netmask, &tm) < 0)
            return -1;

        for (i = 0; i < 4; i++)
            if (tm[i] == 0xff)
                c += 8;
            else
                break;

        if (c == 8 * 4)
            return c;

        j = i << 3;
        while (j < (8 * 4)) {
            bit = 1 << (7 - (j & 7));
            if ((tm[j >> 3] & bit)) {
                c++;
            } else
                break;
            j++;
        }

        while (j < (8 * 4)) {
            bit = 1 << (7 - (j & 7));
            if ((tm[j >> 3] & bit))
                return -1;
            j++;
        }

        return c;
    } else if (netmask->data.stor.ss_family == AF_INET6) {
        virSocketAddrIPv6 tm;
        uint16_t bit;

        if (virSocketAddrGetIPv6Addr(netmask, &tm) < 0)
            return -1;

        for (i = 0; i < 8; i++)
            if (tm[i] == 0xffff)
                c += 16;
            else
                break;

        if (c == 16 * 8)
            return c;

        j = i << 4;
        while (j < (16 * 8)) {
            bit = 1 << (15 - (j & 0xf));
            if ((tm[j >> 4] & bit)) {
                c++;
            } else
                break;
            j++;
        }

        while (j < (16 * 8)) {
            bit = 1 << (15 - (j & 0xf));
            if ((tm[j >> 4]) & bit)
                return -1;
            j++;
        }

        return c;
    }
    return -1;
}

/**
 * virSocketPrefixToNetmask:
 * @prefix: number of 1 bits to put in the netmask
 * @netmask: address to fill in with the desired netmask
 * @family: family of the address (AF_INET or AF_INET6 only)
 *
 * given @prefix and @family, fill in @netmask with a netmask
 * (eg 255.255.255.0).
 *
 * Returns 0 on success or -1 on error.
 */

int
virSocketAddrPrefixToNetmask(unsigned int prefix,
                             virSocketAddrPtr netmask,
                             int family)
{
    int result = -1;

    netmask->data.stor.ss_family = AF_UNSPEC; /* assume failure */

    if (family == AF_INET) {
        int ip;

        if (prefix > 32)
            goto error;

        ip = prefix ? ~((1 << (32 - prefix)) - 1) : 0;
        netmask->data.inet4.sin_addr.s_addr = htonl(ip);
        netmask->data.stor.ss_family = AF_INET;
        result = 0;

    } else if (family == AF_INET6) {
        int ii = 0;

        if (prefix > 128)
            goto error;

        while (prefix >= 8) {
            /* do as much as possible an entire byte at a time */
            netmask->data.inet6.sin6_addr.s6_addr[ii++] = 0xff;
            prefix -= 8;
        }
        if (prefix > 0) {
            /* final partial byte */
            netmask->data.inet6.sin6_addr.s6_addr[ii++]
                = ~((1 << (8 - prefix)) -1);
        }
        while (ii < 16) {
            /* zerofill remainder in case it wasn't initialized */
            netmask->data.inet6.sin6_addr.s6_addr[ii++] = 0;
        }
        netmask->data.stor.ss_family = AF_INET6;
        result = 0;
    }

error:
    return result;
}
