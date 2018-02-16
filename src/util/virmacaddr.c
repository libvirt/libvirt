/*
 * virmacaddr.c: MAC address handling
 *
 * Copyright (C) 2006-2013 Red Hat, Inc.
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
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>

#include "c-ctype.h"
#include "virmacaddr.h"
#include "virrandom.h"
#include "virutil.h"

static const unsigned char virMacAddrBroadcastAddrRaw[VIR_MAC_BUFLEN] =
    { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* Compare two MAC addresses, ignoring differences in case,
 * as well as leading zeros.
 */
int
virMacAddrCompare(const char *p, const char *q)
{
    unsigned char c, d;
    do {
        while (*p == '0' && c_isxdigit(p[1]))
            ++p;
        while (*q == '0' && c_isxdigit(q[1]))
            ++q;
        c = c_tolower(*p);
        d = c_tolower(*q);

        if (c == 0 || d == 0)
            break;

        ++p;
        ++q;
    } while (c == d);

    if (UCHAR_MAX <= INT_MAX)
        return c - d;

    /* On machines where 'char' and 'int' are types of the same size, the
       difference of two 'unsigned char' values - including the sign bit -
       doesn't fit in an 'int'.  */
    return c > d ? 1 : c < d ? -1 : 0;
}

/**
 * virMacAddrCmp:
 * @mac1: pointer to 1st MAC address
 * @mac2: pointer to 2nd MAC address
 *
 * Return 0 if MAC addresses are equal,
 * < 0 if mac1 < mac2,
 * > 0 if mac1 > mac2
 */
int
virMacAddrCmp(const virMacAddr *mac1, const virMacAddr *mac2)
{
    return memcmp(mac1->addr, mac2->addr, VIR_MAC_BUFLEN);
}

/**
 * virMacAddrCmpRaw:
 * @mac1: pointer to 1st MAC address
 * @mac2: pointer to 2nd MAC address in plain buffer
 *
 * Return 0 if MAC addresses are equal,
 * < 0 if mac1 < mac2,
 * > 0 if mac1 > mac2
 */
int
virMacAddrCmpRaw(const virMacAddr *mac1,
                 const unsigned char mac2[VIR_MAC_BUFLEN])
{
    return memcmp(mac1->addr, mac2, VIR_MAC_BUFLEN);
}

/**
 * virMacAddrSet
 * @dst: pointer to destination
 * @src: pointer to source
 *
 * Copy src to dst
 */
void
virMacAddrSet(virMacAddrPtr dst, const virMacAddr *src)
{
    memcpy(dst, src, sizeof(*src));
}

/**
 * virMacAddrSetRaw
 * @dst: pointer to destination to hold MAC address
 * @src: raw MAC address data
 *
 * Set the MAC address to the given value
 */
void
virMacAddrSetRaw(virMacAddrPtr dst, const unsigned char src[VIR_MAC_BUFLEN])
{
    memcpy(dst->addr, src, VIR_MAC_BUFLEN);
}

/**
 * virMacAddrGetRaw
 * @src: pointer to MAC address
 * @dst: pointer to raw memory to write MAC address into
 *
 * Copies the MAC address into raw memory
 */
void
virMacAddrGetRaw(const virMacAddr *src, unsigned char dst[VIR_MAC_BUFLEN])
{
    memcpy(dst, src->addr, VIR_MAC_BUFLEN);
}

/**
 * virMacAddrParse:
 * @str: string representation of MAC address, e.g., "0:1E:FC:E:3a:CB"
 * @addr: 6-byte MAC address
 *
 * Parse a MAC address
 *
 * Return 0 upon success, or -1 in case of error.
 */
int
virMacAddrParse(const char* str, virMacAddrPtr addr)
{
    size_t i;

    errno = 0;
    for (i = 0; i < VIR_MAC_BUFLEN; i++) {
        char *end_ptr;
        unsigned long result;

        /* This is solely to avoid accepting the leading
         * space or "+" that strtoul would otherwise accept.
         */
        if (!c_isxdigit(*str))
            break;

        result = strtoul(str, &end_ptr, 16); /* exempt from syntax-check */

        if ((end_ptr - str) < 1 || 2 < (end_ptr - str) ||
            (errno != 0) ||
            (0xFF < result))
            break;

        addr->addr[i] = (unsigned char) result;

        if ((i == 5) && (*end_ptr <= ' '))
            return 0;
        if (*end_ptr != ':')
            break;

        str = end_ptr + 1;
    }

    return -1;
}

/* virMacAddrFormat
 * Converts the binary mac address in addr into a NULL-terminated
 * character string in str. It is assumed that the memory pointed to
 * by str is at least VIR_MAC_STRING_BUFLEN bytes long.
 *
 * Returns a pointer to the resulting character string.
 */
const char *
virMacAddrFormat(const virMacAddr *addr,
                 char *str)
{
    snprintf(str, VIR_MAC_STRING_BUFLEN,
             "%02x:%02x:%02x:%02x:%02x:%02x",
             addr->addr[0], addr->addr[1], addr->addr[2],
             addr->addr[3], addr->addr[4], addr->addr[5]);
    str[VIR_MAC_STRING_BUFLEN-1] = '\0';
    return str;
}

/**
 * virMacAddrParseHex:
 * @str: string hexadecimal representation of MAC address, e.g., "F801EFCE3aCB"
 * @addr: 6-byte MAC address
 *
 * Parse the hexadecimal representation of a MAC address
 *
 * Return 0 upon success, or -1 in case of error.
 */
int
virMacAddrParseHex(const char *str, virMacAddrPtr addr)
{
    size_t i;

    if (strspn(str, "0123456789abcdefABCDEF") != VIR_MAC_HEXLEN ||
        str[VIR_MAC_HEXLEN])
        return -1;

    for (i = 0; i < VIR_MAC_BUFLEN; i++)
        addr->addr[i] = (virHexToBin(str[2 * i]) << 4 |
                         virHexToBin(str[2 * i + 1]));
    return 0;
}

void virMacAddrGenerate(const unsigned char prefix[VIR_MAC_PREFIX_BUFLEN],
                        virMacAddrPtr addr)
{
    addr->addr[0] = prefix[0];
    addr->addr[1] = prefix[1];
    addr->addr[2] = prefix[2];
    addr->addr[3] = virRandomBits(8);
    addr->addr[4] = virRandomBits(8);
    addr->addr[5] = virRandomBits(8);
}

/* The low order bit of the first byte is the "multicast" bit. */
bool
virMacAddrIsMulticast(const virMacAddr *mac)
{
    return !!(mac->addr[0] & 1);
}

bool
virMacAddrIsUnicast(const virMacAddr *mac)
{
    return !(mac->addr[0] & 1);
}

bool
virMacAddrIsBroadcastRaw(const unsigned char s[VIR_MAC_BUFLEN])
{
    return memcmp(virMacAddrBroadcastAddrRaw, s, sizeof(*s)) == 0;
}
