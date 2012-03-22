/*
 * virmacaddr.c: MAC address handling
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>

#include "c-ctype.h"
#include "virmacaddr.h"
#include "virrandom.h"

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
 * virMacAddrParse:
 * @str: string representation of MAC address, e.g., "0:1E:FC:E:3a:CB"
 * @addr: 6-byte MAC address
 *
 * Parse a MAC address
 *
 * Return 0 upon success, or -1 in case of error.
 */
int
virMacAddrParse(const char* str, unsigned char *addr)
{
    int i;

    errno = 0;
    for (i = 0; i < VIR_MAC_BUFLEN; i++) {
        char *end_ptr;
        unsigned long result;

        /* This is solely to avoid accepting the leading
         * space or "+" that strtoul would otherwise accept.
         */
        if (!c_isxdigit(*str))
            break;

        result = strtoul(str, &end_ptr, 16);

        if ((end_ptr - str) < 1 || 2 < (end_ptr - str) ||
            (errno != 0) ||
            (0xFF < result))
            break;

        addr[i] = (unsigned char) result;

        if ((i == 5) && (*end_ptr == '\0'))
            return 0;
        if (*end_ptr != ':')
            break;

        str = end_ptr + 1;
    }

    return -1;
}

void virMacAddrFormat(const unsigned char *addr,
                      char *str)
{
    snprintf(str, VIR_MAC_STRING_BUFLEN,
             "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[0], addr[1], addr[2],
             addr[3], addr[4], addr[5]);
    str[VIR_MAC_STRING_BUFLEN-1] = '\0';
}

void virMacAddrGenerate(const unsigned char *prefix,
                        unsigned char *addr)
{
    addr[0] = prefix[0];
    addr[1] = prefix[1];
    addr[2] = prefix[2];
    addr[3] = virRandomBits(8);
    addr[4] = virRandomBits(8);
    addr[5] = virRandomBits(8);
}

/* The low order bit of the first byte is the "multicast" bit. */
bool
virMacAddrIsMulticast(const unsigned char *addr)
{
    return !!(addr[0] & 1);
}

bool
virMacAddrIsUnicast(const unsigned char *addr)
{
    return !(addr[0] & 1);
}
