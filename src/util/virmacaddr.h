/*
 * virmacaddr.h: MAC address handling
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

#ifndef __VIR_MACADDR_H__
# define __VIR_MACADDR_H__

# include "internal.h"

# define VIR_MAC_BUFLEN 6
# define VIR_MAC_HEXLEN (VIR_MAC_BUFLEN * 2)
# define VIR_MAC_PREFIX_BUFLEN 3
# define VIR_MAC_STRING_BUFLEN (VIR_MAC_BUFLEN * 3)

typedef struct _virMacAddr virMacAddr;
typedef virMacAddr *virMacAddrPtr;

struct _virMacAddr {
    unsigned char addr[VIR_MAC_BUFLEN];
};

int virMacAddrCompare(const char *mac1, const char *mac2);
int virMacAddrCmp(const virMacAddr *mac1, const virMacAddr *mac2);
int virMacAddrCmpRaw(const virMacAddr *mac1,
                     const unsigned char s[VIR_MAC_BUFLEN]);
void virMacAddrSet(virMacAddrPtr dst, const virMacAddr *src);
void virMacAddrSetRaw(virMacAddrPtr dst, const unsigned char s[VIR_MAC_BUFLEN]);
void virMacAddrGetRaw(const virMacAddr *src, unsigned char dst[VIR_MAC_BUFLEN]);
const char *virMacAddrFormat(const virMacAddr *addr,
                             char *str);
void virMacAddrGenerate(const unsigned char prefix[VIR_MAC_PREFIX_BUFLEN],
                        virMacAddrPtr addr);
int virMacAddrParse(const char* str,
                    virMacAddrPtr addr) ATTRIBUTE_RETURN_CHECK;
int virMacAddrParseHex(const char* str,
                       virMacAddrPtr addr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
bool virMacAddrIsUnicast(const virMacAddr *addr);
bool virMacAddrIsMulticast(const virMacAddr *addr);
bool virMacAddrIsBroadcastRaw(const unsigned char s[VIR_MAC_BUFLEN]);

#endif /* __VIR_MACADDR_H__ */
