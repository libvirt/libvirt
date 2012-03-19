/*
 * virmacaddr.h: MAC address handling
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

#ifndef __VIR_MACADDR_H__
# define __VIR_MACADDR_H__

# include "internal.h"

# define VIR_MAC_BUFLEN 6
# define VIR_MAC_PREFIX_BUFLEN 3
# define VIR_MAC_STRING_BUFLEN VIR_MAC_BUFLEN * 3

int virMacAddrCompare(const char *mac1, const char *mac2);
void virMacAddrFormat(const unsigned char *addr,
                      char *str);
void virMacAddrGenerate(const unsigned char *prefix,
                        unsigned char *addr);
int virMacAddrParse(const char* str,
                    unsigned char *addr) ATTRIBUTE_RETURN_CHECK;
bool virMacAddrIsUnicast(const unsigned char *addr);
bool virMacAddrIsMulticast(const unsigned char *addr);
#endif /* __VIR_MACADDR_H__ */
