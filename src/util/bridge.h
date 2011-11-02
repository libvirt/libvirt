/*
 * Copyright (C) 2007 Red Hat, Inc.
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
 *     Mark McLoughlin <markmc@redhat.com>
 */

#ifndef __QEMUD_BRIDGE_H__
# define __QEMUD_BRIDGE_H__

# include <config.h>

# if defined(WITH_BRIDGE)

#  include <net/if.h>
#  include <netinet/in.h>
#  include "network.h"

/**
 * BR_IFNAME_MAXLEN:
 * maximum size in byte of the name for an interface
 */
#  define BR_IFNAME_MAXLEN    IF_NAMESIZE

/**
 * BR_INET_ADDR_MAXLEN:
 * maximum size in bytes for an inet addess name
 */
#  define BR_INET_ADDR_MAXLEN INET_ADDRSTRLEN

int     brAddBridge             (const char *brname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int     brDeleteBridge          (const char *brname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int     brHasBridge             (const char *brname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int     brAddInterface          (const char *brname,
                                 const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int     brDeleteInterface       (const char *brname,
                                 const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

enum {
    BR_TAP_VNET_HDR = (1 << 0),
    BR_TAP_PERSIST =  (1 << 1),
};

int     brAddTap                (const char *brname,
                                 char **ifname,
                                 const unsigned char *macaddr,
                                 int vnet_hdr,
                                 bool up,
                                 int *tapfd)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;


int     brDeleteTap             (const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int     brSetInterfaceUp        (const char *ifname,
                                 int up)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int     brGetInterfaceUp        (const char *ifname,
                                 int *up)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int     brAddInetAddress        (const char *ifname,
                                 virSocketAddr *addr,
                                 unsigned int prefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int     brDelInetAddress        (const char *ifname,
                                 virSocketAddr *addr,
                                 unsigned int prefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int     brSetForwardDelay       (const char *brname,
                                 int delay)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int     brGetForwardDelay       (const char *brname,
                                 int *delay)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int     brSetEnableSTP          (const char *brname,
                                 int enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int     brGetEnableSTP          (const char *brname,
                                 int *enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int     brCreateTap             (char **ifname,
                                 int vnet_hdr,
                                 int *tapfd)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int     brSetInterfaceMac       (const char *ifname,
                                 const unsigned char *macaddr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

# endif /* WITH_BRIDGE */

#endif /* __QEMUD_BRIDGE_H__ */
