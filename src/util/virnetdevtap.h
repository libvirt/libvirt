/*
 * Copyright (C) 2007-2011 Red Hat, Inc.
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
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NETDEV_TAP_H__
# define __VIR_NETDEV_TAP_H__

# include "internal.h"
# include "virnetdevvportprofile.h"

int virNetDevTapCreate(char **ifname,
                       int *tapfd,
                       unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevTapDelete(const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

typedef enum {
   VIR_NETDEV_TAP_CREATE_NONE = 0,
   /* Bring the interface up */
   VIR_NETDEV_TAP_CREATE_IFUP               = 1 << 0,
   /* Enable IFF_VNET_HDR on the tap device */
   VIR_NETDEV_TAP_CREATE_VNET_HDR           = 1 << 1,
   /* Set this interface's MAC as the bridge's MAC address */
   VIR_NETDEV_TAP_CREATE_USE_MAC_FOR_BRIDGE = 1 << 2,
} virNetDevTapCreateFlags;

int virNetDevTapCreateInBridgePort(const char *brname,
                                   char **ifname,
                                   const unsigned char *macaddr,
                                   const unsigned char *vmuuid,
                                   int *tapfd,
                                   virNetDevVPortProfilePtr virtPortProfile,
                                   unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;


#endif /* __VIR_NETDEV_TAP_H__ */
