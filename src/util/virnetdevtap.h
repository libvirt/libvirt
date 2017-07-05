/*
 * Copyright (C) 2007-2011, 2013 Red Hat, Inc.
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
 *     Mark McLoughlin <markmc@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NETDEV_TAP_H__
# define __VIR_NETDEV_TAP_H__

# include "internal.h"
# include "virnetdev.h"
# include "virnetdevvportprofile.h"
# include "virnetdevvlan.h"

# ifdef __FreeBSD__
/* This should be defined on OSes that don't automatically
 * cleanup released devices */
#  define VIR_NETDEV_TAP_REQUIRE_MANUAL_CLEANUP 1
# endif

int virNetDevTapCreate(char **ifname,
                       const char *tunpath,
                       int *tapfd,
                       size_t tapfdSize,
                       unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK ATTRIBUTE_MOCKABLE;

int virNetDevTapDelete(const char *ifname,
                       const char *tunpath)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevTapGetName(int tapfd, char **ifname)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

char* virNetDevTapGetRealDeviceName(char *ifname)
      ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK ATTRIBUTE_MOCKABLE;

typedef enum {
   VIR_NETDEV_TAP_CREATE_NONE = 0,
   /* Bring the interface up */
   VIR_NETDEV_TAP_CREATE_IFUP               = 1 << 0,
   /* Enable IFF_VNET_HDR on the tap device */
   VIR_NETDEV_TAP_CREATE_VNET_HDR           = 1 << 1,
   /* Set this interface's MAC as the bridge's MAC address */
   VIR_NETDEV_TAP_CREATE_USE_MAC_FOR_BRIDGE = 1 << 2,
   /* The device will persist after the file descriptor is closed */
   VIR_NETDEV_TAP_CREATE_PERSIST            = 1 << 3,
} virNetDevTapCreateFlags;

int
virNetDevTapAttachBridge(const char *tapname,
                         const char *brname,
                         const virMacAddr *macaddr,
                         const unsigned char *vmuuid,
                         virNetDevVPortProfilePtr virtPortProfile,
                         virNetDevVlanPtr virtVlan,
                         unsigned int mtu,
                         unsigned int *actualMTU)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevTapCreateInBridgePort(const char *brname,
                                   char **ifname,
                                   const virMacAddr *macaddr,
                                   const unsigned char *vmuuid,
                                   const char *tunpath,
                                   int *tapfd,
                                   size_t tapfdSize,
                                   virNetDevVPortProfilePtr virtPortProfile,
                                   virNetDevVlanPtr virtVlan,
                                   virNetDevCoalescePtr coalesce,
                                   unsigned int mtu,
                                   unsigned int *actualMTU,
                                   unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK ATTRIBUTE_MOCKABLE;

int virNetDevTapInterfaceStats(const char *ifname,
                               virDomainInterfaceStatsPtr stats)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

#endif /* __VIR_NETDEV_TAP_H__ */
