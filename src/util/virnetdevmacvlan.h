/*
 * Copyright (C) 2011, 2013, 2016 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corporation
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
 *     Stefan Berger <stefanb@us.ibm.com>
 */

#ifndef __UTIL_MACVTAP_H__
# define __UTIL_MACVTAP_H__

# include "internal.h"
# include "virmacaddr.h"
# include "virsocketaddr.h"
# include "virnetdevbandwidth.h"
# include "virnetdevvportprofile.h"
# include "virnetdevvlan.h"

/* the mode type for macvtap devices */
typedef enum {
    VIR_NETDEV_MACVLAN_MODE_VEPA,
    VIR_NETDEV_MACVLAN_MODE_PRIVATE,
    VIR_NETDEV_MACVLAN_MODE_BRIDGE,
    VIR_NETDEV_MACVLAN_MODE_PASSTHRU,

    VIR_NETDEV_MACVLAN_MODE_LAST,
} virNetDevMacVLanMode;
VIR_ENUM_DECL(virNetDevMacVLanMode)

typedef enum {
   VIR_NETDEV_MACVLAN_CREATE_NONE     = 0,
   /* Create with a tap device */
   VIR_NETDEV_MACVLAN_CREATE_WITH_TAP = 1 << 0,
   /* Bring the interface up */
   VIR_NETDEV_MACVLAN_CREATE_IFUP     = 1 << 1,
   /* Enable VNET_HDR */
   VIR_NETDEV_MACVLAN_VNET_HDR          = 1 << 2,
} virNetDevMacVLanCreateFlags;

/* libvirt will start macvtap/macvlan interface names with one of
 * these prefixes when it auto-generates the name
 */
# define VIR_NET_GENERATED_MACVTAP_PREFIX "macvtap"
# define VIR_NET_GENERATED_MACVLAN_PREFIX "macvlan"

int virNetDevMacVLanReserveName(const char *name, bool quietfail);
int virNetDevMacVLanReleaseName(const char *name);

int virNetDevMacVLanCreate(const char *ifname,
                           const char *type,
                           const virMacAddr *macaddress,
                           const char *srcdev,
                           uint32_t macvlan_mode,
                           int *retry)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevMacVLanDelete(const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevMacVLanCreateWithVPortProfile(const char *ifname,
                                           const virMacAddr *macaddress,
                                           const char *linkdev,
                                           virNetDevMacVLanMode mode,
                                           virNetDevVlanPtr vlan,
                                           const unsigned char *vmuuid,
                                           virNetDevVPortProfilePtr virtPortProfile,
                                           char **res_ifname,
                                           virNetDevVPortProfileOp vmop,
                                           char *stateDir,
                                           int *tapfd,
                                           size_t tapfdSize,
                                           unsigned int flags)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(6)
    ATTRIBUTE_NONNULL(8) ATTRIBUTE_NONNULL(10) ATTRIBUTE_RETURN_CHECK;

int virNetDevMacVLanDeleteWithVPortProfile(const char *ifname,
                                           const virMacAddr *macaddress,
                                           const char *linkdev,
                                           int mode,
                                           virNetDevVPortProfilePtr virtPortProfile,
                                           char *stateDir)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(6) ATTRIBUTE_RETURN_CHECK;

int virNetDevMacVLanRestartWithVPortProfile(const char *cr_ifname,
                                            const virMacAddr *macaddress,
                                            const char *linkdev,
                                            const unsigned char *vmuuid,
                                            virNetDevVPortProfilePtr virtPortProfile,
                                            virNetDevVPortProfileOp vmOp)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_RETURN_CHECK;

int virNetDevMacVLanVPortProfileRegisterCallback(const char *ifname,
                                                 const virMacAddr *macaddress,
                                                 const char *linkdev,
                                                 const unsigned char *vmuuid,
                                                 virNetDevVPortProfilePtr virtPortProfile,
                                                 virNetDevVPortProfileOp vmOp)
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
ATTRIBUTE_NONNULL(4) ATTRIBUTE_RETURN_CHECK;
#endif /* __UTIL_MACVTAP_H__ */
