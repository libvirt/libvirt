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
 */

#pragma once

#include "internal.h"
#include "virmacaddr.h"
#include "virnetdevvportprofile.h"
#include "virnetdevvlan.h"
#include "virenum.h"

/* the mode type for macvtap devices */
typedef enum {
    VIR_NETDEV_MACVLAN_MODE_VEPA,
    VIR_NETDEV_MACVLAN_MODE_PRIVATE,
    VIR_NETDEV_MACVLAN_MODE_BRIDGE,
    VIR_NETDEV_MACVLAN_MODE_PASSTHRU,

    VIR_NETDEV_MACVLAN_MODE_LAST,
} virNetDevMacVLanMode;
VIR_ENUM_DECL(virNetDevMacVLanMode);

typedef enum {
   VIR_NETDEV_MACVLAN_CREATE_NONE     = 0,
   /* Create with a tap device */
   VIR_NETDEV_MACVLAN_CREATE_WITH_TAP = 1 << 0,
   /* Bring the interface up */
   VIR_NETDEV_MACVLAN_CREATE_IFUP     = 1 << 1,
   /* Enable VNET_HDR */
   VIR_NETDEV_MACVLAN_VNET_HDR          = 1 << 2,
} virNetDevMacVLanCreateFlags;

bool virNetDevMacVLanIsMacvtap(const char *ifname)
   ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT G_NO_INLINE;

int virNetDevMacVLanCreate(const char *ifname,
                           const virMacAddr *macaddress,
                           const char *srcdev,
                           uint32_t macvlan_mode,
                           unsigned int flags)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    G_GNUC_WARN_UNUSED_RESULT;

int virNetDevMacVLanDelete(const char *ifname)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

int virNetDevMacVLanCreateWithVPortProfile(const char *ifname,
                                           const virMacAddr *macaddress,
                                           const char *linkdev,
                                           virNetDevMacVLanMode mode,
                                           const virNetDevVlan *vlan,
                                           const unsigned char *vmuuid,
                                           const virNetDevVPortProfile *virtPortProfile,
                                           char **res_ifname,
                                           virNetDevVPortProfileOp vmop,
                                           char *stateDir,
                                           int *tapfd,
                                           size_t tapfdSize,
                                           unsigned int flags)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(6)
    ATTRIBUTE_NONNULL(8) ATTRIBUTE_NONNULL(10) G_GNUC_WARN_UNUSED_RESULT;

int virNetDevMacVLanTapOpen(const char *ifname,
                            int *tapfd,
                            size_t tapfdSize)
   ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
   G_GNUC_WARN_UNUSED_RESULT;

int virNetDevMacVLanTapSetup(int *tapfd, size_t tapfdSize, bool vnet_hdr)
   ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

int virNetDevMacVLanDeleteWithVPortProfile(const char *ifname,
                                           const virMacAddr *macaddress,
                                           const char *linkdev,
                                           int mode,
                                           const virNetDevVPortProfile *virtPortProfile,
                                           char *stateDir)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(6);

int virNetDevMacVLanRestartWithVPortProfile(const char *cr_ifname,
                                            const virMacAddr *macaddress,
                                            const char *linkdev,
                                            const unsigned char *vmuuid,
                                            const virNetDevVPortProfile *virtPortProfile,
                                            virNetDevVPortProfileOp vmOp)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;

int virNetDevMacVLanVPortProfileRegisterCallback(const char *ifname,
                                                 const virMacAddr *macaddress,
                                                 const char *linkdev,
                                                 const unsigned char *vmuuid,
                                                 const virNetDevVPortProfile *virtPortProfile,
                                                 virNetDevVPortProfileOp vmOp)
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
ATTRIBUTE_NONNULL(4) G_GNUC_WARN_UNUSED_RESULT;
