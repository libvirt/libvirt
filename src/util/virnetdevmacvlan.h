/*
 * Copyright (C) 2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     Stefan Berger <stefanb@us.ibm.com>
 */

#ifndef __UTIL_MACVTAP_H__
# define __UTIL_MACVTAP_H__

# include "internal.h"
# include "virsocketaddr.h"
# include "virnetdevbandwidth.h"
# include "virnetdevvportprofile.h"

/* the mode type for macvtap devices */
enum virNetDevMacVLanMode {
    VIR_NETDEV_MACVLAN_MODE_VEPA,
    VIR_NETDEV_MACVLAN_MODE_PRIVATE,
    VIR_NETDEV_MACVLAN_MODE_BRIDGE,
    VIR_NETDEV_MACVLAN_MODE_PASSTHRU,

    VIR_NETDEV_MACVLAN_MODE_LAST,
};
VIR_ENUM_DECL(virNetDevMacVLanMode)

int virNetDevMacVLanCreate(const char *ifname,
                           const char *type,
                           const unsigned char *macaddress,
                           const char *srcdev,
                           uint32_t macvlan_mode,
                           int *retry)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevMacVLanDelete(const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevMacVLanCreateWithVPortProfile(const char *ifname,
                                           const unsigned char *macaddress,
                                           const char *linkdev,
                                           enum virNetDevMacVLanMode mode,
                                           bool withTap,
                                           int vnet_hdr,
                                           const unsigned char *vmuuid,
                                           virNetDevVPortProfilePtr virtPortProfile,
                                           char **res_ifname,
                                           enum virNetDevVPortProfileOp vmop,
                                           char *stateDir,
                                           virNetDevBandwidthPtr bandwidth)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(7)
    ATTRIBUTE_NONNULL(9) ATTRIBUTE_NONNULL(11) ATTRIBUTE_RETURN_CHECK;

int virNetDevMacVLanDeleteWithVPortProfile(const char *ifname,
                                           const unsigned char *macaddress,
                                           const char *linkdev,
                                           int mode,
                                           virNetDevVPortProfilePtr virtPortProfile,
                                           char *stateDir)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(6) ATTRIBUTE_RETURN_CHECK;

int virNetDevMacVLanRestartWithVPortProfile(const char *cr_ifname,
                                           const unsigned char *macaddress,
                                           const char *linkdev,
                                           const unsigned char *vmuuid,
                                           virNetDevVPortProfilePtr virtPortProfile,
                                           enum virNetDevVPortProfileOp vmOp)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5) ATTRIBUTE_RETURN_CHECK;

#endif /* __UTIL_MACVTAP_H__ */
