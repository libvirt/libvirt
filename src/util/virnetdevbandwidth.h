/*
 * Copyright (C) 2009-2015 Red Hat, Inc.
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
 *     Michal Privoznik <mprivozn@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NETDEV_BANDWIDTH_H__
# define __VIR_NETDEV_BANDWIDTH_H__

# include "internal.h"
# include "virmacaddr.h"

typedef struct _virNetDevBandwidthRate virNetDevBandwidthRate;
typedef virNetDevBandwidthRate *virNetDevBandwidthRatePtr;
struct _virNetDevBandwidthRate {
    unsigned long long average;  /* kbytes/s */
    unsigned long long peak;     /* kbytes/s */
    unsigned long long floor;    /* kbytes/s */
    unsigned long long burst;    /* kbytes */
};

typedef struct _virNetDevBandwidth virNetDevBandwidth;
typedef virNetDevBandwidth *virNetDevBandwidthPtr;
struct _virNetDevBandwidth {
    virNetDevBandwidthRatePtr in, out;
};

void virNetDevBandwidthFree(virNetDevBandwidthPtr def);

int virNetDevBandwidthSet(const char *ifname,
                          virNetDevBandwidthPtr bandwidth,
                          bool hierarchical_class)
    ATTRIBUTE_RETURN_CHECK;
int virNetDevBandwidthClear(const char *ifname);
int virNetDevBandwidthCopy(virNetDevBandwidthPtr *dest,
                           const virNetDevBandwidth *src)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

bool virNetDevBandwidthEqual(virNetDevBandwidthPtr a, virNetDevBandwidthPtr b);

int virNetDevBandwidthPlug(const char *brname,
                           virNetDevBandwidthPtr net_bandwidth,
                           const virMacAddr *ifmac_ptr,
                           virNetDevBandwidthPtr bandwidth,
                           unsigned int id)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevBandwidthUnplug(const char *brname,
                             unsigned int id)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevBandwidthUpdateRate(const char *ifname,
                                 unsigned int id,
                                 virNetDevBandwidthPtr bandwidth,
                                 unsigned long long new_rate)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevBandwidthUpdateFilter(const char *ifname,
                                   const virMacAddr *ifmac_ptr,
                                   unsigned int id)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_RETURN_CHECK;
#endif /* __VIR_NETDEV_BANDWIDTH_H__ */
