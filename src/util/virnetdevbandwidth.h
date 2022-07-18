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
 */

#pragma once

#include "internal.h"
#include "virmacaddr.h"

typedef struct _virNetDevBandwidthRate virNetDevBandwidthRate;
struct _virNetDevBandwidthRate {
    unsigned long long average;  /* kilobytes/s */
    unsigned long long peak;     /* kilobytes/s */
    unsigned long long floor;    /* kilobytes/s */
    unsigned long long burst;    /* kibibytes */
};

typedef struct _virNetDevBandwidth virNetDevBandwidth;
struct _virNetDevBandwidth {
    virNetDevBandwidthRate *in;
    virNetDevBandwidthRate *out;
};

void virNetDevBandwidthFree(virNetDevBandwidth *def);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNetDevBandwidth, virNetDevBandwidthFree);

int virNetDevBandwidthSet(const char *ifname,
                          const virNetDevBandwidth *bandwidth,
                          bool hierarchical_class,
                          bool swapped)
    G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBandwidthClear(const char *ifname);
int virNetDevBandwidthCopy(virNetDevBandwidth **dest,
                           const virNetDevBandwidth *src)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

bool virNetDevBandwidthEqual(const virNetDevBandwidth *a, const virNetDevBandwidth *b);

int virNetDevBandwidthPlug(const char *brname,
                           virNetDevBandwidth *net_bandwidth,
                           const virMacAddr *ifmac_ptr,
                           virNetDevBandwidth *bandwidth,
                           unsigned int id)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
    G_GNUC_WARN_UNUSED_RESULT;

int virNetDevBandwidthUnplug(const char *brname,
                             unsigned int id)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

int virNetDevBandwidthUpdateRate(const char *ifname,
                                 unsigned int id,
                                 virNetDevBandwidth *bandwidth,
                                 unsigned long long new_rate)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

int virNetDevBandwidthUpdateFilter(const char *ifname,
                                   const virMacAddr *ifmac_ptr,
                                   unsigned int id)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    G_GNUC_WARN_UNUSED_RESULT;

int virNetDevBandwidthSetRootQDisc(const char *ifname,
                                   const char *qdisc)
    G_NO_INLINE;
