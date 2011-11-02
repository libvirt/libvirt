/*
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
 *     Michal Privoznik <mprivozn@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NETDEV_BANDWIDTH_H__
# define __VIR_NETDEV_BANDWIDTH_H__

# include "internal.h"

typedef struct _virNetDevBandwidthRate virNetDevBandwidthRate;
typedef virNetDevBandwidthRate *virNetDevBandwidthRatePtr;
struct _virNetDevBandwidthRate {
    unsigned long long average;  /* kbytes/s */
    unsigned long long peak;     /* kbytes/s */
    unsigned long long burst;    /* kbytes */
};

typedef struct _virNetDevBandwidth virNetDevBandwidth;
typedef virNetDevBandwidth *virNetDevBandwidthPtr;
struct _virNetDevBandwidth {
    virNetDevBandwidthRatePtr in, out;
};

void virNetDevBandwidthFree(virNetDevBandwidthPtr def);

int virNetDevBandwidthSet(const char *ifname, virNetDevBandwidthPtr bandwidth)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevBandwidthClear(const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevBandwidthCopy(virNetDevBandwidthPtr *dest, const virNetDevBandwidthPtr src)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

bool virNetDevBandwidthEqual(virNetDevBandwidthPtr a, virNetDevBandwidthPtr b);

#endif /* __VIR_NETDEV_BANDWIDTH_H__ */
