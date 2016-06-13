/*
 * Copyright (C) 2007-2016 Red Hat, Inc.
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

#ifndef __VIR_NETDEVIP_H__
# define __VIR_NETDEVIP_H__

# include "virsocketaddr.h"

/* manipulating/querying the netdev */
int virNetDevIPAddrAdd(const char *ifname,
                       virSocketAddr *addr,
                       virSocketAddr *peer,
                       unsigned int prefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevIPRouteAdd(const char *ifname,
                        virSocketAddrPtr addr,
                        unsigned int prefix,
                        virSocketAddrPtr gateway,
                        unsigned int metric)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_RETURN_CHECK;
int virNetDevIPAddrDel(const char *ifname,
                       virSocketAddr *addr,
                       unsigned int prefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevIPAddrGet(const char *ifname, virSocketAddrPtr addr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevIPWaitDadFinish(virSocketAddrPtr *addrs, size_t count)
    ATTRIBUTE_NONNULL(1);

#endif /* __VIR_NETDEVIP_H__ */
