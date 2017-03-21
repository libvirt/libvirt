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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Michal Privoznik <mprivozn@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NETDEV_BANDWIDTH_CONF_H__
# define __VIR_NETDEV_BANDWIDTH_CONF_H__

# include "internal.h"
# include "virnetdevbandwidth.h"
# include "virbuffer.h"
# include "virxml.h"
# include "domain_conf.h"

int virNetDevBandwidthParse(virNetDevBandwidthPtr *bandwidth,
                            xmlNodePtr node,
                            int net_type)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevBandwidthFormat(virNetDevBandwidthPtr def,
                             virBufferPtr buf)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virDomainClearNetBandwidth(virDomainObjPtr vm)
    ATTRIBUTE_NONNULL(1);

static inline bool virNetDevSupportBandwidth(virDomainNetType type)
{
    switch (type) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        return true;
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }
    return false;
}

#endif /* __VIR_NETDEV_BANDWIDTH_CONF_H__ */
