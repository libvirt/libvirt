/*
 * device_conf.h: device XML handling entry points
 *
 * Copyright (C) 2006-2012, 2014-2015 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __DEVICE_CONF_H__
# define __DEVICE_CONF_H__

# include <libxml/parser.h>
# include <libxml/tree.h>
# include <libxml/xpath.h>

# include "internal.h"
# include "virutil.h"
# include "virthread.h"
# include "virbuffer.h"

typedef enum {
    VIR_INTERFACE_STATE_UNKNOWN = 1,
    VIR_INTERFACE_STATE_NOT_PRESENT,
    VIR_INTERFACE_STATE_DOWN,
    VIR_INTERFACE_STATE_LOWER_LAYER_DOWN,
    VIR_INTERFACE_STATE_TESTING,
    VIR_INTERFACE_STATE_DORMANT,
    VIR_INTERFACE_STATE_UP,
    VIR_INTERFACE_STATE_LAST
} virInterfaceState;

VIR_ENUM_DECL(virInterfaceState)

typedef struct _virDevicePCIAddress virDevicePCIAddress;
typedef virDevicePCIAddress *virDevicePCIAddressPtr;
struct _virDevicePCIAddress {
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int function;
    int          multi;  /* virTristateSwitch */
};

typedef struct _virInterfaceLink virInterfaceLink;
typedef virInterfaceLink *virInterfaceLinkPtr;
struct _virInterfaceLink {
    virInterfaceState state; /* link state */
    unsigned int speed;      /* link speed in Mbits per second */
};

typedef enum {
    VIR_NET_DEV_FEAT_GRXCSUM,
    VIR_NET_DEV_FEAT_GTXCSUM,
    VIR_NET_DEV_FEAT_GSG,
    VIR_NET_DEV_FEAT_GTSO,
    VIR_NET_DEV_FEAT_GGSO,
    VIR_NET_DEV_FEAT_GGRO,
    VIR_NET_DEV_FEAT_LRO,
    VIR_NET_DEV_FEAT_RXVLAN,
    VIR_NET_DEV_FEAT_TXVLAN,
    VIR_NET_DEV_FEAT_NTUPLE,
    VIR_NET_DEV_FEAT_RXHASH,
    VIR_NET_DEV_FEAT_RDMA,
    VIR_NET_DEV_FEAT_TXUDPTNL,
    VIR_NET_DEV_FEAT_LAST
} virNetDevFeature;

VIR_ENUM_DECL(virNetDevFeature)

int virDevicePCIAddressIsValid(virDevicePCIAddressPtr addr,
                               bool report);

int virDevicePCIAddressParseXML(xmlNodePtr node,
                                virDevicePCIAddressPtr addr);

int virDevicePCIAddressFormat(virBufferPtr buf,
                              virDevicePCIAddress addr,
                              bool includeTypeInAddr);

bool virDevicePCIAddressEqual(virDevicePCIAddress *addr1,
                              virDevicePCIAddress *addr2);

int virInterfaceLinkParseXML(xmlNodePtr node,
                             virInterfaceLinkPtr lnk);

int virInterfaceLinkFormat(virBufferPtr buf,
                           const virInterfaceLink *lnk);

#endif /* __DEVICE_CONF_H__ */
