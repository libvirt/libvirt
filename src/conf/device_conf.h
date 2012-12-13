/*
 * device_conf.h: device XML handling entry points
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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

enum virDeviceAddressPciMulti {
    VIR_DEVICE_ADDRESS_PCI_MULTI_DEFAULT = 0,
    VIR_DEVICE_ADDRESS_PCI_MULTI_ON,
    VIR_DEVICE_ADDRESS_PCI_MULTI_OFF,

    VIR_DEVICE_ADDRESS_PCI_MULTI_LAST
};

typedef struct _virDevicePCIAddress virDevicePCIAddress;
typedef virDevicePCIAddress *virDevicePCIAddressPtr;
struct _virDevicePCIAddress {
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int function;
    int          multi;  /* enum virDomainDeviceAddressPciMulti */
};

int virDevicePCIAddressIsValid(virDevicePCIAddressPtr addr);

int virDevicePCIAddressParseXML(xmlNodePtr node,
                                virDevicePCIAddressPtr addr);

int virDevicePCIAddressFormat(virBufferPtr buf,
                              virDevicePCIAddress addr,
                              bool includeTypeInAddr);

bool virDevicePCIAddressEqual(virDevicePCIAddress *addr1,
                              virDevicePCIAddress *addr2);


VIR_ENUM_DECL(virDeviceAddressPciMulti)

#endif /* __DEVICE_CONF_H__ */
