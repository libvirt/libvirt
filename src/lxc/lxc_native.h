/*
 * lxc_native.h: LXC native configuration import
 *
 * Copyright (c) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include "domain_conf.h"
#include "virenum.h"

#define LXC_CONFIG_FORMAT "lxc-tools"

typedef enum {
    VIR_LXC_NETWORK_CONFIG_NAME,
    VIR_LXC_NETWORK_CONFIG_TYPE,
    VIR_LXC_NETWORK_CONFIG_LINK,
    VIR_LXC_NETWORK_CONFIG_HWADDR,
    VIR_LXC_NETWORK_CONFIG_FLAGS,
    VIR_LXC_NETWORK_CONFIG_MACVLAN_MODE,
    VIR_LXC_NETWORK_CONFIG_VLAN_ID,
    VIR_LXC_NETWORK_CONFIG_IPV4,
    VIR_LXC_NETWORK_CONFIG_IPV4_GATEWAY,
    VIR_LXC_NETWORK_CONFIG_IPV4_ADDRESS,
    VIR_LXC_NETWORK_CONFIG_IPV6,
    VIR_LXC_NETWORK_CONFIG_IPV6_GATEWAY,
    VIR_LXC_NETWORK_CONFIG_IPV6_ADDRESS,
    VIR_LXC_NETWORK_CONFIG_LAST,
} virLXCNetworkConfigEntry;

VIR_ENUM_DECL(virLXCNetworkConfigEntry);

virDomainDef *lxcParseConfigString(const char *config,
                                     virCaps *caps,
                                     virDomainXMLOption *xmlopt);
