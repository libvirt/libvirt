/*
 * network_iptables.h: helper APIs for managing iptables in network driver
 *
 * Copyright (C) 2007, 2008 Red Hat, Inc.
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

#include "virfirewall.h"
#include "network_conf.h"

int iptablesAddFirewallRules(virNetworkDef *def, virFirewall **fwRemoval);

void iptablesRemoveFirewallRules(virNetworkDef *def);

int iptablesSetupPrivateChains(virFirewallLayer layer);
