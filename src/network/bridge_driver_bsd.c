/*
 * Copyright (C) 2025 FreeBSD Foundation
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

#include <config.h>

#include "virlog.h"
#include "network_pf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("network.bridge_driver_bsd");


void networkPreReloadFirewallRules(virNetworkDriverState *driver G_GNUC_UNUSED,
                                   bool startup G_GNUC_UNUSED,
                                   bool force G_GNUC_UNUSED)
{
}


void networkPostReloadFirewallRules(bool startup G_GNUC_UNUSED)
{
}


int networkCheckRouteCollision(virNetworkDef *def G_GNUC_UNUSED)
{
    return 0;
}

int networkAddFirewallRules(virNetworkDef *def G_GNUC_UNUSED,
                            virFirewallBackend firewallBackend,
                            virFirewall **fwRemoval G_GNUC_UNUSED)
{
    if (def->bridgeZone) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("zone %1$s requested for network %2$s but firewalld is not supported on BSD"),
                       def->bridgeZone, def->name);
        return -1;
    }

    if (def->forward.type == VIR_NETWORK_FORWARD_OPEN) {
        VIR_DEBUG("No firewall rules to add for mode='open' network '%s'", def->name);
    } else {
        VIR_DEBUG("Adding firewall rules for mode='%s' network '%s' using %s",
                  virNetworkForwardTypeToString(def->forward.type),
                  def->name,
                  virFirewallBackendTypeToString(firewallBackend));

        /* now actually add the rules */
        switch (firewallBackend) {
        case VIR_FIREWALL_BACKEND_NONE:
            virReportError(VIR_ERR_NO_SUPPORT, "%s",
                           _("No firewall backend is available"));
            return -1;

        case VIR_FIREWALL_BACKEND_PF:
            return pfAddFirewallRules(def);

        case VIR_FIREWALL_BACKEND_IPTABLES:
        case VIR_FIREWALL_BACKEND_NFTABLES:
        case VIR_FIREWALL_BACKEND_LAST:
            virReportEnumRangeError(virFirewallBackend, firewallBackend);
            return -1;
        }
    }
    return 0;
}

void
networkRemoveFirewallRules(virNetworkObj *obj,
                           bool unsetZone G_GNUC_UNUSED)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);

    if (def->forward.type == VIR_NETWORK_FORWARD_OPEN) {
        VIR_DEBUG("No firewall rules to remove for mode='open' network '%s'",
                  def->name);
        return;
    }

    pfRemoveFirewallRules(def);
}
