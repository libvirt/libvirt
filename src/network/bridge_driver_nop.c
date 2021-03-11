/*
 * Copyright (C) 2006-2013 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

int networkAddFirewallRules(virNetworkDef *def G_GNUC_UNUSED)
{
    return 0;
}

void networkRemoveFirewallRules(virNetworkDef *def G_GNUC_UNUSED)
{
}
