/*
 * virfirewalld.h: support for firewalld (https://firewalld.org)
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRFIREWALLD_H
# define LIBVIRT_VIRFIREWALLD_H

# define VIR_FIREWALL_FIREWALLD_SERVICE "org.fedoraproject.FirewallD1"

typedef enum {
    VIR_FIREWALLD_BACKEND_NONE,
    VIR_FIREWALLD_BACKEND_IPTABLES,
    VIR_FIREWALLD_BACKEND_NFTABLES,
    VIR_FIREWALLD_BACKEND_LAST,
} virFirewallDBackendType;

int virFirewallDGetVersion(unsigned long *version);
int virFirewallDGetBackend(void);
int virFirewallDIsRegistered(void);
int virFirewallDGetZones(char ***zones, size_t *nzones);
bool virFirewallDZoneExists(const char *match);
int virFirewallDApplyRule(virFirewallLayer layer,
                          char **args, size_t argsLen,
                          bool ignoreErrors,
                          char **output);

int virFirewallDInterfaceSetZone(const char *iface,
                                 const char *zone);

#endif /* LIBVIRT_VIRFIREWALLD_H */
