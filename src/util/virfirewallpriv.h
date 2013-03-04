/*
 * virfirewallpriv.h: integration with firewalls private APIs
 *
 * Copyright (C) 2013 Red Hat, Inc.
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
 *    Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_FIREWALL_PRIV_H_ALLOW__
# error "virfirewallpriv.h may only be included by virfirewall.c or test suites"
#endif

#ifndef __VIR_FIREWALL_PRIV_H__
# define __VIR_FIREWALL_PRIV_H__

# include "virfirewall.h"

# define VIR_FIREWALL_FIREWALLD_SERVICE "org.fedoraproject.FirewallD1"

typedef enum {
    VIR_FIREWALL_BACKEND_AUTOMATIC,
    VIR_FIREWALL_BACKEND_DIRECT,
    VIR_FIREWALL_BACKEND_FIREWALLD,

    VIR_FIREWALL_BACKEND_LAST,
} virFirewallBackend;

int virFirewallSetBackend(virFirewallBackend backend);

#endif /* __VIR_FIREWALL_PRIV_H__ */
