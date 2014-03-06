/*
 * viriptables.h: helper APIs for managing iptables
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
 *
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 */

#ifndef __VIR_IPTABLES_H__
# define __VIR_IPTABLES_H__

# include "virsocketaddr.h"
# include "virfirewall.h"

void             iptablesAddTcpInput             (virFirewallPtr fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);
void             iptablesRemoveTcpInput          (virFirewallPtr fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);

void             iptablesAddUdpInput             (virFirewallPtr fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);
void             iptablesRemoveUdpInput          (virFirewallPtr fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);

void             iptablesAddUdpOutput            (virFirewallPtr fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);
void             iptablesRemoveUdpOutput         (virFirewallPtr fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);

int              iptablesAddForwardAllowOut      (virFirewallPtr fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev)
    ATTRIBUTE_RETURN_CHECK;
int              iptablesRemoveForwardAllowOut   (virFirewallPtr fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev)
    ATTRIBUTE_RETURN_CHECK;
int              iptablesAddForwardAllowRelatedIn(virFirewallPtr fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev)
    ATTRIBUTE_RETURN_CHECK;
int              iptablesRemoveForwardAllowRelatedIn(virFirewallPtr fw,
                                                     virSocketAddr *netaddr,
                                                     unsigned int prefix,
                                                     const char *iface,
                                                     const char *physdev)
    ATTRIBUTE_RETURN_CHECK;

int              iptablesAddForwardAllowIn       (virFirewallPtr fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev)
    ATTRIBUTE_RETURN_CHECK;
int              iptablesRemoveForwardAllowIn    (virFirewallPtr fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev)
    ATTRIBUTE_RETURN_CHECK;

void             iptablesAddForwardAllowCross    (virFirewallPtr fw,
                                                  virFirewallLayer layer,
                                                  const char *iface);
void             iptablesRemoveForwardAllowCross (virFirewallPtr fw,
                                                  virFirewallLayer layer,
                                                  const char *iface);

void             iptablesAddForwardRejectOut     (virFirewallPtr fw,
                                                  virFirewallLayer layer,
                                                  const char *iface);
void             iptablesRemoveForwardRejectOut  (virFirewallPtr fw,
                                                  virFirewallLayer layer,
                                                  const char *iface);

void             iptablesAddForwardRejectIn      (virFirewallPtr fw,
                                                  virFirewallLayer layer,
                                                  const char *iface);
void             iptablesRemoveForwardRejectIn   (virFirewallPtr fw,
                                                  virFirewallLayer layery,
                                                  const char *iface);

int              iptablesAddForwardMasquerade    (virFirewallPtr fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  virSocketAddrRangePtr addr,
                                                  virPortRangePtr port,
                                                  const char *protocol)
    ATTRIBUTE_RETURN_CHECK;
int              iptablesRemoveForwardMasquerade (virFirewallPtr fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  virSocketAddrRangePtr addr,
                                                  virPortRangePtr port,
                                                  const char *protocol)
    ATTRIBUTE_RETURN_CHECK;
int              iptablesAddDontMasquerade       (virFirewallPtr fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  const char *destaddr)
    ATTRIBUTE_RETURN_CHECK;
int              iptablesRemoveDontMasquerade    (virFirewallPtr fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  const char *destaddr)
    ATTRIBUTE_RETURN_CHECK;
void             iptablesAddOutputFixUdpChecksum (virFirewallPtr fw,
                                                  const char *iface,
                                                  int port);
void             iptablesRemoveOutputFixUdpChecksum (virFirewallPtr fw,
                                                     const char *iface,
                                                     int port);

#endif /* __VIR_IPTABLES_H__ */
