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
 */

#pragma once

#include "virsocketaddr.h"
#include "virfirewall.h"

int              iptablesSetupPrivateChains      (virFirewallLayer layer);

void             iptablesAddTcpInput             (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);
void             iptablesRemoveTcpInput          (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);

void             iptablesAddUdpInput             (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);
void             iptablesRemoveUdpInput          (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);

void             iptablesAddTcpOutput            (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);
void             iptablesRemoveTcpOutput         (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);
void             iptablesAddUdpOutput            (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);
void             iptablesRemoveUdpOutput         (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface,
                                                  int port);

int              iptablesAddForwardAllowOut      (virFirewall *fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev)
    G_GNUC_WARN_UNUSED_RESULT;
int              iptablesRemoveForwardAllowOut   (virFirewall *fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev)
    G_GNUC_WARN_UNUSED_RESULT;
int              iptablesAddForwardAllowRelatedIn(virFirewall *fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev)
    G_GNUC_WARN_UNUSED_RESULT;
int              iptablesRemoveForwardAllowRelatedIn(virFirewall *fw,
                                                     virSocketAddr *netaddr,
                                                     unsigned int prefix,
                                                     const char *iface,
                                                     const char *physdev)
    G_GNUC_WARN_UNUSED_RESULT;

int              iptablesAddForwardAllowIn       (virFirewall *fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev)
    G_GNUC_WARN_UNUSED_RESULT;
int              iptablesRemoveForwardAllowIn    (virFirewall *fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev)
    G_GNUC_WARN_UNUSED_RESULT;

void             iptablesAddForwardAllowCross    (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface);
void             iptablesRemoveForwardAllowCross (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface);

void             iptablesAddForwardRejectOut     (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface);
void             iptablesRemoveForwardRejectOut  (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface);

void             iptablesAddForwardRejectIn      (virFirewall *fw,
                                                  virFirewallLayer layer,
                                                  const char *iface);
void             iptablesRemoveForwardRejectIn   (virFirewall *fw,
                                                  virFirewallLayer layery,
                                                  const char *iface);

int              iptablesAddForwardMasquerade    (virFirewall *fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  virSocketAddrRange *addr,
                                                  virPortRange *port,
                                                  const char *protocol)
    G_GNUC_WARN_UNUSED_RESULT;
int              iptablesRemoveForwardMasquerade (virFirewall *fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  virSocketAddrRange *addr,
                                                  virPortRange *port,
                                                  const char *protocol)
    G_GNUC_WARN_UNUSED_RESULT;
int              iptablesAddDontMasquerade       (virFirewall *fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  const char *destaddr)
    G_GNUC_WARN_UNUSED_RESULT;
int              iptablesRemoveDontMasquerade    (virFirewall *fw,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  const char *destaddr)
    G_GNUC_WARN_UNUSED_RESULT;
void             iptablesAddOutputFixUdpChecksum (virFirewall *fw,
                                                  const char *iface,
                                                  int port);
void             iptablesRemoveOutputFixUdpChecksum (virFirewall *fw,
                                                     const char *iface,
                                                     int port);
