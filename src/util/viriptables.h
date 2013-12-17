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

#ifndef __QEMUD_IPTABLES_H__
# define __QEMUD_IPTABLES_H__

# include "virsocketaddr.h"

int              iptablesAddTcpInput             (int family,
                                                  const char *iface,
                                                  int port);
int              iptablesRemoveTcpInput          (int family,
                                                  const char *iface,
                                                  int port);

int              iptablesAddUdpInput             (int family,
                                                  const char *iface,
                                                  int port);
int              iptablesRemoveUdpInput          (int family,
                                                  const char *iface,
                                                  int port);

int              iptablesAddUdpOutput            (int family,
                                                  const char *iface,
                                                  int port);
int              iptablesRemoveUdpOutput         (int family,
                                                  const char *iface,
                                                  int port);

int              iptablesAddForwardAllowOut      (virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);
int              iptablesRemoveForwardAllowOut   (virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);

int              iptablesAddForwardAllowRelatedIn(virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);
int              iptablesRemoveForwardAllowRelatedIn(virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);

int              iptablesAddForwardAllowIn       (virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);
int              iptablesRemoveForwardAllowIn    (virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);

int              iptablesAddForwardAllowCross    (int family,
                                                  const char *iface);
int              iptablesRemoveForwardAllowCross (int family,
                                                  const char *iface);

int              iptablesAddForwardRejectOut     (int family,
                                                  const char *iface);
int              iptablesRemoveForwardRejectOut  (int family,
                                                  const char *iface);

int              iptablesAddForwardRejectIn      (int family,
                                                  const char *iface);
int              iptablesRemoveForwardRejectIn   (int family,
                                                  const char *iface);

int              iptablesAddForwardMasquerade    (virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  virSocketAddrRangePtr addr,
                                                  virPortRangePtr port,
                                                  const char *protocol);
int              iptablesRemoveForwardMasquerade (virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  virSocketAddrRangePtr addr,
                                                  virPortRangePtr port,
                                                  const char *protocol);
int              iptablesAddDontMasquerade       (virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  const char *destaddr);
int              iptablesRemoveDontMasquerade    (virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  const char *destaddr);
int              iptablesAddOutputFixUdpChecksum (const char *iface,
                                                  int port);
int              iptablesRemoveOutputFixUdpChecksum (const char *iface,
                                                     int port);

#endif /* __QEMUD_IPTABLES_H__ */
