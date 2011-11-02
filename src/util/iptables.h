/*
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 */

#ifndef __QEMUD_IPTABLES_H__
# define __QEMUD_IPTABLES_H__

# include "virsocketaddr.h"

typedef struct _iptablesContext iptablesContext;

iptablesContext *iptablesContextNew              (void);
void             iptablesContextFree             (iptablesContext *ctx);

int              iptablesAddTcpInput             (iptablesContext *ctx,
                                                  int family,
                                                  const char *iface,
                                                  int port);
int              iptablesRemoveTcpInput          (iptablesContext *ctx,
                                                  int family,
                                                  const char *iface,
                                                  int port);

int              iptablesAddUdpInput             (iptablesContext *ctx,
                                                  int family,
                                                  const char *iface,
                                                  int port);
int              iptablesRemoveUdpInput          (iptablesContext *ctx,
                                                  int family,
                                                  const char *iface,
                                                  int port);

int              iptablesAddForwardAllowOut      (iptablesContext *ctx,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);
int              iptablesRemoveForwardAllowOut   (iptablesContext *ctx,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);

int              iptablesAddForwardAllowRelatedIn(iptablesContext *ctx,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);
int              iptablesRemoveForwardAllowRelatedIn(iptablesContext *ctx,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);

int              iptablesAddForwardAllowIn       (iptablesContext *ctx,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);
int              iptablesRemoveForwardAllowIn    (iptablesContext *ctx,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *iface,
                                                  const char *physdev);

int              iptablesAddForwardAllowCross    (iptablesContext *ctx,
                                                  int family,
                                                  const char *iface);
int              iptablesRemoveForwardAllowCross (iptablesContext *ctx,
                                                  int family,
                                                  const char *iface);

int              iptablesAddForwardRejectOut     (iptablesContext *ctx,
                                                  int family,
                                                  const char *iface);
int              iptablesRemoveForwardRejectOut  (iptablesContext *ctx,
                                                  int family,
                                                  const char *iface);

int              iptablesAddForwardRejectIn      (iptablesContext *ctx,
                                                  int family,
                                                  const char *iface);
int              iptablesRemoveForwardRejectIn   (iptablesContext *ctx,
                                                  int family,
                                                  const char *iface);

int              iptablesAddForwardMasquerade    (iptablesContext *ctx,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  const char *protocol);
int              iptablesRemoveForwardMasquerade (iptablesContext *ctx,
                                                  virSocketAddr *netaddr,
                                                  unsigned int prefix,
                                                  const char *physdev,
                                                  const char *protocol);
int              iptablesAddOutputFixUdpChecksum (iptablesContext *ctx,
                                                  const char *iface,
                                                  int port);
int              iptablesRemoveOutputFixUdpChecksum (iptablesContext *ctx,
                                                     const char *iface,
                                                     int port);

#endif /* __QEMUD_IPTABLES_H__ */
