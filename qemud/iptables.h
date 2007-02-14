/*
 * Copyright (C) 2007 Red Hat, Inc.
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
#define __QEMUD_IPTABLES_H__

typedef struct _iptablesContext iptablesContext;

iptablesContext *iptablesContextNew              (void);
void             iptablesContextFree             (iptablesContext *ctx);

int              iptablesAddTcpInput             (iptablesContext *ctx,
                                                  const char *iface,
                                                  int port);
int              iptablesRemoveTcpInput          (iptablesContext *ctx,
                                                  const char *iface,
                                                  int port);

int              iptablesAddUdpInput             (iptablesContext *ctx,
                                                  const char *iface,
                                                  int port);
int              iptablesRemoveUdpInput          (iptablesContext *ctx,
                                                  const char *iface,
                                                  int port);

int              iptablesAddPhysdevForward       (iptablesContext *ctx,
                                                  const char *iface);
int              iptablesRemovePhysdevForward    (iptablesContext *ctx,
                                                  const char *iface);

int              iptablesAddInterfaceForward     (iptablesContext *ctx,
                                                  const char *iface);
int              iptablesRemoveInterfaceForward  (iptablesContext *ctx,
                                                  const char *iface);

int              iptablesAddStateForward         (iptablesContext *ctx,
                                                  const char *iface);
int              iptablesRemoveStateForward      (iptablesContext *ctx,
                                                  const char *iface);

int              iptablesAddNonBridgedMasq       (iptablesContext *ctx);
int              iptablesRemoveNonBridgedMasq    (iptablesContext *ctx);

#endif /* __QEMUD_IPTABLES_H__ */

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
