/*
 * Copyright (C) 2007-2012, 2014 Red Hat, Inc.
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
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NETDEV_BRIDGE_H__
# define __VIR_NETDEV_BRIDGE_H__

# include "internal.h"
# include "virmacaddr.h"

int virNetDevBridgeCreate(const char *brname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevBridgeDelete(const char *brname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetDevBridgeAddPort(const char *brname,
                           const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevBridgeRemovePort(const char *brname,
                              const char *ifname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevBridgeSetSTPDelay(const char *brname,
                               int delay)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevBridgeGetSTPDelay(const char *brname,
                               int *delay)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevBridgeSetSTP(const char *brname,
                          bool enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevBridgeGetSTP(const char *brname,
                          bool *enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevBridgeSetVlanFiltering(const char *brname,
                                    bool enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetDevBridgeGetVlanFiltering(const char *brname,
                                    bool *enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetDevBridgePortGetLearning(const char *brname,
                                   const char *ifname,
                                   bool *enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;
int virNetDevBridgePortSetLearning(const char *brname,
                                   const char *ifname,
                                   bool enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevBridgePortGetUnicastFlood(const char *brname,
                                       const char *ifname,
                                       bool *enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;
int virNetDevBridgePortSetUnicastFlood(const char *brname,
                                       const char *ifname,
                                       bool enable)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

typedef enum {
    VIR_NETDEVBRIDGE_FDB_FLAG_ROUTER    = (1 << 0),
    VIR_NETDEVBRIDGE_FDB_FLAG_SELF      = (1 << 1),
    VIR_NETDEVBRIDGE_FDB_FLAG_MASTER    = (1 << 2),

    VIR_NETDEVBRIDGE_FDB_FLAG_PERMANENT = (1 << 3),
    VIR_NETDEVBRIDGE_FDB_FLAG_TEMP      = (1 << 4),
} virNetDevBridgeFDBFlags;

int virNetDevBridgeFDBAdd(const virMacAddr *mac, const char *ifname,
                          unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetDevBridgeFDBDel(const virMacAddr *mac, const char *ifname,
                          unsigned int flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
#endif /* __VIR_NETDEV_BRIDGE_H__ */
