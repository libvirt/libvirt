/*
 * bridge_driver_platform.h: platform specific routines for bridge driver
 *
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_BRIDGE_DRIVER_PLATFORM_H__
# define __VIR_BRIDGE_DRIVER_PLATFORM_H__

# include "internal.h"
# include "virthread.h"
# include "virdnsmasq.h"
# include "virnetworkobj.h"
# include "object_event.h"

/* Main driver state */
struct _virNetworkDriverState {
    virMutex lock;

    /* Immutable pointer, self-locking APIs */
    virNetworkObjListPtr networks;

    /* Immutable pointers, Immutable objects */
    char *networkConfigDir;
    char *networkAutostartDir;
    char *stateDir;
    char *pidDir;
    char *dnsmasqStateDir;
    char *radvdStateDir;

    /* Require lock to get a reference on the object,
     * lockless access thereafter
     */
    dnsmasqCapsPtr dnsmasqCaps;

    /* Immutable pointer, self-locking APIs */
    virObjectEventStatePtr networkEventState;
};

typedef struct _virNetworkDriverState virNetworkDriverState;
typedef virNetworkDriverState *virNetworkDriverStatePtr;

int networkCheckRouteCollision(virNetworkDefPtr def);

int networkAddFirewallRules(virNetworkDefPtr def);

void networkRemoveFirewallRules(virNetworkDefPtr def);

#endif /* __VIR_BRIDGE_DRIVER_PLATFORM_H__ */
