/*
 * nwfilter_driver_conf.h: nwfilter driver state and config objects
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
 */

#pragma once

#include "libvirt_internal.h"
#include "virthread.h"
#include "virnwfilterobj.h"
#include "virfirewall.h"
#include "virinhibitor.h"

typedef struct _virNWFilterDriverConfig virNWFilterDriverConfig;
struct _virNWFilterDriverConfig {
    virObject parent;

    /* Immutable pointers, Immutable objects */
    char *stateDir;
    char *configDir;
    char *bindingDir;

    virFirewallBackend firewallBackend;

    bool firewallTracing;
    bool ruleCounters;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNWFilterDriverConfig, virObjectUnref);

/* Main driver state */
typedef struct _virNWFilterDriverState virNWFilterDriverState;
struct _virNWFilterDriverState {
    bool privileged;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    virNWFilterObjList *nwfilters;

    virNWFilterBindingObjList *bindings;

    virNWFilterDriverConfig *config;

    /* Recursive. Hold for filter changes, instantiation or deletion */
    virMutex updateLock;
    bool updateLockInitialized;
};

virNWFilterDriverConfig *
virNWFilterDriverConfigNew(bool privileged);
virNWFilterDriverConfig *
virNWFilterDriverGetConfig(virNWFilterDriverState *driver);
