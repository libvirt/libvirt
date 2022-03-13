/*
 * Copyright (C) 2022 Red Hat, Inc.
 *
 * bridge_driver__conf.c: network.conf config file inspection
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
 */

/* includes */
#include <config.h>
#include "virerror.h"
#include "datatypes.h"
#include "virlog.h"
#include "bridge_driver_conf.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

VIR_LOG_INIT("network.bridge_driver");


dnsmasqCaps *
networkGetDnsmasqCaps(virNetworkDriverState *driver)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);
    return virObjectRef(driver->dnsmasqCaps);
}


int
networkDnsmasqCapsRefresh(virNetworkDriverState *driver)
{
    dnsmasqCaps *caps;

    if (!(caps = dnsmasqCapsNewFromBinary()))
        return -1;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        virObjectUnref(driver->dnsmasqCaps);
        driver->dnsmasqCaps = caps;
    }

    return 0;
}
