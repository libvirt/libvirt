/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
 *
 * lxc_monitor.h: client for LXC controller monitor
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

#include "virobject.h"
#include "domain_conf.h"
#include "lxc_monitor_protocol.h"

typedef struct _virLXCMonitor virLXCMonitor;
typedef virLXCMonitor *virLXCMonitorPtr;

typedef struct _virLXCMonitorCallbacks virLXCMonitorCallbacks;
typedef virLXCMonitorCallbacks *virLXCMonitorCallbacksPtr;

typedef void (*virLXCMonitorCallbackDestroy)(virLXCMonitorPtr mon,
                                             virDomainObjPtr vm);
typedef void (*virLXCMonitorCallbackEOFNotify)(virLXCMonitorPtr mon,
                                               virDomainObjPtr vm);

typedef void (*virLXCMonitorCallbackExitNotify)(virLXCMonitorPtr mon,
                                                virLXCMonitorExitStatus status,
                                                virDomainObjPtr vm);

typedef void (*virLXCMonitorCallbackInitNotify)(virLXCMonitorPtr mon,
                                                pid_t pid,
                                                virDomainObjPtr vm);

struct _virLXCMonitorCallbacks {
    virLXCMonitorCallbackDestroy destroy;
    virLXCMonitorCallbackEOFNotify eofNotify;
    virLXCMonitorCallbackExitNotify exitNotify;
    virLXCMonitorCallbackInitNotify initNotify;
};

virLXCMonitorPtr virLXCMonitorNew(virDomainObjPtr vm,
                                  const char *socketdir,
                                  virLXCMonitorCallbacksPtr cb);

void virLXCMonitorClose(virLXCMonitorPtr mon);

void virLXCMonitorLock(virLXCMonitorPtr mon);
void virLXCMonitorUnlock(virLXCMonitorPtr mon);
