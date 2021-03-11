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

typedef struct _virLXCMonitorCallbacks virLXCMonitorCallbacks;

typedef void (*virLXCMonitorCallbackDestroy)(virLXCMonitor *mon,
                                             virDomainObj *vm);
typedef void (*virLXCMonitorCallbackEOFNotify)(virLXCMonitor *mon,
                                               virDomainObj *vm);

typedef void (*virLXCMonitorCallbackExitNotify)(virLXCMonitor *mon,
                                                virLXCMonitorExitStatus status,
                                                virDomainObj *vm);

typedef void (*virLXCMonitorCallbackInitNotify)(virLXCMonitor *mon,
                                                pid_t pid,
                                                virDomainObj *vm);

struct _virLXCMonitorCallbacks {
    virLXCMonitorCallbackDestroy destroy;
    virLXCMonitorCallbackEOFNotify eofNotify;
    virLXCMonitorCallbackExitNotify exitNotify;
    virLXCMonitorCallbackInitNotify initNotify;
};

virLXCMonitor *virLXCMonitorNew(virDomainObj *vm,
                                  const char *socketdir,
                                  virLXCMonitorCallbacks *cb);

void virLXCMonitorClose(virLXCMonitor *mon);

void virLXCMonitorLock(virLXCMonitor *mon);
void virLXCMonitorUnlock(virLXCMonitor *mon);
