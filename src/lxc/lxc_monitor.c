/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
 *
 * lxc_monitor.c: client for LXC controller monitor
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

#include <config.h>

#include "lxc_monitor.h"
#include "lxc_conf.h"
#include "lxc_monitor_dispatch.h"

#include "viralloc.h"

#include "virerror.h"
#include "virlog.h"
#include "virthread.h"
#include "rpc/virnetclient.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_monitor");

struct _virLXCMonitor {
    virObjectLockable parent;

    virDomainObjPtr vm;
    virLXCMonitorCallbacks cb;

    virNetClientPtr client;
    virNetClientProgramPtr program;
};

static virClassPtr virLXCMonitorClass;
static void virLXCMonitorDispose(void *obj);

static int virLXCMonitorOnceInit(void)
{
    if (!(virLXCMonitorClass = virClassNew(virClassForObjectLockable(),
                                           "virLXCMonitor",
                                           sizeof(virLXCMonitor),
                                           virLXCMonitorDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virLXCMonitor)

static void
virLXCMonitorHandleEventExit(virNetClientProgramPtr prog,
                             virNetClientPtr client,
                             void *evdata, void *opaque);
static void
virLXCMonitorHandleEventInit(virNetClientProgramPtr prog,
                             virNetClientPtr client,
                             void *evdata, void *opaque);

static virNetClientProgramEvent virLXCMonitorEvents[] = {
    { VIR_LXC_MONITOR_PROC_EXIT_EVENT,
      virLXCMonitorHandleEventExit,
      sizeof(virLXCMonitorExitEventMsg),
      (xdrproc_t)xdr_virLXCMonitorExitEventMsg },
    { VIR_LXC_MONITOR_PROC_INIT_EVENT,
      virLXCMonitorHandleEventInit,
      sizeof(virLXCMonitorInitEventMsg),
      (xdrproc_t)xdr_virLXCMonitorInitEventMsg },
};


static void
virLXCMonitorHandleEventExit(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                             virNetClientPtr client ATTRIBUTE_UNUSED,
                             void *evdata, void *opaque)
{
    virLXCMonitorPtr mon = opaque;
    virLXCMonitorExitEventMsg *msg = evdata;

    VIR_DEBUG("Event exit %d", msg->status);
    if (mon->cb.exitNotify)
        mon->cb.exitNotify(mon, msg->status, mon->vm);
}


static void
virLXCMonitorHandleEventInit(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                             virNetClientPtr client ATTRIBUTE_UNUSED,
                             void *evdata, void *opaque)
{
    virLXCMonitorPtr mon = opaque;
    virLXCMonitorInitEventMsg *msg = evdata;

    VIR_DEBUG("Event init %llu",
              (unsigned long long)msg->initpid);
    if (mon->cb.initNotify)
        mon->cb.initNotify(mon, (pid_t)msg->initpid, mon->vm);
}


static void virLXCMonitorEOFNotify(virNetClientPtr client ATTRIBUTE_UNUSED,
                                   int reason ATTRIBUTE_UNUSED,
                                   void *opaque)
{
    virLXCMonitorPtr mon = opaque;
    virLXCMonitorCallbackEOFNotify eofNotify;
    virDomainObjPtr vm;

    VIR_DEBUG("EOF notify mon=%p", mon);
    virObjectLock(mon);
    eofNotify = mon->cb.eofNotify;
    vm = mon->vm;
    virObjectUnlock(mon);

    if (eofNotify) {
        VIR_DEBUG("EOF callback mon=%p vm=%p", mon, vm);
        eofNotify(mon, vm);
    } else {
        VIR_DEBUG("No EOF callback");
    }
}


static void virLXCMonitorCloseFreeCallback(void *opaque)
{
    virLXCMonitorPtr mon = opaque;
    virObjectUnref(mon);
}


virLXCMonitorPtr virLXCMonitorNew(virDomainObjPtr vm,
                                  const char *socketdir,
                                  virLXCMonitorCallbacksPtr cb)
{
    virLXCMonitorPtr mon;
    char *sockpath = NULL;

    if (virLXCMonitorInitialize() < 0)
        return NULL;

    if (!(mon = virObjectLockableNew(virLXCMonitorClass)))
        return NULL;

    if (virAsprintf(&sockpath, "%s/%s.sock",
                    socketdir, vm->def->name) < 0)
        goto error;

    if (!(mon->client = virNetClientNewUNIX(sockpath, false, NULL)))
        goto error;

    if (virNetClientRegisterAsyncIO(mon->client) < 0)
        goto error;

    if (!(mon->program = virNetClientProgramNew(VIR_LXC_MONITOR_PROGRAM,
                                                VIR_LXC_MONITOR_PROGRAM_VERSION,
                                                virLXCMonitorEvents,
                                                ARRAY_CARDINALITY(virLXCMonitorEvents),
                                                mon)))
        goto error;

    if (virNetClientAddProgram(mon->client,
                               mon->program) < 0)
        goto error;

    mon->vm = vm;
    memcpy(&mon->cb, cb, sizeof(mon->cb));

    virObjectRef(mon);
    virNetClientSetCloseCallback(mon->client, virLXCMonitorEOFNotify, mon,
                                 virLXCMonitorCloseFreeCallback);

 cleanup:
    VIR_FREE(sockpath);
    return mon;

 error:
    virObjectUnref(mon);
    mon = NULL;
    goto cleanup;
}


static void virLXCMonitorDispose(void *opaque)
{
    virLXCMonitorPtr mon = opaque;

    VIR_DEBUG("mon=%p", mon);
    if (mon->cb.destroy)
        (mon->cb.destroy)(mon, mon->vm);
    virObjectUnref(mon->program);
}


void virLXCMonitorClose(virLXCMonitorPtr mon)
{
    virDomainObjPtr vm;
    virNetClientPtr client;

    VIR_DEBUG("mon=%p", mon);
    if (mon->client) {
        /* When manually closing the monitor, we don't
         * want to have callbacks back into us, since
         * the caller is not re-entrant safe
         */
        VIR_DEBUG("Clear EOF callback mon=%p", mon);
        vm = mon->vm;
        client = mon->client;
        mon->client = NULL;
        mon->cb.eofNotify = NULL;

        virObjectRef(vm);
        virObjectUnlock(vm);

        virNetClientClose(client);
        virObjectUnref(client);

        virObjectLock(vm);
        virObjectUnref(vm);
    }
}
