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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "lxc_monitor.h"
#include "lxc_conf.h"
#include "lxc_protocol.h"
#include "lxc_monitor_dispatch.h"

#include "memory.h"

#include "virterror_internal.h"
#include "logging.h"
#include "threads.h"
#include "rpc/virnetclient.h"

#define VIR_FROM_THIS VIR_FROM_LXC

struct _virLXCMonitor {
    int refs;

    virMutex lock; /* also used to protect refs */

    virDomainObjPtr vm;
    virLXCMonitorCallbacksPtr cb;

    virNetClientPtr client;
    virNetClientProgramPtr program;
};

static void virLXCMonitorFree(virLXCMonitorPtr mon);
static void
virLXCMonitorHandleEventExit(virNetClientProgramPtr prog,
                             virNetClientPtr client,
                             void *evdata, void *opaque);

static virNetClientProgramEvent virLXCProtocolEvents[] = {
    { VIR_LXC_PROTOCOL_PROC_EXIT_EVENT,
      virLXCMonitorHandleEventExit,
      sizeof(virLXCProtocolExitEventMsg),
      (xdrproc_t)xdr_virLXCProtocolExitEventMsg },
};


static void
virLXCMonitorHandleEventExit(virNetClientProgramPtr prog ATTRIBUTE_UNUSED,
                             virNetClientPtr client ATTRIBUTE_UNUSED,
                             void *evdata, void *opaque)
{
    virLXCMonitorPtr mon = opaque;
    virLXCProtocolExitEventMsg *msg = evdata;

    VIR_DEBUG("Event exit %d", msg->status);
    if (mon->cb->exitNotify)
        mon->cb->exitNotify(mon, msg->status, mon->vm);
}


static void virLXCMonitorEOFNotify(virNetClientPtr client ATTRIBUTE_UNUSED,
                                   int reason ATTRIBUTE_UNUSED,
                                   void *opaque)
{
    virLXCMonitorPtr mon = opaque;
    virLXCMonitorCallbackEOFNotify eofNotify;
    virDomainObjPtr vm;

    VIR_DEBUG("EOF notify");
    virLXCMonitorLock(mon);
    eofNotify = mon->cb->eofNotify;
    vm = mon->vm;
    virLXCMonitorUnlock(mon);

    eofNotify(mon, vm);
}


static void virLXCMonitorCloseFreeCallback(void *opaque)
{
    virLXCMonitorPtr mon = opaque;
    virLXCMonitorLock(mon);
    if (virLXCMonitorUnref(mon) > 0)
        virLXCMonitorUnlock(mon);
}


virLXCMonitorPtr virLXCMonitorNew(virDomainObjPtr vm,
                                  const char *socketdir,
                                  virLXCMonitorCallbacksPtr cb)
{
    virLXCMonitorPtr mon;
    char *sockpath = NULL;

    if (VIR_ALLOC(mon) < 0) {
        virReportOOMError();
        return NULL;
    }

    mon->refs = 1;

    if (virMutexInit(&mon->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize monitor mutex"));
        VIR_FREE(mon);
        return NULL;
    }

    if (virAsprintf(&sockpath, "%s/%s.sock",
                    socketdir, vm->def->name) < 0)
        goto no_memory;

    if (!(mon->client = virNetClientNewUNIX(sockpath, false, NULL)))
        goto error;


    if (!(mon->program = virNetClientProgramNew(VIR_LXC_PROTOCOL_PROGRAM,
                                                VIR_LXC_PROTOCOL_PROGRAM_VERSION,
                                                virLXCProtocolEvents,
                                                ARRAY_CARDINALITY(virLXCProtocolEvents),
                                                mon)))
        goto error;

    if (virNetClientAddProgram(mon->client,
                               mon->program) < 0)
        goto error;

    mon->vm = vm;
    mon->cb = cb;

    virLXCMonitorRef(mon);
    virNetClientSetCloseCallback(mon->client, virLXCMonitorEOFNotify, mon,
                                 virLXCMonitorCloseFreeCallback);

cleanup:
    VIR_FREE(sockpath);
    return mon;

no_memory:
    virReportOOMError();
error:
    virLXCMonitorFree(mon);
    mon = NULL;
    goto cleanup;
}


static void virLXCMonitorFree(virLXCMonitorPtr mon)
{
    VIR_DEBUG("mon=%p", mon);
    if (mon->client)
        virLXCMonitorClose(mon);

    if (mon->cb && mon->cb->destroy)
        (mon->cb->destroy)(mon, mon->vm);
    virMutexDestroy(&mon->lock);
    virNetClientProgramFree(mon->program);
    VIR_FREE(mon);
}


int virLXCMonitorRef(virLXCMonitorPtr mon)
{
    mon->refs++;
    return mon->refs;
}

int virLXCMonitorUnref(virLXCMonitorPtr mon)
{
    mon->refs--;

    if (mon->refs == 0) {
        virLXCMonitorUnlock(mon);
        virLXCMonitorFree(mon);
        return 0;
    }

    return mon->refs;
}


void virLXCMonitorClose(virLXCMonitorPtr mon)
{
    if (mon->client) {
        virNetClientClose(mon->client);
        virNetClientFree(mon->client);
        mon->client = NULL;
    }
}


void virLXCMonitorLock(virLXCMonitorPtr mon)
{
    virMutexLock(&mon->lock);
}


void virLXCMonitorUnlock(virLXCMonitorPtr mon)
{
    virMutexUnlock(&mon->lock);
}
