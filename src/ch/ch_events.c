/*
 * Copyright Microsoft Corp. 2024
 *
 * ch_events.c: Handle Cloud-Hypervisor events
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

#include "ch_domain.h"
#include "ch_events.h"
#include "ch_process.h"
#include "virfile.h"
#include "virlog.h"

VIR_LOG_INIT("ch.ch_events");


static void
virCHEventHandlerLoop(void *data)
{
    virCHMonitor *mon = data;
    virDomainObj *vm = NULL;

    /* Obtain a vm reference */
    vm = virObjectRef(mon->vm);

    VIR_DEBUG("%s: Event handler loop thread starting", vm->def->name);

    while (g_atomic_int_get(&mon->event_handler_stop) == 0) {
        VIR_DEBUG("%s: Reading events from event monitor file", vm->def->name);
        /* Read and process events here */
    }

    virObjectUnref(vm);
    VIR_DEBUG("%s: Event handler loop thread exiting", vm->def->name);
    return;
}

int
virCHStartEventHandler(virCHMonitor *mon)
{
    g_autofree char *name = NULL;
    name = g_strdup_printf("ch-evt-%d", mon->pid);

    virObjectRef(mon);
    if (virThreadCreateFull(&mon->event_handler_thread,
                            false,
                            virCHEventHandlerLoop,
                            name,
                            false,
                            mon) < 0) {
        virObjectUnref(mon);
        return -1;
    }
    virObjectUnref(mon);

    g_atomic_int_set(&mon->event_handler_stop, 0);
    return 0;
}

void
virCHStopEventHandler(virCHMonitor *mon)
{
    g_atomic_int_set(&mon->event_handler_stop, 1);
}
