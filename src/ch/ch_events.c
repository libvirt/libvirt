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

#include <unistd.h>

#include "ch_domain.h"
#include "ch_events.h"
#include "ch_process.h"
#include "virfile.h"
#include "virlog.h"

VIR_LOG_INIT("ch.ch_events");

VIR_ENUM_IMPL(virCHEvent,
              VIR_CH_EVENT_LAST,
              "vmm:starting",
              "vmm:shutdown",
              "vm:booting",
              "vm:booted",
              "vm:rebooting",
              "vm:rebooted",
              "vm:shutdown",
              "vm:deleted",
              "vm:pausing",
              "vm:paused",
              "vm:resuming",
              "vm:resumed",
              "vm:snapshotting",
              "vm:snapshotted",
              "vm:restoring",
              "vm:restored",
);

static int
virCHEventStopProcess(virDomainObj *vm,
                      virDomainShutoffReason reason)
{
    virCHDriver *driver =  ((virCHDomainObjPrivate *)vm->privateData)->driver;

    virObjectLock(vm);
    if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY))
        return -1;
    virCHProcessStop(driver, vm, reason);
    virDomainObjEndJob(vm);
    virObjectUnlock(vm);

    return 0;
}

static int
virCHProcessEvent(virCHMonitor *mon,
                  virJSONValue *eventJSON)
{
    const char *event;
    const char *source;
    virCHEvent ev;
    g_autofree char *timestamp = NULL;
    g_autofree char *full_event = NULL;
    virDomainObj *vm = mon->vm;
    int ret = 0;

    if (virJSONValueObjectHasKey(eventJSON, "source") == 0) {
        VIR_WARN("%s: Invalid JSON from monitor, no source key", vm->def->name);
        return -1;
    }
    if (virJSONValueObjectHasKey(eventJSON, "event") == 0) {
        VIR_WARN("%s: Invalid JSON from monitor, no event key", vm->def->name);
        return -1;
    }
    source = virJSONValueObjectGetString(eventJSON, "source");
    event = virJSONValueObjectGetString(eventJSON, "event");
    full_event = g_strdup_printf("%s:%s", source, event);
    ev = virCHEventTypeFromString(full_event);
    VIR_DEBUG("%s: Source: %s, Event: %s, ev: %d", vm->def->name, source, event, ev);

    switch (ev) {
    case VIR_CH_EVENT_VMM_STARTING:
    case VIR_CH_EVENT_VM_BOOTING:
    case VIR_CH_EVENT_VM_BOOTED:
    case VIR_CH_EVENT_VM_REBOOTING:
    case VIR_CH_EVENT_VM_REBOOTED:
    case VIR_CH_EVENT_VM_PAUSING:
    case VIR_CH_EVENT_VM_PAUSED:
    case VIR_CH_EVENT_VM_RESUMING:
    case VIR_CH_EVENT_VM_RESUMED:
    case VIR_CH_EVENT_VM_SNAPSHOTTING:
    case VIR_CH_EVENT_VM_SNAPSHOTTED:
    case VIR_CH_EVENT_VM_RESTORING:
    case VIR_CH_EVENT_VM_RESTORED:
    case VIR_CH_EVENT_VM_DELETED:
        break;
    case VIR_CH_EVENT_VMM_SHUTDOWN:
        if (virCHEventStopProcess(vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN)) {
            VIR_WARN("Failed to mark the VM(%s) as SHUTDOWN!",
                     vm->def->name);
            ret = -1;
        }
        break;
    case VIR_CH_EVENT_VM_SHUTDOWN:
        virObjectLock(vm);
        virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
        virObjectUnlock(vm);
        break;
    case VIR_CH_EVENT_LAST:
    default:
        VIR_WARN("%s: Unknown event: %s", vm->def->name, full_event);
    }

    return ret;
}

/**
 * virCHProcessEvents:
 * @mon: the CH monitor object
 *
 * Parse the events from the event buffer and process them
 * Example event:
 * {
 *   "timestamp": {
 *     "secs": 0,
 *     "nanos": 29228206
 *    },
 *   "source": "vm",
 *   "event": "booted",
 *   "properties": null
 * }
 *
 * Returns: 0 on success, -1 on failure
 */
static int
virCHProcessEvents(virCHMonitor *mon)
{
    virDomainObj *vm = mon->vm;
    char *buf = mon->event_buffer.buffer;
    ssize_t sz = mon->event_buffer.buf_fill_sz;
    virJSONValue *obj = NULL;
    int blocks = 0;
    size_t i = 0;
    char *json_start;
    ssize_t start_index = -1;
    ssize_t end_index = -1;
    char tmp;

    while (i < sz) {
        if (buf[i] == '{') {
            blocks++;
            if (blocks == 1)
                start_index = i;
        } else if (buf[i] == '}' && blocks > 0) {
            blocks--;
            if (blocks == 0) {
                /* valid json document */
                end_index = i;

                /* temporarily null terminate the JSON doc */
                tmp = buf[end_index + 1];
                buf[end_index + 1] = '\0';
                json_start = buf + start_index;

                if ((obj = virJSONValueFromString(json_start))) {
                    if (virCHProcessEvent(mon, obj) < 0) {
                        VIR_ERROR(_("%1$s: Failed to process JSON event doc: %2$s"),
                                  vm->def->name, json_start);
                        return -1;
                    }
                    virJSONValueFree(obj);
                } else {
                    VIR_ERROR(_("%1$s: Invalid JSON event doc: %2$s"),
                              vm->def->name, json_start);
                    return -1;
                }

                /* replace the original character */
                buf[end_index + 1] = tmp;
                start_index = -1;
            }
        }

        i++;
    }

    if (start_index == -1) {
        /* We have processed all the JSON docs in the buffer */
        mon->event_buffer.buf_fill_sz = 0;
    } else if (start_index > 0) {
        /* We have an incomplete JSON doc at the end of the buffer
         * Move it to the start of the buffer
         */
        mon->event_buffer.buf_fill_sz = sz - start_index;
        memmove(buf, buf+start_index, mon->event_buffer.buf_fill_sz);
    }

    return 0;
}

static int
virCHReadProcessEvents(virCHMonitor *mon)
{
    /* Event json string must always terminate with null char.
     * So, reserve one byte for '\0' at the end.
     */
    size_t max_sz = CH_EVENT_BUFFER_SZ - 1;
    char *buf = mon->event_buffer.buffer;
    virDomainObj *vm = mon->vm;
    bool incomplete = false;
    size_t sz = 0;
    int event_monitor_fd = mon->eventmonitorfd;

    memset(buf, 0, max_sz);
    do {
        ssize_t ret;

        ret = read(event_monitor_fd, buf + sz, max_sz - sz);
        if (ret == 0 || (ret < 0 && errno == EINTR)) {
            g_usleep(G_USEC_PER_SEC);
            continue;
        } else if (ret < 0) {
            /* We should never reach here. read(2) says possible errors
             * are EINTR, EAGAIN, EBADF, EFAULT, EINVAL, EIO, EISDIR
             * We handle EINTR gracefully. There is some serious issue
             * if we encounter any of the other errors(either in our code
             * or in the system).
             */
            VIR_ERROR(_("%1$s: Failed to read ch events!: %2$s"),
                      vm->def->name, g_strerror(errno));
            return -1;
        }

        sz += ret;
        mon->event_buffer.buf_fill_sz = sz;

        if (virCHProcessEvents(mon) < 0) {
            VIR_ERROR(_("%1$s: Failed to parse and process events"),
                      vm->def->name);
            return -1;
        }

        if (mon->event_buffer.buf_fill_sz != 0)
            incomplete = true;
        else
            incomplete = false;
        sz = mon->event_buffer.buf_fill_sz;

    } while (virDomainObjIsActive(vm) && (sz < max_sz) && incomplete);

    return 0;
}

static void
virCHEventHandlerLoop(void *data)
{
    virCHMonitor *mon = data;
    virDomainObj *vm = NULL;

    /* Obtain a vm reference */
    vm = virObjectRef(mon->vm);

    VIR_DEBUG("%s: Event handler loop thread starting", vm->def->name);

    mon->event_buffer.buffer = g_new0(char, CH_EVENT_BUFFER_SZ);
    mon->event_buffer.buf_fill_sz = 0;

    while (g_atomic_int_get(&mon->event_handler_stop) == 0) {
        VIR_DEBUG("%s: Reading events from event monitor file", vm->def->name);
        if (virCHReadProcessEvents(mon) < 0) {
            virCHStopEventHandler(mon);
        }
    }

    g_clear_pointer(&mon->event_buffer.buffer, g_free);
    VIR_DEBUG("%s: Event handler loop thread exiting", vm->def->name);
    virObjectUnref(vm);
    virObjectUnref(mon);
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

    g_atomic_int_set(&mon->event_handler_stop, 0);
    return 0;
}

void
virCHStopEventHandler(virCHMonitor *mon)
{
    g_atomic_int_set(&mon->event_handler_stop, 1);
}
