/*
 * bhyve_monitor.c: Tear-down or reboot bhyve domains on guest shutdown
 *
 * Copyright (C) 2014 Conrad Meyer
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

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/wait.h>

#include "bhyve_domain.h"
#include "bhyve_monitor.h"
#include "bhyve_process.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virobject.h"

#define VIR_FROM_THIS   VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_monitor");

struct _bhyveMonitor {
    virObject parent;

    struct _bhyveConn *driver;
    virDomainObj *vm;
    int kq;
    int watch;
    bool reboot;
};

static virClass *bhyveMonitorClass;

static void
bhyveMonitorDispose(void *obj)
{
    bhyveMonitor *mon = obj;

    VIR_FORCE_CLOSE(mon->kq);
    virObjectUnref(mon->vm);
}

static int
bhyveMonitorOnceInit(void)
{
    if (!VIR_CLASS_NEW(bhyveMonitor, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(bhyveMonitor);

static void bhyveMonitorIO(int, int, int, void *);

static bool
bhyveMonitorRegister(bhyveMonitor *mon)
{
    virObjectRef(mon);
    mon->watch = virEventAddHandle(mon->kq,
                                   VIR_EVENT_HANDLE_READABLE |
                                   VIR_EVENT_HANDLE_ERROR |
                                   VIR_EVENT_HANDLE_HANGUP,
                                   bhyveMonitorIO,
                                   mon,
                                   virObjectUnref);
    if (mon->watch < 0) {
        VIR_DEBUG("failed to add event handle for mon %p", mon);
        virObjectUnref(mon);
        return false;
    }
    return true;
}

static void
bhyveMonitorUnregister(bhyveMonitor *mon)
{
    if (mon->watch < 0)
        return;

    virEventRemoveHandle(mon->watch);
    mon->watch = -1;
}

void
bhyveMonitorSetReboot(bhyveMonitor *mon)
{
    mon->reboot = true;
}

static void
bhyveMonitorIO(int watch, int kq, int events G_GNUC_UNUSED, void *opaque)
{
    const struct timespec zerowait = { 0, 0 };
    bhyveMonitor *mon = opaque;
    virDomainObj *vm = mon->vm;
    struct _bhyveConn *driver = mon->driver;
    const char *name;
    struct kevent kev;
    int rc, status;

    if (watch != mon->watch || kq != mon->kq) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("event from unexpected fd %1$d!=%2$d / watch %3$d!=%4$d"),
                       mon->kq, kq, mon->watch, watch);
        return;
    }

    rc = kevent(kq, NULL, 0, &kev, 1, &zerowait);
    if (rc < 0) {
        virReportSystemError(errno, "%s", _("Unable to query kqueue"));
        return;
    }

    if (rc == 0)
        return;

    if ((kev.flags & EV_ERROR) != 0) {
        virReportSystemError(kev.data, "%s", _("Unable to query kqueue"));
        return;
    }

    if (kev.filter == EVFILT_PROC && (kev.fflags & NOTE_EXIT) != 0) {
        if ((pid_t)kev.ident != vm->pid) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("event from unexpected proc %1$ju!=%2$ju"),
                           (uintmax_t)vm->pid, (uintmax_t)kev.ident);
            return;
        }

        name = vm->def->name;
        status = kev.data;
        if (WIFSIGNALED(status) && WCOREDUMP(status)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Guest %1$s got signal %2$d and crashed"),
                           name, WTERMSIG(status));
            virBhyveProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_CRASHED);
        } else if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 0 || mon->reboot) {
                /* 0 - reboot */
                VIR_INFO("Guest %s rebooted; restarting domain.", name);
                virBhyveProcessRestart(driver, vm);
            } else if (WEXITSTATUS(status) < 3) {
                /* 1 - shutdown, 2 - halt, 3 - triple fault. others - error */
                VIR_INFO("Guest %s shut itself down; destroying domain.", name);
                virBhyveProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
            } else {
                VIR_INFO("Guest %s had an error and exited with status %d; destroying domain.",
                         name, WEXITSTATUS(status));
                virBhyveProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_UNKNOWN);
            }
        }
    }
}

static bhyveMonitor *
bhyveMonitorOpenImpl(virDomainObj *vm, struct _bhyveConn *driver)
{
    bhyveMonitor *mon;
    struct kevent kev;

    if (bhyveMonitorInitialize() < 0)
        return NULL;

    if (!(mon = virObjectNew(bhyveMonitorClass)))
        return NULL;

    mon->driver = driver;
    mon->reboot = false;

    virObjectRef(vm);
    mon->vm = vm;

    mon->kq = kqueue();
    if (mon->kq < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("Unable to create kqueue"));
        goto cleanup;
    }

    EV_SET(&kev, vm->pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, mon);
    if (kevent(mon->kq, &kev, 1, NULL, 0, NULL) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("Unable to register process kevent"));
        goto cleanup;
    }

    if (!bhyveMonitorRegister(mon)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to register monitor events"));
        goto cleanup;
    }

    return mon;

 cleanup:
    bhyveMonitorClose(mon);
    return NULL;
}

bhyveMonitor *
bhyveMonitorOpen(virDomainObj *vm, struct _bhyveConn *driver)
{
    bhyveMonitor *mon;

    virObjectRef(vm);
    mon = bhyveMonitorOpenImpl(vm, driver);
    virObjectUnref(vm);

    return mon;
}

void
bhyveMonitorClose(bhyveMonitor *mon)
{
    if (mon == NULL)
        return;

    VIR_DEBUG("cleaning up bhyveMonitor %p", mon);

    bhyveMonitorUnregister(mon);
    virObjectUnref(mon);
}
