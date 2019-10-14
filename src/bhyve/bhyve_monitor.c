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

#define VIR_FROM_THIS   VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_monitor");

struct _bhyveMonitor {
    int kq;
    int watch;
    bhyveConnPtr driver;
};

static void
bhyveMonitorIO(int watch, int kq, int events G_GNUC_UNUSED, void *opaque)
{
    const struct timespec zerowait = { 0, 0 };
    virDomainObjPtr vm = opaque;
    bhyveDomainObjPrivatePtr priv = vm->privateData;
    bhyveMonitorPtr mon = priv->mon;
    struct kevent kev;
    int rc, status;

    if (watch != mon->watch || kq != mon->kq) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("event from unexpected fd %d!=%d / watch %d!=%d"),
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
                        _("event from unexpected proc %ju!=%ju"),
                        (uintmax_t)vm->pid, (uintmax_t)kev.ident);
            return;
        }

        status = kev.data;
        if (WIFSIGNALED(status) && WCOREDUMP(status)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Guest %s got signal %d and crashed"),
                           vm->def->name,
                           WTERMSIG(status));
            virBhyveProcessStop(mon->driver, vm,
                                VIR_DOMAIN_SHUTOFF_CRASHED);
        } else if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 0) {
                /* 0 - reboot */
                /* TODO: Implementing reboot is a little more complicated. */
                VIR_INFO("Guest %s rebooted; destroying domain.",
                         vm->def->name);
                virBhyveProcessStop(mon->driver, vm,
                                    VIR_DOMAIN_SHUTOFF_SHUTDOWN);
            } else if (WEXITSTATUS(status) < 3) {
                /* 1 - shutdown, 2 - halt, 3 - triple fault. others - error */
                VIR_INFO("Guest %s shut itself down; destroying domain.",
                         vm->def->name);
                virBhyveProcessStop(mon->driver, vm,
                                    VIR_DOMAIN_SHUTOFF_SHUTDOWN);
            } else {
                VIR_INFO("Guest %s had an error and exited with status %d; destroying domain.",
                         vm->def->name, WEXITSTATUS(status));
                virBhyveProcessStop(mon->driver, vm,
                                    VIR_DOMAIN_SHUTOFF_UNKNOWN);
            }
        }
    }
}

static void
bhyveMonitorRelease(void *opaque)
{
    virDomainObjPtr vm = opaque;
    bhyveDomainObjPrivatePtr priv = vm->privateData;
    bhyveMonitorPtr mon = priv->mon;

    VIR_FORCE_CLOSE(mon->kq);
    VIR_FREE(mon);
}

bhyveMonitorPtr
bhyveMonitorOpen(virDomainObjPtr vm, bhyveConnPtr driver)
{
    bhyveMonitorPtr mon = NULL;
    struct kevent kev;
    int rc;

    if (VIR_ALLOC(mon) < 0)
        return NULL;

    mon->driver = driver;

    mon->kq = kqueue();
    if (mon->kq < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("Unable to create kqueue"));
        goto cleanup;
    }

    EV_SET(&kev, vm->pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, mon);
    rc = kevent(mon->kq, &kev, 1, NULL, 0, NULL);
    if (rc < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("Unable to register process kevent"));
        goto cleanup;
    }

    mon->watch = virEventAddHandle(mon->kq,
                                   VIR_EVENT_HANDLE_READABLE |
                                   VIR_EVENT_HANDLE_ERROR |
                                   VIR_EVENT_HANDLE_HANGUP,
                                   bhyveMonitorIO,
                                   vm,
                                   bhyveMonitorRelease);
    if (mon->watch < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to register monitor events"));
        goto cleanup;
    }

    return mon;

 cleanup:
    bhyveMonitorRelease(mon);
    return NULL;
}

void
bhyveMonitorClose(bhyveMonitorPtr mon)
{
    if (mon == NULL)
        return;

    if (mon->watch > 0)
        virEventRemoveHandle(mon->watch);
    else
        bhyveMonitorRelease(mon);
}
