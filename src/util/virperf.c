/*
 * virperf.c: methods for managing perf events
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
 * Authors:
 *  Ren Qiaowei <qiaowei.ren@intel.com>
 */
#include <config.h>

#include <sys/ioctl.h>
#if defined HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif

#include "virperf.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virfile.h"
#include "virstring.h"
#include "virtypedparam.h"

VIR_LOG_INIT("util.perf");

#define VIR_FROM_THIS VIR_FROM_PERF

VIR_ENUM_IMPL(virPerfEvent, VIR_PERF_EVENT_LAST,
              "cmt");

struct virPerfEvent {
    int type;
    int fd;
    bool enabled;
    union {
        /* cmt */
        struct {
            int scale;
        } cmt;
    } efields;
};
typedef struct virPerfEvent *virPerfEventPtr;

struct virPerf {
    struct virPerfEvent events[VIR_PERF_EVENT_LAST];
};

virPerfPtr
virPerfNew(void)
{
    size_t i;
    virPerfPtr perf;

    if (VIR_ALLOC(perf) < 0)
        return NULL;

    for (i = 0; i < VIR_PERF_EVENT_LAST; i++) {
        perf->events[i].type = i;
        perf->events[i].fd = -1;
        perf->events[i].enabled = false;
    }

    return perf;
}

void
virPerfFree(virPerfPtr perf)
{
    size_t i;

    if (perf == NULL)
        return;

    for (i = 0; i < VIR_PERF_EVENT_LAST; i++) {
        if (perf->events[i].enabled)
            virPerfEventDisable(perf, i);
    }

    VIR_FREE(perf);
}

#if defined(__linux__) && defined(HAVE_SYS_SYSCALL_H)

# include <linux/perf_event.h>

static virPerfEventPtr
virPerfGetEvent(virPerfPtr perf,
                virPerfEventType type)
{
    if (type >= VIR_PERF_EVENT_LAST) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Event '%d' is not supported"),
                       type);
        return NULL;
    }

    return perf->events + type;
}

static int
virPerfCmtEnable(virPerfEventPtr event,
                 pid_t pid)
{
    struct perf_event_attr cmt_attr;
    char *buf = NULL;
    char *tmp = NULL;
    unsigned int event_type, scale;

    if (virFileReadAll("/sys/devices/intel_cqm/type",
                       10, &buf) < 0)
        goto cleanup;

    if ((tmp = strchr(buf, '\n')))
        *tmp = '\0';

    if (virStrToLong_ui(buf, NULL, 10, &event_type) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to get cmt event type"));
        goto cleanup;
    }
    VIR_FREE(buf);

    if (virFileReadAll("/sys/devices/intel_cqm/events/llc_occupancy.scale",
                       10, &buf) < 0)
        goto cleanup;

    if (virStrToLong_ui(buf, NULL, 10, &scale) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to get cmt scaling factor"));
        goto cleanup;
    }

    event->efields.cmt.scale = scale;

    memset(&cmt_attr, 0, sizeof(cmt_attr));
    cmt_attr.size = sizeof(cmt_attr);
    cmt_attr.type = event_type;
    cmt_attr.config = 1;
    cmt_attr.inherit = 1;
    cmt_attr.disabled = 1;
    cmt_attr.enable_on_exec = 0;

    event->fd = syscall(__NR_perf_event_open, &cmt_attr, pid, -1, -1, 0);
    if (event->fd < 0) {
        virReportSystemError(errno,
                             _("Unable to open perf type=%d for pid=%d"),
                             event_type, pid);
        goto cleanup;
    }

    if (ioctl(event->fd, PERF_EVENT_IOC_ENABLE) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to enable perf event for CMT"));
        goto cleanup;
    }

    event->enabled = true;
    return 0;

 cleanup:
    VIR_FORCE_CLOSE(event->fd);
    VIR_FREE(buf);
    return -1;
}

int
virPerfEventEnable(virPerfPtr perf,
                   virPerfEventType type,
                   pid_t pid)
{
    virPerfEventPtr event = virPerfGetEvent(perf, type);
    if (event == NULL)
        return -1;

    switch (type) {
    case VIR_PERF_EVENT_CMT:
        if (virPerfCmtEnable(event, pid))
            return -1;
        break;
    case VIR_PERF_EVENT_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected perf event type=%d"), type);
        return -1;
    }

    return 0;
}

int
virPerfEventDisable(virPerfPtr perf,
                    virPerfEventType type)
{
    virPerfEventPtr event = virPerfGetEvent(perf, type);
    if (event == NULL)
        return -1;

    if (ioctl(event->fd, PERF_EVENT_IOC_DISABLE) < 0) {
        virReportSystemError(errno,
                             _("Unable to disable perf event type=%d"),
                             event->type);
        return -1;
    }

    event->enabled = false;
    VIR_FORCE_CLOSE(event->fd);
    return 0;
}

bool virPerfEventIsEnabled(virPerfPtr perf,
                           virPerfEventType type)
{
    virPerfEventPtr event = virPerfGetEvent(perf, type);
    if (event == NULL)
        return false;

    return event->enabled;
}

int virPerfGetEventFd(virPerfPtr perf,
                      virPerfEventType type)
{
    virPerfEventPtr event = virPerfGetEvent(perf, type);
    if (event == NULL)
        return false;

    return event->fd;
}

int
virPerfReadEvent(virPerfPtr perf,
                 virPerfEventType type,
                 uint64_t *value)
{
    virPerfEventPtr event = virPerfGetEvent(perf, type);
    if (event == NULL || !event->enabled)
        return -1;

    if (read(event->fd, value, sizeof(uint64_t)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to read cache data"));
        return -1;
    }

    if (type == VIR_PERF_EVENT_CMT)
        *value *= event->efields.cmt.scale;

    return 0;
}

#else
int
virPerfEventEnable(virPerfPtr perf ATTRIBUTE_UNUSED,
                   virPerfEventType type ATTRIBUTE_UNUSED,
                   pid_t pid ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Perf not supported on this platform"));
    return -1;
}

int
virPerfEventDisable(virPerfPtr perf ATTRIBUTE_UNUSED,
                    virPerfEventType type ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Perf not supported on this platform"));
    return -1;
}

bool
virPerfEventIsEnabled(virPerfPtr perf ATTRIBUTE_UNUSED,
                      virPerfEventType type ATTRIBUTE_UNUSED)
{
    return false;
}

int
virPerfGetEventFd(virPerfPtr perf ATTRIBUTE_UNUSED,
                  virPerfEventType type ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Perf not supported on this platform"));
    return -1;
}

int
virPerfReadEvent(virPerfPtr perf ATTRIBUTE_UNUSED,
                 virPerfEventType type ATTRIBUTE_UNUSED,
                 uint64_t *value ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Perf not supported on this platform"));
    return -1;
}

#endif
