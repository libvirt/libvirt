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
 */
#include <config.h>

#include <unistd.h>
#ifndef WIN32
# include <sys/ioctl.h>
#endif
#if defined WITH_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif

#include "virperf.h"
#include "virerror.h"
#include "virlog.h"
#include "virfile.h"
#include "virstring.h"

VIR_LOG_INIT("util.perf");

#define VIR_FROM_THIS VIR_FROM_PERF

VIR_ENUM_IMPL(virPerfEvent,
              VIR_PERF_EVENT_LAST,
              "cmt", "mbmt", "mbml",
              "cpu_cycles", "instructions",
              "cache_references", "cache_misses",
              "branch_instructions", "branch_misses",
              "bus_cycles", "stalled_cycles_frontend",
              "stalled_cycles_backend", "ref_cpu_cycles",
              "cpu_clock", "task_clock", "page_faults",
              "context_switches", "cpu_migrations",
              "page_faults_min", "page_faults_maj",
              "alignment_faults", "emulation_faults",
);

struct virPerfEvent {
    int fd;
    bool enabled;
    union {
        /* cmt */
        struct {
            int scale;
        } cmt;
    } efields;
};

struct _virPerf {
    struct virPerfEvent events[VIR_PERF_EVENT_LAST];
};

#if defined(__linux__) && defined(WITH_SYS_SYSCALL_H)

# include <linux/perf_event.h>

struct virPerfEventAttr {
    unsigned int attrType;
    unsigned long long attrConfig;
};

static struct virPerfEventAttr attrs[] = {
    [VIR_PERF_EVENT_CMT] = {
        .attrType = 0,
        .attrConfig = 1
    },
    [VIR_PERF_EVENT_MBMT] = {
        .attrType = 0,
        .attrConfig = 2
    },
    [VIR_PERF_EVENT_MBML] = {
        .attrType = 0,
        .attrConfig = 3
    },
    [VIR_PERF_EVENT_CPU_CYCLES] = {
        .attrType = PERF_TYPE_HARDWARE,
        .attrConfig = PERF_COUNT_HW_CPU_CYCLES
    },
    [VIR_PERF_EVENT_INSTRUCTIONS] = {
        .attrType = PERF_TYPE_HARDWARE,
        .attrConfig = PERF_COUNT_HW_INSTRUCTIONS
    },
    [VIR_PERF_EVENT_CACHE_REFERENCES] = {
        .attrType = PERF_TYPE_HARDWARE,
        .attrConfig = PERF_COUNT_HW_CACHE_REFERENCES
    },
    [VIR_PERF_EVENT_CACHE_MISSES] = {
        .attrType = PERF_TYPE_HARDWARE,
        .attrConfig = PERF_COUNT_HW_CACHE_MISSES
    },
    [VIR_PERF_EVENT_BRANCH_INSTRUCTIONS] = {
        .attrType = PERF_TYPE_HARDWARE,
        .attrConfig = PERF_COUNT_HW_BRANCH_INSTRUCTIONS
    },
    [VIR_PERF_EVENT_BRANCH_MISSES] = {
        .attrType = PERF_TYPE_HARDWARE,
        .attrConfig = PERF_COUNT_HW_BRANCH_MISSES
    },
    [VIR_PERF_EVENT_BUS_CYCLES] = {
        .attrType = PERF_TYPE_HARDWARE,
        .attrConfig = PERF_COUNT_HW_BUS_CYCLES
    },
    [VIR_PERF_EVENT_STALLED_CYCLES_FRONTEND] = {
        .attrType = PERF_TYPE_HARDWARE,
        .attrConfig = PERF_COUNT_HW_STALLED_CYCLES_FRONTEND
    },
    [VIR_PERF_EVENT_STALLED_CYCLES_BACKEND] = {
        .attrType = PERF_TYPE_HARDWARE,
        .attrConfig = PERF_COUNT_HW_STALLED_CYCLES_BACKEND
    },
    [VIR_PERF_EVENT_REF_CPU_CYCLES] = {
# ifdef PERF_COUNT_HW_REF_CPU_CYCLES
        .attrType = PERF_TYPE_HARDWARE,
        .attrConfig = PERF_COUNT_HW_REF_CPU_CYCLES
# else
        .attrType = 0,
        .attrConfig = 0,
# endif
    },
    [VIR_PERF_EVENT_CPU_CLOCK] = {
        .attrType = PERF_TYPE_SOFTWARE,
        .attrConfig = PERF_COUNT_SW_CPU_CLOCK
    },
    [VIR_PERF_EVENT_TASK_CLOCK] = {
        .attrType = PERF_TYPE_SOFTWARE,
        .attrConfig = PERF_COUNT_SW_TASK_CLOCK
    },
    [VIR_PERF_EVENT_PAGE_FAULTS] = {
        .attrType = PERF_TYPE_SOFTWARE,
        .attrConfig = PERF_COUNT_SW_PAGE_FAULTS
    },
    [VIR_PERF_EVENT_CONTEXT_SWITCHES] = {
        .attrType = PERF_TYPE_SOFTWARE,
        .attrConfig = PERF_COUNT_SW_CONTEXT_SWITCHES
    },
    [VIR_PERF_EVENT_CPU_MIGRATIONS] = {
        .attrType = PERF_TYPE_SOFTWARE,
        .attrConfig = PERF_COUNT_SW_CPU_MIGRATIONS
    },
    [VIR_PERF_EVENT_PAGE_FAULTS_MIN] = {
        .attrType = PERF_TYPE_SOFTWARE,
        .attrConfig = PERF_COUNT_SW_PAGE_FAULTS_MIN
    },
    [VIR_PERF_EVENT_PAGE_FAULTS_MAJ] = {
        .attrType = PERF_TYPE_SOFTWARE,
        .attrConfig = PERF_COUNT_SW_PAGE_FAULTS_MAJ
    },
    [VIR_PERF_EVENT_ALIGNMENT_FAULTS] = {
        .attrType = PERF_TYPE_SOFTWARE,
        .attrConfig = PERF_COUNT_SW_ALIGNMENT_FAULTS
    },
    [VIR_PERF_EVENT_EMULATION_FAULTS] = {
        .attrType = PERF_TYPE_SOFTWARE,
        .attrConfig = PERF_COUNT_SW_EMULATION_FAULTS
    },
};
G_STATIC_ASSERT(G_N_ELEMENTS(attrs) == VIR_PERF_EVENT_LAST);


static int
virPerfRdtAttrInit(void)
{
    char *tmp = NULL;
    unsigned int attr_type = 0;
    g_autofree char *buf = NULL;

    if (virFileReadAllQuiet("/sys/devices/intel_cqm/type", 10, &buf) < 0)
        return -1;

    if ((tmp = strchr(buf, '\n')))
        *tmp = '\0';

    if (virStrToLong_ui(buf, NULL, 10, &attr_type) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to get rdt event type"));
        return -1;
    }

    attrs[VIR_PERF_EVENT_CMT].attrType = attr_type;
    attrs[VIR_PERF_EVENT_MBMT].attrType = attr_type;
    attrs[VIR_PERF_EVENT_MBML].attrType = attr_type;

    return 0;
}


int
virPerfEventEnable(virPerf *perf,
                   virPerfEventType type,
                   pid_t pid)
{
    struct perf_event_attr attr = { 0 };
    struct virPerfEvent *event = &(perf->events[type]);
    struct virPerfEventAttr *event_attr = &attrs[type];

    if (event->enabled)
        return 0;

    if (event_attr->attrType == 0 && (type == VIR_PERF_EVENT_CMT ||
                                      type == VIR_PERF_EVENT_MBMT ||
                                      type == VIR_PERF_EVENT_MBML)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                       _("unable to enable host cpu perf event for %1$s"),
                       virPerfEventTypeToString(type));
        return -1;
    }

    if (type == VIR_PERF_EVENT_CMT) {
        g_autofree char *buf = NULL;

        if (virFileReadAll("/sys/devices/intel_cqm/events/llc_occupancy.scale",
                           10, &buf) < 0)
            goto error;

        if (virStrToLong_i(buf, NULL, 10, &event->efields.cmt.scale) < 0) {
            virReportSystemError(errno, "%s",
                                 _("failed to get cmt scaling factor"));
            goto error;
        }
    }

    attr.size = sizeof(attr);
    attr.inherit = 1;
    attr.disabled = 1;
    attr.enable_on_exec = 0;
    attr.type = event_attr->attrType;
    attr.config = event_attr->attrConfig;

    event->fd = syscall(__NR_perf_event_open, &attr, pid, -1, -1, 0);
    if (event->fd < 0) {
        virReportSystemError(errno,
                             _("unable to open host cpu perf event for %1$s"),
                             virPerfEventTypeToString(type));
        goto error;
    }

    if (ioctl(event->fd, PERF_EVENT_IOC_ENABLE) < 0) {
        virReportSystemError(errno,
                             _("unable to enable host cpu perf event for %1$s"),
                             virPerfEventTypeToString(type));
        goto error;
    }

    event->enabled = true;
    return 0;

 error:
    VIR_FORCE_CLOSE(event->fd);
    return -1;
}

int
virPerfEventDisable(virPerf *perf,
                    virPerfEventType type)
{
    struct virPerfEvent *event = &(perf->events[type]);

    if (!event->enabled)
        return 0;

    if (ioctl(event->fd, PERF_EVENT_IOC_DISABLE) < 0) {
        virReportSystemError(errno,
                             _("unable to disable host cpu perf event for %1$s"),
                             virPerfEventTypeToString(type));
        return -1;
    }

    event->enabled = false;
    VIR_FORCE_CLOSE(event->fd);
    return 0;
}

bool virPerfEventIsEnabled(virPerf *perf,
                           virPerfEventType type)
{
    return perf && perf->events[type].enabled;
}

int
virPerfReadEvent(virPerf *perf,
                 virPerfEventType type,
                 uint64_t *value)
{
    struct virPerfEvent *event = &perf->events[type];
    if (!event->enabled)
        return -1;

    if (saferead(event->fd, value, sizeof(uint64_t)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to read cache data"));
        return -1;
    }

    if (type == VIR_PERF_EVENT_CMT)
        *value *= event->efields.cmt.scale;

    return 0;
}

#else
static int
virPerfRdtAttrInit(void)
{
    return 0;
}


int
virPerfEventEnable(virPerf *perf G_GNUC_UNUSED,
                   virPerfEventType type G_GNUC_UNUSED,
                   pid_t pid G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Perf not supported on this platform"));
    return -1;
}

int
virPerfEventDisable(virPerf *perf G_GNUC_UNUSED,
                    virPerfEventType type G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Perf not supported on this platform"));
    return -1;
}

bool
virPerfEventIsEnabled(virPerf *perf G_GNUC_UNUSED,
                      virPerfEventType type G_GNUC_UNUSED)
{
    return false;
}

int
virPerfReadEvent(virPerf *perf G_GNUC_UNUSED,
                 virPerfEventType type G_GNUC_UNUSED,
                 uint64_t *value G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Perf not supported on this platform"));
    return -1;
}

#endif

virPerf *
virPerfNew(void)
{
    size_t i;
    virPerf *perf;

    perf = g_new0(virPerf, 1);

    for (i = 0; i < VIR_PERF_EVENT_LAST; i++) {
        perf->events[i].fd = -1;
        perf->events[i].enabled = false;
    }

    if (virPerfRdtAttrInit() < 0)
        virResetLastError();

    return perf;
}

void
virPerfFree(virPerf *perf)
{
    size_t i;

    if (perf == NULL)
        return;

    for (i = 0; i < VIR_PERF_EVENT_LAST; i++) {
        if (perf->events[i].enabled)
            virPerfEventDisable(perf, i);
    }

    g_free(perf);
}
