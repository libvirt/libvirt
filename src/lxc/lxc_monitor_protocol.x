/* -*- c -*-
 * Define wire protocol for communication between the
 * LXC driver in libvirtd, and the LXC controller in
 * the libvirt_lxc helper program.
 */

%#include "virxdrdefs.h"

enum virLXCMonitorExitStatus {
    VIR_LXC_MONITOR_EXIT_STATUS_ERROR = 0,
    VIR_LXC_MONITOR_EXIT_STATUS_SHUTDOWN = 1,
    VIR_LXC_MONITOR_EXIT_STATUS_REBOOT = 2
};

struct virLXCMonitorExitEventMsg {
    virLXCMonitorExitStatus status;
};

struct virLXCMonitorInitEventMsg {
    unsigned hyper initpid;
};

const VIR_LXC_MONITOR_PROGRAM = 0x12341234;
const VIR_LXC_MONITOR_PROGRAM_VERSION = 1;

enum virLXCMonitorProcedure {
    VIR_LXC_MONITOR_PROC_EXIT_EVENT = 1, /* skipgen skipgen */
    VIR_LXC_MONITOR_PROC_INIT_EVENT = 2 /* skipgen skipgen */
};
