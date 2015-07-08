/* -*- c -*-
 * Define wire protocol for communication between the
 * LXC driver in libvirtd, and the LXC controller in
 * the libvirt_lxc helper program.
 */

/* cygwin's xdr implementation defines xdr_u_int64_t instead of xdr_uint64_t
 * and lacks IXDR_PUT_INT32 and IXDR_GET_INT32
 */
%#ifdef HAVE_XDR_U_INT64_T
%# define xdr_uint64_t xdr_u_int64_t
%#endif
%#ifndef IXDR_PUT_INT32
%# define IXDR_PUT_INT32 IXDR_PUT_LONG
%#endif
%#ifndef IXDR_GET_INT32
%# define IXDR_GET_INT32 IXDR_GET_LONG
%#endif
%#ifndef IXDR_PUT_U_INT32
%# define IXDR_PUT_U_INT32 IXDR_PUT_U_LONG
%#endif
%#ifndef IXDR_GET_U_INT32
%# define IXDR_GET_U_INT32 IXDR_GET_U_LONG
%#endif

enum virLXCMonitorExitStatus {
    VIR_LXC_MONITOR_EXIT_STATUS_ERROR,
    VIR_LXC_MONITOR_EXIT_STATUS_SHUTDOWN,
    VIR_LXC_MONITOR_EXIT_STATUS_REBOOT
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
