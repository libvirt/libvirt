/* -*- c -*-
 * Define wire protocol for communication between the
 * LXC driver in libvirtd, and the LXC controller in
 * the libvirt_lxc helper program.
 */

enum virLXCProtocolExitStatus {
    VIR_LXC_PROTOCOL_EXIT_STATUS_ERROR,
    VIR_LXC_PROTOCOL_EXIT_STATUS_SHUTDOWN,
    VIR_LXC_PROTOCOL_EXIT_STATUS_REBOOT
};

struct virLXCProtocolExitEventMsg {
    enum virLXCProtocolExitStatus status;
};

const VIR_LXC_PROTOCOL_PROGRAM = 0x12341234;
const VIR_LXC_PROTOCOL_PROGRAM_VERSION = 1;

enum virLXCProtocolProcedure {
    VIR_LXC_PROTOCOL_PROC_EXIT_EVENT = 1 /* skipgen skipgen */
};
