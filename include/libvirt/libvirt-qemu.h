/* -*- c -*-
 * libvirt-qemu.h:
 * Summary: qemu specific interfaces
 * Description: Provides the interfaces of the libvirt library to handle
 *              qemu specific methods
 *
 * Copy:  Copyright (C) 2010, 2012 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Author: Chris Lalancette <clalance@redhat.com>
 */

#ifndef __VIR_QEMU_H__
# define __VIR_QEMU_H__

# include "libvirt/libvirt.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef enum {
    VIR_DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT = 0,
    VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP     = (1 << 0), /* cmd is in HMP */
} virDomainQemuMonitorCommandFlags;

int virDomainQemuMonitorCommand(virDomainPtr domain, const char *cmd,
                                char **result, unsigned int flags);

virDomainPtr virDomainQemuAttach(virConnectPtr domain,
                                 unsigned int pid_value,
                                 unsigned int flags);

# ifdef __cplusplus
}
# endif

#endif /* __VIR_QEMU_H__ */
