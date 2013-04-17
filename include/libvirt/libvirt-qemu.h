/* -*- c -*-
 * libvirt-qemu.h: Interfaces specific for QEMU/KVM driver
 * Summary: qemu specific interfaces
 * Description: Provides the interfaces of the libvirt library to handle
 *              qemu specific methods
 *
 * Copyright (C) 2010, 2012 Red Hat, Inc.
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
 * Author: Chris Lalancette <clalance@redhat.com>
 */

#ifndef __VIR_QEMU_H__
# define __VIR_QEMU_H__

# include <libvirt/libvirt.h>

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

typedef enum {
    VIR_DOMAIN_QEMU_AGENT_COMMAND_MIN = -2,
    VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK = -2,
    VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT = -1,
    VIR_DOMAIN_QEMU_AGENT_COMMAND_NOWAIT = 0,
} virDomainQemuAgentCommandTimeoutValues;

char *virDomainQemuAgentCommand(virDomainPtr domain, const char *cmd,
                                int timeout, unsigned int flags);

# ifdef __cplusplus
}
# endif

#endif /* __VIR_QEMU_H__ */
