/*
 * virt-host-validate-lxc.c: Sanity check a LXC hypervisor host
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 */

#include <config.h>

#include "virt-host-validate-lxc.h"
#include "virt-host-validate-common.h"
#include "vircgroup.h"

int virHostValidateLXC(void)
{
    int ret = 0;

    if (virHostValidateLinuxKernel("LXC", (2 << 16) | (6 << 8) | 26,
                                   VIR_HOST_VALIDATE_FAIL,
                                   _("Upgrade to a kernel supporting namespaces")) < 0)
        ret = -1;

    if (virHostValidateNamespace("LXC", "ipc",
                                 VIR_HOST_VALIDATE_FAIL,
                                 _("IPC namespace support is required")) < 0)
        ret = -1;

    if (virHostValidateNamespace("LXC", "mnt",
                                 VIR_HOST_VALIDATE_FAIL,
                                 _("Mount namespace support is required")) < 0)
        ret = -1;

    if (virHostValidateNamespace("LXC", "pid",
                                 VIR_HOST_VALIDATE_FAIL,
                                 _("PID namespace support is required")) < 0)
        ret = -1;

    if (virHostValidateNamespace("LXC", "uts",
                                 VIR_HOST_VALIDATE_FAIL,
                                 _("UTS namespace support is required")) < 0)
        ret = -1;

    if (virHostValidateNamespace("LXC", "net",
                                 VIR_HOST_VALIDATE_WARN,
                                 _("Network namespace support is recommended")) < 0)
        ret = -1;

    if (virHostValidateNamespace("LXC", "user",
                                 VIR_HOST_VALIDATE_WARN,
                                 _("User namespace support is recommended")) < 0)
        ret = -1;

    if (virHostValidateCGroupControllers("LXC",
                                         (1 << VIR_CGROUP_CONTROLLER_MEMORY) |
                                         (1 << VIR_CGROUP_CONTROLLER_CPU) |
                                         (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
                                         (1 << VIR_CGROUP_CONTROLLER_CPUSET) |
                                         (1 << VIR_CGROUP_CONTROLLER_DEVICES) |
                                         (1 << VIR_CGROUP_CONTROLLER_FREEZER) |
                                         (1 << VIR_CGROUP_CONTROLLER_BLKIO),
                                         VIR_HOST_VALIDATE_FAIL) < 0) {
        ret = -1;
    }

#if WITH_FUSE
    if (virHostValidateDeviceExists("LXC", "/sys/fs/fuse/connections",
                                    VIR_HOST_VALIDATE_FAIL,
                                    _("Load the 'fuse' module to enable /proc/ overrides")) < 0)
        ret = -1;
#endif

    return ret;
}
