/*
 * virt-host-validate-qemu.c: Sanity check a QEMU hypervisor host
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
#include <unistd.h>

#include "virt-host-validate-qemu.h"
#include "virt-host-validate-common.h"

int virHostValidateQEMU(void)
{
    int ret = 0;

    virHostMsgCheck("QEMU", "%s", ("for hardware virtualization"));
    if (virHostValidateHasCPUFlag("svm") ||
        virHostValidateHasCPUFlag("vmx")) {
        virHostMsgPass();
        if (virHostValidateDeviceExists("QEMU", "/dev/kvm",
                                        VIR_HOST_VALIDATE_FAIL,
                                        _("Check that the 'kvm-intel' or 'kvm-amd' modules are "
                                          "loaded & the BIOS has enabled virtualization")) < 0)
            ret = -1;
        else if (virHostValidateDeviceAccessible("QEMU", "/dev/kvm",
                                                 VIR_HOST_VALIDATE_FAIL,
                                                 _("Check /dev/kvm is world writable or you are in "
                                                   "a group that is allowed to access it")) < 0)
            ret = -1;
    } else {
        virHostMsgFail(VIR_HOST_VALIDATE_WARN,
                       _("Only emulated CPUs are available, performance will be significantly limited"));
    }

    if (virHostValidateDeviceExists("QEMU", "/dev/vhost-net",
                                    VIR_HOST_VALIDATE_WARN,
                                    _("Load the 'vhost_net' module to improve performance "
                                      "of virtio networking")) < 0)
        ret = -1;

    if (virHostValidateDeviceExists("QEMU", "/dev/net/tun",
                                    VIR_HOST_VALIDATE_FAIL,
                                    _("Load the 'tun' module to enable networking for QEMU guests")) < 0)
        ret = -1;

    if (virHostValidateCGroupController("QEMU", "memory",
                                        VIR_HOST_VALIDATE_WARN,
                                        "MEMCG") < 0)
        ret = -1;

    if (virHostValidateCGroupController("QEMU", "cpu",
                                        VIR_HOST_VALIDATE_WARN,
                                        "CGROUP_CPU") < 0)
        ret = -1;

    if (virHostValidateCGroupController("QEMU", "cpuacct",
                                        VIR_HOST_VALIDATE_WARN,
                                        "CGROUP_CPUACCT") < 0)
        ret = -1;

    if (virHostValidateCGroupController("QEMU", "devices",
                                        VIR_HOST_VALIDATE_WARN,
                                        "CGROUP_DEVICES") < 0)
        ret = -1;

    if (virHostValidateCGroupController("QEMU", "net_cls",
                                        VIR_HOST_VALIDATE_WARN,
                                        "NET_CLS_CGROUP") < 0)
        ret = -1;

    if (virHostValidateCGroupController("QEMU", "blkio",
                                        VIR_HOST_VALIDATE_WARN,
                                        "BLK_CGROUP") < 0)
        ret = -1;

    if (virHostValidateIOMMU("QEMU",
                             VIR_HOST_VALIDATE_WARN) < 0)
        ret = -1;

    return ret;
}
