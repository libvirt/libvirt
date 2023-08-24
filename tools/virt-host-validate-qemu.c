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

#include "virt-host-validate-qemu.h"
#include "virt-host-validate-common.h"
#include "virarch.h"
#include "virbitmap.h"
#include "vircgroup.h"

int virHostValidateQEMU(void)
{
    g_autoptr(virBitmap) flags = NULL;
    int ret = 0;
    bool hasHwVirt = false;
    bool hasVirtFlag = false;
    virArch arch = virArchFromHost();
    const char *kvmhint = _("Check that CPU and firmware supports virtualization and kvm module is loaded");

    if (!(flags = virHostValidateGetCPUFlags()))
        return -1;

    switch ((int)arch) {
    case VIR_ARCH_I686:
    case VIR_ARCH_X86_64:
        hasVirtFlag = true;
        kvmhint = _("Check that the 'kvm-intel' or 'kvm-amd' modules are loaded & the BIOS has enabled virtualization");
        if (virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_SVM) ||
            virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_VMX))
            hasHwVirt = true;
        break;
    case VIR_ARCH_S390:
    case VIR_ARCH_S390X:
        hasVirtFlag = true;
        if (virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_SIE))
            hasHwVirt = true;
        break;
    case VIR_ARCH_PPC64:
    case VIR_ARCH_PPC64LE:
        hasVirtFlag = true;
        hasHwVirt = true;
        break;
    default:
        hasHwVirt = false;
    }

    if (hasVirtFlag) {
        virHostMsgCheck("QEMU", "%s", _("for hardware virtualization"));
        if (hasHwVirt) {
            virHostMsgPass();
        } else {
            virHostMsgFail(VIR_HOST_VALIDATE_FAIL,
                           _("Host not compatible with KVM; HW virtualization CPU features not found. Only emulated CPUs are available; performance will be significantly limited"));
            ret = -1;
        }
    }

    if (hasHwVirt || !hasVirtFlag) {
        if (virHostValidateDeviceExists("QEMU", "/dev/kvm",
                                        VIR_HOST_VALIDATE_FAIL,
                                        kvmhint) <0)
            ret = -1;
        else if (virHostValidateDeviceAccessible("QEMU", "/dev/kvm",
                                                 VIR_HOST_VALIDATE_FAIL,
                                                 _("Check /dev/kvm is world writable or you are in a group that is allowed to access it")) < 0)
            ret = -1;
    }

    if (arch == VIR_ARCH_PPC64 || arch == VIR_ARCH_PPC64LE) {
        virHostMsgCheck("QEMU", "%s", _("for PowerPC KVM module loaded"));

        if (!virHostKernelModuleIsLoaded("kvm_hv"))
            virHostMsgFail(VIR_HOST_VALIDATE_WARN,
                          _("Load kvm_hv for better performance"));
        else
            virHostMsgPass();
    }

    if (virHostValidateDeviceExists("QEMU", "/dev/vhost-net",
                                    VIR_HOST_VALIDATE_WARN,
                                    _("Load the 'vhost_net' module to improve performance of virtio networking")) < 0)
        ret = -1;

    if (virHostValidateDeviceExists("QEMU", "/dev/net/tun",
                                    VIR_HOST_VALIDATE_FAIL,
                                    _("Load the 'tun' module to enable networking for QEMU guests")) < 0)
        ret = -1;

    if (virHostValidateCGroupControllers("QEMU",
                                         (1 << VIR_CGROUP_CONTROLLER_MEMORY) |
                                         (1 << VIR_CGROUP_CONTROLLER_CPU) |
                                         (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
                                         (1 << VIR_CGROUP_CONTROLLER_CPUSET) |
                                         (1 << VIR_CGROUP_CONTROLLER_DEVICES) |
                                         (1 << VIR_CGROUP_CONTROLLER_BLKIO),
                                         VIR_HOST_VALIDATE_WARN) < 0) {
        ret = -1;
    }

    if (virHostValidateIOMMU("QEMU",
                             VIR_HOST_VALIDATE_WARN) < 0)
        ret = -1;

    if (virHostValidateSecureGuests("QEMU",
                                    VIR_HOST_VALIDATE_WARN) < 0)
        ret = -1;

    return ret;
}
