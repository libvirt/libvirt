/*
 * virt-host-validate-ch.c: Sanity check a CH hypervisor host
 *
 * Copyright Microsoft Corp. 2020-2021
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

#include "virarch.h"
#include "virbitmap.h"
#include "virt-host-validate-ch.h"
#include "virt-host-validate-common.h"

int virHostValidateCh(void)
{
    int ret = 0;
    g_autoptr(virBitmap) flags = NULL;
    bool hasHwVirt = false;
    bool hasVirtFlag = false;
    virArch arch = virArchFromHost();
    const char *kvmhint =
        _("Check that CPU and firmware supports virtualization and kvm module is loaded");

    if (!(flags = virHostValidateGetCPUFlags()))
        return -1;

    /* Cloud-Hypervisor only supports x86_64 and aarch64 */
    switch ((int)arch) {
    case VIR_ARCH_X86_64:
        hasVirtFlag = true;
        kvmhint = _("Check that the 'kvm-intel' or 'kvm-amd' modules are loaded & the BIOS has enabled virtualization");
        if (virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_SVM) ||
            virBitmapIsBitSet(flags, VIR_HOST_VALIDATE_CPU_FLAG_VMX))
            hasHwVirt = true;
        break;
    case VIR_ARCH_AARCH64:
        hasVirtFlag = true;
        hasHwVirt = true;
        break;
    default:
        hasHwVirt = false;
        break;
    }

    if (hasVirtFlag) {
        virHostMsgCheck("CH", "%s", _("for hardware virtualization"));
        if (hasHwVirt) {
            virHostMsgPass();
        } else {
            virHostMsgFail(VIR_HOST_VALIDATE_FAIL,
                           _("Only emulated CPUs are available, performance will be significantly limited"));
            ret = -1;
        }
    }

    if (hasHwVirt || !hasVirtFlag) {
        if (virHostValidateDeviceExists("CH", "/dev/kvm", VIR_HOST_VALIDATE_FAIL,
                                        kvmhint) < 0)
            ret = -1;
        else if (virHostValidateDeviceAccessible("CH", "/dev/kvm", VIR_HOST_VALIDATE_FAIL,
                                                 _("Check /dev/kvm is world writable or you are in a group that is allowed to access it")) < 0)
            ret = -1;
    }

    return ret;
}
