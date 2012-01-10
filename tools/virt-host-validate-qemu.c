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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include "virt-host-validate-qemu.h"
#include "virt-host-validate-common.h"

int virHostValidateQEMU(void)
{
    int ret = 0;

    virHostMsgCheck("QEMU", "%s", ("for hardware virtualization"));
    if (virHostValidateHasCPUFlag("svm") ||
        virHostValidateHasCPUFlag("vmx")) {
        virHostMsgPass();
        if (virHostValidateDevice("QEMU", "/dev/kvm",
                                  VIR_HOST_VALIDATE_FAIL,
                                  _("Check that the 'kvm-intel' or 'kvm-amd' modules are "
                                    "loaded & the BIOS has enabled virtualization")) < 0)
            ret = -1;
    } else {
        virHostMsgFail(VIR_HOST_VALIDATE_WARN,
                       _("Only emulated CPUs are available, performance will be significantly limited"));
    }

    if (virHostValidateDevice("QEMU", "/dev/vhost-net",
                              VIR_HOST_VALIDATE_WARN,
                              _("Load the 'vhost_net' module to improve performance "
                                "of virtio networking")) < 0)
        ret = -1;

    if (virHostValidateDevice("QEMU", "/dev/net/tun",
                              VIR_HOST_VALIDATE_FAIL,
                              _("Load the 'tun' module to enable networking for QEMU guests")) < 0)
        ret = -1;

    return ret;
}
