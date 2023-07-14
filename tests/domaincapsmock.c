/*
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

#include "virhostcpu.h"
#include "virhostmem.h"

#if WITH_QEMU
# include "virmock.h"
# include "qemu/qemu_capabilities.h"
#endif

int
virHostCPUGetKVMMaxVCPUs(void)
{
    return INT_MAX;
}

unsigned int
virHostCPUGetMicrocodeVersion(virArch hostArch G_GNUC_UNUSED)
{
    return 0;
}

int
virHostCPUGetPhysAddrSize(const virArch hostArch,
                          unsigned int *size)
{
    if (ARCH_IS_S390(hostArch))
        *size = 0;
    else
        *size = 64;
    return 0;
}

#if WITH_QEMU
static bool (*real_virQEMUCapsGetKVMSupportsSecureGuest)(virQEMUCaps *qemuCaps);

bool
virQEMUCapsGetKVMSupportsSecureGuest(virQEMUCaps *qemuCaps)
{
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_MACHINE_CONFIDENTAL_GUEST_SUPPORT) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_S390_PV_GUEST))
        return true;

    if (!real_virQEMUCapsGetKVMSupportsSecureGuest)
        VIR_MOCK_REAL_INIT(virQEMUCapsGetKVMSupportsSecureGuest);

    return real_virQEMUCapsGetKVMSupportsSecureGuest(qemuCaps);
}
#endif

int
virHostMemGetTHPSize(unsigned long long *size)
{
    /* Pretend Transparent Huge Page size is 2MiB. */
    *size = 2048;
    return 0;
}
