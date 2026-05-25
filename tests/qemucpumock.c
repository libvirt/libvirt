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


#include "conf/cpu_conf.h"
#include "qemu/qemu_capabilities.h"
#define LIBVIRT_QEMU_CAPSPRIV_H_ALLOW
#include "qemu/qemu_capspriv.h"
#include "testutilshostcpus.h"
#include "virarch.h"
#include "util/virhostcpu.h"


virCPUDef *
virQEMUCapsProbeHostCPU(virArch hostArch G_GNUC_UNUSED,
                        virDomainCapsCPUModels *models G_GNUC_UNUSED)
{
    const char *model = g_getenv("VIR_TEST_MOCK_FAKE_HOST_CPU");

    return testUtilsHostCpusGetDefForModel(model);
}


int
virHostCPUGetMSRFromKVM(unsigned long index,
                        uint64_t *result)
{
    if (index == 0x10a) {
        /* Return some arbitrary bits in arch-capabilities MSR */
        *result =
            0x00000001 | /* rdctl-no */
            0x00000008 | /* skip-l1dfl-vmentry */
            0x00000020 | /* mds-no */
            0x00000040 | /* pschange-mc-no */
            0x04000000 | /* gds-no */
            0x08000000;  /* rfds-no */
        return 0;
    }

    errno = ENOTSUP;
    return -1;
}
