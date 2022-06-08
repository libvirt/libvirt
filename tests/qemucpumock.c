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


virCPUDef *
virQEMUCapsProbeHostCPU(virArch hostArch G_GNUC_UNUSED,
                        virDomainCapsCPUModels *models G_GNUC_UNUSED)
{
    const char *model = getenv("VIR_TEST_MOCK_FAKE_HOST_CPU");

    return testUtilsHostCpusGetDefForModel(model);
}
