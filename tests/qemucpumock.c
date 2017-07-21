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

#include <stdlib.h>

#include "conf/cpu_conf.h"
#include "cpu/cpu.h"
#include "qemu/qemu_capabilities.h"
#define __QEMU_CAPSPRIV_H_ALLOW__
#include "qemu/qemu_capspriv.h"
#undef __QEMU_CAPSPRIV_H_ALLOW__
#include "testutilshostcpus.h"
#include "virarch.h"


virCPUDefPtr
virQEMUCapsProbeHostCPUForEmulator(virArch hostArch ATTRIBUTE_UNUSED,
                                   virQEMUCapsPtr qemuCaps ATTRIBUTE_UNUSED,
                                   virDomainVirtType type ATTRIBUTE_UNUSED)
{
    const char *model = getenv("VIR_TEST_MOCK_FAKE_HOST_CPU");

    return testUtilsHostCpusGetDefForModel(model);
}
