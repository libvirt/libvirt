/*
 * cpu_arm.c: CPU driver for arm CPUs
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright (C) Canonical Ltd. 2012
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
 * Authors:
 *      Chuck Short <chuck.short@canonical.com>
 */

#include <config.h>

#include "viralloc.h"
#include "cpu.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_CPU

static const virArch archs[] = { VIR_ARCH_ARMV7L };

static virCPUDataPtr
ArmNodeData(virArch arch)
{
    virCPUDataPtr data;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    data->arch = arch;

    return data;
}

static int
ArmDecode(virCPUDefPtr cpu,
          const virCPUData *data ATTRIBUTE_UNUSED,
          const char **models ATTRIBUTE_UNUSED,
          unsigned int nmodels ATTRIBUTE_UNUSED,
          const char *preferred ATTRIBUTE_UNUSED,
          unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, -1);

    if (cpu->model == NULL &&
        VIR_STRDUP(cpu->model, "host") < 0)
        return -1;

    return 0;
}

static void
ArmDataFree(virCPUDataPtr data)
{
    VIR_FREE(data);
}

static int
ArmUpdate(virCPUDefPtr guest,
          const virCPUDef *host)
{
    guest->match = VIR_CPU_MATCH_EXACT;
    virCPUDefFreeModel(guest);
    return virCPUDefCopyModel(guest, host, true);
}

static virCPUCompareResult
ArmGuestData(virCPUDefPtr host ATTRIBUTE_UNUSED,
             virCPUDefPtr guest ATTRIBUTE_UNUSED,
             virCPUDataPtr *data ATTRIBUTE_UNUSED,
             char **message ATTRIBUTE_UNUSED)
{
    return VIR_CPU_COMPARE_IDENTICAL;
}

static virCPUDefPtr
ArmBaseline(virCPUDefPtr *cpus,
            unsigned int ncpus ATTRIBUTE_UNUSED,
            const char **models ATTRIBUTE_UNUSED,
            unsigned int nmodels ATTRIBUTE_UNUSED,
            unsigned int flags)
{
    virCPUDefPtr cpu = NULL;

    virCheckFlags(VIR_CONNECT_BASELINE_CPU_EXPAND_FEATURES, NULL);

    if (VIR_ALLOC(cpu) < 0 ||
        VIR_STRDUP(cpu->model, cpus[0]->model) < 0) {
        virCPUDefFree(cpu);
        return NULL;
    }

    cpu->type = VIR_CPU_TYPE_GUEST;
    cpu->match = VIR_CPU_MATCH_EXACT;

    return cpu;
}

struct cpuArchDriver cpuDriverArm = {
    .name = "arm",
    .arch = archs,
    .narch = ARRAY_CARDINALITY(archs),
    .compare = NULL,
    .decode = ArmDecode,
    .encode = NULL,
    .free = ArmDataFree,
    .nodeData = ArmNodeData,
    .guestData = ArmGuestData,
    .baseline = ArmBaseline,
    .update = ArmUpdate,
    .hasFeature = NULL,
};
