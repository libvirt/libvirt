/*
 * cpu_aarch64.c: CPU driver for AArch64 CPUs
 *
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
 *      Anup Patel <anup.patel@linaro.org>
 *      Pranavkumar Sawargaonkar <pranavkumar@linaro.org>
 */

#include <config.h>

#include "viralloc.h"
#include "cpu.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_CPU

static const virArch archs[] = { VIR_ARCH_AARCH64 };

static virCPUDataPtr
AArch64NodeData(virArch arch)
{
    virCPUDataPtr data;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    data->arch = arch;

    return data;
}

static int
AArch64Decode(virCPUDefPtr cpu,
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
AArch64DataFree(virCPUDataPtr data)
{
    VIR_FREE(data);
}

static int
AArch64Update(virCPUDefPtr guest,
              const virCPUDef *host)
{
    guest->match = VIR_CPU_MATCH_EXACT;
    virCPUDefFreeModel(guest);
    return virCPUDefCopyModel(guest, host, true);
}

static virCPUCompareResult
AArch64GuestData(virCPUDefPtr host ATTRIBUTE_UNUSED,
                 virCPUDefPtr guest ATTRIBUTE_UNUSED,
                 virCPUDataPtr *data ATTRIBUTE_UNUSED,
                 char **message ATTRIBUTE_UNUSED)
{
    return VIR_CPU_COMPARE_IDENTICAL;
}

static virCPUDefPtr
AArch64Baseline(virCPUDefPtr *cpus,
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

struct cpuArchDriver cpuDriverAARCH64 = {
    .name = "aarch64",
    .arch = archs,
    .narch = ARRAY_CARDINALITY(archs),
    .compare = NULL,
    .decode = AArch64Decode,
    .encode = NULL,
    .free = AArch64DataFree,
    .nodeData = AArch64NodeData,
    .guestData = AArch64GuestData,
    .baseline = AArch64Baseline,
    .update = AArch64Update,
    .hasFeature = NULL,
};
