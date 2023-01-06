/*
 * cpu_riscv64.c: CPU driver for riscv64 CPUs
 *
 * Copyright (C) 2023, Ventana Micro
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

#include "cpu.h"


#define VIR_FROM_THIS VIR_FROM_CPU

static const virArch archs[] = { VIR_ARCH_RISCV64 };

static virCPUCompareResult
virCPURiscv64Compare(virCPUDef *host G_GNUC_UNUSED,
                     virCPUDef *cpu G_GNUC_UNUSED,
                     bool failMessages G_GNUC_UNUSED)
{
    /*
     * For now QEMU will perform all runtime checks.
     */
    return VIR_CPU_COMPARE_IDENTICAL;
}


static int
virCPURiscv64ValidateFeatures(virCPUDef *cpu G_GNUC_UNUSED)
{
    return 0;
}


struct cpuArchDriver cpuDriverRiscv64 = {
    .name = "riscv64",
    .arch = archs,
    .narch = G_N_ELEMENTS(archs),
    .compare    = virCPURiscv64Compare,
    .decode     = NULL,
    .encode     = NULL,
    .baseline   = NULL,
    .update     = NULL,
    .validateFeatures = virCPURiscv64ValidateFeatures,
};
