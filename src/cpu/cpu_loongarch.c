/*
 * cpu_loongarch.c: CPU driver for 64-bit LOONGARCH CPUs
 *
 * Copyright (C) 2024 Loongson Technology.
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
#include "virlog.h"
#include "cpu.h"

#define VIR_FROM_THIS VIR_FROM_CPU

VIR_LOG_INIT("cpu.cpu_loongarch");

static const virArch archs[] = { VIR_ARCH_LOONGARCH64 };

static virCPUCompareResult
virCPULoongArchCompare(virCPUDef *host G_GNUC_UNUSED,
                       virCPUDef *cpu G_GNUC_UNUSED,
                       bool failIncompatible G_GNUC_UNUSED)
{
    return VIR_CPU_COMPARE_IDENTICAL;
}

static int
virCPULoongArchUpdate(virCPUDef *guest G_GNUC_UNUSED,
                      const virCPUDef *host G_GNUC_UNUSED,
                      bool relative G_GNUC_UNUSED,
                      virCPUFeaturePolicy removedPolicy G_GNUC_UNUSED)
{
    return 0;
}

struct cpuArchDriver cpuDriverLoongArch = {
    .name       = "LoongArch",
    .arch       = archs,
    .narch      = G_N_ELEMENTS(archs),
    .compare    = virCPULoongArchCompare,
    .decode     = NULL,
    .encode     = NULL,
    .dataFree   = NULL,
    .baseline   = NULL,
    .update     = virCPULoongArchUpdate,
    .getModels  = NULL,
};
