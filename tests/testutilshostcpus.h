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

#pragma once

#include "conf/cpu_conf.h"
#include "internal.h"
#include "util/virarch.h"

static virCPUFeatureDef cpuDefaultFeatures[] = {
    { (char *) "ds",        -1 },
    { (char *) "acpi",      -1 },
    { (char *) "ss",        -1 },
    { (char *) "ht",        -1 },
    { (char *) "tm",        -1 },
    { (char *) "pbe",       -1 },
    { (char *) "ds_cpl",    -1 },
    { (char *) "vmx",       -1 },
    { (char *) "est",       -1 },
    { (char *) "tm2",       -1 },
    { (char *) "cx16",      -1 },
    { (char *) "xtpr",      -1 },
    { (char *) "lahf_lm",   -1 },
};
static virCPUDef cpuDefaultData = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_X86_64,
    .model = (char *) "core2duo",
    .vendor = (char *) "Intel",
    .sockets = 1,
    .cores = 2,
    .threads = 1,
    .nfeatures = G_N_ELEMENTS(cpuDefaultFeatures),
    .nfeatures_max = G_N_ELEMENTS(cpuDefaultFeatures),
    .features = cpuDefaultFeatures,
};

static virCPUFeatureDef cpuHaswellFeatures[] = {
    { (char *) "vme",       -1 },
    { (char *) "ds",        -1 },
    { (char *) "acpi",      -1 },
    { (char *) "ss",        -1 },
    { (char *) "ht",        -1 },
    { (char *) "tm",        -1 },
    { (char *) "pbe",       -1 },
    { (char *) "dtes64",    -1 },
    { (char *) "monitor",   -1 },
    { (char *) "ds_cpl",    -1 },
    { (char *) "vmx",       -1 },
    { (char *) "smx",       -1 },
    { (char *) "est",       -1 },
    { (char *) "tm2",       -1 },
    { (char *) "xtpr",      -1 },
    { (char *) "pdcm",      -1 },
    { (char *) "osxsave",   -1 },
    { (char *) "f16c",      -1 },
    { (char *) "rdrand",    -1 },
    { (char *) "cmt",       -1 },
    { (char *) "pdpe1gb",   -1 },
    { (char *) "abm",       -1 },
    { (char *) "invtsc",    -1 },
    { (char *) "lahf_lm",   -1 },
};
static virCPUDef cpuHaswellData = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_X86_64,
    .model = (char *) "Haswell",
    .vendor = (char *) "Intel",
    .sockets = 1,
    .cores = 2,
    .threads = 2,
    .nfeatures = G_N_ELEMENTS(cpuHaswellFeatures),
    .nfeatures_max = G_N_ELEMENTS(cpuHaswellFeatures),
    .features = cpuHaswellFeatures,
};

static virCPUDef cpuBroadwellData = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_X86_64,
    .model = (char *) "Broadwell",
    .sockets = 1,
    .cores = 2,
    .threads = 2,
};

static virCPUDef cpuPower8Data = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_PPC64,
    .model = (char *) "POWER8",
    .sockets = 1,
    .cores = 8,
    .threads = 8,
};

static virCPUDef cpuPower9Data = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_PPC64,
    .model = (char *) "POWER9",
    .sockets = 1,
    .cores = 16,
    .threads = 1,
};

static virCPUDef cpuPower10Data = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_PPC64,
    .model = (char *) "POWER10",
    .sockets = 1,
    .cores = 16,
    .threads = 1,
};

static virCPUDef cpuAarch64Data = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_AARCH64,
    .sockets = 1,
    .cores = 4,
    .threads = 1,
};

static virCPUDef cpuS390Data = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_S390X,
    .sockets = 2,
    .cores = 1,
    .threads = 1,
};

static virCPUDef cpuSparcData = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_SPARC,
    .sockets = 1,
    .cores = 1,
    .threads = 1,
};

static virCPUDef cpuPPCData = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_PPC,
    .sockets = 1,
    .cores = 1,
    .threads = 1,
};

static virCPUDef cpuRiscv64Data = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_RISCV64,
    .sockets = 1,
    .cores = 4,
    .threads = 1,
};

static inline virCPUDef *
testUtilsHostCpusGetDefForModel(const char *model)
{
    if (!model)
        return NULL;

    if (STREQ(model, "core2duo"))
        return virCPUDefCopy(&cpuDefaultData);
    else if (STREQ(model, "Haswell"))
        return virCPUDefCopy(&cpuHaswellData);
    else if (STREQ(model, "Broadwell"))
        return virCPUDefCopy(&cpuBroadwellData);
    else if (STREQ(model, "POWER8"))
        return virCPUDefCopy(&cpuPower8Data);
    else if (STREQ(model, "POWER9"))
        return virCPUDefCopy(&cpuPower9Data);
    else if (STREQ(model, "POWER10"))
        return virCPUDefCopy(&cpuPower10Data);

    return NULL;
}

static inline virCPUDef *
testUtilsHostCpusGetDefForArch(virArch arch)
{
    if (ARCH_IS_X86(arch))
        return virCPUDefCopy(&cpuBroadwellData);
    else if (ARCH_IS_PPC64(arch))
        return virCPUDefCopy(&cpuPower8Data);
    else if (ARCH_IS_S390(arch))
        return virCPUDefCopy(&cpuS390Data);
    else if (arch == VIR_ARCH_AARCH64)
        return virCPUDefCopy(&cpuAarch64Data);
    else if (arch == VIR_ARCH_SPARC)
        return virCPUDefCopy(&cpuSparcData);
    else if (arch == VIR_ARCH_RISCV64)
        return virCPUDefCopy(&cpuRiscv64Data);
    else if (arch == VIR_ARCH_PPC)
        return virCPUDefCopy(&cpuPPCData);

    return NULL;
}
