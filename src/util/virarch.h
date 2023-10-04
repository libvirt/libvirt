/*
 * virarch.h: architecture handling
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include "internal.h"

typedef enum {
    VIR_ARCH_NONE,
    VIR_ARCH_ALPHA,        /* Alpha       64 BE https://en.wikipedia.org/wiki/DEC_Alpha */
    VIR_ARCH_ARMV6L,       /* ARMv6       32 LE https://en.wikipedia.org/wiki/ARM_architecture */
    VIR_ARCH_ARMV7L,       /* ARMv7       32 LE https://en.wikipedia.org/wiki/ARM_architecture */
    VIR_ARCH_ARMV7B,       /* ARMv7       32 BE https://en.wikipedia.org/wiki/ARM_architecture */

    VIR_ARCH_AARCH64,      /* ARMv8       64 LE https://en.wikipedia.org/wiki/ARM_architecture */
    VIR_ARCH_CRIS,         /* ETRAX       32 LE https://en.wikipedia.org/wiki/ETRAX_CRIS */
    VIR_ARCH_I686,         /* x86         32 LE https://en.wikipedia.org/wiki/X86 */
    VIR_ARCH_ITANIUM,      /* Itanium     64 LE https://en.wikipedia.org/wiki/Itanium */
    VIR_ARCH_LM32,         /* MilkyMist   32 BE https://en.wikipedia.org/wiki/Milkymist */

    VIR_ARCH_M68K,         /* m68k        32 BE https://en.wikipedia.org/wiki/Motorola_68000_family */
    VIR_ARCH_MICROBLAZE,   /* Microblaze  32 BE https://en.wikipedia.org/wiki/MicroBlaze */
    VIR_ARCH_MICROBLAZEEL, /* Microblaze  32 LE https://en.wikipedia.org/wiki/MicroBlaze */
    VIR_ARCH_MIPS,         /* MIPS        32 BE https://en.wikipedia.org/wiki/MIPS_architecture */
    VIR_ARCH_MIPSEL,       /* MIPS        32 LE https://en.wikipedia.org/wiki/MIPS_architecture */

    VIR_ARCH_MIPS64,       /* MIPS        64 BE https://en.wikipedia.org/wiki/MIPS_architecture */
    VIR_ARCH_MIPS64EL,     /* MIPS        64 LE https://en.wikipedia.org/wiki/MIPS_architecture */
    VIR_ARCH_OR32,         /* OpenRisc    32 BE https://en.wikipedia.org/wiki/OpenRISC#QEMU_support */
    VIR_ARCH_PARISC,       /* PA-Risc     32 BE https://en.wikipedia.org/wiki/PA-RISC */
    VIR_ARCH_PARISC64,     /* PA-Risc     64 BE https://en.wikipedia.org/wiki/PA-RISC */

    VIR_ARCH_PPC,          /* PowerPC     32 BE https://en.wikipedia.org/wiki/PowerPC */
    VIR_ARCH_PPCLE,        /* PowerPC     32 LE https://en.wikipedia.org/wiki/PowerPC */
    VIR_ARCH_PPC64,        /* PowerPC     64 BE https://en.wikipedia.org/wiki/PowerPC */
    VIR_ARCH_PPC64LE,      /* PowerPC     64 LE https://en.wikipedia.org/wiki/PowerPC */
    VIR_ARCH_PPCEMB,       /* PowerPC     32 BE https://en.wikipedia.org/wiki/PowerPC */

    VIR_ARCH_RISCV32,      /* RISC-V      32 LE https://en.wikipedia.org/wiki/RISC-V */
    VIR_ARCH_RISCV64,      /* RISC-V      64 LE https://en.wikipedia.org/wiki/RISC-V */
    VIR_ARCH_S390,         /* S390        32 BE https://en.wikipedia.org/wiki/S390 */
    VIR_ARCH_S390X,        /* S390        64 BE https://en.wikipedia.org/wiki/S390x */
    VIR_ARCH_SH4,          /* SuperH4     32 LE https://en.wikipedia.org/wiki/SuperH */

    VIR_ARCH_SH4EB,        /* SuperH4     32 BE https://en.wikipedia.org/wiki/SuperH */
    VIR_ARCH_SPARC,        /* Sparc       32 BE https://en.wikipedia.org/wiki/Sparc */
    VIR_ARCH_SPARC64,      /* Sparc       64 BE https://en.wikipedia.org/wiki/Sparc */
    VIR_ARCH_UNICORE32,    /* UniCore     32 LE https://en.wikipedia.org/wiki/Unicore */
    VIR_ARCH_X86_64,       /* x86         64 LE https://en.wikipedia.org/wiki/X86 */

    VIR_ARCH_XTENSA,       /* XTensa      32 LE https://en.wikipedia.org/wiki/Xtensa#Processor_Cores */
    VIR_ARCH_XTENSAEB,     /* XTensa      32 BE https://en.wikipedia.org/wiki/Xtensa#Processor_Cores */

    VIR_ARCH_LAST,
} virArch;

#define ARCH_IS_X86(arch)  ((arch) == VIR_ARCH_X86_64 ||\
                            (arch) == VIR_ARCH_I686)

#define ARCH_IS_PPC(arch)  ((arch) == VIR_ARCH_PPC ||\
                            (arch) == VIR_ARCH_PPCLE ||\
                            (arch) == VIR_ARCH_PPC64 ||\
                            (arch) == VIR_ARCH_PPC64LE ||\
                            (arch) == VIR_ARCH_PPCEMB)

#define ARCH_IS_PPC64(arch)  ((arch) == VIR_ARCH_PPC64 ||\
                              (arch) == VIR_ARCH_PPC64LE)

#define ARCH_IS_ARM(arch)  ((arch) == VIR_ARCH_ARMV6L ||\
                            (arch) == VIR_ARCH_ARMV7L ||\
                            (arch) == VIR_ARCH_ARMV7B ||\
                            (arch) == VIR_ARCH_AARCH64)

#define ARCH_IS_RISCV(arch) ((arch) == VIR_ARCH_RISCV32 ||\
                             (arch) == VIR_ARCH_RISCV64)

#define ARCH_IS_S390(arch) ((arch) == VIR_ARCH_S390 ||\
                            (arch) == VIR_ARCH_S390X)

#define ARCH_IS_MIPS(arch) ((arch) == VIR_ARCH_MIPS ||\
                            (arch) == VIR_ARCH_MIPSEL ||\
                            (arch) == VIR_ARCH_MIPS64 ||\
                            (arch) == VIR_ARCH_MIPS64EL)

#define ARCH_IS_MIPS64(arch) ((arch) == VIR_ARCH_MIPS64 ||\
                              (arch) == VIR_ARCH_MIPS64EL)

#define ARCH_IS_SH4(arch) ((arch) == VIR_ARCH_SH4 ||\
                           (arch) == VIR_ARCH_SH4EB)

typedef enum {
    VIR_ARCH_LITTLE_ENDIAN,
    VIR_ARCH_BIG_ENDIAN,
} virArchEndian;

unsigned int virArchGetWordSize(virArch arch);
virArchEndian virArchGetEndian(virArch arch);
const char *virArchToString(virArch arch);
virArch virArchFromString(const char *name);

virArch virArchFromHost(void);
