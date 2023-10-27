/*
 * virarch.c: architecture handling
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

#include <config.h>

#ifdef WIN32
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#else
# include <sys/utsname.h>
#endif

#include "virlog.h"
#include "virarch.h"

VIR_LOG_INIT("util.arch");

/* The canonical names are used in XML documents. ie ABI sensitive */
static const struct virArchData {
    const char *name;
    unsigned int wordsize;
    virArchEndian endian;
} virArchData[] = {
    { "none",          0, VIR_ARCH_LITTLE_ENDIAN },
    { "alpha",        64, VIR_ARCH_BIG_ENDIAN },
    { "armv6l",       32, VIR_ARCH_LITTLE_ENDIAN },
    { "armv7l",       32, VIR_ARCH_LITTLE_ENDIAN },
    { "armv7b",       32, VIR_ARCH_BIG_ENDIAN },

    { "aarch64",      64, VIR_ARCH_LITTLE_ENDIAN },
    { "cris",         32, VIR_ARCH_LITTLE_ENDIAN },
    { "i686",         32, VIR_ARCH_LITTLE_ENDIAN },
    { "ia64",         64, VIR_ARCH_LITTLE_ENDIAN },
    { "lm32",         32, VIR_ARCH_BIG_ENDIAN },

    { "m68k",         32, VIR_ARCH_BIG_ENDIAN },
    { "microblaze",   32, VIR_ARCH_BIG_ENDIAN },
    { "microblazeel", 32, VIR_ARCH_LITTLE_ENDIAN},
    { "mips",         32, VIR_ARCH_BIG_ENDIAN },
    { "mipsel",       32, VIR_ARCH_LITTLE_ENDIAN },

    { "mips64",       64, VIR_ARCH_BIG_ENDIAN },
    { "mips64el",     64, VIR_ARCH_LITTLE_ENDIAN },
    { "openrisc",     32, VIR_ARCH_BIG_ENDIAN },
    { "parisc",       32, VIR_ARCH_BIG_ENDIAN },
    { "parisc64",     64, VIR_ARCH_BIG_ENDIAN },

    { "ppc",          32, VIR_ARCH_BIG_ENDIAN },
    { "ppcle",        32, VIR_ARCH_LITTLE_ENDIAN },
    { "ppc64",        64, VIR_ARCH_BIG_ENDIAN },
    { "ppc64le",      64, VIR_ARCH_LITTLE_ENDIAN },
    { "ppcemb",       32, VIR_ARCH_BIG_ENDIAN },

    { "riscv32",      32, VIR_ARCH_LITTLE_ENDIAN },
    { "riscv64",      64, VIR_ARCH_LITTLE_ENDIAN },
    { "s390",         32, VIR_ARCH_BIG_ENDIAN },
    { "s390x",        64, VIR_ARCH_BIG_ENDIAN },
    { "sh4",          32, VIR_ARCH_LITTLE_ENDIAN },

    { "sh4eb",        64, VIR_ARCH_BIG_ENDIAN },
    { "sparc",        32, VIR_ARCH_BIG_ENDIAN },
    { "sparc64",      64, VIR_ARCH_BIG_ENDIAN },
    { "unicore32",    32, VIR_ARCH_LITTLE_ENDIAN },
    { "x86_64",       64, VIR_ARCH_LITTLE_ENDIAN },

    { "xtensa",       32, VIR_ARCH_LITTLE_ENDIAN },
    { "xtensaeb",     32, VIR_ARCH_BIG_ENDIAN },
};

G_STATIC_ASSERT(G_N_ELEMENTS(virArchData) == VIR_ARCH_LAST);


/**
 * virArchGetWordSize:
 * @arch: the CPU architecture
 *
 * Return the wordsize of the CPU architecture (32 or 64)
 */
unsigned int virArchGetWordSize(virArch arch)
{
    if (arch >= VIR_ARCH_LAST)
        arch = VIR_ARCH_NONE;

    return virArchData[arch].wordsize;
}

/**
 * virArchGetEndian:
 * @arch: the CPU architecture
 *
 * Return the endian-ness of the CPU architecture
 * (VIR_ARCH_LITTLE_ENDIAN or VIR_ARCH_BIG_ENDIAN)
 */
virArchEndian virArchGetEndian(virArch arch)
{
    if (arch >= VIR_ARCH_LAST)
        arch = VIR_ARCH_NONE;

    return virArchData[arch].endian;
}

/**
 * virArchToString:
 * @arch: the CPU architecture
 *
 * Return the string name of the architecture
 */
const char *virArchToString(virArch arch)
{
    if (arch >= VIR_ARCH_LAST)
        arch = VIR_ARCH_NONE;

    return virArchData[arch].name;
}


/**
 * virArchFromString:
 * @archstr: the CPU architecture string
 *
 * Return the architecture matching @archstr,
 * defaulting to VIR_ARCH_NONE if unidentified
 */
virArch virArchFromString(const char *archstr)
{
    size_t i;
    for (i = 1; i < VIR_ARCH_LAST; i++) {
        if (STREQ(virArchData[i].name, archstr))
            return i;
    }

    VIR_DEBUG("Unknown arch %s", archstr);
    return VIR_ARCH_NONE;
}


/**
 * virArchFromHost:
 *
 * Return the host architecture. Prefer this to the
 * uname 'machine' field, since this will canonicalize
 * architecture names like 'amd64' into 'x86_64'.
 */
#ifdef WIN32

/*
 * Missing in ming64 headers 6.0.0, but defined as '12' in:
 *
 * https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
 */
# ifndef PROCESSOR_ARCHITECTURE_ARM64
#  define PROCESSOR_ARCHITECTURE_ARM64 12
# endif

virArch virArchFromHost(void)
{
    SYSTEM_INFO info;

    GetSystemInfo(&info);

    switch (info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        return VIR_ARCH_X86_64;
    case PROCESSOR_ARCHITECTURE_IA64:
        return VIR_ARCH_ITANIUM;
    case PROCESSOR_ARCHITECTURE_INTEL:
    case PROCESSOR_ARCHITECTURE_IA32_ON_WIN64:
        return VIR_ARCH_I686;
    case PROCESSOR_ARCHITECTURE_MIPS:
        return VIR_ARCH_MIPS;
    case PROCESSOR_ARCHITECTURE_ALPHA:
        return VIR_ARCH_ALPHA;
    case PROCESSOR_ARCHITECTURE_PPC:
        return VIR_ARCH_PPC;
    case PROCESSOR_ARCHITECTURE_SHX:
        return VIR_ARCH_SH4;
    case PROCESSOR_ARCHITECTURE_ARM:
        return VIR_ARCH_ARMV7L;
    case PROCESSOR_ARCHITECTURE_ARM64:
        return VIR_ARCH_AARCH64;
    default:
        VIR_WARN("Unknown host arch '%d', report to devel@lists.libvirt.org",
                 info.wProcessorArchitecture);
        return VIR_ARCH_NONE;
    }
}
#else /* !WIN32 */
virArch virArchFromHost(void)
{
    struct utsname ut;
    virArch arch;

    uname(&ut);

    /* Some special cases we need to handle first
     * for non-canonical names */
    if (strlen(ut.machine) == 4 &&
        ut.machine[0] == 'i' &&
        ut.machine[2] == '8' &&
        ut.machine[3] == '6' &&
        ut.machine[4] == '\0') {
        arch = VIR_ARCH_I686;
    } else if (STREQ(ut.machine, "amd64")) {
        arch = VIR_ARCH_X86_64;
    } else if (STREQ(ut.machine, "arm64")) {
        arch = VIR_ARCH_AARCH64;
    } else {
        /* Otherwise assume the canonical name */
        if ((arch = virArchFromString(ut.machine)) == VIR_ARCH_NONE) {
            VIR_WARN("Unknown host arch %s, report to devel@lists.libvirt.org",
                     ut.machine);
        }
    }

    VIR_DEBUG("Mapped %s to %d (%s)",
              ut.machine, arch, virArchToString(arch));

    return arch;
}
#endif /* !WIN32 */
