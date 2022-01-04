/*
 * Copyright (C) IBM Corp 2014
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

#include "testutils.h"
#include "testutilslxc.h"
#include "testutilsqemu.h"
#include "capabilities.h"
#include "virbitmap.h"


#define VIR_FROM_THIS VIR_FROM_NONE


static int
test_virCapabilitiesGetCpusForNodemask(const void *data G_GNUC_UNUSED)
{
    const char *nodestr = "3,4,5,6";
    g_autoptr(virBitmap) nodemask = NULL;
    g_autoptr(virBitmap) cpumap = NULL;
    g_autoptr(virCapsHostNUMA) caps = NULL;
    int mask_size = 8;

    if (!(caps = virTestCapsBuildNUMATopology(3)))
        return -1;

    if (virBitmapParse(nodestr, &nodemask, mask_size) < 0)
        return -1;

    if (!(cpumap = virCapabilitiesHostNUMAGetCpus(caps, nodemask)))
        return -1;

    return 0;
}


static bool G_GNUC_UNUSED
doCapsExpectFailure(virCaps *caps,
                    int ostype,
                    virArch arch,
                    int domaintype,
                    const char *emulator,
                    const char *machinetype)
{
    virCapsDomainData *data = virCapabilitiesDomainDataLookup(caps, ostype,
        arch, domaintype, emulator, machinetype);

    if (data) {
        VIR_FREE(data);
        return false;
    }

    return true;
}

static bool G_GNUC_UNUSED
doCapsCompare(virCaps *caps,
              int ostype,
              virArch arch,
              int domaintype,
              const char *emulator,
              const char *machinetype,
              int expect_ostype,
              virArch expect_arch,
              int expect_domaintype,
              const char *expect_emulator,
              const char *expect_machinetype)
{
    bool ret = false;
    virCapsDomainData *data = virCapabilitiesDomainDataLookup(caps, ostype,
        arch, domaintype, emulator, machinetype);

    if (!data)
        goto error;

    if (data->ostype != expect_ostype) {
        fprintf(stderr, "data->ostype=%s doesn't match expect_ostype=%s\n",
                virDomainOSTypeToString(data->ostype),
                virDomainOSTypeToString(expect_ostype));
        goto error;
    }

    if (data->arch != expect_arch) {
        fprintf(stderr, "data->arch=%s doesn't match expect_arch=%s\n",
                virArchToString(data->arch),
                virArchToString(expect_arch));
        goto error;
    }

    if (data->domaintype != expect_domaintype) {
        fprintf(stderr, "data->domaintype=%s doesn't match "
                "expect_domaintype=%s\n",
                virDomainVirtTypeToString(data->domaintype),
                virDomainVirtTypeToString(expect_domaintype));
        goto error;
    }

    if (STRNEQ(data->emulator, expect_emulator)) {
        fprintf(stderr, "data->emulator=%s doesn't match expect_emulator=%s\n",
                data->emulator, expect_emulator);
        goto error;
    }

    if (STRNEQ_NULLABLE(data->machinetype, expect_machinetype)) {
        fprintf(stderr, "data->machinetype=%s doesn't match "
                "expect_machinetype=%s\n",
                NULLSTR(data->machinetype), NULLSTR(expect_machinetype));
        goto error;
    }

    ret = true;
 error:
    VIR_FREE(data);
    return ret;
}

#define CAPSCOMP(o, a, d, e, m, fo, fa, fd, fe, fm) \
    if (!doCapsCompare(caps, o, a, d, e, m, fo, fa, fd, fe, fm)) \
        ret = -1;

#define CAPS_EXPECT_ERR(o, a, d, e, m) \
    if (!doCapsExpectFailure(caps, o, a, d, e, m)) \
        ret = -1;

#ifdef WITH_QEMU
static int
test_virCapsDomainDataLookupQEMU(const void *data G_GNUC_UNUSED)
{
    int ret = 0;
    g_autoptr(virCaps) caps = NULL;

    if (!(caps = testQemuCapsInit()))
        return -1;

    /* Checking each parameter individually */
    CAPSCOMP(-1, VIR_ARCH_NONE, VIR_DOMAIN_VIRT_NONE, NULL, NULL,
        VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_X86_64,
        VIR_DOMAIN_VIRT_QEMU, "/usr/bin/qemu-system-x86_64", "pc");
    CAPSCOMP(VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_NONE, VIR_DOMAIN_VIRT_NONE, NULL, NULL,
        VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_X86_64,
        VIR_DOMAIN_VIRT_QEMU, "/usr/bin/qemu-system-x86_64", "pc");
    CAPSCOMP(-1, VIR_ARCH_AARCH64, VIR_DOMAIN_VIRT_NONE, NULL, NULL,
        VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_AARCH64,
        VIR_DOMAIN_VIRT_QEMU, "/usr/bin/qemu-system-aarch64", "virt");
    CAPSCOMP(-1, VIR_ARCH_NONE, VIR_DOMAIN_VIRT_KVM, NULL, NULL,
        VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_X86_64,
        VIR_DOMAIN_VIRT_KVM, "/usr/bin/qemu-system-x86_64", "pc");
    CAPSCOMP(-1, VIR_ARCH_NONE, VIR_DOMAIN_VIRT_NONE, "/usr/bin/qemu-system-ppc64", NULL,
        VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_PPC64,
        VIR_DOMAIN_VIRT_QEMU, "/usr/bin/qemu-system-ppc64", "pseries");

    CAPSCOMP(-1, VIR_ARCH_NONE, VIR_DOMAIN_VIRT_NONE, NULL, "pseries",
        VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_PPC64,
        VIR_DOMAIN_VIRT_QEMU, "/usr/bin/qemu-system-ppc64", "pseries");
    CAPSCOMP(-1, VIR_ARCH_PPC64LE, VIR_DOMAIN_VIRT_NONE, NULL, "pseries",
        VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_PPC64LE,
        VIR_DOMAIN_VIRT_QEMU, "/usr/bin/qemu-system-ppc64", "pseries");

    CAPS_EXPECT_ERR(VIR_DOMAIN_OSTYPE_LINUX, VIR_ARCH_NONE, VIR_DOMAIN_VIRT_NONE, NULL, NULL);
    CAPS_EXPECT_ERR(-1, VIR_ARCH_PPC64LE, VIR_DOMAIN_VIRT_NONE, NULL, "pc");
    CAPS_EXPECT_ERR(-1, VIR_ARCH_MIPS, VIR_DOMAIN_VIRT_NONE, NULL, NULL);
    CAPS_EXPECT_ERR(-1, VIR_ARCH_NONE, VIR_DOMAIN_VIRT_NONE,
        "/usr/bin/qemu-system-aarch64", "pc");
    CAPS_EXPECT_ERR(-1, VIR_ARCH_NONE, VIR_DOMAIN_VIRT_VMWARE, NULL, "pc");

    return ret;
}
#endif /* WITH_QEMU */

#ifdef WITH_LXC
static int
test_virCapsDomainDataLookupLXC(const void *data G_GNUC_UNUSED)
{
    int ret = 0;
    g_autoptr(virCaps) caps = NULL;

    if (!(caps = testLXCCapsInit()))
        return -1;

    CAPSCOMP(-1, VIR_ARCH_NONE, VIR_DOMAIN_VIRT_NONE, NULL, NULL,
        VIR_DOMAIN_OSTYPE_EXE, VIR_ARCH_X86_64,
        VIR_DOMAIN_VIRT_LXC, "/usr/libexec/libvirt_lxc", NULL);
    CAPSCOMP(-1, VIR_ARCH_X86_64, VIR_DOMAIN_VIRT_NONE, NULL, NULL,
        VIR_DOMAIN_OSTYPE_EXE, VIR_ARCH_X86_64,
        VIR_DOMAIN_VIRT_LXC, "/usr/libexec/libvirt_lxc", NULL);

    return ret;
}
#endif /* WITH_LXC */

static int
mymain(void)
{
    int ret = 0;

    if (virTestRun("virCapabilitiesGetCpusForNodemask",
                   test_virCapabilitiesGetCpusForNodemask, NULL) < 0)
        ret = -1;
#ifdef WITH_QEMU
    if (virTestRun("virCapsDomainDataLookupQEMU",
                   test_virCapsDomainDataLookupQEMU, NULL) < 0)
        ret = -1;
#endif
#ifdef WITH_LXC
    if (virTestRun("virCapsDomainDataLookupLXC",
                   test_virCapsDomainDataLookupLXC, NULL) < 0)
        ret = -1;
#endif /* WITH_LXC */

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
