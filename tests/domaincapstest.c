/*
 * Copyright (C) Red Hat, Inc. 2014
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

#include "testutils.h"
#include "domain_capabilities.h"
#include "virfilewrapper.h"
#include "configmake.h"


#define VIR_FROM_THIS VIR_FROM_NONE

#if WITH_QEMU || WITH_BHYVE
static int ATTRIBUTE_SENTINEL
fillStringValues(virDomainCapsStringValuesPtr values, ...)
{
    int ret = 0;
    va_list list;
    const char *str;

    va_start(list, values);
    while ((str = va_arg(list, const char *))) {
        if (VIR_REALLOC_N(values->values, values->nvalues + 1) < 0 ||
            VIR_STRDUP(values->values[values->nvalues], str) < 0) {
            ret = -1;
            break;
        }
        values->nvalues++;
    }
    va_end(list);

    return ret;
}
#endif /* WITH_QEMU || WITH_BHYVE */

#if WITH_QEMU
# include "testutilsqemu.h"
# include "testutilshostcpus.h"

static int
fakeHostCPU(virCapsPtr caps,
            virArch arch)
{
    virCPUDefPtr cpu;

    if (!(cpu = testUtilsHostCpusGetDefForArch(arch))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "cannot fake host CPU for arch %s",
                       virArchToString(arch));
        return -1;
    }

    qemuTestSetHostCPU(caps, cpu);

    return 0;
}

static int
fillQemuCaps(virDomainCapsPtr domCaps,
             const char *name,
             const char *arch,
             const char *machine,
             virQEMUDriverConfigPtr cfg)
{
    int ret = -1;
    char *path = NULL;
    virCapsPtr caps = NULL;
    virQEMUCapsPtr qemuCaps = NULL;
    virDomainCapsLoaderPtr loader = &domCaps->os.loader;

    if (!(caps = virCapabilitiesNew(domCaps->arch, false, false)) ||
        fakeHostCPU(caps, domCaps->arch) < 0)
        goto cleanup;

    if (virAsprintf(&path, "%s/%s.%s.xml",
                    TEST_QEMU_CAPS_PATH, name, arch) < 0 ||
        !(qemuCaps = qemuTestParseCapabilities(caps, path)))
        goto cleanup;

    if (machine) {
        VIR_FREE(domCaps->machine);
        if (VIR_STRDUP(domCaps->machine,
                       virQEMUCapsGetCanonicalMachine(qemuCaps, machine)) < 0)
            goto cleanup;
    }

    if (!domCaps->machine &&
        VIR_STRDUP(domCaps->machine,
                   virQEMUCapsGetPreferredMachine(qemuCaps)) < 0)
        goto cleanup;

    if (virQEMUCapsFillDomainCaps(caps, domCaps, qemuCaps,
                                  false,
                                  cfg->firmwares,
                                  cfg->nfirmwares) < 0)
        goto cleanup;

    /* The function above tries to query host's VFIO capabilities by calling
     * qemuHostdevHostSupportsPassthroughVFIO() which, however, can't be
     * successfully mocked as they are not exposed as internal APIs. Therefore,
     * instead of mocking set the expected values here by hand. */
    VIR_DOMAIN_CAPS_ENUM_SET(domCaps->hostdev.pciBackend,
                             VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT,
                             VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO);

    /* As of f05b6a918e28 we are expecting to see OVMF_CODE.fd file which
     * may not exists everywhere. */
    while (loader->values.nvalues)
        VIR_FREE(loader->values.values[--loader->values.nvalues]);

    if (fillStringValues(&loader->values,
                         "/usr/share/AAVMF/AAVMF_CODE.fd",
                         "/usr/share/AAVMF/AAVMF32_CODE.fd",
                         "/usr/share/OVMF/OVMF_CODE.fd",
                         NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virObjectUnref(caps);
    virObjectUnref(qemuCaps);
    VIR_FREE(path);
    return ret;
}
#endif /* WITH_QEMU */


#ifdef WITH_LIBXL
# include "testutilsxen.h"

static int
fillXenCaps(virDomainCapsPtr domCaps)
{
    virFirmwarePtr *firmwares;
    int ret = -1;

    if (VIR_ALLOC_N(firmwares, 2) < 0)
        return ret;

    if (VIR_ALLOC(firmwares[0]) < 0 || VIR_ALLOC(firmwares[1]) < 0)
        goto cleanup;
    if (VIR_STRDUP(firmwares[0]->name, "/usr/lib/xen/boot/hvmloader") < 0 ||
        VIR_STRDUP(firmwares[1]->name, "/usr/lib/xen/boot/ovmf.bin") < 0)
        goto cleanup;

    if (libxlMakeDomainCapabilities(domCaps, firmwares, 2) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virFirmwareFreeList(firmwares, 2);
    return ret;
}
#endif /* WITH_LIBXL */

#ifdef WITH_BHYVE
# include "bhyve/bhyve_capabilities.h"

static int
fillBhyveCaps(virDomainCapsPtr domCaps, unsigned int *bhyve_caps)
{
    virDomainCapsStringValuesPtr firmwares = NULL;
    int ret = -1;

    if (VIR_ALLOC(firmwares) < 0)
        return -1;

    if (fillStringValues(firmwares, "/foo/bar", "/foo/baz", NULL) < 0)
        goto cleanup;

    if (virBhyveDomainCapsFill(domCaps, *bhyve_caps, firmwares) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(firmwares);
    return ret;
}
#endif /* WITH_BHYVE */

enum testCapsType {
    CAPS_NONE,
    CAPS_QEMU,
    CAPS_LIBXL,
    CAPS_BHYVE,
};

struct testData {
    const char *name;
    const char *emulator;
    const char *machine;
    const char *arch;
    virDomainVirtType type;
    enum testCapsType capsType;
    const char *capsName;
    void *capsOpaque;
};

static int
test_virDomainCapsFormat(const void *opaque)
{
    const struct testData *data = opaque;
    virDomainCapsPtr domCaps = NULL;
    char *path = NULL;
    char *domCapsXML = NULL;
    int ret = -1;

    if (virAsprintf(&path, "%s/domaincapsschemadata/%s.xml",
                    abs_srcdir, data->name) < 0)
        goto cleanup;

    if (!(domCaps = virDomainCapsNew(data->emulator, data->machine,
                                     virArchFromString(data->arch),
                                     data->type)))
        goto cleanup;

    switch (data->capsType) {
    case CAPS_NONE:
        break;

    case CAPS_QEMU:
#if WITH_QEMU
        if (fillQemuCaps(domCaps, data->capsName, data->arch, data->machine,
                         data->capsOpaque) < 0)
            goto cleanup;
#endif
        break;

    case CAPS_LIBXL:
#if WITH_LIBXL
        if (fillXenCaps(domCaps) < 0)
            goto cleanup;
#endif
        break;
    case CAPS_BHYVE:
#if WITH_BHYVE
        if (fillBhyveCaps(domCaps, data->capsOpaque) < 0)
            goto cleanup;
#endif
        break;
    }

    if (!(domCapsXML = virDomainCapsFormat(domCaps)))
        goto cleanup;

    if (virTestCompareToFile(domCapsXML, path) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(domCapsXML);
    VIR_FREE(path);
    virObjectUnref(domCaps);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

#if WITH_BHYVE
    unsigned int bhyve_caps = 0;
#endif

#if WITH_QEMU
    virQEMUDriverConfigPtr cfg = virQEMUDriverConfigNew(false);

    if (!cfg)
        return EXIT_FAILURE;
#endif

#define DO_TEST(Name, Emulator, Machine, Arch, Type, CapsType) \
    do { \
        struct testData data = { \
            .name = Name, \
            .emulator = Emulator, \
            .machine = Machine, \
            .arch = Arch, \
            .type = Type, \
            .capsType = CapsType, \
        }; \
        if (virTestRun(Name, test_virDomainCapsFormat, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_QEMU(Name, CapsName, Emulator, Machine, Arch, Type) \
    do { \
        char *name = NULL; \
        if (virAsprintf(&name, "qemu_%s%s%s.%s", \
                        Name, \
                        Machine ? "-" : "", Machine ? Machine : "", \
                        Arch) < 0) { \
            ret = -1; \
            break; \
        } \
        struct testData data = { \
            .name = name, \
            .emulator = Emulator, \
            .machine = Machine, \
            .arch = Arch, \
            .type = Type, \
            .capsType = CAPS_QEMU, \
            .capsName = CapsName, \
            .capsOpaque = cfg, \
        }; \
        if (virTestRun(name, test_virDomainCapsFormat, &data) < 0) \
            ret = -1; \
        VIR_FREE(name); \
    } while (0)

#define DO_TEST_LIBXL(Name, Emulator, Machine, Arch, Type) \
    do { \
        struct testData data = { \
            .name = Name, \
            .emulator = Emulator, \
            .machine = Machine, \
            .arch = Arch, \
            .type = Type, \
            .capsType = CAPS_LIBXL, \
        }; \
        if (virTestRun(Name, test_virDomainCapsFormat, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_BHYVE(Name, Emulator, BhyveCaps, Type) \
    do { \
        char *name = NULL; \
        if (virAsprintf(&name, "bhyve_%s.x86_64", Name) < 0) { \
             ret = -1; \
             break; \
        } \
        struct testData data = { \
            .name = name, \
            .emulator = Emulator, \
            .arch = "x86_64", \
            .type = Type, \
            .capsType = CAPS_BHYVE, \
            .capsOpaque = BhyveCaps, \
        }; \
        if (virTestRun(name, test_virDomainCapsFormat, &data) < 0) \
            ret = -1; \
        VIR_FREE(name); \
    } while (0)

    DO_TEST("empty", "/bin/emulatorbin", "my-machine-type",
            "x86_64", VIR_DOMAIN_VIRT_KVM, CAPS_NONE);

#if WITH_QEMU

    virFileWrapperAddPrefix(SYSCONFDIR "/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/etc/qemu/firmware");
    virFileWrapperAddPrefix(PREFIX "/share/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/usr/share/qemu/firmware");
    virFileWrapperAddPrefix("/home/user/.config/qemu/firmware",
                            abs_srcdir "/qemufirmwaredata/home/user/.config/qemu/firmware");

    DO_TEST_QEMU("1.7.0", "caps_1.7.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.6.0", "caps_2.6.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.8.0", "caps_2.8.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.8.0-tcg", "caps_2.8.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_QEMU);

    DO_TEST_QEMU("2.9.0", "caps_2.9.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.9.0", "caps_2.9.0",
                 "/usr/bin/qemu-system-x86_64", "q35",
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.9.0-tcg", "caps_2.9.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_QEMU);

    DO_TEST_QEMU("2.12.0", "caps_2.12.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.6.0", "caps_2.6.0",
                 "/usr/bin/qemu-system-aarch64", NULL,
                 "aarch64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.6.0", "caps_2.6.0",
                 "/usr/bin/qemu-system-aarch64", "virt",
                 "aarch64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.12.0", "caps_2.12.0",
                 "/usr/bin/qemu-system-aarch64", "virt",
                 "aarch64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.6.0", "caps_2.6.0",
                 "/usr/bin/qemu-system-ppc64", NULL,
                 "ppc64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.12.0", "caps_2.12.0",
                 "/usr/bin/qemu-system-ppc64", NULL,
                 "ppc64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.7.0", "caps_2.7.0",
                 "/usr/bin/qemu-system-s390x", NULL,
                 "s390x", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.8.0", "caps_2.8.0",
                 "/usr/bin/qemu-system-s390x", NULL,
                 "s390x", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.12.0", "caps_2.12.0",
                 "/usr/bin/qemu-system-s390x", NULL,
                 "s390x", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("3.0.0", "caps_3.0.0",
                 "/usr/bin/qemu-system-s390x", NULL,
                 "s390x", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("3.1.0", "caps_3.1.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("4.0.0", "caps_4.0.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("4.0.0", "caps_4.0.0",
                 "/usr/bin/qemu-system-s390x", NULL,
                 "s390x", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("4.1.0", "caps_4.1.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    virObjectUnref(cfg);

    virFileWrapperClearPrefixes();

#endif /* WITH_QEMU */

#if WITH_LIBXL

    DO_TEST_LIBXL("libxl-xenpv", "/usr/bin/qemu-system-x86_64",
                  "xenpv", "x86_64", VIR_DOMAIN_VIRT_XEN);
    DO_TEST_LIBXL("libxl-xenfv", "/usr/bin/qemu-system-x86_64",
                  "xenfv", "x86_64", VIR_DOMAIN_VIRT_XEN);

#endif /* WITH_LIBXL */

#if WITH_BHYVE
    DO_TEST_BHYVE("basic", "/usr/sbin/bhyve", &bhyve_caps, VIR_DOMAIN_VIRT_BHYVE);

    bhyve_caps |= BHYVE_CAP_LPC_BOOTROM;
    DO_TEST_BHYVE("uefi", "/usr/sbin/bhyve", &bhyve_caps, VIR_DOMAIN_VIRT_BHYVE);

    bhyve_caps |= BHYVE_CAP_FBUF;
    DO_TEST_BHYVE("fbuf", "/usr/sbin/bhyve", &bhyve_caps, VIR_DOMAIN_VIRT_BHYVE);
#endif /* WITH_BHYVE */

    return ret;
}

#if WITH_QEMU
VIR_TEST_MAIN_PRELOAD(mymain,
                       abs_builddir "/.libs/domaincapsmock.so",
                       abs_builddir "/.libs/qemucpumock.so")
#else
VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/domaincapsmock.so")
#endif
