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
static int G_GNUC_NULL_TERMINATED
fillStringValues(virDomainCapsStringValuesPtr values, ...)
{
    int ret = 0;
    va_list list;
    const char *str;

    va_start(list, values);
    while ((str = va_arg(list, const char *))) {
        if (VIR_REALLOC_N(values->values, values->nvalues + 1) < 0) {
            ret = -1;
            break;
        }
        values->values[values->nvalues] = g_strdup(str);
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
fakeHostCPU(virArch arch)
{
    g_autoptr(virCPUDef) cpu = NULL;

    if (!(cpu = testUtilsHostCpusGetDefForArch(arch))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "cannot fake host CPU for arch %s",
                       virArchToString(arch));
        return -1;
    }

    qemuTestSetHostCPU(NULL, arch, cpu);

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
    virQEMUCapsPtr qemuCaps = NULL;
    virDomainCapsLoaderPtr loader = &domCaps->os.loader;
    virDomainVirtType virtType;

    if (fakeHostCPU(domCaps->arch) < 0)
        goto cleanup;

    path = g_strdup_printf("%s/%s.%s.xml", TEST_QEMU_CAPS_PATH, name, arch);
    if (!(qemuCaps = qemuTestParseCapabilitiesArch(domCaps->arch, path)))
        goto cleanup;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_KVM))
        virtType = VIR_DOMAIN_VIRT_KVM;
    else
        virtType = VIR_DOMAIN_VIRT_QEMU;

    if (machine) {
        VIR_FREE(domCaps->machine);
        domCaps->machine = g_strdup(virQEMUCapsGetCanonicalMachine(qemuCaps, virtType, machine));
    }

    if (!domCaps->machine)
        domCaps->machine = g_strdup(virQEMUCapsGetPreferredMachine(qemuCaps, virtType));

    if (virQEMUCapsFillDomainCaps(qemuCaps, domCaps->arch, domCaps,
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
    firmwares[0]->name = g_strdup("/usr/lib/xen/boot/hvmloader");
    firmwares[1]->name = g_strdup("/usr/lib/xen/boot/ovmf.bin");

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

    path = g_strdup_printf("%s/domaincapsdata/%s.xml", abs_srcdir, data->name);

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


#if WITH_QEMU

static int
doTestQemuInternal(const char *version,
                   const char *machine,
                   const char *arch,
                   virDomainVirtType type,
                   void *opaque)
{
    g_autofree char *name = NULL;
    g_autofree char *capsName = NULL;
    g_autofree char *emulator = NULL;

    name = g_strdup_printf("qemu_%s%s%s%s.%s",
                           version,
                           (type == VIR_DOMAIN_VIRT_QEMU ? "-tcg" : ""),
                           (machine ? "-" : ""), (machine ? machine : ""),
                           arch);
    capsName = g_strdup_printf("caps_%s", version);
    emulator = g_strdup_printf("/usr/bin/qemu-system-%s", arch);

    VIR_WARNINGS_NO_DECLARATION_AFTER_STATEMENT
    struct testData data = {
        .name = name,
        .emulator = emulator,
        .machine = machine,
        .arch = arch,
        .type = type,
        .capsType = CAPS_QEMU,
        .capsName = capsName,
        .capsOpaque = opaque,
    };
    VIR_WARNINGS_RESET

    if (virTestRun(name, test_virDomainCapsFormat, &data) < 0)
        return -1;

    return 0;
}

static int
doTestQemu(const char *inputDir G_GNUC_UNUSED,
           const char *prefix G_GNUC_UNUSED,
           const char *version,
           const char *arch,
           const char *suffix G_GNUC_UNUSED,
           void *opaque)
{
    int ret = 0;

    if (STREQ(arch, "x86_64")) {
        /* For x86_64 we test three combinations:
         *
         *   - KVM with default machine
         *   - KVM with Q35 machine
         *   - TCG with default machine
         */
        if (doTestQemuInternal(version, NULL, arch,
                               VIR_DOMAIN_VIRT_KVM, opaque) < 0)
            ret = -1;

        if (doTestQemuInternal(version, "q35", arch,
                               VIR_DOMAIN_VIRT_KVM, opaque) < 0)
            ret = -1;

        if (doTestQemuInternal(version, NULL, arch,
                               VIR_DOMAIN_VIRT_QEMU, opaque) < 0)
            ret = -1;
    } else if (STREQ(arch, "aarch64")) {
        /* For aarch64 we test two combinations:
         *
         *   - KVM with default machine
         *   - KVM with virt machine
         */
        if (doTestQemuInternal(version, NULL, arch,
                               VIR_DOMAIN_VIRT_KVM, opaque) < 0)
            ret = -1;

        if (doTestQemuInternal(version, "virt", arch,
                               VIR_DOMAIN_VIRT_KVM, opaque) < 0)
            ret = -1;
    } else if (STRPREFIX(arch, "riscv")) {
        /* Unfortunately we have to skip RISC-V at the moment */
        return 0;
    } else {
        if (doTestQemuInternal(version, NULL, arch,
                               VIR_DOMAIN_VIRT_KVM, opaque) < 0)
            ret = -1;
    }

    return ret;
}

#endif

static int
mymain(void)
{
    int ret = 0;

#if WITH_BHYVE
    unsigned int bhyve_caps = 0;
#endif

#if WITH_QEMU
    virQEMUDriverConfigPtr cfg = virQEMUDriverConfigNew(false, NULL);

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
        name = g_strdup_printf("bhyve_%s.x86_64", Name); \
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

    if (testQemuCapsIterate(".xml", doTestQemu, cfg) < 0)
        ret = -1;

    /*
     * Run "tests/qemucapsprobe /path/to/qemu/binary >foo.replies"
     * to generate updated or new *.replies data files.
     *
     * If you manually edit replies files you can run
     * "tests/qemucapsfixreplies foo.replies" to fix the replies ids.
     *
     * Once a replies file has been generated and tweaked if necessary,
     * you can drop it into tests/qemucapabilitiesdata/ (with a sensible
     * name - look at what's already there for inspiration) and test
     * programs will automatically pick it up.
     *
     * To generate the corresponding output files after a new replies
     * file has been added, run "VIR_TEST_REGENERATE_OUTPUT=1 ninja test".
     */

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
                      VIR_TEST_MOCK("domaincaps"),
                      VIR_TEST_MOCK("qemucpu"))
#else
VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("domaincaps"))
#endif
