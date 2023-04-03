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
fillStringValues(virDomainCapsStringValues *values, ...)
{
    va_list list;
    const char *str;

    va_start(list, values);
    while ((str = va_arg(list, const char *))) {
        VIR_REALLOC_N(values->values, values->nvalues + 1);
        values->values[values->nvalues] = g_strdup(str);
        values->nvalues++;
    }
    va_end(list);

    return 0;
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
fillQemuCaps(virDomainCaps *domCaps,
             const char *name,
             const char *arch,
             const char *machine,
             virQEMUDriverConfig *cfg)
{
    g_autofree char *path = NULL;
    g_autoptr(virQEMUCaps) qemuCaps = NULL;
    virDomainCapsLoader *loader = &domCaps->os.loader;
    virDomainVirtType virtType;

    if (fakeHostCPU(domCaps->arch) < 0)
        return -1;

    path = g_strdup_printf("%s/%s_%s.xml", TEST_QEMU_CAPS_PATH, name, arch);
    if (!(qemuCaps = qemuTestParseCapabilitiesArch(domCaps->arch, path)))
        return -1;

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
        return -1;

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
                         "/obviously/fake/firmware1.fd",
                         "/obviously/fake/firmware2.fd",
                         NULL) < 0)
        return -1;

    return 0;
}


#endif /* WITH_QEMU */


#ifdef WITH_LIBXL
# include "testutilsxen.h"

static int
fillXenCaps(virDomainCaps *domCaps)
{
    g_autoptr(virFirmware) fw_hvmloader = g_new0(virFirmware, 1);
    g_autoptr(virFirmware) fw_ovmf = g_new0(virFirmware, 1);
    virFirmware *firmwares[] = { fw_hvmloader, fw_ovmf };

    firmwares[0]->name = g_strdup("/usr/lib/xen/boot/hvmloader");
    firmwares[1]->name = g_strdup("/usr/lib/xen/boot/ovmf.bin");

    if (libxlMakeDomainCapabilities(domCaps, firmwares, 2) < 0)
        return -1;

    return 0;
}
#endif /* WITH_LIBXL */

#ifdef WITH_BHYVE
# include "bhyve/bhyve_capabilities.h"

static int
fillBhyveCaps(virDomainCaps *domCaps, unsigned int *bhyve_caps)
{
    g_autofree virDomainCapsStringValues *firmwares = NULL;

    firmwares = g_new0(virDomainCapsStringValues, 1);

    if (fillStringValues(firmwares, "/foo/bar", "/foo/baz", NULL) < 0)
        return -1;

    if (virBhyveDomainCapsFill(domCaps, *bhyve_caps, firmwares) < 0)
        return -1;

    return 0;
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
    g_autoptr(virDomainCaps) domCaps = NULL;
    g_autofree char *path = NULL;
    g_autofree char *domCapsXML = NULL;

    path = g_strdup_printf("%s/domaincapsdata/%s.xml", abs_srcdir, data->name);

    if (!(domCaps = virDomainCapsNew(data->emulator, data->machine,
                                     virArchFromString(data->arch),
                                     data->type)))
        return -1;

    switch (data->capsType) {
    case CAPS_NONE:
        break;

    case CAPS_QEMU:
#if WITH_QEMU
        if (fillQemuCaps(domCaps, data->capsName, data->arch, data->machine,
                         data->capsOpaque) < 0)
            return -1;
#endif
        break;

    case CAPS_LIBXL:
#if WITH_LIBXL
        if (fillXenCaps(domCaps) < 0)
            return -1;
#endif
        break;
    case CAPS_BHYVE:
#if WITH_BHYVE
        if (fillBhyveCaps(domCaps, data->capsOpaque) < 0)
            return -1;
#endif
        break;
    }

    if (!(domCapsXML = virDomainCapsFormat(domCaps)))
        return -1;

    if (virTestCompareToFile(domCapsXML, path) < 0)
        return -1;

    return 0;
}


#if WITH_QEMU

static int
doTestQemuInternal(const char *version,
                   const char *machine,
                   const char *arch,
                   const char *variant,
                   virDomainVirtType type,
                   void *opaque)
{
    g_autofree char *name = NULL;
    g_autofree char *capsName = g_strdup_printf("caps_%s", version);
    g_autofree char *emulator = g_strdup_printf("/usr/bin/qemu-system-%s", arch);
    const char *typestr = NULL;
    g_autofree char *mach = NULL;
    int rc;
    struct testData data = {
        .emulator = emulator,
        .machine = machine,
        .arch = arch,
        .type = type,
        .capsType = CAPS_QEMU,
        .capsName = capsName,
        .capsOpaque = opaque,
    };

    switch ((unsigned int) type) {
    case VIR_DOMAIN_VIRT_QEMU:
        typestr = "-tcg";
        break;

    case VIR_DOMAIN_VIRT_KVM:
        typestr = "";
        break;

    case VIR_DOMAIN_VIRT_HVF:
        typestr = "-hvf";
        break;

    default:
        abort();
        break;
    }

    if (machine)
        mach = g_strdup_printf("-%s", machine);
    else
        mach = g_strdup("");

    data.name = name = g_strdup_printf("qemu_%s%s%s.%s%s",
                                       version, typestr, mach, arch, variant);

    if (STRPREFIX(version, "3.") ||
        STRPREFIX(version, "4.") ||
        STRPREFIX(version, "5.")) {
        g_setenv(TEST_TPM_ENV_VAR, TPM_VER_1_2, true);
    } else if (STRPREFIX(version, "6.")) {
        g_setenv(TEST_TPM_ENV_VAR, TPM_VER_1_2 TPM_VER_2_0, true);
    } else {
        g_setenv(TEST_TPM_ENV_VAR, TPM_VER_2_0, true);
    }

    rc = virTestRun(name, test_virDomainCapsFormat, &data);

    g_unsetenv(TEST_TPM_ENV_VAR);

    if (rc < 0)
        return -1;

    return 0;
}

static int
doTestQemu(const char *inputDir G_GNUC_UNUSED,
           const char *prefix G_GNUC_UNUSED,
           const char *version,
           const char *arch,
           const char *variant,
           const char *suffix G_GNUC_UNUSED,
           void *opaque)
{
    bool hvf = false;
    int ret = 0;

    if (STREQ(variant, "+hvf"))
        hvf = true;
    else if (STRNEQ(variant, ""))
        return 0;

    if (STREQ(arch, "x86_64")) {
        /* For x86_64 based on the test variant we test:
         *
         *   '' (default) variant (KVM):
         *      - KVM with default machine
         *      - KVM with Q35 machine
         *  '+hvf' variant:
         *      - hvf with default machine
         *
         *   - TCG with default machine
         */
        if (hvf) {
            if (doTestQemuInternal(version, NULL, arch, variant,
                                   VIR_DOMAIN_VIRT_HVF, opaque) < 0)
                ret = -1;
        } else {
            if (doTestQemuInternal(version, NULL, arch, variant,
                                   VIR_DOMAIN_VIRT_KVM, opaque) < 0)
                ret = -1;

            if (doTestQemuInternal(version, "q35", arch, variant,
                                   VIR_DOMAIN_VIRT_KVM, opaque) < 0)
                ret = -1;
        }

        if (doTestQemuInternal(version, NULL, arch, variant,
                               VIR_DOMAIN_VIRT_QEMU, opaque) < 0)
            ret = -1;
    } else if (STREQ(arch, "aarch64")) {
        /* For aarch64 based on the test variant we test:
         *
         *   '' (default) variant (KVM):
         *      - KVM with default machine
         *      - KVM with virt machine
         *
         *  '+hvf' variant:
         *    - hvf with default machine
         */
        if (hvf) {
            if (doTestQemuInternal(version, NULL, arch, variant,
                                   VIR_DOMAIN_VIRT_HVF, opaque) < 0)
                ret = -1;
        } else {
            if (doTestQemuInternal(version, NULL, arch, variant,
                                   VIR_DOMAIN_VIRT_KVM, opaque) < 0)
                ret = -1;

            if (doTestQemuInternal(version, "virt", arch, variant,
                                   VIR_DOMAIN_VIRT_KVM, opaque) < 0)
                ret = -1;
        }
    } else if (STRPREFIX(arch, "riscv")) {
        /* For riscv64 we test two combinations:
         *
         *   - KVM with virt machine
         *   - TCG with virt machine
         */
        if (doTestQemuInternal(version, "virt", arch, variant,
                               VIR_DOMAIN_VIRT_KVM, opaque) < 0)
            ret = -1;

        if (doTestQemuInternal(version, "virt", arch, variant,
                               VIR_DOMAIN_VIRT_QEMU, opaque) < 0)
            ret = -1;
    } else {
        if (doTestQemuInternal(version, NULL, arch, variant,
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
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverConfigNew(false, NULL);

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
        g_autofree char *name = NULL; \
        struct testData data; \
        name = g_strdup_printf("bhyve_%s.x86_64", Name); \
        data = (struct testData) { \
            .name = name, \
            .emulator = Emulator, \
            .arch = "x86_64", \
            .type = Type, \
            .capsType = CAPS_BHYVE, \
            .capsOpaque = BhyveCaps, \
        }; \
        if (virTestRun(name, test_virDomainCapsFormat, &data) < 0) \
            ret = -1; \
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
     * VIR_TEST_REGENERATE_OUTPUT=1 tests/qemucapabilitiesnumbering
     * to fix the replies ids.
     *
     * Once a replies file has been generated and tweaked if necessary,
     * you can drop it into tests/qemucapabilitiesdata/ (with a sensible
     * name - look at what's already there for inspiration) and test
     * programs will automatically pick it up.
     *
     * To generate the corresponding output files after a new replies
     * file has been added, run "VIR_TEST_REGENERATE_OUTPUT=1 ninja test".
     */

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

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

#if WITH_QEMU
VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("domaincaps"),
                      VIR_TEST_MOCK("qemucpu"))
#else
VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("domaincaps"))
#endif
