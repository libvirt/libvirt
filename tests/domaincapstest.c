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
 *
 * Authors:
 *      Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>
#include <stdlib.h>

#include "testutils.h"
#include "domain_capabilities.h"


#define VIR_FROM_THIS VIR_FROM_NONE

typedef int (*virDomainCapsFill)(virDomainCapsPtr domCaps,
                                 void *opaque);

#define SET_ALL_BITS(x) \
    memset(&(x.values), 0xff, sizeof(x.values))

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

static int
fillAllCaps(virDomainCapsPtr domCaps)
{
    virDomainCapsOSPtr os = &domCaps->os;
    virDomainCapsLoaderPtr loader = &os->loader;
    virDomainCapsCPUPtr cpu = &domCaps->cpu;
    virDomainCapsDeviceDiskPtr disk = &domCaps->disk;
    virDomainCapsDeviceGraphicsPtr graphics = &domCaps->graphics;
    virDomainCapsDeviceVideoPtr video = &domCaps->video;
    virDomainCapsDeviceHostdevPtr hostdev = &domCaps->hostdev;
    virCPUDef host = {
        .type = VIR_CPU_TYPE_HOST,
        .arch = VIR_ARCH_X86_64,
        .model = (char *) "host",
        .vendor = (char *) "CPU Vendorrr",
    };

    domCaps->maxvcpus = 255;
    os->supported = true;

    loader->supported = true;
    SET_ALL_BITS(loader->type);
    SET_ALL_BITS(loader->readonly);
    if (fillStringValues(&loader->values,
                         "/foo/bar",
                         "/tmp/my_path",
                         NULL) < 0)
        return -1;

    cpu->hostPassthrough = true;
    cpu->hostModel = virCPUDefCopy(&host);
    if (!(cpu->custom = virDomainCapsCPUModelsNew(3)) ||
        virDomainCapsCPUModelsAdd(cpu->custom, "Model1", -1,
                                  VIR_DOMCAPS_CPU_USABLE_UNKNOWN) < 0 ||
        virDomainCapsCPUModelsAdd(cpu->custom, "Model2", -1,
                                  VIR_DOMCAPS_CPU_USABLE_NO) < 0 ||
        virDomainCapsCPUModelsAdd(cpu->custom, "Model3", -1,
                                  VIR_DOMCAPS_CPU_USABLE_YES) < 0)
        return -1;

    disk->supported = true;
    SET_ALL_BITS(disk->diskDevice);
    SET_ALL_BITS(disk->bus);

    graphics->supported = true;
    SET_ALL_BITS(graphics->type);

    video->supported = true;
    SET_ALL_BITS(video->modelType);

    hostdev->supported = true;
    SET_ALL_BITS(hostdev->mode);
    SET_ALL_BITS(hostdev->startupPolicy);
    SET_ALL_BITS(hostdev->subsysType);
    SET_ALL_BITS(hostdev->capsType);
    SET_ALL_BITS(hostdev->pciBackend);
    return 0;
}


#if WITH_QEMU
# include "testutilsqemu.h"

static virCPUDef aarch64Cpu = {
    .sockets = 1,
    .cores = 1,
    .threads = 1,
};

static virCPUDef ppc64leCpu = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_PPC64LE,
    .model = (char *) "POWER8",
    .sockets = 1,
    .cores = 1,
    .threads = 1,
};

static virCPUDef x86Cpu = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_X86_64,
    .model = (char *) "Broadwell",
    .sockets = 1,
    .cores = 1,
    .threads = 1,
};

static virCPUDef s390Cpu = {
    .type = VIR_CPU_TYPE_HOST,
    .arch = VIR_ARCH_S390X,
    .sockets = 1,
    .cores = 1,
    .threads = 1,
};

static int
fakeHostCPU(virCapsPtr caps,
            virArch arch)
{
    virCPUDefPtr cpu;

    switch (arch) {
    case VIR_ARCH_AARCH64:
        cpu = &aarch64Cpu;
        break;

    case VIR_ARCH_PPC64LE:
        cpu = &ppc64leCpu;
        break;

    case VIR_ARCH_X86_64:
        cpu = &x86Cpu;
        break;

    case VIR_ARCH_S390X:
        cpu = &s390Cpu;
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "cannot fake host CPU for arch %s",
                       virArchToString(arch));
        return -1;
    }

    if (!(caps->host.cpu = virCPUDefCopy(cpu)))
        return -1;

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

    if (virAsprintf(&path, "%s/qemucapabilitiesdata/%s.%s.xml",
                    abs_srcdir, name, arch) < 0 ||
        !(qemuCaps = qemuTestParseCapabilities(caps, path)))
        goto cleanup;

    if (machine &&
        VIR_STRDUP(domCaps->machine,
                   virQEMUCapsGetCanonicalMachine(qemuCaps, machine)) < 0)
        goto cleanup;

    if (!domCaps->machine &&
        VIR_STRDUP(domCaps->machine,
                   virQEMUCapsGetDefaultMachine(qemuCaps)) < 0)
        goto cleanup;

    if (virQEMUCapsFillDomainCaps(caps, domCaps, qemuCaps,
                                  cfg->firmwares,
                                  cfg->nfirmwares) < 0)
        goto cleanup;

    /* The function above tries to query host's KVM & VFIO capabilities by
     * calling qemuHostdevHostSupportsPassthroughLegacy() and
     * qemuHostdevHostSupportsPassthroughVFIO() which, however, can't be
     * successfully mocked as they are not exposed as internal APIs. Therefore,
     * instead of mocking set the expected values here by hand. */
    VIR_DOMAIN_CAPS_ENUM_SET(domCaps->hostdev.pciBackend,
                             VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT,
                             VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM,
                             VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO);

    /* As of f05b6a918e28 we are expecting to see OVMF_CODE.fd file which
     * may not exists everywhere. */
    while (loader->values.nvalues)
        VIR_FREE(loader->values.values[--loader->values.nvalues]);

    if (fillStringValues(&loader->values,
                         "/usr/share/AAVMF/AAVMF_CODE.fd",
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
    CAPS_ALL,
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

    case CAPS_ALL:
        if (fillAllCaps(domCaps) < 0)
            goto cleanup;
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

#define DO_TEST(Name, Emulator, Machine, Arch, Type, CapsType)          \
    do {                                                                \
        struct testData data = {                                        \
            .name = Name,                                               \
            .emulator = Emulator,                                       \
            .machine = Machine,                                         \
            .arch = Arch,                                               \
            .type = Type,                                               \
            .capsType = CapsType,                                       \
        };                                                              \
        if (virTestRun(Name, test_virDomainCapsFormat, &data) < 0)      \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST_QEMU(Name, CapsName, Emulator, Machine, Arch, Type)     \
    do {                                                                \
        char *name = NULL;                                              \
        if (virAsprintf(&name, "qemu_%s%s%s.%s",                        \
                        Name,                                           \
                        Machine ? "-" : "", Machine ? Machine : "",     \
                        Arch) < 0) {                                    \
            ret = -1;                                                   \
            break;                                                      \
        }                                                               \
        struct testData data = {                                        \
            .name = name,                                               \
            .emulator = Emulator,                                       \
            .machine = Machine,                                         \
            .arch = Arch,                                               \
            .type = Type,                                               \
            .capsType = CAPS_QEMU,                                      \
            .capsName = CapsName,                                       \
            .capsOpaque = cfg,                                          \
        };                                                              \
        if (virTestRun(name, test_virDomainCapsFormat, &data) < 0)      \
            ret = -1;                                                   \
        VIR_FREE(name);                                                 \
    } while (0)

#define DO_TEST_LIBXL(Name, Emulator, Machine, Arch, Type)              \
    do {                                                                \
        struct testData data = {                                        \
            .name = Name,                                               \
            .emulator = Emulator,                                       \
            .machine = Machine,                                         \
            .arch = Arch,                                               \
            .type = Type,                                               \
            .capsType = CAPS_LIBXL,                                     \
        };                                                              \
        if (virTestRun(Name, test_virDomainCapsFormat, &data) < 0)     \
            ret = -1;                                                   \
    } while (0)

    DO_TEST("basic", "/bin/emulatorbin", "my-machine-type",
            "x86_64", VIR_DOMAIN_VIRT_UML, CAPS_NONE);
    DO_TEST("full", "/bin/emulatorbin", "my-machine-type",
            "x86_64", VIR_DOMAIN_VIRT_KVM, CAPS_ALL);

#define DO_TEST_BHYVE(Name, Emulator, BhyveCaps, Type) \
    do {                                                                \
        char *name = NULL;                                              \
        if (virAsprintf(&name, "bhyve_%s.x86_64", Name) < 0) {          \
             ret = -1;                                                  \
             break;                                                     \
        }                                                               \
        struct testData data = {                                        \
            .name = name,                                               \
            .emulator = Emulator,                                       \
            .arch = "x86_64",                                           \
            .type = Type,                                               \
            .capsType = CAPS_BHYVE,                                     \
            .capsOpaque = BhyveCaps,                                    \
        };                                                              \
        if (virTestRun(name, test_virDomainCapsFormat, &data) < 0)      \
            ret = -1;                                                   \
        VIR_FREE(name);                                                 \
    } while (0)

#if WITH_QEMU

    DO_TEST_QEMU("1.7.0", "caps_1.7.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.6.0", "caps_2.6.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.6.0", "caps_2.6.0-gicv2",
                 "/usr/bin/qemu-system-aarch64", NULL,
                 "aarch64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.6.0-gicv2", "caps_2.6.0-gicv2",
                 "/usr/bin/qemu-system-aarch64", "virt",
                 "aarch64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.6.0-gicv3", "caps_2.6.0-gicv3",
                 "/usr/bin/qemu-system-aarch64", "virt",
                 "aarch64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.6.0", "caps_2.6.0",
                 "/usr/bin/qemu-system-ppc64", NULL,
                 "ppc64le", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.8.0", "caps_2.8.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.8.0-tcg", "caps_2.8.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_QEMU);

    DO_TEST_QEMU("2.9.0", "caps_2.9.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.9.0-tcg", "caps_2.9.0",
                 "/usr/bin/qemu-system-x86_64", NULL,
                 "x86_64", VIR_DOMAIN_VIRT_QEMU);

    DO_TEST_QEMU("2.7.0", "caps_2.7.0",
                 "/usr/bin/qemu-system-s390x", NULL,
                 "s390x", VIR_DOMAIN_VIRT_KVM);

    DO_TEST_QEMU("2.8.0", "caps_2.8.0",
                 "/usr/bin/qemu-system-s390x", NULL,
                 "s390x", VIR_DOMAIN_VIRT_KVM);

#endif /* WITH_QEMU */

#if WITH_LIBXL

# ifdef LIBXL_HAVE_PVUSB
#  define LIBXL_XENPV_CAPS "libxl-xenpv-usb"
#  define LIBXL_XENFV_CAPS "libxl-xenfv-usb"
# else
#  define LIBXL_XENPV_CAPS "libxl-xenpv"
#  define LIBXL_XENFV_CAPS "libxl-xenfv"
# endif

    DO_TEST_LIBXL(LIBXL_XENPV_CAPS, "/usr/bin/qemu-system-x86_64",
                  "xenpv", "x86_64", VIR_DOMAIN_VIRT_XEN);
    DO_TEST_LIBXL(LIBXL_XENFV_CAPS, "/usr/bin/qemu-system-x86_64",
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
