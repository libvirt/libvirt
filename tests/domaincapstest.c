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

typedef void (*virDomainCapsFill)(virDomainCapsPtr domCaps,
                                  void *opaque);

#define SET_ALL_BITS(x) \
    memset(&(x.values), 0xff, sizeof(x.values))

static void
fillAll(virDomainCapsPtr domCaps,
        void *opaque ATTRIBUTE_UNUSED)
{
    virDomainCapsDeviceDiskPtr disk = &domCaps->disk;
    virDomainCapsDeviceHostdevPtr hostdev = &domCaps->hostdev;
    domCaps->maxvcpus = 255;

    disk->device.supported = true;
    SET_ALL_BITS(disk->diskDevice);
    SET_ALL_BITS(disk->bus);

    hostdev->device.supported = true;
    SET_ALL_BITS(hostdev->mode);
    SET_ALL_BITS(hostdev->startupPolicy);
    SET_ALL_BITS(hostdev->subsysType);
    SET_ALL_BITS(hostdev->capsType);
    SET_ALL_BITS(hostdev->pciBackend);
}


#ifdef WITH_QEMU
# include "testutilsqemu.h"
static void
fillQemuCaps(virDomainCapsPtr domCaps,
             void *opaque)
{
    virQEMUCapsPtr qemuCaps = (virQEMUCapsPtr) opaque;

    virQEMUCapsFillDomainCaps(domCaps, qemuCaps);

    /* The function above tries to query host's KVM & VFIO capabilities by
     * calling qemuHostdevHostSupportsPassthroughLegacy() and
     * qemuHostdevHostSupportsPassthroughVFIO() which, however, can't be
     * successfully mocked as they are not exposed as internal APIs. Therefore,
     * instead of mocking set the expected values here by hand. */
    VIR_DOMAIN_CAPS_ENUM_SET(domCaps->hostdev.pciBackend,
                             VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT,
                             VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM,
                             VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO);
}
#endif /* WITH_QEMU */


static virDomainCapsPtr
buildVirDomainCaps(const char *emulatorbin,
                   const char *machine,
                   virArch arch,
                   virDomainVirtType type,
                   virDomainCapsFill fillFunc,
                   void *opaque)
{
    virDomainCapsPtr domCaps;

    if (!(domCaps = virDomainCapsNew(emulatorbin, machine, arch, type)))
        goto cleanup;

    if (fillFunc)
        fillFunc(domCaps, opaque);

 cleanup:
    return domCaps;
}

struct test_virDomainCapsFormatData {
    const char *filename;
    const char *emulatorbin;
    const char *machine;
    virArch arch;
    virDomainVirtType type;
    virDomainCapsFill fillFunc;
    void *opaque;
};

static int
test_virDomainCapsFormat(const void *opaque)
{
    struct test_virDomainCapsFormatData *data =
        (struct test_virDomainCapsFormatData *) opaque;
    virDomainCapsPtr domCaps = NULL;
    char *path = NULL;
    char *domCapsXML = NULL;
    char *domCapsFromFile = NULL;
    int ret = -1;

    if (virAsprintf(&path, "%s/domaincapsschemadata/domaincaps-%s.xml",
                    abs_srcdir, data->filename) < 0)
        goto cleanup;

    if (virFileReadAll(path, 8192, &domCapsFromFile) < 0)
        goto cleanup;

    if (!(domCaps = buildVirDomainCaps(data->emulatorbin, data->machine,
                                       data->arch, data->type,
                                       data->fillFunc, data->opaque)))
        goto cleanup;

    if (!(domCapsXML = virDomainCapsFormat(domCaps)))
        goto cleanup;

    if (STRNEQ(domCapsFromFile, domCapsXML)) {
        virtTestDifference(stderr, domCapsFromFile, domCapsXML);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(domCapsFromFile);
    VIR_FREE(domCapsXML);
    VIR_FREE(path);
    virObjectUnref(domCaps);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(Filename, Emulatorbin, Machine, Arch, Type, ...)                    \
    do {                                                                            \
        struct test_virDomainCapsFormatData data = {.filename = Filename,           \
            .emulatorbin = Emulatorbin, .machine = Machine, .arch = Arch,           \
            .type = Type, __VA_ARGS__};                                             \
        if (virtTestRun(Filename, test_virDomainCapsFormat, &data) < 0)             \
            ret = -1;                                                               \
    } while (0)

    DO_TEST("basic", "/bin/emulatorbin", "my-machine-type",
            VIR_ARCH_X86_64, VIR_DOMAIN_VIRT_UML);
    DO_TEST("full", "/bin/emulatorbin", "my-machine-type",
            VIR_ARCH_X86_64, VIR_DOMAIN_VIRT_KVM, .fillFunc = fillAll);

#ifdef WITH_QEMU

# define DO_TEST_QEMU(Filename, QemuCapsFile, Emulatorbin, Machine, Arch, Type, ...)    \
    do {                                                                                \
        const char *capsPath = abs_srcdir "/qemucapabilitiesdata/" QemuCapsFile ".caps";    \
        virQEMUCapsPtr qemuCaps = qemuTestParseCapabilities(capsPath);                  \
        struct test_virDomainCapsFormatData data = {.filename = Filename,               \
            .emulatorbin = Emulatorbin, .machine = Machine, .arch = Arch,               \
            .type = Type, .fillFunc = fillQemuCaps, .opaque = qemuCaps};                \
        if (!qemuCaps) {                                                                \
            fprintf(stderr, "Unable to build qemu caps from %s\n", capsPath);           \
            ret = -1;                                                                   \
        } else if (virtTestRun(Filename, test_virDomainCapsFormat, &data) < 0)          \
            ret = -1;                                                                   \
    } while (0)

    DO_TEST_QEMU("qemu_1.6.50-1", "caps_1.6.50-1", "/usr/bin/qemu-system-x86_64",
                 "pc-1.2",  VIR_ARCH_X86_64, VIR_DOMAIN_VIRT_KVM);

#endif /* WITH_QEMU */

    return ret;
}

VIRT_TEST_MAIN(mymain)
