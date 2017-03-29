/*
 * Copyright (C) 2013, 2014 Red Hat, Inc.
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
 * Author: Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>

#include "testutils.h"

#ifdef __linux__

# include <stdlib.h>
# include <stdio.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <virpci.h>

# define VIR_FROM_THIS VIR_FROM_NONE

static int
testVirPCIDeviceCheckDriver(virPCIDevicePtr dev, const char *expected)
{
    char *path = NULL;
    char *driver = NULL;
    int ret = -1;

    if (virPCIDeviceGetDriverPathAndName(dev, &path, &driver) < 0)
        goto cleanup;

    if (STRNEQ_NULLABLE(driver, expected)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "PCI device %s driver mismatch: %s, expecting %s",
                       virPCIDeviceGetName(dev), NULLSTR(driver),
                       NULLSTR(expected));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(path);
    VIR_FREE(driver);
    return ret;
}

static int
testVirPCIDeviceNew(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    virPCIDevicePtr dev;
    const char *devName;

    if (!(dev = virPCIDeviceNew(0, 0, 0, 0)))
        goto cleanup;

    devName = virPCIDeviceGetName(dev);
    if (STRNEQ(devName, "0000:00:00.0")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "PCI device name mismatch: %s, expecting %s",
                       devName, "0000:00:00.0");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virPCIDeviceFree(dev);
    return ret;
}

# define CHECK_LIST_COUNT(list, cnt)                                    \
    if ((count = virPCIDeviceListCount(list)) != cnt) {                 \
        virReportError(VIR_ERR_INTERNAL_ERROR,                          \
                       "Unexpected count of items in " #list ": %d, "   \
                       "expecting %zu", count, (size_t) cnt);           \
        goto cleanup;                                                   \
    }

static int
testVirPCIDeviceDetach(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    virPCIDevicePtr dev[] = {NULL, NULL, NULL};
    size_t i, nDev = ARRAY_CARDINALITY(dev);
    virPCIDeviceListPtr activeDevs = NULL, inactiveDevs = NULL;
    int count;

    if (!(activeDevs = virPCIDeviceListNew()) ||
        !(inactiveDevs = virPCIDeviceListNew()))
        goto cleanup;

    CHECK_LIST_COUNT(activeDevs, 0);
    CHECK_LIST_COUNT(inactiveDevs, 0);

    for (i = 0; i < nDev; i++) {
        if (!(dev[i] = virPCIDeviceNew(0, 0, i + 1, 0)))
            goto cleanup;

        virPCIDeviceSetStubDriver(dev[i], VIR_PCI_STUB_DRIVER_KVM);

        if (virPCIDeviceDetach(dev[i], activeDevs, inactiveDevs) < 0)
            goto cleanup;

        if (testVirPCIDeviceCheckDriver(dev[i], "pci-stub") < 0)
            goto cleanup;

        CHECK_LIST_COUNT(activeDevs, 0);
        CHECK_LIST_COUNT(inactiveDevs, i + 1);
    }

    ret = 0;
 cleanup:
    for (i = 0; i < nDev; i++)
        virPCIDeviceFree(dev[i]);
    virObjectUnref(activeDevs);
    virObjectUnref(inactiveDevs);
    return ret;
}

static int
testVirPCIDeviceReset(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    virPCIDevicePtr dev[] = {NULL, NULL, NULL};
    size_t i, nDev = ARRAY_CARDINALITY(dev);
    virPCIDeviceListPtr activeDevs = NULL, inactiveDevs = NULL;
    int count;

    if (!(activeDevs = virPCIDeviceListNew()) ||
        !(inactiveDevs = virPCIDeviceListNew()))
        goto cleanup;

    CHECK_LIST_COUNT(activeDevs, 0);
    CHECK_LIST_COUNT(inactiveDevs, 0);

    for (i = 0; i < nDev; i++) {
        if (!(dev[i] = virPCIDeviceNew(0, 0, i + 1, 0)))
            goto cleanup;

        virPCIDeviceSetStubDriver(dev[i], VIR_PCI_STUB_DRIVER_KVM);

        if (virPCIDeviceReset(dev[i], activeDevs, inactiveDevs) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    for (i = 0; i < nDev; i++)
        virPCIDeviceFree(dev[i]);
    virObjectUnref(activeDevs);
    virObjectUnref(inactiveDevs);
    return ret;
}

static int
testVirPCIDeviceReattach(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    virPCIDevicePtr dev[] = {NULL, NULL, NULL};
    size_t i, nDev = ARRAY_CARDINALITY(dev);
    virPCIDeviceListPtr activeDevs = NULL, inactiveDevs = NULL;
    int count;

    if (!(activeDevs = virPCIDeviceListNew()) ||
        !(inactiveDevs = virPCIDeviceListNew()))
        goto cleanup;

    for (i = 0; i < nDev; i++) {
        if (!(dev[i] = virPCIDeviceNew(0, 0, i + 1, 0)))
            goto cleanup;

        if (virPCIDeviceListAdd(inactiveDevs, dev[i]) < 0) {
            virPCIDeviceFree(dev[i]);
            goto cleanup;
        }

        CHECK_LIST_COUNT(activeDevs, 0);
        CHECK_LIST_COUNT(inactiveDevs, i + 1);

        virPCIDeviceSetStubDriver(dev[i], VIR_PCI_STUB_DRIVER_KVM);
    }

    CHECK_LIST_COUNT(activeDevs, 0);
    CHECK_LIST_COUNT(inactiveDevs, nDev);

    for (i = 0; i < nDev; i++) {
        if (virPCIDeviceReattach(dev[i], activeDevs, inactiveDevs) < 0)
            goto cleanup;

        CHECK_LIST_COUNT(activeDevs, 0);
        CHECK_LIST_COUNT(inactiveDevs, nDev - i - 1);
    }

    ret = 0;
 cleanup:
    virObjectUnref(activeDevs);
    virObjectUnref(inactiveDevs);
    return ret;
}

struct testPCIDevData {
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int function;
    const char *driver;
};

static int
testVirPCIDeviceIsAssignable(const void *opaque)
{
    const struct testPCIDevData *data = opaque;
    int ret = -1;
    virPCIDevicePtr dev;

    if (!(dev = virPCIDeviceNew(data->domain, data->bus, data->slot, data->function)))
        goto cleanup;

    if (virPCIDeviceIsAssignable(dev, true))
        ret = 0;

    virPCIDeviceFree(dev);
 cleanup:
    return ret;
}

static int
testVirPCIDeviceDetachSingle(const void *opaque)
{
    const struct testPCIDevData *data = opaque;
    int ret = -1;
    virPCIDevicePtr dev;

    dev = virPCIDeviceNew(data->domain, data->bus, data->slot, data->function);
    if (!dev)
        goto cleanup;

    virPCIDeviceSetStubDriver(dev, VIR_PCI_STUB_DRIVER_KVM);

    if (virPCIDeviceDetach(dev, NULL, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virPCIDeviceFree(dev);
    return ret;
}

static int
testVirPCIDeviceDetachFail(const void *opaque)
{
    const struct testPCIDevData *data = opaque;
    int ret = -1;
    virPCIDevicePtr dev;

    dev = virPCIDeviceNew(data->domain, data->bus, data->slot, data->function);
    if (!dev)
        goto cleanup;

    virPCIDeviceSetStubDriver(dev, VIR_PCI_STUB_DRIVER_VFIO);

    if (virPCIDeviceDetach(dev, NULL, NULL) < 0) {
        if (virTestGetVerbose() || virTestGetDebug())
            virDispatchError(NULL);
        virResetLastError();
        ret = 0;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Attaching device %s to %s should have failed",
                       virPCIDeviceGetName(dev),
                       virPCIStubDriverTypeToString(VIR_PCI_STUB_DRIVER_VFIO));
    }

 cleanup:
    virPCIDeviceFree(dev);
    return ret;
}

static int
testVirPCIDeviceReattachSingle(const void *opaque)
{
    const struct testPCIDevData *data = opaque;
    int ret = -1;
    virPCIDevicePtr dev;

    dev = virPCIDeviceNew(data->domain, data->bus, data->slot, data->function);
    if (!dev)
        goto cleanup;

    virPCIDeviceSetUnbindFromStub(dev, true);
    virPCIDeviceSetRemoveSlot(dev, true);
    virPCIDeviceSetReprobe(dev, true);

    if (virPCIDeviceReattach(dev, NULL, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virPCIDeviceFree(dev);
    return ret;
}

static int
testVirPCIDeviceCheckDriverTest(const void *opaque)
{
    const struct testPCIDevData *data = opaque;
    int ret = -1;
    virPCIDevicePtr dev;

    dev = virPCIDeviceNew(data->domain, data->bus, data->slot, data->function);
    if (!dev)
        goto cleanup;

    if (testVirPCIDeviceCheckDriver(dev, data->driver) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virPCIDeviceFree(dev);
    return ret;
}

static int
testVirPCIDeviceUnbind(const void *opaque)
{
    const struct testPCIDevData *data = opaque;
    int ret = -1;
    virPCIDevicePtr dev;

    dev = virPCIDeviceNew(data->domain, data->bus, data->slot, data->function);
    if (!dev)
        goto cleanup;

    if (virPCIDeviceUnbind(dev) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virPCIDeviceFree(dev);
    return ret;
}

# define FAKEROOTDIRTEMPLATE abs_builddir "/fakerootdir-XXXXXX"

static int
mymain(void)
{
    int ret = 0;
    char *fakerootdir;

    if (VIR_STRDUP_QUIET(fakerootdir, FAKEROOTDIRTEMPLATE) < 0) {
        VIR_TEST_DEBUG("Out of memory\n");
        abort();
    }

    if (!mkdtemp(fakerootdir)) {
        VIR_TEST_DEBUG("Cannot create fakerootdir");
        abort();
    }

    setenv("LIBVIRT_FAKE_ROOT_DIR", fakerootdir, 1);

# define DO_TEST(fnc)                                   \
    do {                                                \
        if (virTestRun(#fnc, fnc, NULL) < 0)            \
            ret = -1;                                   \
    } while (0)

# define DO_TEST_PCI(fnc, domain, bus, slot, function)                  \
    do {                                                                \
        struct testPCIDevData data = {                                  \
            domain, bus, slot, function, NULL                           \
        };                                                              \
        char *label = NULL;                                             \
        if (virAsprintf(&label, "%s(%04x:%02x:%02x.%x)",                \
                        #fnc, domain, bus, slot, function) < 0) {       \
            ret = -1;                                                   \
            break;                                                      \
        }                                                               \
        if (virTestRun(label, fnc, &data) < 0)                          \
            ret = -1;                                                   \
        VIR_FREE(label);                                                \
    } while (0)

# define DO_TEST_PCI_DRIVER(domain, bus, slot, function, driver)        \
    do {                                                                \
        struct testPCIDevData data = {                                  \
            domain, bus, slot, function, driver                         \
        };                                                              \
        char *label = NULL;                                             \
        if (virAsprintf(&label, "PCI driver %04x:%02x:%02x.%x is %s",   \
                        domain, bus, slot, function,                    \
                        NULLSTR(driver)) < 0) {                         \
            ret = -1;                                                   \
            break;                                                      \
        }                                                               \
        if (virTestRun(label, testVirPCIDeviceCheckDriverTest,          \
                       &data) < 0)                                      \
            ret = -1;                                                   \
        VIR_FREE(label);                                                \
    } while (0)

    /* Changes made to individual devices are persistent and the
     * tests often rely on the state set by previous tests.
     */

    DO_TEST(testVirPCIDeviceNew);
    DO_TEST(testVirPCIDeviceDetach);
    DO_TEST(testVirPCIDeviceReset);
    DO_TEST(testVirPCIDeviceReattach);
    DO_TEST_PCI(testVirPCIDeviceIsAssignable, 5, 0x90, 1, 0);
    DO_TEST_PCI(testVirPCIDeviceIsAssignable, 1, 1, 0, 0);

    DO_TEST_PCI(testVirPCIDeviceDetachFail, 0, 0x0a, 1, 0);

    /* Reattach a device already bound to non-stub a driver */
    DO_TEST_PCI_DRIVER(0, 0x0a, 1, 0, "i915");
    DO_TEST_PCI(testVirPCIDeviceReattachSingle, 0, 0x0a, 1, 0);
    DO_TEST_PCI_DRIVER(0, 0x0a, 1, 0, "i915");

    /* Reattach an unbound device */
    DO_TEST_PCI(testVirPCIDeviceUnbind, 0, 0x0a, 1, 0);
    DO_TEST_PCI_DRIVER(0, 0x0a, 1, 0, NULL);
    DO_TEST_PCI(testVirPCIDeviceReattachSingle, 0, 0x0a, 1, 0);
    DO_TEST_PCI_DRIVER(0, 0x0a, 1, 0, "i915");

    /* Detach an unbound device */
    DO_TEST_PCI_DRIVER(0, 0x0a, 2, 0, NULL);
    DO_TEST_PCI(testVirPCIDeviceDetachSingle, 0, 0x0a, 2, 0);
    DO_TEST_PCI_DRIVER(0, 0x0a, 2, 0, "pci-stub");

    /* Reattach an unknown unbound device */
    DO_TEST_PCI_DRIVER(0, 0x0a, 3, 0, NULL);
    DO_TEST_PCI(testVirPCIDeviceReattachSingle, 0, 0x0a, 3, 0);
    DO_TEST_PCI_DRIVER(0, 0x0a, 3, 0, NULL);

    if (getenv("LIBVIRT_SKIP_CLEANUP") == NULL)
        virFileDeleteTree(fakerootdir);

    VIR_FREE(fakerootdir);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virpcimock.so")
#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
