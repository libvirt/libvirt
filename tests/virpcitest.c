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
 */

#include <config.h>
#include "internal.h"

#include "testutils.h"

#ifdef __linux__

# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <virpci.h>
# include <virpcivpd.h>

# define VIR_FROM_THIS VIR_FROM_NONE

static int
testVirPCIDeviceCheckDriver(virPCIDevice *dev, const char *expected)
{
    g_autofree char *path = NULL;
    g_autofree char *driver = NULL;

    if (virPCIDeviceGetCurrentDriverPathAndName(dev, &path, &driver) < 0)
        return -1;

    if (STRNEQ_NULLABLE(driver, expected)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "PCI device %s driver mismatch: %s, expecting %s",
                       virPCIDeviceGetName(dev), NULLSTR(driver),
                       NULLSTR(expected));
        return -1;
    }

    return 0;
}

static int
testVirPCIDeviceNew(const void *opaque G_GNUC_UNUSED)
{
    int ret = -1;
    virPCIDevice *dev;
    const char *devName;
    virPCIDeviceAddress devAddr = {.domain = 0, .bus = 0, .slot = 0, .function = 0};

    if (!(dev = virPCIDeviceNew(&devAddr)))
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

# define CHECK_LIST_COUNT(list, cnt) \
    if ((count = virPCIDeviceListCount(list)) != cnt) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       "Unexpected count of items in " #list ": %d, " \
                       "expecting %zu", count, (size_t) cnt); \
        goto cleanup; \
    }

static int
testVirPCIDeviceDetach(const void *opaque G_GNUC_UNUSED)
{
    int ret = -1;
    virPCIDevice *dev[] = {NULL, NULL, NULL};
    size_t i, nDev = G_N_ELEMENTS(dev);
    g_autoptr(virPCIDeviceList) activeDevs = NULL;
    g_autoptr(virPCIDeviceList) inactiveDevs = NULL;
    int count;

    if (!(activeDevs = virPCIDeviceListNew()) ||
        !(inactiveDevs = virPCIDeviceListNew()))
        goto cleanup;

    CHECK_LIST_COUNT(activeDevs, 0);
    CHECK_LIST_COUNT(inactiveDevs, 0);

    for (i = 0; i < nDev; i++) {
        virPCIDeviceAddress devAddr = {.domain = 0, .bus = 0,
                                       .slot = i + 1, .function = 0};
        if (!(dev[i] = virPCIDeviceNew(&devAddr)))
            goto cleanup;

        virPCIDeviceSetStubDriverType(dev[i], VIR_PCI_STUB_DRIVER_VFIO);

        if (virPCIDeviceDetach(dev[i], activeDevs, inactiveDevs) < 0)
            goto cleanup;

        if (testVirPCIDeviceCheckDriver(dev[i], "vfio-pci") < 0)
            goto cleanup;

        CHECK_LIST_COUNT(activeDevs, 0);
        CHECK_LIST_COUNT(inactiveDevs, i + 1);
    }

    ret = 0;
 cleanup:
    for (i = 0; i < nDev; i++)
        virPCIDeviceFree(dev[i]);
    return ret;
}

static int
testVirPCIDeviceReset(const void *opaque G_GNUC_UNUSED)
{
    int ret = -1;
    virPCIDevice *dev[] = {NULL, NULL, NULL};
    size_t i, nDev = G_N_ELEMENTS(dev);
    g_autoptr(virPCIDeviceList) activeDevs = NULL;
    g_autoptr(virPCIDeviceList) inactiveDevs = NULL;
    int count;

    if (!(activeDevs = virPCIDeviceListNew()) ||
        !(inactiveDevs = virPCIDeviceListNew()))
        goto cleanup;

    CHECK_LIST_COUNT(activeDevs, 0);
    CHECK_LIST_COUNT(inactiveDevs, 0);

    for (i = 0; i < nDev; i++) {
        virPCIDeviceAddress devAddr = {.domain = 0, .bus = 0,
                                       .slot = i + 1, .function = 0};
        if (!(dev[i] = virPCIDeviceNew(&devAddr)))
            goto cleanup;

        virPCIDeviceSetStubDriverType(dev[i], VIR_PCI_STUB_DRIVER_VFIO);

        if (virPCIDeviceReset(dev[i], activeDevs, inactiveDevs) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    for (i = 0; i < nDev; i++)
        virPCIDeviceFree(dev[i]);
    return ret;
}

static int
testVirPCIDeviceReattach(const void *opaque G_GNUC_UNUSED)
{
    int ret = -1;
    virPCIDevice *dev[] = {NULL, NULL, NULL};
    size_t i, nDev = G_N_ELEMENTS(dev);
    g_autoptr(virPCIDeviceList) activeDevs = NULL;
    g_autoptr(virPCIDeviceList) inactiveDevs = NULL;
    int count;

    if (!(activeDevs = virPCIDeviceListNew()) ||
        !(inactiveDevs = virPCIDeviceListNew()))
        goto cleanup;

    for (i = 0; i < nDev; i++) {
        virPCIDeviceAddress devAddr = {.domain = 0, .bus = 0,
                                       .slot = i + 1, .function = 0};
        if (!(dev[i] = virPCIDeviceNew(&devAddr)))
            goto cleanup;

        if (virPCIDeviceListAdd(inactiveDevs, dev[i]) < 0) {
            virPCIDeviceFree(dev[i]);
            goto cleanup;
        }

        CHECK_LIST_COUNT(activeDevs, 0);
        CHECK_LIST_COUNT(inactiveDevs, i + 1);

        virPCIDeviceSetStubDriverType(dev[i], VIR_PCI_STUB_DRIVER_VFIO);
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
    virPCIDevice *dev;
    virPCIDeviceAddress devAddr = {.domain = data->domain, .bus = data->bus,
                                   .slot = data->slot, .function = data->function};

    if (!(dev = virPCIDeviceNew(&devAddr)))
        return -1;

    if (virPCIDeviceIsAssignable(dev, true))
        ret = 0;

    virPCIDeviceFree(dev);
    return ret;
}

static int
testVirPCIDeviceDetachSingle(const void *opaque)
{
    const struct testPCIDevData *data = opaque;
    int ret = -1;
    virPCIDevice *dev;
    virPCIDeviceAddress devAddr = {.domain = data->domain, .bus = data->bus,
                                   .slot = data->slot, .function = data->function};

    dev = virPCIDeviceNew(&devAddr);
    if (!dev)
        goto cleanup;

    virPCIDeviceSetStubDriverType(dev, VIR_PCI_STUB_DRIVER_VFIO);

    if (virPCIDeviceDetach(dev, NULL, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virPCIDeviceFree(dev);
    return ret;
}

static int
testVirPCIDeviceReattachSingle(const void *opaque)
{
    const struct testPCIDevData *data = opaque;
    int ret = -1;
    virPCIDevice *dev;
    virPCIDeviceAddress devAddr = {.domain = data->domain, .bus = data->bus,
                                   .slot = data->slot, .function = data->function};

    dev = virPCIDeviceNew(&devAddr);
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
    virPCIDevice *dev;
    virPCIDeviceAddress devAddr = {.domain = data->domain, .bus = data->bus,
                                   .slot = data->slot, .function = data->function};

    dev = virPCIDeviceNew(&devAddr);
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
    virPCIDevice *dev;
    virPCIDeviceAddress devAddr = {.domain = data->domain, .bus = data->bus,
                                   .slot = data->slot, .function = data->function};

    dev = virPCIDeviceNew(&devAddr);
    if (!dev)
        goto cleanup;

    if (virPCIDeviceUnbind(dev) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virPCIDeviceFree(dev);
    return ret;
}


static int
testVirPCIDeviceGetVPD(const void *opaque)
{
    const struct testPCIDevData *data = opaque;
    g_autoptr(virPCIDevice) dev = NULL;
    virPCIDeviceAddress devAddr = {.domain = data->domain, .bus = data->bus,
                                   .slot = data->slot, .function = data->function};
    g_autoptr(virPCIVPDResource) res = NULL;

    dev = virPCIDeviceNew(&devAddr);
    if (!dev)
        return -1;

    res = virPCIDeviceGetVPD(dev);

    /* Only basic checks - full parser validation is done elsewhere. */
    if (res->ro == NULL)
        return -1;

    if (STRNEQ(res->name, "testname")) {
        VIR_TEST_DEBUG("Unexpected name present in VPD: %s", res->name);
        return -1;
    }

    if (STRNEQ(res->ro->part_number, "42")) {
        VIR_TEST_DEBUG("Unexpected part number value present in VPD: %s", res->ro->part_number);
        return -1;
    }

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

# define DO_TEST(fnc) \
    do { \
        if (virTestRun(#fnc, fnc, NULL) < 0) \
            ret = -1; \
    } while (0)

# define DO_TEST_PCI(fnc, domain, bus, slot, function) \
    do { \
        struct testPCIDevData data = { \
            domain, bus, slot, function, NULL \
        }; \
        g_autofree char *label = NULL; \
        label = g_strdup_printf("%s(%04x:%02x:%02x.%x)", \
                                #fnc, domain, bus, slot, function); \
        if (virTestRun(label, fnc, &data) < 0) \
            ret = -1; \
    } while (0)

# define DO_TEST_PCI_DRIVER(domain, bus, slot, function, driver) \
    do { \
        struct testPCIDevData data = { \
            domain, bus, slot, function, driver \
        }; \
        g_autofree char *label = NULL; \
        label = g_strdup_printf("PCI driver %04x:%02x:%02x.%x is %s", \
                                domain, bus, slot, function, \
                                NULLSTR(driver)); \
        if (virTestRun(label, testVirPCIDeviceCheckDriverTest, \
                       &data) < 0) \
            ret = -1; \
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
    DO_TEST_PCI_DRIVER(0, 0x0a, 2, 0, "vfio-pci");

    /* Reattach an unknown unbound device */
    DO_TEST_PCI_DRIVER(0, 0x0a, 3, 0, NULL);
    DO_TEST_PCI(testVirPCIDeviceReattachSingle, 0, 0x0a, 3, 0);
    DO_TEST_PCI_DRIVER(0, 0x0a, 3, 0, NULL);

    DO_TEST_PCI(testVirPCIDeviceGetVPD, 0, 0x03, 0, 0);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virpci"))
#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
