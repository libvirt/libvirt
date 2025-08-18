/*
 * Copyright (C) 2013-2014 Red Hat, Inc.
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

#include "virerror.h"
#include "virusb.h"

#include "testutils.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef enum {
    FIND_BY_VENDOR,
    FIND_BY_DEVICE,
    FIND_BY_VENDOR_AND_DEVICE,
} testUSBFindFlags;

struct findTestInfo {
    const char *name;
    unsigned int vendor;
    unsigned int product;
    unsigned int bus;
    unsigned int devno;
    const char *vroot;
    bool mandatory;
    int how;
    bool expectFailure;
};

static int testDeviceFileActor(virUSBDevice *dev,
                               const char *path,
                               void *opaque G_GNUC_UNUSED)
{
    g_autofree char *str = NULL;
    int ret = 0;

    str = g_strdup_printf(USB_DEVFS "%03d/%03d", virUSBDeviceGetBus(dev),
                          virUSBDeviceGetDevno(dev));

    if (STRNEQ(path, str)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Device path '%s' does not match expected '%s'",
                       path, str);
        ret = -1;
    }
    return ret;
}

static int testDeviceFind(const void *opaque)
{
    const struct findTestInfo *info = opaque;
    int ret = -1;
    virUSBDevice *dev = NULL;
    g_autoptr(virUSBDeviceList) devs = NULL;
    int rv = 0;
    size_t i, ndevs = 0;
    unsigned int flags = 0;

    switch (info->how) {
    case FIND_BY_VENDOR:
        flags = USB_DEVICE_FIND_BY_VENDOR;
        break;
    case FIND_BY_DEVICE:
        flags = USB_DEVICE_FIND_BY_DEVICE;
        break;
    case FIND_BY_VENDOR_AND_DEVICE:
        flags = USB_DEVICE_FIND_BY_VENDOR |
                USB_DEVICE_FIND_BY_DEVICE;
        break;
    }

    rv = virUSBDeviceFind(info->vendor, info->product,
                          info->bus, info->devno,
                          info->vroot, info->mandatory, flags, &devs);

    if (info->expectFailure) {
        if (rv >= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           "unexpected success");
        } else {
            ret = 0;
        }
        goto cleanup;
    } else if (rv < 0) {
        goto cleanup;
    }

    if (info->how != FIND_BY_VENDOR) {
        if (rv == 1) {
            dev = virUSBDeviceListGet(devs, 0);
            virUSBDeviceListSteal(devs, dev);
        } else {
            goto cleanup;
        }
    }

    switch (info->how) {
    case FIND_BY_DEVICE:
    case FIND_BY_VENDOR_AND_DEVICE:
        if (virUSBDeviceFileIterate(dev, testDeviceFileActor, NULL) < 0)
            goto cleanup;
        break;

    case FIND_BY_VENDOR:
        ndevs = virUSBDeviceListCount(devs);

        for (i = 0; i < ndevs; i++) {
            virUSBDevice *device = virUSBDeviceListGet(devs, i);
            if (virUSBDeviceFileIterate(device, testDeviceFileActor, NULL) < 0)
                goto cleanup;
        }
        break;
    }

    ret = 0;

 cleanup:
    virUSBDeviceFree(dev);
    return ret;
}


static int
testCheckNdevs(const char* occasion,
               size_t got,
               size_t expected)
{
    if (got != expected) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s: got %zu devices, expected %zu",
                       occasion, got, expected);
        return -1;
    }
    return 0;
}


static int
testUSBList(const void *opaque G_GNUC_UNUSED)
{
    virUSBDeviceList *list = NULL;
    virUSBDeviceList *devlist = NULL;
    virUSBDevice *dev = NULL;
    virUSBDeviceList *devs = NULL;
    int ret = -1;
    int rv;
    size_t i, ndevs;

    if (!(list = virUSBDeviceListNew()))
        goto cleanup;

#define EXPECTED_NDEVS_ONE 3
    if (virUSBDeviceFind(0x1d6b, 0x0002, 0, 0, NULL, true,
                         USB_DEVICE_FIND_BY_VENDOR, &devlist) < 0)
        goto cleanup;

    ndevs = virUSBDeviceListCount(devlist);
    if (testCheckNdevs("After first find", ndevs, EXPECTED_NDEVS_ONE) < 0)
        goto cleanup;

    for (i = 0; i < ndevs; i++) {
        dev = virUSBDeviceListGet(devlist, 0);
        dev = virUSBDeviceListSteal(devlist, dev);

        if (virUSBDeviceListAdd(list, &dev) < 0)
            goto cleanup;
        dev = NULL;
    }

    g_clear_pointer(&devlist, virObjectUnref);

    ndevs = virUSBDeviceListCount(list);
    if (testCheckNdevs("After first loop", ndevs, EXPECTED_NDEVS_ONE) < 0)
        goto cleanup;

#define EXPECTED_NDEVS_TWO 3
    if (virUSBDeviceFind(0x18d1, 0x4e22, 0, 0, NULL, true,
                         USB_DEVICE_FIND_BY_VENDOR, &devlist) < 0)
        goto cleanup;

    ndevs = virUSBDeviceListCount(devlist);
    if (testCheckNdevs("After second find", ndevs, EXPECTED_NDEVS_TWO) < 0)
        goto cleanup;
    for (i = 0; i < ndevs; i++) {
        dev = virUSBDeviceListGet(devlist, 0);
        dev = virUSBDeviceListSteal(devlist, dev);

        if (virUSBDeviceListAdd(list, &dev) < 0)
            goto cleanup;
        dev = NULL;
    }

    if (testCheckNdevs("After second loop",
                       virUSBDeviceListCount(list),
                       EXPECTED_NDEVS_ONE + EXPECTED_NDEVS_TWO) < 0)
        goto cleanup;

    rv = virUSBDeviceFind(0x18d1, 0x4e22, 1, 20, NULL, true,
                            USB_DEVICE_FIND_BY_VENDOR |
                            USB_DEVICE_FIND_BY_DEVICE, &devs);
    if (rv != 1) {
        goto cleanup;
    } else {
        dev = virUSBDeviceListGet(devs, 0);
        virUSBDeviceListSteal(devs, dev);
    }
    virObjectUnref(devs);

    if (!virUSBDeviceListFind(list, dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Device '%s' not in list when it should be",
                       virUSBDeviceGetName(dev));
        goto cleanup;
    }

    virUSBDeviceListDel(list, dev);
    g_clear_pointer(&dev, virUSBDeviceFree);

    if (testCheckNdevs("After deleting one",
                       virUSBDeviceListCount(list),
                       EXPECTED_NDEVS_ONE + EXPECTED_NDEVS_TWO - 1) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnref(list);
    virObjectUnref(devlist);
    virUSBDeviceFree(dev);
    return ret;
}


static int
mymain(void)
{
    int rv = 0;

#define DO_TEST_FIND_FULL(name, vend, prod, bus, devno, \
                          vroot, mand, how, fail) \
    do { \
        struct findTestInfo data = { name, vend, prod, bus, \
            devno, vroot, mand, how, fail \
        }; \
        if (virTestRun("USBDeviceFind " name, testDeviceFind, &data) < 0) \
            rv = -1; \
    } while (0)

#define DO_TEST_FIND_BY_VENDOR(name, vend, prod) \
    DO_TEST_FIND_FULL(name, vend, prod, 123, 456, NULL, true, \
                      FIND_BY_VENDOR, false)
#define DO_TEST_FIND_BY_VENDOR_FAIL(name, vend, prod) \
    DO_TEST_FIND_FULL(name, vend, prod, 123, 456, NULL, true, \
                      FIND_BY_VENDOR, true)

#define DO_TEST_FIND_BY_DEVICE(name, bus, devno) \
    DO_TEST_FIND_FULL(name, 0x1010, 0x2020, bus, devno, NULL, true, \
                      FIND_BY_DEVICE, false)
#define DO_TEST_FIND_BY_DEVICE_FAIL(name, bus, devno) \
    DO_TEST_FIND_FULL(name, 0x1010, 0x2020, bus, devno, NULL, true, \
                      FIND_BY_DEVICE, true)

#define DO_TEST_FIND_BY_VENDOR_AND_DEVICE(name, vend, prod, bus, devno) \
    DO_TEST_FIND_FULL(name, vend, prod, bus, devno, NULL, true, \
                      FIND_BY_VENDOR_AND_DEVICE, false)
#define DO_TEST_FIND_BY_VENDOR_AND_DEVICE_FAIL(name, vend, prod, bus, devno) \
    DO_TEST_FIND_FULL(name, vend, prod, bus, devno, NULL, true, \
                      FIND_BY_VENDOR_AND_DEVICE, true)

    DO_TEST_FIND_BY_DEVICE("integrated camera", 1, 5);
    DO_TEST_FIND_BY_DEVICE_FAIL("wrong bus/devno combination", 2, 20);
    DO_TEST_FIND_BY_DEVICE_FAIL("missing bus", 5, 20);
    DO_TEST_FIND_BY_DEVICE_FAIL("missing devnum", 1, 158);

    DO_TEST_FIND_BY_VENDOR("Nexus (multiple results)", 0x18d1, 0x4e22);
    DO_TEST_FIND_BY_VENDOR_FAIL("Bogus vendor and product", 0xf00d, 0xbeef);
    DO_TEST_FIND_BY_VENDOR_FAIL("Valid vendor", 0x1d6b, 0xbeef);

    DO_TEST_FIND_BY_VENDOR_AND_DEVICE("Nexus", 0x18d1, 0x4e22, 1, 20);
    DO_TEST_FIND_BY_VENDOR_AND_DEVICE_FAIL("Bogus vendor and product", 0xf00d, 0xbeef, 1, 25);
    DO_TEST_FIND_BY_VENDOR_AND_DEVICE_FAIL("Nexus wrong devnum", 0x18d1, 0x4e22, 1, 25);
    DO_TEST_FIND_BY_VENDOR_AND_DEVICE_FAIL("Bogus", 0xf00d, 0xbeef, 1024, 768);

    if (virTestRun("USB List test", testUSBList, NULL) < 0)
        rv = -1;

    if (rv < 0)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virusb"))
