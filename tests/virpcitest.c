/*
 * Copyright (C) 2013 Red Hat, Inc.
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
testVirPCIDeviceDetach(const void *oaque ATTRIBUTE_UNUSED)
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
        if (!(dev[i] = virPCIDeviceNew(0, 0, i + 1, 0)) ||
            virPCIDeviceSetStubDriver(dev[i], "pci-stub") < 0)
            goto cleanup;

        if (virPCIDeviceDetach(dev[i], activeDevs, inactiveDevs) < 0)
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
        if (!(dev[i] = virPCIDeviceNew(0, 0, i + 1, 0)) ||
            virPCIDeviceSetStubDriver(dev[i], "pci-stub") < 0)
            goto cleanup;

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

        if (virPCIDeviceSetStubDriver(dev[i], "pci-stub") < 0)
            goto cleanup;
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

# define FAKESYSFSDIRTEMPLATE abs_builddir "/fakesysfsdir-XXXXXX"

static int
mymain(void)
{
    int ret = 0;
    char *fakesysfsdir;

    if (VIR_STRDUP_QUIET(fakesysfsdir, FAKESYSFSDIRTEMPLATE) < 0) {
        fprintf(stderr, "Out of memory\n");
        abort();
    }

    if (!mkdtemp(fakesysfsdir)) {
        fprintf(stderr, "Cannot create fakesysfsdir");
        abort();
    }

    setenv("LIBVIRT_FAKE_SYSFS_DIR", fakesysfsdir, 1);

# define DO_TEST(fnc)                                   \
    do {                                                \
        if (virtTestRun(#fnc, fnc, NULL) < 0)           \
            ret = -1;                                   \
    } while (0)

# define DO_TEST_PCI(fnc, domain, bus, slot, function)                  \
    do {                                                                \
        struct testPCIDevData data = { domain, bus, slot, function };   \
        if (virtTestRun(#fnc, fnc, &data) < 0)                          \
            ret = -1;                                                   \
    } while (0)

    DO_TEST(testVirPCIDeviceNew);
    DO_TEST(testVirPCIDeviceDetach);
    DO_TEST(testVirPCIDeviceReset);
    DO_TEST(testVirPCIDeviceReattach);
    DO_TEST_PCI(testVirPCIDeviceIsAssignable, 5, 0x90, 1, 0);
    DO_TEST_PCI(testVirPCIDeviceIsAssignable, 1, 1, 0, 0);

    if (getenv("LIBVIRT_SKIP_CLEANUP") == NULL)
        virFileDeleteTree(fakesysfsdir);

    VIR_FREE(fakesysfsdir);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virpcimock.so")
#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
