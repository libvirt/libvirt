/*
 * Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
 * Copyright (C) 2014-2016 Red Hat, Inc.
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
 * Author: Chunyan Liu <cyliu@suse.com>
 */

#include <config.h>

#include "testutils.h"

#ifdef __linux__

# include <stdlib.h>
# include <stdio.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/ioctl.h>
# include <fcntl.h>
# include "virlog.h"
# include "virhostdev.h"

# define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.hostdevtest");

# define CHECK_LIST_COUNT(list, cnt)                                        \
    do {                                                                    \
        size_t actualCount;                                                 \
        if ((actualCount = virPCIDeviceListCount(list)) != cnt) {           \
            virReportError(VIR_ERR_INTERNAL_ERROR,                          \
                           "Unexpected count of items in " #list ": %zu, "  \
                           "expecting %zu", actualCount, (size_t) cnt);     \
            goto cleanup;                                                   \
        }                                                                   \
    } while (0)

# define TEST_STATE_DIR abs_builddir "/hostdevmgr"
static const char *drv_name = "test_driver";
static const char *dom_name = "test_domain";
static const unsigned char *uuid =
            (unsigned char *)("f92360b0-2541-8791-fb32-d1f838811541");
static int nhostdevs = 3;
static virDomainHostdevDefPtr hostdevs[] = {NULL, NULL, NULL};
static virPCIDevicePtr dev[] = {NULL, NULL, NULL};
static virHostdevManagerPtr mgr;

static void
myCleanup(void)
{
    size_t i;
    for (i = 0; i < nhostdevs; i++) {
         virPCIDeviceFree(dev[i]);
         virDomainHostdevDefFree(hostdevs[i]);
    }

    if (mgr) {
        if (!getenv("LIBVIRT_SKIP_CLEANUP"))
            virFileDeleteTree(mgr->stateDir);

        virObjectUnref(mgr->activePCIHostdevs);
        virObjectUnref(mgr->inactivePCIHostdevs);
        virObjectUnref(mgr->activeUSBHostdevs);
        VIR_FREE(mgr->stateDir);
        VIR_FREE(mgr);
    }
}

static int
myInit(void)
{
    size_t i;

    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevSubsys subsys;
        hostdevs[i] = virDomainHostdevDefNew(NULL);
        if (!hostdevs[i])
            goto cleanup;
        hostdevs[i]->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
        subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
        subsys.u.pci.addr.domain = 0;
        subsys.u.pci.addr.bus = 0;
        subsys.u.pci.addr.slot = i + 1;
        subsys.u.pci.addr.function = 0;
        subsys.u.pci.backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM;
        hostdevs[i]->source.subsys = subsys;
    }

    for (i = 0; i < nhostdevs; i++) {
        if (!(dev[i] = virPCIDeviceNew(0, 0, i + 1, 0)))
            goto cleanup;

        virPCIDeviceSetStubDriver(dev[i], VIR_PCI_STUB_DRIVER_KVM);
    }

    if (VIR_ALLOC(mgr) < 0)
        goto cleanup;
    if ((mgr->activePCIHostdevs = virPCIDeviceListNew()) == NULL)
        goto cleanup;
    if ((mgr->activeUSBHostdevs = virUSBDeviceListNew()) == NULL)
        goto cleanup;
    if ((mgr->inactivePCIHostdevs = virPCIDeviceListNew()) == NULL)
        goto cleanup;
    if ((mgr->activeSCSIHostdevs = virSCSIDeviceListNew()) == NULL)
        goto cleanup;
    if (VIR_STRDUP(mgr->stateDir, TEST_STATE_DIR) < 0)
        goto cleanup;
    if (virFileMakePath(mgr->stateDir) < 0)
        goto cleanup;

    return 0;

 cleanup:
    myCleanup();
    return -1;
}

# if HAVE_LINUX_KVM_H
#  include <linux/kvm.h>
static bool
virHostdevHostSupportsPassthroughKVM(void)
{
    int kvmfd = -1;
    bool ret = false;

    if ((kvmfd = open("/dev/kvm", O_RDONLY)) < 0)
        goto cleanup;

#  ifdef KVM_CAP_IOMMU
    if ((ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_IOMMU)) <= 0)
        goto cleanup;

    ret = true;
#  endif

 cleanup:
    VIR_FORCE_CLOSE(kvmfd);

    return ret;
}
# else
static bool
virHostdevHostSupportsPassthroughKVM(void)
{
    return false;
}
# endif

static int
testVirHostdevPreparePCIHostdevs_unmanaged(void)
{
    int ret = -1;
    size_t active_count, inactive_count, i;

    for (i = 0; i < nhostdevs; i++)
         hostdevs[i]->managed = false;

    active_count = virPCIDeviceListCount(mgr->activePCIHostdevs);
    inactive_count = virPCIDeviceListCount(mgr->inactivePCIHostdevs);

    /* Test normal functionality */
    VIR_DEBUG("Test 0 hostdevs");
    if (virHostdevPreparePCIDevices(mgr, drv_name, dom_name, uuid,
                                    NULL, 0, 0) < 0)
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    /* Test unmanaged hostdevs */
    VIR_DEBUG("Test >=1 unmanaged hostdevs");
    if (virHostdevPreparePCIDevices(mgr, drv_name, dom_name, uuid,
                                    hostdevs, nhostdevs, 0) < 0)
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count + nhostdevs);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count - nhostdevs);

    /* Test conflict */
    active_count = virPCIDeviceListCount(mgr->activePCIHostdevs);
    inactive_count = virPCIDeviceListCount(mgr->inactivePCIHostdevs);
    VIR_DEBUG("Test: prepare same hostdevs for same driver/domain again");
    if (!virHostdevPreparePCIDevices(mgr, drv_name, dom_name, uuid,
                                     &hostdevs[0], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    VIR_DEBUG("Test: prepare same hostdevs for same driver, diff domain again");
    if (!virHostdevPreparePCIDevices(mgr, drv_name, "test_domain1", uuid,
                                     &hostdevs[1], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    VIR_DEBUG("Test: prepare same hostdevs for diff driver/domain again");
    if (!virHostdevPreparePCIDevices(mgr, "test_driver1", dom_name, uuid,
                                     &hostdevs[2], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevReAttachPCIHostdevs_unmanaged(void)
{
    int ret = -1;
    size_t active_count, inactive_count, i;

    for (i = 0; i < nhostdevs; i++) {
        if (hostdevs[i]->managed != false) {
            VIR_DEBUG("invalid test");
            return -1;
        }
    }

    active_count = virPCIDeviceListCount(mgr->activePCIHostdevs);
    inactive_count = virPCIDeviceListCount(mgr->inactivePCIHostdevs);

    VIR_DEBUG("Test 0 hostdevs");
    virHostdevReAttachPCIDevices(mgr, drv_name, dom_name, NULL, 0, NULL);
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    VIR_DEBUG("Test >=1 unmanaged hostdevs");
    virHostdevReAttachPCIDevices(mgr, drv_name, dom_name,
                                  hostdevs, nhostdevs, NULL);
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count - nhostdevs);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count + nhostdevs);

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevPreparePCIHostdevs_managed(bool mixed)
{
    int ret = -1;
    size_t active_count, inactive_count, i;

    for (i = 0; i < nhostdevs; i++)
        hostdevs[i]->managed = true;

    active_count = virPCIDeviceListCount(mgr->activePCIHostdevs);
    inactive_count = virPCIDeviceListCount(mgr->inactivePCIHostdevs);

    /* Test normal functionality */
    VIR_DEBUG("Test >=1 hostdevs");
    if (virHostdevPreparePCIDevices(mgr, drv_name, dom_name, uuid,
                                     hostdevs, nhostdevs, 0) < 0)
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count + nhostdevs);
    /* If testing a mixed roundtrip, devices are already in the inactive list
     * before we start and are removed from it as soon as we attach them to
     * the guest */
    if (mixed)
        CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count - nhostdevs);
    else
        CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    /* Test conflict */
    active_count = virPCIDeviceListCount(mgr->activePCIHostdevs);
    inactive_count = virPCIDeviceListCount(mgr->inactivePCIHostdevs);
    VIR_DEBUG("Test: prepare same hostdevs for same driver/domain again");
    if (!virHostdevPreparePCIDevices(mgr, drv_name, dom_name, uuid,
                                      &hostdevs[0], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    VIR_DEBUG("Test: prepare same hostdevs for same driver, diff domain again");
    if (!virHostdevPreparePCIDevices(mgr, drv_name, "test_domain1", uuid,
                                      &hostdevs[1], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    VIR_DEBUG("Test: prepare same hostdevs for diff driver/domain again");
    if (!virHostdevPreparePCIDevices(mgr, "test_driver1", dom_name, uuid,
                                      &hostdevs[2], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevReAttachPCIHostdevs_managed(bool mixed)
{
    int ret = -1;
    size_t active_count, inactive_count, i;

    for (i = 0; i < nhostdevs; i++) {
        if (hostdevs[i]->managed != true) {
            VIR_DEBUG("invalid test");
            return -1;
        }
    }

    active_count = virPCIDeviceListCount(mgr->activePCIHostdevs);
    inactive_count = virPCIDeviceListCount(mgr->inactivePCIHostdevs);

    VIR_DEBUG("Test 0 hostdevs");
    virHostdevReAttachPCIDevices(mgr, drv_name, dom_name, NULL, 0, NULL);
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    VIR_DEBUG("Test >=1 hostdevs");
    virHostdevReAttachPCIDevices(mgr, drv_name, dom_name,
                                  hostdevs, nhostdevs, NULL);
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count - nhostdevs);
    /* If testing a mixed roundtrip, devices are added back to the inactive
     * list as soon as we detach from the guest */
    if (mixed)
        CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count + nhostdevs);
    else
        CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevDetachPCINodeDevice(void)
{
    int ret = -1;
    size_t active_count, inactive_count, i;

    for (i = 0; i < nhostdevs; i++) {
        active_count = virPCIDeviceListCount(mgr->activePCIHostdevs);
        inactive_count = virPCIDeviceListCount(mgr->inactivePCIHostdevs);
        if (virHostdevPCINodeDeviceDetach(mgr, dev[i]) < 0)
            goto cleanup;
        CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
        CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count + 1);
    }

    ret = 0;

 cleanup:
    return ret;
}

static int
testVirHostdevResetPCINodeDevice(void)
{
    int ret = -1;
    size_t active_count, inactive_count, i;

    for (i = 0; i < nhostdevs; i++) {
        active_count = virPCIDeviceListCount(mgr->activePCIHostdevs);
        inactive_count = virPCIDeviceListCount(mgr->inactivePCIHostdevs);
        if (virHostdevPCINodeDeviceReset(mgr, dev[i]) < 0)
            goto cleanup;
        CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
        CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);
    }

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevReAttachPCINodeDevice(void)
{
    int ret = -1;
    size_t active_count, inactive_count, i;

    for (i = 0; i < nhostdevs; i++) {
        active_count = virPCIDeviceListCount(mgr->activePCIHostdevs);
        inactive_count = virPCIDeviceListCount(mgr->inactivePCIHostdevs);
        if (virHostdevPCINodeDeviceReAttach(mgr, dev[i]) < 0)
            goto cleanup;
        CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
        CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count - 1);
    }

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevUpdateActivePCIHostdevs(void)
{
    int ret = -1;
    size_t active_count, inactive_count;

    active_count = virPCIDeviceListCount(mgr->activePCIHostdevs);
    inactive_count = virPCIDeviceListCount(mgr->inactivePCIHostdevs);

    VIR_DEBUG("Test 0 hostdevs");
    if (virHostdevUpdateActivePCIDevices(mgr, NULL, 0,
                                         drv_name, dom_name) < 0)
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    VIR_DEBUG("Test >=1 hostdevs");
    if (virHostdevUpdateActivePCIDevices(mgr, hostdevs, nhostdevs,
                                         drv_name, dom_name) < 0)
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, active_count + nhostdevs);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, inactive_count);

    ret = 0;

 cleanup:
    return ret;
}

/**
 * testVirHostdevRoundtripNoGuest:
 * @opaque: unused
 *
 * Perform a roundtrip without ever assigning devices to the guest.
 *
 *   1. Detach devices from the host
 *   2. Reattach devices to the host
 */
static int
testVirHostdevRoundtripNoGuest(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;

    if (testVirHostdevDetachPCINodeDevice() < 0)
        goto out;
    if (testVirHostdevReAttachPCINodeDevice() < 0)
        goto out;

    ret = 0;

 out:
    return ret;
}

/**
 * testVirHostdevRoundtripUnmanaged:
 * @opaque: unused
 *
 * Perform a roundtrip with unmanaged devices.
 *
 *   1. Detach devices from the host
 *   2. Attach devices to the guest as unmanaged
 *   3. Detach devices from the guest as unmanaged
 *   4. Reattach devices to the host
 */
static int
testVirHostdevRoundtripUnmanaged(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;

    if (testVirHostdevDetachPCINodeDevice() < 0)
        goto out;
    if (virHostdevHostSupportsPassthroughKVM()) {
        if (testVirHostdevPreparePCIHostdevs_unmanaged() < 0)
            goto out;
        if (testVirHostdevReAttachPCIHostdevs_unmanaged() < 0)
            goto out;
    }
    if (testVirHostdevReAttachPCINodeDevice() < 0)
        goto out;

    ret = 0;

 out:
    return ret;
}

/**
 * testVirHostdevRoundtripManaged:
 * @opaque: unused
 *
 * Perform a roundtrip with managed devices.
 *
 *   1. Attach devices to the guest as managed
 *   2. Detach devices from the guest as managed
 */
static int
testVirHostdevRoundtripManaged(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;

    if (virHostdevHostSupportsPassthroughKVM()) {
        if (testVirHostdevPreparePCIHostdevs_managed(false) < 0)
            goto out;
        if (testVirHostdevReAttachPCIHostdevs_managed(false) < 0)
            goto out;
    }

    ret = 0;

 out:
    return ret;
}

/**
 * testVirHostdevRoundtripMixed:
 * @opaque: unused
 *
 * Perform a roundtrip with managed devices but manually detach the devices
 * from the host first.
 *
 *   1. Detach devices from the host
 *   2. Attach devices to the guest as managed
 *   3. Detach devices from the guest as managed
 *   4. Reattach devices to the host
 */
static int
testVirHostdevRoundtripMixed(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;

    if (testVirHostdevDetachPCINodeDevice() < 0)
        goto out;
    if (virHostdevHostSupportsPassthroughKVM()) {
        if (testVirHostdevPreparePCIHostdevs_managed(true) < 0)
            goto out;
        if (testVirHostdevReAttachPCIHostdevs_managed(true) < 0)
            goto out;
    }
    if (testVirHostdevReAttachPCINodeDevice() < 0)
        goto out;

    ret = 0;

 out:
    return ret;
}

/**
 * testVirHostdevOther:
 * @opaque: unused
 *
 * Perform other operations on devices.
 *
 *   1. Reset devices
 *   2. Update list of active devices
 */
static int
testVirHostdevOther(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;

    if (testVirHostdevResetPCINodeDevice() < 0)
        goto out;
    if (testVirHostdevUpdateActivePCIHostdevs() < 0)
        goto out;

    ret = 0;

 out:
    return ret;
}

# define FAKEROOTDIRTEMPLATE abs_builddir "/fakerootdir-XXXXXX"

static int
mymain(void)
{
    int ret = 0;
    char *fakerootdir;

    if (VIR_STRDUP_QUIET(fakerootdir, FAKEROOTDIRTEMPLATE) < 0) {
        fprintf(stderr, "Out of memory\n");
        abort();
    }

    if (!mkdtemp(fakerootdir)) {
        fprintf(stderr, "Cannot create fakerootdir");
        abort();
    }

    setenv("LIBVIRT_FAKE_ROOT_DIR", fakerootdir, 1);

# define DO_TEST(fnc)                                   \
    do {                                                \
        VIR_DEBUG("Testing: %s", #fnc);                 \
        if (virTestRun(#fnc, fnc, NULL) < 0)            \
            ret = -1;                                   \
    } while (0)

    if (myInit() < 0)
        fprintf(stderr, "Init data structures failed.");

    DO_TEST(testVirHostdevRoundtripNoGuest);
    DO_TEST(testVirHostdevRoundtripUnmanaged);
    DO_TEST(testVirHostdevRoundtripManaged);
    DO_TEST(testVirHostdevRoundtripMixed);
    DO_TEST(testVirHostdevOther);

    myCleanup();

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
