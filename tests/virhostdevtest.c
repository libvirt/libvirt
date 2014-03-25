/*
 * Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

# define CHECK_LIST_COUNT(list, cnt)                                    \
    if ((count = virPCIDeviceListCount(list)) != cnt) {                 \
        virReportError(VIR_ERR_INTERNAL_ERROR,                          \
                       "Unexpected count of items in " #list ": %d, "   \
                       "expecting %zu", count, (size_t) cnt);           \
        goto cleanup;                                                   \
    }

# define TEST_STATE_DIR abs_builddir "/hostdevmgr"
static const char *drv_name = "test_driver";
static const char *dom_name = "test_domain";
static const unsigned char *uuid =
            (unsigned char *)("f92360b0-2541-8791-fb32-d1f838811541");
static int nhostdevs = 3;
static virDomainHostdevDefPtr hostdevs[] = {NULL, NULL, NULL};
static virPCIDevicePtr dev[] = {NULL, NULL, NULL};
static virHostdevManagerPtr mgr = NULL;

static void
myCleanup(void)
{
    size_t i;
    for (i = 0; i < nhostdevs; i++) {
         virPCIDeviceFree(dev[i]);
         virDomainHostdevDefFree(hostdevs[i]);
    }

    if (mgr) {
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
        hostdevs[i] = virDomainHostdevDefAlloc();
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
        if (!(dev[i] = virPCIDeviceNew(0, 0, i + 1, 0)) ||
            virPCIDeviceSetStubDriver(dev[i], "pci-stub") < 0)
            goto cleanup;
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
testVirHostdevPreparePCIHostdevs_unmanaged(const void *oaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    size_t i;
    int count, count1, count2;

    for (i = 0; i < nhostdevs; i++)
         hostdevs[i]->managed = false;

    count1 = virPCIDeviceListCount(mgr->activePCIHostdevs);
    count2 = virPCIDeviceListCount(mgr->inactivePCIHostdevs);

    /* Test normal functionality */
    VIR_DEBUG("Test 0 hostdevs\n");
    if (virHostdevPreparePCIDevices(mgr, drv_name, dom_name, uuid,
                                    NULL, 0, 0) < 0)
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1);

    /* Test unmanaged hostdevs */
    VIR_DEBUG("Test >=1 unmanaged hostdevs\n");
    if (virHostdevPreparePCIDevices(mgr, drv_name, dom_name, uuid,
                                    hostdevs, nhostdevs, 0) < 0)
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1 + 3);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, count2 - 3);

    /* Test conflict */
    count1 = virPCIDeviceListCount(mgr->activePCIHostdevs);
    count2 = virPCIDeviceListCount(mgr->inactivePCIHostdevs);
    VIR_DEBUG("Test: prepare same hostdevs for same driver/domain again\n");
    if (!virHostdevPreparePCIDevices(mgr, drv_name, dom_name, uuid,
                                     &hostdevs[0], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, count2);

    VIR_DEBUG("Test: prepare same hostdevs for same driver, diff domain again\n");
    if (!virHostdevPreparePCIDevices(mgr, drv_name, "test_domain1", uuid,
                                     &hostdevs[1], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, count2);

    VIR_DEBUG("Test: prepare same hostdevs for diff driver/domain again\n");
    if (!virHostdevPreparePCIDevices(mgr, "test_driver1", dom_name, uuid,
                                     &hostdevs[2], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, count2);

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevReAttachPCIHostdevs_unmanaged(const void *oaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    size_t i;
    int count, count1, count2;

    for (i = 0; i < nhostdevs; i++) {
        if (hostdevs[i]->managed != false) {
            VIR_DEBUG("invalid test\n");
            return -1;
        }
    }

    count1 = virPCIDeviceListCount(mgr->activePCIHostdevs);
    count2 = virPCIDeviceListCount(mgr->inactivePCIHostdevs);

    VIR_DEBUG("Test 0 hostdevs\n");
    virHostdevReAttachPCIDevices(mgr, drv_name, dom_name, NULL, 0, NULL);
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1);

    VIR_DEBUG("Test >=1 unmanaged hostdevs\n");
    virHostdevReAttachPCIDevices(mgr, drv_name, dom_name,
                                  hostdevs, nhostdevs, NULL);
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1 - 3);
    CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, count2 + 3);

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevPreparePCIHostdevs_managed(const void *oaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    size_t i;
    int count, count1;

    for (i = 0; i < nhostdevs; i++)
        hostdevs[i]->managed = true;

    count1 = virPCIDeviceListCount(mgr->activePCIHostdevs);

    /* Test normal functionality */
    VIR_DEBUG("Test >=1 hostdevs\n");
    if (virHostdevPreparePCIDevices(mgr, drv_name, dom_name, uuid,
                                     hostdevs, nhostdevs, 0) < 0)
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1 + 3);

    /* Test conflict */
    count1 = virPCIDeviceListCount(mgr->activePCIHostdevs);
    VIR_DEBUG("Test: prepare same hostdevs for same driver/domain again\n");
    if (!virHostdevPreparePCIDevices(mgr, drv_name, dom_name, uuid,
                                      &hostdevs[0], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1);

    VIR_DEBUG("Test: prepare same hostdevs for same driver, diff domain again\n");
    if (!virHostdevPreparePCIDevices(mgr, drv_name, "test_domain1", uuid,
                                      &hostdevs[1], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1);

    VIR_DEBUG("Test: prepare same hostdevs for diff driver/domain again\n");
    if (!virHostdevPreparePCIDevices(mgr, "test_driver1", dom_name, uuid,
                                      &hostdevs[2], 1, 0))
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1);

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevReAttachPCIHostdevs_managed(const void *oaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    size_t i;
    int count, count1;

    for (i = 0; i < nhostdevs; i++) {
        if (hostdevs[i]->managed != true) {
            VIR_DEBUG("invalid test\n");
            return -1;
        }
    }

    count1 = virPCIDeviceListCount(mgr->activePCIHostdevs);

    VIR_DEBUG("Test 0 hostdevs\n");
    virHostdevReAttachPCIDevices(mgr, drv_name, dom_name, NULL, 0, NULL);
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1);

    VIR_DEBUG("Test >=1 hostdevs\n");
    virHostdevReAttachPCIDevices(mgr, drv_name, dom_name,
                                  hostdevs, nhostdevs, NULL);
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1 - 3);

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevDetachPCINodeDevice(const void *oaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    size_t i;
    int count, count1;

    for (i = 0; i < nhostdevs; i++) {
        count1 = virPCIDeviceListCount(mgr->inactivePCIHostdevs);
        if (virHostdevPCINodeDeviceDetach(mgr, dev[i]) < 0)
            goto cleanup;
        CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, count1 + 1);
    }

    ret = 0;

 cleanup:
    return ret;
}
static int
testVirHostdevResetPCINodeDevice(const void *oaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    size_t i;

    for (i = 0; i < nhostdevs; i++) {
        if (virHostdevPCINodeDeviceReset(mgr, dev[i]) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevReAttachPCINodeDevice(const void *oaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    size_t i;
    int count, count1;

    for (i = 0; i < nhostdevs; i++) {
        count1 = virPCIDeviceListCount(mgr->inactivePCIHostdevs);
        if (virHostdevPCINodeDeviceReAttach(mgr, dev[i]) < 0)
            goto cleanup;
        CHECK_LIST_COUNT(mgr->inactivePCIHostdevs, count1 - 1);
    }

    ret = 0;

 cleanup:
    return ret;

}

static int
testVirHostdevUpdateActivePCIHostdevs(const void *oaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    int count, count1;

    count1 = virPCIDeviceListCount(mgr->activePCIHostdevs);

    VIR_DEBUG("Test 0 hostdevs\n");
    if (virHostdevUpdateActivePCIDevices(mgr, NULL, 0,
                                         drv_name, dom_name) < 0)
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1);

    VIR_DEBUG("Test >=1 hostdevs\n");
    if (virHostdevUpdateActivePCIDevices(mgr, hostdevs, nhostdevs,
                                         drv_name, dom_name) < 0)
        goto cleanup;
    CHECK_LIST_COUNT(mgr->activePCIHostdevs, count1 + 3);

    ret = 0;

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
        VIR_DEBUG("\nTesting: %s", #fnc);                 \
        if (virtTestRun(#fnc, fnc, NULL) < 0)           \
            ret = -1;                                   \
    } while (0)

    if (myInit() < 0)
        fprintf(stderr, "Init data structures failed.");

    DO_TEST(testVirHostdevDetachPCINodeDevice);
    if (virHostdevHostSupportsPassthroughKVM()) {
        /* following tests would check KVM support */
        DO_TEST(testVirHostdevPreparePCIHostdevs_unmanaged);
        DO_TEST(testVirHostdevReAttachPCIHostdevs_unmanaged);
    }
    DO_TEST(testVirHostdevResetPCINodeDevice);
    DO_TEST(testVirHostdevReAttachPCINodeDevice);
    if (virHostdevHostSupportsPassthroughKVM()) {
        /* following tests would check KVM support */
        DO_TEST(testVirHostdevPreparePCIHostdevs_managed);
        DO_TEST(testVirHostdevReAttachPCIHostdevs_managed);
    }
    DO_TEST(testVirHostdevUpdateActivePCIHostdevs);

    myCleanup();

    if (getenv("LIBVIRT_SKIP_CLEANUP") == NULL)
        virFileDeleteTree(fakesysfsdir);

    VIR_FREE(fakesysfsdir);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virpcimock.so")
#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
