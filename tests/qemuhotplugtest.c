/*
 * Copyright (C) 2011-2013 Red Hat, Inc.
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
 */

#include <config.h>

#include "qemu/qemu_conf.h"
#include "qemu/qemu_hotplug.h"
#include "qemumonitortestutils.h"
#include "testutils.h"
#include "testutilsqemu.h"
#include "virerror.h"
#include "virstring.h"
#include "virthread.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virQEMUDriver driver;

struct qemuHotplugTestData {
    const char *domain_filename;
    const char *device_filename;
    bool fail;
    const char *const *mon;
};

static int
qemuHotplugCreateObjects(virDomainXMLOptionPtr xmlopt,
                         virDomainObjPtr *vm,
                         const char *filename)
{
    int ret = -1;

    if (!(*vm = virDomainObjNew(xmlopt)))
        goto cleanup;

    if (!((*vm)->def = virDomainDefParseFile(filename,
                                             driver.caps,
                                             driver.xmlopt,
                                             QEMU_EXPECTED_VIRT_TYPES,
                                             0)))
        goto cleanup;

    ret = 0;
cleanup:
    return ret;
}

static int
testQemuHotplug(const void *data)
{
    int ret = -1;
    struct qemuHotplugTestData *test = (struct qemuHotplugTestData *) data;
    char *domain_filename = NULL;
    char *device_filename = NULL;
    char *device_xml = NULL;
    const char *const *tmp;
    bool fail = test->fail;
    virDomainObjPtr vm = NULL;
    virDomainDeviceDefPtr dev = NULL;
    virCapsPtr caps = NULL;
    qemuMonitorTestPtr test_mon = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    if (virAsprintf(&domain_filename, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
                    abs_srcdir, test->domain_filename) < 0 ||
        virAsprintf(&device_filename, "%s/qemuhotplugtestdata/qemuhotplug-%s.xml",
                    abs_srcdir, test->device_filename) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(&driver, false)))
        goto cleanup;

    if (qemuHotplugCreateObjects(driver.xmlopt, &vm, domain_filename) < 0)
        goto cleanup;

    priv = vm->privateData;

    if (virtTestLoadFile(device_filename, &device_xml) < 0)
        goto cleanup;

    if (!(dev = virDomainDeviceDefParse(device_xml, vm->def,
                                        caps, driver.xmlopt,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    /* Now is the best time to feed the spoofed monitor with predefined
     * replies. */
    if (!(test_mon = qemuMonitorTestNew(true, driver.xmlopt)))
        goto cleanup;

    tmp = test->mon;
    while (tmp && *tmp) {
        const char *command_name;
        const char *response;

        if (!(command_name = *tmp++) ||
            !(response = *tmp++))
            break;
        if (qemuMonitorTestAddItem(test_mon, command_name, response) < 0)
            goto cleanup;
    }

    priv->mon = qemuMonitorTestGetMonitor(test_mon);
    priv->monJSON = true;

    /* XXX We need to unlock the monitor here, as
     * qemuDomainObjEnterMonitorInternal (called from qemuDomainChangeGraphics)
     * tries to lock it again */
    virObjectUnlock(priv->mon);

    /* XXX Ideally, we would call qemuDomainUpdateDeviceLive here.  But that
     * would require us to provide virConnectPtr and virDomainPtr (they're used
     * in case of updating a disk device. So for now, we will proceed with
     * breaking the function into pieces. If we ever learn how to fake those
     * required object, we can replace this code then. */
    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_GRAPHICS:
        ret = qemuDomainChangeGraphics(&driver, vm, dev->data.graphics);
        break;
    default:
        if (virTestGetVerbose())
            fprintf(stderr, "device type '%s' cannot be updated",
                    virDomainDeviceTypeToString(dev->type));
        break;
    }

cleanup:
    VIR_FREE(domain_filename);
    VIR_FREE(device_filename);
    VIR_FREE(device_xml);
    /* don't dispose test monitor with VM */
    if (priv)
        priv->mon = NULL;
    virObjectUnref(vm);
    virDomainDeviceDefFree(dev);
    virObjectUnref(caps);
    qemuMonitorTestFree(test_mon);
    return ((ret < 0 && fail) || (!ret && !fail)) ? 0 : -1;
}

static int
mymain(void)
{
    int ret = 0;

#if !WITH_YAJL
    fputs("libvirt not compiled with yajl, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    if (virThreadInitialize() < 0 ||
        !(driver.caps = testQemuCapsInit()) ||
        !(driver.xmlopt = virQEMUDriverCreateXMLConf(&driver)))
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

    driver.config = virQEMUDriverConfigNew(false);
    VIR_FREE(driver.config->spiceListen);
    VIR_FREE(driver.config->vncListen);

    /* some dummy values from 'config file' */
    if (VIR_STRDUP_QUIET(driver.config->spicePassword, "123456") < 0)
        return EXIT_FAILURE;

#define DO_TEST(file, dev, fial, ...) \
    do { \
        const char *my_mon[] = { __VA_ARGS__, NULL}; \
        struct qemuHotplugTestData data =                                    \
            {.domain_filename = file, .device_filename = dev, .fail = fial,  \
             .mon = my_mon}; \
        if (virtTestRun(#file, 1, testQemuHotplug, &data) < 0)               \
            ret = -1;                                                        \
    } while (0)

    DO_TEST("graphics-spice", "graphics-spice-nochange", false, NULL);
    DO_TEST("graphics-spice-timeout", "graphics-spice-timeout-nochange", false,
            "set_password", "{\"return\":{}}", "expire_password", "{\"return\":{}}");
    DO_TEST("graphics-spice-timeout", "graphics-spice-timeout-password", false,
            "set_password", "{\"return\":{}}", "expire_password", "{\"return\":{}}");
    DO_TEST("graphics-spice", "graphics-spice-listen", true, NULL);
    DO_TEST("graphics-spice-listen-network", "graphics-spice-listen-network", false,
            "set_password", "{\"return\":{}}", "expire_password", "{\"return\":{}}");
    /* Strange huh? Currently, only graphics can be testet :-P */
    DO_TEST("disk-cdrom", "disk-cdrom-nochange", true, NULL);

    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
