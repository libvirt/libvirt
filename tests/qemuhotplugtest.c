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

enum {
    ATTACH,
    DETACH,
    UPDATE
};

struct qemuHotplugTestData {
    const char *domain_filename;
    const char *device_filename;
    bool fail;
    const char *const *mon;
    int action;
    bool keep;
    virDomainObjPtr vm;
};

static int
qemuHotplugCreateObjects(virDomainXMLOptionPtr xmlopt,
                         virDomainObjPtr *vm,
                         const char *filename)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = NULL;

    if (!(*vm = virDomainObjNew(xmlopt)))
        goto cleanup;

    if (!((*vm)->def = virDomainDefParseFile(filename,
                                             driver.caps,
                                             driver.xmlopt,
                                             QEMU_EXPECTED_VIRT_TYPES,
                                             0)))
        goto cleanup;

    priv = (*vm)->privateData;

    if (!(priv->qemuCaps = virQEMUCapsNew()))
        goto cleanup;

    /* for attach & detach qemu must support -device */
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE);

    ret = 0;
cleanup:
    return ret;
}

static int
testQemuHotplugAttach(virDomainObjPtr vm,
                      virDomainDeviceDefPtr dev)
{
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_CHR:
        ret = qemuDomainAttachChrDevice(&driver, vm, dev->data.chr);
        if (!ret) {
            /* vm->def stolen dev->data.chr so we ought to avoid freeing it */
            dev->data.chr = NULL;
        }
        break;
    default:
        if (virTestGetVerbose())
            fprintf(stderr, "device type '%s' cannot be attached",
                    virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}

static int
testQemuHotplugDetach(virDomainObjPtr vm,
                      virDomainDeviceDefPtr dev)
{
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_CHR:
        ret = qemuDomainDetachChrDevice(&driver, vm, dev->data.chr);
        break;
    default:
        if (virTestGetVerbose())
            fprintf(stderr, "device type '%s' cannot be attached",
                    virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}

static int
testQemuHotplugUpdate(virDomainObjPtr vm,
                      virDomainDeviceDefPtr dev)
{
    int ret = -1;

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
    bool keep = test->keep;
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

    if (test->vm) {
        vm = test->vm;
    } else {
        if (qemuHotplugCreateObjects(driver.xmlopt, &vm, domain_filename) < 0)
            goto cleanup;
    }

    if (virtTestLoadFile(device_filename, &device_xml) < 0)
        goto cleanup;

    if (!(dev = virDomainDeviceDefParse(device_xml, vm->def,
                                        caps, driver.xmlopt, 0)))
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

    priv = vm->privateData;
    priv->mon = qemuMonitorTestGetMonitor(test_mon);
    priv->monJSON = true;

    /* XXX We need to unlock the monitor here, as
     * qemuDomainObjEnterMonitorInternal (called from qemuDomainChangeGraphics)
     * tries to lock it again */
    virObjectUnlock(priv->mon);

    switch (test->action) {
    case ATTACH:
        ret = testQemuHotplugAttach(vm, dev);
        break;

    case DETACH:
        ret = testQemuHotplugDetach(vm, dev);
        break;

    case UPDATE:
        ret = testQemuHotplugUpdate(vm, dev);
    }

cleanup:
    VIR_FREE(domain_filename);
    VIR_FREE(device_filename);
    VIR_FREE(device_xml);
    /* don't dispose test monitor with VM */
    if (priv)
        priv->mon = NULL;
    if (keep) {
        test->vm = vm;
    } else {
        virObjectUnref(vm);
        test->vm = NULL;
    }
    virDomainDeviceDefFree(dev);
    virObjectUnref(caps);
    qemuMonitorTestFree(test_mon);
    return ((ret < 0 && fail) || (!ret && !fail)) ? 0 : -1;
}

static int
mymain(void)
{
    int ret = 0;
    struct qemuHotplugTestData data = {0};

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

    if (!(driver.domainEventState = virDomainEventStateNew()))
        return EXIT_FAILURE;

    /* some dummy values from 'config file' */
    if (VIR_STRDUP_QUIET(driver.config->spicePassword, "123456") < 0)
        return EXIT_FAILURE;

#define DO_TEST(file, dev, fial, kep, ...)                                  \
        const char *my_mon[] = { __VA_ARGS__, NULL};                        \
        data.domain_filename = file;                                        \
        data.device_filename = dev;                                         \
        data.fail = fial;                                                   \
        data.mon = my_mon;                                                  \
        data.keep = kep;                                                    \
        if (virtTestRun(#file, 1, testQemuHotplug, &data) < 0)              \
            ret = -1;                                                       \

#define DO_TEST_ATTACH(file, dev, fial, kep, ...)                           \
    do {                                                                    \
        data.action = ATTACH;                                               \
        DO_TEST(file, dev, fial, kep, __VA_ARGS__)                          \
    } while (0)

#define DO_TEST_DETACH(file, dev, fial, kep, ...)                           \
    do {                                                                    \
        data.action = DETACH;                                               \
        DO_TEST(file, dev, fial, kep, __VA_ARGS__)                          \
    } while (0)

#define DO_TEST_UPDATE(file, dev, fial, kep, ...)                           \
    do {                                                                    \
        data.action = UPDATE;                                               \
        DO_TEST(file, dev, fial, kep, __VA_ARGS__)                          \
    } while (0)

    DO_TEST_UPDATE("graphics-spice", "graphics-spice-nochange", false, false, NULL);
    DO_TEST_UPDATE("graphics-spice-timeout", "graphics-spice-timeout-nochange", false, false,
                   "set_password", "{\"return\":{}}", "expire_password", "{\"return\":{}}");
    DO_TEST_UPDATE("graphics-spice-timeout", "graphics-spice-timeout-password", false, false,
                   "set_password", "{\"return\":{}}", "expire_password", "{\"return\":{}}");
    DO_TEST_UPDATE("graphics-spice", "graphics-spice-listen", true, false, NULL);
    DO_TEST_UPDATE("graphics-spice-listen-network", "graphics-spice-listen-network", false, false,
                   "set_password", "{\"return\":{}}", "expire_password", "{\"return\":{}}");
    /* Strange huh? Currently, only graphics can be updated :-P */
    DO_TEST_UPDATE("disk-cdrom", "disk-cdrom-nochange", true, false, NULL);

    DO_TEST_ATTACH("console-compat-2", "console-virtio", false, true,
                   "chardev-add", "{\"return\": {\"pty\": \"/dev/pts/26\"}}",
                   "device_add", "{\"return\": {}}");

    DO_TEST_DETACH("console-compat-2", "console-virtio", false, false,
                   "device_del", "{\"return\": {}}",
                   "chardev-remove", "{\"return\": {}}");

    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);
    virObjectUnref(driver.config);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
