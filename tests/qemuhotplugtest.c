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
#include "qemu/qemu_hotplugpriv.h"
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
    bool deviceDeletedEvent;
};

static int
qemuHotplugCreateObjects(virDomainXMLOptionPtr xmlopt,
                         virDomainObjPtr *vm,
                         const char *domxml,
                         bool event)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = NULL;

    if (!(*vm = virDomainObjNew(xmlopt)))
        goto cleanup;

    if (!((*vm)->def = virDomainDefParseString(domxml,
                                               driver.caps,
                                               driver.xmlopt,
                                               QEMU_EXPECTED_VIRT_TYPES,
                                               VIR_DOMAIN_XML_INACTIVE)))
        goto cleanup;

    priv = (*vm)->privateData;

    if (!(priv->qemuCaps = virQEMUCapsNew()))
        goto cleanup;

    /* for attach & detach qemu must support -device */
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DRIVE);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_NET_NAME);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_VIRTIO_SCSI);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_USB_STORAGE);
    if (event)
        virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_DEL_EVENT);

    if (qemuDomainAssignPCIAddresses((*vm)->def, priv->qemuCaps, *vm) < 0)
        goto cleanup;

    if (qemuAssignDeviceAliases((*vm)->def, priv->qemuCaps) < 0)
        goto cleanup;

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
    case VIR_DOMAIN_DEVICE_DISK:
        /* conn in only used for storage pool and secrets lookup so as long
         * as we don't use any of them, passing NULL should be safe
         */
        ret = qemuDomainAttachDeviceDiskLive(NULL, &driver, vm, dev);
        break;
    case VIR_DOMAIN_DEVICE_CHR:
        ret = qemuDomainAttachChrDevice(&driver, vm, dev->data.chr);
        break;
    default:
        if (virTestGetVerbose())
            fprintf(stderr, "device type '%s' cannot be attached\n",
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
    case VIR_DOMAIN_DEVICE_DISK:
        ret = qemuDomainDetachDeviceDiskLive(&driver, vm, dev);
        break;
    case VIR_DOMAIN_DEVICE_CHR:
        ret = qemuDomainDetachChrDevice(&driver, vm, dev->data.chr);
        break;
    default:
        if (virTestGetVerbose())
            fprintf(stderr, "device type '%s' cannot be detached\n",
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
            fprintf(stderr, "device type '%s' cannot be updated\n",
                    virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}

static int
testQemuHotplugCheckResult(virDomainObjPtr vm,
                           const char *expected,
                           bool fail)
{
    char *actual;
    int ret;

    actual = virDomainDefFormat(vm->def, VIR_DOMAIN_XML_SECURE);
    if (!actual)
        return -1;

    if (STREQ(expected, actual)) {
        if (fail && virTestGetVerbose())
            fprintf(stderr, "domain XML should not match the expected result\n");
        ret = 0;
    } else {
        if (!fail)
            virtTestDifference(stderr, expected, actual);
        ret = -1;
    }

    VIR_FREE(actual);
    return ret;
}

static int
testQemuHotplug(const void *data)
{
    int ret = -1;
    struct qemuHotplugTestData *test = (struct qemuHotplugTestData *) data;
    char *domain_filename = NULL;
    char *device_filename = NULL;
    char *result_filename = NULL;
    char *domain_xml = NULL;
    char *device_xml = NULL;
    char *result_xml = NULL;
    const char *const *tmp;
    bool fail = test->fail;
    bool keep = test->keep;
    unsigned int device_parse_flags = 0;
    virDomainObjPtr vm = NULL;
    virDomainDeviceDefPtr dev = NULL;
    virCapsPtr caps = NULL;
    qemuMonitorTestPtr test_mon = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    if (virAsprintf(&domain_filename, "%s/qemuxml2argvdata/qemuxml2argv-%s.xml",
                    abs_srcdir, test->domain_filename) < 0 ||
        virAsprintf(&device_filename, "%s/qemuhotplugtestdata/qemuhotplug-%s.xml",
                    abs_srcdir, test->device_filename) < 0 ||
        virAsprintf(&result_filename,
                    "%s/qemuhotplugtestdata/qemuhotplug-%s+%s.xml",
                    abs_srcdir, test->domain_filename,
                    test->device_filename) < 0)
        goto cleanup;

    if (virtTestLoadFile(domain_filename, &domain_xml) < 0 ||
        virtTestLoadFile(device_filename, &device_xml) < 0)
        goto cleanup;

    if (test->action != UPDATE &&
        virtTestLoadFile(result_filename, &result_xml) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(&driver, false)))
        goto cleanup;

    if (test->vm) {
        vm = test->vm;
    } else {
        if (qemuHotplugCreateObjects(driver.xmlopt, &vm, domain_xml,
                                     test->deviceDeletedEvent) < 0)
            goto cleanup;
    }

    if (test->action == ATTACH)
        device_parse_flags = VIR_DOMAIN_XML_INACTIVE;

    if (!(dev = virDomainDeviceDefParse(device_xml, vm->def,
                                        caps, driver.xmlopt,
                                        device_parse_flags)))
        goto cleanup;

    /* Now is the best time to feed the spoofed monitor with predefined
     * replies. */
    if (!(test_mon = qemuMonitorTestNew(true, driver.xmlopt, vm, &driver, NULL)))
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
        if (ret == 0) {
            /* vm->def stolen dev->data.* so we just need to free the dev
             * envelope */
            VIR_FREE(dev);
        }
        if (ret == 0 || fail)
            ret = testQemuHotplugCheckResult(vm, result_xml, fail);
        break;

    case DETACH:
        ret = testQemuHotplugDetach(vm, dev);
        if (ret == 0 || fail)
            ret = testQemuHotplugCheckResult(vm, domain_xml, fail);
        break;

    case UPDATE:
        ret = testQemuHotplugUpdate(vm, dev);
    }

 cleanup:
    VIR_FREE(domain_filename);
    VIR_FREE(device_filename);
    VIR_FREE(result_filename);
    VIR_FREE(domain_xml);
    VIR_FREE(device_xml);
    VIR_FREE(result_xml);
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
    virSecurityManagerPtr mgr;

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

    if (!(driver.domainEventState = virObjectEventStateNew()))
        return EXIT_FAILURE;

    driver.lockManager = virLockManagerPluginNew("nop", "qemu",
                                                 driver.config->configBaseDir,
                                                 0);
    if (!driver.lockManager)
        return EXIT_FAILURE;

    if (!(mgr = virSecurityManagerNew("none", "qemu", false, false, false)))
        return EXIT_FAILURE;
    if (!(driver.securityManager = virSecurityManagerNewStack(mgr)))
        return EXIT_FAILURE;

    /* wait only 100ms for DEVICE_DELETED event */
    qemuDomainRemoveDeviceWaitTime = 100;

#define DO_TEST(file, ACTION, dev, event, fial, kep, ...)                   \
    do {                                                                    \
        const char *my_mon[] = { __VA_ARGS__, NULL};                        \
        const char *name = file " " #ACTION " " dev;                        \
        data.action = ACTION;                                               \
        data.domain_filename = file;                                        \
        data.device_filename = dev;                                         \
        data.fail = fial;                                                   \
        data.mon = my_mon;                                                  \
        data.keep = kep;                                                    \
        data.deviceDeletedEvent = event;                                    \
        if (virtTestRun(name, testQemuHotplug, &data) < 0)                  \
            ret = -1;                                                       \
    } while (0)

#define DO_TEST_ATTACH(file, dev, fial, kep, ...)                           \
    DO_TEST(file, ATTACH, dev, false, fial, kep, __VA_ARGS__)

#define DO_TEST_DETACH(file, dev, fial, kep, ...)                           \
    DO_TEST(file, DETACH, dev, false, fial, kep, __VA_ARGS__)

#define DO_TEST_ATTACH_EVENT(file, dev, fial, kep, ...)                     \
    DO_TEST(file, ATTACH, dev, true, fial, kep, __VA_ARGS__)

#define DO_TEST_DETACH_EVENT(file, dev, fial, kep, ...)                     \
    DO_TEST(file, DETACH, dev, true, fial, kep, __VA_ARGS__)

#define DO_TEST_UPDATE(file, dev, fial, kep, ...)                           \
    DO_TEST(file, UPDATE, dev, false, fial, kep, __VA_ARGS__)


#define QMP_OK      "{\"return\": {}}"
#define HMP(msg)    "{\"return\": \"" msg "\"}"

#define QMP_DEVICE_DELETED(dev) \
    "{"                                                     \
    "    \"timestamp\": {"                                  \
    "        \"seconds\": 1374137171,"                      \
    "        \"microseconds\": 2659"                        \
    "    },"                                                \
    "    \"event\": \"DEVICE_DELETED\","                    \
    "    \"data\": {"                                       \
    "        \"device\": \"" dev "\","                      \
    "        \"path\": \"/machine/peripheral/" dev "\""     \
    "    }"                                                 \
    "}\r\n"

    DO_TEST_UPDATE("graphics-spice", "graphics-spice-nochange", false, false, NULL);
    DO_TEST_UPDATE("graphics-spice-timeout", "graphics-spice-timeout-nochange", false, false,
                   "set_password", QMP_OK, "expire_password", QMP_OK);
    DO_TEST_UPDATE("graphics-spice-timeout", "graphics-spice-timeout-password", false, false,
                   "set_password", QMP_OK, "expire_password", QMP_OK);
    DO_TEST_UPDATE("graphics-spice", "graphics-spice-listen", true, false, NULL);
    DO_TEST_UPDATE("graphics-spice-listen-network", "graphics-spice-listen-network", false, false,
                   "set_password", QMP_OK, "expire_password", QMP_OK);
    /* Strange huh? Currently, only graphics can be updated :-P */
    DO_TEST_UPDATE("disk-cdrom", "disk-cdrom-nochange", true, false, NULL);

    DO_TEST_ATTACH("console-compat-2", "console-virtio", false, true,
                   "chardev-add", "{\"return\": {\"pty\": \"/dev/pts/26\"}}",
                   "device_add", QMP_OK);

    DO_TEST_DETACH("console-compat-2", "console-virtio", false, false,
                   "device_del", QMP_OK,
                   "chardev-remove", QMP_OK);

    DO_TEST_ATTACH("hotplug-base", "disk-virtio", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("hotplug-base", "disk-virtio", false, false,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH_EVENT("hotplug-base", "disk-virtio", false, true,
                         "human-monitor-command", HMP("OK\\r\\n"),
                         "device_add", QMP_OK);
    DO_TEST_DETACH("hotplug-base", "disk-virtio", true, true,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));
    DO_TEST_DETACH("hotplug-base", "disk-virtio", false, false,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk4") QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("hotplug-base", "disk-usb", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("hotplug-base", "disk-usb", false, false,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH_EVENT("hotplug-base", "disk-usb", false, true,
                         "human-monitor-command", HMP("OK\\r\\n"),
                         "device_add", QMP_OK);
    DO_TEST_DETACH("hotplug-base", "disk-usb", true, true,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));
    DO_TEST_DETACH("hotplug-base", "disk-usb", false, false,
                   "device_del", QMP_DEVICE_DELETED("usb-disk16") QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("hotplug-base", "disk-scsi", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("hotplug-base", "disk-scsi", false, false,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH_EVENT("hotplug-base", "disk-scsi", false, true,
                         "human-monitor-command", HMP("OK\\r\\n"),
                         "device_add", QMP_OK);
    DO_TEST_DETACH("hotplug-base", "disk-scsi", true, true,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));
    DO_TEST_DETACH("hotplug-base", "disk-scsi", false, false,
                   "device_del", QMP_DEVICE_DELETED("scsi0-0-0-5") QMP_OK,
                   "human-monitor-command", HMP(""));

    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);
    virObjectUnref(driver.config);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
