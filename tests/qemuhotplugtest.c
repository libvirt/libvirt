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

#include "qemu/qemu_alias.h"
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

#define QEMU_HOTPLUG_TEST_DOMAIN_ID 7

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
                         bool event, const char *testname)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = NULL;

    if (!(*vm = virDomainObjNew(xmlopt)))
        goto cleanup;

    priv = (*vm)->privateData;

    if (!(priv->qemuCaps = virQEMUCapsNew()))
        goto cleanup;

    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_VIRTIO_SCSI);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_USB_STORAGE);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_IVSHMEM_PLAIN);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_IVSHMEM_DOORBELL);
    if (event)
        virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_DEL_EVENT);

    if (qemuTestCapsCacheInsert(driver.qemuCapsCache, testname,
                                priv->qemuCaps) < 0)
        goto cleanup;

    if (!((*vm)->def = virDomainDefParseString(domxml,
                                               driver.caps,
                                               driver.xmlopt,
                                               NULL,
                                               VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto cleanup;

    if (qemuDomainAssignAddresses((*vm)->def, priv->qemuCaps,
                                  &driver, *vm, true) < 0) {
        goto cleanup;
    }

    if (qemuAssignDeviceAliases((*vm)->def, priv->qemuCaps) < 0)
        goto cleanup;

    (*vm)->def->id = QEMU_HOTPLUG_TEST_DOMAIN_ID;

    if (qemuDomainSetPrivatePaths(&driver, *vm) < 0)
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
        ret = qemuDomainAttachChrDevice(NULL, &driver, vm, dev->data.chr);
        break;
    case VIR_DOMAIN_DEVICE_SHMEM:
        ret = qemuDomainAttachShmemDevice(&driver, vm, dev->data.shmem);
        break;
    default:
        VIR_TEST_VERBOSE("device type '%s' cannot be attached\n",
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
    case VIR_DOMAIN_DEVICE_SHMEM:
        ret = qemuDomainDetachShmemDevice(&driver, vm, dev->data.shmem);
        break;
    default:
        VIR_TEST_VERBOSE("device type '%s' cannot be detached\n",
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
        VIR_TEST_VERBOSE("device type '%s' cannot be updated\n",
                virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}

static int
testQemuHotplugCheckResult(virDomainObjPtr vm,
                           const char *expected,
                           const char *expectedFile,
                           bool fail)
{
    char *actual;
    int ret;

    actual = virDomainDefFormat(vm->def, driver.caps,
                                VIR_DOMAIN_DEF_FORMAT_SECURE);
    if (!actual)
        return -1;
    vm->def->id = QEMU_HOTPLUG_TEST_DOMAIN_ID;

    if (STREQ(expected, actual)) {
        if (fail)
            VIR_TEST_VERBOSE("domain XML should not match the expected result\n");
        ret = 0;
    } else {
        if (!fail)
            virTestDifferenceFull(stderr,
                                  expected, expectedFile,
                                  actual, NULL);
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

    if (virAsprintf(&domain_filename, "%s/qemuhotplugtestdomains/qemuhotplug-%s.xml",
                    abs_srcdir, test->domain_filename) < 0 ||
        virAsprintf(&device_filename, "%s/qemuhotplugtestdevices/qemuhotplug-%s.xml",
                    abs_srcdir, test->device_filename) < 0 ||
        virAsprintf(&result_filename,
                    "%s/qemuhotplugtestdomains/qemuhotplug-%s+%s.xml",
                    abs_srcdir, test->domain_filename,
                    test->device_filename) < 0)
        goto cleanup;

    if (virTestLoadFile(domain_filename, &domain_xml) < 0 ||
        virTestLoadFile(device_filename, &device_xml) < 0)
        goto cleanup;

    if (test->action == ATTACH &&
        virTestLoadFile(result_filename, &result_xml) < 0)
        goto cleanup;

    if (!(caps = virQEMUDriverGetCapabilities(&driver, false)))
        goto cleanup;

    if (test->vm) {
        vm = test->vm;
    } else {
        if (qemuHotplugCreateObjects(driver.xmlopt, &vm, domain_xml,
                                     test->deviceDeletedEvent,
                                     test->domain_filename) < 0)
            goto cleanup;
    }

    if (test->action == ATTACH)
        device_parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

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
            ret = testQemuHotplugCheckResult(vm, result_xml,
                                             result_filename, fail);
        break;

    case DETACH:
        ret = testQemuHotplugDetach(vm, dev);
        if (ret == 0 || fail)
            ret = testQemuHotplugCheckResult(vm, domain_xml,
                                             domain_filename, fail);
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


struct testQemuHotplugCpuData {
    char *file_xml_dom;
    char *file_xml_res_live;
    char *file_xml_res_conf;
    char *file_json_monitor;

    char *xml_dom;

    virDomainObjPtr vm;
    qemuMonitorTestPtr mon;
    bool modern;
};


static void
testQemuHotplugCpuDataFree(struct testQemuHotplugCpuData *data)
{
    qemuDomainObjPrivatePtr priv;

    if (!data)
        return;

    VIR_FREE(data->file_xml_dom);
    VIR_FREE(data->file_xml_res_live);
    VIR_FREE(data->file_xml_res_conf);
    VIR_FREE(data->file_json_monitor);

    VIR_FREE(data->xml_dom);

    if (data->vm) {
        priv = data->vm->privateData;
        priv->mon = NULL;

        virObjectUnref(data->vm);
    }

    qemuMonitorTestFree(data->mon);
    VIR_FREE(data);
}


static struct testQemuHotplugCpuData *
testQemuHotplugCpuPrepare(const char *test,
                          bool modern)
{
    qemuDomainObjPrivatePtr priv = NULL;
    virCapsPtr caps = NULL;
    char *prefix = NULL;
    struct testQemuHotplugCpuData *data = NULL;

    if (virAsprintf(&prefix, "%s/qemuhotplugtestcpus/%s", abs_srcdir, test) < 0)
        return NULL;

    if (VIR_ALLOC(data) < 0)
        goto error;

    data->modern = modern;

    if (virAsprintf(&data->file_xml_dom, "%s-domain.xml", prefix) < 0 ||
        virAsprintf(&data->file_xml_res_live, "%s-result-live.xml", prefix) < 0 ||
        virAsprintf(&data->file_xml_res_conf, "%s-result-conf.xml", prefix) < 0 ||
        virAsprintf(&data->file_json_monitor, "%s-monitor.json", prefix) < 0)
        goto error;

    if (virTestLoadFile(data->file_xml_dom, &data->xml_dom) < 0)
        goto error;

    if (qemuHotplugCreateObjects(driver.xmlopt, &data->vm, data->xml_dom, true,
                                 "cpu-hotplug-test-domain") < 0)
        goto error;

    if (!(caps = virQEMUDriverGetCapabilities(&driver, false)))
        goto error;

    /* create vm->newDef */
    data->vm->persistent = true;
    if (virDomainObjSetDefTransient(caps, driver.xmlopt, data->vm) < 0)
        goto error;

    priv = data->vm->privateData;

    if (data->modern)
        virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_QUERY_HOTPLUGGABLE_CPUS);

    if (!(data->mon = qemuMonitorTestNewFromFileFull(data->file_json_monitor,
                                                     &driver, data->vm)))
        goto error;

    priv->mon = qemuMonitorTestGetMonitor(data->mon);
    priv->monJSON = true;
    virObjectUnlock(priv->mon);

    if (qemuDomainRefreshVcpuInfo(&driver, data->vm, 0, false) < 0)
        goto error;

    VIR_FREE(prefix);

    return data;

 error:
    virObjectUnref(caps);
    testQemuHotplugCpuDataFree(data);
    VIR_FREE(prefix);
    return NULL;
}


static int
testQemuHotplugCpuFinalize(struct testQemuHotplugCpuData *data)
{
    int ret = -1;
    char *activeXML = NULL;
    char *configXML = NULL;

    if (data->file_xml_res_live) {
        if (!(activeXML = virDomainDefFormat(data->vm->def, driver.caps,
                                             VIR_DOMAIN_DEF_FORMAT_SECURE)))
            goto cleanup;

        if (virTestCompareToFile(activeXML, data->file_xml_res_live) < 0)
            goto cleanup;
    }

    if (data->file_xml_res_conf) {
        if (!(configXML = virDomainDefFormat(data->vm->newDef, driver.caps,
                                             VIR_DOMAIN_DEF_FORMAT_SECURE |
                                             VIR_DOMAIN_DEF_FORMAT_INACTIVE)))
            goto cleanup;

        if (virTestCompareToFile(configXML, data->file_xml_res_conf) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
     VIR_FREE(activeXML);
     VIR_FREE(configXML);
     return ret;
}


struct testQemuHotplugCpuParams {
    const char *test;
    int newcpus;
    const char *cpumap;
    bool state;
    bool modern;
    bool fail;
};


static int
testQemuHotplugCpuGroup(const void *opaque)
{
    const struct testQemuHotplugCpuParams *params = opaque;
    struct testQemuHotplugCpuData *data = NULL;
    int ret = -1;
    int rc;

    if (!(data = testQemuHotplugCpuPrepare(params->test, params->modern)))
        return -1;

    rc = qemuDomainSetVcpusInternal(&driver, data->vm, data->vm->def,
                                    data->vm->newDef, params->newcpus,
                                    params->modern);

    if (params->fail) {
        if (rc == 0)
            fprintf(stderr, "cpu test '%s' should have failed\n", params->test);
        else
            ret = 0;

        goto cleanup;
    } else {
        if (rc < 0)
            goto cleanup;
    }

    ret = testQemuHotplugCpuFinalize(data);

 cleanup:
    testQemuHotplugCpuDataFree(data);
    return ret;
}


static int
testQemuHotplugCpuIndividual(const void *opaque)
{
    const struct testQemuHotplugCpuParams *params = opaque;
    struct testQemuHotplugCpuData *data = NULL;
    virBitmapPtr map = NULL;
    int ret = -1;
    int rc;

    if (!(data = testQemuHotplugCpuPrepare(params->test, params->modern)))
        return -1;

    if (virBitmapParse(params->cpumap, &map, 128) < 0)
        goto cleanup;

    rc = qemuDomainSetVcpuInternal(&driver, data->vm, data->vm->def,
                                   data->vm->newDef, map, params->state);

    if (params->fail) {
        if (rc == 0)
            fprintf(stderr, "cpu test '%s' should have failed\n", params->test);
        else
            ret = 0;

        goto cleanup;
    } else {
        if (rc < 0)
            goto cleanup;
    }

    ret = testQemuHotplugCpuFinalize(data);

 cleanup:
    virBitmapFree(map);
    testQemuHotplugCpuDataFree(data);
    return ret;
}



static int
mymain(void)
{
    int ret = 0;
    struct qemuHotplugTestData data = {0};
    struct testQemuHotplugCpuParams cpudata;

#if !WITH_YAJL
    fputs("libvirt not compiled with yajl, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    if (virThreadInitialize() < 0 ||
        qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

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
        if (virTestRun(name, testQemuHotplug, &data) < 0)                   \
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
    DO_TEST_UPDATE("graphics-spice-listen-network", "graphics-spice-listen-network-password", false, false,
                   "set_password", QMP_OK, "expire_password", QMP_OK);
    /* Strange huh? Currently, only graphics can be updated :-P */
    DO_TEST_UPDATE("disk-cdrom", "disk-cdrom-nochange", true, false, NULL);

    DO_TEST_ATTACH("console-compat-2-live", "console-virtio", false, true,
                   "chardev-add", "{\"return\": {\"pty\": \"/dev/pts/26\"}}",
                   "device_add", QMP_OK);

    DO_TEST_DETACH("console-compat-2-live", "console-virtio", false, false,
                   "device_del", QMP_OK,
                   "chardev-remove", QMP_OK);

    DO_TEST_ATTACH("base-live", "disk-virtio", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-virtio", false, false,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH_EVENT("base-live", "disk-virtio", false, true,
                         "human-monitor-command", HMP("OK\\r\\n"),
                         "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-virtio", true, true,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));
    DO_TEST_DETACH("base-live", "disk-virtio", false, false,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk4") QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-live", "disk-usb", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-usb", false, false,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH_EVENT("base-live", "disk-usb", false, true,
                         "human-monitor-command", HMP("OK\\r\\n"),
                         "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-usb", true, true,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));
    DO_TEST_DETACH("base-live", "disk-usb", false, false,
                   "device_del", QMP_DEVICE_DELETED("usb-disk16") QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-live", "disk-scsi", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-scsi", false, false,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH_EVENT("base-live", "disk-scsi", false, true,
                         "human-monitor-command", HMP("OK\\r\\n"),
                         "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-scsi", true, true,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));
    DO_TEST_DETACH("base-live", "disk-scsi", false, false,
                   "device_del", QMP_DEVICE_DELETED("scsi0-0-0-5") QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-without-scsi-controller-live", "disk-scsi-2", false, true,
                   /* Four controllers added */
                   "device_add", QMP_OK,
                   "device_add", QMP_OK,
                   "device_add", QMP_OK,
                   "device_add", QMP_OK,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   /* Disk added */
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-with-scsi-controller-live", "disk-scsi-2", false, false,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH_EVENT("base-without-scsi-controller-live", "disk-scsi-2", false, true,
                         /* Four controllers added */
                         "device_add", QMP_OK,
                         "device_add", QMP_OK,
                         "device_add", QMP_OK,
                         "device_add", QMP_OK,
                         "human-monitor-command", HMP("OK\\r\\n"),
                         /* Disk added */
                         "device_add", QMP_OK);
    DO_TEST_DETACH("base-with-scsi-controller-live", "disk-scsi-2", true, true,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));
    DO_TEST_DETACH("base-with-scsi-controller-live", "disk-scsi-2", false, false,
                   "device_del", QMP_DEVICE_DELETED("scsi3-0-5-7") QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-live", "qemu-agent", false, true,
                   "chardev-add", QMP_OK,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "qemu-agent-detach", false, false,
                   "device_del", QMP_OK,
                   "chardev-remove", QMP_OK);

    DO_TEST_ATTACH("base-ccw-live", "ccw-virtio", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-ccw-live", "ccw-virtio", false, false,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-ccw-live-with-ccw-virtio", "ccw-virtio-2", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);

    DO_TEST_DETACH("base-ccw-live-with-ccw-virtio", "ccw-virtio-2", false, false,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-ccw-live-with-ccw-virtio", "ccw-virtio-2-explicit", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);

    DO_TEST_DETACH("base-ccw-live-with-ccw-virtio", "ccw-virtio-2-explicit", false, false,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));

    /* Attach a second device, then detach the first one. Then attach the first one again. */
    DO_TEST_ATTACH("base-ccw-live-with-ccw-virtio", "ccw-virtio-2-explicit", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);

    DO_TEST_DETACH("base-ccw-live-with-2-ccw-virtio", "ccw-virtio-1-explicit", false, true,
                   "device_del", QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-ccw-live-with-2-ccw-virtio", "ccw-virtio-1-reverse", false, false,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);

    DO_TEST_ATTACH("base-live", "ivshmem-plain", false, true,
                   "object-add", QMP_OK,
                   "device_add", QMP_OK);
    DO_TEST_ATTACH("base-live", "ivshmem-doorbell", false, true,
                   "chardev-add", QMP_OK,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live+ivshmem-plain", "ivshmem-doorbell-detach", false, true,
                   "device_del", QMP_OK,
                   "chardev-remove", QMP_OK);
    DO_TEST_DETACH("base-live", "ivshmem-plain-detach", false, false,
                   "device_del", QMP_OK,
                   "object-del", QMP_OK);

#define DO_TEST_CPU_GROUP(prefix, vcpus, modernhp, expectfail)                 \
    do {                                                                       \
        cpudata.test = prefix;                                                 \
        cpudata.newcpus = vcpus;                                               \
        cpudata.modern = modernhp;                                             \
        cpudata.fail = expectfail;                                             \
        if (virTestRun("hotplug vcpus group " prefix,                          \
                       testQemuHotplugCpuGroup, &cpudata) < 0)                 \
            ret = -1;                                                          \
    } while (0)

    DO_TEST_CPU_GROUP("x86-modern-bulk", 7, true, false);
    DO_TEST_CPU_GROUP("x86-old-bulk", 7, false, false);
    DO_TEST_CPU_GROUP("ppc64-modern-bulk", 24, true, false);
    DO_TEST_CPU_GROUP("ppc64-modern-bulk", 15, true, true);
    DO_TEST_CPU_GROUP("ppc64-modern-bulk", 23, true, true);
    DO_TEST_CPU_GROUP("ppc64-modern-bulk", 25, true, true);

#define DO_TEST_CPU_INDIVIDUAL(prefix, mapstr, statefl, modernhp, expectfail)  \
    do {                                                                       \
        cpudata.test = prefix;                                                 \
        cpudata.cpumap = mapstr;                                               \
        cpudata.state = statefl;                                               \
        cpudata.modern = modernhp;                                             \
        cpudata.fail = expectfail;                                             \
        if (virTestRun("hotplug vcpus group " prefix,                          \
                       testQemuHotplugCpuIndividual, &cpudata) < 0)            \
            ret = -1;                                                          \
    } while (0)

    DO_TEST_CPU_INDIVIDUAL("x86-modern-individual-add", "7", true, true, false);
    DO_TEST_CPU_INDIVIDUAL("x86-modern-individual-add", "6,7", true, true, true);
    DO_TEST_CPU_INDIVIDUAL("x86-modern-individual-add", "7", false, true, true);
    DO_TEST_CPU_INDIVIDUAL("x86-modern-individual-add", "7", true, false, true);

    DO_TEST_CPU_INDIVIDUAL("ppc64-modern-individual", "16-23", true, true, false);
    DO_TEST_CPU_INDIVIDUAL("ppc64-modern-individual", "16-22", true, true, true);
    DO_TEST_CPU_INDIVIDUAL("ppc64-modern-individual", "17", true, true, true);

    qemuTestDriverFree(&driver);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
