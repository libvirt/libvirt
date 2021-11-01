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
#include "qemumonitortestutils.h"
#include "testutils.h"
#include "testutilsqemu.h"
#include "testutilsqemuschema.h"
#include "virhostdev.h"
#include "virerror.h"
#include "virstring.h"
#include "virthread.h"
#include "virfile.h"

#define LIBVIRT_QEMU_CAPSPRIV_H_ALLOW
#include "qemu/qemu_capspriv.h"

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
    virDomainObj *vm;
    bool deviceDeletedEvent;
};

static int
qemuHotplugCreateObjects(virDomainXMLOption *xmlopt,
                         virDomainObj **vm,
                         const char *domxml)
{
    qemuDomainObjPrivate *priv = NULL;
    const unsigned int parseFlags = 0;

    if (!(*vm = virDomainObjNew(xmlopt)))
        return -1;

    priv = (*vm)->privateData;

    if (!(priv->qemuCaps = virQEMUCapsNew()))
        return -1;

    virQEMUCapsInitQMPBasicArch(priv->qemuCaps);

    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_VIRTIO_SCSI);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_USB_STORAGE);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_CCW);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_IVSHMEM_PLAIN);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_IVSHMEM_DOORBELL);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_SCSI_DISK_WWN);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_VFIO_PCI);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_SPAPR_PCI_HOST_BRIDGE);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_QXL);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_VGA);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_CIRRUS_VGA);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_PIIX_DISABLE_S3);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_PIIX_DISABLE_S4);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_VNC);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_SPICE);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_PR_MANAGER_HELPER);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_SCSI_BLOCK);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_DEVICE_USB_KBD);
    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_NETDEV_VHOST_VDPA);

    if (qemuTestCapsCacheInsert(driver.qemuCapsCache, priv->qemuCaps) < 0)
        return -1;

    if (!((*vm)->def = virDomainDefParseString(domxml,
                                               driver.xmlopt,
                                               NULL,
                                               parseFlags)))
        return -1;

    if (qemuDomainAssignAddresses((*vm)->def, priv->qemuCaps,
                                  &driver, *vm, true) < 0) {
        return -1;
    }

    if (qemuAssignDeviceAliases((*vm)->def, priv->qemuCaps) < 0)
        return -1;

    (*vm)->def->id = QEMU_HOTPLUG_TEST_DOMAIN_ID;

    if (qemuDomainSetPrivatePaths(&driver, *vm) < 0)
        return -1;

    return 0;
}

static int
testQemuHotplugAttach(virDomainObj *vm,
                      virDomainDeviceDef *dev)
{
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        /* conn in only used for storage pool and secrets lookup so as long
         * as we don't use any of them, passing NULL should be safe
         */
        ret = qemuDomainAttachDeviceDiskLive(&driver, vm, dev);
        break;
    case VIR_DOMAIN_DEVICE_CHR:
        ret = qemuDomainAttachChrDevice(&driver, vm, dev->data.chr);
        break;
    case VIR_DOMAIN_DEVICE_SHMEM:
        ret = qemuDomainAttachShmemDevice(&driver, vm, dev->data.shmem);
        break;
    case VIR_DOMAIN_DEVICE_WATCHDOG:
        ret = qemuDomainAttachWatchdog(&driver, vm, dev->data.watchdog);
        break;
    case VIR_DOMAIN_DEVICE_HOSTDEV:
        ret = qemuDomainAttachHostDevice(&driver, vm, dev->data.hostdev);
        break;
    case VIR_DOMAIN_DEVICE_NET:
        ret = qemuDomainAttachNetDevice(&driver, vm, dev->data.net);
        break;
    default:
        VIR_TEST_VERBOSE("device type '%s' cannot be attached",
                virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}

static int
testQemuHotplugDetach(virDomainObj *vm,
                      virDomainDeviceDef *dev,
                      bool async)
{
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
    case VIR_DOMAIN_DEVICE_CHR:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_NET:
        ret = qemuDomainDetachDeviceLive(vm, dev, &driver, async);
        break;
    default:
        VIR_TEST_VERBOSE("device type '%s' cannot be detached",
                virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}

static int
testQemuHotplugUpdate(virDomainObj *vm,
                      virDomainDeviceDef *dev)
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
        VIR_TEST_VERBOSE("device type '%s' cannot be updated",
                virDomainDeviceTypeToString(dev->type));
        break;
    }

    return ret;
}

static int
testQemuHotplugCheckResult(virDomainObj *vm,
                           const char *expected,
                           const char *expectedFile,
                           bool fail)
{
    g_autofree char *actual = NULL;
    int ret;

    actual = virDomainDefFormat(vm->def, driver.xmlopt,
                                VIR_DOMAIN_DEF_FORMAT_SECURE);
    if (!actual)
        return -1;
    vm->def->id = QEMU_HOTPLUG_TEST_DOMAIN_ID;

    if (STREQ(expected, actual)) {
        if (fail)
            VIR_TEST_VERBOSE("domain XML should not match the expected result");
        ret = 0;
    } else {
        if (!fail)
            virTestDifferenceFull(stderr,
                                  expected, expectedFile,
                                  actual, NULL);
        ret = -1;
    }

    return ret;
}

static int
testQemuHotplug(const void *data)
{
    int ret = -1;
    struct qemuHotplugTestData *test = (struct qemuHotplugTestData *) data;
    g_autofree char *domain_filename = NULL;
    g_autofree char *device_filename = NULL;
    g_autofree char *result_filename = NULL;
    g_autofree char *domain_xml = NULL;
    g_autofree char *device_xml = NULL;
    g_autofree char *result_xml = NULL;
    const char *const *tmp;
    bool fail = test->fail;
    bool keep = test->keep;
    unsigned int device_parse_flags = 0;
    virDomainObj *vm = NULL;
    virDomainDeviceDef *dev = NULL;
    g_autoptr(virCaps) caps = NULL;
    g_autoptr(qemuMonitorTest) test_mon = NULL;
    qemuDomainObjPrivate *priv = NULL;

    domain_filename = g_strdup_printf("%s/qemuhotplugtestdomains/qemuhotplug-%s.xml",
                                      abs_srcdir, test->domain_filename);
    device_filename = g_strdup_printf("%s/qemuhotplugtestdevices/qemuhotplug-%s.xml",
                                      abs_srcdir, test->device_filename);
    result_filename = g_strdup_printf("%s/qemuhotplugtestdomains/qemuhotplug-%s+%s.xml",
                                      abs_srcdir, test->domain_filename,
                                      test->device_filename);

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
        if (!vm->def) {
            VIR_TEST_VERBOSE("test skipped due to failure of dependent test");
            goto cleanup;
        }
    } else {
        if (qemuHotplugCreateObjects(driver.xmlopt, &vm, domain_xml) < 0)
            goto cleanup;
    }

    if (test->action == ATTACH)
        device_parse_flags = VIR_DOMAIN_DEF_PARSE_INACTIVE;

    if (!(dev = virDomainDeviceDefParse(device_xml, vm->def,
                                        driver.xmlopt, NULL,
                                        device_parse_flags)))
        goto cleanup;

    /* Now is the best time to feed the spoofed monitor with predefined
     * replies. */
    if (!(test_mon = qemuMonitorTestNew(driver.xmlopt, vm, &driver,
                                        NULL, NULL)))
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
        ret = testQemuHotplugDetach(vm, dev, false);
        if (ret == 0 || fail)
            ret = testQemuHotplugCheckResult(vm, domain_xml,
                                             domain_filename, fail);
        break;

    case UPDATE:
        ret = testQemuHotplugUpdate(vm, dev);
    }

    virObjectLock(priv->mon);

 cleanup:
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
    return ((ret < 0 && fail) || (!ret && !fail)) ? 0 : -1;
}


struct testQemuHotplugCpuData {
    char *file_xml_dom;
    char *file_xml_res_live;
    char *file_xml_res_conf;
    char *file_json_monitor;

    char *xml_dom;

    virDomainObj *vm;
    qemuMonitorTest *mon;
    bool modern;
};


static void
testQemuHotplugCpuDataFree(struct testQemuHotplugCpuData *data)
{
    qemuDomainObjPrivate *priv;
    qemuMonitor *mon;

    if (!data)
        return;

    g_free(data->file_xml_dom);
    g_free(data->file_xml_res_live);
    g_free(data->file_xml_res_conf);
    g_free(data->file_json_monitor);

    g_free(data->xml_dom);

    if (data->vm) {
        priv = data->vm->privateData;
        priv->mon = NULL;

        virObjectUnref(data->vm);
    }

    if (data->mon) {
        mon = qemuMonitorTestGetMonitor(data->mon);
        virObjectLock(mon);
        qemuMonitorTestFree(data->mon);
    }
    g_free(data);
}


static struct testQemuHotplugCpuData *
testQemuHotplugCpuPrepare(const char *test,
                          bool modern,
                          bool fail,
                          GHashTable *qmpschema)
{
    qemuDomainObjPrivate *priv = NULL;
    virCaps *caps = NULL;
    g_autofree char *prefix = NULL;
    struct testQemuHotplugCpuData *data = NULL;

    prefix = g_strdup_printf("%s/qemuhotplugtestcpus/%s", abs_srcdir, test);

    data = g_new0(struct testQemuHotplugCpuData, 1);

    data->modern = modern;

    data->file_xml_dom = g_strdup_printf("%s-domain.xml", prefix);
    data->file_xml_res_live = g_strdup_printf("%s-result-live.xml", prefix);
    data->file_xml_res_conf = g_strdup_printf("%s-result-conf.xml", prefix);
    data->file_json_monitor = g_strdup_printf("%s-monitor.json", prefix);

    if (virTestLoadFile(data->file_xml_dom, &data->xml_dom) < 0)
        goto error;

    if (qemuHotplugCreateObjects(driver.xmlopt, &data->vm, data->xml_dom) < 0)
        goto error;

    if (!(caps = virQEMUDriverGetCapabilities(&driver, false)))
        goto error;

    /* create vm->newDef */
    data->vm->persistent = true;
    if (virDomainObjSetDefTransient(driver.xmlopt, data->vm, NULL) < 0)
        goto error;

    priv = data->vm->privateData;

    virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_QUERY_CPUS_FAST);

    if (data->modern)
        virQEMUCapsSet(priv->qemuCaps, QEMU_CAPS_QUERY_HOTPLUGGABLE_CPUS);

    if (!(data->mon = qemuMonitorTestNewFromFileFull(data->file_json_monitor,
                                                     &driver, data->vm, qmpschema)))
        goto error;

    if (fail)
        qemuMonitorTestAllowUnusedCommands(data->mon);

    if (!data->modern)
        qemuMonitorTestSkipDeprecatedValidation(data->mon, true);

    priv->mon = qemuMonitorTestGetMonitor(data->mon);
    virObjectUnlock(priv->mon);

    if (qemuDomainRefreshVcpuInfo(&driver, data->vm, 0, false) < 0)
        goto error;

    return data;

 error:
    virObjectUnref(caps);
    testQemuHotplugCpuDataFree(data);
    return NULL;
}


static int
testQemuHotplugCpuFinalize(struct testQemuHotplugCpuData *data)
{
    g_autofree char *activeXML = NULL;
    g_autofree char *configXML = NULL;

    if (data->file_xml_res_live) {
        if (!(activeXML = virDomainDefFormat(data->vm->def, driver.xmlopt,
                                             VIR_DOMAIN_DEF_FORMAT_SECURE)))
            return -1;

        if (virTestCompareToFile(activeXML, data->file_xml_res_live) < 0)
            return -1;
    }

    if (data->file_xml_res_conf) {
        if (!(configXML = virDomainDefFormat(data->vm->newDef, driver.xmlopt,
                                             VIR_DOMAIN_DEF_FORMAT_SECURE |
                                             VIR_DOMAIN_DEF_FORMAT_INACTIVE)))
            return -1;

        if (virTestCompareToFile(configXML, data->file_xml_res_conf) < 0)
            return -1;
    }

     return 0;
}


struct testQemuHotplugCpuParams {
    const char *test;
    int newcpus;
    const char *cpumap;
    bool state;
    bool modern;
    bool fail;
    GHashTable *schema;
};


static int
testQemuHotplugCpuGroup(const void *opaque)
{
    const struct testQemuHotplugCpuParams *params = opaque;
    struct testQemuHotplugCpuData *data = NULL;
    int ret = -1;
    int rc;

    if (!(data = testQemuHotplugCpuPrepare(params->test, params->modern,
                                           params->fail, params->schema)))
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
    g_autoptr(virBitmap) map = NULL;
    int ret = -1;
    int rc;

    if (!(data = testQemuHotplugCpuPrepare(params->test, params->modern,
                                           params->fail, params->schema)))
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
    testQemuHotplugCpuDataFree(data);
    return ret;
}

#define FAKEROOTDIRTEMPLATE abs_builddir "/fakerootdir-XXXXXX"


static int
mymain(void)
{
    g_autoptr(GHashTable) qmpschema = NULL;
    int ret = 0;
    struct qemuHotplugTestData data = {0};
    struct testQemuHotplugCpuParams cpudata;
    g_autofree char *fakerootdir = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;

    fakerootdir = g_strdup(FAKEROOTDIRTEMPLATE);

    if (!g_mkdtemp(fakerootdir)) {
        fprintf(stderr, "Cannot create fakerootdir");
        abort();
    }

    g_setenv("LIBVIRT_FAKE_ROOT_DIR", fakerootdir, TRUE);

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    cfg = virQEMUDriverGetConfig(&driver);

    virEventRegisterDefaultImpl();

    VIR_FREE(driver.config->spiceListen);
    VIR_FREE(driver.config->vncListen);
    /* some dummy values from 'config file' */
    driver.config->spicePassword = g_strdup("123456");

    if (!(driver.domainEventState = virObjectEventStateNew()))
        return EXIT_FAILURE;

    if (!(qmpschema = testQEMUSchemaLoadLatest("x86_64"))) {
        VIR_TEST_VERBOSE("failed to load qapi schema\n");
        return EXIT_FAILURE;
    }

    cpudata.schema = qmpschema;

    driver.lockManager = virLockManagerPluginNew("nop", "qemu",
                                                 driver.config->configBaseDir,
                                                 0);
    if (!driver.lockManager)
        return EXIT_FAILURE;

    driver.hostdevMgr = virHostdevManagerGetDefault();
    if (driver.hostdevMgr == NULL) {
        VIR_TEST_VERBOSE("Could not initialize HostdevManager - %s\n",
                         virGetLastErrorMessage());
        return EXIT_FAILURE;
    }


#define DO_TEST(file, ACTION, dev, fail_, keep_, ...) \
    do { \
        const char *my_mon[] = { __VA_ARGS__, NULL}; \
        const char *name = file " " #ACTION " " dev; \
        data.action = ACTION; \
        data.domain_filename = file; \
        data.device_filename = dev; \
        data.fail = fail_; \
        data.mon = my_mon; \
        data.keep = keep_; \
        if (virTestRun(name, testQemuHotplug, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_ATTACH(file, dev, fail, keep, ...) \
    DO_TEST(file, ATTACH, dev, fail, keep, __VA_ARGS__)

#define DO_TEST_DETACH(file, dev, fail, keep, ...) \
    DO_TEST(file, DETACH, dev, fail, keep, __VA_ARGS__)

#define DO_TEST_UPDATE(file, dev, fail, keep, ...) \
    DO_TEST(file, UPDATE, dev, fail, keep, __VA_ARGS__)


#define QMP_OK      "{\"return\": {}}"
#define HMP(msg)    "{\"return\": \"" msg "\"}"

#define QMP_DEVICE_DELETED(dev) \
    "{" \
    "    \"timestamp\": {" \
    "        \"seconds\": 1374137171," \
    "        \"microseconds\": 2659" \
    "    }," \
    "    \"event\": \"DEVICE_DELETED\"," \
    "    \"data\": {" \
    "        \"device\": \"" dev "\"," \
    "        \"path\": \"/machine/peripheral/" dev "\"" \
    "    }" \
    "}\r\n"

    cfg->spiceTLS = true;
    DO_TEST_UPDATE("graphics-spice", "graphics-spice-nochange", false, false, NULL);
    DO_TEST_UPDATE("graphics-spice-timeout", "graphics-spice-timeout-nochange", false, false,
                   "set_password", QMP_OK, "expire_password", QMP_OK);
    DO_TEST_UPDATE("graphics-spice-timeout", "graphics-spice-timeout-password", false, false,
                   "set_password", QMP_OK, "expire_password", QMP_OK);
    DO_TEST_UPDATE("graphics-spice", "graphics-spice-listen", true, false, NULL);
    DO_TEST_UPDATE("graphics-spice-listen-network", "graphics-spice-listen-network-password", false, false,
                   "set_password", QMP_OK, "expire_password", QMP_OK);
    cfg->spiceTLS = false;
    /* Strange huh? Currently, only graphics can be updated :-P */
    DO_TEST_UPDATE("disk-cdrom", "disk-cdrom-nochange", true, false, NULL);

    DO_TEST_ATTACH("console-compat-2-live", "console-virtio", false, true,
                   "chardev-add", "{\"return\": {\"pty\": \"/dev/pts/26\"}}",
                   "device_add", QMP_OK);

    DO_TEST_DETACH("console-compat-2-live", "console-virtio", false, false,
                   "device_del", QMP_DEVICE_DELETED("console1") QMP_OK,
                   "chardev-remove", QMP_OK);

    DO_TEST_ATTACH("base-live", "disk-virtio", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-virtio", true, true,
                   "device_del", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-virtio", false, false,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk4") QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-live", "disk-usb", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-usb", true, true,
                   "device_del", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-usb", false, false,
                   "device_del", QMP_DEVICE_DELETED("usb-disk16") QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-live", "disk-scsi", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-scsi", true, true,
                   "device_del", QMP_OK);
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
    DO_TEST_DETACH("base-with-scsi-controller-live", "disk-scsi-2", true, true,
                   "device_del", QMP_OK);
    DO_TEST_DETACH("base-with-scsi-controller-live", "disk-scsi-2", false, false,
                   "device_del", QMP_DEVICE_DELETED("scsi3-0-5-6") QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-live", "disk-scsi-multipath", false, true,
                   "object-add", QMP_OK,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-scsi-multipath", true, true,
                   "device_del", QMP_OK);
    DO_TEST_DETACH("base-live", "disk-scsi-multipath", false, false,
                   "device_del", QMP_DEVICE_DELETED("scsi0-0-0-0") QMP_OK,
                   "human-monitor-command", HMP(""),
                   "object-del", QMP_OK);

    DO_TEST_ATTACH("base-live", "qemu-agent", false, true,
                   "chardev-add", QMP_OK,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "qemu-agent-detach", false, false,
                   "device_del", QMP_DEVICE_DELETED("channel0") QMP_OK,
                   "chardev-remove", QMP_OK);

    DO_TEST_ATTACH("base-ccw-live", "ccw-virtio", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-ccw-live", "ccw-virtio", false, false,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk4") QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-ccw-live-with-ccw-virtio", "ccw-virtio-2", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);

    DO_TEST_DETACH("base-ccw-live-with-ccw-virtio", "ccw-virtio-2", false, false,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk0") QMP_OK,
                   "human-monitor-command", HMP(""));

    DO_TEST_ATTACH("base-ccw-live-with-ccw-virtio", "ccw-virtio-2-explicit", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);

    DO_TEST_DETACH("base-ccw-live-with-ccw-virtio", "ccw-virtio-2-explicit", false, false,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk0") QMP_OK,
                   "human-monitor-command", HMP(""));

    /* Attach a second device, then detach the first one. Then attach the first one again. */
    DO_TEST_ATTACH("base-ccw-live-with-ccw-virtio", "ccw-virtio-2-explicit", false, true,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);

    DO_TEST_DETACH("base-ccw-live-with-2-ccw-virtio", "ccw-virtio-1-explicit", false, true,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk4") QMP_OK,
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
                   "device_del", QMP_DEVICE_DELETED("shmem1") QMP_OK,
                   "chardev-remove", QMP_OK);
    DO_TEST_DETACH("base-live", "ivshmem-plain-detach", false, false,
                   "device_del", QMP_DEVICE_DELETED("shmem0") QMP_OK,
                   "object-del", QMP_OK);
    DO_TEST_ATTACH("base-live+disk-scsi-wwn",
                   "disk-scsi-duplicate-wwn", false, false,
                   "human-monitor-command", HMP("OK\\r\\n"),
                   "device_add", QMP_OK);

    DO_TEST_ATTACH("base-live", "hostdev-pci", false, true,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "hostdev-pci", false, false,
                   "device_del", QMP_DEVICE_DELETED("hostdev0") QMP_OK);
    DO_TEST_ATTACH("pseries-base-live", "hostdev-pci", false, true,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("pseries-base-live", "hostdev-pci", false, false,
                   "device_del", QMP_DEVICE_DELETED("hostdev0") QMP_OK);

    DO_TEST_ATTACH("base-live", "interface-vdpa", false, true,
                   "add-fd", "{ \"return\": { \"fdset-id\": 1, \"fd\": 95 }}",
                   "netdev_add", QMP_OK, "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "interface-vdpa", false, false,
                   "device_del", QMP_DEVICE_DELETED("net0") QMP_OK,
                   "netdev_del", QMP_OK,
                   "query-fdsets",
                   "{ \"return\": [{\"fds\": [{\"fd\": 95, \"opaque\": \"/dev/vhost-vdpa-0\"}], \"fdset-id\": 1}]}",
                   "remove-fd", QMP_OK
                   );

    DO_TEST_ATTACH("base-live", "watchdog", false, true,
                   "watchdog-set-action", QMP_OK,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "watchdog-full", false, false,
                   "device_del", QMP_DEVICE_DELETED("watchdog0") QMP_OK);

    DO_TEST_ATTACH("base-live", "watchdog-user-alias", false, true,
                   "watchdog-set-action", QMP_OK,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("base-live", "watchdog-user-alias-full", false, false,
                   "device_del", QMP_DEVICE_DELETED("ua-UserWatchdog") QMP_OK);

    DO_TEST_ATTACH("base-live", "guestfwd", false, true,
                   "chardev-add", QMP_OK,
                   "netdev_add", QMP_OK);
    DO_TEST_DETACH("base-live", "guestfwd", false, false,
                   "netdev_del", QMP_OK);

#define DO_TEST_CPU_GROUP(prefix, vcpus, modernhp, expectfail) \
    do { \
        cpudata.test = prefix; \
        cpudata.newcpus = vcpus; \
        cpudata.modern = modernhp; \
        cpudata.fail = expectfail; \
        if (virTestRun("hotplug vcpus group " prefix, \
                       testQemuHotplugCpuGroup, &cpudata) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_CPU_GROUP("x86-modern-bulk", 7, true, false);
    DO_TEST_CPU_GROUP("ppc64-modern-bulk", 24, true, false);
    DO_TEST_CPU_GROUP("ppc64-modern-bulk", 15, true, true);
    DO_TEST_CPU_GROUP("ppc64-modern-bulk", 23, true, true);
    DO_TEST_CPU_GROUP("ppc64-modern-bulk", 25, true, true);

#define DO_TEST_CPU_INDIVIDUAL(prefix, mapstr, statefl, modernhp, expectfail) \
    do { \
        cpudata.test = prefix; \
        cpudata.cpumap = mapstr; \
        cpudata.state = statefl; \
        cpudata.modern = modernhp; \
        cpudata.fail = expectfail; \
        if (virTestRun("hotplug vcpus group " prefix, \
                       testQemuHotplugCpuIndividual, &cpudata) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_CPU_INDIVIDUAL("x86-modern-individual-add", "7", true, true, false);
    DO_TEST_CPU_INDIVIDUAL("x86-modern-individual-add", "6,7", true, true, true);
    DO_TEST_CPU_INDIVIDUAL("x86-modern-individual-add", "7", false, true, true);

    DO_TEST_CPU_INDIVIDUAL("ppc64-modern-individual", "16-23", true, true, false);
    DO_TEST_CPU_INDIVIDUAL("ppc64-modern-individual", "16-22", true, true, true);
    DO_TEST_CPU_INDIVIDUAL("ppc64-modern-individual", "17", true, true, true);

    if (getenv("LIBVIRT_SKIP_CLEANUP") == NULL)
        virFileDeleteTree(fakerootdir);

    qemuTestDriverFree(&driver);
    virObjectUnref(data.vm);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virhostdev"),
                      VIR_TEST_MOCK("virpci"),
                      VIR_TEST_MOCK("domaincaps"),
                      VIR_TEST_MOCK("virprocess"),
                      VIR_TEST_MOCK("qemuhotplug"));
