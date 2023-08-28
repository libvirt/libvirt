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
    const char *arch;
    GHashTable *capsLatestFiles;
    GHashTable *capsCache;
    GHashTable *schemaCache;
    GHashTable *schema;
};

static int
qemuHotplugCreateObjects(virDomainXMLOption *xmlopt,
                         virDomainObj **vm,
                         const char *domxml,
                         const char *arch,
                         GHashTable *capsLatestFiles,
                         GHashTable *capsCache,
                         GHashTable *schemaCache,
                         GHashTable **schema)

{
    qemuDomainObjPrivate *priv = NULL;
    const unsigned int parseFlags = 0;

    if (!(*vm = virDomainObjNew(xmlopt)))
        return -1;

    priv = (*vm)->privateData;

    if (!(priv->qemuCaps = testQemuGetRealCaps(arch, "latest", "",
                                               capsLatestFiles, capsCache,
                                               schemaCache, schema)))
        return -1;

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

    if (qemuAssignDeviceAliases((*vm)->def) < 0)
        return -1;

    (*vm)->def->id = QEMU_HOTPLUG_TEST_DOMAIN_ID;

    if (qemuDomainSetPrivatePaths(&driver, *vm) < 0)
        return -1;

    return 0;
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

    if (STREQ_NULLABLE(expected, actual)) {
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
    g_autoptr(virDomainDeviceDef) dev = NULL;
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

    if (!fail &&
        (test->action == ATTACH ||
         test->action == UPDATE) &&
        virTestLoadFile(result_filename, &result_xml) < 0)
        goto cleanup;

    if (test->vm) {
        vm = test->vm;
        if (!vm->def) {
            VIR_TEST_VERBOSE("test skipped due to failure of dependent test");
            goto cleanup;
        }
    } else {
        if (qemuHotplugCreateObjects(driver.xmlopt, &vm, domain_xml,
                                     test->arch, test->capsLatestFiles,
                                     test->capsCache, test->schemaCache,
                                     &test->schema) < 0)
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
    if (!(test_mon = qemuMonitorTestNew(driver.xmlopt, vm, NULL, test->schema)))
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

    /* After successful attach, we list all aliases. We don't care for that in
     * the test. Add a dummy reply. */
    if (test->action == ATTACH &&
        qemuMonitorTestAddItem(test_mon, "qom-list", "{\"return\":[]}") < 0)
        goto cleanup;

    priv = vm->privateData;
    priv->mon = qemuMonitorTestGetMonitor(test_mon);

    /* We need to unlock the monitor here, as any function below talks
     * (transitively) on the monitor. */
    virObjectUnlock(priv->mon);

    switch (test->action) {
    case ATTACH:
        ret = qemuDomainAttachDeviceLive(vm, dev, &driver);
        if (ret == 0 || fail)
            ret = testQemuHotplugCheckResult(vm, result_xml,
                                             result_filename, fail);
        break;

    case DETACH:
        ret = qemuDomainDetachDeviceLive(vm, dev, &driver, false);
        if (ret == 0 || fail)
            ret = testQemuHotplugCheckResult(vm, domain_xml,
                                             domain_filename, fail);
        break;

    case UPDATE:
        ret = qemuDomainUpdateDeviceLive(vm, dev, &driver, false);
        if (ret == 0 || fail)
            ret = testQemuHotplugCheckResult(vm, result_xml,
                                             result_filename, fail);
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


struct testQemuHotplugCpuParams {
    const char *test;
    int newcpus;
    const char *cpumap;
    bool state;
    bool fail;
    const char *arch;
    GHashTable *capsLatestFiles;
    GHashTable *capsCache;
    GHashTable *schemaCache;
};


static struct testQemuHotplugCpuData *
testQemuHotplugCpuPrepare(const struct testQemuHotplugCpuParams *params)
{
    qemuDomainObjPrivate *priv = NULL;
    g_autofree char *prefix = NULL;
    struct testQemuHotplugCpuData *data = NULL;
    GHashTable *schema = NULL;

    prefix = g_strdup_printf("%s/qemuhotplugtestcpus/%s", abs_srcdir, params->test);

    data = g_new0(struct testQemuHotplugCpuData, 1);

    data->file_xml_dom = g_strdup_printf("%s-domain.xml", prefix);
    data->file_xml_res_live = g_strdup_printf("%s-result-live.xml", prefix);
    data->file_xml_res_conf = g_strdup_printf("%s-result-conf.xml", prefix);
    data->file_json_monitor = g_strdup_printf("%s-monitor.json", prefix);

    if (virTestLoadFile(data->file_xml_dom, &data->xml_dom) < 0)
        goto error;

    if (qemuHotplugCreateObjects(driver.xmlopt, &data->vm, data->xml_dom,
                                 params->arch, params->capsLatestFiles,
                                 params->capsCache, params->schemaCache, &schema) < 0)
        goto error;

    /* create vm->newDef */
    data->vm->persistent = true;
    if (virDomainObjSetDefTransient(driver.xmlopt, data->vm, NULL) < 0)
        goto error;

    priv = data->vm->privateData;

    if (!(data->mon = qemuMonitorTestNewFromFileFull(data->file_json_monitor,
                                                     &driver, data->vm, schema)))
        goto error;

    if (params->fail)
        qemuMonitorTestAllowUnusedCommands(data->mon);

    priv->mon = qemuMonitorTestGetMonitor(data->mon);
    virObjectUnlock(priv->mon);

    if (qemuDomainRefreshVcpuInfo(data->vm, 0, false) < 0)
        goto error;

    return data;

 error:
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


static int
testQemuHotplugCpuGroup(const void *opaque)
{
    const struct testQemuHotplugCpuParams *params = opaque;
    struct testQemuHotplugCpuData *data = NULL;
    int ret = -1;
    int rc;

    if (!(data = testQemuHotplugCpuPrepare(params)))
        return -1;

    rc = qemuDomainSetVcpusInternal(&driver, data->vm, data->vm->def,
                                    data->vm->newDef, params->newcpus,
                                    true);

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

    if (!(data = testQemuHotplugCpuPrepare(params)))
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


static int
mymain(void)
{
    int ret = 0;
    g_autoptr(virQEMUDriverConfig) cfg = NULL;
    g_autoptr(GHashTable) capsLatestFiles = testQemuGetLatestCaps();
    g_autoptr(GHashTable) capsCache = virHashNew(virObjectUnref);
    g_autoptr(GHashTable) schemaCache = virHashNew((GDestroyNotify) g_hash_table_unref);
    struct qemuHotplugTestData data = { .capsLatestFiles = capsLatestFiles,
                                        .capsCache = capsCache,
                                        .schemaCache = schemaCache };
    struct testQemuHotplugCpuParams cpudata = { .capsLatestFiles = capsLatestFiles,
                                                .capsCache = capsCache,
                                                .schemaCache = schemaCache };

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    cfg = virQEMUDriverGetConfig(&driver);

    virEventRegisterDefaultImpl();

    if (!(driver.domainEventState = virObjectEventStateNew()))
        return EXIT_FAILURE;

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


#define DO_TEST(archname, file, ACTION, dev, fail_, keep_, ...) \
    do { \
        const char *my_mon[] = { __VA_ARGS__, NULL}; \
        const char *name = file " " #ACTION " " dev; \
        data.arch = archname; \
        data.action = ACTION; \
        data.domain_filename = file; \
        data.device_filename = dev; \
        data.fail = fail_; \
        data.mon = my_mon; \
        data.keep = keep_; \
        if (virTestRun(name, testQemuHotplug, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_ATTACH(arch, file, dev, fail, keep, ...) \
    DO_TEST(arch, file, ATTACH, dev, fail, keep, __VA_ARGS__)

#define DO_TEST_DETACH(arch, file, dev, fail, keep, ...) \
    DO_TEST(arch, file, DETACH, dev, fail, keep, __VA_ARGS__)

#define DO_TEST_UPDATE(arch, file, dev, fail, keep, ...) \
    DO_TEST(arch, file, UPDATE, dev, fail, keep, __VA_ARGS__)


#define QMP_OK      "{\"return\": {}}"
#define QMP_EMPTY_ARRAY "{\"return\": []}"

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
    DO_TEST_UPDATE("x86_64", "graphics-spice", "graphics-spice-nochange", false, false, NULL);
    DO_TEST_UPDATE("x86_64", "graphics-spice-timeout", "graphics-spice-timeout-nochange", false, false,
                   "set_password", QMP_OK, "expire_password", QMP_OK);
    DO_TEST_UPDATE("x86_64", "graphics-spice-timeout", "graphics-spice-timeout-password", false, false,
                   "set_password", QMP_OK, "expire_password", QMP_OK);
    DO_TEST_UPDATE("x86_64", "graphics-spice", "graphics-spice-listen", true, false, NULL);
    DO_TEST_UPDATE("x86_64", "graphics-spice-listen-network", "graphics-spice-listen-network-password", false, false,
                   "set_password", QMP_OK, "expire_password", QMP_OK);
    cfg->spiceTLS = false;

    DO_TEST_UPDATE("x86_64", "disk-cdrom", "disk-cdrom-nochange", false, false, NULL);

    DO_TEST_ATTACH("x86_64", "console-compat-2-live", "console-virtio", false, true,
                   "chardev-add", "{\"return\": {\"pty\": \"/dev/pts/26\"}}",
                   "device_add", QMP_OK);

    DO_TEST_DETACH("x86_64", "console-compat-2-live", "console-virtio", false, false,
                   "device_del", QMP_DEVICE_DELETED("console1") QMP_OK,
                   "chardev-remove", QMP_OK, "query-fdsets", "{\"return\": []}");

    DO_TEST_ATTACH("x86_64", "base-live", "disk-virtio", false, true,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);
    DO_TEST_DETACH("x86_64", "base-live", "disk-virtio", true, true,
                   "device_del", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "disk-virtio", false, false,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk4") QMP_OK,
                   "blockdev-del", QMP_OK,
                   "blockdev-del", QMP_OK);

    DO_TEST_ATTACH("x86_64", "base-live", "disk-usb", false, true,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);
    DO_TEST_DETACH("x86_64", "base-live", "disk-usb", true, true,
                   "device_del", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "disk-usb", false, false,
                   "device_del", QMP_DEVICE_DELETED("usb-disk16") QMP_OK,
                   "blockdev-del", QMP_OK,
                   "blockdev-del", QMP_OK);

    DO_TEST_ATTACH("x86_64", "base-live", "disk-scsi", false, true,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);
    DO_TEST_DETACH("x86_64", "base-live", "disk-scsi", true, true,
                   "device_del", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "disk-scsi", false, false,
                   "device_del", QMP_DEVICE_DELETED("scsi0-0-0-5") QMP_OK,
                   "blockdev-del", QMP_OK,
                   "blockdev-del", QMP_OK);

    DO_TEST_ATTACH("x86_64", "base-without-scsi-controller-live", "disk-scsi-2", false, true,
                   /* Four controllers added */
                   "device_add", QMP_OK,
                   "device_add", QMP_OK,
                   "device_add", QMP_OK,
                   "device_add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);
    DO_TEST_DETACH("x86_64", "base-with-scsi-controller-live", "disk-scsi-2", true, true,
                   "device_del", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-with-scsi-controller-live", "disk-scsi-2", false, false,
                   "device_del", QMP_DEVICE_DELETED("scsi3-0-6") QMP_OK,
                   "blockdev-del", QMP_OK,
                   "blockdev-del", QMP_OK);

    DO_TEST_ATTACH("x86_64", "base-live", "disk-scsi-multipath", false, true,
                   "object-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);
    DO_TEST_DETACH("x86_64", "base-live", "disk-scsi-multipath", true, true,
                   "device_del", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "disk-scsi-multipath", false, false,
                   "device_del", QMP_DEVICE_DELETED("scsi0-0-0-0") QMP_OK,
                   "blockdev-del", QMP_OK,
                   "blockdev-del", QMP_OK,
                   "object-del", QMP_OK);

    DO_TEST_ATTACH("x86_64", "base-live", "qemu-agent", false, true,
                   "getfd", QMP_OK,
                   "chardev-add", QMP_OK,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "qemu-agent-detach", false, false,
                   "device_del", QMP_DEVICE_DELETED("channel0") QMP_OK,
                   "chardev-remove", QMP_OK, "query-fdsets", "{\"return\": []}");

    DO_TEST_ATTACH("s390x", "base-ccw-live", "ccw-virtio", false, true,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);
    DO_TEST_DETACH("s390x", "base-ccw-live", "ccw-virtio", false, false,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk4") QMP_OK,
                   "blockdev-del", QMP_OK,
                   "blockdev-del", QMP_OK);

    DO_TEST_ATTACH("s390x", "base-ccw-live-with-ccw-virtio", "ccw-virtio-2", false, true,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);

    DO_TEST_DETACH("s390x", "base-ccw-live-with-ccw-virtio", "ccw-virtio-2", false, false,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk0") QMP_OK,
                   "blockdev-del", QMP_OK,
                   "blockdev-del", QMP_OK);

    DO_TEST_ATTACH("s390x", "base-ccw-live-with-ccw-virtio", "ccw-virtio-2-explicit", false, true,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);

    DO_TEST_DETACH("s390x", "base-ccw-live-with-ccw-virtio", "ccw-virtio-2-explicit", false, false,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk0") QMP_OK,
                   "blockdev-del", QMP_OK,
                   "blockdev-del", QMP_OK);

    /* Attach a second device, then detach the first one. Then attach the first one again. */
    DO_TEST_ATTACH("s390x", "base-ccw-live-with-ccw-virtio", "ccw-virtio-2-explicit", false, true,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);

    DO_TEST_DETACH("s390x", "base-ccw-live-with-2-ccw-virtio", "ccw-virtio-1-explicit", false, true,
                   "device_del", QMP_DEVICE_DELETED("virtio-disk4") QMP_OK);

    DO_TEST_ATTACH("s390x", "base-ccw-live-with-2-ccw-virtio", "ccw-virtio-1-reverse", false, false,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);

    DO_TEST_ATTACH("x86_64", "base-live", "ivshmem-plain", false, true,
                   "object-add", QMP_OK,
                   "device_add", QMP_OK);
    DO_TEST_ATTACH("x86_64", "base-live", "ivshmem-doorbell", false, true,
                   "chardev-add", QMP_OK,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live+ivshmem-plain", "ivshmem-doorbell-detach", false, true,
                   "device_del", QMP_DEVICE_DELETED("shmem1") QMP_OK,
                   "chardev-remove", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "ivshmem-plain-detach", false, false,
                   "device_del", QMP_DEVICE_DELETED("shmem0") QMP_OK,
                   "object-del", QMP_OK);
    DO_TEST_ATTACH("x86_64", "base-live+disk-scsi-wwn",
                   "disk-scsi-duplicate-wwn", false, false,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);

    DO_TEST_ATTACH("x86_64", "base-live", "hostdev-pci", false, true,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "hostdev-pci", false, false,
                   "device_del", QMP_DEVICE_DELETED("hostdev0") QMP_OK);
    DO_TEST_ATTACH("ppc64", "pseries-base-live", "hostdev-pci", false, true,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("ppc64", "pseries-base-live", "hostdev-pci", false, false,
                   "device_del", QMP_DEVICE_DELETED("hostdev0") QMP_OK);

    DO_TEST_ATTACH("x86_64", "base-live", "interface-vdpa", false, true,
                   "query-fdsets", "{\"return\":[{\"fdset-id\":99999}]}",
                   "add-fd", "{ \"return\": { \"fdset-id\": 1, \"fd\": 95 }}",
                   "netdev_add", QMP_OK, "device_add", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "interface-vdpa", false, false,
                   "device_del", QMP_DEVICE_DELETED("net0") QMP_OK,
                   "netdev_del", QMP_OK,
                   "query-fdsets",
                   "{ \"return\": [{\"fds\": [{\"fd\": 95, \"opaque\": \"/dev/vhost-vdpa-0\"}], \"fdset-id\": 1}]}",
                   "remove-fd", QMP_OK
                   );

    DO_TEST_ATTACH("x86_64", "base-live", "watchdog", false, true,
                   "set-action", QMP_OK,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "watchdog-full", false, false,
                   "device_del", QMP_DEVICE_DELETED("watchdog0") QMP_OK);

    DO_TEST_ATTACH("x86_64", "base-live", "watchdog-user-alias", false, true,
                   "set-action", QMP_OK,
                   "device_add", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "watchdog-user-alias-full", false, false,
                   "device_del", QMP_DEVICE_DELETED("ua-UserWatchdog") QMP_OK);

    /* attaching a watchdog with different action should fail */
    DO_TEST_ATTACH("x86_64", "base-live+watchdog", "watchdog-reset", true, false, NULL);

    DO_TEST_ATTACH("x86_64", "base-live", "guestfwd", false, true,
                   "getfd", QMP_OK,
                   "chardev-add", QMP_OK,
                   "netdev_add", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "guestfwd", false, false,
                   "netdev_del", QMP_OK);

    DO_TEST_ATTACH("x86_64", "base-live", "cdrom-usb", false, true,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);
    DO_TEST_DETACH("x86_64", "base-live", "cdrom-usb", true, true,
                   "device_del", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "cdrom-usb", false, false,
                   "device_del", QMP_DEVICE_DELETED("usb-disk4") QMP_OK,
                   "blockdev-del", QMP_OK,
                   "blockdev-del", QMP_OK);

    DO_TEST_ATTACH("x86_64", "base-live", "cdrom-scsi", false, true,
                   "blockdev-add", QMP_OK,
                   "blockdev-add", QMP_OK,
                   "device_add", QMP_OK,
                   "query-block", QMP_EMPTY_ARRAY);
    DO_TEST_DETACH("x86_64", "base-live", "cdrom-scsi", true, true,
                   "device_del", QMP_OK);
    DO_TEST_DETACH("x86_64", "base-live", "cdrom-scsi", false, false,
                   "device_del", QMP_DEVICE_DELETED("scsi0-0-0-4") QMP_OK,
                   "blockdev-del", QMP_OK,
                   "blockdev-del", QMP_OK);

#define DO_TEST_CPU_GROUP(archname, prefix, vcpus, expectfail) \
    do { \
        cpudata.test = prefix; \
        cpudata.arch = archname; \
        cpudata.newcpus = vcpus; \
        cpudata.fail = expectfail; \
        if (virTestRun("hotplug vcpus group " prefix, \
                       testQemuHotplugCpuGroup, &cpudata) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_CPU_GROUP("x86_64", "x86-modern-bulk", 7, false);
    DO_TEST_CPU_GROUP("ppc64", "ppc64-modern-bulk", 24, false);
    DO_TEST_CPU_GROUP("ppc64", "ppc64-modern-bulk", 15, true);
    DO_TEST_CPU_GROUP("ppc64", "ppc64-modern-bulk", 23, true);
    DO_TEST_CPU_GROUP("ppc64", "ppc64-modern-bulk", 25, true);

#define DO_TEST_CPU_INDIVIDUAL(archname, prefix, mapstr, statefl, expectfail) \
    do { \
        cpudata.test = prefix; \
        cpudata.arch = archname; \
        cpudata.cpumap = mapstr; \
        cpudata.state = statefl; \
        cpudata.fail = expectfail; \
        if (virTestRun("hotplug vcpus group " prefix, \
                       testQemuHotplugCpuIndividual, &cpudata) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_CPU_INDIVIDUAL("x86_64", "x86-modern-individual-add", "7", true, false);
    DO_TEST_CPU_INDIVIDUAL("x86_64", "x86-modern-individual-add", "6,7", true, true);
    DO_TEST_CPU_INDIVIDUAL("x86_64", "x86-modern-individual-add", "7", false, true);

    DO_TEST_CPU_INDIVIDUAL("ppc64", "ppc64-modern-individual", "16-23", true, false);
    DO_TEST_CPU_INDIVIDUAL("ppc64", "ppc64-modern-individual", "16-22", true, true);
    DO_TEST_CPU_INDIVIDUAL("ppc64", "ppc64-modern-individual", "17", true, true);

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
