/*
 * Copyright (C) 2011-2014 Red Hat, Inc.
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

#include "testutils.h"
#include "testutilsqemu.h"
#include "testutilsqemuschema.h"
#include "qemumonitortestutils.h"
#include "qemu/qemu_domain.h"
#include "qemu/qemu_block.h"
#include "qemu/qemu_monitor_json.h"
#include "qemu/qemu_qapi.h"
#include "qemu/qemu_alias.h"
#include "virerror.h"
#include "cpu/cpu.h"
#include "qemu/qemu_monitor.h"
#include "qemu/qemu_migration_params.h"
#define LIBVIRT_QEMU_MIGRATION_PARAMSPRIV_H_ALLOW
#include "qemu/qemu_migration_paramspriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _testQemuMonitorJSONSimpleFuncData testQemuMonitorJSONSimpleFuncData;
struct _testQemuMonitorJSONSimpleFuncData {
    const char *cmd;
    int (* func) (qemuMonitor *mon);
    virDomainXMLOption *xmlopt;
    const char *reply;
    GHashTable *schema;
    bool allowDeprecated;
    bool allowRemoved;
};

typedef struct _testGenericData testGenericData;
struct _testGenericData {
    virDomainXMLOption *xmlopt;
    GHashTable *schema;
};

const char *queryBlockReply =
"{"
"    \"return\": ["
"        {"
"            \"io-status\": \"ok\","
"            \"device\": \"drive-virtio-disk0\","
"            \"locked\": false,"
"            \"removable\": false,"
"            \"inserted\": {"
"                \"iops_rd\": 5,"
"                \"iops_wr\": 6,"
"                \"ro\": false,"
"                \"backing_file_depth\": 0,"
"                \"drv\": \"qcow2\","
"                \"iops\": 4,"
"                \"bps_wr\": 3,"
"                \"encrypted\": false,"
"                \"bps\": 1,"
"                \"bps_rd\": 2,"
"                \"bps_max\": 7,"
"                \"iops_max\": 10,"
"                \"bps_rd_max\": 8,"
"                \"bps_wr_max\": 9,"
"                \"iops_rd_max\": 11,"
"                \"iops_wr_max\": 12,"
"                \"iops_size\": 13,"
"                \"group\": \"group14\","
"                \"bps_max_length\": 15,"
"                \"bps_rd_max_length\": 16,"
"                \"bps_wr_max_length\": 17,"
"                \"iops_max_length\": 18,"
"                \"iops_rd_max_length\": 19,"
"                \"iops_wr_max_length\": 20,"
"                \"file\": \"/home/zippy/work/tmp/gentoo.qcow2\","
"                \"encryption_key_missing\": false"
"            },"
"            \"type\": \"unknown\""
"        },"
"        {"
"            \"io-status\": \"ok\","
"            \"device\": \"drive-virtio-disk1\","
"            \"locked\": false,"
"            \"removable\": false,"
"            \"inserted\": {"
"                \"iops_rd\": 0,"
"                \"iops_wr\": 0,"
"                \"ro\": false,"
"                \"backing_file_depth\": 0,"
"                \"drv\": \"raw\","
"                \"iops\": 0,"
"                \"bps_wr\": 0,"
"                \"encrypted\": false,"
"                \"bps\": 0,"
"                \"bps_rd\": 0,"
"                \"file\": \"/home/zippy/test.bin\","
"                \"encryption_key_missing\": false"
"            },"
"            \"type\": \"unknown\""
"        },"
"        {"
"            \"io-status\": \"ok\","
"            \"device\": \"drive-ide0-1-0\","
"            \"locked\": true,"
"            \"removable\": true,"
"            \"inserted\": {"
"                \"iops_rd\": 0,"
"                \"iops_wr\": 0,"
"                \"ro\": true,"
"                \"backing_file_depth\": 0,"
"                \"drv\": \"raw\","
"                \"iops\": 0,"
"                \"bps_wr\": 0,"
"                \"encrypted\": false,"
"                \"bps\": 0,"
"                \"bps_rd\": 0,"
"                \"file\": \"/home/zippy/tmp/install-amd64-minimal-20121210.iso\","
"                \"encryption_key_missing\": false"
"            },"
"            \"tray_open\": false,"
"            \"type\": \"unknown\""
"        },"
"        {"
"            \"io-status\": \"ok\","
"            \"device\": \"drive-ide0-1-1\","
"            \"locked\": false,"
"            \"removable\": true,"
"            \"tray_open\": false,"
"            \"type\": \"unknown\""
"        }"
"    ],"
"    \"id\": \"libvirt-10\""
"}";

static int
testQemuMonitorJSONGetStatus(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    bool running = false;
    virDomainPausedReason reason = 0;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-status",
                               "{ "
                               "    \"return\": { "
                               "        \"status\": \"running\", "
                               "        \"singlestep\": false, "
                               "        \"running\": true "
                               "    } "
                               "}") < 0)
        return -1;
    if (qemuMonitorTestAddItem(test, "query-status",
                               "{ "
                               "    \"return\": { "
                               "        \"singlestep\": false, "
                               "        \"running\": false "
                               "    } "
                               "}") < 0)
        return -1;
    if (qemuMonitorTestAddItem(test, "query-status",
                               "{ "
                               "    \"return\": { "
                               "        \"status\": \"inmigrate\", "
                               "        \"singlestep\": false, "
                               "        \"running\": false "
                               "    } "
                               "}") < 0)
        return -1;

    if (qemuMonitorGetStatus(qemuMonitorTestGetMonitor(test),
                             &running, &reason) < 0)
        return -1;

    if (!running) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Running was not true");
        return -1;
    }

    if (reason != VIR_DOMAIN_PAUSED_UNKNOWN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Reason was unexpectedly set to %d", reason);
        return -1;
    }

    if (qemuMonitorGetStatus(qemuMonitorTestGetMonitor(test),
                             &running, &reason) < 0)
        return -1;

    if (running) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Running was not false");
        return -1;
    }

    if (reason != VIR_DOMAIN_PAUSED_UNKNOWN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Reason was unexpectedly set to %d", reason);
        return -1;
    }

    if (qemuMonitorGetStatus(qemuMonitorTestGetMonitor(test),
                             &running, &reason) < 0)
        return -1;

    if (running) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Running was not false");
        return -1;
    }

    if (reason != VIR_DOMAIN_PAUSED_MIGRATION) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Reason was unexpectedly set to %d", reason);
        return -1;
    }

    return 0;
}

static int
testQemuMonitorJSONGetVersion(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    int major;
    int minor;
    int micro;
    g_autofree char *package = NULL;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-version",
                               "{ "
                               "  \"return\":{ "
                               "     \"qemu\":{ "
                               "        \"major\":1, "
                               "        \"minor\":2, "
                               "        \"micro\":3 "
                               "      },"
                               "     \"package\":\"\""
                               "  }"
                               "}") < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-version",
                               "{ "
                               "  \"return\":{ "
                               "     \"qemu\":{ "
                               "        \"major\":0, "
                               "        \"minor\":11, "
                               "        \"micro\":6 "
                               "      },"
                               "     \"package\":\"2.283.el6\""
                               "  }"
                               "}") < 0)
        return -1;

    if (qemuMonitorGetVersion(qemuMonitorTestGetMonitor(test),
                              &major, &minor, &micro,
                              &package) < 0)
        return -1;

    if (major != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Major %d was not 1", major);
        return -1;
    }
    if (minor != 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Minor %d was not 2", major);
        return -1;
    }
    if (micro != 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Micro %d was not 3", major);
        return -1;
    }

    if (STRNEQ(package, "")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Package %s was not ''", package);
        return -1;
    }
    VIR_FREE(package);

    if (qemuMonitorGetVersion(qemuMonitorTestGetMonitor(test),
                              &major, &minor, &micro,
                              &package) < 0)
        return -1;

    if (major != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Major %d was not 0", major);
        return -1;
    }
    if (minor != 11) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Minor %d was not 11", major);
        return -1;
    }
    if (micro != 6) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Micro %d was not 6", major);
        return -1;
    }

    if (STRNEQ(package, "2.283.el6")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Package %s was not '2.283.el6'", package);
        return -1;
    }

    return 0;
}

static int
testQemuMonitorJSONGetMachines(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    int ret = -1;
    qemuMonitorMachineInfo **info;
    int ninfo = 0;
    const char *null = NULL;
    size_t i;

    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-machines",
                               "{ "
                               "  \"return\": [ "
                               "   { "
                               "     \"name\": \"pc-1.0\" "
                               "   }, "
                               "   { "
                               "     \"name\": \"pc-1.1\" "
                               "   }, "
                               "   { "
                               "     \"name\": \"pc-1.2\", "
                               "     \"is-default\": true, "
                               "     \"alias\": \"pc\" "
                               "   } "
                               "  ]"
                               "}") < 0)
        goto cleanup;

    if ((ninfo = qemuMonitorGetMachines(qemuMonitorTestGetMonitor(test),
                                        &info)) < 0)
        goto cleanup;

    if (ninfo != 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "ninfo %d is not 3", ninfo);
        goto cleanup;
    }

#define CHECK(i, wantname, wantisDefault, wantalias) \
    do { \
        if (STRNEQ(info[i]->name, (wantname))) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "name %s is not %s", \
                           info[i]->name, (wantname)); \
            goto cleanup; \
        } \
        if (info[i]->isDefault != (wantisDefault)) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "isDefault %d is not %d", \
                           info[i]->isDefault, (wantisDefault)); \
            goto cleanup; \
        } \
        if (STRNEQ_NULLABLE(info[i]->alias, (wantalias))) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "alias %s is not %s", \
                           info[i]->alias, NULLSTR(wantalias)); \
            goto cleanup; \
        } \
    } while (0)

    CHECK(0, "pc-1.0", false, null);
    CHECK(1, "pc-1.1", false, null);
    CHECK(2, "pc-1.2", true, "pc");

#undef CHECK

    ret = 0;

 cleanup:
    for (i = 0; i < ninfo; i++)
        qemuMonitorMachineInfoFree(info[i]);
    VIR_FREE(info);

    return ret;
}


static int
testQemuMonitorJSONGetCPUDefinitions(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    g_autoptr(qemuMonitorCPUDefs) defs = NULL;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-cpu-definitions",
                               "{ "
                               "  \"return\": [ "
                               "   { "
                               "     \"name\": \"qemu64\" "
                               "   }, "
                               "   { "
                               "     \"name\": \"Opteron_G4\", "
                               "     \"unavailable-features\": [\"vme\"]"
                               "   }, "
                               "   { "
                               "     \"name\": \"Westmere\", "
                               "     \"unavailable-features\": []"
                               "   } "
                               "  ]"
                               "}") < 0)
        return -1;

    if (qemuMonitorGetCPUDefinitions(qemuMonitorTestGetMonitor(test), &defs) < 0)
        return -1;

    if (defs->ncpus != 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "ncpus %zu is not 3", defs->ncpus);
        return -1;
    }

#define CHECK_FULL(i, wantname, Usable) \
    do { \
        if (STRNEQ(defs->cpus[i].name, (wantname))) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "name %s is not %s", \
                           defs->cpus[i].name, (wantname)); \
            return -1; \
        } \
        if (defs->cpus[i].usable != (Usable)) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "%s: expecting usable flag %d, got %d", \
                           defs->cpus[i].name, Usable, defs->cpus[i].usable); \
            return -1; \
        } \
    } while (0)

#define CHECK(i, wantname) \
    CHECK_FULL(i, wantname, VIR_DOMCAPS_CPU_USABLE_UNKNOWN)

#define CHECK_USABLE(i, wantname, usable) \
    CHECK_FULL(i, wantname, \
               usable ? VIR_DOMCAPS_CPU_USABLE_YES : VIR_DOMCAPS_CPU_USABLE_NO)

    CHECK(0, "qemu64");
    CHECK_USABLE(1, "Opteron_G4", false);
    CHECK_USABLE(2, "Westmere", true);

#undef CHECK
#undef CHECK_USABLE
#undef CHECK_FULL

    return 0;
}


static int
testQemuMonitorJSONGetTPMModels(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    g_auto(GStrv) tpmmodels = NULL;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-tpm-models",
                               "{ "
                               "  \"return\": [ "
                               "  \"passthrough\""
                               "  ]"
                               "}") < 0)
        return -1;

    if (qemuMonitorGetTPMModels(qemuMonitorTestGetMonitor(test), &tpmmodels) < 0)
        return -1;

    if (g_strv_length(tpmmodels) != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "expected 1 tpm model");
        return -1;
    }

#define CHECK(i, wantname) \
    do { \
        if (STRNEQ(tpmmodels[i], (wantname))) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "name %s is not %s", \
                           tpmmodels[i], (wantname)); \
            return -1; \
        } \
    } while (0)

    CHECK(0, "passthrough");

#undef CHECK

    return 0;
}


struct qemuMonitorJSONTestAttachChardevData {
    virDomainChrSourceDef *chr;
    const char *expectPty;
    bool fail;

    virDomainXMLOption *xmlopt;
    GHashTable *schema;
    const char *expectargs;
    const char *reply;
};

static int
testQemuMonitorJSONAttachChardev(const void *opaque)
{
    const struct qemuMonitorJSONTestAttachChardevData *data = opaque;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewSchema(data->xmlopt, data->schema);
    int rc;

    if (!test)
        return -1;

    if (data->expectargs) {
        g_autofree char *jsonreply = g_strdup_printf("{\"return\": {%s}}", NULLSTR_EMPTY(data->reply));
        g_autofree char *jsoncommand = NULL;
        char *n;

        jsoncommand = g_strdup_printf("{\"execute\": \"chardev-add\", \"arguments\": %s, \"id\" : \"libvirt-1\"}", data->expectargs);

        /* data->expectargs has ' instead of " */
        for (n = jsoncommand; *n; n++) {
            if (*n == '\'')
                *n = '"';
        }

        if (qemuMonitorTestAddItemVerbatim(test, jsoncommand, NULL, jsonreply) < 0)
            return -1;
    }

    if ((rc = qemuMonitorAttachCharDev(qemuMonitorTestGetMonitor(test),
                                       "alias", data->chr)) < 0)
        goto cleanup;

    if (data->chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
        if (STRNEQ_NULLABLE(data->expectPty, data->chr->data.file.path)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "expected PTY path: %s got: %s",
                           NULLSTR(data->expectPty),
                           NULLSTR(data->chr->data.file.path));
            rc = -1;
        }

        VIR_FREE(data->chr->data.file.path);
    }

 cleanup:
    if ((rc != 0) != data->fail)
        return -1;
    else
        return 0;
}


static int
qemuMonitorJSONTestAttachOneChardev(virDomainXMLOption *xmlopt,
                                    GHashTable *schema,
                                    const char *label,
                                    virDomainChrSourceDef *chr,
                                    const char *expectargs,
                                    const char *reply,
                                    const char *expectPty,
                                    bool fail)

{
    struct qemuMonitorJSONTestAttachChardevData data = { .chr = chr,
                                                         .fail = fail,
                                                         .expectPty = expectPty,
                                                         .expectargs = expectargs,
                                                         .reply = reply,
                                                         .xmlopt = xmlopt,
                                                         .schema = schema };
    g_autofree char *fulllabel = g_strdup_printf("qemuMonitorJSONTestAttachChardev(%s)", label);

    return virTestRun(fulllabel, &testQemuMonitorJSONAttachChardev, &data);
}


static int
qemuMonitorJSONTestAttachChardev(virDomainXMLOption *xmlopt,
                                 GHashTable *schema)
{
    virDomainChrDef chrdev = { .info = { .alias = (char *) "alias" }};
    virDomainDeviceDef dev = { .type = VIR_DOMAIN_DEVICE_CHR, .data.chr = &chrdev };
    int ret = 0;

#define CHECK(label, fail, expectargs) \
    if (qemuMonitorJSONTestAttachOneChardev(xmlopt, schema, label, chr, \
                                            expectargs, NULL, NULL, fail) < 0) \
        ret = -1

    {
        g_autoptr(virDomainChrSourceDef) chr = virDomainChrSourceDefNew(xmlopt);

        chr->type = VIR_DOMAIN_CHR_TYPE_NULL;
        CHECK("null", false,
              "{'id':'alias','backend':{'type':'null','data':{}}}");

        chr->type = VIR_DOMAIN_CHR_TYPE_VC;
        CHECK("vc", false,
              "{'id':'alias','backend':{'type':'vc','data':{}}}");

        chr->type = VIR_DOMAIN_CHR_TYPE_SPICEVMC;
        CHECK("spicevmc", false,
              "{'id':'alias','backend':{'type':'spicevmc',"
                                       "'data':{'type':'vdagent'}}}");

        chr->type = VIR_DOMAIN_CHR_TYPE_PIPE;
        CHECK("pipe", true, NULL);

        chr->type = VIR_DOMAIN_CHR_TYPE_STDIO;
        CHECK("stdio", true, NULL);

        chr->type = VIR_DOMAIN_CHR_TYPE_PTY;
        CHECK("pty missing path", true,
              "{'id':'alias','backend':{'type':'pty','data':{}}}");
        if (qemuMonitorJSONTestAttachOneChardev(xmlopt, schema, "pty", chr,
                                                "{'id':'alias',"
                                                 "'backend':{'type':'pty',"
                                                 "'data':{}}}",
                                                "\"pty\" : \"/dev/pts/0\"",
                                                "/dev/pts/0", false) < 0)
            ret = -1;
    }

    {
        g_autoptr(virDomainChrSourceDef) chr = virDomainChrSourceDefNew(xmlopt);

        chr->data.file.path = g_strdup("/test/path");

        chr->type = VIR_DOMAIN_CHR_TYPE_DEV;
        CHECK("device", false,
              "{'id':'alias','backend':{'type':'serial','data':{'device':'/test/path'}}}");

        chr->type = VIR_DOMAIN_CHR_TYPE_FILE;
        chr->logfile = g_strdup("/test/logfile");
        chr->logappend = VIR_TRISTATE_SWITCH_OFF;
        CHECK("file", false,
              "{'id':'alias','backend':{'type':'file','data':{'out':'/test/path',"
                                                             "'logfile':'/test/logfile',"
                                                             "'logappend':false}}}");

        chrdev.source = chr;
        ignore_value(testQemuPrepareHostBackendChardevOne(&dev, chr, NULL));
        CHECK("file", false,
              "{'id':'alias','backend':{'type':'file','data':{'out':'/dev/fdset/monitor-fake',"
                                                             "'append':true,"
                                                             "'logfile':'/dev/fdset/monitor-fake',"
                                                             "'logappend':true}}}");
    }

    {
        g_autoptr(virDomainChrSourceDef) chr = virDomainChrSourceDefNew(xmlopt);
        qemuDomainChrSourcePrivate *chrSourcePriv = QEMU_DOMAIN_CHR_SOURCE_PRIVATE(chr);

        chr->type = VIR_DOMAIN_CHR_TYPE_TCP;
        chr->data.tcp.host = g_strdup("example.com");
        chr->data.tcp.service = g_strdup("1234");
        CHECK("tcp", false,
              "{'id':'alias',"
               "'backend':{'type':'socket',"
                          "'data':{'addr':{'type':'inet',"
                                          "'data':{'host':'example.com',"
                                                  "'port':'1234'}},"
                                  "'telnet':false,"
                                  "'server':false}}}");

        chr->data.tcp.tlscreds = true;
        chrSourcePriv->tlsCredsAlias = qemuAliasTLSObjFromSrcAlias("alias");
        chr->logfile = g_strdup("/test/log");
        CHECK("tcp", false,
              "{'id':'alias',"
               "'backend':{'type':'socket',"
                          "'data':{'addr':{'type':'inet',"
                                          "'data':{'host':'example.com',"
                                                  "'port':'1234'}},"
                                  "'telnet':false,"
                                  "'server':false,"
                                  "'tls-creds':'objalias_tls0',"
                                  "'logfile':'/test/log'}}}");

    }

    {
        g_autoptr(virDomainChrSourceDef) chr = virDomainChrSourceDefNew(xmlopt);

        chr->type = VIR_DOMAIN_CHR_TYPE_UDP;
        chr->data.udp.connectHost = g_strdup("example.com");
        chr->data.udp.connectService = g_strdup("1234");
        CHECK("udp", false,
              "{'id':'alias',"
               "'backend':{'type':'udp',"
                          "'data':{'remote':{'type':'inet',"
                                            "'data':{'host':'example.com',"
                                                    "'port':'1234'}}}}}");

        chr->data.udp.bindService = g_strdup("4321");
        CHECK("udp", false,
              "{'id':'alias',"
               "'backend':{'type':'udp',"
                          "'data':{'remote':{'type':'inet',"
                                            "'data':{'host':'example.com',"
                                                    "'port':'1234'}},"
                                  "'local':{'type':'inet',"
                                           "'data':{'host':'',"
                                                   "'port':'4321'}}}}}");

        chr->data.udp.bindHost = g_strdup("localhost");
        CHECK("udp", false,
              "{'id':'alias',"
               "'backend':{'type':'udp',"
                          "'data':{'remote':{'type':'inet',"
                                            "'data':{'host':'example.com',"
                                                    "'port':'1234'}},"
                                  "'local':{'type':'inet',"
                                           "'data':{'host':'localhost',"
                                                   "'port':'4321'}}}}}");
    }

    {
        g_autoptr(virDomainChrSourceDef) chr = virDomainChrSourceDefNew(xmlopt);

        chr->type = VIR_DOMAIN_CHR_TYPE_UNIX;
        chr->data.nix.path = g_strdup("/path/to/socket");
        CHECK("unix", false,
              "{'id':'alias',"
               "'backend':{'type':'socket',"
                          "'data':{'addr':{'type':'unix',"
                                          "'data':{'path':'/path/to/socket'}},"
                                  "'server':false}}}");
    }

#undef CHECK

    return ret;
}


static int
testQemuMonitorJSONDetachChardev(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "chardev-remove", "{\"return\": {}}") < 0)
        return -1;

    if (qemuMonitorDetachCharDev(qemuMonitorTestGetMonitor(test),
                                 "dummy_chrID") < 0)
        return -1;

    return 0;
}

/*
 * This test will request to return a list of paths for "/". It should be
 * a simple list of 1 real element that being the "machine". The following
 * is the execution and expected return:
 *
 *  {"execute":"qom-list", "arguments": { "path": "/"}}"
 *  {"return": [{"name": "machine", "type": "child<container>"}, \
 *              {"name": "type", "type": "string"}]}
 */
static int
testQemuMonitorJSONGetListPaths(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    int ret = -1;
    qemuMonitorJSONListPath **paths;
    int npaths = 0;
    size_t i;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "qom-list",
                               "{ "
                               "  \"return\": [ "
                               "  {\"name\": \"machine\", "
                               "   \"type\": \"child<container>\"}, "
                               "  {\"name\": \"type\", "
                               "   \"type\": \"string\"} "
                               " ]"
                               "}") < 0)
        goto cleanup;

    /* present with path */
    if ((npaths = qemuMonitorJSONGetObjectListPaths(
                                                qemuMonitorTestGetMonitor(test),
                                                "/",
                                                &paths)) < 0)
        goto cleanup;

    if (npaths != 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "npaths was %d, expected 1", npaths);
        goto cleanup;
    }

#define CHECK(i, wantname, wanttype) \
    do { \
        if (STRNEQ(paths[i]->name, (wantname))) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "name was %s, expected %s", \
                           paths[i]->name, (wantname)); \
            goto cleanup; \
        } \
        if (STRNEQ_NULLABLE(paths[i]->type, (wanttype))) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "type was %s, expected %s", \
                           NULLSTR(paths[i]->type), (wanttype)); \
            goto cleanup; \
        } \
    } while (0)

    CHECK(0, "machine", "child<container>");

#undef CHECK

    ret = 0;

 cleanup:
    for (i = 0; i < npaths; i++)
        qemuMonitorJSONListPathFree(paths[i]);
    VIR_FREE(paths);
    return ret;
}


/*
 * This test will use a path to /machine/i440fx which should exist in order
 * to ensure that the qom-get property fetch works properly. The following
 * is the execution and expected return:
 *
 *
 *  { "execute": "qom-get","arguments": \
 *      { "path": "/machine/i440fx","property": "realized"}}
 *   {"return": true}
 */
static int
testQemuMonitorJSONGetObjectProperty(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    qemuMonitorJSONObjectProperty prop = { 0 };
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "qom-get",
                               "{ \"return\": true }") < 0)
        return -1;

    /* Present with path and property */
    prop.type = QEMU_MONITOR_OBJECT_PROPERTY_BOOLEAN;
    if (qemuMonitorJSONGetObjectProperty(qemuMonitorTestGetMonitor(test),
                                         "/machine/i440fx",
                                         "realized",
                                         &prop) < 0)
        return -1;

    if (!prop.val.b) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "expected true, but false returned");
        return -1;
    }

    return 0;
}


/*
 * This test will use a path to /machine/i440fx which should exist in order
 * to ensure that the qom-set property set works properly. The test will
 * set a true property to true just as a proof of concept.  Setting it to
 * false is not a good idea...
 */
static int
testQemuMonitorJSONSetObjectProperty(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    qemuMonitorJSONObjectProperty prop = { 0 };
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "qom-set",
                               "{ \"return\": {} }") < 0)
        return -1;
    if (qemuMonitorTestAddItem(test, "qom-get",
                               "{ \"return\": true }") < 0)
        return -1;

    /* Let's attempt the setting */
    prop.type = QEMU_MONITOR_OBJECT_PROPERTY_BOOLEAN;
    prop.val.b = true;
    if (qemuMonitorJSONSetObjectProperty(qemuMonitorTestGetMonitor(test),
                                         "/machine/i440fx",
                                         "realized",
                                         &prop) < 0)
        return -1;

    /* To make sure it worked, fetch the property - if this succeeds then
     * we didn't hose things
     */
    memset(&prop, 0, sizeof(qemuMonitorJSONObjectProperty));
    prop.type = QEMU_MONITOR_OBJECT_PROPERTY_BOOLEAN;
    if (qemuMonitorJSONGetObjectProperty(qemuMonitorTestGetMonitor(test),
                                         "/machine/i440fx",
                                         "realized",
                                         &prop) < 0)
        return -1;

    if (!prop.val.b) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "expected true, but false returned");
        return -1;
    }

    return 0;
}


static int
testQemuMonitorJSONGetDeviceAliases(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    int ret = -1;
    g_auto(GStrv) aliases = NULL;
    const char **alias;
    const char *expected[] = {
        "virtio-disk25", "video0", "serial0", "ide0-0-0", "usb", NULL };
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test,
                               "qom-list",
                               "{\"return\": ["
                               " {\"name\": \"virtio-disk25\","
                               "  \"type\": \"child<virtio-blk-pci>\"},"
                               " {\"name\": \"video0\","
                               "  \"type\": \"child<VGA>\"},"
                               " {\"name\": \"serial0\","
                               "  \"type\": \"child<isa-serial>\"},"
                               " {\"name\": \"ide0-0-0\","
                               "  \"type\": \"child<ide-cd>\"},"
                               " {\"name\": \"usb\","
                               "  \"type\": \"child<piix3-usb-uhci>\"},"
                               " {\"name\": \"type\", \"type\": \"string\"}"
                               "]}") < 0)
        return -1;

    if (qemuMonitorJSONGetDeviceAliases(qemuMonitorTestGetMonitor(test),
                                        &aliases) < 0)
        return -1;

    if (!aliases) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", "no aliases returned");
        return -1;
    }

    ret = 0;
    for (alias = (const char **) aliases; *alias; alias++) {
        if (!g_strv_contains(expected, *alias)) {
            fprintf(stderr, "got unexpected device alias '%s'\n", *alias);
            ret = -1;
        }
    }
    for (alias = expected; *alias; alias++) {
        if (!g_strv_contains((const char **) aliases, *alias)) {
            fprintf(stderr, "missing expected alias '%s'\n", *alias);
            ret = -1;
        }
    }

    return ret;
}

static int
testQemuMonitorJSONCPU(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    bool running = false;
    virDomainPausedReason reason = 0;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "stop", "{\"return\": {}}") < 0 ||
        qemuMonitorTestAddItem(test, "query-status",
                               "{\"return\": {"
                               "   \"status\": \"paused\","
                               "   \"singlestep\": false,"
                               "   \"running\": false}}") < 0 ||
        qemuMonitorTestAddItem(test, "cont", "{\"return\": {}}") < 0 ||
        qemuMonitorTestAddItem(test, "query-status",
                               "{\"return\": {"
                               "    \"status\": \"running\","
                               "    \"singlestep\": false,"
                               "    \"running\": true}}") < 0)
        return -1;

    if (qemuMonitorJSONStopCPUs(qemuMonitorTestGetMonitor(test)) < 0)
        return -1;

    if (qemuMonitorGetStatus(qemuMonitorTestGetMonitor(test),
                             &running, &reason) < 0)
        return -1;

    if (running) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Running was not false");
        return -1;
    }

    if (qemuMonitorJSONStartCPUs(qemuMonitorTestGetMonitor(test)) < 0)
        return -1;

    if (qemuMonitorGetStatus(qemuMonitorTestGetMonitor(test),
                             &running, &reason) < 0)
        return -1;

    if (!running) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Running was not true");
        return -1;
    }

    return 0;
}

static int
testQemuMonitorJSONSimpleFunc(const void *opaque)
{
    testQemuMonitorJSONSimpleFuncData *data =
        (testQemuMonitorJSONSimpleFuncData *) opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    const char *reply = data->reply;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (!reply)
        reply = "{\"return\":{}}";

    if (qemuMonitorTestAddItem(test, data->cmd, reply) < 0)
        return -1;

    if (data->func(qemuMonitorTestGetMonitor(test)) < 0)
        return -1;

    return 0;
}

#define GEN_TEST_FUNC(funcName, ...) \
static int \
testQemuMonitorJSON ## funcName(const void *opaque) \
{ \
    const testQemuMonitorJSONSimpleFuncData *data = opaque; \
    virDomainXMLOption *xmlopt = data->xmlopt; \
    const char *reply = data->reply; \
    g_autoptr(qemuMonitorTest) test = NULL; \
 \
    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema))) \
        return -1; \
 \
    if (data->allowDeprecated) \
        qemuMonitorTestSkipDeprecatedValidation(test, data->allowRemoved); \
 \
    if (!reply) \
        reply = "{\"return\":{}}"; \
 \
    if (qemuMonitorTestAddItem(test, data->cmd, reply) < 0) \
        return -1; \
 \
    if (funcName(qemuMonitorTestGetMonitor(test), __VA_ARGS__) < 0) \
        return -1; \
 \
    return 0; \
}

GEN_TEST_FUNC(qemuMonitorJSONSetLink, "vnet0", VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN)
GEN_TEST_FUNC(qemuMonitorJSONBlockResize, "vda", "asdf", 123456)
GEN_TEST_FUNC(qemuMonitorJSONSetPassword, "spice", "secret_password", "disconnect")
GEN_TEST_FUNC(qemuMonitorJSONExpirePassword, "spice", "123456")
GEN_TEST_FUNC(qemuMonitorJSONSetBalloon, 1024)
GEN_TEST_FUNC(qemuMonitorJSONSaveVirtualMemory, 0, 1024, "/foo/bar")
GEN_TEST_FUNC(qemuMonitorJSONSavePhysicalMemory, 0, 1024, "/foo/bar")
GEN_TEST_FUNC(qemuMonitorJSONMigrate, 0, "tcp:localhost:12345")
GEN_TEST_FUNC(qemuMonitorJSONMigrateRecover, "tcp://destination.host:54321");
GEN_TEST_FUNC(qemuMonitorJSONDump, "dummy_protocol", "elf",
              true)
GEN_TEST_FUNC(qemuMonitorJSONGraphicsRelocate, VIR_DOMAIN_GRAPHICS_TYPE_SPICE,
              "localhost", 12345, 12346, "certsubjectval")
GEN_TEST_FUNC(qemuMonitorJSONRemoveNetdev, "net0")
GEN_TEST_FUNC(qemuMonitorJSONDelDevice, "ide0")
GEN_TEST_FUNC(qemuMonitorJSONBlockdevMirror, "jobname", true, "vdb", "targetnode", 1024, 1234, 31234, true, true)
GEN_TEST_FUNC(qemuMonitorJSONBlockStream, "vdb", "jobname", "backingnode", "backingfilename", 1024)
GEN_TEST_FUNC(qemuMonitorJSONBlockCommit, "vdb", "jobname", "topnode", "basenode", "backingfilename", 1024, VIR_TRISTATE_BOOL_YES)
GEN_TEST_FUNC(qemuMonitorJSONScreendump, "devicename", 1, NULL, "/foo/bar")
GEN_TEST_FUNC(qemuMonitorJSONOpenGraphics, "spice", "spicefd", false)
GEN_TEST_FUNC(qemuMonitorJSONNBDServerAdd, "vda", "export", true, "bitmap")
GEN_TEST_FUNC(qemuMonitorJSONDetachCharDev, "serial1")
GEN_TEST_FUNC(qemuMonitorJSONBlockdevTrayOpen, "foodev", true)
GEN_TEST_FUNC(qemuMonitorJSONBlockdevTrayClose, "foodev")
GEN_TEST_FUNC(qemuMonitorJSONBlockdevMediumRemove, "foodev")
GEN_TEST_FUNC(qemuMonitorJSONBlockdevMediumInsert, "foodev", "newnode")
GEN_TEST_FUNC(qemuMonitorJSONBitmapRemove, "foodev", "newnode")
GEN_TEST_FUNC(qemuMonitorJSONJobDismiss, "jobname")
GEN_TEST_FUNC(qemuMonitorJSONJobComplete, "jobname")
GEN_TEST_FUNC(qemuMonitorJSONJobFinalize, "jobname")
GEN_TEST_FUNC(qemuMonitorJSONBlockJobCancel, "jobname", true)
GEN_TEST_FUNC(qemuMonitorJSONSetAction,
              QEMU_MONITOR_ACTION_SHUTDOWN_PAUSE,
              QEMU_MONITOR_ACTION_REBOOT_RESET,
              QEMU_MONITOR_ACTION_WATCHDOG_SHUTDOWN,
              QEMU_MONITOR_ACTION_PANIC_SHUTDOWN)
GEN_TEST_FUNC(qemuMonitorJSONSetLaunchSecurityState, "sev_secret_header",
              "sev_secret", 0, true)

static int
testQemuMonitorJSONqemuMonitorJSONNBDServerStart(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    virStorageNetHostDef server_tcp = {
        .name = (char *)"localhost",
        .port = 12345,
        .transport = VIR_STORAGE_NET_HOST_TRANS_TCP,
    };
    virStorageNetHostDef server_unix = {
        .socket = (char *)"/tmp/sock",
        .transport = VIR_STORAGE_NET_HOST_TRANS_UNIX,
    };
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "nbd-server-start",
                               "{\"return\":{}}") < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "nbd-server-start",
                               "{\"return\":{}}") < 0)
        return -1;

    if (qemuMonitorJSONNBDServerStart(qemuMonitorTestGetMonitor(test),
                                      &server_tcp, "test-alias") < 0)
        return -1;

    if (qemuMonitorJSONNBDServerStart(qemuMonitorTestGetMonitor(test),
                                      &server_unix, "test-alias") < 0)
        return -1;

    return 0;
}

static bool
testQemuMonitorJSONqemuMonitorJSONQueryCPUsEqual(struct qemuMonitorQueryCpusEntry *a,
                                                 struct qemuMonitorQueryCpusEntry *b)
{
    if (a->tid != b->tid ||
        STRNEQ_NULLABLE(a->qom_path, b->qom_path))
        return false;

    return true;
}


static int
testQEMUMonitorJSONqemuMonitorJSONQueryCPUsHelper(qemuMonitorTest *test,
                                                  struct qemuMonitorQueryCpusEntry *expect,
                                                  size_t num)
{
    struct qemuMonitorQueryCpusEntry *cpudata = NULL;
    size_t ncpudata = 0;
    size_t i;
    int ret = -1;

    if (qemuMonitorJSONQueryCPUs(qemuMonitorTestGetMonitor(test),
                                 &cpudata, &ncpudata, true) < 0)
        goto cleanup;

    if (ncpudata != num) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expecting ncpupids = %zu but got %zu", num, ncpudata);
        goto cleanup;
    }

    for (i = 0; i < ncpudata; i++) {
        if (!testQemuMonitorJSONqemuMonitorJSONQueryCPUsEqual(cpudata + i,
                                                              expect + i)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "vcpu entry %zu does not match expected data", i);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    qemuMonitorQueryCpusFree(cpudata, ncpudata);
    return ret;
}


static int
testQemuMonitorJSONqemuMonitorJSONQueryCPUsFast(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    struct qemuMonitorQueryCpusEntry expect_fast[] = {
            {0, 17629, (char *) "/machine/unattached/device[0]", false},
            {1, 17630, (char *) "/machine/unattached/device[1]", false},
    };
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-cpus-fast",
                               "{"
                               "    \"return\": ["
                               "        {"
                               "            \"cpu-index\": 0,"
                               "            \"qom-path\": \"/machine/unattached/device[0]\","
                               "            \"thread-id\": 17629"
                               "        },"
                               "        {"
                               "            \"cpu-index\": 1,"
                               "            \"qom-path\": \"/machine/unattached/device[1]\","
                               "            \"thread-id\": 17630"
                               "        }"
                               "    ],"
                               "    \"id\": \"libvirt-8\""
                               "}") < 0)
        return -1;

    /* query-cpus-fast */
    if (testQEMUMonitorJSONqemuMonitorJSONQueryCPUsHelper(test, expect_fast, 2))
        return -1;

    return 0;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetBalloonInfo(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    unsigned long long currmem;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-balloon",
                               "{"
                               "    \"return\": {"
                               "        \"actual\": 18446744073709551615"
                               "    },"
                               "    \"id\": \"libvirt-9\""
                               "}") < 0)
        return -1;

    if (qemuMonitorJSONGetBalloonInfo(qemuMonitorTestGetMonitor(test), &currmem) < 0)
        return -1;

    if (currmem != (18446744073709551615ULL/1024)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected currmem value: %llu", currmem);
        return -1;
    }

    return 0;
}

static void
testQemuMonitorJSONGetBlockInfoPrint(const struct qemuDomainDiskInfo *d)
{
    VIR_TEST_VERBOSE("removable: %d, tray: %d, tray_open: %d, empty: %d, "
                     "io_status: %d, nodename: '%s'",
                     d->removable, d->tray, d->tray_open, d->empty,
                     d->io_status, NULLSTR(d->nodename));
}


static int
testHashEqualQemuDomainDiskInfo(const void *value1, const void *value2)
{
    const struct qemuDomainDiskInfo *info1 = value1, *info2 = value2;
    int ret;

    if ((ret = memcmp(info1, info2, sizeof(*info1))) != 0) {
        testQemuMonitorJSONGetBlockInfoPrint(info1);
        testQemuMonitorJSONGetBlockInfoPrint(info2);
    }

    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetBlockInfo(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    g_autoptr(GHashTable) blockDevices = virHashNew(g_free);
    g_autoptr(GHashTable) expectedBlockDevices = virHashNew(g_free);
    struct qemuDomainDiskInfo *info;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    info = g_new0(struct qemuDomainDiskInfo, 1);

    if (virHashAddEntry(expectedBlockDevices, "virtio-disk0", info) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unable to create expectedBlockDevices hash table");
        return -1;
    }

    info = g_new0(struct qemuDomainDiskInfo, 1);

    if (virHashAddEntry(expectedBlockDevices, "virtio-disk1", info) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unable to create expectedBlockDevices hash table");
        return -1;
    }

    info = g_new0(struct qemuDomainDiskInfo, 1);

    info->removable = true;
    info->tray = true;

    if (virHashAddEntry(expectedBlockDevices, "ide0-1-0", info) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unable to create expectedBlockDevices hash table");
        return -1;
    }

    info = g_new0(struct qemuDomainDiskInfo, 1);

    info->removable = true;
    info->tray = true;
    info->empty = true;

    if (virHashAddEntry(expectedBlockDevices, "ide0-1-1", info) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unable to create expectedBlockDevices hash table");
        return -1;
    }

    if (qemuMonitorTestAddItem(test, "query-block", queryBlockReply) < 0)
        return -1;

    if (qemuMonitorJSONGetBlockInfo(qemuMonitorTestGetMonitor(test), blockDevices) < 0)
        return -1;

    if (!virHashEqual(blockDevices, expectedBlockDevices, testHashEqualQemuDomainDiskInfo)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Hashtable is different to the expected one");
        return -1;
    }

    return 0;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetAllBlockStatsInfo(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    g_autoptr(GHashTable) blockstats = virHashNew(g_free);
    qemuBlockStats *stats;
    g_autoptr(qemuMonitorTest) test = NULL;

    const char *reply =
        "{"
        "    \"return\": ["
        "        {"
        "            \"device\": \"drive-virtio-disk0\","
        "            \"parent\": {"
        "                \"stats\": {"
        "                    \"flush_total_time_ns\": 0,"
        "                    \"wr_highest_offset\": 5256018944,"
        "                    \"wr_total_time_ns\": 0,"
        "                    \"wr_bytes\": 0,"
        "                    \"rd_total_time_ns\": 0,"
        "                    \"flush_operations\": 0,"
        "                    \"wr_operations\": 0,"
        "                    \"rd_bytes\": 0,"
        "                    \"rd_operations\": 0"
        "                }"
        "            },"
        "            \"stats\": {"
        "                \"flush_total_time_ns\": 0,"
        "                \"wr_highest_offset\": 10406001664,"
        "                \"wr_total_time_ns\": 530699221,"
        "                \"wr_bytes\": 2845696,"
        "                \"rd_total_time_ns\": 640616474,"
        "                \"flush_operations\": 0,"
        "                \"wr_operations\": 174,"
        "                \"rd_bytes\": 28505088,"
        "                \"rd_operations\": 1279"
        "            }"
        "        },"
        "        {"
        "            \"device\": \"drive-virtio-disk1\","
        "            \"parent\": {"
        "                \"stats\": {"
        "                    \"flush_total_time_ns\": 0,"
        "                    \"wr_highest_offset\": 0,"
        "                    \"wr_total_time_ns\": 0,"
        "                    \"wr_bytes\": 0,"
        "                    \"rd_total_time_ns\": 0,"
        "                    \"flush_operations\": 0,"
        "                    \"wr_operations\": 0,"
        "                    \"rd_bytes\": 0,"
        "                    \"rd_operations\": 0"
        "                }"
        "            },"
        "            \"stats\": {"
        "                \"flush_total_time_ns\": 0,"
        "                \"wr_highest_offset\": 0,"
        "                \"wr_total_time_ns\": 0,"
        "                \"wr_bytes\": 0,"
        "                \"rd_total_time_ns\": 8232156,"
        "                \"flush_operations\": 0,"
        "                \"wr_operations\": 0,"
        "                \"rd_bytes\": 348160,"
        "                \"rd_operations\": 85"
        "            }"
        "        },"
        "        {"
        "            \"device\": \"drive-ide0-1-0\","
        "            \"parent\": {"
        "                \"stats\": {"
        "                    \"flush_total_time_ns\": 0,"
        "                    \"wr_total_time_ns\": 0,"
        "                    \"wr_bytes\": 0,"
        "                    \"rd_total_time_ns\": 0,"
        "                    \"flush_operations\": 0,"
        "                    \"wr_operations\": 0,"
        "                    \"rd_bytes\": 0,"
        "                    \"rd_operations\": 0"
        "                }"
        "            },"
        "            \"stats\": {"
        "                \"flush_total_time_ns\": 0,"
        "                \"wr_highest_offset\": 0,"
        "                \"wr_total_time_ns\": 0,"
        "                \"wr_bytes\": 0,"
        "                \"rd_total_time_ns\": 1004952,"
        "                \"flush_operations\": 0,"
        "                \"wr_operations\": 0,"
        "                \"rd_bytes\": 49250,"
        "                \"rd_operations\": 16"
        "            }"
        "        }"
        "    ],"
        "    \"id\": \"libvirt-11\""
        "}";

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-blockstats", reply) < 0)
        return -1;
    if (qemuMonitorTestAddItem(test, "query-blockstats", reply) < 0)
        return -1;

#define CHECK0FULL(var, value, varformat, valformat) \
    if (stats->var != value) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       "Invalid " #var " value: " varformat \
                       ", expected " valformat, \
                       stats->var, value); \
        return -1; \
    }

#define CHECK0(var, value) CHECK0FULL(var, value, "%lld", "%d")

#define CHECK(NAME, RD_REQ, RD_BYTES, RD_TOTAL_TIMES, WR_REQ, WR_BYTES, \
              WR_TOTAL_TIMES, FLUSH_REQ, FLUSH_TOTAL_TIMES, \
              WR_HIGHEST_OFFSET, WR_HIGHEST_OFFSET_VALID) \
    if (!(stats = virHashLookup(blockstats, NAME))) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       "block stats for device '%s' is missing", NAME); \
        return -1; \
    } \
    CHECK0(rd_req, RD_REQ) \
    CHECK0(rd_bytes, RD_BYTES) \
    CHECK0(rd_total_times, RD_TOTAL_TIMES) \
    CHECK0(wr_req, WR_REQ) \
    CHECK0(wr_bytes, WR_BYTES) \
    CHECK0(wr_total_times, WR_TOTAL_TIMES) \
    CHECK0(flush_req, FLUSH_REQ) \
    CHECK0(flush_total_times, FLUSH_TOTAL_TIMES) \
    CHECK0FULL(wr_highest_offset, WR_HIGHEST_OFFSET, "%llu", "%llu") \
    CHECK0FULL(wr_highest_offset_valid, WR_HIGHEST_OFFSET_VALID, "%d", "%d")

    if (qemuMonitorJSONGetAllBlockStatsInfo(qemuMonitorTestGetMonitor(test),
                                            blockstats) < 0)
        return -1;

    if (!blockstats) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "qemuMonitorJSONGetAllBlockStatsInfo didn't return stats");
        return -1;
    }

    CHECK("virtio-disk0", 1279, 28505088, 640616474, 174, 2845696, 530699221, 0, 0, 5256018944ULL, true)
    CHECK("virtio-disk1", 85, 348160, 8232156, 0, 0, 0, 0, 0, 0ULL, true)
    CHECK("ide0-1-0", 16, 49250, 1004952, 0, 0, 0, 0, 0, 0ULL, false)

    return 0;

#undef CHECK
#undef CHECK0
#undef CHECK0FULL

}


static int
testQemuMonitorJSONqemuMonitorJSONGetMigrationStats(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    qemuMonitorMigrationStats stats;
    qemuMonitorMigrationStats expectedStats = { 0 };
    g_autofree char *error = NULL;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    expectedStats.status = QEMU_MONITOR_MIGRATION_STATUS_ACTIVE;
    expectedStats.total_time = 47;
    expectedStats.ram_total = 1611038720;
    expectedStats.ram_remaining = 1605013504;
    expectedStats.ram_transferred = 3625548;

    if (qemuMonitorTestAddItem(test, "query-migrate",
                               "{"
                               "    \"return\": {"
                               "        \"status\": \"active\","
                               "        \"total-time\": 47,"
                               "        \"ram\": {"
                               "            \"total\": 1611038720,"
                               "            \"remaining\": 1605013504,"
                               "            \"transferred\": 3625548"
                               "        }"
                               "    },"
                               "    \"id\": \"libvirt-13\""
                               "}") < 0 ||
        qemuMonitorTestAddItem(test, "query-migrate",
                               "{"
                               "    \"return\": {"
                               "        \"status\": \"failed\","
                               "        \"error-desc\": \"It's broken\""
                               "    },"
                               "    \"id\": \"libvirt-14\""
                               "}") < 0)
        return -1;

    if (qemuMonitorJSONGetMigrationStats(qemuMonitorTestGetMonitor(test),
                                         &stats, &error) < 0)
        return -1;

    if (memcmp(&stats, &expectedStats, sizeof(stats)) != 0 || error) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Invalid migration statistics");
        return -1;
    }

    memset(&stats, 0, sizeof(stats));
    if (qemuMonitorJSONGetMigrationStats(qemuMonitorTestGetMonitor(test),
                                         &stats, &error) < 0)
        return -1;

    if (stats.status != QEMU_MONITOR_MIGRATION_STATUS_ERROR ||
        STRNEQ_NULLABLE(error, "It's broken")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Invalid failed migration status");
        return -1;
    }

    return 0;
}

static int
testHashEqualChardevInfo(const void *value1, const void *value2)
{
    const qemuMonitorChardevInfo *info1 = value1;
    const qemuMonitorChardevInfo *info2 = value2;

    if (info1->state != info2->state)
        goto error;

    if (STRNEQ_NULLABLE(info1->ptyPath, info2->ptyPath))
        goto error;

    return 0;

 error:
    fprintf(stderr, "\n"
            "info1->state: %d info2->state: %d\n"
            "info1->ptyPath: %s info2->ptyPath: %s\n",
            info1->state, info2->state, info1->ptyPath, info2->ptyPath);
    return -1;
}


static int
testQemuMonitorJSONqemuMonitorJSONGetChardevInfo(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    g_autoptr(GHashTable) info = virHashNew(qemuMonitorChardevInfoFree);
    g_autoptr(GHashTable) expectedInfo = virHashNew(NULL);
    qemuMonitorChardevInfo info0 = { NULL, VIR_DOMAIN_CHR_DEVICE_STATE_DEFAULT };
    qemuMonitorChardevInfo info1 = { (char *) "/dev/pts/21", VIR_DOMAIN_CHR_DEVICE_STATE_CONNECTED };
    qemuMonitorChardevInfo info2 = { (char *) "/dev/pts/20", VIR_DOMAIN_CHR_DEVICE_STATE_DEFAULT };
    qemuMonitorChardevInfo info3 = { NULL, VIR_DOMAIN_CHR_DEVICE_STATE_DISCONNECTED };
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (virHashAddEntry(expectedInfo, "charserial1", &info1) < 0 ||
        virHashAddEntry(expectedInfo, "charserial0", &info2) < 0 ||
        virHashAddEntry(expectedInfo, "charmonitor", &info0) < 0 ||
        virHashAddEntry(expectedInfo, "charserial2", &info3) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unable to create expectedInfo hash table");
        return -1;
    }

    if (qemuMonitorTestAddItem(test, "query-chardev",
                               "{"
                               "    \"return\": ["
                               "        {"
                               "            \"filename\": \"pty:/dev/pts/21\","
                               "            \"label\": \"charserial1\","
                               "            \"frontend-open\": true"
                               "        },"
                               "        {"
                               "            \"filename\": \"pty:/dev/pts/20\","
                               "            \"label\": \"charserial0\""
                               "        },"
                               "        {"
                               "            \"filename\": \"unix:/var/lib/libvirt/qemu/gentoo.monitor,server\","
                               "            \"label\": \"charmonitor\""
                               "        },"
                               "        {"
                               "            \"filename\": \"unix:/path/to/socket,server\","
                               "            \"label\": \"charserial2\","
                               "            \"frontend-open\": false"
                               "        }"
                               "    ],"
                               "    \"id\": \"libvirt-15\""
                               "}") < 0)
        return -1;

    if (qemuMonitorJSONGetChardevInfo(qemuMonitorTestGetMonitor(test),
                                      info) < 0)
        return -1;

    if (!virHashEqual(info, expectedInfo, testHashEqualChardevInfo)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Hashtable is different to the expected one");
        return -1;
    }

    return 0;
}


static int
testValidateGetBlockIoThrottle(const virDomainBlockIoTuneInfo *info,
                               const virDomainBlockIoTuneInfo *expectedInfo)
{
#define VALIDATE_IOTUNE(field) \
    if (info->field != expectedInfo->field) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       "info->%s=%llu != expected=%llu", \
                       #field, info->field, expectedInfo->field); \
        return -1; \
    } \
    if (info->field##_max != expectedInfo->field##_max) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       "info->%s_max=%llu != expected=%llu", \
                       #field, info->field##_max, expectedInfo->field##_max); \
        return -1; \
    } \
    if (info->field##_max_length != expectedInfo->field##_max_length) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       "info->%s_max_length=%llu != expected=%llu", \
                       #field, info->field##_max_length, \
                       expectedInfo->field##_max_length); \
        return -1; \
    }
    VALIDATE_IOTUNE(total_bytes_sec);
    VALIDATE_IOTUNE(read_bytes_sec);
    VALIDATE_IOTUNE(write_bytes_sec);
    VALIDATE_IOTUNE(total_iops_sec);
    VALIDATE_IOTUNE(read_iops_sec);
    VALIDATE_IOTUNE(write_iops_sec);
    if (info->size_iops_sec != expectedInfo->size_iops_sec) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "info->size_iops_sec=%llu != expected=%llu",
                       info->size_iops_sec, expectedInfo->size_iops_sec);
        return -1;
    }
    if (STRNEQ(info->group_name, expectedInfo->group_name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "info->group_name=%s != expected=%s",
                       info->group_name, expectedInfo->group_name);
        return -1;
    }
#undef VALIDATE_IOTUNE

    return 0;
}


static int
testQemuMonitorJSONqemuMonitorJSONSetBlockIoThrottle(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    int ret = -1;
    virDomainBlockIoTuneInfo info, expectedInfo;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    expectedInfo = (virDomainBlockIoTuneInfo) {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, NULL, 15, 16, 17, 18, 19, 20};
    expectedInfo.group_name = g_strdup("group14");

    if (qemuMonitorTestAddItem(test, "query-block", queryBlockReply) < 0)
        return -1;

    if (qemuMonitorTestAddItemVerbatim(test,
                                       "{\"execute\":\"block_set_io_throttle\","
                                       " \"arguments\":{\"id\": \"drive-virtio-disk1\","
                                       "                \"bps\": 1,"
                                       "                \"bps_rd\": 2,"
                                       "                \"bps_wr\": 3,"
                                       "                \"iops\": 4,"
                                       "                \"iops_rd\": 5,"
                                       "                \"iops_wr\": 6,"
                                       "                \"bps_max\": 7,"
                                       "                \"bps_rd_max\": 8,"
                                       "                \"bps_wr_max\": 9,"
                                       "                \"iops_max\": 10,"
                                       "                \"iops_rd_max\": 11,"
                                       "                \"iops_wr_max\": 12,"
                                       "                \"iops_size\": 13,"
                                       "                \"group\": \"group14\","
                                       "                \"bps_max_length\": 15,"
                                       "                \"bps_rd_max_length\": 16,"
                                       "                \"bps_wr_max_length\": 17,"
                                       "                \"iops_max_length\": 18,"
                                       "                \"iops_rd_max_length\": 19,"
                                       "                \"iops_wr_max_length\": 20},"
                                       " \"id\":\"libvirt-2\"}",
                                       NULL,
                                       "{ \"return\" : {}}") < 0)
        return -1;

    if (qemuMonitorJSONGetBlockIoThrottle(qemuMonitorTestGetMonitor(test),
                                          "drive-virtio-disk0", &info) < 0)
        goto cleanup;

    if (testValidateGetBlockIoThrottle(&info, &expectedInfo) < 0)
        goto cleanup;

    if (qemuMonitorJSONSetBlockIoThrottle(qemuMonitorTestGetMonitor(test),
                                          "drive-virtio-disk1", &info) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(info.group_name);
    VIR_FREE(expectedInfo.group_name);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetTargetArch(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    g_autofree char *arch = NULL;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-target",
                               "{"
                               "    \"return\": {"
                               "        \"arch\": \"x86_64\""
                               "    },"
                               "    \"id\": \"libvirt-21\""
                               "}") < 0)
        return -1;

    if (!(arch = qemuMonitorJSONGetTargetArch(qemuMonitorTestGetMonitor(test))))
        return -1;

    if (STRNEQ(arch, "x86_64")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected architecture %s, expecting x86_64",
                       arch);
        return -1;
    }

    return 0;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetMigrationCapabilities(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    size_t cap;
    g_auto(GStrv) caps = NULL;
    g_autoptr(virBitmap) bitmap = NULL;
    g_autoptr(virJSONValue) json = NULL;
    const char *reply =
        "{"
        "    \"return\": ["
        "        {"
        "            \"state\": false,"
        "            \"capability\": \"xbzrle\""
        "        },"
        "        {"
        "            \"state\": true,"
        "            \"capability\": \"events\""
        "        }"
        "    ],"
        "    \"id\": \"libvirt-22\""
        "}";
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-migrate-capabilities", reply) < 0 ||
        qemuMonitorTestAddItem(test, "migrate-set-capabilities",
                               "{\"return\":{}}") < 0)
        return -1;

    if (qemuMonitorGetMigrationCapabilities(qemuMonitorTestGetMonitor(test),
                                            &caps) < 0)
        return -1;

    for (cap = 0; cap < QEMU_MIGRATION_CAP_LAST; cap++) {
        const char *capStr = qemuMigrationCapabilityTypeToString(cap);
        bool present = g_strv_contains((const char **) caps, capStr);

        switch (cap) {
        case QEMU_MIGRATION_CAP_XBZRLE:
        case QEMU_MIGRATION_CAP_EVENTS:
            if (!present) {
                VIR_TEST_VERBOSE("Expected capability %s is missing", capStr);
                return -1;
            }
            break;

        default:
            if (present) {
                VIR_TEST_VERBOSE("Unexpected capability %s found", capStr);
                return -1;
            }
        }
    }

    bitmap = virBitmapNew(QEMU_MIGRATION_CAP_LAST);
    ignore_value(virBitmapSetBit(bitmap, QEMU_MIGRATION_CAP_XBZRLE));
    if (!(json = qemuMigrationCapsToJSON(bitmap, bitmap)))
        return -1;

    return qemuMonitorJSONSetMigrationCapabilities(qemuMonitorTestGetMonitor(test),
                                                   &json);
}

static int
testQemuMonitorJSONqemuMonitorJSONSendKey(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    unsigned int keycodes[] = {43, 26, 46, 32};
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "send-key",
                               "{\"return\": {}, \"id\": \"libvirt-16\"}") < 0)
        return -1;

    if (qemuMonitorJSONSendKey(qemuMonitorTestGetMonitor(test),
                               0, keycodes, G_N_ELEMENTS(keycodes)) < 0)
        return -1;

    return 0;
}

static int
testQemuMonitorJSONqemuMonitorJSONSendKeyHoldtime(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    unsigned int keycodes[] = {43, 26, 46, 32};
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItemVerbatim(test,
                                       "{\"execute\":\"send-key\","
                                       " \"arguments\":{\"keys\":[{\"type\":\"number\",\"data\":43},"
                                       "                          {\"type\":\"number\",\"data\":26},"
                                       "                          {\"type\":\"number\",\"data\":46},"
                                       "                          {\"type\":\"number\",\"data\":32}],"
                                       "                \"hold-time\":31337},"
                                       " \"id\":\"libvirt-1\"}",
                                       NULL,
                                       "{ \"return\" : {}}") < 0)
        return -1;

    if (qemuMonitorJSONSendKey(qemuMonitorTestGetMonitor(test),
                               31337, keycodes,
                               G_N_ELEMENTS(keycodes)) < 0)
        return -1;

    return 0;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetDumpGuestMemoryCapability(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    int cap;
    const char *reply =
        "{"
        "    \"return\": {"
        "        \"formats\": ["
        "            \"elf\","
        "            \"kdump-zlib\","
        "            \"kdump-lzo\","
        "            \"kdump-snappy\""
        "        ]"
        "    },"
        "    \"id\": \"libvirt-9\""
        "}";
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-dump-guest-memory-capability",
                               reply) < 0)
        return -1;

    cap = qemuMonitorJSONGetDumpGuestMemoryCapability(
                                    qemuMonitorTestGetMonitor(test), "elf");

    if (cap != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected capability: %d, expecting 1",
                       cap);
        return -1;
    }

    return 0;
}

struct testCPUData {
    const char *name;
    virDomainXMLOption *xmlopt;
    GHashTable *schema;
};


static int
testQemuMonitorJSONGetCPUData(const void *opaque)
{
    const struct testCPUData *data = opaque;
    g_autoptr(virCPUData) cpuData = NULL;
    g_autofree char *jsonFile = NULL;
    g_autofree char *dataFile = NULL;
    g_autofree char *jsonStr = NULL;
    g_autofree char *actual = NULL;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(data->xmlopt, data->schema)))
        return -1;

    jsonFile = g_strdup_printf("%s/qemumonitorjsondata/qemumonitorjson-getcpu-%s.json",
                               abs_srcdir, data->name);
    dataFile = g_strdup_printf("%s/qemumonitorjsondata/qemumonitorjson-getcpu-%s.data",
                               abs_srcdir, data->name);

    if (virTestLoadFile(jsonFile, &jsonStr) < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "qom-list",
                               "{"
                               "    \"return\": ["
                               "        {"
                               "            \"name\": \"filtered-features\","
                               "            \"type\": \"X86CPUFeatureWordInfo\""
                               "        },"
                               "        {"
                               "            \"name\": \"feature-words\","
                               "            \"type\": \"X86CPUFeatureWordInfo\""
                               "        }"
                               "    ],"
                               "    \"id\": \"libvirt-19\""
                               "}") < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "qom-get", jsonStr) < 0)
        return -1;

    if (qemuMonitorJSONGetGuestCPUx86(qemuMonitorTestGetMonitor(test),
                                      "dummy",
                                      &cpuData, NULL) < 0)
        return -1;

    if (!(actual = virCPUDataFormat(cpuData)))
        return -1;

    if (virTestCompareToFile(actual, dataFile) < 0)
        return -1;

    return 0;
}

static int
testQemuMonitorJSONGetNonExistingCPUData(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    g_autoptr(virCPUData) cpuData = NULL;
    int rv;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "qom-list",
                               "{"
                               "    \"id\": \"libvirt-7\","
                               "    \"error\": {"
                               "        \"class\": \"CommandNotFound\","
                               "        \"desc\": \"The command qom-list has not been found\""
                               "    }"
                               "}") < 0)
        return -1;

    rv = qemuMonitorJSONGetGuestCPUx86(qemuMonitorTestGetMonitor(test),
                                       "dummy",
                                       &cpuData, NULL);
    if (rv != -2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected return value %d, expecting -2", rv);
        return -1;
    }

    if (cpuData) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected allocation of data = %p, expecting NULL",
                       cpuData);
        return -1;
    }

    return 0;
}

static int
testQemuMonitorJSONGetIOThreads(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    qemuMonitorIOThreadInfo **info;
    int ninfo = 0;
    int ret = -1;
    size_t i;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-iothreads",
                               "{ "
                               "  \"return\": [ "
                               "   { "
                               "     \"id\": \"iothread1\", "
                               "     \"thread-id\": 30992 "
                               "   }, "
                               "   { "
                               "     \"id\": \"iothread2\", "
                               "     \"thread-id\": 30993 "
                               "   } "
                               "  ]"
                               "}") < 0)
        goto cleanup;

    if (qemuMonitorGetIOThreads(qemuMonitorTestGetMonitor(test),
                                &info, &ninfo) < 0)
        goto cleanup;

    if (ninfo != 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "ninfo %d is not 2", ninfo);
        goto cleanup;
    }

#define CHECK(i, wantiothread_id, wantthread_id) \
    do { \
        if (info[i]->iothread_id != (wantiothread_id)) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "iothread_id %u is not %u", \
                           info[i]->iothread_id, (wantiothread_id)); \
            goto cleanup; \
        } \
        if (info[i]->thread_id != (wantthread_id)) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "thread_id %d is not %d", \
                           info[i]->thread_id, (wantthread_id)); \
            goto cleanup; \
        } \
    } while (0)

    CHECK(0, 1, 30992);
    CHECK(1, 2, 30993);

#undef CHECK

    ret = 0;

 cleanup:
    for (i = 0; i < ninfo; i++)
        VIR_FREE(info[i]);
    VIR_FREE(info);

    return ret;
}

struct testCPUInfoData {
    const char *name;
    size_t maxvcpus;
    virDomainXMLOption *xmlopt;
    GHashTable *schema;
};


static char *
testQemuMonitorCPUInfoFormat(qemuMonitorCPUInfo *vcpus,
                             size_t nvcpus)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    qemuMonitorCPUInfo *vcpu;
    size_t i;

    for (i = 0; i < nvcpus; i++) {
        vcpu = vcpus + i;

        virBufferAsprintf(&buf, "[vcpu libvirt-id='%zu']\n", i);
        virBufferAdjustIndent(&buf, 4);

        virBufferAsprintf(&buf, "online=%s\n", vcpu->online ? "yes" : "no");
        virBufferAsprintf(&buf, "hotpluggable=%s\n", vcpu->hotpluggable ? "yes" : "no");

        if (vcpu->tid)
            virBufferAsprintf(&buf, "thread-id='%llu'\n",
                              (unsigned long long) vcpu->tid);

        if (vcpu->id != 0)
            virBufferAsprintf(&buf, "enable-id='%d'\n", vcpu->id);

        if (vcpu->qemu_id != -1)
            virBufferAsprintf(&buf, "query-cpus-id='%d'\n", vcpu->qemu_id);

        if (vcpu->type)
            virBufferAsprintf(&buf, "type='%s'\n", vcpu->type);

        if (vcpu->alias)
            virBufferAsprintf(&buf, "alias='%s'\n", vcpu->alias);
        if (vcpu->qom_path)
            virBufferAsprintf(&buf, "qom_path='%s'\n", vcpu->qom_path);

        if (vcpu->socket_id != -1 || vcpu->core_id != -1 ||
            vcpu->thread_id != -1 || vcpu->vcpus != 0) {
            virBufferAddLit(&buf, "topology:");
            if (vcpu->socket_id != -1)
                virBufferAsprintf(&buf, " socket='%d'", vcpu->socket_id);
            if (vcpu->die_id != -1)
                virBufferAsprintf(&buf, " die='%d'", vcpu->die_id);
            if (vcpu->core_id != -1)
                virBufferAsprintf(&buf, " core='%d'", vcpu->core_id);
            if (vcpu->thread_id != -1)
                virBufferAsprintf(&buf, " thread='%d'", vcpu->thread_id);
            if (vcpu->node_id != -1)
                virBufferAsprintf(&buf, " node='%d'", vcpu->node_id);
            if (vcpu->vcpus != 0)
                virBufferAsprintf(&buf, " vcpus='%u'", vcpu->vcpus);
            virBufferAddLit(&buf, "\n");
        }

        if (vcpu->halted)
            virBufferAddLit(&buf, "halted\n");

        virBufferAdjustIndent(&buf, -4);
    }

    return virBufferContentAndReset(&buf);
}


static int
testQemuMonitorCPUInfo(const void *opaque)
{
    const struct testCPUInfoData *data = opaque;
    virDomainObj *vm = NULL;
    g_autofree char *queryCpusFile = NULL;
    g_autofree char *queryHotpluggableFile = NULL;
    g_autofree char *dataFile = NULL;
    g_autofree char *queryCpusStr = NULL;
    g_autofree char *queryHotpluggableStr = NULL;
    g_autofree char *actual = NULL;
    qemuMonitorCPUInfo *vcpus = NULL;
    int rc;
    int ret = -1;
    g_autoptr(qemuMonitorTest) test = NULL;

    if (!(test = qemuMonitorTestNewSchema(data->xmlopt, data->schema)))
        return -1;

    queryCpusFile = g_strdup_printf("%s/qemumonitorjsondata/qemumonitorjson-cpuinfo-%s-cpus.json",
                                    abs_srcdir, data->name);
    queryHotpluggableFile = g_strdup_printf("%s/qemumonitorjsondata/qemumonitorjson-cpuinfo-%s-hotplug.json",
                                            abs_srcdir, data->name);
    dataFile = g_strdup_printf("%s/qemumonitorjsondata/qemumonitorjson-cpuinfo-%s.data",
                               abs_srcdir, data->name);

    if (virTestLoadFile(queryCpusFile, &queryCpusStr) < 0)
        goto cleanup;

    if (virTestLoadFile(queryHotpluggableFile, &queryHotpluggableStr) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "query-hotpluggable-cpus",
                               queryHotpluggableStr) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "query-cpus-fast", queryCpusStr) < 0)
        goto cleanup;

    vm = qemuMonitorTestGetDomainObj(test);
    if (!vm)
        goto cleanup;

    rc = qemuMonitorGetCPUInfo(qemuMonitorTestGetMonitor(test),
                               &vcpus, data->maxvcpus, true);

    if (rc < 0)
        goto cleanup;

    actual = testQemuMonitorCPUInfoFormat(vcpus, data->maxvcpus);

    if (virTestCompareToFile(actual, dataFile) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    qemuMonitorCPUInfoFree(vcpus, data->maxvcpus);
    return ret;
}


struct testQAPISchemaData {
    GHashTable *schema;
    const char *name;
    const char *query;
    const char *json;
    bool success;
    int rc;
    bool replyobj;
};


static int
testQAPISchemaQuery(const void *opaque)
{
    const struct testQAPISchemaData *data = opaque;
    virJSONValue *replyobj = NULL;
    int rc;

    rc = virQEMUQAPISchemaPathGet(data->query, data->schema, &replyobj);

    if (data->rc != rc || data->replyobj != !!replyobj) {
        VIR_TEST_VERBOSE("\n success: expected '%d' got '%d', replyobj: expected '%d' got '%d'",
                         data->rc, rc, data->replyobj, !!replyobj);
        return -1;
    }

    return 0;
}


static int
testQAPISchemaValidate(const void *opaque)
{
    const struct testQAPISchemaData *data = opaque;
    g_auto(virBuffer) debug = VIR_BUFFER_INITIALIZER;
    virJSONValue *schemaroot;
    g_autoptr(virJSONValue) json = NULL;
    int ret = -1;

    if (virQEMUQAPISchemaPathGet(data->query, data->schema, &schemaroot) < 0)
        return -1;

    if (!(json = virJSONValueFromString(data->json)))
        return -1;

    if ((testQEMUSchemaValidate(json, schemaroot, data->schema, false,
                                &debug) == 0) != data->success) {
        if (!data->success)
            VIR_TEST_VERBOSE("\nschema validation should have failed");
    } else {
        ret = 0;
    }

    if (virTestGetDebug() >= 3 ||
        (ret < 0 && virTestGetVerbose())) {
        char *debugstr = virBufferContentAndReset(&debug);
        fprintf(stderr, "\n%s\n", debugstr);
        VIR_FREE(debugstr);
    }

    return ret;
}


/**
 * testQAPISchemaObjectDeviceAdd:
 *
 * Purpose of this test is to add a last-resort notification that 'object-add'
 * and 'device_add' are not covered by the QMP schema by surprise. Ideally QEMU
 * developers will notify us before they switch so we have time to adapt our
 * generators first. This didn't work out when netdev-add was converted.
 *
 * We validate that the QMP schema describes only the expected types and nothing
 * else assuming that no new field will be added until final conversion.
 */
static int
testQAPISchemaObjectDeviceAdd(const void *opaque)
{
    GHashTable *schema = (GHashTable *) opaque;
    virJSONValue *entry;

    if (virQEMUQAPISchemaPathGet("device_add/arg-type", schema, &entry) < 0) {
        fprintf(stderr, "schema for 'device_add' not found\n");
        return -1;
    }

    if (testQEMUSchemaEntryMatchTemplate(entry,
                                         "str:driver",
                                         "str:bus",
                                         "str:id",
                                         NULL) < 0) {
        VIR_TEST_VERBOSE("device_add has unexpected members in schema");
        return -1;
    }

    return 0;
}


static void
testQueryJobsPrintJob(virBuffer *buf,
                      qemuMonitorJobInfo *job)
{
    virBufferAddLit(buf, "[job]\n");
    virBufferAsprintf(buf, "id=%s\n", NULLSTR(job->id));
    virBufferAsprintf(buf, "type=%s\n", NULLSTR(qemuMonitorJobTypeToString(job->type)));
    virBufferAsprintf(buf, "status=%s\n", NULLSTR(qemuMonitorJobStatusTypeToString(job->status)));
    virBufferAsprintf(buf, "error=%s\n", NULLSTR(job->error));
    virBufferAddLit(buf, "\n");
}


struct testQueryJobsData {
    const char *name;
    virDomainXMLOption *xmlopt;
};


static int
testQueryJobs(const void *opaque)
{
    const struct testQueryJobsData *data = opaque;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewSimple(data->xmlopt);
    g_autofree char *filenameJSON = NULL;
    g_autofree char *fileJSON = NULL;
    g_autofree char *filenameResult = NULL;
    g_autofree char *actual = NULL;
    qemuMonitorJobInfo **jobs = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t njobs = 0;
    size_t i;
    int ret = -1;

    if (!test)
        return -1;

    filenameJSON = g_strdup_printf(abs_srcdir "/qemumonitorjsondata/query-jobs-%s.json",
                                   data->name);
    filenameResult = g_strdup_printf(abs_srcdir "/qemumonitorjsondata/query-jobs-%s.result",
                                     data->name);

    if (virTestLoadFile(filenameJSON, &fileJSON) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "query-jobs", fileJSON) < 0)
        goto cleanup;

    if (qemuMonitorJSONGetJobInfo(qemuMonitorTestGetMonitor(test),
                                  &jobs, &njobs) < 0)
        goto cleanup;

    for (i = 0; i < njobs; i++)
        testQueryJobsPrintJob(&buf, jobs[i]);

    virBufferTrim(&buf, "\n");

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToFile(actual, filenameResult) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    for (i = 0; i < njobs; i++)
        qemuMonitorJobInfoFree(jobs[i]);
    VIR_FREE(jobs);
    return ret;
}


static int
testQemuMonitorJSONTransaction(const void *opaque)
{
    const testGenericData *data = opaque;
    g_autoptr(qemuMonitorTest) test = NULL;
    g_autoptr(virJSONValue) actions = NULL;
    g_autoptr(virJSONValue) mergebitmaps = NULL;

    if (!(test = qemuMonitorTestNewSchema(data->xmlopt, data->schema)))
        return -1;

    actions = virJSONValueNewArray();
    mergebitmaps = virJSONValueNewArray();

    if (qemuMonitorTransactionBitmapMergeSourceAddBitmap(mergebitmaps, "node1", "bitmap1") < 0 ||
        qemuMonitorTransactionBitmapMergeSourceAddBitmap(mergebitmaps, "node2", "bitmap2") < 0)
        return -1;

    if (qemuMonitorTransactionBitmapAdd(actions, "node1", "bitmap1", true, true, 1234) < 0 ||
        qemuMonitorTransactionBitmapRemove(actions, "node2", "bitmap2") < 0 ||
        qemuMonitorTransactionBitmapEnable(actions, "node3", "bitmap3") < 0 ||
        qemuMonitorTransactionBitmapDisable(actions, "node4", "bitmap4") < 0 ||
        qemuMonitorTransactionBitmapMerge(actions, "node5", "bitmap5", &mergebitmaps) < 0 ||
        qemuMonitorTransactionSnapshotBlockdev(actions, "node7", "overlay7") < 0 ||
        qemuMonitorTransactionBackup(actions, "dev8", "job8", "target8", "bitmap8",
                                     QEMU_MONITOR_TRANSACTION_BACKUP_SYNC_MODE_NONE) < 0 ||
        qemuMonitorTransactionBackup(actions, "dev9", "job9", "target9", "bitmap9",
                                     QEMU_MONITOR_TRANSACTION_BACKUP_SYNC_MODE_INCREMENTAL) < 0 ||
        qemuMonitorTransactionBackup(actions, "devA", "jobA", "targetA", "bitmapA",
                                     QEMU_MONITOR_TRANSACTION_BACKUP_SYNC_MODE_FULL) < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "transaction", "{\"return\":{}}") < 0)
        return -1;

    if (qemuMonitorJSONTransaction(qemuMonitorTestGetMonitor(test), &actions) < 0)
        return -1;

    return 0;
}


static int
testQemuMonitorJSONBlockExportAdd(const void *opaque)
{
    const testGenericData *data = opaque;
    g_autoptr(qemuMonitorTest) test = NULL;
    g_autoptr(virJSONValue) nbddata = NULL;
    const char *bitmaps[] = { "bitmap1", "bitmap2", NULL };

    if (!(test = qemuMonitorTestNewSchema(data->xmlopt, data->schema)))
        return -1;

    if (!(nbddata = qemuBlockExportGetNBDProps("nodename", "exportname", true, bitmaps)))
        return -1;

    if (qemuMonitorTestAddItem(test, "block-export-add", "{\"return\":{}}") < 0)
        return -1;

    if (qemuMonitorJSONBlockExportAdd(qemuMonitorTestGetMonitor(test), &nbddata) < 0)
        return -1;

    return 0;
}


static int
testQemuMonitorJSONBlockdevReopen(const void *opaque)
{
    const testGenericData *data = opaque;
    g_autoptr(qemuMonitorTest) test = NULL;
    g_autoptr(virStorageSource) src = virStorageSourceNew();

    if (!(test = qemuMonitorTestNewSchema(data->xmlopt, data->schema)))
        return -1;

    src->format = VIR_STORAGE_FILE_QCOW2;
    src->readonly = true;
    qemuBlockStorageSourceSetFormatNodename(src, g_strdup("test node"));
    qemuBlockStorageSourceSetStorageNodename(src, g_strdup("backing nodename"));
    src->backingStore = virStorageSourceNew();

    if (qemuMonitorTestAddItem(test, "blockdev-reopen", "{\"return\":{}}") < 0)
        return -1;

    if (qemuBlockReopenFormatMon(qemuMonitorTestGetMonitor(test), src) < 0)
        return -1;

    return 0;
}


static int
testQemuMonitorJSONqemuMonitorJSONGetCPUModelComparison(const void *opaque)
{
    const testGenericData *data = opaque;
    g_autoptr(qemuMonitorTest) test = NULL;
    g_autoptr(virCPUDef) cpu_a = virCPUDefNew();
    g_autoptr(virCPUDef) cpu_b = virCPUDefNew();
    g_autofree char *result = NULL;

    if (!(test = qemuMonitorTestNewSchema(data->xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-cpu-model-comparison",
                               "{\"return\":{\"result\":\"test\"}}") < 0)
        return -1;

    cpu_a->model = g_strdup("cpu_a");
    cpu_b->model = g_strdup("cpu_b");

    if (qemuMonitorJSONGetCPUModelComparison(qemuMonitorTestGetMonitor(test),
                                             cpu_a, cpu_b, &result) < 0)
        return -1;

    if (!result || STRNEQ(result, "test")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Compare result not set");
        return -1;
    }

    return 0;
}


static int
testQemuMonitorJSONqemuMonitorJSONGetCPUModelBaseline(const void *opaque)
{
    const testGenericData *data = opaque;
    g_autoptr(qemuMonitorTest) test = NULL;
    g_autoptr(virCPUDef) cpu_a = virCPUDefNew();
    g_autoptr(virCPUDef) cpu_b = virCPUDefNew();
    g_autoptr(qemuMonitorCPUModelInfo) baseline = NULL;

    if (!(test = qemuMonitorTestNewSchema(data->xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-cpu-model-baseline",
                               "{ "
                               "   \"return\": { "
                               "       \"model\": { "
                               "           \"name\": \"cpu_c\", "
                               "           \"props\": { "
                               "                \"feat_a\": true, "
                               "                \"feat_b\": false "
                               "            } "
                               "        } "
                               "    } "
                               "}") < 0)
        return -1;

    cpu_a->model = g_strdup("cpu_a");
    cpu_b->model = g_strdup("cpu_b");

    if (virCPUDefAddFeature(cpu_a, "feat_a", VIR_CPU_FEATURE_REQUIRE) < 0 ||
        virCPUDefAddFeature(cpu_a, "feat_b", VIR_CPU_FEATURE_REQUIRE) < 0 ||
        virCPUDefAddFeature(cpu_a, "feat_c", VIR_CPU_FEATURE_REQUIRE) < 0)
        return -1;

    if (qemuMonitorJSONGetCPUModelBaseline(qemuMonitorTestGetMonitor(test),
                                           cpu_a, cpu_b, &baseline) < 0)
        return -1;

    if (!baseline) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Baseline missing result");
        return -1;
    }
    if (!baseline->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Baseline missing model name");
        return -1;
    }
    if (baseline->nprops != 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Baseline missing properties");
        return -1;
    }
    if (STRNEQ(baseline->props[0].name, "feat_a") ||
        !baseline->props[0].value.boolean ||
        STRNEQ(baseline->props[1].name, "feat_b") ||
        baseline->props[1].value.boolean) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Baseline property error");
        return -1;
    }

    return 0;
}


static int
testQemuMonitorJSONGetSEVInfo(const void *opaque)
{
    const testGenericData *data = opaque;
    virDomainXMLOption *xmlopt = data->xmlopt;
    g_autoptr(qemuMonitorTest) test = NULL;
    unsigned int apiMajor = 0;
    unsigned int apiMinor = 0;
    unsigned int buildID = 0;
    unsigned int policy = 0;

    if (!(test = qemuMonitorTestNewSchema(xmlopt, data->schema)))
        return -1;

    if (qemuMonitorTestAddItem(test, "query-sev",
                               "{"
                               "    \"return\": {"
                               "        \"enabled\": false,"
                               "        \"api-minor\": 8,"
                               "        \"handle\": 0,"
                               "        \"state\": \"uninit\","
                               "        \"api-major\": 1,"
                               "        \"build-id\": 834,"
                               "        \"policy\": 3"
                               "    },"
                               "    \"id\": \"libvirt-15\""
                               "}") < 0)
        return -1;

    if (qemuMonitorGetSEVInfo(qemuMonitorTestGetMonitor(test),
                              &apiMajor, &apiMinor, &buildID, &policy) < 0)
        return -1;

    if (apiMajor != 1 || apiMinor != 8 || buildID != 834 || policy != 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unexpected SEV info values");
        return -1;
    }

    return 0;
}

static int
mymain(void)
{
    int ret = 0;
    virQEMUDriver driver;
    testQemuMonitorJSONSimpleFuncData simpleFunc;
    g_autoptr(GHashTable) qapischema_x86_64 = NULL;
    g_autoptr(GHashTable) qapischema_s390x = NULL;
    struct testQAPISchemaData qapiData;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

    if (!(qapischema_x86_64 = testQEMUSchemaLoadLatest("x86_64"))) {
        VIR_TEST_VERBOSE("failed to load x86_64 qapi schema");
        ret = -1;
        goto cleanup;
    }

    qapiData.schema = qapischema_x86_64;

#define DO_TEST(name) \
    do { \
        testGenericData data = { driver.xmlopt, qapiData.schema }; \
        if (virTestRun(# name, testQemuMonitorJSON ## name, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_SIMPLE(CMD, FNC, ...) \
    simpleFunc = (testQemuMonitorJSONSimpleFuncData) {.cmd = CMD, .func = FNC, \
                                       .xmlopt = driver.xmlopt, \
                                       .schema = qapiData.schema, \
                                       __VA_ARGS__ }; \
    if (virTestRun(# FNC, testQemuMonitorJSONSimpleFunc, &simpleFunc) < 0) \
        ret = -1

#define DO_TEST_GEN_FULL(name, dpr, rmvd, ...) \
    simpleFunc = (testQemuMonitorJSONSimpleFuncData) {.xmlopt = driver.xmlopt, \
                                                      .allowDeprecated = dpr, \
                                                      .allowRemoved = rmvd, \
                                                      .schema = qapiData.schema \
                                                     __VA_ARGS__ }; \
    if (virTestRun(# name, testQemuMonitorJSON ## name, &simpleFunc) < 0) \
        ret = -1

#define DO_TEST_GEN(name, ...) DO_TEST_GEN_FULL(name, false, false, __VA_ARGS__)
#define DO_TEST_GEN_DEPRECATED(name, removed, ...) \
    DO_TEST_GEN_FULL(name, true, removed, __VA_ARGS__)

#define DO_TEST_CPU_DATA(name) \
    do { \
        struct testCPUData data = { name, driver.xmlopt, qapiData.schema }; \
        const char *label = "GetCPUData(" name ")"; \
        if (virTestRun(label, testQemuMonitorJSONGetCPUData, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_CPU_INFO(name, maxvcpus) \
    do { \
        struct testCPUInfoData data = {name, maxvcpus, driver.xmlopt, \
                                       qapiData.schema}; \
        if (virTestRun("GetCPUInfo(" name ")", testQemuMonitorCPUInfo, \
                       &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST(GetStatus);
    DO_TEST(GetVersion);
    DO_TEST(GetMachines);
    DO_TEST(GetCPUDefinitions);
    DO_TEST(GetTPMModels);
    if (qemuMonitorJSONTestAttachChardev(driver.xmlopt, qapiData.schema) < 0)
        ret = -1;
    DO_TEST(DetachChardev);
    DO_TEST(GetListPaths);
    DO_TEST(GetObjectProperty);
    DO_TEST(SetObjectProperty);
    DO_TEST(GetDeviceAliases);
    DO_TEST(CPU);
    DO_TEST(GetNonExistingCPUData);
    DO_TEST(GetIOThreads);
    DO_TEST(GetSEVInfo);
    DO_TEST(Transaction);
    DO_TEST(BlockExportAdd);
    DO_TEST(BlockdevReopen);
    DO_TEST_SIMPLE("qmp_capabilities", qemuMonitorJSONSetCapabilities);
    DO_TEST_SIMPLE("system_powerdown", qemuMonitorJSONSystemPowerdown);
    DO_TEST_SIMPLE("system_reset", qemuMonitorJSONSystemReset);
    DO_TEST_SIMPLE("migrate_cancel", qemuMonitorJSONMigrateCancel);
    DO_TEST_SIMPLE("inject-nmi", qemuMonitorJSONInjectNMI);
    DO_TEST_SIMPLE("system_wakeup", qemuMonitorJSONSystemWakeup);
    DO_TEST_SIMPLE("nbd-server-stop", qemuMonitorJSONNBDServerStop);
    DO_TEST_SIMPLE("rtc-reset-reinjection", qemuMonitorJSONRTCResetReinjection);
    DO_TEST_GEN(qemuMonitorJSONSetLink);
    DO_TEST_GEN(qemuMonitorJSONBlockResize);
    DO_TEST_GEN(qemuMonitorJSONSetPassword);
    DO_TEST_GEN(qemuMonitorJSONExpirePassword);
    DO_TEST_GEN(qemuMonitorJSONSetBalloon);
    DO_TEST_GEN(qemuMonitorJSONSaveVirtualMemory);
    DO_TEST_GEN(qemuMonitorJSONSavePhysicalMemory);
    DO_TEST_GEN(qemuMonitorJSONMigrate);
    DO_TEST_GEN(qemuMonitorJSONMigrateRecover);
    DO_TEST_SIMPLE("migrate-pause", qemuMonitorJSONMigratePause);
    DO_TEST_GEN(qemuMonitorJSONDump);
    DO_TEST_GEN(qemuMonitorJSONGraphicsRelocate);
    DO_TEST_GEN(qemuMonitorJSONRemoveNetdev);
    DO_TEST_GEN(qemuMonitorJSONDelDevice);
    DO_TEST_GEN(qemuMonitorJSONBlockdevMirror);
    DO_TEST_GEN(qemuMonitorJSONBlockStream);
    DO_TEST_GEN(qemuMonitorJSONBlockCommit);
    DO_TEST_GEN(qemuMonitorJSONScreendump);
    DO_TEST_GEN(qemuMonitorJSONOpenGraphics);
    DO_TEST_GEN_DEPRECATED(qemuMonitorJSONNBDServerAdd, true);
    DO_TEST_GEN(qemuMonitorJSONDetachCharDev);
    DO_TEST_GEN(qemuMonitorJSONBlockdevTrayOpen);
    DO_TEST_GEN(qemuMonitorJSONBlockdevTrayClose);
    DO_TEST_GEN(qemuMonitorJSONBlockdevMediumRemove);
    DO_TEST_GEN(qemuMonitorJSONBlockdevMediumInsert);
    DO_TEST_GEN(qemuMonitorJSONBitmapRemove);
    DO_TEST_GEN(qemuMonitorJSONJobDismiss);
    DO_TEST_GEN(qemuMonitorJSONJobComplete);
    DO_TEST_GEN(qemuMonitorJSONJobFinalize);
    DO_TEST_GEN(qemuMonitorJSONBlockJobCancel);
    DO_TEST_GEN(qemuMonitorJSONSetAction);
    DO_TEST_GEN(qemuMonitorJSONSetLaunchSecurityState);
    DO_TEST(qemuMonitorJSONGetBalloonInfo);
    DO_TEST(qemuMonitorJSONGetBlockInfo);
    DO_TEST(qemuMonitorJSONGetAllBlockStatsInfo);
    DO_TEST(qemuMonitorJSONGetMigrationStats);
    DO_TEST(qemuMonitorJSONGetChardevInfo);
    DO_TEST(qemuMonitorJSONSetBlockIoThrottle);
    DO_TEST(qemuMonitorJSONGetTargetArch);
    DO_TEST(qemuMonitorJSONGetMigrationCapabilities);
    DO_TEST(qemuMonitorJSONQueryCPUsFast);
    DO_TEST(qemuMonitorJSONSendKey);
    DO_TEST(qemuMonitorJSONGetDumpGuestMemoryCapability);
    DO_TEST(qemuMonitorJSONSendKeyHoldtime);
    DO_TEST(qemuMonitorJSONNBDServerStart);

    DO_TEST_CPU_DATA("host");
    DO_TEST_CPU_DATA("full");
    DO_TEST_CPU_DATA("ecx");

    DO_TEST_CPU_INFO("x86-basic-pluggable", 8);
    DO_TEST_CPU_INFO("x86-full", 11);
    DO_TEST_CPU_INFO("x86-node-full", 8);
    DO_TEST_CPU_INFO("x86-dies", 16);

    DO_TEST_CPU_INFO("ppc64-basic", 24);
    DO_TEST_CPU_INFO("ppc64-hotplug-1", 24);
    DO_TEST_CPU_INFO("ppc64-hotplug-2", 24);
    DO_TEST_CPU_INFO("ppc64-hotplug-4", 24);
    DO_TEST_CPU_INFO("ppc64-no-threads", 16);

    DO_TEST_CPU_INFO("s390", 2);


#define DO_TEST_QAPI_QUERY(nme, qry, scc, rplobj) \
    do { \
        qapiData.name = nme; \
        qapiData.query = qry; \
        qapiData.rc = scc; \
        qapiData.replyobj = rplobj; \
        if (virTestRun("qapi schema query " nme, testQAPISchemaQuery, &qapiData) < 0)\
            ret = -1; \
    } while (0)

    DO_TEST_QAPI_QUERY("command", "blockdev-add", 1, true);
    DO_TEST_QAPI_QUERY("event", "RTC_CHANGE", 1, true);
    DO_TEST_QAPI_QUERY("object property", "screendump/arg-type/device", 1, true);
    DO_TEST_QAPI_QUERY("optional property", "block-commit/arg-type/*top", 1, true);
    DO_TEST_QAPI_QUERY("variant", "blockdev-add/arg-type/+file", 1, true);
    DO_TEST_QAPI_QUERY("variant property", "blockdev-add/arg-type/+file/filename", 1, true);
    DO_TEST_QAPI_QUERY("enum value", "query-status/ret-type/status/^debug", 1, false);
    DO_TEST_QAPI_QUERY("builtin type", "query-qmp-schema/ret-type/name/!string", 1, false);
    DO_TEST_QAPI_QUERY("alternate variant 1", "blockdev-add/arg-type/+qcow2/backing/!null", 1, false);
    DO_TEST_QAPI_QUERY("alternate variant 2", "blockdev-add/arg-type/+qcow2/backing/!string", 1, false);
    DO_TEST_QAPI_QUERY("alternate variant 3", "blockdev-add/arg-type/+qcow2/backing/+file/filename", 1, true);

    DO_TEST_QAPI_QUERY("nonexistent command", "nonexistent", 0, false);
    DO_TEST_QAPI_QUERY("nonexistent attr", "screendump/arg-type/nonexistent", 0, false);
    DO_TEST_QAPI_QUERY("nonexistent variant", "blockdev-add/arg-type/+nonexistent", 0, false);
    DO_TEST_QAPI_QUERY("nonexistent enum value", "query-status/ret-type/status/^nonexistentdebug", 0, false);
    DO_TEST_QAPI_QUERY("broken query for enum value", "query-status/ret-type/status/^debug/test", -1, false);
    DO_TEST_QAPI_QUERY("builtin type", "query-qmp-schema/ret-type/name/!number", 0, false);

#undef DO_TEST_QAPI_QUERY


#define DO_TEST_QAPI_VALIDATE(nme, rootquery, scc, jsonstr) \
    do { \
        qapiData.name = nme; \
        qapiData.query = rootquery; \
        qapiData.success = scc; \
        qapiData.json = jsonstr; \
        if (virTestRun("qapi schema validate " nme, testQAPISchemaValidate, &qapiData) < 0)\
            ret = -1; \
    } while (0)


    DO_TEST_QAPI_VALIDATE("string", "trace-event-get-state/arg-type", true,
                          "{\"name\":\"test\"}");
    DO_TEST_QAPI_VALIDATE("attr type mismatch", "trace-event-get-state/arg-type", false,
                          "{\"name\":123}");
    DO_TEST_QAPI_VALIDATE("missing mandatory attr", "trace-event-get-state/arg-type", false,
                          "{}");
    DO_TEST_QAPI_VALIDATE("attr name not present", "trace-event-get-state/arg-type", false,
                          "{\"name\":\"test\", \"blah\":123}");
    DO_TEST_QAPI_VALIDATE("variant", "blockdev-add/arg-type", true,
                          "{\"driver\":\"file\", \"filename\":\"ble\"}");
    DO_TEST_QAPI_VALIDATE("variant wrong", "blockdev-add/arg-type", false,
                          "{\"driver\":\"filefilefilefile\", \"filename\":\"ble\"}");
    DO_TEST_QAPI_VALIDATE("variant missing mandatory", "blockdev-add/arg-type", false,
                          "{\"driver\":\"file\", \"pr-manager\":\"ble\"}");
    DO_TEST_QAPI_VALIDATE("variant missing discriminator", "blockdev-add/arg-type", false,
                          "{\"node-name\":\"dfgfdg\"}");
    DO_TEST_QAPI_VALIDATE("alternate 1", "blockdev-add/arg-type", true,
                          "{\"driver\":\"qcow2\","
                          "\"file\": { \"driver\":\"file\", \"filename\":\"ble\"}}");
    DO_TEST_QAPI_VALIDATE("alternate 2", "blockdev-add/arg-type", true,
                          "{\"driver\":\"qcow2\",\"file\": \"somepath\"}");
    DO_TEST_QAPI_VALIDATE("alternate 2", "blockdev-add/arg-type", false,
                          "{\"driver\":\"qcow2\",\"file\": 1234}");

#undef DO_TEST_QAPI_VALIDATE

    if (virTestRun("validate that object-add and device_add don't have schema",
                   testQAPISchemaObjectDeviceAdd, qapiData.schema) < 0)
        ret = -1;

#define DO_TEST_QUERY_JOBS(name) \
    do { \
        struct testQueryJobsData data = { name, driver.xmlopt}; \
        if (virTestRun("query-jobs-" name, testQueryJobs, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_QUERY_JOBS("empty");
    DO_TEST_QUERY_JOBS("create");

#undef DO_TEST_QUERY_JOBS

    if (!(qapischema_s390x = testQEMUSchemaLoadLatest("s390x"))) {
        VIR_TEST_VERBOSE("failed to load qapi schema for s390x");
        ret = -1;
        goto cleanup;
    }

    qapiData.schema = qapischema_s390x;

    DO_TEST(qemuMonitorJSONGetCPUModelComparison);
    DO_TEST(qemuMonitorJSONGetCPUModelBaseline);

 cleanup:
    qemuTestDriverFree(&driver);
    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
