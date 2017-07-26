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
#include "qemumonitortestutils.h"
#include "qemu/qemu_domain.h"
#include "qemu/qemu_block.h"
#include "qemu/qemu_monitor_json.h"
#include "virthread.h"
#include "virerror.h"
#include "virstring.h"
#include "cpu/cpu.h"
#include "qemu/qemu_monitor.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _testQemuMonitorJSONSimpleFuncData testQemuMonitorJSONSimpleFuncData;
typedef testQemuMonitorJSONSimpleFuncData *testQemuMonitorJSONSimpleFuncDataPtr;
struct _testQemuMonitorJSONSimpleFuncData {
    const char *cmd;
    int (* func) (qemuMonitorPtr mon);
    virDomainXMLOptionPtr xmlopt;
    const char *reply;
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
testQemuMonitorJSONGetStatus(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    bool running = false;
    virDomainPausedReason reason = 0;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-status",
                               "{ "
                               "    \"return\": { "
                               "        \"status\": \"running\", "
                               "        \"singlestep\": false, "
                               "        \"running\": true "
                               "    } "
                               "}") < 0)
        goto cleanup;
    if (qemuMonitorTestAddItem(test, "query-status",
                               "{ "
                               "    \"return\": { "
                               "        \"singlestep\": false, "
                               "        \"running\": false "
                               "    } "
                               "}") < 0)
        goto cleanup;
    if (qemuMonitorTestAddItem(test, "query-status",
                               "{ "
                               "    \"return\": { "
                               "        \"status\": \"inmigrate\", "
                               "        \"singlestep\": false, "
                               "        \"running\": false "
                               "    } "
                               "}") < 0)
        goto cleanup;

    if (qemuMonitorGetStatus(qemuMonitorTestGetMonitor(test),
                             &running, &reason) < 0)
        goto cleanup;

    if (!running) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Running was not true");
        goto cleanup;
    }

    if (reason != VIR_DOMAIN_PAUSED_UNKNOWN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Reason was unexpectedly set to %d", reason);
        goto cleanup;
    }

    if (qemuMonitorGetStatus(qemuMonitorTestGetMonitor(test),
                             &running, &reason) < 0)
        goto cleanup;

    if (running) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Running was not false");
        goto cleanup;
    }

    if (reason != VIR_DOMAIN_PAUSED_UNKNOWN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Reason was unexpectedly set to %d", reason);
        goto cleanup;
    }

    if (qemuMonitorGetStatus(qemuMonitorTestGetMonitor(test),
                             &running, &reason) < 0)
        goto cleanup;

    if (running) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Running was not false");
        goto cleanup;
    }

    if (reason != VIR_DOMAIN_PAUSED_MIGRATION) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Reason was unexpectedly set to %d", reason);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONGetVersion(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    int major;
    int minor;
    int micro;
    char *package = NULL;

    if (!test)
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
        goto cleanup;

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
        goto cleanup;

    if (qemuMonitorGetVersion(qemuMonitorTestGetMonitor(test),
                              &major, &minor, &micro,
                              &package) < 0)
        goto cleanup;

    if (major != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Major %d was not 1", major);
        goto cleanup;
    }
    if (minor != 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Minor %d was not 2", major);
        goto cleanup;
    }
    if (micro != 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Micro %d was not 3", major);
        goto cleanup;
    }

    if (STRNEQ(package, "")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Package %s was not ''", package);
        goto cleanup;
    }
    VIR_FREE(package);

    if (qemuMonitorGetVersion(qemuMonitorTestGetMonitor(test),
                              &major, &minor, &micro,
                              &package) < 0)
        goto cleanup;

    if (major != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Major %d was not 0", major);
        goto cleanup;
    }
    if (minor != 11) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Minor %d was not 11", major);
        goto cleanup;
    }
    if (micro != 6) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Micro %d was not 6", major);
        goto cleanup;
    }

    if (STRNEQ(package, "2.283.el6")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Package %s was not '2.283.el6'", package);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    VIR_FREE(package);
    return ret;
}

static int
testQemuMonitorJSONGetMachines(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    qemuMonitorMachineInfoPtr *info;
    int ninfo = 0;
    const char *null = NULL;
    size_t i;

    if (!test)
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

#define CHECK(i, wantname, wantisDefault, wantalias)                    \
    do {                                                                \
        if (STRNEQ(info[i]->name, (wantname))) {                        \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "name %s is not %s",                         \
                           info[i]->name, (wantname));                  \
            goto cleanup;                                               \
        }                                                               \
        if (info[i]->isDefault != (wantisDefault)) {                    \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "isDefault %d is not %d",                    \
                           info[i]->isDefault, (wantisDefault));        \
            goto cleanup;                                               \
        }                                                               \
        if (STRNEQ_NULLABLE(info[i]->alias, (wantalias))) {             \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "alias %s is not %s",                        \
                           info[i]->alias, NULLSTR(wantalias));         \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

    CHECK(0, "pc-1.0", false, null);
    CHECK(1, "pc-1.1", false, null);
    CHECK(2, "pc-1.2", true, "pc");

#undef CHECK

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    for (i = 0; i < ninfo; i++)
        qemuMonitorMachineInfoFree(info[i]);
    VIR_FREE(info);

    return ret;
}


static int
testQemuMonitorJSONGetCPUDefinitions(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    qemuMonitorCPUDefInfoPtr *cpus = NULL;
    int ncpus = 0;
    size_t i;

    if (!test)
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
        goto cleanup;

    if ((ncpus = qemuMonitorGetCPUDefinitions(qemuMonitorTestGetMonitor(test),
                                              &cpus)) < 0)
        goto cleanup;

    if (ncpus != 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "ncpus %d is not 3", ncpus);
        goto cleanup;
    }

#define CHECK_FULL(i, wantname, Usable)                                 \
    do {                                                                \
        if (STRNEQ(cpus[i]->name, (wantname))) {                        \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "name %s is not %s",                         \
                           cpus[i]->name, (wantname));                  \
            goto cleanup;                                               \
        }                                                               \
        if (cpus[i]->usable != (Usable)) {                              \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "%s: expecting usable flag %d, got %d",      \
                           cpus[i]->name, Usable, cpus[i]->usable);     \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

#define CHECK(i, wantname)                                              \
    CHECK_FULL(i, wantname, VIR_TRISTATE_BOOL_ABSENT)

#define CHECK_USABLE(i, wantname, usable)                               \
    CHECK_FULL(i, wantname,                                             \
               usable ? VIR_TRISTATE_BOOL_YES : VIR_TRISTATE_BOOL_NO)

    CHECK(0, "qemu64");
    CHECK_USABLE(1, "Opteron_G4", false);
    CHECK_USABLE(2, "Westmere", true);

#undef CHECK
#undef CHECK_USABLE
#undef CHECK_FULL

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    for (i = 0; i < ncpus; i++)
        qemuMonitorCPUDefInfoFree(cpus[i]);
    VIR_FREE(cpus);
    return ret;
}


static int
testQemuMonitorJSONGetCommands(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    char **commands = NULL;
    int ncommands = 0;
    size_t i;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-commands",
                               "{ "
                               "  \"return\": [ "
                               "   { "
                               "     \"name\": \"system_wakeup\" "
                               "   }, "
                               "   { "
                               "     \"name\": \"cont\" "
                               "   }, "
                               "   { "
                               "     \"name\": \"quit\" "
                               "   } "
                               "  ]"
                               "}") < 0)
        goto cleanup;

    if ((ncommands = qemuMonitorGetCommands(qemuMonitorTestGetMonitor(test),
                                        &commands)) < 0)
        goto cleanup;

    if (ncommands != 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "ncommands %d is not 3", ncommands);
        goto cleanup;
    }

#define CHECK(i, wantname)                                              \
    do {                                                                \
        if (STRNEQ(commands[i], (wantname))) {                          \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "name %s is not %s",                         \
                           commands[i], (wantname));                    \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

    CHECK(0, "system_wakeup");
    CHECK(1, "cont");
    CHECK(2, "quit");

#undef CHECK
    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    for (i = 0; i < ncommands; i++)
        VIR_FREE(commands[i]);
    VIR_FREE(commands);
    return ret;
}


static int
testQemuMonitorJSONGetTPMModels(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    char **tpmmodels = NULL;
    int ntpmmodels = 0;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-tpm-models",
                               "{ "
                               "  \"return\": [ "
                               "  \"passthrough\""
                               "  ]"
                               "}") < 0)
        goto cleanup;

    if ((ntpmmodels = qemuMonitorGetTPMModels(qemuMonitorTestGetMonitor(test),
                                              &tpmmodels)) < 0)
        goto cleanup;

    if (ntpmmodels != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "ntpmmodels %d is not 1", ntpmmodels);
        goto cleanup;
    }

#define CHECK(i, wantname)                                              \
    do {                                                                \
        if (STRNEQ(tpmmodels[i], (wantname))) {                         \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "name %s is not %s",                         \
                           tpmmodels[i], (wantname));                   \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

    CHECK(0, "passthrough");

#undef CHECK

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    virStringListFree(tpmmodels);
    return ret;
}


static int
testQemuMonitorJSONGetCommandLineOptionParameters(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    char **params = NULL;
    int nparams = 0;
    bool found = false;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-command-line-options",
                               "{ "
                               "  \"return\": [ "
                               "  {\"parameters\": [], \"option\": \"acpi\" },"
                               "  {\"parameters\": ["
                               "    {\"name\": \"romfile\", "
                               "     \"type\": \"string\"}, "
                               "    {\"name\": \"bootindex\", "
                               "     \"type\": \"number\"}], "
                               "   \"option\": \"option-rom\"}"
                               "  ]"
                               "}") < 0)
        goto cleanup;

    /* present with params */
    if ((nparams = qemuMonitorGetCommandLineOptionParameters(qemuMonitorTestGetMonitor(test),
                                                             "option-rom",
                                                             &params,
                                                             NULL)) < 0)
        goto cleanup;

    if (nparams != 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "nparams was %d, expected 2", nparams);
        goto cleanup;
    }

#define CHECK(i, wantname)                                              \
    do {                                                                \
        if (STRNEQ(params[i], (wantname))) {                            \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "name was %s, expected %s",                  \
                           params[i], (wantname));                      \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

    CHECK(0, "romfile");
    CHECK(1, "bootindex");

#undef CHECK

    virStringListFree(params);
    params = NULL;

    /* present but empty */
    if ((nparams = qemuMonitorGetCommandLineOptionParameters(qemuMonitorTestGetMonitor(test),
                                                             "acpi",
                                                             &params,
                                                             &found)) < 0)
        goto cleanup;

    if (nparams != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "nparams was %d, expected 0", nparams);
        goto cleanup;
    }
    if (!found) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "found was false, expected true");
        goto cleanup;
    }
    if (params && params[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected array contents");
        goto cleanup;
    }

    virStringListFree(params);
    params = NULL;

    /* no such option */
    if ((nparams = qemuMonitorGetCommandLineOptionParameters(qemuMonitorTestGetMonitor(test),
                                                             "foobar",
                                                             &params,
                                                             &found)) < 0)
        goto cleanup;

    if (nparams != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "nparams was %d, expected 0", nparams);
        goto cleanup;
    }
    if (found) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "found was true, expected false");
        goto cleanup;
    }
    if (params && params[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected array contents");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    virStringListFree(params);
    return ret;
}


struct qemuMonitorJSONTestAttachChardevData {
    qemuMonitorTestPtr test;
    virDomainChrSourceDefPtr chr;
    const char *expectPty;
    bool fail;
};

static int
testQemuMonitorJSONAttachChardev(const void *opaque)
{
    const struct qemuMonitorJSONTestAttachChardevData *data = opaque;
    int rc;

    if ((rc = qemuMonitorAttachCharDev(qemuMonitorTestGetMonitor(data->test),
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
qemuMonitorJSONTestAttachOneChardev(virDomainXMLOptionPtr xmlopt,
                                    const char *label,
                                    virDomainChrSourceDefPtr chr,
                                    const char *expectargs,
                                    const char *reply,
                                    const char *expectPty,
                                    bool fail)

{
    struct qemuMonitorJSONTestAttachChardevData data = {0};
    char *jsonreply = NULL;
    char *fulllabel = NULL;
    int ret = -1;

    if (!reply)
        reply = "";

    if (virAsprintf(&jsonreply, "{\"return\": {%s}}", reply) < 0)
        goto cleanup;

    if (virAsprintf(&fulllabel, "qemuMonitorJSONTestAttachChardev(%s)", label) < 0)
        goto cleanup;

    data.chr = chr;
    data.fail = fail;
    data.expectPty = expectPty;
    if (!(data.test = qemuMonitorTestNewSimple(true, xmlopt)))
        goto cleanup;

    if (qemuMonitorTestAddItemExpect(data.test, "chardev-add",
                                     expectargs, true, jsonreply) < 0)
        goto cleanup;

    if (virTestRun(fulllabel, &testQemuMonitorJSONAttachChardev, &data) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    qemuMonitorTestFree(data.test);
    VIR_FREE(jsonreply);
    VIR_FREE(fulllabel);
    return ret;
}

static int
qemuMonitorJSONTestAttachChardev(virDomainXMLOptionPtr xmlopt)
{
    virDomainChrSourceDef chr;
    int ret = 0;

#define CHECK(label, fail, expectargs)                                         \
    if (qemuMonitorJSONTestAttachOneChardev(xmlopt, label, &chr, expectargs,   \
                                            NULL, NULL, fail) < 0)             \
        ret = -1

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_NULL };
    CHECK("null", false,
          "{'id':'alias','backend':{'type':'null','data':{}}}");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_VC };
    CHECK("vc", false,
          "{'id':'alias','backend':{'type':'null','data':{}}}");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_PTY };
    if (qemuMonitorJSONTestAttachOneChardev(xmlopt, "pty", &chr,
                                            "{'id':'alias',"
                                             "'backend':{'type':'pty',"
                                                        "'data':{}}}",
                                            "\"pty\" : \"/dev/pts/0\"",
                                            "/dev/pts/0", false) < 0)
        ret = -1;

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_PTY };
    CHECK("pty missing path", true,
          "{'id':'alias','backend':{'type':'pty','data':{}}}");

    memset(&chr, 0, sizeof(chr));
    chr.type = VIR_DOMAIN_CHR_TYPE_FILE;
    chr.data.file.path = (char *) "/test/path";
    CHECK("file", false,
          "{'id':'alias','backend':{'type':'file','data':{'out':'/test/path'}}}");

    memset(&chr, 0, sizeof(chr));
    chr.type = VIR_DOMAIN_CHR_TYPE_DEV;
    chr.data.file.path = (char *) "/test/path";
    CHECK("device", false,
          "{'id':'alias','backend':{'type':'serial','data':{'device':'/test/path'}}}");

    memset(&chr, 0, sizeof(chr));
    chr.type = VIR_DOMAIN_CHR_TYPE_TCP;
    chr.data.tcp.host = (char *) "example.com";
    chr.data.tcp.service = (char *) "1234";
    CHECK("tcp", false,
          "{'id':'alias',"
           "'backend':{'type':'socket',"
                      "'data':{'addr':{'type':'inet',"
                                      "'data':{'host':'example.com',"
                                              "'port':'1234'}},"
                              "'wait':false,"
                              "'telnet':false,"
                              "'server':false}}}");

    memset(&chr, 0, sizeof(chr));
    chr.type = VIR_DOMAIN_CHR_TYPE_UDP;
    chr.data.udp.connectHost = (char *) "example.com";
    chr.data.udp.connectService = (char *) "1234";
    CHECK("udp", false,
          "{'id':'alias',"
           "'backend':{'type':'udp',"
                      "'data':{'remote':{'type':'inet',"
                                        "'data':{'host':'example.com',"
                                                "'port':'1234'}}}}}");

    chr.data.udp.bindHost = (char *) "localhost";
    chr.data.udp.bindService = (char *) "4321";
    CHECK("udp", false,
          "{'id':'alias',"
           "'backend':{'type':'udp',"
                      "'data':{'remote':{'type':'inet',"
                                        "'data':{'host':'example.com',"
                                                "'port':'1234'}},"
                              "'local':{'type':'inet',"
                                       "'data':{'host':'localhost',"
                                               "'port':'4321'}}}}}");

    chr.data.udp.bindHost = NULL;
    chr.data.udp.bindService = (char *) "4321";
    CHECK("udp", false,
          "{'id':'alias',"
           "'backend':{'type':'udp',"
                      "'data':{'remote':{'type':'inet',"
                                        "'data':{'host':'example.com',"
                                                "'port':'1234'}},"
                              "'local':{'type':'inet',"
                                       "'data':{'host':'',"
                                               "'port':'4321'}}}}}");
    memset(&chr, 0, sizeof(chr));
    chr.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    chr.data.nix.path = (char *) "/path/to/socket";
    CHECK("unix", false,
          "{'id':'alias',"
           "'backend':{'type':'socket',"
                      "'data':{'addr':{'type':'unix',"
                                      "'data':{'path':'/path/to/socket'}},"
                              "'wait':false,"
                              "'server':false}}}");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_SPICEVMC };
    CHECK("spicevmc", false,
          "{'id':'alias','backend':{'type':'spicevmc','"
                                    "data':{'type':'vdagent'}}}");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_PIPE };
    CHECK("pipe", true, "");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_STDIO };
    CHECK("stdio", true, "");
#undef CHECK

    return ret;
}


static int
testQemuMonitorJSONDetachChardev(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;

    if (!test)
        return ret;

    if (qemuMonitorTestAddItem(test, "chardev-remove", "{\"return\": {}}") < 0)
        goto cleanup;

    if (qemuMonitorDetachCharDev(qemuMonitorTestGetMonitor(test),
                                 "dummy_chrID") < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
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
testQemuMonitorJSONGetListPaths(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    qemuMonitorJSONListPathPtr *paths;
    int npaths = 0;
    size_t i;

    if (!test)
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

#define CHECK(i, wantname, wanttype)                                    \
    do {                                                                \
        if (STRNEQ(paths[i]->name, (wantname))) {                       \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "name was %s, expected %s",                  \
                           paths[i]->name, (wantname));                 \
            goto cleanup;                                               \
        }                                                               \
        if (STRNEQ_NULLABLE(paths[i]->type, (wanttype))) {              \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "type was %s, expected %s",                  \
                           NULLSTR(paths[i]->type), (wanttype));        \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

    CHECK(0, "machine", "child<container>");

#undef CHECK

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
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
testQemuMonitorJSONGetObjectProperty(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    qemuMonitorJSONObjectProperty prop;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "qom-get",
                               "{ \"return\": true }") < 0)
        goto cleanup;

    /* Present with path and property */
    memset(&prop, 0, sizeof(qemuMonitorJSONObjectProperty));
    prop.type = QEMU_MONITOR_OBJECT_PROPERTY_BOOLEAN;
    if (qemuMonitorJSONGetObjectProperty(qemuMonitorTestGetMonitor(test),
                                         "/machine/i440fx",
                                         "realized",
                                         &prop) < 0)
        goto cleanup;

    if (!prop.val.b) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "expected true, but false returned");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}


/*
 * This test will use a path to /machine/i440fx which should exist in order
 * to ensure that the qom-set property set works properly. The test will
 * set a true property to true just as a proof of concept.  Setting it to
 * false is not a good idea...
 */
static int
testQemuMonitorJSONSetObjectProperty(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    qemuMonitorJSONObjectProperty prop;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "qom-set",
                               "{ \"return\": {} }") < 0)
        goto cleanup;
    if (qemuMonitorTestAddItem(test, "qom-get",
                               "{ \"return\": true }") < 0)
        goto cleanup;

    /* Let's attempt the setting */
    memset(&prop, 0, sizeof(qemuMonitorJSONObjectProperty));
    prop.type = QEMU_MONITOR_OBJECT_PROPERTY_BOOLEAN;
    prop.val.b = true;
    if (qemuMonitorJSONSetObjectProperty(qemuMonitorTestGetMonitor(test),
                                         "/machine/i440fx",
                                         "realized",
                                         &prop) < 0)
        goto cleanup;

    /* To make sure it worked, fetch the property - if this succeeds then
     * we didn't hose things
     */
    memset(&prop, 0, sizeof(qemuMonitorJSONObjectProperty));
    prop.type = QEMU_MONITOR_OBJECT_PROPERTY_BOOLEAN;
    if (qemuMonitorJSONGetObjectProperty(qemuMonitorTestGetMonitor(test),
                                         "/machine/i440fx",
                                         "realized",
                                         &prop) < 0)
        goto cleanup;

    if (!prop.val.b) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "expected true, but false returned");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}


static int
testQemuMonitorJSONGetDeviceAliases(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    char **aliases = NULL;
    const char **alias;
    const char *expected[] = {
        "virtio-disk25", "video0", "serial0", "ide0-0-0", "usb", NULL };

    if (!test)
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
        goto cleanup;

    if (qemuMonitorJSONGetDeviceAliases(qemuMonitorTestGetMonitor(test),
                                        &aliases) < 0)
        goto cleanup;

    if (!aliases) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", "no aliases returned");
        goto cleanup;
    }

    ret = 0;
    for (alias = (const char **) aliases; *alias; alias++) {
        if (!virStringListHasString(expected, *alias)) {
            fprintf(stderr, "got unexpected device alias '%s'\n", *alias);
            ret = -1;
        }
    }
    for (alias = expected; *alias; alias++) {
        if (!virStringListHasString((const char **) aliases, *alias)) {
            fprintf(stderr, "missing expected alias '%s'\n", *alias);
            ret = -1;
        }
    }

 cleanup:
    virStringListFree(aliases);
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONCPU(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    bool running = false;
    virDomainPausedReason reason = 0;

    if (!test)
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
        goto cleanup;

    if (qemuMonitorJSONStopCPUs(qemuMonitorTestGetMonitor(test)) < 0)
        goto cleanup;

    if (qemuMonitorGetStatus(qemuMonitorTestGetMonitor(test),
                             &running, &reason) < 0)
        goto cleanup;

    if (running) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Running was not false");
        goto cleanup;
    }

    if (qemuMonitorJSONStartCPUs(qemuMonitorTestGetMonitor(test), NULL) < 0)
        goto cleanup;

    if (qemuMonitorGetStatus(qemuMonitorTestGetMonitor(test),
                             &running, &reason) < 0)
        goto cleanup;

    if (!running) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Running was not true");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONSimpleFunc(const void *opaque)
{
    testQemuMonitorJSONSimpleFuncDataPtr data =
        (testQemuMonitorJSONSimpleFuncDataPtr) opaque;
    virDomainXMLOptionPtr xmlopt = data->xmlopt;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    const char *reply = data->reply;
    int ret = -1;

    if (!test)
        return -1;

    if (!reply)
        reply = "{\"return\":{}}";

    if (qemuMonitorTestAddItem(test, data->cmd, reply) < 0)
        goto cleanup;

    if (data->func(qemuMonitorTestGetMonitor(test)) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

#define GEN_TEST_FUNC(funcName, ...)                                    \
static int                                                              \
testQemuMonitorJSON ## funcName(const void *opaque)                     \
{                                                                       \
    const testQemuMonitorJSONSimpleFuncData *data = opaque;             \
    virDomainXMLOptionPtr xmlopt = data->xmlopt;                        \
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);   \
    const char *reply = data->reply;                                    \
    int ret = -1;                                                       \
                                                                        \
    if (!test)                                                          \
        return -1;                                                      \
                                                                        \
    if (!reply)                                                         \
        reply = "{\"return\":{}}";                                      \
                                                                        \
    if (qemuMonitorTestAddItem(test, data->cmd, reply) < 0)             \
        goto cleanup;                                                   \
                                                                        \
    if (funcName(qemuMonitorTestGetMonitor(test), __VA_ARGS__) < 0)     \
        goto cleanup;                                                   \
                                                                        \
    ret = 0;                                                            \
cleanup:                                                                \
    qemuMonitorTestFree(test);                                          \
    return ret;                                                         \
}

GEN_TEST_FUNC(qemuMonitorJSONSetLink, "vnet0", VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN)
GEN_TEST_FUNC(qemuMonitorJSONBlockResize, "vda", 123456)
GEN_TEST_FUNC(qemuMonitorJSONSetVNCPassword, "secret_password")
GEN_TEST_FUNC(qemuMonitorJSONSetPassword, "spice", "secret_password", "disconnect")
GEN_TEST_FUNC(qemuMonitorJSONExpirePassword, "spice", "123456")
GEN_TEST_FUNC(qemuMonitorJSONSetBalloon, 1024)
GEN_TEST_FUNC(qemuMonitorJSONSetCPU, 1, true)
GEN_TEST_FUNC(qemuMonitorJSONEjectMedia, "hdc", true)
GEN_TEST_FUNC(qemuMonitorJSONChangeMedia, "hdc", "/foo/bar", NULL)
GEN_TEST_FUNC(qemuMonitorJSONSaveVirtualMemory, 0, 1024, "/foo/bar")
GEN_TEST_FUNC(qemuMonitorJSONSavePhysicalMemory, 0, 1024, "/foo/bar")
GEN_TEST_FUNC(qemuMonitorJSONSetMigrationSpeed, 1024)
GEN_TEST_FUNC(qemuMonitorJSONSetMigrationDowntime, 1)
GEN_TEST_FUNC(qemuMonitorJSONMigrate, QEMU_MONITOR_MIGRATE_BACKGROUND |
              QEMU_MONITOR_MIGRATE_NON_SHARED_DISK |
              QEMU_MONITOR_MIGRATE_NON_SHARED_INC, "tcp:localhost:12345")
GEN_TEST_FUNC(qemuMonitorJSONDump, "dummy_protocol", "dummy_memory_dump_format")
GEN_TEST_FUNC(qemuMonitorJSONGraphicsRelocate, VIR_DOMAIN_GRAPHICS_TYPE_SPICE,
              "localhost", 12345, 12346, NULL)
GEN_TEST_FUNC(qemuMonitorJSONAddNetdev, "some_dummy_netdevstr")
GEN_TEST_FUNC(qemuMonitorJSONRemoveNetdev, "net0")
GEN_TEST_FUNC(qemuMonitorJSONDelDevice, "ide0")
GEN_TEST_FUNC(qemuMonitorJSONAddDevice, "some_dummy_devicestr")
GEN_TEST_FUNC(qemuMonitorJSONSetDrivePassphrase, "drive-vda", "secret_passhprase")
GEN_TEST_FUNC(qemuMonitorJSONDriveMirror, "vdb", "/foo/bar", NULL, 1024, 0, 0,
              VIR_DOMAIN_BLOCK_REBASE_SHALLOW | VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT)
GEN_TEST_FUNC(qemuMonitorJSONBlockCommit, "vdb", "/foo/bar1", "/foo/bar2", NULL, 1024)
GEN_TEST_FUNC(qemuMonitorJSONDrivePivot, "vdb")
GEN_TEST_FUNC(qemuMonitorJSONScreendump, "/foo/bar")
GEN_TEST_FUNC(qemuMonitorJSONOpenGraphics, "spice", "spicefd", false)
GEN_TEST_FUNC(qemuMonitorJSONNBDServerStart, "localhost", 12345)
GEN_TEST_FUNC(qemuMonitorJSONNBDServerAdd, "vda", true)
GEN_TEST_FUNC(qemuMonitorJSONDetachCharDev, "serial1")

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
testQemuMonitorJSONqemuMonitorJSONQueryCPUs(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    struct qemuMonitorQueryCpusEntry *cpudata = NULL;
    struct qemuMonitorQueryCpusEntry expect[] = {
        {0, 17622, (char *) "/machine/unattached/device[0]", true},
        {1, 17624, (char *) "/machine/unattached/device[1]", true},
        {2, 17626, (char *) "/machine/unattached/device[2]", true},
        {3, 17628, NULL, true},
    };
    size_t ncpudata = 0;
    size_t i;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-cpus",
                               "{"
                               "    \"return\": ["
                               "        {"
                               "            \"current\": true,"
                               "            \"CPU\": 0,"
                               "            \"qom_path\": \"/machine/unattached/device[0]\","
                               "            \"pc\": -2130530478,"
                               "            \"halted\": true,"
                               "            \"thread_id\": 17622"
                               "        },"
                               "        {"
                               "            \"current\": false,"
                               "            \"CPU\": 1,"
                               "            \"qom_path\": \"/machine/unattached/device[1]\","
                               "            \"pc\": -2130530478,"
                               "            \"halted\": true,"
                               "            \"thread_id\": 17624"
                               "        },"
                               "        {"
                               "            \"current\": false,"
                               "            \"CPU\": 2,"
                               "            \"qom_path\": \"/machine/unattached/device[2]\","
                               "            \"pc\": -2130530478,"
                               "            \"halted\": true,"
                               "            \"thread_id\": 17626"
                               "        },"
                               "        {"
                               "            \"current\": false,"
                               "            \"CPU\": 3,"
                               "            \"pc\": -2130530478,"
                               "            \"halted\": true,"
                               "            \"thread_id\": 17628"
                               "        }"
                               "    ],"
                               "    \"id\": \"libvirt-7\""
                               "}") < 0)
        goto cleanup;

    if (qemuMonitorJSONQueryCPUs(qemuMonitorTestGetMonitor(test),
                                 &cpudata, &ncpudata, true) < 0)
        goto cleanup;

    if (ncpudata != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expecting ncpupids = 4 but got %zu", ncpudata);
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
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetBalloonInfo(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    unsigned long long currmem;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-balloon",
                               "{"
                               "    \"return\": {"
                               "        \"actual\": 4294967296"
                               "    },"
                               "    \"id\": \"libvirt-9\""
                               "}") < 0)
        goto cleanup;

    if (qemuMonitorJSONGetBalloonInfo(qemuMonitorTestGetMonitor(test), &currmem) < 0)
        goto cleanup;

    if (currmem != (4294967296ULL/1024)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected currmem value: %llu", currmem);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetVirtType(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    virDomainVirtType virtType;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-kvm",
                               "{"
                               "    \"return\": {"
                               "        \"enabled\": true,"
                               "        \"present\": true"
                               "    },"
                               "    \"id\": \"libvirt-8\""
                               "}") < 0 ||
        qemuMonitorTestAddItem(test, "query-kvm",
                               "{"
                               "    \"return\": {"
                               "        \"enabled\": false,"
                               "        \"present\": true"
                               "    },"
                               "    \"id\": \"libvirt-7\""
                               "}") < 0)
        goto cleanup;

    if (qemuMonitorJSONGetVirtType(qemuMonitorTestGetMonitor(test), &virtType) < 0)
        goto cleanup;

    if (virtType != VIR_DOMAIN_VIRT_KVM) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected virt type: %d, expecting %d", virtType, VIR_DOMAIN_VIRT_KVM);
        goto cleanup;
    }

    if (qemuMonitorJSONGetVirtType(qemuMonitorTestGetMonitor(test), &virtType) < 0)
        goto cleanup;

    if (virtType != VIR_DOMAIN_VIRT_QEMU) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected virt type: %d, expecting %d", virtType, VIR_DOMAIN_VIRT_QEMU);
    }

    ret = 0;
 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

static int
testHashEqualQemuDomainDiskInfo(const void *value1, const void *value2)
{
    const struct qemuDomainDiskInfo *info1 = value1, *info2 = value2;

    return memcmp(info1, info2, sizeof(*info1));
}

static int
testQemuMonitorJSONqemuMonitorJSONGetBlockInfo(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    virHashTablePtr blockDevices = NULL, expectedBlockDevices = NULL;
    struct qemuDomainDiskInfo *info;

    if (!test)
        return -1;

    if (!(blockDevices = virHashCreate(32, virHashValueFree)) ||
        !(expectedBlockDevices = virHashCreate(32, virHashValueFree)))
        goto cleanup;

    if (VIR_ALLOC(info) < 0)
        goto cleanup;

    if (virHashAddEntry(expectedBlockDevices, "virtio-disk0", info) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unable to create expectedBlockDevices hash table");
        goto cleanup;
    }

    if (VIR_ALLOC(info) < 0)
        goto cleanup;

    if (virHashAddEntry(expectedBlockDevices, "virtio-disk1", info) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unable to create expectedBlockDevices hash table");
        goto cleanup;
    }

    if (VIR_ALLOC(info) < 0)
        goto cleanup;

    info->locked = true;
    info->removable = true;
    info->tray = true;

    if (virHashAddEntry(expectedBlockDevices, "ide0-1-0", info) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unable to create expectedBlockDevices hash table");
        goto cleanup;
    }

    if (VIR_ALLOC(info) < 0)
        goto cleanup;

    info->removable = true;
    info->tray = true;
    info->empty = true;

    if (virHashAddEntry(expectedBlockDevices, "ide0-1-1", info) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unable to create expectedBlockDevices hash table");
        goto cleanup;
    }

    if (qemuMonitorTestAddItem(test, "query-block", queryBlockReply) < 0)
        goto cleanup;

    if (qemuMonitorJSONGetBlockInfo(qemuMonitorTestGetMonitor(test), blockDevices) < 0)
        goto cleanup;

    if (!virHashEqual(blockDevices, expectedBlockDevices, testHashEqualQemuDomainDiskInfo)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Hashtable is different to the expected one");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virHashFree(blockDevices);
    virHashFree(expectedBlockDevices);
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetBlockStatsInfo(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    virHashTablePtr blockstats = NULL;
    qemuBlockStatsPtr stats;
    int ret = -1;

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

    if (!test)
        return -1;

    /* fill in seven times - we are gonna ask seven times later on */
    if (qemuMonitorTestAddItem(test, "query-blockstats", reply) < 0 ||
        qemuMonitorTestAddItem(test, "query-blockstats", reply) < 0 ||
        qemuMonitorTestAddItem(test, "query-blockstats", reply) < 0 ||
        qemuMonitorTestAddItem(test, "query-blockstats", reply) < 0)
        goto cleanup;

#define CHECK0FULL(var, value, varformat, valformat) \
    if (stats->var != value) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       "Invalid " #var " value: " varformat \
                       ", expected " valformat, \
                       stats->var, value); \
        goto cleanup; \
    }

#define CHECK0(var, value) CHECK0FULL(var, value, "%lld", "%d")

#define CHECK(NAME, RD_REQ, RD_BYTES, RD_TOTAL_TIMES, WR_REQ, WR_BYTES,        \
              WR_TOTAL_TIMES, FLUSH_REQ, FLUSH_TOTAL_TIMES,                    \
              WR_HIGHEST_OFFSET, WR_HIGHEST_OFFSET_VALID)                      \
    if (!(stats = virHashLookup(blockstats, NAME))) {                          \
        virReportError(VIR_ERR_INTERNAL_ERROR,                                 \
                       "block stats for device '%s' is missing", NAME);        \
        goto cleanup;                                                          \
    }                                                                          \
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

    if (qemuMonitorGetAllBlockStatsInfo(qemuMonitorTestGetMonitor(test),
                                        &blockstats, false) < 0)
        goto cleanup;

    if (!blockstats) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "qemuMonitorJSONGetBlockStatsInfo didn't return stats");
        goto cleanup;
    }

    CHECK("virtio-disk0", 1279, 28505088, 640616474, 174, 2845696, 530699221, 0, 0, 5256018944ULL, true)
    CHECK("virtio-disk1", 85, 348160, 8232156, 0, 0, 0, 0, 0, 0ULL, true)
    CHECK("ide0-1-0", 16, 49250, 1004952, 0, 0, 0, 0, 0, 0ULL, false)

    ret = 0;

#undef CHECK
#undef CHECK0
#undef CHECK0FULL

 cleanup:
    qemuMonitorTestFree(test);
    virHashFree(blockstats);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetMigrationParams(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    qemuMonitorMigrationParams params;
    int ret = -1;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-migrate-parameters",
                               "{"
                               "    \"return\": {"
                               "        \"decompress-threads\": 2,"
                               "        \"cpu-throttle-increment\": 10,"
                               "        \"compress-threads\": 8,"
                               "        \"compress-level\": 1,"
                               "        \"cpu-throttle-initial\": 20,"
                               "        \"tls-creds\": \"tls0\","
                               "        \"tls-hostname\": \"\""
                               "    }"
                               "}") < 0) {
        goto cleanup;
    }

    if (qemuMonitorJSONGetMigrationParams(qemuMonitorTestGetMonitor(test),
                                          &params) < 0)
        goto cleanup;

#define CHECK(VAR, FIELD, VALUE)                                            \
    do {                                                                    \
        if (!params.VAR ## _set) {                                          \
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s is not set", FIELD); \
            goto cleanup;                                                   \
        }                                                                   \
        if (params.VAR != VALUE) {                                          \
            virReportError(VIR_ERR_INTERNAL_ERROR,                          \
                           "Invalid %s: %d, expected %d",                   \
                           FIELD, params.VAR, VALUE);                       \
            goto cleanup;                                                   \
        }                                                                   \
    } while (0)

    CHECK(compressLevel, "compress-level", 1);
    CHECK(compressThreads, "compress-threads", 8);
    CHECK(decompressThreads, "decompress-threads", 2);
    CHECK(cpuThrottleInitial, "cpu-throttle-initial", 20);
    CHECK(cpuThrottleIncrement, "cpu-throttle-increment", 10);

#undef CHECK

#define CHECK(VAR, FIELD, VALUE)                                            \
    do {                                                                    \
        if (!params.VAR) {                                                  \
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s is not set", FIELD); \
            goto cleanup;                                                   \
        }                                                                   \
        if (STRNEQ(params.VAR, VALUE)) {                                    \
            virReportError(VIR_ERR_INTERNAL_ERROR,                          \
                           "Invalid %s:'%s', expected '%s'",                \
                           FIELD, params.VAR, VALUE);                       \
            goto cleanup;                                                   \
        }                                                                   \
    } while (0)

    CHECK(migrateTLSAlias, "tls-creds", "tls0");
    CHECK(migrateTLSHostname, "tls-hostname", "");

#undef CHECK

    ret = 0;

 cleanup:
    VIR_FREE(params.migrateTLSAlias);
    VIR_FREE(params.migrateTLSHostname);
    qemuMonitorTestFree(test);
    return ret;
}


static int
testQemuMonitorJSONqemuMonitorJSONGetMigrationCacheSize(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    unsigned long long cacheSize;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-migrate-cache-size",
                               "{"
                               "    \"return\": 67108864,"
                               "    \"id\": \"libvirt-12\""
                               "}") < 0)
        goto cleanup;

    if (qemuMonitorJSONGetMigrationCacheSize(qemuMonitorTestGetMonitor(test),
                                             &cacheSize) < 0)
        goto cleanup;

    if (cacheSize != 67108864) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Invalid cacheSize: %llu, expected 67108864",
                       cacheSize);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetMigrationStats(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    qemuMonitorMigrationStats stats, expectedStats;

    if (!test)
        return -1;

    memset(&expectedStats, 0, sizeof(expectedStats));

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
                               "}") < 0)
        goto cleanup;

    if (qemuMonitorJSONGetMigrationStats(qemuMonitorTestGetMonitor(test), &stats) < 0)
        goto cleanup;

    if (memcmp(&stats, &expectedStats, sizeof(stats)) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Invalid migration status");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    qemuMonitorTestFree(test);
    return ret;
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
testQemuMonitorJSONqemuMonitorJSONGetChardevInfo(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    virHashTablePtr info = NULL, expectedInfo = NULL;
    qemuMonitorChardevInfo info0 = { NULL, VIR_DOMAIN_CHR_DEVICE_STATE_DEFAULT };
    qemuMonitorChardevInfo info1 = { (char *) "/dev/pts/21", VIR_DOMAIN_CHR_DEVICE_STATE_CONNECTED };
    qemuMonitorChardevInfo info2 = { (char *) "/dev/pts/20", VIR_DOMAIN_CHR_DEVICE_STATE_DEFAULT };
    qemuMonitorChardevInfo info3 = { NULL, VIR_DOMAIN_CHR_DEVICE_STATE_DISCONNECTED };

    if (!test)
        return -1;

    if (!(info = virHashCreate(32, qemuMonitorChardevInfoFree)) ||
        !(expectedInfo = virHashCreate(32, NULL)))
        goto cleanup;

    if (virHashAddEntry(expectedInfo, "charserial1", &info1) < 0 ||
        virHashAddEntry(expectedInfo, "charserial0", &info2) < 0 ||
        virHashAddEntry(expectedInfo, "charmonitor", &info0) < 0 ||
        virHashAddEntry(expectedInfo, "charserial2", &info3) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unable to create expectedInfo hash table");
        goto cleanup;
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
        goto cleanup;

    if (qemuMonitorJSONGetChardevInfo(qemuMonitorTestGetMonitor(test),
                                      info) < 0)
        goto cleanup;

    if (!virHashEqual(info, expectedInfo, testHashEqualChardevInfo)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Hashtable is different to the expected one");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virHashFree(info);
    virHashFree(expectedInfo);
    qemuMonitorTestFree(test);
    return ret;
}


static int
testValidateGetBlockIoThrottle(const virDomainBlockIoTuneInfo *info,
                               const virDomainBlockIoTuneInfo *expectedInfo)
{
#define VALIDATE_IOTUNE(field) \
    if (info->field != expectedInfo->field) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       "info->%s=%llu != expected=%llu",  \
                       #field, info->field, expectedInfo->field); \
        return -1; \
    } \
    if (info->field##_max != expectedInfo->field##_max) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       "info->%s_max=%llu != expected=%llu",  \
                       #field, info->field##_max, expectedInfo->field##_max); \
        return -1; \
    } \
    if (info->field##_max_length != expectedInfo->field##_max_length) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       "info->%s_max_length=%llu != expected=%llu",  \
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
testQemuMonitorJSONqemuMonitorJSONSetBlockIoThrottle(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    virDomainBlockIoTuneInfo info, expectedInfo;

    if (!test)
        return -1;

    expectedInfo = (virDomainBlockIoTuneInfo) {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, NULL, 15, 16, 17, 18, 19, 20};
    if (VIR_STRDUP(expectedInfo.group_name, "group14") < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-block", queryBlockReply) < 0 ||
        qemuMonitorTestAddItemParams(test, "block_set_io_throttle",
                                     "{\"return\":{}}",
                                     "device", "\"drive-virtio-disk1\"",
                                     "bps", "1", "bps_rd", "2", "bps_wr", "3",
                                     "iops", "4", "iops_rd", "5", "iops_wr", "6",
                                     "bps_max", "7", "bps_rd_max", "8",
                                     "bps_wr_max", "9",
                                     "iops_max", "10", "iops_rd_max", "11",
                                     "iops_wr_max", "12", "iops_size", "13",
                                     "group", "\"group14\"",
                                     "bps_max_length", "15",
                                     "bps_rd_max_length", "16",
                                     "bps_wr_max_length", "17",
                                     "iops_max_length", "18",
                                     "iops_rd_max_length", "19",
                                     "iops_wr_max_length", "20",
                                     NULL, NULL) < 0)
        goto cleanup;

    if (qemuMonitorJSONGetBlockIoThrottle(qemuMonitorTestGetMonitor(test),
                                          "drive-virtio-disk0", &info) < 0)
        goto cleanup;

    if (testValidateGetBlockIoThrottle(&info, &expectedInfo) < 0)
        goto cleanup;

    if (qemuMonitorJSONSetBlockIoThrottle(qemuMonitorTestGetMonitor(test),
                                          "drive-virtio-disk1", &info, true,
                                          true, true) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(info.group_name);
    VIR_FREE(expectedInfo.group_name);
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetTargetArch(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    char *arch;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-target",
                               "{"
                               "    \"return\": {"
                               "        \"arch\": \"x86_64\""
                               "    },"
                               "    \"id\": \"libvirt-21\""
                               "}") < 0)
        goto cleanup;

    if (!(arch = qemuMonitorJSONGetTargetArch(qemuMonitorTestGetMonitor(test))))
        goto cleanup;

    if (STRNEQ(arch, "x86_64")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected architecture %s, expecting x86_64",
                       arch);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(arch);
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetMigrationCapability(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    int cap;
    const char *reply =
        "{"
        "    \"return\": ["
        "        {"
        "            \"state\": false,"
        "            \"capability\": \"xbzrle\""
        "        }"
        "    ],"
        "    \"id\": \"libvirt-22\""
        "}";

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-migrate-capabilities", reply) < 0 ||
        qemuMonitorTestAddItem(test, "migrate-set-capabilities",
                               "{\"return\":{}}") < 0)
        goto cleanup;

    cap = qemuMonitorJSONGetMigrationCapability(qemuMonitorTestGetMonitor(test),
                                              QEMU_MONITOR_MIGRATION_CAPS_XBZRLE);
    if (cap != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected capability: %d, expecting 1",
                       cap);
        goto cleanup;
    }

    if (qemuMonitorJSONSetMigrationCapability(qemuMonitorTestGetMonitor(test),
                                              QEMU_MONITOR_MIGRATION_CAPS_XBZRLE,
                                              true) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONSendKey(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    unsigned int keycodes[] = {43, 26, 46, 32};

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "send-key",
                               "{\"return\": {}, \"id\": \"libvirt-16\"}") < 0)
        goto cleanup;

    if (qemuMonitorJSONSendKey(qemuMonitorTestGetMonitor(test),
                               0, keycodes, ARRAY_CARDINALITY(keycodes)) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONSendKeyHoldtime(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    unsigned int keycodes[] = {43, 26, 46, 32};

    if (!test)
        return -1;

    if (qemuMonitorTestAddItemParams(test, "send-key",
                                     "{\"return\":{}}",
                                     "hold-time", "31337",
                                     "keys", "[{\"type\":\"number\",\"data\":43},"
                                              "{\"type\":\"number\",\"data\":26},"
                                              "{\"type\":\"number\",\"data\":46},"
                                              "{\"type\":\"number\",\"data\":32}]",
                                     NULL, NULL) < 0)
        goto cleanup;

    if (qemuMonitorJSONSendKey(qemuMonitorTestGetMonitor(test),
                               31337, keycodes,
                               ARRAY_CARDINALITY(keycodes)) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorSupportsActiveCommit(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    const char *error1 =
        "{"
        "  \"error\": {"
        "    \"class\": \"DeviceNotFound\","
        "    \"desc\": \"Device 'bogus' not found\""
        "  }"
        "}";
    const char *error2 =
        "{"
        "  \"error\": {"
        "    \"class\": \"GenericError\","
        "    \"desc\": \"Parameter 'top' is missing\""
        "  }"
        "}";

    if (!test)
        return -1;

    if (qemuMonitorTestAddItemParams(test, "block-commit", error1,
                                     "device", "\"bogus\"",
                                     NULL, NULL) < 0)
        goto cleanup;

    if (!qemuMonitorSupportsActiveCommit(qemuMonitorTestGetMonitor(test)))
        goto cleanup;

    if (qemuMonitorTestAddItemParams(test, "block-commit", error2,
                                     "device", "\"bogus\"",
                                     NULL, NULL) < 0)
        goto cleanup;

    if (qemuMonitorSupportsActiveCommit(qemuMonitorTestGetMonitor(test)))
        goto cleanup;

    ret = 0;
 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONqemuMonitorJSONGetDumpGuestMemoryCapability(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
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

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-dump-guest-memory-capability",
                               reply) < 0)
        goto cleanup;

    cap = qemuMonitorJSONGetDumpGuestMemoryCapability(
                                    qemuMonitorTestGetMonitor(test), "elf");

    if (cap != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected capability: %d, expecting 1",
                       cap);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

struct testCPUData {
    const char *name;
    virDomainXMLOptionPtr xmlopt;
};


static int
testQemuMonitorJSONGetCPUData(const void *opaque)
{
    const struct testCPUData *data = opaque;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, data->xmlopt);
    virCPUDataPtr cpuData = NULL;
    char *jsonFile = NULL;
    char *dataFile = NULL;
    char *jsonStr = NULL;
    char *actual = NULL;
    int ret = -1;

    if (!test)
        return -1;

    if (virAsprintf(&jsonFile,
                    "%s/qemumonitorjsondata/qemumonitorjson-getcpu-%s.json",
                    abs_srcdir, data->name) < 0 ||
        virAsprintf(&dataFile,
                    "%s/qemumonitorjsondata/qemumonitorjson-getcpu-%s.data",
                    abs_srcdir, data->name) < 0)
        goto cleanup;

    if (virTestLoadFile(jsonFile, &jsonStr) < 0)
        goto cleanup;

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
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "qom-get", jsonStr) < 0)
        goto cleanup;

    if (qemuMonitorJSONGetGuestCPU(qemuMonitorTestGetMonitor(test),
                                   VIR_ARCH_X86_64,
                                   &cpuData, NULL) < 0)
        goto cleanup;

    if (!(actual = virCPUDataFormat(cpuData)))
        goto cleanup;

    if (virTestCompareToFile(actual, dataFile) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(jsonFile);
    VIR_FREE(dataFile);
    VIR_FREE(jsonStr);
    VIR_FREE(actual);
    virCPUDataFree(cpuData);
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuMonitorJSONGetNonExistingCPUData(const void *opaque)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr) opaque;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    virCPUDataPtr cpuData = NULL;
    int rv, ret = -1;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "qom-list",
                               "{"
                               "    \"id\": \"libvirt-7\","
                               "    \"error\": {"
                               "        \"class\": \"CommandNotFound\","
                               "        \"desc\": \"The command qom-list has not been found\""
                               "    }"
                               "}") < 0)
        goto cleanup;

    rv = qemuMonitorJSONGetGuestCPU(qemuMonitorTestGetMonitor(test),
                                   VIR_ARCH_X86_64,
                                   &cpuData, NULL);
    if (rv != -2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected return value %d, expecting -2", rv);
        goto cleanup;
    }

    if (cpuData) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Unexpected allocation of data = %p, expecting NULL",
                       cpuData);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    qemuMonitorTestFree(test);
    virCPUDataFree(cpuData);
    return ret;
}

static int
testQemuMonitorJSONGetIOThreads(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    qemuMonitorIOThreadInfoPtr *info;
    int ninfo = 0;
    int ret = -1;
    size_t i;

    if (!test)
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

    if ((ninfo = qemuMonitorGetIOThreads(qemuMonitorTestGetMonitor(test),
                                         &info)) < 0)
        goto cleanup;

    if (ninfo != 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "ninfo %d is not 2", ninfo);
        goto cleanup;
    }

#define CHECK(i, wantiothread_id, wantthread_id)                        \
    do {                                                                \
        if (info[i]->iothread_id != (wantiothread_id)) {                \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "iothread_id %u is not %u",                  \
                           info[i]->iothread_id, (wantiothread_id));    \
            goto cleanup;                                               \
        }                                                               \
        if (info[i]->thread_id != (wantthread_id)) {                    \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "thread_id %d is not %d",                    \
                           info[i]->thread_id, (wantthread_id));        \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

    CHECK(0, 1, 30992);
    CHECK(1, 2, 30993);

#undef CHECK

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    for (i = 0; i < ninfo; i++)
        VIR_FREE(info[i]);
    VIR_FREE(info);

    return ret;
}

struct testCPUInfoData {
    const char *name;
    size_t maxvcpus;
    virDomainXMLOptionPtr xmlopt;
};


static char *
testQemuMonitorCPUInfoFormat(qemuMonitorCPUInfoPtr vcpus,
                             size_t nvcpus)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    qemuMonitorCPUInfoPtr vcpu;
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

        virBufferAdjustIndent(&buf, -4);
    }

    return virBufferContentAndReset(&buf);
}


static int
testQemuMonitorCPUInfo(const void *opaque)
{
    const struct testCPUInfoData *data = opaque;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, data->xmlopt);
    char *queryCpusFile = NULL;
    char *queryHotpluggableFile = NULL;
    char *dataFile = NULL;
    char *queryCpusStr = NULL;
    char *queryHotpluggableStr = NULL;
    char *actual = NULL;
    qemuMonitorCPUInfoPtr vcpus = NULL;
    int rc;
    int ret = -1;

    if (!test)
        return -1;

    if (virAsprintf(&queryCpusFile,
                    "%s/qemumonitorjsondata/qemumonitorjson-cpuinfo-%s-cpus.json",
                    abs_srcdir, data->name) < 0 ||
        virAsprintf(&queryHotpluggableFile,
                    "%s/qemumonitorjsondata/qemumonitorjson-cpuinfo-%s-hotplug.json",
                    abs_srcdir, data->name) < 0 ||
        virAsprintf(&dataFile,
                    "%s/qemumonitorjsondata/qemumonitorjson-cpuinfo-%s.data",
                    abs_srcdir, data->name) < 0)
        goto cleanup;

    if (virTestLoadFile(queryCpusFile, &queryCpusStr) < 0)
        goto cleanup;

    if (virTestLoadFile(queryHotpluggableFile, &queryHotpluggableStr) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "query-hotpluggable-cpus",
                               queryHotpluggableStr) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "query-cpus", queryCpusStr) < 0)
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
    VIR_FREE(queryCpusFile);
    VIR_FREE(queryHotpluggableFile);
    VIR_FREE(dataFile);
    VIR_FREE(queryCpusStr);
    VIR_FREE(queryHotpluggableStr);
    VIR_FREE(actual);
    qemuMonitorCPUInfoFree(vcpus, data->maxvcpus);
    qemuMonitorTestFree(test);
    return ret;
}


static int
testBlockNodeNameDetectFormat(void *payload,
                              const void *name,
                              void *opaque)
{
    qemuBlockNodeNameBackingChainDataPtr entry = payload;
    const char *diskalias = name;
    virBufferPtr buf = opaque;

    virBufferSetIndent(buf, 0);

    virBufferAdd(buf, diskalias, -1);
    virBufferAddLit(buf, "\n");

    while (entry) {
        virBufferAsprintf(buf, "filename    : '%s'\n", entry->qemufilename);
        virBufferAsprintf(buf, "format node : '%s'\n",
                          NULLSTR(entry->nodeformat));
        virBufferAsprintf(buf, "storage node: '%s'\n",
                          NULLSTR(entry->nodestorage));

        virBufferAdjustIndent(buf, 2);

        entry = entry->backing;
    }

    virBufferSetIndent(buf, 0);
    virBufferAddLit(buf, "\n");
    return 0;
}


static int
testBlockNodeNameDetect(const void *opaque)
{
    const char *testname = opaque;
    const char *pathprefix = "qemumonitorjsondata/qemumonitorjson-nodename-";
    char *resultFile = NULL;
    char *actual = NULL;
    virJSONValuePtr namedNodesJson = NULL;
    virJSONValuePtr blockstatsJson = NULL;
    virHashTablePtr nodedata = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int ret = -1;

    if (virAsprintf(&resultFile, "%s/%s%s.result",
                    abs_srcdir, pathprefix, testname) < 0)
        goto cleanup;

    if (!(namedNodesJson = virTestLoadFileJSON(pathprefix, testname,
                                               "-named-nodes.json", NULL)))
        goto cleanup;

    if (!(blockstatsJson = virTestLoadFileJSON(pathprefix, testname,
                                               "-blockstats.json", NULL)))
        goto cleanup;

    if (!(nodedata = qemuBlockNodeNameGetBackingChain(namedNodesJson,
                                                      blockstatsJson)))
        goto cleanup;

    virHashForEach(nodedata, testBlockNodeNameDetectFormat, &buf);

    virBufferTrim(&buf, "\n", -1);

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToFile(actual, resultFile) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(resultFile);
    VIR_FREE(actual);
    virHashFree(nodedata);
    virJSONValueFree(namedNodesJson);
    virJSONValueFree(blockstatsJson);

    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    virQEMUDriver driver;
    testQemuMonitorJSONSimpleFuncData simpleFunc;

#if !WITH_YAJL
    fputs("libvirt not compiled with yajl, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    if (virThreadInitialize() < 0 ||
        qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

#define DO_TEST(name)                                                          \
    if (virTestRun(# name, testQemuMonitorJSON ## name, driver.xmlopt) < 0)    \
        ret = -1

#define DO_TEST_SIMPLE(CMD, FNC, ...)                                          \
    simpleFunc = (testQemuMonitorJSONSimpleFuncData) {.cmd = CMD, .func = FNC, \
                                       .xmlopt = driver.xmlopt, __VA_ARGS__ }; \
    if (virTestRun(# FNC, testQemuMonitorJSONSimpleFunc, &simpleFunc) < 0)     \
        ret = -1

#define DO_TEST_GEN(name, ...) \
    simpleFunc = (testQemuMonitorJSONSimpleFuncData) {.xmlopt = driver.xmlopt, \
                                                     __VA_ARGS__ };            \
    if (virTestRun(# name, testQemuMonitorJSON ## name, &simpleFunc) < 0)      \
        ret = -1

#define DO_TEST_CPU_DATA(name) \
    do {                                                                  \
        struct testCPUData data = { name, driver.xmlopt };                \
        const char *label = "GetCPUData(" name ")";                       \
        if (virTestRun(label, testQemuMonitorJSONGetCPUData, &data) < 0)  \
            ret = -1;                                                     \
    } while (0)

#define DO_TEST_CPU_INFO(name, maxvcpus)                                       \
    do {                                                                       \
        struct testCPUInfoData data = {name, maxvcpus, driver.xmlopt};         \
        if (virTestRun("GetCPUInfo(" name ")", testQemuMonitorCPUInfo,         \
                       &data) < 0)                                             \
            ret = -1;                                                          \
    } while (0)

    DO_TEST(GetStatus);
    DO_TEST(GetVersion);
    DO_TEST(GetMachines);
    DO_TEST(GetCPUDefinitions);
    DO_TEST(GetCommands);
    DO_TEST(GetTPMModels);
    DO_TEST(GetCommandLineOptionParameters);
    if (qemuMonitorJSONTestAttachChardev(driver.xmlopt) < 0)
        ret = -1;
    DO_TEST(DetachChardev);
    DO_TEST(GetListPaths);
    DO_TEST(GetObjectProperty);
    DO_TEST(SetObjectProperty);
    DO_TEST(GetDeviceAliases);
    DO_TEST(CPU);
    DO_TEST(GetNonExistingCPUData);
    DO_TEST(GetIOThreads);
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
    DO_TEST_GEN(qemuMonitorJSONSetVNCPassword);
    DO_TEST_GEN(qemuMonitorJSONSetPassword);
    DO_TEST_GEN(qemuMonitorJSONExpirePassword);
    DO_TEST_GEN(qemuMonitorJSONSetBalloon);
    DO_TEST_GEN(qemuMonitorJSONSetCPU);
    DO_TEST_GEN(qemuMonitorJSONEjectMedia);
    DO_TEST_GEN(qemuMonitorJSONChangeMedia);
    DO_TEST_GEN(qemuMonitorJSONSaveVirtualMemory);
    DO_TEST_GEN(qemuMonitorJSONSavePhysicalMemory);
    DO_TEST_GEN(qemuMonitorJSONSetMigrationSpeed);
    DO_TEST_GEN(qemuMonitorJSONSetMigrationDowntime);
    DO_TEST_GEN(qemuMonitorJSONMigrate);
    DO_TEST_GEN(qemuMonitorJSONDump);
    DO_TEST_GEN(qemuMonitorJSONGraphicsRelocate);
    DO_TEST_GEN(qemuMonitorJSONAddNetdev);
    DO_TEST_GEN(qemuMonitorJSONRemoveNetdev);
    DO_TEST_GEN(qemuMonitorJSONDelDevice);
    DO_TEST_GEN(qemuMonitorJSONAddDevice);
    DO_TEST_GEN(qemuMonitorJSONSetDrivePassphrase);
    DO_TEST_GEN(qemuMonitorJSONDriveMirror);
    DO_TEST_GEN(qemuMonitorJSONBlockCommit);
    DO_TEST_GEN(qemuMonitorJSONDrivePivot);
    DO_TEST_GEN(qemuMonitorJSONScreendump);
    DO_TEST_GEN(qemuMonitorJSONOpenGraphics);
    DO_TEST_GEN(qemuMonitorJSONNBDServerStart);
    DO_TEST_GEN(qemuMonitorJSONNBDServerAdd);
    DO_TEST_GEN(qemuMonitorJSONDetachCharDev);
    DO_TEST(qemuMonitorJSONGetBalloonInfo);
    DO_TEST(qemuMonitorJSONGetBlockInfo);
    DO_TEST(qemuMonitorJSONGetBlockStatsInfo);
    DO_TEST(qemuMonitorJSONGetMigrationCacheSize);
    DO_TEST(qemuMonitorJSONGetMigrationParams);
    DO_TEST(qemuMonitorJSONGetMigrationStats);
    DO_TEST(qemuMonitorJSONGetChardevInfo);
    DO_TEST(qemuMonitorJSONSetBlockIoThrottle);
    DO_TEST(qemuMonitorJSONGetTargetArch);
    DO_TEST(qemuMonitorJSONGetMigrationCapability);
    DO_TEST(qemuMonitorJSONQueryCPUs);
    DO_TEST(qemuMonitorJSONGetVirtType);
    DO_TEST(qemuMonitorJSONSendKey);
    DO_TEST(qemuMonitorJSONGetDumpGuestMemoryCapability);
    DO_TEST(qemuMonitorJSONSendKeyHoldtime);
    DO_TEST(qemuMonitorSupportsActiveCommit);

    DO_TEST_CPU_DATA("host");
    DO_TEST_CPU_DATA("full");
    DO_TEST_CPU_DATA("ecx");

    DO_TEST_CPU_INFO("x86-basic-pluggable", 8);
    DO_TEST_CPU_INFO("x86-full", 11);
    DO_TEST_CPU_INFO("x86-node-full", 8);

    DO_TEST_CPU_INFO("ppc64-basic", 24);
    DO_TEST_CPU_INFO("ppc64-hotplug-1", 24);
    DO_TEST_CPU_INFO("ppc64-hotplug-2", 24);
    DO_TEST_CPU_INFO("ppc64-hotplug-4", 24);
    DO_TEST_CPU_INFO("ppc64-no-threads", 16);

#define DO_TEST_BLOCK_NODE_DETECT(testname)                                    \
    do {                                                                       \
        if (virTestRun("node-name-detect(" testname ")",                       \
                       testBlockNodeNameDetect, testname) < 0)                 \
            ret = -1;                                                          \
    } while (0)

    DO_TEST_BLOCK_NODE_DETECT("basic");
/*    DO_TEST_BLOCK_NODE_DETECT("same-backing"); */
/*    DO_TEST_BLOCK_NODE_DETECT("relative"); */
/*    DO_TEST_BLOCK_NODE_DETECT("gluster"); */

#undef DO_TEST_BLOCK_NODE_DETECT

    qemuTestDriverFree(&driver);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virdeterministichashmock.so")
