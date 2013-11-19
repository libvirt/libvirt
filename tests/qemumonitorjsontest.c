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

#include "testutils.h"
#include "testutilsqemu.h"
#include "qemumonitortestutils.h"
#include "qemu/qemu_conf.h"
#include "qemu/qemu_monitor_json.h"
#include "virthread.h"
#include "virerror.h"
#include "virstring.h"
#include "cpu/cpu.h"


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
    char **cpus = NULL;
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
                               "     \"name\": \"Opteron_G4\" "
                               "   }, "
                               "   { "
                               "     \"name\": \"Westmere\" "
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

#define CHECK(i, wantname)                                              \
    do {                                                                \
        if (STRNEQ(cpus[i], (wantname))) {                              \
            virReportError(VIR_ERR_INTERNAL_ERROR,                      \
                           "name %s is not %s",                         \
                           cpus[i], (wantname));                        \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

    CHECK(0, "qemu64");
    CHECK(1, "Opteron_G4");
    CHECK(2, "Westmere");

#undef CHECK

    ret = 0;

cleanup:
    qemuMonitorTestFree(test);
    for (i = 0; i < ncpus; i++)
        VIR_FREE(cpus[i]);
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
    virStringFreeList(tpmmodels);
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
                                                             &params)) < 0)
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

    virStringFreeList(params);
    params = NULL;

    /* present but empty */
    if ((nparams = qemuMonitorGetCommandLineOptionParameters(qemuMonitorTestGetMonitor(test),
                                                             "acpi",
                                                             &params)) < 0)
        goto cleanup;

    if (nparams != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "nparams was %d, expected 0", nparams);
        goto cleanup;
    }
    if (params && params[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected array contents");
        goto cleanup;
    }

    virStringFreeList(params);
    params = NULL;

    /* no such option */
    if ((nparams = qemuMonitorGetCommandLineOptionParameters(qemuMonitorTestGetMonitor(test),
                                                             "foobar",
                                                             &params)) < 0)
        goto cleanup;

    if (nparams != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "nparams was %d, expected 0", nparams);
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
    virStringFreeList(params);
    return ret;
}

static int
testQemuMonitorJSONAttachChardev(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    virDomainChrSourceDef chr;
    int ret = 0;

    if (!test)
        return -1;

#define DO_CHECK(chrID, reply, fail)                                \
    if (qemuMonitorTestAddItem(test, "chardev-add", reply) < 0)     \
        goto cleanup;                                               \
    if (qemuMonitorAttachCharDev(qemuMonitorTestGetMonitor(test),   \
                                     chrID, &chr) < 0)              \
        ret = fail ? ret  : -1;                                     \
    else                                                            \
        ret = fail ? -1 : ret;                                      \

#define CHECK(chrID, reply) \
    DO_CHECK(chrID, reply, false)

#define CHECK_FAIL(chrID, reply) \
    DO_CHECK(chrID, reply, true)

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_NULL };
    CHECK("chr_null", "{\"return\": {}}");

    chr = (virDomainChrSourceDef) { .type =VIR_DOMAIN_CHR_TYPE_VC };
    CHECK("chr_vc", "{\"return\": {}}");

#define PTY_PATH "/dev/ttyS0"
    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_PTY };
    CHECK("chr_pty", "{\"return\": {\"pty\" : \"" PTY_PATH "\"}}");
    if (STRNEQ_NULLABLE(PTY_PATH, chr.data.file.path)) {
        VIR_FREE(chr.data.file.path);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected PTY path: %s got: %s",
                       PTY_PATH, NULLSTR(chr.data.file.path));
        ret = -1;
    }
    VIR_FREE(chr.data.file.path);

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_PTY };
    CHECK_FAIL("chr_pty_fail", "{\"return\": {}}");
#undef PTY_PATH

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_FILE };
    CHECK("chr_file", "{\"return\": {}}");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_DEV };
    CHECK("chr_dev", "{\"return\": {}}");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_TCP };
    CHECK("chr_tcp", "{\"return\": {}}");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_UDP };
    CHECK("chr_udp", "{\"return\": {}}");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_UNIX };
    CHECK("chr_unix", "{\"return\": {}}");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_SPICEVMC };
    CHECK_FAIL("chr_spicevmc", "{\"return\": {}}");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_PIPE };
    CHECK_FAIL("chr_pipe", "{\"return\": {}}");

    chr = (virDomainChrSourceDef) { .type = VIR_DOMAIN_CHR_TYPE_STDIO };
    CHECK_FAIL("chr_stdio", "{\"return\": {}}");

#undef CHECK
#undef CHECK_FAIL
#undef DO_CHECK

cleanup:
    qemuMonitorTestFree(test);
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
    char **alias;
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
    for (alias = aliases; *alias; alias++) {
        if (!virStringArrayHasString((char **) expected, *alias)) {
            fprintf(stderr, "got unexpected device alias '%s'\n", *alias);
            ret = -1;
        }
    }
    for (alias = (char **) expected; *alias; alias++) {
        if (!virStringArrayHasString(aliases, *alias)) {
            fprintf(stderr, "missing expected alias '%s'\n", *alias);
            ret = -1;
        }
    }

cleanup:
    virStringFreeList(aliases);
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
GEN_TEST_FUNC(qemuMonitorJSONDump, "dummy_protocol")
GEN_TEST_FUNC(qemuMonitorJSONGraphicsRelocate, VIR_DOMAIN_GRAPHICS_TYPE_SPICE,
              "localhost", 12345, 12346, NULL)
GEN_TEST_FUNC(qemuMonitorJSONAddNetdev, "some_dummy_netdevstr")
GEN_TEST_FUNC(qemuMonitorJSONRemoveNetdev, "net0")
GEN_TEST_FUNC(qemuMonitorJSONDelDevice, "ide0")
GEN_TEST_FUNC(qemuMonitorJSONAddDevice, "some_dummy_devicestr")
GEN_TEST_FUNC(qemuMonitorJSONSetDrivePassphrase, "vda", "secret_passhprase")
GEN_TEST_FUNC(qemuMonitorJSONDriveMirror, "vdb", "/foo/bar", NULL, 1024,
              VIR_DOMAIN_BLOCK_REBASE_SHALLOW | VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT)
GEN_TEST_FUNC(qemuMonitorJSONBlockCommit, "vdb", "/foo/bar1", "/foo/bar2", 1024)
GEN_TEST_FUNC(qemuMonitorJSONDrivePivot, "vdb", NULL, NULL)
GEN_TEST_FUNC(qemuMonitorJSONScreendump, "/foo/bar")
GEN_TEST_FUNC(qemuMonitorJSONOpenGraphics, "spice", "spicefd", false)
GEN_TEST_FUNC(qemuMonitorJSONNBDServerStart, "localhost", 12345)
GEN_TEST_FUNC(qemuMonitorJSONNBDServerAdd, "vda", true)
GEN_TEST_FUNC(qemuMonitorJSONDetachCharDev, "serial1")


static int
testQemuMonitorJSONqemuMonitorJSONGetCPUInfo(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    pid_t *cpupids = NULL;
    pid_t expected_cpupids[] = {17622, 17624, 17626, 17628};
    int ncpupids;
    size_t i;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-cpus",
                               "{"
                               "    \"return\": ["
                               "        {"
                               "            \"current\": true,"
                               "            \"CPU\": 0,"
                               "            \"pc\": -2130530478,"
                               "            \"halted\": true,"
                               "            \"thread_id\": 17622"
                               "        },"
                               "        {"
                               "            \"current\": false,"
                               "            \"CPU\": 1,"
                               "            \"pc\": -2130530478,"
                               "            \"halted\": true,"
                               "            \"thread_id\": 17624"
                               "        },"
                               "        {"
                               "            \"current\": false,"
                               "            \"CPU\": 2,"
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

    ncpupids = qemuMonitorJSONGetCPUInfo(qemuMonitorTestGetMonitor(test), &cpupids);

    if (ncpupids != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expecting ncpupids = 4 but got %d", ncpupids);
        goto cleanup;
    }

    for (i = 0; i < ncpupids; i++) {
        if (cpupids[i] != expected_cpupids[i]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "Expecting cpupids[%zu] = %d but got %d",
                           i, expected_cpupids[i], cpupids[i]);
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    VIR_FREE(cpupids);
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
    int virtType;

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

    if (!(blockDevices = virHashCreate(32, (virHashDataFree) free)) ||
        !(expectedBlockDevices = virHashCreate(32, (virHashDataFree) (free))))
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
    if (virHashAddEntry(expectedBlockDevices, "ide0-1-0", info) < 0) {
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
    int ret = -1;
    long long rd_req, rd_bytes, rd_total_times;
    long long wr_req, wr_bytes, wr_total_times;
    long long flush_req, flush_total_times, errs;
    int nparams;
    unsigned long long extent;

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
        qemuMonitorTestAddItem(test, "query-blockstats", reply) < 0 ||
        qemuMonitorTestAddItem(test, "query-blockstats", reply) < 0 ||
        qemuMonitorTestAddItem(test, "query-blockstats", reply) < 0 ||
        qemuMonitorTestAddItem(test, "query-blockstats", reply) < 0)
        goto cleanup;

#define CHECK0(var, value) \
    if (var != value) { \
        virReportError(VIR_ERR_INTERNAL_ERROR, \
                       "Invalid " #var " value: %lld, expected %d", \
                       var, value); \
        goto cleanup; \
    }

#define CHECK(RD_REQ, RD_BYTES, RD_TOTAL_TIMES, WR_REQ, WR_BYTES, WR_TOTAL_TIMES, \
              FLUSH_REQ, FLUSH_TOTAL_TIMES, ERRS) \
    CHECK0(rd_req, RD_REQ) \
    CHECK0(rd_bytes, RD_BYTES) \
    CHECK0(rd_total_times, RD_TOTAL_TIMES) \
    CHECK0(wr_req, WR_REQ) \
    CHECK0(wr_bytes, WR_BYTES) \
    CHECK0(wr_total_times, WR_TOTAL_TIMES) \
    CHECK0(flush_req, FLUSH_REQ) \
    CHECK0(flush_total_times, FLUSH_TOTAL_TIMES) \
    CHECK0(errs, ERRS)

    if (qemuMonitorJSONGetBlockStatsInfo(qemuMonitorTestGetMonitor(test), "virtio-disk0",
                                         &rd_req, &rd_bytes, &rd_total_times,
                                         &wr_req, &wr_bytes, &wr_total_times,
                                         &flush_req, &flush_total_times, &errs) < 0)
        goto cleanup;

    CHECK(1279, 28505088, 640616474, 174, 2845696, 530699221, 0, 0, -1)

    if (qemuMonitorJSONGetBlockStatsInfo(qemuMonitorTestGetMonitor(test), "virtio-disk1",
                                         &rd_req, &rd_bytes, &rd_total_times,
                                         &wr_req, &wr_bytes, &wr_total_times,
                                         &flush_req, &flush_total_times, &errs) < 0)
        goto cleanup;

    CHECK(85, 348160, 8232156, 0, 0, 0, 0, 0, -1)

    if (qemuMonitorJSONGetBlockStatsInfo(qemuMonitorTestGetMonitor(test), "ide0-1-0",
                                         &rd_req, &rd_bytes, &rd_total_times,
                                         &wr_req, &wr_bytes, &wr_total_times,
                                         &flush_req, &flush_total_times, &errs) < 0)
        goto cleanup;

    CHECK(16, 49250, 1004952, 0, 0, 0, 0, 0, -1)

    if (qemuMonitorJSONGetBlockStatsParamsNumber(qemuMonitorTestGetMonitor(test),
                                                 &nparams) < 0)
        goto cleanup;

    if (nparams != 8) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Invalid number of stats: %d, expected 8",
                       nparams);
        goto cleanup;
    }

    if (qemuMonitorJSONGetBlockExtent(qemuMonitorTestGetMonitor(test), "virtio-disk0",
                                      &extent) < 0)
        goto cleanup;

    if (extent != 5256018944ULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Invalid extent: %llu, expected 5256018944",
                       extent);
        goto cleanup;
    }

    if (qemuMonitorJSONGetBlockExtent(qemuMonitorTestGetMonitor(test), "virtio-disk1",
                                      &extent) < 0)
        goto cleanup;

    if (extent != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Invalid extent: %llu, expected 0",
                       extent);
        goto cleanup;
    }

    if (qemuMonitorJSONGetBlockExtent(qemuMonitorTestGetMonitor(test), "ide0-1-0",
                                      &extent) < 0)
        goto cleanup;

    if (extent != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Invalid extent: %llu, expected 0",
                       extent);
        goto cleanup;
    }

    ret = 0;

#undef CHECK
#undef CHECK0

cleanup:
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
testQemuMonitorJSONqemuMonitorJSONGetMigrationStatus(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    qemuMonitorMigrationStatus status, expectedStatus;

    if (!test)
        return -1;

    memset(&expectedStatus, 0, sizeof(expectedStatus));

    expectedStatus.status = QEMU_MONITOR_MIGRATION_STATUS_ACTIVE;
    expectedStatus.total_time = 47;
    expectedStatus.ram_total = 1611038720;
    expectedStatus.ram_remaining = 1605013504;
    expectedStatus.ram_transferred = 3625548;

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

    if (qemuMonitorJSONGetMigrationStatus(qemuMonitorTestGetMonitor(test), &status) < 0)
        goto cleanup;

    if (memcmp(&status, &expectedStatus, sizeof(status)) != 0) {
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
testQemuMonitorJSONqemuMonitorJSONGetSpiceMigrationStatus(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    bool spiceMigrated;

    if (!test)
        return -1;

    if (qemuMonitorTestAddItem(test, "query-spice",
                               "{"
                               "    \"return\": {"
                               "        \"migrated\": true,"
                               "        \"enabled\": false,"
                               "        \"mouse-mode\": \"client\""
                               "    },"
                               "    \"id\": \"libvirt-14\""
                               "}") < 0)
        goto cleanup;

    if (qemuMonitorJSONGetSpiceMigrationStatus(qemuMonitorTestGetMonitor(test),
                                               &spiceMigrated) < 0)
        goto cleanup;

    if (!spiceMigrated) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Invalid spice migration status: %d, expecting 1",
                       spiceMigrated);
        goto cleanup;
    }

    ret = 0;
cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

static int
testHashEqualString(const void *value1, const void *value2)
{
    return strcmp(value1, value2);
}

static int
testQemuMonitorJSONqemuMonitorJSONGetPtyPaths(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(true, xmlopt);
    int ret = -1;
    virHashTablePtr paths = NULL, expectedPaths = NULL;

    if (!test)
        return -1;

    if (!(paths = virHashCreate(32, (virHashDataFree) free)) ||
        !(expectedPaths = virHashCreate(32, NULL)))
        goto cleanup;

    if (virHashAddEntry(expectedPaths, "charserial1", (void *) "/dev/pts/21") < 0 ||
        virHashAddEntry(expectedPaths, "charserial0", (void *) "/dev/pts/20") < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Unable to create expectedPaths hash table");
        goto cleanup;
    }

    if (qemuMonitorTestAddItem(test, "query-chardev",
                               "{"
                               "    \"return\": ["
                               "        {"
                               "            \"filename\": \"pty:/dev/pts/21\","
                               "            \"label\": \"charserial1\""
                               "        },"
                               "        {"
                               "            \"filename\": \"pty:/dev/pts/20\","
                               "            \"label\": \"charserial0\""
                               "        },"
                               "        {"
                               "            \"filename\": \"unix:/var/lib/libvirt/qemu/gentoo.monitor,server\","
                               "            \"label\": \"charmonitor\""
                               "        }"
                               "    ],"
                               "    \"id\": \"libvirt-15\""
                               "}") < 0)
        goto cleanup;

    if (qemuMonitorJSONGetPtyPaths(qemuMonitorTestGetMonitor(test),
                                   paths) < 0)
        goto cleanup;

    if (!virHashEqual(paths, expectedPaths, testHashEqualString)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Hashtable is different to the expected one");
        goto cleanup;
    }

    ret = 0;
cleanup:
    virHashFree(paths);
    virHashFree(expectedPaths);
    qemuMonitorTestFree(test);
    return ret;
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

    expectedInfo = (virDomainBlockIoTuneInfo) {1, 2, 3, 4, 5, 6};

    if (qemuMonitorTestAddItem(test, "query-block", queryBlockReply) < 0 ||
        qemuMonitorTestAddItemParams(test, "block_set_io_throttle",
                                     "{\"return\":{}}",
                                     "device", "\"drive-virtio-disk1\"",
                                     "bps", "1", "bps_rd", "2", "bps_wr", "3",
                                     "iops", "4", "iops_rd", "5", "iops_wr", "6",
                                     NULL, NULL) < 0)
        goto cleanup;

    if (qemuMonitorJSONGetBlockIoThrottle(qemuMonitorTestGetMonitor(test),
                                          "drive-virtio-disk0", &info) < 0)
        goto cleanup;

    if (memcmp(&info, &expectedInfo, sizeof(info) != 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Invalid @info");
        goto cleanup;
    }

    if (qemuMonitorJSONSetBlockIoThrottle(qemuMonitorTestGetMonitor(test),
                                          "drive-virtio-disk1", &info) < 0)
        goto cleanup;

    ret = 0;
cleanup:
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
                                              QEMU_MONITOR_MIGRATION_CAPS_XBZRLE) < 0)
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
    char *expected = NULL;
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

    if (virtTestLoadFile(jsonFile, &jsonStr) < 0 ||
        virtTestLoadFile(dataFile, &expected) < 0)
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
                                   &cpuData) < 0)
        goto cleanup;

    if (!(actual = cpuDataFormat(cpuData)))
        goto cleanup;

    if (STRNEQ(expected, actual)) {
        virtTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(jsonFile);
    VIR_FREE(dataFile);
    VIR_FREE(jsonStr);
    VIR_FREE(expected);
    VIR_FREE(actual);
    cpuDataFree(cpuData);
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
                                   &cpuData);
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
    cpuDataFree(cpuData);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;
    virDomainXMLOptionPtr xmlopt;
    testQemuMonitorJSONSimpleFuncData simpleFunc;

#if !WITH_YAJL
    fputs("libvirt not compiled with yajl, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    if (virThreadInitialize() < 0 ||
        !(xmlopt = virQEMUDriverCreateXMLConf(NULL)))
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

#define DO_TEST(name)                                                   \
    if (virtTestRun(# name, testQemuMonitorJSON ## name, xmlopt) < 0)   \
        ret = -1

#define DO_TEST_SIMPLE(CMD, FNC, ...)                                   \
    simpleFunc = (testQemuMonitorJSONSimpleFuncData) {.cmd = CMD, .func = FNC, \
                                              .xmlopt = xmlopt, __VA_ARGS__ }; \
    if (virtTestRun(# FNC, testQemuMonitorJSONSimpleFunc, &simpleFunc) < 0)    \
        ret = -1

#define DO_TEST_GEN(name, ...) \
    simpleFunc = (testQemuMonitorJSONSimpleFuncData) {.xmlopt = xmlopt, __VA_ARGS__ }; \
    if (virtTestRun(# name, testQemuMonitorJSON ## name, &simpleFunc) < 0) \
        ret = -1

#define DO_TEST_CPU_DATA(name) \
    do {                                                                  \
        struct testCPUData data = { name, xmlopt };                       \
        const char *label = "GetCPUData(" name ")";                       \
        if (virtTestRun(label, testQemuMonitorJSONGetCPUData, &data) < 0) \
            ret = -1;                                                     \
    } while (0)

    DO_TEST(GetStatus);
    DO_TEST(GetVersion);
    DO_TEST(GetMachines);
    DO_TEST(GetCPUDefinitions);
    DO_TEST(GetCommands);
    DO_TEST(GetTPMModels);
    DO_TEST(GetCommandLineOptionParameters);
    DO_TEST(AttachChardev);
    DO_TEST(DetachChardev);
    DO_TEST(GetListPaths);
    DO_TEST(GetObjectProperty);
    DO_TEST(SetObjectProperty);
    DO_TEST(GetDeviceAliases);
    DO_TEST(CPU);
    DO_TEST(GetNonExistingCPUData);
    DO_TEST_SIMPLE("qmp_capabilities", qemuMonitorJSONSetCapabilities);
    DO_TEST_SIMPLE("system_powerdown", qemuMonitorJSONSystemPowerdown);
    DO_TEST_SIMPLE("system_reset", qemuMonitorJSONSystemReset);
    DO_TEST_SIMPLE("migrate_cancel", qemuMonitorJSONMigrateCancel);
    DO_TEST_SIMPLE("inject-nmi", qemuMonitorJSONInjectNMI);
    DO_TEST_SIMPLE("system_wakeup", qemuMonitorJSONSystemWakeup);
    DO_TEST_SIMPLE("nbd-server-stop", qemuMonitorJSONNBDServerStop);
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
    DO_TEST(qemuMonitorJSONGetMigrationStatus);
    DO_TEST(qemuMonitorJSONGetSpiceMigrationStatus);
    DO_TEST(qemuMonitorJSONGetPtyPaths);
    DO_TEST(qemuMonitorJSONSetBlockIoThrottle);
    DO_TEST(qemuMonitorJSONGetTargetArch);
    DO_TEST(qemuMonitorJSONGetMigrationCapability);
    DO_TEST(qemuMonitorJSONGetCPUInfo);
    DO_TEST(qemuMonitorJSONGetVirtType);
    DO_TEST(qemuMonitorJSONSendKey);

    DO_TEST_CPU_DATA("host");
    DO_TEST_CPU_DATA("full");

    virObjectUnref(xmlopt);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
