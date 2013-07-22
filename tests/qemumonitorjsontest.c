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


#define VIR_FROM_THIS VIR_FROM_NONE

static int
testQemuMonitorJSONGetStatus(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    const virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    const virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    const virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    const virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    const virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    const virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    const virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
    const virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNew(true, xmlopt);
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
mymain(void)
{
    int ret = 0;
    virDomainXMLOptionPtr xmlopt;

#if !WITH_YAJL
    fputs("libvirt not compiled with yajl, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    if (virThreadInitialize() < 0 ||
        !(xmlopt = virQEMUDriverCreateXMLConf(NULL)))
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

#define DO_TEST(name) \
    if (virtTestRun(# name, 1, testQemuMonitorJSON ## name, xmlopt) < 0) \
        ret = -1

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

    virObjectUnref(xmlopt);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
