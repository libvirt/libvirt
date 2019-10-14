/*
 * Copyright (C) 2013, 2014 Red Hat, Inc.
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
#include "qemu/qemu_agent.h"
#include "virthread.h"
#include "virerror.h"
#include "virstring.h"


#define VIR_FROM_THIS VIR_FROM_NONE


virQEMUDriver driver;


static int
testQemuAgentFSFreeze(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    const char *mountpoints[] = {"/fs1", "/fs2", "/fs3", "/fs4", "/fs5"};
    int ret = -1;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-fsfreeze-freeze-list",
                               "{ \"return\" : 5 }") < 0)
        goto cleanup;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-fsfreeze-freeze",
                               "{ \"return\" : 7 }") < 0)
        goto cleanup;

    if ((ret = qemuAgentFSFreeze(qemuMonitorTestGetAgent(test),
                                 mountpoints, 5)) < 0)
        goto cleanup;

    if (ret != 5) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 5 frozen filesystems, got %d", ret);
        goto cleanup;
    }

    if ((ret = qemuAgentFSFreeze(qemuMonitorTestGetAgent(test), NULL, 0)) < 0)
        goto cleanup;

    if (ret != 7) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 7 frozen filesystems, got %d", ret);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}


static int
testQemuAgentFSThaw(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    int ret = -1;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-fsfreeze-thaw",
                               "{ \"return\" : 5 }") < 0)
        goto cleanup;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-fsfreeze-thaw",
                               "{ \"return\" : 7 }") < 0)
        goto cleanup;

    if ((ret = qemuAgentFSThaw(qemuMonitorTestGetAgent(test))) < 0)
        goto cleanup;

    if (ret != 5) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 5 thawed filesystems, got %d", ret);
        goto cleanup;
    }

    if ((ret = qemuAgentFSThaw(qemuMonitorTestGetAgent(test))) < 0)
        goto cleanup;

    if (ret != 7) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 7 thawed filesystems, got %d", ret);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}


static int
testQemuAgentFSTrim(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    int ret = -1;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItemParams(test, "guest-fstrim",
                                     "{ \"return\" : {} }",
                                     "minimum", "1337",
                                     NULL) < 0)
        goto cleanup;

    if (qemuAgentFSTrim(qemuMonitorTestGetAgent(test), 1337) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}


static int
testQemuAgentGetFSInfoCommon(virDomainXMLOptionPtr xmlopt,
                             qemuMonitorTestPtr *test,
                             virDomainDefPtr *def)
{
    int ret = -1;
    char *domain_filename = NULL;
    qemuMonitorTestPtr ret_test = NULL;
    virDomainDefPtr ret_def = NULL;

    if (!test || !def)
        return -1;

    if (!(ret_test = qemuMonitorTestNewAgent(xmlopt)))
        return -1;

    if (virAsprintf(&domain_filename, "%s/qemuagentdata/fsinfo.xml",
                    abs_srcdir) < 0)
        goto cleanup;

    if (!(ret_def = virDomainDefParseFile(domain_filename, driver.caps, xmlopt,
                                          NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto cleanup;

    if (qemuMonitorTestAddAgentSyncResponse(ret_test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(ret_test, "guest-get-fsinfo",
                               "{\"return\": ["
                               "  {\"name\": \"sda1\", \"mountpoint\": \"/\","
                               "   \"total-bytes\":952840192,"
                               "   \"used-bytes\":229019648,"
                               "   \"disk\": ["
                               "     {\"serial\": \"ARBITRARYSTRING\","
                               "      \"bus-type\": \"ide\","
                               "      \"bus\": 1, \"unit\": 0,"
                               "      \"pci-controller\": {"
                               "        \"bus\": 0, \"slot\": 1,"
                               "        \"domain\": 0, \"function\": 1},"
                               "      \"dev\": \"/dev/sda1\","
                               "      \"target\": 0}],"
                               "   \"type\": \"ext4\"},"
                               "  {\"name\": \"dm-1\","
                               "   \"mountpoint\": \"/opt\","
                               "   \"disk\": ["
                               "     {\"bus-type\": \"virtio\","
                               "      \"bus\": 0, \"unit\": 0,"
                               "      \"pci-controller\": {"
                               "        \"bus\": 0, \"slot\": 6,"
                               "        \"domain\": 0, \"function\": 0},"
                               "      \"target\": 0},"
                               "     {\"bus-type\": \"virtio\","
                               "      \"bus\": 0, \"unit\": 0,"
                               "      \"pci-controller\": {"
                               "        \"bus\": 0, \"slot\": 7,"
                               "        \"domain\": 0, \"function\": 0},"
                               "      \"target\": 0}],"
                               "   \"type\": \"vfat\"},"
                               "  {\"name\": \"sdb1\","
                               "   \"mountpoint\": \"/mnt/disk\","
                               "   \"disk\": [], \"type\": \"xfs\"}]}") < 0)
                               goto cleanup;

    VIR_STEAL_PTR(*test, ret_test);
    VIR_STEAL_PTR(*def, ret_def);
    ret = 0;

 cleanup:
    VIR_FREE(domain_filename);
    if (ret_test)
        qemuMonitorTestFree(ret_test);
    virDomainDefFree(ret_def);

    return ret;
}

static int
testQemuAgentGetFSInfo(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = NULL;
    virDomainDefPtr def = NULL;
    virDomainFSInfoPtr *info = NULL;
    int ret = -1, ninfo = 0, i;

    if (testQemuAgentGetFSInfoCommon(xmlopt, &test, &def) < 0)
        goto cleanup;

    if ((ninfo = qemuAgentGetFSInfo(qemuMonitorTestGetAgent(test),
                                    &info, def)) < 0)
        goto cleanup;

    if (ninfo != 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 3 filesystems information, got %d", ninfo);
        ret = -1;
        goto cleanup;
    }
    if (STRNEQ(info[2]->name, "sda1") ||
        STRNEQ(info[2]->mountpoint, "/") ||
        STRNEQ(info[2]->fstype, "ext4") ||
        info[2]->ndevAlias != 1 ||
        !info[2]->devAlias || !info[2]->devAlias[0] ||
        STRNEQ(info[2]->devAlias[0], "hdc")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "unexpected filesystems information returned for sda1 (%s,%s)",
            info[2]->name, info[2]->devAlias ? info[2]->devAlias[0] : "null");
        ret = -1;
        goto cleanup;
    }
    if (STRNEQ(info[1]->name, "dm-1") ||
        STRNEQ(info[1]->mountpoint, "/opt") ||
        STRNEQ(info[1]->fstype, "vfat") ||
        info[1]->ndevAlias != 2 ||
        !info[1]->devAlias || !info[1]->devAlias[0] || !info[1]->devAlias[1] ||
        STRNEQ(info[1]->devAlias[0], "vda") ||
        STRNEQ(info[1]->devAlias[1], "vdb")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "unexpected filesystems information returned for dm-1 (%s,%s)",
            info[0]->name, info[0]->devAlias ? info[0]->devAlias[0] : "null");
        ret = -1;
        goto cleanup;
    }
    if (STRNEQ(info[0]->name, "sdb1") ||
        STRNEQ(info[0]->mountpoint, "/mnt/disk") ||
        STRNEQ(info[0]->fstype, "xfs") ||
        info[0]->ndevAlias != 0 || info[0]->devAlias) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "unexpected filesystems information returned for sdb1 (%s,%s)",
            info[0]->name, info[0]->devAlias ? info[0]->devAlias[0] : "null");
        ret = -1;
        goto cleanup;
    }

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-get-fsinfo",
                               "{\"error\":"
                               "    {\"class\":\"CommandDisabled\","
                               "     \"desc\":\"The command guest-get-fsinfo "
                                               "has been disabled for "
                                               "this instance\","
                               "     \"data\":{\"name\":\"guest-get-fsinfo\"}"
                               "    }"
                               "}") < 0)
        goto cleanup;

    if (qemuAgentGetFSInfo(qemuMonitorTestGetAgent(test), &info, def) != -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "agent get-fsinfo command should have failed");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    for (i = 0; i < ninfo; i++)
        virDomainFSInfoFree(info[i]);
    VIR_FREE(info);
    virDomainDefFree(def);
    qemuMonitorTestFree(test);
    return ret;
}

static int
testQemuAgentGetFSInfoParams(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = NULL;
    virDomainDefPtr def = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0, maxparams = 0;
    int ret = -1;
    unsigned int count;
    const char *name, *mountpoint, *fstype, *alias, *serial;
    unsigned int diskcount;
    unsigned long long bytesused, bytestotal;
    const char *alias2;

    if (testQemuAgentGetFSInfoCommon(xmlopt, &test, &def) < 0)
        goto cleanup;

    if (qemuAgentGetFSInfoParams(qemuMonitorTestGetAgent(test),
                                 &params, &nparams, &maxparams, def) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Failed to execute qemuAgentGetFSInfoParams()");
        goto cleanup;
    }

    if (virTypedParamsGetUInt(params, nparams, "fs.count", &count) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "expected filesystem count");
        goto cleanup;
    }

    if (count != 3) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 3 filesystems information, got %d", count);
        goto cleanup;
    }

    if (virTypedParamsGetString(params, nparams, "fs.2.name", &name) < 0 ||
        virTypedParamsGetString(params, nparams, "fs.2.mountpoint", &mountpoint) < 0 ||
        virTypedParamsGetString(params, nparams, "fs.2.fstype", &fstype) < 0 ||
        virTypedParamsGetULLong(params, nparams, "fs.2.used-bytes", &bytesused) <= 0 ||
        virTypedParamsGetULLong(params, nparams, "fs.2.total-bytes", &bytestotal) <= 0 ||
        virTypedParamsGetUInt(params, nparams, "fs.2.disk.count", &diskcount) < 0 ||
        virTypedParamsGetString(params, nparams, "fs.2.disk.0.alias", &alias) < 0 ||
        virTypedParamsGetString(params, nparams, "fs.2.disk.0.serial", &serial) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "Missing an expected parameter for sda1 (%s,%s)",
            name, alias);
        goto cleanup;
    }

    if (STRNEQ(name, "sda1") ||
        STRNEQ(mountpoint, "/") ||
        STRNEQ(fstype, "ext4") ||
        bytesused != 229019648 ||
        bytestotal != 952840192 ||
        diskcount != 1 ||
        STRNEQ(alias, "hdc") ||
        STRNEQ(serial, "ARBITRARYSTRING")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "unexpected filesystems information returned for sda1 (%s,%s)",
            name, alias);
        goto cleanup;
    }

    if (virTypedParamsGetString(params, nparams, "fs.1.name", &name) < 0 ||
        virTypedParamsGetString(params, nparams, "fs.1.mountpoint", &mountpoint) < 0 ||
        virTypedParamsGetString(params, nparams, "fs.1.fstype", &fstype) < 0 ||
        virTypedParamsGetULLong(params, nparams, "fs.1.used-bytes", &bytesused) == 1 ||
        virTypedParamsGetULLong(params, nparams, "fs.1.total-bytes", &bytestotal) == 1 ||
        virTypedParamsGetUInt(params, nparams, "fs.1.disk.count", &diskcount) < 0 ||
        virTypedParamsGetString(params, nparams, "fs.1.disk.0.alias", &alias) < 0 ||
        virTypedParamsGetString(params, nparams, "fs.1.disk.1.alias", &alias2) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "Incorrect parameters for dm-1 (%s,%s)",
            name, alias);
        goto cleanup;
    }
    if (STRNEQ(name, "dm-1") ||
        STRNEQ(mountpoint, "/opt") ||
        STRNEQ(fstype, "vfat") ||
        diskcount != 2 ||
        STRNEQ(alias, "vda") ||
        STRNEQ(alias2, "vdb")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "unexpected filesystems information returned for dm-1 (%s,%s)",
            name, alias);
        goto cleanup;
    }

    alias = NULL;
    if (virTypedParamsGetString(params, nparams, "fs.0.name", &name) < 0 ||
        virTypedParamsGetString(params, nparams, "fs.0.mountpoint", &mountpoint) < 0 ||
        virTypedParamsGetString(params, nparams, "fs.0.fstype", &fstype) < 0 ||
        virTypedParamsGetULLong(params, nparams, "fs.0.used-bytes", &bytesused) == 1 ||
        virTypedParamsGetULLong(params, nparams, "fs.0.total-bytes", &bytestotal) == 1 ||
        virTypedParamsGetUInt(params, nparams, "fs.0.disk.count", &diskcount) < 0 ||
        virTypedParamsGetString(params, nparams, "fs.0.disk.0.alias", &alias) == 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "Incorrect parameters for sdb1 (%s,%s)",
            name, alias);
        goto cleanup;
    }

    if (STRNEQ(name, "sdb1") ||
        STRNEQ(mountpoint, "/mnt/disk") ||
        STRNEQ(fstype, "xfs") ||
        diskcount != 0 ||
        alias != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "unexpected filesystems information returned for sdb1 (%s,%s)",
            name, alias);
        goto cleanup;
    }

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-get-fsinfo",
                               "{\"error\":"
                               "    {\"class\":\"CommandDisabled\","
                               "     \"desc\":\"The command guest-get-fsinfo "
                                               "has been disabled for "
                                               "this instance\","
                               "     \"data\":{\"name\":\"guest-get-fsinfo\"}"
                               "    }"
                               "}") < 0)
        goto cleanup;

    if (qemuAgentGetFSInfoParams(qemuMonitorTestGetAgent(test), &params,
                                 &nparams, &maxparams, def) != -2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "agent get-fsinfo command should have failed");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virTypedParamsFree(params, nparams);
    virDomainDefFree(def);
    qemuMonitorTestFree(test);
    return ret;
}


static int
testQemuAgentSuspend(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    int ret = -1;
    size_t i;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-suspend-ram",
                               "{ \"return\" : {} }") < 0)
        goto cleanup;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-suspend-disk",
                               "{ \"return\" : {} }") < 0)
        goto cleanup;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-suspend-hybrid",
                               "{ \"return\" : {} }") < 0)
        goto cleanup;

    /* try the commands - fail if ordering changes */
    for (i = 0; i < VIR_NODE_SUSPEND_TARGET_LAST; i++) {
        if (qemuAgentSuspend(qemuMonitorTestGetAgent(test), i) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}


struct qemuAgentShutdownTestData {
    const char *mode;
    qemuAgentEvent event;
};


static int
qemuAgentShutdownTestMonitorHandler(qemuMonitorTestPtr test,
                                    qemuMonitorTestItemPtr item,
                                    const char *cmdstr)
{
    struct qemuAgentShutdownTestData *data;
    virJSONValuePtr val = NULL;
    virJSONValuePtr args;
    const char *cmdname;
    const char *mode;
    int ret = -1;

    data = qemuMonitorTestItemGetPrivateData(item);

    if (!(val = virJSONValueFromString(cmdstr)))
        return -1;

    if (!(cmdname = virJSONValueObjectGetString(val, "execute"))) {
        ret = qemuMonitorReportError(test, "Missing command name in %s", cmdstr);
        goto cleanup;
    }

    if (STRNEQ(cmdname, "guest-shutdown")) {
        ret = qemuMonitorTestAddInvalidCommandResponse(test, "guest-shutdown",
                                                       cmdname);
        goto cleanup;
    }

    if (!(args = virJSONValueObjectGet(val, "arguments"))) {
        ret = qemuMonitorReportError(test,
                                     "Missing arguments section");
        goto cleanup;
    }

    if (!(mode = virJSONValueObjectGetString(args, "mode"))) {
        ret = qemuMonitorReportError(test, "Missing shutdown mode");
        goto cleanup;
    }

    if (STRNEQ(mode, data->mode)) {
        ret = qemuMonitorReportError(test,
                                     "expected shutdown mode '%s' got '%s'",
                                     data->mode, mode);
        goto cleanup;
    }

    /* now don't reply but return a qemu agent event */
    qemuAgentNotifyEvent(qemuMonitorTestGetAgent(test),
                         data->event);

    ret = 0;

 cleanup:
    virJSONValueFree(val);
    return ret;

}


static int
testQemuAgentShutdown(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    struct qemuAgentShutdownTestData priv;
    int ret = -1;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    priv.event = QEMU_AGENT_EVENT_SHUTDOWN;
    priv.mode = "halt";

    if (qemuMonitorTestAddHandler(test, qemuAgentShutdownTestMonitorHandler,
                                  &priv, NULL) < 0)
        goto cleanup;

    if (qemuAgentShutdown(qemuMonitorTestGetAgent(test),
                          QEMU_AGENT_SHUTDOWN_HALT) < 0)
        goto cleanup;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    priv.event = QEMU_AGENT_EVENT_SHUTDOWN;
    priv.mode = "powerdown";

    if (qemuMonitorTestAddHandler(test, qemuAgentShutdownTestMonitorHandler,
                                  &priv, NULL) < 0)
        goto cleanup;

    if (qemuAgentShutdown(qemuMonitorTestGetAgent(test),
                          QEMU_AGENT_SHUTDOWN_POWERDOWN) < 0)
        goto cleanup;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    priv.event = QEMU_AGENT_EVENT_RESET;
    priv.mode = "reboot";

    if (qemuMonitorTestAddHandler(test, qemuAgentShutdownTestMonitorHandler,
                                  &priv, NULL) < 0)
        goto cleanup;

    if (qemuAgentShutdown(qemuMonitorTestGetAgent(test),
                          QEMU_AGENT_SHUTDOWN_REBOOT) < 0)
        goto cleanup;

    /* check negative response, so that we can verify that the agent breaks
     * out from sleep */

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-shutdown",
                               "{\"error\":"
                               "    {\"class\":\"CommandDisabled\","
                               "     \"desc\":\"The command guest-shutdown has "
                                               "been disabled for this instance\","
                               "     \"data\":{\"name\":\"guest-shutdown\"}"
                               "    }"
                               "}") < 0)
        goto cleanup;

    if (qemuAgentShutdown(qemuMonitorTestGetAgent(test),
                          QEMU_AGENT_SHUTDOWN_REBOOT) != -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "agent shutdown command should have failed");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}


static const char testQemuAgentCPUResponse[] =
    "{\"return\": "
    "   ["
    "       {\"online\": true,"
    "        \"can-offline\": false,"
    "        \"logical-id\": 0"
    "       },"
    "       {\"online\": true,"
    "        \"can-offline\": true,"
    "        \"logical-id\": 1"
    "       },"
    "       {\"online\": true,"
    "        \"can-offline\": true,"
    "        \"logical-id\": 2"
    "        },"
    "       {\"online\": false,"
    "        \"can-offline\": true,"
    "        \"logical-id\": 3"
    "       }"
    "   ]"
    "}";

static const char testQemuAgentCPUArguments1[] =
    "[{\"logical-id\":1,\"online\":false}]";

static const char testQemuAgentCPUArguments2[] =
    "[{\"logical-id\":1,\"online\":true},"
     "{\"logical-id\":3,\"online\":true}]";

static const char testQemuAgentCPUArguments3[] =
    "[{\"logical-id\":3,\"online\":true}]";

static int
testQemuAgentCPU(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    qemuAgentCPUInfoPtr cpuinfo = NULL;
    int nvcpus;
    int ret = -1;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-get-vcpus",
                               testQemuAgentCPUResponse) < 0)
        goto cleanup;

    /* get cpus */
    if ((nvcpus = qemuAgentGetVCPUs(qemuMonitorTestGetAgent(test),
                                    &cpuinfo)) < 0)
        goto cleanup;

    if (nvcpus != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected '4' cpus, got '%d'", nvcpus);
        goto cleanup;
    }

    /* try to unplug one */
    if (qemuAgentUpdateCPUInfo(2, cpuinfo, nvcpus) < 0)
        goto cleanup;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItemParams(test, "guest-set-vcpus",
                                     "{ \"return\" : 1 }",
                                     "vcpus", testQemuAgentCPUArguments1,
                                     NULL) < 0)
        goto cleanup;

    if (qemuAgentSetVCPUs(qemuMonitorTestGetAgent(test), cpuinfo, nvcpus) < 0)
        goto cleanup;

    /* try to hotplug two, second one will fail*/
    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItemParams(test, "guest-set-vcpus",
                                     "{ \"return\" : 1 }",
                                     "vcpus", testQemuAgentCPUArguments2,
                                     NULL) < 0)
        goto cleanup;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItemParams(test, "guest-set-vcpus",
                                     "{ \"error\" : \"random error\" }",
                                     "vcpus", testQemuAgentCPUArguments3,
                                     NULL) < 0)
        goto cleanup;

    if (qemuAgentUpdateCPUInfo(4, cpuinfo, nvcpus) < 0)
        goto cleanup;

    /* this should fail */
    if (qemuAgentSetVCPUs(qemuMonitorTestGetAgent(test), cpuinfo, nvcpus) != -1)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(cpuinfo);
    qemuMonitorTestFree(test);
    return ret;
}


static const char testQemuAgentArbitraryCommandResponse[] =
    "{\"return\":\"bla\"}";

static int
testQemuAgentArbitraryCommand(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    int ret = -1;
    char *reply = NULL;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "ble",
                               testQemuAgentArbitraryCommandResponse) < 0)
        goto cleanup;

    if (qemuAgentArbitraryCommand(qemuMonitorTestGetAgent(test),
                                  "{\"execute\":\"ble\"}",
                                  &reply,
                                  VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) < 0)
        goto cleanup;

    if (STRNEQ(reply, testQemuAgentArbitraryCommandResponse)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "invalid processing of guest agent reply: "
                       "got '%s' expected '%s'",
                       reply, testQemuAgentArbitraryCommandResponse);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(reply);
    qemuMonitorTestFree(test);
    return ret;
}


static int
qemuAgentTimeoutTestMonitorHandler(qemuMonitorTestPtr test G_GNUC_UNUSED,
                                   qemuMonitorTestItemPtr item G_GNUC_UNUSED,
                                   const char *cmdstr G_GNUC_UNUSED)
{
    return 0;
}


static int
testQemuAgentTimeout(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    char *reply = NULL;
    int ret = -1;

    if (!test)
        return -1;

    if (virTestGetExpensive() == 0) {
        ret = EXIT_AM_SKIP;
        goto cleanup;
    }

    if (qemuMonitorTestAddHandler(test, qemuAgentTimeoutTestMonitorHandler,
                                  NULL, NULL) < 0)
        goto cleanup;

    if (qemuAgentFSFreeze(qemuMonitorTestGetAgent(test), NULL, 0) != -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "agent command should have failed");
        goto cleanup;
    }

    /* test timeout */
    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddHandler(test, qemuAgentTimeoutTestMonitorHandler,
                                  NULL, NULL) < 0)
        goto cleanup;

    if (qemuAgentArbitraryCommand(qemuMonitorTestGetAgent(test),
                                  "{\"execute\":\"ble\"}",
                                  &reply,
                                  1) != -2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "agent command didn't time out");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(reply);
    qemuMonitorTestFree(test);
    return ret;
}

static const char testQemuAgentGetInterfacesResponse[] =
    "{\"return\": "
    "    ["
    "       {\"name\":\"eth2\","
    "        \"hardware-address\":\"52:54:00:36:2a:e5\""
    "       },"
    "       {\"name\":\"eth1:0\","
    "        \"ip-addresses\":"
    "          ["
    "             {\"ip-address-type\":\"ipv4\","
    "              \"ip-address\":\"192.168.10.91\","
    "              \"prefix\":24"
    "             },"
    "             {\"ip-address-type\":\"ipv6\","
    "              \"ip-address\":\"fe80::fc54:ff:fefe:4c4f\","
    "              \"prefix\":64"
    "             }"
    "          ],"
    "        \"hardware-address\":\"52:54:00:d3:39:ee\""
    "       },"
    "       {\"name\":\"eth0\","
    "        \"ip-addresses\":"
    "          ["
    "             {\"ip-address-type\":\"ipv6\","
    "              \"ip-address\":\"fe80::5054:ff:fe89:ad35\","
    "              \"prefix\":64"
    "             },"
    "             {\"ip-address-type\":\"ipv4\","
    "              \"ip-address\":\"192.168.102.142\","
    "              \"prefix\":24"
    "             },"
    "             {\"ip-address-type\":\"ipv4\","
    "              \"ip-address\":\"192.168.234.152\","
    "              \"prefix\":16"
    "             },"
    "             {\"ip-address-type\":\"ipv6\","
    "              \"ip-address\":\"fe80::5054:ff:fec3:68bb\","
    "              \"prefix\":64"
    "             }"
    "          ],"
    "        \"hardware-address\":\"52:54:00:89:ad:35\""
    "       },"
    "       {\"name\":\"eth1\","
    "        \"ip-addresses\":"
    "          ["
    "             {\"ip-address-type\":\"ipv4\","
    "              \"ip-address\":\"192.168.103.83\","
    "              \"prefix\":32"
    "             },"
    "             {\"ip-address-type\":\"ipv6\","
    "              \"ip-address\":\"fe80::5054:ff:fed3:39ee\","
    "              \"prefix\":64"
    "             }"
    "          ],"
    "        \"hardware-address\":\"52:54:00:d3:39:ee\""
    "       },"
    "       {\"name\":\"lo\","
    "        \"ip-addresses\":"
    "          ["
    "             {\"ip-address-type\":\"ipv4\","
    "              \"ip-address\":\"127.0.0.1\","
    "              \"prefix\":8"
    "             },"
    "             {\"ip-address-type\":\"ipv6\","
    "              \"ip-address\":\"::1\","
    "              \"prefix\":128"
    "             }"
    "          ],"
    "        \"hardware-address\":\"00:00:00:00:00:00\""
    "       }"
    "    ]"
    "}";

static int
testQemuAgentGetInterfaces(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    size_t i;
    int ret = -1;
    int ifaces_count = 0;
    virDomainInterfacePtr *ifaces = NULL;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-network-get-interfaces",
                               testQemuAgentGetInterfacesResponse) < 0)
        goto cleanup;

    if ((ifaces_count = qemuAgentGetInterfaces(qemuMonitorTestGetAgent(test),
                                               &ifaces)) < 0)
        goto cleanup;

    if (ifaces_count != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 4 interfaces, got %d", ret);
        goto cleanup;
    }

    if (STRNEQ(ifaces[0]->name, "eth2") ||
        STRNEQ(ifaces[1]->name, "eth1") ||
        STRNEQ(ifaces[2]->name, "eth0") ||
        STRNEQ(ifaces[3]->name, "lo")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected return values for interface names");
        goto cleanup;
    }

    if (STRNEQ(ifaces[0]->hwaddr, "52:54:00:36:2a:e5") ||
        STRNEQ(ifaces[1]->hwaddr, "52:54:00:d3:39:ee") ||
        STRNEQ(ifaces[2]->hwaddr, "52:54:00:89:ad:35") ||
        STRNEQ(ifaces[3]->hwaddr, "00:00:00:00:00:00")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected return values for MAC addresses");
        goto cleanup;
    }

    if (ifaces[0]->naddrs != 0 ||
        ifaces[1]->naddrs != 4 ||
        ifaces[2]->naddrs != 4 ||
        ifaces[3]->naddrs != 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected return values for number of IP addresses");
        goto cleanup;
    }

    if (ifaces[1]->addrs[0].type != VIR_IP_ADDR_TYPE_IPV4 ||
        ifaces[1]->addrs[1].type != VIR_IP_ADDR_TYPE_IPV6 ||
        ifaces[1]->addrs[2].type != VIR_IP_ADDR_TYPE_IPV4 ||
        ifaces[1]->addrs[3].type != VIR_IP_ADDR_TYPE_IPV6 ||
        ifaces[2]->addrs[0].type != VIR_IP_ADDR_TYPE_IPV6 ||
        ifaces[2]->addrs[1].type != VIR_IP_ADDR_TYPE_IPV4 ||
        ifaces[2]->addrs[2].type != VIR_IP_ADDR_TYPE_IPV4 ||
        ifaces[2]->addrs[3].type != VIR_IP_ADDR_TYPE_IPV6 ||
        ifaces[3]->addrs[0].type != VIR_IP_ADDR_TYPE_IPV4 ||
        ifaces[3]->addrs[1].type != VIR_IP_ADDR_TYPE_IPV6) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected return values for IP address types");
        goto cleanup;
    }

    if (ifaces[1]->addrs[0].prefix != 24 ||
        ifaces[1]->addrs[1].prefix != 64 ||
        ifaces[1]->addrs[2].prefix != 32 ||
        ifaces[1]->addrs[3].prefix != 64 ||
        ifaces[2]->addrs[0].prefix != 64 ||
        ifaces[2]->addrs[1].prefix != 24 ||
        ifaces[2]->addrs[2].prefix != 16 ||
        ifaces[2]->addrs[3].prefix != 64 ||
        ifaces[3]->addrs[0].prefix != 8 ||
        ifaces[3]->addrs[1].prefix != 128) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected return values for IP address prefix");
        goto cleanup;
    }

    if (STRNEQ(ifaces[1]->addrs[0].addr, "192.168.10.91") ||
        STRNEQ(ifaces[1]->addrs[1].addr, "fe80::fc54:ff:fefe:4c4f") ||
        STRNEQ(ifaces[1]->addrs[2].addr, "192.168.103.83") ||
        STRNEQ(ifaces[1]->addrs[3].addr, "fe80::5054:ff:fed3:39ee") ||
        STRNEQ(ifaces[2]->addrs[0].addr, "fe80::5054:ff:fe89:ad35") ||
        STRNEQ(ifaces[2]->addrs[1].addr, "192.168.102.142") ||
        STRNEQ(ifaces[2]->addrs[2].addr, "192.168.234.152") ||
        STRNEQ(ifaces[2]->addrs[3].addr, "fe80::5054:ff:fec3:68bb") ||
        STRNEQ(ifaces[3]->addrs[0].addr, "127.0.0.1") ||
        STRNEQ(ifaces[3]->addrs[1].addr, "::1")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected return values for IP address values");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    if (ifaces) {
        for (i = 0; i < ifaces_count; i++)
            virDomainInterfaceFree(ifaces[i]);
    }
    VIR_FREE(ifaces);

    return ret;
}

static const char testQemuAgentUsersResponse[] =
    "{\"return\": "
    "   ["
    "       {\"user\": \"test\","
    "        \"login-time\": 1561739203.584038"
    "       },"
    "       {\"user\": \"test2\","
    "        \"login-time\": 1561739229.190697"
    "       }"
    "   ]"
    "}";

static const char testQemuAgentUsersResponse2[] =
    "{\"return\": "
    "   ["
    "       {\"user\": \"test\","
    "        \"domain\": \"DOMAIN\","
    "        \"login-time\": 1561739203.584038"
    "       }"
    "   ]"
    "}";

static int
checkUserInfo(virTypedParameterPtr params,
              int nparams,
              size_t nth,
              const char *expUsername,
              const char *expDomain,
              unsigned long long expLogintime)
{
    char param_name[VIR_TYPED_PARAM_FIELD_LENGTH];
    const char *username = NULL;
    const char *domain = NULL;
    unsigned long long logintime = 0;

    snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH,
             "user.%zu.name", nth);
    if (virTypedParamsGetString(params, nparams, param_name, &username) < 0)
        return -1;

    if (STRNEQ_NULLABLE(expUsername, username)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected user name '%s', got '%s'",
                       expUsername, username);
        return -1;
    }

    snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH,
             "user.%zu.domain", nth);
    virTypedParamsGetString(params, nparams, param_name, &domain);
    if (STRNEQ_NULLABLE(expDomain, domain)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected domain '%s', got '%s'",
                       NULLSTR(expDomain), NULLSTR(domain));
        return -1;
    }

    snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH,
             "user.%zu.login-time", nth);
    if (virTypedParamsGetULLong(params, nparams, param_name, &logintime) < 0)
        return -1;

    if (expLogintime != logintime) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected login time of '%llu', got '%llu'",
                       expLogintime, logintime);
        return -1;
    }

    return 0;
}

static int
testQemuAgentUsers(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    int ret = -1;
    unsigned int count;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-get-users",
                               testQemuAgentUsersResponse) < 0)
        goto cleanup;

    /* get users */
    if (qemuAgentGetUsers(qemuMonitorTestGetAgent(test),
                          &params, &nparams, &maxparams) < 0)
        goto cleanup;

    if (virTypedParamsGetUInt(params, nparams, "user.count", &count) < 0)
        goto cleanup;
    if (count != 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected '2' users, got '%u'", count);
        goto cleanup;
    }

    if (checkUserInfo(params, nparams, 0, "test", NULL, 1561739203584) < 0 ||
        checkUserInfo(params, nparams, 1, "test2", NULL, 1561739229190) < 0)
        goto cleanup;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-get-users",
                               testQemuAgentUsersResponse2) < 0)
        goto cleanup;

    virTypedParamsFree(params, nparams);
    params = NULL;
    nparams = 0;
    maxparams = 0;

    /* get users with domain */
    if (qemuAgentGetUsers(qemuMonitorTestGetAgent(test),
                          &params, &nparams, &maxparams) < 0)
        goto cleanup;

    if (virTypedParamsGetUInt(params, nparams, "user.count", &count) < 0)
        goto cleanup;
    if (count != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected '1' user, got '%u'", count);
        goto cleanup;
    }

    if (checkUserInfo(params, nparams, 0, "test", "DOMAIN", 1561739203584) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virTypedParamsFree(params, nparams);
    qemuMonitorTestFree(test);
    return ret;
}

static const char testQemuAgentOSInfoResponse[] =
    "{\"return\": "
    "   {\"name\":\"CentOS Linux\", "
    "   \"kernel-release\":\"3.10.0-862.14.4.el7.x86_64\", "
    "   \"version\":\"7 (Core)\", "
    "   \"pretty-name\":\"CentOS Linux 7 (Core)\", "
    "   \"version-id\":\"7\", "
    "   \"kernel-version\":\"#1 SMP Wed Sep 26 15:12:11 UTC 2018\", "
    "   \"machine\":\"x86_64\", "
    "   \"id\":\"centos\"} "
    "}";

static const char testQemuAgentOSInfoResponse2[] =
    "{\"return\": "
    "   {\"name\":\"Microsoft Windows\", "
    "   \"kernel-release\":\"7601\", "
    "   \"version\":\"Microsoft Windows 77\", "
    "   \"variant\":\"client\", "
    "   \"pretty-name\":\"Windows 7 Professional\", "
    "   \"version-id\":\"\", "
    "   \"variant-id\":\"client\", "
    "   \"kernel-version\":\"6.1\", "
    "   \"machine\":\"x86_64\", "
    "   \"id\":\"mswindows\"} "
    "}";

static int
testQemuAgentOSInfo(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    int ret = -1;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-get-osinfo",
                               testQemuAgentOSInfoResponse) < 0)
        goto cleanup;

    /* get osinfo */
    if (qemuAgentGetOSInfo(qemuMonitorTestGetAgent(test),
                           &params, &nparams, &maxparams) < 0)
        goto cleanup;

    if (nparams != 8) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected 8 params, got %d", nparams);
        goto cleanup;
    }
#define VALIDATE_PARAM(param_name_, expected_) \
    do { \
        const char *value_ = NULL; \
        if (virTypedParamsGetString(params, nparams, param_name_, &value_) < 0 || \
            value_ == NULL) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, "missing param '%s'", param_name_); \
            goto cleanup; \
        } \
        if (STRNEQ(value_, expected_)) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "Expected name '%s', got '%s'", expected_, value_); \
            goto cleanup; \
        } \
    } while (0)

    VALIDATE_PARAM("os.id", "centos");
    VALIDATE_PARAM("os.name", "CentOS Linux");
    VALIDATE_PARAM("os.version", "7 (Core)");
    VALIDATE_PARAM("os.version-id", "7");
    VALIDATE_PARAM("os.pretty-name", "CentOS Linux 7 (Core)");
    VALIDATE_PARAM("os.kernel-release", "3.10.0-862.14.4.el7.x86_64");
    VALIDATE_PARAM("os.kernel-version", "#1 SMP Wed Sep 26 15:12:11 UTC 2018");
    VALIDATE_PARAM("os.machine", "x86_64");
    virTypedParamsFree(params, nparams);
    params = NULL;
    nparams = 0;
    maxparams = 0;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-get-osinfo",
                               testQemuAgentOSInfoResponse2) < 0)
        goto cleanup;

    /* get users with domain */
    if (qemuAgentGetOSInfo(qemuMonitorTestGetAgent(test),
                           &params, &nparams, &maxparams) < 0)
        goto cleanup;

    if (nparams != 10) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected 10 params, got %d", nparams);
        goto cleanup;
    }

    VALIDATE_PARAM("os.id", "mswindows");
    VALIDATE_PARAM("os.name", "Microsoft Windows");
    VALIDATE_PARAM("os.pretty-name", "Windows 7 Professional");
    VALIDATE_PARAM("os.version", "Microsoft Windows 77");
    VALIDATE_PARAM("os.version-id", "");
    VALIDATE_PARAM("os.variant", "client");
    VALIDATE_PARAM("os.variant-id", "client");
    VALIDATE_PARAM("os.kernel-release", "7601");
    VALIDATE_PARAM("os.kernel-version", "6.1");
    VALIDATE_PARAM("os.machine", "x86_64");
    virTypedParamsFree(params, nparams);

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}

static const char testQemuAgentTimezoneResponse1[] =
"{\"return\":{\"zone\":\"IST\",\"offset\":19800}}";
static const char testQemuAgentTimezoneResponse2[] =
"{\"return\":{\"zone\":\"CEST\",\"offset\":7200}}";
static const char testQemuAgentTimezoneResponse3[] =
"{\"return\":{\"zone\":\"NDT\",\"offset\":-9000}}";
static const char testQemuAgentTimezoneResponse4[] =
"{\"return\":{\"zone\":\"PDT\",\"offset\":-25200}}";

static int
testQemuAgentTimezone(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    int ret = -1;

    if (!test)
        return -1;

#define VALIDATE_TIMEZONE(response_, expected_name_, expected_offset_) \
    do { \
        virTypedParameterPtr params_ = NULL; \
        int nparams_ = 0; \
        int maxparams_ = 0; \
        const char *name_ = NULL; \
        int offset_; \
        if (qemuMonitorTestAddAgentSyncResponse(test) < 0) \
            goto cleanup; \
        if (qemuMonitorTestAddItem(test, "guest-get-timezone", \
                                   response_) < 0) \
            goto cleanup; \
        if (qemuAgentGetTimezone(qemuMonitorTestGetAgent(test), \
                                 &params_, &nparams_, &maxparams_) < 0) \
            goto cleanup; \
        if (nparams_ != 2) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "Expected 2 params, got %d", nparams_); \
            goto cleanup; \
        } \
        if (virTypedParamsGetString(params_, nparams_, \
                                    "timezone.name", &name_) < 0) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, "missing param '%s'", \
                           "tiemzone.name"); \
            goto cleanup; \
        } \
        if (STRNEQ(name_, expected_name_)) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "Expected name '%s', got '%s'", expected_name_, name_); \
            goto cleanup; \
        } \
        if (virTypedParamsGetInt(params_, nparams_, \
                                 "timezone.offset", &offset_) < 0) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, "missing param '%s'", \
                           "tiemzone.offset"); \
            goto cleanup; \
        } \
        if (offset_ != expected_offset_) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "Expected offset '%i', got '%i'", offset_, \
                           expected_offset_); \
            goto cleanup; \
        } \
        virTypedParamsFree(params_, nparams_); \
    } while (0)

    VALIDATE_TIMEZONE(testQemuAgentTimezoneResponse1, "IST", 19800);
    VALIDATE_TIMEZONE(testQemuAgentTimezoneResponse2, "CEST", 7200);
    VALIDATE_TIMEZONE(testQemuAgentTimezoneResponse3, "NDT", -9000);
    VALIDATE_TIMEZONE(testQemuAgentTimezoneResponse4, "PDT", -25200);

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    return ret;
}
static int
mymain(void)
{
    int ret = 0;

#if !WITH_YAJL
    fputs("libvirt not compiled with JSON support, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

#define DO_TEST(name) \
    if (virTestRun(# name, testQemuAgent ## name, driver.xmlopt) < 0) \
        ret = -1

    DO_TEST(FSFreeze);
    DO_TEST(FSThaw);
    DO_TEST(FSTrim);
    DO_TEST(GetFSInfoParams);
    DO_TEST(GetFSInfo);
    DO_TEST(Suspend);
    DO_TEST(Shutdown);
    DO_TEST(CPU);
    DO_TEST(ArbitraryCommand);
    DO_TEST(GetInterfaces);
    DO_TEST(Users);
    DO_TEST(OSInfo);
    DO_TEST(Timezone);

    DO_TEST(Timeout); /* Timeout should always be called last */

    qemuTestDriverFree(&driver);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
