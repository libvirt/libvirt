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
#include "virerror.h"


#define VIR_FROM_THIS VIR_FROM_NONE


virQEMUDriver driver;


static int
testQemuAgentSSHKeys(const void *data)
{
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
    g_auto(GStrv) keys = NULL;
    int nkeys = 0;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "guest-ssh-get-authorized-keys",
                               "{\"return\": {"
                               "  \"keys\": ["
                               "    \"algo1 key1 comments1\","
                               "    \"algo2 key2 comments2\""
                               "  ]"
                               "}}") < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "guest-ssh-add-authorized-keys",
                               "{ \"return\" : {} }") < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "guest-ssh-remove-authorized-keys",
                               "{ \"return\" : {} }") < 0)
        return -1;

    if ((nkeys = qemuAgentSSHGetAuthorizedKeys(qemuMonitorTestGetAgent(test),
                                               "user",
                                               &keys)) < 0)
        return -1;

    if (nkeys != 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 2 keys, got %d", nkeys);
        return -1;
    }

    if (STRNEQ(keys[1], "algo2 key2 comments2")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "Unexpected key returned: %s", keys[1]);
        return -1;
    }

    if (qemuAgentSSHAddAuthorizedKeys(qemuMonitorTestGetAgent(test),
                                      "user",
                                      (const char **) keys,
                                      nkeys,
                                      true) < 0)
        return -1;

    if (qemuAgentSSHRemoveAuthorizedKeys(qemuMonitorTestGetAgent(test),
                                         "user",
                                         (const char **) keys,
                                         nkeys) < 0)
        return -1;

    return 0;
}


static int
testQemuAgentFSFreeze(const void *data)
{
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
    const char *mountpoints[] = {"/fs1", "/fs2", "/fs3", "/fs4", "/fs5"};
    int rc;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "guest-fsfreeze-freeze-list",
                               "{ \"return\" : 5 }") < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "guest-fsfreeze-freeze",
                               "{ \"return\" : 7 }") < 0)
        return -1;

    if ((rc = qemuAgentFSFreeze(qemuMonitorTestGetAgent(test),
                                mountpoints, 5)) < 0)
        return -1;

    if (rc != 5) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 5 frozen filesystems, got %d", rc);
        return -1;
    }

    if ((rc = qemuAgentFSFreeze(qemuMonitorTestGetAgent(test), NULL, 0)) < 0)
        return -1;

    if (rc != 7) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 7 frozen filesystems, got %d", rc);
        return -1;
    }

    return 0;
}


static int
testQemuAgentFSThaw(const void *data)
{
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
    int rc;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "guest-fsfreeze-thaw",
                               "{ \"return\" : 5 }") < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "guest-fsfreeze-thaw",
                               "{ \"return\" : 7 }") < 0)
        return -1;

    if ((rc = qemuAgentFSThaw(qemuMonitorTestGetAgent(test))) < 0)
        return -1;

    if (rc != 5) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 5 thawed filesystems, got %d", rc);
        return -1;
    }

    if ((rc = qemuAgentFSThaw(qemuMonitorTestGetAgent(test))) < 0)
        return -1;

    if (rc != 7) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 7 thawed filesystems, got %d", rc);
        return -1;
    }

    return 0;
}


static int
testQemuAgentFSTrim(const void *data)
{
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        return -1;

    if (qemuMonitorTestAddItemVerbatim(test,
                                       "{\"execute\":\"guest-fstrim\","
                                       " \"arguments\": {\"minimum\":1337}}",
                                       NULL,
                                       "{ \"return\" : {}}") < 0)
        return -1;

    if (qemuAgentFSTrim(qemuMonitorTestGetAgent(test), 1337) < 0)
        return -1;

    return 0;
}


static int
testQemuAgentGetFSInfoCommon(virDomainXMLOption *xmlopt,
                             qemuMonitorTest **test,
                             virDomainDef **def)
{
    g_autofree char *domain_filename = NULL;
    g_autoptr(qemuMonitorTest) ret_test = NULL;
    g_autoptr(virDomainDef) ret_def = NULL;

    if (!test || !def)
        return -1;

    if (!(ret_test = qemuMonitorTestNewAgent(xmlopt)))
        return -1;

    domain_filename = g_strdup_printf("%s/qemuagentdata/fsinfo.xml", abs_srcdir);

    if (!(ret_def = virDomainDefParseFile(domain_filename, xmlopt,
                                          NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(ret_test) < 0)
        return -1;

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
                               return -1;

    *test = g_steal_pointer(&ret_test);
    *def = g_steal_pointer(&ret_def);
    return 0;
}

static int
testQemuAgentGetFSInfo(const void *data)
{
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = NULL;
    g_autoptr(virDomainDef) def = NULL;
    qemuAgentFSInfo **info = NULL;
    int ret = -1, ninfo = 0, i;

    if (testQemuAgentGetFSInfoCommon(xmlopt, &test, &def) < 0)
        goto cleanup;

    if ((ninfo = qemuAgentGetFSInfo(qemuMonitorTestGetAgent(test),
                                    &info, true)) < 0)
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
        info[2]->ndisks != 1 ||
        !info[2]->disks || !info[2]->disks[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "unexpected filesystems information returned for sda1 (%s)",
            info[2]->name);
        ret = -1;
        goto cleanup;
    }
    if (STRNEQ(info[1]->name, "dm-1") ||
        STRNEQ(info[1]->mountpoint, "/opt") ||
        STRNEQ(info[1]->fstype, "vfat") ||
        info[1]->ndisks != 2 ||
        !info[1]->disks || !info[1]->disks[0] || !info[1]->disks[1] ||
        STRNEQ(info[1]->disks[0]->bus_type, "virtio") ||
        info[1]->disks[0]->bus != 0 ||
        info[1]->disks[0]->target != 0 ||
        info[1]->disks[0]->unit != 0 ||
        info[1]->disks[0]->pci_controller.domain != 0 ||
        info[1]->disks[0]->pci_controller.bus != 0 ||
        info[1]->disks[0]->pci_controller.slot != 6 ||
        info[1]->disks[0]->pci_controller.function != 0 ||
        STRNEQ(info[1]->disks[1]->bus_type, "virtio") ||
        info[1]->disks[1]->bus != 0 ||
        info[1]->disks[1]->target != 0 ||
        info[1]->disks[1]->unit != 0 ||
        info[1]->disks[1]->pci_controller.domain != 0 ||
        info[1]->disks[1]->pci_controller.bus != 0 ||
        info[1]->disks[1]->pci_controller.slot != 7 ||
        info[1]->disks[1]->pci_controller.function != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "unexpected filesystems information returned for dm-1 (%s)",
            info[0]->name);
        ret = -1;
        goto cleanup;
    }
    if (STRNEQ(info[0]->name, "sdb1") ||
        STRNEQ(info[0]->mountpoint, "/mnt/disk") ||
        STRNEQ(info[0]->fstype, "xfs") ||
        info[0]->ndisks != 0 || info[0]->disks) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
            "unexpected filesystems information returned for sdb1 (%s)",
            info[0]->name);
        ret = -1;
        goto cleanup;
    }

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

    if (qemuAgentGetFSInfo(qemuMonitorTestGetAgent(test), &info, true) >= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "agent get-fsinfo command should have failed");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    for (i = 0; i < ninfo; i++)
        qemuAgentFSInfoFree(info[i]);
    VIR_FREE(info);
    return ret;
}

static int
testQemuAgentSuspend(const void *data)
{
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
    size_t i;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "guest-suspend-ram",
                               "{ \"return\" : {} }") < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "guest-suspend-disk",
                               "{ \"return\" : {} }") < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "guest-suspend-hybrid",
                               "{ \"return\" : {} }") < 0)
        return -1;

    /* try the commands - fail if ordering changes */
    for (i = 0; i < VIR_NODE_SUSPEND_TARGET_LAST; i++) {
        if (qemuAgentSuspend(qemuMonitorTestGetAgent(test), i) < 0)
            return -1;
    }

    return 0;
}


struct qemuAgentShutdownTestData {
    const char *mode;
    qemuAgentEvent event;
};


static int
qemuAgentShutdownTestMonitorHandler(qemuMonitorTest *test,
                                    qemuMonitorTestItem *item,
                                    const char *cmdstr)
{
    struct qemuAgentShutdownTestData *data;
    g_autoptr(virJSONValue) val = NULL;
    virJSONValue *args;
    const char *cmdname;
    const char *mode;

    data = qemuMonitorTestItemGetPrivateData(item);

    if (!(val = virJSONValueFromString(cmdstr)))
        return -1;

    if (!(cmdname = virJSONValueObjectGetString(val, "execute")))
        return qemuMonitorTestAddErrorResponse(test, "Missing command name in %s", cmdstr);

    if (STRNEQ(cmdname, "guest-shutdown")) {
        return qemuMonitorTestAddInvalidCommandResponse(test, "guest-shutdown",
                                                       cmdname);
    }

    if (!(args = virJSONValueObjectGet(val, "arguments"))) {
        return qemuMonitorTestAddErrorResponse(test,
                                              "Missing arguments section");
    }

    if (!(mode = virJSONValueObjectGetString(args, "mode")))
        return qemuMonitorTestAddErrorResponse(test, "Missing shutdown mode");

    if (STRNEQ(mode, data->mode)) {
        return qemuMonitorTestAddErrorResponse(test,
                                              "expected shutdown mode '%s' got '%s'",
                                              data->mode, mode);
    }

    /* now don't reply but return a qemu agent event */
    qemuAgentNotifyEvent(qemuMonitorTestGetAgent(test),
                         data->event);

    return 0;
}


static int
testQemuAgentShutdown(const void *data)
{
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
    struct qemuAgentShutdownTestData priv;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        return -1;

    priv.event = QEMU_AGENT_EVENT_SHUTDOWN;
    priv.mode = "halt";

    qemuMonitorTestAddHandler(test, "guest-shutdown",
                              qemuAgentShutdownTestMonitorHandler,
                              &priv, NULL);

    if (qemuAgentShutdown(qemuMonitorTestGetAgent(test),
                          QEMU_AGENT_SHUTDOWN_HALT) < 0)
        return -1;

    priv.event = QEMU_AGENT_EVENT_SHUTDOWN;
    priv.mode = "powerdown";

    qemuMonitorTestAddHandler(test, "guest-shutdown",
                              qemuAgentShutdownTestMonitorHandler,
                              &priv, NULL);

    if (qemuAgentShutdown(qemuMonitorTestGetAgent(test),
                          QEMU_AGENT_SHUTDOWN_POWERDOWN) < 0)
        return -1;

    priv.event = QEMU_AGENT_EVENT_RESET;
    priv.mode = "reboot";

    qemuMonitorTestAddHandler(test,
                              "guest-shutdown",
                              qemuAgentShutdownTestMonitorHandler,
                              &priv, NULL);

    if (qemuAgentShutdown(qemuMonitorTestGetAgent(test),
                          QEMU_AGENT_SHUTDOWN_REBOOT) < 0)
        return -1;

    /* check negative response, so that we can verify that the agent breaks
     * out from sleep */

    if (qemuMonitorTestAddItem(test, "guest-shutdown",
                               "{\"error\":"
                               "    {\"class\":\"CommandDisabled\","
                               "     \"desc\":\"The command guest-shutdown has "
                                               "been disabled for this instance\","
                               "     \"data\":{\"name\":\"guest-shutdown\"}"
                               "    }"
                               "}") < 0)
        return -1;

    if (qemuAgentShutdown(qemuMonitorTestGetAgent(test),
                          QEMU_AGENT_SHUTDOWN_REBOOT) != -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "agent shutdown command should have failed");
        return -1;
    }

    return 0;
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

static int
testQemuAgentCPU(const void *data)
{
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
    g_autofree qemuAgentCPUInfo *cpuinfo = NULL;
    int nvcpus;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "guest-get-vcpus",
                               testQemuAgentCPUResponse) < 0)
        return -1;

    /* get cpus */
    if ((nvcpus = qemuAgentGetVCPUs(qemuMonitorTestGetAgent(test),
                                    &cpuinfo)) < 0)
        return -1;

    if (nvcpus != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected '4' cpus, got '%d'", nvcpus);
        return -1;
    }

    /* try to unplug one */
    if (qemuAgentUpdateCPUInfo(2, cpuinfo, nvcpus) < 0)
        return -1;

    if (qemuMonitorTestAddItemVerbatim(test,
                                       "{\"execute\":\"guest-set-vcpus\","
                                       " \"arguments\": {"
                                       "     \"vcpus\":[{\"logical-id\":1,\"online\":false}]"
                                       "}}",
                                       NULL,
                                       "{ \"return\" : 1 }") < 0)
        return -1;

    if (qemuAgentSetVCPUs(qemuMonitorTestGetAgent(test), cpuinfo, nvcpus) < 0)
        return -1;

    /* try to hotplug two, second one will fail */
    if (qemuMonitorTestAddItemVerbatim(test,
                                       "{\"execute\":\"guest-set-vcpus\","
                                       " \"arguments\": {"
                                       "     \"vcpus\":[{\"logical-id\":1,\"online\":true},"
                                       "                {\"logical-id\":3,\"online\":true}]"
                                       "}}",
                                       NULL,
                                       "{ \"return\" : 1 }") < 0)
        return -1;

    if (qemuMonitorTestAddItemVerbatim(test,
                                       "{\"execute\":\"guest-set-vcpus\","
                                       " \"arguments\": {"
                                       "     \"vcpus\":[{\"logical-id\":3,\"online\":true}]"
                                       "}}",
                                       NULL,
                                       "{ \"error\" : \"random error\" }") < 0)
        return -1;

    if (qemuAgentUpdateCPUInfo(4, cpuinfo, nvcpus) < 0)
        return -1;

    /* this should fail */
    if (qemuAgentSetVCPUs(qemuMonitorTestGetAgent(test), cpuinfo, nvcpus) != -1)
        return -1;

    return 0;
}


static const char testQemuAgentArbitraryCommandResponse[] =
    "{\"return\":\"bla\"}";

static int
testQemuAgentArbitraryCommand(const void *data)
{
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
    g_autofree char *reply = NULL;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        return -1;

    if (qemuMonitorTestAddItem(test, "ble",
                               testQemuAgentArbitraryCommandResponse) < 0)
        return -1;

    if (qemuAgentArbitraryCommand(qemuMonitorTestGetAgent(test),
                                  "{\"execute\":\"ble\"}",
                                  &reply,
                                  VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK) < 0)
        return -1;

    if (STRNEQ(reply, testQemuAgentArbitraryCommandResponse)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "invalid processing of guest agent reply: "
                       "got '%s' expected '%s'",
                       reply, testQemuAgentArbitraryCommandResponse);
        return -1;
    }

    return 0;
}


static int
qemuAgentTimeoutTestMonitorHandler(qemuMonitorTest *test G_GNUC_UNUSED,
                                   qemuMonitorTestItem *item G_GNUC_UNUSED,
                                   const char *cmdstr G_GNUC_UNUSED)
{
    return 0;
}


static int
testQemuAgentTimeout(const void *data)
{
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
    g_autofree char *reply = NULL;

    if (!test)
        return -1;

    if (virTestGetExpensive() == 0)
        return EXIT_AM_SKIP;

    qemuMonitorTestAddHandler(test, NULL,
                              qemuAgentTimeoutTestMonitorHandler,
                              NULL, NULL);

    if (qemuAgentFSFreeze(qemuMonitorTestGetAgent(test), NULL, 0) != -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "agent command should have failed");
        return -1;
    }

    /* test timeout */
    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        return -1;

    qemuMonitorTestAddHandler(test,
                              NULL,
                              qemuAgentTimeoutTestMonitorHandler,
                              NULL, NULL);

    if (qemuAgentArbitraryCommand(qemuMonitorTestGetAgent(test),
                                  "{\"execute\":\"ble\"}",
                                  &reply,
                                  1) != -2) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "agent command didn't time out");
        return -1;
    }

    return 0;
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
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
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
                                               &ifaces, true)) < 0)
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
    if (ifaces) {
        for (i = 0; i < ifaces_count; i++)
            virDomainInterfaceFree(ifaces[i]);
    }
    VIR_FREE(ifaces);

    return ret;
}


/* this is a bit of a pathological response on a real hw */
static const char testQemuAgentGetDisksResponse[] =
    "{\"return\": "
    "  ["
    "    {\"alias\" : \"fedora_localhost--live-home\","
    "     \"dependencies\" : "
    "     ["
    "       \"/dev/dm-0\""
    "     ],"
    "     \"name\" : \"/dev/dm-3\","
    "     \"partition\" : false"
    "    },"
    "    {\"address\" : "
    "      {\"bus\" : 0,"
    "       \"bus-type\" : \"unknown\","
    "       \"dev\" : \"/dev/nvme0n1\","
    "       \"pci-controller\" : "
    "         {\"bus\" : -1,"
    "          \"domain\" : -1,"
    "          \"function\" : -1,"
    "          \"slot\" : -1"
    "         },"
    "     \"serial\" : \"GIGABYTE GP-ASM2NE6100TTTD_SN202208900567\","
    "     \"target\" : 0,"
    "     \"unit\" : 0"
    "    },"
    "    \"dependencies\" : [],"
    "    \"name\" : \"/dev/nvme0n1\","
    "    \"partition\" : false"
    "   }"
    "  ]"
    "}";

static int
testQemuAgentGetDisks(const void *data)
{
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
    size_t i;
    int ret = -1;
    int disks_count = 0;
    qemuAgentDiskInfo **disks = NULL;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-get-disks",
                               testQemuAgentGetDisksResponse) < 0)
        goto cleanup;

    if ((disks_count = qemuAgentGetDisks(qemuMonitorTestGetAgent(test),
                                         &disks, true)) < 0)
        goto cleanup;

    if (disks_count != 2) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 2 disks, got %d", ret);
        goto cleanup;
    }

    if (STRNEQ(disks[0]->name, "/dev/dm-3") ||
        STRNEQ(disks[1]->name, "/dev/nvme0n1")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected return values for disks names");
        goto cleanup;
    }

    if (STRNEQ(disks[0]->alias, "fedora_localhost--live-home") ||
        disks[1]->alias != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected return values for disks aliases");
        goto cleanup;
    }

    if (STRNEQ(disks[0]->dependencies[0], "/dev/dm-0") ||
        disks[0]->dependencies[1] != NULL ||
        disks[1]->dependencies[0] != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected return values for disks dependencies");
        goto cleanup;
    }

    if (disks[0]->address != NULL ||
        disks[1]->address->bus != 0 ||
        disks[1]->address->target != 0 ||
        disks[1]->address->unit != 0 ||
        STRNEQ(disks[1]->address->serial, "GIGABYTE GP-ASM2NE6100TTTD_SN202208900567") ||
        STRNEQ(disks[1]->address->bus_type, "unknown")) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "unexpected return values for disks addresses");
        goto cleanup;
    }
    ret = 0;

 cleanup:
    if (disks) {
        for (i = 0; i < disks_count; i++)
            qemuAgentDiskInfoFree(disks[i]);
    }
    VIR_FREE(disks);

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

    g_snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH,
               "user.%zu.name", nth);
    if (virTypedParamsGetString(params, nparams, param_name, &username) < 0)
        return -1;

    if (STRNEQ_NULLABLE(expUsername, username)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected user name '%s', got '%s'",
                       expUsername, username);
        return -1;
    }

    g_snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH,
               "user.%zu.domain", nth);
    if (virTypedParamsGetString(params, nparams, param_name, &domain) < 0)
        return -1;

    if (STRNEQ_NULLABLE(expDomain, domain)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected domain '%s', got '%s'",
                       NULLSTR(expDomain), NULLSTR(domain));
        return -1;
    }

    g_snprintf(param_name, VIR_TYPED_PARAM_FIELD_LENGTH,
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
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
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
                          &params, &nparams, &maxparams, true) < 0)
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

    if (qemuMonitorTestAddItem(test, "guest-get-users",
                               testQemuAgentUsersResponse2) < 0)
        goto cleanup;

    virTypedParamsFree(params, nparams);
    params = NULL;
    nparams = 0;
    maxparams = 0;

    /* get users with domain */
    if (qemuAgentGetUsers(qemuMonitorTestGetAgent(test),
                          &params, &nparams, &maxparams, true) < 0)
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
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
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
                           &params, &nparams, &maxparams, true) < 0)
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

    if (qemuMonitorTestAddItem(test, "guest-get-osinfo",
                               testQemuAgentOSInfoResponse2) < 0)
        goto cleanup;

    /* get users with domain */
    if (qemuAgentGetOSInfo(qemuMonitorTestGetAgent(test),
                           &params, &nparams, &maxparams, true) < 0)
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

    ret = 0;

 cleanup:
    virTypedParamsFree(params, nparams);
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
    virDomainXMLOption *xmlopt = (virDomainXMLOption *)data;
    g_autoptr(qemuMonitorTest) test = qemuMonitorTestNewAgent(xmlopt);
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int ret = -1;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

#define VALIDATE_TIMEZONE(response_, expected_name_, expected_offset_) \
    do { \
        int maxparams_ = 0; \
        const char *name_ = NULL; \
        int offset_; \
        if (qemuMonitorTestAddItem(test, "guest-get-timezone", \
                                   response_) < 0) \
            goto cleanup; \
        virTypedParamsFree(params, nparams); \
        params = NULL; \
        nparams = 0; \
        if (qemuAgentGetTimezone(qemuMonitorTestGetAgent(test), \
                                 &params, &nparams, &maxparams_, true) < 0) \
            goto cleanup; \
        if (nparams != 2) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           "Expected 2 params, got %d", nparams); \
            goto cleanup; \
        } \
        if (virTypedParamsGetString(params, nparams, \
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
        if (virTypedParamsGetInt(params, nparams, \
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
    } while (0)

    VALIDATE_TIMEZONE(testQemuAgentTimezoneResponse1, "IST", 19800);
    VALIDATE_TIMEZONE(testQemuAgentTimezoneResponse2, "CEST", 7200);
    VALIDATE_TIMEZONE(testQemuAgentTimezoneResponse3, "NDT", -9000);
    VALIDATE_TIMEZONE(testQemuAgentTimezoneResponse4, "PDT", -25200);

    ret = 0;

 cleanup:
    virTypedParamsFree(params, nparams);
    return ret;
}
static int
mymain(void)
{
    g_autoptr(GHashTable) capslatest = testQemuGetLatestCaps();
    g_autoptr(GHashTable) capscache = virHashNew(virObjectUnref);
    int ret = 0;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    /* Some test cases need a real definition thus parse a XML. We need
     * qemu capabilities for that. */
    if (testQemuInsertRealCaps(driver.qemuCapsCache, "x86_64", "latest", "",
                               capslatest, capscache, NULL, NULL) < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

#define DO_TEST(name) \
    if (virTestRun(# name, testQemuAgent ## name, driver.xmlopt) < 0) \
        ret = -1

    DO_TEST(FSFreeze);
    DO_TEST(FSThaw);
    DO_TEST(FSTrim);
    DO_TEST(GetFSInfo);
    DO_TEST(Suspend);
    DO_TEST(Shutdown);
    DO_TEST(CPU);
    DO_TEST(ArbitraryCommand);
    DO_TEST(GetInterfaces);
    DO_TEST(Users);
    DO_TEST(OSInfo);
    DO_TEST(Timezone);
    DO_TEST(SSHKeys);
    DO_TEST(GetDisks);

    DO_TEST(Timeout); /* Timeout should always be called last */

    qemuTestDriverFree(&driver);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
