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

static int
testQemuAgentFSFreeze(const void *data)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr)data;
    qemuMonitorTestPtr test = qemuMonitorTestNewAgent(xmlopt);
    int ret = -1;

    if (!test)
        return -1;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-fsfreeze-freeze",
                               "{ \"return\" : 5 }") < 0)
        goto cleanup;

    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "guest-fsfreeze-freeze",
                               "{ \"return\" : 7 }") < 0)
        goto cleanup;

    if ((ret = qemuAgentFSFreeze(qemuMonitorTestGetAgent(test))) < 0)
        goto cleanup;

    if (ret != 5) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "expected 5 frozen filesystems, got %d", ret);
        goto cleanup;
    }

    if ((ret = qemuAgentFSFreeze(qemuMonitorTestGetAgent(test))) < 0)
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
        ret = qemuMonitorTestAddUnexpectedErrorResponse(test);
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
    "[{\"logical-id\":0,\"online\":true},"
     "{\"logical-id\":1,\"online\":false},"
     "{\"logical-id\":2,\"online\":true},"
     "{\"logical-id\":3,\"online\":false}]";

static const char testQemuAgentCPUArguments2[] =
    "[{\"logical-id\":0,\"online\":true},"
     "{\"logical-id\":1,\"online\":true},"
     "{\"logical-id\":2,\"online\":true},"
     "{\"logical-id\":3,\"online\":true}]";

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
                                     "{ \"return\" : 4 }",
                                     "vcpus", testQemuAgentCPUArguments1,
                                     NULL) < 0)
        goto cleanup;

    if ((nvcpus = qemuAgentSetVCPUs(qemuMonitorTestGetAgent(test),
                                    cpuinfo, nvcpus)) < 0)
        goto cleanup;

    if (nvcpus != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected '4' cpus updated , got '%d'", nvcpus);
        goto cleanup;
    }

    /* try to hotplug two */
    if (qemuMonitorTestAddAgentSyncResponse(test) < 0)
        goto cleanup;

    if (qemuMonitorTestAddItemParams(test, "guest-set-vcpus",
                                     "{ \"return\" : 4 }",
                                     "vcpus", testQemuAgentCPUArguments2,
                                     NULL) < 0)
        goto cleanup;

    if (qemuAgentUpdateCPUInfo(4, cpuinfo, nvcpus) < 0)
        goto cleanup;

    if ((nvcpus = qemuAgentSetVCPUs(qemuMonitorTestGetAgent(test),
                                    cpuinfo, nvcpus)) < 0)
        goto cleanup;

    if (nvcpus != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected '4' cpus updated , got '%d'", nvcpus);
        goto cleanup;
    }

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
qemuAgentTimeoutTestMonitorHandler(qemuMonitorTestPtr test ATTRIBUTE_UNUSED,
                                   qemuMonitorTestItemPtr item ATTRIBUTE_UNUSED,
                                   const char *cmdstr ATTRIBUTE_UNUSED)
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

    if (qemuAgentFSFreeze(qemuMonitorTestGetAgent(test)) != -1) {
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

#define DO_TEST(name)                                           \
    if (virtTestRun(# name, testQemuAgent ## name, xmlopt) < 0) \
        ret = -1

    DO_TEST(FSFreeze);
    DO_TEST(FSThaw);
    DO_TEST(FSTrim);
    DO_TEST(Suspend);
    DO_TEST(Shutdown);
    DO_TEST(CPU);
    DO_TEST(ArbitraryCommand);

    DO_TEST(Timeout); /* Timeout should always be called last */

    virObjectUnref(xmlopt);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
