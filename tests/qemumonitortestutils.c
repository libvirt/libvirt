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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "testutils.h"
#include "qemumonitortestutils.h"

#include "virthread.h"
#include "qemu/qemu_processpriv.h"
#include "qemu/qemu_monitor.h"
#include "qemu/qemu_agent.h"
#include "rpc/virnetsocket.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.qemumonitortestutils");

struct _qemuMonitorTestItem {
    qemuMonitorTestResponseCallback cb;
    void *opaque;
    virFreeCallback freecb;
};

struct _qemuMonitorTest {
    virMutex lock;
    virThread thread;

    bool json;
    bool quit;
    bool running;
    bool started;

    char *incoming;
    size_t incomingLength;
    size_t incomingCapacity;

    char *outgoing;
    size_t outgoingLength;
    size_t outgoingCapacity;

    virNetSocketPtr server;
    virNetSocketPtr client;

    qemuMonitorPtr mon;
    qemuAgentPtr agent;

    char *tmpdir;

    size_t nitems;
    qemuMonitorTestItemPtr *items;

    virDomainObjPtr vm;
};


static void
qemuMonitorTestItemFree(qemuMonitorTestItemPtr item)
{
    if (!item)
        return;

    if (item->freecb)
        (item->freecb)(item->opaque);

    VIR_FREE(item);
}


/*
 * Appends data for a reply to the outgoing buffer
 */
int
qemuMonitorTestAddResponse(qemuMonitorTestPtr test,
                           const char *response)
{
    size_t want = strlen(response) + 2;
    size_t have = test->outgoingCapacity - test->outgoingLength;

    VIR_DEBUG("Adding response to monitor command: '%s", response);

    if (have < want) {
        size_t need = want - have;
        if (VIR_EXPAND_N(test->outgoing, test->outgoingCapacity, need) < 0)
            return -1;
    }

    want -= 2;
    memcpy(test->outgoing + test->outgoingLength, response, want);
    memcpy(test->outgoing + test->outgoingLength + want, "\r\n", 2);
    test->outgoingLength += want + 2;
    return 0;
}


static int
qemuMonitorTestAddErrorResponse(qemuMonitorTestPtr test,
                                const char *usermsg)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *escapemsg = NULL;
    char *jsonmsg = NULL;
    const char *monmsg = NULL;
    char *tmp;
    int ret = -1;

    if (!usermsg)
        usermsg = "unexpected command";

    if (test->json || test->agent) {
        virBufferEscape(&buf, '\\', "\"", "%s", usermsg);
        if (virBufferCheckError(&buf) < 0)
            goto error;
        escapemsg = virBufferContentAndReset(&buf);

        /* replace newline/carriage return with space */
        tmp = escapemsg;
        while (*tmp) {
            if (*tmp == '\r' || *tmp == '\n')
                *tmp = ' ';

            tmp++;
        }

        /* format the JSON error message */
        if (virAsprintf(&jsonmsg, "{ \"error\": "
                                  " { \"desc\": \"%s\", "
                                  "   \"class\": \"UnexpectedCommand\" } }",
                                  escapemsg) < 0)
            goto error;

        monmsg = jsonmsg;
    } else {
        monmsg = usermsg;
    }

    ret = qemuMonitorTestAddResponse(test, monmsg);

 error:
    VIR_FREE(escapemsg);
    VIR_FREE(jsonmsg);
    return ret;
}


static int
qemuMonitorTestAddUnexpectedErrorResponse(qemuMonitorTestPtr test,
                                          const char *command)
{
    char *msg;
    int ret;

    if (virAsprintf(&msg, "unexpected command: '%s'", command) < 0)
        return -1;

    ret = qemuMonitorTestAddErrorResponse(test, msg);

    VIR_FREE(msg);
    return ret;
}


int
qemuMonitorTestAddInvalidCommandResponse(qemuMonitorTestPtr test,
                                         const char *expectedcommand,
                                         const char *actualcommand)
{
    char *msg;
    int ret;

    if (virAsprintf(&msg, "expected command '%s' got '%s'",
                    expectedcommand, actualcommand) < 0)
        return -1;

    ret = qemuMonitorTestAddErrorResponse(test, msg);

    VIR_FREE(msg);
    return ret;
}


int ATTRIBUTE_FMT_PRINTF(2, 3)
qemuMonitorReportError(qemuMonitorTestPtr test, const char *errmsg, ...)
{
    va_list msgargs;
    char *msg = NULL;
    char *jsonmsg = NULL;
    int ret = -1;

    va_start(msgargs, errmsg);

    if (virVasprintf(&msg, errmsg, msgargs) < 0)
        goto cleanup;

    if (test->agent || test->json) {
        char *tmp = msg;
        msg = qemuMonitorEscapeArg(tmp);
        VIR_FREE(tmp);
        if (!msg)
            goto cleanup;

        if (virAsprintf(&jsonmsg, "{ \"error\": "
                                  " { \"desc\": \"%s\", "
                                  "   \"class\": \"UnexpectedCommand\" } }",
                                  msg) < 0)
            goto cleanup;
    } else {
        if (virAsprintf(&jsonmsg, "error: '%s'", msg) < 0)
            goto cleanup;
    }

    ret = qemuMonitorTestAddResponse(test, jsonmsg);

 cleanup:
    va_end(msgargs);
    VIR_FREE(msg);
    VIR_FREE(jsonmsg);
    return ret;
}


static int
qemuMonitorTestProcessCommand(qemuMonitorTestPtr test,
                              const char *cmdstr)
{
    int ret;

    VIR_DEBUG("Processing string from monitor handler: '%s", cmdstr);

    if (test->nitems == 0) {
        return qemuMonitorTestAddUnexpectedErrorResponse(test, cmdstr);
    } else {
        qemuMonitorTestItemPtr item = test->items[0];
        ret = (item->cb)(test, item, cmdstr);
        qemuMonitorTestItemFree(item);
        if (VIR_DELETE_ELEMENT(test->items, 0, test->nitems) < 0)
            return -1;
    }

    return ret;
}


/*
 * Handles read/write of monitor data on the monitor server side
 */
static void
qemuMonitorTestIO(virNetSocketPtr sock,
                  int events,
                  void *opaque)
{
    qemuMonitorTestPtr test = opaque;
    bool err = false;

    virMutexLock(&test->lock);
    if (test->quit) {
        virMutexUnlock(&test->lock);
        return;
    }
    if (events & VIR_EVENT_HANDLE_WRITABLE) {
        ssize_t ret;
        if ((ret = virNetSocketWrite(sock,
                                     test->outgoing,
                                     test->outgoingLength)) < 0) {
            err = true;
            goto cleanup;
        }

        memmove(test->outgoing,
                test->outgoing + ret,
                test->outgoingLength - ret);
        test->outgoingLength -= ret;

        if ((test->outgoingCapacity - test->outgoingLength) > 1024)
            VIR_SHRINK_N(test->outgoing, test->outgoingCapacity, 1024);
    }

    if (events & VIR_EVENT_HANDLE_READABLE) {
        ssize_t ret, used;
        char *t1, *t2;

        if ((test->incomingCapacity - test->incomingLength) < 1024) {
            if (VIR_EXPAND_N(test->incoming, test->incomingCapacity, 1024) < 0) {
                err = true;
                goto cleanup;
            }
        }

        if ((ret = virNetSocketRead(sock,
                                    test->incoming + test->incomingLength,
                                    (test->incomingCapacity - test->incomingLength) - 1)) < 0) {
            err = true;
            goto cleanup;
        }
        test->incomingLength += ret;
        test->incoming[test->incomingLength] = '\0';

        /* Look to see if we've got a complete line, and
         * if so, handle that command
         */
        t1 = test->incoming;
        while ((t2 = strstr(t1, "\n")) ||
                (!test->json && (t2 = strstr(t1, "\r")))) {
            *t2 = '\0';

            if (qemuMonitorTestProcessCommand(test, t1) < 0) {
                err = true;
                goto cleanup;
            }

            t1 = t2 + 1;
        }
        used = t1 - test->incoming;
        memmove(test->incoming, t1, test->incomingLength - used);
        test->incomingLength -= used;
        if ((test->incomingCapacity - test->incomingLength) > 1024) {
            VIR_SHRINK_N(test->incoming,
                         test->incomingCapacity,
                         1024);
        }
    }

    if (events & (VIR_EVENT_HANDLE_HANGUP |
                  VIR_EVENT_HANDLE_ERROR))
        err = true;

 cleanup:
    if (err) {
        virNetSocketRemoveIOCallback(sock);
        virNetSocketClose(sock);
        virObjectUnref(test->client);
        test->client = NULL;
    } else {
        events = VIR_EVENT_HANDLE_READABLE;

        if (test->outgoingLength)
            events |= VIR_EVENT_HANDLE_WRITABLE;

        virNetSocketUpdateIOCallback(sock, events);
    }
    virMutexUnlock(&test->lock);
}


static void
qemuMonitorTestWorker(void *opaque)
{
    qemuMonitorTestPtr test = opaque;

    virMutexLock(&test->lock);

    while (!test->quit) {
        virMutexUnlock(&test->lock);

        if (virEventRunDefaultImpl() < 0) {
            virMutexLock(&test->lock);
            test->quit = true;
            break;
        }

        virMutexLock(&test->lock);
    }

    test->running = false;

    virMutexUnlock(&test->lock);
    return;
}


static void
qemuMonitorTestFreeTimer(int timer ATTRIBUTE_UNUSED,
                         void *opaque ATTRIBUTE_UNUSED)
{
    /* nothing to be done here */
}


void
qemuMonitorTestFree(qemuMonitorTestPtr test)
{
    size_t i;
    int timer = -1;

    if (!test)
        return;

    virMutexLock(&test->lock);
    if (test->running) {
        test->quit = true;
        /* HACK: Add a dummy timeout to break event loop */
        timer = virEventAddTimeout(0, qemuMonitorTestFreeTimer, NULL, NULL);
    }
    virMutexUnlock(&test->lock);

    if (test->client) {
        virNetSocketRemoveIOCallback(test->client);
        virNetSocketClose(test->client);
        virObjectUnref(test->client);
    }

    virObjectUnref(test->server);
    if (test->mon) {
        virObjectUnlock(test->mon);
        qemuMonitorClose(test->mon);
    }

    if (test->agent) {
        virObjectUnlock(test->agent);
        qemuAgentClose(test->agent);
    }

    virObjectUnref(test->vm);

    if (test->started)
        virThreadJoin(&test->thread);

    if (timer != -1)
        virEventRemoveTimeout(timer);

    VIR_FREE(test->incoming);
    VIR_FREE(test->outgoing);

    for (i = 0; i < test->nitems; i++)
        qemuMonitorTestItemFree(test->items[i]);
    VIR_FREE(test->items);

    if (test->tmpdir && rmdir(test->tmpdir) < 0)
        VIR_WARN("Failed to remove tempdir: %s", strerror(errno));

    VIR_FREE(test->tmpdir);

    virMutexDestroy(&test->lock);
    VIR_FREE(test);
}


int
qemuMonitorTestAddHandler(qemuMonitorTestPtr test,
                          qemuMonitorTestResponseCallback cb,
                          void *opaque,
                          virFreeCallback freecb)
{
    qemuMonitorTestItemPtr item;

    if (VIR_ALLOC(item) < 0)
        goto error;

    item->cb = cb;
    item->freecb = freecb;
    item->opaque = opaque;

    virMutexLock(&test->lock);
    if (VIR_APPEND_ELEMENT(test->items, test->nitems, item) < 0) {
        virMutexUnlock(&test->lock);
        goto error;
    }
    virMutexUnlock(&test->lock);

    return 0;

 error:
    if (freecb)
        (freecb)(opaque);
    VIR_FREE(item);
    return -1;
}

void *
qemuMonitorTestItemGetPrivateData(qemuMonitorTestItemPtr item)
{
    return item ? item->opaque : NULL;
}


typedef struct _qemuMonitorTestCommandArgs qemuMonitorTestCommandArgs;
typedef qemuMonitorTestCommandArgs *qemuMonitorTestCommandArgsPtr;
struct _qemuMonitorTestCommandArgs {
    char *argname;
    char *argval;
};


struct qemuMonitorTestHandlerData {
    char *command_name;
    char *response;
    size_t nargs;
    qemuMonitorTestCommandArgsPtr args;
    char *expectArgs;
};

static void
qemuMonitorTestHandlerDataFree(void *opaque)
{
    struct qemuMonitorTestHandlerData *data = opaque;
    size_t i;

    if (!data)
        return;

    for (i = 0; i < data->nargs; i++) {
        VIR_FREE(data->args[i].argname);
        VIR_FREE(data->args[i].argval);
    }

    VIR_FREE(data->command_name);
    VIR_FREE(data->response);
    VIR_FREE(data->args);
    VIR_FREE(data->expectArgs);
    VIR_FREE(data);
}

static int
qemuMonitorTestProcessCommandDefault(qemuMonitorTestPtr test,
                                     qemuMonitorTestItemPtr item,
                                     const char *cmdstr)
{
    struct qemuMonitorTestHandlerData *data = item->opaque;
    virJSONValuePtr val = NULL;
    char *cmdcopy = NULL;
    const char *cmdname;
    char *tmp;
    int ret = -1;

    if (test->agent || test->json) {
        if (!(val = virJSONValueFromString(cmdstr)))
            return -1;

        if (!(cmdname = virJSONValueObjectGetString(val, "execute"))) {
            ret = qemuMonitorReportError(test, "Missing command name in %s", cmdstr);
            goto cleanup;
        }
    } else {
        if (VIR_STRDUP(cmdcopy, cmdstr) < 0)
            return -1;

        cmdname = cmdcopy;

        if (!(tmp = strchr(cmdcopy, ' '))) {
            ret = qemuMonitorReportError(test,
                                         "Cannot find command name in '%s'",
                                         cmdstr);
            goto cleanup;
        }
        *tmp = '\0';
    }

    if (data->command_name && STRNEQ(data->command_name, cmdname))
        ret = qemuMonitorTestAddInvalidCommandResponse(test, data->command_name,
                                                       cmdname);
    else
        ret = qemuMonitorTestAddResponse(test, data->response);

 cleanup:
    VIR_FREE(cmdcopy);
    virJSONValueFree(val);
    return ret;
}


int
qemuMonitorTestAddItem(qemuMonitorTestPtr test,
                       const char *command_name,
                       const char *response)
{
    struct qemuMonitorTestHandlerData *data;

    if (VIR_ALLOC(data) < 0)
        return -1;

    if (VIR_STRDUP(data->command_name, command_name) < 0 ||
        VIR_STRDUP(data->response, response) < 0) {
        qemuMonitorTestHandlerDataFree(data);
        return -1;
    }

    return qemuMonitorTestAddHandler(test,
                                     qemuMonitorTestProcessCommandDefault,
                                     data, qemuMonitorTestHandlerDataFree);
}


static int
qemuMonitorTestProcessGuestAgentSync(qemuMonitorTestPtr test,
                                     qemuMonitorTestItemPtr item ATTRIBUTE_UNUSED,
                                     const char *cmdstr)
{
    virJSONValuePtr val = NULL;
    virJSONValuePtr args;
    unsigned long long id;
    const char *cmdname;
    char *retmsg = NULL;
    int ret = -1;

    if (!(val = virJSONValueFromString(cmdstr)))
        return -1;

    if (!(cmdname = virJSONValueObjectGetString(val, "execute"))) {
        ret = qemuMonitorReportError(test, "Missing guest-sync command name");
        goto cleanup;
    }

    if (STRNEQ(cmdname, "guest-sync")) {
        ret = qemuMonitorTestAddInvalidCommandResponse(test, "guest-sync", cmdname);
        goto cleanup;
    }

    if (!(args = virJSONValueObjectGet(val, "arguments"))) {
        ret = qemuMonitorReportError(test, "Missing arguments for guest-sync");
        goto cleanup;
    }

    if (virJSONValueObjectGetNumberUlong(args, "id", &id)) {
        ret = qemuMonitorReportError(test, "Missing id for guest sync");
        goto cleanup;
    }

    if (virAsprintf(&retmsg, "{\"return\":%llu}", id) < 0)
        goto cleanup;


    ret = qemuMonitorTestAddResponse(test, retmsg);

 cleanup:
    virJSONValueFree(val);
    VIR_FREE(retmsg);
    return ret;
}


int
qemuMonitorTestAddAgentSyncResponse(qemuMonitorTestPtr test)
{
    if (!test->agent) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "This test is not an agent test");
        return -1;
    }

    return qemuMonitorTestAddHandler(test,
                                     qemuMonitorTestProcessGuestAgentSync,
                                     NULL, NULL);
}


static int
qemuMonitorTestProcessCommandWithArgs(qemuMonitorTestPtr test,
                                      qemuMonitorTestItemPtr item,
                                      const char *cmdstr)
{
    struct qemuMonitorTestHandlerData *data = item->opaque;
    virJSONValuePtr val = NULL;
    virJSONValuePtr args;
    virJSONValuePtr argobj;
    char *argstr = NULL;
    const char *cmdname;
    size_t i;
    int ret = -1;

    if (!(val = virJSONValueFromString(cmdstr)))
        return -1;

    if (!(cmdname = virJSONValueObjectGetString(val, "execute"))) {
        ret = qemuMonitorReportError(test, "Missing command name in %s", cmdstr);
        goto cleanup;
    }

    if (data->command_name &&
        STRNEQ(data->command_name, cmdname)) {
        ret = qemuMonitorTestAddInvalidCommandResponse(test, data->command_name,
                                                       cmdname);
        goto cleanup;
    }

    if (!(args = virJSONValueObjectGet(val, "arguments"))) {
        ret = qemuMonitorReportError(test,
                                     "Missing arguments section for command '%s'",
                                     NULLSTR(data->command_name));
        goto cleanup;
    }

    /* validate the args */
    for (i = 0; i < data->nargs; i++) {
        qemuMonitorTestCommandArgsPtr arg = &data->args[i];
        if (!(argobj = virJSONValueObjectGet(args, arg->argname))) {
            ret = qemuMonitorReportError(test,
                                         "Missing argument '%s' for command '%s'",
                                         arg->argname,
                                         NULLSTR(data->command_name));
            goto cleanup;
        }

        /* convert the argument to string */
        if (!(argstr = virJSONValueToString(argobj, false)))
            goto cleanup;

        /* verify that the argument value is expected */
        if (STRNEQ(argstr, arg->argval)) {
            ret = qemuMonitorReportError(test,
                                         "Invalid value of argument '%s' "
                                         "of command '%s': "
                                         "expected '%s' got '%s'",
                                         arg->argname,
                                         NULLSTR(data->command_name),
                                         arg->argval, argstr);
            goto cleanup;
        }

        VIR_FREE(argstr);
    }

    /* arguments checked out, return the response */
    ret = qemuMonitorTestAddResponse(test, data->response);

 cleanup:
    VIR_FREE(argstr);
    virJSONValueFree(val);
    return ret;
}



/* this allows to add a responder that is able to check
 * a (shallow) structure of arguments for a command */
int
qemuMonitorTestAddItemParams(qemuMonitorTestPtr test,
                             const char *cmdname,
                             const char *response,
                             ...)
{
    struct qemuMonitorTestHandlerData *data;
    const char *argname;
    const char *argval;
    va_list args;

    va_start(args, response);

    if (VIR_ALLOC(data) < 0)
        goto error;

    if (VIR_STRDUP(data->command_name, cmdname) < 0 ||
        VIR_STRDUP(data->response, response) < 0)
        goto error;

    while ((argname = va_arg(args, char *))) {
        size_t i;
        if (!(argval = va_arg(args, char *))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "Missing argument value for argument '%s'",
                           argname);
            goto error;
        }

        i = data->nargs;
        if (VIR_EXPAND_N(data->args, data->nargs, 1))
            goto error;

        if (VIR_STRDUP(data->args[i].argname, argname) < 0 ||
            VIR_STRDUP(data->args[i].argval, argval) < 0)
            goto error;
    }

    va_end(args);

    return qemuMonitorTestAddHandler(test,
                                     qemuMonitorTestProcessCommandWithArgs,
                                     data, qemuMonitorTestHandlerDataFree);

 error:
    va_end(args);
    qemuMonitorTestHandlerDataFree(data);
    return -1;
}


static int
qemuMonitorTestProcessCommandWithArgStr(qemuMonitorTestPtr test,
                                        qemuMonitorTestItemPtr item,
                                        const char *cmdstr)
{
    struct qemuMonitorTestHandlerData *data = item->opaque;
    virJSONValuePtr val = NULL;
    virJSONValuePtr args;
    char *argstr = NULL;
    const char *cmdname;
    int ret = -1;

    if (!(val = virJSONValueFromString(cmdstr)))
        return -1;

    if (!(cmdname = virJSONValueObjectGetString(val, "execute"))) {
        ret = qemuMonitorReportError(test, "Missing command name in %s", cmdstr);
        goto cleanup;
    }

    if (STRNEQ(data->command_name, cmdname)) {
        ret = qemuMonitorTestAddInvalidCommandResponse(test, data->command_name,
                                                       cmdname);
        goto cleanup;
    }

    if (!(args = virJSONValueObjectGet(val, "arguments"))) {
        ret = qemuMonitorReportError(test,
                                     "Missing arguments section for command '%s'",
                                     data->command_name);
        goto cleanup;
    }

    /* convert the arguments to string */
    if (!(argstr = virJSONValueToString(args, false)))
        goto cleanup;

    /* verify that the argument value is expected */
    if (STRNEQ(argstr, data->expectArgs)) {
        ret = qemuMonitorReportError(test,
                                     "%s: expected arguments: '%s', got: '%s'",
                                     data->command_name,
                                     data->expectArgs, argstr);
        goto cleanup;
    }

    /* arguments checked out, return the response */
    ret = qemuMonitorTestAddResponse(test, data->response);

 cleanup:
    VIR_FREE(argstr);
    virJSONValueFree(val);
    return ret;
}


/**
 * qemuMonitorTestAddItemExpect:
 *
 * @test: test monitor object
 * @cmdname: command name
 * @cmdargs: expected arguments of the command
 * @apostrophe: convert apostrophes (') in @cmdargs to quotes (")
 * @response: simulated response of the command
 *
 * Simulates a qemu monitor command. Checks that the 'arguments' of the qmp
 * command are expected. If @apostrophe is true apostrophes are converted to
 * quotes for simplification of writing the strings into code.
 */
int
qemuMonitorTestAddItemExpect(qemuMonitorTestPtr test,
                             const char *cmdname,
                             const char *cmdargs,
                             bool apostrophe,
                             const char *response)
{
    struct qemuMonitorTestHandlerData *data;

    if (VIR_ALLOC(data) < 0)
        goto error;

    if (VIR_STRDUP(data->command_name, cmdname) < 0 ||
        VIR_STRDUP(data->response, response) < 0 ||
        VIR_STRDUP(data->expectArgs, cmdargs) < 0)
        goto error;

    if (apostrophe) {
        char *tmp = data->expectArgs;

        while (*tmp != '\0') {
            if (*tmp == '\'')
                *tmp = '"';

            tmp++;
        }
    }

    return qemuMonitorTestAddHandler(test,
                                     qemuMonitorTestProcessCommandWithArgStr,
                                     data, qemuMonitorTestHandlerDataFree);

 error:
    qemuMonitorTestHandlerDataFree(data);
    return -1;
}


static void
qemuMonitorTestEOFNotify(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                         virDomainObjPtr vm ATTRIBUTE_UNUSED,
                         void *opaque ATTRIBUTE_UNUSED)
{
}


static void
qemuMonitorTestErrorNotify(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                           virDomainObjPtr vm ATTRIBUTE_UNUSED,
                           void *opaque ATTRIBUTE_UNUSED)
{
}


static qemuMonitorCallbacks qemuMonitorTestCallbacks = {
    .eofNotify = qemuMonitorTestEOFNotify,
    .errorNotify = qemuMonitorTestErrorNotify,
    .domainDeviceDeleted = qemuProcessHandleDeviceDeleted,
};


static void
qemuMonitorTestAgentNotify(qemuAgentPtr agent ATTRIBUTE_UNUSED,
                           virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
}


static qemuAgentCallbacks qemuMonitorTestAgentCallbacks = {
    .eofNotify = qemuMonitorTestAgentNotify,
    .errorNotify = qemuMonitorTestAgentNotify,
};


static qemuMonitorTestPtr
qemuMonitorCommonTestNew(virDomainXMLOptionPtr xmlopt,
                         virDomainObjPtr vm,
                         virDomainChrSourceDefPtr src)
{
    qemuMonitorTestPtr test = NULL;
    char *path = NULL;
    char *tmpdir_template = NULL;

    if (VIR_ALLOC(test) < 0)
        goto error;

    if (virMutexInit(&test->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Cannot initialize mutex");
        VIR_FREE(test);
        return NULL;
    }

    if (VIR_STRDUP(tmpdir_template, "/tmp/libvirt_XXXXXX") < 0)
        goto error;

    if (!(test->tmpdir = mkdtemp(tmpdir_template))) {
        virReportSystemError(errno, "%s",
                             "Failed to create temporary directory");
        goto error;
    }

    tmpdir_template = NULL;

    if (virAsprintf(&path, "%s/qemumonitorjsontest.sock", test->tmpdir) < 0)
        goto error;

    if (vm) {
        virObjectRef(vm);
        test->vm = vm;
    } else {
        test->vm = virDomainObjNew(xmlopt);
        if (!test->vm)
            goto error;
    }

    if (virNetSocketNewListenUNIX(path, 0700, geteuid(), getegid(),
                                  &test->server) < 0)
        goto error;

    memset(src, 0, sizeof(*src));
    src->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    src->data.nix.path = (char *)path;
    src->data.nix.listen = false;
    path = NULL;

    if (virNetSocketListen(test->server, 1) < 0)
        goto error;

 cleanup:
    return test;

 error:
    VIR_FREE(path);
    VIR_FREE(tmpdir_template);
    qemuMonitorTestFree(test);
    test = NULL;
    goto cleanup;

}


static int
qemuMonitorCommonTestInit(qemuMonitorTestPtr test)
{
    int events = VIR_EVENT_HANDLE_READABLE;

    if (!test)
        return -1;

    if (virNetSocketAccept(test->server, &test->client) < 0)
        goto error;

    if (!test->client)
        goto error;

    if (test->outgoingLength > 0)
        events = VIR_EVENT_HANDLE_WRITABLE;

    if (virNetSocketAddIOCallback(test->client,
                                  events,
                                  qemuMonitorTestIO,
                                  test,
                                  NULL) < 0)
        goto error;

    virMutexLock(&test->lock);
    if (virThreadCreate(&test->thread,
                        true,
                        qemuMonitorTestWorker,
                        test) < 0) {
        virMutexUnlock(&test->lock);
        goto error;
    }
    test->started = test->running = true;
    virMutexUnlock(&test->lock);

    return 0;

 error:
    return -1;
}


#define QEMU_JSON_GREETING  "{\"QMP\":"\
                            "   {\"version\":"\
                            "       {\"qemu\":"\
                            "           {\"micro\": 1,"\
                            "            \"minor\": 0,"\
                            "            \"major\": 1"\
                            "           },"\
                            "        \"package\": \"(qemu-kvm-1.0.1)"\
                            "       \"},"\
                            "    \"capabilities\": []"\
                            "   }"\
                            "}"
/* We skip the normal handshake reply of "{\"execute\":\"qmp_capabilities\"}" */

#define QEMU_TEXT_GREETING "QEMU 1.0,1 monitor - type 'help' for more information"

qemuMonitorTestPtr
qemuMonitorTestNew(bool json,
                   virDomainXMLOptionPtr xmlopt,
                   virDomainObjPtr vm,
                   virQEMUDriverPtr driver,
                   const char *greeting)
{
    qemuMonitorTestPtr test = NULL;
    virDomainChrSourceDef src;

    memset(&src, 0, sizeof(src));

    if (!(test = qemuMonitorCommonTestNew(xmlopt, vm, &src)))
        goto error;

    test->json = json;
    if (!(test->mon = qemuMonitorOpen(test->vm,
                                      &src,
                                      json,
                                      &qemuMonitorTestCallbacks,
                                      driver)))
        goto error;

    virObjectLock(test->mon);

    if (!greeting)
        greeting = json ? QEMU_JSON_GREETING : QEMU_TEXT_GREETING;

    if (qemuMonitorTestAddResponse(test, greeting) < 0)
        goto error;

    if (qemuMonitorCommonTestInit(test) < 0)
        goto error;

    virDomainChrSourceDefClear(&src);

    return test;

 error:
    virDomainChrSourceDefClear(&src);
    qemuMonitorTestFree(test);
    return NULL;
}


/**
 * qemuMonitorTestNewFromFile:
 * @fileName: File name to load monitor replies from
 * @xmlopt: XML parser configuration object
 * @simple: see below
 *
 * Create a JSON test monitor simulator object and fill it with replies
 * specified in @fileName. The file contains JSON reply objects separated by
 * empty lines. If @simple is true a generic QMP greeting is automatically
 * added as the first reply, otherwise the first entry in the file is used.
 *
 * Returns the monitor object on success; NULL on error.
 */
qemuMonitorTestPtr
qemuMonitorTestNewFromFile(const char *fileName,
                           virDomainXMLOptionPtr xmlopt,
                           bool simple)
{
    qemuMonitorTestPtr test = NULL;
    char *json = NULL;
    char *tmp;
    char *singleReply;

    if (virTestLoadFile(fileName, &json) < 0)
        goto cleanup;

    if (simple && !(test = qemuMonitorTestNewSimple(true, xmlopt)))
        goto cleanup;

    /* Our JSON parser expects replies to be separated by a newline character.
     * Hence we must preprocess the file a bit. */
    tmp = singleReply = json;
    while ((tmp = strchr(tmp, '\n'))) {
        /* It is safe to touch tmp[1] since all strings ends with '\0'. */
        bool eof = !tmp[1];

        if (*(tmp + 1) != '\n') {
            *tmp = ' ';
            tmp++;
        } else {
            /* Cut off a single reply. */
            *(tmp + 1) = '\0';

            if (test) {
                if (qemuMonitorTestAddItem(test, NULL, singleReply) < 0)
                    goto error;
            } else {
                /* Create new mocked monitor with our greeting */
                if (!(test = qemuMonitorTestNew(true, xmlopt, NULL, NULL, singleReply)))
                    goto error;
            }

            if (!eof) {
                /* Move the @tmp and @singleReply. */
                tmp += 2;
                singleReply = tmp;
            }
        }

        if (eof)
            break;
    }

    if (test && qemuMonitorTestAddItem(test, NULL, singleReply) < 0)
        goto error;

 cleanup:
    VIR_FREE(json);
    return test;

 error:
    qemuMonitorTestFree(test);
    test = NULL;
    goto cleanup;
}


qemuMonitorTestPtr
qemuMonitorTestNewAgent(virDomainXMLOptionPtr xmlopt)
{
    qemuMonitorTestPtr test = NULL;
    virDomainChrSourceDef src;

    memset(&src, 0, sizeof(src));

    if (!(test = qemuMonitorCommonTestNew(xmlopt, NULL, &src)))
        goto error;

    if (!(test->agent = qemuAgentOpen(test->vm,
                                      &src,
                                      &qemuMonitorTestAgentCallbacks)))
        goto error;

    virObjectLock(test->agent);

    if (qemuMonitorCommonTestInit(test) < 0)
        goto error;

    virDomainChrSourceDefClear(&src);

    return test;

 error:
    virDomainChrSourceDefClear(&src);
    qemuMonitorTestFree(test);
    return NULL;
}


qemuMonitorPtr
qemuMonitorTestGetMonitor(qemuMonitorTestPtr test)
{
    return test->mon;
}


qemuAgentPtr
qemuMonitorTestGetAgent(qemuMonitorTestPtr test)
{
    return test->agent;
}
