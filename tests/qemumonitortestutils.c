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

#include <time.h>

#include "testutils.h"
#include "testutilsqemuschema.h"
#include "qemumonitortestutils.h"

#include "virthread.h"
#define LIBVIRT_QEMU_PROCESSPRIV_H_ALLOW
#include "qemu/qemu_processpriv.h"
#include "qemu/qemu_monitor.h"
#include "qemu/qemu_agent.h"
#include "qemu/qemu_qapi.h"
#include "rpc/virnetsocket.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virstring.h"
#include "vireventthread.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.qemumonitortestutils");

struct _qemuMonitorTestItem {
    char *identifier;
    qemuMonitorTestResponseCallback cb;
    void *opaque;
    virFreeCallback freecb;
};

struct _qemuMonitorTest {
    virMutex lock;
    virThread thread;

    bool quit;
    bool running;
    bool started;

    bool allowUnusedCommands;

    bool skipValidationDeprecated;
    bool skipValidationRemoved;

    char *incoming;
    size_t incomingLength;
    size_t incomingCapacity;

    char *outgoing;
    size_t outgoingLength;
    size_t outgoingCapacity;

    virNetSocketPtr server;
    virNetSocketPtr client;

    virEventThread *eventThread;

    qemuMonitorPtr mon;
    qemuAgentPtr agent;

    char *tmpdir;

    size_t nitems;
    qemuMonitorTestItemPtr *items;

    virDomainObjPtr vm;
    virHashTablePtr qapischema;
};


static void
qemuMonitorTestItemFree(qemuMonitorTestItemPtr item)
{
    if (!item)
        return;

    g_free(item->identifier);

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
qemuMonitorTestAddErrorResponseInternal(qemuMonitorTestPtr test,
                                        const char *usermsg)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *escapemsg = NULL;
    g_autofree char *jsonmsg = NULL;
    char *tmp;

    if (!usermsg)
        usermsg = "unexpected command";

    virBufferEscape(&buf, '\\', "\"", "%s", usermsg);
    escapemsg = virBufferContentAndReset(&buf);

    /* replace newline/carriage return with space */
    tmp = escapemsg;
    while (*tmp) {
        if (*tmp == '\r' || *tmp == '\n')
            *tmp = ' ';

        tmp++;
    }

    /* format the JSON error message */
    jsonmsg = g_strdup_printf("{ \"error\": " " { \"desc\": \"%s\", "
                              "   \"class\": \"UnexpectedCommand\" } }", escapemsg);

    return qemuMonitorTestAddResponse(test, jsonmsg);
}


int
qemuMonitorTestAddInvalidCommandResponse(qemuMonitorTestPtr test,
                                         const char *expectedcommand,
                                         const char *actualcommand)
{
    g_autofree char *msg = NULL;

    msg = g_strdup_printf("expected command '%s' got '%s'", expectedcommand,
                          actualcommand);

    return qemuMonitorTestAddErrorResponseInternal(test, msg);
}


int G_GNUC_PRINTF(2, 3)
qemuMonitorTestAddErrorResponse(qemuMonitorTestPtr test, const char *errmsg, ...)
{
    va_list msgargs;
    g_autofree char *msg = NULL;
    g_autofree char *jsonmsg = NULL;
    int ret = -1;

    va_start(msgargs, errmsg);

    msg = g_strdup_vprintf(errmsg, msgargs);

    jsonmsg = g_strdup_printf("{ \"error\": " " { \"desc\": \"%s\", "
                              "   \"class\": \"UnexpectedCommand\" } }", msg);

    ret = qemuMonitorTestAddResponse(test, jsonmsg);

    va_end(msgargs);
    return ret;
}


static void G_GNUC_NORETURN G_GNUC_PRINTF(1, 2)
qemuMonitorTestError(const char *errmsg,
                     ...)
{
    va_list msgargs;

    va_start(msgargs, errmsg);

    g_fprintf(stderr, "\n");
    g_vfprintf(stderr, errmsg, msgargs);
    g_fprintf(stderr, "\n");
    exit(EXIT_FAILURE); /* exempt from syntax-check */
}


static void G_GNUC_NORETURN
qemuMonitorTestErrorInvalidCommand(const char *expectedcommand,
                                   const char *actualcommand)
{
    qemuMonitorTestError("expected command '%s' got '%s'",
                         expectedcommand, actualcommand);
}



static int
qemuMonitorTestProcessCommand(qemuMonitorTestPtr test,
                              const char *cmdstr)
{
    int ret;

    VIR_DEBUG("Processing string from monitor handler: '%s", cmdstr);

    if (test->nitems == 0) {
        qemuMonitorTestError("unexpected command: '%s'", cmdstr);
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
                (test->agent && (t2 = strstr(t1, "\r")))) {
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
qemuMonitorTestFreeTimer(int timer G_GNUC_UNUSED,
                         void *opaque G_GNUC_UNUSED)
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

    g_object_unref(test->eventThread);

    virObjectUnref(test->vm);

    if (test->started)
        virThreadJoin(&test->thread);

    if (timer != -1)
        virEventRemoveTimeout(timer);

    VIR_FREE(test->incoming);
    VIR_FREE(test->outgoing);

    for (i = 0; i < test->nitems; i++) {
        if (!test->allowUnusedCommands) {
            g_fprintf(stderr,
                      "\nunused test monitor item '%s'",
                      NULLSTR(test->items[i]->identifier));
        }

        qemuMonitorTestItemFree(test->items[i]);
    }
    VIR_FREE(test->items);

    if (test->tmpdir && rmdir(test->tmpdir) < 0)
        VIR_WARN("Failed to remove tempdir: %s", g_strerror(errno));

    VIR_FREE(test->tmpdir);

    if (!test->allowUnusedCommands &&
        test->nitems != 0) {
        qemuMonitorTestError("unused test monitor items are not allowed for this test\n");
    }

    virMutexDestroy(&test->lock);
    VIR_FREE(test);
}


int
qemuMonitorTestAddHandler(qemuMonitorTestPtr test,
                          const char *identifier,
                          qemuMonitorTestResponseCallback cb,
                          void *opaque,
                          virFreeCallback freecb)
{
    qemuMonitorTestItemPtr item;

    if (VIR_ALLOC(item) < 0)
        goto error;

    item->identifier = g_strdup(identifier);
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
    char *cmderr;
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
    VIR_FREE(data->cmderr);
    VIR_FREE(data->response);
    VIR_FREE(data->args);
    VIR_FREE(data->expectArgs);
    VIR_FREE(data);
}


/* Returns -1 on error, 0 if validation was successful/not necessary */
static int
qemuMonitorTestProcessCommandDefaultValidate(qemuMonitorTestPtr test,
                                             const char *cmdname,
                                             virJSONValuePtr args)
{
    g_auto(virBuffer) debug = VIR_BUFFER_INITIALIZER;

    if (!test->qapischema)
        return 0;

    if (test->agent) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Command validation testing is not "
                       "implemented for the guest agent");
        return -1;
    }

    /* 'device_add' needs to be skipped as it does not have fully defined schema */
    if (STREQ(cmdname, "device_add"))
        return 0;

    if (testQEMUSchemaValidateCommand(cmdname, args, test->qapischema,
                                      test->skipValidationDeprecated,
                                      test->skipValidationRemoved,
                                      &debug) < 0) {
        if (virTestGetDebug() == 2) {
            g_autofree char *argstr = NULL;

            if (args)
                argstr = virJSONValueToString(args, true);

            fprintf(stderr,
                    "\nfailed to validate arguments of '%s' against QAPI schema\n"
                    "args:\n%s\nvalidator output:\n %s\n",
                    cmdname, NULLSTR(argstr), virBufferCurrentContent(&debug));
        }

        qemuMonitorTestError("failed to validate arguments of '%s' "
                             "against QAPI schema "
                             "(to see debug output use VIR_TEST_DEBUG=2)",
                             cmdname);
        return -1;
    }

    return 0;
}


static int
qemuMonitorTestProcessCommandDefault(qemuMonitorTestPtr test,
                                     qemuMonitorTestItemPtr item,
                                     const char *cmdstr)
{
    struct qemuMonitorTestHandlerData *data = item->opaque;
    g_autoptr(virJSONValue) val = NULL;
    virJSONValuePtr cmdargs = NULL;
    const char *cmdname;

    if (!(val = virJSONValueFromString(cmdstr)))
        return -1;

    if (!(cmdname = virJSONValueObjectGetString(val, "execute"))) {
        qemuMonitorTestError("Missing command name in %s", cmdstr);
        return -1;
    }

    cmdargs = virJSONValueObjectGet(val, "arguments");
    if (qemuMonitorTestProcessCommandDefaultValidate(test, cmdname, cmdargs) < 0)
        return -1;

    if (data->command_name && STRNEQ(data->command_name, cmdname)) {
        qemuMonitorTestErrorInvalidCommand(data->command_name, cmdname);
        return -1;
    } else {
        return qemuMonitorTestAddResponse(test, data->response);
    }
}


int
qemuMonitorTestAddItem(qemuMonitorTestPtr test,
                       const char *command_name,
                       const char *response)
{
    struct qemuMonitorTestHandlerData *data;

    if (VIR_ALLOC(data) < 0)
        return -1;

    data->command_name = g_strdup(command_name);
    data->response = g_strdup(response);

    return qemuMonitorTestAddHandler(test,
                                     command_name,
                                     qemuMonitorTestProcessCommandDefault,
                                     data, qemuMonitorTestHandlerDataFree);
}


static int
qemuMonitorTestProcessCommandVerbatim(qemuMonitorTestPtr test,
                                      qemuMonitorTestItemPtr item,
                                      const char *cmdstr)
{
    struct qemuMonitorTestHandlerData *data = item->opaque;
    g_autofree char *reformatted = NULL;
    g_autoptr(virJSONValue) json = NULL;
    virJSONValuePtr cmdargs;
    const char *cmdname;
    int ret = -1;

    /* JSON strings will be reformatted to simplify checking */
    if (!(json = virJSONValueFromString(cmdstr)) ||
        !(reformatted = virJSONValueToString(json, false)))
        return -1;

    cmdstr = reformatted;

    /* in this case we do a best-effort schema check if we can find the command */
    if ((cmdname = virJSONValueObjectGetString(json, "execute"))) {
        cmdargs = virJSONValueObjectGet(json, "arguments");
        if (qemuMonitorTestProcessCommandDefaultValidate(test, cmdname, cmdargs) < 0)
            return -1;
    }

    if (STREQ(data->command_name, cmdstr)) {
        ret = qemuMonitorTestAddResponse(test, data->response);
    } else {
        if (data->cmderr) {
            qemuMonitorTestError("%s: %s", data->cmderr, cmdstr);
        } else {
            qemuMonitorTestErrorInvalidCommand(data->command_name, cmdstr);
        }
    }

    return ret;
}


/**
 * qemuMonitorTestAddItemVerbatim:
 * @test: monitor test object
 * @command: full expected command syntax
 * @cmderr: possible explanation of expected command (may be NULL)
 * @response: full reply of @command
 *
 * Adds a test command for the simulated monitor. The full syntax is checked
 * as specified in @command. For JSON monitor tests formatting/whitespace is
 * ignored. If the command on the monitor is not as expected an error containing
 * @cmderr is returned. Otherwise @response is put as-is on the monitor.
 *
 * Returns 0 when command was successfully added, -1 on error.
 */
int
qemuMonitorTestAddItemVerbatim(qemuMonitorTestPtr test,
                               const char *command,
                               const char *cmderr,
                               const char *response)
{
    struct qemuMonitorTestHandlerData *data;

    if (VIR_ALLOC(data) < 0)
        return -1;

    data->response = g_strdup(response);
    data->cmderr = g_strdup(cmderr);

    data->command_name = virJSONStringReformat(command, false);
    if (!data->command_name)
        goto error;

    return qemuMonitorTestAddHandler(test,
                                     command,
                                     qemuMonitorTestProcessCommandVerbatim,
                                     data, qemuMonitorTestHandlerDataFree);

 error:
    qemuMonitorTestHandlerDataFree(data);
    return -1;
}


static int
qemuMonitorTestProcessGuestAgentSync(qemuMonitorTestPtr test,
                                     qemuMonitorTestItemPtr item G_GNUC_UNUSED,
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
        ret = qemuMonitorTestAddErrorResponse(test, "Missing guest-sync command name");
        goto cleanup;
    }

    if (STRNEQ(cmdname, "guest-sync")) {
        ret = qemuMonitorTestAddInvalidCommandResponse(test, "guest-sync", cmdname);
        goto cleanup;
    }

    if (!(args = virJSONValueObjectGet(val, "arguments"))) {
        ret = qemuMonitorTestAddErrorResponse(test, "Missing arguments for guest-sync");
        goto cleanup;
    }

    if (virJSONValueObjectGetNumberUlong(args, "id", &id)) {
        ret = qemuMonitorTestAddErrorResponse(test, "Missing id for guest sync");
        goto cleanup;
    }

    retmsg = g_strdup_printf("{\"return\":%llu}", id);


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
                                     "agent-sync",
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
        qemuMonitorTestError("Missing command name in %s", cmdstr);
        goto cleanup;
    }

    if (data->command_name &&
        STRNEQ(data->command_name, cmdname)) {
        qemuMonitorTestErrorInvalidCommand(data->command_name, cmdname);
        goto cleanup;
    }

    if (!(args = virJSONValueObjectGet(val, "arguments"))) {
        qemuMonitorTestError("Missing arguments section for command '%s'",
                             NULLSTR(data->command_name));
        goto cleanup;
    }

    /* validate the args */
    for (i = 0; i < data->nargs; i++) {
        qemuMonitorTestCommandArgsPtr arg = &data->args[i];
        if (!(argobj = virJSONValueObjectGet(args, arg->argname))) {
            qemuMonitorTestError("Missing argument '%s' for command '%s'",
                                 arg->argname,
                                 NULLSTR(data->command_name));
            goto cleanup;
        }

        /* convert the argument to string */
        if (!(argstr = virJSONValueToString(argobj, false)))
            goto cleanup;

        /* verify that the argument value is expected */
        if (STRNEQ(argstr, arg->argval)) {
            qemuMonitorTestError("Invalid value of argument '%s' of command '%s': "
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

    data->command_name = g_strdup(cmdname);
    data->response = g_strdup(response);

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

        data->args[i].argname = g_strdup(argname);
        data->args[i].argval = g_strdup(argval);
    }

    va_end(args);

    return qemuMonitorTestAddHandler(test,
                                     cmdname,
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
        qemuMonitorTestError("Missing command name in %s", cmdstr);
        goto cleanup;
    }

    if (STRNEQ(data->command_name, cmdname)) {
        qemuMonitorTestErrorInvalidCommand(data->command_name, cmdname);
        goto cleanup;
    }

    if (!(args = virJSONValueObjectGet(val, "arguments"))) {
        qemuMonitorTestError("Missing arguments section for command '%s'",
                             data->command_name);
        goto cleanup;
    }

    /* convert the arguments to string */
    if (!(argstr = virJSONValueToString(args, false)))
        goto cleanup;

    /* verify that the argument value is expected */
    if (STRNEQ(argstr, data->expectArgs)) {
        qemuMonitorTestError("%s: expected arguments: '%s', got: '%s'",
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

    data->command_name = g_strdup(cmdname);
    data->response = g_strdup(response);
    data->expectArgs = g_strdup(cmdargs);

    if (apostrophe) {
        char *tmp = data->expectArgs;

        while (*tmp != '\0') {
            if (*tmp == '\'')
                *tmp = '"';

            tmp++;
        }
    }

    return qemuMonitorTestAddHandler(test,
                                     cmdname,
                                     qemuMonitorTestProcessCommandWithArgStr,
                                     data, qemuMonitorTestHandlerDataFree);

 error:
    qemuMonitorTestHandlerDataFree(data);
    return -1;
}


static void
qemuMonitorTestEOFNotify(qemuMonitorPtr mon G_GNUC_UNUSED,
                         virDomainObjPtr vm G_GNUC_UNUSED,
                         void *opaque G_GNUC_UNUSED)
{
}


static void
qemuMonitorTestErrorNotify(qemuMonitorPtr mon G_GNUC_UNUSED,
                           virDomainObjPtr vm G_GNUC_UNUSED,
                           void *opaque G_GNUC_UNUSED)
{
}


static qemuMonitorCallbacks qemuMonitorTestCallbacks = {
    .eofNotify = qemuMonitorTestEOFNotify,
    .errorNotify = qemuMonitorTestErrorNotify,
    .domainDeviceDeleted = qemuProcessHandleDeviceDeleted,
};


static void
qemuMonitorTestAgentNotify(qemuAgentPtr agent G_GNUC_UNUSED,
                           virDomainObjPtr vm G_GNUC_UNUSED)
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

    tmpdir_template = g_strdup("/tmp/libvirt_XXXXXX");

    if (!(test->tmpdir = g_mkdtemp(tmpdir_template))) {
        virReportSystemError(errno, "%s",
                             "Failed to create temporary directory");
        goto error;
    }

    tmpdir_template = NULL;

    path = g_strdup_printf("%s/qemumonitorjsontest.sock", test->tmpdir);

    if (vm) {
        test->vm = virObjectRef(vm);
    } else {
        test->vm = virDomainObjNew(xmlopt);
        if (!test->vm)
            goto error;
        if (!(test->vm->def = virDomainDefNew()))
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

    return test;

 error:
    VIR_FREE(path);
    VIR_FREE(tmpdir_template);
    qemuMonitorTestFree(test);
    return NULL;

}


static int
qemuMonitorCommonTestInit(qemuMonitorTestPtr test)
{
    int events = VIR_EVENT_HANDLE_READABLE;

    if (!test)
        return -1;

    if (virNetSocketAccept(test->server, &test->client) < 0)
        return -1;

    if (!test->client)
        return -1;

    if (test->outgoingLength > 0)
        events = VIR_EVENT_HANDLE_WRITABLE;

    if (virNetSocketAddIOCallback(test->client,
                                  events,
                                  qemuMonitorTestIO,
                                  test,
                                  NULL) < 0)
        return -1;

    virMutexLock(&test->lock);
    if (virThreadCreate(&test->thread,
                        true,
                        qemuMonitorTestWorker,
                        test) < 0) {
        virMutexUnlock(&test->lock);
        return -1;
    }
    test->started = test->running = true;
    virMutexUnlock(&test->lock);

    return 0;
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


qemuMonitorTestPtr
qemuMonitorTestNew(virDomainXMLOptionPtr xmlopt,
                   virDomainObjPtr vm,
                   virQEMUDriverPtr driver,
                   const char *greeting,
                   virHashTablePtr schema)
{
    qemuMonitorTestPtr test = NULL;
    virDomainChrSourceDef src;

    memset(&src, 0, sizeof(src));

    if (!(test = qemuMonitorCommonTestNew(xmlopt, vm, &src)))
        goto error;

    if (!(test->eventThread = virEventThreadNew("mon-test")))
        goto error;

    test->qapischema = schema;
    if (!(test->mon = qemuMonitorOpen(test->vm,
                                      &src,
                                      true,
                                      0,
                                      virEventThreadGetContext(test->eventThread),
                                      &qemuMonitorTestCallbacks,
                                      driver)))
        goto error;

    virObjectLock(test->mon);

    if (!greeting)
        greeting = QEMU_JSON_GREETING;

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

    if (simple && !(test = qemuMonitorTestNewSimple(xmlopt)))
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
                if (!(test = qemuMonitorTestNew(xmlopt, NULL, NULL,
                                                singleReply, NULL)))
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


/**
 * qemuMonitorTestAllowUnusedCommands:
 * @test: test monitor object
 *
 * By default all test items/commands must be used by the test. This function
 * allows to override the requirement for individual tests e.g. if it's necessary
 * to test some negative scenarios which would not use all commands.
 */
void
qemuMonitorTestAllowUnusedCommands(qemuMonitorTestPtr test)
{
    test->allowUnusedCommands = true;
}


/**
 * qemuMonitorTestSkipDeprecatedValidation:
 * @test: test monitor object
 * @allowRemoved: don't produce errors if command was removed from QMP schema
 *
 * By default if the QMP schema is provided all test items/commands are
 * validated against the schema. This function allows to override the validation
 * and additionally if @allowRemoved is true and if such a command is no longer
 * present in the QMP, only a warning is printed.
 *
 * '@allowRemoved' must be used only if a suitable replacement is already in
 * use and the code tests legacy interactions.
 *
 * Note that currently '@allowRemoved' influences only removed commands. If an
 * argument is removed it will still fail validation.
 */
void
qemuMonitorTestSkipDeprecatedValidation(qemuMonitorTestPtr test,
                                        bool allowRemoved)
{
    test->skipValidationDeprecated = true;
    test->skipValidationRemoved = allowRemoved;
}


static int
qemuMonitorTestFullAddItem(qemuMonitorTestPtr test,
                           const char *filename,
                           const char *command,
                           const char *response,
                           size_t line)
{
    char *cmderr;
    int ret;

    cmderr = g_strdup_printf("wrong expected command in %s:%zu: ", filename, line);

    ret = qemuMonitorTestAddItemVerbatim(test, command, cmderr, response);

    VIR_FREE(cmderr);
    return ret;
}


/**
 * qemuMonitorTestNewFromFileFull:
 * @fileName: File name to load monitor replies from
 * @driver: qemu driver object
 * @vm: domain object (may be null if it's not needed by the test)
 * @qmpschema: QMP schema data hash table if QMP checking is required
 *
 * Create a JSON test monitor simulator object and fill it with expected command
 * sequence and replies specified in @fileName.
 *
 * The file contains a sequence of JSON commands and reply objects separated by
 * empty lines. A command is followed by a reply. The QMP greeting is added
 * automatically.
 *
 * Returns the monitor object on success; NULL on error.
 */
qemuMonitorTestPtr
qemuMonitorTestNewFromFileFull(const char *fileName,
                               virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               virHashTablePtr qmpschema)
{
    qemuMonitorTestPtr ret = NULL;
    char *jsonstr = NULL;
    char *tmp;
    size_t line = 0;

    char *command = NULL;
    char *response = NULL;
    size_t commandln = 0;

    if (virTestLoadFile(fileName, &jsonstr) < 0)
        return NULL;

    if (!(ret = qemuMonitorTestNew(driver->xmlopt, vm, driver, NULL,
                                   qmpschema)))
        goto cleanup;

    tmp = jsonstr;
    command = tmp;
    while ((tmp = strchr(tmp, '\n'))) {
        line++;

        /* eof */
        if (!tmp[1])
            break;

        /* concatenate block which was broken up for readability */
        if (*(tmp + 1) != '\n') {
            *tmp = ' ';
            tmp++;
            continue;
        }

        /* Cut off a single reply. */
        *(tmp + 1) = '\0';

        if (response) {
            if (qemuMonitorTestFullAddItem(ret, fileName, command,
                                           response, commandln) < 0)
                goto error;
            command = NULL;
            response = NULL;
        }

        /* Move the @tmp and @singleReply. */
        tmp += 2;

        if (!command) {
            commandln = line;
            command = tmp;
        } else {
            response = tmp;
        }
    }

    if (command) {
        if (!response) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "missing response for command "
                           "on line '%zu' in '%s'", commandln, fileName);
            goto error;
        }

        if (qemuMonitorTestFullAddItem(ret, fileName, command,
                                       response, commandln) < 0)
            goto error;
    }

 cleanup:
    VIR_FREE(jsonstr);
    return ret;

 error:
    qemuMonitorTestFree(ret);
    ret = NULL;
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

    if (!(test->eventThread = virEventThreadNew("agent-test")))
        goto error;

    if (!(test->agent = qemuAgentOpen(test->vm,
                                      &src,
                                      virEventThreadGetContext(test->eventThread),
                                      &qemuMonitorTestAgentCallbacks,
                                      false)))
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


virDomainObjPtr
qemuMonitorTestGetDomainObj(qemuMonitorTestPtr test)
{
    return test->vm;
}
