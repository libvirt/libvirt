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
#include "rpc/virnetsocket.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
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

    virNetSocket *server;
    virNetSocket *client;

    virEventThread *eventThread;

    qemuMonitor *mon;
    qemuAgent *agent;

    char *tmpdir;

    size_t nitems;
    qemuMonitorTestItem **items;

    virDomainObj *vm;
    GHashTable *qapischema;
};


static void
qemuMonitorTestItemFree(qemuMonitorTestItem *item)
{
    if (!item)
        return;

    g_free(item->identifier);

    if (item->freecb)
        (item->freecb)(item->opaque);

    g_free(item);
}


/*
 * Appends data for a reply to the outgoing buffer
 */
int
qemuMonitorTestAddResponse(qemuMonitorTest *test,
                           const char *response)
{
    size_t want = strlen(response) + 2;
    size_t have = test->outgoingCapacity - test->outgoingLength;

    VIR_DEBUG("Adding response to monitor command: '%s", response);

    if (have < want) {
        size_t need = want - have;
        VIR_EXPAND_N(test->outgoing, test->outgoingCapacity, need);
    }

    want -= 2;
    memcpy(test->outgoing + test->outgoingLength, response, want);
    memcpy(test->outgoing + test->outgoingLength + want, "\r\n", 2);
    test->outgoingLength += want + 2;
    return 0;
}


static int
qemuMonitorTestAddErrorResponseInternal(qemuMonitorTest *test,
                                        const char *usermsg)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
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
qemuMonitorTestAddInvalidCommandResponse(qemuMonitorTest *test,
                                         const char *expectedcommand,
                                         const char *actualcommand)
{
    g_autofree char *msg = NULL;

    msg = g_strdup_printf("expected command '%s' got '%s'", expectedcommand,
                          actualcommand);

    return qemuMonitorTestAddErrorResponseInternal(test, msg);
}


int G_GNUC_PRINTF(2, 3)
qemuMonitorTestAddErrorResponse(qemuMonitorTest *test, const char *errmsg, ...)
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
qemuMonitorTestProcessCommand(qemuMonitorTest *test,
                              const char *cmdstr)
{
    int ret;

    VIR_DEBUG("Processing string from monitor handler: '%s", cmdstr);

    if (test->nitems == 0) {
        qemuMonitorTestError("unexpected command: '%s'", cmdstr);
    } else {
        qemuMonitorTestItem *item = test->items[0];
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
qemuMonitorTestIO(virNetSocket *sock,
                  int events,
                  void *opaque)
{
    qemuMonitorTest *test = opaque;
    bool err = false;
    VIR_LOCK_GUARD lock = virLockGuardLock(&test->lock);

    if (test->quit)
        return;

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
            VIR_EXPAND_N(test->incoming, test->incomingCapacity, 1024);
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
        g_clear_pointer(&test->client, virObjectUnref);
    } else {
        events = VIR_EVENT_HANDLE_READABLE;

        if (test->outgoingLength)
            events |= VIR_EVENT_HANDLE_WRITABLE;

        virNetSocketUpdateIOCallback(sock, events);
    }
}


static void
qemuMonitorTestWorker(void *opaque)
{
    qemuMonitorTest *test = opaque;

    while (true) {
        VIR_WITH_MUTEX_LOCK_GUARD(&test->lock) {
            if (test->quit) {
                test->running = false;
                return;
            }
        }

        if (virEventRunDefaultImpl() < 0) {
            VIR_WITH_MUTEX_LOCK_GUARD(&test->lock) {
                test->quit = true;
                test->running = false;
                return;
            }
        }
    }
}


static void
qemuMonitorTestFreeTimer(int timer G_GNUC_UNUSED,
                         void *opaque G_GNUC_UNUSED)
{
    /* nothing to be done here */
}


void
qemuMonitorTestFree(qemuMonitorTest *test)
{
    size_t i;
    int timer = -1;

    if (!test)
        return;

    VIR_WITH_MUTEX_LOCK_GUARD(&test->lock) {
        if (test->running) {
            test->quit = true;
            /* HACK: Add a dummy timeout to break event loop */
            timer = virEventAddTimeout(0, qemuMonitorTestFreeTimer, NULL, NULL);
        }
    }

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

    g_free(test->incoming);
    g_free(test->outgoing);

    for (i = 0; i < test->nitems; i++) {
        if (!test->allowUnusedCommands) {
            g_fprintf(stderr,
                      "\nunused test monitor item '%s'",
                      NULLSTR(test->items[i]->identifier));
        }

        qemuMonitorTestItemFree(test->items[i]);
    }
    g_free(test->items);

    if (test->tmpdir && rmdir(test->tmpdir) < 0)
        VIR_WARN("Failed to remove tempdir: %s", g_strerror(errno));

    g_free(test->tmpdir);

    if (!test->allowUnusedCommands &&
        test->nitems != 0) {
        qemuMonitorTestError("unused test monitor items are not allowed for this test\n");
    }

    virMutexDestroy(&test->lock);
    g_free(test);
}


void
qemuMonitorTestAddHandler(qemuMonitorTest *test,
                          const char *identifier,
                          qemuMonitorTestResponseCallback cb,
                          void *opaque,
                          virFreeCallback freecb)
{
    qemuMonitorTestItem *item;

    item = g_new0(qemuMonitorTestItem, 1);

    item->identifier = g_strdup(identifier);
    item->cb = cb;
    item->freecb = freecb;
    item->opaque = opaque;

    VIR_WITH_MUTEX_LOCK_GUARD(&test->lock) {
        VIR_APPEND_ELEMENT(test->items, test->nitems, item);
    }
}

void *
qemuMonitorTestItemGetPrivateData(qemuMonitorTestItem *item)
{
    return item ? item->opaque : NULL;
}


struct qemuMonitorTestHandlerData {
    char *command_name;
    char *cmderr;
    char *response;
    char *expectArgs;
};

static void
qemuMonitorTestHandlerDataFree(void *opaque)
{
    struct qemuMonitorTestHandlerData *data = opaque;

    if (!data)
        return;

    g_free(data->command_name);
    g_free(data->cmderr);
    g_free(data->response);
    g_free(data->expectArgs);
    g_free(data);
}


/* Returns -1 on error, 0 if validation was successful/not necessary */
static int
qemuMonitorTestProcessCommandDefaultValidate(qemuMonitorTest *test,
                                             const char *cmdname,
                                             virJSONValue *args)
{
    g_auto(virBuffer) debug = VIR_BUFFER_INITIALIZER;
    bool allowIncomplete = false;

    if (!test->qapischema)
        return 0;

    if (test->agent) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Command validation testing is not "
                       "implemented for the guest agent");
        return -1;
    }

    /* The schema of 'device_add' is incomplete so we relax the validator */
    if (STREQ(cmdname, "device_add"))
        allowIncomplete = true;

    if (testQEMUSchemaValidateCommand(cmdname, args, test->qapischema,
                                      test->skipValidationDeprecated,
                                      test->skipValidationRemoved,
                                      allowIncomplete,
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
qemuMonitorTestProcessCommandDefault(qemuMonitorTest *test,
                                     qemuMonitorTestItem *item,
                                     const char *cmdstr)
{
    struct qemuMonitorTestHandlerData *data = item->opaque;
    g_autoptr(virJSONValue) val = NULL;
    virJSONValue *cmdargs = NULL;
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
qemuMonitorTestAddItem(qemuMonitorTest *test,
                       const char *command_name,
                       const char *response)
{
    struct qemuMonitorTestHandlerData *data;

    data = g_new0(struct qemuMonitorTestHandlerData, 1);

    data->command_name = g_strdup(command_name);
    data->response = g_strdup(response);

    qemuMonitorTestAddHandler(test,
                              command_name,
                              qemuMonitorTestProcessCommandDefault,
                              data, qemuMonitorTestHandlerDataFree);

    return 0;
}


static int
qemuMonitorTestProcessCommandVerbatim(qemuMonitorTest *test,
                                      qemuMonitorTestItem *item,
                                      const char *cmdstr)
{
    struct qemuMonitorTestHandlerData *data = item->opaque;
    g_autofree char *reformatted = NULL;
    g_autoptr(virJSONValue) json = NULL;
    virJSONValue *cmdargs;
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
            qemuMonitorTestError("%s: %s expected %s",
                                 data->cmderr, cmdstr, data->command_name);
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
qemuMonitorTestAddItemVerbatim(qemuMonitorTest *test,
                               const char *command,
                               const char *cmderr,
                               const char *response)
{
    struct qemuMonitorTestHandlerData *data;
    char *reformatted = NULL;

    if (!(reformatted = virJSONStringReformat(command, false)))
        return -1;

    data = g_new0(struct qemuMonitorTestHandlerData, 1);

    data->response = g_strdup(response);
    data->cmderr = g_strdup(cmderr);
    data->command_name = g_steal_pointer(&reformatted);

    qemuMonitorTestAddHandler(test,
                              command,
                              qemuMonitorTestProcessCommandVerbatim,
                              data, qemuMonitorTestHandlerDataFree);

    return 0;
}


static int
qemuMonitorTestProcessGuestAgentSync(qemuMonitorTest *test,
                                     qemuMonitorTestItem *item G_GNUC_UNUSED,
                                     const char *cmdstr)
{
    g_autoptr(virJSONValue) val = NULL;
    virJSONValue *args;
    unsigned long long id;
    const char *cmdname;
    g_autofree char *retmsg = NULL;

    if (!(val = virJSONValueFromString(cmdstr)))
        return -1;

    if (!(cmdname = virJSONValueObjectGetString(val, "execute")))
        return qemuMonitorTestAddErrorResponse(test, "Missing guest-sync command name");

    if (STRNEQ(cmdname, "guest-sync"))
        return qemuMonitorTestAddInvalidCommandResponse(test, "guest-sync", cmdname);

    if (!(args = virJSONValueObjectGet(val, "arguments")))
        return qemuMonitorTestAddErrorResponse(test, "Missing arguments for guest-sync");

    if (virJSONValueObjectGetNumberUlong(args, "id", &id))
        return qemuMonitorTestAddErrorResponse(test, "Missing id for guest sync");

    retmsg = g_strdup_printf("{\"return\":%llu}", id);

    return qemuMonitorTestAddResponse(test, retmsg);
}


int
qemuMonitorTestAddAgentSyncResponse(qemuMonitorTest *test)
{
    if (!test->agent) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "This test is not an agent test");
        return -1;
    }

    qemuMonitorTestAddHandler(test,
                              "agent-sync",
                              qemuMonitorTestProcessGuestAgentSync,
                              NULL, NULL);

    return 0;
}


static void
qemuMonitorTestEOFNotify(qemuMonitor *mon G_GNUC_UNUSED,
                         virDomainObj *vm G_GNUC_UNUSED)
{
}


static void
qemuMonitorTestErrorNotify(qemuMonitor *mon G_GNUC_UNUSED,
                           virDomainObj *vm G_GNUC_UNUSED)
{
}


static qemuMonitorCallbacks qemuMonitorTestCallbacks = {
    .eofNotify = qemuMonitorTestEOFNotify,
    .errorNotify = qemuMonitorTestErrorNotify,
    .domainDeviceDeleted = qemuProcessHandleDeviceDeleted,
};


static void
qemuMonitorTestAgentNotify(qemuAgent *agent G_GNUC_UNUSED,
                           virDomainObj *vm G_GNUC_UNUSED)
{
}


static qemuAgentCallbacks qemuMonitorTestAgentCallbacks = {
    .eofNotify = qemuMonitorTestAgentNotify,
    .errorNotify = qemuMonitorTestAgentNotify,
};


static qemuMonitorTest *
qemuMonitorCommonTestNew(virDomainXMLOption *xmlopt,
                         virDomainObj *vm,
                         virDomainChrSourceDef *src)
{
    g_autoptr(qemuMonitorTest) test = NULL;
    g_autofree char *path = NULL;
    g_autofree char *tmpdir_template = NULL;

    test = g_new0(qemuMonitorTest, 1);

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
        return NULL;
    }

    tmpdir_template = NULL;

    path = g_strdup_printf("%s/qemumonitorjsontest.sock", test->tmpdir);

    if (vm) {
        test->vm = virObjectRef(vm);
    } else {
        test->vm = virDomainObjNew(xmlopt);
        if (!test->vm)
            return NULL;
        if (!(test->vm->def = virDomainDefNew(xmlopt)))
            return NULL;
    }

    if (virNetSocketNewListenUNIX(path, 0700, geteuid(), getegid(),
                                  &test->server) < 0)
        return NULL;

    memset(src, 0, sizeof(*src));
    src->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    src->data.nix.path = (char *)path;
    src->data.nix.listen = false;
    path = NULL;

    if (virNetSocketListen(test->server, 1) < 0)
        return NULL;

    return g_steal_pointer(&test);
}


static int
qemuMonitorCommonTestInit(qemuMonitorTest *test)
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

    VIR_WITH_MUTEX_LOCK_GUARD(&test->lock) {
        if (virThreadCreate(&test->thread, true, qemuMonitorTestWorker, test) < 0)
            return -1;
        test->started = test->running = true;
    }

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


qemuMonitorTest *
qemuMonitorTestNew(virDomainXMLOption *xmlopt,
                   virDomainObj *vm,
                   const char *greeting,
                   GHashTable *schema)
{
    g_autoptr(qemuMonitorTest) test = NULL;
    virDomainChrSourceDef src = { 0 };

    if (!(test = qemuMonitorCommonTestNew(xmlopt, vm, &src)))
        goto error;

    if (!(test->eventThread = virEventThreadNew("mon-test")))
        goto error;

    test->qapischema = schema;
    if (!(test->mon = qemuMonitorOpen(test->vm,
                                      &src,
                                      virEventThreadGetContext(test->eventThread),
                                      &qemuMonitorTestCallbacks)))
        goto error;

    virObjectLock(test->mon);

    if (!greeting)
        greeting = QEMU_JSON_GREETING;

    if (qemuMonitorTestAddResponse(test, greeting) < 0)
        goto error;

    if (qemuMonitorCommonTestInit(test) < 0)
        goto error;

    virDomainChrSourceDefClear(&src);

    return g_steal_pointer(&test);

 error:
    virDomainChrSourceDefClear(&src);
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
qemuMonitorTest *
qemuMonitorTestNewFromFile(const char *fileName,
                           virDomainXMLOption *xmlopt,
                           bool simple)
{
    g_autoptr(qemuMonitorTest) test = NULL;
    g_autofree char *json = NULL;
    char *tmp;
    char *singleReply;

    if (virTestLoadFile(fileName, &json) < 0)
        return NULL;

    if (simple && !(test = qemuMonitorTestNewSimple(xmlopt)))
        return NULL;

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
                    return NULL;
            } else {
                /* Create new mocked monitor with our greeting */
                if (!(test = qemuMonitorTestNew(xmlopt, NULL,
                                                singleReply, NULL)))
                    return NULL;
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
        return NULL;

    return g_steal_pointer(&test);
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
qemuMonitorTestAllowUnusedCommands(qemuMonitorTest *test)
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
qemuMonitorTestSkipDeprecatedValidation(qemuMonitorTest *test,
                                        bool allowRemoved)
{
    test->skipValidationDeprecated = true;
    test->skipValidationRemoved = allowRemoved;
}


static int
qemuMonitorTestFullAddItem(qemuMonitorTest *test,
                           const char *filename,
                           const char *command,
                           const char *response,
                           size_t line)
{
    g_autofree char *cmderr = NULL;

    cmderr = g_strdup_printf("wrong expected command in %s:%zu: ", filename, line);

    return qemuMonitorTestAddItemVerbatim(test, command, cmderr, response);
}


/**
 * qemuMonitorTestProcessFileEntries:
 * @inputstr: input file contents (modified)
 * @fileName: File name of @inputstr (for error reporting)
 * @items: filled with command, reply tuples
 * @nitems: Count of elements in @items.
 *
 * Process a monitor interaction file.
 *
 * The file contains a sequence of JSON commands and reply objects separated by
 * empty lines. A command is followed by a reply.
 */
int
qemuMonitorTestProcessFileEntries(char *inputstr,
                                  const char *fileName,
                                  struct qemuMonitorTestCommandReplyTuple **items,
                                  size_t *nitems)
{
    size_t nalloc = 0;
    char *tmp = inputstr;
    size_t line = 0;
    char *command = inputstr;
    char *response = NULL;
    size_t commandln = 0;

    *items = NULL;
    *nitems = 0;

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

        /* We've seen a new line, increment the counter */
        line++;

        /* Cut off a single reply. */
        *(tmp + 1) = '\0';

        if (response) {
            struct qemuMonitorTestCommandReplyTuple *item;

            VIR_RESIZE_N(*items, nalloc, *nitems, 1);

            item = *items + *nitems;

            item->command = g_steal_pointer(&command);
            item->reply = g_steal_pointer(&response);
            item->line = commandln;
            (*nitems)++;
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
        struct qemuMonitorTestCommandReplyTuple *item;

        if (!response) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "missing response for command "
                           "on line '%zu' in '%s'", commandln, fileName);
            return -1;
        }

        VIR_RESIZE_N(*items, nalloc, *nitems, 1);

        item = *items + *nitems;

        item->command = g_steal_pointer(&command);
        item->reply = g_steal_pointer(&response);
        item->line = commandln;
        (*nitems)++;
    }

    return 0;
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
qemuMonitorTest *
qemuMonitorTestNewFromFileFull(const char *fileName,
                               virQEMUDriver *driver,
                               virDomainObj *vm,
                               GHashTable *qmpschema)
{
    g_autoptr(qemuMonitorTest) ret = NULL;
    g_autofree char *jsonstr = NULL;
    g_autofree struct qemuMonitorTestCommandReplyTuple *items = NULL;
    size_t nitems = 0;
    size_t i;

    if (virTestLoadFile(fileName, &jsonstr) < 0)
        return NULL;

    if (!(ret = qemuMonitorTestNew(driver->xmlopt, vm, NULL, qmpschema)))
        return NULL;

    if (qemuMonitorTestProcessFileEntries(jsonstr, fileName, &items, &nitems) < 0)
        return NULL;

    for (i = 0; i < nitems; i++) {
        struct qemuMonitorTestCommandReplyTuple *item = items + i;

        if (qemuMonitorTestFullAddItem(ret, fileName, item->command, item->reply,
                                       item->line) < 0)
            return NULL;
    }

    return g_steal_pointer(&ret);
}


qemuMonitorTest *
qemuMonitorTestNewAgent(virDomainXMLOption *xmlopt)
{
    g_autoptr(qemuMonitorTest) test = NULL;
    virDomainChrSourceDef src = { 0 };

    if (!(test = qemuMonitorCommonTestNew(xmlopt, NULL, &src)))
        goto error;

    if (!(test->eventThread = virEventThreadNew("agent-test")))
        goto error;

    if (!(test->agent = qemuAgentOpen(test->vm,
                                      &src,
                                      virEventThreadGetContext(test->eventThread),
                                      &qemuMonitorTestAgentCallbacks)))
        goto error;

    virObjectLock(test->agent);

    if (qemuMonitorCommonTestInit(test) < 0)
        goto error;

    virDomainChrSourceDefClear(&src);

    return g_steal_pointer(&test);

 error:
    virDomainChrSourceDefClear(&src);
    return NULL;
}


qemuMonitor *
qemuMonitorTestGetMonitor(qemuMonitorTest *test)
{
    return test->mon;
}


qemuAgent *
qemuMonitorTestGetAgent(qemuMonitorTest *test)
{
    return test->agent;
}


virDomainObj *
qemuMonitorTestGetDomainObj(qemuMonitorTest *test)
{
    return test->vm;
}
