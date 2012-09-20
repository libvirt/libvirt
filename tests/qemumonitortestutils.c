/*
 * Copyright (C) 2011-2012 Red Hat, Inc.
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

#include "qemumonitortestutils.h"

#include "threads.h"
#include "qemu/qemu_monitor.h"
#include "rpc/virnetsocket.h"
#include "memory.h"
#include "util.h"
#include "logging.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _qemuMonitorTestItem qemuMonitorTestItem;
typedef qemuMonitorTestItem *qemuMonitorTestItemPtr;

struct _qemuMonitorTestItem {
    char *command_name;
    char *response;
};

struct _qemuMonitorTest {
    virMutex lock;
    virThread thread;

    bool json;
    bool quit;
    bool running;

    char *incoming;
    size_t incomingLength;
    size_t incomingCapacity;

    char *outgoing;
    size_t outgoingLength;
    size_t outgoingCapacity;

    virNetSocketPtr server;
    virNetSocketPtr client;

    qemuMonitorPtr mon;

    size_t nitems;
    qemuMonitorTestItemPtr *items;

    virDomainObjPtr vm;
};


static void qemuMonitorTestItemFree(qemuMonitorTestItemPtr item);

/*
 * Appends data for a reply onto the outgoing buffer
 */
static int qemuMonitorTestAddReponse(qemuMonitorTestPtr test,
                                     const char *response)
{
    size_t want = strlen(response) + 2;
    size_t have = test->outgoingCapacity - test->outgoingLength;

    if (have < want) {
        size_t need = want - have;
        if (VIR_EXPAND_N(test->outgoing, test->outgoingCapacity, need) < 0) {
            virReportOOMError();
            return -1;
        }
    }

    want -= 2;
    memcpy(test->outgoing + test->outgoingLength,
           response,
           want);
    memcpy(test->outgoing + test->outgoingLength + want,
           "\r\n",
           2);
    test->outgoingLength += want + 2;
    return 0;
}


/*
 * Processes a single line, looking for a matching expected
 * item to reply with, else replies with an error
 */
static int qemuMonitorTestProcessCommandJSON(qemuMonitorTestPtr test,
                                             const char *cmdstr)
{
    virJSONValuePtr val;
    const char *cmdname;
    int ret = -1;

    if (!(val = virJSONValueFromString(cmdstr)))
        return -1;

    if (!(cmdname = virJSONValueObjectGetString(val, "execute"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Missing command name in %s", cmdstr);
        goto cleanup;
    }

    if (test->nitems == 0 ||
        STRNEQ(test->items[0]->command_name, cmdname)) {
        ret = qemuMonitorTestAddReponse(test,
                                        "{ \"error\": "
                                        " { \"desc\": \"Unexpected command\", "
                                        "   \"class\": \"UnexpectedCommand\" } }");
    } else {
        ret = qemuMonitorTestAddReponse(test,
                                        test->items[0]->response);
        qemuMonitorTestItemFree(test->items[0]);
        if (test->nitems == 1) {
            VIR_FREE(test->items);
            test->nitems = 0;
        } else {
            memmove(test->items,
                    test->items + 1,
                    sizeof(test->items[0]) * (test->nitems - 1));
            VIR_SHRINK_N(test->items, test->nitems, 1);
        }
    }

cleanup:
    virJSONValueFree(val);
    return ret;
}


static int qemuMonitorTestProcessCommandText(qemuMonitorTestPtr test,
                                             const char *cmdstr)
{
    char *tmp;
    char *cmdname;
    int ret = -1;

    if (!(cmdname = strdup(cmdstr))) {
        virReportOOMError();
        return -1;
    }
    if (!(tmp = strchr(cmdname, ' '))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Cannot find command name in '%s'", cmdstr);
        goto cleanup;
    }
    *tmp = '\0';

    if (test->nitems == 0 ||
        STRNEQ(test->items[0]->command_name, cmdname)) {
        ret = qemuMonitorTestAddReponse(test,
                                        "unexpected command");
    } else {
        ret = qemuMonitorTestAddReponse(test,
                                        test->items[0]->response);
        qemuMonitorTestItemFree(test->items[0]);
        if (test->nitems == 1) {
            VIR_FREE(test->items);
            test->nitems = 0;
        } else {
            memmove(test->items,
                    test->items + 1,
                    sizeof(test->items[0]) * (test->nitems - 1));
            VIR_SHRINK_N(test->items, test->nitems, 1);
        }
    }

cleanup:
    VIR_FREE(cmdname);
    return ret;
}

static int qemuMonitorTestProcessCommand(qemuMonitorTestPtr test,
                                         const char *cmdstr)
{
    if (test->json)
        return qemuMonitorTestProcessCommandJSON(test ,cmdstr);
    else
        return qemuMonitorTestProcessCommandText(test ,cmdstr);
}

/*
 * Handles read/write of monitor data on the monitor server side
 */
static void qemuMonitorTestIO(virNetSocketPtr sock,
                              int events,
                              void *opaque)
{
    qemuMonitorTestPtr test = opaque;
    bool err = false;

    virMutexLock(&test->lock);
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
        while ((t2 = strstr(t1, "\r\n"))) {
            *t2 = '\0';

            if (qemuMonitorTestProcessCommand(test, t1) < 0) {
                err = true;
                goto cleanup;
            }

            t1 = t2 + 2;
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


static void qemuMonitorTestWorker(void *opaque)
{
    qemuMonitorTestPtr test = opaque;

    virMutexLock(&test->lock);

    while (!test->quit) {
        virMutexUnlock(&test->lock);

        if (virEventRunDefaultImpl() < 0) {
            test->quit = true;
            break;
        }

        virMutexLock(&test->lock);
    }

    test->running = false;

    virMutexUnlock(&test->lock);
    return;
}

static void qemuMonitorTestItemFree(qemuMonitorTestItemPtr item)
{
    if (!item)
        return;

    VIR_FREE(item->command_name);
    VIR_FREE(item->response);

    VIR_FREE(item);
}


void qemuMonitorTestFree(qemuMonitorTestPtr test)
{
    size_t i;

    if (!test)
        return;

    virMutexLock(&test->lock);
    if (test->running) {
        test->quit = true;
    }
    virMutexUnlock(&test->lock);

    if (test->client) {
        virNetSocketRemoveIOCallback(test->client);
        virNetSocketClose(test->client);
        virObjectUnref(test->client);
    }

    virObjectUnref(test->server);
    if (test->mon) {
        qemuMonitorUnlock(test->mon);
        qemuMonitorClose(test->mon);
    }

    virObjectUnref(test->vm);

    if (test->running)
        virThreadJoin(&test->thread);

    for (i = 0 ; i < test->nitems ; i++)
        qemuMonitorTestItemFree(test->items[i]);
    VIR_FREE(test->items);

    virMutexDestroy(&test->lock);
    VIR_FREE(test);
}


int
qemuMonitorTestAddItem(qemuMonitorTestPtr test,
                       const char *command_name,
                       const char *response)
{
    qemuMonitorTestItemPtr item;

    if (VIR_ALLOC(item) < 0)
        goto no_memory;

    if (!(item->command_name = strdup(command_name)) ||
        !(item->response = strdup(response)))
        goto no_memory;

    virMutexLock(&test->lock);
    if (VIR_EXPAND_N(test->items, test->nitems, 1) < 0) {
        virMutexUnlock(&test->lock);
        goto no_memory;
    }
    test->items[test->nitems - 1] = item;

    virMutexUnlock(&test->lock);

    return 0;

no_memory:
    virReportOOMError();
    qemuMonitorTestItemFree(item);
    return -1;
}


static void qemuMonitorTestEOFNotify(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                         virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
}

static void qemuMonitorTestErrorNotify(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                           virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
}


static qemuMonitorCallbacks qemuCallbacks = {
    .eofNotify = qemuMonitorTestEOFNotify,
    .errorNotify = qemuMonitorTestErrorNotify,
};

#define QEMU_JSON_GREETING "{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 1, \"minor\": 0, \"major\": 1}, \"package\": \" (qemu-kvm-1.0.1)\"}, \"capabilities\": []}}"
#define QEMU_TEXT_GREETING "QEMU 1.0,1 monitor - type 'help' for more information"

qemuMonitorTestPtr qemuMonitorTestNew(bool json, virCapsPtr caps)
{
    qemuMonitorTestPtr test;
    const char *path = abs_builddir "/qemumonitorjsontest.sock";
    virDomainChrSourceDef src;

    memset(&src, 0, sizeof(src));
    src.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    src.data.nix.path = (char *)path;
    src.data.nix.listen = false;

    if (VIR_ALLOC(test) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&test->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "Cannot initialize mutex");
        VIR_FREE(test);
        return NULL;
    }

    test->json = json;
    if (!(test->vm = virDomainObjNew(caps)))
        goto error;

    if (virNetSocketNewListenUNIX(path,
                                  0700,
                                  getuid(),
                                  getgid(),
                                  &test->server) < 0)
        goto error;


    if (virNetSocketListen(test->server, 1) < 0)
        goto error;

    if (!(test->mon = qemuMonitorOpen(test->vm,
                                      &src,
                                      json ? 1 : 0,
                                      &qemuCallbacks)))
        goto error;
    qemuMonitorLock(test->mon);

    if (virNetSocketAccept(test->server, &test->client) < 0)
        goto error;
    if (!test->client)
        goto error;

    if (qemuMonitorTestAddReponse(test, json ?
                                  QEMU_JSON_GREETING :
                                  QEMU_TEXT_GREETING) < 0)
        goto error;

    if (virNetSocketAddIOCallback(test->client,
                                  VIR_EVENT_HANDLE_WRITABLE,
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
    test->running = true;
    virMutexUnlock(&test->lock);

    return test;

error:
    qemuMonitorTestFree(test);
    return NULL;
}

qemuMonitorPtr qemuMonitorTestGetMonitor(qemuMonitorTestPtr test)
{
    return test->mon;
}
