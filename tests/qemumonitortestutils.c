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

#include "qemumonitortestutils.h"

#include "virthread.h"
#include "qemu/qemu_monitor.h"
#include "rpc/virnetsocket.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virstring.h"

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

    char *tmpdir;

    size_t nitems;
    qemuMonitorTestItemPtr *items;

    virDomainObjPtr vm;
};


static void qemuMonitorTestItemFree(qemuMonitorTestItemPtr item);

/*
 * Appends data for a reply to the outgoing buffer
 */
static int qemuMonitorTestAddReponse(qemuMonitorTestPtr test,
                                     const char *response)
{
    size_t want = strlen(response) + 2;
    size_t have = test->outgoingCapacity - test->outgoingLength;

    if (have < want) {
        size_t need = want - have;
        if (VIR_EXPAND_N(test->outgoing, test->outgoingCapacity, need) < 0)
            return -1;
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

    if (VIR_STRDUP(cmdname, cmdstr) < 0)
        return -1;
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

static void qemuMonitorTestItemFree(qemuMonitorTestItemPtr item)
{
    if (!item)
        return;

    VIR_FREE(item->command_name);
    VIR_FREE(item->response);

    VIR_FREE(item);
}


static void
qemuMonitorTestFreeTimer(int timer ATTRIBUTE_UNUSED, void *opaque ATTRIBUTE_UNUSED)
{
    /* nothing to be done here */
}


void qemuMonitorTestFree(qemuMonitorTestPtr test)
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

    virObjectUnref(test->vm);

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
qemuMonitorTestAddItem(qemuMonitorTestPtr test,
                       const char *command_name,
                       const char *response)
{
    qemuMonitorTestItemPtr item;

    if (VIR_ALLOC(item) < 0)
        goto error;

    if (VIR_STRDUP(item->command_name, command_name) < 0 ||
        VIR_STRDUP(item->response, response) < 0)
        goto error;

    virMutexLock(&test->lock);
    if (VIR_EXPAND_N(test->items, test->nitems, 1) < 0) {
        virMutexUnlock(&test->lock);
        goto error;
    }
    test->items[test->nitems - 1] = item;

    virMutexUnlock(&test->lock);

    return 0;

error:
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
/* We skip the normal handshake reply of "{\"execute\":\"qmp_capabilities\"}" */

#define QEMU_TEXT_GREETING "QEMU 1.0,1 monitor - type 'help' for more information"

qemuMonitorTestPtr qemuMonitorTestNew(bool json, virDomainXMLOptionPtr xmlopt)
{
    qemuMonitorTestPtr test = NULL;
    virDomainChrSourceDef src;
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

    test->json = json;
    if (!(test->vm = virDomainObjNew(xmlopt)))
        goto error;

    if (virNetSocketNewListenUNIX(path,
                                  0700,
                                  getuid(),
                                  getgid(),
                                  &test->server) < 0)
        goto error;

    memset(&src, 0, sizeof(src));
    src.type = VIR_DOMAIN_CHR_TYPE_UNIX;
    src.data.nix.path = (char *)path;
    src.data.nix.listen = false;

    if (virNetSocketListen(test->server, 1) < 0)
        goto error;

    if (!(test->mon = qemuMonitorOpen(test->vm,
                                      &src,
                                      json,
                                      &qemuCallbacks)))
        goto error;
    virObjectLock(test->mon);

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

cleanup:
    VIR_FREE(path);
    return test;

error:
    VIR_FREE(tmpdir_template);
    qemuMonitorTestFree(test);
    test = NULL;
    goto cleanup;
}

qemuMonitorPtr qemuMonitorTestGetMonitor(qemuMonitorTestPtr test)
{
    return test->mon;
}
