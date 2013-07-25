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
qemuMonitorTestAddReponse(qemuMonitorTestPtr test,
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
    memcpy(test->outgoing + test->outgoingLength, response, want);
    memcpy(test->outgoing + test->outgoingLength + want, "\r\n", 2);
    test->outgoingLength += want + 2;
    return 0;
}


static int
qemuMonitorTestAddUnexpectedErrorResponse(qemuMonitorTestPtr test)
{
    if (test->json) {
        return qemuMonitorTestAddReponse(test,
                                         "{ \"error\": "
                                         " { \"desc\": \"Unexpected command\", "
                                         "   \"class\": \"UnexpectedCommand\" } }");
    } else {
        return qemuMonitorTestAddReponse(test, "unexpected command");
    }
}


static int
qemuMonitorTestProcessCommand(qemuMonitorTestPtr test,
                              const char *cmdstr)
{
    int ret;

    if (test->nitems == 0) {
        return qemuMonitorTestAddUnexpectedErrorResponse(test);
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
        while ((t2 = strstr(t1, "\n"))) {
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

    virObjectUnref(test->vm);

    if (test->running)
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


struct qemuMonitorTestDefaultHandlerData {
    const char *command_name;
    const char *response;
};


static int
qemuMonitorTestProcessCommandDefault(qemuMonitorTestPtr test,
                                     qemuMonitorTestItemPtr item,
                                     const char *cmdstr)
{
    struct qemuMonitorTestDefaultHandlerData *data = item->opaque;
    virJSONValuePtr val = NULL;
    char *cmdcopy = NULL;
    const char *cmdname;
    char *tmp;
    int ret = -1;

    if (test->json) {
        if (!(val = virJSONValueFromString(cmdstr)))
            return -1;

        if (!(cmdname = virJSONValueObjectGetString(val, "execute"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "Missing command name in %s", cmdstr);
            goto cleanup;
        }
    } else {
        if (VIR_STRDUP(cmdcopy, cmdstr) < 0)
            return -1;

        cmdname = cmdcopy;

        if (!(tmp = strchr(cmdcopy, ' '))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "Cannot find command name in '%s'", cmdstr);
            goto cleanup;
        }
        *tmp = '\0';
    }

    if (STRNEQ(data->command_name, cmdname))
        ret = qemuMonitorTestAddUnexpectedErrorResponse(test);
    else
        ret = qemuMonitorTestAddReponse(test, data->response);

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
    struct qemuMonitorTestDefaultHandlerData *data;

    if (VIR_ALLOC(data) < 0)
        return -1;

    data->command_name = command_name;
    data->response = response;

    return qemuMonitorTestAddHandler(test,
                                     qemuMonitorTestProcessCommandDefault,
                                     data,
                                     free);
}


static void
qemuMonitorTestEOFNotify(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                         virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
}


static void
qemuMonitorTestErrorNotify(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                           virDomainObjPtr vm ATTRIBUTE_UNUSED)
{
}


static qemuMonitorCallbacks qemuMonitorTestCallbacks = {
    .eofNotify = qemuMonitorTestEOFNotify,
    .errorNotify = qemuMonitorTestErrorNotify,
};


static qemuMonitorTestPtr
qemuMonitorCommonTestNew(virDomainXMLOptionPtr xmlopt,
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

    if (!(test->vm = virDomainObjNew(xmlopt)))
        goto error;

    if (virNetSocketNewListenUNIX(path, 0700, getuid(), getgid(),
                                  &test->server) < 0)
        goto error;

    memset(src, 0, sizeof(*src));
    src->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    src->data.nix.path = (char *)path;
    src->data.nix.listen = false;

    if (virNetSocketListen(test->server, 1) < 0)
        goto error;

cleanup:
    return test;

error:
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
    test->running = true;
    virMutexUnlock(&test->lock);

    return 0;

error:
    qemuMonitorTestFree(test);
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
qemuMonitorTestNew(bool json, virDomainXMLOptionPtr xmlopt)
{
    qemuMonitorTestPtr test = NULL;
    virDomainChrSourceDef src;

    if (!(test = qemuMonitorCommonTestNew(xmlopt, &src)))
        goto error;

    test->json = json;
    if (!(test->mon = qemuMonitorOpen(test->vm,
                                      &src,
                                      json,
                                      &qemuMonitorTestCallbacks)))
        goto error;

    virObjectLock(test->mon);

    if (qemuMonitorTestAddReponse(test, json ?
                                  QEMU_JSON_GREETING :
                                  QEMU_TEXT_GREETING) < 0)
        goto error;

    if (qemuMonitorCommonTestInit(test) < 0)
        goto error;

    virDomainChrSourceDefClear(&src);

    return test;

error:
    qemuMonitorTestFree(test);
    return NULL;
}


qemuMonitorPtr
qemuMonitorTestGetMonitor(qemuMonitorTestPtr test)
{
    return test->mon;
}
