/*
 * virkeepalive.c: keepalive handling
 *
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
 * Author: Jiri Denemark <jdenemar@redhat.com>
 */

#include <config.h>

#include "viralloc.h"
#include "virthread.h"
#include "virfile.h"
#include "virlog.h"
#include "virerror.h"
#include "virnetsocket.h"
#include "virkeepaliveprotocol.h"
#include "virkeepalive.h"
#include "virprobe.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.keepalive");

struct _virKeepAlive {
    virObjectLockable parent;

    int interval;
    unsigned int count;
    unsigned int countToDeath;
    time_t lastPacketReceived;
    time_t intervalStart;
    int timer;

    virKeepAliveSendFunc sendCB;
    virKeepAliveDeadFunc deadCB;
    virKeepAliveFreeFunc freeCB;
    void *client;
};


static virClassPtr virKeepAliveClass;
static void virKeepAliveDispose(void *obj);

static int virKeepAliveOnceInit(void)
{
    if (!(virKeepAliveClass = virClassNew(virClassForObjectLockable(),
                                          "virKeepAlive",
                                          sizeof(virKeepAlive),
                                          virKeepAliveDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virKeepAlive)

static virNetMessagePtr
virKeepAliveMessage(virKeepAlivePtr ka, int proc)
{
    virNetMessagePtr msg;
    const char *procstr = NULL;

    switch (proc) {
    case KEEPALIVE_PROC_PING:
        procstr = "request";
        break;
    case KEEPALIVE_PROC_PONG:
        procstr = "response";
        break;
    default:
        VIR_WARN("Refusing to send unknown keepalive message: %d", proc);
        return NULL;
    }

    if (!(msg = virNetMessageNew(false)))
        goto error;

    msg->header.prog = KEEPALIVE_PROGRAM;
    msg->header.vers = KEEPALIVE_PROTOCOL_VERSION;
    msg->header.type = VIR_NET_MESSAGE;
    msg->header.proc = proc;

    if (virNetMessageEncodeHeader(msg) < 0 ||
        virNetMessageEncodePayloadEmpty(msg) < 0) {
        virNetMessageFree(msg);
        goto error;
    }

    VIR_DEBUG("Sending keepalive %s to client %p", procstr, ka->client);
    PROBE(RPC_KEEPALIVE_SEND,
          "ka=%p client=%p prog=%d vers=%d proc=%d",
          ka, ka->client, msg->header.prog, msg->header.vers, msg->header.proc);

    return msg;

 error:
    VIR_WARN("Failed to generate keepalive %s", procstr);
    return NULL;
}


static bool
virKeepAliveTimerInternal(virKeepAlivePtr ka,
                          virNetMessagePtr *msg)
{
    time_t now = time(NULL);
    int timeval;

    if (ka->interval <= 0 || ka->intervalStart == 0)
        return false;

    if (now - ka->intervalStart < ka->interval) {
        timeval = ka->interval - (now - ka->intervalStart);
        virEventUpdateTimeout(ka->timer, timeval * 1000);
        return false;
    }

    timeval = now - ka->lastPacketReceived;
    PROBE(RPC_KEEPALIVE_TIMEOUT,
          "ka=%p client=%p countToDeath=%d idle=%d",
          ka, ka->client, ka->countToDeath, timeval);

    if (ka->countToDeath == 0) {
        VIR_DEBUG("No response from client %p after %d keepalive messages "
                  "in %d seconds",
                  ka->client, ka->count, timeval);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("connection closed due to keepalive timeout"));
        return true;
    } else {
        ka->countToDeath--;
        ka->intervalStart = now;
        *msg = virKeepAliveMessage(ka, KEEPALIVE_PROC_PING);
        virEventUpdateTimeout(ka->timer, ka->interval * 1000);
        return false;
    }
}


static void
virKeepAliveTimer(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virKeepAlivePtr ka = opaque;
    virNetMessagePtr msg = NULL;
    bool dead;
    void *client;

    virObjectRef(ka);
    virObjectLock(ka);

    client = ka->client;
    dead = virKeepAliveTimerInternal(ka, &msg);

    virObjectUnlock(ka);

    if (!dead && !msg)
        goto cleanup;

    if (dead) {
        ka->deadCB(client);
    } else if (ka->sendCB(client, msg) < 0) {
        VIR_WARN("Failed to send keepalive request to client %p", client);
        virNetMessageFree(msg);
    }

 cleanup:
    virObjectUnref(ka);
}


virKeepAlivePtr
virKeepAliveNew(int interval,
                unsigned int count,
                void *client,
                virKeepAliveSendFunc sendCB,
                virKeepAliveDeadFunc deadCB,
                virKeepAliveFreeFunc freeCB)
{
    virKeepAlivePtr ka;

    VIR_DEBUG("client=%p, interval=%d, count=%u", client, interval, count);

    if (virKeepAliveInitialize() < 0)
        return NULL;

    if (!(ka = virObjectLockableNew(virKeepAliveClass)))
        return NULL;

    ka->interval = interval;
    ka->count = count;
    ka->countToDeath = count;
    ka->timer = -1;
    ka->client = client;
    ka->sendCB = sendCB;
    ka->deadCB = deadCB;
    ka->freeCB = freeCB;

    PROBE(RPC_KEEPALIVE_NEW,
          "ka=%p client=%p",
          ka, ka->client);

    return ka;
}


void
virKeepAliveDispose(void *obj)
{
    virKeepAlivePtr ka = obj;

    PROBE(RPC_KEEPALIVE_DISPOSE,
          "ka=%p", ka);

    ka->freeCB(ka->client);
}


int
virKeepAliveStart(virKeepAlivePtr ka,
                  int interval,
                  unsigned int count)
{
    int ret = -1;
    time_t delay;
    int timeout;
    time_t now;

    virObjectLock(ka);

    if (ka->timer >= 0) {
        VIR_DEBUG("Keepalive messages already enabled");
        ret = 0;
        goto cleanup;
    }

    if (interval > 0) {
        if (ka->interval > 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("keepalive interval already set"));
            goto cleanup;
        }
        /* Guard against overflow */
        if (interval > INT_MAX / 1000) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("keepalive interval %d too large"), interval);
            goto cleanup;
        }
        ka->interval = interval;
        ka->count = count;
        ka->countToDeath = count;
    }

    if (ka->interval <= 0) {
        VIR_DEBUG("Keepalive messages disabled by configuration");
        ret = 0;
        goto cleanup;
    }

    PROBE(RPC_KEEPALIVE_START,
          "ka=%p client=%p interval=%d count=%u",
          ka, ka->client, interval, count);

    now = time(NULL);
    delay = now - ka->lastPacketReceived;
    if (delay > ka->interval)
        timeout = 0;
    else
        timeout = ka->interval - delay;
    ka->intervalStart = now - (ka->interval - timeout);
    ka->timer = virEventAddTimeout(timeout * 1000, virKeepAliveTimer,
                                   ka, virObjectFreeCallback);
    if (ka->timer < 0)
        goto cleanup;

    /* the timer now has another reference to this object */
    virObjectRef(ka);
    ret = 0;

 cleanup:
    virObjectUnlock(ka);
    return ret;
}


void
virKeepAliveStop(virKeepAlivePtr ka)
{
    virObjectLock(ka);

    PROBE(RPC_KEEPALIVE_STOP,
          "ka=%p client=%p",
          ka, ka->client);

    if (ka->timer > 0) {
        virEventRemoveTimeout(ka->timer);
        ka->timer = -1;
    }

    virObjectUnlock(ka);
}


int
virKeepAliveTimeout(virKeepAlivePtr ka)
{
    int timeout;

    if (!ka)
        return -1;

    virObjectLock(ka);

    if (ka->interval <= 0 || ka->intervalStart == 0) {
        timeout = -1;
    } else {
        timeout = ka->interval - (time(NULL) - ka->intervalStart);
        if (timeout < 0)
            timeout = 0;
        /* Guard against overflow */
        if (timeout > INT_MAX / 1000)
            timeout = INT_MAX / 1000;
    }

    virObjectUnlock(ka);

    if (timeout < 0)
        return -1;
    else
        return timeout * 1000;
}


bool
virKeepAliveTrigger(virKeepAlivePtr ka,
                    virNetMessagePtr *msg)
{
    bool dead;

    *msg = NULL;
    if (!ka)
        return false;

    virObjectLock(ka);
    dead = virKeepAliveTimerInternal(ka, msg);
    virObjectUnlock(ka);

    return dead;
}


bool
virKeepAliveCheckMessage(virKeepAlivePtr ka,
                         virNetMessagePtr msg,
                         virNetMessagePtr *response)
{
    bool ret = false;

    VIR_DEBUG("ka=%p, client=%p, msg=%p",
              ka, ka ? ka->client : "(null)", msg);

    *response = NULL;
    if (!ka)
        return false;

    virObjectLock(ka);

    ka->countToDeath = ka->count;
    ka->lastPacketReceived = ka->intervalStart = time(NULL);

    if (msg->header.prog == KEEPALIVE_PROGRAM &&
        msg->header.vers == KEEPALIVE_PROTOCOL_VERSION &&
        msg->header.type == VIR_NET_MESSAGE) {
        PROBE(RPC_KEEPALIVE_RECEIVED,
              "ka=%p client=%p prog=%d vers=%d proc=%d",
              ka, ka->client, msg->header.prog,
              msg->header.vers, msg->header.proc);
        ret = true;
        switch (msg->header.proc) {
        case KEEPALIVE_PROC_PING:
            VIR_DEBUG("Got keepalive request from client %p", ka->client);
            *response = virKeepAliveMessage(ka, KEEPALIVE_PROC_PONG);
            break;

        case KEEPALIVE_PROC_PONG:
            VIR_DEBUG("Got keepalive response from client %p", ka->client);
            break;

        default:
            VIR_DEBUG("Ignoring unknown keepalive message %d from client %p",
                      msg->header.proc, ka->client);
        }
    }

    if (ka->timer >= 0)
        virEventUpdateTimeout(ka->timer, ka->interval * 1000);

    virObjectUnlock(ka);

    return ret;
}
