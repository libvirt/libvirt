/*
 * virkeepalive.c: keepalive handling
 *
 * Copyright (C) 2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Jiri Denemark <jdenemar@redhat.com>
 */

#include <config.h>

#include "memory.h"
#include "threads.h"
#include "virfile.h"
#include "logging.h"
#include "util.h"
#include "virterror_internal.h"
#include "virnetsocket.h"
#include "virkeepaliveprotocol.h"
#include "virkeepalive.h"

#define VIR_FROM_THIS VIR_FROM_RPC
#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

struct _virKeepAlive {
    int refs;
    virMutex lock;

    int interval;
    unsigned int count;
    unsigned int countToDeath;
    time_t lastPacketReceived;
    int timer;

    virNetMessagePtr response;
    int responseTimer;

    virKeepAliveSendFunc sendCB;
    virKeepAliveDeadFunc deadCB;
    virKeepAliveFreeFunc freeCB;
    void *client;
};


static void
virKeepAliveLock(virKeepAlivePtr ka)
{
    virMutexLock(&ka->lock);
}

static void
virKeepAliveUnlock(virKeepAlivePtr ka)
{
    virMutexUnlock(&ka->lock);
}


static virNetMessagePtr
virKeepAliveMessage(int proc)
{
    virNetMessagePtr msg;

    if (!(msg = virNetMessageNew(false)))
        return NULL;

    msg->header.prog = KEEPALIVE_PROGRAM;
    msg->header.vers = KEEPALIVE_PROTOCOL_VERSION;
    msg->header.type = VIR_NET_MESSAGE;
    msg->header.proc = proc;

    if (virNetMessageEncodeHeader(msg) < 0 ||
        virNetMessageEncodePayloadEmpty(msg) < 0) {
        virNetMessageFree(msg);
        return NULL;
    }

    return msg;
}


static void
virKeepAliveSend(virKeepAlivePtr ka, virNetMessagePtr msg)
{
    const char *proc = NULL;
    void *client = ka->client;
    virKeepAliveSendFunc sendCB = ka->sendCB;

    switch (msg->header.proc) {
    case KEEPALIVE_PROC_PING:
        proc = "request";
        break;
    case KEEPALIVE_PROC_PONG:
        proc = "response";
        break;
    }

    if (!proc) {
        VIR_WARN("Refusing to send unknown keepalive message: %d",
                 msg->header.proc);
        virNetMessageFree(msg);
        return;
    }

    VIR_DEBUG("Sending keepalive %s to client %p", proc, ka->client);
    PROBE(RPC_KEEPALIVE_SEND,
          "ka=%p client=%p prog=%d vers=%d proc=%d",
          ka, ka->client, msg->header.prog, msg->header.vers, msg->header.proc);

    ka->refs++;
    virKeepAliveUnlock(ka);

    if (sendCB(client, msg) < 0) {
        VIR_WARN("Failed to send keepalive %s to client %p", proc, client);
        virNetMessageFree(msg);
    }

    virKeepAliveLock(ka);
    ka->refs--;
}


static void
virKeepAliveScheduleResponse(virKeepAlivePtr ka)
{
    if (ka->responseTimer == -1)
        return;

    VIR_DEBUG("Scheduling keepalive response to client %p", ka->client);

    if (!ka->response &&
        !(ka->response = virKeepAliveMessage(KEEPALIVE_PROC_PONG))) {
        VIR_WARN("Failed to generate keepalive response");
        return;
    }

    virEventUpdateTimeout(ka->responseTimer, 0);
}


static void
virKeepAliveTimer(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virKeepAlivePtr ka = opaque;
    time_t now = time(NULL);

    virKeepAliveLock(ka);

    PROBE(RPC_KEEPALIVE_TIMEOUT,
          "ka=%p client=%p countToDeath=%d idle=%d",
          ka, ka->client, ka->countToDeath,
          (int) (now - ka->lastPacketReceived));

    if (now - ka->lastPacketReceived < ka->interval - 1) {
        int timeout = ka->interval - (now - ka->lastPacketReceived);
        virEventUpdateTimeout(ka->timer, timeout * 1000);
        goto cleanup;
    }

    if (ka->countToDeath == 0) {
        virKeepAliveDeadFunc deadCB = ka->deadCB;
        void *client = ka->client;

        VIR_WARN("No response from client %p after %d keepalive messages in"
                 " %d seconds",
                 ka->client,
                 ka->count,
                 (int) (now - ka->lastPacketReceived));
        ka->refs++;
        virKeepAliveUnlock(ka);
        deadCB(client);
        virKeepAliveLock(ka);
        ka->refs--;
    } else {
        virNetMessagePtr msg;

        ka->countToDeath--;
        if (!(msg = virKeepAliveMessage(KEEPALIVE_PROC_PING)))
            VIR_WARN("Failed to generate keepalive request");
        else
            virKeepAliveSend(ka, msg);
        virEventUpdateTimeout(ka->timer, ka->interval * 1000);
    }

cleanup:
    virKeepAliveUnlock(ka);
}


static void
virKeepAliveResponseTimer(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virKeepAlivePtr ka = opaque;
    virNetMessagePtr msg;

    virKeepAliveLock(ka);

    VIR_DEBUG("ka=%p, client=%p, response=%p",
              ka, ka->client, ka->response);

    if (ka->response) {
        msg = ka->response;
        ka->response = NULL;
        virKeepAliveSend(ka, msg);
    }

    virEventUpdateTimeout(ka->responseTimer, ka->response ? 0 : -1);

    virKeepAliveUnlock(ka);
}


static void
virKeepAliveTimerFree(void *opaque)
{
    virKeepAliveFree(opaque);
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

    if (VIR_ALLOC(ka) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&ka->lock) < 0) {
        VIR_FREE(ka);
        return NULL;
    }

    ka->refs = 1;
    ka->interval = interval;
    ka->count = count;
    ka->countToDeath = count;
    ka->timer = -1;
    ka->client = client;
    ka->sendCB = sendCB;
    ka->deadCB = deadCB;
    ka->freeCB = freeCB;

    ka->responseTimer = virEventAddTimeout(-1, virKeepAliveResponseTimer,
                                           ka, virKeepAliveTimerFree);
    if (ka->responseTimer < 0) {
        virKeepAliveFree(ka);
        return NULL;
    }
    /* the timer now has a reference to ka */
    ka->refs++;

    PROBE(RPC_KEEPALIVE_NEW,
          "ka=%p client=%p refs=%d",
          ka, ka->client, ka->refs);

    return ka;
}


void
virKeepAliveRef(virKeepAlivePtr ka)
{
    virKeepAliveLock(ka);
    ka->refs++;
    PROBE(RPC_KEEPALIVE_REF,
          "ka=%p client=%p refs=%d",
          ka, ka->client, ka->refs);
    virKeepAliveUnlock(ka);
}


void
virKeepAliveFree(virKeepAlivePtr ka)
{
    if (!ka)
        return;

    virKeepAliveLock(ka);
    PROBE(RPC_KEEPALIVE_FREE,
          "ka=%p client=%p refs=%d",
          ka, ka->client, ka->refs);

    if (--ka->refs > 0) {
        virKeepAliveUnlock(ka);
        return;
    }

    virMutexDestroy(&ka->lock);
    ka->freeCB(ka->client);
    VIR_FREE(ka);
}


int
virKeepAliveStart(virKeepAlivePtr ka,
                  int interval,
                  unsigned int count)
{
    int ret = -1;
    time_t delay;
    int timeout;

    virKeepAliveLock(ka);

    if (ka->timer >= 0) {
        VIR_DEBUG("Keepalive messages already enabled");
        ret = 0;
        goto cleanup;
    }

    if (interval > 0) {
        if (ka->interval > 0) {
            virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("keepalive interval already set"));
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

    delay = time(NULL) - ka->lastPacketReceived;
    if (delay > ka->interval)
        timeout = 0;
    else
        timeout = ka->interval - delay;
    ka->timer = virEventAddTimeout(timeout * 1000, virKeepAliveTimer,
                                   ka, virKeepAliveTimerFree);
    if (ka->timer < 0)
        goto cleanup;

    /* the timer now has another reference to this object */
    ka->refs++;
    ret = 0;

cleanup:
    virKeepAliveUnlock(ka);
    return ret;
}


void
virKeepAliveStop(virKeepAlivePtr ka)
{
    virKeepAliveLock(ka);

    PROBE(RPC_KEEPALIVE_STOP,
          "ka=%p client=%p",
          ka, ka->client);

    if (ka->timer > 0) {
        virEventRemoveTimeout(ka->timer);
        ka->timer = -1;
    }

    if (ka->responseTimer > 0) {
        virEventRemoveTimeout(ka->responseTimer);
        ka->responseTimer = -1;
    }

    virNetMessageFree(ka->response);
    ka->response = NULL;

    virKeepAliveUnlock(ka);
}


bool
virKeepAliveCheckMessage(virKeepAlivePtr ka,
                         virNetMessagePtr msg)
{
    bool ret = false;

    VIR_DEBUG("ka=%p, client=%p, msg=%p",
              ka, ka ? ka->client : "(null)", msg);

    if (!ka)
        return false;

    virKeepAliveLock(ka);

    ka->countToDeath = ka->count;
    ka->lastPacketReceived = time(NULL);

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
            virKeepAliveScheduleResponse(ka);
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

    virKeepAliveUnlock(ka);

    return ret;
}
