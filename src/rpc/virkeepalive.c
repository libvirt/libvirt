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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
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

struct _virKeepAlive {
    int refs;
    virMutex lock;

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
    VIR_FREE(msg);
    return NULL;
}


static bool
virKeepAliveTimerInternal(virKeepAlivePtr ka,
                          virNetMessagePtr *msg)
{
    time_t now = time(NULL);

    if (ka->interval <= 0 || ka->intervalStart == 0)
        return false;

    if (now - ka->intervalStart < ka->interval) {
        int timeout = ka->interval - (now - ka->intervalStart);
        virEventUpdateTimeout(ka->timer, timeout * 1000);
        return false;
    }

    PROBE(RPC_KEEPALIVE_TIMEOUT,
          "ka=%p client=%p countToDeath=%d idle=%d",
          ka, ka->client, ka->countToDeath,
          (int) (now - ka->lastPacketReceived));


    if (ka->countToDeath == 0) {
        VIR_WARN("No response from client %p after %d keepalive messages in"
                 " %d seconds",
                 ka->client,
                 ka->count,
                 (int) (now - ka->lastPacketReceived));
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

    virKeepAliveLock(ka);

    client = ka->client;
    dead = virKeepAliveTimerInternal(ka, &msg);

    if (!dead && !msg)
        goto cleanup;

    ka->refs++;
    virKeepAliveUnlock(ka);

    if (dead) {
        ka->deadCB(client);
    } else if (ka->sendCB(client, msg) < 0) {
        VIR_WARN("Failed to send keepalive request to client %p", client);
        virNetMessageFree(msg);
    }

    virKeepAliveLock(ka);
    ka->refs--;

cleanup:
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
    time_t now;

    virKeepAliveLock(ka);

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

    virKeepAliveUnlock(ka);
}


int
virKeepAliveTimeout(virKeepAlivePtr ka)
{
    int timeout;

    if (!ka)
        return -1;

    virKeepAliveLock(ka);

    if (ka->interval <= 0 || ka->intervalStart == 0) {
        timeout = -1;
    } else {
        timeout = ka->interval - (time(NULL) - ka->intervalStart);
        if (timeout < 0)
            timeout = 0;
    }

    virKeepAliveUnlock(ka);

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

    virKeepAliveLock(ka);
    dead = virKeepAliveTimerInternal(ka, msg);
    virKeepAliveUnlock(ka);

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

    virKeepAliveLock(ka);

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

    virKeepAliveUnlock(ka);

    return ret;
}
