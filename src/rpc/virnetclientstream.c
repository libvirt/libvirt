/*
 * virnetclientstream.c: generic network RPC client stream
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virnetclientstream.h"
#include "virnetclient.h"
#include "memory.h"
#include "virterror_internal.h"
#include "logging.h"
#include "event.h"
#include "threads.h"

#define VIR_FROM_THIS VIR_FROM_RPC
#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

struct _virNetClientStream {
    virMutex lock;

    virNetClientProgramPtr prog;
    int proc;
    unsigned serial;
    int refs;

    virError err;

    /* XXX this buffer is unbounded if the client
     * app has domain events registered, since packets
     * may be read off wire, while app isn't ready to
     * recv them. Figure out how to address this some
     * time by stopping consuming any incoming data
     * off the socket....
     */
    char *incoming;
    size_t incomingOffset;
    size_t incomingLength;
    bool incomingEOF;

    virNetClientStreamEventCallback cb;
    void *cbOpaque;
    virFreeCallback cbFree;
    int cbEvents;
    int cbTimer;
    int cbDispatch;
};


static void
virNetClientStreamEventTimerUpdate(virNetClientStreamPtr st)
{
    if (!st->cb)
        return;

    VIR_DEBUG("Check timer offset=%zu %d", st->incomingOffset, st->cbEvents);

    if (((st->incomingOffset || st->incomingEOF) &&
         (st->cbEvents & VIR_STREAM_EVENT_READABLE)) ||
        (st->cbEvents & VIR_STREAM_EVENT_WRITABLE)) {
        VIR_DEBUG("Enabling event timer");
        virEventUpdateTimeout(st->cbTimer, 0);
    } else {
        VIR_DEBUG("Disabling event timer");
        virEventUpdateTimeout(st->cbTimer, -1);
    }
}


static void
virNetClientStreamEventTimer(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virNetClientStreamPtr st = opaque;
    int events = 0;


    virMutexLock(&st->lock);

    if (st->cb &&
        (st->cbEvents & VIR_STREAM_EVENT_READABLE) &&
        (st->incomingOffset || st->incomingEOF))
        events |= VIR_STREAM_EVENT_READABLE;
    if (st->cb &&
        (st->cbEvents & VIR_STREAM_EVENT_WRITABLE))
        events |= VIR_STREAM_EVENT_WRITABLE;

    VIR_DEBUG("Got Timer dispatch %d %d offset=%zu", events, st->cbEvents, st->incomingOffset);
    if (events) {
        virNetClientStreamEventCallback cb = st->cb;
        void *cbOpaque = st->cbOpaque;
        virFreeCallback cbFree = st->cbFree;

        st->cbDispatch = 1;
        virMutexUnlock(&st->lock);
        (cb)(st, events, cbOpaque);
        virMutexLock(&st->lock);
        st->cbDispatch = 0;

        if (!st->cb && cbFree)
            (cbFree)(cbOpaque);
    }
    virMutexUnlock(&st->lock);
}


static void
virNetClientStreamEventTimerFree(void *opaque)
{
    virNetClientStreamPtr st = opaque;
    virNetClientStreamFree(st);
}


virNetClientStreamPtr virNetClientStreamNew(virNetClientProgramPtr prog,
                                            int proc,
                                            unsigned serial)
{
    virNetClientStreamPtr st;

    if (VIR_ALLOC(st) < 0) {
        virReportOOMError();
        return NULL;
    }

    st->refs = 1;
    st->prog = prog;
    st->proc = proc;
    st->serial = serial;

    if (virMutexInit(&st->lock) < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("cannot initialize mutex"));
        VIR_FREE(st);
        return NULL;
    }

    virNetClientProgramRef(prog);

    return st;
}


void virNetClientStreamRef(virNetClientStreamPtr st)
{
    virMutexLock(&st->lock);
    st->refs++;
    virMutexUnlock(&st->lock);
}

void virNetClientStreamFree(virNetClientStreamPtr st)
{
    virMutexLock(&st->lock);
    st->refs--;
    if (st->refs > 0) {
        virMutexUnlock(&st->lock);
        return;
    }

    virMutexUnlock(&st->lock);

    virResetError(&st->err);
    VIR_FREE(st->incoming);
    virMutexDestroy(&st->lock);
    virNetClientProgramFree(st->prog);
    VIR_FREE(st);
}

bool virNetClientStreamMatches(virNetClientStreamPtr st,
                               virNetMessagePtr msg)
{
    bool match = false;
    virMutexLock(&st->lock);
    if (virNetClientProgramMatches(st->prog, msg) &&
        st->proc == msg->header.proc &&
        st->serial == msg->header.serial)
        match = true;
    virMutexUnlock(&st->lock);
    return match;
}


bool virNetClientStreamRaiseError(virNetClientStreamPtr st)
{
    virMutexLock(&st->lock);
    if (st->err.code == VIR_ERR_OK) {
        virMutexUnlock(&st->lock);
        return false;
    }

    virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,
                      st->err.domain,
                      st->err.code,
                      st->err.level,
                      st->err.str1,
                      st->err.str2,
                      st->err.str3,
                      st->err.int1,
                      st->err.int2,
                      "%s", st->err.message ? st->err.message : _("Unknown error"));
    virMutexUnlock(&st->lock);
    return true;
}


int virNetClientStreamSetError(virNetClientStreamPtr st,
                               virNetMessagePtr msg)
{
    virNetMessageError err;
    int ret = -1;

    virMutexLock(&st->lock);

    if (st->err.code != VIR_ERR_OK)
        VIR_DEBUG("Overwriting existing stream error %s", NULLSTR(st->err.message));

    virResetError(&st->err);
    memset(&err, 0, sizeof(err));

    if (virNetMessageDecodePayload(msg, (xdrproc_t)xdr_virNetMessageError, &err) < 0)
        goto cleanup;

    if (err.domain == VIR_FROM_REMOTE &&
        err.code == VIR_ERR_RPC &&
        err.level == VIR_ERR_ERROR &&
        err.message &&
        STRPREFIX(*err.message, "unknown procedure")) {
        st->err.code = VIR_ERR_NO_SUPPORT;
    } else {
        st->err.code = err.code;
    }
    if (err.message) {
        st->err.message = *err.message;
        *err.message = NULL;
    }
    st->err.domain = err.domain;
    st->err.level = err.level;
    if (err.str1) {
        st->err.str1 = *err.str1;
        *err.str1 = NULL;
    }
    if (err.str2) {
        st->err.str2 = *err.str2;
        *err.str2 = NULL;
    }
    if (err.str3) {
        st->err.str3 = *err.str3;
        *err.str3 = NULL;
    }
    st->err.int1 = err.int1;
    st->err.int2 = err.int2;

    st->incomingEOF = true;
    virNetClientStreamEventTimerUpdate(st);

    ret = 0;

cleanup:
    xdr_free((xdrproc_t)xdr_virNetMessageError, (void*)&err);
    virMutexUnlock(&st->lock);
    return ret;
}


int virNetClientStreamQueuePacket(virNetClientStreamPtr st,
                                  virNetMessagePtr msg)
{
    int ret = -1;
    size_t need;

    virMutexLock(&st->lock);
    need = msg->bufferLength - msg->bufferOffset;
    if (need) {
        size_t avail = st->incomingLength - st->incomingOffset;
        if (need > avail) {
            size_t extra = need - avail;
            if (VIR_REALLOC_N(st->incoming,
                              st->incomingLength + extra) < 0) {
                VIR_DEBUG("Out of memory handling stream data");
                goto cleanup;
            }
            st->incomingLength += extra;
        }

        memcpy(st->incoming + st->incomingOffset,
               msg->buffer + msg->bufferOffset,
               msg->bufferLength - msg->bufferOffset);
        st->incomingOffset += (msg->bufferLength - msg->bufferOffset);
    } else {
        st->incomingEOF = true;
    }

    VIR_DEBUG("Stream incoming data offset %zu length %zu EOF %d",
              st->incomingOffset, st->incomingLength,
              st->incomingEOF);
    virNetClientStreamEventTimerUpdate(st);

    ret = 0;

cleanup:
    virMutexUnlock(&st->lock);
    return ret;
}


int virNetClientStreamSendPacket(virNetClientStreamPtr st,
                                 virNetClientPtr client,
                                 int status,
                                 const char *data,
                                 size_t nbytes)
{
    virNetMessagePtr msg;
    VIR_DEBUG("st=%p status=%d data=%p nbytes=%zu", st, status, data, nbytes);

    if (!(msg = virNetMessageNew(false)))
        return -1;

    virMutexLock(&st->lock);

    msg->header.prog = virNetClientProgramGetProgram(st->prog);
    msg->header.vers = virNetClientProgramGetVersion(st->prog);
    msg->header.status = status;
    msg->header.type = VIR_NET_STREAM;
    msg->header.serial = st->serial;
    msg->header.proc = st->proc;

    virMutexUnlock(&st->lock);

    if (virNetMessageEncodeHeader(msg) < 0)
        goto error;

    /* Data packets are async fire&forget, but OK/ERROR packets
     * need a synchronous confirmation
     */
    if (status == VIR_NET_CONTINUE) {
        if (virNetMessageEncodePayloadRaw(msg, data, nbytes) < 0)
            goto error;

        if (virNetClientSendNoReply(client, msg) < 0)
            goto error;
    } else {
        if (virNetMessageEncodePayloadRaw(msg, NULL, 0) < 0)
            goto error;

        if (virNetClientSendWithReply(client, msg) < 0)
            goto error;
    }


    virNetMessageFree(msg);

    return nbytes;

error:
    virNetMessageFree(msg);
    return -1;
}

int virNetClientStreamRecvPacket(virNetClientStreamPtr st,
                                 virNetClientPtr client,
                                 char *data,
                                 size_t nbytes,
                                 bool nonblock)
{
    int rv = -1;
    VIR_DEBUG("st=%p client=%p data=%p nbytes=%zu nonblock=%d",
              st, client, data, nbytes, nonblock);
    virMutexLock(&st->lock);
    if (!st->incomingOffset && !st->incomingEOF) {
        virNetMessagePtr msg;
        int ret;

        if (nonblock) {
            VIR_DEBUG("Non-blocking mode and no data available");
            rv = -2;
            goto cleanup;
        }

        if (!(msg = virNetMessageNew(false))) {
            virReportOOMError();
            goto cleanup;
        }

        msg->header.prog = virNetClientProgramGetProgram(st->prog);
        msg->header.vers = virNetClientProgramGetVersion(st->prog);
        msg->header.type = VIR_NET_STREAM;
        msg->header.serial = st->serial;
        msg->header.proc = st->proc;
        msg->header.status = VIR_NET_CONTINUE;

        VIR_DEBUG("Dummy packet to wait for stream data");
        virMutexUnlock(&st->lock);
        ret = virNetClientSendWithReplyStream(client, msg, st);
        virMutexLock(&st->lock);
        virNetMessageFree(msg);

        if (ret < 0)
            goto cleanup;
    }

    VIR_DEBUG("After IO %zu", st->incomingOffset);
    if (st->incomingOffset) {
        int want = st->incomingOffset;
        if (want > nbytes)
            want = nbytes;
        memcpy(data, st->incoming, want);
        if (want < st->incomingOffset) {
            memmove(st->incoming, st->incoming + want, st->incomingOffset - want);
            st->incomingOffset -= want;
        } else {
            VIR_FREE(st->incoming);
            st->incomingOffset = st->incomingLength = 0;
        }
        rv = want;
    } else {
        rv = 0;
    }

    virNetClientStreamEventTimerUpdate(st);

cleanup:
    virMutexUnlock(&st->lock);
    return rv;
}


int virNetClientStreamEventAddCallback(virNetClientStreamPtr st,
                                       int events,
                                       virNetClientStreamEventCallback cb,
                                       void *opaque,
                                       virFreeCallback ff)
{
    int ret = -1;

    virMutexLock(&st->lock);
    if (st->cb) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("multiple stream callbacks not supported"));
        goto cleanup;
    }

    st->refs++;
    if ((st->cbTimer =
         virEventAddTimeout(-1,
                            virNetClientStreamEventTimer,
                            st,
                            virNetClientStreamEventTimerFree)) < 0) {
        st->refs--;
        goto cleanup;
    }

    st->cb = cb;
    st->cbOpaque = opaque;
    st->cbFree = ff;
    st->cbEvents = events;

    virNetClientStreamEventTimerUpdate(st);

    ret = 0;

cleanup:
    virMutexUnlock(&st->lock);
    return ret;
}

int virNetClientStreamEventUpdateCallback(virNetClientStreamPtr st,
                                          int events)
{
    int ret = -1;

    virMutexLock(&st->lock);
    if (!st->cb) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("no stream callback registered"));
        goto cleanup;
    }

    st->cbEvents = events;

    virNetClientStreamEventTimerUpdate(st);

    ret = 0;

cleanup:
    virMutexUnlock(&st->lock);
    return ret;
}

int virNetClientStreamEventRemoveCallback(virNetClientStreamPtr st)
{
    int ret = -1;

    virMutexUnlock(&st->lock);
    if (!st->cb) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("no stream callback registered"));
        goto cleanup;
    }

    if (!st->cbDispatch &&
        st->cbFree)
        (st->cbFree)(st->cbOpaque);
    st->cb = NULL;
    st->cbOpaque = NULL;
    st->cbFree = NULL;
    st->cbEvents = 0;
    virEventRemoveTimeout(st->cbTimer);

    ret = 0;

cleanup:
    virMutexUnlock(&st->lock);
    return ret;
}

bool virNetClientStreamEOF(virNetClientStreamPtr st)
{
    return st->incomingEOF;
}
