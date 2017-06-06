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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virnetclientstream.h"
#include "virnetclient.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virthread.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netclientstream");

struct _virNetClientStream {
    virObjectLockable parent;

    virStreamPtr stream; /* Reverse pointer to parent stream */

    virNetClientProgramPtr prog;
    int proc;
    unsigned serial;

    virError err;

    /* XXX this buffer is unbounded if the client
     * app has domain events registered, since packets
     * may be read off wire, while app isn't ready to
     * recv them. Figure out how to address this some
     * time by stopping consuming any incoming data
     * off the socket....
     */
    virNetMessagePtr rx;
    bool incomingEOF;

    bool allowSkip;
    long long holeLength;  /* Size of incoming hole in stream. */

    virNetClientStreamEventCallback cb;
    void *cbOpaque;
    virFreeCallback cbFree;
    int cbEvents;
    int cbTimer;
    int cbDispatch;
};


static virClassPtr virNetClientStreamClass;
static void virNetClientStreamDispose(void *obj);

static int virNetClientStreamOnceInit(void)
{
    if (!(virNetClientStreamClass = virClassNew(virClassForObjectLockable(),
                                                "virNetClientStream",
                                                sizeof(virNetClientStream),
                                                virNetClientStreamDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetClientStream)


static void
virNetClientStreamEventTimerUpdate(virNetClientStreamPtr st)
{
    if (!st->cb)
        return;

    VIR_DEBUG("Check timer rx=%p cbEvents=%d", st->rx, st->cbEvents);

    if (((st->rx || st->incomingEOF) &&
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

    virObjectLock(st);

    if (st->cb &&
        (st->cbEvents & VIR_STREAM_EVENT_READABLE) &&
        (st->rx || st->incomingEOF))
        events |= VIR_STREAM_EVENT_READABLE;
    if (st->cb &&
        (st->cbEvents & VIR_STREAM_EVENT_WRITABLE))
        events |= VIR_STREAM_EVENT_WRITABLE;

    VIR_DEBUG("Got Timer dispatch events=%d cbEvents=%d rx=%p", events, st->cbEvents, st->rx);
    if (events) {
        virNetClientStreamEventCallback cb = st->cb;
        void *cbOpaque = st->cbOpaque;
        virFreeCallback cbFree = st->cbFree;

        st->cbDispatch = 1;
        virObjectUnlock(st);
        (cb)(st, events, cbOpaque);
        virObjectLock(st);
        st->cbDispatch = 0;

        if (!st->cb && cbFree)
            (cbFree)(cbOpaque);
    }
    virObjectUnlock(st);
}


virNetClientStreamPtr virNetClientStreamNew(virStreamPtr stream,
                                            virNetClientProgramPtr prog,
                                            int proc,
                                            unsigned serial,
                                            bool allowSkip)
{
    virNetClientStreamPtr st;

    if (virNetClientStreamInitialize() < 0)
        return NULL;

    if (!(st = virObjectLockableNew(virNetClientStreamClass)))
        return NULL;

    st->stream = virObjectRef(stream);
    st->prog = virObjectRef(prog);
    st->proc = proc;
    st->serial = serial;
    st->allowSkip = allowSkip;

    return st;
}

void virNetClientStreamDispose(void *obj)
{
    virNetClientStreamPtr st = obj;

    virResetError(&st->err);
    while (st->rx) {
        virNetMessagePtr msg = st->rx;
        virNetMessageQueueServe(&st->rx);
        virNetMessageFree(msg);
    }
    virObjectUnref(st->prog);
    virObjectUnref(st->stream);
}

bool virNetClientStreamMatches(virNetClientStreamPtr st,
                               virNetMessagePtr msg)
{
    bool match = false;
    virObjectLock(st);
    if (virNetClientProgramMatches(st->prog, msg) &&
        st->proc == msg->header.proc &&
        st->serial == msg->header.serial)
        match = true;
    virObjectUnlock(st);
    return match;
}


bool virNetClientStreamRaiseError(virNetClientStreamPtr st)
{
    virObjectLock(st);
    if (st->err.code == VIR_ERR_OK) {
        virObjectUnlock(st);
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
    virObjectUnlock(st);
    return true;
}


int virNetClientStreamSetError(virNetClientStreamPtr st,
                               virNetMessagePtr msg)
{
    virNetMessageError err;
    int ret = -1;

    virObjectLock(st);

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
    virObjectUnlock(st);
    return ret;
}


int virNetClientStreamQueuePacket(virNetClientStreamPtr st,
                                  virNetMessagePtr msg)
{
    virNetMessagePtr tmp_msg;

    VIR_DEBUG("Incoming stream message: stream=%p message=%p", st, msg);

    if (msg->bufferLength == msg->bufferOffset) {
        /* No payload means end of the stream. */
        virObjectLock(st);
        st->incomingEOF = true;
        virNetClientStreamEventTimerUpdate(st);
        virObjectUnlock(st);
        return 0;
    }

    /* Unfortunately, we must allocate new message as the one we
     * get in @msg is going to be cleared later in the process. */

    if (!(tmp_msg = virNetMessageNew(false)))
        return -1;

    /* Copy header */
    memcpy(&tmp_msg->header, &msg->header, sizeof(msg->header));

    /* Steal message buffer */
    tmp_msg->buffer = msg->buffer;
    tmp_msg->bufferLength = msg->bufferLength;
    tmp_msg->bufferOffset = msg->bufferOffset;
    msg->buffer = NULL;
    msg->bufferLength = msg->bufferOffset = 0;

    virObjectLock(st);

    /* Don't distinguish VIR_NET_STREAM and VIR_NET_STREAM_SKIP
     * here just yet. We want in order processing! */
    virNetMessageQueuePush(&st->rx, tmp_msg);

    virNetClientStreamEventTimerUpdate(st);

    virObjectUnlock(st);
    return 0;
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

    virObjectLock(st);

    msg->header.prog = virNetClientProgramGetProgram(st->prog);
    msg->header.vers = virNetClientProgramGetVersion(st->prog);
    msg->header.status = status;
    msg->header.type = VIR_NET_STREAM;
    msg->header.serial = st->serial;
    msg->header.proc = st->proc;

    virObjectUnlock(st);

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


static int
virNetClientStreamSetHole(virNetClientStreamPtr st,
                          long long length,
                          unsigned int flags)
{
    virCheckFlags(0, -1);
    virCheckPositiveArgReturn(length, -1);

    /* Shouldn't happen, But it's better to safe than sorry. */
    if (st->holeLength) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unprocessed hole of size %lld already in the queue"),
                       st->holeLength);
        return -1;
    }

    st->holeLength += length;
    return 0;
}


/**
 * virNetClientStreamHandleHole:
 * @client: client
 * @st: stream
 *
 * Called whenever current message processed in the stream is
 * VIR_NET_STREAM_HOLE. The stream @st is expected to be locked
 * already.
 *
 * Returns: 0 on success,
 *          -1 otherwise.
 */
static int
virNetClientStreamHandleHole(virNetClientPtr client,
                             virNetClientStreamPtr st)
{
    virNetMessagePtr msg;
    virNetStreamHole data;
    int ret = -1;

    VIR_DEBUG("client=%p st=%p", client, st);

    msg = st->rx;
    memset(&data, 0, sizeof(data));

    /* We should not be called unless there's VIR_NET_STREAM_HOLE
     * message at the head of the list. But doesn't hurt to check */
    if (!msg) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("No message in the queue"));
        goto cleanup;
    }

    if (msg->header.type != VIR_NET_STREAM_HOLE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid message prog=%d type=%d serial=%u proc=%d"),
                       msg->header.prog,
                       msg->header.type,
                       msg->header.serial,
                       msg->header.proc);
        goto cleanup;
    }

    /* Server should not send us VIR_NET_STREAM_HOLE unless we
     * have requested so. But does not hurt to check ... */
    if (!st->allowSkip) {
        virReportError(VIR_ERR_RPC, "%s",
                       _("Unexpected stream hole"));
        goto cleanup;
    }

    if (virNetMessageDecodePayload(msg,
                                   (xdrproc_t) xdr_virNetStreamHole,
                                   &data) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed stream hole packet"));
        goto cleanup;
    }

    virNetMessageQueueServe(&st->rx);
    virNetMessageFree(msg);

    if (virNetClientStreamSetHole(st, data.length, data.flags) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0) {
        /* Abort stream? */
    }
    return ret;
}


int virNetClientStreamRecvPacket(virNetClientStreamPtr st,
                                 virNetClientPtr client,
                                 char *data,
                                 size_t nbytes,
                                 bool nonblock,
                                 unsigned int flags)
{
    int rv = -1;
    size_t want;

    VIR_DEBUG("st=%p client=%p data=%p nbytes=%zu nonblock=%d flags=%x",
              st, client, data, nbytes, nonblock, flags);

    virCheckFlags(VIR_STREAM_RECV_STOP_AT_HOLE, -1);

    virObjectLock(st);

 reread:
    if (!st->rx && !st->incomingEOF) {
        virNetMessagePtr msg;
        int ret;

        if (nonblock) {
            VIR_DEBUG("Non-blocking mode and no data available");
            rv = -2;
            goto cleanup;
        }

        if (!(msg = virNetMessageNew(false)))
            goto cleanup;

        msg->header.prog = virNetClientProgramGetProgram(st->prog);
        msg->header.vers = virNetClientProgramGetVersion(st->prog);
        msg->header.type = VIR_NET_STREAM;
        msg->header.serial = st->serial;
        msg->header.proc = st->proc;
        msg->header.status = VIR_NET_CONTINUE;

        VIR_DEBUG("Dummy packet to wait for stream data");
        virObjectUnlock(st);
        ret = virNetClientSendWithReplyStream(client, msg, st);
        virObjectLock(st);
        virNetMessageFree(msg);

        if (ret < 0)
            goto cleanup;
    }

    VIR_DEBUG("After IO rx=%p", st->rx);

    if (st->rx &&
        st->rx->header.type == VIR_NET_STREAM_HOLE &&
        st->holeLength == 0) {
        /* Handle skip sent to us by server. */

        if (virNetClientStreamHandleHole(client, st) < 0)
            goto cleanup;
    }

    if (!st->rx && !st->incomingEOF && st->holeLength == 0) {
        if (nonblock) {
            VIR_DEBUG("Non-blocking mode and no data available");
            rv = -2;
            goto cleanup;
        }

        /* We have consumed all packets from incoming queue but those
         * were only skip packets, no data. Read the stream again. */
        goto reread;
    }

    want = nbytes;

    if (st->holeLength) {
        /* Pretend holeLength zeroes was read from stream. */
        size_t len = want;

        /* Yes, pretend unless we are asked not to. */
        if (flags & VIR_STREAM_RECV_STOP_AT_HOLE) {
            /* No error reporting here. Caller knows what they are doing. */
            rv = -3;
            goto cleanup;
        }

        if (len > st->holeLength)
            len = st->holeLength;

        memset(data, 0, len);
        st->holeLength -= len;
        want -= len;
    }

    while (want &&
           st->rx &&
           st->rx->header.type == VIR_NET_STREAM) {
        virNetMessagePtr msg = st->rx;
        size_t len = want;

        if (len > msg->bufferLength - msg->bufferOffset)
            len = msg->bufferLength - msg->bufferOffset;

        if (!len)
            break;

        memcpy(data + (nbytes - want), msg->buffer + msg->bufferOffset, len);
        want -= len;
        msg->bufferOffset += len;

        if (msg->bufferOffset == msg->bufferLength) {
            virNetMessageQueueServe(&st->rx);
            virNetMessageFree(msg);
        }
    }
    rv = nbytes - want;

    virNetClientStreamEventTimerUpdate(st);

 cleanup:
    virObjectUnlock(st);
    return rv;
}


int
virNetClientStreamSendHole(virNetClientStreamPtr st,
                           virNetClientPtr client,
                           long long length,
                           unsigned int flags)
{
    virNetMessagePtr msg = NULL;
    virNetStreamHole data;
    int ret = -1;

    VIR_DEBUG("st=%p length=%llu", st, length);

    if (!st->allowSkip) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Skipping is not supported with this stream"));
        return -1;
    }

    memset(&data, 0, sizeof(data));
    data.length = length;
    data.flags = flags;

    if (!(msg = virNetMessageNew(false)))
        return -1;

    virObjectLock(st);

    msg->header.prog = virNetClientProgramGetProgram(st->prog);
    msg->header.vers = virNetClientProgramGetVersion(st->prog);
    msg->header.status = VIR_NET_CONTINUE;
    msg->header.type = VIR_NET_STREAM_HOLE;
    msg->header.serial = st->serial;
    msg->header.proc = st->proc;

    virObjectUnlock(st);

    if (virNetMessageEncodeHeader(msg) < 0)
        goto cleanup;

    if (virNetMessageEncodePayload(msg,
                                   (xdrproc_t) xdr_virNetStreamHole,
                                   &data) < 0)
        goto cleanup;

    if (virNetClientSendNoReply(client, msg) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virNetMessageFree(msg);
    return ret;
}


int
virNetClientStreamRecvHole(virNetClientPtr client ATTRIBUTE_UNUSED,
                           virNetClientStreamPtr st,
                           long long *length)
{
    if (!st->allowSkip) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Holes are not supported with this stream"));
        return -1;
    }

    *length = st->holeLength;
    st->holeLength = 0;
    return 0;
}


int virNetClientStreamEventAddCallback(virNetClientStreamPtr st,
                                       int events,
                                       virNetClientStreamEventCallback cb,
                                       void *opaque,
                                       virFreeCallback ff)
{
    int ret = -1;

    virObjectLock(st);
    if (st->cb) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("multiple stream callbacks not supported"));
        goto cleanup;
    }

    virObjectRef(st);
    if ((st->cbTimer =
         virEventAddTimeout(-1,
                            virNetClientStreamEventTimer,
                            st,
                            virObjectFreeCallback)) < 0) {
        virObjectUnref(st);
        goto cleanup;
    }

    st->cb = cb;
    st->cbOpaque = opaque;
    st->cbFree = ff;
    st->cbEvents = events;

    virNetClientStreamEventTimerUpdate(st);

    ret = 0;

 cleanup:
    virObjectUnlock(st);
    return ret;
}

int virNetClientStreamEventUpdateCallback(virNetClientStreamPtr st,
                                          int events)
{
    int ret = -1;

    virObjectLock(st);
    if (!st->cb) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no stream callback registered"));
        goto cleanup;
    }

    st->cbEvents = events;

    virNetClientStreamEventTimerUpdate(st);

    ret = 0;

 cleanup:
    virObjectUnlock(st);
    return ret;
}

int virNetClientStreamEventRemoveCallback(virNetClientStreamPtr st)
{
    int ret = -1;

    virObjectLock(st);
    if (!st->cb) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
    virObjectUnlock(st);
    return ret;
}

bool virNetClientStreamEOF(virNetClientStreamPtr st)
{
    return st->incomingEOF;
}
