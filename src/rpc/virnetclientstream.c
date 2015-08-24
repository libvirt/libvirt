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
    struct iovec *incomingVec; /* I/O Vector to hold data */
    size_t writeVec;           /* Vectors produced */
    size_t readVec;            /* Vectors consumed */
    bool incomingEOF;

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

    VIR_DEBUG("Check timer readVec %zu writeVec %zu %d", st->readVec, st->writeVec, st->cbEvents);

    if ((((st->readVec < st->writeVec) || st->incomingEOF) &&
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
        ((st->readVec < st->writeVec) || st->incomingEOF))
        events |= VIR_STREAM_EVENT_READABLE;
    if (st->cb &&
        (st->cbEvents & VIR_STREAM_EVENT_WRITABLE))
        events |= VIR_STREAM_EVENT_WRITABLE;

    VIR_DEBUG("Got Timer dispatch %d %d readVec %zu writeVec %zu", events, st->cbEvents,
              st->readVec, st->writeVec);
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


virNetClientStreamPtr virNetClientStreamNew(virNetClientProgramPtr prog,
                                            int proc,
                                            unsigned serial)
{
    virNetClientStreamPtr st;

    if (virNetClientStreamInitialize() < 0)
        return NULL;

    if (!(st = virObjectLockableNew(virNetClientStreamClass)))
        return NULL;

    st->prog = prog;
    st->proc = proc;
    st->serial = serial;

    virObjectRef(prog);

    return st;
}

void virNetClientStreamDispose(void *obj)
{
    virNetClientStreamPtr st = obj;

    virResetError(&st->err);
    VIR_FREE(st->incomingVec);
    virObjectUnref(st->prog);
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
    int ret = -1;
    struct iovec iov;
    char *base;
    size_t piece, pieces, length, offset = 0, size = 1024*1024;

    virObjectLock(st);

    length = msg->bufferLength - msg->bufferOffset;

    if (length == 0) {
        st->incomingEOF = true;
        goto end;
    }

    pieces = VIR_DIV_UP(length, size);
    for (piece = 0; piece < pieces; piece++) {
        if (size > length - offset)
            size = length - offset;

        if (VIR_ALLOC_N(base, size)) {
            VIR_DEBUG("Allocation failed");
            goto cleanup;
        }

        memcpy(base, msg->buffer + msg->bufferOffset + offset, size);
        iov.iov_base = base;
        iov.iov_len = size;
        offset += size;

        if (VIR_APPEND_ELEMENT(st->incomingVec, st->writeVec, iov) < 0) {
            VIR_DEBUG("Append failed");
            VIR_FREE(base);
            goto cleanup;
        }
        VIR_DEBUG("Wrote piece of vector. readVec %zu, writeVec %zu size %zu",
                  st->readVec, st->writeVec, size);
    }

 end:
    virNetClientStreamEventTimerUpdate(st);
    ret = 0;

 cleanup:
    VIR_DEBUG("Stream incoming data readVec %zu writeVec %zu EOF %d",
              st->readVec, st->writeVec, st->incomingEOF);
    virObjectUnlock(st);
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

int virNetClientStreamRecvPacket(virNetClientStreamPtr st,
                                 virNetClientPtr client,
                                 char *data,
                                 size_t nbytes,
                                 bool nonblock)
{
    int ret = -1;
    size_t partial, offset;

    virObjectLock(st);

    VIR_DEBUG("st=%p client=%p data=%p nbytes=%zu nonblock=%d",
              st, client, data, nbytes, nonblock);

    if ((st->readVec >= st->writeVec) && !st->incomingEOF) {
        virNetMessagePtr msg;
        int rv;

        if (nonblock) {
            VIR_DEBUG("Non-blocking mode and no data available");
            ret = -2;
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
        rv = virNetClientSendWithReplyStream(client, msg, st);
        virObjectLock(st);
        virNetMessageFree(msg);

        if (rv < 0)
            goto cleanup;
    }

    offset = 0;
    partial = nbytes;

    while (st->incomingVec && (st->readVec < st->writeVec)) {
        struct iovec *iov = st->incomingVec + st->readVec;

        if (!iov || !iov->iov_base) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("NULL pointer encountered"));
            goto cleanup;
        }

        if (partial < iov->iov_len) {
            memcpy(data+offset, iov->iov_base, partial);
            memmove(iov->iov_base, (char*)iov->iov_base+partial,
                    iov->iov_len-partial);
            iov->iov_len -= partial;
            offset += partial;
            VIR_DEBUG("Consumed %zu, left %zu", partial, iov->iov_len);
            break;
        }

        memcpy(data+offset, iov->iov_base, iov->iov_len);
        VIR_DEBUG("Consumed %zu. Moving to next piece", iov->iov_len);
        partial -= iov->iov_len;
        offset += iov->iov_len;
        VIR_FREE(iov->iov_base);
        iov->iov_len = 0;
        st->readVec++;

        VIR_DEBUG("Read piece of vector. read %zu, readVec %zu, writeVec %zu",
                  offset, st->readVec, st->writeVec);
    }

    /* Shrink the I/O Vector buffer to free up memory. Do the
       shrinking only when there is selected amount or more buffers to
       free so it doesn't constantly memmove() and realloc() buffers.
     */
    if (st->readVec >= 16) {
        memmove(st->incomingVec, st->incomingVec + st->readVec,
                sizeof(*st->incomingVec)*(st->writeVec - st->readVec));
        VIR_SHRINK_N(st->incomingVec, st->writeVec, st->readVec);
        VIR_DEBUG("shrink removed %zu, left %zu", st->readVec, st->writeVec);
        st->readVec = 0;
    }

    ret = offset;
    virNetClientStreamEventTimerUpdate(st);

 cleanup:
    virObjectUnlock(st);
    return ret;
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
