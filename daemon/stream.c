/*
 * stream.c: APIs for managing client streams
 *
 * Copyright (C) 2009-2014 Red Hat, Inc.
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

#include "stream.h"
#include "remote.h"
#include "viralloc.h"
#include "virlog.h"
#include "virnetserverclient.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_STREAMS

VIR_LOG_INIT("daemon.stream");

struct daemonClientStream {
    daemonClientPrivatePtr priv;
    int refs;

    virNetServerProgramPtr prog;

    virStreamPtr st;
    int procedure;
    unsigned int serial;

    bool recvEOF;
    bool closed;

    int filterID;

    virNetMessagePtr rx;
    bool tx;

    bool allowSkip;

    daemonClientStreamPtr next;
};

static int
daemonStreamHandleWrite(virNetServerClientPtr client,
                        daemonClientStream *stream);
static int
daemonStreamHandleRead(virNetServerClientPtr client,
                       daemonClientStream *stream);
static int
daemonStreamHandleFinish(virNetServerClientPtr client,
                         daemonClientStream *stream,
                         virNetMessagePtr msg);
static int
daemonStreamHandleAbort(virNetServerClientPtr client,
                        daemonClientStream *stream,
                        virNetMessagePtr msg);



static void
daemonStreamUpdateEvents(daemonClientStream *stream)
{
    int newEvents = 0;
    if (stream->closed)
        return;
    if (stream->rx)
        newEvents |= VIR_STREAM_EVENT_WRITABLE;
    if (stream->tx && !stream->recvEOF)
        newEvents |= VIR_STREAM_EVENT_READABLE;

    virStreamEventUpdateCallback(stream->st, newEvents);
}

/*
 * Invoked when an outgoing data packet message has been fully sent.
 * This simply re-enables TX of further data.
 *
 * The idea is to stop the daemon growing without bound due to
 * fast stream, but slow client
 */
static void
daemonStreamMessageFinished(virNetMessagePtr msg,
                            void *opaque)
{
    daemonClientStream *stream = opaque;
    VIR_DEBUG("stream=%p proc=%d serial=%u",
              stream, msg->header.proc, msg->header.serial);

    stream->tx = true;
    daemonStreamUpdateEvents(stream);

    daemonFreeClientStream(NULL, stream);
}


/*
 * Callback that gets invoked when a stream becomes writable/readable
 */
static void
daemonStreamEvent(virStreamPtr st, int events, void *opaque)
{
    virNetServerClientPtr client = opaque;
    daemonClientStream *stream;
    daemonClientPrivatePtr priv = virNetServerClientGetPrivateData(client);

    virMutexLock(&priv->lock);

    stream = priv->streams;
    while (stream) {
        if (stream->st == st)
            break;
        stream = stream->next;
    }

    if (!stream) {
        VIR_WARN("event for client=%p stream st=%p, but missing stream state", client, st);
        virStreamEventRemoveCallback(st);
        goto cleanup;
    }

    VIR_DEBUG("st=%p events=%d EOF=%d closed=%d", st, events, stream->recvEOF, stream->closed);

    if (!stream->closed &&
        (events & VIR_STREAM_EVENT_WRITABLE)) {
        if (daemonStreamHandleWrite(client, stream) < 0) {
            daemonRemoveClientStream(client, stream);
            virNetServerClientClose(client);
            goto cleanup;
        }
    }

    if (!stream->closed && !stream->recvEOF &&
        (events & (VIR_STREAM_EVENT_READABLE))) {
        events = events & ~(VIR_STREAM_EVENT_READABLE);
        if (daemonStreamHandleRead(client, stream) < 0) {
            daemonRemoveClientStream(client, stream);
            virNetServerClientClose(client);
            goto cleanup;
        }
        /* If we detected EOF during read processing,
         * then clear hangup/error conditions, since
         * we want the client to see the EOF message
         * we just sent them
         */
        if (stream->recvEOF)
            events = events & ~(VIR_STREAM_EVENT_HANGUP |
                                VIR_STREAM_EVENT_ERROR);
    }

    /* If we have a completion/abort message, always process it */
    if (stream->rx) {
        virNetMessagePtr msg = stream->rx;
        switch (msg->header.status) {
        case VIR_NET_CONTINUE:
            /* nada */
            break;
        case VIR_NET_OK:
            virNetMessageQueueServe(&stream->rx);
            if (daemonStreamHandleFinish(client, stream, msg) < 0) {
                virNetMessageFree(msg);
                daemonRemoveClientStream(client, stream);
                virNetServerClientClose(client);
                goto cleanup;
            }
            break;
        case VIR_NET_ERROR:
        default:
            virNetMessageQueueServe(&stream->rx);
            if (daemonStreamHandleAbort(client, stream, msg) < 0) {
                virNetMessageFree(msg);
                daemonRemoveClientStream(client, stream);
                virNetServerClientClose(client);
                goto cleanup;
            }
            break;
        }
    }


    /* If we got HANGUP, we need to only send an empty
     * packet so the client sees an EOF and cleans up
     */
    if (!stream->closed && !stream->recvEOF &&
        (events & VIR_STREAM_EVENT_HANGUP)) {
        virNetMessagePtr msg;
        events &= ~(VIR_STREAM_EVENT_HANGUP);
        stream->tx = false;
        stream->recvEOF = true;
        if (!(msg = virNetMessageNew(false))) {
            daemonRemoveClientStream(client, stream);
            virNetServerClientClose(client);
            goto cleanup;
        }
        msg->cb = daemonStreamMessageFinished;
        msg->opaque = stream;
        stream->refs++;
        if (virNetServerProgramSendStreamData(remoteProgram,
                                              client,
                                              msg,
                                              stream->procedure,
                                              stream->serial,
                                              "", 0) < 0) {
            virNetMessageFree(msg);
            daemonRemoveClientStream(client, stream);
            virNetServerClientClose(client);
            goto cleanup;
        }
    }

    if (!stream->closed &&
        (events & (VIR_STREAM_EVENT_ERROR | VIR_STREAM_EVENT_HANGUP))) {
        int ret;
        virNetMessagePtr msg;
        virNetMessageError rerr;

        memset(&rerr, 0, sizeof(rerr));
        stream->closed = true;
        virStreamEventRemoveCallback(stream->st);
        virStreamAbort(stream->st);
        if (events & VIR_STREAM_EVENT_HANGUP)
            virReportError(VIR_ERR_RPC,
                           "%s", _("stream had unexpected termination"));
        else
            virReportError(VIR_ERR_RPC,
                           "%s", _("stream had I/O failure"));

        msg = virNetMessageNew(false);
        if (!msg) {
            ret = -1;
        } else {
            ret = virNetServerProgramSendStreamError(remoteProgram,
                                                     client,
                                                     msg,
                                                     &rerr,
                                                     stream->procedure,
                                                     stream->serial);
        }
        daemonRemoveClientStream(client, stream);
        if (ret < 0)
            virNetServerClientClose(client);
        goto cleanup;
    }

    if (stream->closed) {
        daemonRemoveClientStream(client, stream);
    } else {
        daemonStreamUpdateEvents(stream);
    }

 cleanup:
    virMutexUnlock(&priv->lock);
}


/*
 * @client: a locked client object
 *
 * Invoked by the main loop when filtering incoming messages.
 *
 * Returns 1 if the message was processed, 0 if skipped,
 * -1 on fatal client error
 */
static int
daemonStreamFilter(virNetServerClientPtr client ATTRIBUTE_UNUSED,
                   virNetMessagePtr msg,
                   void *opaque)
{
    daemonClientStream *stream = opaque;
    int ret = 0;

    virMutexLock(&stream->priv->lock);

    if (msg->header.type != VIR_NET_STREAM)
        goto cleanup;

    if (!virNetServerProgramMatches(stream->prog, msg))
        goto cleanup;

    if (msg->header.proc != stream->procedure ||
        msg->header.serial != stream->serial)
        goto cleanup;

    VIR_DEBUG("Incoming client=%p, rx=%p, serial=%u, proc=%d, status=%d",
              client, stream->rx, msg->header.proc,
              msg->header.serial, msg->header.status);

    virNetMessageQueuePush(&stream->rx, msg);
    daemonStreamUpdateEvents(stream);
    ret = 1;

 cleanup:
    virMutexUnlock(&stream->priv->lock);
    return ret;
}


/*
 * @conn: a connection object to associate the stream with
 * @header: the method call to associate with the stream
 *
 * Creates a new stream for this conn
 *
 * Returns a new stream object, or NULL upon OOM
 */
daemonClientStream *
daemonCreateClientStream(virNetServerClientPtr client,
                         virStreamPtr st,
                         virNetServerProgramPtr prog,
                         virNetMessageHeaderPtr header,
                         bool allowSkip)
{
    daemonClientStream *stream;
    daemonClientPrivatePtr priv = virNetServerClientGetPrivateData(client);

    VIR_DEBUG("client=%p, proc=%d, serial=%u, st=%p",
              client, header->proc, header->serial, st);

    if (VIR_ALLOC(stream) < 0)
        return NULL;

    stream->refs = 1;
    stream->priv = priv;
    stream->prog = virObjectRef(prog);
    stream->procedure = header->proc;
    stream->serial = header->serial;
    stream->filterID = -1;
    stream->st = st;
    stream->allowSkip = allowSkip;

    return stream;
}

/*
 * @stream: an unused client stream
 *
 * Frees the memory associated with this inactive client
 * stream
 */
int daemonFreeClientStream(virNetServerClientPtr client,
                           daemonClientStream *stream)
{
    virNetMessagePtr msg;
    int ret = 0;

    if (!stream)
        return 0;

    stream->refs--;
    if (stream->refs)
        return 0;

    VIR_DEBUG("client=%p, proc=%d, serial=%u",
              client, stream->procedure, stream->serial);

    virObjectUnref(stream->prog);

    msg = stream->rx;
    while (msg) {
        virNetMessagePtr tmp = msg->next;
        if (client) {
            /* Send a dummy reply to free up 'msg' & unblock client rx */
            virNetMessageClear(msg);
            msg->header.type = VIR_NET_REPLY;
            if (virNetServerClientSendMessage(client, msg) < 0) {
                virNetServerClientImmediateClose(client);
                virNetMessageFree(msg);
                ret = -1;
            }
        } else {
            virNetMessageFree(msg);
        }
        msg = tmp;
    }

    virObjectUnref(stream->st);
    VIR_FREE(stream);

    return ret;
}


/*
 * @client: a locked client to add the stream to
 * @stream: a stream to add
 */
int daemonAddClientStream(virNetServerClientPtr client,
                          daemonClientStream *stream,
                          bool transmit)
{
    VIR_DEBUG("client=%p, proc=%d, serial=%u, st=%p, transmit=%d",
              client, stream->procedure, stream->serial, stream->st, transmit);
    daemonClientPrivatePtr priv = virNetServerClientGetPrivateData(client);

    if (stream->filterID != -1) {
        VIR_WARN("Filter already added to client %p", client);
        return -1;
    }

    if (virStreamEventAddCallback(stream->st, 0,
                                  daemonStreamEvent, client,
                                  virObjectFreeCallback) < 0)
        return -1;

    virObjectRef(client);

    if ((stream->filterID = virNetServerClientAddFilter(client,
                                                        daemonStreamFilter,
                                                        stream)) < 0) {
        virStreamEventRemoveCallback(stream->st);
        return -1;
    }

    if (transmit)
        stream->tx = true;

    virMutexLock(&priv->lock);
    stream->next = priv->streams;
    priv->streams = stream;

    daemonStreamUpdateEvents(stream);

    virMutexUnlock(&priv->lock);

    return 0;
}


/*
 * @client: a locked client object
 * @stream: an inactive, closed stream object
 *
 * Removes a stream from the list of active streams for the client
 *
 * Returns 0 if the stream was removed, -1 if it doesn't exist
 */
int
daemonRemoveClientStream(virNetServerClientPtr client,
                         daemonClientStream *stream)
{
    VIR_DEBUG("client=%p, proc=%d, serial=%u, st=%p",
              client, stream->procedure, stream->serial, stream->st);
    daemonClientPrivatePtr priv = virNetServerClientGetPrivateData(client);
    daemonClientStream *curr = priv->streams;
    daemonClientStream *prev = NULL;

    if (stream->filterID != -1) {
        virNetServerClientRemoveFilter(client,
                                       stream->filterID);
        stream->filterID = -1;
    }

    if (!stream->closed) {
        stream->closed = true;
        virStreamEventRemoveCallback(stream->st);
        virStreamAbort(stream->st);
    }

    while (curr) {
        if (curr == stream) {
            if (prev)
                prev->next = curr->next;
            else
                priv->streams = curr->next;
            return daemonFreeClientStream(client, stream);
        }
        prev = curr;
        curr = curr->next;
    }
    return -1;
}


void
daemonRemoveAllClientStreams(daemonClientStream *stream)
{
    daemonClientStream *tmp;

    VIR_DEBUG("stream=%p", stream);

    while (stream) {
        tmp = stream->next;

        if (!stream->closed) {
            stream->closed = true;
            virStreamEventRemoveCallback(stream->st);
            virStreamAbort(stream->st);
        }

        daemonFreeClientStream(NULL, stream);

        VIR_DEBUG("next stream=%p", tmp);
        stream = tmp;
    }
}

/*
 * Returns:
 *   -1  if fatal error occurred
 *    0  if message was fully processed
 *    1  if message is still being processed
 */
static int
daemonStreamHandleWriteData(virNetServerClientPtr client,
                            daemonClientStream *stream,
                            virNetMessagePtr msg)
{
    int ret;

    VIR_DEBUG("client=%p, stream=%p, proc=%d, serial=%u, len=%zu, offset=%zu",
              client, stream, msg->header.proc, msg->header.serial,
              msg->bufferLength, msg->bufferOffset);

    ret = virStreamSend(stream->st,
                        msg->buffer + msg->bufferOffset,
                        msg->bufferLength - msg->bufferOffset);

    if (ret > 0) {
        msg->bufferOffset += ret;

        /* Partial write, so indicate we have more todo later */
        if (msg->bufferOffset < msg->bufferLength)
            return 1;
    } else if (ret == -2) {
        /* Blocking, so indicate we have more todo later */
        return 1;
    } else {
        virNetMessageError rerr;

        memset(&rerr, 0, sizeof(rerr));

        VIR_INFO("Stream send failed");
        stream->closed = true;
        virStreamEventRemoveCallback(stream->st);
        virStreamAbort(stream->st);

        return virNetServerProgramSendReplyError(stream->prog,
                                                 client,
                                                 msg,
                                                 &rerr,
                                                 &msg->header);
    }

    return 0;
}


/*
 * Process a finish handshake from the client.
 *
 * Returns a VIR_NET_OK confirmation if successful, or a VIR_NET_ERROR
 * if there was a stream error
 *
 * Returns 0 if successfully sent RPC reply, -1 upon fatal error
 */
static int
daemonStreamHandleFinish(virNetServerClientPtr client,
                         daemonClientStream *stream,
                         virNetMessagePtr msg)
{
    int ret;

    VIR_DEBUG("client=%p, stream=%p, proc=%d, serial=%u",
              client, stream, msg->header.proc, msg->header.serial);

    stream->closed = true;
    virStreamEventRemoveCallback(stream->st);
    ret = virStreamFinish(stream->st);

    if (ret < 0) {
        virNetMessageError rerr;
        memset(&rerr, 0, sizeof(rerr));
        return virNetServerProgramSendReplyError(stream->prog,
                                                 client,
                                                 msg,
                                                 &rerr,
                                                 &msg->header);
    } else {
        /* Send zero-length confirm */
        return virNetServerProgramSendStreamData(stream->prog,
                                                 client,
                                                 msg,
                                                 stream->procedure,
                                                 stream->serial,
                                                 NULL, 0);
    }
}


/*
 * Process an abort request from the client.
 *
 * Returns 0 if successfully aborted, -1 upon error
 */
static int
daemonStreamHandleAbort(virNetServerClientPtr client,
                        daemonClientStream *stream,
                        virNetMessagePtr msg)
{
    VIR_DEBUG("client=%p, stream=%p, proc=%d, serial=%u",
              client, stream, msg->header.proc, msg->header.serial);
    int ret;
    bool raise_error = false;

    stream->closed = true;
    virStreamEventRemoveCallback(stream->st);
    ret = virStreamAbort(stream->st);

    if (msg->header.status == VIR_NET_ERROR) {
        VIR_INFO("stream aborted at client request");
        raise_error = (ret < 0);
    } else {
        virReportError(VIR_ERR_RPC,
                       _("stream aborted with unexpected status %d"),
                       msg->header.status);
        raise_error = true;
    }

    if (raise_error) {
        virNetMessageError rerr;
        memset(&rerr, 0, sizeof(rerr));
        return virNetServerProgramSendReplyError(remoteProgram,
                                                 client,
                                                 msg,
                                                 &rerr,
                                                 &msg->header);
    } else {
        /* Send zero-length confirm */
        return virNetServerProgramSendStreamData(stream->prog,
                                                 client,
                                                 msg,
                                                 stream->procedure,
                                                 stream->serial,
                                                 NULL, 0);
    }
}



/*
 * Called when the stream is signalled has being able to accept
 * data writes. Will process all pending incoming messages
 * until they're all gone, or I/O blocks
 *
 * Returns 0 on success, or -1 upon fatal error
 */
static int
daemonStreamHandleWrite(virNetServerClientPtr client,
                        daemonClientStream *stream)
{
    VIR_DEBUG("client=%p, stream=%p", client, stream);

    while (stream->rx && !stream->closed) {
        virNetMessagePtr msg = stream->rx;
        int ret;

        switch (msg->header.status) {
        case VIR_NET_OK:
            ret = daemonStreamHandleFinish(client, stream, msg);
            break;

        case VIR_NET_CONTINUE:
            ret = daemonStreamHandleWriteData(client, stream, msg);
            break;

        case VIR_NET_ERROR:
        default:
            ret = daemonStreamHandleAbort(client, stream, msg);
            break;
        }

        if (ret > 0)
            break;  /* still processing data from msg */

        virNetMessageQueueServe(&stream->rx);
        if (ret < 0) {
            virNetMessageFree(msg);
            virNetServerClientImmediateClose(client);
            return -1;
        }

        /* 'CONTINUE' messages don't send a reply (unless error
         * occurred), so to release the 'msg' object we need to
         * send a fake zero-length reply. Nothing actually gets
         * onto the wire, but this causes the client to reset
         * its active request count / throttling
         */
        if (msg->header.status == VIR_NET_CONTINUE) {
            virNetMessageClear(msg);
            msg->header.type = VIR_NET_REPLY;
            if (virNetServerClientSendMessage(client, msg) < 0) {
                virNetMessageFree(msg);
                virNetServerClientImmediateClose(client);
                return -1;
            }
        }
    }

    return 0;
}



/*
 * Invoked when a stream is signalled as having data
 * available to read. This reads up to one message
 * worth of data, and then queues that for transmission
 * to the client.
 *
 * Returns 0 if data was queued for TX, or an error RPC
 * was sent, or -1 on fatal error, indicating client should
 * be killed
 */
static int
daemonStreamHandleRead(virNetServerClientPtr client,
                       daemonClientStream *stream)
{
    virNetMessagePtr msg = NULL;
    virNetMessageError rerr;
    char *buffer;
    size_t bufferLen = VIR_NET_MESSAGE_LEGACY_PAYLOAD_MAX;
    int ret = -1;
    int rv;

    VIR_DEBUG("client=%p, stream=%p tx=%d closed=%d",
              client, stream, stream->tx, stream->closed);

    /* We might have had an event pending before we shut
     * down the stream, so if we're marked as closed,
     * then do nothing
     */
    if (stream->closed)
        return 0;

    /* Shouldn't ever be called unless we're marked able to
     * transmit, but doesn't hurt to check */
    if (!stream->tx)
        return 0;

    memset(&rerr, 0, sizeof(rerr));

    if (VIR_ALLOC_N(buffer, bufferLen) < 0)
        return -1;

    if (!(msg = virNetMessageNew(false)))
        goto cleanup;

    rv = virStreamRecv(stream->st, buffer, bufferLen);
    if (rv == -2) {
        /* Should never get this, since we're only called when we know
         * we're readable, but hey things change... */
    } else if (rv < 0) {
        if (virNetServerProgramSendStreamError(remoteProgram,
                                               client,
                                               msg,
                                               &rerr,
                                               stream->procedure,
                                               stream->serial) < 0)
            goto cleanup;
        msg = NULL;
    } else {
        stream->tx = false;
        if (rv == 0)
            stream->recvEOF = true;

        msg->cb = daemonStreamMessageFinished;
        msg->opaque = stream;
        stream->refs++;
        if (virNetServerProgramSendStreamData(remoteProgram,
                                              client,
                                              msg,
                                              stream->procedure,
                                              stream->serial,
                                              buffer, rv) < 0)
            goto cleanup;
        msg = NULL;
    }

    ret = 0;
 cleanup:
    VIR_FREE(buffer);
    virNetMessageFree(msg);
    return ret;
}
