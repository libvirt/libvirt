/*
 * stream.c: APIs for managing client streams
 *
 * Copyright (C) 2009 Red Hat, Inc.
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

#include "stream.h"
#include "memory.h"
#include "dispatch.h"
#include "logging.h"

static int
remoteStreamHandleWrite(struct qemud_client *client,
                        struct qemud_client_stream *stream);
static int
remoteStreamHandleRead(struct qemud_client *client,
                       struct qemud_client_stream *stream);
static int
remoteStreamHandleFinish(struct qemud_client *client,
                         struct qemud_client_stream *stream,
                         struct qemud_client_message *msg);
static int
remoteStreamHandleAbort(struct qemud_client *client,
                        struct qemud_client_stream *stream,
                        struct qemud_client_message *msg);



static void
remoteStreamUpdateEvents(struct qemud_client_stream *stream)
{
    int newEvents = 0;
    if (stream->rx)
        newEvents |= VIR_STREAM_EVENT_WRITABLE;
    if (stream->tx && !stream->recvEOF)
        newEvents |= VIR_STREAM_EVENT_READABLE;

    virStreamEventUpdateCallback(stream->st, newEvents);
}


/*
 * Callback that gets invoked when a stream becomes writable/readable
 */
static void
remoteStreamEvent(virStreamPtr st, int events, void *opaque)
{
    struct qemud_client *client = opaque;
    struct qemud_client_stream *stream;

    /* XXX sub-optimal - we really should be taking the server lock
     * first, but we have no handle to the server object
     * We're lucky to get away with it for now, due to this callback
     * executing in the main thread, but this should really be fixed
     */
    virMutexLock(&client->lock);

    stream = remoteFindClientStream(client, st);

    if (!stream) {
        VIR_WARN("event for client=%p stream st=%p, but missing stream state", client, st);
        virStreamEventRemoveCallback(st);
        goto cleanup;
    }

    VIR_DEBUG("st=%p events=%d", st, events);

    if (events & VIR_STREAM_EVENT_WRITABLE) {
        if (remoteStreamHandleWrite(client, stream) < 0) {
            remoteRemoveClientStream(client, stream);
            qemudDispatchClientFailure(client);
            goto cleanup;
        }
    }

    if (!stream->recvEOF &&
        (events & (VIR_STREAM_EVENT_READABLE | VIR_STREAM_EVENT_HANGUP))) {
        events = events & ~(VIR_STREAM_EVENT_READABLE | VIR_STREAM_EVENT_HANGUP);
        if (remoteStreamHandleRead(client, stream) < 0) {
            remoteRemoveClientStream(client, stream);
            qemudDispatchClientFailure(client);
            goto cleanup;
        }
    }

    if (!stream->closed &&
        (events & (VIR_STREAM_EVENT_ERROR | VIR_STREAM_EVENT_HANGUP))) {
        int ret;
        remote_error rerr;
        memset(&rerr, 0, sizeof rerr);
        stream->closed = 1;
        virStreamEventRemoveCallback(stream->st);
        virStreamAbort(stream->st);
        if (events & VIR_STREAM_EVENT_HANGUP)
            remoteDispatchFormatError(&rerr, "%s", _("stream had unexpected termination"));
        else
            remoteDispatchFormatError(&rerr, "%s", _("stream had I/O failure"));
        ret = remoteSerializeStreamError(client, &rerr, stream->procedure, stream->serial);
        remoteRemoveClientStream(client, stream);
        if (ret < 0)
            qemudDispatchClientFailure(client);
        goto cleanup;
    }

    if (stream->closed) {
        remoteRemoveClientStream(client, stream);
    } else {
        remoteStreamUpdateEvents(stream);
    }

cleanup:
    virMutexUnlock(&client->lock);
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
remoteStreamFilter(struct qemud_client *client,
                   struct qemud_client_message *msg, void *opaque)
{
    struct qemud_client_stream *stream = opaque;

    if (msg->hdr.serial == stream->serial &&
        msg->hdr.proc == stream->procedure &&
        msg->hdr.type == REMOTE_STREAM) {
        VIR_DEBUG("Incoming rx=%p serial=%d proc=%d status=%d",
              stream->rx, msg->hdr.proc, msg->hdr.serial, msg->hdr.status);

        /* If there are queued packets, we need to queue all further
         * messages, since they must be processed strictly in order.
         * If there are no queued packets, then OK/ERROR messages
         * should be processed immediately. Data packets are still
         * queued to only be processed when the stream is marked as
         * writable.
         */
        if (stream->rx) {
            qemudClientMessageQueuePush(&stream->rx, msg);
            remoteStreamUpdateEvents(stream);
        } else {
            int ret = 0;
            switch (msg->hdr.status) {
            case REMOTE_OK:
                ret = remoteStreamHandleFinish(client, stream, msg);
                if (ret == 0)
                    qemudClientMessageRelease(client, msg);
                break;

            case REMOTE_CONTINUE:
                qemudClientMessageQueuePush(&stream->rx, msg);
                remoteStreamUpdateEvents(stream);
                break;

            case REMOTE_ERROR:
            default:
                ret = remoteStreamHandleAbort(client, stream, msg);
                if (ret == 0)
                    qemudClientMessageRelease(client, msg);
                break;
            }

            if (ret < 0)
                return -1;
        }
        return 1;
    }
    return 0;
}


/*
 * @conn: a connection object to associate the stream with
 * @hdr: the method call to associate with the stram
 *
 * Creates a new stream for this conn
 *
 * Returns a new stream object, or NULL upon OOM
 */
struct qemud_client_stream *
remoteCreateClientStream(virConnectPtr conn,
                         remote_message_header *hdr)
{
    struct qemud_client_stream *stream;

    VIR_DEBUG("proc=%d serial=%d", hdr->proc, hdr->serial);

    if (VIR_ALLOC(stream) < 0)
        return NULL;

    stream->procedure = hdr->proc;
    stream->serial = hdr->serial;

    stream->st = virStreamNew(conn, VIR_STREAM_NONBLOCK);
    if (!stream->st) {
        VIR_FREE(stream);
        return NULL;
    }

    stream->filter.query = remoteStreamFilter;
    stream->filter.opaque = stream;

    return stream;
}

/*
 * @stream: an unused client stream
 *
 * Frees the memory associated with this inactive client
 * stream
 */
void remoteFreeClientStream(struct qemud_client *client,
                            struct qemud_client_stream *stream)
{
    struct qemud_client_message *msg;

    if (!stream)
        return;

    VIR_DEBUG("proc=%d serial=%d", stream->procedure, stream->serial);

    msg = stream->rx;
    while (msg) {
        struct qemud_client_message *tmp = msg->next;
        qemudClientMessageRelease(client, msg);
        msg = tmp;
    }

    virStreamFree(stream->st);
    VIR_FREE(stream);
}


/*
 * @client: a locked client to add the stream to
 * @stream: a stream to add
 */
int remoteAddClientStream(struct qemud_client *client,
                          struct qemud_client_stream *stream,
                          int transmit)
{
    struct qemud_client_stream *tmp = client->streams;

    VIR_DEBUG("client=%p proc=%d serial=%d", client, stream->procedure, stream->serial);

    if (virStreamEventAddCallback(stream->st, 0,
                                  remoteStreamEvent, client, NULL) < 0)
        return -1;

    if (tmp) {
        while (tmp->next)
            tmp = tmp->next;
        tmp->next = stream;
    } else {
        client->streams = stream;
    }

    stream->filter.next = client->filters;
    client->filters = &stream->filter;

    if (transmit)
        stream->tx = 1;

    remoteStreamUpdateEvents(stream);

    return 0;
}


/*
 * @client: a locked client object
 * @procedure: procedure associated with the stream
 * @serial: serial number associated with the stream
 *
 * Finds a existing active stream
 *
 * Returns a stream object matching the procedure+serial number, or NULL
 */
struct qemud_client_stream *
remoteFindClientStream(struct qemud_client *client,
                       virStreamPtr st)
{
    struct qemud_client_stream *stream = client->streams;

    while (stream) {
        if (stream->st == st)
            return stream;
        stream = stream->next;
    }

    return NULL;
}


/*
 * @client: a locked client object
 * @stream: an inactive, closed stream object
 *
 * Removes a stream from the list of active streams for the client
 *
 * Returns 0 if the stream was removd, -1 if it doesn't exist
 */
int
remoteRemoveClientStream(struct qemud_client *client,
                         struct qemud_client_stream *stream)
{
    VIR_DEBUG("client=%p proc=%d serial=%d", client, stream->procedure, stream->serial);

    struct qemud_client_stream *curr = client->streams;
    struct qemud_client_stream *prev = NULL;
    struct qemud_client_filter *filter = NULL;

    if (client->filters == &stream->filter) {
        client->filters = client->filters->next;
    } else {
        filter = client->filters;
        while (filter) {
            if (filter->next == &stream->filter) {
                filter->next = filter->next->next;
                break;
            }
            filter = filter->next;
        }
    }

    if (!stream->closed) {
        virStreamEventRemoveCallback(stream->st);
        virStreamAbort(stream->st);
    }

    while (curr) {
        if (curr == stream) {
            if (prev)
                prev->next = curr->next;
            else
                client->streams = curr->next;
            remoteFreeClientStream(client, stream);
            return 0;
        }
        prev = curr;
        curr = curr->next;
    }
    return -1;
}


/*
 * Returns:
 *   -1  if fatal error occurred
 *    0  if message was fully processed
 *    1  if message is still being processed
 */
static int
remoteStreamHandleWriteData(struct qemud_client *client,
                            struct qemud_client_stream *stream,
                            struct qemud_client_message *msg)
{
    remote_error rerr;
    int ret;

    VIR_DEBUG("stream=%p proc=%d serial=%d len=%d offset=%d",
          stream, msg->hdr.proc, msg->hdr.serial, msg->bufferLength, msg->bufferOffset);

    memset(&rerr, 0, sizeof rerr);

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
        VIR_INFO0("Stream send failed");
        stream->closed = 1;
        remoteDispatchConnError(&rerr, client->conn);
        return remoteSerializeReplyError(client, &rerr, &msg->hdr);
    }

    return 0;
}


/*
 * Process an finish handshake from the client.
 *
 * Returns a REMOTE_OK confirmation if successful, or a REMOTE_ERROR
 * if there was a stream error
 *
 * Returns 0 if successfully sent RPC reply, -1 upon fatal error
 */
static int
remoteStreamHandleFinish(struct qemud_client *client,
                         struct qemud_client_stream *stream,
                         struct qemud_client_message *msg)
{
    remote_error rerr;
    int ret;

    VIR_DEBUG("stream=%p proc=%d serial=%d",
          stream, msg->hdr.proc, msg->hdr.serial);

    memset(&rerr, 0, sizeof rerr);

    stream->closed = 1;
    virStreamEventRemoveCallback(stream->st);
    ret = virStreamFinish(stream->st);

    if (ret < 0) {
        remoteDispatchConnError(&rerr, client->conn);
        return remoteSerializeReplyError(client, &rerr, &msg->hdr);
    } else {
        /* Send zero-length confirm */
        if (remoteSendStreamData(client, stream, NULL, 0) < 0)
            return -1;
    }

    return 0;
}


/*
 * Process an abort request from the client.
 *
 * Returns 0 if successfully aborted, -1 upon error
 */
static int
remoteStreamHandleAbort(struct qemud_client *client,
                        struct qemud_client_stream *stream,
                        struct qemud_client_message *msg)
{
    remote_error rerr;

    VIR_DEBUG("stream=%p proc=%d serial=%d",
          stream, msg->hdr.proc, msg->hdr.serial);

    memset(&rerr, 0, sizeof rerr);

    stream->closed = 1;
    virStreamEventRemoveCallback(stream->st);
    virStreamAbort(stream->st);

    if (msg->hdr.status == REMOTE_ERROR)
        remoteDispatchFormatError(&rerr, "%s", _("stream aborted at client request"));
    else {
        VIR_WARN("unexpected stream status %d", msg->hdr.status);
        remoteDispatchFormatError(&rerr, _("stream aborted with unexpected status %d"),
                                  msg->hdr.status);
    }

    return remoteSerializeReplyError(client, &rerr, &msg->hdr);
}



/*
 * Called when the stream is signalled has being able to accept
 * data writes. Will process all pending incoming messages
 * until they're all gone, or I/O blocks
 *
 * Returns 0 on success, or -1 upon fatal error
 */
static int
remoteStreamHandleWrite(struct qemud_client *client,
                        struct qemud_client_stream *stream)
{
    struct qemud_client_message *msg, *tmp;

    VIR_DEBUG("stream=%p", stream);

    msg = stream->rx;
    while (msg && !stream->closed) {
        int ret;
        switch (msg->hdr.status) {
        case REMOTE_OK:
            ret = remoteStreamHandleFinish(client, stream, msg);
            break;

        case REMOTE_CONTINUE:
            ret = remoteStreamHandleWriteData(client, stream, msg);
            break;

        case REMOTE_ERROR:
        default:
            ret = remoteStreamHandleAbort(client, stream, msg);
            break;
        }

        if (ret == 0)
            qemudClientMessageQueueServe(&stream->rx);
        else if (ret < 0)
            return -1;
        else
            break; /* still processing data */

        tmp = msg->next;
        qemudClientMessageRelease(client, msg);
        msg = tmp;
    }

    return 0;
}



/*
 * Invoked when a stream is signalled as having data
 * available to read. This reads upto one message
 * worth of data, and then queues that for transmission
 * to the client.
 *
 * Returns 0 if data was queued for TX, or a error RPC
 * was sent, or -1 on fatal error, indicating client should
 * be killed
 */
static int
remoteStreamHandleRead(struct qemud_client *client,
                       struct qemud_client_stream *stream)
{
    char *buffer;
    size_t bufferLen = REMOTE_MESSAGE_PAYLOAD_MAX;
    int ret;

    VIR_DEBUG("stream=%p", stream);

    /* Shouldn't ever be called unless we're marked able to
     * transmit, but doesn't hurt to check */
    if (!stream->tx)
        return 0;

    if (VIR_ALLOC_N(buffer, bufferLen) < 0)
        return -1;

    ret = virStreamRecv(stream->st, buffer, bufferLen);
    if (ret == -2) {
        /* Should never get this, since we're only called when we know
         * we're readable, but hey things change... */
        ret = 0;
    } else if (ret < 0) {
        remote_error rerr;
        memset(&rerr, 0, sizeof rerr);
        remoteDispatchConnError(&rerr, NULL);

        ret = remoteSerializeStreamError(client, &rerr, stream->procedure, stream->serial);
    } else {
        stream->tx = 0;
        if (ret == 0)
            stream->recvEOF = 1;
        ret = remoteSendStreamData(client, stream, buffer, ret);
    }

    VIR_FREE(buffer);
    return ret;
}


/*
 * Invoked when an outgoing data packet message has been fully sent.
 * This simply re-enables TX of further data.
 *
 * The idea is to stop the daemon growing without bound due to
 * fast stream, but slow client
 */
void
remoteStreamMessageFinished(struct qemud_client *client,
                            struct qemud_client_message *msg)
{
    struct qemud_client_stream *stream = client->streams;

    while (stream) {
        if (msg->hdr.proc == stream->procedure &&
            msg->hdr.serial == stream->serial)
            break;
        stream = stream->next;
    }

    VIR_DEBUG("Message client=%p stream=%p proc=%d serial=%d", client, stream, msg->hdr.proc, msg->hdr.serial);

    if (stream) {
        stream->tx = 1;
        remoteStreamUpdateEvents(stream);
    }
}
