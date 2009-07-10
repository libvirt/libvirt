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


/*
 * @client: a locked client object
 *
 * Invoked by the main loop when filtering incoming messages.
 *
 * Returns 1 if the message was processed, 0 if skipped,
 * -1 on fatal client error
 */
static int
remoteStreamFilter(struct qemud_client *client ATTRIBUTE_UNUSED,
                   struct qemud_client_message *msg ATTRIBUTE_UNUSED,
                   void *opaque ATTRIBUTE_UNUSED)
{
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

    DEBUG("proc=%d serial=%d", hdr->proc, hdr->serial);

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

    DEBUG("proc=%d serial=%d", stream->procedure, stream->serial);

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
                          struct qemud_client_stream *stream)
{
    struct qemud_client_stream *tmp = client->streams;

    DEBUG("client=%p proc=%d serial=%d", client, stream->procedure, stream->serial);

    if (tmp) {
        while (tmp->next)
            tmp = tmp->next;
        tmp->next = stream;
    } else {
        client->streams = stream;
    }

    stream->filter.next = client->filters;
    client->filters = &stream->filter;

    stream->tx = 1;

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
    DEBUG("client=%p proc=%d serial=%d", client, stream->procedure, stream->serial);

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
        }
    }

    if (!stream->closed)
        virStreamAbort(stream->st);

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
