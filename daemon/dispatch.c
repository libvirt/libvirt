/*
 * dispatch.h: RPC message dispatching infrastructure
 *
 * Copyright (C) 2007, 2008, 2009 Red Hat, Inc.
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
 * Author: Richard W.M. Jones <rjones@redhat.com>
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>

#include "dispatch.h"
#include "remote.h"

#include "memory.h"

/* Convert a libvirt  virError object into wire format */
static void
remoteDispatchCopyError (remote_error *rerr,
                         virErrorPtr verr)
{
    rerr->code = verr->code;
    rerr->domain = verr->domain;
    rerr->message = verr->message ? malloc(sizeof(char*)) : NULL;
    if (rerr->message) *rerr->message = strdup(verr->message);
    rerr->level = verr->level;
    rerr->str1 = verr->str1 ? malloc(sizeof(char*)) : NULL;
    if (rerr->str1) *rerr->str1 = strdup(verr->str1);
    rerr->str2 = verr->str2 ? malloc(sizeof(char*)) : NULL;
    if (rerr->str2) *rerr->str2 = strdup(verr->str2);
    rerr->str3 = verr->str3 ? malloc(sizeof(char*)) : NULL;
    if (rerr->str3) *rerr->str3 = strdup(verr->str3);
    rerr->int1 = verr->int1;
    rerr->int2 = verr->int2;
}


/* A set of helpers for sending back errors to client
   in various ways .... */

static void
remoteDispatchStringError (remote_error *rerr,
                           int code, const char *msg)
{
    virError verr;

    memset(&verr, 0, sizeof verr);

    /* Construct the dummy libvirt virError. */
    verr.code = code;
    verr.domain = VIR_FROM_REMOTE;
    verr.message = (char *)msg;
    verr.level = VIR_ERR_ERROR;
    verr.str1 = (char *)msg;

    remoteDispatchCopyError(rerr, &verr);
}


void remoteDispatchAuthError (remote_error *rerr)
{
    remoteDispatchStringError (rerr, VIR_ERR_AUTH_FAILED, "authentication failed");
}


void remoteDispatchFormatError (remote_error *rerr,
                                const char *fmt, ...)
{
    va_list args;
    char msgbuf[1024];
    char *msg = msgbuf;

    va_start (args, fmt);
    vsnprintf (msgbuf, sizeof msgbuf, fmt, args);
    va_end (args);

    remoteDispatchStringError (rerr, VIR_ERR_RPC, msg);
}


void remoteDispatchGenericError (remote_error *rerr)
{
    remoteDispatchStringError(rerr,
                              VIR_ERR_INTERNAL_ERROR,
                              "library function returned error but did not set virterror");
}


void remoteDispatchOOMError (remote_error *rerr)
{
    remoteDispatchStringError(rerr,
                              VIR_ERR_NO_MEMORY,
                              "out of memory");
}


void remoteDispatchConnError (remote_error *rerr,
                              virConnectPtr conn)
{
    virErrorPtr verr;

    if (conn)
        verr = virConnGetLastError(conn);
    else
        verr = virGetLastError();
    if (verr)
        remoteDispatchCopyError(rerr, verr);
    else
        remoteDispatchGenericError(rerr);
}

static int
remoteSerializeError(struct qemud_client *client,
                     remote_error *rerr,
                     int program,
                     int version,
                     int procedure,
                     int type,
                     int serial)
{
    XDR xdr;
    unsigned int len;
    struct qemud_client_message *msg = NULL;

    DEBUG("prog=%d ver=%d proc=%d type=%d serial=%d, msg=%s",
          program, version, procedure, type, serial,
          rerr->message ? *rerr->message : "(none)");

    if (VIR_ALLOC(msg) < 0)
        goto fatal_error;

    /* Return header. */
    msg->hdr.prog = program;
    msg->hdr.vers = version;
    msg->hdr.proc = procedure;
    msg->hdr.type = type;
    msg->hdr.serial = serial;
    msg->hdr.status = REMOTE_ERROR;

    msg->bufferLength = sizeof(msg->buffer);

    /* Serialise the return header. */
    xdrmem_create (&xdr,
                   msg->buffer,
                   msg->bufferLength,
                   XDR_ENCODE);

    len = 0; /* We'll come back and write this later. */
    if (!xdr_u_int (&xdr, &len))
        goto xdr_error;

    if (!xdr_remote_message_header (&xdr, &msg->hdr))
        goto xdr_error;

    /* Error was not set, so synthesize a generic error message. */
    if (rerr->code == 0)
        remoteDispatchGenericError(rerr);

    if (!xdr_remote_error (&xdr, rerr))
        goto xdr_error;

    /* Write the length word. */
    len = xdr_getpos (&xdr);
    if (xdr_setpos (&xdr, 0) == 0)
        goto xdr_error;

    if (!xdr_u_int (&xdr, &len))
        goto xdr_error;

    xdr_destroy (&xdr);

    msg->bufferLength = len;
    msg->bufferOffset = 0;

    /* Put reply on end of tx queue to send out  */
    qemudClientMessageQueuePush(&client->tx, msg);
    qemudUpdateClientEvent(client);
    xdr_free((xdrproc_t)xdr_remote_error,  (char *)rerr);

    return 0;

xdr_error:
    VIR_WARN("Failed to serialize remote error '%s' as XDR",
             rerr->message ? *rerr->message : "<unknown>");
    xdr_destroy(&xdr);
    VIR_FREE(msg);
fatal_error:
    xdr_free((xdrproc_t)xdr_remote_error,  (char *)rerr);
    return -1;
}


/*
 * @client: the client to send the error to
 * @rerr: the error object to send
 * @req: the message this error is in reply to
 *
 * Send an error message to the client
 *
 * Returns 0 if the error was sent, -1 upon fatal error
 */
int
remoteSerializeReplyError(struct qemud_client *client,
                          remote_error *rerr,
                          remote_message_header *req) {
    /*
     * For data streams, errors are sent back as data streams
     * For method calls, errors are sent back as method replies
     */
    return remoteSerializeError(client,
                                rerr,
                                req->prog,
                                req->vers,
                                req->proc,
                                req->type == REMOTE_STREAM ? REMOTE_STREAM : REMOTE_REPLY,
                                req->serial);
}

int
remoteSerializeStreamError(struct qemud_client *client,
                           remote_error *rerr,
                           int proc,
                           int serial)
{
    return remoteSerializeError(client,
                                rerr,
                                REMOTE_PROGRAM,
                                REMOTE_PROTOCOL_VERSION,
                                proc,
                                REMOTE_STREAM,
                                serial);
}

/*
 * @msg: the complete incoming message, whose header to decode
 *
 * Decodes the header part of the client message, but does not
 * validate the decoded fields in the header. It expects
 * bufferLength to refer to length of the data packet. Upon
 * return bufferOffset will refer to the amount of the packet
 * consumed by decoding of the header.
 *
 * returns 0 if successfully decoded, -1 upon fatal error
 */
int
remoteDecodeClientMessageHeader (struct qemud_client_message *msg)
{
    XDR xdr;
    int ret = -1;

    msg->bufferOffset = REMOTE_MESSAGE_HEADER_XDR_LEN;

    /* Parse the header. */
    xdrmem_create (&xdr,
                   msg->buffer + msg->bufferOffset,
                   msg->bufferLength - msg->bufferOffset,
                   XDR_DECODE);

    if (!xdr_remote_message_header (&xdr, &msg->hdr))
        goto cleanup;

    msg->bufferOffset += xdr_getpos(&xdr);

    ret = 0;

cleanup:
    xdr_destroy(&xdr);
    return ret;
}


/*
 * @msg: the outgoing message, whose header to encode
 *
 * Encodes the header part of the client message, setting the
 * message offset ready to encode the payload. Leaves space
 * for the length field later. Upon return bufferLength will
 * refer to the total available space for message, while
 * bufferOffset will refer to current space used by header
 *
 * returns 0 if successfully encoded, -1 upon fatal error
 */
int
remoteEncodeClientMessageHeader (struct qemud_client_message *msg)
{
    XDR xdr;
    int ret = -1;
    unsigned int len = 0;

    msg->bufferLength = sizeof(msg->buffer);
    msg->bufferOffset = 0;

    /* Format the header. */
    xdrmem_create (&xdr,
                   msg->buffer,
                   msg->bufferLength,
                   XDR_ENCODE);

    /* The real value is filled in shortly */
    if (!xdr_u_int (&xdr, &len)) {
        goto cleanup;
    }

    if (!xdr_remote_message_header (&xdr, &msg->hdr))
        goto cleanup;

    len = xdr_getpos(&xdr);
    xdr_setpos(&xdr, 0);

    /* Fill in current length - may be re-written later
     * if a payload is added
     */
    if (!xdr_u_int (&xdr, &len)) {
        goto cleanup;
    }

    msg->bufferOffset += len;

    ret = 0;

cleanup:
    xdr_destroy(&xdr);
    return ret;
}


static int
remoteDispatchClientCall (struct qemud_server *server,
                          struct qemud_client *client,
                          struct qemud_client_message *msg,
                          bool qemu_protocol);


/*
 * @server: the unlocked server object
 * @client: the locked client object
 * @msg: the complete incoming message packet, with header already decoded
 *
 * This function gets called from qemud when it pulls a incoming
 * remote protocol message off the dispatch queue for processing.
 *
 * The @msg parameter must have had its header decoded already by
 * calling remoteDecodeClientMessageHeader
 *
 * Returns 0 if the message was dispatched, -1 upon fatal error
 */
int
remoteDispatchClientRequest(struct qemud_server *server,
                            struct qemud_client *client,
                            struct qemud_client_message *msg)
{
    int ret;
    remote_error rerr;
    bool qemu_call;

    DEBUG("prog=%d ver=%d type=%d status=%d serial=%d proc=%d",
          msg->hdr.prog, msg->hdr.vers, msg->hdr.type,
          msg->hdr.status, msg->hdr.serial, msg->hdr.proc);

    memset(&rerr, 0, sizeof rerr);

    /* Check version, etc. */
    if (msg->hdr.prog == REMOTE_PROGRAM)
        qemu_call = false;
    else if (msg->hdr.prog == QEMU_PROGRAM)
        qemu_call = true;
    else {
        remoteDispatchFormatError (&rerr,
                                   _("program mismatch (actual %x, expected %x or %x)"),
                                   msg->hdr.prog, REMOTE_PROGRAM, QEMU_PROGRAM);
        goto error;
    }

    if (!qemu_call && msg->hdr.vers != REMOTE_PROTOCOL_VERSION) {
        remoteDispatchFormatError (&rerr,
                                   _("version mismatch (actual %x, expected %x)"),
                                   msg->hdr.vers, REMOTE_PROTOCOL_VERSION);
        goto error;
    }
    else if (qemu_call && msg->hdr.vers != QEMU_PROTOCOL_VERSION) {
        remoteDispatchFormatError (&rerr,
                                   _("version mismatch (actual %x, expected %x)"),
                                   msg->hdr.vers, QEMU_PROTOCOL_VERSION);
        goto error;
    }

    switch (msg->hdr.type) {
    case REMOTE_CALL:
        return remoteDispatchClientCall(server, client, msg, qemu_call);

    case REMOTE_STREAM:
        /* Since stream data is non-acked, async, we may continue to received
         * stream packets after we closed down a stream. Just drop & ignore
         * these.
         */
        VIR_INFO("Ignoring unexpected stream data serial=%d proc=%d status=%d",
                 msg->hdr.serial, msg->hdr.proc, msg->hdr.status);
        qemudClientMessageRelease(client, msg);
        break;

    default:
        remoteDispatchFormatError (&rerr, _("type (%d) != REMOTE_CALL"),
                                   (int) msg->hdr.type);
        goto error;
    }

    return 0;

error:
    ret = remoteSerializeReplyError(client, &rerr, &msg->hdr);

    if (ret >= 0)
        VIR_FREE(msg);

    return ret;
}


/*
 * @server: the unlocked server object
 * @client: the locked client object
 * @msg: the complete incoming method call, with header already decoded
 *
 * This method is used to dispatch an message representing an
 * incoming method call from a client. It decodes the payload
 * to obtain method call arguments, invokves the method and
 * then sends a reply packet with the return values
 *
 * Returns 0 if the reply was sent, or -1 upon fatal error
 */
static int
remoteDispatchClientCall (struct qemud_server *server,
                          struct qemud_client *client,
                          struct qemud_client_message *msg,
                          bool qemu_protocol)
{
    XDR xdr;
    remote_error rerr;
    dispatch_args args;
    dispatch_ret ret;
    const dispatch_data *data = NULL;
    int rv = -1;
    unsigned int len;
    virConnectPtr conn = NULL;

    memset(&args, 0, sizeof args);
    memset(&ret, 0, sizeof ret);
    memset(&rerr, 0, sizeof rerr);

    if (msg->hdr.status != REMOTE_OK) {
        remoteDispatchFormatError (&rerr, _("status (%d) != REMOTE_OK"),
                                   (int) msg->hdr.status);
        goto rpc_error;
    }

    /* If client is marked as needing auth, don't allow any RPC ops,
     * except for authentication ones
     */
    if (client->auth) {
        if (msg->hdr.proc != REMOTE_PROC_AUTH_LIST &&
            msg->hdr.proc != REMOTE_PROC_AUTH_SASL_INIT &&
            msg->hdr.proc != REMOTE_PROC_AUTH_SASL_START &&
            msg->hdr.proc != REMOTE_PROC_AUTH_SASL_STEP &&
            msg->hdr.proc != REMOTE_PROC_AUTH_POLKIT
            ) {
            /* Explicitly *NOT* calling  remoteDispatchAuthError() because
               we want back-compatability with libvirt clients which don't
               support the VIR_ERR_AUTH_FAILED error code */
            remoteDispatchFormatError (&rerr, "%s", _("authentication required"));
            goto rpc_error;
        }
    }

    if (qemu_protocol)
        data = qemuGetDispatchData(msg->hdr.proc);
    else
        data = remoteGetDispatchData(msg->hdr.proc);

    if (!data) {
        remoteDispatchFormatError (&rerr, _("unknown procedure: %d"),
                                   msg->hdr.proc);
        goto rpc_error;
    }

    /* De-serialize payload with args from the wire message */
    xdrmem_create (&xdr,
                   msg->buffer + msg->bufferOffset,
                   msg->bufferLength - msg->bufferOffset,
                   XDR_DECODE);
    if (!((data->args_filter)(&xdr, &args))) {
        xdr_destroy (&xdr);
        remoteDispatchFormatError (&rerr, "%s", _("parse args failed"));
        goto rpc_error;
    }
    xdr_destroy (&xdr);

    /* Call function. */
    conn = client->conn;
    virMutexUnlock(&client->lock);

    /*
     * When the RPC handler is called:
     *
     *  - Server object is unlocked
     *  - Client object is unlocked
     *
     * Without locking, it is safe to use:
     *
     *   'conn', 'rerr', 'args and 'ret'
     */
    rv = (data->fn)(server, client, conn, &msg->hdr, &rerr, &args, &ret);

    virMutexLock(&server->lock);
    virMutexLock(&client->lock);
    virMutexUnlock(&server->lock);

    xdr_free (data->args_filter, (char*)&args);

    if (rv < 0)
        goto rpc_error;

    /* Return header. We're re-using same message object, so
     * only need to tweak type/status fields */
    /*msg->hdr.prog = msg->hdr.prog;*/
    /*msg->hdr.vers = msg->hdr.vers;*/
    /*msg->hdr.proc = msg->hdr.proc;*/
    msg->hdr.type = REMOTE_REPLY;
    /*msg->hdr.serial = msg->hdr.serial;*/
    msg->hdr.status = REMOTE_OK;

    if (remoteEncodeClientMessageHeader(msg) < 0) {
        xdr_free (data->ret_filter, (char*)&ret);
        remoteDispatchFormatError(&rerr, "%s", _("failed to serialize reply header"));
        goto xdr_hdr_error;
    }


    /* Now for the payload */
    xdrmem_create (&xdr,
                   msg->buffer,
                   msg->bufferLength,
                   XDR_ENCODE);

    if (xdr_setpos(&xdr, msg->bufferOffset) == 0) {
        remoteDispatchFormatError(&rerr, "%s", _("failed to change XDR reply offset"));
        goto xdr_error;
    }

    /* If OK, serialise return structure, if error serialise error. */
    /* Serialise reply data */
    if (!((data->ret_filter) (&xdr, &ret))) {
        remoteDispatchFormatError(&rerr, "%s", _("failed to serialize reply payload (probable message size limit)"));
        goto xdr_error;
    }

    /* Update the length word. */
    msg->bufferOffset += xdr_getpos (&xdr);
    len = msg->bufferOffset;
    if (xdr_setpos (&xdr, 0) == 0) {
        remoteDispatchFormatError(&rerr, "%s", _("failed to change XDR reply offset"));
        goto xdr_error;
    }

    if (!xdr_u_int (&xdr, &len)) {
        remoteDispatchFormatError(&rerr, "%s", _("failed to update reply length header"));
        goto xdr_error;
    }

    xdr_destroy (&xdr);
    xdr_free (data->ret_filter, (char*)&ret);

    /* Reset ready for I/O */
    msg->bufferLength = len;
    msg->bufferOffset = 0;

    /* Put reply on end of tx queue to send out  */
    qemudClientMessageQueuePush(&client->tx, msg);
    qemudUpdateClientEvent(client);

    return 0;

xdr_error:
    /* Bad stuff serializing reply. Try to send a little info
     * back to client to assist in bug reporting/diagnosis */
    xdr_free (data->ret_filter, (char*)&ret);
    xdr_destroy (&xdr);
    /* fallthrough */

xdr_hdr_error:
    VIR_WARN("Failed to serialize reply for program '%d' proc '%d' as XDR",
             msg->hdr.prog, msg->hdr.proc);
    /* fallthrough */

rpc_error:
    /* Bad stuff (de-)serializing message, but we have an
     * RPC error message we can send back to the client */
    rv = remoteSerializeReplyError(client, &rerr, &msg->hdr);

    if (rv >= 0)
        VIR_FREE(msg);

    return rv;
}


int
remoteSendStreamData(struct qemud_client *client,
                     struct qemud_client_stream *stream,
                     const char *data,
                     unsigned int len)
{
    struct qemud_client_message *msg;
    XDR xdr;

    DEBUG("client=%p stream=%p data=%p len=%d", client, stream, data, len);

    if (VIR_ALLOC(msg) < 0) {
        return -1;
    }

    /* Return header. We're re-using same message object, so
     * only need to tweak type/status fields */
    msg->hdr.prog = REMOTE_PROGRAM;
    msg->hdr.vers = REMOTE_PROTOCOL_VERSION;
    msg->hdr.proc = stream->procedure;
    msg->hdr.type = REMOTE_STREAM;
    msg->hdr.serial = stream->serial;
    /*
     * NB
     *   data != NULL + len > 0    => REMOTE_CONTINUE   (Sending back data)
     *   data != NULL + len == 0   => REMOTE_CONTINUE   (Sending read EOF)
     *   data == NULL              => REMOTE_OK         (Sending finish handshake confirmation)
     */
    msg->hdr.status = data ? REMOTE_CONTINUE : REMOTE_OK;

    if (remoteEncodeClientMessageHeader(msg) < 0)
        goto fatal_error;

    if (data && len) {
        if ((msg->bufferLength - msg->bufferOffset) < len)
            goto fatal_error;

        /* Now for the payload */
        xdrmem_create (&xdr,
                       msg->buffer,
                       msg->bufferLength,
                       XDR_ENCODE);

        /* Skip over existing header already written */
        if (xdr_setpos(&xdr, msg->bufferOffset) == 0)
            goto xdr_error;

        memcpy(msg->buffer + msg->bufferOffset, data, len);
        msg->bufferOffset += len;

        /* Update the length word. */
        len = msg->bufferOffset;
        if (xdr_setpos (&xdr, 0) == 0)
            goto xdr_error;

        if (!xdr_u_int (&xdr, &len))
            goto xdr_error;

        xdr_destroy (&xdr);

        DEBUG("Total %d", msg->bufferOffset);
    }
    if (data)
        msg->streamTX = 1;

    /* Reset ready for I/O */
    msg->bufferLength = msg->bufferOffset;
    msg->bufferOffset = 0;

    /* Put reply on end of tx queue to send out  */
    qemudClientMessageQueuePush(&client->tx, msg);
    qemudUpdateClientEvent(client);

    return 0;

xdr_error:
    xdr_destroy (&xdr);
fatal_error:
    VIR_FREE(msg);
    VIR_WARN("Failed to serialize stream data for proc %d as XDR",
             stream->procedure);
    return -1;
}
