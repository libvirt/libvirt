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
                              NULL);
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
    xdr_destroy(&xdr);
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
static int
remoteSerializeReplyError(struct qemud_client *client,
                          remote_error *rerr,
                          remote_message_header *req) {
    return remoteSerializeError(client,
                                rerr,
                                req->prog,
                                req->vers,
                                req->proc,
                                REMOTE_REPLY,
                                req->serial);
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


int
remoteDispatchClientCall (struct qemud_server *server,
                          struct qemud_client *client,
                          struct qemud_client_message *msg);


/*
 * @server: the unlocked server object
 * @client: the locked client object
 * @msg: the complete incoming message packet, with header already decoded
 *
 * This function gets called from qemud when it pulls a incoming
 * remote protocol messsage off the dispatch queue for processing.
 *
 * The @msg parameter must have had its header decoded already by
 * calling remoteDecodeClientMessageHeader
 *
 * Returns 0 if the message was dispatched, -1 upon fatal error
 */
int
remoteDispatchClientRequest (struct qemud_server *server,
                             struct qemud_client *client,
                             struct qemud_client_message *msg)
{
    remote_error rerr;

    memset(&rerr, 0, sizeof rerr);

    /* Check version, etc. */
    if (msg->hdr.prog != REMOTE_PROGRAM) {
        remoteDispatchFormatError (&rerr,
                                   _("program mismatch (actual %x, expected %x)"),
                                   msg->hdr.prog, REMOTE_PROGRAM);
        goto error;
    }
    if (msg->hdr.vers != REMOTE_PROTOCOL_VERSION) {
        remoteDispatchFormatError (&rerr,
                                   _("version mismatch (actual %x, expected %x)"),
                                   msg->hdr.vers, REMOTE_PROTOCOL_VERSION);
        goto error;
    }

    switch (msg->hdr.type) {
    case REMOTE_CALL:
        return remoteDispatchClientCall(server, client, msg);

    default:
        remoteDispatchFormatError (&rerr, _("type (%d) != REMOTE_CALL"),
                                   (int) msg->hdr.type);
    }

error:
    return remoteSerializeReplyError(client, &rerr, &msg->hdr);
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
int
remoteDispatchClientCall (struct qemud_server *server,
                          struct qemud_client *client,
                          struct qemud_client_message *msg)
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
    rv = (data->fn)(server, client, conn, &rerr, &args, &ret);

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
        goto fatal_error;
    }


    /* Now for the payload */
    xdrmem_create (&xdr,
                   msg->buffer,
                   msg->bufferLength,
                   XDR_ENCODE);

    if (xdr_setpos(&xdr, msg->bufferOffset) == 0)
        goto xdr_error;

    /* If OK, serialise return structure, if error serialise error. */
    /* Serialise reply data */
    if (!((data->ret_filter) (&xdr, &ret)))
        goto xdr_error;

    /* Update the length word. */
    msg->bufferOffset += xdr_getpos (&xdr);
    len = msg->bufferOffset;
    if (xdr_setpos (&xdr, 0) == 0)
        goto xdr_error;

    if (!xdr_u_int (&xdr, &len))
        goto xdr_error;

    xdr_destroy (&xdr);
    xdr_free (data->ret_filter, (char*)&ret);

    /* Reset ready for I/O */
    msg->bufferLength = len;
    msg->bufferOffset = 0;

    /* Put reply on end of tx queue to send out  */
    qemudClientMessageQueuePush(&client->tx, msg);
    qemudUpdateClientEvent(client);

    return 0;

rpc_error:
    /* Semi-bad stuff happened, we can still try to send back
     * an RPC error message to client */
    return remoteSerializeReplyError(client, &rerr, &msg->hdr);


xdr_error:
    /* Seriously bad stuff happened, so we'll kill off this client
       and not send back any RPC error */
    xdr_free (data->ret_filter, (char*)&ret);
    xdr_destroy (&xdr);
fatal_error:
    return -1;
}
