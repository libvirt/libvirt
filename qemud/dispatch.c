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


/*
 * @msg: the complete incoming message, whose header to decode
 *
 * Decodes the header part of the client message, but does not
 * validate the decoded fields in the header.
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
    XDR xdr;
    remote_message_header rep;
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


    /* Check version, etc. */
    if (msg->hdr.prog != REMOTE_PROGRAM) {
        remoteDispatchFormatError (&rerr,
                                   _("program mismatch (actual %x, expected %x)"),
                                   msg->hdr.prog, REMOTE_PROGRAM);
        goto rpc_error;
    }
    if (msg->hdr.vers != REMOTE_PROTOCOL_VERSION) {
        remoteDispatchFormatError (&rerr,
                                   _("version mismatch (actual %x, expected %x)"),
                                   msg->hdr.vers, REMOTE_PROTOCOL_VERSION);
        goto rpc_error;
    }
    if (msg->hdr.direction != REMOTE_CALL) {
        remoteDispatchFormatError (&rerr, _("direction (%d) != REMOTE_CALL"),
                                   (int) msg->hdr.direction);
        goto rpc_error;
    }
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

rpc_error:

    /* Return header. */
    rep.prog = msg->hdr.prog;
    rep.vers = msg->hdr.vers;
    rep.proc = msg->hdr.proc;
    rep.direction = REMOTE_REPLY;
    rep.serial = msg->hdr.serial;
    rep.status = rv < 0 ? REMOTE_ERROR : REMOTE_OK;

    /* Serialise the return header. */
    xdrmem_create (&xdr, msg->buffer, sizeof msg->buffer, XDR_ENCODE);

    len = 0; /* We'll come back and write this later. */
    if (!xdr_u_int (&xdr, &len)) {
        if (rv == 0) xdr_free (data->ret_filter, (char*)&ret);
        goto fatal_error;
    }

    if (!xdr_remote_message_header (&xdr, &rep)) {
        if (rv == 0) xdr_free (data->ret_filter, (char*)&ret);
        goto fatal_error;
    }

    /* If OK, serialise return structure, if error serialise error. */
    if (rv >= 0) {
        if (!((data->ret_filter) (&xdr, &ret)))
            goto fatal_error;
        xdr_free (data->ret_filter, (char*)&ret);
    } else /* error */ {
        /* Error was NULL so synthesize an error. */
        if (rerr.code == 0)
            remoteDispatchGenericError(&rerr);
        if (!xdr_remote_error (&xdr, &rerr))
            goto fatal_error;
        xdr_free((xdrproc_t)xdr_remote_error,  (char *)&rerr);
    }

    /* Write the length word. */
    len = xdr_getpos (&xdr);
    if (xdr_setpos (&xdr, 0) == 0)
        goto fatal_error;

    if (!xdr_u_int (&xdr, &len))
        goto fatal_error;

    xdr_destroy (&xdr);

    msg->bufferLength = len;
    msg->bufferOffset = 0;

    return 0;

fatal_error:
    /* Seriously bad stuff happened, so we'll kill off this client
       and not send back any RPC error */
    xdr_destroy (&xdr);
    return -1;
}
