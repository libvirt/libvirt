/*
 * virnetserverprogram.c: generic network RPC server program
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include "virnetserverprogram.h"
#include "virnetserverclient.h"

#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virfile.h"
#include "virthread.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netserverprogram");

struct _virNetServerProgram {
    virObject object;

    unsigned program;
    unsigned version;
    virNetServerProgramProcPtr procs;
    size_t nprocs;
};


static virClassPtr virNetServerProgramClass;
static void virNetServerProgramDispose(void *obj);

static int virNetServerProgramOnceInit(void)
{
    if (!(virNetServerProgramClass = virClassNew(virClassForObject(),
                                                 "virNetServerProgram",
                                                 sizeof(virNetServerProgram),
                                                 virNetServerProgramDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetServerProgram)


virNetServerProgramPtr virNetServerProgramNew(unsigned program,
                                              unsigned version,
                                              virNetServerProgramProcPtr procs,
                                              size_t nprocs)
{
    virNetServerProgramPtr prog;

    if (virNetServerProgramInitialize() < 0)
        return NULL;

    if (!(prog = virObjectNew(virNetServerProgramClass)))
        return NULL;

    prog->program = program;
    prog->version = version;
    prog->procs = procs;
    prog->nprocs = nprocs;

    VIR_DEBUG("prog=%p", prog);

    return prog;
}


int virNetServerProgramGetID(virNetServerProgramPtr prog)
{
    return prog->program;
}


int virNetServerProgramGetVersion(virNetServerProgramPtr prog)
{
    return prog->version;
}


int virNetServerProgramMatches(virNetServerProgramPtr prog,
                               virNetMessagePtr msg)
{
    if (prog->program == msg->header.prog &&
        prog->version == msg->header.vers)
        return 1;
    return 0;
}


static virNetServerProgramProcPtr virNetServerProgramGetProc(virNetServerProgramPtr prog,
                                                             int procedure)
{
    virNetServerProgramProcPtr proc;

    if (procedure < 0)
        return NULL;
    if (procedure >= prog->nprocs)
        return NULL;

    proc = &prog->procs[procedure];

    if (!proc->func)
        return NULL;

    return proc;
}

unsigned int
virNetServerProgramGetPriority(virNetServerProgramPtr prog,
                               int procedure)
{
    virNetServerProgramProcPtr proc = virNetServerProgramGetProc(prog, procedure);

    if (!proc)
        return 0;

    return proc->priority;
}

static int
virNetServerProgramSendError(unsigned program,
                             unsigned version,
                             virNetServerClientPtr client,
                             virNetMessagePtr msg,
                             virNetMessageErrorPtr rerr,
                             int procedure,
                             int type,
                             int serial)
{
    VIR_DEBUG("prog=%d ver=%d proc=%d type=%d serial=%d msg=%p rerr=%p",
              program, version, procedure, type, serial, msg, rerr);

    virNetMessageSaveError(rerr);

    /* Return header. */
    msg->header.prog = program;
    msg->header.vers = version;
    msg->header.proc = procedure;
    msg->header.type = type;
    msg->header.serial = serial;
    msg->header.status = VIR_NET_ERROR;

    if (virNetMessageEncodeHeader(msg) < 0)
        goto error;

    if (virNetMessageEncodePayload(msg, (xdrproc_t)xdr_virNetMessageError, rerr) < 0)
        goto error;
    xdr_free((xdrproc_t)xdr_virNetMessageError, (void*)rerr);

    /* Put reply on end of tx queue to send out  */
    if (virNetServerClientSendMessage(client, msg) < 0)
        return -1;

    return 0;

 error:
    VIR_WARN("Failed to serialize remote error '%p'", rerr);
    xdr_free((xdrproc_t)xdr_virNetMessageError, (void*)rerr);
    return -1;
}


/*
 * @client: the client to send the error to
 * @req: the message this error is in reply to
 *
 * Send an error message to the client
 *
 * Returns 0 if the error was sent, -1 upon fatal error
 */
int
virNetServerProgramSendReplyError(virNetServerProgramPtr prog,
                                  virNetServerClientPtr client,
                                  virNetMessagePtr msg,
                                  virNetMessageErrorPtr rerr,
                                  virNetMessageHeaderPtr req)
{
    /*
     * For data streams, errors are sent back as data streams
     * For method calls, errors are sent back as method replies
     */
    return virNetServerProgramSendError(prog->program,
                                        prog->version,
                                        client,
                                        msg,
                                        rerr,
                                        req->proc,
                                        req->type == VIR_NET_STREAM ? VIR_NET_STREAM : VIR_NET_REPLY,
                                        req->serial);
}


int virNetServerProgramSendStreamError(virNetServerProgramPtr prog,
                                       virNetServerClientPtr client,
                                       virNetMessagePtr msg,
                                       virNetMessageErrorPtr rerr,
                                       int procedure,
                                       int serial)
{
    return virNetServerProgramSendError(prog->program,
                                        prog->version,
                                        client,
                                        msg,
                                        rerr,
                                        procedure,
                                        VIR_NET_STREAM,
                                        serial);
}


int virNetServerProgramUnknownError(virNetServerClientPtr client,
                                    virNetMessagePtr msg,
                                    virNetMessageHeaderPtr req)
{
    virNetMessageError rerr;

    virReportError(VIR_ERR_RPC,
                   _("Cannot find program %d version %d"), req->prog, req->vers);

    memset(&rerr, 0, sizeof(rerr));
    return virNetServerProgramSendError(req->prog,
                                        req->vers,
                                        client,
                                        msg,
                                        &rerr,
                                        req->proc,
                                        VIR_NET_REPLY,
                                        req->serial);
}


static int
virNetServerProgramDispatchCall(virNetServerProgramPtr prog,
                                virNetServerPtr server,
                                virNetServerClientPtr client,
                                virNetMessagePtr msg);

/*
 * @server: the unlocked server object
 * @client: the unlocked client object
 * @msg: the complete incoming message packet, with header already decoded
 *
 * This function is intended to be called from worker threads
 * when an incoming message is ready to be dispatched for
 * execution.
 *
 * Upon successful return the '@msg' instance will be released
 * by this function (or more often, reused to send a reply).
 * Upon failure, the '@msg' must be freed by the caller.
 *
 * Returns 0 if the message was dispatched, -1 upon fatal error
 */
int virNetServerProgramDispatch(virNetServerProgramPtr prog,
                                virNetServerPtr server,
                                virNetServerClientPtr client,
                                virNetMessagePtr msg)
{
    int ret = -1;
    virNetMessageError rerr;

    memset(&rerr, 0, sizeof(rerr));

    VIR_DEBUG("prog=%d ver=%d type=%d status=%d serial=%d proc=%d",
              msg->header.prog, msg->header.vers, msg->header.type,
              msg->header.status, msg->header.serial, msg->header.proc);

    /* Check version, etc. */
    if (msg->header.prog != prog->program) {
        virReportError(VIR_ERR_RPC,
                       _("program mismatch (actual %x, expected %x)"),
                       msg->header.prog, prog->program);
        goto error;
    }

    if (msg->header.vers != prog->version) {
        virReportError(VIR_ERR_RPC,
                       _("version mismatch (actual %x, expected %x)"),
                       msg->header.vers, prog->version);
        goto error;
    }

    switch (msg->header.type) {
    case VIR_NET_CALL:
    case VIR_NET_CALL_WITH_FDS:
        ret = virNetServerProgramDispatchCall(prog, server, client, msg);
        break;

    case VIR_NET_STREAM:
        /* Since stream data is non-acked, async, we may continue to receive
         * stream packets after we closed down a stream. Just drop & ignore
         * these.
         */
        VIR_INFO("Ignoring unexpected stream data serial=%d proc=%d status=%d",
                 msg->header.serial, msg->header.proc, msg->header.status);
        /* Send a dummy reply to free up 'msg' & unblock client rx */
        virNetMessageClear(msg);
        msg->header.type = VIR_NET_REPLY;
        if (virNetServerClientSendMessage(client, msg) < 0) {
            ret = -1;
            goto cleanup;
        }
        ret = 0;
        break;

    default:
        virReportError(VIR_ERR_RPC,
                       _("Unexpected message type %u"),
                       msg->header.type);
        goto error;
    }

    return ret;

 error:
    if (msg->header.type == VIR_NET_CALL ||
        msg->header.type == VIR_NET_CALL_WITH_FDS) {
        ret = virNetServerProgramSendReplyError(prog, client, msg, &rerr, &msg->header);
    } else {
        /* Send a dummy reply to free up 'msg' & unblock client rx */
        virNetMessageClear(msg);
        msg->header.type = VIR_NET_REPLY;
        if (virNetServerClientSendMessage(client, msg) < 0) {
            ret = -1;
            goto cleanup;
        }
        ret = 0;
    }

 cleanup:
    return ret;
}


/*
 * @server: the unlocked server object
 * @client: the unlocked client object
 * @msg: the complete incoming method call, with header already decoded
 *
 * This method is used to dispatch a message representing an
 * incoming method call from a client. It decodes the payload
 * to obtain method call arguments, invokves the method and
 * then sends a reply packet with the return values
 *
 * Returns 0 if the reply was sent, or -1 upon fatal error
 */
static int
virNetServerProgramDispatchCall(virNetServerProgramPtr prog,
                                virNetServerPtr server,
                                virNetServerClientPtr client,
                                virNetMessagePtr msg)
{
    char *arg = NULL;
    char *ret = NULL;
    int rv = -1;
    virNetServerProgramProcPtr dispatcher;
    virNetMessageError rerr;
    size_t i;
    virIdentityPtr identity = NULL;

    memset(&rerr, 0, sizeof(rerr));

    if (msg->header.status != VIR_NET_OK) {
        virReportError(VIR_ERR_RPC,
                       _("Unexpected message status %u"),
                       msg->header.status);
        goto error;
    }

    dispatcher = virNetServerProgramGetProc(prog, msg->header.proc);

    if (!dispatcher) {
        virReportError(VIR_ERR_RPC,
                       _("unknown procedure: %d"),
                       msg->header.proc);
        goto error;
    }

    /* If client is marked as needing auth, don't allow any RPC ops
     * which are except for authentication ones
     */
    if (virNetServerClientNeedAuth(client) &&
        dispatcher->needAuth) {
        /* Explicitly *NOT* calling  remoteDispatchAuthError() because
           we want back-compatibility with libvirt clients which don't
           support the VIR_ERR_AUTH_FAILED error code */
        virReportError(VIR_ERR_RPC,
                       "%s", _("authentication required"));
        goto error;
    }

    if (VIR_ALLOC_N(arg, dispatcher->arg_len) < 0)
        goto error;
    if (VIR_ALLOC_N(ret, dispatcher->ret_len) < 0)
        goto error;

    if (virNetMessageDecodePayload(msg, dispatcher->arg_filter, arg) < 0)
        goto error;

    if (!(identity = virNetServerClientGetIdentity(client)))
        goto error;

    if (virIdentitySetCurrent(identity) < 0)
        goto error;

    /*
     * When the RPC handler is called:
     *
     *  - Server object is unlocked
     *  - Client object is unlocked
     *
     * Without locking, it is safe to use:
     *
     *   'args and 'ret'
     */
    rv = (dispatcher->func)(server, client, msg, &rerr, arg, ret);

    if (virIdentitySetCurrent(NULL) < 0)
        goto error;

    /*
     * If rv == 1, this indicates the dispatch func has
     * populated 'msg' with a list of FDs to return to
     * the caller.
     *
     * Otherwise we must clear out the FDs we got from
     * the client originally.
     *
     */
    if (rv != 1) {
        for (i = 0; i < msg->nfds; i++)
            VIR_FORCE_CLOSE(msg->fds[i]);
        VIR_FREE(msg->fds);
        msg->nfds = 0;
    }

    xdr_free(dispatcher->arg_filter, arg);

    if (rv < 0)
        goto error;

    /* Return header. We're re-using same message object, so
     * only need to tweak type/status fields */
    /*msg->header.prog = msg->header.prog;*/
    /*msg->header.vers = msg->header.vers;*/
    /*msg->header.proc = msg->header.proc;*/
    msg->header.type = msg->nfds ? VIR_NET_REPLY_WITH_FDS : VIR_NET_REPLY;
    /*msg->header.serial = msg->header.serial;*/
    msg->header.status = VIR_NET_OK;

    if (virNetMessageEncodeHeader(msg) < 0) {
        xdr_free(dispatcher->ret_filter, ret);
        goto error;
    }

    if (msg->nfds &&
        virNetMessageEncodeNumFDs(msg) < 0) {
        xdr_free(dispatcher->ret_filter, ret);
        goto error;
    }

    if (virNetMessageEncodePayload(msg, dispatcher->ret_filter, ret) < 0) {
        xdr_free(dispatcher->ret_filter, ret);
        goto error;
    }

    xdr_free(dispatcher->ret_filter, ret);
    VIR_FREE(arg);
    VIR_FREE(ret);

    virObjectUnref(identity);
    /* Put reply on end of tx queue to send out  */
    return virNetServerClientSendMessage(client, msg);

 error:
    /* Bad stuff (de-)serializing message, but we have an
     * RPC error message we can send back to the client */
    rv = virNetServerProgramSendReplyError(prog, client, msg, &rerr, &msg->header);

    VIR_FREE(arg);
    VIR_FREE(ret);
    virObjectUnref(identity);

    return rv;
}


int virNetServerProgramSendStreamData(virNetServerProgramPtr prog,
                                      virNetServerClientPtr client,
                                      virNetMessagePtr msg,
                                      int procedure,
                                      int serial,
                                      const char *data,
                                      size_t len)
{
    VIR_DEBUG("client=%p msg=%p data=%p len=%zu", client, msg, data, len);

    /* Return header. We're reusing same message object, so
     * only need to tweak type/status fields */
    msg->header.prog = prog->program;
    msg->header.vers = prog->version;
    msg->header.proc = procedure;
    msg->header.type = VIR_NET_STREAM;
    msg->header.serial = serial;
    /*
     * NB
     *   data != NULL + len > 0    => REMOTE_CONTINUE   (Sending back data)
     *   data != NULL + len == 0   => REMOTE_CONTINUE   (Sending read EOF)
     *   data == NULL              => REMOTE_OK         (Sending finish handshake confirmation)
     */
    msg->header.status = data ? VIR_NET_CONTINUE : VIR_NET_OK;

    if (virNetMessageEncodeHeader(msg) < 0)
        return -1;

    if (data && len) {
        if (virNetMessageEncodePayloadRaw(msg, data, len) < 0)
            return -1;

    } else {
        if (virNetMessageEncodePayloadEmpty(msg) < 0)
            return -1;
    }
    VIR_DEBUG("Total %zu", msg->bufferLength);

    return virNetServerClientSendMessage(client, msg);
}


void virNetServerProgramDispose(void *obj ATTRIBUTE_UNUSED)
{
}
