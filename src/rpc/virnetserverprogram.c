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
    virObject parent;

    unsigned program;
    unsigned version;
    virNetServerProgramProc *procs;
    size_t nprocs;
};


static virClass *virNetServerProgramClass;
static void virNetServerProgramDispose(void *obj);

static int virNetServerProgramOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetServerProgram, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetServerProgram);


virNetServerProgram *virNetServerProgramNew(unsigned program,
                                              unsigned version,
                                              virNetServerProgramProc *procs,
                                              size_t nprocs)
{
    virNetServerProgram *prog;

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


int virNetServerProgramGetID(virNetServerProgram *prog)
{
    return prog->program;
}


int virNetServerProgramGetVersion(virNetServerProgram *prog)
{
    return prog->version;
}


int virNetServerProgramMatches(virNetServerProgram *prog,
                               virNetMessage *msg)
{
    if (prog->program == msg->header.prog &&
        prog->version == msg->header.vers)
        return 1;
    return 0;
}


static virNetServerProgramProc *virNetServerProgramGetProc(virNetServerProgram *prog,
                                                             int procedure)
{
    virNetServerProgramProc *proc;

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
virNetServerProgramGetPriority(virNetServerProgram *prog,
                               int procedure)
{
    virNetServerProgramProc *proc = virNetServerProgramGetProc(prog, procedure);

    if (!proc)
        return 0;

    return proc->priority;
}

static int
virNetServerProgramSendError(unsigned program,
                             unsigned version,
                             virNetServerClient *client,
                             virNetMessage *msg,
                             struct virNetMessageError *rerr,
                             int procedure,
                             int type,
                             unsigned int serial)
{
    VIR_DEBUG("prog=%d ver=%d proc=%d type=%d serial=%u msg=%p rerr=%p",
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
virNetServerProgramSendReplyError(virNetServerProgram *prog,
                                  virNetServerClient *client,
                                  virNetMessage *msg,
                                  struct virNetMessageError *rerr,
                                  struct virNetMessageHeader *req)
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


int virNetServerProgramSendStreamError(virNetServerProgram *prog,
                                       virNetServerClient *client,
                                       virNetMessage *msg,
                                       struct virNetMessageError *rerr,
                                       int procedure,
                                       unsigned int serial)
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


int virNetServerProgramUnknownError(virNetServerClient *client,
                                    virNetMessage *msg,
                                    struct virNetMessageHeader *req)
{
    virNetMessageError rerr = { 0 };

    virReportError(VIR_ERR_RPC,
                   _("Cannot find program %1$d version %2$d"), req->prog, req->vers);

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
virNetServerProgramDispatchCall(virNetServerProgram *prog,
                                virNetServer *server,
                                virNetServerClient *client,
                                virNetMessage *msg);

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
int virNetServerProgramDispatch(virNetServerProgram *prog,
                                virNetServer *server,
                                virNetServerClient *client,
                                virNetMessage *msg)
{
    int ret = -1;
    virNetMessageError rerr = { 0 };

    VIR_DEBUG("prog=%d ver=%d type=%d status=%d serial=%u proc=%d",
              msg->header.prog, msg->header.vers, msg->header.type,
              msg->header.status, msg->header.serial, msg->header.proc);

    /* Check version, etc. */
    if (msg->header.prog != prog->program) {
        virReportError(VIR_ERR_RPC,
                       _("program mismatch (actual %1$x, expected %2$x)"),
                       msg->header.prog, prog->program);
        goto error;
    }

    if (msg->header.vers != prog->version) {
        virReportError(VIR_ERR_RPC,
                       _("version mismatch (actual %1$x, expected %2$x)"),
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
        VIR_INFO("Ignoring unexpected stream data serial=%u proc=%d status=%d",
                 msg->header.serial, msg->header.proc, msg->header.status);
        /* Send a dummy reply to free up 'msg' & unblock client rx */
        virNetMessageClear(msg);
        msg->header.type = VIR_NET_REPLY;
        if (virNetServerClientSendMessage(client, msg) < 0)
            return -1;
        ret = 0;
        break;

    case VIR_NET_REPLY:
    case VIR_NET_REPLY_WITH_FDS:
    case VIR_NET_MESSAGE:
    case VIR_NET_STREAM_HOLE:
    default:
        virReportError(VIR_ERR_RPC,
                       _("Unexpected message type %1$u"),
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
        if (virNetServerClientSendMessage(client, msg) < 0)
            return -1;
        ret = 0;
    }

    return ret;
}


/*
 * @server: the unlocked server object
 * @client: the unlocked client object
 * @msg: the complete incoming method call, with header already decoded
 *
 * This method is used to dispatch a message representing an
 * incoming method call from a client. It decodes the payload
 * to obtain method call arguments, invokes the method and
 * then sends a reply packet with the return values
 *
 * Returns 0 if the reply was sent, or -1 upon fatal error
 */
static int
virNetServerProgramDispatchCall(virNetServerProgram *prog,
                                virNetServer *server,
                                virNetServerClient *client,
                                virNetMessage *msg)
{
    g_autofree char *arg = NULL;
    g_autofree char *ret = NULL;
    int rv = -1;
    virNetServerProgramProc *dispatcher = NULL;
    virNetMessageError rerr = { 0 };
    size_t i;
    g_autoptr(virIdentity) identity = NULL;

    if (msg->header.status != VIR_NET_OK) {
        virReportError(VIR_ERR_RPC,
                       _("Unexpected message status %1$u"),
                       msg->header.status);
        goto error;
    }

    dispatcher = virNetServerProgramGetProc(prog, msg->header.proc);

    if (!dispatcher) {
        virReportError(VIR_ERR_RPC,
                       _("unknown procedure: %1$d"),
                       msg->header.proc);
        goto error;
    }

    /* If the client is not authenticated, don't allow any RPC ops
     * which are except for authentication ones */
    if (dispatcher->needAuth &&
        !virNetServerClientIsAuthenticated(client)) {
        /* Explicitly *NOT* calling  remoteDispatchAuthError() because
           we want back-compatibility with libvirt clients which don't
           support the VIR_ERR_AUTH_FAILED error code */
        virReportError(VIR_ERR_RPC,
                       "%s", _("authentication required"));
        goto error;
    }

    arg = g_new0(char, dispatcher->arg_len);
    ret = g_new0(char, dispatcher->ret_len);

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

    if (virNetMessageEncodeHeader(msg) < 0)
        goto error;

    if (msg->nfds &&
        virNetMessageEncodeNumFDs(msg) < 0)
        goto error;

    if (virNetMessageEncodePayload(msg, dispatcher->ret_filter, ret) < 0)
        goto error;

    xdr_free(dispatcher->arg_filter, arg);
    xdr_free(dispatcher->ret_filter, ret);

    /* Put reply on end of tx queue to send out  */
    return virNetServerClientSendMessage(client, msg);

 error:
    if (arg)
        xdr_free(dispatcher->arg_filter, arg);
    if (ret)
        xdr_free(dispatcher->ret_filter, ret);

    /* Bad stuff (de-)serializing message, but we have an
     * RPC error message we can send back to the client */
    rv = virNetServerProgramSendReplyError(prog, client, msg, &rerr, &msg->header);

    return rv;
}


int virNetServerProgramSendStreamData(virNetServerProgram *prog,
                                      virNetServerClient *client,
                                      virNetMessage *msg,
                                      int procedure,
                                      unsigned int serial,
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
     *   data != NULL + len > 0    => VIR_NET_CONTINUE   (Sending back data)
     *   data != NULL + len == 0   => VIR_NET_CONTINUE   (Sending read EOF)
     *   data == NULL              => VIR_NET_OK         (Sending finish handshake confirmation)
     */
    msg->header.status = data ? VIR_NET_CONTINUE : VIR_NET_OK;

    if (virNetMessageEncodeHeader(msg) < 0)
        return -1;

    if (virNetMessageEncodePayloadRaw(msg, data, len) < 0)
        return -1;

    VIR_DEBUG("Total %zu", msg->bufferLength);

    return virNetServerClientSendMessage(client, msg);
}


int virNetServerProgramSendStreamHole(virNetServerProgram *prog,
                                      virNetServerClient *client,
                                      virNetMessage *msg,
                                      int procedure,
                                      unsigned int serial,
                                      long long length,
                                      unsigned int flags)
{
    virNetStreamHole data = { 0 };

    VIR_DEBUG("client=%p msg=%p length=%lld", client, msg, length);

    data.length = length;
    data.flags = flags;

    msg->header.prog = prog->program;
    msg->header.vers = prog->version;
    msg->header.proc = procedure;
    msg->header.type = VIR_NET_STREAM_HOLE;
    msg->header.serial = serial;
    msg->header.status = VIR_NET_CONTINUE;

    if (virNetMessageEncodeHeader(msg) < 0)
        return -1;

    if (virNetMessageEncodePayload(msg,
                                   (xdrproc_t)xdr_virNetStreamHole,
                                   &data) < 0)
        return -1;

    return virNetServerClientSendMessage(client, msg);
}


void virNetServerProgramDispose(void *obj G_GNUC_UNUSED)
{
}
