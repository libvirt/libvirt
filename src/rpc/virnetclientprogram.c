/*
 * virnetclientprogram.c: generic network RPC client program
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
 */

#include <config.h>

#include <unistd.h>

#include "virnetclientprogram.h"
#include "virnetclient.h"
#include "virnetprotocol.h"

#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virutil.h"
#include "virfile.h"
#include "virthread.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netclientprogram");

struct _virNetClientProgram {
    virObject parent;

    unsigned program;
    unsigned version;
    virNetClientProgramEvent *events;
    size_t nevents;
    void *eventOpaque;
};

static virClass *virNetClientProgramClass;
static void virNetClientProgramDispose(void *obj);

static int virNetClientProgramOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetClientProgram, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetClientProgram);


virNetClientProgram *virNetClientProgramNew(unsigned program,
                                              unsigned version,
                                              virNetClientProgramEvent *events,
                                              size_t nevents,
                                              void *eventOpaque)
{
    virNetClientProgram *prog;

    if (virNetClientProgramInitialize() < 0)
        return NULL;

    if (!(prog = virObjectNew(virNetClientProgramClass)))
        return NULL;

    prog->program = program;
    prog->version = version;
    prog->events = events;
    prog->nevents = nevents;
    prog->eventOpaque = eventOpaque;

    return prog;
}


void virNetClientProgramDispose(void *obj G_GNUC_UNUSED)
{
}


unsigned virNetClientProgramGetProgram(virNetClientProgram *prog)
{
    return prog->program;
}


unsigned virNetClientProgramGetVersion(virNetClientProgram *prog)
{
    return prog->version;
}


int virNetClientProgramMatches(virNetClientProgram *prog,
                               virNetMessage *msg)
{
    if (prog->program == msg->header.prog &&
        prog->version == msg->header.vers)
        return 1;
    return 0;
}


static int
virNetClientProgramDispatchError(virNetClientProgram *prog G_GNUC_UNUSED,
                                 virNetMessage *msg)
{
    virNetMessageError err = { 0 };
    int ret = -1;

    if (virNetMessageDecodePayload(msg, (xdrproc_t)xdr_virNetMessageError, &err) < 0)
        goto cleanup;

    /* Interop for virErrorNumber glitch in 0.8.0, if server is
     * 0.7.1 through 0.7.7; see comments in virterror.h. */
    switch (err.code) {
    case VIR_WAR_NO_NWFILTER:
        /* no way to tell old VIR_WAR_NO_SECRET apart from
         * VIR_WAR_NO_NWFILTER, but both are very similar
         * warnings, so ignore the difference */
        break;
    case VIR_ERR_INVALID_NWFILTER:
    case VIR_ERR_NO_NWFILTER:
    case VIR_ERR_BUILD_FIREWALL:
        /* server was trying to pass VIR_ERR_INVALID_SECRET,
         * VIR_ERR_NO_SECRET, or VIR_ERR_CONFIG_UNSUPPORTED */
        if (err.domain != VIR_FROM_NWFILTER)
            err.code += 4;
        break;
    case VIR_WAR_NO_SECRET:
        if (err.domain == VIR_FROM_QEMU)
            err.code = VIR_ERR_OPERATION_TIMEOUT;
        break;
    case VIR_ERR_INVALID_SECRET:
        if (err.domain == VIR_FROM_XEN)
            err.code = VIR_ERR_MIGRATE_PERSIST_FAILED;
        break;
    default:
        /* Nothing to alter. */
        break;
    }

    if ((err.domain == VIR_FROM_REMOTE || err.domain == VIR_FROM_RPC) &&
        err.code == VIR_ERR_RPC &&
        err.level == VIR_ERR_ERROR &&
        err.message &&
        STRPREFIX(*err.message, "unknown procedure")) {
        virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,
                          err.domain,
                          VIR_ERR_NO_SUPPORT,
                          err.level,
                          err.str1 ? *err.str1 : NULL,
                          err.str2 ? *err.str2 : NULL,
                          err.str3 ? *err.str3 : NULL,
                          err.int1,
                          err.int2,
                          "%s", *err.message);
    } else {
        virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,
                          err.domain,
                          err.code,
                          err.level,
                          err.str1 ? *err.str1 : NULL,
                          err.str2 ? *err.str2 : NULL,
                          err.str3 ? *err.str3 : NULL,
                          err.int1,
                          err.int2,
                          "%s", err.message ? *err.message : _("Unknown error"));
    }

    ret = 0;

 cleanup:
    xdr_free((xdrproc_t)xdr_virNetMessageError, (void*)&err);
    return ret;
}


static virNetClientProgramEvent *virNetClientProgramGetEvent(virNetClientProgram *prog,
                                                               int procedure)
{
    size_t i;

    for (i = 0; i < prog->nevents; i++) {
        if (prog->events[i].proc == procedure)
            return &prog->events[i];
    }

    return NULL;
}


int virNetClientProgramDispatch(virNetClientProgram *prog,
                                virNetClient *client,
                                virNetMessage *msg)
{
    virNetClientProgramEvent *event;
    g_autofree char *evdata = NULL;

    VIR_DEBUG("prog=%d ver=%d type=%d status=%d serial=%d proc=%d",
              msg->header.prog, msg->header.vers, msg->header.type,
              msg->header.status, msg->header.serial, msg->header.proc);

    /* Check version, etc. */
    if (msg->header.prog != prog->program) {
        VIR_ERROR(_("program mismatch in event (actual 0x%1$x, expected 0x%2$x)"),
                  msg->header.prog, prog->program);
        return -1;
    }

    if (msg->header.vers != prog->version) {
        VIR_ERROR(_("version mismatch in event (actual 0x%1$x, expected 0x%2$x)"),
                  msg->header.vers, prog->version);
        return -1;
    }

    if (msg->header.status != VIR_NET_OK) {
        VIR_ERROR(_("status mismatch in event (actual 0x%1$x, expected 0x%2$x)"),
                  msg->header.status, VIR_NET_OK);
        return -1;
    }

    if (msg->header.type != VIR_NET_MESSAGE) {
        VIR_ERROR(_("type mismatch in event (actual 0x%1$x, expected 0x%2$x)"),
                  msg->header.type, VIR_NET_MESSAGE);
        return -1;
    }

    event = virNetClientProgramGetEvent(prog, msg->header.proc);

    if (!event) {
        VIR_ERROR(_("No event expected with procedure 0x%1$x"),
                  msg->header.proc);
        return -1;
    }

    evdata = g_new0(char, event->msg_len);

    if (virNetMessageDecodePayload(msg, event->msg_filter, evdata) < 0)
        return 0;

    event->func(prog, client, evdata, prog->eventOpaque);

    xdr_free(event->msg_filter, evdata);

    return 0;
}


int virNetClientProgramCall(virNetClientProgram *prog,
                            virNetClient *client,
                            unsigned serial,
                            int proc,
                            size_t noutfds,
                            int *outfds,
                            size_t *ninfds,
                            int **infds,
                            xdrproc_t args_filter, void *args,
                            xdrproc_t ret_filter, void *ret)
{
    virNetMessage *msg;
    size_t i;

    if (infds)
        *infds = NULL;
    if (ninfds)
        *ninfds = 0;

    if (!(msg = virNetMessageNew(false)))
        return -1;

    msg->header.prog = prog->program;
    msg->header.vers = prog->version;
    msg->header.status = VIR_NET_OK;
    msg->header.type = noutfds ? VIR_NET_CALL_WITH_FDS : VIR_NET_CALL;
    msg->header.serial = serial;
    msg->header.proc = proc;
    msg->fds = g_new0(int, noutfds);
    msg->nfds = noutfds;
    for (i = 0; i < msg->nfds; i++)
        msg->fds[i] = -1;
    for (i = 0; i < msg->nfds; i++) {
        if ((msg->fds[i] = dup(outfds[i])) < 0) {
            virReportSystemError(errno,
                                 _("Cannot duplicate FD %1$d"),
                                 outfds[i]);
            goto error;
        }
        if (virSetInherit(msg->fds[i], false) < 0) {
            virReportSystemError(errno,
                                 _("Cannot set close-on-exec %1$d"),
                                 msg->fds[i]);
            goto error;
        }
    }

    if (virNetMessageEncodeHeader(msg) < 0)
        goto error;

    if (msg->nfds &&
        virNetMessageEncodeNumFDs(msg) < 0)
        goto error;

    if (virNetMessageEncodePayload(msg, args_filter, args) < 0)
        goto error;

    if (virNetClientSendWithReply(client, msg) < 0)
        goto error;

    /* None of these 3 should ever happen here, because
     * virNetClientSend should have validated the reply,
     * but it doesn't hurt to check again.
     */
    if (msg->header.type != VIR_NET_REPLY &&
        msg->header.type != VIR_NET_REPLY_WITH_FDS) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected message type %1$d"), msg->header.type);
        goto error;
    }
    if (msg->header.proc != proc) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected message proc %1$d != %2$d"),
                       msg->header.proc, proc);
        goto error;
    }
    if (msg->header.serial != serial) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected message serial %1$d != %2$d"),
                       msg->header.serial, serial);
        goto error;
    }

    switch (msg->header.status) {
    case VIR_NET_OK:
        if (infds && ninfds) {
            *ninfds = msg->nfds;
            *infds = g_new0(int, *ninfds);

            for (i = 0; i < *ninfds; i++)
                (*infds)[i] = -1;
            for (i = 0; i < *ninfds; i++) {
                if (((*infds)[i] = dup(msg->fds[i])) < 0) {
                    virReportSystemError(errno,
                                         _("Cannot duplicate FD %1$d"),
                                         msg->fds[i]);
                    goto error;
                }
                if (virSetInherit((*infds)[i], false) < 0) {
                    virReportSystemError(errno,
                                         _("Cannot set close-on-exec %1$d"),
                                         (*infds)[i]);
                    goto error;
                }
            }

        }
        if (virNetMessageDecodePayload(msg, ret_filter, ret) < 0)
            goto error;
        break;

    case VIR_NET_ERROR:
        virNetClientProgramDispatchError(prog, msg);
        goto error;

    case VIR_NET_CONTINUE:
    default:
        virReportError(VIR_ERR_RPC,
                       _("Unexpected message status %1$d"), msg->header.status);
        goto error;
    }

    virNetMessageFree(msg);

    return 0;

 error:
    virNetMessageFree(msg);
    if (infds && ninfds) {
        for (i = 0; i < *ninfds; i++)
            VIR_FORCE_CLOSE((*infds)[i]);
    }
    return -1;
}
