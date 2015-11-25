/*
 * admin_remote.c
 *
 * Copyright (C) 2015 Red Hat, Inc.
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
 * Author: Erik Skultety <eskultet@redhat.com>
 */

#include <config.h>
#include <rpc/rpc.h>
#include "admin_protocol.h"

typedef struct _remoteAdminPriv remoteAdminPriv;
typedef remoteAdminPriv *remoteAdminPrivPtr;

struct _remoteAdminPriv {
    virObjectLockable parent;

    int counter;
    virNetClientPtr client;
    virNetClientProgramPtr program;
};

static virClassPtr remoteAdminPrivClass;

static void
remoteAdminPrivDispose(void *opaque)
{
    remoteAdminPrivPtr priv = opaque;

    virObjectUnref(priv->program);
    virObjectUnref(priv->client);
}


static int
callFull(virAdmDaemonPtr dmn ATTRIBUTE_UNUSED,
         remoteAdminPrivPtr priv,
         int *fdin,
         size_t fdinlen,
         int **fdout,
         size_t *fdoutlen,
         int proc_nr,
         xdrproc_t args_filter, char *args,
         xdrproc_t ret_filter, char *ret)
{
    int rv;
    virNetClientProgramPtr prog = priv->program;
    int counter = priv->counter++;
    virNetClientPtr client = priv->client;

    /* Unlock, so that if we get any async events/stream data
     * while processing the RPC, we don't deadlock when our
     * callbacks for those are invoked
     */
    virObjectRef(priv);
    virObjectUnlock(priv);

    rv = virNetClientProgramCall(prog,
                                 client,
                                 counter,
                                 proc_nr,
                                 fdinlen, fdin,
                                 fdoutlen, fdout,
                                 args_filter, args,
                                 ret_filter, ret);

    virObjectLock(priv);
    virObjectUnref(priv);

    return rv;
}

static int
call(virAdmDaemonPtr dmn,
     unsigned int flags,
     int proc_nr,
     xdrproc_t args_filter, char *args,
     xdrproc_t ret_filter, char *ret)
{
    virCheckFlags(0, -1);

    return callFull(dmn, dmn->privateData,
                    NULL, 0, NULL, NULL, proc_nr,
                    args_filter, args, ret_filter, ret);
}

#include "admin_client.h"

static void
remoteAdminClientCloseFunc(virNetClientPtr client ATTRIBUTE_UNUSED,
                           int reason,
                           void *opaque)
{
    virAdmDaemonCloseCallbackDataPtr cbdata = opaque;

    virObjectLock(cbdata);

    if (cbdata->callback) {
        VIR_DEBUG("Triggering connection close callback %p reason=%d, opaque=%p",
                  cbdata->callback, reason, cbdata->opaque);
        cbdata->callback(cbdata->dmn, reason, cbdata->opaque);

        if (cbdata->freeCallback)
            cbdata->freeCallback(cbdata->opaque);
        cbdata->callback = NULL;
        cbdata->freeCallback = NULL;
    }
    virObjectUnlock(cbdata);
}

static int
remoteAdminDaemonOpen(virAdmDaemonPtr dmn, unsigned int flags)
{
    int rv = -1;
    remoteAdminPrivPtr priv = dmn->privateData;
    admin_daemon_open_args args;

    virObjectLock(priv);

    args.flags = flags;

    if (virNetClientRegisterAsyncIO(priv->client) < 0) {
        VIR_DEBUG("Failed to add event watch, disabling events and support for"
                  " keepalive messages");
        virResetLastError();
    }

    virObjectRef(dmn->closeCallback);
    virNetClientSetCloseCallback(priv->client, remoteAdminClientCloseFunc,
                                 dmn->closeCallback,
                                 virObjectFreeCallback);

    if (call(dmn, 0, ADMIN_PROC_DAEMON_OPEN,
             (xdrproc_t)xdr_admin_daemon_open_args, (char *)&args,
             (xdrproc_t)xdr_void, (char *)NULL) == -1) {
        goto done;
    }

    rv = 0;

 done:
    virObjectUnlock(priv);
    return rv;
}

static int
remoteAdminDaemonClose(virAdmDaemonPtr dmn)
{
    int rv = -1;
    remoteAdminPrivPtr priv = dmn->privateData;

    virObjectLock(priv);

    if (call(dmn, 0, ADMIN_PROC_DAEMON_CLOSE,
             (xdrproc_t)xdr_void, (char *)NULL,
             (xdrproc_t)xdr_void, (char *)NULL) == -1) {
        goto done;
    }

    virNetClientSetCloseCallback(priv->client, NULL, NULL, NULL);

    rv = 0;

 done:
    virObjectUnlock(priv);
    return rv;
}

static void
remoteAdminPrivFree(void *opaque)
{
    virAdmDaemonPtr dmn = opaque;

    remoteAdminDaemonClose(dmn);
    virObjectUnref(dmn->privateData);
}

static remoteAdminPrivPtr
remoteAdminPrivNew(const char *sock_path)
{
    remoteAdminPrivPtr priv = NULL;

    if (!(priv = virObjectLockableNew(remoteAdminPrivClass)))
        goto error;

    if (!(priv->client = virNetClientNewUNIX(sock_path, false, NULL)))
        goto error;

    if (!(priv->program = virNetClientProgramNew(ADMIN_PROGRAM,
                                                 ADMIN_PROTOCOL_VERSION,
                                                 NULL, 0, NULL)))
        goto error;

    if (virNetClientAddProgram(priv->client, priv->program) < 0)
        goto error;

    return priv;
 error:
    virObjectUnref(priv);
    return NULL;
}
