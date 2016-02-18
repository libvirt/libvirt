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


/* Helpers */
static virAdmServerPtr
get_nonnull_server(virAdmConnectPtr conn, admin_nonnull_server server)
{
    return virAdmGetServer(conn, server.name);
}


static int
callFull(virAdmConnectPtr conn ATTRIBUTE_UNUSED,
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
call(virAdmConnectPtr conn,
     unsigned int flags,
     int proc_nr,
     xdrproc_t args_filter, char *args,
     xdrproc_t ret_filter, char *ret)
{
    virCheckFlags(0, -1);

    return callFull(conn, conn->privateData,
                    NULL, 0, NULL, NULL, proc_nr,
                    args_filter, args, ret_filter, ret);
}

#include "admin_client.h"

static void
remoteAdminClientCloseFunc(virNetClientPtr client ATTRIBUTE_UNUSED,
                           int reason,
                           void *opaque)
{
    virAdmConnectCloseCallbackDataPtr cbdata = opaque;

    virObjectLock(cbdata);

    if (cbdata->callback) {
        VIR_DEBUG("Triggering connection close callback %p reason=%d, opaque=%p",
                  cbdata->callback, reason, cbdata->opaque);
        cbdata->callback(cbdata->conn, reason, cbdata->opaque);

        if (cbdata->freeCallback)
            cbdata->freeCallback(cbdata->opaque);
        cbdata->callback = NULL;
        cbdata->freeCallback = NULL;
    }
    virObjectUnlock(cbdata);
}

static int
remoteAdminConnectOpen(virAdmConnectPtr conn, unsigned int flags)
{
    int rv = -1;
    remoteAdminPrivPtr priv = conn->privateData;
    admin_connect_open_args args;

    virObjectLock(priv);

    args.flags = flags;

    if (virNetClientRegisterAsyncIO(priv->client) < 0) {
        VIR_DEBUG("Failed to add event watch, disabling events and support for"
                  " keepalive messages");
        virResetLastError();
    }

    virObjectRef(conn->closeCallback);
    virNetClientSetCloseCallback(priv->client, remoteAdminClientCloseFunc,
                                 conn->closeCallback,
                                 virObjectFreeCallback);

    if (call(conn, 0, ADMIN_PROC_CONNECT_OPEN,
             (xdrproc_t)xdr_admin_connect_open_args, (char *)&args,
             (xdrproc_t)xdr_void, (char *)NULL) == -1) {
        goto done;
    }

    rv = 0;

 done:
    virObjectUnlock(priv);
    return rv;
}

static int
remoteAdminConnectClose(virAdmConnectPtr conn)
{
    int rv = -1;
    remoteAdminPrivPtr priv = conn->privateData;

    virObjectLock(priv);

    if (call(conn, 0, ADMIN_PROC_CONNECT_CLOSE,
             (xdrproc_t)xdr_void, (char *)NULL,
             (xdrproc_t)xdr_void, (char *)NULL) == -1) {
        goto done;
    }

    virNetClientSetCloseCallback(priv->client, NULL, conn->closeCallback,
                                 virObjectFreeCallback);
    virNetClientClose(priv->client);

    rv = 0;

 done:
    virObjectUnlock(priv);
    return rv;
}

static void
remoteAdminPrivFree(void *opaque)
{
    virAdmConnectPtr conn = opaque;

    remoteAdminConnectClose(conn);
    virObjectUnref(conn->privateData);
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

static int
remoteAdminConnectListServers(virAdmConnectPtr conn,
                              virAdmServerPtr **servers,
                              unsigned int flags)
{
    int rv = -1;
    size_t i;
    virAdmServerPtr *tmp_srvs = NULL;
    remoteAdminPrivPtr priv = conn->privateData;
    admin_connect_list_servers_args args;
    admin_connect_list_servers_ret ret;

    args.need_results = !!servers;
    args.flags = flags;

    memset(&ret, 0, sizeof(ret));
    virObjectLock(priv);

    if (call(conn,
             0,
             ADMIN_PROC_CONNECT_LIST_SERVERS,
             (xdrproc_t) xdr_admin_connect_list_servers_args,
             (char *) &args,
             (xdrproc_t) xdr_admin_connect_list_servers_ret,
             (char *) &ret) == -1)
        goto done;

    if (ret.servers.servers_len > ADMIN_SERVER_LIST_MAX) {
        virReportError(VIR_ERR_RPC,
                       _("Too many servers '%d' for limit '%d'"),
                       ret.servers.servers_len, ADMIN_SERVER_LIST_MAX);
        goto cleanup;
    }

    if (servers) {
        if (VIR_ALLOC_N(tmp_srvs, ret.servers.servers_len + 1) < 0)
            goto cleanup;

        for (i = 0; i < ret.servers.servers_len; i++) {
            tmp_srvs[i] = get_nonnull_server(conn, ret.servers.servers_val[i]);
            if (!tmp_srvs[i])
                goto cleanup;
        }
        *servers = tmp_srvs;
        tmp_srvs = NULL;
    }

    rv = ret.ret;

 cleanup:
    if (tmp_srvs) {
        for (i = 0; i < ret.servers.servers_len; i++)
            virObjectUnref(tmp_srvs[i]);
        VIR_FREE(tmp_srvs);
    }

    xdr_free((xdrproc_t) xdr_admin_connect_list_servers_ret, (char *) &ret);

 done:
    virObjectUnlock(priv);
    return rv;
}
