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
 */

#include <config.h>
#include <rpc/rpc.h>
#include "virtypedparam.h"
#include "admin_protocol.h"

typedef struct _remoteAdminPriv remoteAdminPriv;
struct _remoteAdminPriv {
    virObjectLockable parent;

    int counter;
    virNetClient *client;
    virNetClientProgram *program;
};

static virClass *remoteAdminPrivClass;

static void
remoteAdminPrivDispose(void *opaque)
{
    remoteAdminPriv *priv = opaque;

    virObjectUnref(priv->program);
    virObjectUnref(priv->client);
}


/* Helpers */
static virAdmServerPtr
get_nonnull_server(virAdmConnectPtr conn, admin_nonnull_server server)
{
    return virAdmGetServer(conn, server.name);
}

static virAdmClientPtr
get_nonnull_client(virAdmServerPtr srv, admin_nonnull_client client)
{
    return virAdmGetClient(srv, client.id, client.timestamp, client.transport);
}

static void
make_nonnull_server(admin_nonnull_server *srv_dst, virAdmServerPtr srv_src)
{
    srv_dst->name = srv_src->name;
}

static void
make_nonnull_client(admin_nonnull_client *client_dst,
                    virAdmClientPtr client_src)
{
    client_dst->id = client_src->id;
    client_dst->transport = client_src->transport;
    client_dst->timestamp = client_src->timestamp;
    make_nonnull_server(&client_dst->srv, client_src->srv);
}

static int
callFull(virAdmConnectPtr conn G_GNUC_UNUSED,
         remoteAdminPriv *priv,
         int *fdin,
         size_t fdinlen,
         int **fdout,
         size_t *fdoutlen,
         int proc_nr,
         xdrproc_t args_filter, char *args,
         xdrproc_t ret_filter, char *ret)
{
    int rv;
    virNetClientProgram *prog = priv->program;
    int counter = priv->counter++;
    virNetClient *client = priv->client;

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
remoteAdminClientCloseFunc(virNetClient *client G_GNUC_UNUSED,
                           int reason,
                           void *opaque)
{
    virAdmConnectCloseCallbackData *cbdata = opaque;
    VIR_LOCK_GUARD lock = virObjectLockGuard(cbdata);

    if (cbdata->callback) {
        VIR_DEBUG("Triggering connection close callback %p reason=%d, opaque=%p",
                  cbdata->callback, reason, cbdata->opaque);
        cbdata->callback(cbdata->conn, reason, cbdata->opaque);
        virAdmConnectCloseCallbackDataReset(cbdata);
    }
}

static int
remoteAdminConnectOpen(virAdmConnectPtr conn, unsigned int flags)
{
    remoteAdminPriv *priv = conn->privateData;
    admin_connect_open_args args;
    VIR_LOCK_GUARD lock = virObjectLockGuard(priv);

    args.flags = flags & ~VIR_CONNECT_NO_ALIASES;

    if (virNetClientRegisterAsyncIO(priv->client) < 0) {
        VIR_DEBUG("Failed to add event watch, disabling events and support for"
                  " keepalive messages");
        virResetLastError();
    }

    virObjectRef(conn->closeCallback);
    virNetClientSetCloseCallback(priv->client, remoteAdminClientCloseFunc,
                                 conn->closeCallback,
                                 virObjectUnref);

    if (call(conn, 0, ADMIN_PROC_CONNECT_OPEN,
             (xdrproc_t)xdr_admin_connect_open_args, (char *)&args,
             (xdrproc_t)xdr_void, (char *)NULL) == -1)
        return -1;

    return 0;
}

static int
remoteAdminConnectClose(virAdmConnectPtr conn)
{
    remoteAdminPriv *priv = conn->privateData;
    VIR_LOCK_GUARD lock = virObjectLockGuard(priv);

    if (call(conn, 0, ADMIN_PROC_CONNECT_CLOSE,
             (xdrproc_t)xdr_void, (char *)NULL,
             (xdrproc_t)xdr_void, (char *)NULL) == -1)
        return -1;

    virNetClientSetCloseCallback(priv->client, NULL, conn->closeCallback,
                                 virObjectUnref);
    virNetClientClose(priv->client);

    return 0;
}

static void
remoteAdminPrivFree(void *opaque)
{
    virAdmConnectPtr conn = opaque;

    remoteAdminConnectClose(conn);
    virObjectUnref(conn->privateData);
}

static remoteAdminPriv *
remoteAdminPrivNew(const char *sock_path)
{
    remoteAdminPriv *priv = NULL;

    if (!(priv = virObjectLockableNew(remoteAdminPrivClass)))
        goto error;

    if (!(priv->client = virNetClientNewUNIX(sock_path, NULL)))
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
remoteAdminServerGetThreadPoolParameters(virAdmServerPtr srv,
                                         virTypedParameterPtr *params,
                                         int *nparams,
                                         unsigned int flags)
{
    int rv = -1;
    remoteAdminPriv *priv = srv->conn->privateData;
    admin_server_get_threadpool_parameters_args args;
    admin_server_get_threadpool_parameters_ret ret = {0};
    VIR_LOCK_GUARD lock = virObjectLockGuard(priv);

    args.flags = flags;
    make_nonnull_server(&args.srv, srv);

    if (call(srv->conn, 0, ADMIN_PROC_SERVER_GET_THREADPOOL_PARAMETERS,
             (xdrproc_t)xdr_admin_server_get_threadpool_parameters_args, (char *) &args,
             (xdrproc_t)xdr_admin_server_get_threadpool_parameters_ret, (char *) &ret) == -1)
        return -1;

    if (virTypedParamsDeserialize((struct _virTypedParameterRemote *) ret.params.params_val,
                                  ret.params.params_len,
                                  ADMIN_SERVER_THREADPOOL_PARAMETERS_MAX,
                                  params,
                                  nparams) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    xdr_free((xdrproc_t)xdr_admin_server_get_threadpool_parameters_ret, (char *) &ret);
    return rv;
}

static int
remoteAdminServerSetThreadPoolParameters(virAdmServerPtr srv,
                                         virTypedParameterPtr params,
                                         int nparams,
                                         unsigned int flags)
{
    int rv = -1;
    remoteAdminPriv *priv = srv->conn->privateData;
    admin_server_set_threadpool_parameters_args args;
    VIR_LOCK_GUARD lock = virObjectLockGuard(priv);

    args.flags = flags;
    make_nonnull_server(&args.srv, srv);

    if (virTypedParamsSerialize(params, nparams,
                                ADMIN_SERVER_THREADPOOL_PARAMETERS_MAX,
                                (struct _virTypedParameterRemote **) &args.params.params_val,
                                &args.params.params_len,
                                0) < 0)
        goto cleanup;


    if (call(srv->conn, 0, ADMIN_PROC_SERVER_SET_THREADPOOL_PARAMETERS,
             (xdrproc_t)xdr_admin_server_set_threadpool_parameters_args, (char *) &args,
             (xdrproc_t)xdr_void, (char *) NULL) == -1)
        goto cleanup;

    rv = 0;
 cleanup:
    virTypedParamsRemoteFree((struct _virTypedParameterRemote *) args.params.params_val,
                             args.params.params_len);
    return rv;
}

static int
remoteAdminClientGetInfo(virAdmClientPtr client,
                         virTypedParameterPtr *params,
                         int *nparams,
                         unsigned int flags)
{
    int rv = -1;
    remoteAdminPriv *priv = client->srv->conn->privateData;
    admin_client_get_info_args args;
    admin_client_get_info_ret ret = {0};
    VIR_LOCK_GUARD lock = virObjectLockGuard(priv);

    args.flags = flags;
    make_nonnull_client(&args.clnt, client);

    if (call(client->srv->conn, 0, ADMIN_PROC_CLIENT_GET_INFO,
             (xdrproc_t)xdr_admin_client_get_info_args, (char *) &args,
             (xdrproc_t)xdr_admin_client_get_info_ret, (char *) &ret) == -1)
        return -1;

    if (virTypedParamsDeserialize((struct _virTypedParameterRemote *) ret.params.params_val,
                                  ret.params.params_len,
                                  ADMIN_CLIENT_INFO_PARAMETERS_MAX,
                                  params,
                                  nparams) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    xdr_free((xdrproc_t)xdr_admin_client_get_info_ret, (char *) &ret);
    return rv;
}

static int
remoteAdminServerGetClientLimits(virAdmServerPtr srv,
                                 virTypedParameterPtr *params,
                                 int *nparams,
                                 unsigned int flags)
{
    int rv = -1;
    admin_server_get_client_limits_args args;
    admin_server_get_client_limits_ret ret = {0};
    remoteAdminPriv *priv = srv->conn->privateData;
    VIR_LOCK_GUARD lock = virObjectLockGuard(priv);

    args.flags = flags;
    make_nonnull_server(&args.srv, srv);

    if (call(srv->conn, 0, ADMIN_PROC_SERVER_GET_CLIENT_LIMITS,
             (xdrproc_t) xdr_admin_server_get_client_limits_args,
             (char *) &args,
             (xdrproc_t) xdr_admin_server_get_client_limits_ret,
             (char *) &ret) == -1)
        return -1;

    if (virTypedParamsDeserialize((struct _virTypedParameterRemote *) ret.params.params_val,
                                  ret.params.params_len,
                                  ADMIN_SERVER_CLIENT_LIMITS_MAX,
                                  params,
                                  nparams) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    xdr_free((xdrproc_t) xdr_admin_server_get_client_limits_ret,
             (char *) &ret);
    return rv;
}

static int
remoteAdminServerSetClientLimits(virAdmServerPtr srv,
                                 virTypedParameterPtr params,
                                 int nparams,
                                 unsigned int flags)
{
    int rv = -1;
    admin_server_set_client_limits_args args;
    remoteAdminPriv *priv = srv->conn->privateData;
    VIR_LOCK_GUARD lock = virObjectLockGuard(priv);

    args.flags = flags;
    make_nonnull_server(&args.srv, srv);

    if (virTypedParamsSerialize(params, nparams,
                                ADMIN_SERVER_CLIENT_LIMITS_MAX,
                                (struct _virTypedParameterRemote **) &args.params.params_val,
                                &args.params.params_len,
                                0) < 0)
        goto cleanup;

    if (call(srv->conn, 0, ADMIN_PROC_SERVER_SET_CLIENT_LIMITS,
             (xdrproc_t) xdr_admin_server_set_client_limits_args,
             (char *) &args,
             (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto cleanup;

    rv = 0;
 cleanup:
    virTypedParamsRemoteFree((struct _virTypedParameterRemote *) args.params.params_val,
                             args.params.params_len);
    return rv;
}

static int
remoteAdminConnectGetLoggingOutputs(virAdmConnectPtr conn,
                                    char **outputs,
                                    unsigned int flags)
{
    int rv = -1;
    remoteAdminPriv *priv = conn->privateData;
    admin_connect_get_logging_outputs_args args;
    admin_connect_get_logging_outputs_ret ret = {0};
    VIR_LOCK_GUARD lock = virObjectLockGuard(priv);

    args.flags = flags;

    if (call(conn,
             0,
             ADMIN_PROC_CONNECT_GET_LOGGING_OUTPUTS,
             (xdrproc_t) xdr_admin_connect_get_logging_outputs_args,
             (char *) &args,
             (xdrproc_t) xdr_admin_connect_get_logging_outputs_ret,
             (char *) &ret) == -1)
        return -1;

    if (outputs)
        *outputs = g_steal_pointer(&ret.outputs);

    rv = ret.noutputs;
    xdr_free((xdrproc_t) xdr_admin_connect_get_logging_outputs_ret, (char *) &ret);
    return rv;
}

static int
remoteAdminConnectGetLoggingFilters(virAdmConnectPtr conn,
                                    char **filters,
                                    unsigned int flags)
{
    int rv = -1;
    remoteAdminPriv *priv = conn->privateData;
    admin_connect_get_logging_filters_args args;
    admin_connect_get_logging_filters_ret ret = {0};
    VIR_LOCK_GUARD lock = virObjectLockGuard(priv);

    args.flags = flags;

    if (call(conn,
             0,
             ADMIN_PROC_CONNECT_GET_LOGGING_FILTERS,
             (xdrproc_t) xdr_admin_connect_get_logging_filters_args,
             (char *) &args,
             (xdrproc_t) xdr_admin_connect_get_logging_filters_ret,
             (char *) &ret) == -1)
        return -1;

    if (filters)
        *filters = ret.filters ? *ret.filters : NULL;

    rv = ret.nfilters;
    VIR_FREE(ret.filters);
    return rv;
}
