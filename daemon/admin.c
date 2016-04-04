/*
 * admin.c: handlers for admin RPC method calls
 *
 * Copyright (C) 2014-2016 Red Hat, Inc.
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
 * Author: Martin Kletzander <mkletzan@redhat.com>
 */

#include <config.h>

#include "internal.h"
#include "libvirtd.h"
#include "libvirt_internal.h"

#include "admin_protocol.h"
#include "admin.h"
#include "admin_server.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virnetdaemon.h"
#include "virnetserver.h"
#include "virstring.h"
#include "virthreadjob.h"
#include "virtypedparam.h"

#define VIR_FROM_THIS VIR_FROM_ADMIN

VIR_LOG_INIT("daemon.admin");


void
remoteAdmClientFreeFunc(void *data)
{
    struct daemonAdmClientPrivate *priv = data;

    virMutexDestroy(&priv->lock);
    virObjectUnref(priv->dmn);
    VIR_FREE(priv);
}

void *
remoteAdmClientInitHook(virNetServerClientPtr client ATTRIBUTE_UNUSED,
                        void *opaque)
{
    struct daemonAdmClientPrivate *priv;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    if (virMutexInit(&priv->lock) < 0) {
        VIR_FREE(priv);
        virReportSystemError(errno, "%s", _("unable to init mutex"));
        return NULL;
    }

    /*
     * We don't necessarily need to ref this object right now as there
     * must be one ref being held throughout the life of the daemon,
     * but let's just be safe for future.
     */
    priv->dmn = virObjectRef(opaque);

    return priv;
}

/* Helpers */

static virNetServerPtr
get_nonnull_server(virNetDaemonPtr dmn, admin_nonnull_server srv)
{
    return virNetDaemonGetServer(dmn, srv.name);
}

static void
make_nonnull_server(admin_nonnull_server *srv_dst,
                    virNetServerPtr srv_src)
{
    ignore_value(VIR_STRDUP_QUIET(srv_dst->name, virNetServerGetName(srv_src)));
}

static virNetServerClientPtr
get_nonnull_client(virNetServerPtr srv, admin_nonnull_client clnt)
{
    return virNetServerGetClient(srv, clnt.id);
}

static void
make_nonnull_client(admin_nonnull_client *clt_dst,
                    virNetServerClientPtr clt_src)
{
    clt_dst->id = virNetServerClientGetID(clt_src);
    clt_dst->timestamp = virNetServerClientGetTimestamp(clt_src);
    clt_dst->transport = virNetServerClientGetTransport(clt_src);
}

/* Functions */
static int
adminDispatchConnectOpen(virNetServerPtr server ATTRIBUTE_UNUSED,
                         virNetServerClientPtr client,
                         virNetMessagePtr msg ATTRIBUTE_UNUSED,
                         virNetMessageErrorPtr rerr,
                         struct admin_connect_open_args *args)
{
    unsigned int flags;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);
    int ret = -1;

    VIR_DEBUG("priv=%p dmn=%p", priv, priv->dmn);
    virMutexLock(&priv->lock);

    flags = args->flags;
    virCheckFlagsGoto(0, cleanup);

    ret = 0;
 cleanup:
    if (ret < 0)
        virNetMessageSaveError(rerr);
    virMutexUnlock(&priv->lock);
    return ret;
}

static int
adminDispatchConnectClose(virNetServerPtr server ATTRIBUTE_UNUSED,
                          virNetServerClientPtr client,
                          virNetMessagePtr msg ATTRIBUTE_UNUSED,
                          virNetMessageErrorPtr rerr ATTRIBUTE_UNUSED)
{
    virNetServerClientDelayedClose(client);
    return 0;
}

static int
adminConnectGetLibVersion(virNetDaemonPtr dmn ATTRIBUTE_UNUSED,
                          unsigned long long *libVer)
{
    if (libVer)
        *libVer = LIBVIR_VERSION_NUMBER;
    return 0;
}

static int
adminDispatchServerGetThreadpoolParameters(virNetServerPtr server ATTRIBUTE_UNUSED,
                                           virNetServerClientPtr client,
                                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                           virNetMessageErrorPtr rerr,
                                           struct admin_server_get_threadpool_parameters_args *args,
                                           struct admin_server_get_threadpool_parameters_ret *ret)
{
    int rv = -1;
    virNetServerPtr srv = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!(srv = virNetDaemonGetServer(priv->dmn, args->srv.name)))
        goto cleanup;

    if (adminServerGetThreadPoolParameters(srv, &params, &nparams,
                                           args->flags) < 0)
        goto cleanup;

    if (nparams > ADMIN_SERVER_THREADPOOL_PARAMETERS_MAX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Number of threadpool parameters %d exceeds max "
                         "allowed limit: %d"), nparams,
                       ADMIN_SERVER_THREADPOOL_PARAMETERS_MAX);
        goto cleanup;
    }

    if (virTypedParamsSerialize(params, nparams,
                                (virTypedParameterRemotePtr *) &ret->params.params_val,
                                &ret->params.params_len, 0) < 0)
        goto cleanup;

    rv = 0;
 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);

    virTypedParamsFree(params, nparams);
    virObjectUnref(srv);
    return rv;
}

static int
adminDispatchServerSetThreadpoolParameters(virNetServerPtr server ATTRIBUTE_UNUSED,
                                           virNetServerClientPtr client,
                                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                           virNetMessageErrorPtr rerr,
                                           struct admin_server_set_threadpool_parameters_args *args)
{
    int rv = -1;
    virNetServerPtr srv = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!(srv = virNetDaemonGetServer(priv->dmn, args->srv.name))) {
        virReportError(VIR_ERR_NO_SERVER,
                       _("no server with matching name '%s' found"),
                       args->srv.name);
        goto cleanup;
    }

    if (virTypedParamsDeserialize((virTypedParameterRemotePtr) args->params.params_val,
                                  args->params.params_len,
                                  ADMIN_SERVER_THREADPOOL_PARAMETERS_MAX,
                                  &params,
                                  &nparams) < 0)
        goto cleanup;


    if (adminServerSetThreadPoolParameters(srv, params,
                                           nparams, args->flags) < 0)
        goto cleanup;

    rv = 0;
 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);

    virTypedParamsFree(params, nparams);
    virObjectUnref(srv);
    return rv;
}

static int
adminDispatchClientGetInfo(virNetServerPtr server ATTRIBUTE_UNUSED,
                           virNetServerClientPtr client,
                           virNetMessagePtr msg ATTRIBUTE_UNUSED,
                           virNetMessageErrorPtr rerr,
                           struct admin_client_get_info_args *args,
                           struct admin_client_get_info_ret *ret)
{
    int rv = -1;
    virNetServerPtr srv = NULL;
    virNetServerClientPtr clnt = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!(srv = virNetDaemonGetServer(priv->dmn, args->clnt.srv.name))) {
        virReportError(VIR_ERR_NO_SERVER,
                       _("no server with matching name '%s' found"),
                       args->clnt.srv.name);
        goto cleanup;
    }

    if (!(clnt = virNetServerGetClient(srv, args->clnt.id))) {
        virReportError(VIR_ERR_NO_CLIENT,
                       _("no client with matching id '%llu' found"),
                       (unsigned long long) args->clnt.id);
        goto cleanup;
    }

    if (adminClientGetInfo(clnt, &params, &nparams, args->flags) < 0)
        goto cleanup;

    if (nparams > ADMIN_CLIENT_INFO_PARAMETERS_MAX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Number of client info parameters %d exceeds max "
                         "allowed limit: %d"), nparams,
                       ADMIN_CLIENT_INFO_PARAMETERS_MAX);
        goto cleanup;
    }

    if (virTypedParamsSerialize(params, nparams,
                                (virTypedParameterRemotePtr *) &ret->params.params_val,
                                &ret->params.params_len,
                                VIR_TYPED_PARAM_STRING_OKAY) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);

    virTypedParamsFree(params, nparams);
    virObjectUnref(clnt);
    virObjectUnref(srv);
    return rv;
}

static int
adminDispatchServerGetClientLimits(virNetServerPtr server ATTRIBUTE_UNUSED,
                                   virNetServerClientPtr client,
                                   virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                   virNetMessageErrorPtr rerr ATTRIBUTE_UNUSED,
                                   admin_server_get_client_limits_args *args,
                                   admin_server_get_client_limits_ret *ret)
{
    int rv = -1;
    virNetServerPtr srv = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!(srv = virNetDaemonGetServer(priv->dmn, args->srv.name)))
        goto cleanup;

    if (adminServerGetClientLimits(srv, &params, &nparams, args->flags) < 0)
        goto cleanup;

    if (nparams > ADMIN_SERVER_CLIENT_LIMITS_MAX) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Number of client processing parameters %d exceeds "
                         "max allowed limit: %d"), nparams,
                       ADMIN_SERVER_CLIENT_LIMITS_MAX);
        goto cleanup;
    }

    if (virTypedParamsSerialize(params, nparams,
                                (virTypedParameterRemotePtr *) &ret->params.params_val,
                                &ret->params.params_len, 0) < 0)
        goto cleanup;

    rv = 0;
 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);

    virTypedParamsFree(params, nparams);
    virObjectUnref(srv);
    return rv;
}

static int
adminDispatchServerSetClientLimits(virNetServerPtr server ATTRIBUTE_UNUSED,
                                   virNetServerClientPtr client,
                                   virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                   virNetMessageErrorPtr rerr ATTRIBUTE_UNUSED,
                                   admin_server_set_client_limits_args *args)
{
    int rv = -1;
    virNetServerPtr srv = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!(srv = virNetDaemonGetServer(priv->dmn, args->srv.name))) {
        virReportError(VIR_ERR_NO_SERVER,
                       _("no server with matching name '%s' found"),
                       args->srv.name);
        goto cleanup;
    }

    if (virTypedParamsDeserialize((virTypedParameterRemotePtr) args->params.params_val,
        args->params.params_len,
        ADMIN_SERVER_CLIENT_LIMITS_MAX, &params, &nparams) < 0)
        goto cleanup;

    if (adminServerSetClientLimits(srv, params, nparams, args->flags) < 0)
        goto cleanup;

    rv = 0;
 cleanup:
    if (rv < 0)
        virNetMessageSaveError(rerr);
    virTypedParamsFree(params, nparams);
    virObjectUnref(srv);
    return rv;
}
#include "admin_dispatch.h"
