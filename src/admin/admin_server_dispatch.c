/*
 * admin_server_dispatch.c: handlers for admin RPC method calls
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
 */

#include <config.h>

#include "internal.h"
#include "libvirt_internal.h"

#include "admin_server_dispatch.h"
#include "admin_server.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "rpc/virnetdaemon.h"
#include "rpc/virnetserver.h"
#include "virstring.h"
#include "virthreadjob.h"
#include "virtypedparam.h"

#define VIR_FROM_THIS VIR_FROM_ADMIN

VIR_LOG_INIT("daemon.admin");

typedef struct daemonAdmClientPrivate daemonAdmClientPrivate;
typedef daemonAdmClientPrivate *daemonAdmClientPrivatePtr;
/* Separate private data for admin connection */
struct daemonAdmClientPrivate {
    /* Just a placeholder, not that there is anything to be locked */
    virMutex lock;

    virNetDaemonPtr dmn;
};

void
remoteAdmClientFree(void *data)
{
    struct daemonAdmClientPrivate *priv = data;

    virMutexDestroy(&priv->lock);
    virObjectUnref(priv->dmn);
    VIR_FREE(priv);
}

void *
remoteAdmClientNew(virNetServerClientPtr client ATTRIBUTE_UNUSED,
                   void *opaque)
{
    struct daemonAdmClientPrivate *priv;
    uid_t clientuid;
    gid_t clientgid;
    pid_t clientpid;
    unsigned long long timestamp;

    if (virNetServerClientGetUNIXIdentity(client,
                                          &clientuid,
                                          &clientgid,
                                          &clientpid,
                                          &timestamp) < 0)
        return NULL;

    VIR_DEBUG("New client pid %lld uid %lld",
              (long long)clientpid,
              (long long)clientuid);

    if (geteuid() != clientuid) {
        virReportRestrictedError(_("Disallowing client %lld with uid %lld"),
                                 (long long)clientpid,
                                 (long long)clientuid);
        return NULL;
    }

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

void *remoteAdmClientNewPostExecRestart(virNetServerClientPtr client,
                                        virJSONValuePtr object ATTRIBUTE_UNUSED,
                                        void *opaque)
{
    return remoteAdmClientNew(client, opaque);
}

virJSONValuePtr remoteAdmClientPreExecRestart(virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                              void *data ATTRIBUTE_UNUSED)
{
    virJSONValuePtr object = virJSONValueNewObject();

    if (!object)
        return NULL;

    /* No content to add at this time - just need empty object */

    return object;
}


/* Helpers */

static virNetServerPtr
get_nonnull_server(virNetDaemonPtr dmn, admin_nonnull_server srv)
{
    return virNetDaemonGetServer(dmn, srv.name);
}

static int G_GNUC_WARN_UNUSED_RESULT
make_nonnull_server(admin_nonnull_server *srv_dst,
                    virNetServerPtr srv_src)
{
    if (VIR_STRDUP(srv_dst->name, virNetServerGetName(srv_src)) < 0)
        return -1;
    return 0;
}

static virNetServerClientPtr
get_nonnull_client(virNetServerPtr srv, admin_nonnull_client clnt)
{
    return virNetServerGetClient(srv, clnt.id);
}

static int
make_nonnull_client(admin_nonnull_client *clt_dst,
                    virNetServerClientPtr clt_src)
{
    clt_dst->id = virNetServerClientGetID(clt_src);
    clt_dst->timestamp = virNetServerClientGetTimestamp(clt_src);
    clt_dst->transport = virNetServerClientGetTransport(clt_src);
    return 0;
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

static virNetDaemonPtr
adminGetConn(virNetServerClientPtr client)
{
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    return priv->dmn;
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

    if (virTypedParamsSerialize(params, nparams,
                                ADMIN_SERVER_THREADPOOL_PARAMETERS_MAX,
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

    if (virTypedParamsSerialize(params, nparams,
                                ADMIN_CLIENT_INFO_PARAMETERS_MAX,
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

    if (virTypedParamsSerialize(params, nparams,
                                ADMIN_SERVER_CLIENT_LIMITS_MAX,
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

/* Returns the number of outputs stored in @outputs */
static int
adminConnectGetLoggingOutputs(char **outputs, unsigned int flags)
{
    char *tmp = NULL;

    virCheckFlags(0, -1);

    if (!(tmp = virLogGetOutputs()))
        return -1;

    *outputs = tmp;
    return virLogGetNbOutputs();
}

/* Returns the number of defined filters or -1 in case of an error */
static int
adminConnectGetLoggingFilters(char **filters, unsigned int flags)
{
    char *tmp = NULL;
    int ret = 0;

    virCheckFlags(0, -1);

    if ((ret = virLogGetNbFilters()) > 0 && !(tmp = virLogGetFilters()))
        return -1;

    *filters = tmp;
    return ret;
}

static int
adminConnectSetLoggingOutputs(virNetDaemonPtr dmn ATTRIBUTE_UNUSED,
                              const char *outputs,
                              unsigned int flags)
{
    virCheckFlags(0, -1);

    return virLogSetOutputs(outputs);
}

static int
adminConnectSetLoggingFilters(virNetDaemonPtr dmn ATTRIBUTE_UNUSED,
                              const char *filters,
                              unsigned int flags)
{
    virCheckFlags(0, -1);

    return virLogSetFilters(filters);
}

static int
adminDispatchConnectGetLoggingOutputs(virNetServerPtr server ATTRIBUTE_UNUSED,
                                      virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                      virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                      virNetMessageErrorPtr rerr,
                                      admin_connect_get_logging_outputs_args *args,
                                      admin_connect_get_logging_outputs_ret *ret)
{
    char *outputs = NULL;
    int noutputs = 0;

    if ((noutputs = adminConnectGetLoggingOutputs(&outputs, args->flags)) < 0) {
        virNetMessageSaveError(rerr);
        return -1;
    }

    VIR_STEAL_PTR(ret->outputs, outputs);
    ret->noutputs = noutputs;

    return 0;
}

static int
adminDispatchConnectGetLoggingFilters(virNetServerPtr server ATTRIBUTE_UNUSED,
                                      virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                      virNetMessagePtr msg ATTRIBUTE_UNUSED,
                                      virNetMessageErrorPtr rerr,
                                      admin_connect_get_logging_filters_args *args,
                                      admin_connect_get_logging_filters_ret *ret)
{
    char *filters = NULL;
    int nfilters = 0;

    if ((nfilters = adminConnectGetLoggingFilters(&filters, args->flags)) < 0) {
        virNetMessageSaveError(rerr);
        return -1;
    }

    if (nfilters == 0) {
        ret->filters = NULL;
    } else {
        char **ret_filters = NULL;
        if (VIR_ALLOC(ret_filters) < 0)
            return -1;

        *ret_filters = filters;
        ret->filters = ret_filters;
    }
    ret->nfilters = nfilters;

    return 0;
}
#include "admin_server_dispatch_stubs.h"
