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

#include "admin_server_dispatch.h"
#include "admin_server.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "rpc/virnetdaemon.h"
#include "rpc/virnetserver.h"
#include "virthreadjob.h"
#include "virtypedparam.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_ADMIN

VIR_LOG_INIT("daemon.admin");

typedef struct daemonAdmClientPrivate daemonAdmClientPrivate;
/* Separate private data for admin connection */
struct daemonAdmClientPrivate {
    /* Just a placeholder, not that there is anything to be locked */
    virMutex lock;

    virNetDaemon *dmn;
};

void
remoteAdmClientFree(void *data)
{
    struct daemonAdmClientPrivate *priv = data;

    virMutexDestroy(&priv->lock);
    virObjectUnref(priv->dmn);
    g_free(priv);
}

void *
remoteAdmClientNew(virNetServerClient *client G_GNUC_UNUSED,
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
        virReportRestrictedError(_("Disallowing client %1$lld with uid %2$lld"),
                                 (long long)clientpid,
                                 (long long)clientuid);
        return NULL;
    }

    priv = g_new0(struct daemonAdmClientPrivate, 1);

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

void *remoteAdmClientNewPostExecRestart(virNetServerClient *client,
                                        virJSONValue *object G_GNUC_UNUSED,
                                        void *opaque)
{
    return remoteAdmClientNew(client, opaque);
}

virJSONValue *remoteAdmClientPreExecRestart(virNetServerClient *client G_GNUC_UNUSED,
                                            void *data G_GNUC_UNUSED)
{
    virJSONValue *object = virJSONValueNewObject();

    /* No content to add at this time - just need empty object */

    return object;
}


/* Helpers */

static virNetServer *
get_nonnull_server(virNetDaemon *dmn, admin_nonnull_server srv)
{
    return virNetDaemonGetServer(dmn, srv.name);
}

static void
make_nonnull_server(admin_nonnull_server *srv_dst,
                    virNetServer *srv_src)
{
    srv_dst->name = g_strdup(virNetServerGetName(srv_src));
}

static virNetServerClient *
get_nonnull_client(virNetServer *srv, admin_nonnull_client clnt)
{
    return virNetServerGetClient(srv, clnt.id);
}

static void
make_nonnull_client(admin_nonnull_client *clt_dst,
                    virNetServerClient *clt_src)
{
    clt_dst->id = virNetServerClientGetID(clt_src);
    clt_dst->timestamp = virNetServerClientGetTimestamp(clt_src);
    clt_dst->transport = virNetServerClientGetTransport(clt_src);
}

/* Functions */
static int
adminDispatchConnectOpen(virNetServer *server G_GNUC_UNUSED,
                         virNetServerClient *client,
                         virNetMessage *msg G_GNUC_UNUSED,
                         struct virNetMessageError *rerr,
                         struct admin_connect_open_args *args)
{
    unsigned int flags;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);
    int ret = -1;
    VIR_LOCK_GUARD lock = virLockGuardLock(&priv->lock);

    VIR_DEBUG("priv=%p dmn=%p", priv, priv->dmn);

    flags = args->flags;
    virCheckFlagsGoto(0, cleanup);

    ret = 0;
 cleanup:
    if (ret < 0)
        virNetMessageSaveError(rerr);
    return ret;
}

static int
adminDispatchConnectClose(virNetServer *server G_GNUC_UNUSED,
                          virNetServerClient *client,
                          virNetMessage *msg G_GNUC_UNUSED,
                          struct virNetMessageError *rerr G_GNUC_UNUSED)
{
    virNetServerClientDelayedClose(client);
    return 0;
}

static int
adminConnectGetLibVersion(virNetDaemon *dmn G_GNUC_UNUSED,
                          unsigned long long *libVer)
{
    if (libVer)
        *libVer = LIBVIR_VERSION_NUMBER;
    return 0;
}

static virNetDaemon *
adminGetConn(virNetServerClient *client)
{
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    return priv->dmn;
}

static int
adminDispatchServerGetThreadpoolParameters(virNetServer *server G_GNUC_UNUSED,
                                           virNetServerClient *client,
                                           virNetMessage *msg G_GNUC_UNUSED,
                                           struct virNetMessageError *rerr,
                                           struct admin_server_get_threadpool_parameters_args *args,
                                           struct admin_server_get_threadpool_parameters_ret *ret)
{
    int rv = -1;
    virNetServer *srv = NULL;
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
                                (struct _virTypedParameterRemote **) &ret->params.params_val,
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
adminDispatchServerSetThreadpoolParameters(virNetServer *server G_GNUC_UNUSED,
                                           virNetServerClient *client,
                                           virNetMessage *msg G_GNUC_UNUSED,
                                           struct virNetMessageError *rerr,
                                           struct admin_server_set_threadpool_parameters_args *args)
{
    int rv = -1;
    virNetServer *srv = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!(srv = virNetDaemonGetServer(priv->dmn, args->srv.name))) {
        virReportError(VIR_ERR_NO_SERVER,
                       _("no server with matching name '%1$s' found"),
                       args->srv.name);
        goto cleanup;
    }

    if (virTypedParamsDeserialize((struct _virTypedParameterRemote *) args->params.params_val,
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
adminDispatchClientGetInfo(virNetServer *server G_GNUC_UNUSED,
                           virNetServerClient *client,
                           virNetMessage *msg G_GNUC_UNUSED,
                           struct virNetMessageError *rerr,
                           struct admin_client_get_info_args *args,
                           struct admin_client_get_info_ret *ret)
{
    int rv = -1;
    virNetServer *srv = NULL;
    virNetServerClient *clnt = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!(srv = virNetDaemonGetServer(priv->dmn, args->clnt.srv.name))) {
        virReportError(VIR_ERR_NO_SERVER,
                       _("no server with matching name '%1$s' found"),
                       args->clnt.srv.name);
        goto cleanup;
    }

    if (!(clnt = virNetServerGetClient(srv, args->clnt.id))) {
        virReportError(VIR_ERR_NO_CLIENT,
                       _("no client with matching id '%1$llu' found"),
                       (unsigned long long) args->clnt.id);
        goto cleanup;
    }

    if (adminClientGetInfo(clnt, &params, &nparams, args->flags) < 0)
        goto cleanup;

    if (virTypedParamsSerialize(params, nparams,
                                ADMIN_CLIENT_INFO_PARAMETERS_MAX,
                                (struct _virTypedParameterRemote **) &ret->params.params_val,
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
adminDispatchServerGetClientLimits(virNetServer *server G_GNUC_UNUSED,
                                   virNetServerClient *client,
                                   virNetMessage *msg G_GNUC_UNUSED,
                                   struct virNetMessageError *rerr G_GNUC_UNUSED,
                                   admin_server_get_client_limits_args *args,
                                   admin_server_get_client_limits_ret *ret)
{
    int rv = -1;
    virNetServer *srv = NULL;
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
                                (struct _virTypedParameterRemote **) &ret->params.params_val,
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
adminDispatchServerSetClientLimits(virNetServer *server G_GNUC_UNUSED,
                                   virNetServerClient *client,
                                   virNetMessage *msg G_GNUC_UNUSED,
                                   struct virNetMessageError *rerr G_GNUC_UNUSED,
                                   admin_server_set_client_limits_args *args)
{
    int rv = -1;
    virNetServer *srv = NULL;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    struct daemonAdmClientPrivate *priv =
        virNetServerClientGetPrivateData(client);

    if (!(srv = virNetDaemonGetServer(priv->dmn, args->srv.name))) {
        virReportError(VIR_ERR_NO_SERVER,
                       _("no server with matching name '%1$s' found"),
                       args->srv.name);
        goto cleanup;
    }

    if (virTypedParamsDeserialize((struct _virTypedParameterRemote *) args->params.params_val,
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
adminConnectSetLoggingOutputs(virNetDaemon *dmn G_GNUC_UNUSED,
                              const char *outputs,
                              unsigned int flags)
{
    virCheckFlags(0, -1);

    return virLogSetOutputs(outputs);
}

static int
adminConnectSetLoggingFilters(virNetDaemon *dmn G_GNUC_UNUSED,
                              const char *filters,
                              unsigned int flags)
{
    virCheckFlags(0, -1);

    return virLogSetFilters(filters);
}


static int
adminConnectSetDaemonTimeout(virNetDaemon *dmn,
                             unsigned int timeout,
                             unsigned int flags)
{
    virCheckFlags(0, -1);

    return virNetDaemonAutoShutdown(dmn, timeout);
}


static int
adminDispatchConnectGetLoggingOutputs(virNetServer *server G_GNUC_UNUSED,
                                      virNetServerClient *client G_GNUC_UNUSED,
                                      virNetMessage *msg G_GNUC_UNUSED,
                                      struct virNetMessageError *rerr,
                                      admin_connect_get_logging_outputs_args *args,
                                      admin_connect_get_logging_outputs_ret *ret)
{
    char *outputs = NULL;
    int noutputs = 0;

    if ((noutputs = adminConnectGetLoggingOutputs(&outputs, args->flags)) < 0) {
        virNetMessageSaveError(rerr);
        return -1;
    }

    ret->outputs = g_steal_pointer(&outputs);
    ret->noutputs = noutputs;

    return 0;
}

static int
adminDispatchConnectGetLoggingFilters(virNetServer *server G_GNUC_UNUSED,
                                      virNetServerClient *client G_GNUC_UNUSED,
                                      virNetMessage *msg G_GNUC_UNUSED,
                                      struct virNetMessageError *rerr,
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
        ret_filters = g_new0(char *, 1);

        *ret_filters = filters;
        ret->filters = ret_filters;
    }
    ret->nfilters = nfilters;

    return 0;
}
#include "admin_server_dispatch_stubs.h"
