/*
 * admin_server.c: admin methods to manage daemons and clients
 *
 * Copyright (C) 2016 Red Hat, Inc.
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

#include "admin_server.h"
#include "virerror.h"
#include "viridentity.h"
#include "virlog.h"
#include "rpc/virnetdaemon.h"
#include "rpc/virnetserver.h"
#include "virtypedparam.h"

#define VIR_FROM_THIS VIR_FROM_ADMIN

VIR_LOG_INIT("daemon.admin_server");

int
adminConnectListServers(virNetDaemon *dmn,
                        virNetServer ***servers,
                        unsigned int flags)
{
    int ret = -1;
    virNetServer **srvs = NULL;

    virCheckFlags(0, -1);

    if ((ret = virNetDaemonGetServers(dmn, &srvs)) < 0)
        return ret;

    if (servers) {
        *servers = g_steal_pointer(&srvs);
    }

    if (ret > 0)
        virObjectListFreeCount(srvs, ret);
    return ret;
}

virNetServer *
adminConnectLookupServer(virNetDaemon *dmn,
                         const char *name,
                         unsigned int flags)
{
    virCheckFlags(flags, NULL);

    return virNetDaemonGetServer(dmn, name);
}

int
adminServerGetThreadPoolParameters(virNetServer *srv,
                                   virTypedParameterPtr *params,
                                   int *nparams,
                                   unsigned int flags)
{
    size_t minWorkers;
    size_t maxWorkers;
    size_t nWorkers;
    size_t freeWorkers;
    size_t nPrioWorkers;
    size_t jobQueueDepth;
    g_autoptr(virTypedParamList) paramlist = virTypedParamListNew();

    virCheckFlags(0, -1);

    if (virNetServerGetThreadPoolParameters(srv, &minWorkers, &maxWorkers,
                                            &nWorkers, &freeWorkers,
                                            &nPrioWorkers,
                                            &jobQueueDepth) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to retrieve threadpool parameters"));
        return -1;
    }

    virTypedParamListAddUInt(paramlist, minWorkers, VIR_THREADPOOL_WORKERS_MIN);
    virTypedParamListAddUInt(paramlist, maxWorkers, VIR_THREADPOOL_WORKERS_MAX);
    virTypedParamListAddUInt(paramlist, nWorkers, VIR_THREADPOOL_WORKERS_CURRENT);
    virTypedParamListAddUInt(paramlist, freeWorkers, VIR_THREADPOOL_WORKERS_FREE);
    virTypedParamListAddUInt(paramlist, nPrioWorkers, VIR_THREADPOOL_WORKERS_PRIORITY);
    virTypedParamListAddUInt(paramlist, jobQueueDepth, VIR_THREADPOOL_JOB_QUEUE_DEPTH);

    if (virTypedParamListSteal(paramlist, params, nparams) < 0)
        return -1;

    return 0;
}

int
adminServerSetThreadPoolParameters(virNetServer *srv,
                                   virTypedParameterPtr params,
                                   int nparams,
                                   unsigned int flags)
{
    long long int minWorkers = -1;
    long long int maxWorkers = -1;
    long long int prioWorkers = -1;
    virTypedParameterPtr param = NULL;

    virCheckFlags(0, -1);

    if (virTypedParamsValidate(params, nparams,
                               VIR_THREADPOOL_WORKERS_MIN,
                               VIR_TYPED_PARAM_UINT,
                               VIR_THREADPOOL_WORKERS_MAX,
                               VIR_TYPED_PARAM_UINT,
                               VIR_THREADPOOL_WORKERS_PRIORITY,
                               VIR_TYPED_PARAM_UINT,
                               NULL) < 0)
        return -1;

    if ((param = virTypedParamsGet(params, nparams,
                                   VIR_THREADPOOL_WORKERS_MIN)))
        minWorkers = param->value.ui;

    if ((param = virTypedParamsGet(params, nparams,
                                   VIR_THREADPOOL_WORKERS_MAX)))
        maxWorkers = param->value.ui;

    if ((param = virTypedParamsGet(params, nparams,
                                   VIR_THREADPOOL_WORKERS_PRIORITY)))
        prioWorkers = param->value.ui;

    if (virNetServerSetThreadPoolParameters(srv, minWorkers,
                                            maxWorkers, prioWorkers) < 0)
        return -1;

    return 0;
}

int
adminServerListClients(virNetServer *srv,
                       virNetServerClient ***clients,
                       unsigned int flags)
{
    int ret = -1;
    virNetServerClient **clts;

    virCheckFlags(0, -1);

    if ((ret = virNetServerGetClients(srv, &clts)) < 0)
        return -1;

    if (clients) {
        *clients = g_steal_pointer(&clts);
    }

    virObjectListFreeCount(clts, ret);
    return ret;
}

virNetServerClient *
adminServerLookupClient(virNetServer *srv,
                        unsigned long long id,
                        unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virNetServerGetClient(srv, id);
}

int
adminClientGetInfo(virNetServerClient *client,
                   virTypedParameterPtr *params,
                   int *nparams,
                   unsigned int flags)
{
    bool readonly;
    g_autofree char *sock_addr = NULL;
    const char *attr = NULL;
    g_autoptr(virTypedParamList) paramlist = virTypedParamListNew();
    g_autoptr(virIdentity) identity = NULL;
    int rc;

    virCheckFlags(0, -1);

    if (virNetServerClientGetInfo(client, &readonly,
                                  &sock_addr, &identity) < 0)
        return -1;

    virTypedParamListAddBoolean(paramlist, readonly, VIR_CLIENT_INFO_READONLY);

    if ((rc = virIdentityGetSASLUserName(identity, &attr)) < 0)
        return -1;
    if (rc == 1)
        virTypedParamListAddString(paramlist, attr, VIR_CLIENT_INFO_SASL_USER_NAME);

    if (!virNetServerClientIsLocal(client)) {
        virTypedParamListAddString(paramlist, sock_addr, VIR_CLIENT_INFO_SOCKET_ADDR);

        if ((rc = virIdentityGetX509DName(identity, &attr)) < 0)
            return -1;
        if (rc == 1)
            virTypedParamListAddString(paramlist, attr, VIR_CLIENT_INFO_X509_DISTINGUISHED_NAME);
    } else {
        pid_t pid;
        uid_t uid;
        gid_t gid;
        if ((rc = virIdentityGetUNIXUserID(identity, &uid)) < 0)
            return -1;
        if (rc == 1)
            virTypedParamListAddInt(paramlist, uid, VIR_CLIENT_INFO_UNIX_USER_ID);

        if ((rc = virIdentityGetUserName(identity, &attr)) < 0)
            return -1;
        if (rc == 1)
            virTypedParamListAddString(paramlist, attr, VIR_CLIENT_INFO_UNIX_USER_NAME);

        if ((rc = virIdentityGetUNIXGroupID(identity, &gid)) < 0)
            return -1;
        if (rc == 1)
            virTypedParamListAddInt(paramlist, gid, VIR_CLIENT_INFO_UNIX_GROUP_ID);

        if ((rc = virIdentityGetGroupName(identity, &attr)) < 0)
            return -1;
        if (rc == 1)
            virTypedParamListAddString(paramlist, attr, VIR_CLIENT_INFO_UNIX_GROUP_NAME);

        if ((rc = virIdentityGetProcessID(identity, &pid)) < 0)
            return -1;
        if (rc == 1)
            virTypedParamListAddInt(paramlist, pid, VIR_CLIENT_INFO_UNIX_PROCESS_ID);
    }

    if ((rc = virIdentityGetSELinuxContext(identity, &attr)) < 0)
        return -1;
    if (rc == 1)
        virTypedParamListAddString(paramlist, attr, VIR_CLIENT_INFO_SELINUX_CONTEXT);

    if (virTypedParamListSteal(paramlist, params, nparams) < 0)
        return -1;

    return 0;
}

int adminClientClose(virNetServerClient *client,
                     unsigned int flags)
{
    virCheckFlags(0, -1);

    virNetServerClientClose(client);
    return 0;
}

int
adminServerGetClientLimits(virNetServer *srv,
                           virTypedParameterPtr *params,
                           int *nparams,
                           unsigned int flags)
{
    g_autoptr(virTypedParamList) paramlist = virTypedParamListNew();

    virCheckFlags(0, -1);

    virTypedParamListAddUInt(paramlist, virNetServerGetMaxClients(srv), VIR_SERVER_CLIENTS_MAX);
    virTypedParamListAddUInt(paramlist, virNetServerGetCurrentClients(srv), VIR_SERVER_CLIENTS_CURRENT);
    virTypedParamListAddUInt(paramlist, virNetServerGetMaxUnauthClients(srv), VIR_SERVER_CLIENTS_UNAUTH_MAX);
    virTypedParamListAddUInt(paramlist, virNetServerGetCurrentUnauthClients(srv), VIR_SERVER_CLIENTS_UNAUTH_CURRENT);

    if (virTypedParamListSteal(paramlist, params, nparams) < 0)
        return -1;

    return 0;
}

int
adminServerSetClientLimits(virNetServer *srv,
                           virTypedParameterPtr params,
                           int nparams,
                           unsigned int flags)
{
    long long int maxClients = -1;
    long long int maxClientsUnauth = -1;
    virTypedParameterPtr param = NULL;

    virCheckFlags(0, -1);

    if (virTypedParamsValidate(params, nparams,
                               VIR_SERVER_CLIENTS_MAX,
                               VIR_TYPED_PARAM_UINT,
                               VIR_SERVER_CLIENTS_UNAUTH_MAX,
                               VIR_TYPED_PARAM_UINT,
                               NULL) < 0)
        return -1;

    if ((param = virTypedParamsGet(params, nparams,
                                   VIR_SERVER_CLIENTS_MAX)))
        maxClients = param->value.ui;

    if ((param = virTypedParamsGet(params, nparams,
                                   VIR_SERVER_CLIENTS_UNAUTH_MAX)))
        maxClientsUnauth = param->value.ui;

    if (virNetServerSetClientLimits(srv, maxClients,
                                    maxClientsUnauth) < 0)
        return -1;

    return 0;
}

int
adminServerUpdateTlsFiles(virNetServer *srv,
                          unsigned int flags)
{
    virCheckFlags(0, -1);

    return virNetServerUpdateTlsFiles(srv);
}
