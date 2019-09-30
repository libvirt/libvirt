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
#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"
#include "viridentity.h"
#include "virlog.h"
#include "rpc/virnetdaemon.h"
#include "rpc/virnetserver.h"
#include "virstring.h"
#include "virthreadpool.h"
#include "virtypedparam.h"

#define VIR_FROM_THIS VIR_FROM_ADMIN

VIR_LOG_INIT("daemon.admin_server");

int
adminConnectListServers(virNetDaemonPtr dmn,
                        virNetServerPtr **servers,
                        unsigned int flags)
{
    int ret = -1;
    virNetServerPtr *srvs = NULL;

    virCheckFlags(0, -1);

    if ((ret = virNetDaemonGetServers(dmn, &srvs)) < 0)
        goto cleanup;

    if (servers) {
        *servers = srvs;
        srvs = NULL;
    }
 cleanup:
    if (ret > 0)
        virObjectListFreeCount(srvs, ret);
    return ret;
}

virNetServerPtr
adminConnectLookupServer(virNetDaemonPtr dmn,
                         const char *name,
                         unsigned int flags)
{
    virCheckFlags(flags, NULL);

    return virNetDaemonGetServer(dmn, name);
}

int
adminServerGetThreadPoolParameters(virNetServerPtr srv,
                                   virTypedParameterPtr *params,
                                   int *nparams,
                                   unsigned int flags)
{
    int ret = -1;
    int maxparams = 0;
    size_t minWorkers;
    size_t maxWorkers;
    size_t nWorkers;
    size_t freeWorkers;
    size_t nPrioWorkers;
    size_t jobQueueDepth;
    virTypedParameterPtr tmpparams = NULL;

    virCheckFlags(0, -1);

    if (virNetServerGetThreadPoolParameters(srv, &minWorkers, &maxWorkers,
                                            &nWorkers, &freeWorkers,
                                            &nPrioWorkers,
                                            &jobQueueDepth) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to retrieve threadpool parameters"));
        goto cleanup;
    }

    if (virTypedParamsAddUInt(&tmpparams, nparams,
                              &maxparams, VIR_THREADPOOL_WORKERS_MIN,
                              minWorkers) < 0)
        goto cleanup;

    if (virTypedParamsAddUInt(&tmpparams, nparams,
                              &maxparams, VIR_THREADPOOL_WORKERS_MAX,
                              maxWorkers) < 0)
        goto cleanup;

    if (virTypedParamsAddUInt(&tmpparams, nparams,
                              &maxparams, VIR_THREADPOOL_WORKERS_CURRENT,
                              nWorkers) < 0)
        goto cleanup;

    if (virTypedParamsAddUInt(&tmpparams, nparams,
                              &maxparams, VIR_THREADPOOL_WORKERS_FREE,
                              freeWorkers) < 0)
        goto cleanup;

    if (virTypedParamsAddUInt(&tmpparams, nparams,
                              &maxparams, VIR_THREADPOOL_WORKERS_PRIORITY,
                              nPrioWorkers) < 0)
        goto cleanup;

    if (virTypedParamsAddUInt(&tmpparams, nparams,
                              &maxparams, VIR_THREADPOOL_JOB_QUEUE_DEPTH,
                              jobQueueDepth) < 0)
        goto cleanup;

    *params = tmpparams;
    tmpparams = NULL;
    ret = 0;

 cleanup:
    virTypedParamsFree(tmpparams, *nparams);
    return ret;
}

int
adminServerSetThreadPoolParameters(virNetServerPtr srv,
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
adminServerListClients(virNetServerPtr srv,
                       virNetServerClientPtr **clients,
                       unsigned int flags)
{
    int ret = -1;
    virNetServerClientPtr *clts;

    virCheckFlags(0, -1);

    if ((ret = virNetServerGetClients(srv, &clts)) < 0)
        return -1;

    if (clients) {
        *clients = clts;
        clts = NULL;
    }

    virObjectListFreeCount(clts, ret);
    return ret;
}

virNetServerClientPtr
adminServerLookupClient(virNetServerPtr srv,
                        unsigned long long id,
                        unsigned int flags)
{
    virCheckFlags(0, NULL);

    return virNetServerGetClient(srv, id);
}

int
adminClientGetInfo(virNetServerClientPtr client,
                   virTypedParameterPtr *params,
                   int *nparams,
                   unsigned int flags)
{
    int ret = -1;
    int maxparams = 0;
    bool readonly;
    char *sock_addr = NULL;
    const char *attr = NULL;
    virTypedParameterPtr tmpparams = NULL;
    virIdentityPtr identity = NULL;
    int rc;

    virCheckFlags(0, -1);

    if (virNetServerClientGetInfo(client, &readonly,
                                  &sock_addr, &identity) < 0)
        goto cleanup;

    if (virTypedParamsAddBoolean(&tmpparams, nparams, &maxparams,
                                 VIR_CLIENT_INFO_READONLY,
                                 readonly) < 0)
        goto cleanup;

    if ((rc = virIdentityGetSASLUserName(identity, &attr)) < 0)
        goto cleanup;
    if (rc == 1 &&
        virTypedParamsAddString(&tmpparams, nparams, &maxparams,
                                VIR_CLIENT_INFO_SASL_USER_NAME,
                                attr) < 0)
        goto cleanup;

    if (!virNetServerClientIsLocal(client)) {
        if (virTypedParamsAddString(&tmpparams, nparams, &maxparams,
                                    VIR_CLIENT_INFO_SOCKET_ADDR,
                                    sock_addr) < 0)
            goto cleanup;

        if ((rc = virIdentityGetX509DName(identity, &attr)) < 0)
            goto cleanup;
        if (rc == 1 &&
            virTypedParamsAddString(&tmpparams, nparams, &maxparams,
                                    VIR_CLIENT_INFO_X509_DISTINGUISHED_NAME,
                                    attr) < 0)
            goto cleanup;
    } else {
        pid_t pid;
        uid_t uid;
        gid_t gid;
        if ((rc = virIdentityGetUNIXUserID(identity, &uid)) < 0)
            goto cleanup;
        if (rc == 1 &&
            virTypedParamsAddInt(&tmpparams, nparams, &maxparams,
                                 VIR_CLIENT_INFO_UNIX_USER_ID, uid) < 0)
            goto cleanup;

        if ((rc = virIdentityGetUserName(identity, &attr)) < 0)
            goto cleanup;
        if (rc == 1 &&
            virTypedParamsAddString(&tmpparams, nparams, &maxparams,
                                    VIR_CLIENT_INFO_UNIX_USER_NAME,
                                    attr) < 0)
            goto cleanup;

        if ((rc = virIdentityGetUNIXGroupID(identity, &gid)) < 0)
            goto cleanup;
        if (rc == 1 &&
            virTypedParamsAddInt(&tmpparams, nparams, &maxparams,
                                 VIR_CLIENT_INFO_UNIX_GROUP_ID, gid) < 0)
            goto cleanup;

        if ((rc = virIdentityGetGroupName(identity, &attr)) < 0)
            goto cleanup;
        if (rc == 1 &&
            virTypedParamsAddString(&tmpparams, nparams, &maxparams,
                                    VIR_CLIENT_INFO_UNIX_GROUP_NAME,
                                    attr) < 0)
            goto cleanup;

        if ((rc = virIdentityGetProcessID(identity, &pid)) < 0)
            goto cleanup;
        if (rc == 1 &&
            virTypedParamsAddInt(&tmpparams, nparams, &maxparams,
                                 VIR_CLIENT_INFO_UNIX_PROCESS_ID, pid) < 0)
            goto cleanup;
    }

    if ((rc = virIdentityGetSELinuxContext(identity, &attr)) < 0)
        goto cleanup;
    if (rc == 1 &&
        virTypedParamsAddString(&tmpparams, nparams, &maxparams,
                                VIR_CLIENT_INFO_SELINUX_CONTEXT, attr) < 0)
        goto cleanup;

    *params = tmpparams;
    tmpparams = NULL;
    ret = 0;

 cleanup:
    if (tmpparams)
        virTypedParamsFree(tmpparams, *nparams);
    virObjectUnref(identity);
    VIR_FREE(sock_addr);
    return ret;
}

int adminClientClose(virNetServerClientPtr client,
                     unsigned int flags)
{
    virCheckFlags(0, -1);

    virNetServerClientClose(client);
    return 0;
}

int
adminServerGetClientLimits(virNetServerPtr srv,
                           virTypedParameterPtr *params,
                           int *nparams,
                           unsigned int flags)
{
    int ret = -1;
    int maxparams = 0;
    virTypedParameterPtr tmpparams = NULL;

    virCheckFlags(0, -1);

    if (virTypedParamsAddUInt(&tmpparams, nparams, &maxparams,
                              VIR_SERVER_CLIENTS_MAX,
                              virNetServerGetMaxClients(srv)) < 0)
        goto cleanup;

    if (virTypedParamsAddUInt(&tmpparams, nparams, &maxparams,
                              VIR_SERVER_CLIENTS_CURRENT,
                              virNetServerGetCurrentClients(srv)) < 0)
        goto cleanup;

    if (virTypedParamsAddUInt(&tmpparams, nparams, &maxparams,
                              VIR_SERVER_CLIENTS_UNAUTH_MAX,
                              virNetServerGetMaxUnauthClients(srv)) < 0)
        goto cleanup;

    if (virTypedParamsAddUInt(&tmpparams, nparams, &maxparams,
                              VIR_SERVER_CLIENTS_UNAUTH_CURRENT,
                              virNetServerGetCurrentUnauthClients(srv)) < 0)
        goto cleanup;

    *params = tmpparams;
    tmpparams = NULL;
    ret = 0;

 cleanup:
    virTypedParamsFree(tmpparams, *nparams);
    return ret;
}

int
adminServerSetClientLimits(virNetServerPtr srv,
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
