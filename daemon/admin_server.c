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
 *
 * Authors: Erik Skultety <eskultet@redhat.com>
 *          Martin Kletzander <mkletzan@redhat.com>
 */

#include <config.h>

#include "admin_server.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virnetdaemon.h"
#include "virnetserver.h"
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
