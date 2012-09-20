/*
 * virnetserverservice.c: generic network RPC server service
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virnetserverservice.h"

#include "memory.h"
#include "virterror_internal.h"
#include "threads.h"

#define VIR_FROM_THIS VIR_FROM_RPC

struct _virNetServerService {
    virObject object;

    size_t nsocks;
    virNetSocketPtr *socks;

    int auth;
    bool readonly;
    size_t nrequests_client_max;

    virNetTLSContextPtr tls;

    virNetServerServiceDispatchFunc dispatchFunc;
    void *dispatchOpaque;
};


static virClassPtr virNetServerServiceClass;
static void virNetServerServiceDispose(void *obj);

static int virNetServerServiceOnceInit(void)
{
    if (!(virNetServerServiceClass = virClassNew("virNetServerService",
                                                 sizeof(virNetServerService),
                                                 virNetServerServiceDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetServerService)


static void virNetServerServiceAccept(virNetSocketPtr sock,
                                      int events ATTRIBUTE_UNUSED,
                                      void *opaque)
{
    virNetServerServicePtr svc = opaque;
    virNetSocketPtr clientsock = NULL;

    if (virNetSocketAccept(sock, &clientsock) < 0)
        goto cleanup;

    if (!clientsock) /* Connection already went away */
        goto cleanup;

    if (!svc->dispatchFunc)
        goto cleanup;

    svc->dispatchFunc(svc, clientsock, svc->dispatchOpaque);

cleanup:
    virObjectUnref(clientsock);
}


virNetServerServicePtr virNetServerServiceNewTCP(const char *nodename,
                                                 const char *service,
                                                 int auth,
                                                 bool readonly,
                                                 size_t nrequests_client_max,
                                                 virNetTLSContextPtr tls)
{
    virNetServerServicePtr svc;
    size_t i;

    if (virNetServerServiceInitialize() < 0)
        return NULL;

    if (!(svc = virObjectNew(virNetServerServiceClass)))
        return NULL;

    svc->auth = auth;
    svc->readonly = readonly;
    svc->nrequests_client_max = nrequests_client_max;
    svc->tls = virObjectRef(tls);

    if (virNetSocketNewListenTCP(nodename,
                                 service,
                                 &svc->socks,
                                 &svc->nsocks) < 0)
        goto error;

    for (i = 0 ; i < svc->nsocks ; i++) {
        if (virNetSocketListen(svc->socks[i], 0) < 0)
            goto error;

        /* IO callback is initially disabled, until we're ready
         * to deal with incoming clients */
        virObjectRef(svc);
        if (virNetSocketAddIOCallback(svc->socks[i],
                                      0,
                                      virNetServerServiceAccept,
                                      svc,
                                      virObjectFreeCallback) < 0) {
            virObjectUnref(svc);
            goto error;
        }
    }


    return svc;

error:
    virObjectUnref(svc);
    return NULL;
}


virNetServerServicePtr virNetServerServiceNewUNIX(const char *path,
                                                  mode_t mask,
                                                  gid_t grp,
                                                  int auth,
                                                  bool readonly,
                                                  size_t nrequests_client_max,
                                                  virNetTLSContextPtr tls)
{
    virNetServerServicePtr svc;
    int i;

    if (virNetServerServiceInitialize() < 0)
        return NULL;

    if (!(svc = virObjectNew(virNetServerServiceClass)))
        return NULL;

    svc->auth = auth;
    svc->readonly = readonly;
    svc->nrequests_client_max = nrequests_client_max;
    svc->tls = virObjectRef(tls);

    svc->nsocks = 1;
    if (VIR_ALLOC_N(svc->socks, svc->nsocks) < 0)
        goto no_memory;

    if (virNetSocketNewListenUNIX(path,
                                  mask,
                                  -1,
                                  grp,
                                  &svc->socks[0]) < 0)
        goto error;

    for (i = 0 ; i < svc->nsocks ; i++) {
        if (virNetSocketListen(svc->socks[i], 0) < 0)
            goto error;

        /* IO callback is initially disabled, until we're ready
         * to deal with incoming clients */
        virObjectRef(svc);
        if (virNetSocketAddIOCallback(svc->socks[i],
                                      0,
                                      virNetServerServiceAccept,
                                      svc,
                                      virObjectFreeCallback) < 0) {
            virObjectUnref(svc);
            goto error;
        }
    }


    return svc;

no_memory:
    virReportOOMError();
error:
    virObjectUnref(svc);
    return NULL;
}

virNetServerServicePtr virNetServerServiceNewFD(int fd,
                                                int auth,
                                                bool readonly,
                                                size_t nrequests_client_max,
                                                virNetTLSContextPtr tls)
{
    virNetServerServicePtr svc;
    int i;

    if (virNetServerServiceInitialize() < 0)
        return NULL;

    if (!(svc = virObjectNew(virNetServerServiceClass)))
        return NULL;

    svc->auth = auth;
    svc->readonly = readonly;
    svc->nrequests_client_max = nrequests_client_max;
    svc->tls = virObjectRef(tls);

    svc->nsocks = 1;
    if (VIR_ALLOC_N(svc->socks, svc->nsocks) < 0)
        goto no_memory;

    if (virNetSocketNewListenFD(fd,
                                &svc->socks[0]) < 0)
        goto error;

    for (i = 0 ; i < svc->nsocks ; i++) {
        /* IO callback is initially disabled, until we're ready
         * to deal with incoming clients */
        if (virNetSocketAddIOCallback(svc->socks[i],
                                      0,
                                      virNetServerServiceAccept,
                                      svc,
                                      virObjectFreeCallback) < 0)
            goto error;
    }


    return svc;

no_memory:
    virReportOOMError();
error:
    virObjectUnref(svc);
    return NULL;
}


int virNetServerServiceGetPort(virNetServerServicePtr svc)
{
    /* We're assuming if there are multiple sockets
     * for IPv4 & 6, then they are all on same port */
    return virNetSocketGetPort(svc->socks[0]);
}


int virNetServerServiceGetAuth(virNetServerServicePtr svc)
{
    return svc->auth;
}


bool virNetServerServiceIsReadonly(virNetServerServicePtr svc)
{
    return svc->readonly;
}


size_t virNetServerServiceGetMaxRequests(virNetServerServicePtr svc)
{
    return svc->nrequests_client_max;
}

virNetTLSContextPtr virNetServerServiceGetTLSContext(virNetServerServicePtr svc)
{
    return svc->tls;
}


void virNetServerServiceSetDispatcher(virNetServerServicePtr svc,
                                      virNetServerServiceDispatchFunc func,
                                      void *opaque)
{
    svc->dispatchFunc = func;
    svc->dispatchOpaque = opaque;
}


void virNetServerServiceDispose(void *obj)
{
    virNetServerServicePtr svc = obj;
    int i;

    for (i = 0 ; i < svc->nsocks ; i++)
        virObjectUnref(svc->socks[i]);
    VIR_FREE(svc->socks);

    virObjectUnref(svc->tls);
}

void virNetServerServiceToggle(virNetServerServicePtr svc,
                               bool enabled)
{
    int i;

    for (i = 0 ; i < svc->nsocks ; i++)
        virNetSocketUpdateIOCallback(svc->socks[i],
                                     enabled ?
                                     VIR_EVENT_HANDLE_READABLE :
                                     0);
}

void virNetServerServiceClose(virNetServerServicePtr svc)
{
    int i;

    if (!svc)
        return;

    for (i = 0; i < svc->nsocks; i++) {
        virNetSocketClose(svc->socks[i]);
    }
}
