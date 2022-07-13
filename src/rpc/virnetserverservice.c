/*
 * virnetserverservice.c: generic network RPC server service
 *
 * Copyright (C) 2006-2012, 2014 Red Hat, Inc.
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
 */

#include <config.h>

#include "virnetserverservice.h"

#include <unistd.h>

#include "viralloc.h"
#include "virerror.h"
#include "virthread.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netserverservice");

struct _virNetServerService {
    virObject parent;

    size_t nsocks;
    virNetSocket **socks;

    int auth;
    bool readonly;
    size_t nrequests_client_max;
    int timer;
    bool timerActive;

    virNetTLSContext *tls;

    virNetServerServiceDispatchFunc dispatchFunc;
    void *dispatchOpaque;
};


static virClass *virNetServerServiceClass;
static void virNetServerServiceDispose(void *obj);

static int virNetServerServiceOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetServerService, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetServerService);


static void virNetServerServiceAccept(virNetSocket *sock,
                                      int events G_GNUC_UNUSED,
                                      void *opaque)
{
    virNetServerService *svc = opaque;
    virNetSocket *clientsock = NULL;
    int rc;

    rc = virNetSocketAccept(sock, &clientsock);
    if (rc < 0) {
        if (rc == -2) {
            /* Could not accept new client due to EMFILE. Suspend listening on
             * the socket and set up a timer to enable it later. Hopefully,
             * some FDs will be closed meanwhile. */
            VIR_DEBUG("Temporarily suspending listening on svc=%p because accept() on sock=%p failed (errno=%d)",
                      svc, sock, errno);

            virNetServerServiceToggle(svc, false);

            svc->timerActive = true;
            /* Retry in 5 seconds. */
            virEventUpdateTimeout(svc->timer, 5 * 1000);
        }
        goto cleanup;
    }

    if (!clientsock) /* Connection already went away */
        goto cleanup;

    if (!svc->dispatchFunc)
        goto cleanup;

    svc->dispatchFunc(svc, clientsock, svc->dispatchOpaque);

 cleanup:
    virObjectUnref(clientsock);
}


static void
virNetServerServiceTimerFunc(int timer,
                             void *opaque)
{
    virNetServerService *svc = opaque;

    VIR_DEBUG("Resuming listening on service svc=%p after previous suspend", svc);

    virNetServerServiceToggle(svc, true);

    virEventUpdateTimeout(timer, -1);
    svc->timerActive = false;
}


static virNetServerService *
virNetServerServiceNewSocket(virNetSocket **socks,
                             size_t nsocks,
                             int auth,
                             virNetTLSContext *tls,
                             bool readonly,
                             size_t max_queued_clients,
                             size_t nrequests_client_max)
{
    virNetServerService *svc;
    size_t i;

    if (virNetServerServiceInitialize() < 0)
        return NULL;

    if (!(svc = virObjectNew(virNetServerServiceClass)))
        return NULL;

    svc->socks = g_new0(virNetSocket *, nsocks);
    svc->nsocks = nsocks;
    for (i = 0; i < svc->nsocks; i++) {
        svc->socks[i] = socks[i];
        virObjectRef(svc->socks[i]);
    }
    svc->auth = auth;
    svc->readonly = readonly;
    svc->nrequests_client_max = nrequests_client_max;
    svc->tls = virObjectRef(tls);

    virObjectRef(svc);
    svc->timer = virEventAddTimeout(-1, virNetServerServiceTimerFunc,
                                    svc, virObjectUnref);
    if (svc->timer < 0) {
        virObjectUnref(svc);
        goto error;
    }

    for (i = 0; i < svc->nsocks; i++) {
        if (virNetSocketListen(svc->socks[i], max_queued_clients) < 0)
            goto error;

        /* IO callback is initially disabled, until we're ready
         * to deal with incoming clients */
        virObjectRef(svc);
        if (virNetSocketAddIOCallback(svc->socks[i],
                                      0,
                                      virNetServerServiceAccept,
                                      svc,
                                      virObjectUnref) < 0) {
            virObjectUnref(svc);
            goto error;
        }
    }


    return svc;

 error:
    virObjectUnref(svc);
    return NULL;
}


virNetServerService *virNetServerServiceNewTCP(const char *nodename,
                                                 const char *service,
                                                 int family,
                                                 int auth,
                                                 virNetTLSContext *tls,
                                                 bool readonly,
                                                 size_t max_queued_clients,
                                                 size_t nrequests_client_max)
{
    virNetServerService *svc;
    size_t i;
    virNetSocket **socks;
    size_t nsocks;

    VIR_DEBUG("Creating new TCP server nodename='%s' service='%s'",
              NULLSTR(nodename), NULLSTR(service));
    if (virNetSocketNewListenTCP(nodename,
                                 service,
                                 family,
                                 &socks,
                                 &nsocks) < 0)
        return NULL;

    svc = virNetServerServiceNewSocket(socks,
                                       nsocks,
                                       auth,
                                       tls,
                                       readonly,
                                       max_queued_clients,
                                       nrequests_client_max);

    for (i = 0; i < nsocks; i++)
        virObjectUnref(socks[i]);
    VIR_FREE(socks);

    return svc;
}


virNetServerService *virNetServerServiceNewUNIX(const char *path,
                                                  mode_t mask,
                                                  gid_t grp,
                                                  int auth,
                                                  virNetTLSContext *tls,
                                                  bool readonly,
                                                  size_t max_queued_clients,
                                                  size_t nrequests_client_max)
{
    virNetServerService *svc;
    virNetSocket *sock;

    VIR_DEBUG("Creating new UNIX server path='%s' mask=%o gid=%u",
              path, mask, grp);
    if (virNetSocketNewListenUNIX(path,
                                  mask,
                                  -1,
                                  grp,
                                  &sock) < 0)
        return NULL;

    svc = virNetServerServiceNewSocket(&sock,
                                       1,
                                       auth,
                                       tls,
                                       readonly,
                                       max_queued_clients,
                                       nrequests_client_max);

    virObjectUnref(sock);

    return svc;
}

virNetServerService *virNetServerServiceNewFDs(int *fds,
                                                 size_t nfds,
                                                 bool unlinkUNIX,
                                                 int auth,
                                                 virNetTLSContext *tls,
                                                 bool readonly,
                                                 size_t max_queued_clients,
                                                 size_t nrequests_client_max)
{
    virNetServerService *svc = NULL;
    virNetSocket **socks;
    size_t i;

    socks = g_new0(virNetSocket *, nfds);

    for (i = 0; i < nfds; i++) {
        if (virNetSocketNewListenFD(fds[i],
                                    unlinkUNIX,
                                    &socks[i]) < 0)
            goto cleanup;
    }

    svc = virNetServerServiceNewSocket(socks,
                                       nfds,
                                       auth,
                                       tls,
                                       readonly,
                                       max_queued_clients,
                                       nrequests_client_max);

 cleanup:
    for (i = 0; i < nfds && socks; i++)
        virObjectUnref(socks[i]);
    VIR_FREE(socks);
    return svc;
}


virNetServerService *virNetServerServiceNewPostExecRestart(virJSONValue *object)
{
    virNetServerService *svc;
    virJSONValue *socks;
    size_t i;
    size_t n;
    unsigned int max;

    if (virNetServerServiceInitialize() < 0)
        return NULL;

    if (!(svc = virObjectNew(virNetServerServiceClass)))
        return NULL;

    if (virJSONValueObjectGetNumberInt(object, "auth", &svc->auth) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing auth field in JSON state document"));
        goto error;
    }
    if (virJSONValueObjectGetBoolean(object, "readonly", &svc->readonly) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing readonly field in JSON state document"));
        goto error;
    }
    if (virJSONValueObjectGetNumberUint(object, "nrequests_client_max",
                                        &max) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing nrequests_client_max field in JSON state document"));
        goto error;
    }
    svc->nrequests_client_max = max;

    if (!(socks = virJSONValueObjectGet(object, "socks"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing socks field in JSON state document"));
        goto error;
    }

    if (!virJSONValueIsArray(socks)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed socks array"));
        goto error;
    }

    n = virJSONValueArraySize(socks);
    svc->socks = g_new0(virNetSocket *, n);
    svc->nsocks = n;

    for (i = 0; i < svc->nsocks; i++) {
        virJSONValue *child = virJSONValueArrayGet(socks, i);
        virNetSocket *sock;

        if (!(sock = virNetSocketNewPostExecRestart(child))) {
            virObjectUnref(sock);
            goto error;
        }

        svc->socks[i] = sock;

        /* IO callback is initially disabled, until we're ready
         * to deal with incoming clients */
        virObjectRef(svc);
        if (virNetSocketAddIOCallback(sock,
                                      0,
                                      virNetServerServiceAccept,
                                      svc,
                                      virObjectUnref) < 0) {
            virObjectUnref(svc);
            goto error;
        }
    }

    return svc;

 error:
    virObjectUnref(svc);
    return NULL;
}


virJSONValue *virNetServerServicePreExecRestart(virNetServerService *svc)
{
    g_autoptr(virJSONValue) object = virJSONValueNewObject();
    g_autoptr(virJSONValue) socks = virJSONValueNewArray();
    size_t i;

    if (virJSONValueObjectAppendNumberInt(object, "auth", svc->auth) < 0)
        return NULL;
    if (virJSONValueObjectAppendBoolean(object, "readonly", svc->readonly) < 0)
        return NULL;
    if (virJSONValueObjectAppendNumberUint(object, "nrequests_client_max", svc->nrequests_client_max) < 0)
        return NULL;

    for (i = 0; i < svc->nsocks; i++) {
        g_autoptr(virJSONValue) child = NULL;
        if (!(child = virNetSocketPreExecRestart(svc->socks[i])))
            return NULL;

        if (virJSONValueArrayAppend(socks, &child) < 0)
            return NULL;
    }

    if (virJSONValueObjectAppend(object, "socks", &socks) < 0)
        return NULL;

    return g_steal_pointer(&object);
}


int virNetServerServiceGetPort(virNetServerService *svc)
{
    /* We're assuming if there are multiple sockets
     * for IPv4 & 6, then they are all on same port */
    return virNetSocketGetPort(svc->socks[0]);
}


int virNetServerServiceGetAuth(virNetServerService *svc)
{
    return svc->auth;
}


bool virNetServerServiceIsReadonly(virNetServerService *svc)
{
    return svc->readonly;
}


size_t virNetServerServiceGetMaxRequests(virNetServerService *svc)
{
    return svc->nrequests_client_max;
}

virNetTLSContext *virNetServerServiceGetTLSContext(virNetServerService *svc)
{
    return svc->tls;
}

void virNetServerServiceSetDispatcher(virNetServerService *svc,
                                      virNetServerServiceDispatchFunc func,
                                      void *opaque)
{
    svc->dispatchFunc = func;
    svc->dispatchOpaque = opaque;
}


void virNetServerServiceDispose(void *obj)
{
    virNetServerService *svc = obj;
    size_t i;

    if (svc->timer >= 0)
        virEventRemoveTimeout(svc->timer);

    for (i = 0; i < svc->nsocks; i++)
       virObjectUnref(svc->socks[i]);
    g_free(svc->socks);

    virObjectUnref(svc->tls);
}

void virNetServerServiceToggle(virNetServerService *svc,
                               bool enabled)
{
    size_t i;

    for (i = 0; i < svc->nsocks; i++)
        virNetSocketUpdateIOCallback(svc->socks[i],
                                     enabled ?
                                     VIR_EVENT_HANDLE_READABLE :
                                     0);
}

void virNetServerServiceClose(virNetServerService *svc)
{
    size_t i;

    if (!svc)
        return;

    for (i = 0; i < svc->nsocks; i++) {
        virNetSocketRemoveIOCallback(svc->socks[i]);
        virNetSocketClose(svc->socks[i]);
    }
}


bool
virNetServerServiceTimerActive(virNetServerService *svc)
{
    return svc->timerActive;
}
