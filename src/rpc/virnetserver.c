/*
 * virnetserver.c: generic network RPC server
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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

#include "virnetserver.h"
#include "virlog.h"
#include "viralloc.h"
#include "virerror.h"
#include "virthread.h"
#include "virthreadpool.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netserver");


typedef struct _virNetServerJob virNetServerJob;
struct _virNetServerJob {
    virNetServerClient *client;
    virNetMessage *msg;
    virNetServerProgram *prog;
};

struct _virNetServer {
    virObjectLockable parent;

    char *name;

    /* Immutable pointer, self-locking APIs */
    virThreadPool *workers;

    size_t nservices;
    virNetServerService **services;

    size_t nprograms;
    virNetServerProgram **programs;

    size_t nclients;                    /* Current clients count */
    virNetServerClient **clients;     /* Clients */
    unsigned long long next_client_id;  /* next client ID */
    size_t nclients_max;                /* Max allowed clients count */
    size_t nclients_unauth;             /* Unauthenticated clients count */
    size_t nclients_unauth_max;         /* Max allowed unauth clients count */

    int keepaliveInterval;
    unsigned int keepaliveCount;

    virNetTLSContext *tls;

    virNetServerClientPrivNew clientPrivNew;
    virNetServerClientPrivPreExecRestart clientPrivPreExecRestart;
    virFreeCallback clientPrivFree;
    void *clientPrivOpaque;
};


static virClass *virNetServerClass;
static void virNetServerDispose(void *obj);
static void virNetServerUpdateServicesLocked(virNetServer *srv,
                                             bool enabled);
static inline size_t virNetServerTrackPendingAuthLocked(virNetServer *srv);
static inline size_t virNetServerTrackCompletedAuthLocked(virNetServer *srv);

static int virNetServerOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetServer, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetServer);

unsigned long long virNetServerNextClientID(virNetServer *srv)
{
    unsigned long long val;

    virObjectLock(srv);
    val = srv->next_client_id++;
    virObjectUnlock(srv);

    return val;
}

static int virNetServerProcessMsg(virNetServer *srv,
                                  virNetServerClient *client,
                                  virNetServerProgram *prog,
                                  virNetMessage *msg)
{
    if (!prog) {
        /* Only send back an error for type == CALL. Other
         * message types are not expecting replies, so we
         * must just log it & drop them
         */
        if (msg->header.type == VIR_NET_CALL ||
            msg->header.type == VIR_NET_CALL_WITH_FDS) {
            if (virNetServerProgramUnknownError(client,
                                                msg,
                                                &msg->header) < 0)
                return -1;
        } else {
            VIR_INFO("Dropping client message, unknown program %d version %d type %d proc %d",
                     msg->header.prog, msg->header.vers,
                     msg->header.type, msg->header.proc);
            /* Send a dummy reply to free up 'msg' & unblock client rx */
            virNetMessageClear(msg);
            msg->header.type = VIR_NET_REPLY;
            if (virNetServerClientSendMessage(client, msg) < 0)
                return -1;
        }
        return 0;
    }

    if (virNetServerProgramDispatch(prog,
                                    srv,
                                    client,
                                    msg) < 0)
        return -1;

    return 0;
}

static void virNetServerHandleJob(void *jobOpaque, void *opaque)
{
    virNetServer *srv = opaque;
    virNetServerJob *job = jobOpaque;

    VIR_DEBUG("server=%p client=%p message=%p prog=%p",
              srv, job->client, job->msg, job->prog);

    if (virNetServerProcessMsg(srv, job->client, job->prog, job->msg) < 0)
        goto error;

    virObjectUnref(job->prog);
    virObjectUnref(job->client);
    VIR_FREE(job);
    return;

 error:
    virObjectUnref(job->prog);
    virNetMessageFree(job->msg);
    virNetServerClientClose(job->client);
    virObjectUnref(job->client);
    VIR_FREE(job);
}

/**
 * virNetServerGetProgramLocked:
 * @srv: server (must be locked by the caller)
 * @msg: message
 *
 * Searches @srv for the right program for a given message @msg.
 *
 * Returns a pointer to the server program or NULL if not found.
 */
static virNetServerProgram *
virNetServerGetProgramLocked(virNetServer *srv,
                             virNetMessage *msg)
{
    size_t i;
    for (i = 0; i < srv->nprograms; i++) {
        if (virNetServerProgramMatches(srv->programs[i], msg))
            return srv->programs[i];
    }
    return NULL;
}

static void
virNetServerDispatchNewMessage(virNetServerClient *client,
                               virNetMessage *msg,
                               void *opaque)
{
    virNetServer *srv = opaque;
    virNetServerProgram *prog = NULL;
    unsigned int priority = 0;

    VIR_DEBUG("server=%p client=%p message=%p",
              srv, client, msg);

    virObjectLock(srv);
    prog = virNetServerGetProgramLocked(srv, msg);
    /* we can unlock @srv since @prog can only become invalid in case
     * of disposing @srv, but let's grab a ref first to ensure nothing
     * disposes of it before we use it. */
    virObjectRef(srv);
    virObjectUnlock(srv);

    if (virThreadPoolGetMaxWorkers(srv->workers) > 0)  {
        virNetServerJob *job;

        job = g_new0(virNetServerJob, 1);

        job->client = virObjectRef(client);
        job->msg = msg;

        if (prog) {
            job->prog = virObjectRef(prog);
            priority = virNetServerProgramGetPriority(prog, msg->header.proc);
        }

        if (virThreadPoolSendJob(srv->workers, priority, job) < 0) {
            virObjectUnref(client);
            VIR_FREE(job);
            virObjectUnref(prog);
            goto error;
        }
    } else {
        if (virNetServerProcessMsg(srv, client, prog, msg) < 0)
            goto error;
    }

    virObjectUnref(srv);
    return;

 error:
    virNetMessageFree(msg);
    virNetServerClientClose(client);
    virObjectUnref(srv);
}


/**
 * virNetServerCheckLimits:
 * @srv: server to check limits on
 *
 * Check if limits like max_clients or max_anonymous_clients
 * are satisfied. If so, re-enable accepting new clients. If these are violated
 * however, temporarily disable accepting new clients.
 * The @srv must be locked when this function is called.
 */
static void
virNetServerCheckLimits(virNetServer *srv)
{
    VIR_DEBUG("Checking client-related limits to re-enable or temporarily "
              "suspend services: nclients=%zu nclients_max=%zu "
              "nclients_unauth=%zu nclients_unauth_max=%zu",
              srv->nclients, srv->nclients_max,
              srv->nclients_unauth, srv->nclients_unauth_max);

    /* Check the max_anonymous_clients and max_clients limits so that we can
     * decide whether the services should be temporarily suspended, thus not
     * accepting any more clients for a while or re-enabling the previously
     * suspended services in order to accept new clients again.
     * A new client can only be accepted if both max_clients and
     * max_anonymous_clients wouldn't get overcommitted by accepting it.
     */
    if (srv->nclients >= srv->nclients_max ||
        (srv->nclients_unauth_max &&
         srv->nclients_unauth >= srv->nclients_unauth_max)) {
        /* Temporarily stop accepting new clients */
        VIR_INFO("Temporarily suspending services");
        virNetServerUpdateServicesLocked(srv, false);
    } else if (srv->nclients < srv->nclients_max &&
               (!srv->nclients_unauth_max ||
                srv->nclients_unauth < srv->nclients_unauth_max)) {
        /* Now it makes sense to accept() a new client. */
        VIR_INFO("Re-enabling services");
        virNetServerUpdateServicesLocked(srv, true);
    }
}

int virNetServerAddClient(virNetServer *srv,
                          virNetServerClient *client)
{
    virObjectLock(srv);

    if (virNetServerClientInit(client) < 0)
        goto error;

    VIR_EXPAND_N(srv->clients, srv->nclients, 1);
    srv->clients[srv->nclients-1] = virObjectRef(client);

    virObjectLock(client);
    if (virNetServerClientIsAuthPendingLocked(client))
        virNetServerTrackPendingAuthLocked(srv);
    virObjectUnlock(client);

    virNetServerCheckLimits(srv);

    virNetServerClientSetDispatcher(client,
                                    virNetServerDispatchNewMessage,
                                    srv);

    if (virNetServerClientInitKeepAlive(client, srv->keepaliveInterval,
                                        srv->keepaliveCount) < 0)
        goto error;

    virObjectUnlock(srv);
    return 0;

 error:
    virObjectUnlock(srv);
    return -1;
}

static int virNetServerDispatchNewClient(virNetServerService *svc,
                                         virNetSocket *clientsock,
                                         void *opaque)
{
    virNetServer *srv = opaque;
    virNetServerClient *client;

    if (!(client = virNetServerClientNew(virNetServerNextClientID(srv),
                                         clientsock,
                                         virNetServerServiceGetAuth(svc),
                                         virNetServerServiceIsReadonly(svc),
                                         virNetServerServiceGetMaxRequests(svc),
                                         virNetServerServiceGetTLSContext(svc),
                                         srv->clientPrivNew,
                                         srv->clientPrivPreExecRestart,
                                         srv->clientPrivFree,
                                         srv->clientPrivOpaque)))
        return -1;

    if (virNetServerAddClient(srv, client) < 0) {
        virNetServerClientClose(client);
        virObjectUnref(client);
        return -1;
    }
    virObjectUnref(client);
    return 0;
}


virNetServer *virNetServerNew(const char *name,
                                unsigned long long next_client_id,
                                size_t min_workers,
                                size_t max_workers,
                                size_t priority_workers,
                                size_t max_clients,
                                size_t max_anonymous_clients,
                                int keepaliveInterval,
                                unsigned int keepaliveCount,
                                virNetServerClientPrivNew clientPrivNew,
                                virNetServerClientPrivPreExecRestart clientPrivPreExecRestart,
                                virFreeCallback clientPrivFree,
                                void *clientPrivOpaque)
{
    virNetServer *srv;

    if (virNetServerInitialize() < 0)
        return NULL;

    if (!(srv = virObjectLockableNew(virNetServerClass)))
        return NULL;

    if (!(srv->workers = virThreadPoolNewFull(min_workers, max_workers,
                                              priority_workers,
                                              virNetServerHandleJob,
                                              "rpc-worker",
                                              srv)))
        goto error;

    srv->name = g_strdup(name);

    srv->next_client_id = next_client_id;
    srv->nclients_max = max_clients;
    srv->nclients_unauth_max = max_anonymous_clients;
    srv->keepaliveInterval = keepaliveInterval;
    srv->keepaliveCount = keepaliveCount;
    srv->clientPrivNew = clientPrivNew;
    srv->clientPrivPreExecRestart = clientPrivPreExecRestart;
    srv->clientPrivFree = clientPrivFree;
    srv->clientPrivOpaque = clientPrivOpaque;

    return srv;
 error:
    virObjectUnref(srv);
    return NULL;
}


virNetServer *virNetServerNewPostExecRestart(virJSONValue *object,
                                               const char *name,
                                               virNetServerClientPrivNew clientPrivNew,
                                               virNetServerClientPrivNewPostExecRestart clientPrivNewPostExecRestart,
                                               virNetServerClientPrivPreExecRestart clientPrivPreExecRestart,
                                               virFreeCallback clientPrivFree,
                                               void *clientPrivOpaque)
{
    virNetServer *srv = NULL;
    virJSONValue *clients;
    virJSONValue *services;
    size_t i;
    unsigned int min_workers;
    unsigned int max_workers;
    unsigned int priority_workers;
    unsigned int max_clients;
    unsigned int max_anonymous_clients;
    unsigned int keepaliveInterval;
    unsigned int keepaliveCount;
    unsigned long long next_client_id;

    if (virJSONValueObjectGetNumberUint(object, "min_workers", &min_workers) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing min_workers data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectGetNumberUint(object, "max_workers", &max_workers) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing max_workers data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectGetNumberUint(object, "priority_workers", &priority_workers) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing priority_workers data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectGetNumberUint(object, "max_clients", &max_clients) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing max_clients data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectHasKey(object, "max_anonymous_clients")) {
        if (virJSONValueObjectGetNumberUint(object, "max_anonymous_clients",
                                            &max_anonymous_clients) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed max_anonymous_clients data in JSON document"));
            goto error;
        }
    } else {
        max_anonymous_clients = max_clients;
    }
    if (virJSONValueObjectGetNumberUint(object, "keepaliveInterval", &keepaliveInterval) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing keepaliveInterval data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectGetNumberUint(object, "keepaliveCount", &keepaliveCount) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing keepaliveCount data in JSON document"));
        goto error;
    }

    if (virJSONValueObjectGetNumberUlong(object, "next_client_id",
                                         &next_client_id) < 0) {
        VIR_WARN("Missing next_client_id data in JSON document");
        next_client_id = 1;
    }

    if (!(srv = virNetServerNew(name, next_client_id,
                                min_workers, max_workers,
                                priority_workers, max_clients,
                                max_anonymous_clients,
                                keepaliveInterval, keepaliveCount,
                                clientPrivNew, clientPrivPreExecRestart,
                                clientPrivFree, clientPrivOpaque)))
        goto error;

    if (!(services = virJSONValueObjectGet(object, "services"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing services data in JSON document"));
        goto error;
    }

    if (!virJSONValueIsArray(services)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed services array"));
        goto error;
    }

    for (i = 0; i < virJSONValueArraySize(services); i++) {
        virNetServerService *service;
        virJSONValue *child = virJSONValueArrayGet(services, i);
        if (!child) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing service data in JSON document"));
            goto error;
        }

        if (!(service = virNetServerServiceNewPostExecRestart(child)))
            goto error;

        if (virNetServerAddService(srv, service) < 0) {
            virObjectUnref(service);
            goto error;
        }
    }


    if (!(clients = virJSONValueObjectGet(object, "clients"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing clients data in JSON document"));
        goto error;
    }

    if (!virJSONValueIsArray(clients)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed clients array"));
        goto error;
    }

    for (i = 0; i < virJSONValueArraySize(clients); i++) {
        virNetServerClient *client;
        virJSONValue *child = virJSONValueArrayGet(clients, i);
        if (!child) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing client data in JSON document"));
            goto error;
        }

        if (!(client = virNetServerClientNewPostExecRestart(srv,
                                                            child,
                                                            clientPrivNewPostExecRestart,
                                                            clientPrivPreExecRestart,
                                                            clientPrivFree,
                                                            clientPrivOpaque)))
            goto error;

        if (virNetServerAddClient(srv, client) < 0) {
            virObjectUnref(client);
            goto error;
        }
        virObjectUnref(client);
    }

    return srv;

 error:
    virObjectUnref(srv);
    return NULL;
}


virJSONValue *virNetServerPreExecRestart(virNetServer *srv)
{
    g_autoptr(virJSONValue) object = virJSONValueNewObject();
    g_autoptr(virJSONValue) clients = virJSONValueNewArray();
    g_autoptr(virJSONValue) services = virJSONValueNewArray();
    size_t i;

    virObjectLock(srv);

    if (virJSONValueObjectAppendNumberUint(object, "min_workers",
                                           virThreadPoolGetMinWorkers(srv->workers)) < 0)
        goto error;
    if (virJSONValueObjectAppendNumberUint(object, "max_workers",
                                           virThreadPoolGetMaxWorkers(srv->workers)) < 0)
        goto error;
    if (virJSONValueObjectAppendNumberUint(object, "priority_workers",
                                           virThreadPoolGetPriorityWorkers(srv->workers)) < 0)
        goto error;

    if (virJSONValueObjectAppendNumberUint(object, "max_clients", srv->nclients_max) < 0)
        goto error;
    if (virJSONValueObjectAppendNumberUint(object, "max_anonymous_clients",
                                           srv->nclients_unauth_max) < 0)
        goto error;

    if (virJSONValueObjectAppendNumberUint(object, "keepaliveInterval", srv->keepaliveInterval) < 0)
        goto error;
    if (virJSONValueObjectAppendNumberUint(object, "keepaliveCount", srv->keepaliveCount) < 0)
        goto error;

    if (virJSONValueObjectAppendNumberUlong(object, "next_client_id",
                                            srv->next_client_id) < 0)
        goto error;

    for (i = 0; i < srv->nservices; i++) {
        g_autoptr(virJSONValue) child = NULL;
        if (!(child = virNetServerServicePreExecRestart(srv->services[i])))
            goto error;

        if (virJSONValueArrayAppend(services, &child) < 0)
            goto error;
    }

    if (virJSONValueObjectAppend(object, "services", &services) < 0)
        goto error;

    for (i = 0; i < srv->nclients; i++) {
        g_autoptr(virJSONValue) child = NULL;
        if (!(child = virNetServerClientPreExecRestart(srv->clients[i])))
            goto error;

        if (virJSONValueArrayAppend(clients, &child) < 0)
            goto error;
    }

    if (virJSONValueObjectAppend(object, "clients", &clients) < 0)
        goto error;

    virObjectUnlock(srv);

    return g_steal_pointer(&object);

 error:
    virObjectUnlock(srv);
    return NULL;
}



int virNetServerAddService(virNetServer *srv,
                           virNetServerService *svc)
{
    virObjectLock(srv);

    VIR_EXPAND_N(srv->services, srv->nservices, 1);
    srv->services[srv->nservices-1] = virObjectRef(svc);

    virNetServerServiceSetDispatcher(svc,
                                     virNetServerDispatchNewClient,
                                     srv);

    virObjectUnlock(srv);
    return 0;
}


static int
virNetServerAddServiceActivation(virNetServer *srv,
                                 virSystemdActivation *act,
                                 const char *actname,
                                 int auth,
                                 virNetTLSContext *tls,
                                 bool readonly,
                                 size_t max_queued_clients,
                                 size_t nrequests_client_max)
{
    int *fds;
    size_t nfds;

    if (act == NULL)
        return 0;

    virSystemdActivationClaimFDs(act, actname, &fds, &nfds);

    if (nfds) {
        virNetServerService *svc;

        svc = virNetServerServiceNewFDs(fds,
                                        nfds,
                                        false,
                                        auth,
                                        tls,
                                        readonly,
                                        max_queued_clients,
                                        nrequests_client_max);
        if (!svc)
            return -1;

        if (virNetServerAddService(srv, svc) < 0) {
            virObjectUnref(svc);
            return -1;
        }
    }

    /* Intentionally return 1 any time activation is present,
     * even if we didn't find any sockets with the matching
     * name. The user needs to be free to disable some of the
     * services via unit files without causing us to fallback
     * to creating the service manually.
     */
    return 1;
}


int virNetServerAddServiceTCP(virNetServer *srv,
                              virSystemdActivation *act,
                              const char *actname,
                              const char *nodename,
                              const char *service,
                              int family,
                              int auth,
                              virNetTLSContext *tls,
                              bool readonly,
                              size_t max_queued_clients,
                              size_t nrequests_client_max)
{
    virNetServerService *svc = NULL;
    int ret;

    ret = virNetServerAddServiceActivation(srv, act, actname,
                                           auth,
                                           tls,
                                           readonly,
                                           max_queued_clients,
                                           nrequests_client_max);
    if (ret < 0)
        return -1;

    if (ret == 1)
        return 0;

    if (!(svc = virNetServerServiceNewTCP(nodename,
                                          service,
                                          family,
                                          auth,
                                          tls,
                                          readonly,
                                          max_queued_clients,
                                          nrequests_client_max)))
        return -1;

    if (virNetServerAddService(srv, svc) < 0) {
        virObjectUnref(svc);
        return -1;
    }

    virObjectUnref(svc);

    return 0;
}


int virNetServerAddServiceUNIX(virNetServer *srv,
                               virSystemdActivation *act,
                               const char *actname,
                               const char *path,
                               mode_t mask,
                               gid_t grp,
                               int auth,
                               virNetTLSContext *tls,
                               bool readonly,
                               size_t max_queued_clients,
                               size_t nrequests_client_max)
{
    virNetServerService *svc = NULL;
    int ret;

    ret = virNetServerAddServiceActivation(srv, act, actname,
                                           auth,
                                           tls,
                                           readonly,
                                           max_queued_clients,
                                           nrequests_client_max);
    if (ret < 0)
        return -1;

    if (ret == 1)
        return 0;

    if (!(svc = virNetServerServiceNewUNIX(path,
                                           mask,
                                           grp,
                                           auth,
                                           tls,
                                           readonly,
                                           max_queued_clients,
                                           nrequests_client_max)))
        return -1;

    if (virNetServerAddService(srv, svc) < 0) {
        virObjectUnref(svc);
        return -1;
    }

    virObjectUnref(svc);

    return 0;
}


int virNetServerAddProgram(virNetServer *srv,
                           virNetServerProgram *prog)
{
    virObjectLock(srv);

    VIR_EXPAND_N(srv->programs, srv->nprograms, 1);
    srv->programs[srv->nprograms-1] = virObjectRef(prog);

    virObjectUnlock(srv);
    return 0;
}

int virNetServerSetTLSContext(virNetServer *srv,
                              virNetTLSContext *tls)
{
    srv->tls = virObjectRef(tls);
    return 0;
}


/**
 * virNetServerSetClientAuthCompletedLocked:
 * @srv: server must be locked by the caller
 * @client: client must be locked by the caller
 *
 * If the client authentication was pending, clear that pending and
 * update the server tracking.
 */
static void
virNetServerSetClientAuthCompletedLocked(virNetServer *srv,
                                         virNetServerClient *client)
{
    if (virNetServerClientIsAuthPendingLocked(client)) {
        virNetServerClientSetAuthPendingLocked(client, false);
        virNetServerTrackCompletedAuthLocked(srv);
    }
}


/**
 * virNetServerSetClientAuthenticated:
 * @srv: server must be unlocked
 * @client: client must be unlocked
 *
 * Mark @client as authenticated and tracks on @srv that the
 * authentication of this @client has been completed. Also it checks
 * the limits of @srv.
 */
void
virNetServerSetClientAuthenticated(virNetServer *srv,
                                   virNetServerClient *client)
{
    virObjectLock(srv);
    virObjectLock(client);
    virNetServerClientSetAuthLocked(client, VIR_NET_SERVER_SERVICE_AUTH_NONE);
    virNetServerSetClientAuthCompletedLocked(srv, client);
    virNetServerCheckLimits(srv);
    virObjectUnlock(client);
    virObjectUnlock(srv);
}


static void
virNetServerUpdateServicesLocked(virNetServer *srv,
                                 bool enabled)
{
    size_t i;

    for (i = 0; i < srv->nservices; i++)
        virNetServerServiceToggle(srv->services[i], enabled);
}


void virNetServerUpdateServices(virNetServer *srv,
                                bool enabled)
{
    virObjectLock(srv);
    virNetServerUpdateServicesLocked(srv, enabled);
    virObjectUnlock(srv);
}

void virNetServerDispose(void *obj)
{
    virNetServer *srv = obj;
    size_t i;

    g_free(srv->name);

    virThreadPoolFree(srv->workers);

    for (i = 0; i < srv->nservices; i++)
        virObjectUnref(srv->services[i]);
    g_free(srv->services);

    for (i = 0; i < srv->nprograms; i++)
        virObjectUnref(srv->programs[i]);
    g_free(srv->programs);

    for (i = 0; i < srv->nclients; i++)
        virObjectUnref(srv->clients[i]);
    g_free(srv->clients);
}

void virNetServerClose(virNetServer *srv)
{
    size_t i;

    if (!srv)
        return;

    virObjectLock(srv);

    for (i = 0; i < srv->nservices; i++)
        virNetServerServiceClose(srv->services[i]);

    for (i = 0; i < srv->nclients; i++)
        virNetServerClientClose(srv->clients[i]);

    virThreadPoolStop(srv->workers);

    virObjectUnlock(srv);
}

void
virNetServerShutdownWait(virNetServer *srv)
{
    virThreadPoolDrain(srv->workers);
}

static inline size_t
virNetServerTrackPendingAuthLocked(virNetServer *srv)
{
    return ++srv->nclients_unauth;
}

static inline size_t
virNetServerTrackCompletedAuthLocked(virNetServer *srv)
{
    return --srv->nclients_unauth;
}


bool
virNetServerHasClients(virNetServer *srv)
{
    bool ret;

    virObjectLock(srv);
    ret = !!srv->nclients;
    virObjectUnlock(srv);

    return ret;
}

void
virNetServerProcessClients(virNetServer *srv)
{
    size_t i;
    virNetServerClient *client;

    virObjectLock(srv);

 reprocess:
    for (i = 0; i < srv->nclients; i++) {
        client = srv->clients[i];
        virObjectLock(client);
        if (virNetServerClientWantCloseLocked(client))
            virNetServerClientCloseLocked(client);

        if (virNetServerClientIsClosedLocked(client)) {
            VIR_DELETE_ELEMENT(srv->clients, i, srv->nclients);

            /* Update server authentication tracking */
            virNetServerSetClientAuthCompletedLocked(srv, client);
            virObjectUnlock(client);

            virNetServerCheckLimits(srv);

            virObjectUnlock(srv);
            virObjectUnref(client);
            virObjectLock(srv);

            goto reprocess;
        } else {
            virObjectUnlock(client);
        }
    }

    virObjectUnlock(srv);
}

const char *
virNetServerGetName(virNetServer *srv)
{
    return srv->name;
}

int
virNetServerGetThreadPoolParameters(virNetServer *srv,
                                    size_t *minWorkers,
                                    size_t *maxWorkers,
                                    size_t *nWorkers,
                                    size_t *freeWorkers,
                                    size_t *nPrioWorkers,
                                    size_t *jobQueueDepth)
{
    virObjectLock(srv);

    *minWorkers = virThreadPoolGetMinWorkers(srv->workers);
    *maxWorkers = virThreadPoolGetMaxWorkers(srv->workers);
    *freeWorkers = virThreadPoolGetFreeWorkers(srv->workers);
    *nWorkers = virThreadPoolGetCurrentWorkers(srv->workers);
    *nPrioWorkers = virThreadPoolGetPriorityWorkers(srv->workers);
    *jobQueueDepth = virThreadPoolGetJobQueueDepth(srv->workers);

    virObjectUnlock(srv);
    return 0;
}

int
virNetServerSetThreadPoolParameters(virNetServer *srv,
                                    long long int minWorkers,
                                    long long int maxWorkers,
                                    long long int prioWorkers)
{
    int ret;

    virObjectLock(srv);
    ret = virThreadPoolSetParameters(srv->workers, minWorkers,
                                     maxWorkers, prioWorkers);
    virObjectUnlock(srv);

    return ret;
}

size_t
virNetServerGetMaxClients(virNetServer *srv)
{
    size_t ret;

    virObjectLock(srv);
    ret = srv->nclients_max;
    virObjectUnlock(srv);

    return ret;
}

size_t
virNetServerGetCurrentClients(virNetServer *srv)
{
    size_t ret;

    virObjectLock(srv);
    ret = srv->nclients;
    virObjectUnlock(srv);

    return ret;
}

size_t
virNetServerGetMaxUnauthClients(virNetServer *srv)
{
    size_t ret;

    virObjectLock(srv);
    ret = srv->nclients_unauth_max;
    virObjectUnlock(srv);

    return ret;
}

size_t
virNetServerGetCurrentUnauthClients(virNetServer *srv)
{
    size_t ret;

    virObjectLock(srv);
    ret = srv->nclients_unauth;
    virObjectUnlock(srv);

    return ret;
}


bool virNetServerNeedsAuth(virNetServer *srv,
                           int auth)
{
    bool ret = false;
    size_t i;

    virObjectLock(srv);
    for (i = 0; i < srv->nservices; i++) {
        if (virNetServerServiceGetAuth(srv->services[i]) == auth)
            ret = true;
    }
    virObjectUnlock(srv);

    return ret;
}

int
virNetServerGetClients(virNetServer *srv,
                       virNetServerClient ***clts)
{
    int ret = -1;
    size_t i;
    size_t nclients = 0;
    virNetServerClient **list = NULL;

    virObjectLock(srv);

    for (i = 0; i < srv->nclients; i++) {
        virNetServerClient *client = virObjectRef(srv->clients[i]);
        if (VIR_APPEND_ELEMENT(list, nclients, client) < 0) {
            virObjectUnref(client);
            goto cleanup;
        }
    }

    *clts = g_steal_pointer(&list);
    ret = nclients;

 cleanup:
    virObjectListFreeCount(list, nclients);
    virObjectUnlock(srv);
    return ret;
}

virNetServerClient *
virNetServerGetClient(virNetServer *srv,
                      unsigned long long id)
{
    size_t i;
    virNetServerClient *ret = NULL;

    virObjectLock(srv);

    for (i = 0; i < srv->nclients; i++) {
        virNetServerClient *client = srv->clients[i];
        if (virNetServerClientGetID(client) == id)
            ret = virObjectRef(client);
    }

    virObjectUnlock(srv);

    if (!ret)
        virReportError(VIR_ERR_NO_CLIENT,
                       _("No client with matching ID '%llu'"), id);
    return ret;
}

int
virNetServerSetClientLimits(virNetServer *srv,
                            long long int maxClients,
                            long long int maxClientsUnauth)
{
    int ret = -1;
    size_t max, max_unauth;

    virObjectLock(srv);

    max = maxClients >= 0 ? maxClients : srv->nclients_max;
    max_unauth = maxClientsUnauth >= 0 ?
        maxClientsUnauth : srv->nclients_unauth_max;

    if (max < max_unauth) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("The overall maximum number of clients must be "
                         "greater than the maximum number of clients waiting "
                         "for authentication"));
        goto cleanup;
    }

    if (maxClients >= 0)
        srv->nclients_max = maxClients;

    if (maxClientsUnauth >= 0)
        srv->nclients_unauth_max = maxClientsUnauth;

    virNetServerCheckLimits(srv);

    ret = 0;
 cleanup:
    virObjectUnlock(srv);
    return ret;
}

static virNetTLSContext *
virNetServerGetTLSContext(virNetServer *srv)
{
    size_t i;
    virNetTLSContext *ctxt = NULL;
    virNetServerService *svc = NULL;

    /* find svcTLS from srv, get svcTLS->tls */
    for (i = 0; i < srv->nservices; i++) {
        svc = srv->services[i];
        ctxt = virNetServerServiceGetTLSContext(svc);
        if (ctxt != NULL)
            break;
    }

    return ctxt;
}

int
virNetServerUpdateTlsFiles(virNetServer *srv)
{
    int ret = -1;
    virNetTLSContext *ctxt = NULL;
    bool privileged = geteuid() == 0;

    ctxt = virNetServerGetTLSContext(srv);
    if (!ctxt) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no tls service found, unable to update tls files"));
        return -1;
    }

    virObjectLock(srv);
    virObjectLock(ctxt);

    if (virNetTLSContextReloadForServer(ctxt, !privileged)) {
        VIR_DEBUG("failed to reload server's tls context");
        goto cleanup;
    }

    VIR_DEBUG("update tls files success");
    ret = 0;

 cleanup:
    virObjectUnlock(ctxt);
    virObjectUnlock(srv);
    return ret;
}
