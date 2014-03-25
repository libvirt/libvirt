/*
 * virnetserver.c: generic network RPC server
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "virnetserver.h"
#include "virlog.h"
#include "viralloc.h"
#include "virerror.h"
#include "virthread.h"
#include "virthreadpool.h"
#include "virutil.h"
#include "virfile.h"
#include "virnetservermdns.h"
#include "virdbus.h"
#include "virstring.h"
#include "virsystemd.h"

#ifndef SA_SIGINFO
# define SA_SIGINFO 0
#endif

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netserver");

typedef struct _virNetServerSignal virNetServerSignal;
typedef virNetServerSignal *virNetServerSignalPtr;

struct _virNetServerSignal {
    struct sigaction oldaction;
    int signum;
    virNetServerSignalFunc func;
    void *opaque;
};

typedef struct _virNetServerJob virNetServerJob;
typedef virNetServerJob *virNetServerJobPtr;

struct _virNetServerJob {
    virNetServerClientPtr client;
    virNetMessagePtr msg;
    virNetServerProgramPtr prog;
};

struct _virNetServer {
    virObjectLockable parent;

    virThreadPoolPtr workers;

    bool privileged;

    size_t nsignals;
    virNetServerSignalPtr *signals;
    int sigread;
    int sigwrite;
    int sigwatch;

    char *mdnsGroupName;
    virNetServerMDNSPtr mdns;
    virNetServerMDNSGroupPtr mdnsGroup;

    size_t nservices;
    virNetServerServicePtr *services;

    size_t nprograms;
    virNetServerProgramPtr *programs;

    size_t nclients;                    /* Current clients count */
    virNetServerClientPtr *clients;     /* Clients */
    size_t nclients_max;                /* Max allowed clients count */
    size_t nclients_unauth;             /* Unauthenticated clients count */
    size_t nclients_unauth_max;         /* Max allowed unauth clients count */

    int keepaliveInterval;
    unsigned int keepaliveCount;
    bool keepaliveRequired;

    bool quit;

#ifdef WITH_GNUTLS
    virNetTLSContextPtr tls;
#endif

    unsigned int autoShutdownTimeout;
    size_t autoShutdownInhibitions;
    bool autoShutdownCallingInhibit;
    int autoShutdownInhibitFd;

    virNetServerClientPrivNew clientPrivNew;
    virNetServerClientPrivPreExecRestart clientPrivPreExecRestart;
    virFreeCallback clientPrivFree;
    void *clientPrivOpaque;
};


static virClassPtr virNetServerClass;
static void virNetServerDispose(void *obj);
static void virNetServerUpdateServicesLocked(virNetServerPtr srv,
                                             bool enabled);
static inline size_t virNetServerTrackPendingAuthLocked(virNetServerPtr srv);
static inline size_t virNetServerTrackCompletedAuthLocked(virNetServerPtr srv);

static int virNetServerOnceInit(void)
{
    if (!(virNetServerClass = virClassNew(virClassForObjectLockable(),
                                          "virNetServer",
                                          sizeof(virNetServer),
                                          virNetServerDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetServer)


static int virNetServerProcessMsg(virNetServerPtr srv,
                                  virNetServerClientPtr client,
                                  virNetServerProgramPtr prog,
                                  virNetMessagePtr msg)
{
    int ret = -1;
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
                goto cleanup;
        } else {
            VIR_INFO("Dropping client mesage, unknown program %d version %d type %d proc %d",
                     msg->header.prog, msg->header.vers,
                     msg->header.type, msg->header.proc);
            /* Send a dummy reply to free up 'msg' & unblock client rx */
            virNetMessageClear(msg);
            msg->header.type = VIR_NET_REPLY;
            if (virNetServerClientSendMessage(client, msg) < 0)
                goto cleanup;
        }
        goto done;
    }

    if (virNetServerProgramDispatch(prog,
                                    srv,
                                    client,
                                    msg) < 0)
        goto cleanup;

 done:
    ret = 0;

 cleanup:
    return ret;
}

static void virNetServerHandleJob(void *jobOpaque, void *opaque)
{
    virNetServerPtr srv = opaque;
    virNetServerJobPtr job = jobOpaque;

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

static int virNetServerDispatchNewMessage(virNetServerClientPtr client,
                                          virNetMessagePtr msg,
                                          void *opaque)
{
    virNetServerPtr srv = opaque;
    virNetServerProgramPtr prog = NULL;
    unsigned int priority = 0;
    size_t i;
    int ret = -1;

    VIR_DEBUG("server=%p client=%p message=%p",
              srv, client, msg);

    virObjectLock(srv);
    for (i = 0; i < srv->nprograms; i++) {
        if (virNetServerProgramMatches(srv->programs[i], msg)) {
            prog = srv->programs[i];
            break;
        }
    }

    if (srv->workers) {
        virNetServerJobPtr job;

        if (VIR_ALLOC(job) < 0)
            goto cleanup;

        job->client = client;
        job->msg = msg;

        if (prog) {
            virObjectRef(prog);
            job->prog = prog;
            priority = virNetServerProgramGetPriority(prog, msg->header.proc);
        }

        ret = virThreadPoolSendJob(srv->workers, priority, job);

        if (ret < 0) {
            VIR_FREE(job);
            virObjectUnref(prog);
        }
    } else {
        ret = virNetServerProcessMsg(srv, client, prog, msg);
    }

 cleanup:
    virObjectUnlock(srv);

    return ret;
}


static int virNetServerAddClient(virNetServerPtr srv,
                                 virNetServerClientPtr client)
{
    virObjectLock(srv);

    if (srv->nclients >= srv->nclients_max) {
        virReportError(VIR_ERR_RPC,
                       _("Too many active clients (%zu), dropping connection from %s"),
                       srv->nclients_max, virNetServerClientRemoteAddrString(client));
        goto error;
    }

    if (virNetServerClientInit(client) < 0)
        goto error;

    if (VIR_EXPAND_N(srv->clients, srv->nclients, 1) < 0)
        goto error;
    srv->clients[srv->nclients-1] = client;
    virObjectRef(client);

    if (virNetServerClientNeedAuth(client))
        virNetServerTrackPendingAuthLocked(srv);

    if (srv->nclients_unauth_max &&
        srv->nclients_unauth == srv->nclients_unauth_max) {
        /* Temporarily stop accepting new clients */
        VIR_DEBUG("Temporarily suspending services "
                  "due to max_anonymous_clients");
        virNetServerUpdateServicesLocked(srv, false);
    }

    if (srv->nclients == srv->nclients_max) {
        /* Temporarily stop accepting new clients */
        VIR_DEBUG("Temporarily suspending services due to max_clients");
        virNetServerUpdateServicesLocked(srv, false);
    }

    virNetServerClientSetDispatcher(client,
                                    virNetServerDispatchNewMessage,
                                    srv);

    virNetServerClientInitKeepAlive(client, srv->keepaliveInterval,
                                    srv->keepaliveCount);

    virObjectUnlock(srv);
    return 0;

 error:
    virObjectUnlock(srv);
    return -1;
}

static int virNetServerDispatchNewClient(virNetServerServicePtr svc,
                                         virNetSocketPtr clientsock,
                                         void *opaque)
{
    virNetServerPtr srv = opaque;
    virNetServerClientPtr client;

    if (!(client = virNetServerClientNew(clientsock,
                                         virNetServerServiceGetAuth(svc),
                                         virNetServerServiceIsReadonly(svc),
                                         virNetServerServiceGetMaxRequests(svc),
#if WITH_GNUTLS
                                         virNetServerServiceGetTLSContext(svc),
#endif
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


virNetServerPtr virNetServerNew(size_t min_workers,
                                size_t max_workers,
                                size_t priority_workers,
                                size_t max_clients,
                                size_t max_anonymous_clients,
                                int keepaliveInterval,
                                unsigned int keepaliveCount,
                                bool keepaliveRequired,
                                const char *mdnsGroupName,
                                virNetServerClientPrivNew clientPrivNew,
                                virNetServerClientPrivPreExecRestart clientPrivPreExecRestart,
                                virFreeCallback clientPrivFree,
                                void *clientPrivOpaque)
{
    virNetServerPtr srv;
    struct sigaction sig_action;

    if (virNetServerInitialize() < 0)
        return NULL;

    if (!(srv = virObjectLockableNew(virNetServerClass)))
        return NULL;

    if (max_workers &&
        !(srv->workers = virThreadPoolNew(min_workers, max_workers,
                                          priority_workers,
                                          virNetServerHandleJob,
                                          srv)))
        goto error;

    srv->nclients_max = max_clients;
    srv->nclients_unauth_max = max_anonymous_clients;
    srv->keepaliveInterval = keepaliveInterval;
    srv->keepaliveCount = keepaliveCount;
    srv->keepaliveRequired = keepaliveRequired;
    srv->sigwrite = srv->sigread = -1;
    srv->clientPrivNew = clientPrivNew;
    srv->clientPrivPreExecRestart = clientPrivPreExecRestart;
    srv->clientPrivFree = clientPrivFree;
    srv->clientPrivOpaque = clientPrivOpaque;
    srv->privileged = geteuid() == 0;
    srv->autoShutdownInhibitFd = -1;

    if (VIR_STRDUP(srv->mdnsGroupName, mdnsGroupName) < 0)
        goto error;
    if (srv->mdnsGroupName) {
        if (!(srv->mdns = virNetServerMDNSNew()))
            goto error;
        if (!(srv->mdnsGroup = virNetServerMDNSAddGroup(srv->mdns,
                                                        srv->mdnsGroupName)))
            goto error;
    }

    if (virEventRegisterDefaultImpl() < 0)
        goto error;

    memset(&sig_action, 0, sizeof(sig_action));
    sig_action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig_action, NULL);

    return srv;

 error:
    virObjectUnref(srv);
    return NULL;
}


virNetServerPtr virNetServerNewPostExecRestart(virJSONValuePtr object,
                                               virNetServerClientPrivNew clientPrivNew,
                                               virNetServerClientPrivNewPostExecRestart clientPrivNewPostExecRestart,
                                               virNetServerClientPrivPreExecRestart clientPrivPreExecRestart,
                                               virFreeCallback clientPrivFree,
                                               void *clientPrivOpaque)
{
    virNetServerPtr srv = NULL;
    virJSONValuePtr clients;
    virJSONValuePtr services;
    size_t i;
    int n;
    unsigned int min_workers;
    unsigned int max_workers;
    unsigned int priority_workers;
    unsigned int max_clients;
    unsigned int max_anonymous_clients;
    unsigned int keepaliveInterval;
    unsigned int keepaliveCount;
    bool keepaliveRequired;
    const char *mdnsGroupName = NULL;

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
    if (virJSONValueObjectGetBoolean(object, "keepaliveRequired", &keepaliveRequired) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing keepaliveRequired data in JSON document"));
        goto error;
    }

    if (virJSONValueObjectHasKey(object, "mdnsGroupName") &&
        (!(mdnsGroupName = virJSONValueObjectGetString(object, "mdnsGroupName")))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed mdnsGroupName data in JSON document"));
        goto error;
    }

    if (!(srv = virNetServerNew(min_workers, max_clients,
                                priority_workers, max_clients,
                                max_anonymous_clients,
                                keepaliveInterval, keepaliveCount,
                                keepaliveRequired, mdnsGroupName,
                                clientPrivNew, clientPrivPreExecRestart,
                                clientPrivFree, clientPrivOpaque)))
        goto error;

    if (!(services = virJSONValueObjectGet(object, "services"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing services data in JSON document"));
        goto error;
    }

    n =  virJSONValueArraySize(services);
    if (n < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed services data in JSON document"));
        goto error;
    }

    for (i = 0; i < n; i++) {
        virNetServerServicePtr service;
        virJSONValuePtr child = virJSONValueArrayGet(services, i);
        if (!child) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing service data in JSON document"));
            goto error;
        }

        if (!(service = virNetServerServiceNewPostExecRestart(child)))
            goto error;

        /* XXX mdns entry names ? */
        if (virNetServerAddService(srv, service, NULL) < 0) {
            virObjectUnref(service);
            goto error;
        }
    }


    if (!(clients = virJSONValueObjectGet(object, "clients"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing clients data in JSON document"));
        goto error;
    }

    n =  virJSONValueArraySize(clients);
    if (n < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed clients data in JSON document"));
        goto error;
    }

    for (i = 0; i < n; i++) {
        virNetServerClientPtr client;
        virJSONValuePtr child = virJSONValueArrayGet(clients, i);
        if (!child) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing client data in JSON document"));
            goto error;
        }

        if (!(client = virNetServerClientNewPostExecRestart(child,
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


virJSONValuePtr virNetServerPreExecRestart(virNetServerPtr srv)
{
    virJSONValuePtr object;
    virJSONValuePtr clients;
    virJSONValuePtr services;
    size_t i;

    virObjectLock(srv);

    if (!(object = virJSONValueNewObject()))
        goto error;

    if (virJSONValueObjectAppendNumberUint(object, "min_workers",
                                           virThreadPoolGetMinWorkers(srv->workers)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set min_workers data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectAppendNumberUint(object, "max_workers",
                                           virThreadPoolGetMaxWorkers(srv->workers)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set max_workers data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectAppendNumberUint(object, "priority_workers",
                                           virThreadPoolGetPriorityWorkers(srv->workers)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set priority_workers data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectAppendNumberUint(object, "max_clients", srv->nclients_max) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set max_clients data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectAppendNumberUint(object, "max_anonymous_clients",
                                           srv->nclients_unauth_max) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set max_anonymous_clients data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectAppendNumberUint(object, "keepaliveInterval", srv->keepaliveInterval) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set keepaliveInterval data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectAppendNumberUint(object, "keepaliveCount", srv->keepaliveCount) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set keepaliveCount data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectAppendBoolean(object, "keepaliveRequired", srv->keepaliveRequired) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set keepaliveRequired data in JSON document"));
        goto error;
    }

    if (srv->mdnsGroupName &&
        virJSONValueObjectAppendString(object, "mdnsGroupName", srv->mdnsGroupName) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set mdnsGroupName data in JSON document"));
        goto error;
    }

    services = virJSONValueNewArray();
    if (virJSONValueObjectAppend(object, "services", services) < 0) {
        virJSONValueFree(services);
        goto error;
    }

    for (i = 0; i < srv->nservices; i++) {
        virJSONValuePtr child;
        if (!(child = virNetServerServicePreExecRestart(srv->services[i])))
            goto error;

        if (virJSONValueArrayAppend(services, child) < 0) {
            virJSONValueFree(child);
            goto error;
        }
    }

    clients = virJSONValueNewArray();
    if (virJSONValueObjectAppend(object, "clients", clients) < 0) {
        virJSONValueFree(clients);
        goto error;
    }

    for (i = 0; i < srv->nclients; i++) {
        virJSONValuePtr child;
        if (!(child = virNetServerClientPreExecRestart(srv->clients[i])))
            goto error;

        if (virJSONValueArrayAppend(clients, child) < 0) {
            virJSONValueFree(child);
            goto error;
        }
    }

    virObjectUnlock(srv);

    return object;

 error:
    virJSONValueFree(object);
    virObjectUnlock(srv);
    return NULL;
}


bool virNetServerIsPrivileged(virNetServerPtr srv)
{
    bool priv;
    virObjectLock(srv);
    priv = srv->privileged;
    virObjectUnlock(srv);
    return priv;
}


void virNetServerAutoShutdown(virNetServerPtr srv,
                              unsigned int timeout)
{
    virObjectLock(srv);

    srv->autoShutdownTimeout = timeout;

    virObjectUnlock(srv);
}


#if defined(HAVE_DBUS) && defined(DBUS_TYPE_UNIX_FD)
static void virNetServerGotInhibitReply(DBusPendingCall *pending,
                                        void *opaque)
{
    virNetServerPtr srv = opaque;
    DBusMessage *reply;
    int fd;

    virObjectLock(srv);
    srv->autoShutdownCallingInhibit = false;

    VIR_DEBUG("srv=%p", srv);

    reply = dbus_pending_call_steal_reply(pending);
    if (reply == NULL)
        goto cleanup;

    if (dbus_message_get_args(reply, NULL,
                              DBUS_TYPE_UNIX_FD, &fd,
                              DBUS_TYPE_INVALID)) {
        if (srv->autoShutdownInhibitions) {
            srv->autoShutdownInhibitFd = fd;
        } else {
            /* We stopped the last VM since we made the inhibit call */
            VIR_FORCE_CLOSE(fd);
        }
    }
    dbus_message_unref(reply);

 cleanup:
    virObjectUnlock(srv);
}


/* As per: http://www.freedesktop.org/wiki/Software/systemd/inhibit */
static void virNetServerCallInhibit(virNetServerPtr srv,
                                    const char *what,
                                    const char *who,
                                    const char *why,
                                    const char *mode)
{
    DBusMessage *message;
    DBusPendingCall *pendingReply;
    DBusConnection *systemBus;

    VIR_DEBUG("srv=%p what=%s who=%s why=%s mode=%s",
              srv, NULLSTR(what), NULLSTR(who), NULLSTR(why), NULLSTR(mode));

    if (!(systemBus = virDBusGetSystemBus()))
        return;

    /* Only one outstanding call at a time */
    if (srv->autoShutdownCallingInhibit)
        return;

    message = dbus_message_new_method_call("org.freedesktop.login1",
                                           "/org/freedesktop/login1",
                                           "org.freedesktop.login1.Manager",
                                           "Inhibit");
    if (message == NULL)
        return;

    dbus_message_append_args(message,
                             DBUS_TYPE_STRING, &what,
                             DBUS_TYPE_STRING, &who,
                             DBUS_TYPE_STRING, &why,
                             DBUS_TYPE_STRING, &mode,
                             DBUS_TYPE_INVALID);

    pendingReply = NULL;
    if (dbus_connection_send_with_reply(systemBus, message,
                                        &pendingReply,
                                        25*1000)) {
        dbus_pending_call_set_notify(pendingReply,
                                     virNetServerGotInhibitReply,
                                     srv, NULL);
        srv->autoShutdownCallingInhibit = true;
    }
    dbus_message_unref(message);
}
#endif

void virNetServerAddShutdownInhibition(virNetServerPtr srv)
{
    virObjectLock(srv);
    srv->autoShutdownInhibitions++;

    VIR_DEBUG("srv=%p inhibitions=%zu", srv, srv->autoShutdownInhibitions);

#if defined(HAVE_DBUS) && defined(DBUS_TYPE_UNIX_FD)
    if (srv->autoShutdownInhibitions == 1)
        virNetServerCallInhibit(srv,
                                "shutdown",
                                _("Libvirt"),
                                _("Virtual machines need to be saved"),
                                "delay");
#endif

    virObjectUnlock(srv);
}


void virNetServerRemoveShutdownInhibition(virNetServerPtr srv)
{
    virObjectLock(srv);
    srv->autoShutdownInhibitions--;

    VIR_DEBUG("srv=%p inhibitions=%zu", srv, srv->autoShutdownInhibitions);

    if (srv->autoShutdownInhibitions == 0)
        VIR_FORCE_CLOSE(srv->autoShutdownInhibitFd);

    virObjectUnlock(srv);
}



static sig_atomic_t sigErrors = 0;
static int sigLastErrno = 0;
static int sigWrite = -1;

static void
virNetServerSignalHandler(int sig, siginfo_t * siginfo,
                          void* context ATTRIBUTE_UNUSED)
{
    int origerrno;
    int r;
    siginfo_t tmp;

    if (SA_SIGINFO)
        tmp = *siginfo;
    else
        memset(&tmp, 0, sizeof(tmp));

    /* set the sig num in the struct */
    tmp.si_signo = sig;

    origerrno = errno;
    r = safewrite(sigWrite, &tmp, sizeof(tmp));
    if (r == -1) {
        sigErrors++;
        sigLastErrno = errno;
    }
    errno = origerrno;
}

static void
virNetServerSignalEvent(int watch,
                        int fd ATTRIBUTE_UNUSED,
                        int events ATTRIBUTE_UNUSED,
                        void *opaque)
{
    virNetServerPtr srv = opaque;
    siginfo_t siginfo;
    size_t i;

    virObjectLock(srv);

    if (saferead(srv->sigread, &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
        virReportSystemError(errno, "%s",
                             _("Failed to read from signal pipe"));
        virEventRemoveHandle(watch);
        srv->sigwatch = -1;
        goto cleanup;
    }

    for (i = 0; i < srv->nsignals; i++) {
        if (siginfo.si_signo == srv->signals[i]->signum) {
            virNetServerSignalFunc func = srv->signals[i]->func;
            void *funcopaque = srv->signals[i]->opaque;
            virObjectUnlock(srv);
            func(srv, &siginfo, funcopaque);
            return;
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unexpected signal received: %d"), siginfo.si_signo);

 cleanup:
    virObjectUnlock(srv);
}

static int virNetServerSignalSetup(virNetServerPtr srv)
{
    int fds[2] = { -1, -1 };

    if (srv->sigwrite != -1)
        return 0;

    if (pipe2(fds, O_CLOEXEC|O_NONBLOCK) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create signal pipe"));
        return -1;
    }

    if ((srv->sigwatch = virEventAddHandle(fds[0],
                                           VIR_EVENT_HANDLE_READABLE,
                                           virNetServerSignalEvent,
                                           srv, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to add signal handle watch"));
        goto error;
    }

    srv->sigread = fds[0];
    srv->sigwrite = fds[1];
    sigWrite = fds[1];

    return 0;

 error:
    VIR_FORCE_CLOSE(fds[0]);
    VIR_FORCE_CLOSE(fds[1]);
    return -1;
}

int virNetServerAddSignalHandler(virNetServerPtr srv,
                                 int signum,
                                 virNetServerSignalFunc func,
                                 void *opaque)
{
    virNetServerSignalPtr sigdata = NULL;
    struct sigaction sig_action;

    virObjectLock(srv);

    if (virNetServerSignalSetup(srv) < 0)
        goto error;

    if (VIR_EXPAND_N(srv->signals, srv->nsignals, 1) < 0)
        goto error;

    if (VIR_ALLOC(sigdata) < 0)
        goto error;

    sigdata->signum = signum;
    sigdata->func = func;
    sigdata->opaque = opaque;

    memset(&sig_action, 0, sizeof(sig_action));
    sig_action.sa_sigaction = virNetServerSignalHandler;
    sig_action.sa_flags = SA_SIGINFO;
    sigemptyset(&sig_action.sa_mask);

    sigaction(signum, &sig_action, &sigdata->oldaction);

    srv->signals[srv->nsignals-1] = sigdata;

    virObjectUnlock(srv);
    return 0;

 error:
    VIR_FREE(sigdata);
    virObjectUnlock(srv);
    return -1;
}



int virNetServerAddService(virNetServerPtr srv,
                           virNetServerServicePtr svc,
                           const char *mdnsEntryName)
{
    virObjectLock(srv);

    if (VIR_EXPAND_N(srv->services, srv->nservices, 1) < 0)
        goto error;

    if (mdnsEntryName) {
        int port = virNetServerServiceGetPort(svc);

        if (!virNetServerMDNSAddEntry(srv->mdnsGroup,
                                      mdnsEntryName,
                                      port))
            goto error;
    }

    srv->services[srv->nservices-1] = svc;
    virObjectRef(svc);

    virNetServerServiceSetDispatcher(svc,
                                     virNetServerDispatchNewClient,
                                     srv);

    virObjectUnlock(srv);
    return 0;

 error:
    virObjectUnlock(srv);
    return -1;
}

int virNetServerAddProgram(virNetServerPtr srv,
                           virNetServerProgramPtr prog)
{
    virObjectLock(srv);

    if (VIR_EXPAND_N(srv->programs, srv->nprograms, 1) < 0)
        goto error;

    srv->programs[srv->nprograms-1] = virObjectRef(prog);

    virObjectUnlock(srv);
    return 0;

 error:
    virObjectUnlock(srv);
    return -1;
}

#if WITH_GNUTLS
int virNetServerSetTLSContext(virNetServerPtr srv,
                              virNetTLSContextPtr tls)
{
    srv->tls = virObjectRef(tls);
    return 0;
}
#endif


static void virNetServerAutoShutdownTimer(int timerid ATTRIBUTE_UNUSED,
                                          void *opaque)
{
    virNetServerPtr srv = opaque;

    virObjectLock(srv);

    if (!srv->autoShutdownInhibitions) {
        VIR_DEBUG("Automatic shutdown triggered");
        srv->quit = true;
    }

    virObjectUnlock(srv);
}


static void
virNetServerUpdateServicesLocked(virNetServerPtr srv,
                                 bool enabled)
{
    size_t i;

    for (i = 0; i < srv->nservices; i++)
        virNetServerServiceToggle(srv->services[i], enabled);
}


void virNetServerUpdateServices(virNetServerPtr srv,
                                bool enabled)
{
    virObjectLock(srv);
    virNetServerUpdateServicesLocked(srv, enabled);
    virObjectUnlock(srv);
}

/**
 * virNetServerCheckLimits:
 * @srv: server to check limits on
 *
 * Check if limits like max_clients or max_anonymous_clients
 * are satisfied and if so, re-enable accepting new clients.
 * The @srv must be locked when this function is called.
 */
static void
virNetServerCheckLimits(virNetServerPtr srv)
{
    /* Enable services if we can accept a new client.
     * The new client can be accepted if both max_clients and
     * max_anonymous_clients wouldn't get overcommitted by
     * accepting it. */
    VIR_DEBUG("Considering re-enabling services: "
              "nclients=%zu nclients_max=%zu "
              "nclients_unauth=%zu nclients_unauth_max=%zu",
              srv->nclients, srv->nclients_max,
              srv->nclients_unauth, srv->nclients_unauth_max);
    if (srv->nclients < srv->nclients_max &&
        (!srv->nclients_unauth_max ||
         srv->nclients_unauth < srv->nclients_unauth_max)) {
        /* Now it makes sense to accept() a new client. */
        VIR_DEBUG("Re-enabling services");
        virNetServerUpdateServicesLocked(srv, true);
    }
}

void virNetServerRun(virNetServerPtr srv)
{
    int timerid = -1;
    bool timerActive = false;
    size_t i;

    virObjectLock(srv);

    if (srv->mdns &&
        virNetServerMDNSStart(srv->mdns) < 0)
        goto cleanup;

    srv->quit = false;

    if (srv->autoShutdownTimeout &&
        (timerid = virEventAddTimeout(-1,
                                      virNetServerAutoShutdownTimer,
                                      srv, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to register shutdown timeout"));
        goto cleanup;
    }

    /* We are accepting connections now. Notify systemd
     * so it can start dependent services. */
    virSystemdNotifyStartup();

    VIR_DEBUG("srv=%p quit=%d", srv, srv->quit);
    while (!srv->quit) {
        /* A shutdown timeout is specified, so check
         * if any drivers have active state, if not
         * shutdown after timeout seconds
         */
        if (srv->autoShutdownTimeout) {
            if (timerActive) {
                if (srv->clients) {
                    VIR_DEBUG("Deactivating shutdown timer %d", timerid);
                    virEventUpdateTimeout(timerid, -1);
                    timerActive = false;
                }
            } else {
                if (!srv->clients) {
                    VIR_DEBUG("Activating shutdown timer %d", timerid);
                    virEventUpdateTimeout(timerid,
                                          srv->autoShutdownTimeout * 1000);
                    timerActive = true;
                }
            }
        }

        virObjectUnlock(srv);
        if (virEventRunDefaultImpl() < 0) {
            virObjectLock(srv);
            VIR_DEBUG("Loop iteration error, exiting");
            break;
        }
        virObjectLock(srv);

    reprocess:
        for (i = 0; i < srv->nclients; i++) {
            /* Coverity 5.3.0 couldn't see that srv->clients is non-NULL
             * if srv->nclients is non-zero.  */
            sa_assert(srv->clients);
            if (virNetServerClientWantClose(srv->clients[i]))
                virNetServerClientClose(srv->clients[i]);
            if (virNetServerClientIsClosed(srv->clients[i])) {
                virNetServerClientPtr client = srv->clients[i];

                VIR_DELETE_ELEMENT(srv->clients, i, srv->nclients);

                if (virNetServerClientNeedAuth(client))
                    virNetServerTrackCompletedAuthLocked(srv);

                virNetServerCheckLimits(srv);

                virObjectUnlock(srv);
                virObjectUnref(client);
                virObjectLock(srv);

                goto reprocess;
            }
        }
    }

 cleanup:
    virObjectUnlock(srv);
}


void virNetServerQuit(virNetServerPtr srv)
{
    virObjectLock(srv);

    VIR_DEBUG("Quit requested %p", srv);
    srv->quit = true;

    virObjectUnlock(srv);
}

void virNetServerDispose(void *obj)
{
    virNetServerPtr srv = obj;
    size_t i;

    VIR_FORCE_CLOSE(srv->autoShutdownInhibitFd);

    for (i = 0; i < srv->nservices; i++)
        virNetServerServiceToggle(srv->services[i], false);

    virThreadPoolFree(srv->workers);

    for (i = 0; i < srv->nsignals; i++) {
        sigaction(srv->signals[i]->signum, &srv->signals[i]->oldaction, NULL);
        VIR_FREE(srv->signals[i]);
    }
    VIR_FREE(srv->signals);
    VIR_FORCE_CLOSE(srv->sigread);
    VIR_FORCE_CLOSE(srv->sigwrite);
    if (srv->sigwatch > 0)
        virEventRemoveHandle(srv->sigwatch);

    for (i = 0; i < srv->nservices; i++)
        virObjectUnref(srv->services[i]);
    VIR_FREE(srv->services);

    for (i = 0; i < srv->nprograms; i++)
        virObjectUnref(srv->programs[i]);
    VIR_FREE(srv->programs);

    for (i = 0; i < srv->nclients; i++) {
        virNetServerClientClose(srv->clients[i]);
        virObjectUnref(srv->clients[i]);
    }
    VIR_FREE(srv->clients);

    VIR_FREE(srv->mdnsGroupName);
    virNetServerMDNSFree(srv->mdns);
}

void virNetServerClose(virNetServerPtr srv)
{
    size_t i;

    if (!srv)
        return;

    virObjectLock(srv);

    for (i = 0; i < srv->nservices; i++) {
        virNetServerServiceClose(srv->services[i]);
    }

    virObjectUnlock(srv);
}

bool virNetServerKeepAliveRequired(virNetServerPtr srv)
{
    bool required;
    virObjectLock(srv);
    required = srv->keepaliveRequired;
    virObjectUnlock(srv);
    return required;
}

static inline size_t
virNetServerTrackPendingAuthLocked(virNetServerPtr srv)
{
    return ++srv->nclients_unauth;
}

static inline size_t
virNetServerTrackCompletedAuthLocked(virNetServerPtr srv)
{
    return --srv->nclients_unauth;
}

size_t virNetServerTrackPendingAuth(virNetServerPtr srv)
{
    size_t ret;
    virObjectLock(srv);
    ret = virNetServerTrackPendingAuthLocked(srv);
    virObjectUnlock(srv);
    return ret;
}

size_t virNetServerTrackCompletedAuth(virNetServerPtr srv)
{
    size_t ret;
    virObjectLock(srv);
    ret = virNetServerTrackCompletedAuthLocked(srv);
    virNetServerCheckLimits(srv);
    virObjectUnlock(srv);
    return ret;
}
