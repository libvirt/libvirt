/*
 * virnetserver.c: generic network RPC server
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "virnetserver.h"
#include "logging.h"
#include "memory.h"
#include "virterror_internal.h"
#include "threads.h"
#include "threadpool.h"
#include "util.h"
#include "virfile.h"
#include "event.h"
#if HAVE_AVAHI
# include "virnetservermdns.h"
#endif
#if HAVE_DBUS
# include <dbus/dbus.h>
#endif

#define VIR_FROM_THIS VIR_FROM_RPC
#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

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
    int refs;

    virMutex lock;

    virThreadPoolPtr workers;

    bool privileged;

    size_t nsignals;
    virNetServerSignalPtr *signals;
    int sigread;
    int sigwrite;
    int sigwatch;

    char *mdnsGroupName;
#if HAVE_AVAHI
    virNetServerMDNSPtr mdns;
    virNetServerMDNSGroupPtr mdnsGroup;
#endif

#if HAVE_DBUS
    DBusConnection *sysbus;
#endif

    size_t nservices;
    virNetServerServicePtr *services;

    size_t nprograms;
    virNetServerProgramPtr *programs;

    size_t nclients;
    size_t nclients_max;
    virNetServerClientPtr *clients;

    int keepaliveInterval;
    unsigned int keepaliveCount;
    bool keepaliveRequired;

    unsigned int quit :1;

    virNetTLSContextPtr tls;

    unsigned int autoShutdownTimeout;
    virNetServerAutoShutdownFunc autoShutdownFunc;
    void *autoShutdownOpaque;

    virNetServerClientInitHook clientInitHook;
};


static void virNetServerLock(virNetServerPtr srv)
{
    virMutexLock(&srv->lock);
}

static void virNetServerUnlock(virNetServerPtr srv)
{
    virMutexUnlock(&srv->lock);
}


static void virNetServerHandleJob(void *jobOpaque, void *opaque)
{
    virNetServerPtr srv = opaque;
    virNetServerJobPtr job = jobOpaque;

    VIR_DEBUG("server=%p client=%p message=%p prog=%p",
              srv, job->client, job->msg, job->prog);

    if (!job->prog) {
        /* Only send back an error for type == CALL. Other
         * message types are not expecting replies, so we
         * must just log it & drop them
         */
        if (job->msg->header.type == VIR_NET_CALL ||
            job->msg->header.type == VIR_NET_CALL_WITH_FDS) {
            if (virNetServerProgramUnknownError(job->client,
                                                job->msg,
                                                &job->msg->header) < 0)
                goto error;
        } else {
            VIR_INFO("Dropping client mesage, unknown program %d version %d type %d proc %d",
                     job->msg->header.prog, job->msg->header.vers,
                     job->msg->header.type, job->msg->header.proc);
            /* Send a dummy reply to free up 'msg' & unblock client rx */
            virNetMessageClear(job->msg);
            job->msg->header.type = VIR_NET_REPLY;
            if (virNetServerClientSendMessage(job->client, job->msg) < 0)
                goto error;
        }
        goto cleanup;
    }

    if (virNetServerProgramDispatch(job->prog,
                                    srv,
                                    job->client,
                                    job->msg) < 0)
        goto error;

    virNetServerLock(srv);
    virNetServerProgramFree(job->prog);
    virNetServerUnlock(srv);

cleanup:
    virNetServerClientFree(job->client);
    VIR_FREE(job);
    return;

error:
    virNetServerProgramFree(job->prog);
    virNetMessageFree(job->msg);
    virNetServerClientClose(job->client);
    virNetServerClientFree(job->client);
    VIR_FREE(job);
}

static int virNetServerDispatchNewMessage(virNetServerClientPtr client,
                                          virNetMessagePtr msg,
                                          void *opaque)
{
    virNetServerPtr srv = opaque;
    virNetServerJobPtr job;
    virNetServerProgramPtr prog = NULL;
    unsigned int priority = 0;
    size_t i;
    int ret = -1;

    VIR_DEBUG("server=%p client=%p message=%p",
              srv, client, msg);

    if (VIR_ALLOC(job) < 0) {
        virReportOOMError();
        return -1;
    }

    job->client = client;
    job->msg = msg;

    virNetServerLock(srv);
    for (i = 0 ; i < srv->nprograms ; i++) {
        if (virNetServerProgramMatches(srv->programs[i], job->msg)) {
            prog = srv->programs[i];
            break;
        }
    }

    if (prog) {
        virNetServerProgramRef(prog);
        job->prog = prog;
        priority = virNetServerProgramGetPriority(prog, msg->header.proc);
    }

    ret = virThreadPoolSendJob(srv->workers, priority, job);

    if (ret < 0) {
        VIR_FREE(job);
        virNetServerProgramFree(prog);
    }
    virNetServerUnlock(srv);

    return ret;
}


static int virNetServerDispatchNewClient(virNetServerServicePtr svc ATTRIBUTE_UNUSED,
                                         virNetServerClientPtr client,
                                         void *opaque)
{
    virNetServerPtr srv = opaque;

    virNetServerLock(srv);

    if (srv->nclients >= srv->nclients_max) {
        virNetError(VIR_ERR_RPC,
                    _("Too many active clients (%zu), dropping connection from %s"),
                    srv->nclients_max, virNetServerClientRemoteAddrString(client));
        goto error;
    }

    if (virNetServerClientInit(client) < 0)
        goto error;

    if (srv->clientInitHook &&
        srv->clientInitHook(srv, client) < 0)
        goto error;

    if (VIR_EXPAND_N(srv->clients, srv->nclients, 1) < 0) {
        virReportOOMError();
        goto error;
    }
    srv->clients[srv->nclients-1] = client;
    virNetServerClientRef(client);

    virNetServerClientSetDispatcher(client,
                                    virNetServerDispatchNewMessage,
                                    srv);

    virNetServerClientInitKeepAlive(client, srv->keepaliveInterval,
                                    srv->keepaliveCount);

    virNetServerUnlock(srv);
    return 0;

error:
    virNetServerUnlock(srv);
    return -1;
}


static void virNetServerFatalSignal(int sig, siginfo_t *siginfo ATTRIBUTE_UNUSED,
                                    void *context ATTRIBUTE_UNUSED)
{
    struct sigaction sig_action;
    int origerrno;

    origerrno = errno;
    virLogEmergencyDumpAll(sig);

    /*
     * If the signal is fatal, avoid looping over this handler
     * by deactivating it
     */
#ifdef SIGUSR2
    if (sig != SIGUSR2) {
#endif
        sig_action.sa_handler = SIG_DFL;
        sigaction(sig, &sig_action, NULL);
        raise(sig);
#ifdef SIGUSR2
    }
#endif
    errno = origerrno;
}


virNetServerPtr virNetServerNew(size_t min_workers,
                                size_t max_workers,
                                size_t priority_workers,
                                size_t max_clients,
                                int keepaliveInterval,
                                unsigned int keepaliveCount,
                                bool keepaliveRequired,
                                const char *mdnsGroupName,
                                bool connectDBus ATTRIBUTE_UNUSED,
                                virNetServerClientInitHook clientInitHook)
{
    virNetServerPtr srv;
    struct sigaction sig_action;

    if (VIR_ALLOC(srv) < 0) {
        virReportOOMError();
        return NULL;
    }

    srv->refs = 1;

    if (!(srv->workers = virThreadPoolNew(min_workers, max_workers,
                                          priority_workers,
                                          virNetServerHandleJob,
                                          srv)))
        goto error;

    srv->nclients_max = max_clients;
    srv->keepaliveInterval = keepaliveInterval;
    srv->keepaliveCount = keepaliveCount;
    srv->keepaliveRequired = keepaliveRequired;
    srv->sigwrite = srv->sigread = -1;
    srv->clientInitHook = clientInitHook;
    srv->privileged = geteuid() == 0 ? true : false;

    if (mdnsGroupName &&
        !(srv->mdnsGroupName = strdup(mdnsGroupName))) {
        virReportOOMError();
        goto error;
    }
#if HAVE_AVAHI
    if (srv->mdnsGroupName) {
        if (!(srv->mdns = virNetServerMDNSNew()))
            goto error;
        if (!(srv->mdnsGroup = virNetServerMDNSAddGroup(srv->mdns,
                                                        srv->mdnsGroupName)))
            goto error;
    }
#endif

#if HAVE_DBUS
    if (connectDBus) {
        DBusError derr;

        dbus_connection_set_change_sigpipe(FALSE);
        dbus_threads_init_default();

        dbus_error_init(&derr);
        srv->sysbus = dbus_bus_get(DBUS_BUS_SYSTEM, &derr);
        if (!(srv->sysbus)) {
            VIR_ERROR(_("Failed to connect to system bus for PolicyKit auth: %s"),
                      derr.message);
            dbus_error_free(&derr);
            goto error;
        }
        dbus_connection_set_exit_on_disconnect(srv->sysbus, FALSE);
    }
#endif

    if (virMutexInit(&srv->lock) < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("cannot initialize mutex"));
        goto error;
    }

    if (virEventRegisterDefaultImpl() < 0)
        goto error;

    memset(&sig_action, 0, sizeof(sig_action));
    sig_action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig_action, NULL);

    /*
     * catch fatal errors to dump a log, also hook to USR2 for dynamic
     * debugging purposes or testing
     */
    sig_action.sa_sigaction = virNetServerFatalSignal;
    sigaction(SIGFPE, &sig_action, NULL);
    sigaction(SIGSEGV, &sig_action, NULL);
    sigaction(SIGILL, &sig_action, NULL);
    sigaction(SIGABRT, &sig_action, NULL);
#ifdef SIGBUS
    sigaction(SIGBUS, &sig_action, NULL);
#endif
#ifdef SIGUSR2
    sigaction(SIGUSR2, &sig_action, NULL);
#endif

    VIR_DEBUG("srv=%p refs=%d", srv, srv->refs);
    return srv;

error:
    virNetServerFree(srv);
    return NULL;
}


void virNetServerRef(virNetServerPtr srv)
{
    virNetServerLock(srv);
    srv->refs++;
    VIR_DEBUG("srv=%p refs=%d", srv, srv->refs);
    virNetServerUnlock(srv);
}


bool virNetServerIsPrivileged(virNetServerPtr srv)
{
    bool priv;
    virNetServerLock(srv);
    priv = srv->privileged;
    virNetServerUnlock(srv);
    return priv;
}


#if HAVE_DBUS
DBusConnection* virNetServerGetDBusConn(virNetServerPtr srv)
{
    return srv->sysbus;
}
#endif


void virNetServerAutoShutdown(virNetServerPtr srv,
                              unsigned int timeout,
                              virNetServerAutoShutdownFunc func,
                              void *opaque)
{
    virNetServerLock(srv);

    srv->autoShutdownTimeout = timeout;
    srv->autoShutdownFunc = func;
    srv->autoShutdownOpaque = opaque;

    virNetServerUnlock(srv);
}

static sig_atomic_t sigErrors = 0;
static int sigLastErrno = 0;
static int sigWrite = -1;

static void virNetServerSignalHandler(int sig, siginfo_t * siginfo,
                                      void* context ATTRIBUTE_UNUSED)
{
    int origerrno;
    int r;

    /* set the sig num in the struct */
    siginfo->si_signo = sig;

    origerrno = errno;
    r = safewrite(sigWrite, siginfo, sizeof(*siginfo));
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
                        void *opaque) {
    virNetServerPtr srv = opaque;
    siginfo_t siginfo;
    int i;

    virNetServerLock(srv);

    if (saferead(srv->sigread, &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
        virReportSystemError(errno, "%s",
                             _("Failed to read from signal pipe"));
        virEventRemoveHandle(watch);
        srv->sigwatch = -1;
        goto cleanup;
    }

    for (i = 0 ; i < srv->nsignals ; i++) {
        if (siginfo.si_signo == srv->signals[i]->signum) {
            virNetServerSignalFunc func = srv->signals[i]->func;
            void *funcopaque = srv->signals[i]->opaque;
            virNetServerUnlock(srv);
            func(srv, &siginfo, funcopaque);
            return;
        }
    }

    virNetError(VIR_ERR_INTERNAL_ERROR,
                _("Unexpected signal received: %d"), siginfo.si_signo);

cleanup:
    virNetServerUnlock(srv);
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
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
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
    virNetServerSignalPtr sigdata;
    struct sigaction sig_action;

    virNetServerLock(srv);

    if (virNetServerSignalSetup(srv) < 0)
        goto error;

    if (VIR_EXPAND_N(srv->signals, srv->nsignals, 1) < 0)
        goto no_memory;

    if (VIR_ALLOC(sigdata) < 0)
        goto no_memory;

    sigdata->signum = signum;
    sigdata->func = func;
    sigdata->opaque = opaque;

    memset(&sig_action, 0, sizeof(sig_action));
    sig_action.sa_sigaction = virNetServerSignalHandler;
#ifdef SA_SIGINFO
    sig_action.sa_flags = SA_SIGINFO;
#endif
    sigemptyset(&sig_action.sa_mask);

    sigaction(signum, &sig_action, &sigdata->oldaction);

    srv->signals[srv->nsignals-1] = sigdata;

    virNetServerUnlock(srv);
    return 0;

no_memory:
    virReportOOMError();
error:
    VIR_FREE(sigdata);
    virNetServerUnlock(srv);
    return -1;
}



int virNetServerAddService(virNetServerPtr srv,
                           virNetServerServicePtr svc,
                           const char *mdnsEntryName ATTRIBUTE_UNUSED)
{
    virNetServerLock(srv);

    if (VIR_EXPAND_N(srv->services, srv->nservices, 1) < 0)
        goto no_memory;

#if HAVE_AVAHI
    if (mdnsEntryName) {
        int port = virNetServerServiceGetPort(svc);

        if (!virNetServerMDNSAddEntry(srv->mdnsGroup,
                                      mdnsEntryName,
                                      port))
            goto error;
    }
#endif

    srv->services[srv->nservices-1] = svc;
    virNetServerServiceRef(svc);

    virNetServerServiceSetDispatcher(svc,
                                     virNetServerDispatchNewClient,
                                     srv);

    virNetServerUnlock(srv);
    return 0;

no_memory:
    virReportOOMError();
#if HAVE_AVAHI
error:
#endif
    virNetServerUnlock(srv);
    return -1;
}

int virNetServerAddProgram(virNetServerPtr srv,
                           virNetServerProgramPtr prog)
{
    virNetServerLock(srv);

    if (VIR_EXPAND_N(srv->programs, srv->nprograms, 1) < 0)
        goto no_memory;

    srv->programs[srv->nprograms-1] = prog;
    virNetServerProgramRef(prog);

    virNetServerUnlock(srv);
    return 0;

no_memory:
    virReportOOMError();
    virNetServerUnlock(srv);
    return -1;
}

int virNetServerSetTLSContext(virNetServerPtr srv,
                              virNetTLSContextPtr tls)
{
    srv->tls = tls;
    virNetTLSContextRef(tls);
    return 0;
}


static void virNetServerAutoShutdownTimer(int timerid ATTRIBUTE_UNUSED,
                                          void *opaque) {
    virNetServerPtr srv = opaque;

    virNetServerLock(srv);

    if (srv->autoShutdownFunc(srv, srv->autoShutdownOpaque)) {
        VIR_DEBUG("Automatic shutdown triggered");
        srv->quit = 1;
    }

    virNetServerUnlock(srv);
}


void virNetServerUpdateServices(virNetServerPtr srv,
                                bool enabled)
{
    int i;

    virNetServerLock(srv);
    for (i = 0 ; i < srv->nservices ; i++)
        virNetServerServiceToggle(srv->services[i], enabled);

    virNetServerUnlock(srv);
}


void virNetServerRun(virNetServerPtr srv)
{
    int timerid = -1;
    int timerActive = 0;
    int i;

    virNetServerLock(srv);

#if HAVE_AVAHI
    if (srv->mdns &&
        virNetServerMDNSStart(srv->mdns) < 0)
        goto cleanup;
#endif

    if (srv->autoShutdownTimeout &&
        (timerid = virEventAddTimeout(-1,
                                      virNetServerAutoShutdownTimer,
                                      srv, NULL)) < 0) {
        virNetError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("Failed to register shutdown timeout"));
        goto cleanup;
    }

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
                    timerActive = 0;
                }
            } else {
                if (!srv->clients) {
                    VIR_DEBUG("Activating shutdown timer %d", timerid);
                    virEventUpdateTimeout(timerid,
                                          srv->autoShutdownTimeout * 1000);
                    timerActive = 1;
                }
            }
        }

        virNetServerUnlock(srv);
        if (virEventRunDefaultImpl() < 0) {
            virNetServerLock(srv);
            VIR_DEBUG("Loop iteration error, exiting");
            break;
        }
        virNetServerLock(srv);

    reprocess:
        for (i = 0 ; i < srv->nclients ; i++) {
            /* Coverity 5.3.0 couldn't see that srv->clients is non-NULL
             * if srv->nclients is non-zero.  */
            sa_assert(srv->clients);
            if (virNetServerClientWantClose(srv->clients[i]))
                virNetServerClientClose(srv->clients[i]);
            if (virNetServerClientIsClosed(srv->clients[i])) {
                virNetServerClientFree(srv->clients[i]);
                if (srv->nclients > 1) {
                    memmove(srv->clients + i,
                            srv->clients + i + 1,
                            sizeof(*srv->clients) * (srv->nclients - (i + 1)));
                    VIR_SHRINK_N(srv->clients, srv->nclients, 1);
                } else {
                    VIR_FREE(srv->clients);
                    srv->nclients = 0;
                }

                goto reprocess;
            }
        }
    }

cleanup:
    virNetServerUnlock(srv);
}


void virNetServerQuit(virNetServerPtr srv)
{
    virNetServerLock(srv);

    VIR_DEBUG("Quit requested %p", srv);
    srv->quit = 1;

    virNetServerUnlock(srv);
}

void virNetServerFree(virNetServerPtr srv)
{
    int i;

    if (!srv)
        return;

    virNetServerLock(srv);
    VIR_DEBUG("srv=%p refs=%d", srv, srv->refs);
    srv->refs--;
    if (srv->refs > 0) {
        virNetServerUnlock(srv);
        return;
    }

    for (i = 0 ; i < srv->nservices ; i++)
        virNetServerServiceToggle(srv->services[i], false);

    virThreadPoolFree(srv->workers);

    for (i = 0 ; i < srv->nsignals ; i++) {
        sigaction(srv->signals[i]->signum, &srv->signals[i]->oldaction, NULL);
        VIR_FREE(srv->signals[i]);
    }
    VIR_FREE(srv->signals);
    VIR_FORCE_CLOSE(srv->sigread);
    VIR_FORCE_CLOSE(srv->sigwrite);
    if (srv->sigwatch > 0)
        virEventRemoveHandle(srv->sigwatch);

    for (i = 0 ; i < srv->nservices ; i++)
        virNetServerServiceFree(srv->services[i]);
    VIR_FREE(srv->services);

    for (i = 0 ; i < srv->nprograms ; i++)
        virNetServerProgramFree(srv->programs[i]);
    VIR_FREE(srv->programs);

    for (i = 0 ; i < srv->nclients ; i++) {
        virNetServerClientClose(srv->clients[i]);
        virNetServerClientFree(srv->clients[i]);
    }
    VIR_FREE(srv->clients);

    VIR_FREE(srv->mdnsGroupName);
#if HAVE_AVAHI
    virNetServerMDNSFree(srv->mdns);
#endif

#if HAVE_DBUS
    if (srv->sysbus)
        dbus_connection_unref(srv->sysbus);
#endif

    virNetServerUnlock(srv);
    virMutexDestroy(&srv->lock);
    VIR_FREE(srv);
}

void virNetServerClose(virNetServerPtr srv)
{
    int i;

    if (!srv)
        return;

    virNetServerLock(srv);

    for (i = 0; i < srv->nservices; i++) {
        virNetServerServiceClose(srv->services[i]);
    }

    virNetServerUnlock(srv);
}

bool virNetServerKeepAliveRequired(virNetServerPtr srv)
{
    bool required;
    virNetServerLock(srv);
    required = srv->keepaliveRequired;
    virNetServerUnlock(srv);
    return required;
}
