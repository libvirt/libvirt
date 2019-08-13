/*
 * virnetdaemon.c
 *
 * Copyright (C) 2015 Red Hat, Inc.
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

#include <unistd.h>
#include <fcntl.h>

#include "virnetdaemon.h"
#include "virlog.h"
#include "viralloc.h"
#include "virerror.h"
#include "virthread.h"
#include "virthreadpool.h"
#include "virutil.h"
#include "virfile.h"
#include "virnetserver.h"
#include "virdbus.h"
#include "virhash.h"
#include "virstring.h"
#include "virsystemd.h"

#ifndef SA_SIGINFO
# define SA_SIGINFO 0
#endif

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netdaemon");

typedef struct _virNetDaemonSignal virNetDaemonSignal;
typedef virNetDaemonSignal *virNetDaemonSignalPtr;

struct _virNetDaemonSignal {
    struct sigaction oldaction;
    int signum;
    virNetDaemonSignalFunc func;
    void *opaque;
};

struct _virNetDaemon {
    virObjectLockable parent;

    bool privileged;

    size_t nsignals;
    virNetDaemonSignalPtr *signals;
    int sigread;
    int sigwrite;
    int sigwatch;

    virHashTablePtr servers;
    virJSONValuePtr srvObject;

    bool quit;

    unsigned int autoShutdownTimeout;
    size_t autoShutdownInhibitions;
    bool autoShutdownCallingInhibit;
    int autoShutdownInhibitFd;
};


static virClassPtr virNetDaemonClass;

static void
virNetDaemonDispose(void *obj)
{
    virNetDaemonPtr dmn = obj;
    size_t i;

    VIR_FORCE_CLOSE(dmn->autoShutdownInhibitFd);

    for (i = 0; i < dmn->nsignals; i++) {
        sigaction(dmn->signals[i]->signum, &dmn->signals[i]->oldaction, NULL);
        VIR_FREE(dmn->signals[i]);
    }
    VIR_FREE(dmn->signals);
    VIR_FORCE_CLOSE(dmn->sigread);
    VIR_FORCE_CLOSE(dmn->sigwrite);
    if (dmn->sigwatch > 0)
        virEventRemoveHandle(dmn->sigwatch);

    virHashFree(dmn->servers);

    virJSONValueFree(dmn->srvObject);
}

static int
virNetDaemonOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetDaemon, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetDaemon);


virNetDaemonPtr
virNetDaemonNew(void)
{
    virNetDaemonPtr dmn;
    struct sigaction sig_action;

    if (virNetDaemonInitialize() < 0)
        return NULL;

    if (!(dmn = virObjectLockableNew(virNetDaemonClass)))
        return NULL;

    if (!(dmn->servers = virHashCreate(5, virObjectFreeHashData)))
        goto error;

    dmn->sigwrite = dmn->sigread = -1;
    dmn->privileged = geteuid() == 0;
    dmn->autoShutdownInhibitFd = -1;

    if (virEventRegisterDefaultImpl() < 0)
        goto error;

    memset(&sig_action, 0, sizeof(sig_action));
    sig_action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig_action, NULL);

    return dmn;

 error:
    virObjectUnref(dmn);
    return NULL;
}


int
virNetDaemonAddServer(virNetDaemonPtr dmn,
                      virNetServerPtr srv)
{
    int ret = -1;
    const char *serverName = virNetServerGetName(srv);

    virObjectLock(dmn);

    if (virHashAddEntry(dmn->servers, serverName, srv) < 0)
        goto cleanup;

    virObjectRef(srv);

    ret = 0;
 cleanup:
    virObjectUnlock(dmn);
    return ret;
}


virNetServerPtr
virNetDaemonGetServer(virNetDaemonPtr dmn,
                      const char *serverName)
{
    virNetServerPtr srv = NULL;

    virObjectLock(dmn);
    srv = virObjectRef(virHashLookup(dmn->servers, serverName));
    virObjectUnlock(dmn);

    if (!srv) {
        virReportError(VIR_ERR_NO_SERVER,
                       _("No server named '%s'"), serverName);
    }

    return srv;
}

bool
virNetDaemonHasServer(virNetDaemonPtr dmn,
                      const char *serverName)
{
    void *ent;

    virObjectLock(dmn);
    ent = virHashLookup(dmn->servers, serverName);
    virObjectUnlock(dmn);

    return ent != NULL;
}


struct collectData {
    virNetServerPtr **servers;
    size_t nservers;
};


static int
collectServers(void *payload,
               const void *name ATTRIBUTE_UNUSED,
               void *opaque)
{
    virNetServerPtr srv = virObjectRef(payload);
    struct collectData *data = opaque;

    if (!srv)
        return -1;

    return VIR_APPEND_ELEMENT(*data->servers, data->nservers, srv);
}


/*
 * Returns number of names allocated in *servers, on error sets
 * *servers to NULL and returns -1.  List of *servers must be free()d,
 * but not the items in it (similarly to virHashGetItems).
 */
ssize_t
virNetDaemonGetServers(virNetDaemonPtr dmn,
                       virNetServerPtr **servers)
{
    struct collectData data = { servers, 0 };
    ssize_t ret = -1;

    *servers = NULL;

    virObjectLock(dmn);

    if (virHashForEach(dmn->servers, collectServers, &data) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot get all servers from daemon"));
        goto cleanup;
    }

    ret = data.nservers;

 cleanup:
    if (ret < 0)
        virObjectListFreeCount(*servers, data.nservers);
    virObjectUnlock(dmn);
    return ret;
}


struct virNetDaemonServerData {
    virNetDaemonPtr dmn;
    virNetDaemonNewServerPostExecRestart cb;
    void *opaque;
};

static int
virNetDaemonServerIterator(const char *key,
                           virJSONValuePtr value,
                           void *opaque)
{
    struct virNetDaemonServerData *data = opaque;
    virNetServerPtr srv;

    VIR_DEBUG("Creating server '%s'", key);
    srv = data->cb(data->dmn, key, value, data->opaque);
    if (!srv)
        return -1;

    if (virHashAddEntry(data->dmn->servers, key, srv) < 0)
        return -1;

    return 0;
}


virNetDaemonPtr
virNetDaemonNewPostExecRestart(virJSONValuePtr object,
                               size_t nDefServerNames,
                               const char **defServerNames,
                               virNetDaemonNewServerPostExecRestart cb,
                               void *opaque)
{
    virNetDaemonPtr dmn = NULL;
    virJSONValuePtr servers = virJSONValueObjectGet(object, "servers");
    bool new_version = virJSONValueObjectHasKey(object, "servers");

    if (!(dmn = virNetDaemonNew()))
        goto error;

    if (new_version && !servers) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed servers data in JSON document"));
        goto error;
    }

    if (!new_version) {
        virNetServerPtr srv;

        if (nDefServerNames < 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("No default server names provided"));
            goto error;
        }

        VIR_DEBUG("No 'servers' data, creating default '%s' name", defServerNames[0]);

        srv = cb(dmn, defServerNames[0], object, opaque);

        if (virHashAddEntry(dmn->servers, defServerNames[0], srv) < 0)
            goto error;
    } else if (virJSONValueIsArray(servers)) {
        size_t i;
        size_t n = virJSONValueArraySize(servers);
        if (n > nDefServerNames) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Server count %zd greater than default name count %zu"),
                           n, nDefServerNames);
            goto error;
        }

        for (i = 0; i < n; i++) {
            virNetServerPtr srv;
            virJSONValuePtr value = virJSONValueArrayGet(servers, i);

            VIR_DEBUG("Creating server '%s'", defServerNames[i]);
            srv = cb(dmn, defServerNames[i], value, opaque);
            if (!srv)
                goto error;

            if (virHashAddEntry(dmn->servers, defServerNames[i], srv) < 0) {
                virObjectUnref(srv);
                goto error;
            }
        }
    } else {
        struct virNetDaemonServerData data = {
            dmn,
            cb,
            opaque,
        };
        if (virJSONValueObjectForeachKeyValue(servers,
                                              virNetDaemonServerIterator,
                                              &data) < 0)
            goto error;
    }

    return dmn;

 error:
    virObjectUnref(dmn);
    return NULL;
}


static int
daemonServerCompare(const virHashKeyValuePair *a, const virHashKeyValuePair *b)
{
    const char *as = a->key;
    const char *bs = b->key;

    return strcmp(as, bs);
}

virJSONValuePtr
virNetDaemonPreExecRestart(virNetDaemonPtr dmn)
{
    size_t i = 0;
    virJSONValuePtr object = NULL;
    virJSONValuePtr srvObj = NULL;
    virHashKeyValuePairPtr srvArray = NULL;

    virObjectLock(dmn);

    if (!(object = virJSONValueNewObject()))
        goto error;

    if (!(srvObj = virJSONValueNewObject()))
        goto error;

    if (virJSONValueObjectAppend(object, "servers", srvObj) < 0) {
        virJSONValueFree(srvObj);
        goto error;
    }

    if (!(srvArray = virHashGetItems(dmn->servers, daemonServerCompare)))
        goto error;

    for (i = 0; srvArray[i].key; i++) {
        virNetServerPtr server = virHashLookup(dmn->servers, srvArray[i].key);
        virJSONValuePtr srvJSON;

        if (!server)
            goto error;

        srvJSON = virNetServerPreExecRestart(server);
        if (!srvJSON)
            goto error;

        if (virJSONValueObjectAppend(srvObj, srvArray[i].key, srvJSON) < 0) {
            virJSONValueFree(srvJSON);
            goto error;
        }
    }

    VIR_FREE(srvArray);
    virObjectUnlock(dmn);

    return object;

 error:
    VIR_FREE(srvArray);
    virJSONValueFree(object);
    virObjectUnlock(dmn);
    return NULL;
}


bool
virNetDaemonIsPrivileged(virNetDaemonPtr dmn)
{
    bool priv;
    virObjectLock(dmn);
    priv = dmn->privileged;
    virObjectUnlock(dmn);
    return priv;
}


void
virNetDaemonAutoShutdown(virNetDaemonPtr dmn,
                         unsigned int timeout)
{
    virObjectLock(dmn);

    dmn->autoShutdownTimeout = timeout;

    virObjectUnlock(dmn);
}


#if defined(WITH_DBUS) && defined(DBUS_TYPE_UNIX_FD)
static void
virNetDaemonGotInhibitReplyLocked(DBusPendingCall *pending,
                                  virNetDaemonPtr dmn)
{
    DBusMessage *reply;
    int fd;

    dmn->autoShutdownCallingInhibit = false;

    VIR_DEBUG("dmn=%p", dmn);

    reply = dbus_pending_call_steal_reply(pending);
    if (reply == NULL)
        goto cleanup;

    if (dbus_message_get_args(reply, NULL,
                              DBUS_TYPE_UNIX_FD, &fd,
                              DBUS_TYPE_INVALID)) {
        if (dmn->autoShutdownInhibitions) {
            dmn->autoShutdownInhibitFd = fd;
            VIR_DEBUG("Got inhibit FD %d", fd);
        } else {
            /* We stopped the last VM since we made the inhibit call */
            VIR_DEBUG("Closing inhibit FD %d", fd);
            VIR_FORCE_CLOSE(fd);
        }
    }
    virDBusMessageUnref(reply);

 cleanup:
    dbus_pending_call_unref(pending);
}


static void
virNetDaemonGotInhibitReply(DBusPendingCall *pending,
                            void *opaque)
{
    virNetDaemonPtr dmn = opaque;

    virObjectLock(dmn);
    virNetDaemonGotInhibitReplyLocked(pending, dmn);
    virObjectUnlock(dmn);
}


/* As per: http://www.freedesktop.org/wiki/Software/systemd/inhibit */
static void
virNetDaemonCallInhibit(virNetDaemonPtr dmn,
                        const char *what,
                        const char *who,
                        const char *why,
                        const char *mode)
{
    DBusMessage *message;
    DBusPendingCall *pendingReply = NULL;
    DBusConnection *systemBus;

    VIR_DEBUG("dmn=%p what=%s who=%s why=%s mode=%s",
              dmn, NULLSTR(what), NULLSTR(who), NULLSTR(why), NULLSTR(mode));

    if (virSystemdHasLogind() < 0)
        return;

    if (!(systemBus = virDBusGetSystemBus()))
        return;

    /* Only one outstanding call at a time */
    if (dmn->autoShutdownCallingInhibit)
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

    if (dbus_connection_send_with_reply(systemBus, message,
                                        &pendingReply,
                                        25 * 1000) &&
        pendingReply) {
        if (dbus_pending_call_get_completed(pendingReply)) {
            virNetDaemonGotInhibitReplyLocked(pendingReply, dmn);
        } else {
            dbus_pending_call_set_notify(pendingReply,
                                         virNetDaemonGotInhibitReply,
                                         dmn, NULL);
        }
        dmn->autoShutdownCallingInhibit = true;
    }
    virDBusMessageUnref(message);
}
#endif

void
virNetDaemonAddShutdownInhibition(virNetDaemonPtr dmn)
{
    virObjectLock(dmn);
    dmn->autoShutdownInhibitions++;

    VIR_DEBUG("dmn=%p inhibitions=%zu", dmn, dmn->autoShutdownInhibitions);

#if defined(WITH_DBUS) && defined(DBUS_TYPE_UNIX_FD)
    if (dmn->autoShutdownInhibitions == 1)
        virNetDaemonCallInhibit(dmn,
                                "shutdown",
                                _("Libvirt"),
                                _("Virtual machines need to be saved"),
                                "delay");
#endif

    virObjectUnlock(dmn);
}


void
virNetDaemonRemoveShutdownInhibition(virNetDaemonPtr dmn)
{
    virObjectLock(dmn);
    dmn->autoShutdownInhibitions--;

    VIR_DEBUG("dmn=%p inhibitions=%zu", dmn, dmn->autoShutdownInhibitions);

    if (dmn->autoShutdownInhibitions == 0) {
        VIR_DEBUG("Closing inhibit FD %d", dmn->autoShutdownInhibitFd);
        VIR_FORCE_CLOSE(dmn->autoShutdownInhibitFd);
    }

    virObjectUnlock(dmn);
}



static sig_atomic_t sigErrors;
static int sigLastErrno;
static int sigWrite = -1;

static void
virNetDaemonSignalHandler(int sig, siginfo_t * siginfo,
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
virNetDaemonSignalEvent(int watch,
                        int fd ATTRIBUTE_UNUSED,
                        int events ATTRIBUTE_UNUSED,
                        void *opaque)
{
    virNetDaemonPtr dmn = opaque;
    siginfo_t siginfo;
    size_t i;

    virObjectLock(dmn);

    if (saferead(dmn->sigread, &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
        virReportSystemError(errno, "%s",
                             _("Failed to read from signal pipe"));
        virEventRemoveHandle(watch);
        dmn->sigwatch = -1;
        goto cleanup;
    }

    for (i = 0; i < dmn->nsignals; i++) {
        if (siginfo.si_signo == dmn->signals[i]->signum) {
            virNetDaemonSignalFunc func = dmn->signals[i]->func;
            void *funcopaque = dmn->signals[i]->opaque;
            virObjectUnlock(dmn);
            func(dmn, &siginfo, funcopaque);
            return;
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unexpected signal received: %d"), siginfo.si_signo);

 cleanup:
    virObjectUnlock(dmn);
}

static int
virNetDaemonSignalSetup(virNetDaemonPtr dmn)
{
    int fds[2] = { -1, -1 };

    if (dmn->sigwrite != -1)
        return 0;

    if (pipe2(fds, O_CLOEXEC|O_NONBLOCK) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create signal pipe"));
        return -1;
    }

    if ((dmn->sigwatch = virEventAddHandle(fds[0],
                                           VIR_EVENT_HANDLE_READABLE,
                                           virNetDaemonSignalEvent,
                                           dmn, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to add signal handle watch"));
        goto error;
    }

    dmn->sigread = fds[0];
    dmn->sigwrite = fds[1];
    sigWrite = fds[1];

    return 0;

 error:
    VIR_FORCE_CLOSE(fds[0]);
    VIR_FORCE_CLOSE(fds[1]);
    return -1;
}

int
virNetDaemonAddSignalHandler(virNetDaemonPtr dmn,
                             int signum,
                             virNetDaemonSignalFunc func,
                             void *opaque)
{
    virNetDaemonSignalPtr sigdata = NULL;
    struct sigaction sig_action;

    virObjectLock(dmn);

    if (virNetDaemonSignalSetup(dmn) < 0)
        goto error;

    if (VIR_EXPAND_N(dmn->signals, dmn->nsignals, 1) < 0)
        goto error;

    if (VIR_ALLOC(sigdata) < 0)
        goto error;

    sigdata->signum = signum;
    sigdata->func = func;
    sigdata->opaque = opaque;

    memset(&sig_action, 0, sizeof(sig_action));
    sig_action.sa_sigaction = virNetDaemonSignalHandler;
    sig_action.sa_flags = SA_SIGINFO;
    sigemptyset(&sig_action.sa_mask);

    sigaction(signum, &sig_action, &sigdata->oldaction);

    dmn->signals[dmn->nsignals-1] = sigdata;

    virObjectUnlock(dmn);
    return 0;

 error:
    VIR_FREE(sigdata);
    virObjectUnlock(dmn);
    return -1;
}


static void
virNetDaemonAutoShutdownTimer(int timerid ATTRIBUTE_UNUSED,
                              void *opaque)
{
    virNetDaemonPtr dmn = opaque;

    virObjectLock(dmn);

    if (!dmn->autoShutdownInhibitions) {
        VIR_DEBUG("Automatic shutdown triggered");
        dmn->quit = true;
    }

    virObjectUnlock(dmn);
}

static int
daemonServerUpdateServices(void *payload,
                           const void *key ATTRIBUTE_UNUSED,
                           void *opaque)
{
    bool *enable = opaque;
    virNetServerPtr srv = payload;

    virNetServerUpdateServices(srv, *enable);
    return 0;
}

void
virNetDaemonUpdateServices(virNetDaemonPtr dmn,
                           bool enabled)
{
    virObjectLock(dmn);
    virHashForEach(dmn->servers, daemonServerUpdateServices, &enabled);
    virObjectUnlock(dmn);
}

static int
daemonServerProcessClients(void *payload,
                           const void *key ATTRIBUTE_UNUSED,
                           void *opaque ATTRIBUTE_UNUSED)
{
    virNetServerPtr srv = payload;

    virNetServerProcessClients(srv);
    return 0;
}

void
virNetDaemonRun(virNetDaemonPtr dmn)
{
    int timerid = -1;
    bool timerActive = false;

    virObjectLock(dmn);

    if (dmn->srvObject) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Not all servers restored, cannot run server"));
        goto cleanup;
    }

    dmn->quit = false;

    if (dmn->autoShutdownTimeout &&
        (timerid = virEventAddTimeout(-1,
                                      virNetDaemonAutoShutdownTimer,
                                      dmn, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to register shutdown timeout"));
        goto cleanup;
    }

    /* We are accepting connections now. Notify systemd
     * so it can start dependent services. */
    virSystemdNotifyStartup();

    VIR_DEBUG("dmn=%p quit=%d", dmn, dmn->quit);
    while (!dmn->quit) {
        /* A shutdown timeout is specified, so check
         * if any drivers have active state, if not
         * shutdown after timeout seconds
         */
        if (dmn->autoShutdownTimeout) {
            if (timerActive) {
                if (virNetDaemonHasClients(dmn)) {
                    VIR_DEBUG("Deactivating shutdown timer %d", timerid);
                    virEventUpdateTimeout(timerid, -1);
                    timerActive = false;
                }
            } else {
                if (!virNetDaemonHasClients(dmn)) {
                    VIR_DEBUG("Activating shutdown timer %d", timerid);
                    virEventUpdateTimeout(timerid,
                                          dmn->autoShutdownTimeout * 1000);
                    timerActive = true;
                }
            }
        }

        virObjectUnlock(dmn);
        if (virEventRunDefaultImpl() < 0) {
            virObjectLock(dmn);
            VIR_DEBUG("Loop iteration error, exiting");
            break;
        }
        virObjectLock(dmn);

        virHashForEach(dmn->servers, daemonServerProcessClients, NULL);
    }

 cleanup:
    virObjectUnlock(dmn);
}


void
virNetDaemonQuit(virNetDaemonPtr dmn)
{
    virObjectLock(dmn);

    VIR_DEBUG("Quit requested %p", dmn);
    dmn->quit = true;

    virObjectUnlock(dmn);
}

static int
daemonServerClose(void *payload,
                  const void *key ATTRIBUTE_UNUSED,
                  void *opaque ATTRIBUTE_UNUSED)
{
    virNetServerPtr srv = payload;

    virNetServerClose(srv);
    return 0;
}

void
virNetDaemonClose(virNetDaemonPtr dmn)
{
    if (!dmn)
        return;

    virObjectLock(dmn);

    virHashForEach(dmn->servers, daemonServerClose, NULL);

    virObjectUnlock(dmn);
}

static int
daemonServerHasClients(void *payload,
                       const void *key ATTRIBUTE_UNUSED,
                       void *opaque)
{
    bool *clients = opaque;
    virNetServerPtr srv = payload;

    if (virNetServerHasClients(srv))
        *clients = true;

    return 0;
}

bool
virNetDaemonHasClients(virNetDaemonPtr dmn)
{
    bool ret = false;

    virHashForEach(dmn->servers, daemonServerHasClients, &ret);

    return ret;
}
