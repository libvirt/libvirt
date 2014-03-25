/*
 * lock_daemon.c: lock management daemon
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <getopt.h>
#include <stdlib.h>
#include <locale.h>


#include "lock_daemon.h"
#include "lock_daemon_config.h"
#include "virutil.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virprocess.h"
#include "virerror.h"
#include "virlog.h"
#include "viralloc.h"
#include "virconf.h"
#include "rpc/virnetserver.h"
#include "virrandom.h"
#include "virhash.h"
#include "viruuid.h"
#include "virstring.h"

#include "locking/lock_daemon_dispatch.h"
#include "locking/lock_protocol.h"

#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_LOCKING

VIR_LOG_INIT("locking.lock_daemon");

#define VIR_LOCK_DAEMON_NUM_LOCKSPACES 3

struct _virLockDaemon {
    virMutex lock;
    virNetServerPtr srv;
    virHashTablePtr lockspaces;
    virLockSpacePtr defaultLockspace;
};

virLockDaemonPtr lockDaemon = NULL;

static bool execRestart = false;

enum {
    VIR_LOCK_DAEMON_ERR_NONE = 0,
    VIR_LOCK_DAEMON_ERR_PIDFILE,
    VIR_LOCK_DAEMON_ERR_RUNDIR,
    VIR_LOCK_DAEMON_ERR_INIT,
    VIR_LOCK_DAEMON_ERR_SIGNAL,
    VIR_LOCK_DAEMON_ERR_PRIVS,
    VIR_LOCK_DAEMON_ERR_NETWORK,
    VIR_LOCK_DAEMON_ERR_CONFIG,
    VIR_LOCK_DAEMON_ERR_HOOKS,
    VIR_LOCK_DAEMON_ERR_REEXEC,

    VIR_LOCK_DAEMON_ERR_LAST
};

VIR_ENUM_DECL(virDaemonErr)
VIR_ENUM_IMPL(virDaemonErr, VIR_LOCK_DAEMON_ERR_LAST,
              "Initialization successful",
              "Unable to obtain pidfile",
              "Unable to create rundir",
              "Unable to initialize libvirt",
              "Unable to setup signal handlers",
              "Unable to drop privileges",
              "Unable to initialize network sockets",
              "Unable to load configuration file",
              "Unable to look for hook scripts",
              "Unable to re-execute daemon");

static void *
virLockDaemonClientNew(virNetServerClientPtr client,
                       void *opaque);
static void
virLockDaemonClientFree(void *opaque);

static void *
virLockDaemonClientNewPostExecRestart(virNetServerClientPtr client,
                                      virJSONValuePtr object,
                                      void *opaque);
static virJSONValuePtr
virLockDaemonClientPreExecRestart(virNetServerClientPtr client,
                                  void *opaque);

static void
virLockDaemonFree(virLockDaemonPtr lockd)
{
    if (!lockd)
        return;

    virObjectUnref(lockd->srv);
    virHashFree(lockd->lockspaces);
    virLockSpaceFree(lockd->defaultLockspace);

    VIR_FREE(lockd);
}


static void virLockDaemonLockSpaceDataFree(void *data,
                                           const void *key ATTRIBUTE_UNUSED)
{
    virLockSpaceFree(data);
}

static virLockDaemonPtr
virLockDaemonNew(virLockDaemonConfigPtr config, bool privileged)
{
    virLockDaemonPtr lockd;

    if (VIR_ALLOC(lockd) < 0)
        return NULL;

    if (virMutexInit(&lockd->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize mutex"));
        VIR_FREE(lockd);
        return NULL;
    }

    if (!(lockd->srv = virNetServerNew(1, 1, 0, config->max_clients,
                                       config->max_clients, -1, 0,
                                       false, NULL,
                                       virLockDaemonClientNew,
                                       virLockDaemonClientPreExecRestart,
                                       virLockDaemonClientFree,
                                       (void*)(intptr_t)(privileged ? 0x1 : 0x0))))
        goto error;

    if (!(lockd->lockspaces = virHashCreate(VIR_LOCK_DAEMON_NUM_LOCKSPACES,
                                            virLockDaemonLockSpaceDataFree)))
        goto error;

    if (!(lockd->defaultLockspace = virLockSpaceNew(NULL)))
        goto error;

    return lockd;

 error:
    virLockDaemonFree(lockd);
    return NULL;
}


static virLockDaemonPtr
virLockDaemonNewPostExecRestart(virJSONValuePtr object, bool privileged)
{
    virLockDaemonPtr lockd;
    virJSONValuePtr child;
    virJSONValuePtr lockspaces;
    size_t i;
    int n;

    if (VIR_ALLOC(lockd) < 0)
        return NULL;

    if (virMutexInit(&lockd->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize mutex"));
        VIR_FREE(lockd);
        return NULL;
    }

    if (!(lockd->lockspaces = virHashCreate(VIR_LOCK_DAEMON_NUM_LOCKSPACES,
                                            virLockDaemonLockSpaceDataFree)))
        goto error;

    if (!(child = virJSONValueObjectGet(object, "defaultLockspace"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing defaultLockspace data from JSON file"));
        goto error;
    }

    if (!(lockd->defaultLockspace =
          virLockSpaceNewPostExecRestart(child)))
        goto error;

    if (!(lockspaces = virJSONValueObjectGet(object, "lockspaces"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing lockspaces data from JSON file"));
        goto error;
    }

    if ((n = virJSONValueArraySize(lockspaces)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed lockspaces data from JSON file"));
        goto error;
    }

    for (i = 0; i < n; i++) {
        virLockSpacePtr lockspace;

        child = virJSONValueArrayGet(lockspaces, i);

        if (!(lockspace = virLockSpaceNewPostExecRestart(child)))
            goto error;

        if (virHashAddEntry(lockd->lockspaces,
                            virLockSpaceGetDirectory(lockspace),
                            lockspace) < 0) {
            virLockSpaceFree(lockspace);
        }
    }

    if (!(child = virJSONValueObjectGet(object, "server"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing server data from JSON file"));
        goto error;
    }

    if (!(lockd->srv = virNetServerNewPostExecRestart(child,
                                                      virLockDaemonClientNew,
                                                      virLockDaemonClientNewPostExecRestart,
                                                      virLockDaemonClientPreExecRestart,
                                                      virLockDaemonClientFree,
                                                      (void*)(intptr_t)(privileged ? 0x1 : 0x0))))
        goto error;

    return lockd;

 error:
    virLockDaemonFree(lockd);
    return NULL;
}


int virLockDaemonAddLockSpace(virLockDaemonPtr lockd,
                              const char *path,
                              virLockSpacePtr lockspace)
{
    int ret;
    virMutexLock(&lockd->lock);
    ret = virHashAddEntry(lockd->lockspaces, path, lockspace);
    virMutexUnlock(&lockd->lock);
    return ret;
}

virLockSpacePtr virLockDaemonFindLockSpace(virLockDaemonPtr lockd,
                                           const char *path)
{
    virLockSpacePtr lockspace;
    virMutexLock(&lockd->lock);
    if (path && STRNEQ(path, ""))
        lockspace = virHashLookup(lockd->lockspaces, path);
    else
        lockspace = lockd->defaultLockspace;
    virMutexUnlock(&lockd->lock);
    return lockspace;
}


static int
virLockDaemonForkIntoBackground(const char *argv0)
{
    int statuspipe[2];
    if (pipe(statuspipe) < 0)
        return -1;

    pid_t pid = fork();
    switch (pid) {
    case 0:
        {
            int stdinfd = -1;
            int stdoutfd = -1;
            int nextpid;

            VIR_FORCE_CLOSE(statuspipe[0]);

            if ((stdinfd = open("/dev/null", O_RDONLY)) < 0)
                goto cleanup;
            if ((stdoutfd = open("/dev/null", O_WRONLY)) < 0)
                goto cleanup;
            if (dup2(stdinfd, STDIN_FILENO) != STDIN_FILENO)
                goto cleanup;
            if (dup2(stdoutfd, STDOUT_FILENO) != STDOUT_FILENO)
                goto cleanup;
            if (dup2(stdoutfd, STDERR_FILENO) != STDERR_FILENO)
                goto cleanup;
            if (VIR_CLOSE(stdinfd) < 0)
                goto cleanup;
            if (VIR_CLOSE(stdoutfd) < 0)
                goto cleanup;

            if (setsid() < 0)
                goto cleanup;

            nextpid = fork();
            switch (nextpid) {
            case 0:
                return statuspipe[1];
            case -1:
                return -1;
            default:
                _exit(0);
            }

        cleanup:
            VIR_FORCE_CLOSE(stdoutfd);
            VIR_FORCE_CLOSE(stdinfd);
            return -1;

        }

    case -1:
        return -1;

    default:
        {
            int got, exitstatus = 0;
            int ret;
            char status;

            VIR_FORCE_CLOSE(statuspipe[1]);

            /* We wait to make sure the first child forked successfully */
            if ((got = waitpid(pid, &exitstatus, 0)) < 0 ||
                got != pid ||
                exitstatus != 0) {
                return -1;
            }

            /* Now block until the second child initializes successfully */
        again:
            ret = read(statuspipe[0], &status, 1);
            if (ret == -1 && errno == EINTR)
                goto again;

            if (ret == 1 && status != 0) {
                fprintf(stderr,
                        _("%s: error: %s. Check /var/log/messages or run without "
                          "--daemon for more info.\n"), argv0,
                        virDaemonErrTypeToString(status));
            }
            _exit(ret == 1 && status == 0 ? 0 : 1);
        }
    }
}


static int
virLockDaemonPidFilePath(bool privileged,
                         char **pidfile)
{
    if (privileged) {
        if (VIR_STRDUP(*pidfile, LOCALSTATEDIR "/run/virtlockd.pid") < 0)
            goto error;
    } else {
        char *rundir = NULL;
        mode_t old_umask;

        if (!(rundir = virGetUserRuntimeDirectory()))
            goto error;

        old_umask = umask(077);
        if (virFileMakePath(rundir) < 0) {
            umask(old_umask);
            goto error;
        }
        umask(old_umask);

        if (virAsprintf(pidfile, "%s/virtlockd.pid", rundir) < 0) {
            VIR_FREE(rundir);
            goto error;
        }

        VIR_FREE(rundir);
    }

    return 0;

 error:
    return -1;
}


static int
virLockDaemonUnixSocketPaths(bool privileged,
                             char **sockfile)
{
    if (privileged) {
        if (VIR_STRDUP(*sockfile, LOCALSTATEDIR "/run/libvirt/virtlockd-sock") < 0)
            goto error;
    } else {
        char *rundir = NULL;
        mode_t old_umask;

        if (!(rundir = virGetUserRuntimeDirectory()))
            goto error;

        old_umask = umask(077);
        if (virFileMakePath(rundir) < 0) {
            umask(old_umask);
            goto error;
        }
        umask(old_umask);

        if (virAsprintf(sockfile, "%s/virtlockd-sock", rundir) < 0) {
            VIR_FREE(rundir);
            goto error;
        }

        VIR_FREE(rundir);
    }
    return 0;

 error:
    return -1;
}


static void
virLockDaemonErrorHandler(void *opaque ATTRIBUTE_UNUSED,
                          virErrorPtr err ATTRIBUTE_UNUSED)
{
    /* Don't do anything, since logging infrastructure already
     * took care of reporting the error */
}


/*
 * Set up the logging environment
 * By default if daemonized all errors go to the logfile libvirtd.log,
 * but if verbose or error debugging is asked for then also output
 * informational and debug messages. Default size if 64 kB.
 */
static int
virLockDaemonSetupLogging(virLockDaemonConfigPtr config,
                          bool privileged,
                          bool verbose,
                          bool godaemon)
{
    virLogReset();

    /*
     * Libvirtd's order of precedence is:
     * cmdline > environment > config
     *
     * In order to achieve this, we must process configuration in
     * different order for the log level versus the filters and
     * outputs. Because filters and outputs append, we have to look at
     * the environment first and then only check the config file if
     * there was no result from the environment. The default output is
     * then applied only if there was no setting from either of the
     * first two. Because we don't have a way to determine if the log
     * level has been set, we must process variables in the opposite
     * order, each one overriding the previous.
     */
    if (config->log_level != 0)
        virLogSetDefaultPriority(config->log_level);

    virLogSetFromEnv();

    if (virLogGetNbFilters() == 0)
        virLogParseFilters(config->log_filters);

    if (virLogGetNbOutputs() == 0)
        virLogParseOutputs(config->log_outputs);

    /*
     * If no defined outputs, and either running
     * as daemon or not on a tty, then first try
     * to direct it to the systemd journal
     * (if it exists)....
     */
    if (virLogGetNbOutputs() == 0 &&
        (godaemon || !isatty(STDIN_FILENO))) {
        char *tmp;
        if (access("/run/systemd/journal/socket", W_OK) >= 0) {
            if (virAsprintf(&tmp, "%d:journald", virLogGetDefaultPriority()) < 0)
                goto error;
            virLogParseOutputs(tmp);
            VIR_FREE(tmp);
        }
    }

    /*
     * otherwise direct to libvirtd.log when running
     * as daemon. Otherwise the default output is stderr.
     */
    if (virLogGetNbOutputs() == 0) {
        char *tmp = NULL;

        if (godaemon) {
            if (privileged) {
                if (virAsprintf(&tmp, "%d:file:%s/log/libvirt/virtlockd.log",
                                virLogGetDefaultPriority(),
                                LOCALSTATEDIR) == -1)
                    goto error;
            } else {
                char *logdir = virGetUserCacheDirectory();
                mode_t old_umask;

                if (!logdir)
                    goto error;

                old_umask = umask(077);
                if (virFileMakePath(logdir) < 0) {
                    umask(old_umask);
                    goto error;
                }
                umask(old_umask);

                if (virAsprintf(&tmp, "%d:file:%s/virtlockd.log",
                                virLogGetDefaultPriority(), logdir) == -1) {
                    VIR_FREE(logdir);
                    goto error;
                }
                VIR_FREE(logdir);
            }
        } else {
            if (virAsprintf(&tmp, "%d:stderr", virLogGetDefaultPriority()) < 0)
                goto error;
        }
        virLogParseOutputs(tmp);
        VIR_FREE(tmp);
    }

    /*
     * Command line override for --verbose
     */
    if ((verbose) && (virLogGetDefaultPriority() > VIR_LOG_INFO))
        virLogSetDefaultPriority(VIR_LOG_INFO);

    return 0;

 error:
    return -1;
}



/* Display version information. */
static void
virLockDaemonVersion(const char *argv0)
{
    printf("%s (%s) %s\n", argv0, PACKAGE_NAME, PACKAGE_VERSION);
}

static void
virLockDaemonShutdownHandler(virNetServerPtr srv,
                             siginfo_t *sig ATTRIBUTE_UNUSED,
                             void *opaque ATTRIBUTE_UNUSED)
{
    virNetServerQuit(srv);
}

static void
virLockDaemonExecRestartHandler(virNetServerPtr srv,
                                siginfo_t *sig ATTRIBUTE_UNUSED,
                                void *opaque ATTRIBUTE_UNUSED)
{
    execRestart = true;
    virNetServerQuit(srv);
}

static int
virLockDaemonSetupSignals(virNetServerPtr srv)
{
    if (virNetServerAddSignalHandler(srv, SIGINT, virLockDaemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetServerAddSignalHandler(srv, SIGQUIT, virLockDaemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetServerAddSignalHandler(srv, SIGTERM, virLockDaemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetServerAddSignalHandler(srv, SIGUSR1, virLockDaemonExecRestartHandler, NULL) < 0)
        return -1;
    return 0;
}


static int
virLockDaemonSetupNetworkingSystemD(virNetServerPtr srv)
{
    virNetServerServicePtr svc;
    const char *pidstr;
    const char *fdstr;
    unsigned long long procid;
    unsigned int nfds;

    VIR_DEBUG("Setting up networking from systemd");

    if (!(pidstr = virGetEnvAllowSUID("LISTEN_PID"))) {
        VIR_DEBUG("No LISTEN_FDS from systemd");
        return 0;
    }

    if (virStrToLong_ull(pidstr, NULL, 10, &procid) < 0) {
        VIR_DEBUG("Malformed LISTEN_PID from systemd %s", pidstr);
        return 0;
    }

    if ((pid_t)procid != getpid()) {
        VIR_DEBUG("LISTEN_PID %s is not for us %llu",
                  pidstr, (unsigned long long)getpid());
        return 0;
    }

    if (!(fdstr = virGetEnvAllowSUID("LISTEN_FDS"))) {
        VIR_DEBUG("No LISTEN_FDS from systemd");
        return 0;
    }

    if (virStrToLong_ui(fdstr, NULL, 10, &nfds) < 0) {
        VIR_DEBUG("Malformed LISTEN_FDS from systemd %s", fdstr);
        return 0;
    }

    if (nfds > 1) {
        VIR_DEBUG("Too many (%d) file descriptors from systemd",
                  nfds);
        nfds = 1;
    }

    unsetenv("LISTEN_PID");
    unsetenv("LISTEN_FDS");

    if (nfds == 0)
        return 0;

    /* Systemd passes FDs, starting immediately after stderr,
     * so the first FD we'll get is '3'. */
    if (!(svc = virNetServerServiceNewFD(3, 0,
#if WITH_GNUTLS
                                         NULL,
#endif
                                         false, 1)))
        return -1;

    if (virNetServerAddService(srv, svc, NULL) < 0) {
        virObjectUnref(svc);
        return -1;
    }
    return 1;
}


static int
virLockDaemonSetupNetworkingNative(virNetServerPtr srv, const char *sock_path)
{
    virNetServerServicePtr svc;

    VIR_DEBUG("Setting up networking natively");

    if (!(svc = virNetServerServiceNewUNIX(sock_path, 0700, 0, 0,
#if WITH_GNUTLS
                                           NULL,
#endif
                                           false, 0, 1)))
        return -1;

    if (virNetServerAddService(srv, svc, NULL) < 0) {
        virObjectUnref(svc);
        return -1;
    }
    return 0;
}


struct virLockDaemonClientReleaseData {
    virLockDaemonClientPtr client;
    bool hadSomeLeases;
    bool gotError;
};

static void
virLockDaemonClientReleaseLockspace(void *payload,
                                    const void *name ATTRIBUTE_UNUSED,
                                    void *opaque)
{
    virLockSpacePtr lockspace = payload;
    struct virLockDaemonClientReleaseData *data = opaque;
    int rc;

    rc = virLockSpaceReleaseResourcesForOwner(lockspace,
                                              data->client->clientPid);
    if (rc > 0)
        data->hadSomeLeases = true;
    else if (rc < 0)
        data->gotError = true;
}


static void
virLockDaemonClientFree(void *opaque)
{
    virLockDaemonClientPtr priv = opaque;

    if (!priv)
        return;

    VIR_DEBUG("priv=%p client=%lld owner=%lld",
              priv,
              (unsigned long long)priv->clientPid,
              (unsigned long long)priv->ownerPid);

    /* If client & owner match, this is the lock holder */
    if (priv->clientPid == priv->ownerPid) {
        size_t i;
        struct virLockDaemonClientReleaseData data = {
            .client = priv, .hadSomeLeases = false, .gotError = false
        };

        /* Release all locks associated with this
         * owner in all lockspaces */
        virMutexLock(&lockDaemon->lock);
        virHashForEach(lockDaemon->lockspaces,
                       virLockDaemonClientReleaseLockspace,
                       &data);
        virLockDaemonClientReleaseLockspace(lockDaemon->defaultLockspace,
                                            "",
                                            &data);
        virMutexUnlock(&lockDaemon->lock);

        /* If the client had some active leases when it
         * closed the connection, we must kill it off
         * to make sure it doesn't do nasty stuff */
        if (data.gotError || data.hadSomeLeases) {
            for (i = 0; i < 15; i++) {
                int signum;
                if (i == 0)
                    signum = SIGTERM;
                else if (i == 8)
                    signum = SIGKILL;
                else
                    signum = 0;
                if (virProcessKill(priv->clientPid, signum) < 0) {
                    if (errno == ESRCH)
                        break;

                    VIR_WARN("Failed to kill off pid %lld",
                             (unsigned long long)priv->clientPid);
                }
                usleep(200 * 1000);
            }
        }
    }

    virMutexDestroy(&priv->lock);
    VIR_FREE(priv);
}


static void *
virLockDaemonClientNew(virNetServerClientPtr client,
                       void *opaque)
{
    virLockDaemonClientPtr priv;
    uid_t clientuid;
    gid_t clientgid;
    unsigned long long timestamp;
    bool privileged = opaque != NULL;

    if (VIR_ALLOC(priv) < 0)
        return NULL;

    if (virMutexInit(&priv->lock) < 0) {
        VIR_FREE(priv);
        virReportSystemError(errno, "%s", _("unable to init mutex"));
        return NULL;
    }

    if (virNetServerClientGetUNIXIdentity(client,
                                          &clientuid,
                                          &clientgid,
                                          &priv->clientPid,
                                          &timestamp) < 0)
        goto error;

    VIR_DEBUG("New client pid %llu uid %llu",
              (unsigned long long)priv->clientPid,
              (unsigned long long)clientuid);

    if (!privileged) {
        if (geteuid() != clientuid) {
            virReportRestrictedError(_("Disallowing client %llu with uid %llu"),
                                     (unsigned long long)priv->clientPid,
                                     (unsigned long long)clientuid);
            goto error;
        }
    } else {
        if (clientuid != 0) {
            virReportRestrictedError(_("Disallowing client %llu with uid %llu"),
                                     (unsigned long long)priv->clientPid,
                                     (unsigned long long)clientuid);
            goto error;
        }
    }

    return priv;

 error:
    virMutexDestroy(&priv->lock);
    VIR_FREE(priv);
    return NULL;
}


static void *
virLockDaemonClientNewPostExecRestart(virNetServerClientPtr client,
                                      virJSONValuePtr object,
                                      void *opaque)
{
    virLockDaemonClientPtr priv = virLockDaemonClientNew(client, opaque);
    unsigned int ownerPid;
    const char *ownerUUID;
    const char *ownerName;

    if (!priv)
        return NULL;

    if (virJSONValueObjectGetBoolean(object, "restricted", &priv->restricted) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing restricted data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectGetNumberUint(object, "ownerPid", &ownerPid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing ownerPid data in JSON document"));
        goto error;
    }
    priv->ownerPid = (pid_t)ownerPid;
    if (virJSONValueObjectGetNumberUint(object, "ownerId", &priv->ownerId) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing ownerId data in JSON document"));
        goto error;
    }
    if (!(ownerName = virJSONValueObjectGetString(object, "ownerName"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing ownerName data in JSON document"));
        goto error;
    }
    if (VIR_STRDUP(priv->ownerName, ownerName) < 0)
        goto error;
    if (!(ownerUUID = virJSONValueObjectGetString(object, "ownerUUID"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing ownerUUID data in JSON document"));
        goto error;
    }
    if (virUUIDParse(ownerUUID, priv->ownerUUID) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing ownerUUID data in JSON document"));
        goto error;
    }
    return priv;

 error:
    virLockDaemonClientFree(priv);
    return NULL;
}


static virJSONValuePtr
virLockDaemonClientPreExecRestart(virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                  void *opaque)
{
    virLockDaemonClientPtr priv = opaque;
    virJSONValuePtr object = virJSONValueNewObject();
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!object)
        return NULL;

    if (virJSONValueObjectAppendBoolean(object, "restricted", priv->restricted) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set restricted data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectAppendNumberUint(object, "ownerPid", priv->ownerPid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set ownerPid data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectAppendNumberUint(object, "ownerId", priv->ownerId) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set ownerId data in JSON document"));
        goto error;
    }
    if (virJSONValueObjectAppendString(object, "ownerName", priv->ownerName) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set ownerName data in JSON document"));
        goto error;
    }
    virUUIDFormat(priv->ownerUUID, uuidstr);
    if (virJSONValueObjectAppendString(object, "ownerUUID", uuidstr) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot set ownerUUID data in JSON document"));
        goto error;
    }

    return object;

 error:
    virJSONValueFree(object);
    return NULL;
}


static int
virLockDaemonExecRestartStatePath(bool privileged,
                                  char **state_file)
{
    if (privileged) {
        if (VIR_STRDUP(*state_file, LOCALSTATEDIR "/run/virtlockd-restart-exec.json") < 0)
            goto error;
    } else {
        char *rundir = NULL;
        mode_t old_umask;

        if (!(rundir = virGetUserRuntimeDirectory()))
            goto error;

        old_umask = umask(077);
        if (virFileMakePath(rundir) < 0) {
            umask(old_umask);
            VIR_FREE(rundir);
            goto error;
        }
        umask(old_umask);

        if (virAsprintf(state_file, "%s/virtlockd-restart-exec.json", rundir) < 0) {
            VIR_FREE(rundir);
            goto error;
        }

        VIR_FREE(rundir);
    }

    return 0;

 error:
    return -1;
}


static char *
virLockDaemonGetExecRestartMagic(void)
{
    char *ret;

    ignore_value(virAsprintf(&ret, "%lld", (long long int)getpid()));
    return ret;
}


static int
virLockDaemonPostExecRestart(const char *state_file,
                             const char *pid_file,
                             int *pid_file_fd,
                             bool privileged)
{
    const char *gotmagic;
    char *wantmagic = NULL;
    int ret = -1;
    char *state = NULL;
    virJSONValuePtr object = NULL;

    VIR_DEBUG("Running post-restart exec");

    if (!virFileExists(state_file)) {
        VIR_DEBUG("No restart state file %s present",
                  state_file);
        ret = 0;
        goto cleanup;
    }

    if (virFileReadAll(state_file,
                       1024 * 1024 * 10, /* 10 MB */
                       &state) < 0)
        goto cleanup;

    VIR_DEBUG("Loading state %s", state);

    if (!(object = virJSONValueFromString(state)))
        goto cleanup;

    gotmagic = virJSONValueObjectGetString(object, "magic");
    if (!gotmagic) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing magic data in JSON document"));
        goto cleanup;
    }

    if (!(wantmagic = virLockDaemonGetExecRestartMagic()))
        goto cleanup;

    if (STRNEQ(gotmagic, wantmagic)) {
        VIR_WARN("Found restart exec file with old magic %s vs wanted %s",
                 gotmagic, wantmagic);
        ret = 0;
        goto cleanup;
    }

    /* Re-claim PID file now as we will not be daemonizing */
    if (pid_file &&
        (*pid_file_fd = virPidFileAcquirePath(pid_file, false, getpid())) < 0)
        goto cleanup;

    if (!(lockDaemon = virLockDaemonNewPostExecRestart(object, privileged)))
        goto cleanup;

    ret = 1;

 cleanup:
    unlink(state_file);
    VIR_FREE(wantmagic);
    VIR_FREE(state);
    virJSONValueFree(object);
    return ret;
}


static int
virLockDaemonPreExecRestart(const char *state_file,
                            virNetServerPtr srv,
                            char **argv)
{
    virJSONValuePtr child;
    char *state = NULL;
    int ret = -1;
    virJSONValuePtr object;
    char *magic;
    virHashKeyValuePairPtr pairs = NULL, tmp;
    virJSONValuePtr lockspaces;

    VIR_DEBUG("Running pre-restart exec");

    if (!(object = virJSONValueNewObject()))
        goto cleanup;

    if (!(child = virNetServerPreExecRestart(srv)))
        goto cleanup;

    if (virJSONValueObjectAppend(object, "server", child) < 0) {
        virJSONValueFree(child);
        goto cleanup;
    }

    if (!(child = virLockSpacePreExecRestart(lockDaemon->defaultLockspace)))
        goto cleanup;

    if (virJSONValueObjectAppend(object, "defaultLockspace", child) < 0) {
        virJSONValueFree(child);
        goto cleanup;
    }

    if (!(lockspaces = virJSONValueNewArray()))
        goto cleanup;
    if (virJSONValueObjectAppend(object, "lockspaces", lockspaces) < 0) {
        virJSONValueFree(lockspaces);
        goto cleanup;
    }


    tmp = pairs = virHashGetItems(lockDaemon->lockspaces, NULL);
    while (tmp && tmp->key) {
        virLockSpacePtr lockspace = (virLockSpacePtr)tmp->value;

        if (!(child = virLockSpacePreExecRestart(lockspace)))
            goto cleanup;

        if (virJSONValueArrayAppend(lockspaces, child) < 0) {
            virJSONValueFree(child);
            goto cleanup;
        }

        tmp++;
    }

    if (!(magic = virLockDaemonGetExecRestartMagic()))
        goto cleanup;

    if (virJSONValueObjectAppendString(object, "magic", magic) < 0) {
        VIR_FREE(magic);
        goto cleanup;
    }

    if (!(state = virJSONValueToString(object, true)))
        goto cleanup;

    VIR_DEBUG("Saving state %s", state);

    if (virFileWriteStr(state_file,
                        state, 0700) < 0) {
        virReportSystemError(errno,
                             _("Unable to save state file %s"),
                             state_file);
        goto cleanup;
    }

    if (execvp(argv[0], argv) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to restart self"));
        goto cleanup;
    }

    abort(); /* This should be impossible to reach */

 cleanup:
    VIR_FREE(pairs);
    VIR_FREE(state);
    virJSONValueFree(object);
    return ret;
}


static void
virLockDaemonUsage(const char *argv0, bool privileged)
{
    fprintf(stderr,
            _("\n"
              "Usage:\n"
              "  %s [options]\n"
              "\n"
              "Options:\n"
              "  -h | --help            Display program help:\n"
              "  -v | --verbose         Verbose messages.\n"
              "  -d | --daemon          Run as a daemon & write PID file.\n"
              "  -f | --config <file>   Configuration file.\n"
              "  -V | --version         Display version information.\n"
              "  -p | --pid-file <file> Change name of PID file.\n"
              "\n"
              "libvirt lock management daemon:\n"), argv0);

    if (privileged) {
        fprintf(stderr,
                _("\n"
                  "  Default paths:\n"
                  "\n"
                  "    Configuration file (unless overridden by -f):\n"
                  "      %s/libvirt/virtlockd.conf\n"
                  "\n"
                  "    Sockets:\n"
                  "      %s/run/libvirt/virtlockd-sock\n"
                  "\n"
                  "    PID file (unless overridden by -p):\n"
                  "      %s/run/virtlockd.pid\n"
                  "\n"),
                SYSCONFDIR,
                LOCALSTATEDIR,
                LOCALSTATEDIR);
    } else {
        fprintf(stderr, "%s",
                _("\n"
                  "  Default paths:\n"
                  "\n"
                  "    Configuration file (unless overridden by -f):\n"
                  "      $XDG_CONFIG_HOME/libvirt/virtlockd.conf\n"
                  "\n"
                  "    Sockets:\n"
                  "      $XDG_RUNTIME_DIR/libvirt/virtlockd-sock\n"
                  "\n"
                  "    PID file:\n"
                  "      $XDG_RUNTIME_DIR/libvirt/virtlockd.pid\n"
                  "\n"));
    }
}

#define MAX_LISTEN 5
int main(int argc, char **argv) {
    virNetServerProgramPtr lockProgram = NULL;
    char *remote_config_file = NULL;
    int statuswrite = -1;
    int ret = 1;
    int verbose = 0;
    int godaemon = 0;
    char *run_dir = NULL;
    char *pid_file = NULL;
    int pid_file_fd = -1;
    char *sock_file = NULL;
    char *state_file = NULL;
    bool implicit_conf = false;
    mode_t old_umask;
    bool privileged = false;
    virLockDaemonConfigPtr config = NULL;
    int rv;

    struct option opts[] = {
        { "verbose", no_argument, &verbose, 'v'},
        { "daemon", no_argument, &godaemon, 'd'},
        { "config", required_argument, NULL, 'f'},
        { "pid-file", required_argument, NULL, 'p'},
        { "version", no_argument, NULL, 'V' },
        { "help", no_argument, NULL, 'h' },
        {0, 0, 0, 0}
    };

    privileged = geteuid() == 0;

    if (setlocale(LC_ALL, "") == NULL ||
        bindtextdomain(PACKAGE, LOCALEDIR) == NULL ||
        textdomain(PACKAGE) == NULL ||
        virThreadInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int optidx = 0;
        int c;

        c = getopt_long(argc, argv, "ldf:p:t:vVh", opts, &optidx);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 0:
            /* Got one of the flags */
            break;
        case 'v':
            verbose = 1;
            break;
        case 'd':
            godaemon = 1;
            break;

        case 'p':
            VIR_FREE(pid_file);
            if (VIR_STRDUP_QUIET(pid_file, optarg) < 0)
                goto no_memory;
            break;

        case 'f':
            VIR_FREE(remote_config_file);
            if (VIR_STRDUP_QUIET(remote_config_file, optarg) < 0)
                goto no_memory;
            break;

        case 'V':
            virLockDaemonVersion(argv[0]);
            exit(EXIT_SUCCESS);

        case 'h':
            virLockDaemonUsage(argv[0], privileged);
            exit(EXIT_SUCCESS);

        case '?':
        default:
            virLockDaemonUsage(argv[0], privileged);
            exit(EXIT_FAILURE);
        }
    }

    if (!(config = virLockDaemonConfigNew(privileged))) {
        VIR_ERROR(_("Can't create initial configuration"));
        exit(EXIT_FAILURE);
    }

    /* No explicit config, so try and find a default one */
    if (remote_config_file == NULL) {
        implicit_conf = true;
        if (virLockDaemonConfigFilePath(privileged,
                                        &remote_config_file) < 0) {
            VIR_ERROR(_("Can't determine config path"));
            exit(EXIT_FAILURE);
        }
    }

    /* Read the config file if it exists*/
    if (remote_config_file &&
        virLockDaemonConfigLoadFile(config, remote_config_file, implicit_conf) < 0) {
        virErrorPtr err = virGetLastError();
        if (err && err->message)
            VIR_ERROR(_("Can't load config file: %s: %s"),
                      err->message, remote_config_file);
        else
            VIR_ERROR(_("Can't load config file: %s"), remote_config_file);
        exit(EXIT_FAILURE);
    }

    if (virLockDaemonSetupLogging(config, privileged, verbose, godaemon) < 0) {
        VIR_ERROR(_("Can't initialize logging"));
        exit(EXIT_FAILURE);
    }

    if (!pid_file &&
        virLockDaemonPidFilePath(privileged,
                                 &pid_file) < 0) {
        VIR_ERROR(_("Can't determine pid file path."));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on pid file path '%s'", NULLSTR(pid_file));

    if (virLockDaemonUnixSocketPaths(privileged,
                                     &sock_file) < 0) {
        VIR_ERROR(_("Can't determine socket paths"));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on socket paths '%s'",
              sock_file);

    if (virLockDaemonExecRestartStatePath(privileged,
                                          &state_file) < 0) {
        VIR_ERROR(_("Can't determine restart state file path"));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on restart state file path '%s'",
              state_file);

    /* Ensure the rundir exists (on tmpfs on some systems) */
    if (privileged) {
        if (VIR_STRDUP_QUIET(run_dir, LOCALSTATEDIR "/run/libvirt") < 0)
            goto no_memory;
    } else {
        if (!(run_dir = virGetUserRuntimeDirectory())) {
            VIR_ERROR(_("Can't determine user directory"));
            goto cleanup;
        }
    }

    if (privileged)
        old_umask = umask(022);
    else
        old_umask = umask(077);
    VIR_DEBUG("Ensuring run dir '%s' exists", run_dir);
    if (virFileMakePath(run_dir) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("unable to create rundir %s: %s"), run_dir,
                  virStrerror(errno, ebuf, sizeof(ebuf)));
        ret = VIR_LOCK_DAEMON_ERR_RUNDIR;
        goto cleanup;
    }
    umask(old_umask);

    if ((rv = virLockDaemonPostExecRestart(state_file,
                                           pid_file,
                                           &pid_file_fd,
                                           privileged)) < 0) {
        ret = VIR_LOCK_DAEMON_ERR_INIT;
        goto cleanup;
    }

    /* rv == 1, means we setup everything from saved state,
     * so only (possibly) daemonize and setup stuff from
     * scratch if rv == 0
     */
    if (rv == 0) {
        if (godaemon) {
            char ebuf[1024];

            if (chdir("/") < 0) {
                VIR_ERROR(_("cannot change to root directory: %s"),
                          virStrerror(errno, ebuf, sizeof(ebuf)));
                goto cleanup;
            }

            if ((statuswrite = virLockDaemonForkIntoBackground(argv[0])) < 0) {
                VIR_ERROR(_("Failed to fork as daemon: %s"),
                          virStrerror(errno, ebuf, sizeof(ebuf)));
                goto cleanup;
            }
        }

        /* If we have a pidfile set, claim it now, exiting if already taken */
        if ((pid_file_fd = virPidFileAcquirePath(pid_file, false, getpid())) < 0) {
            ret = VIR_LOCK_DAEMON_ERR_PIDFILE;
            goto cleanup;
        }

        if (!(lockDaemon = virLockDaemonNew(config, privileged))) {
            ret = VIR_LOCK_DAEMON_ERR_INIT;
            goto cleanup;
        }

        if ((rv = virLockDaemonSetupNetworkingSystemD(lockDaemon->srv)) < 0) {
            ret = VIR_LOCK_DAEMON_ERR_NETWORK;
            goto cleanup;
        }

        /* Only do this, if systemd did not pass a FD */
        if (rv == 0 &&
            virLockDaemonSetupNetworkingNative(lockDaemon->srv, sock_file) < 0) {
            ret = VIR_LOCK_DAEMON_ERR_NETWORK;
            goto cleanup;
        }
    }

    if ((virLockDaemonSetupSignals(lockDaemon->srv)) < 0) {
        ret = VIR_LOCK_DAEMON_ERR_SIGNAL;
        goto cleanup;
    }

    if (!(lockProgram = virNetServerProgramNew(VIR_LOCK_SPACE_PROTOCOL_PROGRAM,
                                               VIR_LOCK_SPACE_PROTOCOL_PROGRAM_VERSION,
                                               virLockSpaceProtocolProcs,
                                               virLockSpaceProtocolNProcs))) {
        ret = VIR_LOCK_DAEMON_ERR_INIT;
        goto cleanup;
    }
    if (virNetServerAddProgram(lockDaemon->srv, lockProgram) < 0) {
        ret = VIR_LOCK_DAEMON_ERR_INIT;
        goto cleanup;
    }

    /* Disable error func, now logging is setup */
    virSetErrorFunc(NULL, virLockDaemonErrorHandler);


    /* Tell parent of daemon that basic initialization is complete
     * In particular we're ready to accept net connections & have
     * written the pidfile
     */
    if (statuswrite != -1) {
        char status = 0;
        while (write(statuswrite, &status, 1) == -1 &&
               errno == EINTR)
            ;
        VIR_FORCE_CLOSE(statuswrite);
    }

    /* Start accepting new clients from network */

    virNetServerUpdateServices(lockDaemon->srv, true);
    virNetServerRun(lockDaemon->srv);

    if (execRestart &&
        virLockDaemonPreExecRestart(state_file,
                                    lockDaemon->srv,
                                    argv) < 0)
        ret = VIR_LOCK_DAEMON_ERR_REEXEC;
    else
        ret = 0;

 cleanup:
    virObjectUnref(lockProgram);
    virLockDaemonFree(lockDaemon);
    if (statuswrite != -1) {
        if (ret != 0) {
            /* Tell parent of daemon what failed */
            char status = ret;
            while (write(statuswrite, &status, 1) == -1 &&
                   errno == EINTR)
                ;
        }
        VIR_FORCE_CLOSE(statuswrite);
    }
    if (pid_file_fd != -1)
        virPidFileReleasePath(pid_file, pid_file_fd);
    VIR_FREE(pid_file);
    VIR_FREE(sock_file);
    VIR_FREE(state_file);
    VIR_FREE(run_dir);
    return ret;

 no_memory:
    VIR_ERROR(_("Can't allocate memory"));
    exit(EXIT_FAILURE);
}
