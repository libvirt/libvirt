/*
 * log_daemon.c: log management daemon
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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


#include "log_daemon.h"
#include "log_daemon_config.h"
#include "virutil.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virprocess.h"
#include "virerror.h"
#include "virlog.h"
#include "viralloc.h"
#include "virconf.h"
#include "rpc/virnetdaemon.h"
#include "virrandom.h"
#include "virhash.h"
#include "viruuid.h"
#include "virstring.h"
#include "virgettext.h"

#include "log_daemon_dispatch.h"
#include "log_protocol.h"

#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_LOGGING

VIR_LOG_INIT("logging.log_daemon");

struct _virLogDaemon {
    virMutex lock;
    virNetDaemonPtr dmn;
    virNetServerPtr srv;
    virLogHandlerPtr handler;
};

virLogDaemonPtr logDaemon = NULL;

static bool execRestart;

enum {
    VIR_LOG_DAEMON_ERR_NONE = 0,
    VIR_LOG_DAEMON_ERR_PIDFILE,
    VIR_LOG_DAEMON_ERR_RUNDIR,
    VIR_LOG_DAEMON_ERR_INIT,
    VIR_LOG_DAEMON_ERR_SIGNAL,
    VIR_LOG_DAEMON_ERR_PRIVS,
    VIR_LOG_DAEMON_ERR_NETWORK,
    VIR_LOG_DAEMON_ERR_CONFIG,
    VIR_LOG_DAEMON_ERR_HOOKS,
    VIR_LOG_DAEMON_ERR_REEXEC,

    VIR_LOG_DAEMON_ERR_LAST
};

VIR_ENUM_DECL(virDaemonErr)
VIR_ENUM_IMPL(virDaemonErr, VIR_LOG_DAEMON_ERR_LAST,
              "Initialization successful",
              "Unable to obtain pidfile",
              "Unable to create rundir",
              "Unable to initialize log daemon",
              "Unable to setup signal handlers",
              "Unable to drop privileges",
              "Unable to initialize network sockets",
              "Unable to load configuration file",
              "Unable to look for hook scripts",
              "Unable to re-execute daemon");

static void *
virLogDaemonClientNew(virNetServerClientPtr client,
                      void *opaque);
static void
virLogDaemonClientFree(void *opaque);

static void *
virLogDaemonClientNewPostExecRestart(virNetServerClientPtr client,
                                     virJSONValuePtr object,
                                     void *opaque);
static virJSONValuePtr
virLogDaemonClientPreExecRestart(virNetServerClientPtr client,
                                 void *opaque);

static void
virLogDaemonFree(virLogDaemonPtr logd)
{
    if (!logd)
        return;

    virObjectUnref(logd->handler);
    virMutexDestroy(&logd->lock);
    virObjectUnref(logd->srv);
    virObjectUnref(logd->dmn);

    VIR_FREE(logd);
}


static void
virLogDaemonInhibitor(bool inhibit, void *opaque)
{
    virLogDaemonPtr dmn = opaque;

    if (inhibit)
        virNetDaemonAddShutdownInhibition(dmn->dmn);
    else
        virNetDaemonRemoveShutdownInhibition(dmn->dmn);
}

static virLogDaemonPtr
virLogDaemonNew(virLogDaemonConfigPtr config, bool privileged)
{
    virLogDaemonPtr logd;

    if (VIR_ALLOC(logd) < 0)
        return NULL;

    if (virMutexInit(&logd->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize mutex"));
        VIR_FREE(logd);
        return NULL;
    }

    if (!(logd->srv = virNetServerNew("virtlogd", 1,
                                      1, 1, 0, config->max_clients,
                                      config->max_clients, -1, 0,
                                      NULL,
                                      virLogDaemonClientNew,
                                      virLogDaemonClientPreExecRestart,
                                      virLogDaemonClientFree,
                                      (void*)(intptr_t)(privileged ? 0x1 : 0x0))))
        goto error;

    if (!(logd->dmn = virNetDaemonNew()) ||
        virNetDaemonAddServer(logd->dmn, logd->srv) < 0)
        goto error;

    if (!(logd->handler = virLogHandlerNew(privileged,
                                           config->max_size,
                                           config->max_backups,
                                           virLogDaemonInhibitor,
                                           logd)))
        goto error;

    return logd;

 error:
    virLogDaemonFree(logd);
    return NULL;
}


virLogHandlerPtr
virLogDaemonGetHandler(virLogDaemonPtr dmn)
{
    return dmn->handler;
}


static virLogDaemonPtr
virLogDaemonNewPostExecRestart(virJSONValuePtr object, bool privileged,
                               virLogDaemonConfigPtr config)
{
    virLogDaemonPtr logd;
    virJSONValuePtr child;

    if (VIR_ALLOC(logd) < 0)
        return NULL;

    if (virMutexInit(&logd->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize mutex"));
        VIR_FREE(logd);
        return NULL;
    }

    if (!(child = virJSONValueObjectGet(object, "daemon"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed daemon data from JSON file"));
        goto error;
    }

    if (!(logd->dmn = virNetDaemonNewPostExecRestart(child)))
        goto error;

    if (!(logd->srv = virNetDaemonAddServerPostExec(logd->dmn,
                                                    "virtlogd",
                                                    virLogDaemonClientNew,
                                                    virLogDaemonClientNewPostExecRestart,
                                                    virLogDaemonClientPreExecRestart,
                                                    virLogDaemonClientFree,
                                                    (void*)(intptr_t)(privileged ? 0x1 : 0x0))))
        goto error;

    if (!(child = virJSONValueObjectGet(object, "handler"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed daemon data from JSON file"));
        goto error;
    }

    if (!(logd->handler = virLogHandlerNewPostExecRestart(child,
                                                          privileged,
                                                          config->max_size,
                                                          config->max_backups,
                                                          virLogDaemonInhibitor,
                                                          logd)))
        goto error;

    return logd;

 error:
    virLogDaemonFree(logd);
    return NULL;
}


static int
virLogDaemonForkIntoBackground(const char *argv0)
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
virLogDaemonUnixSocketPaths(bool privileged,
                            char **sockfile)
{
    if (privileged) {
        if (VIR_STRDUP(*sockfile, LOCALSTATEDIR "/run/libvirt/virtlogd-sock") < 0)
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

        if (virAsprintf(sockfile, "%s/virtlogd-sock", rundir) < 0) {
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
virLogDaemonErrorHandler(void *opaque ATTRIBUTE_UNUSED,
                         virErrorPtr err ATTRIBUTE_UNUSED)
{
    /* Don't do anything, since logging infrastructure already
     * took care of reporting the error */
}


static int
virLogDaemonSetupLogging(virLogDaemonConfigPtr config,
                         bool privileged,
                         bool verbose,
                         bool godaemon)
{
    virLogReset();

    /*
     * Libvirtd's order of precedence is:
     * cmdline > environment > config
     *
     * The default output is applied only if there was no setting from either
     * the config or the environment. Because we don't have a way to determine
     * if the log level has been set, we must process variables in the opposite
     * order, each one overriding the previous.
     */
    if (config->log_level != 0)
        virLogSetDefaultPriority(config->log_level);

    if (virLogSetDefaultOutput("virtlogd.log", godaemon, privileged) < 0)
        return -1;

    /* In case the config is empty, the filters become empty and outputs will
     * be set to default
     */
    ignore_value(virLogSetFilters(config->log_filters));
    ignore_value(virLogSetOutputs(config->log_outputs));

    /* If there are some environment variables defined, use those instead */
    virLogSetFromEnv();

    /*
     * Command line override for --verbose
     */
    if ((verbose) && (virLogGetDefaultPriority() > VIR_LOG_INFO))
        virLogSetDefaultPriority(VIR_LOG_INFO);

    return 0;
}



/* Display version information. */
static void
virLogDaemonVersion(const char *argv0)
{
    printf("%s (%s) %s\n", argv0, PACKAGE_NAME, PACKAGE_VERSION);
}

static void
virLogDaemonShutdownHandler(virNetDaemonPtr dmn,
                            siginfo_t *sig ATTRIBUTE_UNUSED,
                            void *opaque ATTRIBUTE_UNUSED)
{
    virNetDaemonQuit(dmn);
}

static void
virLogDaemonExecRestartHandler(virNetDaemonPtr dmn,
                               siginfo_t *sig ATTRIBUTE_UNUSED,
                               void *opaque ATTRIBUTE_UNUSED)
{
    execRestart = true;
    virNetDaemonQuit(dmn);
}

static int
virLogDaemonSetupSignals(virNetDaemonPtr dmn)
{
    if (virNetDaemonAddSignalHandler(dmn, SIGINT, virLogDaemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetDaemonAddSignalHandler(dmn, SIGQUIT, virLogDaemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetDaemonAddSignalHandler(dmn, SIGTERM, virLogDaemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetDaemonAddSignalHandler(dmn, SIGUSR1, virLogDaemonExecRestartHandler, NULL) < 0)
        return -1;
    return 0;
}


static int
virLogDaemonSetupNetworkingSystemD(virNetServerPtr srv)
{
    virNetServerServicePtr svc;
    unsigned int nfds;

    if ((nfds = virGetListenFDs()) == 0)
        return 0;
    if (nfds > 1)
        VIR_DEBUG("Too many (%d) file descriptors from systemd", nfds);
    nfds = 1;

    /* Systemd passes FDs, starting immediately after stderr,
     * so the first FD we'll get is '3'. */
    if (!(svc = virNetServerServiceNewFD(3, 0,
#if WITH_GNUTLS
                                         NULL,
#endif
                                         false, 0, 1)))
        return -1;

    if (virNetServerAddService(srv, svc, NULL) < 0) {
        virObjectUnref(svc);
        return -1;
    }
    return 1;
}


static int
virLogDaemonSetupNetworkingNative(virNetServerPtr srv, const char *sock_path)
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


static void
virLogDaemonClientFree(void *opaque)
{
    virLogDaemonClientPtr priv = opaque;

    if (!priv)
        return;

    VIR_DEBUG("priv=%p client=%lld",
              priv,
              (unsigned long long)priv->clientPid);

    virMutexDestroy(&priv->lock);
    VIR_FREE(priv);
}


static void *
virLogDaemonClientNew(virNetServerClientPtr client,
                      void *opaque)
{
    virLogDaemonClientPtr priv;
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

    /* there's no closing handshake in the logging protocol */
    virNetServerClientSetQuietEOF(client);

    return priv;

 error:
    virLogDaemonClientFree(priv);
    return NULL;
}


static void *
virLogDaemonClientNewPostExecRestart(virNetServerClientPtr client,
                                     virJSONValuePtr object ATTRIBUTE_UNUSED,
                                     void *opaque)
{
    virLogDaemonClientPtr priv = virLogDaemonClientNew(client, opaque);

    if (!priv)
        return NULL;

    return priv;
}


static virJSONValuePtr
virLogDaemonClientPreExecRestart(virNetServerClientPtr client ATTRIBUTE_UNUSED,
                                 void *opaque ATTRIBUTE_UNUSED)
{
    virJSONValuePtr object = virJSONValueNewObject();

    if (!object)
        return NULL;

    return object;
}


static int
virLogDaemonExecRestartStatePath(bool privileged,
                                 char **state_file)
{
    if (privileged) {
        if (VIR_STRDUP(*state_file, LOCALSTATEDIR "/run/virtlogd-restart-exec.json") < 0)
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

        if (virAsprintf(state_file, "%s/virtlogd-restart-exec.json", rundir) < 0) {
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
virLogDaemonGetExecRestartMagic(void)
{
    char *ret;

    ignore_value(virAsprintf(&ret, "%lld", (long long int)getpid()));
    return ret;
}


static int
virLogDaemonPostExecRestart(const char *state_file,
                            const char *pid_file,
                            int *pid_file_fd,
                            bool privileged,
                            virLogDaemonConfigPtr config)
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

    if (!(wantmagic = virLogDaemonGetExecRestartMagic()))
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

    if (!(logDaemon = virLogDaemonNewPostExecRestart(object,
                                                     privileged,
                                                     config)))
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
virLogDaemonPreExecRestart(const char *state_file,
                           virNetDaemonPtr dmn,
                           char **argv)
{
    virJSONValuePtr child;
    char *state = NULL;
    int ret = -1;
    virJSONValuePtr object;
    char *magic;
    virHashKeyValuePairPtr pairs = NULL;

    VIR_DEBUG("Running pre-restart exec");

    if (!(object = virJSONValueNewObject()))
        goto cleanup;

    if (!(child = virNetDaemonPreExecRestart(dmn)))
        goto cleanup;

    if (virJSONValueObjectAppend(object, "daemon", child) < 0) {
        virJSONValueFree(child);
        goto cleanup;
    }

    if (!(magic = virLogDaemonGetExecRestartMagic()))
        goto cleanup;

    if (virJSONValueObjectAppendString(object, "magic", magic) < 0) {
        VIR_FREE(magic);
        goto cleanup;
    }

    if (!(child = virLogHandlerPreExecRestart(logDaemon->handler)))
        goto cleanup;

    if (virJSONValueObjectAppend(object, "handler", child) < 0) {
        virJSONValueFree(child);
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
virLogDaemonUsage(const char *argv0, bool privileged)
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
              "  -t | --timeout <secs>  Exit after timeout period.\n"
              "  -f | --config <file>   Configuration file.\n"
              "  -V | --version         Display version information.\n"
              "  -p | --pid-file <file> Change name of PID file.\n"
              "\n"
              "libvirt log management daemon:\n"), argv0);

    if (privileged) {
        fprintf(stderr,
                _("\n"
                  "  Default paths:\n"
                  "\n"
                  "    Configuration file (unless overridden by -f):\n"
                  "      %s/libvirt/virtlogd.conf\n"
                  "\n"
                  "    Sockets:\n"
                  "      %s/run/libvirt/virtlogd-sock\n"
                  "\n"
                  "    PID file (unless overridden by -p):\n"
                  "      %s/run/virtlogd.pid\n"
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
                  "      $XDG_CONFIG_HOME/libvirt/virtlogd.conf\n"
                  "\n"
                  "    Sockets:\n"
                  "      $XDG_RUNTIME_DIR/libvirt/virtlogd-sock\n"
                  "\n"
                  "    PID file:\n"
                  "      $XDG_RUNTIME_DIR/libvirt/virtlogd.pid\n"
                  "\n"));
    }
}

int main(int argc, char **argv) {
    virNetServerProgramPtr logProgram = NULL;
    char *remote_config_file = NULL;
    int statuswrite = -1;
    int ret = 1;
    int verbose = 0;
    int godaemon = 0;
    char *run_dir = NULL;
    char *pid_file = NULL;
    int pid_file_fd = -1;
    char *sock_file = NULL;
    int timeout = -1;        /* -t: Shutdown timeout */
    char *state_file = NULL;
    bool implicit_conf = false;
    mode_t old_umask;
    bool privileged = false;
    virLogDaemonConfigPtr config = NULL;
    int rv;

    struct option opts[] = {
        { "verbose", no_argument, &verbose, 'v'},
        { "daemon", no_argument, &godaemon, 'd'},
        { "config", required_argument, NULL, 'f'},
        { "timeout", required_argument, NULL, 't'},
        { "pid-file", required_argument, NULL, 'p'},
        { "version", no_argument, NULL, 'V' },
        { "help", no_argument, NULL, 'h' },
        {0, 0, 0, 0}
    };

    privileged = geteuid() == 0;

    if (virGettextInitialize() < 0 ||
        virThreadInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int optidx = 0;
        int c;
        char *tmp;

        c = getopt_long(argc, argv, "df:p:t:vVh", opts, &optidx);

        if (c == -1)
            break;

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

        case 't':
            if (virStrToLong_i(optarg, &tmp, 10, &timeout) != 0
                || timeout <= 0
                /* Ensure that we can multiply by 1000 without overflowing.  */
                || timeout > INT_MAX / 1000) {
                VIR_ERROR(_("Invalid value for timeout"));
                exit(EXIT_FAILURE);
            }
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
            virLogDaemonVersion(argv[0]);
            exit(EXIT_SUCCESS);

        case 'h':
            virLogDaemonUsage(argv[0], privileged);
            exit(EXIT_SUCCESS);

        case '?':
        default:
            virLogDaemonUsage(argv[0], privileged);
            exit(EXIT_FAILURE);
        }
    }

    virFileActivateDirOverride(argv[0]);

    if (!(config = virLogDaemonConfigNew(privileged))) {
        VIR_ERROR(_("Can't create initial configuration"));
        exit(EXIT_FAILURE);
    }

    /* No explicit config, so try and find a default one */
    if (remote_config_file == NULL) {
        implicit_conf = true;
        if (virLogDaemonConfigFilePath(privileged,
                                       &remote_config_file) < 0) {
            VIR_ERROR(_("Can't determine config path"));
            exit(EXIT_FAILURE);
        }
    }

    /* Read the config file if it exists*/
    if (remote_config_file &&
        virLogDaemonConfigLoadFile(config, remote_config_file, implicit_conf) < 0) {
        VIR_ERROR(_("Can't load config file: %s: %s"),
                  virGetLastErrorMessage(), remote_config_file);
        exit(EXIT_FAILURE);
    }

    if (virLogDaemonSetupLogging(config, privileged, verbose, godaemon) < 0) {
        VIR_ERROR(_("Can't initialize logging"));
        exit(EXIT_FAILURE);
    }

    if (!pid_file &&
        virPidFileConstructPath(privileged,
                                LOCALSTATEDIR,
                                "virtlogd",
                                &pid_file) < 0) {
        VIR_ERROR(_("Can't determine pid file path."));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on pid file path '%s'", NULLSTR(pid_file));

    if (virLogDaemonUnixSocketPaths(privileged,
                                    &sock_file) < 0) {
        VIR_ERROR(_("Can't determine socket paths"));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on socket paths '%s'",
              sock_file);

    if (virLogDaemonExecRestartStatePath(privileged,
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
        ret = VIR_LOG_DAEMON_ERR_RUNDIR;
        umask(old_umask);
        goto cleanup;
    }
    umask(old_umask);

    if ((rv = virLogDaemonPostExecRestart(state_file,
                                          pid_file,
                                          &pid_file_fd,
                                          privileged,
                                          config)) < 0) {
        ret = VIR_LOG_DAEMON_ERR_INIT;
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

            if ((statuswrite = virLogDaemonForkIntoBackground(argv[0])) < 0) {
                VIR_ERROR(_("Failed to fork as daemon: %s"),
                          virStrerror(errno, ebuf, sizeof(ebuf)));
                goto cleanup;
            }
        }

        /* If we have a pidfile set, claim it now, exiting if already taken */
        if ((pid_file_fd = virPidFileAcquirePath(pid_file, false, getpid())) < 0) {
            ret = VIR_LOG_DAEMON_ERR_PIDFILE;
            goto cleanup;
        }

        if (!(logDaemon = virLogDaemonNew(config, privileged))) {
            ret = VIR_LOG_DAEMON_ERR_INIT;
            goto cleanup;
        }

        if ((rv = virLogDaemonSetupNetworkingSystemD(logDaemon->srv)) < 0) {
            ret = VIR_LOG_DAEMON_ERR_NETWORK;
            goto cleanup;
        }

        /* Only do this, if systemd did not pass a FD */
        if (rv == 0 &&
            virLogDaemonSetupNetworkingNative(logDaemon->srv, sock_file) < 0) {
            ret = VIR_LOG_DAEMON_ERR_NETWORK;
            goto cleanup;
        }
    }

    if (timeout != -1) {
        VIR_DEBUG("Registering shutdown timeout %d", timeout);
        virNetDaemonAutoShutdown(logDaemon->dmn,
                                 timeout);
    }

    if ((virLogDaemonSetupSignals(logDaemon->dmn)) < 0) {
        ret = VIR_LOG_DAEMON_ERR_SIGNAL;
        goto cleanup;
    }

    if (!(logProgram = virNetServerProgramNew(VIR_LOG_MANAGER_PROTOCOL_PROGRAM,
                                              VIR_LOG_MANAGER_PROTOCOL_PROGRAM_VERSION,
                                              virLogManagerProtocolProcs,
                                              virLogManagerProtocolNProcs))) {
        ret = VIR_LOG_DAEMON_ERR_INIT;
        goto cleanup;
    }
    if (virNetServerAddProgram(logDaemon->srv, logProgram) < 0) {
        ret = VIR_LOG_DAEMON_ERR_INIT;
        goto cleanup;
    }

    /* Disable error func, now logging is setup */
    virSetErrorFunc(NULL, virLogDaemonErrorHandler);

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

    virNetServerUpdateServices(logDaemon->srv, true);
    virNetDaemonRun(logDaemon->dmn);

    if (execRestart &&
        virLogDaemonPreExecRestart(state_file,
                                   logDaemon->dmn,
                                   argv) < 0)
        ret = VIR_LOG_DAEMON_ERR_REEXEC;
    else
        ret = 0;

 cleanup:
    virObjectUnref(logProgram);
    virLogDaemonFree(logDaemon);
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
    VIR_FREE(remote_config_file);
    virLogDaemonConfigFree(config);
    return ret;

 no_memory:
    VIR_ERROR(_("Can't allocate memory"));
    exit(EXIT_FAILURE);
}
