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
 */

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <getopt.h>


#include "log_daemon.h"
#include "log_daemon_config.h"
#include "admin/admin_server_dispatch.h"
#include "virutil.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virerror.h"
#include "virlog.h"
#include "viralloc.h"
#include "rpc/virnetdaemon.h"
#include "virstring.h"
#include "virgettext.h"
#include "virdaemon.h"

#include "log_daemon_dispatch.h"
#include "log_protocol.h"

#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_LOGGING

VIR_LOG_INIT("logging.log_daemon");

struct _virLogDaemon {
    GMutex lock;
    virNetDaemon *dmn;
    virLogHandler *handler;
};

virLogDaemon *logDaemon = NULL;

static bool execRestart;

static void *
virLogDaemonClientNew(virNetServerClient *client,
                      void *opaque);
static void
virLogDaemonClientFree(void *opaque);

static void *
virLogDaemonClientNewPostExecRestart(virNetServerClient *client,
                                     virJSONValue *object,
                                     void *opaque);
static virJSONValue *
virLogDaemonClientPreExecRestart(virNetServerClient *client,
                                 void *opaque);

static void
virLogDaemonFree(virLogDaemon *logd)
{
    if (!logd)
        return;

    virObjectUnref(logd->handler);
    g_mutex_clear(&logd->lock);
    virObjectUnref(logd->dmn);

    g_free(logd);
}


static void
virLogDaemonInhibitor(bool inhibit, void *opaque)
{
    virLogDaemon *dmn = opaque;

    /* virtlogd uses inhibition only to stop session daemon being killed after
     * the specified timeout, for the system daemon this is taken care of by
     * libvirtd and the dependencies between the services. */
    if (virNetDaemonIsPrivileged(dmn->dmn))
        return;

    if (inhibit)
        virNetDaemonAddShutdownInhibition(dmn->dmn);
    else
        virNetDaemonRemoveShutdownInhibition(dmn->dmn);
}

static virLogDaemon *
virLogDaemonNew(virLogDaemonConfig *config, bool privileged)
{
    virLogDaemon *logd;
    virNetServer *srv = NULL;

    logd = g_new0(virLogDaemon, 1);

    g_mutex_init(&logd->lock);

    if (!(logd->dmn = virNetDaemonNew()))
        goto error;

    if (!(srv = virNetServerNew("virtlogd", 1,
                                0, 0, 0, config->max_clients,
                                config->max_clients, -1, 0,
                                virLogDaemonClientNew,
                                virLogDaemonClientPreExecRestart,
                                virLogDaemonClientFree,
                                (void*)(intptr_t)(privileged ? 0x1 : 0x0))))
        goto error;

    if (virNetDaemonAddServer(logd->dmn, srv) < 0)
        goto error;
    g_clear_pointer(&srv, virObjectUnref);

    if (!(srv = virNetServerNew("admin", 1,
                                0, 0, 0, config->admin_max_clients,
                                config->admin_max_clients, -1, 0,
                                remoteAdmClientNew,
                                remoteAdmClientPreExecRestart,
                                remoteAdmClientFree,
                                logd->dmn)))
        goto error;

    if (virNetDaemonAddServer(logd->dmn, srv) < 0)
        goto error;
    g_clear_pointer(&srv, virObjectUnref);

    if (!(logd->handler = virLogHandlerNew(privileged,
                                           config,
                                           virLogDaemonInhibitor,
                                           logd)))
        goto error;

    return logd;

 error:
    virObjectUnref(srv);
    virLogDaemonFree(logd);
    return NULL;
}


virLogHandler *
virLogDaemonGetHandler(virLogDaemon *dmn)
{
    return dmn->handler;
}


static virNetServer *
virLogDaemonNewServerPostExecRestart(virNetDaemon *dmn,
                                     const char *name,
                                     virJSONValue *object,
                                     void *opaque)
{
    if (STREQ(name, "virtlogd")) {
        return virNetServerNewPostExecRestart(object,
                                              name,
                                              virLogDaemonClientNew,
                                              virLogDaemonClientNewPostExecRestart,
                                              virLogDaemonClientPreExecRestart,
                                              virLogDaemonClientFree,
                                              opaque);
    } else if (STREQ(name, "admin")) {
        return virNetServerNewPostExecRestart(object,
                                              name,
                                              remoteAdmClientNew,
                                              remoteAdmClientNewPostExecRestart,
                                              remoteAdmClientPreExecRestart,
                                              remoteAdmClientFree,
                                              dmn);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected server name '%1$s' during restart"),
                       name);
        return NULL;
    }
}


static virLogDaemon *
virLogDaemonNewPostExecRestart(virJSONValue *object, bool privileged,
                               virLogDaemonConfig *config)
{
    virLogDaemon *logd;
    virJSONValue *child;
    const char *serverNames[] = { "virtlogd" };

    logd = g_new0(virLogDaemon, 1);

    g_mutex_init(&logd->lock);

    if (!(child = virJSONValueObjectGet(object, "daemon"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed daemon data from JSON file"));
        goto error;
    }

    if (!(logd->dmn = virNetDaemonNewPostExecRestart(child,
                                                     G_N_ELEMENTS(serverNames),
                                                     serverNames,
                                                     virLogDaemonNewServerPostExecRestart,
                                                     (void*)(intptr_t)(privileged ? 0x1 : 0x0))))
        goto error;

    if (!(child = virJSONValueObjectGet(object, "handler"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed daemon data from JSON file"));
        goto error;
    }

    if (!(logd->handler = virLogHandlerNewPostExecRestart(child,
                                                          privileged,
                                                          config,
                                                          virLogDaemonInhibitor,
                                                          logd)))
        goto error;

    return logd;

 error:
    virLogDaemonFree(logd);
    return NULL;
}


static void
virLogDaemonErrorHandler(void *opaque G_GNUC_UNUSED,
                         virErrorPtr err G_GNUC_UNUSED)
{
    /* Don't do anything, since logging infrastructure already
     * took care of reporting the error */
}



/* Display version information. */
static void
virLogDaemonVersion(const char *argv0)
{
    printf("%s (%s) %s\n", argv0, PACKAGE_NAME, PACKAGE_VERSION);
}

static void
virLogDaemonShutdownHandler(virNetDaemon *dmn,
                            siginfo_t *sig G_GNUC_UNUSED,
                            void *opaque G_GNUC_UNUSED)
{
    virNetDaemonQuit(dmn);
}

static void
virLogDaemonExecRestartHandler(virNetDaemon *dmn,
                               siginfo_t *sig G_GNUC_UNUSED,
                               void *opaque G_GNUC_UNUSED)
{
    execRestart = true;
    virNetDaemonQuitExecRestart(dmn);
}

static int
virLogDaemonSetupSignals(virNetDaemon *dmn)
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


static void
virLogDaemonClientFree(void *opaque)
{
    virLogDaemonClient *priv = opaque;

    if (!priv)
        return;

    VIR_DEBUG("priv=%p client=%lld",
              priv,
              (unsigned long long)priv->clientPid);

    g_mutex_clear(&priv->lock);
    g_free(priv);
}


static void *
virLogDaemonClientNew(virNetServerClient *client,
                      void *opaque)
{
    virLogDaemonClient *priv;
    uid_t clientuid;
    gid_t clientgid;
    unsigned long long timestamp;
    bool privileged = opaque != NULL;

    priv = g_new0(virLogDaemonClient, 1);

    g_mutex_init(&priv->lock);

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
            virReportRestrictedError(_("Disallowing client %1$llu with uid %2$llu"),
                                     (unsigned long long)priv->clientPid,
                                     (unsigned long long)clientuid);
            goto error;
        }
    } else {
        if (clientuid != 0) {
            virReportRestrictedError(_("Disallowing client %1$llu with uid %2$llu"),
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
virLogDaemonClientNewPostExecRestart(virNetServerClient *client,
                                     virJSONValue *object G_GNUC_UNUSED,
                                     void *opaque)
{
    virLogDaemonClient *priv = virLogDaemonClientNew(client, opaque);

    if (!priv)
        return NULL;

    return priv;
}


static virJSONValue *
virLogDaemonClientPreExecRestart(virNetServerClient *client G_GNUC_UNUSED,
                                 void *opaque G_GNUC_UNUSED)
{
    virJSONValue *object = virJSONValueNewObject();

    return object;
}


static int
virLogDaemonExecRestartStatePath(bool privileged,
                                 char **state_file)
{
    if (privileged) {
        *state_file = g_strdup(RUNSTATEDIR "/virtlogd-restart-exec.json");
    } else {
        g_autofree char *rundir = NULL;
        mode_t old_umask;

        rundir = virGetUserRuntimeDirectory();

        old_umask = umask(077);
        if (g_mkdir_with_parents(rundir, 0777) < 0) {
            umask(old_umask);
            return -1;
        }
        umask(old_umask);

        *state_file = g_strdup_printf("%s/virtlogd-restart-exec.json", rundir);
    }

    return 0;
}


static char *
virLogDaemonGetExecRestartMagic(void)
{
    return g_strdup_printf("%lld", (long long int)getpid());
}


static int
virLogDaemonPostExecRestart(const char *state_file,
                            const char *pid_file,
                            int *pid_file_fd,
                            bool privileged,
                            virLogDaemonConfig *config)
{
    const char *gotmagic;
    g_autofree char *wantmagic = NULL;
    g_autofree char *state = NULL;
    g_autoptr(virJSONValue) object = NULL;
    int rc;

    VIR_DEBUG("Running post-restart exec");

    if (!virFileExists(state_file)) {
        VIR_DEBUG("No restart state file %s present",
                  state_file);
        return 0;
    }

    rc = virFileReadAll(state_file, 1024 * 1024 * 10, /* 10 MB */ &state);
    unlink(state_file);

    if (rc < 0)
        return -1;

    VIR_DEBUG("Loading state %s", state);

    if (!(object = virJSONValueFromString(state)))
        return -1;

    gotmagic = virJSONValueObjectGetString(object, "magic");
    if (!gotmagic) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing magic data in JSON document"));
        return -1;
    }

    if (!(wantmagic = virLogDaemonGetExecRestartMagic()))
        return -1;

    if (STRNEQ(gotmagic, wantmagic)) {
        VIR_WARN("Found restart exec file with old magic %s vs wanted %s",
                 gotmagic, wantmagic);
        return 0;
    }

    /* Re-claim PID file now as we will not be daemonizing */
    if (pid_file &&
        (*pid_file_fd = virPidFileAcquirePath(pid_file, getpid())) < 0)
        return -1;

    if (!(logDaemon = virLogDaemonNewPostExecRestart(object,
                                                     privileged,
                                                     config)))
        return -1;

    return 1;
}


static int
virLogDaemonPreExecRestart(const char *state_file,
                           virNetDaemon *dmn,
                           char **argv)
{
    g_autoptr(virJSONValue) object = virJSONValueNewObject();
    g_autoptr(virJSONValue) daemon = NULL;
    g_autoptr(virJSONValue) handler = NULL;
    g_autofree char *state = NULL;
    g_autofree char *magic = NULL;

    VIR_DEBUG("Running pre-restart exec");

    if (!(daemon = virNetDaemonPreExecRestart(dmn)))
        return -1;

    if (virJSONValueObjectAppend(object, "daemon", &daemon) < 0)
        return -1;

    if (!(magic = virLogDaemonGetExecRestartMagic()))
        return -1;

    if (virJSONValueObjectAppendString(object, "magic", magic) < 0)
        return -1;

    if (!(handler = virLogHandlerPreExecRestart(logDaemon->handler)))
        return -1;

    if (virJSONValueObjectAppend(object, "handler", &handler) < 0)
        return -1;

    if (!(state = virJSONValueToString(object, true)))
        return -1;

    VIR_DEBUG("Saving state %s", state);

    if (virFileWriteStr(state_file, state, 0700) < 0) {
        virReportSystemError(errno,
                             _("Unable to save state file %1$s"), state_file);
        return -1;
    }

    if (execvp(argv[0], argv) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to restart self"));
        return -1;
    }

    abort(); /* This should be impossible to reach */

    return 0;
}


static void
virLogDaemonUsage(const char *argv0, bool privileged)
{
    fprintf(stderr,
            _("\n"
              "Usage:\n"
              "  %1$s [options]\n"
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
                  "      %1$s/libvirt/virtlogd.conf\n"
                  "\n"
                  "    Sockets:\n"
                  "      %2$s/libvirt/virtlogd-sock\n"
                  "\n"
                  "    PID file (unless overridden by -p):\n"
                  "      %3$s/virtlogd.pid\n"
                  "\n"),
                SYSCONFDIR,
                RUNSTATEDIR,
                RUNSTATEDIR);
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
    virNetServer *logSrv = NULL;
    virNetServer *adminSrv = NULL;
    virNetServerProgram *logProgram = NULL;
    virNetServerProgram *adminProgram = NULL;
    char *remote_config_file = NULL;
    int statuswrite = -1;
    int ret = 1;
    int verbose = 0;
    int godaemon = 0;
    char *run_dir = NULL;
    char *pid_file = NULL;
    int pid_file_fd = -1;
    char *sock_file = NULL;
    char *admin_sock_file = NULL;
    int timeout = 0;         /* -t: Shutdown timeout */
    char *state_file = NULL;
    bool implicit_conf = false;
    mode_t old_umask;
    bool privileged = false;
    virLogDaemonConfig *config = NULL;
    int rv;

    struct option opts[] = {
        { "verbose", no_argument, &verbose, 'v' },
        { "daemon", no_argument, &godaemon, 'd' },
        { "config", required_argument, NULL, 'f' },
        { "timeout", required_argument, NULL, 't' },
        { "pid-file", required_argument, NULL, 'p' },
        { "version", no_argument, NULL, 'V' },
        { "help", no_argument, NULL, 'h' },
        { 0, 0, 0, 0 },
    };

    privileged = geteuid() == 0;

    if (virGettextInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%1$s: initialization failed\n"), argv[0]);
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
                || timeout < 0
                /* Ensure that we can multiply by 1000 without overflowing.  */
                || timeout > INT_MAX / 1000) {
                VIR_ERROR(_("Invalid value for timeout"));
                exit(EXIT_FAILURE);
            }
            break;

        case 'p':
            VIR_FREE(pid_file);
            pid_file = g_strdup(optarg);
            break;

        case 'f':
            VIR_FREE(remote_config_file);
            remote_config_file = g_strdup(optarg);
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

    virFileActivateDirOverrideForProg(argv[0]);

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

    /* Read the config file if it exists */
    if (remote_config_file &&
        virLogDaemonConfigLoadFile(config, remote_config_file, implicit_conf) < 0) {
        VIR_ERROR(_("Can't load config file: %1$s: %2$s"),
                  virGetLastErrorMessage(), remote_config_file);
        exit(EXIT_FAILURE);
    }

    if (virDaemonSetupLogging("virtlogd",
                              config->log_level,
                              config->log_filters,
                              config->log_outputs,
                              privileged,
                              verbose,
                              godaemon) < 0) {
        virDispatchError(NULL);
        exit(EXIT_FAILURE);
    }

    if (!pid_file &&
        virPidFileConstructPath(privileged,
                                RUNSTATEDIR,
                                "virtlogd",
                                &pid_file) < 0) {
        VIR_ERROR(_("Can't determine pid file path."));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on pid file path '%s'", NULLSTR(pid_file));

    if (virDaemonUnixSocketPaths("virtlogd",
                                 privileged,
                                 NULL,
                                 &sock_file,
                                 NULL,
                                 &admin_sock_file) < 0) {
        VIR_ERROR(_("Can't determine socket paths"));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on socket paths '%s' and '%s'",
              sock_file, admin_sock_file);

    if (virLogDaemonExecRestartStatePath(privileged,
                                         &state_file) < 0) {
        VIR_ERROR(_("Can't determine restart state file path"));
        exit(EXIT_FAILURE);
    }
    VIR_DEBUG("Decided on restart state file path '%s'",
              state_file);

    /* Ensure the rundir exists (on tmpfs on some systems) */
    if (privileged) {
        run_dir = g_strdup(RUNSTATEDIR "/libvirt");
    } else {
        run_dir = virGetUserRuntimeDirectory();
    }

    if (privileged)
        old_umask = umask(022);
    else
        old_umask = umask(077);
    VIR_DEBUG("Ensuring run dir '%s' exists", run_dir);
    if (g_mkdir_with_parents(run_dir, 0777) < 0) {
        VIR_ERROR(_("unable to create rundir %1$s: %2$s"), run_dir,
                  g_strerror(errno));
        ret = VIR_DAEMON_ERR_RUNDIR;
        umask(old_umask);
        goto cleanup;
    }
    umask(old_umask);

    if ((rv = virLogDaemonPostExecRestart(state_file,
                                          pid_file,
                                          &pid_file_fd,
                                          privileged,
                                          config)) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    /* rv == 1, means we setup everything from saved state,
     * so only (possibly) daemonize and setup stuff from
     * scratch if rv == 0
     */
    if (rv == 0) {
        g_autoptr(virSystemdActivation) act = NULL;

        if (godaemon) {
            if (chdir("/") < 0) {
                VIR_ERROR(_("cannot change to root directory: %1$s"),
                          g_strerror(errno));
                goto cleanup;
            }

            if ((statuswrite = virDaemonForkIntoBackground(argv[0])) < 0) {
                VIR_ERROR(_("Failed to fork as daemon: %1$s"),
                          g_strerror(errno));
                goto cleanup;
            }
        }

        /* If we have a pidfile set, claim it now, exiting if already taken */
        if ((pid_file_fd = virPidFileAcquirePath(pid_file, getpid())) < 0) {
            ret = VIR_DAEMON_ERR_PIDFILE;
            goto cleanup;
        }

        if (!(logDaemon = virLogDaemonNew(config, privileged))) {
            ret = VIR_DAEMON_ERR_INIT;
            goto cleanup;
        }

        if (virSystemdGetActivation(&act) < 0) {
            ret = VIR_DAEMON_ERR_NETWORK;
            goto cleanup;
        }

        logSrv = virNetDaemonGetServer(logDaemon->dmn, "virtlogd");
        adminSrv = virNetDaemonGetServer(logDaemon->dmn, "admin");

        if (virNetServerAddServiceUNIX(logSrv,
                                       act, "virtlogd.socket",
                                       sock_file, 0700, 0, 0,
                                       NULL,
                                       false, 0, 1) < 0) {
            ret = VIR_DAEMON_ERR_NETWORK;
            goto cleanup;
        }
        if (virNetServerAddServiceUNIX(adminSrv,
                                       act, "virtlogd-admin.socket",
                                       admin_sock_file, 0700, 0, 0,
                                       NULL,
                                       false, 0, 1) < 0) {
            ret = VIR_DAEMON_ERR_NETWORK;
            goto cleanup;
        }

        if (act &&
            virSystemdActivationComplete(act) < 0) {
            ret = VIR_DAEMON_ERR_NETWORK;
            goto cleanup;
        }
    } else {
        logSrv = virNetDaemonGetServer(logDaemon->dmn, "virtlogd");
        /* If exec-restarting from old virtlogd, we won't have an
         * admin server present */
        if (virNetDaemonHasServer(logDaemon->dmn, "admin"))
            adminSrv = virNetDaemonGetServer(logDaemon->dmn, "admin");
    }

    if (timeout > 0) {
        if (virNetDaemonAutoShutdown(logDaemon->dmn, timeout) < 0)
            return -1;
    }

    if ((virLogDaemonSetupSignals(logDaemon->dmn)) < 0) {
        ret = VIR_DAEMON_ERR_SIGNAL;
        goto cleanup;
    }

    if (!(logProgram = virNetServerProgramNew(VIR_LOG_MANAGER_PROTOCOL_PROGRAM,
                                              VIR_LOG_MANAGER_PROTOCOL_PROGRAM_VERSION,
                                              virLogManagerProtocolProcs,
                                              virLogManagerProtocolNProcs))) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }
    if (virNetServerAddProgram(logSrv, logProgram) < 0) {
        ret = VIR_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (adminSrv != NULL) {
        if (!(adminProgram = virNetServerProgramNew(ADMIN_PROGRAM,
                                                    ADMIN_PROTOCOL_VERSION,
                                                    adminProcs,
                                                    adminNProcs))) {
            ret = VIR_DAEMON_ERR_INIT;
            goto cleanup;
        }
        if (virNetServerAddProgram(adminSrv, adminProgram) < 0) {
            ret = VIR_DAEMON_ERR_INIT;
            goto cleanup;
        }
    }

    /* Disable error func, now logging is setup */
    virSetErrorFunc(NULL, virLogDaemonErrorHandler);

    /* Tell parent of daemon that basic initialization is complete
     * In particular we're ready to accept net connections & have
     * written the pidfile
     */
    if (statuswrite != -1) {
        char status = 0;
        while (write(statuswrite, &status, 1) == -1 && /* sc_avoid_write */
               errno == EINTR)
            ;
        VIR_FORCE_CLOSE(statuswrite);
    }

    /* Start accepting new clients from network */

    virNetDaemonUpdateServices(logDaemon->dmn, true);
    virNetDaemonRun(logDaemon->dmn);

    if (execRestart &&
        virLogDaemonPreExecRestart(state_file,
                                   logDaemon->dmn,
                                   argv) < 0)
        ret = VIR_DAEMON_ERR_REEXEC;
    else
        ret = 0;

 cleanup:
    virObjectUnref(logProgram);
    virObjectUnref(adminProgram);
    virObjectUnref(logSrv);
    virObjectUnref(adminSrv);
    virLogDaemonFree(logDaemon);
    if (statuswrite != -1) {
        if (ret != 0) {
            /* Tell parent of daemon what failed */
            char status = ret;
            while (write(statuswrite, &status, 1) == -1 && /* sc_avoid_write */
                   errno == EINTR)
                ;
        }
        VIR_FORCE_CLOSE(statuswrite);
    }
    if (pid_file_fd != -1)
        virPidFileReleasePath(pid_file, pid_file_fd);
    VIR_FREE(pid_file);
    VIR_FREE(sock_file);
    VIR_FREE(admin_sock_file);
    VIR_FREE(state_file);
    VIR_FREE(run_dir);
    VIR_FREE(remote_config_file);
    virLogDaemonConfigFree(config);
    return ret;
}
