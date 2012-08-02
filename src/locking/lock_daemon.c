/*
 * lock_daemon.c: lock management daemon
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
#include "util.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virterror_internal.h"
#include "logging.h"
#include "memory.h"
#include "conf.h"
#include "rpc/virnetserver.h"
#include "virrandom.h"
#include "virhash.h"

#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_LOCKING

struct _virLockDaemon {
    virMutex lock;
    virNetServerPtr srv;
};

virLockDaemonPtr lockDaemon = NULL;

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
              "Unable to look for hook scripts");

static void *
virLockDaemonClientNew(virNetServerClientPtr client,
                       void *opaque);
static void
virLockDaemonClientFree(void *opaque);

static void
virLockDaemonFree(virLockDaemonPtr lockd)
{
    if (!lockd)
        return;

    virObjectUnref(lockd->srv);

    VIR_FREE(lockd);
}


static virLockDaemonPtr
virLockDaemonNew(bool privileged)
{
    virLockDaemonPtr lockd;

    if (VIR_ALLOC(lockd) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&lockd->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize mutex"));
        VIR_FREE(lockd);
        return NULL;
    }

    if (!(lockd->srv = virNetServerNew(1, 1, 0, 20,
                                       -1, 0,
                                       false, NULL,
                                       virLockDaemonClientNew,
                                       NULL,
                                       virLockDaemonClientFree,
                                       (void*)(intptr_t)(privileged ? 0x1 : 0x0))))
        goto error;

    return lockd;

error:
    virLockDaemonFree(lockd);
    return NULL;
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
        if (!(*pidfile = strdup(LOCALSTATEDIR "/run/virtlockd.pid")))
            goto no_memory;
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
            goto no_memory;
        }

        VIR_FREE(rundir);
    }

    return 0;

no_memory:
    virReportOOMError();
error:
    return -1;
}


static int
virLockDaemonUnixSocketPaths(bool privileged,
                             char **sockfile)
{
    if (privileged) {
        if (!(*sockfile = strdup(LOCALSTATEDIR "/run/libvirt/virtlockd-sock")))
            goto no_memory;
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
            goto no_memory;
        }

        VIR_FREE(rundir);
    }
    return 0;

no_memory:
    virReportOOMError();
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

    virLogSetBufferSize(config->log_buffer_size);

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
                goto no_memory;
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
                    goto no_memory;
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
                    goto no_memory;
                }
                VIR_FREE(logdir);
            }
        } else {
            if (virAsprintf(&tmp, "%d:stderr", virLogGetDefaultPriority()) < 0)
                goto no_memory;
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

no_memory:
    virReportOOMError();
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

static int
virLockDaemonSetupSignals(virNetServerPtr srv)
{
    if (virNetServerAddSignalHandler(srv, SIGINT, virLockDaemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetServerAddSignalHandler(srv, SIGQUIT, virLockDaemonShutdownHandler, NULL) < 0)
        return -1;
    if (virNetServerAddSignalHandler(srv, SIGTERM, virLockDaemonShutdownHandler, NULL) < 0)
        return -1;
    return 0;
}

static int
virLockDaemonSetupNetworking(virNetServerPtr srv, const char *sock_path)
{
    virNetServerServicePtr svc;

    VIR_DEBUG("Setting up networking natively");

    if (!(svc = virNetServerServiceNewUNIX(sock_path, 0700, 0, 0, false, 1, NULL)))
        return -1;

    if (virNetServerAddService(srv, svc, NULL) < 0) {
        virObjectUnref(svc);
        return -1;
    }
    return 0;
}


static void
virLockDaemonClientFree(void *opaque)
{
    virLockDaemonClientPtr priv = opaque;

    if (!priv)
        return;

    VIR_DEBUG("priv=%p client=%lld",
              priv,
              (unsigned long long)priv->clientPid);

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
    bool privileged = opaque != NULL;

    if (VIR_ALLOC(priv) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&priv->lock) < 0) {
        VIR_FREE(priv);
        virReportOOMError();
        return NULL;
    }

    if (virNetServerClientGetUNIXIdentity(client,
                                          &clientuid,
                                          &clientgid,
                                          &priv->clientPid) < 0)
        goto error;

    VIR_DEBUG("New client pid %llu uid %llu",
              (unsigned long long)priv->clientPid,
              (unsigned long long)clientuid);

    if (!privileged) {
        if (geteuid() != clientuid) {
            virReportError(VIR_ERR_OPERATION_DENIED,
                           _("Disallowing client %llu with uid %llu"),
                           (unsigned long long)priv->clientPid,
                           (unsigned long long)clientuid);
            goto error;
        }
    } else {
        if (clientuid != 0) {
            virReportError(VIR_ERR_OPERATION_DENIED,
                           _("Disallowing client %llu with uid %llu"),
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


static void
virLockDaemonUsage(const char *argv0, bool privileged)
{
    fprintf(stderr,
            _("\n"
              "Usage:\n"
              "  %s [options]\n"
              "\n"
              "Options:\n"
              "  -v | --verbose         Verbose messages.\n"
              "  -d | --daemon          Run as a daemon & write PID file.\n"
              "  -f | --config <file>   Configuration file.\n"
              "     | --version         Display version information.\n"
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

enum {
    OPT_VERSION = 129
};

#define MAX_LISTEN 5
int main(int argc, char **argv) {
    char *remote_config_file = NULL;
    int statuswrite = -1;
    int ret = 1;
    int verbose = 0;
    int godaemon = 0;
    char *run_dir = NULL;
    char *pid_file = NULL;
    int pid_file_fd = -1;
    char *sock_file = NULL;
    bool implicit_conf = false;
    mode_t old_umask;
    bool privileged = false;
    virLockDaemonConfigPtr config = NULL;

    struct option opts[] = {
        { "verbose", no_argument, &verbose, 1},
        { "daemon", no_argument, &godaemon, 1},
        { "config", required_argument, NULL, 'f'},
        { "pid-file", required_argument, NULL, 'p'},
        { "version", no_argument, NULL, OPT_VERSION },
        { "help", no_argument, NULL, '?' },
        {0, 0, 0, 0}
    };

    privileged = getuid() == 0;

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

        c = getopt_long(argc, argv, "ldf:p:t:v", opts, &optidx);

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
            if (!(pid_file = strdup(optarg)))
                exit(EXIT_FAILURE);
            break;

        case 'f':
            VIR_FREE(remote_config_file);
            if (!(remote_config_file = strdup(optarg)))
                exit(EXIT_FAILURE);
            break;

        case OPT_VERSION:
            virLockDaemonVersion(argv[0]);
            return 0;

        case '?':
            virLockDaemonUsage(argv[0], privileged);
            return 2;

        default:
            fprintf(stderr, _("%s: internal error: unknown flag: %c\n"),
                    argv[0], c);
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

    /* Ensure the rundir exists (on tmpfs on some systems) */
    if (privileged) {
        run_dir = strdup(LOCALSTATEDIR "/run/libvirt");
    } else {
        run_dir = virGetUserRuntimeDirectory();

        if (!run_dir) {
            VIR_ERROR(_("Can't determine user directory"));
            goto cleanup;
        }
    }
    if (!run_dir) {
        virReportOOMError();
        goto cleanup;
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

    /* If we have a pidfile set, claim it now, exiting if already taken */
    if ((pid_file_fd = virPidFileAcquirePath(pid_file, getpid())) < 0) {
        ret = VIR_LOCK_DAEMON_ERR_PIDFILE;
        goto cleanup;
    }

    if (!(lockDaemon = virLockDaemonNew(privileged))) {
        ret = VIR_LOCK_DAEMON_ERR_INIT;
        goto cleanup;
    }

    if (virLockDaemonSetupNetworking(lockDaemon->srv, sock_file) < 0) {
        ret = VIR_LOCK_DAEMON_ERR_NETWORK;
        goto cleanup;
    }

    if ((virLockDaemonSetupSignals(lockDaemon->srv)) < 0) {
        ret = VIR_LOCK_DAEMON_ERR_SIGNAL;
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
    ret = 0;

cleanup:
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
    VIR_FREE(run_dir);
    return ret;
}
