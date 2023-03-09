/*
 * virdaemon.c: shared daemon setup code
 *
 * Copyright (C) 2020 Red Hat, Inc.
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

#include <sys/types.h>
#include <sys/stat.h>
#ifndef WIN32
# include <sys/wait.h>
#endif
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>

#include "virdaemon.h"
#include "virutil.h"
#include "virfile.h"
#include "virlog.h"
#include "viralloc.h"

#include "configmake.h"

#ifndef WIN32

int
virDaemonForkIntoBackground(const char *argv0)
{
    int statuspipe[2];
    pid_t pid;

    if (virPipeQuiet(statuspipe) < 0)
        return -1;

    pid = fork();
    switch (pid) {
    case 0:
        {
            /* intermediate child */
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
            case 0: /* grandchild */
                return statuspipe[1];
            case -1: /* error */
                goto cleanup;
            default: /* intermediate child succeeded */
                _exit(EXIT_SUCCESS);
            }

         cleanup:
            VIR_FORCE_CLOSE(stdoutfd);
            VIR_FORCE_CLOSE(stdinfd);
            VIR_FORCE_CLOSE(statuspipe[1]);
            _exit(EXIT_FAILURE);

        }

    case -1: /* error in parent */
        goto error;

    default:
        {
            /* parent */
            int got, exitstatus = 0;
            int ret;
            char status;

            VIR_FORCE_CLOSE(statuspipe[1]);

            /* We wait to make sure the first child forked successfully */
            if ((got = waitpid(pid, &exitstatus, 0)) < 0 ||
                got != pid ||
                exitstatus != 0) {
                goto error;
            }

            /* If we got here, then the grandchild was spawned, so we
             * must exit. Block until the second child initializes
             * successfully */
            ret = saferead(statuspipe[0], &status, 1);

            VIR_FORCE_CLOSE(statuspipe[0]);

            if (ret != 1) {
                fprintf(stderr,
                        _("%1$s: error: unable to determine if daemon is running: %2$s\n"),
                        argv0,
                        g_strerror(errno));
                exit(EXIT_FAILURE);
            } else if (status != 0) {
                fprintf(stderr,
                        _("%1$s: error: %2$s. Check /var/log/messages or run without --daemon for more info.\n"),
                        argv0,
                        virDaemonErrTypeToString(status));
                exit(EXIT_FAILURE);
            }
            _exit(EXIT_SUCCESS);
        }
    }

 error:
    VIR_FORCE_CLOSE(statuspipe[0]);
    VIR_FORCE_CLOSE(statuspipe[1]);
    return -1;
}


/*
 * Set up the logging environment
 * By default if daemonized all errors go to the logfile libvirtd.log,
 * but if verbose or error debugging is asked for then also output
 * informational and debug messages. Default size if 64 kB.
 */
int
virDaemonSetupLogging(const char *daemon_name,
                      unsigned int log_level,
                      char *log_filters,
                      char *log_outputs,
                      bool privileged,
                      bool verbose,
                      bool godaemon)
{
    if (virLogReset() < 0)
        return -1;

    /*
     * Libvirtd's order of precedence is:
     * cmdline > environment > config
     *
     * Given the precedence, we must process the variables in the opposite
     * order, each one overriding the previous.
     */
    if (log_level != 0 &&
        virLogSetDefaultPriority(log_level) < 0)
        return -1;

    /* In case the config is empty, both filters and outputs will become empty,
     * however we can't start with empty outputs, thus we'll need to define and
     * setup a default one.
     */
    if (virLogSetFilters(log_filters) < 0 ||
        virLogSetOutputs(log_outputs) < 0)
        return -1;

    /* If there are some environment variables defined, use those instead */
    if (virLogSetFromEnv() < 0)
        return -1;

    /*
     * Command line override for --verbose
     */
    if (verbose &&
        virLogGetDefaultPriority() > VIR_LOG_INFO &&
        virLogSetDefaultPriority(VIR_LOG_INFO) < 0)
        return -1;

    /* Define the default output. This is only applied if there was no setting
     * from either the config or the environment.
     */
    if (virLogSetDefaultOutput(daemon_name, godaemon, privileged) < 0)
        return -1;

    if (virLogGetNbOutputs() == 0 &&
        virLogSetOutputs(virLogGetDefaultOutput()) < 0)
        return -1;

    return 0;
}


int
virDaemonUnixSocketPaths(const char *sock_prefix,
                         bool privileged,
                         char *unix_sock_dir,
                         char **sockfile,
                         char **rosockfile,
                         char **admsockfile)
{
    int ret = -1;
    char *rundir = NULL;

    if (unix_sock_dir) {
        if (sockfile)
            *sockfile = g_strdup_printf("%s/%s-sock", unix_sock_dir, sock_prefix);

        if (privileged) {
            if (rosockfile)
                *rosockfile = g_strdup_printf("%s/%s-sock-ro",
                                              unix_sock_dir, sock_prefix);
            if (admsockfile)
                *admsockfile = g_strdup_printf("%s/%s-admin-sock",
                                               unix_sock_dir, sock_prefix);
        }
    } else {
        if (privileged) {
            if (sockfile)
                *sockfile = g_strdup_printf("%s/libvirt/%s-sock",
                                            RUNSTATEDIR, sock_prefix);
            if (rosockfile)
                *rosockfile = g_strdup_printf("%s/libvirt/%s-sock-ro",
                                              RUNSTATEDIR, sock_prefix);
            if (admsockfile)
                *admsockfile = g_strdup_printf("%s/libvirt/%s-admin-sock",
                                               RUNSTATEDIR, sock_prefix);
        } else {
            mode_t old_umask;

            rundir = virGetUserRuntimeDirectory();

            old_umask = umask(077);
            if (g_mkdir_with_parents(rundir, 0777) < 0) {
                umask(old_umask);
                goto cleanup;
            }
            umask(old_umask);

            if (sockfile)
                *sockfile = g_strdup_printf("%s/%s-sock", rundir, sock_prefix);
            if (admsockfile)
                *admsockfile = g_strdup_printf("%s/%s-admin-sock", rundir, sock_prefix);
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(rundir);
    return ret;
}

#else /* WIN32 */

int virDaemonForkIntoBackground(const char *argv0 G_GNUC_UNUSED)
{
    errno = ENOTSUP;
    return -1;
}

int virDaemonSetupLogging(const char *daemon_name G_GNUC_UNUSED,
                          unsigned int log_level G_GNUC_UNUSED,
                          char *log_filters G_GNUC_UNUSED,
                          char *log_outputs G_GNUC_UNUSED,
                          bool privileged G_GNUC_UNUSED,
                          bool verbose G_GNUC_UNUSED,
                          bool godaemon G_GNUC_UNUSED)
{
    /* NOOP */
    errno = ENOTSUP;
    return -1;
}

int virDaemonUnixSocketPaths(const char *sock_prefix G_GNUC_UNUSED,
                             bool privileged G_GNUC_UNUSED,
                             char *unix_sock_dir G_GNUC_UNUSED,
                             char **sockfile G_GNUC_UNUSED,
                             char **rosockfile G_GNUC_UNUSED,
                             char **adminSockfile G_GNUC_UNUSED)
{
    errno = ENOTSUP;
    return -1;
}

#endif /* WIN32 */
