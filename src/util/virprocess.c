/*
 * virprocess.c: interaction with processes
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
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
 */


#include <config.h>

#include <signal.h>
#include <errno.h>
#include <sys/wait.h>

#include "virprocess.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"
#include "util.h"

#define VIR_FROM_THIS VIR_FROM_NONE

/**
 * virProcessTranslateStatus:
 * @status: child exit status to translate
 *
 * Translate an exit status into a malloc'd string.  Generic helper
 * for virCommandRun(), virCommandWait(), virRun(), and virProcessWait()
 * status argument, as well as raw waitpid().
 */
char *
virProcessTranslateStatus(int status)
{
    char *buf;
    if (WIFEXITED(status)) {
        ignore_value(virAsprintf(&buf, _("exit status %d"),
                                 WEXITSTATUS(status)));
    } else if (WIFSIGNALED(status)) {
        ignore_value(virAsprintf(&buf, _("fatal signal %d"),
                                 WTERMSIG(status)));
    } else {
        ignore_value(virAsprintf(&buf, _("invalid value %d"), status));
    }
    return buf;
}


#ifndef WIN32
/**
 * virProcessAbort:
 * @pid: child process to kill
 *
 * Abort a child process if PID is positive and that child is still
 * running, without issuing any errors or affecting errno.  Designed
 * for error paths where some but not all paths to the cleanup code
 * might have started the child process.  If @pid is 0 or negative,
 * this does nothing.
 */
void
virProcessAbort(pid_t pid)
{
    int saved_errno;
    int ret;
    int status;
    char *tmp = NULL;

    if (pid <= 0)
        return;

    /* See if intermediate process has exited; if not, try a nice
     * SIGTERM followed by a more severe SIGKILL.
     */
    saved_errno = errno;
    VIR_DEBUG("aborting child process %d", pid);
    while ((ret = waitpid(pid, &status, WNOHANG)) == -1 &&
           errno == EINTR);
    if (ret == pid) {
        tmp = virProcessTranslateStatus(status);
        VIR_DEBUG("process has ended: %s", tmp);
        goto cleanup;
    } else if (ret == 0) {
        VIR_DEBUG("trying SIGTERM to child process %d", pid);
        kill(pid, SIGTERM);
        usleep(10 * 1000);
        while ((ret = waitpid(pid, &status, WNOHANG)) == -1 &&
               errno == EINTR);
        if (ret == pid) {
            tmp = virProcessTranslateStatus(status);
            VIR_DEBUG("process has ended: %s", tmp);
            goto cleanup;
        } else if (ret == 0) {
            VIR_DEBUG("trying SIGKILL to child process %d", pid);
            kill(pid, SIGKILL);
            while ((ret = waitpid(pid, &status, 0)) == -1 &&
                   errno == EINTR);
            if (ret == pid) {
                tmp = virProcessTranslateStatus(status);
                VIR_DEBUG("process has ended: %s", tmp);
                goto cleanup;
            }
        }
    }
    VIR_DEBUG("failed to reap child %lld, abandoning it", (long long) pid);

cleanup:
    VIR_FREE(tmp);
    errno = saved_errno;
}
#else
void
virProcessAbort(pid_t pid)
{
    /* Not yet ported to mingw.  Any volunteers?  */
    VIR_DEBUG("failed to reap child %lld, abandoning it", (long long)pid);
}
#endif


/**
 * virProcessWait:
 * @pid: child to wait on
 * @exitstatus: optional status collection
 *
 * Wait for a child process to complete.
 * Return -1 on any error waiting for
 * completion. Returns 0 if the command
 * finished with the exit status set.  If @exitstatus is NULL, then the
 * child must exit with status 0 for this to succeed.
 */
int
virProcessWait(pid_t pid, int *exitstatus)
{
    int ret;
    int status;

    if (pid <= 0) {
        virReportSystemError(EINVAL, _("unable to wait for process %lld"),
                             (long long) pid);
        return -1;
    }

    /* Wait for intermediate process to exit */
    while ((ret = waitpid(pid, &status, 0)) == -1 &&
           errno == EINTR);

    if (ret == -1) {
        virReportSystemError(errno, _("unable to wait for process %lld"),
                             (long long) pid);
        return -1;
    }

    if (exitstatus == NULL) {
        if (status != 0) {
            char *st = virProcessTranslateStatus(status);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Child process (%lld) unexpected %s"),
                           (long long) pid, NULLSTR(st));
            VIR_FREE(st);
            return -1;
        }
    } else {
        *exitstatus = status;
    }

    return 0;
}


/* send signal to a single process */
int virProcessKill(pid_t pid, int sig)
{
    if (pid <= 1) {
        errno = ESRCH;
        return -1;
    }

#ifdef WIN32
    /* Mingw / Windows don't have many signals (AFAIK) */
    switch (sig) {
    case SIGINT:
        /* This does a Ctrl+C equiv */
        if (!GenerateConsoleCtrlEvent(CTRL_C_EVENT, pid)) {
            errno = ESRCH;
            return -1;
        }
        break;

    case SIGTERM:
        /* Since TerminateProcess is closer to SIG_KILL, we do
         * a Ctrl+Break equiv which is more pleasant like the
         * good old unix SIGTERM/HUP
         */
        if (!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)) {
            errno = ESRCH;
            return -1;
        }
        break;

    default:
    {
        HANDLE proc;
        proc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!proc) {
            errno = ESRCH; /* Not entirely accurate, but close enough */
            return -1;
        }

        /*
         * TerminateProcess is more or less equiv to SIG_KILL, in that
         * a process can't trap / block it
         */
        if (sig != 0 && !TerminateProcess(proc, sig)) {
            errno = ESRCH;
            return -1;
        }
        CloseHandle(proc);
    }
    }
    return 0;
#else
    return kill(pid, sig);
#endif
}


/*
 * Try to kill the process and verify it has exited
 *
 * Returns 0 if it was killed gracefully, 1 if it
 * was killed forcably, -1 if it is still alive,
 * or another error occurred.
 */
int
virProcessKillPainfully(pid_t pid, bool force)
{
    int i, ret = -1;
    const char *signame = "TERM";

    VIR_DEBUG("vpid=%d force=%d", pid, force);

    /* This loop sends SIGTERM, then waits a few iterations (10 seconds)
     * to see if it dies. If the process still hasn't exited, and
     * @force is requested, a SIGKILL will be sent, and this will
     * wait upto 5 seconds more for the process to exit before
     * returning.
     *
     * Note that setting @force could result in dataloss for the process.
     */
    for (i = 0 ; i < 75; i++) {
        int signum;
        if (i == 0) {
            signum = SIGTERM; /* kindly suggest it should exit */
        } else if ((i == 50) & force) {
            VIR_DEBUG("Timed out waiting after SIGTERM to process %d, "
                      "sending SIGKILL", pid);
            /* No SIGKILL kill on Win32 ! Use SIGABRT instead which our
             * virProcessKill proc will handle more or less like SIGKILL */
#ifdef WIN32
            signum = SIGABRT; /* kill it after a grace period */
            signame = "ABRT";
#else
            signum = SIGKILL; /* kill it after a grace period */
            signame = "KILL";
#endif
        } else {
            signum = 0; /* Just check for existence */
        }

        if (virProcessKill(pid, signum) < 0) {
            if (errno != ESRCH) {
                virReportSystemError(errno,
                                     _("Failed to terminate process %d with SIG%s"),
                                     pid, signame);
                goto cleanup;
            }
            ret = signum == SIGTERM ? 0 : 1;
            goto cleanup; /* process is dead */
        }

        usleep(200 * 1000);
    }

    VIR_DEBUG("Timed out waiting after SIGKILL to process %d", pid);

cleanup:
    return ret;
}
