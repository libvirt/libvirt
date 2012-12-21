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

#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sched.h>

#include "virprocess.h"
#include "virerror.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virutil.h"

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

    VIR_DEBUG("vpid=%lld force=%d", (long long)pid, force);

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
            VIR_DEBUG("Timed out waiting after SIGTERM to process %lld, "
                      "sending SIGKILL", (long long)pid);
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
                                     _("Failed to terminate process %lld with SIG%s"),
                                     (long long)pid, signame);
                goto cleanup;
            }
            ret = signum == SIGTERM ? 0 : 1;
            goto cleanup; /* process is dead */
        }

        usleep(200 * 1000);
    }

    VIR_DEBUG("Timed out waiting after SIGKILL to process %lld",
              (long long)pid);

cleanup:
    return ret;
}


#if HAVE_SCHED_GETAFFINITY

int virProcessSetAffinity(pid_t pid, virBitmapPtr map)
{
    int i;
    bool set = false;
# ifdef CPU_ALLOC
    /* New method dynamically allocates cpu mask, allowing unlimted cpus */
    int numcpus = 1024;
    size_t masklen;
    cpu_set_t *mask;

    /* Not only may the statically allocated cpu_set_t be too small,
     * but there is no way to ask the kernel what size is large enough.
     * So you have no option but to pick a size, try, catch EINVAL,
     * enlarge, and re-try.
     *
     * http://lkml.org/lkml/2009/7/28/620
     */
realloc:
    masklen = CPU_ALLOC_SIZE(numcpus);
    mask = CPU_ALLOC(numcpus);

    if (!mask) {
        virReportOOMError();
        return -1;
    }

    CPU_ZERO_S(masklen, mask);
    for (i = 0 ; i < virBitmapSize(map); i++) {
        if (virBitmapGetBit(map, i, &set) < 0)
            return -1;
        if (set)
            CPU_SET_S(i, masklen, mask);
    }

    if (sched_setaffinity(pid, masklen, mask) < 0) {
        CPU_FREE(mask);
        if (errno == EINVAL &&
            numcpus < (1024 << 8)) { /* 262144 cpus ought to be enough for anyone */
            numcpus = numcpus << 2;
            goto realloc;
        }
        virReportSystemError(errno,
                             _("cannot set CPU affinity on process %d"), pid);
        return -1;
    }
    CPU_FREE(mask);
# else
    /* Legacy method uses a fixed size cpu mask, only allows up to 1024 cpus */
    cpu_set_t mask;

    CPU_ZERO(&mask);
    for (i = 0 ; i < virBitmapSize(map); i++) {
        if (virBitmapGetBit(map, i, &set) < 0)
            return -1;
        if (set)
            CPU_SET(i, &mask);
    }

    if (sched_setaffinity(pid, sizeof(mask), &mask) < 0) {
        virReportSystemError(errno,
                             _("cannot set CPU affinity on process %d"), pid);
        return -1;
    }
# endif

    return 0;
}

int virProcessGetAffinity(pid_t pid,
                          virBitmapPtr *map,
                          int maxcpu)
{
    int i;
# ifdef CPU_ALLOC
    /* New method dynamically allocates cpu mask, allowing unlimted cpus */
    int numcpus = 1024;
    size_t masklen;
    cpu_set_t *mask;

    /* Not only may the statically allocated cpu_set_t be too small,
     * but there is no way to ask the kernel what size is large enough.
     * So you have no option but to pick a size, try, catch EINVAL,
     * enlarge, and re-try.
     *
     * http://lkml.org/lkml/2009/7/28/620
     */
realloc:
    masklen = CPU_ALLOC_SIZE(numcpus);
    mask = CPU_ALLOC(numcpus);

    if (!mask) {
        virReportOOMError();
        return -1;
    }

    CPU_ZERO_S(masklen, mask);
    if (sched_getaffinity(pid, masklen, mask) < 0) {
        CPU_FREE(mask);
        if (errno == EINVAL &&
            numcpus < (1024 << 8)) { /* 262144 cpus ought to be enough for anyone */
            numcpus = numcpus << 2;
            goto realloc;
        }
        virReportSystemError(errno,
                             _("cannot get CPU affinity of process %d"), pid);
        return -1;
    }

    *map = virBitmapNew(maxcpu);
    if (!*map) {
        virReportOOMError();
        return -1;
    }

    for (i = 0 ; i < maxcpu ; i++)
        if (CPU_ISSET_S(i, masklen, mask))
            ignore_value(virBitmapSetBit(*map, i));
    CPU_FREE(mask);
# else
    /* Legacy method uses a fixed size cpu mask, only allows up to 1024 cpus */
    cpu_set_t mask;

    CPU_ZERO(&mask);
    if (sched_getaffinity(pid, sizeof(mask), &mask) < 0) {
        virReportSystemError(errno,
                             _("cannot get CPU affinity of process %d"), pid);
        return -1;
    }

    for (i = 0 ; i < maxcpu ; i++)
        if (CPU_ISSET(i, &mask))
            ignore_value(virBitmapSetBit(*map, i));
# endif

    return 0;
}

#elif defined(__FreeBSD__)

int virProcessSetAffinity(pid_t pid ATTRIBUTE_UNUSED,
                          virBitmapPtr map)
{
    if (!virBitmapIsAllSet(map)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("setting process affinity isn't supported "
                         "on FreeBSD yet"));
        return -1;
    }

    return 0;
}

int virProcessGetAffinity(pid_t pid ATTRIBUTE_UNUSED,
                          virBitmapPtr *map,
                          int maxcpu)
{
    if (!(*map = virBitmapNew(maxcpu))) {
        virReportOOMError();
        return -1;
    }
    virBitmapSetAll(*map);

    return 0;
}

#else /* HAVE_SCHED_GETAFFINITY */

int virProcessSetAffinity(pid_t pid ATTRIBUTE_UNUSED,
                          virBitmapPtr map ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Process CPU affinity is not supported on this platform"));
    return -1;
}

int virProcessGetAffinity(pid_t pid ATTRIBUTE_UNUSED,
                          virBitmapPtr *map ATTRIBUTE_UNUSED,
                          int maxcpu ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Process CPU affinity is not supported on this platform"));
    return -1;
}
#endif /* HAVE_SCHED_GETAFFINITY */


#if HAVE_SETNS
int virProcessGetNamespaces(pid_t pid,
                            size_t *nfdlist,
                            int **fdlist)
{
    int ret = -1;
    DIR *dh = NULL;
    struct dirent *de;
    char *nsdir = NULL;
    char *nsfile = NULL;
    size_t i;

    *nfdlist = 0;
    *fdlist = NULL;

    if (virAsprintf(&nsdir, "/proc/%llu/ns",
                    (unsigned long long)pid) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (!(dh = opendir(nsdir))) {
        virReportSystemError(errno,
                             _("Cannot read directory %s"),
                             nsdir);
        goto cleanup;
    }

    while ((de = readdir(dh))) {
        int fd;
        if (de->d_name[0] == '.')
            continue;

        if (VIR_EXPAND_N(*fdlist, *nfdlist, 1) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (virAsprintf(&nsfile, "%s/%s", nsdir, de->d_name) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if ((fd = open(nsfile, O_RDWR)) < 0) {
            virReportSystemError(errno,
                                 _("Unable to open %s"),
                                 nsfile);
            goto cleanup;
        }

        (*fdlist)[(*nfdlist)-1] = fd;

        VIR_FREE(nsfile);
    }

    ret = 0;

cleanup:
    if (dh)
        closedir(dh);
    VIR_FREE(nsdir);
    VIR_FREE(nsfile);
    if (ret < 0) {
        for (i = 0 ; i < *nfdlist ; i++) {
            VIR_FORCE_CLOSE((*fdlist)[i]);
        }
        VIR_FREE(*fdlist);
    }
    return ret;
}


int virProcessSetNamespaces(size_t nfdlist,
                            int *fdlist)
{
    size_t i;

    if (nfdlist == 0) {
        virReportInvalidArg(nfdlist, "%s",
                             _("Expected at least one file descriptor"));
        return -1;
    }
    for (i = 0 ; i < nfdlist ; i++) {
        if (setns(fdlist[i], 0) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to join domain namespace"));
            return -1;
        }
    }
    return 0;
}
#else /* ! HAVE_SETNS */
int virProcessGetNamespaces(pid_t pid,
                            size_t *nfdlist ATTRIBUTE_UNUSED,
                            int **fdlist ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Cannot get namespaces for %llu"),
                         (unsigned long long)pid);
    return -1;
}


int virProcessSetNamespaces(size_t nfdlist ATTRIBUTE_UNUSED,
                            int *fdlist ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Cannot set namespaces"));
    return -1;
}
#endif /* ! HAVE_SETNS */
