/*
 * virprocess.c: interaction with processes
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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

#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>
#if HAVE_SETRLIMIT
# include <sys/time.h>
# include <sys/resource.h>
#endif
#include <sched.h>

#ifdef __FreeBSD__
# include <sys/param.h>
# include <sys/sysctl.h>
# include <sys/user.h>
#endif

#ifdef HAVE_BSD_CPU_AFFINITY
# include <sys/cpuset.h>
#endif

#include "viratomic.h"
#include "virprocess.h"
#include "virerror.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virutil.h"
#include "virstring.h"
#include "vircommand.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.process");

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
 * @raw: whether to pass non-normal status back to caller
 *
 * Wait for a child process to complete.  If @pid is -1, do nothing, but
 * return -1 (useful for error cleanup, and assumes an earlier message was
 * already issued).  All other pids issue an error message on failure.
 *
 * If @exitstatus is NULL, then the child must exit normally with status 0.
 * Otherwise, if @raw is false, the child must exit normally, and
 * @exitstatus will contain the final exit status (no need for the caller
 * to use WEXITSTATUS()).  If @raw is true, then the result of waitpid() is
 * returned in @exitstatus, and the caller must use WIFEXITED() and friends
 * to decipher the child's status.
 *
 * Returns 0 on a successful wait.  Returns -1 on any error waiting for
 * completion, or if the command completed with a status that cannot be
 * reflected via the choice of @exitstatus and @raw.
 */
int
virProcessWait(pid_t pid, int *exitstatus, bool raw)
{
    int ret;
    int status;

    if (pid <= 0) {
        if (pid != -1)
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
        if (status != 0)
            goto error;
    } else if (raw) {
        *exitstatus = status;
    } else if (WIFEXITED(status)) {
        *exitstatus = WEXITSTATUS(status);
    } else {
        goto error;
    }

    return 0;

 error:
    {
        char *st = virProcessTranslateStatus(status);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Child process (%lld) unexpected %s"),
                       (long long) pid, NULLSTR(st));
        VIR_FREE(st);
    }
    return -1;
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
 * was killed forcibly, -1 if it is still alive,
 * or another error occurred.
 */
int
virProcessKillPainfully(pid_t pid, bool force)
{
    size_t i;
    int ret = -1;
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
    for (i = 0; i < 75; i++) {
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

    virReportSystemError(EBUSY,
                         _("Failed to terminate process %lld with SIG%s"),
                         (long long)pid, signame);

 cleanup:
    return ret;
}


#if HAVE_SCHED_GETAFFINITY

int virProcessSetAffinity(pid_t pid, virBitmapPtr map)
{
    size_t i;
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
    for (i = 0; i < virBitmapSize(map); i++) {
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
    for (i = 0; i < virBitmapSize(map); i++) {
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
    size_t i;
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
    if (!*map)
        return -1;

    for (i = 0; i < maxcpu; i++)
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

    for (i = 0; i < maxcpu; i++)
        if (CPU_ISSET(i, &mask))
            ignore_value(virBitmapSetBit(*map, i));
# endif

    return 0;
}

#elif defined(HAVE_BSD_CPU_AFFINITY)

int virProcessSetAffinity(pid_t pid ATTRIBUTE_UNUSED,
                          virBitmapPtr map)
{
    size_t i;
    cpuset_t mask;
    bool set = false;

    CPU_ZERO(&mask);
    for (i = 0; i < virBitmapSize(map); i++) {
        if (virBitmapGetBit(map, i, &set) < 0)
            return -1;
        if (set)
            CPU_SET(i, &mask);
    }

    if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, pid,
                           sizeof(mask), &mask) != 0) {
        virReportSystemError(errno,
                             _("cannot set CPU affinity on process %d"), pid);
        return -1;
    }

    return 0;
}

int virProcessGetAffinity(pid_t pid,
                          virBitmapPtr *map,
                          int maxcpu)
{
    size_t i;
    cpuset_t mask;

    if (!(*map = virBitmapNew(maxcpu)))
        return -1;

    CPU_ZERO(&mask);
    if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, pid,
                           sizeof(mask), &mask) != 0) {
        virReportSystemError(errno,
                             _("cannot get CPU affinity of process %d"), pid);
        return -1;
    }

    for (i = 0; i < maxcpu; i++)
        if (CPU_ISSET(i, &mask))
            ignore_value(virBitmapSetBit(*map, i));

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
    char *nsfile = NULL;
    size_t i = 0;
    const char *ns[] = { "user", "ipc", "uts", "net", "pid", "mnt" };

    *nfdlist = 0;
    *fdlist = NULL;

    for (i = 0; i < ARRAY_CARDINALITY(ns); i++) {
        int fd;

        if (virAsprintf(&nsfile, "/proc/%llu/ns/%s",
                        (unsigned long long)pid,
                        ns[i]) < 0)
            goto cleanup;

        if ((fd = open(nsfile, O_RDWR)) >= 0) {
            if (VIR_EXPAND_N(*fdlist, *nfdlist, 1) < 0) {
                VIR_FORCE_CLOSE(fd);
                goto cleanup;
            }

            (*fdlist)[(*nfdlist)-1] = fd;
        }

        VIR_FREE(nsfile);
    }

    ret = 0;

 cleanup:
    VIR_FREE(nsfile);
    if (ret < 0) {
        for (i = 0; i < *nfdlist; i++)
            VIR_FORCE_CLOSE((*fdlist)[i]);
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
    for (i = 0; i < nfdlist; i++) {
        /* We get EINVAL if new NS is same as the current
         * NS, or if the fd namespace doesn't match the
         * type passed to setns()'s second param. Since we
         * pass 0, we know the EINVAL is harmless
         */
        if (setns(fdlist[i], 0) < 0 &&
            errno != EINVAL) {
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

#if HAVE_PRLIMIT
static int
virProcessPrLimit(pid_t pid, int resource, struct rlimit *rlim)
{
    return prlimit(pid, resource, rlim, NULL);
}
#elif HAVE_SETRLIMIT
static int
virProcessPrLimit(pid_t pid ATTRIBUTE_UNUSED,
                  int resource ATTRIBUTE_UNUSED,
                  struct rlimit *rlim ATTRIBUTE_UNUSED)
{
    errno = ENOSYS;
    return -1;
}
#endif

#if HAVE_SETRLIMIT && defined(RLIMIT_MEMLOCK)
int
virProcessSetMaxMemLock(pid_t pid, unsigned long long bytes)
{
    struct rlimit rlim;

    if (bytes == 0)
        return 0;

    rlim.rlim_cur = rlim.rlim_max = bytes;
    if (pid == 0) {
        if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
            virReportSystemError(errno,
                                 _("cannot limit locked memory to %llu"),
                                 bytes);
            return -1;
        }
    } else {
        if (virProcessPrLimit(pid, RLIMIT_MEMLOCK, &rlim) < 0) {
            virReportSystemError(errno,
                                 _("cannot limit locked memory "
                                   "of process %lld to %llu"),
                                 (long long int)pid, bytes);
            return -1;
        }
    }
    return 0;
}
#else /* ! (HAVE_SETRLIMIT && defined(RLIMIT_MEMLOCK)) */
int
virProcessSetMaxMemLock(pid_t pid ATTRIBUTE_UNUSED, unsigned long long bytes)
{
    if (bytes == 0)
        return 0;

    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}
#endif /* ! (HAVE_SETRLIMIT && defined(RLIMIT_MEMLOCK)) */


#if HAVE_SETRLIMIT && defined(RLIMIT_NPROC)
int
virProcessSetMaxProcesses(pid_t pid, unsigned int procs)
{
    struct rlimit rlim;

    if (procs == 0)
        return 0;

    rlim.rlim_cur = rlim.rlim_max = procs;
    if (pid == 0) {
        if (setrlimit(RLIMIT_NPROC, &rlim) < 0) {
            virReportSystemError(errno,
                                 _("cannot limit number of subprocesses to %u"),
                                 procs);
            return -1;
        }
    } else {
        if (virProcessPrLimit(pid, RLIMIT_NPROC, &rlim) < 0) {
            virReportSystemError(errno,
                                 _("cannot limit number of subprocesses "
                                   "of process %lld to %u"),
                                 (long long int)pid, procs);
            return -1;
        }
    }
    return 0;
}
#else /* ! (HAVE_SETRLIMIT && defined(RLIMIT_NPROC)) */
int
virProcessSetMaxProcesses(pid_t pid ATTRIBUTE_UNUSED, unsigned int procs)
{
    if (procs == 0)
        return 0;

    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}
#endif /* ! (HAVE_SETRLIMIT && defined(RLIMIT_NPROC)) */

#if HAVE_SETRLIMIT && defined(RLIMIT_NOFILE)
int
virProcessSetMaxFiles(pid_t pid, unsigned int files)
{
    struct rlimit rlim;

    if (files == 0)
        return 0;

   /* Max number of opened files is one greater than actual limit. See
    * man setrlimit.
    *
    * NB: That indicates to me that we would want the following code
    * to say "files - 1", but the original of this code in
    * qemu_process.c also had files + 1, so this preserves current
    * behavior.
    */
    rlim.rlim_cur = rlim.rlim_max = files + 1;
    if (pid == 0) {
        if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
            virReportSystemError(errno,
                                 _("cannot limit number of open files to %u"),
                                 files);
            return -1;
        }
    } else {
        if (virProcessPrLimit(pid, RLIMIT_NOFILE, &rlim) < 0) {
            virReportSystemError(errno,
                                 _("cannot limit number of open files "
                                   "of process %lld to %u"),
                                 (long long int)pid, files);
            return -1;
        }
    }
    return 0;
}
#else /* ! (HAVE_SETRLIMIT && defined(RLIMIT_NOFILE)) */
int
virProcessSetMaxFiles(pid_t pid ATTRIBUTE_UNUSED, unsigned int files)
{
    if (files == 0)
        return 0;

    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}
#endif /* ! (HAVE_SETRLIMIT && defined(RLIMIT_NOFILE)) */

#ifdef __linux__
/*
 * Port of code from polkitunixprocess.c under terms
 * of the LGPLv2+
 */
int virProcessGetStartTime(pid_t pid,
                           unsigned long long *timestamp)
{
    char *filename = NULL;
    char *buf = NULL;
    char *tmp;
    int ret = -1;
    int len;
    char **tokens = NULL;

    if (virAsprintf(&filename, "/proc/%llu/stat",
                    (unsigned long long)pid) < 0)
        return -1;

    if ((len = virFileReadAll(filename, 1024, &buf)) < 0)
        goto cleanup;

    /* start time is the token at index 19 after the '(process name)' entry - since only this
     * field can contain the ')' character, search backwards for this to avoid malicious
     * processes trying to fool us
     */

    if (!(tmp = strrchr(buf, ')'))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot find start time in %s"),
                       filename);
        goto cleanup;
    }
    tmp += 2; /* skip ') ' */
    if ((tmp - buf) >= len) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot find start time in %s"),
                       filename);
        goto cleanup;
    }

    tokens = virStringSplit(tmp, " ", 0);

    if (virStringListLength(tokens) < 20) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot find start time in %s"),
                       filename);
        goto cleanup;
    }

    if (virStrToLong_ull(tokens[19],
                         NULL,
                         10,
                         timestamp) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse start time %s in %s"),
                       tokens[19], filename);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virStringFreeList(tokens);
    VIR_FREE(filename);
    VIR_FREE(buf);
    return ret;
}
#elif defined(__FreeBSD__)
int virProcessGetStartTime(pid_t pid,
                           unsigned long long *timestamp)
{
    struct kinfo_proc p;
    int mib[4];
    size_t len = 4;

    sysctlnametomib("kern.proc.pid", mib, &len);

    len = sizeof(struct kinfo_proc);
    mib[3] = pid;

    if (sysctl(mib, 4, &p, &len, NULL, 0) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to query process ID start time"));
        return -1;
    }

    *timestamp = (unsigned long long)p.ki_start.tv_sec;

    return 0;

}
#else
int virProcessGetStartTime(pid_t pid,
                           unsigned long long *timestamp)
{
    static int warned = 0;
    if (virAtomicIntInc(&warned) == 1) {
        VIR_WARN("Process start time of pid %llu not available on this platform",
                 (unsigned long long)pid);
        warned = true;
    }
    *timestamp = 0;
    return 0;
}
#endif


#ifdef HAVE_SETNS
static int virProcessNamespaceHelper(int errfd,
                                     pid_t pid,
                                     virProcessNamespaceCallback cb,
                                     void *opaque)
{
    char *path;
    int fd = -1;
    int ret = -1;

    if (virAsprintf(&path, "/proc/%llu/ns/mnt", (unsigned long long)pid) < 0)
        goto cleanup;

    if ((fd = open(path, O_RDONLY)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Kernel does not provide mount namespace"));
        goto cleanup;
    }

    if (setns(fd, 0) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to enter mount namespace"));
        goto cleanup;
    }

    ret = cb(pid, opaque);

 cleanup:
    if (ret < 0) {
        virErrorPtr err = virGetLastError();
        if (err) {
            size_t len = strlen(err->message) + 1;
            ignore_value(safewrite(errfd, err->message, len));
        }
    }
    VIR_FREE(path);
    VIR_FORCE_CLOSE(fd);
    return ret;
}

/* Run cb(opaque) in the mount namespace of pid.  Return -1 with error
 * message raised if we fail to run the child, if the child dies from
 * a signal, or if the child has status EXIT_CANCELED; otherwise return
 * the exit status of the child. The callback will be run in a child
 * process so must be careful to only use async signal safe functions.
 */
int
virProcessRunInMountNamespace(pid_t pid,
                              virProcessNamespaceCallback cb,
                              void *opaque)
{
    int ret = -1;
    pid_t child = -1;
    int errfd[2] = { -1, -1 };

    if (pipe2(errfd, O_CLOEXEC) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot create pipe for child"));
        return -1;
    }

    if ((child = virFork()) < 0)
        goto cleanup;

    if (child == 0) {
        VIR_FORCE_CLOSE(errfd[0]);
        ret = virProcessNamespaceHelper(errfd[1], pid,
                                        cb, opaque);
        VIR_FORCE_CLOSE(errfd[1]);
        _exit(ret < 0 ? EXIT_CANCELED : ret);
    } else {
        char *buf = NULL;
        int status;

        VIR_FORCE_CLOSE(errfd[1]);
        ignore_value(virFileReadHeaderFD(errfd[0], 1024, &buf));
        ret = virProcessWait(child, &status, false);
        if (!ret)
            ret = status == EXIT_CANCELED ? -1 : status;
        VIR_FREE(buf);
    }

 cleanup:
    VIR_FORCE_CLOSE(errfd[0]);
    VIR_FORCE_CLOSE(errfd[1]);
    return ret;
}
#else /* !HAVE_SETNS */
int
virProcessRunInMountNamespace(pid_t pid ATTRIBUTE_UNUSED,
                              virProcessNamespaceCallback cb ATTRIBUTE_UNUSED,
                              void *opaque ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Mount namespaces are not available on this platform"));
    return -1;
}
#endif


/**
 * virProcessExitWithStatus:
 * @status: raw status to be reproduced when this process dies
 *
 * Given a raw status obtained by waitpid() or similar, attempt to
 * make this process exit in the same manner.  If the child died by
 * signal, reset that signal handler to default and raise the same
 * signal; if that doesn't kill this process, then exit with 128 +
 * signal number.  If @status can't be deciphered, use
 * EXIT_CANNOT_INVOKE.
 *
 * Never returns.
 */
void
virProcessExitWithStatus(int status)
{
    int value = EXIT_CANNOT_INVOKE;

    if (WIFEXITED(status)) {
        value = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        struct sigaction act;
        sigset_t sigs;

        if (sigemptyset(&sigs) == 0 &&
            sigaddset(&sigs, WTERMSIG(status)) == 0)
            sigprocmask(SIG_UNBLOCK, &sigs, NULL);
        memset(&act, 0, sizeof(act));
        act.sa_handler = SIG_DFL;
        sigfillset(&act.sa_mask);
        sigaction(WTERMSIG(status), &act, NULL);
        raise(WTERMSIG(status));
        value = 128 + WTERMSIG(status);
    }
    exit(value);
}
