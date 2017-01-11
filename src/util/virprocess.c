/*
 * virprocess.c: interaction with processes
 *
 * Copyright (C) 2010-2015 Red Hat, Inc.
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
#include <unistd.h>
#if HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#endif
#if HAVE_SETRLIMIT
# include <sys/time.h>
# include <sys/resource.h>
#endif
#if HAVE_SCHED_SETSCHEDULER
# include <sched.h>
#endif

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || HAVE_BSD_CPU_AFFINITY
# include <sys/param.h>
#endif

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
# include <sys/sysctl.h>
# include <sys/user.h>
#endif

#if HAVE_BSD_CPU_AFFINITY
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

#ifdef __linux__
/*
 * Workaround older glibc. While kernel may support the setns
 * syscall, the glibc wrapper might not exist. If that's the
 * case, use our own.
 */
# ifndef __NR_setns
#  if defined(__x86_64__)
#   define __NR_setns 308
#  elif defined(__i386__)
#   define __NR_setns 346
#  elif defined(__arm__)
#   define __NR_setns 375
#  elif defined(__aarch64__)
#   define __NR_setns 375
#  elif defined(__powerpc__)
#   define __NR_setns 350
#  elif defined(__s390__)
#   define __NR_setns 339
#  endif
# endif

# ifndef HAVE_SETNS
#  if defined(__NR_setns)
#   include <sys/syscall.h>

static inline int setns(int fd, int nstype)
{
    return syscall(__NR_setns, fd, nstype);
}
#  else /* !__NR_setns */
#   error Please determine the syscall number for setns on your architecture
#  endif
# endif
#else /* !__linux__ */
static inline int setns(int fd ATTRIBUTE_UNUSED, int nstype ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Namespaces are not supported on this platform."));
    return -1;
}
#endif

VIR_ENUM_IMPL(virProcessSchedPolicy, VIR_PROC_POLICY_LAST,
              "none",
              "batch",
              "idle",
              "fifo",
              "rr");

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
        ignore_value(virAsprintfQuiet(&buf, _("exit status %d"),
                                      WEXITSTATUS(status)));
    } else if (WIFSIGNALED(status)) {
        ignore_value(virAsprintfQuiet(&buf, _("fatal signal %d"),
                                      WTERMSIG(status)));
    } else {
        ignore_value(virAsprintfQuiet(&buf, _("invalid value %d"), status));
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
     * wait up to 5 seconds more for the process to exit before
     * returning.
     *
     * Note that setting @force could result in dataloss for the process.
     */
    for (i = 0; i < 75; i++) {
        int signum;
        if (i == 0) {
            signum = SIGTERM; /* kindly suggest it should exit */
        } else if (i == 50 && force) {
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
    VIR_DEBUG("Set process affinity on %lld", (long long)pid);
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
        if (virBitmapIsBitSet(map, i))
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
        if (virBitmapIsBitSet(map, i))
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

virBitmapPtr
virProcessGetAffinity(pid_t pid)
{
    size_t i;
    cpu_set_t *mask;
    size_t masklen;
    size_t ncpus;
    virBitmapPtr ret = NULL;

# ifdef CPU_ALLOC
    /* 262144 cpus ought to be enough for anyone */
    ncpus = 1024 << 8;
    masklen = CPU_ALLOC_SIZE(ncpus);
    mask = CPU_ALLOC(ncpus);

    if (!mask) {
        virReportOOMError();
        return NULL;
    }

    CPU_ZERO_S(masklen, mask);
# else
    ncpus = 1024;
    if (VIR_ALLOC(mask) < 0)
        return NULL;

    masklen = sizeof(*mask);
    CPU_ZERO(mask);
# endif

    if (sched_getaffinity(pid, masklen, mask) < 0) {
        virReportSystemError(errno,
                             _("cannot get CPU affinity of process %d"), pid);
        goto cleanup;
    }

    if (!(ret = virBitmapNew(ncpus)))
          goto cleanup;

    for (i = 0; i < ncpus; i++) {
# ifdef CPU_ALLOC
         /* coverity[overrun-local] */
        if (CPU_ISSET_S(i, masklen, mask))
            ignore_value(virBitmapSetBit(ret, i));
# else
        if (CPU_ISSET(i, mask))
            ignore_value(virBitmapSetBit(ret, i));
# endif
    }

 cleanup:
# ifdef CPU_ALLOC
    CPU_FREE(mask);
# else
    VIR_FREE(mask);
# endif

    return ret;
}

#elif defined(HAVE_BSD_CPU_AFFINITY)

int virProcessSetAffinity(pid_t pid,
                          virBitmapPtr map)
{
    size_t i;
    cpuset_t mask;

    CPU_ZERO(&mask);
    for (i = 0; i < virBitmapSize(map); i++) {
        if (virBitmapIsBitSet(map, i))
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

virBitmapPtr
virProcessGetAffinity(pid_t pid)
{
    size_t i;
    cpuset_t mask;
    virBitmapPtr ret = NULL;

    CPU_ZERO(&mask);
    if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, pid,
                           sizeof(mask), &mask) != 0) {
        virReportSystemError(errno,
                             _("cannot get CPU affinity of process %d"), pid);
        return NULL;
    }

    if (!(ret = virBitmapNew(sizeof(mask) * 8)))
        return NULL;

    for (i = 0; i < sizeof(mask) * 8; i++)
        if (CPU_ISSET(i, &mask))
            ignore_value(virBitmapSetBit(ret, i));

    return ret;
}

#else /* HAVE_SCHED_GETAFFINITY */

int virProcessSetAffinity(pid_t pid ATTRIBUTE_UNUSED,
                          virBitmapPtr map ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Process CPU affinity is not supported on this platform"));
    return -1;
}

virBitmapPtr
virProcessGetAffinity(pid_t pid ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Process CPU affinity is not supported on this platform"));
    return NULL;
}
#endif /* HAVE_SCHED_GETAFFINITY */


int virProcessGetPids(pid_t pid, size_t *npids, pid_t **pids)
{
    int ret = -1;
    char *taskPath = NULL;
    DIR *dir = NULL;
    int value;
    struct dirent *ent;

    *npids = 0;
    *pids = NULL;

    if (virAsprintf(&taskPath, "/proc/%llu/task", (long long) pid) < 0)
        goto cleanup;

    if (virDirOpen(&dir, taskPath) < 0)
        goto cleanup;

    while ((value = virDirRead(dir, &ent, taskPath)) > 0) {
        long long tmp;
        pid_t tmp_pid;

        if (virStrToLong_ll(ent->d_name, NULL, 10, &tmp) < 0)
            goto cleanup;
        tmp_pid = tmp;

        if (VIR_APPEND_ELEMENT(*pids, *npids, tmp_pid) < 0)
            goto cleanup;
    }

    if (value < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_DIR_CLOSE(dir);
    VIR_FREE(taskPath);
    if (ret < 0)
        VIR_FREE(*pids);
    return ret;
}


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
                        (long long) pid,
                        ns[i]) < 0)
            goto cleanup;

        if ((fd = open(nsfile, O_RDONLY)) >= 0) {
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
        if (fdlist[i] < 0)
            continue;

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

#if HAVE_PRLIMIT
static int
virProcessPrLimit(pid_t pid,
                  int resource,
                  const struct rlimit *new_limit,
                  struct rlimit *old_limit)
{
    return prlimit(pid, resource, new_limit, old_limit);
}
#elif HAVE_SETRLIMIT
static int
virProcessPrLimit(pid_t pid ATTRIBUTE_UNUSED,
                  int resource ATTRIBUTE_UNUSED,
                  const struct rlimit *new_limit ATTRIBUTE_UNUSED,
                  struct rlimit *old_limit ATTRIBUTE_UNUSED)
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
        if (virProcessPrLimit(pid, RLIMIT_MEMLOCK, &rlim, NULL) < 0) {
            virReportSystemError(errno,
                                 _("cannot limit locked memory "
                                   "of process %lld to %llu"),
                                 (long long int)pid, bytes);
            return -1;
        }
    }

    VIR_DEBUG("Locked memory for process %lld limited to %llu bytes",
              (long long int) pid, bytes);

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

#if HAVE_GETRLIMIT && defined(RLIMIT_MEMLOCK)
int
virProcessGetMaxMemLock(pid_t pid,
                        unsigned long long *bytes)
{
    struct rlimit rlim;

    if (!bytes)
        return 0;

    if (pid == 0) {
        if (getrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
            virReportSystemError(errno,
                                 "%s",
                                 _("cannot get locked memory limit"));
            return -1;
        }
    } else {
        if (virProcessPrLimit(pid, RLIMIT_MEMLOCK, NULL, &rlim) < 0) {
            virReportSystemError(errno,
                                 _("cannot get locked memory limit "
                                   "of process %lld"),
                                 (long long int) pid);
            return -1;
        }
    }

    /* virProcessSetMaxMemLock() sets both rlim_cur and rlim_max to the
     * same value, so we can retrieve just rlim_max here */
    *bytes = rlim.rlim_max;

    return 0;
}
#else /* ! (HAVE_GETRLIMIT && defined(RLIMIT_MEMLOCK)) */
int
virProcessGetMaxMemLock(pid_t pid ATTRIBUTE_UNUSED,
                        unsigned long long *bytes)
{
    if (!bytes)
        return 0;

    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}
#endif /* ! (HAVE_GETRLIMIT && defined(RLIMIT_MEMLOCK)) */

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
        if (virProcessPrLimit(pid, RLIMIT_NPROC, &rlim, NULL) < 0) {
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
        if (virProcessPrLimit(pid, RLIMIT_NOFILE, &rlim, NULL) < 0) {
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

#if HAVE_SETRLIMIT && defined(RLIMIT_CORE)
int
virProcessSetMaxCoreSize(pid_t pid, unsigned long long bytes)
{
    struct rlimit rlim;

    rlim.rlim_cur = rlim.rlim_max = bytes;
    if (pid == 0) {
        if (setrlimit(RLIMIT_CORE, &rlim) < 0) {
            virReportSystemError(errno,
                                 _("cannot limit core file size to %llu"),
                                 bytes);
            return -1;
        }
    } else {
        if (virProcessPrLimit(pid, RLIMIT_CORE, &rlim, NULL) < 0) {
            virReportSystemError(errno,
                                 _("cannot limit core file size "
                                   "of process %lld to %llu"),
                                 (long long int)pid, bytes);
            return -1;
        }
    }
    return 0;
}
#else /* ! (HAVE_SETRLIMIT && defined(RLIMIT_CORE)) */
int
virProcessSetMaxCoreSize(pid_t pid ATTRIBUTE_UNUSED,
                         unsigned long long bytes)
{
    if (bytes == 0)
        return 0;

    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}
#endif /* ! (HAVE_SETRLIMIT && defined(RLIMIT_CORE)) */


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

    if (virAsprintf(&filename, "/proc/%llu/stat", (long long) pid) < 0)
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

    if (virStringListLength((const char * const *)tokens) < 20) {
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
    virStringListFree(tokens);
    VIR_FREE(filename);
    VIR_FREE(buf);
    return ret;
}
#elif defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
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
    static int warned;
    if (virAtomicIntInc(&warned) == 1) {
        VIR_WARN("Process start time of pid %lld not available on this platform",
                 (long long) pid);
    }
    *timestamp = 0;
    return 0;
}
#endif


static int virProcessNamespaceHelper(int errfd,
                                     pid_t pid,
                                     virProcessNamespaceCallback cb,
                                     void *opaque)
{
    char *path;
    int fd = -1;
    int ret = -1;

    if (virAsprintf(&path, "/proc/%lld/ns/mnt", (long long) pid) < 0)
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


#if defined(HAVE_SYS_MOUNT_H) && defined(HAVE_UNSHARE)
int
virProcessSetupPrivateMountNS(void)
{
    int ret = -1;

    if (unshare(CLONE_NEWNS) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot unshare mount namespace"));
        goto cleanup;
    }

    if (mount("", "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to switch root mount into slave mode"));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

#else /* !defined(HAVE_SYS_MOUNT_H) || !defined(HAVE_UNSHARE) */

int
virProcessSetupPrivateMountNS(void)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Namespaces are not supported on this platform."));
    return -1;
}
#endif /* !defined(HAVE_SYS_MOUNT_H) || !defined(HAVE_UNSHARE) */

#if defined(__linux__)
ATTRIBUTE_NORETURN static int
virProcessDummyChild(void *argv ATTRIBUTE_UNUSED)
{
    _exit(0);
}

/**
 * virProcessNamespaceAvailable:
 * @ns: what namespaces to check (bitwise-OR of virProcessNamespaceFlags)
 *
 * Check if given list of namespaces (@ns) is available.
 * If not, appropriate error message is produced.
 *
 * Returns: 0 on success (all the namespaces from @flags are available),
 *         -1 on error (with error message reported).
 */
int
virProcessNamespaceAvailable(unsigned int ns)
{
    int flags = 0;
    int cpid;
    char *childStack;
    char *stack;
    int stacksize = getpagesize() * 4;

    if (ns & VIR_PROCESS_NAMESPACE_MNT)
        flags |= CLONE_NEWNS;
    if (ns & VIR_PROCESS_NAMESPACE_IPC)
        flags |= CLONE_NEWIPC;
    if (ns & VIR_PROCESS_NAMESPACE_NET)
        flags |= CLONE_NEWNET;
    if (ns & VIR_PROCESS_NAMESPACE_PID)
        flags |= CLONE_NEWPID;
    if (ns & VIR_PROCESS_NAMESPACE_USER)
        flags |= CLONE_NEWUSER;
    if (ns & VIR_PROCESS_NAMESPACE_UTS)
        flags |= CLONE_NEWUTS;

    /* Signal parent as soon as the child dies. RIP. */
    flags |= SIGCHLD;

    if (VIR_ALLOC_N(stack, stacksize) < 0)
        return -1;

    childStack = stack + stacksize;

    cpid = clone(virProcessDummyChild, childStack, flags, NULL);
    VIR_FREE(stack);
    if (cpid < 0) {
        char ebuf[1024] ATTRIBUTE_UNUSED;
        VIR_DEBUG("clone call returned %s, container support is not enabled",
                  virStrerror(errno, ebuf, sizeof(ebuf)));
        return -1;
    } else if (virProcessWait(cpid, NULL, false) < 0) {
        return -1;
    }

    VIR_DEBUG("All namespaces (%x) are enabled", ns);
    return 0;
}

#else /* !defined(__linux__) */

int
virProcessNamespaceAvailable(unsigned int ns ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Namespaces are not supported on this platform."));
    return -1;
}
#endif /* !defined(__linux__) */

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

#if HAVE_SCHED_SETSCHEDULER

static int
virProcessSchedTranslatePolicy(virProcessSchedPolicy policy)
{
    switch (policy) {
    case VIR_PROC_POLICY_NONE:
        return SCHED_OTHER;

    case VIR_PROC_POLICY_BATCH:
# ifdef SCHED_BATCH
        return SCHED_BATCH;
# else
        return -1;
# endif

    case VIR_PROC_POLICY_IDLE:
# ifdef SCHED_IDLE
        return SCHED_IDLE;
# else
        return -1;
# endif

    case VIR_PROC_POLICY_FIFO:
        return SCHED_FIFO;

    case VIR_PROC_POLICY_RR:
        return SCHED_RR;

    case VIR_PROC_POLICY_LAST:
        /* nada */
        break;
    }

    return -1;
}

int
virProcessSetScheduler(pid_t pid,
                       virProcessSchedPolicy policy,
                       int priority)
{
    struct sched_param param = {0};
    int pol = virProcessSchedTranslatePolicy(policy);

    VIR_DEBUG("pid=%lld, policy=%d, priority=%u",
              (long long) pid, policy, priority);

    if (!policy)
        return 0;

    if (pol < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Scheduler '%s' is not supported on this platform"),
                       virProcessSchedPolicyTypeToString(policy));
        return -1;
    }

    if (pol == SCHED_FIFO || pol == SCHED_RR) {
        int min = 0;
        int max = 0;

        if ((min = sched_get_priority_min(pol)) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Cannot get minimum scheduler "
                                   "priority value"));
            return -1;
        }

        if ((max = sched_get_priority_max(pol)) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Cannot get maximum scheduler "
                                   "priority value"));
            return -1;
        }

        if (priority < min || priority > max) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Scheduler priority %d out of range [%d, %d]"),
                           priority, min, max);
            return -1;
        }

        param.sched_priority = priority;
    }

    if (sched_setscheduler(pid, pol, &param) < 0) {
        virReportSystemError(errno,
                             _("Cannot set scheduler parameters for pid %lld"),
                             (long long) pid);
        return -1;
    }

    return 0;
}

#else /* ! HAVE_SCHED_SETSCHEDULER */

int
virProcessSetScheduler(pid_t pid ATTRIBUTE_UNUSED,
                       virProcessSchedPolicy policy,
                       int priority ATTRIBUTE_UNUSED)
{
    if (!policy)
        return 0;

    virReportSystemError(ENOSYS, "%s",
                         _("Process CPU scheduling is not supported "
                           "on this platform"));
    return -1;
}

#endif /* !HAVE_SCHED_SETSCHEDULER */
