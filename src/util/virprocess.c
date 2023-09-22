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
#include <limits.h>
#include <signal.h>
#ifndef WIN32
# include <sys/wait.h>
#endif
#if WITH_SYS_MOUNT_H
# include <sys/mount.h>
#endif
#if WITH_SETRLIMIT
# include <sys/time.h>
# include <sys/resource.h>
#endif
#if WITH_SCHED_H
# include <sched.h>
#endif

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || WITH_BSD_CPU_AFFINITY || defined(__APPLE__)
# include <sys/param.h>
#endif

#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
# include <sys/sysctl.h>
# include <sys/user.h>
#endif

#if WITH_BSD_CPU_AFFINITY
# include <sys/cpuset.h>
#endif

#ifdef WIN32
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#endif

#ifdef __linux__
# include <sys/prctl.h>
#endif

#if defined(__APPLE__)
# include <sys/syslimits.h>
#endif

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

VIR_ENUM_IMPL(virProcessSchedPolicy,
              VIR_PROC_POLICY_LAST,
              "none",
              "batch",
              "idle",
              "fifo",
              "rr",
);


#ifndef WIN32
/**
 * virProcessTranslateStatus:
 * @status: child exit status to translate
 *
 * Translate an exit status into a malloc'd string.  Generic helper
 * for virCommandRun(), virCommandWait() and virProcessWait()
 * status argument, as well as raw waitpid().
 */
char *
virProcessTranslateStatus(int status)
{
    char *buf;
    if (WIFEXITED(status)) {
        buf = g_strdup_printf(_("exit status %1$d"),
                              WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        buf = g_strdup_printf(_("fatal signal %1$d"),
                              WTERMSIG(status));
    } else {
        buf = g_strdup_printf(_("invalid value %1$d"), status);
    }
    return buf;
}


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
    g_autofree char *tmp = NULL;

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
        g_usleep(10 * 1000);
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
    errno = saved_errno;
}


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
    g_autofree char *st = NULL;

    if (pid <= 0) {
        if (pid != -1)
            virReportSystemError(EINVAL, _("unable to wait for process %1$lld"),
                                 (long long) pid);
        return -1;
    }

    /* Wait for intermediate process to exit */
    while ((ret = waitpid(pid, &status, 0)) == -1 &&
           errno == EINTR);

    if (ret == -1) {
        virReportSystemError(errno, _("unable to wait for process %1$lld"),
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
    st = virProcessTranslateStatus(status);
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Child process (%1$lld) unexpected %2$s"),
                   (long long) pid, NULLSTR(st));
    return -1;
}

#else /* WIN32 */

char *
virProcessTranslateStatus(int status)
{
    return g_strdup_printf(_("invalid value %1$d"), status);
}


void
virProcessAbort(pid_t pid)
{
    /* Not yet ported to mingw.  Any volunteers?  */
    VIR_DEBUG("failed to reap child %lld, abandoning it", (long long)pid);
}


int
virProcessWait(pid_t pid, int *exitstatus G_GNUC_UNUSED, bool raw G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, _("unable to wait for process %1$lld"),
                         (long long) pid);
    return -1;
}

#endif /* WIN32 */


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


/* send signal to a process group */
int virProcessGroupKill(pid_t pid, int sig G_GNUC_UNUSED)
{
    if (pid <= 1) {
        errno = ESRCH;
        return -1;
    }

#ifdef WIN32
    errno = ENOSYS;
    return -1;
#else
    return killpg(pid, sig);
#endif
}


/* get process group from a pid */
pid_t virProcessGroupGet(pid_t pid)
{
    if (pid <= 1) {
        errno = ESRCH;
        return -1;
    }

#ifdef WIN32
    errno = ENOSYS;
    return -1;
#else
    return getpgid(pid);
#endif
}


/*
 * Try to kill the process and verify it has exited
 *
 * Returns 0 if it was killed, -1 if it is still alive or another error
 * occurred.
 *
 * Callers can provide an extra delay in seconds to
 * wait longer than the default.
 */
int
virProcessKillPainfullyDelay(pid_t pid, bool force, unsigned int extradelay, bool group)
{
    size_t i;
    /* This is in 1/5th seconds since polling is on a 0.2s interval */
    unsigned int polldelay = (force ? 200 : 75) + (extradelay*5);
    const char *signame = "TERM";

    VIR_DEBUG("vpid=%lld force=%d extradelay=%u group=%d",
              (long long)pid, force, extradelay, group);

    /* This loop sends SIGTERM, then waits a few iterations (10 seconds)
     * to see if it dies. If the process still hasn't exited, and
     * @force is requested, a SIGKILL will be sent, and this will
     * wait up to 30 seconds more for the process to exit before
     * returning.
     *
     * An extra delay can be passed by the caller for cases that are
     * expected to clean up slower than usual.
     *
     * Note that setting @force could result in dataloss for the process.
     */
    for (i = 0; i < polldelay; i++) {
        int signum;
        int rc;

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

        if (group)
            rc = virProcessGroupKill(pid, signum);
        else
            rc = virProcessKill(pid, signum);

        if (rc < 0) {
            if (errno != ESRCH) {
                virReportSystemError(errno,
                                     _("Failed to terminate process %1$lld with SIG%2$s"),
                                     (long long)pid, signame);
                return -1;
            }
            return 0;
        }

        g_usleep(200 * 1000);
    }

    virReportSystemError(EBUSY,
                         _("Failed to terminate process %1$lld with SIG%2$s"),
                         (long long)pid, signame);

    return -1;
}


int virProcessKillPainfully(pid_t pid, bool force)
{
    return virProcessKillPainfullyDelay(pid, force, 0, false);
}

#if WITH_DECL_CPU_SET_T

int virProcessSetAffinity(pid_t pid, virBitmap *map, bool quiet)
{
    size_t i;
    int numcpus = 1024;
    size_t masklen;
    cpu_set_t *mask;
    int rv = -1;

    VIR_DEBUG("Set process affinity on %lld", (long long)pid);

    /* Not only may the statically allocated cpu_set_t be too small,
     * but there is no way to ask the kernel what size is large enough.
     * So you have no option but to pick a size, try, catch EINVAL,
     * enlarge, and re-try.
     *
     * https://lkml.org/lkml/2009/7/28/620
     */
 realloc:
    masklen = CPU_ALLOC_SIZE(numcpus);
    mask = CPU_ALLOC(numcpus);

    if (!mask)
        abort();

    CPU_ZERO_S(masklen, mask);
    for (i = 0; i < virBitmapSize(map); i++) {
        if (virBitmapIsBitSet(map, i))
            CPU_SET_S(i, masklen, mask);
    }

    rv = sched_setaffinity(pid, masklen, mask);
    CPU_FREE(mask);

    if (rv < 0) {
        if (errno == EINVAL &&
            numcpus < (1024 << 8)) { /* 262144 cpus ought to be enough for anyone */
            numcpus = numcpus << 2;
            goto realloc;
        }
        if (quiet) {
            VIR_DEBUG("cannot set CPU affinity on process %d: %s",
                      pid, g_strerror(errno));
        } else {
            virReportSystemError(errno,
                                 _("cannot set CPU affinity on process %1$d"), pid);
            return -1;
        }
    }

    return 0;
}

virBitmap *
virProcessGetAffinity(pid_t pid)
{
    size_t i;
    cpu_set_t *mask;
    size_t masklen;
    size_t ncpus;
    virBitmap *ret = NULL;

    /* 262144 cpus ought to be enough for anyone */
    ncpus = 1024 << 8;
    masklen = CPU_ALLOC_SIZE(ncpus);
    mask = CPU_ALLOC(ncpus);

    if (!mask)
        abort();

    CPU_ZERO_S(masklen, mask);

    if (sched_getaffinity(pid, masklen, mask) < 0) {
        virReportSystemError(errno,
                             _("cannot get CPU affinity of process %1$d"), pid);
        goto cleanup;
    }

    ret = virBitmapNew(ncpus);

    for (i = 0; i < ncpus; i++) {
        if (CPU_ISSET_S(i, masklen, mask))
            ignore_value(virBitmapSetBit(ret, i));
    }

 cleanup:
    CPU_FREE(mask);

    return ret;
}

#elif defined(WITH_BSD_CPU_AFFINITY)

int virProcessSetAffinity(pid_t pid,
                          virBitmap *map,
                          bool quiet)
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
        if (quiet) {
            VIR_DEBUG("cannot set CPU affinity on process %d: %s",
                      pid, g_strerror(errno));
        } else {
            virReportSystemError(errno,
                                 _("cannot set CPU affinity on process %1$d"), pid);
            return -1;
        }
    }

    return 0;
}

virBitmap *
virProcessGetAffinity(pid_t pid)
{
    size_t i;
    cpuset_t mask;
    virBitmap *ret = NULL;

    CPU_ZERO(&mask);
    if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, pid,
                           sizeof(mask), &mask) != 0) {
        virReportSystemError(errno,
                             _("cannot get CPU affinity of process %1$d"), pid);
        return NULL;
    }

    ret = virBitmapNew(sizeof(mask) * 8);

    for (i = 0; i < sizeof(mask) * 8; i++)
        if (CPU_ISSET(i, &mask))
            ignore_value(virBitmapSetBit(ret, i));

    return ret;
}

#else /* WITH_DECL_CPU_SET_T */

int virProcessSetAffinity(pid_t pid G_GNUC_UNUSED,
                          virBitmap *map G_GNUC_UNUSED,
                          bool quiet G_GNUC_UNUSED)
{
    /* The @quiet parameter is ignored here, it is used only for silencing
     * actual failures. */
    virReportSystemError(ENOSYS, "%s",
                         _("Process CPU affinity is not supported on this platform"));
    return -1;
}

virBitmap *
virProcessGetAffinity(pid_t pid G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Process CPU affinity is not supported on this platform"));
    return NULL;
}
#endif /* WITH_DECL_CPU_SET_T */


int virProcessGetPids(pid_t pid, size_t *npids, pid_t **pids)
{
    int ret = -1;
    g_autoptr(DIR) dir = NULL;
    int value;
    struct dirent *ent;
    g_autofree char *taskPath = NULL;

    *npids = 0;
    *pids = NULL;

    taskPath = g_strdup_printf("/proc/%llu/task", (long long)pid);

    if (virDirOpen(&dir, taskPath) < 0)
        goto cleanup;

    while ((value = virDirRead(dir, &ent, taskPath)) > 0) {
        long long tmp;
        pid_t tmp_pid;

        if (virStrToLong_ll(ent->d_name, NULL, 10, &tmp) < 0)
            goto cleanup;
        tmp_pid = tmp;

        VIR_APPEND_ELEMENT(*pids, *npids, tmp_pid);
    }

    if (value < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (ret < 0)
        VIR_FREE(*pids);
    return ret;
}


int virProcessGetNamespaces(pid_t pid,
                            size_t *nfdlist,
                            int **fdlist)
{
    size_t i = 0;
    const char *ns[] = { "user", "ipc", "uts", "net", "pid", "mnt" };

    *nfdlist = 0;
    *fdlist = NULL;

    for (i = 0; i < G_N_ELEMENTS(ns); i++) {
        int fd;
        g_autofree char *nsfile = NULL;

        nsfile = g_strdup_printf("/proc/%llu/ns/%s", (long long)pid, ns[i]);

        if ((fd = open(nsfile, O_RDONLY)) >= 0) {
            VIR_EXPAND_N(*fdlist, *nfdlist, 1);
            (*fdlist)[(*nfdlist)-1] = fd;
        }
    }

    return 0;
}


#ifdef __linux__
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
#else
int virProcessSetNamespaces(size_t nfdlist G_GNUC_UNUSED,
                            int *fdlist G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Namespaces are not supported on this platform"));
    return -1;
}
#endif


#if WITH_PRLIMIT
static int
virProcessPrLimit(pid_t pid,
                  int resource,
                  const struct rlimit *new_limit,
                  struct rlimit *old_limit)
{
    return prlimit(pid, resource, new_limit, old_limit);
}
#elif WITH_SETRLIMIT
static int
virProcessPrLimit(pid_t pid G_GNUC_UNUSED,
                  int resource G_GNUC_UNUSED,
                  const struct rlimit *new_limit G_GNUC_UNUSED,
                  struct rlimit *old_limit G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}
#endif

#if WITH_GETRLIMIT
static const char*
virProcessLimitResourceToLabel(int resource)
{
    switch (resource) {
# if defined(RLIMIT_MEMLOCK)
        case RLIMIT_MEMLOCK:
            return "Max locked memory";
# endif /* defined(RLIMIT_MEMLOCK) */

# if defined(RLIMIT_NPROC)
        case RLIMIT_NPROC:
            return "Max processes";
# endif /* defined(RLIMIT_NPROC) */

# if defined(RLIMIT_NOFILE)
        case RLIMIT_NOFILE:
            return "Max open files";
# endif /* defined(RLIMIT_NOFILE) */

# if defined(RLIMIT_CORE)
        case RLIMIT_CORE:
            return "Max core file size";
# endif /* defined(RLIMIT_CORE) */

        default:
            return NULL;
    }
}

# if defined(__linux__)
static int
virProcessGetLimitFromProc(pid_t pid,
                           int resource,
                           struct rlimit *limit)
{
    g_autofree char *procfile = NULL;
    g_autofree char *buf = NULL;
    g_auto(GStrv) lines = NULL;
    const char *label;
    size_t i;

    if (!(label = virProcessLimitResourceToLabel(resource))) {
        errno = EINVAL;
        return -1;
    }

    procfile = g_strdup_printf("/proc/%lld/limits", (long long)pid);

    if (virFileReadAllQuiet(procfile, 2048, &buf) < 0) {
        /* virFileReadAllQuiet() already sets errno, so don't overwrite
         * that and return immediately instead */
        return -1;
    }

    lines = g_strsplit(buf, "\n", 0);

    for (i = 0; lines[i]; i++) {
        g_autofree char *softLimit = NULL;
        g_autofree char *hardLimit = NULL;
        char *line = lines[i];
        unsigned long long tmp;

        if (!(line = STRSKIP(line, label)))
            continue;

        if (sscanf(line, "%ms %ms %*s", &softLimit, &hardLimit) < 2)
            goto error;

        if (STREQ(softLimit, "unlimited")) {
            limit->rlim_cur = RLIM_INFINITY;
        } else {
            if (virStrToLong_ull(softLimit, NULL, 10, &tmp) < 0)
                goto error;
            limit->rlim_cur = tmp;
        }
        if (STREQ(hardLimit, "unlimited")) {
            limit->rlim_max = RLIM_INFINITY;
        } else {
            if (virStrToLong_ull(hardLimit, NULL, 10, &tmp) < 0)
                goto error;
            limit->rlim_max = tmp;
        }
    }

    return 0;

 error:
    errno = EIO;
    return -1;
}
# else /* !defined(__linux__) */
static int
virProcessGetLimitFromProc(pid_t pid G_GNUC_UNUSED,
                           int resource G_GNUC_UNUSED,
                           struct rlimit *limit G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}
# endif /* !defined(__linux__) */

static int
virProcessGetLimit(pid_t pid,
                   int resource,
                   struct rlimit *old_limit)
{
    pid_t current_pid = getpid();
    bool same_process = (pid == current_pid);

    if (virProcessPrLimit(pid, resource, NULL, old_limit) == 0)
        return 0;

    /* For whatever reason, using prlimit() on another process - even
     * when it's just to obtain the current limit rather than changing
     * it - requires CAP_SYS_RESOURCE, which we might not have in a
     * containerized environment; on the other hand, no particular
     * permission is needed to poke around /proc, so try that if going
     * through the syscall didn't work */
    if (virProcessGetLimitFromProc(pid, resource, old_limit) == 0)
        return 0;

    if (same_process && getrlimit(resource, old_limit) == 0)
        return 0;

    return -1;
}
#endif /* WITH_GETRLIMIT */

#if WITH_SETRLIMIT
static int
virProcessSetLimit(pid_t pid,
                   int resource,
                   const struct rlimit *new_limit)
{
    pid_t current_pid = getpid();
    bool same_process = (pid == current_pid);

    if (virProcessPrLimit(pid, resource, new_limit, NULL) == 0)
        return 0;

    if (same_process && setrlimit(resource, new_limit) == 0)
        return 0;

    return -1;
}
#endif /* WITH_SETRLIMIT */

#if WITH_SETRLIMIT && defined(RLIMIT_MEMLOCK)
/**
 * virProcessSetMaxMemLock:
 * @pid: process to be changed
 * @bytes: new limit
 *
 * Sets a new limit on the amount of locked memory for a process.
 *
 * Returns: 0 on success, <0 on failure.
 */
int
virProcessSetMaxMemLock(pid_t pid, unsigned long long bytes)
{
    struct rlimit rlim;

    /* We use VIR_DOMAIN_MEMORY_PARAM_UNLIMITED internally to represent
     * unlimited memory amounts, but setrlimit() and prlimit() use
     * RLIM_INFINITY for the same purpose, so we need to translate between
     * the two conventions */
    if (virMemoryLimitIsSet(bytes))
        rlim.rlim_cur = rlim.rlim_max = bytes;
    else
        rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;

    if (virProcessSetLimit(pid, RLIMIT_MEMLOCK, &rlim) < 0) {
        virReportSystemError(errno,
                             _("cannot limit locked memory of process %1$lld to %2$llu"),
                             (long long int)pid, bytes);
        return -1;
    }

    VIR_DEBUG("Locked memory for process %lld limited to %llu bytes",
              (long long int) pid, bytes);

    return 0;
}
#else /* ! (WITH_SETRLIMIT && defined(RLIMIT_MEMLOCK)) */
int
virProcessSetMaxMemLock(pid_t pid G_GNUC_UNUSED,
                        unsigned long long bytes G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}
#endif /* ! (WITH_SETRLIMIT && defined(RLIMIT_MEMLOCK)) */

#if WITH_GETRLIMIT && defined(RLIMIT_MEMLOCK)
/**
 * virProcessGetMaxMemLock:
 * @pid: process to be queried
 * @bytes: return location for the limit
 *
 * Obtain the current limit on the amount of locked memory for a process.
 *
 * Returns: 0 on success, <0 on failure.
 */
int
virProcessGetMaxMemLock(pid_t pid,
                        unsigned long long *bytes)
{
    struct rlimit rlim;

    if (!bytes)
        return 0;

    if (virProcessGetLimit(pid, RLIMIT_MEMLOCK, &rlim) < 0) {
        virReportSystemError(errno,
                             _("cannot get locked memory limit of process %1$lld"),
                             (long long int) pid);
        return -1;
    }

    /* virProcessSetMaxMemLock() sets both rlim_cur and rlim_max to the
     * same value, so we can retrieve just rlim_max here. We use
     * VIR_DOMAIN_MEMORY_PARAM_UNLIMITED internally to represent unlimited
     * memory amounts, but setrlimit() and prlimit() use RLIM_INFINITY for the
     * same purpose, so we need to translate between the two conventions */
    if (rlim.rlim_max == RLIM_INFINITY)
        *bytes = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
    else
        *bytes = rlim.rlim_max;

    return 0;
}
#else /* ! (WITH_GETRLIMIT && defined(RLIMIT_MEMLOCK)) */
int
virProcessGetMaxMemLock(pid_t pid G_GNUC_UNUSED,
                        unsigned long long *bytes G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}
#endif /* ! (WITH_GETRLIMIT && defined(RLIMIT_MEMLOCK)) */

#if WITH_SETRLIMIT && defined(RLIMIT_NPROC)
/**
 * virProcessSetMaxProcesses:
 * @pid: process to be changed
 * @procs: new limit
 *
 * Sets a new limit on the amount of processes for the user the
 * process is running as.
 *
 * Returns: 0 on success, <0 on failure.
 */
int
virProcessSetMaxProcesses(pid_t pid, unsigned int procs)
{
    struct rlimit rlim;

    rlim.rlim_cur = rlim.rlim_max = procs;

    if (virProcessSetLimit(pid, RLIMIT_NPROC, &rlim) < 0) {
        virReportSystemError(errno,
                _("cannot limit number of subprocesses of process %1$lld to %2$u"),
                (long long int)pid, procs);
        return -1;
    }
    return 0;
}
#else /* ! (WITH_SETRLIMIT && defined(RLIMIT_NPROC)) */
int
virProcessSetMaxProcesses(pid_t pid G_GNUC_UNUSED,
                          unsigned int procs G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}
#endif /* ! (WITH_SETRLIMIT && defined(RLIMIT_NPROC)) */

#if WITH_SETRLIMIT && defined(RLIMIT_NOFILE)
/**
 * virProcessSetMaxFiles:
 * @pid: process to be changed
 * @files: new limit
 *
 * Sets a new limit on the number of opened files for a process.
 *
 * Returns: 0 on success, <0 on failure.
 */
int
virProcessSetMaxFiles(pid_t pid, unsigned int files)
{
    struct rlimit rlim;

   /* Max number of opened files is one greater than actual limit. See
    * man setrlimit.
    *
    * NB: That indicates to me that we would want the following code
    * to say "files - 1", but the original of this code in
    * qemu_process.c also had files + 1, so this preserves current
    * behavior.
    */
    rlim.rlim_cur = rlim.rlim_max = files + 1;

    if (virProcessSetLimit(pid, RLIMIT_NOFILE, &rlim) < 0) {
        virReportSystemError(errno,
                             _("cannot limit number of open files of process %1$lld to %2$u"),
                             (long long int)pid, files);
        return -1;
    }

    return 0;
}

void
virProcessActivateMaxFiles(void)
{
    struct rlimit maxfiles = {0};

    /*
     * Ignore errors since we might be inside a container with seccomp
     * filters and limits preset to suitable values.
     */
    if (getrlimit(RLIMIT_NOFILE, &maxfiles) < 0) {
        VIR_DEBUG("Unable to fetch process max files limit: %s",
                  g_strerror(errno));
        return;
    }

    VIR_DEBUG("Initial max files was %llu", (unsigned long long)maxfiles.rlim_cur);

# if defined(__APPLE__)
    /*
     * rlim_max may be RLIM_INFINITY, and macOS 12.6.3 getrlimit(2) says
     *
     * COMPATIBILITY
     *      setrlimit() now returns with errno set to EINVAL in places
     *      that historically succeeded.  It no longer accepts
     *      "rlim_cur = RLIM_INFINITY" for RLIM_NOFILE.
     *      Use "rlim_cur = min(OPEN_MAX, rlim_max)".
     */
    maxfiles.rlim_cur = MIN(OPEN_MAX, maxfiles.rlim_max);
# else
    maxfiles.rlim_cur = maxfiles.rlim_max;
# endif

    if (setrlimit(RLIMIT_NOFILE, &maxfiles) < 0) {
        VIR_DEBUG("Unable to set process max files limit to %llu: %s",
                  (unsigned long long)maxfiles.rlim_cur, g_strerror(errno));
        return;
    }

    VIR_DEBUG("Raised max files to %llu", (unsigned long long)maxfiles.rlim_cur);
}

#else /* ! (WITH_SETRLIMIT && defined(RLIMIT_NOFILE)) */
int
virProcessSetMaxFiles(pid_t pid G_GNUC_UNUSED,
                      unsigned int files G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}

void
virProcessActivateMaxFiles(void)
{
}
#endif /* ! (WITH_SETRLIMIT && defined(RLIMIT_NOFILE)) */

#if WITH_SETRLIMIT && defined(RLIMIT_CORE)
/**
 * virProcessSetMaxCoreSize:
 * @pid: process to be changed
 * @bytes: new limit (0 to disable core dumps)
 *
 * Sets a new limit on the size of core dumps for a process.
 *
 * Returns: 0 on success, <0 on failure.
 */
int
virProcessSetMaxCoreSize(pid_t pid, unsigned long long bytes)
{
    struct rlimit rlim;

    rlim.rlim_cur = rlim.rlim_max = bytes;

    if (virProcessSetLimit(pid, RLIMIT_CORE, &rlim) < 0) {
        virReportSystemError(errno,
                _("cannot limit core file size of process %1$lld to %2$llu"),
                (long long int)pid, bytes);
        return -1;
    }

    return 0;
}
#else /* ! (WITH_SETRLIMIT && defined(RLIMIT_CORE)) */
int
virProcessSetMaxCoreSize(pid_t pid G_GNUC_UNUSED,
                         unsigned long long bytes G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}
#endif /* ! (WITH_SETRLIMIT && defined(RLIMIT_CORE)) */


#ifdef __linux__
/*
 * Port of code from polkitunixprocess.c under terms
 * of the LGPLv2+
 */
int virProcessGetStartTime(pid_t pid,
                           unsigned long long *timestamp)
{
    g_auto(GStrv) proc_stat = virProcessGetStat(pid, 0);
    const char *starttime_str = NULL;

    if (!proc_stat || g_strv_length(proc_stat) < 22) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot find start time for pid %1$d"), (int)pid);
        return -1;
    }

    starttime_str = proc_stat[VIR_PROCESS_STAT_STARTTIME];
    if (virStrToLong_ull(starttime_str, NULL, 10, timestamp) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse start time %1$s for pid %2$d"),
                       starttime_str, (int)pid);
        return -1;
    }
    return 0;
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
    if (g_atomic_int_add(&warned, 1) == 0) {
        VIR_WARN("Process start time of pid %lld not available on this platform",
                 (long long) pid);
    }
    *timestamp = 0;
    return 0;
}
#endif


#ifdef __linux__
typedef struct _virProcessNamespaceHelperData virProcessNamespaceHelperData;
struct _virProcessNamespaceHelperData {
    pid_t pid;
    virProcessNamespaceCallback cb;
    void *opaque;
};

static int virProcessNamespaceHelper(pid_t pid G_GNUC_UNUSED,
                                     void *opaque)
{
    virProcessNamespaceHelperData *data = opaque;
    int fd = -1;
    int ret = -1;
    g_autofree char *path = NULL;

    path = g_strdup_printf("/proc/%lld/ns/mnt", (long long)data->pid);

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

    ret = data->cb(data->pid, data->opaque);

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

/* Run cb(opaque) in the mount namespace of pid.  Return -1 with error
 * message raised if we fail to run the child, if the child dies from
 * a signal, or if the child has status EXIT_CANCELED; otherwise return
 * value is the retval of the callback. The callback will be run in a child
 * process so must be careful to only use async signal safe functions.
 */
int
virProcessRunInMountNamespace(pid_t pid,
                              virProcessNamespaceCallback cb,
                              void *opaque)
{
    virProcessNamespaceHelperData data = {.pid = pid, .cb = cb, .opaque = opaque};

    return virProcessRunInFork(virProcessNamespaceHelper, &data);
}

#else /* ! __linux__ */

int
virProcessRunInMountNamespace(pid_t pid G_GNUC_UNUSED,
                              virProcessNamespaceCallback cb G_GNUC_UNUSED,
                              void *opaque G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Namespaces are not supported on this platform"));
    return -1;
}

#endif /* ! __linux__ */


#ifndef WIN32
/* We assume that error messages will fit into 1024 chars */
# define VIR_PROCESS_ERROR_MAX_LENGTH 1024
typedef struct {
    int code;
    int domain;
    char message[VIR_PROCESS_ERROR_MAX_LENGTH];
    virErrorLevel level;
    char str1[VIR_PROCESS_ERROR_MAX_LENGTH];
    char str2[VIR_PROCESS_ERROR_MAX_LENGTH];
    char str3[VIR_PROCESS_ERROR_MAX_LENGTH];
    int int1;
    int int2;
} errorData;

typedef union {
    errorData data;
    char bindata[sizeof(errorData)];
} errorDataBin;

static int
virProcessRunInForkHelper(int errfd,
                          pid_t ppid,
                          virProcessForkCallback cb,
                          void *opaque)
{
    int ret = 0;

    if ((ret = cb(ppid, opaque)) < 0) {
        virErrorPtr err = virGetLastError();

        if (err) {
            g_autofree errorDataBin *bin = g_new0(errorDataBin, 1);

            bin->data.code = err->code;
            bin->data.domain = err->domain;
            virStrcpyStatic(bin->data.message, err->message);
            bin->data.level = err->level;
            if (err->str1)
                virStrcpyStatic(bin->data.str1, err->str1);
            if (err->str2)
                virStrcpyStatic(bin->data.str2, err->str2);
            if (err->str3)
                virStrcpyStatic(bin->data.str3, err->str3);
            bin->data.int1 = err->int1;
            bin->data.int2 = err->int2;

            ignore_value(safewrite(errfd, bin->bindata, sizeof(*bin)));
        }

        return -1;
    }

    return ret;
}


/**
 * virProcessRunInFork:
 * @cb: callback to run
 * @opaque: opaque data to @cb
 *
 * Do the fork and run @cb in the child. This can be used when
 * @cb does something thread unsafe, for instance.  All signals
 * will be reset to have their platform default handlers and
 * unmasked. @cb must only use async signal safe functions. In
 * particular no mutexes should be used in @cb, unless steps were
 * taken before forking to guarantee a predictable state. @cb
 * must not exec any external binaries, instead
 * virCommand should be used for that purpose.
 *
 * On return, the returned value is either -1 with error message
 * reported if something went bad in the parent, if child has
 * died from a signal or if the child returned EXIT_CANCELED.
 * Otherwise the returned value is the retval of the callback.
 */
int
virProcessRunInFork(virProcessForkCallback cb,
                    void *opaque)
{
    int ret = -1;
    pid_t child = -1;
    pid_t parent = getpid();
    int errfd[2] = { -1, -1 };

    if (virPipe(errfd) < 0)
        return -1;

    if ((child = virFork()) < 0)
        goto cleanup;

    if (child == 0) {
        VIR_FORCE_CLOSE(errfd[0]);
        ret = virProcessRunInForkHelper(errfd[1], parent, cb, opaque);
        VIR_FORCE_CLOSE(errfd[1]);
        _exit(ret < 0 ? EXIT_CANCELED : ret);
    } else {
        int status;
        g_autofree char *buf = NULL;
        g_autofree errorDataBin *bin = NULL;
        int nread;

        VIR_FORCE_CLOSE(errfd[1]);
        nread = virFileReadHeaderFD(errfd[0], sizeof(*bin), &buf);
        ret = virProcessWait(child, &status, false);
        if (ret == 0) {
            ret = status == EXIT_CANCELED ? -1 : status;
            if (ret < 0) {
                if (nread == sizeof(*bin)) {
                    bin = g_new0(errorDataBin, 1);
                    memcpy(bin->bindata, buf, sizeof(*bin));

                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("child reported (status=%1$d): %2$s"),
                                   status, NULLSTR(bin->data.message));

                    virRaiseErrorFull(__FILE__, __FUNCTION__, __LINE__,
                                      bin->data.domain,
                                      bin->data.code,
                                      bin->data.level,
                                      bin->data.str1,
                                      bin->data.str2,
                                      bin->data.str3,
                                      bin->data.int1,
                                      bin->data.int2,
                                      "%s", bin->data.message);
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("child didn't write error (status=%1$d)"),
                                   status);
                }
            }
        }
    }

 cleanup:
    VIR_FORCE_CLOSE(errfd[0]);
    VIR_FORCE_CLOSE(errfd[1]);
    return ret;
}

#else /* WIN32 */

int
virProcessRunInFork(virProcessForkCallback cb G_GNUC_UNUSED,
                    void *opaque G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Process spawning is not supported on this platform"));
    return -1;
}

#endif /* WIN32 */


#if defined(__linux__)
int
virProcessSetupPrivateMountNS(void)
{
    if (unshare(CLONE_NEWNS) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot unshare mount namespace"));
        return -1;
    }

    if (mount("", "/", "none", MS_SLAVE|MS_REC, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed disable mount propagation out of the root filesystem"));
        return -1;
    }

    return 0;
}


G_GNUC_NORETURN static int
virProcessDummyChild(void *argv G_GNUC_UNUSED)
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
    int stacksize = getpagesize() * 4;
    g_autofree char *stack = NULL;

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

    stack = g_new0(char, stacksize);

    childStack = stack + stacksize;

    cpid = clone(virProcessDummyChild, childStack, flags, NULL);

    if (cpid < 0) {
        VIR_DEBUG("clone call returned %s, container support is not enabled",
                  g_strerror(errno));
        return -1;
    } else if (virProcessWait(cpid, NULL, false) < 0) {
        return -1;
    }

    VIR_DEBUG("All namespaces (%x) are enabled", ns);
    return 0;
}

#else /* !defined(__linux__) */

int
virProcessSetupPrivateMountNS(void)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Namespaces are not supported on this platform"));
    return -1;
}

int
virProcessNamespaceAvailable(unsigned int ns G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Namespaces are not supported on this platform"));
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

#ifndef WIN32
    if (WIFEXITED(status)) {
        value = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        struct sigaction act = { 0 };
        sigset_t sigs;

        if (sigemptyset(&sigs) == 0 &&
            sigaddset(&sigs, WTERMSIG(status)) == 0)
            sigprocmask(SIG_UNBLOCK, &sigs, NULL);
        act.sa_handler = SIG_DFL;
        sigfillset(&act.sa_mask);
        sigaction(WTERMSIG(status), &act, NULL);
        raise(WTERMSIG(status));
        value = 128 + WTERMSIG(status);
    }
#else /* WIN32 */
    (void)status;
#endif /* WIN32 */
    exit(value);
}

#if WITH_SCHED_SETSCHEDULER

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
                       _("Scheduler '%1$s' is not supported on this platform"),
                       virProcessSchedPolicyTypeToString(policy));
        return -1;
    }

    if (pol == SCHED_FIFO || pol == SCHED_RR) {
        int min = 0;
        int max = 0;

        if ((min = sched_get_priority_min(pol)) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Cannot get minimum scheduler priority value"));
            return -1;
        }

        if ((max = sched_get_priority_max(pol)) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Cannot get maximum scheduler priority value"));
            return -1;
        }

        if (priority < min || priority > max) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Scheduler priority %1$d out of range [%2$d, %3$d]"),
                           priority, min, max);
            return -1;
        }

        param.sched_priority = priority;
    }

    if (sched_setscheduler(pid, pol, &param) < 0) {
        virReportSystemError(errno,
                             _("Cannot set scheduler parameters for pid %1$lld"),
                             (long long) pid);
        return -1;
    }

    return 0;
}

#else /* ! WITH_SCHED_SETSCHEDULER */

int
virProcessSetScheduler(pid_t pid G_GNUC_UNUSED,
                       virProcessSchedPolicy policy,
                       int priority G_GNUC_UNUSED)
{
    if (!policy)
        return 0;

    virReportSystemError(ENOSYS, "%s",
                         _("Process CPU scheduling is not supported on this platform"));
    return -1;
}

#endif /* !WITH_SCHED_SETSCHEDULER */

/*
 * Get all stat fields for a process based on pid and tid:
 * - pid == 0 && tid == 0 => /proc/self/stat
 * - pid != 0 && tid == 0 => /proc/<pid>/stat
 * - pid == 0 && tid != 0 => /proc/self/task/<tid>/stat
 * - pid != 0 && tid != 0 => /proc/<pid>/task/<tid>/stat
 * and return them as array of strings.
 */
GStrv
virProcessGetStat(pid_t pid,
                  pid_t tid)
{
    int len = 10 * 1024;  /* 10kB ought to be enough for everyone */
    g_autofree char *buf = NULL;
    g_autofree char *path = NULL;
    GStrv rest = NULL;
    GStrv ret = NULL;
    char *comm = NULL;
    char *rparen = NULL;
    size_t nrest = 0;

    if (pid) {
        if (tid)
            path = g_strdup_printf("/proc/%d/task/%d/stat", (int)pid, (int)tid);
        else
            path = g_strdup_printf("/proc/%d/stat", (int)pid);
    } else {
        if (tid)
            path = g_strdup_printf("/proc/self/task/%d/stat", (int)tid);
        else
            path = g_strdup("/proc/self/stat");
    }

    len = virFileReadAllQuiet(path, len, &buf);
    if (len < 0)
        return NULL;

    /* eliminate trailing spaces */
    while (len > 0 && g_ascii_isspace(buf[--len]))
           buf[len] = '\0';

    /* Find end of the first field */
    if (!(comm = strchr(buf, ' ')))
        return NULL;
    *comm = '\0';

    /* Check start of the second field (filename of the executable, in
     * parentheses) */
    comm++;
    if (*comm != '(')
        return NULL;
    comm++;

    /* Check end of the second field (last closing parenthesis) */
    rparen = strrchr(comm, ')');
    if (!rparen)
        return NULL;
    *rparen = '\0';

    /* We need to check that the next char is not '\0', but why not just opt in
     * for the safer way of checking whether it is ' ' (space) instead */
    if (rparen[1] != ' ')
        return NULL;

    rest = g_strsplit(rparen + 2, " ", 0);
    nrest = g_strv_length(rest);
    ret = g_new0(char *, nrest + 3);
    ret[0] = g_strdup(buf);
    ret[1] = g_strdup(comm);
    memcpy(ret + 2, rest, nrest * sizeof(char *));

    /* Do not use g_strfreev() as individual elements they were moved to @ret. */
    VIR_FREE(rest);

    return ret;
}


#ifdef __linux__
int
virProcessGetStatInfo(unsigned long long *cpuTime,
                      unsigned long long *userTime,
                      unsigned long long *sysTime,
                      int *lastCpu,
                      unsigned long long *vm_rss,
                      pid_t pid,
                      pid_t tid)
{
    g_auto(GStrv) proc_stat = virProcessGetStat(pid, tid);
    unsigned long long utime = 0;
    unsigned long long stime = 0;
    const unsigned long long jiff2nsec = 1000ull * 1000ull * 1000ull /
                                         (unsigned long long) sysconf(_SC_CLK_TCK);
    const long pagesize = virGetSystemPageSizeKB();
    unsigned long long rss = 0;
    int cpu = 0;

    if (!proc_stat ||
        virStrToLong_ullp(proc_stat[VIR_PROCESS_STAT_UTIME], NULL, 10, &utime) < 0 ||
        virStrToLong_ullp(proc_stat[VIR_PROCESS_STAT_STIME], NULL, 10, &stime) < 0 ||
        virStrToLong_ullp(proc_stat[VIR_PROCESS_STAT_RSS], NULL, 10, &rss) < 0 ||
        virStrToLong_i(proc_stat[VIR_PROCESS_STAT_PROCESSOR], NULL, 10, &cpu) < 0 ||
        rss > ULLONG_MAX / pagesize) {
        VIR_WARN("cannot parse process status data");
    }

    utime *= jiff2nsec;
    stime *= jiff2nsec;
    if (cpuTime)
        *cpuTime = utime + stime;
    if (userTime)
        *userTime = utime;
    if (sysTime)
        *sysTime = stime;
    if (lastCpu)
        *lastCpu = cpu;

    if (vm_rss)
        *vm_rss = rss * pagesize;


    VIR_DEBUG("Got status for %d/%d user=%llu sys=%llu cpu=%d rss=%lld",
              (int) pid, tid, utime, stime, cpu, rss);

    return 0;
}

int
virProcessGetSchedInfo(unsigned long long *cpuWait,
                       pid_t pid,
                       pid_t tid)
{
    g_autofree char *proc = NULL;
    g_autofree char *data = NULL;
    g_auto(GStrv) lines = NULL;
    size_t i;
    double val;

    *cpuWait = 0;

    /* In general, we cannot assume pid_t fits in int; but /proc parsing
     * is specific to Linux where int works fine.  */
    if (tid)
        proc = g_strdup_printf("/proc/%d/task/%d/sched", (int) pid, (int) tid);
    else
        proc = g_strdup_printf("/proc/%d/sched", (int) pid);

    /* The file is not guaranteed to exist (needs CONFIG_SCHED_DEBUG) */
    if (access(proc, R_OK) < 0) {
        return 0;
    }

    if (virFileReadAll(proc, (1 << 16), &data) < 0)
        return -1;

    lines = g_strsplit(data, "\n", 0);
    if (!lines)
        return -1;

    for (i = 0; lines[i] != NULL; i++) {
        const char *line = lines[i];

        /* Needs CONFIG_SCHEDSTATS. The second check
         * is the old name the kernel used in past */
        if (STRPREFIX(line, "se.statistics.wait_sum") ||
            STRPREFIX(line, "se.wait_sum")) {
            line = strchr(line, ':');
            if (!line) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Missing separator in sched info '%1$s'"),
                               lines[i]);
                return -1;
            }
            line++;
            while (*line == ' ')
                line++;

            if (virStrToDouble(line, NULL, &val) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to parse sched info value '%1$s'"),
                               line);
                return -1;
            }

            *cpuWait = (unsigned long long) (val * 1000000);
            break;
        }
    }

    return 0;
}

#else
int
virProcessGetStatInfo(unsigned long long *cpuTime,
                      unsigned long long *userTime,
                      unsigned long long *sysTime,
                      int *lastCpu,
                      unsigned long long *vm_rss,
                      pid_t pid G_GNUC_UNUSED,
                      pid_t tid G_GNUC_UNUSED)
{
    /* We don't have a way to collect this information on non-Linux
     * platforms, so just report neutral values */
    if (cpuTime)
        *cpuTime = 0;
    if (userTime)
        *userTime = 0;
    if (sysTime)
        *sysTime = 0;
    if (lastCpu)
        *lastCpu = 0;
    if (vm_rss)
        *vm_rss = 0;

    return 0;
}

int
virProcessGetSchedInfo(unsigned long long *cpuWait,
                       pid_t pid G_GNUC_UNUSED,
                       pid_t tid G_GNUC_UNUSED)
{
    /* We don't have a way to collect this information on non-Linux
     * platforms, so just report neutral values */
    if (cpuWait)
        *cpuWait = 0;

    return 0;
}
#endif /* __linux__ */

#ifdef __linux__
# ifndef PR_SCHED_CORE
/* Copied from linux/prctl.h */
#  define PR_SCHED_CORE             62
#  define PR_SCHED_CORE_GET         0
#  define PR_SCHED_CORE_CREATE      1 /* create unique core_sched cookie */
#  define PR_SCHED_CORE_SHARE_TO    2 /* push core_sched cookie to pid */
#  define PR_SCHED_CORE_SHARE_FROM  3 /* pull core_sched cookie to pid */
# endif

/* Unfortunately, kernel-headers forgot to export these. */
# ifndef PR_SCHED_CORE_SCOPE_THREAD
#  define PR_SCHED_CORE_SCOPE_THREAD 0
#  define PR_SCHED_CORE_SCOPE_THREAD_GROUP 1
#  define PR_SCHED_CORE_SCOPE_PROCESS_GROUP 2
# endif

/**
 * virProcessSchedCoreAvailable:
 *
 * Check whether kernel supports Core Scheduling (CONFIG_SCHED_CORE), i.e. only
 * a defined set of PIDs/TIDs can run on sibling Hyper Threads at the same
 * time.
 *
 * Returns: 1 if Core Scheduling is available,
 *          0 if Core Scheduling is NOT available,
 *         -1 otherwise.
 */
int
virProcessSchedCoreAvailable(void)
{
    unsigned long cookie = 0;
    int rc;

    /* Let's just see if we can get our own sched cookie, and if yes we can
     * safely assume CONFIG_SCHED_CORE kernel is available. */
    rc = prctl(PR_SCHED_CORE, PR_SCHED_CORE_GET, 0,
               PR_SCHED_CORE_SCOPE_THREAD, &cookie);

    return rc == 0 ? 1 : errno == EINVAL ? 0 : -1;
}

/**
 * virProcessSchedCoreCreate:
 *
 * Creates a new trusted group for the caller process.
 *
 * Returns: 0 on success,
 *         -1 otherwise, with errno set.
 */
int
virProcessSchedCoreCreate(void)
{
    /* pid = 0 (3rd argument) means the calling process. */
    return prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, 0,
                 PR_SCHED_CORE_SCOPE_THREAD_GROUP, 0);
}

/**
 * virProcessSchedCoreShareFrom:
 * @pid: PID to share group with
 *
 * Places the current caller process into the trusted group of @pid.
 *
 * Returns: 0 on success,
 *         -1 otherwise, with errno set.
 */
int
virProcessSchedCoreShareFrom(pid_t pid)
{
    return prctl(PR_SCHED_CORE, PR_SCHED_CORE_SHARE_FROM, pid,
                 PR_SCHED_CORE_SCOPE_THREAD, 0);
}

/**
 * virProcessSchedCoreShareTo:
 * @pid: PID to share group with
 *
 * Places foreign @pid into the trusted group of the current caller process.
 *
 * Returns: 0 on success,
 *         -1 otherwise, with errno set.
 */
int
virProcessSchedCoreShareTo(pid_t pid)
{
    return prctl(PR_SCHED_CORE, PR_SCHED_CORE_SHARE_TO, pid,
                 PR_SCHED_CORE_SCOPE_THREAD, 0);
}

#else /* !__linux__ */

int
virProcessSchedCoreAvailable(void)
{
    return 0;
}

int
virProcessSchedCoreCreate(void)
{
    errno = ENOSYS;
    return -1;
}

int
virProcessSchedCoreShareFrom(pid_t pid G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}

int
virProcessSchedCoreShareTo(pid_t pid G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}
#endif /* !__linux__ */
