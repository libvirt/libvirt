/*
 * vircommand.c: Child command execution
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

#ifndef WIN32
# include <poll.h>
#endif
#include <signal.h>
#include <stdarg.h>
#include <sys/stat.h>
#ifndef WIN32
# include <sys/wait.h>
#endif
#include <fcntl.h>
#include <unistd.h>

#if WITH_CAPNG
# include <cap-ng.h>
#endif

#if defined(WITH_SECDRIVER_SELINUX)
# include <selinux/selinux.h>
#endif
#if defined(WITH_SECDRIVER_APPARMOR)
# include <sys/apparmor.h>
#endif

#define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
#include "viralloc.h"
#include "vircommandpriv.h"
#include "virerror.h"
#include "virutil.h"
#include "virlog.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virprocess.h"
#include "virbuffer.h"
#include "virsecureerase.h"
#include "virthread.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.command");

/* Flags for virExec */
enum {
    VIR_EXEC_NONE       = 0,
    VIR_EXEC_NONBLOCK   = (1 << 0),
    VIR_EXEC_DAEMON     = (1 << 1),
    VIR_EXEC_CLEAR_CAPS = (1 << 2),
    VIR_EXEC_RUN_SYNC   = (1 << 3),
    VIR_EXEC_ASYNC_IO   = (1 << 4),
};

typedef struct _virCommandFD virCommandFD;
struct _virCommandFD {
    int fd;
    unsigned int flags;
};

struct _virCommand {
    int has_error; /* 0 on success, -1 on error  */

    char *binaryPath; /* only valid if args[0] isn't absolute path */
    char **args;
    size_t nargs;
    size_t maxargs;

    char **env;
    size_t nenv;
    size_t maxenv;

    char *pwd;

    size_t npassfd;
    virCommandFD *passfd;

    unsigned int flags;

    char *inbuf;
    char **outbuf;
    char **errbuf;

    int infd;
    int inpipe;
    int outfd;
    int errfd;
    int *outfdptr;
    int *errfdptr;

    virThread *asyncioThread;

    bool handshake;
    int handshakeWait[2];
    int handshakeNotify[2];

    virExecHook hook;
    void *opaque;

    pid_t pid;
    char *pidfile;
    bool reap;
    bool rawStatus;

    bool setMaxMemLock;
    unsigned long long maxMemLock;
    bool setMaxProcesses;
    unsigned int maxProcesses;
    bool setMaxFiles;
    unsigned int maxFiles;
    bool setMaxCore;
    unsigned long long maxCore;

    uid_t uid;
    gid_t gid;
    unsigned long long capabilities;
#if defined(WITH_SECDRIVER_SELINUX)
    char *seLinuxLabel;
#endif
#if defined(WITH_SECDRIVER_APPARMOR)
    char *appArmorProfile;
#endif
    int mask;

    /* schedCore values:
     *  0: no core scheduling
     * >0: copy scheduling group from PID
     * -1: create new scheduling group
     */
    pid_t schedCore;

    virCommandSendBuffer *sendBuffers;
    size_t numSendBuffers;
};

/* See virCommandSetDryRun for description for this variable */
static virBuffer *dryRunBuffer;
static bool dryRunBufferArgLinebreaks;
static bool dryRunBufferCommandStripPath;
static virCommandDryRunCallback dryRunCallback;
static void *dryRunOpaque;
#ifndef WIN32
static int dryRunStatus;
#endif /* !WIN32 */


static bool
virCommandHasError(virCommand *cmd)
{
    return !cmd || cmd->has_error != 0;
}


static int
virCommandRaiseError(virCommand *cmd)
{
    if (!cmd || cmd->has_error != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid use of command API"));
        return -1;
    }

    return 0;
}


/*
 * virCommandFDIsSet:
 * @cmd: pointer to virCommand
 * @fd: file descriptor to query
 *
 * Check if FD is already in @set or not.
 *
 * Returns true if @set contains @fd,
 * false otherwise.
 */
static bool
virCommandFDIsSet(virCommand *cmd,
                  int fd)
{
    size_t i = 0;
    if (!cmd)
        return false;

    while (i < cmd->npassfd)
        if (cmd->passfd[i++].fd == fd)
            return true;

    return false;
}

/*
 * virCommandFDSet:
 * @cmd: pointer to virCommand
 * @fd: file descriptor to pass
 * @flags: extra flags; binary-OR of virCommandPassFDFlags
 *
 * This is practically generalized implementation
 * of FD_SET() as we do not want to be limited
 * by FD_SETSIZE.
 */
static void
virCommandFDSet(virCommand *cmd,
                int fd,
                unsigned int flags)
{
    if (virCommandFDIsSet(cmd, fd))
        return;

    VIR_EXPAND_N(cmd->passfd, cmd->npassfd, 1);

    cmd->passfd[cmd->npassfd - 1].fd = fd;
    cmd->passfd[cmd->npassfd - 1].flags = flags;
}

#ifndef WIN32

static void virDummyHandler(int sig G_GNUC_UNUSED)
{
}

/**
 * virFork:
 *
 * Wrapper around fork() that avoids various race/deadlock conditions.
 *
 * Like fork(), there are several return possibilities:
 * 1. No child was created: the return is -1, errno is set, and an error
 * message has been reported.  The semantics of virWaitProcess() recognize
 * this to avoid clobbering the error message from here.
 * 2. This is the parent: the return is > 0.  The parent can now attempt
 * to interact with the child (but be aware that unlike raw fork(), the
 * child may not return - some failures in the child result in this
 * function calling _exit(EXIT_CANCELED) if the child cannot be set up
 * correctly).
 * 3. This is the child: the return is 0.  If this happens, the parent
 * is also guaranteed to return.
 */
pid_t
virFork(void)
{
    sigset_t oldmask, newmask;
    struct sigaction sig_action;
    int saved_errno;
    pid_t pid;

    /*
     * Need to block signals now, so that child process can safely
     * kill off caller's signal handlers without a race.
     */
    sigfillset(&newmask);
    if (pthread_sigmask(SIG_SETMASK, &newmask, &oldmask) != 0) {
        virReportSystemError(errno,
                             "%s", _("cannot block signals"));
        return -1;
    }

    /* Ensure we hold the logging lock, to protect child processes
     * from deadlocking on another thread's inherited mutex state */
    virLogLock();

    pid = fork();
    saved_errno = errno; /* save for caller */

    /* Unlock for both parent and child process */
    virLogUnlock();

    if (pid < 0) {
        /* attempt to restore signal mask, but ignore failure, to
         * avoid obscuring the fork failure */
        ignore_value(pthread_sigmask(SIG_SETMASK, &oldmask, NULL));
        virReportSystemError(saved_errno,
                             "%s", _("cannot fork child process"));
        errno = saved_errno;

    } else if (pid) {
        /* parent process */

        /* Restore our original signal mask now that the child is
         * safely running. Only documented failures are EFAULT (not
         * possible, since we are using just-grabbed mask) or EINVAL
         * (not possible, since we are using correct arguments).  */
        ignore_value(pthread_sigmask(SIG_SETMASK, &oldmask, NULL));

    } else {
        /* child process */

        int logprio;
        size_t i;

        /* Remove any error callback so errors in child now get sent
         * to stderr where they stand a fighting chance of being seen
         * and logged */
        virSetErrorFunc(NULL, NULL);
        virSetErrorLogPriorityFunc(NULL);

        /* Make sure any hook logging is sent to stderr, since child
         * process may close the logfile FDs */
        logprio = virLogGetDefaultPriority();
        virLogReset();
        virLogSetDefaultPriority(logprio);

        /* Clear out all signal handlers from parent so nothing
         * unexpected can happen in our child once we unblock
         * signals */
        sig_action.sa_handler = SIG_DFL;
        sig_action.sa_flags = 0;
        sigemptyset(&sig_action.sa_mask);

        for (i = 1; i < NSIG; i++) {
            /* Only possible errors are EFAULT or EINVAL The former
             * won't happen, the latter we expect, so no need to check
             * return value */
            ignore_value(sigaction(i, &sig_action, NULL));
        }

        /* Code that runs between fork & execve might trigger
         * SIG_PIPE, so we must explicitly set that to a no-op
         * handler. This handler will get reset to SIG_DFL when
         * execve() runs
         */
        sig_action.sa_handler = virDummyHandler;
        ignore_value(sigaction(SIGPIPE, &sig_action, NULL));

        /* Unmask all signals in child, since we've no idea what the
         * caller's done with their signal mask and don't want to
         * propagate that to children */
        sigemptyset(&newmask);
        if (pthread_sigmask(SIG_SETMASK, &newmask, NULL) != 0) {
            virReportSystemError(errno, "%s", _("cannot unblock signals"));
            virDispatchError(NULL);
            _exit(EXIT_CANCELED);
        }
    }
    return pid;
}

/*
 * Ensure that *null is an fd visiting /dev/null.  Return 0 on
 * success, -1 on failure.  Allows for lazy opening of shared
 * /dev/null fd only as required.
 */
static int
getDevNull(int *null)
{
    if (*null == -1 && (*null = open("/dev/null", O_RDWR|O_CLOEXEC)) < 0) {
        virReportSystemError(errno,
                             _("cannot open %1$s"),
                             "/dev/null");
        return -1;
    }
    return 0;
}

/* Ensure that STD is an inheritable copy of FD.  Return 0 on success,
 * -1 on failure.  */
static int
prepareStdFd(int fd, int std)
{
    if (fd == std)
        return virSetInherit(fd, true);
    if (dup2(fd, std) != std)
        return -1;
    return 0;
}

/* virCommandHandshakeChild:
 *
 *   child side of handshake - called by child process in virExec() to
 *   indicate to parent that the child process has successfully
 *   completed its pre-exec initialization.
 */
static int
virCommandHandshakeChild(virCommand *cmd)
{
    char c = '1';
    int rv;

    if (!cmd->handshake)
       return 0;

    VIR_DEBUG("Notifying parent for handshake start on %d",
              cmd->handshakeWait[1]);
    if (safewrite(cmd->handshakeWait[1], &c, sizeof(c)) != sizeof(c)) {
        virReportSystemError(errno, "%s",
                             _("Unable to notify parent process"));
        return -1;
    }

    VIR_DEBUG("Waiting on parent for handshake complete on %d",
              cmd->handshakeNotify[0]);
    if ((rv = saferead(cmd->handshakeNotify[0], &c,
                       sizeof(c))) != sizeof(c)) {
        if (rv < 0)
            virReportSystemError(errno, "%s",
                                 _("Unable to wait on parent process"));
        else
            virReportSystemError(EIO, "%s",
                                 _("libvirtd quit during handshake"));
        return -1;
    }
    if (c != '1') {
        virReportSystemError(EINVAL,
                             _("Unexpected confirm code '%1$c' from parent"),
                             c);
        return -1;
    }
    VIR_FORCE_CLOSE(cmd->handshakeWait[1]);
    VIR_FORCE_CLOSE(cmd->handshakeNotify[0]);

    VIR_DEBUG("Handshake with parent is done");
    return 0;
}

static int
virExecCommon(virCommand *cmd, gid_t *groups, int ngroups)
{
    /* Do this before dropping capabilities. */
    if (cmd->schedCore == -1 &&
        virProcessSchedCoreCreate() < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set SCHED_CORE"));
        return -1;
    }

    if (cmd->schedCore > 0 &&
        virProcessSchedCoreShareFrom(cmd->schedCore) < 0) {
        virReportSystemError(errno,
                             _("Unable to run among %1$llu"),
                             (unsigned long long) cmd->schedCore);
        return -1;
    }

    if (cmd->uid != (uid_t)-1 || cmd->gid != (gid_t)-1 ||
        cmd->capabilities || (cmd->flags & VIR_EXEC_CLEAR_CAPS)) {
        VIR_DEBUG("Setting child uid:gid to %d:%d with caps %llx",
                  (int)cmd->uid, (int)cmd->gid, cmd->capabilities);
        if (virSetUIDGIDWithCaps(cmd->uid, cmd->gid, groups, ngroups,
                                 cmd->capabilities,
                                 !!(cmd->flags & VIR_EXEC_CLEAR_CAPS)) < 0)
            return -1;
    }

    if (cmd->pwd) {
        VIR_DEBUG("Running child in %s", cmd->pwd);
        if (chdir(cmd->pwd) < 0) {
            virReportSystemError(errno,
                                 _("Unable to change to %1$s"), cmd->pwd);
            return -1;
        }
    }
    return 0;
}

# ifdef __linux__
static int
virCommandMassCloseGetFDsDir(virBitmap *fds,
                             const char *dirName)
{
    g_autoptr(DIR) dp = NULL;
    struct dirent *entry;
    int rc;

    if (virDirOpen(&dp, dirName) < 0)
        return -1;

    while ((rc = virDirRead(dp, &entry, dirName)) > 0) {
        int fd;

        if (virStrToLong_i(entry->d_name, NULL, 10, &fd) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to parse FD: %1$s"),
                           entry->d_name);
            return -1;
        }

        virBitmapSetBitExpand(fds, fd);
    }

    if (rc < 0)
        return -1;

    return 0;
}
# endif /* __linux__ */

static int
virCommandMassCloseGetFDs(virBitmap *fds)
{
# ifdef __linux__
    /* On Linux, we can utilize procfs and read the table of opened
     * FDs and selectively close only those FDs we don't want to pass
     * onto child process (well, the one we will exec soon since this
     * is called from the child). */
    return virCommandMassCloseGetFDsDir(fds, "/proc/self/fd");
# else
    virBitmapSetAll(fds);
    return 0;
# endif
}

static int
virCommandMassCloseFrom(virCommand *cmd,
                        int childin,
                        int childout,
                        int childerr)
{
    g_autoptr(virBitmap) fds = NULL;
    int openmax = sysconf(_SC_OPEN_MAX);
    int lastfd = -1;
    int fd = -1;
    size_t i;

    /* In general, it is not safe to call malloc() between fork() and exec()
     * because the child might have forked at the worst possible time, i.e.
     * when another thread was in malloc() and thus held its lock. That is to
     * say, POSIX does not mandate malloc() to be async-safe. Fortunately,
     * glibc developers are aware of this and made malloc() async-safe.
     * Therefore we can safely allocate memory here (and transitively call
     * opendir/readdir) without a deadlock. */

    if (openmax <= 0) {
        /* Darwin defaults to 10240. Start with a generous value.
         * virCommandMassCloseGetFDsDir() uses virBitmapSetBitExpand() anyways.
         */
        openmax = 10240;
    }

    fds = virBitmapNew(openmax);

    if (virCommandMassCloseGetFDs(fds) < 0)
        return -1;

    lastfd = MAX(lastfd, childin);
    lastfd = MAX(lastfd, childout);
    lastfd = MAX(lastfd, childerr);

    for (i = 0; i < cmd->npassfd; i++)
        lastfd = MAX(lastfd, cmd->passfd[i].fd);

    fd = virBitmapNextSetBit(fds, 2);
    for (; fd >= 0 && fd <= lastfd; fd = virBitmapNextSetBit(fds, fd)) {
        if (fd == childin || fd == childout || fd == childerr)
            continue;
        if (!virCommandFDIsSet(cmd, fd)) {
            int tmpfd = fd;
            VIR_MASS_CLOSE(tmpfd);
        } else if (virSetInherit(fd, true) < 0) {
            virReportSystemError(errno, _("failed to preserve fd %1$d"), fd);
            return -1;
        }
    }

    if (virCloseFrom(lastfd + 1) < 0) {
        if (errno != ENOSYS)
            return -1;

        if (fd > 0) {
            for (; fd >= 0; fd = virBitmapNextSetBit(fds, fd)) {
                int tmpfd = fd;
                VIR_MASS_CLOSE(tmpfd);
            }
        }
    }

    return 0;
}


static int
virCommandMassCloseRange(virCommand *cmd,
                         int childin,
                         int childout,
                         int childerr)
{
    g_autoptr(virBitmap) fds = virBitmapNew(0);
    ssize_t first;
    ssize_t last;
    size_t i;

    virBitmapSetBitExpand(fds, childin);
    virBitmapSetBitExpand(fds, childout);
    virBitmapSetBitExpand(fds, childerr);

    for (i = 0; i < cmd->npassfd; i++) {
        int fd = cmd->passfd[i].fd;

        virBitmapSetBitExpand(fds, fd);

        if (virSetInherit(fd, true) < 0) {
            virReportSystemError(errno, _("failed to preserve fd %1$d"), fd);
            return -1;
        }
    }

    first = 2;
    while ((last = virBitmapNextSetBit(fds, first)) >= 0) {
        if (first + 1 == last) {
            first = last;
            continue;
        }

        /* Preserve @first and @last and close everything in between. */
        if (virCloseRange(first + 1, last - 1) < 0) {
            virReportSystemError(errno,
                                 _("Unable to mass close FDs (first=%1$zd, last=%2$zd)"),
                                 first + 1, last - 1);
            return -1;
        }

        first = last;
    }

    if (virCloseRange(first + 1, ~0U) < 0) {
        virReportSystemError(errno,
                             _("Unable to mass close FDs (first=%1$zd, last=%2$d"),
                             first + 1, ~0U);
        return -1;
    }

    return 0;
}



static int
virCommandMassClose(virCommand *cmd,
                    int childin,
                    int childout,
                    int childerr)
{
    if (virCloseRangeIsSupported())
        return virCommandMassCloseRange(cmd, childin, childout, childerr);

    return virCommandMassCloseFrom(cmd, childin, childout, childerr);
}


/*
 * virExec:
 * @cmd virCommand * containing all information about the program to
 *      exec.
 */
static int
virExec(virCommand *cmd)
{
    pid_t pid;
    int null = -1;
    int pipeout[2] = {-1, -1};
    int pipeerr[2] = {-1, -1};
    int pipesync[2] = {-1, -1};
    int childin = cmd->infd;
    int childout = -1;
    int childerr = -1;
    const char *binary = NULL;
    int ret;
    g_autofree gid_t *groups = NULL;
    int ngroups;

    if (!(binary = virCommandGetBinaryPath(cmd)))
        return -1;

    if (childin < 0) {
        if (getDevNull(&null) < 0)
            goto cleanup;
        childin = null;
    }

    if (cmd->outfdptr != NULL) {
        if (*cmd->outfdptr == -1) {
            if (virPipe(pipeout) < 0)
                goto cleanup;

            if ((cmd->flags & VIR_EXEC_NONBLOCK) &&
                virSetNonBlock(pipeout[0]) == -1) {
                virReportSystemError(errno, "%s",
                                     _("Failed to set non-blocking file descriptor flag"));
                goto cleanup;
            }

            childout = pipeout[1];
        } else {
            childout = *cmd->outfdptr;
        }
    } else {
        if (getDevNull(&null) < 0)
            goto cleanup;
        childout = null;
    }

    if (cmd->errfdptr != NULL) {
        if (cmd->errfdptr == cmd->outfdptr) {
            childerr = childout;
        } else if (*cmd->errfdptr == -1) {
            if (virPipe(pipeerr) < 0)
                goto cleanup;

            if ((cmd->flags & VIR_EXEC_NONBLOCK) &&
                virSetNonBlock(pipeerr[0]) == -1) {
                virReportSystemError(errno, "%s",
                                     _("Failed to set non-blocking file descriptor flag"));
                goto cleanup;
            }

            childerr = pipeerr[1];
        } else {
            childerr = *cmd->errfdptr;
        }
    } else {
        if (getDevNull(&null) < 0)
            goto cleanup;
        childerr = null;
    }

    ngroups = virGetGroupList(cmd->uid, cmd->gid, &groups);

    pid = virFork();

    if (pid < 0)
        goto cleanup;

    if (pid) { /* parent */
        VIR_FORCE_CLOSE(null);
        if (cmd->outfdptr && *cmd->outfdptr == -1) {
            VIR_FORCE_CLOSE(pipeout[1]);
            *cmd->outfdptr = pipeout[0];
        }
        if (cmd->errfdptr && *cmd->errfdptr == -1) {
            VIR_FORCE_CLOSE(pipeerr[1]);
            *cmd->errfdptr = pipeerr[0];
        }

        cmd->pid = pid;

        return 0;
    }

    /* child */

    if (cmd->mask)
        umask(cmd->mask);
    ret = EXIT_CANCELED;

    if (virCommandMassClose(cmd, childin, childout, childerr) < 0)
        goto fork_error;

    if (prepareStdFd(childin, STDIN_FILENO) < 0) {
        virReportSystemError(errno,
                             "%s", _("failed to setup stdin file handle"));
        goto fork_error;
    }
    if (childout > 0 && prepareStdFd(childout, STDOUT_FILENO) < 0) {
        virReportSystemError(errno,
                             "%s", _("failed to setup stdout file handle"));
        goto fork_error;
    }
    if (childerr > 0 && prepareStdFd(childerr, STDERR_FILENO) < 0) {
        virReportSystemError(errno,
                             "%s", _("failed to setup stderr file handle"));
        goto fork_error;
    }

    if (childin != STDIN_FILENO && childin != null &&
        childin != childerr && childin != childout)
        VIR_FORCE_CLOSE(childin);
    if (childout > STDERR_FILENO && childout != null && childout != childerr)
        VIR_FORCE_CLOSE(childout);
    if (childerr > STDERR_FILENO && childerr != null)
        VIR_FORCE_CLOSE(childerr);
    VIR_FORCE_CLOSE(null);

    /* Initialize full logging for a while */
    if (virLogSetFromEnv() < 0)
        goto fork_error;

    if (cmd->pidfile &&
        virPipe(pipesync) < 0)
        goto fork_error;

    /* Daemonize as late as possible, so the parent process can detect
     * the above errors with wait* */
    if (cmd->flags & VIR_EXEC_DAEMON) {
        char c;

        if (setsid() < 0) {
            virReportSystemError(errno,
                                 "%s", _("cannot become session leader"));
            goto fork_error;
        }

        if (chdir("/") < 0) {
            virReportSystemError(errno,
                                 "%s", _("cannot change to root directory"));
            goto fork_error;
        }

        pid = fork();
        if (pid < 0) {
            virReportSystemError(errno,
                                 "%s", _("cannot fork child process"));
            goto fork_error;
        }

        if (pid > 0) {
            /* At this point it's us and the child that holds the write end of
             * the pipe open. Close the write end of the pipe, so that the pipe
             * is fully closed if child dies prematurely. */
            VIR_FORCE_CLOSE(pipesync[1]);
            /* The parent expect us to have written the pid file before
             * exiting. Wait here for the child to write it and signal us. */
            if (cmd->pidfile &&
                saferead(pipesync[0], &c, sizeof(c)) != sizeof(c)) {
                virReportSystemError(errno, "%s",
                                     _("Unable to wait for child process"));
                _exit(EXIT_FAILURE);
            }
            _exit(EXIT_SUCCESS);
        }
    }

    pid = getpid();

    if (cmd->pidfile) {
        int pidfilefd = -1;
        char c;

        pidfilefd = virPidFileAcquirePath(cmd->pidfile, pid);
        if (pidfilefd < 0)
            goto fork_error;
        if (virSetInherit(pidfilefd, true) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Cannot disable close-on-exec flag"));
            goto fork_error;
        }

        c = '1';
        if (safewrite(pipesync[1], &c, sizeof(c)) != sizeof(c)) {
            virReportSystemError(errno, "%s", _("Unable to notify child process"));
            goto fork_error;
        }
        VIR_FORCE_CLOSE(pipesync[0]);
        VIR_FORCE_CLOSE(pipesync[1]);

        /* pidfilefd is intentionally leaked. */
    }

    if (cmd->setMaxMemLock &&
        virProcessSetMaxMemLock(pid, cmd->maxMemLock) < 0)
        goto fork_error;
    if (cmd->setMaxProcesses &&
        virProcessSetMaxProcesses(pid, cmd->maxProcesses) < 0)
        goto fork_error;
    if (cmd->setMaxFiles &&
        virProcessSetMaxFiles(pid, cmd->maxFiles) < 0)
        goto fork_error;
    if (cmd->setMaxCore &&
        virProcessSetMaxCoreSize(pid, cmd->maxCore) < 0)
        goto fork_error;

    if (cmd->hook) {
        VIR_DEBUG("Run hook %p %p", cmd->hook, cmd->opaque);
        ret = cmd->hook(cmd->opaque);
        VIR_DEBUG("Done hook %d", ret);
        if (ret < 0)
           goto fork_error;
    }

# if defined(WITH_SECDRIVER_SELINUX)
    if (cmd->seLinuxLabel) {
        VIR_DEBUG("Setting child security label to %s", cmd->seLinuxLabel);
        if (setexeccon_raw(cmd->seLinuxLabel) == -1) {
            virReportSystemError(errno,
                                 _("unable to set SELinux security context '%1$s' for '%2$s'"),
                                 cmd->seLinuxLabel, cmd->args[0]);
            if (security_getenforce() == 1)
                goto fork_error;
        }
    }
# endif
# if defined(WITH_SECDRIVER_APPARMOR)
    if (cmd->appArmorProfile) {
        VIR_DEBUG("Setting child AppArmor profile to %s", cmd->appArmorProfile);
        if (aa_change_profile(cmd->appArmorProfile) < 0) {
            virReportSystemError(errno,
                                 _("unable to set AppArmor profile '%1$s' for '%2$s'"),
                                 cmd->appArmorProfile, cmd->args[0]);
            goto fork_error;
        }
    }
# endif

    if (virExecCommon(cmd, groups, ngroups) < 0)
        goto fork_error;

    if (virCommandHandshakeChild(cmd) < 0)
       goto fork_error;

    /* Close logging again to ensure no FDs leak to child */
    virLogReset();

    if (cmd->env)
        execve(binary, cmd->args, cmd->env);
    else
        execv(binary, cmd->args);

    ret = errno == ENOENT ? EXIT_ENOENT : EXIT_CANNOT_INVOKE;
    virReportSystemError(errno,
                         _("cannot execute binary %1$s"),
                         cmd->args[0]);

 fork_error:
    virDispatchError(NULL);
    _exit(ret);

 cleanup:
    /* This is cleanup of parent process only - child
       should never jump here on error */

    /* NB we don't virReportError() on any failures here
       because the code which jumped here already raised
       an error condition which we must not overwrite */
    VIR_FORCE_CLOSE(pipeerr[0]);
    VIR_FORCE_CLOSE(pipeerr[1]);
    VIR_FORCE_CLOSE(pipeout[0]);
    VIR_FORCE_CLOSE(pipeout[1]);
    VIR_FORCE_CLOSE(null);
    return -1;
}


#else /* WIN32 */

pid_t
virFork(void)
{
    errno = ENOTSUP;

    return -1;
}

#endif /* WIN32 */


/**
 * virCommandNew:
 * @binary: program to run
 *
 * Create a new command for named binary.  If @binary is relative,
 * it will be found via a PATH search of the parent's PATH (and not
 * any altered PATH set by virCommandAddEnv* commands).
 */
virCommand *
virCommandNew(const char *binary)
{
    const char *const args[] = { binary, NULL };

    return virCommandNewArgs(args);
}

/**
 * virCommandNewArgs:
 * @args: array of arguments
 *
 * Create a new command with a NULL terminated
 * set of args, taking binary from args[0].  More arguments can
 * be added later.  @args[0] is handled like @binary of virCommandNew.
 */
virCommand *
virCommandNewArgs(const char *const*args)
{
    virCommand *cmd;

    cmd = g_new0(virCommand, 1);

    cmd->handshakeWait[0] = -1;
    cmd->handshakeWait[1] = -1;
    cmd->handshakeNotify[0] = -1;
    cmd->handshakeNotify[1] = -1;

    cmd->infd = cmd->inpipe = cmd->outfd = cmd->errfd = -1;
    cmd->pid = -1;
    cmd->uid = -1;
    cmd->gid = -1;

    virCommandAddArgSet(cmd, args);

    return cmd;
}

/**
 * virCommandNewArgList:
 * @binary: program to run
 * @...: additional arguments
 *
 * Create a new command with a NULL terminated
 * list of args, starting with the binary to run.  More arguments can
 * be added later.  @binary is handled as in virCommandNew.
 */
virCommand *
virCommandNewArgList(const char *binary, ...)
{
    virCommand *cmd;
    va_list list;

    va_start(list, binary);
    cmd = virCommandNewVAList(binary, list);
    va_end(list);

    return cmd;
}

/**
 * virCommandNewVAList:
 * @binary: program to run
 * @va_list: additional arguments
 *
 * Create a new command with a NULL terminated
 * variable argument list.  @binary is handled as in virCommandNew.
 */
virCommand *
virCommandNewVAList(const char *binary, va_list list)
{
    virCommand *cmd = virCommandNew(binary);
    const char *arg;

    if (virCommandHasError(cmd))
        return cmd;

    while ((arg = va_arg(list, const char *)) != NULL)
        virCommandAddArg(cmd, arg);
    return cmd;
}


#define VIR_COMMAND_MAYBE_CLOSE_FD(fd, flags) \
    if ((fd > STDERR_FILENO) && \
        (flags & VIR_COMMAND_PASS_FD_CLOSE_PARENT)) \
        VIR_FORCE_CLOSE(fd)

/**
 * virCommandPassFD:
 * @cmd: the command to modify
 * @fd: fd to reassign to the child
 * @flags: extra flags; binary-OR of virCommandPassFDFlags
 *
 * Transfer the specified file descriptor to the child, instead
 * of closing it on exec. @fd must not be one of the three
 * standard streams.
 *
 * If the flag VIR_COMMAND_PASS_FD_CLOSE_PARENT is set then fd will
 * be closed in the parent no later than Run/RunAsync/Free. The parent
 * should cease using the @fd when this call completes
 */
void
virCommandPassFD(virCommand *cmd, int fd, unsigned int flags)
{
    if (!cmd) {
        VIR_COMMAND_MAYBE_CLOSE_FD(fd, flags);
        return;
    }

    if (fd <= STDERR_FILENO) {
        VIR_DEBUG("invalid fd %d", fd);
        VIR_COMMAND_MAYBE_CLOSE_FD(fd, flags);
        if (!cmd->has_error)
            cmd->has_error = -1;
        return;
    }

    virCommandFDSet(cmd, fd, flags);
}

/**
 * virCommandSetPidFile:
 * @cmd: the command to modify
 * @pidfile: filename to use
 *
 * Save the child PID in a pidfile. The pidfile will be populated before the
 * exec of the child and the child will inherit opened and locked FD to the
 * pidfile.
 */
void
virCommandSetPidFile(virCommand *cmd, const char *pidfile)
{
    if (virCommandHasError(cmd))
        return;

    VIR_FREE(cmd->pidfile);
    cmd->pidfile = g_strdup(pidfile);
}


gid_t
virCommandGetGID(virCommand *cmd)
{
    return cmd->gid;
}


uid_t
virCommandGetUID(virCommand *cmd)
{
    return cmd->uid;
}


void
virCommandSetGID(virCommand *cmd, gid_t gid)
{
    if (virCommandHasError(cmd))
        return;

    cmd->gid = gid;
}

void
virCommandSetUID(virCommand *cmd, uid_t uid)
{
    if (virCommandHasError(cmd))
        return;

    cmd->uid = uid;
}

void
virCommandSetMaxMemLock(virCommand *cmd, unsigned long long bytes)
{
    if (virCommandHasError(cmd))
        return;

    cmd->maxMemLock = bytes;
    cmd->setMaxMemLock = true;
}

void
virCommandSetMaxProcesses(virCommand *cmd, unsigned int procs)
{
    if (virCommandHasError(cmd))
        return;

    cmd->maxProcesses = procs;
    cmd->setMaxProcesses = true;
}

void
virCommandSetMaxFiles(virCommand *cmd, unsigned int files)
{
    if (virCommandHasError(cmd))
        return;

    cmd->maxFiles = files;
    cmd->setMaxFiles = true;
}

void virCommandSetMaxCoreSize(virCommand *cmd, unsigned long long bytes)
{
    if (virCommandHasError(cmd))
        return;

    cmd->maxCore = bytes;
    cmd->setMaxCore = true;
}

void virCommandSetUmask(virCommand *cmd, int mask)
{
    if (virCommandHasError(cmd))
        return;

    cmd->mask = mask;
}

/**
 * virCommandClearCaps:
 * @cmd: the command to modify
 *
 * Remove all capabilities from the child, after any hooks have been run.
 */
void
virCommandClearCaps(virCommand *cmd)
{
    if (virCommandHasError(cmd))
        return;

    cmd->flags |= VIR_EXEC_CLEAR_CAPS;
}

/**
 * virCommandAllowCap:
 * @cmd: the command to modify
 * @capability: what to allow
 *
 * Allow specific capabilities
 */
void
virCommandAllowCap(virCommand *cmd,
                   int capability)
{
    if (virCommandHasError(cmd))
        return;

    cmd->capabilities |= (1ULL << capability);
}


/**
 * virCommandSetSELinuxLabel:
 * @cmd: the command to modify
 * @label: the SELinux label to use for the child process
 *
 * Saves a copy of @label to use when setting the SELinux context
 * label (with setexeccon_raw()) after the child process has been
 * started. If SELinux isn't compiled into libvirt, or if label is
 * NULL, nothing will be done.
 */
void
virCommandSetSELinuxLabel(virCommand *cmd,
                          const char *label G_GNUC_UNUSED)
{
    if (virCommandHasError(cmd))
        return;

#if defined(WITH_SECDRIVER_SELINUX)
    VIR_FREE(cmd->seLinuxLabel);
    cmd->seLinuxLabel = g_strdup(label);
#endif
    return;
}


/**
 * virCommandSetAppArmorProfile:
 * @cmd: the command to modify
 * @profile: the AppArmor profile to use
 *
 * Saves a copy of @profile to use when aa_change_profile() after the
 * child process has been started. If AppArmor support isn't
 * configured into libvirt, or if profile is NULL, nothing will be done.
 */
void
virCommandSetAppArmorProfile(virCommand *cmd,
                             const char *profile G_GNUC_UNUSED)
{
    if (virCommandHasError(cmd))
        return;

#if defined(WITH_SECDRIVER_APPARMOR)
    VIR_FREE(cmd->appArmorProfile);
    cmd->appArmorProfile = g_strdup(profile);
#endif
    return;
}


/**
 * virCommandDaemonize:
 * @cmd: the command to modify
 *
 * Daemonize the child process.  The child will have a current working
 * directory of /, and must be started with virCommandRun, which will
 * complete as soon as the daemon grandchild has started.
 */
void
virCommandDaemonize(virCommand *cmd)
{
    if (virCommandHasError(cmd))
        return;

    cmd->flags |= VIR_EXEC_DAEMON;
}

/**
 * virCommandNonblockingFDs:
 * @cmd: the command to modify
 *
 * Set FDs created by virCommandSetOutputFD and virCommandSetErrorFD
 * as non-blocking in the parent.
 */
void
virCommandNonblockingFDs(virCommand *cmd)
{
    if (virCommandHasError(cmd))
        return;

    cmd->flags |= VIR_EXEC_NONBLOCK;
}

/**
 * virCommandRawStatus:
 * @cmd: the command to modify
 *
 * Mark this command as returning raw exit status via virCommandRun() or
 * virCommandWait() (caller must use WIFEXITED() and friends, and can
 * detect death from signals) instead of the default of only allowing
 * normal exit status (caller must not use WEXITSTATUS(), and death from
 * signals returns -1).
 */
void
virCommandRawStatus(virCommand *cmd)
{
    if (virCommandHasError(cmd))
        return;

    cmd->rawStatus = true;
}

/* Add an environment variable to the cmd->env list.  'env' is a
 * string like "name=value".  If the named environment variable is
 * already set, then it is replaced in the list.
 */
static void
virCommandAddEnv(virCommand *cmd,
                 char *envstr)
{
    g_autofree char *env = envstr;
    size_t namelen;
    size_t i;

    /* Search for the name in the existing environment. */
    namelen = strcspn(env, "=");
    for (i = 0; i < cmd->nenv; ++i) {
        /* + 1 because we want to match the '=' character too. */
        if (STREQLEN(cmd->env[i], env, namelen + 1)) {
            VIR_FREE(cmd->env[i]);
            cmd->env[i] = g_steal_pointer(&env);
            return;
        }
    }

    /* Arg plus trailing NULL. */
    VIR_RESIZE_N(cmd->env, cmd->maxenv, cmd->nenv, 1 + 1);

    cmd->env[cmd->nenv++] = g_steal_pointer(&env);
}

/**
 * virCommandAddEnvFormat:
 * @cmd: the command to modify
 * @format: format of arguments, end result must be in name=value format
 * @...: arguments to be formatted
 *
 * Add an environment variable to the child created by a printf-style format.
 */
void
virCommandAddEnvFormat(virCommand *cmd, const char *format, ...)
{
    char *env;
    va_list list;

    if (virCommandHasError(cmd))
        return;

    va_start(list, format);
    env = g_strdup_vprintf(format, list);
    va_end(list);

    virCommandAddEnv(cmd, env);
}

/**
 * virCommandAddEnvPair:
 * @cmd: the command to modify
 * @name: variable name, must not contain =
 * @value: value to assign to name
 *
 * Add an environment variable to the child
 * using separate name & value strings
 */
void
virCommandAddEnvPair(virCommand *cmd, const char *name, const char *value)
{
    virCommandAddEnvFormat(cmd, "%s=%s", name, value);
}


/**
 * virCommandAddEnvString:
 * @cmd: the command to modify
 * @str: name=value format
 *
 * Add an environment variable to the child
 * using a preformatted env string FOO=BAR
 */
void
virCommandAddEnvString(virCommand *cmd, const char *str)
{
    char *env;

    if (virCommandHasError(cmd))
        return;

    env = g_strdup(str);

    virCommandAddEnv(cmd, env);
}


/**
 * virCommandAddEnvPass:
 * @cmd: the command to modify
 * @name: the name to look up in current environment
 *
 * Pass an environment variable to the child
 * using current process's value
 */
void
virCommandAddEnvPass(virCommand *cmd, const char *name)
{
    const char *value;
    if (virCommandHasError(cmd))
        return;

    value = getenv(name);
    if (value)
        virCommandAddEnvPair(cmd, name, value);
}


/**
 * virCommandAddEnvPassCommon:
 * @cmd: the command to modify
 *
 * Set LC_ALL to C, and propagate other essential environment
 * variables (such as PATH) from the parent process.
 */
void
virCommandAddEnvPassCommon(virCommand *cmd)
{
    if (virCommandHasError(cmd))
        return;

    VIR_RESIZE_N(cmd->env, cmd->maxenv, cmd->nenv, 9);

    virCommandAddEnvPair(cmd, "LC_ALL", "C");

    virCommandAddEnvPass(cmd, "LD_PRELOAD");
    virCommandAddEnvPass(cmd, "LD_LIBRARY_PATH");
    virCommandAddEnvPass(cmd, "DYLD_INSERT_LIBRARIES");
    virCommandAddEnvPass(cmd, "DYLD_FORCE_FLAT_NAMESPACE");
    virCommandAddEnvPass(cmd, "PATH");
    virCommandAddEnvPass(cmd, "HOME");
    virCommandAddEnvPass(cmd, "USER");
    virCommandAddEnvPass(cmd, "LOGNAME");
    virCommandAddEnvPass(cmd, "TMPDIR");
}


void
virCommandAddEnvXDG(virCommand *cmd, const char *baseDir)
{
    if (virCommandHasError(cmd))
        return;

    VIR_RESIZE_N(cmd->env, cmd->maxenv, cmd->nenv, 3);

    virCommandAddEnvFormat(cmd, "XDG_DATA_HOME=%s/%s",
                           baseDir, ".local/share");
    virCommandAddEnvFormat(cmd, "XDG_CACHE_HOME=%s/%s",
                           baseDir, ".cache");
    virCommandAddEnvFormat(cmd, "XDG_CONFIG_HOME=%s/%s",
                           baseDir, ".config");
}


/**
 * virCommandAddArg:
 * @cmd: the command to modify
 * @val: the argument to add
 *
 * Add a command line argument to the child
 */
void
virCommandAddArg(virCommand *cmd, const char *val)
{
    if (virCommandHasError(cmd))
        return;

    if (val == NULL) {
        cmd->has_error = EINVAL;
        return;
    }

    /* Arg plus trailing NULL. */
    VIR_RESIZE_N(cmd->args, cmd->maxargs, cmd->nargs, 1 + 1);

    cmd->args[cmd->nargs++] = g_strdup(val);
}


/**
 * virCommandAddArgBuffer:
 * @cmd: the command to modify
 * @buf: buffer that contains argument string, which will be reset on return
 *
 * Convert a buffer into a command line argument to the child.
 * Correctly transfers memory errors or contents from buf to cmd.
 */
void
virCommandAddArgBuffer(virCommand *cmd, virBuffer *buf)
{
    g_autofree char *str = virBufferContentAndReset(buf);

    if (virCommandHasError(cmd))
        return;

    if (!str)
        str = g_strdup("");

    /* Arg plus trailing NULL. */
    VIR_RESIZE_N(cmd->args, cmd->maxargs, cmd->nargs, 1 + 1);

    cmd->args[cmd->nargs] = g_steal_pointer(&str);
    cmd->nargs++;
}


/**
 * virCommandAddArgFormat:
 * @cmd: the command to modify
 * @format: format of arguments, end result must be in name=value format
 * @...: arguments to be formatted
 *
 * Add a command line argument created by a printf-style format.
 */
void
virCommandAddArgFormat(virCommand *cmd, const char *format, ...)
{
    char *arg;
    va_list list;

    if (virCommandHasError(cmd))
        return;

    va_start(list, format);
    arg = g_strdup_vprintf(format, list);
    va_end(list);

    /* Arg plus trailing NULL. */
    VIR_RESIZE_N(cmd->args, cmd->maxargs, cmd->nargs, 1 + 1);

    cmd->args[cmd->nargs++] = arg;
}

/**
 * virCommandAddArgPair:
 * @cmd: the command to modify
 * @name: left half of argument
 * @value: right half of argument
 *
 * Add "NAME=VAL" as a single command line argument to the child
 */
void
virCommandAddArgPair(virCommand *cmd, const char *name, const char *val)
{
    if (name == NULL || val == NULL) {
        cmd->has_error = EINVAL;
        return;
    }
    virCommandAddArgFormat(cmd, "%s=%s", name, val);
}

/**
 * virCommandAddArgSet:
 * @cmd: the command to modify
 * @vals: array of arguments to add
 *
 * Add a NULL terminated list of args
 */
void
virCommandAddArgSet(virCommand *cmd, const char *const*vals)
{
    int narg = 0;

    if (virCommandHasError(cmd))
        return;

    if (vals[0] == NULL) {
        cmd->has_error = EINVAL;
        return;
    }

    while (vals[narg] != NULL)
        narg++;

    /* narg plus trailing NULL. */
    VIR_RESIZE_N(cmd->args, cmd->maxargs, cmd->nargs, narg + 1);

    narg = 0;
    while (vals[narg] != NULL) {
        char *arg;

        arg = g_strdup(vals[narg++]);
        cmd->args[cmd->nargs++] = arg;
    }
}

/**
 * virCommandAddArgList:
 * @cmd: the command to modify
 * @...: list of arguments to add
 *
 * Add a NULL terminated list of args.
 */
void
virCommandAddArgList(virCommand *cmd, ...)
{
    va_list list;
    int narg = 0;

    if (virCommandHasError(cmd))
        return;

    va_start(list, cmd);
    while (va_arg(list, const char *) != NULL)
        narg++;
    va_end(list);

    /* narg plus trailing NULL. */
    VIR_RESIZE_N(cmd->args, cmd->maxargs, cmd->nargs, narg + 1);

    va_start(list, cmd);
    while (1) {
        char *arg = va_arg(list, char *);
        if (!arg)
            break;
        arg = g_strdup(arg);
        cmd->args[cmd->nargs++] = arg;
    }
    va_end(list);
}

/**
 * virCommandSetWorkingDirectory:
 * @cmd: the command to modify
 * @pwd: directory to use
 *
 * Set the working directory of a non-daemon child process, rather
 * than the parent's working directory.  Daemons automatically get /
 * without using this call.
 */
void
virCommandSetWorkingDirectory(virCommand *cmd, const char *pwd)
{
    if (virCommandHasError(cmd))
        return;

    if (cmd->pwd) {
        cmd->has_error = -1;
        VIR_DEBUG("cannot set directory twice");
    } else {
        cmd->pwd = g_strdup(pwd);
    }
}


static int
virCommandGetNumSendBuffers(virCommand *cmd)
{
    return cmd->numSendBuffers;
}


static void
virCommandFreeSendBuffers(virCommand *cmd)
{
    size_t i;

    for (i = 0; i < virCommandGetNumSendBuffers(cmd); i++) {
        VIR_FORCE_CLOSE(cmd->sendBuffers[i].fd);
        virSecureErase(cmd->sendBuffers[i].buffer, cmd->sendBuffers[i].buflen);
        VIR_FREE(cmd->sendBuffers[i].buffer);
    }
    VIR_FREE(cmd->sendBuffers);
}


#ifndef WIN32
/**
 * virCommandSetSendBuffer
 * @cmd: the command to modify
 * @buffer: buffer to pass to the filedescriptror
 * @buflen: length of @buffer
 *
 * Registers @buffer as an input buffer for @cmd which will be accessible via
 * the returned file descriptor. The returned file descriptor is already
 * registered to be passed to @cmd, so callers must use it only to format the
 * appropriate argument of @cmd.
 *
 * @buffer is always stolen regardless of the return value. This function
 * doesn't raise a libvirt error, but rather propagates the error via virCommand.
 * Thus callers don't need to take a special action if -1 is returned.
 *
 * When the @cmd is daemonized via virCommandDaemonize() remember to request
 * asynchronous IO via virCommandDoAsyncIO().
 */
int
virCommandSetSendBuffer(virCommand *cmd,
                        unsigned char **buffer,
                        size_t buflen)
{
    g_autofree unsigned char *localbuf = g_steal_pointer(buffer);
    int pipefd[2] = { -1, -1 };
    size_t i;

    if (virCommandHasError(cmd))
        return -1;

    if (virPipeQuiet(pipefd) < 0) {
        cmd->has_error = errno;
        return -1;
    }

    if (fcntl(pipefd[1], F_SETFL, O_NONBLOCK) < 0) {
        cmd->has_error = errno;
        VIR_FORCE_CLOSE(pipefd[0]);
        VIR_FORCE_CLOSE(pipefd[1]);
        return -1;
    }

    i = virCommandGetNumSendBuffers(cmd);
    VIR_REALLOC_N(cmd->sendBuffers, i + 1);

    cmd->sendBuffers[i].fd = pipefd[1];
    cmd->sendBuffers[i].buffer = g_steal_pointer(&localbuf);
    cmd->sendBuffers[i].buflen = buflen;
    cmd->sendBuffers[i].offset = 0;

    cmd->numSendBuffers++;

    virCommandPassFD(cmd, pipefd[0], VIR_COMMAND_PASS_FD_CLOSE_PARENT);

    return pipefd[0];
}


static int
virCommandSendBuffersFillPollfd(virCommand *cmd,
                                struct pollfd *fds,
                                int startidx)
{
    size_t i, j;

    for (i = 0, j = 0; i < virCommandGetNumSendBuffers(cmd); i++) {
        if (cmd->sendBuffers[i].fd >= 0) {
            fds[startidx + j].fd = cmd->sendBuffers[i].fd;
            fds[startidx + j].events = POLLOUT;
            fds[startidx + j].revents = 0;
            j++;
        }
    }

    return j;
}


static int
virCommandSendBuffersHandlePoll(virCommand *cmd,
                                struct pollfd *fds)
{
    size_t i;
    ssize_t done;

    for (i = 0; i < virCommandGetNumSendBuffers(cmd); i++) {
        if (fds->fd == cmd->sendBuffers[i].fd)
            break;
    }
    if (i == virCommandGetNumSendBuffers(cmd))
        return 0;

    done = write(fds->fd, /* sc_avoid_write */
                 cmd->sendBuffers[i].buffer + cmd->sendBuffers[i].offset,
                 cmd->sendBuffers[i].buflen - cmd->sendBuffers[i].offset);
    if (done < 0) {
        if (errno == EPIPE) {
            VIR_DEBUG("child closed PIPE early, ignoring EPIPE "
                      "on fd %d", cmd->sendBuffers[i].fd);
            VIR_FORCE_CLOSE(cmd->sendBuffers[i].fd);
        } else if (errno != EINTR && errno != EAGAIN) {
            virReportSystemError(errno, "%s",
                                 _("unable to write to child input"));
            return -1;
        }
    } else {
        cmd->sendBuffers[i].offset += done;
        if (cmd->sendBuffers[i].offset == cmd->sendBuffers[i].buflen)
            VIR_FORCE_CLOSE(cmd->sendBuffers[i].fd);
    }
    return 0;
}

#endif /* !WIN32 */


/**
 * virCommandSetInputBuffer:
 * @cmd: the command to modify
 * @inbuf: string to feed to stdin
 *
 * Feed the child's stdin from a string buffer.  This requires the
 * use of virCommandRun() or combination of virCommandDoAsyncIO and
 * virCommandRunAsync. The buffer is forgotten after each @cmd run.
 */
void
virCommandSetInputBuffer(virCommand *cmd, const char *inbuf)
{
    if (virCommandHasError(cmd))
        return;

    if (cmd->infd != -1 || cmd->inbuf) {
        cmd->has_error = -1;
        VIR_DEBUG("cannot specify input twice");
        return;
    }

    cmd->inbuf = g_strdup(inbuf);
}


/**
 * virCommandSetOutputBuffer:
 * @cmd: the command to modify
 * @outbuf: address of variable to store malloced result buffer
 *
 * Capture the child's stdout to a string buffer.  *outbuf is
 * guaranteed to be allocated after successful virCommandRun or
 * virCommandWait, and is best-effort allocated after failed
 * virCommandRun or virCommandRunAsync; caller is responsible for
 * freeing *outbuf. This requires the use of virCommandRun() or
 * combination of virCommandDoAsyncIO and virCommandRunAsync. The
 * buffer is forgotten after each @cmd run.
 */
void
virCommandSetOutputBuffer(virCommand *cmd, char **outbuf)
{
    *outbuf = NULL;
    if (virCommandHasError(cmd))
        return;

    if (cmd->outfdptr) {
        cmd->has_error = -1;
        VIR_DEBUG("cannot specify output twice");
        return;
    }

    cmd->outbuf = outbuf;
    cmd->outfdptr = &cmd->outfd;
}


/**
 * virCommandSetErrorBuffer:
 * @cmd: the command to modify
 * @errbuf: address of variable to store malloced result buffer
 *
 * Capture the child's stderr to a string buffer.  *errbuf is
 * guaranteed to be allocated after successful virCommandRun or
 * virCommandWait, and is best-effort allocated after failed
 * virCommandRun or virCommandRunAsync; caller is responsible for
 * freeing *errbuf. It is possible to pass the same pointer as
 * for virCommandSetOutputBuffer(), in which case the child
 * process will interleave all output into a single string.  This
 * requires the use of virCommandRun() or combination of
 * virCommandDoAsyncIO and virCommandRunAsync.The buffer is
 * forgotten after each @cmd run.
 */
void
virCommandSetErrorBuffer(virCommand *cmd, char **errbuf)
{
    *errbuf = NULL;
    if (virCommandHasError(cmd))
        return;

    if (cmd->errfdptr) {
        cmd->has_error = -1;
        VIR_DEBUG("cannot specify stderr twice");
        return;
    }

    cmd->errbuf = errbuf;
    cmd->errfdptr = &cmd->errfd;
}


/**
 * virCommandSetInputFD:
 * @cmd: the command to modify
 * @infd: the descriptor to use
 *
 * Attach a file descriptor to the child's stdin
 */
void
virCommandSetInputFD(virCommand *cmd, int infd)
{
    if (virCommandHasError(cmd))
        return;

    if (cmd->infd != -1 || cmd->inbuf) {
        cmd->has_error = -1;
        VIR_DEBUG("cannot specify input twice");
        return;
    }
    if (infd < 0) {
        cmd->has_error = -1;
        VIR_DEBUG("cannot specify invalid input fd");
        return;
    }

    cmd->infd = infd;
}


/**
 * virCommandSetOutputFD:
 * @cmd: the command to modify
 * @outfd: location of output fd
 *
 * Attach a file descriptor to the child's stdout.  If *@outfd is -1 on
 * entry, then a pipe will be created and returned in this variable when
 * the child is run.  Otherwise, *@outfd is used as the output.
 */
void
virCommandSetOutputFD(virCommand *cmd, int *outfd)
{
    if (virCommandHasError(cmd))
        return;

    if (cmd->outfdptr) {
        cmd->has_error = -1;
        VIR_DEBUG("cannot specify output twice");
        return;
    }

    cmd->outfdptr = outfd;
}


/**
 * virCommandSetErrorFD:
 * @cmd: the command to modify
 * @errfd: location of error fd
 *
 * Attach a file descriptor to the child's stderr.  If *@errfd is -1 on
 * entry, then a pipe will be created and returned in this variable when
 * the child is run.  Otherwise, *@errfd is used for error collection,
 * and may be the same as outfd given to virCommandSetOutputFD().
 */
void
virCommandSetErrorFD(virCommand *cmd, int *errfd)
{
    if (virCommandHasError(cmd))
        return;

    if (cmd->errfdptr) {
        cmd->has_error = -1;
        VIR_DEBUG("cannot specify stderr twice");
        return;
    }

    cmd->errfdptr = errfd;
}


/**
 * virCommandSetPreExecHook:
 * @cmd: the command to modify
 * @hook: the hook to run
 * @opaque: argument to pass to the hook
 *
 * Run HOOK(OPAQUE) in the child as the last thing before changing
 * directories, dropping capabilities, and executing the new process.
 * Force the child to fail if HOOK does not return zero.
 *
 * Since @hook runs in the child, it should be careful to avoid
 * any functions that are not async-signal-safe.
 */
void
virCommandSetPreExecHook(virCommand *cmd, virExecHook hook, void *opaque)
{
    if (virCommandHasError(cmd))
        return;

    if (cmd->hook) {
        cmd->has_error = -1;
        VIR_DEBUG("cannot specify hook twice");
        return;
    }
    cmd->hook = hook;
    cmd->opaque = opaque;
}


/**
 * virCommandWriteArgLog:
 * @cmd: the command to log
 * @logfd: where to log the results
 *
 * Call after adding all arguments and environment settings, but before
 * Run/RunAsync, to immediately output the environment and arguments of
 * cmd to logfd.  If virCommandRun cannot succeed (because of an
 * out-of-memory condition while building cmd), nothing will be logged.
 */
void
virCommandWriteArgLog(virCommand *cmd, int logfd)
{
    int ioError = 0;
    size_t i;

    /* Any errors will be reported later by virCommandRun, which means
     * no command will be run, so there is nothing to log. */
    if (virCommandHasError(cmd))
        return;

    for (i = 0; i < cmd->nenv; i++) {
        if (safewrite(logfd, cmd->env[i], strlen(cmd->env[i])) < 0)
            ioError = errno;
        if (safewrite(logfd, " ", 1) < 0)
            ioError = errno;
    }
    for (i = 0; i < cmd->nargs; i++) {
        if (safewrite(logfd, cmd->args[i], strlen(cmd->args[i])) < 0)
            ioError = errno;
        if (safewrite(logfd, i == cmd->nargs - 1 ? "\n" : " ", 1) < 0)
            ioError = errno;
    }

    if (ioError) {
        VIR_WARN("Unable to write command %s args to logfile: %s",
                 cmd->args[0], g_strerror(ioError));
    }
}


/**
 * virCommandToStringBuf:
 * @cmd: the command to convert
 * @buf: buffer to format @cmd into
 * @linebreaks: true to break line after each env var or option
 * @stripCommandPath: strip the path leading to the binary of @cmd
 *
 * Call after adding all arguments and environment settings, but
 * before Run/RunAsync, to return a string representation of the
 * environment and arguments of cmd, suitably quoted for pasting into
 * a shell.  If virCommandRun cannot succeed (because of an
 * out-of-memory condition while building cmd), -1 will be returned.
 */
int
virCommandToStringBuf(virCommand *cmd,
                      virBuffer *buf,
                      bool linebreaks,
                      bool stripCommandPath)
{
    size_t i;
    const char *command = cmd->args[0];
    g_autofree char *basename = NULL;
    bool had_option = false;

    /* Cannot assume virCommandRun will be called; so report the error
     * now.  If virCommandRun is called, it will report the same error. */
    if (virCommandHasError(cmd)) {
        virCommandRaiseError(cmd);
        return -1;
    }

    for (i = 0; i < cmd->nenv; i++) {
        /* In shell, a='b c' has a different meaning than 'a=b c', so
         * we must determine where the '=' lives.  */
        char *eq = strchr(cmd->env[i], '=');

        if (!eq) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("invalid use of command API"));
            return -1;
        }
        eq++;
        virBufferAdd(buf, cmd->env[i], eq - cmd->env[i]);
        virBufferEscapeShell(buf, eq);
        virBufferAddChar(buf, ' ');
        if (linebreaks)
            virBufferAddLit(buf, "\\\n");
    }

    if (stripCommandPath)
        command = basename = g_path_get_basename(command);

    virBufferEscapeShell(buf, command);
    for (i = 1; i < cmd->nargs; i++) {
        virBufferAddChar(buf, ' ');

        if (linebreaks) {
            /* we don't want a linebreak only if
             * - the previous argument is an option (starts with '-')
             * - there was already an option and another option follows
             */
            bool linebreak = true;

            if (cmd->args[i][0] != '-') {
                if (had_option) {
                    size_t j;
                    /* we know that arg[i - 1] is valid and arg[i] is not an option */
                    for (j = i - 1; j < cmd->nargs; j++) {
                        if (cmd->args[j][0] == '-') {
                            linebreak = false;
                            break;
                        }
                    }
                }
            } else {
                had_option = true;
            }

            if (linebreak)
                virBufferAddLit(buf, "\\\n");
        }
        virBufferEscapeShell(buf, cmd->args[i]);
    }

    return 0;
}


char *
virCommandToStringFull(virCommand *cmd,
                       bool linebreaks,
                       bool stripCommandPath)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (virCommandToStringBuf(cmd, &buf, linebreaks, stripCommandPath))
        return NULL;

    return virBufferContentAndReset(&buf);
}


char *
virCommandToString(virCommand *cmd,
                   bool linebreaks)
{
    return virCommandToStringFull(cmd, linebreaks, false);
}


int
virCommandGetArgList(virCommand *cmd,
                     char ***args)
{
    size_t i;

    if (virCommandHasError(cmd)) {
        virCommandRaiseError(cmd);
        return -1;
    }

    *args = g_new0(char *, cmd->nargs);

    for (i = 1; i < cmd->nargs; i++)
        (*args)[i - 1] = g_strdup(cmd->args[i]);

    return 0;
}


/*
 * virCommandGetBinaryPath:
 * @cmd: virCommand* containing all information about the program
 *
 * If args[0] is an absolute path, return that. If not, then resolve
 * args[0] to a full absolute path, cache that in binaryPath, and
 * return a pointer to this resolved string. binaryPath is only set by
 * calling this function, so even other virCommand functions should
 * access binaryPath via this function.
 *
 * returns const char* with the full path of the binary to be
 * executed, or NULL on failure.
 */
const char *
virCommandGetBinaryPath(virCommand *cmd)
{

    if (cmd->binaryPath)
        return cmd->binaryPath;

    if (g_path_is_absolute(cmd->args[0]))
        return cmd->args[0];

    if (!(cmd->binaryPath = virFindFileInPath(cmd->args[0]))) {
        virReportSystemError(ENOENT,
                             _("Cannot find '%1$s' in path"),
                             cmd->args[0]);
        return NULL;
    }

    return cmd->binaryPath;
}


#ifndef WIN32
/*
 * Manage input and output to the child process.
 */
static int
virCommandProcessIO(virCommand *cmd)
{
    int outfd = -1, errfd = -1;
    size_t inlen = 0, outlen = 0, errlen = 0;
    size_t inoff = 0;
    int ret = -1;
    g_autofree struct pollfd *fds = NULL;

    if (dryRunBuffer || dryRunCallback) {
        VIR_DEBUG("Dry run requested, skipping I/O processing");
        return 0;
    }

    /* With an input buffer, feed data to child
     * via pipe */
    if (cmd->inbuf)
        inlen = strlen(cmd->inbuf);

    /* With out/err buffer, the outfd/errfd have been filled with an
     * FD for us.  Guarantee an allocated string with partial results
     * even if we encounter a later failure, as well as freeing any
     * results accumulated over a prior run of the same command.  */
    if (cmd->outbuf) {
        outfd = cmd->outfd;
        VIR_FREE(*cmd->outbuf);
        *cmd->outbuf = g_new0(char, 1);
    }
    if (cmd->errbuf) {
        errfd = cmd->errfd;
        VIR_FREE(*cmd->errbuf);
        *cmd->errbuf = g_new0(char, 1);
    }

    fds = g_new0(struct pollfd, 3 + virCommandGetNumSendBuffers(cmd));

    for (;;) {
        size_t i;
        int nfds = 0;

        if (cmd->inpipe != -1) {
            fds[nfds].fd = cmd->inpipe;
            fds[nfds].events = POLLOUT;
            fds[nfds].revents = 0;
            nfds++;
        }
        if (outfd != -1) {
            fds[nfds].fd = outfd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }
        if (errfd != -1) {
            fds[nfds].fd = errfd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }

        nfds += virCommandSendBuffersFillPollfd(cmd, fds, nfds);

        if (nfds == 0)
            break;

        if (poll(fds, nfds, -1) < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            virReportSystemError(errno, "%s",
                                 _("unable to poll on child"));
            goto cleanup;
        }

        for (i = 0; i < nfds; i++) {
            if (fds[i].revents & (POLLIN | POLLHUP | POLLERR) &&
                (fds[i].fd == errfd || fds[i].fd == outfd)) {
                char data[1024];
                char **buf;
                size_t *len;
                int done;
                if (fds[i].fd == outfd) {
                    buf = cmd->outbuf;
                    len = &outlen;
                } else {
                    buf = cmd->errbuf;
                    len = &errlen;
                }
                done = read(fds[i].fd, data, sizeof(data));
                if (done < 0) {
                    if (errno != EINTR &&
                        errno != EAGAIN) {
                        virReportSystemError(errno, "%s",
                                             (fds[i].fd == outfd) ?
                                             _("unable to read child stdout") :
                                             _("unable to read child stderr"));
                        goto cleanup;
                    }
                } else if (done == 0) {
                    if (fds[i].fd == outfd)
                        outfd = -1;
                    else
                        errfd = -1;
                } else {
                    VIR_REALLOC_N(*buf, *len + done + 1);
                    memcpy(*buf + *len, data, done);
                    *len += done;
                }
            }

            if (fds[i].revents & (POLLOUT | POLLHUP | POLLERR) &&
                fds[i].fd == cmd->inpipe) {
                int done;

                done = write(cmd->inpipe, cmd->inbuf + inoff, /* sc_avoid_write */
                             inlen - inoff);
                if (done < 0) {
                    if (errno == EPIPE) {
                        VIR_DEBUG("child closed stdin early, ignoring EPIPE "
                                  "on fd %d", cmd->inpipe);
                        VIR_FORCE_CLOSE(cmd->inpipe);
                    } else if (errno != EINTR && errno != EAGAIN) {
                        virReportSystemError(errno, "%s",
                                             _("unable to write to child input"));
                        goto cleanup;
                    }
                } else {
                    inoff += done;
                    if (inoff == inlen)
                        VIR_FORCE_CLOSE(cmd->inpipe);
                }
            } else if (fds[i].revents & (POLLOUT | POLLHUP | POLLERR)) {
                if (virCommandSendBuffersHandlePoll(cmd, &fds[i]) < 0)
                    goto cleanup;
            }
        }
    }

    ret = 0;
 cleanup:
    if (cmd->outbuf && *cmd->outbuf)
        (*cmd->outbuf)[outlen] = '\0';
    if (cmd->errbuf && *cmd->errbuf)
        (*cmd->errbuf)[errlen] = '\0';
    return ret;
}

/**
 * virCommandExec:
 * @cmd: command to run
 * @groups: array of supplementary group IDs used for the command
 * @ngroups: number of group IDs in @groups
 *
 * Exec the command, replacing the current process. Meant to be called
 * in the hook after already forking / cloning, so does not attempt to
 * daemonize or preserve any FDs.
 *
 * Returns -1 on any error executing the command.
 * Will not return on success.
 */
int virCommandExec(virCommand *cmd, gid_t *groups, int ngroups)
{
    if (virCommandHasError(cmd)) {
        virCommandRaiseError(cmd);
        return -1;
    }

    if (virExecCommon(cmd, groups, ngroups) < 0)
        return -1;

    execve(cmd->args[0], cmd->args, cmd->env);

    virReportSystemError(errno,
                         _("cannot execute binary %1$s"),
                         cmd->args[0]);
    return -1;
}


/**
 * virCommandRun:
 * @cmd: command to run
 * @exitstatus: optional status collection
 *
 * Run the command and wait for completion.
 * Returns -1 on any error executing the
 * command. Returns 0 if the command executed,
 * with the exit status set.  If @exitstatus is NULL, then the
 * child must exit with status 0 for this to succeed.  By default,
 * a non-NULL @exitstatus contains the normal exit status of the child
 * (death from a signal is treated as execution error); but if
 * virCommandRawStatus() was used, it instead contains the raw exit
 * status that the caller must then decipher using WIFEXITED() and friends.
 */
int
virCommandRun(virCommand *cmd, int *exitstatus)
{
    int ret = 0;
    char *outbuf = NULL;
    char *errbuf = NULL;
    struct stat st;
    bool string_io;
    bool async_io = false;
    char *str;
    int tmpfd;

    if (virCommandHasError(cmd)) {
        virCommandRaiseError(cmd);
        return -1;
    }

    /* Avoid deadlock, by requiring that any open fd not under our
     * control must be visiting a regular file, or that we are
     * daemonized and no string io is required.  */
    string_io = cmd->inbuf || cmd->outbuf || cmd->errbuf;
    if (cmd->infd != -1 &&
        (fstat(cmd->infd, &st) < 0 || !S_ISREG(st.st_mode)))
        async_io = true;
    if (cmd->outfdptr && cmd->outfdptr != &cmd->outfd &&
        (*cmd->outfdptr == -1 ||
         fstat(*cmd->outfdptr, &st) < 0 || !S_ISREG(st.st_mode)))
        async_io = true;
    if (cmd->errfdptr && cmd->errfdptr != &cmd->errfd &&
        (*cmd->errfdptr == -1 ||
         fstat(*cmd->errfdptr, &st) < 0 || !S_ISREG(st.st_mode)))
        async_io = true;
    if (async_io) {
        if (!(cmd->flags & VIR_EXEC_DAEMON) || string_io) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot mix caller fds with blocking execution"));
            return -1;
        }
    } else {
        if ((cmd->flags & VIR_EXEC_DAEMON) && string_io) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot mix string I/O with daemon"));
            return -1;
        }
    }

    /* If caller requested the same string for stdout and stderr, then
     * merge those into one string.  */
    if (cmd->outbuf && cmd->outbuf == cmd->errbuf) {
        cmd->errfdptr = &cmd->outfd;
        cmd->errbuf = NULL;
    }

    /* If caller hasn't requested capture of stdout/err, then capture
     * it ourselves so we can log it.  But the intermediate child for
     * a daemon has no expected output, and we don't want our
     * capturing pipes passed on to the daemon grandchild.
     */
    if (!(cmd->flags & VIR_EXEC_DAEMON)) {
        if (!cmd->outfdptr) {
            cmd->outfdptr = &cmd->outfd;
            cmd->outbuf = &outbuf;
            string_io = true;
        }
        if (!cmd->errfdptr) {
            cmd->errfdptr = &cmd->errfd;
            cmd->errbuf = &errbuf;
            string_io = true;
        }
    }

    cmd->flags |= VIR_EXEC_RUN_SYNC;
    if (virCommandRunAsync(cmd, NULL) < 0) {
        cmd->has_error = -1;
        return -1;
    }

    if (string_io) {
        VIR_FORCE_CLOSE(cmd->infd);
        ret = virCommandProcessIO(cmd);
    }

    if (virCommandWait(cmd, exitstatus) < 0)
        ret = -1;

    str = (exitstatus ? virProcessTranslateStatus(*exitstatus)
           : (char *) "status 0");
    VIR_DEBUG("Result %s, stdout: '%s' stderr: '%s'",
              NULLSTR(str),
              cmd->outbuf ? NULLSTR(*cmd->outbuf) : "(null)",
              cmd->errbuf ? NULLSTR(*cmd->errbuf) : "(null)");
    if (exitstatus)
        VIR_FREE(str);

    /* Reset any capturing, in case caller runs
     * this identical command again */
    VIR_FORCE_CLOSE(cmd->inpipe);
    if (cmd->outbuf == &outbuf) {
        tmpfd = cmd->outfd;
        if (VIR_CLOSE(cmd->outfd) < 0)
            VIR_DEBUG("ignoring failed close on fd %d", tmpfd);
        cmd->outfdptr = NULL;
        cmd->outbuf = NULL;
        VIR_FREE(outbuf);
    }
    if (cmd->errbuf == &errbuf) {
        tmpfd = cmd->errfd;
        if (VIR_CLOSE(cmd->errfd) < 0)
            VIR_DEBUG("ignoring failed close on fd %d", tmpfd);
        cmd->errfdptr = NULL;
        cmd->errbuf = NULL;
        VIR_FREE(errbuf);
    }

    return ret;
}


static void
virCommandDoAsyncIOHelper(void *opaque)
{
    virCommand *cmd = opaque;
    if (virCommandProcessIO(cmd) < 0) {
        /* If something went wrong, save errno or -1 */
        cmd->has_error = errno ? errno : -1;
    }
}


/**
 * virCommandRunAsync:
 * @cmd: command to start
 * @pid: optional variable to track child pid
 *
 * Run the command asynchronously
 * Returns -1 on any error executing the
 * command. Returns 0 if the command executed.
 *
 * There are two approaches to child process cleanup.
 * 1. Use auto-cleanup, by passing NULL for pid.  The child will be
 * auto-reaped by virCommandFree, unless you reap it earlier via
 * virCommandWait or virCommandAbort.  Good for where cmd is in
 * scope for the duration of the child process.
 * 2. Use manual cleanup, by passing the address of a pid_t variable
 * for pid.  While cmd is still in scope, you may reap the child via
 * virCommandWait or virCommandAbort.  But after virCommandFree, if
 * you have not yet reaped the child, then it continues to run until
 * you call virProcessWait or virProcessAbort.
 */
int
virCommandRunAsync(virCommand *cmd, pid_t *pid)
{
    int ret = -1;
    g_autofree char *str = NULL;
    size_t i;
    bool synchronous = false;
    int infd[2] = {-1, -1};

    if (virCommandHasError(cmd)) {
        virCommandRaiseError(cmd);
        return -1;
    }

    synchronous = cmd->flags & VIR_EXEC_RUN_SYNC;
    cmd->flags &= ~VIR_EXEC_RUN_SYNC;

    /* Buffer management can only be requested via virCommandRun or
     * virCommandDoAsyncIO. */
    if (cmd->inbuf && cmd->infd == -1 &&
        (synchronous || cmd->flags & VIR_EXEC_ASYNC_IO)) {
        if (virPipe(infd) < 0) {
            cmd->has_error = -1;
            return -1;
        }
        cmd->infd = infd[0];
        cmd->inpipe = infd[1];

        if (fcntl(cmd->inpipe, F_SETFL, O_NONBLOCK) < 0) {
            virReportSystemError(errno, "%s",
                                 _("fcntl failed to set O_NONBLOCK"));
            cmd->has_error = -1;
            ret = -1;
            goto cleanup;
        }
    } else if ((cmd->inbuf && cmd->infd == -1) ||
               (cmd->outbuf && cmd->outfdptr != &cmd->outfd) ||
               (cmd->errbuf && cmd->errfdptr != &cmd->errfd)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot mix string I/O with asynchronous command"));
        return -1;
    }

    if (cmd->pid != -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("command is already running as pid %1$lld"),
                       (long long) cmd->pid);
        goto cleanup;
    }

    if (!synchronous && (cmd->flags & VIR_EXEC_DAEMON)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("daemonized command cannot use virCommandRunAsync"));
        goto cleanup;
    }
    if (cmd->pwd && (cmd->flags & VIR_EXEC_DAEMON)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("daemonized command cannot set working directory %1$s"),
                       cmd->pwd);
        goto cleanup;
    }
    if (cmd->pidfile && !(cmd->flags & VIR_EXEC_DAEMON)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("creation of pid file requires daemonized command"));
        goto cleanup;
    }

    if (dryRunBuffer || dryRunCallback) {
        g_autofree char *cmdstr = NULL;
        dryRunStatus = EXIT_SUCCESS;

        if (!(cmdstr = virCommandToStringFull(cmd, dryRunBufferArgLinebreaks,
                                              dryRunBufferCommandStripPath)))
            goto cleanup;

        if (dryRunBuffer) {
            VIR_DEBUG("Dry run requested, appending stringified "
                      "command to dryRunBuffer=%p", dryRunBuffer);
            virBufferAdd(dryRunBuffer, cmdstr, -1);
            virBufferAddChar(dryRunBuffer, '\n');
        }
        if (dryRunCallback) {
            dryRunCallback((const char *const*)cmd->args,
                           (const char *const*)cmd->env,
                           cmd->inbuf, cmd->outbuf, cmd->errbuf,
                           &dryRunStatus, dryRunOpaque);
        }
        ret = 0;
        goto cleanup;
    }

    str = virCommandToString(cmd, false);
    VIR_DEBUG("About to run %s", str ? str : cmd->args[0]);
    ret = virExec(cmd);
    VIR_DEBUG("Command result %d, with PID %d",
              ret, (int)cmd->pid);

    for (i = 0; i < cmd->npassfd; i++) {
        if (cmd->passfd[i].flags & VIR_COMMAND_PASS_FD_CLOSE_PARENT)
            VIR_FORCE_CLOSE(cmd->passfd[i].fd);
    }
    cmd->npassfd = 0;
    VIR_FREE(cmd->passfd);

    if (ret == 0 && pid)
        *pid = cmd->pid;
    else
        cmd->reap = true;

    if (ret == 0 && cmd->flags & VIR_EXEC_ASYNC_IO) {
        if (cmd->inbuf)
            VIR_FORCE_CLOSE(cmd->infd);
        /* clear any error so we can catch if the helper thread reports one */
        cmd->has_error = 0;
        cmd->asyncioThread = g_new0(virThread, 1);

        if (virThreadCreateFull(cmd->asyncioThread, true,
                                virCommandDoAsyncIOHelper,
                                "cmd-async-io", false, cmd) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to create thread to process command's IO"));
            VIR_FREE(cmd->asyncioThread);
            virCommandAbort(cmd);
            ret = -1;
        }
    }

 cleanup:
    if (ret < 0) {
        VIR_FORCE_CLOSE(cmd->infd);
        VIR_FORCE_CLOSE(cmd->inpipe);
    }
    return ret;
}


/**
 * virCommandWait:
 * @cmd: command to wait on
 * @exitstatus: optional status collection
 *
 * Wait for the command previously started with virCommandRunAsync()
 * to complete. Return -1 on any error waiting for
 * completion. Returns 0 if the command
 * finished with the exit status set.  If @exitstatus is NULL, then the
 * child must exit with status 0 for this to succeed.  By default,
 * a non-NULL @exitstatus contains the normal exit status of the child
 * (death from a signal is treated as execution error); but if
 * virCommandRawStatus() was used, it instead contains the raw exit
 * status that the caller must then decipher using WIFEXITED() and friends.
 */
int
virCommandWait(virCommand *cmd, int *exitstatus)
{
    int ret;
    int status = 0;

    if (virCommandHasError(cmd)) {
        virCommandRaiseError(cmd);
        return -1;
    }

    if (dryRunBuffer || dryRunCallback) {
        VIR_DEBUG("Dry run requested, returning status %d",
                  dryRunStatus);
        if (exitstatus)
            *exitstatus = dryRunStatus;
        else if (dryRunStatus)
            return -1;
        return 0;
    }

    if (cmd->pid == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("command is not yet running"));
        return -1;
    }

    /* If virProcessWait reaps pid but then returns failure because
     * exitstatus was NULL, then a second virCommandWait would risk
     * calling waitpid on an unrelated process.  Besides, that error
     * message is not as detailed as what we can provide.  So, we
     * guarantee that virProcessWait only fails due to failure to wait,
     * and repeat the exitstatus check code ourselves.  */
    ret = virProcessWait(cmd->pid, &status, true);
    if (cmd->flags & VIR_EXEC_ASYNC_IO) {
        cmd->flags &= ~VIR_EXEC_ASYNC_IO;
        virThreadJoin(cmd->asyncioThread);
        VIR_FREE(cmd->asyncioThread);
        VIR_FORCE_CLOSE(cmd->inpipe);
        if (cmd->has_error) {
            const char *msg = _("Error while processing command's IO");
            if (cmd->has_error < 0)
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s", msg);
            else
                virReportSystemError(cmd->has_error, "%s", msg);
            ret = -1;
        }
    }
    if (ret == 0) {
        cmd->pid = -1;
        cmd->reap = false;
        if (exitstatus && (cmd->rawStatus || WIFEXITED(status))) {
            *exitstatus = cmd->rawStatus ? status : WEXITSTATUS(status);
        } else if (status) {
            g_autofree char *str = virCommandToString(cmd, false);
            g_autofree char *st = virProcessTranslateStatus(status);
            bool haveErrMsg = cmd->errbuf && *cmd->errbuf && (*cmd->errbuf)[0];

            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Child process (%1$s) unexpected %2$s%3$s%4$s"),
                           str ? str : cmd->args[0], NULLSTR(st),
                           haveErrMsg ? ": " : "",
                           haveErrMsg ? *cmd->errbuf : "");
            return -1;
        }
    }

    return ret;
}


/**
 * virCommandAbort:
 * @cmd: command to abort
 *
 * Abort an async command if it is running, without issuing
 * any errors or affecting errno.  Designed for error paths
 * where some but not all paths to the cleanup code might
 * have started the child process.
 */
void
virCommandAbort(virCommand *cmd)
{
    if (!cmd || cmd->pid == -1)
        return;
    virProcessAbort(cmd->pid);
    cmd->pid = -1;
    cmd->reap = false;
}


/**
 * virCommandRequireHandshake:
 * @cmd: command to modify
 *
 * Request that the child perform a handshake with
 * the parent when the hook function has completed
 * execution. The child will not exec() until the
 * parent has notified
 */
void virCommandRequireHandshake(virCommand *cmd)
{
    if (virCommandHasError(cmd))
        return;

    if (cmd->handshake) {
        cmd->has_error = -1;
        VIR_DEBUG("Cannot require handshake twice");
        return;
    }

    if (virPipeQuiet(cmd->handshakeWait) < 0) {
        cmd->has_error = errno;
        return;
    }
    if (virPipeQuiet(cmd->handshakeNotify) < 0) {
        VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
        VIR_FORCE_CLOSE(cmd->handshakeWait[1]);
        cmd->has_error = errno;
        return;
    }

    VIR_DEBUG("Transfer handshake wait=%d notify=%d, "
              "keep handshake wait=%d notify=%d",
              cmd->handshakeWait[1], cmd->handshakeNotify[0],
              cmd->handshakeWait[0], cmd->handshakeNotify[1]);
    virCommandPassFD(cmd, cmd->handshakeWait[1],
                     VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    virCommandPassFD(cmd, cmd->handshakeNotify[0],
                     VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    cmd->handshake = true;
}

/**
 * virCommandHandshakeWait:
 * @cmd: command to wait on
 *
 * Wait for the child to complete execution of its
 * hook function.  To be called in the parent.
 */
int virCommandHandshakeWait(virCommand *cmd)
{
    char c;
    int rv;

    if (virCommandHasError(cmd)) {
        virCommandRaiseError(cmd);
        return -1;
    }

    if (!cmd->handshake) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid use of command API"));
        return -1;
    }

    if (cmd->handshakeWait[0] == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Handshake is already complete"));
        return -1;
    }

    VIR_DEBUG("Wait for handshake on %d", cmd->handshakeWait[0]);
    if ((rv = saferead(cmd->handshakeWait[0], &c, sizeof(c))) != sizeof(c)) {
        if (rv < 0)
            virReportSystemError(errno, "%s",
                                 _("Unable to wait for child process"));
        else
            virReportSystemError(EIO, "%s",
                                 _("Child quit during startup handshake"));
        VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
        return -1;
    }
    if (c != '1') {
        g_autofree char *msg = NULL;
        ssize_t len;
        msg = g_new0(char, 1024);
        /* Close the handshakeNotify fd before trying to read anything
         * further on the handshakeWait pipe; so that a child waiting
         * on our acknowledgment will die rather than deadlock.  */
        VIR_FORCE_CLOSE(cmd->handshakeNotify[1]);

        if ((len = saferead(cmd->handshakeWait[0], msg, 1024)) < 0) {
            VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
            virReportSystemError(errno, "%s",
                                 _("No error message from child failure"));
            return -1;
        }
        VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
        msg[len-1] = '\0';
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", msg);
        return -1;
    }
    VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
    return 0;
}

/**
 * virCommandHandshakeNotify:
 * @cmd: command to resume
 *
 * Notify the child that it is OK to exec() the
 * real binary now.  To be called in the parent.
 */
int virCommandHandshakeNotify(virCommand *cmd)
{
    char c = '1';

    if (virCommandHasError(cmd)) {
        virCommandRaiseError(cmd);
        return -1;
    }

    if (!cmd->handshake) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid use of command API"));
        return -1;
    }

    if (cmd->handshakeNotify[1] == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Handshake is already complete"));
        return -1;
    }

    VIR_DEBUG("Notify handshake on %d", cmd->handshakeNotify[1]);
    if (safewrite(cmd->handshakeNotify[1], &c, sizeof(c)) != sizeof(c)) {
        virReportSystemError(errno, "%s", _("Unable to notify child process"));
        VIR_FORCE_CLOSE(cmd->handshakeNotify[1]);
        return -1;
    }
    VIR_FORCE_CLOSE(cmd->handshakeNotify[1]);
    return 0;
}
#else /* WIN32 */
int
virCommandSetSendBuffer(virCommand *cmd,
                        unsigned char **buffer G_GNUC_UNUSED,
                        size_t buflen G_GNUC_UNUSED)
{
    if (virCommandHasError(cmd))
        return -1;

    cmd->has_error = ENOTSUP;

    return -1;
}


int
virCommandExec(virCommand *cmd G_GNUC_UNUSED, gid_t *groups G_GNUC_UNUSED,
               int ngroups G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Executing new processes is not supported on Win32 platform"));
    return -1;
}


int
virCommandRun(virCommand *cmd G_GNUC_UNUSED, int *exitstatus G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Executing new processes is not supported on Win32 platform"));
    return -1;
}


int
virCommandRunAsync(virCommand *cmd G_GNUC_UNUSED, pid_t *pid G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Executing new processes is not supported on Win32 platform"));
    return -1;
}


int
virCommandWait(virCommand *cmd G_GNUC_UNUSED, int *exitstatus G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Executing new processes is not supported on Win32 platform"));
    return -1;
}


void
virCommandAbort(virCommand *cmd G_GNUC_UNUSED)
{
    /* Mingw lacks WNOHANG and kill().  But since we haven't ported
     * virExec to mingw yet, there's no process to be killed,
     * making this implementation trivially correct for now :)  */
}


void virCommandRequireHandshake(virCommand *cmd)
{
    if (virCommandHasError(cmd))
        return;

    cmd->has_error = ENOSYS;
}


int virCommandHandshakeWait(virCommand *cmd G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Executing new processes is not supported on Win32 platform"));
    return -1;
}


int virCommandHandshakeNotify(virCommand *cmd G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Executing new processes is not supported on Win32 platform"));
    return -1;
}
#endif /* WIN32 */


/**
 * virCommandFree:
 * @cmd: optional command to free
 *
 * Release all resources.  The only exception is that if you called
 * virCommandRunAsync with a non-null pid, then the asynchronous child
 * is not reaped, and you must call virProcessWait() or virProcessAbort() yourself.
 */
void
virCommandFree(virCommand *cmd)
{
    size_t i;
    if (!cmd)
        return;

    for (i = 0; i < cmd->npassfd; i++) {
        if (cmd->passfd[i].flags & VIR_COMMAND_PASS_FD_CLOSE_PARENT)
            VIR_FORCE_CLOSE(cmd->passfd[i].fd);
    }
    cmd->npassfd = 0;
    g_free(cmd->passfd);

    if (cmd->asyncioThread) {
        virThreadJoin(cmd->asyncioThread);
        g_free(cmd->asyncioThread);
    }
    g_free(cmd->inbuf);
    VIR_FORCE_CLOSE(cmd->outfd);
    VIR_FORCE_CLOSE(cmd->errfd);

    g_free(cmd->binaryPath);

    for (i = 0; i < cmd->nargs; i++)
        g_free(cmd->args[i]);
    g_free(cmd->args);

    for (i = 0; i < cmd->nenv; i++)
        g_free(cmd->env[i]);
    g_free(cmd->env);

    g_free(cmd->pwd);

    if (cmd->handshake) {
        /* The other 2 fds in these arrays are closed
         * due to use with virCommandPassFD
         */
        VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
        VIR_FORCE_CLOSE(cmd->handshakeNotify[1]);
    }

    g_free(cmd->pidfile);

    if (cmd->reap)
        virCommandAbort(cmd);

#if defined(WITH_SECDRIVER_SELINUX)
    g_free(cmd->seLinuxLabel);
#endif
#if defined(WITH_SECDRIVER_APPARMOR)
    g_free(cmd->appArmorProfile);
#endif

    virCommandFreeSendBuffers(cmd);

    g_free(cmd);
}

/**
 * virCommandDoAsyncIO:
 * @cmd: command to do async IO on
 *
 * This requests asynchronous string IO on @cmd. It is useful in
 * combination with virCommandRunAsync():
 *
 *      g_autoptr(virCommand) cmd = virCommandNew*(...);
 *      g_autofree char *buf = NULL;
 *
 *      ...
 *
 *      virCommandSetOutputBuffer(cmd, &buf);
 *      virCommandDoAsyncIO(cmd);
 *
 *      if (virCommandRunAsync(cmd, NULL) < 0)
 *          return;
 *
 *      ...
 *
 *      if (virCommandWait(cmd, NULL) < 0)
 *          return;
 *
 *      // @buf now contains @cmd's stdout
 *      VIR_DEBUG("STDOUT: %s", NULLSTR(buf));
 *
 *      ...
 *
 * Since current implementation uses strlen to determine length
 * of data to be written to @cmd's stdin, don't pass any binary
 * data. If you want to re-run command, you need to call this and
 * buffer setting functions (virCommandSet.*Buffer) prior each run.
 */
void
virCommandDoAsyncIO(virCommand *cmd)
{
    if (virCommandHasError(cmd))
        return;

    cmd->flags |= VIR_EXEC_ASYNC_IO | VIR_EXEC_NONBLOCK;
}


struct _virCommandDryRunToken {
    int dummy;
};


/**
 * virCommandDryRunTokenNew:
 *
 * Returns a token which is used with virCommandSetDryRun. Freeing the token
 * with the appropriate automatic cleanup function ensures that the dry run
 * environment is reset.
 */
virCommandDryRunToken *
virCommandDryRunTokenNew(void)
{
    return g_new0(virCommandDryRunToken, 1);
}


/**
 * virCommandDryRunTokenFree:
 *
 * Helper to free a virCommandDryRunToken. Do not use this function directly,
 * always declare virCommandDryRunToken as a g_autoptr.
 */
void
virCommandDryRunTokenFree(virCommandDryRunToken *tok)
{
    dryRunBuffer = NULL;
    dryRunBufferArgLinebreaks = false;
    dryRunBufferCommandStripPath = false;
    dryRunCallback = NULL;
    dryRunOpaque = NULL;
    g_free(tok);
}


/**
 * virCommandSetDryRun:
 * @tok: a virCommandDryRunToken obtained from virCommandDryRunTokenNew
 * @buf: buffer to store stringified commands
 * @bufArgLinebreaks: add linebreaks after command and every argument or argument pair
 * @bufCommandStripPath: strip leading paths of command
 * @callback: callback to process input/output/args
 *
 * Sometimes it's desired to not actually run given command, but
 * see its string representation without having to change the
 * callee. Unit testing serves as a great example. In such cases,
 * the callee constructs the command and calls it via
 * virCommandRun* API. The virCommandSetDryRun allows you to
 * modify this behavior: once called, every call to
 * virCommandRun* results in command string representation being
 * appended to @buf instead of being executed. If @callback is
 * provided, then it is invoked with the argv, env and stdin
 * data string for the command. It is expected to fill the stdout
 * and stderr data strings and exit status variables.
 *
 * The strings stored in @buf are escaped for a shell and
 * separated by a newline. For example:
 *
 * virBuffer buffer = VIR_BUFFER_INITIALIZER;
 * virCommandSetDryRun(&buffer);
 *
 * virCommand *echocmd = virCommandNewArgList("/bin/echo", "Hello world", NULL);
 * virCommandRun(echocmd, NULL);
 *
 * After this, the @buffer should contain:
 *
 * /bin/echo 'Hello world'\n
 *
 * To cancel this effect pass NULL for @buf and @callback.
 */
void
virCommandSetDryRun(virCommandDryRunToken *tok,
                    virBuffer *buf,
                    bool bufArgLinebreaks,
                    bool bufCommandStripPath,
                    virCommandDryRunCallback cb,
                    void *opaque)
{
    if (!tok)
        abort();

    dryRunBuffer = buf;
    dryRunBufferArgLinebreaks = bufArgLinebreaks;
    dryRunBufferCommandStripPath = bufCommandStripPath;
    dryRunCallback = cb;
    dryRunOpaque = opaque;
}

#ifndef WIN32
/**
 * virCommandRunRegex:
 * @cmd: command to run
 * @nregex: number of regexes to apply
 * @regex: array of regexes to apply
 * @nvars: array of numbers of variables each regex will produce
 * @func: callback function that is called for every line of output,
 * needs to return 0 on success
 * @data: additional data that will be passed to the callback function
 * @prefix: prefix that will be skipped at the beginning of each line
 * @exitstatus: allows the caller to handle command run exit failures
 *
 * Run an external program.
 *
 * Read its output and apply a series of regexes to each line
 * When the entire set of regexes has matched consecutively
 * then run a callback passing in all the matches on the current line.
 *
 * Returns: 0 on success, -1 on memory allocation error, virCommandRun
 * error or callback function error
 */
int
virCommandRunRegex(virCommand *cmd,
                   int nregex,
                   const char **regex,
                   int *nvars,
                   virCommandRunRegexFunc func,
                   void *data,
                   const char *prefix,
                   int *exitstatus)
{
    GRegex **reg = NULL;
    size_t i, j, k;
    int totgroups = 0, ngroup = 0;
    char **groups;
    g_autofree char *outbuf = NULL;
    g_auto(GStrv) lines = NULL;
    int ret = -1;

    /* Compile all regular expressions */
    reg = g_new0(GRegex *, nregex);

    for (i = 0; i < nregex; i++) {
        g_autoptr(GError) err = NULL;
        reg[i] = g_regex_new(regex[i], G_REGEX_OPTIMIZE, 0, &err);
        if (!reg[i]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to compile regex %1$s"), err->message);
            for (j = 0; j < i; j++)
                g_regex_unref(reg[j]);
            VIR_FREE(reg);
            return -1;
        }

        totgroups += nvars[i];
    }

    /* Storage for matched variables */
    groups = g_new0(char *, totgroups);

    virCommandSetOutputBuffer(cmd, &outbuf);
    if (virCommandRun(cmd, exitstatus) < 0)
        goto cleanup;

    if (!outbuf) {
        /* no output */
        ret = 0;
        goto cleanup;
    }

    if (!(lines = g_strsplit(outbuf, "\n", 0)))
        goto cleanup;

    for (k = 0; lines[k]; k++) {
        g_autoptr(GMatchInfo) info = NULL;
        const char *p = NULL;

        /* ignore any command prefix */
        if (prefix)
            p = STRSKIP(lines[k], prefix);
        if (!p)
            p = lines[k];

        ngroup = 0;
        for (i = 0; i < nregex; i++) {
            if (!(g_regex_match(reg[i], p, 0, &info)))
                break;

            /* NB match #0 is the full pattern, so we offset j by 1 */
            for (j = 1; j <= nvars[i]; j++)
                groups[ngroup++] = g_match_info_fetch(info, j);
        }
        /* We've matched on the last regex, so callback time */
        if (i == nregex) {
            if (((*func)(groups, data)) < 0)
                goto cleanup;
        }

        for (j = 0; j < ngroup; j++)
            VIR_FREE(groups[j]);
    }

    ret = 0;
 cleanup:
    if (groups) {
        for (j = 0; j < totgroups; j++)
            VIR_FREE(groups[j]);
        VIR_FREE(groups);
    }

    for (i = 0; i < nregex; i++)
        g_regex_unref(reg[i]);

    VIR_FREE(reg);
    return ret;
}

/*
 * Run an external program and read from its standard output
 * a stream of tokens from IN_STREAM, applying FUNC to
 * each successive sequence of N_COLUMNS tokens.
 * If FUNC returns < 0, stop processing input and return -1.
 * Return -1 if N_COLUMNS == 0.
 * Return -1 upon memory allocation error.
 * If the number of input tokens is not a multiple of N_COLUMNS,
 * then the final FUNC call will specify a number smaller than N_COLUMNS.
 * If there are no input tokens (empty input), call FUNC with N_COLUMNS == 0.
 */
int
virCommandRunNul(virCommand *cmd,
                 size_t n_columns,
                 virCommandRunNulFunc func,
                 void *data)
{
    size_t n_tok = 0;
    int fd = -1;
    FILE *fp = NULL;
    char **v;
    int ret = -1;
    size_t i;

    if (n_columns == 0)
        return -1;

    v = g_new0(char *, n_columns);
    for (i = 0; i < n_columns; i++)
        v[i] = NULL;

    virCommandSetOutputFD(cmd, &fd);
    if (virCommandRunAsync(cmd, NULL) < 0)
        goto cleanup;

    if ((fp = VIR_FDOPEN(fd, "r")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot open file using fd"));
        goto cleanup;
    }

    while (1) {
        char *buf = NULL;
        size_t buf_len = 0;
        /* Be careful: even when it returns -1,
           this use of getdelim allocates memory.  */
        ssize_t tok_len = getdelim(&buf, &buf_len, 0, fp);
        v[n_tok] = buf;
        if (tok_len < 0) {
            /* Maybe EOF, maybe an error.
               If n_tok > 0, then we know it's an error.  */
            if (n_tok && func(n_tok, v, data) < 0)
                goto cleanup;
            break;
        }
        ++n_tok;
        if (n_tok == n_columns) {
            if (func(n_tok, v, data) < 0)
                goto cleanup;
            n_tok = 0;
            for (i = 0; i < n_columns; i++)
                VIR_FREE(v[i]);
        }
    }

    if (feof(fp) < 0) {
        virReportSystemError(errno, "%s",
                             _("read error on pipe"));
        goto cleanup;
    }

    ret = virCommandWait(cmd, NULL);
 cleanup:
    for (i = 0; i < n_columns; i++)
        VIR_FREE(v[i]);
    VIR_FREE(v);

    VIR_FORCE_FCLOSE(fp);
    VIR_FORCE_CLOSE(fd);

    return ret;
}

#else /* WIN32 */

int
virCommandRunRegex(virCommand *cmd G_GNUC_UNUSED,
                   int nregex G_GNUC_UNUSED,
                   const char **regex G_GNUC_UNUSED,
                   int *nvars G_GNUC_UNUSED,
                   virCommandRunRegexFunc func G_GNUC_UNUSED,
                   void *data G_GNUC_UNUSED,
                   const char *prefix G_GNUC_UNUSED,
                   int *exitstatus G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("%1$s not implemented on Win32"), __FUNCTION__);
    return -1;
}

int
virCommandRunNul(virCommand *cmd G_GNUC_UNUSED,
                 size_t n_columns G_GNUC_UNUSED,
                 virCommandRunNulFunc func G_GNUC_UNUSED,
                 void *data G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("%1$s not implemented on Win32"), __FUNCTION__);
    return -1;
}
#endif /* WIN32 */

/**
 * virCommandSetRunAlone:
 *
 * Create new trusted group when running the command. In other words, the
 * process won't be scheduled to run on a core among with processes from
 * another, untrusted group.
 */
void
virCommandSetRunAlone(virCommand *cmd)
{
    if (virCommandHasError(cmd))
        return;

    cmd->schedCore = -1;
}

/**
 * virCommandSetRunAmong:
 * @pid: pid from a trusted group
 *
 * When spawning the command place it into the trusted group of @pid so that
 * these two processes can run on Hyper Threads of a single core at the same
 * time.
 */
void
virCommandSetRunAmong(virCommand *cmd,
                      pid_t pid)
{
    if (virCommandHasError(cmd))
        return;

    if (pid <= 0) {
        VIR_DEBUG("invalid pid value: %lld", (long long) pid);
        cmd->has_error = -1;
        return;
    }

    cmd->schedCore = pid;
}

void
virCommandPeekSendBuffers(virCommand *cmd,
                          virCommandSendBuffer **buffers,
                          int *nbuffers)
{
    *buffers = cmd->sendBuffers;
    *nbuffers = cmd->numSendBuffers;
}
