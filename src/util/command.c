/*
 * command.c: Child command execution
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

#if HAVE_CAPNG
# include <cap-ng.h>
#endif

#include "command.h"
#include "memory.h"
#include "virterror_internal.h"
#include "util.h"
#include "logging.h"
#include "virfile.h"
#include "virpidfile.h"
#include "buf.h"
#include "ignore-value.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define virCommandError(code, ...)                                      \
    virReportErrorHelper(VIR_FROM_NONE, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

/* Flags for virExecWithHook */
enum {
    VIR_EXEC_NONE   = 0,
    VIR_EXEC_NONBLOCK = (1 << 0),
    VIR_EXEC_DAEMON = (1 << 1),
    VIR_EXEC_CLEAR_CAPS = (1 << 2),
    VIR_EXEC_RUN_SYNC = (1 << 3),
};

struct _virCommand {
    int has_error; /* ENOMEM on allocation failure, -1 for anything else.  */

    char **args;
    size_t nargs;
    size_t maxargs;

    char **env;
    size_t nenv;
    size_t maxenv;

    char *pwd;

    int *preserve; /* FDs to pass to child. */
    int preserve_size;
    int *transfer; /* FDs to close in parent. */
    int transfer_size;

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

    bool handshake;
    int handshakeWait[2];
    int handshakeNotify[2];

    virExecHook hook;
    void *opaque;

    pid_t pid;
    char *pidfile;
    bool reap;

    unsigned long long capabilities;
};

/*
 * virCommandFDIsSet:
 * @fd: FD to test
 * @set: the set
 * @set_size: actual size of @set
 *
 * Check if FD is already in @set or not.
 *
 * Returns true if @set contains @fd,
 * false otherwise.
 */
static bool
virCommandFDIsSet(int fd,
                  const int *set,
                  int set_size)
{
    int i = 0;

    while (i < set_size)
        if (set[i++] == fd)
            return true;

    return false;
}

/*
 * virCommandFDSet:
 * @fd: FD to be put into @set
 * @set: the set
 * @set_size: actual size of @set
 *
 * This is practically generalized implementation
 * of FD_SET() as we do not want to be limited
 * by FD_SETSIZE.
 *
 * Returns: 0 on success,
 *          -1 on usage error,
 *          ENOMEM on OOM
 */
static int
virCommandFDSet(int fd,
                int **set,
                int *set_size)
{
    if (fd < 0 || !set || !set_size)
        return -1;

    if (virCommandFDIsSet(fd, *set, *set_size))
        return 0;

    if (VIR_REALLOC_N(*set, *set_size + 1) < 0) {
        return ENOMEM;
    }

    (*set)[*set_size] = fd;
    (*set_size)++;

    return 0;
}

#ifndef WIN32

static int virClearCapabilities(void) ATTRIBUTE_UNUSED;

# if HAVE_CAPNG
static int virClearCapabilities(void)
{
    int ret;

    capng_clear(CAPNG_SELECT_BOTH);

    if ((ret = capng_apply(CAPNG_SELECT_BOTH)) < 0) {
        virCommandError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot clear process capabilities %d"), ret);
        return -1;
    }

    return 0;
}

/**
 * virSetCapabilities:
 *  @capabilities - capability flag to set.
 *                  In case of 0, this function is identical to
 *                  virClearCapabilities()
 *
 */
static int virSetCapabilities(unsigned long long capabilities)
{
    int ret, i;

    capng_clear(CAPNG_SELECT_BOTH);

    for (i = 0; i <= CAP_LAST_CAP; i++) {
        if (capabilities & (1ULL << i))
            capng_update(CAPNG_ADD, CAPNG_BOUNDING_SET, i);
    }

    if ((ret = capng_apply(CAPNG_SELECT_BOTH)) < 0) {
        virCommandError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot apply process capabilities %d"), ret);
        return -1;
    }

    return 0;
}
# else
static int virClearCapabilities(void)
{
//    VIR_WARN("libcap-ng support not compiled in, unable to clear "
//             "capabilities");
    return 0;
}

static int
virSetCapabilities(unsigned long long capabilities ATTRIBUTE_UNUSED)
{
    return 0;
}
# endif

/**
 * virFork:
 * @pid - a pointer to a pid_t that will receive the return value from
 *        fork()
 *
 * fork a new process while avoiding various race/deadlock conditions
 *
 * on return from virFork(), if *pid < 0, the fork failed and there is
 * no new process. Otherwise, just like fork(), if *pid == 0, it is the
 * child process returning, and if *pid > 0, it is the parent.
 *
 * Even if *pid >= 0, if the return value from virFork() is < 0, it
 * indicates a failure that occurred in the parent or child process
 * after the fork. In this case, the child process should call
 * _exit(EXIT_FAILURE) after doing any additional error reporting.
 */
int
virFork(pid_t *pid)
{
    sigset_t oldmask, newmask;
    struct sigaction sig_action;
    int saved_errno, ret = -1;

    *pid = -1;

    /*
     * Need to block signals now, so that child process can safely
     * kill off caller's signal handlers without a race.
     */
    sigfillset(&newmask);
    if (pthread_sigmask(SIG_SETMASK, &newmask, &oldmask) != 0) {
        saved_errno = errno;
        virReportSystemError(errno,
                             "%s", _("cannot block signals"));
        goto cleanup;
    }

    /* Ensure we hold the logging lock, to protect child processes
     * from deadlocking on another thread's inherited mutex state */
    virLogLock();

    *pid = fork();
    saved_errno = errno; /* save for caller */

    /* Unlock for both parent and child process */
    virLogUnlock();

    if (*pid < 0) {
        /* attempt to restore signal mask, but ignore failure, to
           avoid obscuring the fork failure */
        ignore_value (pthread_sigmask(SIG_SETMASK, &oldmask, NULL));
        virReportSystemError(saved_errno,
                             "%s", _("cannot fork child process"));
        goto cleanup;
    }

    if (*pid) {

        /* parent process */

        /* Restore our original signal mask now that the child is
           safely running */
        if (pthread_sigmask(SIG_SETMASK, &oldmask, NULL) != 0) {
            saved_errno = errno; /* save for caller */
            virReportSystemError(errno, "%s", _("cannot unblock signals"));
            goto cleanup;
        }
        ret = 0;

    } else {

        /* child process */

        int logprio;
        int i;

        /* Remove any error callback so errors in child now
           get sent to stderr where they stand a fighting chance
           of being seen / logged */
        virSetErrorFunc(NULL, NULL);
        virSetErrorLogPriorityFunc(NULL);

        /* Make sure any hook logging is sent to stderr, since child
         * process may close the logfile FDs */
        logprio = virLogGetDefaultPriority();
        virLogReset();
        virLogSetDefaultPriority(logprio);

        /* Clear out all signal handlers from parent so nothing
           unexpected can happen in our child once we unblock
           signals */
        sig_action.sa_handler = SIG_DFL;
        sig_action.sa_flags = 0;
        sigemptyset(&sig_action.sa_mask);

        for (i = 1; i < NSIG; i++) {
            /* Only possible errors are EFAULT or EINVAL
               The former wont happen, the latter we
               expect, so no need to check return value */

            sigaction(i, &sig_action, NULL);
        }

        /* Unmask all signals in child, since we've no idea
           what the caller's done with their signal mask
           and don't want to propagate that to children */
        sigemptyset(&newmask);
        if (pthread_sigmask(SIG_SETMASK, &newmask, NULL) != 0) {
            saved_errno = errno; /* save for caller */
            virReportSystemError(errno, "%s", _("cannot unblock signals"));
            goto cleanup;
        }
        ret = 0;
    }

cleanup:
    if (ret < 0)
        errno = saved_errno;
    return ret;
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
                             _("cannot open %s"),
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

/*
 * @argv argv to exec
 * @envp optional environment to use for exec
 * @keepfd options fd_ret to keep open for child process
 * @retpid optional pointer to store child process pid
 * @infd optional file descriptor to use as child input, otherwise /dev/null
 * @outfd optional pointer to communicate output fd behavior
 *        outfd == NULL : Use /dev/null
 *        *outfd == -1  : Use a new fd
 *        *outfd != -1  : Use *outfd
 * @errfd optional pointer to communcate error fd behavior. See outfd
 * @flags possible combination of the following:
 *        VIR_EXEC_NONE     : Default function behavior
 *        VIR_EXEC_NONBLOCK : Set child process output fd's as non-blocking
 *        VIR_EXEC_DAEMON   : Daemonize the child process
 * @hook optional virExecHook function to call prior to exec
 * @data data to pass to the hook function
 * @pidfile path to use as pidfile for daemonized process (needs DAEMON flag)
 * @capabilities capabilities to keep
 */
static int
virExecWithHook(const char *const*argv,
                const char *const*envp,
                const int *keepfd,
                int keepfd_size,
                pid_t *retpid,
                int infd, int *outfd, int *errfd,
                unsigned int flags,
                virExecHook hook,
                void *data,
                char *pidfile,
                unsigned long long capabilities)
{
    pid_t pid;
    int null = -1, i, openmax;
    int pipeout[2] = {-1,-1};
    int pipeerr[2] = {-1,-1};
    int childout = -1;
    int childerr = -1;
    int tmpfd;
    const char *binary = NULL;
    int forkRet;

    if (argv[0][0] != '/') {
        if (!(binary = virFindFileInPath(argv[0]))) {
            virReportSystemError(ENOENT,
                                 _("Cannot find '%s' in path"),
                                 argv[0]);
            return -1;
        }
    } else {
        binary = argv[0];
    }

    if (infd < 0) {
        if (getDevNull(&null) < 0)
            goto cleanup;
        infd = null;
    }

    if (outfd != NULL) {
        if (*outfd == -1) {
            if (pipe2(pipeout, O_CLOEXEC) < 0) {
                virReportSystemError(errno,
                                     "%s", _("cannot create pipe"));
                goto cleanup;
            }

            if ((flags & VIR_EXEC_NONBLOCK) &&
                virSetNonBlock(pipeout[0]) == -1) {
                virReportSystemError(errno,
                                     "%s", _("Failed to set non-blocking file descriptor flag"));
                goto cleanup;
            }

            childout = pipeout[1];
        } else {
            childout = *outfd;
        }
    } else {
        if (getDevNull(&null) < 0)
            goto cleanup;
        childout = null;
    }

    if (errfd != NULL) {
        if (errfd == outfd) {
            childerr = childout;
        } else if (*errfd == -1) {
            if (pipe2(pipeerr, O_CLOEXEC) < 0) {
                virReportSystemError(errno,
                                     "%s", _("Failed to create pipe"));
                goto cleanup;
            }

            if ((flags & VIR_EXEC_NONBLOCK) &&
                virSetNonBlock(pipeerr[0]) == -1) {
                virReportSystemError(errno,
                                     "%s", _("Failed to set non-blocking file descriptor flag"));
                goto cleanup;
            }

            childerr = pipeerr[1];
        } else {
            childerr = *errfd;
        }
    } else {
        if (getDevNull(&null) < 0)
            goto cleanup;
        childerr = null;
    }

    forkRet = virFork(&pid);

    if (pid < 0) {
        goto cleanup;
    }

    if (pid) { /* parent */
        VIR_FORCE_CLOSE(null);
        if (outfd && *outfd == -1) {
            VIR_FORCE_CLOSE(pipeout[1]);
            *outfd = pipeout[0];
        }
        if (errfd && *errfd == -1) {
            VIR_FORCE_CLOSE(pipeerr[1]);
            *errfd = pipeerr[0];
        }

        if (forkRet < 0) {
            goto cleanup;
        }

        *retpid = pid;

        if (binary != argv[0])
            VIR_FREE(binary);

        return 0;
    }

    /* child */

    if (forkRet < 0) {
        /* The fork was successful, but after that there was an error
         * in the child (which was already logged).
        */
        goto fork_error;
    }

    openmax = sysconf(_SC_OPEN_MAX);
    for (i = 3; i < openmax; i++) {
        if (i == infd || i == childout || i == childerr)
            continue;
        if (!keepfd || !virCommandFDIsSet(i, keepfd, keepfd_size)) {
            tmpfd = i;
            VIR_FORCE_CLOSE(tmpfd);
        } else if (virSetInherit(i, true) < 0) {
            virReportSystemError(errno, _("failed to preserve fd %d"), i);
            goto fork_error;
        }
    }

    if (prepareStdFd(infd, STDIN_FILENO) < 0) {
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

    if (infd != STDIN_FILENO && infd != null)
        VIR_FORCE_CLOSE(infd);
    if (childout > STDERR_FILENO && childout != null) {
        tmpfd = childout;   /* preserve childout value */
        VIR_FORCE_CLOSE(tmpfd);
    }
    if (childerr > STDERR_FILENO &&
        childerr != childout &&
        childerr != null) {
        VIR_FORCE_CLOSE(childerr);
    }
    VIR_FORCE_CLOSE(null);

    /* Initialize full logging for a while */
    virLogSetFromEnv();

    /* Daemonize as late as possible, so the parent process can detect
     * the above errors with wait* */
    if (flags & VIR_EXEC_DAEMON) {
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
            if (pidfile && (virPidFileWritePath(pidfile,pid) < 0)) {
                kill(pid, SIGTERM);
                usleep(500*1000);
                kill(pid, SIGTERM);
                virReportSystemError(errno,
                                     _("could not write pidfile %s for %d"),
                                     pidfile, pid);
                goto fork_error;
            }
            _exit(0);
        }
    }

    if (hook) {
        /* virFork reset all signal handlers to the defaults.
         * This is good for the child process, but our hook
         * risks running something that generates SIGPIPE,
         * so we need to temporarily block that again
         */
        struct sigaction waxon, waxoff;
        memset(&waxoff, 0, sizeof(waxoff));
        waxoff.sa_handler = SIG_IGN;
        sigemptyset(&waxoff.sa_mask);
        memset(&waxon, 0, sizeof(waxon));
        if (sigaction(SIGPIPE, &waxoff, &waxon) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Could not disable SIGPIPE"));
            goto fork_error;
        }

        if ((hook)(data) != 0) {
            VIR_DEBUG("Hook function failed.");
            goto fork_error;
        }

        if (sigaction(SIGPIPE, &waxon, NULL) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Could not re-enable SIGPIPE"));
            goto fork_error;
        }
    }

    /* The steps above may need todo something privileged, so
     * we delay clearing capabilities until the last minute */
    if (capabilities || (flags & VIR_EXEC_CLEAR_CAPS))
        if (virSetCapabilities(capabilities) < 0)
            goto fork_error;

    /* Close logging again to ensure no FDs leak to child */
    virLogReset();

    if (envp)
        execve(binary, (char **) argv, (char**)envp);
    else
        execv(binary, (char **) argv);

    virReportSystemError(errno,
                         _("cannot execute binary %s"),
                         argv[0]);

 fork_error:
    virDispatchError(NULL);
    _exit(EXIT_FAILURE);

 cleanup:
    /* This is cleanup of parent process only - child
       should never jump here on error */

    if (binary != argv[0])
        VIR_FREE(binary);

    /* NB we don't virCommandError() on any failures here
       because the code which jumped hre already raised
       an error condition which we must not overwrite */
    VIR_FORCE_CLOSE(pipeerr[0]);
    VIR_FORCE_CLOSE(pipeerr[1]);
    VIR_FORCE_CLOSE(pipeout[0]);
    VIR_FORCE_CLOSE(pipeout[1]);
    VIR_FORCE_CLOSE(null);
    return -1;
}

/**
 * virRun:
 * @argv NULL terminated argv to run
 * @status optional variable to return exit status in
 *
 * Run a command without using the shell.
 *
 * If status is NULL, then return 0 if the command run and
 * exited with 0 status; Otherwise return -1
 *
 * If status is not-NULL, then return 0 if the command ran.
 * The status variable is filled with the command exit status
 * and should be checked by caller for success. Return -1
 * only if the command could not be run.
 */
int
virRun(const char *const*argv, int *status)
{
    int ret;
    virCommandPtr cmd = virCommandNewArgs(argv);

    ret = virCommandRun(cmd, status);
    virCommandFree(cmd);
    return ret;
}

#else /* WIN32 */

int
virRun(const char *const *argv ATTRIBUTE_UNUSED,
       int *status)
{
    if (status)
        *status = ENOTSUP;
    else
        virCommandError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("virRun is not implemented for WIN32"));
    return -1;
}

static int
virExecWithHook(const char *const*argv ATTRIBUTE_UNUSED,
                const char *const*envp ATTRIBUTE_UNUSED,
                const int *keepfd ATTRIBUTE_UNUSED,
                int keepfd_size ATTRIBUTE_UNUSED,
                pid_t *retpid ATTRIBUTE_UNUSED,
                int infd ATTRIBUTE_UNUSED,
                int *outfd ATTRIBUTE_UNUSED,
                int *errfd ATTRIBUTE_UNUSED,
                int flags_unused ATTRIBUTE_UNUSED,
                virExecHook hook ATTRIBUTE_UNUSED,
                void *data ATTRIBUTE_UNUSED,
                char *pidfile ATTRIBUTE_UNUSED,
                unsigned long long capabilities ATTRIBUTE_UNUSED)
{
    /* XXX: Some day we can implement pieces of virCommand/virExec on
     * top of _spawn() or CreateProcess(), but we can't implement
     * everything, since mingw completely lacks fork(), so we cannot
     * run hook code in the child.  */
    virCommandError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("virExec is not implemented for WIN32"));
    return -1;
}

int
virFork(pid_t *pid)
{
    *pid = -1;
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
virCommandPtr
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
virCommandPtr
virCommandNewArgs(const char *const*args)
{
    virCommandPtr cmd;

    if (VIR_ALLOC(cmd) < 0)
        return NULL;

    cmd->handshakeWait[0] = -1;
    cmd->handshakeWait[1] = -1;
    cmd->handshakeNotify[0] = -1;
    cmd->handshakeNotify[1] = -1;

    cmd->infd = cmd->outfd = cmd->errfd = -1;
    cmd->inpipe = -1;
    cmd->pid = -1;

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
virCommandPtr
virCommandNewArgList(const char *binary, ...)
{
    virCommandPtr cmd = virCommandNew(binary);
    va_list list;
    const char *arg;

    if (!cmd || cmd->has_error)
        return cmd;

    va_start(list, binary);
    while ((arg = va_arg(list, const char *)) != NULL)
        virCommandAddArg(cmd, arg);
    va_end(list);
    return cmd;
}


/*
 * Preserve the specified file descriptor in the child, instead of
 * closing it.  FD must not be one of the three standard streams.  If
 * transfer is true, then fd will be closed in the parent after a call
 * to Run/RunAsync/Free, otherwise caller is still responsible for fd.
 * Returns true if a transferring caller should close FD now, and
 * false if the transfer is successfully recorded.
 */
static bool
virCommandKeepFD(virCommandPtr cmd, int fd, bool transfer)
{
    int ret = 0;

    if (!cmd)
        return fd > STDERR_FILENO;

    if (fd <= STDERR_FILENO ||
        (ret = virCommandFDSet(fd, &cmd->preserve, &cmd->preserve_size)) ||
        (transfer && (ret = virCommandFDSet(fd, &cmd->transfer,
                                            &cmd->transfer_size)))) {
        if (!cmd->has_error)
            cmd->has_error = ret ? ret : -1 ;
        VIR_DEBUG("cannot preserve %d", fd);
        return fd > STDERR_FILENO;
    }

    return false;
}

/**
 * virCommandPreserveFD:
 * @cmd: the command to modify
 * @fd: fd to mark for inheritance into child
 *
 * Preserve the specified file descriptor
 * in the child, instead of closing it on exec.
 * The parent is still responsible for managing fd.
 */
void
virCommandPreserveFD(virCommandPtr cmd, int fd)
{
    virCommandKeepFD(cmd, fd, false);
}

/**
 * virCommandTransferFD:
 * @cmd: the command to modify
 * @fd: fd to reassign to the child
 *
 * Transfer the specified file descriptor
 * to the child, instead of closing it on exec.
 * The parent should no longer use fd, and the parent's copy will
 * be automatically closed no later than during Run/RunAsync/Free.
 */
void
virCommandTransferFD(virCommandPtr cmd, int fd)
{
    if (virCommandKeepFD(cmd, fd, true))
        VIR_FORCE_CLOSE(fd);
}


/**
 * virCommandSetPidFile:
 * @cmd: the command to modify
 * @pidfile: filename to use
 *
 * Save the child PID in a pidfile.  The pidfile will be populated
 * before the exec of the child.
 */
void
virCommandSetPidFile(virCommandPtr cmd, const char *pidfile)
{
    if (!cmd || cmd->has_error)
        return;

    VIR_FREE(cmd->pidfile);
    if (!(cmd->pidfile = strdup(pidfile))) {
        cmd->has_error = ENOMEM;
    }
}


/**
 * virCommandClearCaps:
 * @cmd: the command to modify
 *
 * Remove all capabilities from the child, after any hooks have been run.
 */
void
virCommandClearCaps(virCommandPtr cmd)
{
    if (!cmd || cmd->has_error)
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
virCommandAllowCap(virCommandPtr cmd,
                   int capability)
{
    if (!cmd || cmd->has_error)
        return;

    cmd->capabilities |= (1ULL << capability);
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
virCommandDaemonize(virCommandPtr cmd)
{
    if (!cmd || cmd->has_error)
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
virCommandNonblockingFDs(virCommandPtr cmd)
{
    if (!cmd || cmd->has_error)
        return;

    cmd->flags |= VIR_EXEC_NONBLOCK;
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
virCommandAddEnvFormat(virCommandPtr cmd, const char *format, ...)
{
    char *env;
    va_list list;

    if (!cmd || cmd->has_error)
        return;

    va_start(list, format);
    if (virVasprintf(&env, format, list) < 0) {
        cmd->has_error = ENOMEM;
        va_end(list);
        return;
    }
    va_end(list);

    /* Arg plus trailing NULL. */
    if (VIR_RESIZE_N(cmd->env, cmd->maxenv, cmd->nenv, 1 + 1) < 0) {
        VIR_FREE(env);
        cmd->has_error = ENOMEM;
        return;
    }

    cmd->env[cmd->nenv++] = env;
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
virCommandAddEnvPair(virCommandPtr cmd, const char *name, const char *value)
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
virCommandAddEnvString(virCommandPtr cmd, const char *str)
{
    char *env;

    if (!cmd || cmd->has_error)
        return;

    if (!(env = strdup(str))) {
        cmd->has_error = ENOMEM;
        return;
    }

    /* env plus trailing NULL */
    if (VIR_RESIZE_N(cmd->env, cmd->maxenv, cmd->nenv, 1 + 1) < 0) {
        VIR_FREE(env);
        cmd->has_error = ENOMEM;
        return;
    }

    cmd->env[cmd->nenv++] = env;
}


/**
 * virCommandAddEnvBuffer:
 * @cmd: the command to modify
 * @buf: buffer that contains name=value string, which will be reset on return
 *
 * Convert a buffer containing preformatted name=value into an
 * environment variable of the child.
 * Correctly transfers memory errors or contents from buf to cmd.
 */
void
virCommandAddEnvBuffer(virCommandPtr cmd, virBufferPtr buf)
{
    if (!cmd || cmd->has_error) {
        virBufferFreeAndReset(buf);
        return;
    }

    /* env plus trailing NULL. */
    if (virBufferError(buf) ||
        VIR_RESIZE_N(cmd->env, cmd->maxenv, cmd->nenv, 1 + 1) < 0) {
        cmd->has_error = ENOMEM;
        virBufferFreeAndReset(buf);
        return;
    }
    if (!virBufferUse(buf)) {
        cmd->has_error = EINVAL;
        return;
    }

    cmd->env[cmd->nenv++] = virBufferContentAndReset(buf);
}


/**
 * virCommandAddEnvPass:
 * @cmd: the command to modify
 * @name: the name to look up in current environment
 *
 * Pass an environment variable to the child
 * using current process' value
 */
void
virCommandAddEnvPass(virCommandPtr cmd, const char *name)
{
    char *value;
    if (!cmd || cmd->has_error)
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
virCommandAddEnvPassCommon(virCommandPtr cmd)
{
    if (!cmd || cmd->has_error)
        return;

    /* Attempt to Pre-allocate; allocation failure will be detected
     * later during virCommandAdd*.  */
    ignore_value(VIR_RESIZE_N(cmd->env, cmd->maxenv, cmd->nenv, 9));

    virCommandAddEnvPair(cmd, "LC_ALL", "C");

    virCommandAddEnvPass(cmd, "LD_PRELOAD");
    virCommandAddEnvPass(cmd, "LD_LIBRARY_PATH");
    virCommandAddEnvPass(cmd, "PATH");
    virCommandAddEnvPass(cmd, "HOME");
    virCommandAddEnvPass(cmd, "USER");
    virCommandAddEnvPass(cmd, "LOGNAME");
    virCommandAddEnvPass(cmd, "TMPDIR");
}

/**
 * virCommandAddArg:
 * @cmd: the command to modify
 * @val: the argument to add
 *
 * Add a command line argument to the child
 */
void
virCommandAddArg(virCommandPtr cmd, const char *val)
{
    char *arg;

    if (!cmd || cmd->has_error)
        return;

    if (!(arg = strdup(val))) {
        cmd->has_error = ENOMEM;
        return;
    }

    /* Arg plus trailing NULL. */
    if (VIR_RESIZE_N(cmd->args, cmd->maxargs, cmd->nargs, 1 + 1) < 0) {
        VIR_FREE(arg);
        cmd->has_error = ENOMEM;
        return;
    }

    cmd->args[cmd->nargs++] = arg;
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
virCommandAddArgBuffer(virCommandPtr cmd, virBufferPtr buf)
{
    if (!cmd || cmd->has_error) {
        virBufferFreeAndReset(buf);
        return;
    }

    /* Arg plus trailing NULL. */
    if (virBufferError(buf) ||
        VIR_RESIZE_N(cmd->args, cmd->maxargs, cmd->nargs, 1 + 1) < 0) {
        cmd->has_error = ENOMEM;
        virBufferFreeAndReset(buf);
        return;
    }

    cmd->args[cmd->nargs] = virBufferContentAndReset(buf);
    if (!cmd->args[cmd->nargs])
        cmd->args[cmd->nargs] = strdup("");
    if (!cmd->args[cmd->nargs]) {
        cmd->has_error = ENOMEM;
        return;
    }
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
virCommandAddArgFormat(virCommandPtr cmd, const char *format, ...)
{
    char *arg;
    va_list list;

    if (!cmd || cmd->has_error)
        return;

    va_start(list, format);
    if (virVasprintf(&arg, format, list) < 0) {
        cmd->has_error = ENOMEM;
        va_end(list);
        return;
    }
    va_end(list);

    /* Arg plus trailing NULL. */
    if (VIR_RESIZE_N(cmd->args, cmd->maxargs, cmd->nargs, 1 + 1) < 0) {
        VIR_FREE(arg);
        cmd->has_error = ENOMEM;
        return;
    }

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
virCommandAddArgPair(virCommandPtr cmd, const char *name, const char *val)
{
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
virCommandAddArgSet(virCommandPtr cmd, const char *const*vals)
{
    int narg = 0;

    if (!cmd || cmd->has_error)
        return;

    if (vals[0] == NULL) {
        cmd->has_error = EINVAL;
        return;
    }

    while (vals[narg] != NULL)
        narg++;

    /* narg plus trailing NULL. */
    if (VIR_RESIZE_N(cmd->args, cmd->maxargs, cmd->nargs, narg + 1) < 0) {
        cmd->has_error = ENOMEM;
        return;
    }

    narg = 0;
    while (vals[narg] != NULL) {
        char *arg = strdup(vals[narg++]);
        if (!arg) {
            cmd->has_error = ENOMEM;
            return;
        }
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
virCommandAddArgList(virCommandPtr cmd, ...)
{
    va_list list;
    int narg = 0;

    if (!cmd || cmd->has_error)
        return;

    va_start(list, cmd);
    while (va_arg(list, const char *) != NULL)
        narg++;
    va_end(list);

    /* narg plus trailing NULL. */
    if (VIR_RESIZE_N(cmd->args, cmd->maxargs, cmd->nargs, narg + 1) < 0) {
        cmd->has_error = ENOMEM;
        return;
    }

    va_start(list, cmd);
    while (1) {
        char *arg = va_arg(list, char *);
        if (!arg)
            break;
        arg = strdup(arg);
        if (!arg) {
            cmd->has_error = ENOMEM;
            va_end(list);
            return;
        }
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
virCommandSetWorkingDirectory(virCommandPtr cmd, const char *pwd)
{
    if (!cmd || cmd->has_error)
        return;

    if (cmd->pwd) {
        cmd->has_error = -1;
        VIR_DEBUG("cannot set directory twice");
    } else {
        cmd->pwd = strdup(pwd);
        if (!cmd->pwd)
            cmd->has_error = ENOMEM;
    }
}


/**
 * virCommandSetInputBuffer:
 * @cmd: the command to modify
 * @inbuf: string to feed to stdin
 *
 * Feed the child's stdin from a string buffer.  This requires the use
 * of virCommandRun().
 */
void
virCommandSetInputBuffer(virCommandPtr cmd, const char *inbuf)
{
    if (!cmd || cmd->has_error)
        return;

    if (cmd->infd != -1 || cmd->inbuf) {
        cmd->has_error = -1;
        VIR_DEBUG("cannot specify input twice");
        return;
    }

    cmd->inbuf = strdup(inbuf);
    if (!cmd->inbuf)
        cmd->has_error = ENOMEM;
}


/**
 * virCommandSetOutputBuffer:
 * @cmd: the command to modify
 * @outbuf: address of variable to store malloced result buffer
 *
 * Capture the child's stdout to a string buffer.  *outbuf is
 * guaranteed to be allocated after successful virCommandRun or
 * virCommandWait, and is best-effort allocated after failed
 * virCommandRun; caller is responsible for freeing *outbuf.
 * This requires the use of virCommandRun.
 */
void
virCommandSetOutputBuffer(virCommandPtr cmd, char **outbuf)
{
    *outbuf = NULL;
    if (!cmd || cmd->has_error)
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
 * virCommandRun; caller is responsible for freeing *errbuf.
 * This requires the use of virCommandRun.  It is possible to
 * pass the same pointer as for virCommandSetOutputBuffer(), in
 * which case the child process will interleave all output into
 * a single string.
 */
void
virCommandSetErrorBuffer(virCommandPtr cmd, char **errbuf)
{
    *errbuf = NULL;
    if (!cmd || cmd->has_error)
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
virCommandSetInputFD(virCommandPtr cmd, int infd)
{
    if (!cmd || cmd->has_error)
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
virCommandSetOutputFD(virCommandPtr cmd, int *outfd)
{
    if (!cmd || cmd->has_error)
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
virCommandSetErrorFD(virCommandPtr cmd, int *errfd)
{
    if (!cmd || cmd->has_error)
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
virCommandSetPreExecHook(virCommandPtr cmd, virExecHook hook, void *opaque)
{
    if (!cmd || cmd->has_error)
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
virCommandWriteArgLog(virCommandPtr cmd, int logfd)
{
    int ioError = 0;
    size_t i;

    /* Any errors will be reported later by virCommandRun, which means
     * no command will be run, so there is nothing to log. */
    if (!cmd || cmd->has_error)
        return;

    for (i = 0 ; i < cmd->nenv ; i++) {
        if (safewrite(logfd, cmd->env[i], strlen(cmd->env[i])) < 0)
            ioError = errno;
        if (safewrite(logfd, " ", 1) < 0)
            ioError = errno;
    }
    for (i = 0 ; i < cmd->nargs ; i++) {
        if (safewrite(logfd, cmd->args[i], strlen(cmd->args[i])) < 0)
            ioError = errno;
        if (safewrite(logfd, i == cmd->nargs - 1 ? "\n" : " ", 1) < 0)
            ioError = errno;
    }

    if (ioError) {
        char ebuf[1024];
        VIR_WARN("Unable to write command %s args to logfile: %s",
                 cmd->args[0], virStrerror(ioError, ebuf, sizeof(ebuf)));
    }
}


/**
 * virCommandToString:
 * @cmd: the command to convert
 *
 * Call after adding all arguments and environment settings, but before
 * Run/RunAsync, to return a string representation of the environment and
 * arguments of cmd.  If virCommandRun cannot succeed (because of an
 * out-of-memory condition while building cmd), NULL will be returned.
 * Caller is responsible for freeing the resulting string.
 */
char *
virCommandToString(virCommandPtr cmd)
{
    size_t i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    /* Cannot assume virCommandRun will be called; so report the error
     * now.  If virCommandRun is called, it will report the same error. */
    if (!cmd ||cmd->has_error == ENOMEM) {
        virReportOOMError();
        return NULL;
    }
    if (cmd->has_error) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("invalid use of command API"));
        return NULL;
    }

    for (i = 0; i < cmd->nenv; i++) {
        virBufferAdd(&buf, cmd->env[i], strlen(cmd->env[i]));
        virBufferAddChar(&buf, ' ');
    }
    virBufferAdd(&buf, cmd->args[0], strlen(cmd->args[0]));
    for (i = 1; i < cmd->nargs; i++) {
        virBufferAddChar(&buf, ' ');
        virBufferAdd(&buf, cmd->args[i], strlen(cmd->args[i]));
    }

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}


/**
 * virCommandTranslateStatus:
 * @status: child exit status to translate
 *
 * Translate an exit status into a malloc'd string.  Generic helper
 * for virCommandRun(), virCommandWait(), virRun(), and virPidWait()
 * status argument, as well as raw waitpid().
 */
char *
virCommandTranslateStatus(int status)
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


/*
 * Manage input and output to the child process.
 */
static int
virCommandProcessIO(virCommandPtr cmd)
{
    int infd = -1, outfd = -1, errfd = -1;
    size_t inlen = 0, outlen = 0, errlen = 0;
    size_t inoff = 0;
    int ret = 0;

    /* With an input buffer, feed data to child
     * via pipe */
    if (cmd->inbuf) {
        inlen = strlen(cmd->inbuf);
        infd = cmd->inpipe;
    }

    /* With out/err buffer, the outfd/errfd have been filled with an
     * FD for us.  Guarantee an allocated string with partial results
     * even if we encounter a later failure, as well as freeing any
     * results accumulated over a prior run of the same command.  */
    if (cmd->outbuf) {
        outfd = cmd->outfd;
        if (VIR_REALLOC_N(*cmd->outbuf, 1) < 0) {
            virReportOOMError();
            ret = -1;
        }
    }
    if (cmd->errbuf) {
        errfd = cmd->errfd;
        if (VIR_REALLOC_N(*cmd->errbuf, 1) < 0) {
            virReportOOMError();
            ret = -1;
        }
    }
    if (ret == -1)
        goto cleanup;
    ret = -1;

    for (;;) {
        int i;
        struct pollfd fds[3];
        int nfds = 0;

        if (infd != -1) {
            fds[nfds].fd = infd;
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

        if (nfds == 0)
            break;

        if (poll(fds, nfds, -1) < 0) {
            if ((errno == EAGAIN) || (errno == EINTR))
                continue;
            virReportSystemError(errno, "%s",
                                 _("unable to poll on child"));
            goto cleanup;
        }

        for (i = 0; i < nfds ; i++) {
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
                /* Silence a false positive from clang. */
                sa_assert(buf);

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
                    if (VIR_REALLOC_N(*buf, *len + done + 1) < 0) {
                        virReportOOMError();
                        goto cleanup;
                    }
                    memcpy(*buf + *len, data, done);
                    *len += done;
                }
            }

            if (fds[i].revents & (POLLOUT | POLLERR) &&
                fds[i].fd == infd) {
                int done;

                /* Coverity 5.3.0 can't see that we only get here if
                 * infd is in the set because it was non-negative.  */
                sa_assert(infd != -1);
                done = write(infd, cmd->inbuf + inoff,
                             inlen - inoff);
                if (done < 0) {
                    if (errno != EINTR &&
                        errno != EAGAIN) {
                        virReportSystemError(errno, "%s",
                                             _("unable to write to child input"));
                        goto cleanup;
                    }
                } else {
                    inoff += done;
                    if (inoff == inlen) {
                        int tmpfd ATTRIBUTE_UNUSED;
                        tmpfd = infd;
                        if (VIR_CLOSE(infd) < 0)
                            VIR_DEBUG("ignoring failed close on fd %d", tmpfd);
                    }
                }
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
 *
 * Exec the command, replacing the current process. Meant to be called
 * in the hook after already forking / cloning, so does not attempt to
 * daemonize or preserve any FDs.
 *
 * Returns -1 on any error executing the command.
 * Will not return on success.
 */
#ifndef WIN32
int virCommandExec(virCommandPtr cmd)
{
    if (!cmd ||cmd->has_error == ENOMEM) {
        virReportOOMError();
        return -1;
    }
    if (cmd->has_error) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("invalid use of command API"));
        return -1;
    }

    return execve(cmd->args[0], cmd->args, cmd->env);
}
#else
int virCommandExec(virCommandPtr cmd ATTRIBUTE_UNUSED)
{
    /* Mingw execve() has a broken signature. Disable this
     * function until gnulib fixes the signature, since we
     * don't really need this on Win32 anyway.
     */
    virReportSystemError(ENOSYS, "%s",
                         _("Executing new processes is not supported on Win32 platform"));
    return -1;
}
#endif

/**
 * virCommandRun:
 * @cmd: command to run
 * @exitstatus: optional status collection
 *
 * Run the command and wait for completion.
 * Returns -1 on any error executing the
 * command. Returns 0 if the command executed,
 * with the exit status set.  If @exitstatus is NULL, then the
 * child must exit with status 0 for this to succeed.
 */
int
virCommandRun(virCommandPtr cmd, int *exitstatus)
{
    int ret = 0;
    char *outbuf = NULL;
    char *errbuf = NULL;
    int infd[2] = { -1, -1 };
    struct stat st;
    bool string_io;
    bool async_io = false;
    char *str;

    if (!cmd ||cmd->has_error == ENOMEM) {
        virReportOOMError();
        return -1;
    }
    if (cmd->has_error) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("invalid use of command API"));
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
            virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cannot mix caller fds with blocking execution"));
            return -1;
        }
    } else {
        if ((cmd->flags & VIR_EXEC_DAEMON) && string_io) {
            virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cannot mix string I/O with daemon"));
            return -1;
        }
    }

    /* If we have an input buffer, we need
     * a pipe to feed the data to the child */
    if (cmd->inbuf) {
        if (pipe2(infd, O_CLOEXEC) < 0) {
            virReportSystemError(errno, "%s",
                                 _("unable to open pipe"));
            cmd->has_error = -1;
            return -1;
        }
        cmd->infd = infd[0];
        cmd->inpipe = infd[1];
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
        if (cmd->inbuf) {
            int tmpfd = infd[0];
            if (VIR_CLOSE(infd[0]) < 0)
                VIR_DEBUG("ignoring failed close on fd %d", tmpfd);
            tmpfd = infd[1];
            if (VIR_CLOSE(infd[1]) < 0)
                VIR_DEBUG("ignoring failed close on fd %d", tmpfd);
        }
        cmd->has_error = -1;
        return -1;
    }

    if (string_io)
        ret = virCommandProcessIO(cmd);

    if (virCommandWait(cmd, exitstatus) < 0)
        ret = -1;

    str = (exitstatus ? virCommandTranslateStatus(*exitstatus)
           : (char *) "status 0");
    VIR_DEBUG("Result %s, stdout: '%s' stderr: '%s'",
              NULLSTR(str),
              cmd->outbuf ? NULLSTR(*cmd->outbuf) : "(null)",
              cmd->errbuf ? NULLSTR(*cmd->errbuf) : "(null)");
    if (exitstatus)
        VIR_FREE(str);

    /* Reset any capturing, in case caller runs
     * this identical command again */
    if (cmd->inbuf) {
        int tmpfd = infd[0];
        if (VIR_CLOSE(infd[0]) < 0)
            VIR_DEBUG("ignoring failed close on fd %d", tmpfd);
        tmpfd = infd[1];
        if (VIR_CLOSE(infd[1]) < 0)
            VIR_DEBUG("ignoring failed close on fd %d", tmpfd);
    }
    if (cmd->outbuf == &outbuf) {
        int tmpfd ATTRIBUTE_UNUSED;
        tmpfd = cmd->outfd;
        if (VIR_CLOSE(cmd->outfd) < 0)
            VIR_DEBUG("ignoring failed close on fd %d", tmpfd);
        cmd->outfdptr = NULL;
        cmd->outbuf = NULL;
        VIR_FREE(outbuf);
    }
    if (cmd->errbuf == &errbuf) {
        int tmpfd ATTRIBUTE_UNUSED;
        tmpfd = cmd->errfd;
        if (VIR_CLOSE(cmd->errfd) < 0)
            VIR_DEBUG("ignoring failed close on fd %d", tmpfd);
        cmd->errfdptr = NULL;
        cmd->errbuf = NULL;
        VIR_FREE(errbuf);
    }

    return ret;
}


/*
 * Perform all virCommand-specific actions, along with the user hook.
 */
static int
virCommandHook(void *data)
{
    virCommandPtr cmd = data;
    int res = 0;

    if (cmd->hook) {
        VIR_DEBUG("Run hook %p %p", cmd->hook, cmd->opaque);
        res = cmd->hook(cmd->opaque);
        VIR_DEBUG("Done hook %d", res);
    }
    if (res == 0 && cmd->pwd) {
        VIR_DEBUG("Running child in %s", cmd->pwd);
        res = chdir(cmd->pwd);
        if (res < 0) {
            virReportSystemError(errno,
                                 _("Unable to change to %s"), cmd->pwd);
        }
    }
    if (cmd->handshake) {
        char c = res < 0 ? '0' : '1';
        int rv;
        VIR_DEBUG("Notifying parent for handshake start on %d", cmd->handshakeWait[1]);
        if (safewrite(cmd->handshakeWait[1], &c, sizeof(c)) != sizeof(c)) {
            virReportSystemError(errno, "%s", _("Unable to notify parent process"));
            return -1;
        }

        /* On failure we pass the error message back to parent,
         * so they don't have to dig through stderr logs
         */
        if (res < 0) {
            virErrorPtr err = virGetLastError();
            const char *msg = err ? err->message :
                _("Unknown failure during hook execution");
            size_t len = strlen(msg) + 1;
            if (safewrite(cmd->handshakeWait[1], msg, len) != len) {
                virReportSystemError(errno, "%s", _("Unable to send error to parent process"));
                return -1;
            }
            return -1;
        }

        VIR_DEBUG("Waiting on parent for handshake complete on %d", cmd->handshakeNotify[0]);
        if ((rv = saferead(cmd->handshakeNotify[0], &c, sizeof(c))) != sizeof(c)) {
            if (rv < 0)
                virReportSystemError(errno, "%s", _("Unable to wait on parent process"));
            else
                virReportSystemError(EIO, "%s", _("libvirtd quit during handshake"));
            return -1;
        }
        if (c != '1') {
            virReportSystemError(EINVAL, _("Unexpected confirm code '%c' from parent process"), c);
            return -1;
        }
        VIR_FORCE_CLOSE(cmd->handshakeWait[1]);
        VIR_FORCE_CLOSE(cmd->handshakeNotify[0]);
    }

    VIR_DEBUG("Hook is done %d", res);

    return res;
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
 * you call virPidWait or virPidAbort.
 */
int
virCommandRunAsync(virCommandPtr cmd, pid_t *pid)
{
    int ret;
    char *str;
    int i;
    bool synchronous = false;

    if (!cmd || cmd->has_error == ENOMEM) {
        virReportOOMError();
        return -1;
    }
    if (cmd->has_error) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("invalid use of command API"));
        return -1;
    }

    synchronous = cmd->flags & VIR_EXEC_RUN_SYNC;
    cmd->flags &= ~VIR_EXEC_RUN_SYNC;

    /* Buffer management can only be requested via virCommandRun.  */
    if ((cmd->inbuf && cmd->infd == -1) ||
        (cmd->outbuf && cmd->outfdptr != &cmd->outfd) ||
        (cmd->errbuf && cmd->errfdptr != &cmd->errfd)) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("cannot mix string I/O with asynchronous command"));
        return -1;
    }

    if (cmd->pid != -1) {
        virCommandError(VIR_ERR_INTERNAL_ERROR,
                        _("command is already running as pid %lld"),
                        (long long) cmd->pid);
        return -1;
    }

    if (!synchronous && (cmd->flags & VIR_EXEC_DAEMON)) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("daemonized command cannot use virCommandRunAsync"));
        return -1;
    }
    if (cmd->pwd && (cmd->flags & VIR_EXEC_DAEMON)) {
        virCommandError(VIR_ERR_INTERNAL_ERROR,
                        _("daemonized command cannot set working directory %s"),
                        cmd->pwd);
        return -1;
    }
    if (cmd->pidfile && !(cmd->flags & VIR_EXEC_DAEMON)) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("creation of pid file requires daemonized command"));
        return -1;
    }

    str = virCommandToString(cmd);
    VIR_DEBUG("About to run %s", str ? str : cmd->args[0]);
    VIR_FREE(str);

    ret = virExecWithHook((const char *const *)cmd->args,
                          (const char *const *)cmd->env,
                          cmd->preserve,
                          cmd->preserve_size,
                          &cmd->pid,
                          cmd->infd,
                          cmd->outfdptr,
                          cmd->errfdptr,
                          cmd->flags,
                          virCommandHook,
                          cmd,
                          cmd->pidfile,
                          cmd->capabilities);

    VIR_DEBUG("Command result %d, with PID %d",
              ret, (int)cmd->pid);

    for (i = 0; i < cmd->transfer_size; i++) {
        VIR_FORCE_CLOSE(cmd->transfer[i]);
    }
    cmd->transfer_size = 0;
    VIR_FREE(cmd->transfer);

    if (ret == 0 && pid)
        *pid = cmd->pid;
    else
        cmd->reap = true;

    return ret;
}


/**
 * virPidWait:
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
virPidWait(pid_t pid, int *exitstatus)
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
            char *st = virCommandTranslateStatus(status);
            virCommandError(VIR_ERR_INTERNAL_ERROR,
                            _("Child process (%lld) status unexpected: %s"),
                            (long long) pid, NULLSTR(st));
            VIR_FREE(st);
            return -1;
        }
    } else {
        *exitstatus = status;
    }

    return 0;
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
 * child must exit with status 0 for this to succeed.
 */
int
virCommandWait(virCommandPtr cmd, int *exitstatus)
{
    int ret;
    int status = 0;

    if (!cmd ||cmd->has_error == ENOMEM) {
        virReportOOMError();
        return -1;
    }
    if (cmd->has_error) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("invalid use of command API"));
        return -1;
    }

    if (cmd->pid == -1) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("command is not yet running"));
        return -1;
    }

    /* If virPidWait reaps pid but then returns failure because
     * exitstatus was NULL, then a second virCommandWait would risk
     * calling waitpid on an unrelated process.  Besides, that error
     * message is not as detailed as what we can provide.  So, we
     * guarantee that virPidWait only fails due to failure to wait,
     * and repeat the exitstatus check code ourselves.  */
    ret = virPidWait(cmd->pid, exitstatus ? exitstatus : &status);
    if (ret == 0) {
        cmd->pid = -1;
        cmd->reap = false;
        if (status) {
            char *str = virCommandToString(cmd);
            char *st = virCommandTranslateStatus(status);
            virCommandError(VIR_ERR_INTERNAL_ERROR,
                            _("Child process (%s) status unexpected: %s"),
                            str ? str : cmd->args[0], NULLSTR(st));
            VIR_FREE(str);
            VIR_FREE(st);
            return -1;
        }
    }

    return ret;
}


#ifndef WIN32
/**
 * virPidAbort:
 * @pid: child process to kill
 *
 * Abort a child process if PID is positive and that child is still
 * running, without issuing any errors or affecting errno.  Designed
 * for error paths where some but not all paths to the cleanup code
 * might have started the child process.  If @pid is 0 or negative,
 * this does nothing.
 */
void
virPidAbort(pid_t pid)
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
        tmp = virCommandTranslateStatus(status);
        VIR_DEBUG("process has ended: %s", tmp);
        goto cleanup;
    } else if (ret == 0) {
        VIR_DEBUG("trying SIGTERM to child process %d", pid);
        kill(pid, SIGTERM);
        usleep(10 * 1000);
        while ((ret = waitpid(pid, &status, WNOHANG)) == -1 &&
               errno == EINTR);
        if (ret == pid) {
            tmp = virCommandTranslateStatus(status);
            VIR_DEBUG("process has ended: %s", tmp);
            goto cleanup;
        } else if (ret == 0) {
            VIR_DEBUG("trying SIGKILL to child process %d", pid);
            kill(pid, SIGKILL);
            while ((ret = waitpid(pid, &status, 0)) == -1 &&
                   errno == EINTR);
            if (ret == pid) {
                tmp = virCommandTranslateStatus(status);
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
virCommandAbort(virCommandPtr cmd)
{
    if (!cmd || cmd->pid == -1)
        return;
    virPidAbort(cmd->pid);
    cmd->pid = -1;
    cmd->reap = false;
}
#else /* WIN32 */
void
virPidAbort(pid_t pid)
{
    /* Not yet ported to mingw.  Any volunteers?  */
    VIR_DEBUG("failed to reap child %d, abandoning it", pid);
}

void
virCommandAbort(virCommandPtr cmd ATTRIBUTE_UNUSED)
{
    /* Mingw lacks WNOHANG and kill().  But since we haven't ported
     * virExecWithHook to mingw yet, there's no process to be killed,
     * making this implementation trivially correct for now :)  */
}
#endif


/**
 * virCommandRequireHandshake:
 * @cmd: command to modify
 *
 * Request that the child perform a handshake with
 * the parent when the hook function has completed
 * execution. The child will not exec() until the
 * parent has notified
 */
void virCommandRequireHandshake(virCommandPtr cmd)
{
    if (!cmd || cmd->has_error)
        return;

    if (cmd->handshake) {
        cmd->has_error = -1;
        VIR_DEBUG("Cannot require handshake twice");
        return;
    }

    if (pipe2(cmd->handshakeWait, O_CLOEXEC) < 0) {
        cmd->has_error = errno;
        return;
    }
    if (pipe2(cmd->handshakeNotify, O_CLOEXEC) < 0) {
        VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
        VIR_FORCE_CLOSE(cmd->handshakeWait[1]);
        cmd->has_error = errno;
        return;
    }

    VIR_DEBUG("Transfer handshake wait=%d notify=%d",
              cmd->handshakeWait[1], cmd->handshakeNotify[0]);
    virCommandTransferFD(cmd, cmd->handshakeWait[1]);
    virCommandTransferFD(cmd, cmd->handshakeNotify[0]);
    cmd->handshake = true;
}

/**
 * virCommandHandshakeWait:
 * @cmd: command to wait on
 *
 * Wait for the child to complete execution of its
 * hook function.  To be called in the parent.
 */
int virCommandHandshakeWait(virCommandPtr cmd)
{
    char c;
    int rv;
    if (!cmd ||cmd->has_error == ENOMEM) {
        virReportOOMError();
        return -1;
    }
    if (cmd->has_error || !cmd->handshake) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("invalid use of command API"));
        return -1;
    }

    if (cmd->handshakeWait[0] == -1) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Handshake is already complete"));
        return -1;
    }

    VIR_DEBUG("Wait for handshake on %d", cmd->handshakeWait[0]);
    if ((rv = saferead(cmd->handshakeWait[0], &c, sizeof(c))) != sizeof(c)) {
        if (rv < 0)
            virReportSystemError(errno, "%s", _("Unable to wait for child process"));
        else
            virReportSystemError(EIO, "%s", _("Child process quit during startup handshake"));
        VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
        return -1;
    }
    if (c != '1') {
        char *msg;
        ssize_t len;
        if (VIR_ALLOC_N(msg, 1024) < 0) {
            virReportOOMError();
            VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
            return -1;
        }
        if ((len = saferead(cmd->handshakeWait[0], msg, 1024)) < 0) {
            VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
            VIR_FREE(msg);
            virReportSystemError(errno, "%s", _("No error message from child failure"));
            return -1;
        }
        VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
        msg[len-1] = '\0';
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s", msg);
        VIR_FREE(msg);
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
int virCommandHandshakeNotify(virCommandPtr cmd)
{
    char c = '1';
    if (!cmd ||cmd->has_error == ENOMEM) {
        virReportOOMError();
        return -1;
    }
    if (cmd->has_error || !cmd->handshake) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("invalid use of command API"));
        return -1;
    }

    if (cmd->handshakeNotify[1] == -1) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Handshake is already complete"));
        return -1;
    }

    VIR_DEBUG("Notify handshake on %d", cmd->handshakeWait[0]);
    if (safewrite(cmd->handshakeNotify[1], &c, sizeof(c)) != sizeof(c)) {
        virReportSystemError(errno, "%s", _("Unable to notify child process"));
        VIR_FORCE_CLOSE(cmd->handshakeNotify[1]);
        return -1;
    }
    VIR_FORCE_CLOSE(cmd->handshakeNotify[1]);
    return 0;
}


/**
 * virCommandFree:
 * @cmd: optional command to free
 *
 * Release all resources.  The only exception is that if you called
 * virCommandRunAsync with a non-null pid, then the asynchronous child
 * is not reaped, and you must call virPidWait() or virPidAbort() yourself.
 */
void
virCommandFree(virCommandPtr cmd)
{
    int i;
    if (!cmd)
        return;

    for (i = 0; i < cmd->transfer_size; i++) {
        VIR_FORCE_CLOSE(cmd->transfer[i]);
    }

    VIR_FREE(cmd->inbuf);
    VIR_FORCE_CLOSE(cmd->outfd);
    VIR_FORCE_CLOSE(cmd->errfd);

    for (i = 0 ; i < cmd->nargs ; i++)
        VIR_FREE(cmd->args[i]);
    VIR_FREE(cmd->args);

    for (i = 0 ; i < cmd->nenv ; i++)
        VIR_FREE(cmd->env[i]);
    VIR_FREE(cmd->env);

    VIR_FREE(cmd->pwd);

    if (cmd->handshake) {
        /* The other 2 fds in these arrays are closed
         * due to use with virCommandTransferFD
         */
        VIR_FORCE_CLOSE(cmd->handshakeWait[0]);
        VIR_FORCE_CLOSE(cmd->handshakeNotify[1]);
    }

    VIR_FREE(cmd->pidfile);

    if (cmd->reap)
        virCommandAbort(cmd);

    VIR_FREE(cmd->transfer);
    VIR_FREE(cmd->preserve);

    VIR_FREE(cmd);
}
