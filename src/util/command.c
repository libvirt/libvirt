/*
 * command.c: Child command execution
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "command.h"
#include "memory.h"
#include "virterror_internal.h"
#include "util.h"
#include "logging.h"
#include "files.h"
#include "buf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define virCommandError(code, ...)                                      \
    virReportErrorHelper(NULL, VIR_FROM_NONE, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

struct _virCommand {
    int has_error; /* ENOMEM on allocation failure, -1 for anything else.  */

    char **args;
    size_t nargs;
    size_t maxargs;

    char **env;
    size_t nenv;
    size_t maxenv;

    char *pwd;

    /* XXX Use int[] if we ever need to support more than FD_SETSIZE fd's.  */
    fd_set preserve; /* FDs to pass to child. */
    fd_set transfer; /* FDs to close in parent. */

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

    virExecHook hook;
    void *opaque;

    pid_t pid;
    char *pidfile;
};

/*
 * Create a new command for named binary
 */
virCommandPtr
virCommandNew(const char *binary)
{
    const char *const args[] = { binary, NULL };

    return virCommandNewArgs(args);
}

/*
 * Create a new command with a NULL terminated
 * set of args, taking binary from args[0]
 */
virCommandPtr
virCommandNewArgs(const char *const*args)
{
    virCommandPtr cmd;

    if (VIR_ALLOC(cmd) < 0)
        return NULL;

    FD_ZERO(&cmd->preserve);
    FD_ZERO(&cmd->transfer);
    cmd->infd = cmd->outfd = cmd->errfd = -1;
    cmd->inpipe = -1;
    cmd->pid = -1;

    virCommandAddArgSet(cmd, args);

    if (cmd->has_error) {
        virCommandFree(cmd);
        return NULL;
    }

    return cmd;
}

/*
 * Create a new command with a NULL terminated
 * list of args, starting with the binary to run
 */
virCommandPtr
virCommandNewArgList(const char *binary, ...)
{
    virCommandPtr cmd = virCommandNew(binary);
    va_list list;
    const char *arg;

    if (!cmd || cmd->has_error)
        return NULL;

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
 */
static void
virCommandKeepFD(virCommandPtr cmd, int fd, bool transfer)
{
    if (!cmd)
        return;

    if (fd <= STDERR_FILENO || FD_SETSIZE <= fd) {
        if (!cmd->has_error)
            cmd->has_error = -1;
        VIR_DEBUG("cannot preserve %d", fd);
        return;
    }

    FD_SET(fd, &cmd->preserve);
    if (transfer)
        FD_SET(fd, &cmd->transfer);
}

/*
 * Preserve the specified file descriptor
 * in the child, instead of closing it.
 * The parent is still responsible for managing fd.
 */
void
virCommandPreserveFD(virCommandPtr cmd, int fd)
{
    return virCommandKeepFD(cmd, fd, false);
}

/*
 * Transfer the specified file descriptor
 * to the child, instead of closing it.
 * Close the fd in the parent during Run/RunAsync/Free.
 */
void
virCommandTransferFD(virCommandPtr cmd, int fd)
{
    return virCommandKeepFD(cmd, fd, true);
}


/*
 * Save the child PID in a pidfile
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


/*
 * Remove all capabilities from the child
 */
void
virCommandClearCaps(virCommandPtr cmd)
{
    if (!cmd || cmd->has_error)
        return;

    cmd->flags |= VIR_EXEC_CLEAR_CAPS;
}

#if 0 /* XXX Enable if we have a need for capability management.  */

/*
 * Re-allow a specific capability
 */
void
virCommandAllowCap(virCommandPtr cmd,
                   int capability ATTRIBUTE_UNUSED)
{
    if (!cmd || cmd->has_error)
        return;

    /* XXX ? */
}

#endif /* 0 */


/*
 * Daemonize the child process
 */
void
virCommandDaemonize(virCommandPtr cmd)
{
    if (!cmd || cmd->has_error)
        return;

    cmd->flags |= VIR_EXEC_DAEMON;
}

/*
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

/*
 * Add an environment variable to the child
 * using separate name & value strings
 */
void
virCommandAddEnvPair(virCommandPtr cmd, const char *name, const char *value)
{
    char *env;

    if (!cmd || cmd->has_error)
        return;

    if (virAsprintf(&env, "%s=%s", name, value ? value : "") < 0) {
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


/*
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


/*
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

    cmd->env[cmd->nenv++] = virBufferContentAndReset(buf);
}


/*
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


/*
 * Set LC_ALL to C, and propagate other essential environment
 * variables from the parent process.
 */
void
virCommandAddEnvPassCommon(virCommandPtr cmd)
{
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

/*
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


/*
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

    cmd->args[cmd->nargs++] = virBufferContentAndReset(buf);
}


/*
 * Add a command line argument created by a printf-style format
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

/*
 * Add "NAME=VAL" as a single command line argument to the child
 */
void
virCommandAddArgPair(virCommandPtr cmd, const char *name, const char *val)
{
    virCommandAddArgFormat(cmd, "%s=%s", name, val);
}

/*
 * Add a NULL terminated list of args
 */
void
virCommandAddArgSet(virCommandPtr cmd, const char *const*vals)
{
    int narg = 0;

    if (!cmd || cmd->has_error)
        return;

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

/*
 * Add a NULL terminated list of args
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

/*
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
        VIR_DEBUG0("cannot set directory twice");
    } else {
        cmd->pwd = strdup(pwd);
        if (!cmd->pwd)
            cmd->has_error = ENOMEM;
    }
}


/*
 * Feed the child's stdin from a string buffer
 */
void
virCommandSetInputBuffer(virCommandPtr cmd, const char *inbuf)
{
    if (!cmd || cmd->has_error)
        return;

    if (cmd->infd != -1 || cmd->inbuf) {
        cmd->has_error = -1;
        VIR_DEBUG0("cannot specify input twice");
        return;
    }

    cmd->inbuf = strdup(inbuf);
    if (!cmd->inbuf)
        cmd->has_error = ENOMEM;
}


/*
 * Capture the child's stdout to a string buffer.  *outbuf is
 * guaranteed to be allocated after successful virCommandRun or
 * virCommandWait, and is best-effort allocated after failed
 * virCommandRun; caller is responsible for freeing *outbuf.
 */
void
virCommandSetOutputBuffer(virCommandPtr cmd, char **outbuf)
{
    *outbuf = NULL;
    if (!cmd || cmd->has_error)
        return;

    if (cmd->outfdptr) {
        cmd->has_error = -1;
        VIR_DEBUG0("cannot specify output twice");
        return;
    }

    cmd->outbuf = outbuf;
    cmd->outfdptr = &cmd->outfd;
}


/*
 * Capture the child's stderr to a string buffer.  *errbuf is
 * guaranteed to be allocated after successful virCommandRun or
 * virCommandWait, and is best-effort allocated after failed
 * virCommandRun; caller is responsible for freeing *errbuf.
 */
void
virCommandSetErrorBuffer(virCommandPtr cmd, char **errbuf)
{
    *errbuf = NULL;
    if (!cmd || cmd->has_error)
        return;

    if (cmd->errfdptr) {
        cmd->has_error = -1;
        VIR_DEBUG0("cannot specify stderr twice");
        return;
    }

    cmd->errbuf = errbuf;
    cmd->errfdptr = &cmd->errfd;
}


/*
 * Attach a file descriptor to the child's stdin
 */
void
virCommandSetInputFD(virCommandPtr cmd, int infd)
{
    if (!cmd || cmd->has_error)
        return;

    if (cmd->infd != -1 || cmd->inbuf) {
        cmd->has_error = -1;
        VIR_DEBUG0("cannot specify input twice");
        return;
    }
    if (infd < 0) {
        cmd->has_error = -1;
        VIR_DEBUG0("cannot specify invalid input fd");
        return;
    }

    cmd->infd = infd;
}


/*
 * Attach a file descriptor to the child's stdout
 */
void
virCommandSetOutputFD(virCommandPtr cmd, int *outfd)
{
    if (!cmd || cmd->has_error)
        return;

    if (cmd->outfdptr) {
        cmd->has_error = -1;
        VIR_DEBUG0("cannot specify output twice");
        return;
    }

    cmd->outfdptr = outfd;
}


/*
 * Attach a file descriptor to the child's stderr
 */
void
virCommandSetErrorFD(virCommandPtr cmd, int *errfd)
{
    if (!cmd || cmd->has_error)
        return;

    if (cmd->errfdptr) {
        cmd->has_error = -1;
        VIR_DEBUG0("cannot specify stderr twice");
        return;
    }

    cmd->errfdptr = errfd;
}


/*
 * Run HOOK(OPAQUE) in the child as the last thing before changing
 * directories, dropping capabilities, and executing the new process.
 * Force the child to fail if HOOK does not return zero.
 */
void
virCommandSetPreExecHook(virCommandPtr cmd, virExecHook hook, void *opaque)
{
    if (!cmd || cmd->has_error)
        return;

    if (cmd->hook) {
        cmd->has_error = -1;
        VIR_DEBUG0("cannot specify hook twice");
        return;
    }
    cmd->hook = hook;
    cmd->opaque = opaque;
}


/*
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
                 cmd->args[0], virStrerror(ioError, ebuf, sizeof ebuf));
    }
}


/*
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
            nfds++;
        }
        if (outfd != -1) {
            fds[nfds].fd = outfd;
            fds[nfds].events = POLLIN;
            nfds++;
        }
        if (errfd != -1) {
            fds[nfds].fd = errfd;
            fds[nfds].events = POLLIN;
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
            if (fds[i].fd == errfd ||
                fds[i].fd == outfd) {
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
                                             _("unable to write to child input"));
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
            } else {
                int done;

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
                        int tmpfd = infd;
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


/*
 * Run the command and wait for completion.
 * Returns -1 on any error executing the
 * command. Returns 0 if the command executed,
 * with the exit status set
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
        if (pipe(infd) < 0) {
            virReportSystemError(errno, "%s",
                                 _("unable to open pipe"));
            cmd->has_error = -1;
            return -1;
        }
        cmd->infd = infd[0];
        cmd->inpipe = infd[1];
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

    VIR_DEBUG("Result stdout: '%s' stderr: '%s'",
              cmd->outbuf ? NULLSTR(*cmd->outbuf) : "(null)",
              cmd->errbuf ? NULLSTR(*cmd->errbuf) : "(null)");

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
        int tmpfd = cmd->outfd;
        if (VIR_CLOSE(cmd->outfd) < 0)
            VIR_DEBUG("ignoring failed close on fd %d", tmpfd);
        cmd->outfdptr = NULL;
        cmd->outbuf = NULL;
        VIR_FREE(outbuf);
    }
    if (cmd->errbuf == &errbuf) {
        int tmpfd = cmd->errfd;
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

    if (cmd->hook)
        res = cmd->hook(cmd->opaque);
    if (res == 0 && cmd->pwd) {
        VIR_DEBUG("Running child in %s", cmd->pwd);
        res = chdir(cmd->pwd);
    }
    return res;
}


/*
 * Run the command asynchronously
 * Returns -1 on any error executing the
 * command. Returns 0 if the command executed.
 */
int
virCommandRunAsync(virCommandPtr cmd, pid_t *pid)
{
    int ret;
    char *str;
    int i;

    if (!cmd || cmd->has_error == ENOMEM) {
        virReportOOMError();
        return -1;
    }
    if (cmd->has_error) {
        virCommandError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("invalid use of command API"));
        return -1;
    }

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
                        _("command is already running as pid %d"),
                        cmd->pid);
        return -1;
    }

    if (cmd->pwd && (cmd->flags & VIR_EXEC_DAEMON)) {
        virCommandError(VIR_ERR_INTERNAL_ERROR,
                        _("daemonized command cannot set working directory %s"),
                        cmd->pwd);
        return -1;
    }


    str = virCommandToString(cmd);
    VIR_DEBUG("About to run %s", str ? str : cmd->args[0]);
    VIR_FREE(str);

    ret = virExecWithHook((const char *const *)cmd->args,
                          (const char *const *)cmd->env,
                          &cmd->preserve,
                          &cmd->pid,
                          cmd->infd,
                          cmd->outfdptr,
                          cmd->errfdptr,
                          cmd->flags,
                          virCommandHook,
                          cmd,
                          cmd->pidfile);

    VIR_DEBUG("Command result %d, with PID %d",
              ret, (int)cmd->pid);

    for (i = STDERR_FILENO + 1; i < FD_SETSIZE; i++) {
        if (FD_ISSET(i, &cmd->transfer)) {
            int tmpfd = i;
            VIR_FORCE_CLOSE(tmpfd);
            FD_CLR(i, &cmd->transfer);
        }
    }

    if (ret == 0 && pid)
        *pid = cmd->pid;

    return ret;
}


/*
 * Wait for the async command to complete.
 * Return -1 on any error waiting for
 * completion. Returns 0 if the command
 * finished with the exit status set
 */
int
virCommandWait(virCommandPtr cmd, int *exitstatus)
{
    int ret;
    int status;

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


    /* Wait for intermediate process to exit */
    while ((ret = waitpid(cmd->pid, &status, 0)) == -1 &&
           errno == EINTR);

    if (ret == -1) {
        virReportSystemError(errno, _("unable to wait for process %d"),
                             cmd->pid);
        return -1;
    }

    cmd->pid = -1;

    if (exitstatus == NULL) {
        if (status != 0) {
            char *str = virCommandToString(cmd);
            virCommandError(VIR_ERR_INTERNAL_ERROR,
                            _("Child process (%s) exited with status %d."),
                            str ? str : cmd->args[0], WEXITSTATUS(status));
            VIR_FREE(str);
            return -1;
        }
    } else {
        *exitstatus = status;
    }

    return 0;
}


/*
 * Release all resources
 */
void
virCommandFree(virCommandPtr cmd)
{
    int i;
    if (!cmd)
        return;

    for (i = STDERR_FILENO + 1; i < FD_SETSIZE; i++) {
        if (FD_ISSET(i, &cmd->transfer)) {
            int tmpfd = i;
            VIR_FORCE_CLOSE(tmpfd);
        }
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

    VIR_FREE(cmd->pidfile);

    VIR_FREE(cmd);
}
