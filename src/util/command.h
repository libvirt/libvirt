/*
 * command.h: Child command execution
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

#ifndef __VIR_COMMAND_H__
# define __VIR_COMMAND_H__

# include "internal.h"
# include "util.h"
# include "buf.h"

typedef struct _virCommand virCommand;
typedef virCommand *virCommandPtr;

/*
 * Create a new command for named binary
 */
virCommandPtr virCommandNew(const char *binary) ATTRIBUTE_NONNULL(1);

/*
 * Create a new command with a NULL terminated
 * set of args, taking binary from argv[0]
 */
virCommandPtr virCommandNewArgs(const char *const*args) ATTRIBUTE_NONNULL(1);

/*
 * Create a new command with a NULL terminated
 * list of args, starting with the binary to run
 */
virCommandPtr virCommandNewArgList(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_SENTINEL;

/* All error report from these setup APIs is
 * delayed until the Run/RunAsync methods
 */

/*
 * Preserve the specified file descriptor
 * in the child, instead of closing it.
 * The parent is still responsible for managing fd.
 */
void virCommandPreserveFD(virCommandPtr cmd,
                          int fd);

/*
 * Transfer the specified file descriptor
 * to the child, instead of closing it.
 * Close the fd in the parent during Run/RunAsync/Free.
 */
void virCommandTransferFD(virCommandPtr cmd,
                          int fd);

/*
 * Save the child PID in a pidfile
 */
void virCommandSetPidFile(virCommandPtr cmd,
                          const char *pidfile) ATTRIBUTE_NONNULL(2);

/*
 * Remove all capabilities from the child
 */
void virCommandClearCaps(virCommandPtr cmd);

# if 0
/*
 * Re-allow a specific capability
 */
void virCommandAllowCap(virCommandPtr cmd,
                        int capability);
# endif

/*
 * Daemonize the child process
 */
void virCommandDaemonize(virCommandPtr cmd);

/*
 * Set FDs created by virCommandSetOutputFD and virCommandSetErrorFD
 * as non-blocking in the parent.
 */
void virCommandNonblockingFDs(virCommandPtr cmd);

/*
 * Add an environment variable to the child created by a printf-style format
 */
void
virCommandAddEnvFormat(virCommandPtr cmd, const char *format, ...)
                       ATTRIBUTE_NONNULL(2) ATTRIBUTE_FMT_PRINTF(2, 3);

/*
 * Add an environment variable to the child
 * using separate name & value strings
 */
void virCommandAddEnvPair(virCommandPtr cmd,
                          const char *name,
                          const char *value) ATTRIBUTE_NONNULL(2);

/*
 * Add an environemnt variable to the child
 * using a preformated env string FOO=BAR
 */
void virCommandAddEnvString(virCommandPtr cmd,
                            const char *str) ATTRIBUTE_NONNULL(2);

/*
 * Convert a buffer containing preformatted name=value into an
 * environment variable of the child.
 * Correctly transfers memory errors or contents from buf to cmd.
 */
void virCommandAddEnvBuffer(virCommandPtr cmd,
                            virBufferPtr buf);

/*
 * Pass an environment variable to the child
 * using current process' value
 */
void virCommandAddEnvPass(virCommandPtr cmd,
                          const char *name) ATTRIBUTE_NONNULL(2);
/*
 * Pass a common set of environment variables
 * to the child using current process' values
 */
void virCommandAddEnvPassCommon(virCommandPtr cmd);

/*
 * Add a command line argument to the child
 */
void virCommandAddArg(virCommandPtr cmd,
                      const char *val) ATTRIBUTE_NONNULL(2);

/*
 * Convert a buffer into a command line argument to the child.
 * Correctly transfers memory errors or contents from buf to cmd.
 */
void virCommandAddArgBuffer(virCommandPtr cmd,
                            virBufferPtr buf);

/*
 * Add a command line argument created by a printf-style format
 */
void virCommandAddArgFormat(virCommandPtr cmd,
                            const char *format, ...)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_FMT_PRINTF(2, 3);

/*
 * Add a command line argument to the child
 */
void virCommandAddArgPair(virCommandPtr cmd,
                          const char *name,
                          const char *val)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
/*
 * Add a NULL terminated array of args
 */
void virCommandAddArgSet(virCommandPtr cmd,
                         const char *const*vals) ATTRIBUTE_NONNULL(2);
/*
 * Add a NULL terminated list of args
 */
void virCommandAddArgList(virCommandPtr cmd,
                          ... /* const char *arg, ..., NULL */)
    ATTRIBUTE_SENTINEL;

/*
 * Set the working directory of a non-daemon child process, rather
 * than the parent's working directory.  Daemons automatically get /
 * without using this call.
 */
void virCommandSetWorkingDirectory(virCommandPtr cmd,
                                   const char *pwd) ATTRIBUTE_NONNULL(2);

/*
 * Feed the child's stdin from a string buffer.
 *
 * NB: Only works with virCommandRun()
 */
void virCommandSetInputBuffer(virCommandPtr cmd,
                              const char *inbuf) ATTRIBUTE_NONNULL(2);
/*
 * Capture the child's stdout to a string buffer
 *
 * NB: Only works with virCommandRun()
 */
void virCommandSetOutputBuffer(virCommandPtr cmd,
                               char **outbuf) ATTRIBUTE_NONNULL(2);
/*
 * Capture the child's stderr to a string buffer
 *
 * NB: Only works with virCommandRun()
 */
void virCommandSetErrorBuffer(virCommandPtr cmd,
                              char **errbuf) ATTRIBUTE_NONNULL(2);

/*
 * Set a file descriptor as the child's stdin
 */
void virCommandSetInputFD(virCommandPtr cmd,
                          int infd);
/*
 * Set a file descriptor as the child's stdout
 */
void virCommandSetOutputFD(virCommandPtr cmd,
                           int *outfd) ATTRIBUTE_NONNULL(2);
/*
 * Set a file descriptor as the child's stderr
 */
void virCommandSetErrorFD(virCommandPtr cmd,
                          int *errfd) ATTRIBUTE_NONNULL(2);

/*
 * A hook function to run between fork + exec
 */
void virCommandSetPreExecHook(virCommandPtr cmd,
                              virExecHook hook,
                              void *opaque) ATTRIBUTE_NONNULL(2);

/*
 * Call after adding all arguments and environment settings, but before
 * Run/RunAsync, to immediately output the environment and arguments of
 * cmd to logfd.  If virCommandRun cannot succeed (because of an
 * out-of-memory condition while building cmd), nothing will be logged.
 */
void virCommandWriteArgLog(virCommandPtr cmd,
                           int logfd);

/*
 * Call after adding all arguments and environment settings, but before
 * Run/RunAsync, to return a string representation of the environment and
 * arguments of cmd.  If virCommandRun cannot succeed (because of an
 * out-of-memory condition while building cmd), NULL will be returned.
 * Caller is responsible for freeing the resulting string.
 */
char *virCommandToString(virCommandPtr cmd) ATTRIBUTE_RETURN_CHECK;


/*
 * Translate an exit status into a malloc'd string.
 */
char *virCommandTranslateStatus(int exitstatus) ATTRIBUTE_RETURN_CHECK;

/*
 * Exec the command, replacing the current process. Meant to be called
 * after already forking / cloning, so does not attempt to daemonize or
 * preserve any FDs.
 *
 * Returns -1 on any error executing the command.
 * Will not return on success.
 */
int virCommandExec(virCommandPtr cmd) ATTRIBUTE_RETURN_CHECK;

/*
 * Run the command and wait for completion.
 * Returns -1 on any error executing the
 * command. Returns 0 if the command executed,
 * with the exit status set
 */
int virCommandRun(virCommandPtr cmd,
                  int *exitstatus) ATTRIBUTE_RETURN_CHECK;

/*
 * Run the command asynchronously
 * Returns -1 on any error executing the
 * command. Returns 0 if the command executed.
 */
int virCommandRunAsync(virCommandPtr cmd,
                       pid_t *pid) ATTRIBUTE_RETURN_CHECK;

/*
 * Wait for the async command to complete.
 * Return -1 on any error waiting for
 * completion. Returns 0 if the command
 * finished with the exit status set
 */
int virCommandWait(virCommandPtr cmd,
                   int *exitstatus) ATTRIBUTE_RETURN_CHECK;

/*
 * Request that the child perform a handshake with
 * the parent when the hook function has completed
 * execution. The child will not exec() until the
 * parent has notified
 */
void virCommandRequireHandshake(virCommandPtr cmd);

/*
 * Wait for the child to complete execution of its
 * hook function
 */
int virCommandHandshakeWait(virCommandPtr cmd)
    ATTRIBUTE_RETURN_CHECK;

/*
 * Notify the child that it is OK to exec() the
 * real binary now
 */
int virCommandHandshakeNotify(virCommandPtr cmd)
    ATTRIBUTE_RETURN_CHECK;

/*
 * Abort an async command if it is running, without issuing
 * any errors or affecting errno.  Designed for error paths
 * where some but not all paths to the cleanup code might
 * have started the child process.
 */
void virCommandAbort(virCommandPtr cmd);

/*
 * Release all resources.  The only exception is that if you called
 * virCommandRunAsync with a non-null pid, then the asynchronous child
 * is not reaped, and you must call waitpid() yourself.
 */
void virCommandFree(virCommandPtr cmd);


#endif /* __VIR_COMMAND_H__ */
