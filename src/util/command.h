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

/* This will execute in the context of the first child
 * after fork() but before execve().  As such, it is unsafe to
 * call any function that is not async-signal-safe.  */
typedef int (*virExecHook)(void *data);

int virFork(pid_t *pid) ATTRIBUTE_RETURN_CHECK;

int virRun(const char *const*argv, int *status) ATTRIBUTE_RETURN_CHECK;

virCommandPtr virCommandNew(const char *binary) ATTRIBUTE_NONNULL(1);

virCommandPtr virCommandNewArgs(const char *const*args) ATTRIBUTE_NONNULL(1);

virCommandPtr virCommandNewArgList(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_SENTINEL;

/* All error report from these setup APIs is
 * delayed until the Run/RunAsync methods
 */

void virCommandPreserveFD(virCommandPtr cmd,
                          int fd);

void virCommandTransferFD(virCommandPtr cmd,
                          int fd);

void virCommandSetPidFile(virCommandPtr cmd,
                          const char *pidfile) ATTRIBUTE_NONNULL(2);

void virCommandClearCaps(virCommandPtr cmd);

void virCommandAllowCap(virCommandPtr cmd,
                        int capability);

void virCommandDaemonize(virCommandPtr cmd);

void virCommandNonblockingFDs(virCommandPtr cmd);

void virCommandAddEnvFormat(virCommandPtr cmd, const char *format, ...)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_FMT_PRINTF(2, 3);

void virCommandAddEnvPair(virCommandPtr cmd,
                          const char *name,
                          const char *value) ATTRIBUTE_NONNULL(2);

void virCommandAddEnvString(virCommandPtr cmd,
                            const char *str) ATTRIBUTE_NONNULL(2);

void virCommandAddEnvBuffer(virCommandPtr cmd,
                            virBufferPtr buf);

void virCommandAddEnvPass(virCommandPtr cmd,
                          const char *name) ATTRIBUTE_NONNULL(2);

void virCommandAddEnvPassCommon(virCommandPtr cmd);

void virCommandAddArg(virCommandPtr cmd,
                      const char *val) ATTRIBUTE_NONNULL(2);

void virCommandAddArgBuffer(virCommandPtr cmd,
                            virBufferPtr buf);

void virCommandAddArgFormat(virCommandPtr cmd,
                            const char *format, ...)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_FMT_PRINTF(2, 3);

void virCommandAddArgPair(virCommandPtr cmd,
                          const char *name,
                          const char *val)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

void virCommandAddArgSet(virCommandPtr cmd,
                         const char *const*vals) ATTRIBUTE_NONNULL(2);

void virCommandAddArgList(virCommandPtr cmd,
                          ... /* const char *arg, ..., NULL */)
    ATTRIBUTE_SENTINEL;

void virCommandSetWorkingDirectory(virCommandPtr cmd,
                                   const char *pwd) ATTRIBUTE_NONNULL(2);

void virCommandSetInputBuffer(virCommandPtr cmd,
                              const char *inbuf) ATTRIBUTE_NONNULL(2);

void virCommandSetOutputBuffer(virCommandPtr cmd,
                               char **outbuf) ATTRIBUTE_NONNULL(2);

void virCommandSetErrorBuffer(virCommandPtr cmd,
                              char **errbuf) ATTRIBUTE_NONNULL(2);

void virCommandSetInputFD(virCommandPtr cmd,
                          int infd);

void virCommandSetOutputFD(virCommandPtr cmd,
                           int *outfd) ATTRIBUTE_NONNULL(2);

void virCommandSetErrorFD(virCommandPtr cmd,
                          int *errfd) ATTRIBUTE_NONNULL(2);

void virCommandSetPreExecHook(virCommandPtr cmd,
                              virExecHook hook,
                              void *opaque) ATTRIBUTE_NONNULL(2);

void virCommandWriteArgLog(virCommandPtr cmd,
                           int logfd);

char *virCommandToString(virCommandPtr cmd) ATTRIBUTE_RETURN_CHECK;


char *virCommandTranslateStatus(int exitstatus) ATTRIBUTE_RETURN_CHECK;

int virCommandExec(virCommandPtr cmd) ATTRIBUTE_RETURN_CHECK;

int virCommandRun(virCommandPtr cmd,
                  int *exitstatus) ATTRIBUTE_RETURN_CHECK;

int virCommandRunAsync(virCommandPtr cmd,
                       pid_t *pid) ATTRIBUTE_RETURN_CHECK;

int virPidWait(pid_t pid,
               int *exitstatus) ATTRIBUTE_RETURN_CHECK;

int virCommandWait(virCommandPtr cmd,
                   int *exitstatus) ATTRIBUTE_RETURN_CHECK;

void virCommandRequireHandshake(virCommandPtr cmd);

int virCommandHandshakeWait(virCommandPtr cmd)
    ATTRIBUTE_RETURN_CHECK;

int virCommandHandshakeNotify(virCommandPtr cmd)
    ATTRIBUTE_RETURN_CHECK;

void virPidAbort(pid_t pid);

void virCommandAbort(virCommandPtr cmd);

void virCommandFree(virCommandPtr cmd);

#endif /* __VIR_COMMAND_H__ */
