/*
 * vircommand.h: Child command execution
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

#pragma once

#include "internal.h"
#include "virbuffer.h"
#include "virautoclean.h"

typedef struct _virCommand virCommand;
typedef virCommand *virCommandPtr;

/* This will execute in the context of the first child
 * after fork() but before execve().  As such, it is unsafe to
 * call any function that is not async-signal-safe.  */
typedef int (*virExecHook)(void *data);

pid_t virFork(void) G_GNUC_WARN_UNUSED_RESULT;

int virRun(const char *const*argv, int *status) G_GNUC_WARN_UNUSED_RESULT;

virCommandPtr virCommandNew(const char *binary) ATTRIBUTE_NONNULL(1);

virCommandPtr virCommandNewArgs(const char *const*args) ATTRIBUTE_NONNULL(1);

virCommandPtr virCommandNewArgList(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) G_GNUC_NULL_TERMINATED;

virCommandPtr virCommandNewVAList(const char *binary, va_list list)
    ATTRIBUTE_NONNULL(1);

/* All error report from these setup APIs is
 * delayed until the Run/RunAsync methods
 */

typedef enum {
    /* Close the FD in the parent */
    VIR_COMMAND_PASS_FD_CLOSE_PARENT = (1 << 0),
} virCommandPassFDFlags;

void virCommandPassFD(virCommandPtr cmd,
                      int fd,
                      unsigned int flags) G_GNUC_NO_INLINE;

int virCommandPassFDGetFDIndex(virCommandPtr cmd,
                               int fd);

void virCommandSetPidFile(virCommandPtr cmd,
                          const char *pidfile) ATTRIBUTE_NONNULL(2);

gid_t virCommandGetGID(virCommandPtr cmd) ATTRIBUTE_NONNULL(1);

uid_t virCommandGetUID(virCommandPtr cmd) ATTRIBUTE_NONNULL(1);

void virCommandSetGID(virCommandPtr cmd, gid_t gid);

void virCommandSetUID(virCommandPtr cmd, uid_t uid);

void virCommandSetMaxMemLock(virCommandPtr cmd, unsigned long long bytes);
void virCommandSetMaxProcesses(virCommandPtr cmd, unsigned int procs);
void virCommandSetMaxFiles(virCommandPtr cmd, unsigned int files);
void virCommandSetMaxCoreSize(virCommandPtr cmd, unsigned long long bytes);
void virCommandSetUmask(virCommandPtr cmd, int umask);

void virCommandClearCaps(virCommandPtr cmd);

void virCommandAllowCap(virCommandPtr cmd,
                        int capability);

void virCommandSetSELinuxLabel(virCommandPtr cmd,
                               const char *label);

void virCommandSetAppArmorProfile(virCommandPtr cmd,
                                  const char *profile);

void virCommandDaemonize(virCommandPtr cmd);

void virCommandNonblockingFDs(virCommandPtr cmd);

void virCommandRawStatus(virCommandPtr cmd);

void virCommandAddEnvFormat(virCommandPtr cmd, const char *format, ...)
    ATTRIBUTE_NONNULL(2) G_GNUC_PRINTF(2, 3);

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

void virCommandAddEnvXDG(virCommandPtr cmd, const char *baseDir);

void virCommandAddArg(virCommandPtr cmd,
                      const char *val) ATTRIBUTE_NONNULL(2);

void virCommandAddArgBuffer(virCommandPtr cmd,
                            virBufferPtr buf);

void virCommandAddArgFormat(virCommandPtr cmd,
                            const char *format, ...)
    ATTRIBUTE_NONNULL(2) G_GNUC_PRINTF(2, 3);

void virCommandAddArgPair(virCommandPtr cmd,
                          const char *name,
                          const char *val)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

void virCommandAddArgSet(virCommandPtr cmd,
                         const char *const*vals) ATTRIBUTE_NONNULL(2);

void virCommandAddArgList(virCommandPtr cmd,
                          ... /* const char *arg, ..., NULL */)
    G_GNUC_NULL_TERMINATED;

void virCommandSetWorkingDirectory(virCommandPtr cmd,
                                   const char *pwd) ATTRIBUTE_NONNULL(2);

int virCommandSetSendBuffer(virCommandPtr cmd,
                            int fd,
                            unsigned char *buffer, size_t buflen)
    ATTRIBUTE_NONNULL(3);

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

char *virCommandToString(virCommandPtr cmd, bool linebreaks) G_GNUC_WARN_UNUSED_RESULT;

int virCommandExec(virCommandPtr cmd, gid_t *groups, int ngroups) G_GNUC_WARN_UNUSED_RESULT;

int virCommandRun(virCommandPtr cmd,
                  int *exitstatus) G_GNUC_WARN_UNUSED_RESULT;

int virCommandRunAsync(virCommandPtr cmd,
                       pid_t *pid) G_GNUC_WARN_UNUSED_RESULT;

int virCommandWait(virCommandPtr cmd,
                   int *exitstatus) G_GNUC_WARN_UNUSED_RESULT;

void virCommandRequireHandshake(virCommandPtr cmd);

int virCommandHandshakeWait(virCommandPtr cmd)
    G_GNUC_WARN_UNUSED_RESULT;

int virCommandHandshakeNotify(virCommandPtr cmd)
    G_GNUC_WARN_UNUSED_RESULT;

void virCommandAbort(virCommandPtr cmd);

void virCommandFree(virCommandPtr cmd);

void virCommandDoAsyncIO(virCommandPtr cmd);

typedef int (*virCommandRunRegexFunc)(char **const groups,
                                      void *data);
typedef int (*virCommandRunNulFunc)(size_t n_tokens,
                                    char **const groups,
                                    void *data);

int virCommandRunRegex(virCommandPtr cmd,
                       int nregex,
                       const char **regex,
                       int *nvars,
                       virCommandRunRegexFunc func,
                       void *data,
                       const char *cmd_to_ignore,
                       int *exitstatus);

int virCommandRunNul(virCommandPtr cmd,
                     size_t n_columns,
                     virCommandRunNulFunc func,
                     void *data);

VIR_DEFINE_AUTOPTR_FUNC(virCommand, virCommandFree);
