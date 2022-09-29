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

typedef struct _virCommandSendBuffer virCommandSendBuffer;
struct _virCommandSendBuffer {
    int fd;
    unsigned char *buffer;
    size_t buflen;
    off_t offset;
};

typedef struct _virCommand virCommand;

/* This will execute in the context of the first child
 * after fork() but before execve().  As such, it is unsafe to
 * call any function that is not async-signal-safe.  */
typedef int (*virExecHook)(void *data);

pid_t virFork(void) G_GNUC_WARN_UNUSED_RESULT;

virCommand *virCommandNew(const char *binary) ATTRIBUTE_NONNULL(1);

virCommand *virCommandNewArgs(const char *const*args) ATTRIBUTE_NONNULL(1);

virCommand *virCommandNewArgList(const char *binary, ...)
    ATTRIBUTE_NONNULL(1) G_GNUC_NULL_TERMINATED;

virCommand *virCommandNewVAList(const char *binary, va_list list)
    ATTRIBUTE_NONNULL(1);

/* All error report from these setup APIs is
 * delayed until the Run/RunAsync methods
 */

typedef enum {
    /* Close the FD in the parent */
    VIR_COMMAND_PASS_FD_CLOSE_PARENT = (1 << 0),
} virCommandPassFDFlags;

void virCommandPassFD(virCommand *cmd,
                      int fd,
                      unsigned int flags) G_NO_INLINE;

void virCommandSetPidFile(virCommand *cmd,
                          const char *pidfile) ATTRIBUTE_NONNULL(2);

gid_t virCommandGetGID(virCommand *cmd) ATTRIBUTE_NONNULL(1);

uid_t virCommandGetUID(virCommand *cmd) ATTRIBUTE_NONNULL(1);

void virCommandSetGID(virCommand *cmd, gid_t gid);

void virCommandSetUID(virCommand *cmd, uid_t uid);

void virCommandSetMaxMemLock(virCommand *cmd, unsigned long long bytes);
void virCommandSetMaxProcesses(virCommand *cmd, unsigned int procs);
void virCommandSetMaxFiles(virCommand *cmd, unsigned int files);
void virCommandSetMaxCoreSize(virCommand *cmd, unsigned long long bytes);
void virCommandSetUmask(virCommand *cmd, int umask);

void virCommandClearCaps(virCommand *cmd);

void virCommandAllowCap(virCommand *cmd,
                        int capability);

void virCommandSetSELinuxLabel(virCommand *cmd,
                               const char *label);

void virCommandSetAppArmorProfile(virCommand *cmd,
                                  const char *profile);

void virCommandDaemonize(virCommand *cmd);

void virCommandNonblockingFDs(virCommand *cmd);

void virCommandRawStatus(virCommand *cmd);

void virCommandAddEnvFormat(virCommand *cmd, const char *format, ...)
    ATTRIBUTE_NONNULL(2) G_GNUC_PRINTF(2, 3);

void virCommandAddEnvPair(virCommand *cmd,
                          const char *name,
                          const char *value) ATTRIBUTE_NONNULL(2);

void virCommandAddEnvString(virCommand *cmd,
                            const char *str) ATTRIBUTE_NONNULL(2);

void virCommandAddEnvPass(virCommand *cmd,
                          const char *name) ATTRIBUTE_NONNULL(2);

void virCommandAddEnvPassCommon(virCommand *cmd);

void virCommandAddEnvXDG(virCommand *cmd, const char *baseDir);

void virCommandAddArg(virCommand *cmd,
                      const char *val) ATTRIBUTE_NONNULL(2);

void virCommandAddArgBuffer(virCommand *cmd,
                            virBuffer *buf);

void virCommandAddArgFormat(virCommand *cmd,
                            const char *format, ...)
    ATTRIBUTE_NONNULL(2) G_GNUC_PRINTF(2, 3);

void virCommandAddArgPair(virCommand *cmd,
                          const char *name,
                          const char *val);

void virCommandAddArgSet(virCommand *cmd,
                         const char *const*vals) ATTRIBUTE_NONNULL(2);

void virCommandAddArgList(virCommand *cmd,
                          ... /* const char *arg, ..., NULL */)
    G_GNUC_NULL_TERMINATED;

void virCommandSetWorkingDirectory(virCommand *cmd,
                                   const char *pwd) ATTRIBUTE_NONNULL(2);

int virCommandSetSendBuffer(virCommand *cmd,
                            unsigned char **buffer,
                            size_t buflen)
    ATTRIBUTE_NONNULL(2);

void virCommandSetInputBuffer(virCommand *cmd,
                              const char *inbuf) ATTRIBUTE_NONNULL(2);

void virCommandSetOutputBuffer(virCommand *cmd,
                               char **outbuf) ATTRIBUTE_NONNULL(2);

void virCommandSetErrorBuffer(virCommand *cmd,
                              char **errbuf) ATTRIBUTE_NONNULL(2);

void virCommandSetInputFD(virCommand *cmd,
                          int infd);

void virCommandSetOutputFD(virCommand *cmd,
                           int *outfd) ATTRIBUTE_NONNULL(2);

void virCommandSetErrorFD(virCommand *cmd,
                          int *errfd) ATTRIBUTE_NONNULL(2);

void virCommandSetPreExecHook(virCommand *cmd,
                              virExecHook hook,
                              void *opaque) ATTRIBUTE_NONNULL(2);

void virCommandWriteArgLog(virCommand *cmd,
                           int logfd);

char *virCommandToString(virCommand *cmd, bool linebreaks) G_GNUC_WARN_UNUSED_RESULT;
char *virCommandToStringFull(virCommand *cmd,
                             bool linebreaks,
                             bool stripCommandPath);
int virCommandToStringBuf(virCommand *cmd,
                          virBuffer *buf,
                          bool linebreaks,
                          bool stripCommandPath);

const char *virCommandGetBinaryPath(virCommand *cmd);
int virCommandGetArgList(virCommand *cmd, char ***args);

int virCommandExec(virCommand *cmd, gid_t *groups, int ngroups) G_GNUC_WARN_UNUSED_RESULT;

int virCommandRun(virCommand *cmd,
                  int *exitstatus) G_GNUC_WARN_UNUSED_RESULT;

int virCommandRunAsync(virCommand *cmd,
                       pid_t *pid) G_GNUC_WARN_UNUSED_RESULT;

int virCommandWait(virCommand *cmd,
                   int *exitstatus) G_GNUC_WARN_UNUSED_RESULT;

void virCommandRequireHandshake(virCommand *cmd);

int virCommandHandshakeWait(virCommand *cmd)
    G_GNUC_WARN_UNUSED_RESULT;

int virCommandHandshakeNotify(virCommand *cmd)
    G_GNUC_WARN_UNUSED_RESULT;

void virCommandAbort(virCommand *cmd);

void virCommandFree(virCommand *cmd);

void virCommandDoAsyncIO(virCommand *cmd);

typedef int (*virCommandRunRegexFunc)(char **const groups,
                                      void *data);
typedef int (*virCommandRunNulFunc)(size_t n_tokens,
                                    char **const groups,
                                    void *data);

int virCommandRunRegex(virCommand *cmd,
                       int nregex,
                       const char **regex,
                       int *nvars,
                       virCommandRunRegexFunc func,
                       void *data,
                       const char *cmd_to_ignore,
                       int *exitstatus);

int virCommandRunNul(virCommand *cmd,
                     size_t n_columns,
                     virCommandRunNulFunc func,
                     void *data);

void virCommandSetRunAlone(virCommand *cmd);

void virCommandSetRunAmong(virCommand *cmd,
                           pid_t pid);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virCommand, virCommandFree);
