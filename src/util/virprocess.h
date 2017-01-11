/*
 * virprocess.h: interaction with processes
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

#ifndef __VIR_PROCESS_H__
# define __VIR_PROCESS_H__

# include <sys/types.h>

# include "internal.h"
# include "virbitmap.h"
# include "virutil.h"

typedef enum {
    VIR_PROC_POLICY_NONE = 0,
    VIR_PROC_POLICY_BATCH,
    VIR_PROC_POLICY_IDLE,
    VIR_PROC_POLICY_FIFO,
    VIR_PROC_POLICY_RR,

    VIR_PROC_POLICY_LAST
} virProcessSchedPolicy;

VIR_ENUM_DECL(virProcessSchedPolicy);

char *
virProcessTranslateStatus(int status);

void
virProcessAbort(pid_t pid);

void virProcessExitWithStatus(int status) ATTRIBUTE_NORETURN;

int
virProcessWait(pid_t pid, int *exitstatus, bool raw)
    ATTRIBUTE_RETURN_CHECK;

int virProcessKill(pid_t pid, int sig);

int virProcessKillPainfully(pid_t pid, bool force);

int virProcessSetAffinity(pid_t pid, virBitmapPtr map);

virBitmapPtr virProcessGetAffinity(pid_t pid);

int virProcessGetPids(pid_t pid, size_t *npids, pid_t **pids);

int virProcessGetStartTime(pid_t pid,
                           unsigned long long *timestamp);

int virProcessGetNamespaces(pid_t pid,
                            size_t *nfdlist,
                            int **fdlist);

int virProcessSetNamespaces(size_t nfdlist,
                            int *fdlist);

int virProcessSetMaxMemLock(pid_t pid, unsigned long long bytes);
int virProcessSetMaxProcesses(pid_t pid, unsigned int procs);
int virProcessSetMaxFiles(pid_t pid, unsigned int files);
int virProcessSetMaxCoreSize(pid_t pid, unsigned long long bytes);

int virProcessGetMaxMemLock(pid_t pid, unsigned long long *bytes);

/* Callback to run code within the mount namespace tied to the given
 * pid.  This function must use only async-signal-safe functions, as
 * it gets run after a fork of a multi-threaded process.  The return
 * value of this function is passed to _exit(), except that a
 * negative value is treated as EXIT_CANCELED.  */
typedef int (*virProcessNamespaceCallback)(pid_t pid, void *opaque);

int virProcessRunInMountNamespace(pid_t pid,
                                  virProcessNamespaceCallback cb,
                                  void *opaque);

int virProcessSetupPrivateMountNS(void);

int virProcessSetScheduler(pid_t pid,
                           virProcessSchedPolicy policy,
                           int priority);
typedef enum {
    VIR_PROCESS_NAMESPACE_MNT = (1 << 1),
    VIR_PROCESS_NAMESPACE_IPC = (1 << 2),
    VIR_PROCESS_NAMESPACE_NET = (1 << 3),
    VIR_PROCESS_NAMESPACE_PID = (1 << 4),
    VIR_PROCESS_NAMESPACE_USER = (1 << 5),
    VIR_PROCESS_NAMESPACE_UTS = (1 << 6),
} virProcessNamespaceFlags;

int virProcessNamespaceAvailable(unsigned int ns);

#endif /* __VIR_PROCESS_H__ */
