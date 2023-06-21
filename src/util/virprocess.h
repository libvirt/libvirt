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

#pragma once

#include <sys/types.h>

#include "internal.h"
#include "virbitmap.h"
#include "virenum.h"

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

void virProcessExitWithStatus(int status) G_GNUC_NORETURN;

int
virProcessWait(pid_t pid, int *exitstatus, bool raw)
    G_GNUC_WARN_UNUSED_RESULT;

int virProcessKill(pid_t pid, int sig);
int virProcessGroupKill(pid_t pid, int sig);
pid_t virProcessGroupGet(pid_t pid);

int virProcessKillPainfully(pid_t pid, bool force);
int virProcessKillPainfullyDelay(pid_t pid,
                                 bool force,
                                 unsigned int extradelay,
                                 bool group);

int virProcessSetAffinity(pid_t pid, virBitmap *map, bool quiet);

virBitmap *virProcessGetAffinity(pid_t pid);

int virProcessGetPids(pid_t pid, size_t *npids, pid_t **pids);

int virProcessGetStartTime(pid_t pid,
                           unsigned long long *timestamp);

int virProcessGetNamespaces(pid_t pid,
                            size_t *nfdlist,
                            int **fdlist);

int virProcessSetNamespaces(size_t nfdlist,
                            int *fdlist);

int virProcessSetMaxMemLock(pid_t pid, unsigned long long bytes) G_NO_INLINE;
int virProcessSetMaxProcesses(pid_t pid, unsigned int procs);
int virProcessSetMaxFiles(pid_t pid, unsigned int files);
int virProcessSetMaxCoreSize(pid_t pid, unsigned long long bytes);
void virProcessActivateMaxFiles(void);

int virProcessGetMaxMemLock(pid_t pid, unsigned long long *bytes) G_NO_INLINE;

/* Callback to run code within the mount namespace tied to the given
 * pid.  This function must use only async-signal-safe functions, as
 * it gets run after a fork of a multi-threaded process.  The return
 * value of this function is passed to _exit(), except that a
 * negative value is treated as EXIT_CANCELED.  */
typedef int (*virProcessNamespaceCallback)(pid_t pid, void *opaque);

int virProcessRunInMountNamespace(pid_t pid,
                                  virProcessNamespaceCallback cb,
                                  void *opaque);

/**
 * virProcessForkCallback:
 * @ppid: parent's pid
 * @opaque: opaque data
 *
 * Callback to run in fork()-ed process.
 *
 * Returns: 0 on success,
 *         -1 on error (treated as EXIT_CANCELED)
 */
typedef int (*virProcessForkCallback)(pid_t ppid,
                                      void *opaque);

int virProcessRunInFork(virProcessForkCallback cb,
                        void *opaque)
    G_NO_INLINE;

int virProcessSetupPrivateMountNS(void);

int virProcessSetScheduler(pid_t pid,
                           virProcessSchedPolicy policy,
                           int priority);

GStrv virProcessGetStat(pid_t pid, pid_t tid);

/* These constants are modelled after proc(5) */
enum {
    VIR_PROCESS_STAT_PID,
    VIR_PROCESS_STAT_COMM,
    VIR_PROCESS_STAT_STATE,
    VIR_PROCESS_STAT_PPID,
    VIR_PROCESS_STAT_PGRP,
    VIR_PROCESS_STAT_SESSION,
    VIR_PROCESS_STAT_TTY_NR,
    VIR_PROCESS_STAT_TPGID,
    VIR_PROCESS_STAT_FLAGS,
    VIR_PROCESS_STAT_MINFLT,
    VIR_PROCESS_STAT_CMINFLT,
    VIR_PROCESS_STAT_MAJFLT,
    VIR_PROCESS_STAT_CMAJFLT,
    VIR_PROCESS_STAT_UTIME,
    VIR_PROCESS_STAT_STIME,
    VIR_PROCESS_STAT_CUTIME,
    VIR_PROCESS_STAT_CSTIME,
    VIR_PROCESS_STAT_PRIORITY,
    VIR_PROCESS_STAT_NICE,
    VIR_PROCESS_STAT_NUM_THREADS,
    VIR_PROCESS_STAT_ITREALVALUE,
    VIR_PROCESS_STAT_STARTTIME,
    VIR_PROCESS_STAT_VSIZE,
    VIR_PROCESS_STAT_RSS,
    VIR_PROCESS_STAT_RSSLIM,
    VIR_PROCESS_STAT_STARTCODE,
    VIR_PROCESS_STAT_ENDCODE,
    VIR_PROCESS_STAT_STARTSTACK,
    VIR_PROCESS_STAT_KSTKESP,
    VIR_PROCESS_STAT_KSTKEIP,
    VIR_PROCESS_STAT_SIGNAL,
    VIR_PROCESS_STAT_BLOCKED,
    VIR_PROCESS_STAT_SIGIGNORE,
    VIR_PROCESS_STAT_SIGCATCH,
    VIR_PROCESS_STAT_WCHAN,
    VIR_PROCESS_STAT_NSWAP,
    VIR_PROCESS_STAT_CNSWAP,
    VIR_PROCESS_STAT_EXIT_SIGNAL,
    VIR_PROCESS_STAT_PROCESSOR,
    VIR_PROCESS_STAT_RT_PRIORITY,
    VIR_PROCESS_STAT_POLICY,
    VIR_PROCESS_STAT_DELAYACCT_BLKIO_TICKS,
    VIR_PROCESS_STAT_GUEST_TIME,
    VIR_PROCESS_STAT_CGUEST_TIME,
    VIR_PROCESS_STAT_START_DATA,
    VIR_PROCESS_STAT_END_DATA,
    VIR_PROCESS_STAT_START_BRK,
    VIR_PROCESS_STAT_ARG_START,
    VIR_PROCESS_STAT_ARG_END,
    VIR_PROCESS_STAT_ENV_START,
    VIR_PROCESS_STAT_ENV_END,
    VIR_PROCESS_STAT_EXIT_CODE,
};

/*
 * At the time of writing there are 52 values reported in /proc/.../stat, the
 * line below checks that the last one has the right value, increase accordingly
 * based on proc(5) whenever adding new fields.
*/
G_STATIC_ASSERT(VIR_PROCESS_STAT_EXIT_CODE == 51);

typedef enum {
    VIR_PROCESS_NAMESPACE_MNT = (1 << 1),
    VIR_PROCESS_NAMESPACE_IPC = (1 << 2),
    VIR_PROCESS_NAMESPACE_NET = (1 << 3),
    VIR_PROCESS_NAMESPACE_PID = (1 << 4),
    VIR_PROCESS_NAMESPACE_USER = (1 << 5),
    VIR_PROCESS_NAMESPACE_UTS = (1 << 6),
} virProcessNamespaceFlags;

int virProcessNamespaceAvailable(unsigned int ns);

int virProcessGetStatInfo(unsigned long long *cpuTime,
                          unsigned long long *userTime,
                          unsigned long long *sysTime,
                          int *lastCpu,
                          unsigned long long *vm_rss,
                          pid_t pid,
                          pid_t tid);
int virProcessGetSchedInfo(unsigned long long *cpuWait,
                           pid_t pid,
                           pid_t tid);

int virProcessSchedCoreAvailable(void);

int virProcessSchedCoreCreate(void);

int virProcessSchedCoreShareFrom(pid_t pid);

int virProcessSchedCoreShareTo(pid_t pid);
