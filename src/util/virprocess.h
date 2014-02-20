/*
 * virprocess.h: interaction with processes
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

#ifndef __VIR_PROCESS_H__
# define __VIR_PROCESS_H__

# include <sys/types.h>

# include "internal.h"
# include "virbitmap.h"

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

int virProcessGetAffinity(pid_t pid,
                          virBitmapPtr *map,
                          int maxcpu);

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

/* Callback to run code within the mount namespace tied to the given
 * pid.  This function must use only async-signal-safe functions, as
 * it gets run after a fork of a multi-threaded process.  The return
 * value of this function is passed to _exit(), except that a
 * negative value is treated as EXIT_CANCELED.  */
typedef int (*virProcessNamespaceCallback)(pid_t pid, void *opaque);

int virProcessRunInMountNamespace(pid_t pid,
                                  virProcessNamespaceCallback cb,
                                  void *opaque);
#endif /* __VIR_PROCESS_H__ */
