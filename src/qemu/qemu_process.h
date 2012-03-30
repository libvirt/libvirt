/*
 * qemu_process.c: QEMU process management
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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

#ifndef __QEMU_PROCESS_H__
# define __QEMU_PROCESS_H__

# include "qemu_conf.h"
# include "qemu_domain.h"

int qemuProcessPrepareMonitorChr(struct qemud_driver *driver,
                                 virDomainChrSourceDefPtr monConfig,
                                 const char *vm);

int qemuProcessStartCPUs(struct qemud_driver *driver,
                         virDomainObjPtr vm,
                         virConnectPtr conn,
                         virDomainRunningReason reason,
                         enum qemuDomainAsyncJob asyncJob);
int qemuProcessStopCPUs(struct qemud_driver *driver,
                        virDomainObjPtr vm,
                        virDomainPausedReason reason,
                        enum qemuDomainAsyncJob asyncJob);

void qemuProcessAutostartAll(struct qemud_driver *driver);
void qemuProcessReconnectAll(virConnectPtr conn, struct qemud_driver *driver);

int qemuProcessAssignPCIAddresses(virDomainDefPtr def);

int qemuProcessStart(virConnectPtr conn,
                     struct qemud_driver *driver,
                     virDomainObjPtr vm,
                     const char *migrateFrom,
                     bool cold_boot,
                     bool start_paused,
                     bool autodestroy,
                     int stdin_fd,
                     const char *stdin_path,
                     virDomainSnapshotObjPtr snapshot,
                     enum virNetDevVPortProfileOp vmop);

void qemuProcessStop(struct qemud_driver *driver,
                     virDomainObjPtr vm,
                     int migrated,
                     virDomainShutoffReason reason);

int qemuProcessAttach(virConnectPtr conn,
                      struct qemud_driver *driver,
                      virDomainObjPtr vm,
                      pid_t pid,
                      const char *pidfile,
                      virDomainChrSourceDefPtr monConfig,
                      bool monJSON);

typedef enum {
   VIR_QEMU_PROCESS_KILL_FORCE  = 1 << 0,
   VIR_QEMU_PROCESS_KILL_NOWAIT = 1 << 1,
   VIR_QEMU_PROCESS_KILL_NOCHECK = 1 << 2, /* bypass the running vm check */
} virQemuProcessKillMode;

int qemuProcessKill(struct qemud_driver *driver,
                    virDomainObjPtr vm, unsigned int flags);

int qemuProcessAutoDestroyInit(struct qemud_driver *driver);
void qemuProcessAutoDestroyRun(struct qemud_driver *driver,
                               virConnectPtr conn);
void qemuProcessAutoDestroyShutdown(struct qemud_driver *driver);
int qemuProcessAutoDestroyAdd(struct qemud_driver *driver,
                              virDomainObjPtr vm,
                              virConnectPtr conn);
int qemuProcessAutoDestroyRemove(struct qemud_driver *driver,
                                 virDomainObjPtr vm);
bool qemuProcessAutoDestroyActive(struct qemud_driver *driver,
                                  virDomainObjPtr vm);

#endif /* __QEMU_PROCESS_H__ */
