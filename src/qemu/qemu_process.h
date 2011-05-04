/*
 * qemu_process.c: QEMU process management
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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

int qemuProcessPrepareMonitorChr(struct qemud_driver *driver,
                                 virDomainChrSourceDefPtr monConfig,
                                 const char *vm);

int qemuProcessStartCPUs(struct qemud_driver *driver,
                         virDomainObjPtr vm,
                         virConnectPtr conn,
                         virDomainRunningReason reason);
int qemuProcessStopCPUs(struct qemud_driver *driver,
                        virDomainObjPtr vm,
                        virDomainPausedReason reason);

void qemuProcessAutostartAll(struct qemud_driver *driver);
void qemuProcessReconnectAll(virConnectPtr conn, struct qemud_driver *driver);

int qemuProcessAssignPCIAddresses(virDomainDefPtr def);

int qemuProcessStart(virConnectPtr conn,
                     struct qemud_driver *driver,
                     virDomainObjPtr vm,
                     const char *migrateFrom,
                     bool start_paused,
                     int stdin_fd,
                     const char *stdin_path,
                     enum virVMOperationType vmop);

void qemuProcessStop(struct qemud_driver *driver,
                     virDomainObjPtr vm,
                     int migrated,
                     virDomainShutoffReason reason);

void qemuProcessKill(virDomainObjPtr vm);

#endif /* __QEMU_PROCESS_H__ */
