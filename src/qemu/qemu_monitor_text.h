/*
 * qemu_monitor_text.h: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */


#ifndef QEMU_MONITOR_TEXT_H
#define QEMU_MONITOR_TEXT_H

#include "internal.h"

#include "domain_conf.h"


/* Formal APIs for each required monitor command */

int qemuMonitorStartCPUs(virConnectPtr conn,
                         const virDomainObjPtr vm);
int qemuMonitorStopCPUs(const virDomainObjPtr vm);

int qemuMonitorSystemPowerdown(const virDomainObjPtr vm);

int qemuMonitorGetCPUInfo(const virDomainObjPtr vm,
                          int **pids);
int qemuMonitorGetBalloonInfo(const virDomainObjPtr vm,
                              unsigned long *currmem);
int qemuMonitorGetBlockStatsInfo(const virDomainObjPtr vm,
                                 const char *devname,
                                 long long *rd_req,
                                 long long *rd_bytes,
                                 long long *wr_req,
                                 long long *wr_bytes,
                                 long long *errs);


int qemuMonitorSetVNCPassword(const virDomainObjPtr vm,
                              const char *password);
int qemuMonitorSetBalloon(const virDomainObjPtr vm,
                          unsigned long newmem);

/* XXX should we pass the virDomainDiskDefPtr instead
 * and hide devname details inside monitor. Reconsider
 * this when doing the QMP implementation
 */
int qemuMonitorEjectMedia(const virDomainObjPtr vm,
                          const char *devname);
int qemuMonitorChangeMedia(const virDomainObjPtr vm,
                           const char *devname,
                           const char *newmedia);


int qemuMonitorSaveVirtualMemory(const virDomainObjPtr vm,
                                 unsigned long long offset,
                                 size_t length,
                                 const char *path);
int qemuMonitorSavePhysicalMemory(const virDomainObjPtr vm,
                                  unsigned long long offset,
                                  size_t length,
                                  const char *path);

int qemuMonitorSetMigrationSpeed(const virDomainObjPtr vm,
                                 unsigned long bandwidth);

enum {
    QEMU_MONITOR_MIGRATION_STATUS_INACTIVE,
    QEMU_MONITOR_MIGRATION_STATUS_ACTIVE,
    QEMU_MONITOR_MIGRATION_STATUS_COMPLETED,
    QEMU_MONITOR_MIGRATION_STATUS_ERROR,
    QEMU_MONITOR_MIGRATION_STATUS_CANCELLED,

    QEMU_MONITOR_MIGRATION_STATUS_LAST
};

int qemuMonitorGetMigrationStatus(const virDomainObjPtr vm,
                                  int *status,
                                  unsigned long long *transferred,
                                  unsigned long long *remaining,
                                  unsigned long long *total);

int qemuMonitorMigrateToHost(const virDomainObjPtr vm,
                             int background,
                             const char *hostname,
                             int port);

int qemuMonitorMigrateToCommand(const virDomainObjPtr vm,
                                int background,
                                const char * const *argv,
                                const char *target);

int qemuMonitorMigrateToUnix(const virDomainObjPtr vm,
                             int background,
                             const char *unixfile);

int qemuMonitorMigrateCancel(const virDomainObjPtr vm);


/* XXX disk driver type eg,  qcow/etc.
 * XXX cache mode
 */
int qemuMonitorAddUSBDisk(const virDomainObjPtr vm,
                          const char *path);

int qemuMonitorAddUSBDeviceExact(const virDomainObjPtr vm,
                                 int bus,
                                 int dev);
int qemuMonitorAddUSBDeviceMatch(const virDomainObjPtr vm,
                                 int vendor,
                                 int product);


int qemuMonitorAddPCIHostDevice(const virDomainObjPtr vm,
                                unsigned hostDomain,
                                unsigned hostBus,
                                unsigned hostSlot,
                                unsigned hostFunction,
                                unsigned *guestDomain,
                                unsigned *guestBus,
                                unsigned *guestSlot);

/* XXX disk driver type eg,  qcow/etc.
 * XXX cache mode
 */
int qemuMonitorAddPCIDisk(const virDomainObjPtr vm,
                          const char *path,
                          const char *bus,
                          unsigned *guestDomain,
                          unsigned *guestBus,
                          unsigned *guestSlot);

/* XXX do we really want to hardcode 'nicstr' as the
 * sendable item here
 */
int qemuMonitorAddPCINetwork(const virDomainObjPtr vm,
                             const char *nicstr,
                             unsigned *guestDomain,
                             unsigned *guestBus,
                             unsigned *guestSlot);

int qemuMonitorRemovePCIDevice(const virDomainObjPtr vm,
                               unsigned guestDomain,
                               unsigned guestBus,
                               unsigned guestSlot);


int qemuMonitorSendFileHandle(const virDomainObjPtr vm,
                              const char *fdname,
                              int fd);

int qemuMonitorCloseFileHandle(const virDomainObjPtr vm,
                               const char *fdname);


/* XXX do we relaly want to hardcode 'netstr' as the
 * sendable item here
 */
int qemuMonitorAddHostNetwork(const virDomainObjPtr vm,
                              const char *netstr);

int qemuMonitorRemoveHostNetwork(const virDomainObjPtr vm,
                                 int vlan,
                                 const char *netname);

#endif /* QEMU_MONITOR_TEXT_H */
