/*
 * qemu_monitor_json.h: interaction with QEMU monitor console
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


#ifndef QEMU_MONITOR_JSON_H
# define QEMU_MONITOR_JSON_H

# include "internal.h"

# include "qemu_monitor.h"

int qemuMonitorJSONIOProcess(qemuMonitorPtr mon,
                             const char *data,
                             size_t len,
                             qemuMonitorMessagePtr msg);

int qemuMonitorJSONSetCapabilities(qemuMonitorPtr mon);

int qemuMonitorJSONStartCPUs(qemuMonitorPtr mon,
                             virConnectPtr conn);
int qemuMonitorJSONStopCPUs(qemuMonitorPtr mon);

int qemuMonitorJSONSystemPowerdown(qemuMonitorPtr mon);

int qemuMonitorJSONGetCPUInfo(qemuMonitorPtr mon,
                              int **pids);
int qemuMonitorJSONGetBalloonInfo(qemuMonitorPtr mon,
                                  unsigned long *currmem);
int qemuMonitorJSONGetMemoryStats(qemuMonitorPtr mon,
                                  virDomainMemoryStatPtr stats,
                                  unsigned int nr_stats);
int qemuMonitorJSONGetBlockStatsInfo(qemuMonitorPtr mon,
                                     const char *devname,
                                     long long *rd_req,
                                     long long *rd_bytes,
                                     long long *wr_req,
                                     long long *wr_bytes,
                                     long long *errs);


int qemuMonitorJSONSetVNCPassword(qemuMonitorPtr mon,
                                  const char *password);
int qemuMonitorJSONSetBalloon(qemuMonitorPtr mon,
                              unsigned long newmem);
int qemuMonitorJSONSetCPU(qemuMonitorPtr mon, int cpu, int online);

int qemuMonitorJSONEjectMedia(qemuMonitorPtr mon,
                              const char *devname);
int qemuMonitorJSONChangeMedia(qemuMonitorPtr mon,
                               const char *devname,
                               const char *newmedia,
                               const char *format);


int qemuMonitorJSONSaveVirtualMemory(qemuMonitorPtr mon,
                                     unsigned long long offset,
                                     size_t length,
                                     const char *path);
int qemuMonitorJSONSavePhysicalMemory(qemuMonitorPtr mon,
                                      unsigned long long offset,
                                      size_t length,
                                      const char *path);

int qemuMonitorJSONSetMigrationSpeed(qemuMonitorPtr mon,
                                     unsigned long bandwidth);

int qemuMonitorJSONSetMigrationDowntime(qemuMonitorPtr mon,
                                        unsigned long long downtime);

int qemuMonitorJSONGetMigrationStatus(qemuMonitorPtr mon,
                                      int *status,
                                      unsigned long long *transferred,
                                      unsigned long long *remaining,
                                      unsigned long long *total);

int qemuMonitorJSONMigrateToHost(qemuMonitorPtr mon,
                                 int background,
                                 const char *hostname,
                                 int port);

int qemuMonitorJSONMigrateToCommand(qemuMonitorPtr mon,
                                    int background,
                                    const char * const *argv);

int qemuMonitorJSONMigrateToFile(qemuMonitorPtr mon,
                                 int background,
                                 const char * const *argv,
                                 const char *target,
                                 unsigned long long offset);

int qemuMonitorJSONMigrateToUnix(qemuMonitorPtr mon,
                                 int background,
                                 const char *unixfile);

int qemuMonitorJSONMigrateCancel(qemuMonitorPtr mon);

int qemuMonitorJSONAddUSBDisk(qemuMonitorPtr mon,
                              const char *path);

int qemuMonitorJSONAddUSBDeviceExact(qemuMonitorPtr mon,
                                     int bus,
                                     int dev);
int qemuMonitorJSONAddUSBDeviceMatch(qemuMonitorPtr mon,
                                     int vendor,
                                     int product);


int qemuMonitorJSONAddPCIHostDevice(qemuMonitorPtr mon,
                                    virDomainDevicePCIAddress *hostAddr,
                                    virDomainDevicePCIAddress *guestAddr);

int qemuMonitorJSONAddPCIDisk(qemuMonitorPtr mon,
                              const char *path,
                              const char *bus,
                              virDomainDevicePCIAddress *guestAddr);

int qemuMonitorJSONAddPCINetwork(qemuMonitorPtr mon,
                                 const char *nicstr,
                                 virDomainDevicePCIAddress *guestAddr);

int qemuMonitorJSONRemovePCIDevice(qemuMonitorPtr mon,
                                   virDomainDevicePCIAddress *guestAddr);

int qemuMonitorJSONSendFileHandle(qemuMonitorPtr mon,
                                  const char *fdname,
                                  int fd);

int qemuMonitorJSONCloseFileHandle(qemuMonitorPtr mon,
                                   const char *fdname);

int qemuMonitorJSONAddHostNetwork(qemuMonitorPtr mon,
                                  const char *netstr);

int qemuMonitorJSONRemoveHostNetwork(qemuMonitorPtr mon,
                                     int vlan,
                                     const char *netname);

int qemuMonitorJSONGetPtyPaths(qemuMonitorPtr mon,
                               virHashTablePtr paths);

int qemuMonitorJSONAttachPCIDiskController(qemuMonitorPtr mon,
                                           const char *bus,
                                           virDomainDevicePCIAddress *guestAddr);

int qemuMonitorJSONAttachDrive(qemuMonitorPtr mon,
                               const char *drivestr,
                               virDomainDevicePCIAddress *controllerAddr,
                               virDomainDeviceDriveAddress *driveAddr);

int qemuMonitorJSONGetAllPCIAddresses(qemuMonitorPtr mon,
                                      qemuMonitorPCIAddress **addrs);

int qemuMonitorJSONAddDevice(qemuMonitorPtr mon,
                             const char *devicestr);

int qemuMonitorJSONDelDevice(qemuMonitorPtr mon,
                             const char *devalias);

int qemuMonitorJSONAddDrive(qemuMonitorPtr mon,
                            const char *drivestr);

int qemuMonitorJSONSetDrivePassphrase(qemuMonitorPtr mon,
                                      const char *alias,
                                      const char *passphrase);

int qemuMonitorJSONCreateSnapshot(qemuMonitorPtr mon, const char *name);
int qemuMonitorJSONLoadSnapshot(qemuMonitorPtr mon, const char *name);
int qemuMonitorJSONDeleteSnapshot(qemuMonitorPtr mon, const char *name);

#endif /* QEMU_MONITOR_JSON_H */
