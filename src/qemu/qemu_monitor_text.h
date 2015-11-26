/*
 * qemu_monitor_text.h: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2009, 2011-2012 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */


#ifndef QEMU_MONITOR_TEXT_H
# define QEMU_MONITOR_TEXT_H

# include "internal.h"

# include "qemu_monitor.h"

int qemuMonitorTextIOProcess(qemuMonitorPtr mon,
                             const char *data,
                             size_t len,
                             qemuMonitorMessagePtr msg);

int qemuMonitorTextCommandWithFd(qemuMonitorPtr mon,
                                 const char *cmd,
                                 int scm_fd,
                                 char **reply);

int qemuMonitorTextStartCPUs(qemuMonitorPtr mon,
                             virConnectPtr conn);
int qemuMonitorTextStopCPUs(qemuMonitorPtr mon);
int qemuMonitorTextGetStatus(qemuMonitorPtr mon,
                             bool *running,
                             virDomainPausedReason *reason);

int qemuMonitorTextSystemPowerdown(qemuMonitorPtr mon);
int qemuMonitorTextSystemReset(qemuMonitorPtr mon);

int qemuMonitorTextGetCPUInfo(qemuMonitorPtr mon,
                              int **pids);
int qemuMonitorTextGetVirtType(qemuMonitorPtr mon,
                               virDomainVirtType *virtType);
int qemuMonitorTextGetBalloonInfo(qemuMonitorPtr mon,
                                  unsigned long long *currmem);
int qemuMonitorTextGetMemoryStats(qemuMonitorPtr mon,
                                  virDomainMemoryStatPtr stats,
                                  unsigned int nr_stats);
int qemuMonitorTextGetBlockInfo(qemuMonitorPtr mon,
                                virHashTablePtr table);

int qemuMonitorTextGetAllBlockStatsInfo(qemuMonitorPtr mon,
                                        virHashTablePtr hash);
int qemuMonitorTextBlockResize(qemuMonitorPtr mon,
                               const char *device,
                               unsigned long long size);
int qemuMonitorTextSetVNCPassword(qemuMonitorPtr mon,
                                  const char *password);
int qemuMonitorTextSetPassword(qemuMonitorPtr mon,
                               const char *protocol,
                               const char *password,
                               const char *action_if_connected);
int qemuMonitorTextExpirePassword(qemuMonitorPtr mon,
                                  const char *protocol,
                                  const char *expire_time);
int qemuMonitorTextSetBalloon(qemuMonitorPtr mon,
                              unsigned long long newmem);
int qemuMonitorTextSetCPU(qemuMonitorPtr mon, int cpu, bool online);

int qemuMonitorTextEjectMedia(qemuMonitorPtr mon,
                              const char *dev_name,
                              bool force);
int qemuMonitorTextChangeMedia(qemuMonitorPtr mon,
                               const char *dev_name,
                               const char *newmedia,
                               const char *format);


int qemuMonitorTextSaveVirtualMemory(qemuMonitorPtr mon,
                                     unsigned long long offset,
                                     size_t length,
                                     const char *path);
int qemuMonitorTextSavePhysicalMemory(qemuMonitorPtr mon,
                                      unsigned long long offset,
                                      size_t length,
                                      const char *path);

int qemuMonitorTextSetMigrationSpeed(qemuMonitorPtr mon,
                                     unsigned long bandwidth);

int qemuMonitorTextSetMigrationDowntime(qemuMonitorPtr mon,
                                        unsigned long long downtime);

int qemuMonitorTextGetMigrationStats(qemuMonitorPtr mon,
                                     qemuMonitorMigrationStatsPtr stats);

int qemuMonitorTextMigrate(qemuMonitorPtr mon,
                           unsigned int flags,
                           const char *uri);

int qemuMonitorTextMigrateCancel(qemuMonitorPtr mon);

int qemuMonitorTextGraphicsRelocate(qemuMonitorPtr mon,
                                    int type,
                                    const char *hostname,
                                    int port,
                                    int tlsPort,
                                    const char *tlsSubject);

int qemuMonitorTextAddUSBDisk(qemuMonitorPtr mon,
                              const char *path);

int qemuMonitorTextAddUSBDeviceExact(qemuMonitorPtr mon,
                                     int bus,
                                     int dev);
int qemuMonitorTextAddUSBDeviceMatch(qemuMonitorPtr mon,
                                     int vendor,
                                     int product);


int qemuMonitorTextAddPCIHostDevice(qemuMonitorPtr mon,
                                    virDevicePCIAddress *hostAddr,
                                    virDevicePCIAddress *guestAddr);

int qemuMonitorTextAddPCIDisk(qemuMonitorPtr mon,
                              const char *path,
                              const char *bus,
                              virDevicePCIAddress *guestAddr);

int qemuMonitorTextAddPCINetwork(qemuMonitorPtr mon,
                                 const char *nicstr,
                                 virDevicePCIAddress *guestAddr);

int qemuMonitorTextRemovePCIDevice(qemuMonitorPtr mon,
                                   virDevicePCIAddress *guestAddr);

int qemuMonitorTextSendFileHandle(qemuMonitorPtr mon,
                                  const char *fdname,
                                  int fd);

int qemuMonitorTextCloseFileHandle(qemuMonitorPtr mon,
                                   const char *fdname);

int qemuMonitorTextAddHostNetwork(qemuMonitorPtr mon,
                                  const char *netstr);

int qemuMonitorTextRemoveHostNetwork(qemuMonitorPtr mon,
                                     int vlan,
                                     const char *netname);

int qemuMonitorTextAddNetdev(qemuMonitorPtr mon,
                             const char *netdevstr);

int qemuMonitorTextRemoveNetdev(qemuMonitorPtr mon,
                                const char *alias);

int qemuMonitorTextGetChardevInfo(qemuMonitorPtr mon,
                                  virHashTablePtr info);

int qemuMonitorTextAttachPCIDiskController(qemuMonitorPtr mon,
                                           const char *bus,
                                           virDevicePCIAddress *guestAddr);

int qemuMonitorTextAttachDrive(qemuMonitorPtr mon,
                               const char *drivestr,
                               virDevicePCIAddress *controllerAddr,
                               virDomainDeviceDriveAddress *driveAddr);

int qemuMonitorTextGetAllPCIAddresses(qemuMonitorPtr mon,
                                      qemuMonitorPCIAddress **addrs);

int qemuMonitorTextAddDevice(qemuMonitorPtr mon,
                             const char *devicestr);

int qemuMonitorTextDelDevice(qemuMonitorPtr mon,
                             const char *devalias);

int qemuMonitorTextAddDrive(qemuMonitorPtr mon,
                             const char *drivestr);

int qemuMonitorTextDriveDel(qemuMonitorPtr mon,
                             const char *drivestr);

int qemuMonitorTextSetDrivePassphrase(qemuMonitorPtr mon,
                                      const char *alias,
                                      const char *passphrase);

int qemuMonitorTextCreateSnapshot(qemuMonitorPtr mon, const char *name);
int qemuMonitorTextLoadSnapshot(qemuMonitorPtr mon, const char *name);
int qemuMonitorTextDeleteSnapshot(qemuMonitorPtr mon, const char *name);

int qemuMonitorTextArbitraryCommand(qemuMonitorPtr mon, const char *cmd,
                                    char **reply);

int qemuMonitorTextInjectNMI(qemuMonitorPtr mon);

int qemuMonitorTextSendKey(qemuMonitorPtr mon,
                           unsigned int holdtime,
                           unsigned int *keycodes,
                           unsigned int nkeycodes);

int qemuMonitorTextScreendump(qemuMonitorPtr mon, const char *file);

int qemuMonitorTextSetLink(qemuMonitorPtr mon,
                           const char *name,
                           virDomainNetInterfaceLinkState state);

int qemuMonitorTextOpenGraphics(qemuMonitorPtr mon,
                                const char *protocol,
                                const char *fdname,
                                bool skipauth);

int qemuMonitorTextSetBlockIoThrottle(qemuMonitorPtr mon,
                                      const char *device,
                                      virDomainBlockIoTuneInfoPtr info);

int qemuMonitorTextGetBlockIoThrottle(qemuMonitorPtr mon,
                                      const char *device,
                                      virDomainBlockIoTuneInfoPtr reply);

#endif /* QEMU_MONITOR_TEXT_H */
