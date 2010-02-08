/*
 * qemu_monitor.h: interaction with QEMU monitor console
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


#ifndef QEMU_MONITOR_H
#define QEMU_MONITOR_H

#include "internal.h"

#include "domain_conf.h"
#include "hash.h"

typedef struct _qemuMonitor qemuMonitor;
typedef qemuMonitor *qemuMonitorPtr;

typedef struct _qemuMonitorMessage qemuMonitorMessage;
typedef qemuMonitorMessage *qemuMonitorMessagePtr;

typedef int (*qemuMonitorPasswordHandler)(qemuMonitorPtr mon,
                                          qemuMonitorMessagePtr msg,
                                          const char *data,
                                          size_t len,
                                          void *opaque);

struct _qemuMonitorMessage {
    int txFD;

    char *txBuffer;
    int txOffset;
    int txLength;

    char *rxBuffer;
    int rxLength;

    int finished;

    int lastErrno;

    qemuMonitorPasswordHandler passwordHandler;
    void *passwordOpaque;
};

typedef struct _qemuMonitorCallbacks qemuMonitorCallbacks;
typedef qemuMonitorCallbacks *qemuMonitorCallbacksPtr;
struct _qemuMonitorCallbacks {
    void (*eofNotify)(qemuMonitorPtr mon,
                      virDomainObjPtr vm,
                      int withError);
    /* XXX we'd really like to avoid virCOnnectPtr here
     * It is required so the callback can find the active
     * secret driver. Need to change this to work like the
     * security drivers do, to avoid this
     */
    int (*diskSecretLookup)(qemuMonitorPtr mon,
                            virConnectPtr conn,
                            virDomainObjPtr vm,
                            const char *path,
                            char **secret,
                            size_t *secretLen);

    int (*domainShutdown)(qemuMonitorPtr mon,
                          virDomainObjPtr vm);
    int (*domainReset)(qemuMonitorPtr mon,
                       virDomainObjPtr vm);
    int (*domainPowerdown)(qemuMonitorPtr mon,
                           virDomainObjPtr vm);
    int (*domainStop)(qemuMonitorPtr mon,
                      virDomainObjPtr vm);
};


char *qemuMonitorEscapeArg(const char *in);
char *qemuMonitorEscapeShell(const char *in);

qemuMonitorPtr qemuMonitorOpen(virDomainObjPtr vm,
                               virDomainChrDefPtr config,
                               int json,
                               qemuMonitorCallbacksPtr cb);

int qemuMonitorClose(qemuMonitorPtr mon);

int qemuMonitorSetCapabilities(qemuMonitorPtr mon);

void qemuMonitorLock(qemuMonitorPtr mon);
void qemuMonitorUnlock(qemuMonitorPtr mon);

int qemuMonitorRef(qemuMonitorPtr mon);
int qemuMonitorUnref(qemuMonitorPtr mon);

/* This API is for use by the internal Text/JSON monitor impl code only */
int qemuMonitorSend(qemuMonitorPtr mon,
                    qemuMonitorMessagePtr msg);

/* XXX same comment about virConnectPtr as above */
int qemuMonitorGetDiskSecret(qemuMonitorPtr mon,
                             virConnectPtr conn,
                             const char *path,
                             char **secret,
                             size_t *secretLen);

int qemuMonitorEmitShutdown(qemuMonitorPtr mon);
int qemuMonitorEmitReset(qemuMonitorPtr mon);
int qemuMonitorEmitPowerdown(qemuMonitorPtr mon);
int qemuMonitorEmitStop(qemuMonitorPtr mon);

int qemuMonitorStartCPUs(qemuMonitorPtr mon,
                         virConnectPtr conn);
int qemuMonitorStopCPUs(qemuMonitorPtr mon);

int qemuMonitorSystemPowerdown(qemuMonitorPtr mon);

int qemuMonitorGetCPUInfo(qemuMonitorPtr mon,
                          int **pids);
int qemuMonitorGetBalloonInfo(qemuMonitorPtr mon,
                              unsigned long *currmem);
int qemuMonitorGetBlockStatsInfo(qemuMonitorPtr mon,
                                 const char *devname,
                                 long long *rd_req,
                                 long long *rd_bytes,
                                 long long *wr_req,
                                 long long *wr_bytes,
                                 long long *errs);


int qemuMonitorSetVNCPassword(qemuMonitorPtr mon,
                              const char *password);
int qemuMonitorSetBalloon(qemuMonitorPtr mon,
                          unsigned long newmem);
int qemuMonitorSetCPU(qemuMonitorPtr mon, int cpu, int online);


/* XXX should we pass the virDomainDiskDefPtr instead
 * and hide devname details inside monitor. Reconsider
 * this when doing the QMP implementation
 *
 * XXXX 'eject' has gained a 'force' flag we might like
 * to make use of...
 */
int qemuMonitorEjectMedia(qemuMonitorPtr mon,
                          const char *devname);
int qemuMonitorChangeMedia(qemuMonitorPtr mon,
                           const char *devname,
                           const char *newmedia,
                           const char *format);


int qemuMonitorSaveVirtualMemory(qemuMonitorPtr mon,
                                 unsigned long long offset,
                                 size_t length,
                                 const char *path);
int qemuMonitorSavePhysicalMemory(qemuMonitorPtr mon,
                                  unsigned long long offset,
                                  size_t length,
                                  const char *path);

int qemuMonitorSetMigrationSpeed(qemuMonitorPtr mon,
                                 unsigned long bandwidth);

enum {
    QEMU_MONITOR_MIGRATION_STATUS_INACTIVE,
    QEMU_MONITOR_MIGRATION_STATUS_ACTIVE,
    QEMU_MONITOR_MIGRATION_STATUS_COMPLETED,
    QEMU_MONITOR_MIGRATION_STATUS_ERROR,
    QEMU_MONITOR_MIGRATION_STATUS_CANCELLED,

    QEMU_MONITOR_MIGRATION_STATUS_LAST
};

VIR_ENUM_DECL(qemuMonitorMigrationStatus)

int qemuMonitorGetMigrationStatus(qemuMonitorPtr mon,
                                  int *status,
                                  unsigned long long *transferred,
                                  unsigned long long *remaining,
                                  unsigned long long *total);

int qemuMonitorMigrateToHost(qemuMonitorPtr mon,
                             int background,
                             const char *hostname,
                             int port);

int qemuMonitorMigrateToCommand(qemuMonitorPtr mon,
                                int background,
                                const char * const *argv,
                                const char *target);

int qemuMonitorMigrateToUnix(qemuMonitorPtr mon,
                             int background,
                             const char *unixfile);

int qemuMonitorMigrateCancel(qemuMonitorPtr mon);


/* XXX disk driver type eg,  qcow/etc.
 * XXX cache mode
 */
int qemuMonitorAddUSBDisk(qemuMonitorPtr mon,
                          const char *path);

int qemuMonitorAddUSBDeviceExact(qemuMonitorPtr mon,
                                 int bus,
                                 int dev);
int qemuMonitorAddUSBDeviceMatch(qemuMonitorPtr mon,
                                 int vendor,
                                 int product);


int qemuMonitorAddPCIHostDevice(qemuMonitorPtr mon,
                                virDomainDevicePCIAddress *hostAddr,
                                virDomainDevicePCIAddress *guestAddr);

/* XXX disk driver type eg,  qcow/etc.
 * XXX cache mode
 */
int qemuMonitorAddPCIDisk(qemuMonitorPtr mon,
                          const char *path,
                          const char *bus,
                          virDomainDevicePCIAddress *guestAddr);

/* XXX do we really want to hardcode 'nicstr' as the
 * sendable item here
 */
int qemuMonitorAddPCINetwork(qemuMonitorPtr mon,
                             const char *nicstr,
                             virDomainDevicePCIAddress *guestAddr);

int qemuMonitorRemovePCIDevice(qemuMonitorPtr mon,
                               virDomainDevicePCIAddress *guestAddr);


int qemuMonitorSendFileHandle(qemuMonitorPtr mon,
                              const char *fdname,
                              int fd);

int qemuMonitorCloseFileHandle(qemuMonitorPtr mon,
                               const char *fdname);


/* XXX do we really want to hardcode 'netstr' as the
 * sendable item here
 */
int qemuMonitorAddHostNetwork(qemuMonitorPtr mon,
                              const char *netstr);

int qemuMonitorRemoveHostNetwork(qemuMonitorPtr mon,
                                 int vlan,
                                 const char *netname);

int qemuMonitorGetPtyPaths(qemuMonitorPtr mon,
                           virHashTablePtr paths);

int qemuMonitorAttachPCIDiskController(qemuMonitorPtr mon,
                                       const char *bus,
                                       virDomainDevicePCIAddress *guestAddr);

int qemuMonitorAttachDrive(qemuMonitorPtr mon,
                           const char *drivestr,
                           virDomainDevicePCIAddress *controllerAddr,
                           virDomainDeviceDriveAddress *driveAddr);


typedef struct _qemuMonitorPCIAddress qemuMonitorPCIAddress;
struct _qemuMonitorPCIAddress {
    unsigned int vendor;
    unsigned int product;
    virDomainDevicePCIAddress addr;
};

int qemuMonitorGetAllPCIAddresses(qemuMonitorPtr mon,
                                  qemuMonitorPCIAddress **addrs);

int qemuMonitorAddDevice(qemuMonitorPtr mon,
                         const char *devicestr);

int qemuMonitorDelDevice(qemuMonitorPtr mon,
                         const char *devicestr);

int qemuMonitorAddDrive(qemuMonitorPtr mon,
                        const char *drivestr);

int qemuMonitorSetDrivePassphrase(qemuMonitorPtr mon,
                                  const char *alias,
                                  const char *passphrase);

#endif /* QEMU_MONITOR_H */
