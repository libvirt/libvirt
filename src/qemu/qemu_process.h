/*
 * qemu_process.h: QEMU process management
 *
 * Copyright (C) 2006-2012, 2015 Red Hat, Inc.
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

#include "qemu_conf.h"
#include "qemu_domain.h"
#include "qemu_saveimage.h"
#include "vireventthread.h"

int qemuProcessPrepareMonitorChr(virDomainChrSourceDef *monConfig,
                                 const char *domainDir);

int qemuProcessStartCPUs(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virDomainRunningReason reason,
                         virDomainAsyncJob asyncJob);
int qemuProcessStopCPUs(virQEMUDriver *driver,
                        virDomainObj *vm,
                        virDomainPausedReason reason,
                        virDomainAsyncJob asyncJob);

int qemuProcessBuildDestroyMemoryPaths(virQEMUDriver *driver,
                                       virDomainObj *vm,
                                       virDomainMemoryDef *mem,
                                       bool build);

int qemuProcessDestroyMemoryBackingPath(virQEMUDriver *driver,
                                        virDomainObj *vm,
                                        virDomainMemoryDef *mem);

void qemuProcessReconnectAll(virQEMUDriver *driver);

typedef struct _qemuProcessIncomingDef qemuProcessIncomingDef;
struct _qemuProcessIncomingDef {
    char *address; /* address where QEMU is supposed to listen */
    char *uri; /* used when calling migrate-incoming QMP command */
    int fd; /* for fd:N URI */
    const char *path; /* path associated with fd */
};

qemuProcessIncomingDef *qemuProcessIncomingDefNew(virQEMUCaps *qemuCaps,
                                                    const char *listenAddress,
                                                    const char *migrateFrom,
                                                    int fd,
                                                    const char *path);
void qemuProcessIncomingDefFree(qemuProcessIncomingDef *inc);

int qemuProcessBeginJob(virDomainObj *vm,
                        virDomainJobOperation operation,
                        unsigned int apiFlags);
void qemuProcessEndJob(virDomainObj *vm);

typedef enum {
    VIR_QEMU_PROCESS_START_COLD         = 1 << 0,
    VIR_QEMU_PROCESS_START_PAUSED       = 1 << 1,
    VIR_QEMU_PROCESS_START_AUTODESTROY  = 1 << 2,
    VIR_QEMU_PROCESS_START_PRETEND      = 1 << 3,
    VIR_QEMU_PROCESS_START_NEW          = 1 << 4, /* internal, new VM is starting */
    VIR_QEMU_PROCESS_START_GEN_VMID     = 1 << 5, /* Generate a new VMID */
    VIR_QEMU_PROCESS_START_RESET_NVRAM  = 1 << 6, /* Re-initialize NVRAM from template */
} qemuProcessStartFlags;

int qemuProcessStart(virConnectPtr conn,
                     virQEMUDriver *driver,
                     virDomainObj *vm,
                     virCPUDef *updatedCPU,
                     virDomainAsyncJob asyncJob,
                     const char *migrateFrom,
                     int stdin_fd,
                     const char *stdin_path,
                     virDomainMomentObj *snapshot,
                     virNetDevVPortProfileOp vmop,
                     unsigned int flags);

int qemuProcessStartWithMemoryState(virConnectPtr conn,
                                    virQEMUDriver *driver,
                                    virDomainObj *vm,
                                    int *fd,
                                    const char *path,
                                    virDomainMomentObj *snapshot,
                                    virQEMUSaveData *data,
                                    virDomainAsyncJob asyncJob,
                                    unsigned int start_flags,
                                    const char *reason,
                                    bool *started);

int qemuProcessCreatePretendCmdPrepare(virQEMUDriver *driver,
                                       virDomainObj *vm,
                                       const char *migrateURI,
                                       unsigned int flags);

virCommand *qemuProcessCreatePretendCmdBuild(virDomainObj *vm,
                                             const char *migrateURI);

int qemuProcessInit(virQEMUDriver *driver,
                    virDomainObj *vm,
                    virCPUDef *updatedCPU,
                    virDomainAsyncJob asyncJob,
                    bool migration,
                    unsigned int flags);

int qemuProcessPrepareDomain(virQEMUDriver *driver,
                             virDomainObj *vm,
                             unsigned int flags);

int qemuProcessOpenVhostVsock(virDomainVsockDef *vsock);

int qemuProcessPrepareHostBackendChardevHotplug(virDomainObj *vm,
                                                virDomainDeviceDef *dev)
    G_NO_INLINE;


int qemuProcessPrepareHost(virQEMUDriver *driver,
                           virDomainObj *vm,
                           unsigned int flags);

int qemuProcessPrepareHostStorageSource(virDomainObj *vm,
                                        virStorageSource *src);
int qemuProcessPrepareHostStorageSourceChain(virDomainObj *vm,
                                             virStorageSource *chain);
int qemuProcessPrepareHostStorageDisk(virDomainObj *vm,
                                  virDomainDiskDef *disk);

int qemuProcessDeleteThreadContext(virDomainObj *vm);

int qemuProcessLaunch(virConnectPtr conn,
                      virQEMUDriver *driver,
                      virDomainObj *vm,
                      virDomainAsyncJob asyncJob,
                      qemuProcessIncomingDef *incoming,
                      virDomainMomentObj *snapshot,
                      virNetDevVPortProfileOp vmop,
                      unsigned int flags);

int qemuProcessFinishStartup(virQEMUDriver *driver,
                             virDomainObj *vm,
                             virDomainAsyncJob asyncJob,
                             bool startCPUs,
                             virDomainPausedReason pausedReason);

int qemuProcessRefreshState(virQEMUDriver *driver,
                            virDomainObj *vm,
                            virDomainAsyncJob asyncJob);

typedef enum {
    VIR_QEMU_PROCESS_STOP_MIGRATED      = 1 << 0,
    VIR_QEMU_PROCESS_STOP_NO_RELABEL    = 1 << 1,
} qemuProcessStopFlags;

int qemuProcessBeginStopJob(virDomainObj *vm,
                            virDomainJob job,
                            bool forceKill);
void qemuProcessStop(virQEMUDriver *driver,
                     virDomainObj *vm,
                     virDomainShutoffReason reason,
                     virDomainAsyncJob asyncJob,
                     unsigned int flags);

typedef enum {
   VIR_QEMU_PROCESS_KILL_FORCE  = 1 << 0,
   VIR_QEMU_PROCESS_KILL_NOWAIT = 1 << 1,
   VIR_QEMU_PROCESS_KILL_NOCHECK = 1 << 2, /* bypass the running vm check */
} virQemuProcessKillMode;

int qemuProcessKill(virDomainObj *vm, unsigned int flags);

void qemuProcessShutdownOrReboot(virDomainObj *vm);

void qemuProcessAutoDestroy(virDomainObj *dom,
                            virConnectPtr conn);

int qemuProcessSetSchedParams(int id, pid_t pid, size_t nsp,
                              virDomainThreadSchedParam *sp);

virDomainDiskDef *qemuProcessFindDomainDiskByAliasOrQOM(virDomainObj *vm,
                                                          const char *alias,
                                                          const char *qomid);

int qemuConnectAgent(virQEMUDriver *driver, virDomainObj *vm);


int qemuProcessSetupVcpu(virDomainObj *vm,
                         unsigned int vcpuid,
                         bool schedCore);
int qemuProcessSetupIOThread(virDomainObj *vm,
                             virDomainIOThreadIDDef *iothread);

int qemuRefreshVirtioChannelState(virQEMUDriver *driver,
                                  virDomainObj *vm,
                                  virDomainAsyncJob asyncJob);

int qemuProcessRefreshBalloonState(virDomainObj *vm,
                                   int asyncJob);

int qemuProcessRefreshDisks(virDomainObj *vm,
                            virDomainAsyncJob asyncJob);

int qemuProcessStartManagedPRDaemon(virDomainObj *vm) G_NO_INLINE;

void qemuProcessKillManagedPRDaemon(virDomainObj *vm) G_NO_INLINE;

typedef struct _qemuProcessQMP qemuProcessQMP;
struct _qemuProcessQMP {
    char *binary;
    char *libDir;
    uid_t runUid;
    gid_t runGid;
    char *stdErr;
    char *monarg;
    char *monpath;
    char *pidfile;
    char *uniqDir;
    virEventThread *eventThread;
    virCommand *cmd;
    qemuMonitor *mon;
    pid_t pid;
    virDomainObj *vm;
    bool forceTCG;
};

qemuProcessQMP *qemuProcessQMPNew(const char *binary,
                                    const char *libDir,
                                    uid_t runUid,
                                    gid_t runGid,
                                    bool forceTCG);

void qemuProcessQMPFree(qemuProcessQMP *proc);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuProcessQMP, qemuProcessQMPFree);

int qemuProcessQMPStart(qemuProcessQMP *proc);

bool qemuProcessRebootAllowed(const virDomainDef *def);

void qemuProcessCleanupMigrationJob(virQEMUDriver *driver,
                                    virDomainObj *vm);

void qemuProcessRefreshDiskProps(virDomainDiskDef *disk,
                                 struct qemuDomainDiskInfo *info);

int qemuProcessSetupEmulator(virDomainObj *vm);

void qemuProcessHandleNbdkitExit(qemuNbdkitProcess *nbdkit,
                                 virDomainObj *vm);
