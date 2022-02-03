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
#include "virstoragefile.h"
#include "vireventthread.h"

int qemuProcessPrepareMonitorChr(virDomainChrSourceDef *monConfig,
                                 const char *domainDir);

int qemuProcessStartCPUs(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virDomainRunningReason reason,
                         qemuDomainAsyncJob asyncJob);
int qemuProcessStopCPUs(virQEMUDriver *driver,
                        virDomainObj *vm,
                        virDomainPausedReason reason,
                        qemuDomainAsyncJob asyncJob);

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
    char *launchURI; /* used as a parameter for -incoming command line option */
    char *deferredURI; /* used when calling migrate-incoming QMP command */
    int fd; /* for fd:N URI */
    const char *path; /* path associated with fd */
};

qemuProcessIncomingDef *qemuProcessIncomingDefNew(virQEMUCaps *qemuCaps,
                                                    const char *listenAddress,
                                                    const char *migrateFrom,
                                                    int fd,
                                                    const char *path);
void qemuProcessIncomingDefFree(qemuProcessIncomingDef *inc);

int qemuProcessBeginJob(virQEMUDriver *driver,
                        virDomainObj *vm,
                        virDomainJobOperation operation,
                        unsigned long apiFlags);
void qemuProcessEndJob(virQEMUDriver *driver,
                       virDomainObj *vm);

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
                     qemuDomainAsyncJob asyncJob,
                     const char *migrateFrom,
                     int stdin_fd,
                     const char *stdin_path,
                     virDomainMomentObj *snapshot,
                     virNetDevVPortProfileOp vmop,
                     unsigned int flags);

int qemuProcessCreatePretendCmdPrepare(virQEMUDriver *driver,
                                       virDomainObj *vm,
                                       const char *migrateURI,
                                       unsigned int flags);

virCommand *qemuProcessCreatePretendCmdBuild(virQEMUDriver *driver,
                                               virDomainObj *vm,
                                               const char *migrateURI,
                                               bool enableFips,
                                               bool standalone);

int qemuProcessInit(virQEMUDriver *driver,
                    virDomainObj *vm,
                    virCPUDef *updatedCPU,
                    qemuDomainAsyncJob asyncJob,
                    bool migration,
                    unsigned int flags);

int qemuProcessPrepareDomain(virQEMUDriver *driver,
                             virDomainObj *vm,
                             unsigned int flags);

int qemuProcessOpenVhostVsock(virDomainVsockDef *vsock);

int qemuProcessPrepareHostHostdev(virDomainHostdevDef *hostdev);


int qemuProcessPrepareHostBackendChardevHotplug(virDomainObj *vm,
                                                virDomainDeviceDef *dev)
    G_GNUC_NO_INLINE;


int qemuProcessPrepareHost(virQEMUDriver *driver,
                           virDomainObj *vm,
                           unsigned int flags);

int qemuProcessLaunch(virConnectPtr conn,
                      virQEMUDriver *driver,
                      virDomainObj *vm,
                      qemuDomainAsyncJob asyncJob,
                      qemuProcessIncomingDef *incoming,
                      virDomainMomentObj *snapshot,
                      virNetDevVPortProfileOp vmop,
                      unsigned int flags);

int qemuProcessFinishStartup(virQEMUDriver *driver,
                             virDomainObj *vm,
                             qemuDomainAsyncJob asyncJob,
                             bool startCPUs,
                             virDomainPausedReason pausedReason);

int qemuProcessRefreshState(virQEMUDriver *driver,
                            virDomainObj *vm,
                            qemuDomainAsyncJob asyncJob);

typedef enum {
    VIR_QEMU_PROCESS_STOP_MIGRATED      = 1 << 0,
    VIR_QEMU_PROCESS_STOP_NO_RELABEL    = 1 << 1,
} qemuProcessStopFlags;

int qemuProcessBeginStopJob(virQEMUDriver *driver,
                            virDomainObj *vm,
                            qemuDomainJob job,
                            bool forceKill);
void qemuProcessStop(virQEMUDriver *driver,
                     virDomainObj *vm,
                     virDomainShutoffReason reason,
                     qemuDomainAsyncJob asyncJob,
                     unsigned int flags);

typedef enum {
   VIR_QEMU_PROCESS_KILL_FORCE  = 1 << 0,
   VIR_QEMU_PROCESS_KILL_NOWAIT = 1 << 1,
   VIR_QEMU_PROCESS_KILL_NOCHECK = 1 << 2, /* bypass the running vm check */
} virQemuProcessKillMode;

int qemuProcessKill(virDomainObj *vm, unsigned int flags);

void qemuProcessShutdownOrReboot(virDomainObj *vm);

int qemuProcessAutoDestroyInit(virQEMUDriver *driver);
void qemuProcessAutoDestroyShutdown(virQEMUDriver *driver);
int qemuProcessAutoDestroyAdd(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virConnectPtr conn);
int qemuProcessAutoDestroyRemove(virQEMUDriver *driver,
                                 virDomainObj *vm);
bool qemuProcessAutoDestroyActive(virQEMUDriver *driver,
                                  virDomainObj *vm);

int qemuProcessSetSchedParams(int id, pid_t pid, size_t nsp,
                              virDomainThreadSchedParam *sp);

virDomainDiskDef *qemuProcessFindDomainDiskByAliasOrQOM(virDomainObj *vm,
                                                          const char *alias,
                                                          const char *qomid);

int qemuConnectAgent(virQEMUDriver *driver, virDomainObj *vm);


int qemuProcessSetupVcpu(virDomainObj *vm,
                         unsigned int vcpuid);
int qemuProcessSetupIOThread(virDomainObj *vm,
                             virDomainIOThreadIDDef *iothread);

int qemuRefreshVirtioChannelState(virQEMUDriver *driver,
                                  virDomainObj *vm,
                                  qemuDomainAsyncJob asyncJob);

int qemuProcessRefreshBalloonState(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   int asyncJob);

int qemuProcessRefreshDisks(virQEMUDriver *driver,
                            virDomainObj *vm,
                            qemuDomainAsyncJob asyncJob);

int qemuProcessStartManagedPRDaemon(virDomainObj *vm) G_GNUC_NO_INLINE;

void qemuProcessKillManagedPRDaemon(virDomainObj *vm) G_GNUC_NO_INLINE;

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
