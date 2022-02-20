/*
 * qemu_monitor.h: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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
 */

#pragma once

#include "internal.h"

#include "domain_conf.h"
#include "virbitmap.h"
#include "virhash.h"
#include "virjson.h"
#include "virnetdev.h"
#include "device_conf.h"
#include "cpu/cpu.h"
#include "util/virgic.h"
#include "virenum.h"

typedef struct _qemuMonitor qemuMonitor;
typedef struct _qemuMonitorMessage qemuMonitorMessage;

typedef enum {
    QEMU_MONITOR_EVENT_PANIC_INFO_TYPE_NONE = 0,
    QEMU_MONITOR_EVENT_PANIC_INFO_TYPE_HYPERV,
    QEMU_MONITOR_EVENT_PANIC_INFO_TYPE_S390,

    QEMU_MONITOR_EVENT_PANIC_INFO_TYPE_LAST
} qemuMonitorEventPanicInfoType;

typedef struct _qemuMonitorEventPanicInfoHyperv qemuMonitorEventPanicInfoHyperv;
struct _qemuMonitorEventPanicInfoHyperv {
    /* Hyper-V specific guest panic information (HV crash MSRs) */
    unsigned long long arg1;
    unsigned long long arg2;
    unsigned long long arg3;
    unsigned long long arg4;
    unsigned long long arg5;
};

typedef struct _qemuMonitorEventPanicInfoS390 qemuMonitorEventPanicInfoS390;
struct _qemuMonitorEventPanicInfoS390 {
    /* S390 specific guest panic information */
    int core;
    unsigned long long psw_mask;
    unsigned long long psw_addr;
    char *reason;
};

typedef struct _qemuMonitorEventPanicInfo qemuMonitorEventPanicInfo;
struct _qemuMonitorEventPanicInfo {
    qemuMonitorEventPanicInfoType type;
    union {
        qemuMonitorEventPanicInfoHyperv hyperv;
        qemuMonitorEventPanicInfoS390 s390;
    } data;
};


typedef struct _qemuMonitorRdmaGidStatus qemuMonitorRdmaGidStatus;
struct _qemuMonitorRdmaGidStatus {
    char *netdev;
    bool gid_status;
    unsigned long long subnet_prefix;
    unsigned long long interface_id;
};


typedef struct _qemuMonitorMemoryDeviceSizeChange qemuMonitorMemoryDeviceSizeChange;
typedef qemuMonitorMemoryDeviceSizeChange *qemuMonitorMemoryDeviceSizeChangePtr;
struct _qemuMonitorMemoryDeviceSizeChange {
    char *devAlias;
    unsigned long long size;
};


typedef enum {
    QEMU_MONITOR_ACTION_SHUTDOWN_KEEP, /* do not change the current setting */
    QEMU_MONITOR_ACTION_SHUTDOWN_POWEROFF,
    QEMU_MONITOR_ACTION_SHUTDOWN_PAUSE,

    QEMU_MONITOR_ACTION_SHUTDOWN_LAST
} qemuMonitorActionShutdown;


typedef enum {
    QEMU_MONITOR_ACTION_REBOOT_KEEP, /* do not change the current setting */
    QEMU_MONITOR_ACTION_REBOOT_RESET,
    QEMU_MONITOR_ACTION_REBOOT_SHUTDOWN,

    QEMU_MONITOR_ACTION_REBOOT_LAST
} qemuMonitorActionReboot;


typedef enum {
    QEMU_MONITOR_ACTION_WATCHDOG_KEEP, /* do not change the current setting */
    QEMU_MONITOR_ACTION_WATCHDOG_RESET,
    QEMU_MONITOR_ACTION_WATCHDOG_SHUTDOWN,
    QEMU_MONITOR_ACTION_WATCHDOG_POWEROFF,
    QEMU_MONITOR_ACTION_WATCHDOG_PAUSE,
    QEMU_MONITOR_ACTION_WATCHDOG_DEBUG,
    QEMU_MONITOR_ACTION_WATCHDOG_NONE,
    QEMU_MONITOR_ACTION_WATCHDOG_INJECT_NMI,

    QEMU_MONITOR_ACTION_WATCHDOG_LAST
} qemuMonitorActionWatchdog;


typedef enum {
    QEMU_MONITOR_ACTION_PANIC_KEEP, /* do not change the current setting */
    QEMU_MONITOR_ACTION_PANIC_PAUSE,
    QEMU_MONITOR_ACTION_PANIC_SHUTDOWN,
    QEMU_MONITOR_ACTION_PANIC_NONE,

    QEMU_MONITOR_ACTION_PANIC_LAST
} qemuMonitorActionPanic;


typedef enum {
    QEMU_MONITOR_JOB_TYPE_UNKNOWN, /* internal value, not exposed by qemu */
    QEMU_MONITOR_JOB_TYPE_COMMIT,
    QEMU_MONITOR_JOB_TYPE_STREAM,
    QEMU_MONITOR_JOB_TYPE_MIRROR,
    QEMU_MONITOR_JOB_TYPE_BACKUP,
    QEMU_MONITOR_JOB_TYPE_CREATE,
    QEMU_MONITOR_JOB_TYPE_LAST
} qemuMonitorJobType;

VIR_ENUM_DECL(qemuMonitorJob);

typedef enum {
    QEMU_MONITOR_JOB_STATUS_UNKNOWN, /* internal value, not exposed by qemu */
    QEMU_MONITOR_JOB_STATUS_CREATED,
    QEMU_MONITOR_JOB_STATUS_RUNNING,
    QEMU_MONITOR_JOB_STATUS_PAUSED,
    QEMU_MONITOR_JOB_STATUS_READY,
    QEMU_MONITOR_JOB_STATUS_STANDBY,
    QEMU_MONITOR_JOB_STATUS_WAITING,
    QEMU_MONITOR_JOB_STATUS_PENDING,
    QEMU_MONITOR_JOB_STATUS_ABORTING,
    QEMU_MONITOR_JOB_STATUS_CONCLUDED,
    QEMU_MONITOR_JOB_STATUS_UNDEFINED, /* the job states below should not be visible outside of qemu */
    QEMU_MONITOR_JOB_STATUS_NULL,
    QEMU_MONITOR_JOB_STATUS_LAST
} qemuMonitorJobStatus;

VIR_ENUM_DECL(qemuMonitorJobStatus);

typedef struct _qemuMonitorJobInfo qemuMonitorJobInfo;
struct _qemuMonitorJobInfo {
    char *id;
    qemuMonitorJobType type;
    qemuMonitorJobStatus status;
    char *error;
    unsigned long long progressCurrent;
    unsigned long long progressTotal;
};


char *qemuMonitorGuestPanicEventInfoFormatMsg(qemuMonitorEventPanicInfo *info);
void qemuMonitorEventPanicInfoFree(qemuMonitorEventPanicInfo *info);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuMonitorEventPanicInfo, qemuMonitorEventPanicInfoFree);
void qemuMonitorEventRdmaGidStatusFree(qemuMonitorRdmaGidStatus *info);
void qemuMonitorMemoryDeviceSizeChangeFree(qemuMonitorMemoryDeviceSizeChange *info);

typedef void (*qemuMonitorDestroyCallback)(qemuMonitor *mon,
                                           virDomainObj *vm,
                                           void *opaque);
typedef void (*qemuMonitorEofNotifyCallback)(qemuMonitor *mon,
                                             virDomainObj *vm,
                                             void *opaque);
typedef void (*qemuMonitorErrorNotifyCallback)(qemuMonitor *mon,
                                               virDomainObj *vm,
                                               void *opaque);
typedef void (*qemuMonitorDomainEventCallback)(qemuMonitor *mon,
                                               virDomainObj *vm,
                                               const char *event,
                                               long long seconds,
                                               unsigned int micros,
                                               const char *details,
                                               void *opaque);
typedef void (*qemuMonitorDomainShutdownCallback)(qemuMonitor *mon,
                                                  virDomainObj *vm,
                                                  virTristateBool guest,
                                                  void *opaque);
typedef void (*qemuMonitorDomainResetCallback)(qemuMonitor *mon,
                                               virDomainObj *vm,
                                               void *opaque);
typedef void (*qemuMonitorDomainStopCallback)(qemuMonitor *mon,
                                              virDomainObj *vm,
                                              void *opaque);
typedef void (*qemuMonitorDomainResumeCallback)(qemuMonitor *mon,
                                                virDomainObj *vm,
                                                void *opaque);
typedef void (*qemuMonitorDomainRTCChangeCallback)(qemuMonitor *mon,
                                                   virDomainObj *vm,
                                                   long long offset,
                                                   void *opaque);
typedef void (*qemuMonitorDomainWatchdogCallback)(qemuMonitor *mon,
                                                  virDomainObj *vm,
                                                  int action,
                                                  void *opaque);
typedef void (*qemuMonitorDomainIOErrorCallback)(qemuMonitor *mon,
                                                 virDomainObj *vm,
                                                 const char *diskAlias,
                                                 const char *nodename,
                                                 int action,
                                                 const char *reason,
                                                 void *opaque);
typedef void (*qemuMonitorDomainGraphicsCallback)(qemuMonitor *mon,
                                                  virDomainObj *vm,
                                                  int phase,
                                                  int localFamily,
                                                  const char *localNode,
                                                  const char *localService,
                                                  int remoteFamily,
                                                  const char *remoteNode,
                                                  const char *remoteService,
                                                  const char *authScheme,
                                                  const char *x509dname,
                                                  const char *saslUsername,
                                                  void *opaque);
typedef void (*qemuMonitorDomainBlockJobCallback)(qemuMonitor *mon,
                                                  virDomainObj *vm,
                                                  const char *diskAlias,
                                                  int type,
                                                  int status,
                                                  const char *error,
                                                  void *opaque);
typedef void (*qemuMonitorDomainJobStatusChangeCallback)(qemuMonitor *mon,
                                                         virDomainObj *vm,
                                                         const char *jobname,
                                                         int status,
                                                         void *opaque);
typedef void (*qemuMonitorDomainTrayChangeCallback)(qemuMonitor *mon,
                                                    virDomainObj *vm,
                                                    const char *devAlias,
                                                    const char *devid,
                                                    int reason,
                                                    void *opaque);
typedef void (*qemuMonitorDomainPMWakeupCallback)(qemuMonitor *mon,
                                                  virDomainObj *vm,
                                                  void *opaque);
typedef void (*qemuMonitorDomainPMSuspendCallback)(qemuMonitor *mon,
                                                   virDomainObj *vm,
                                                   void *opaque);
typedef void (*qemuMonitorDomainBalloonChangeCallback)(qemuMonitor *mon,
                                                       virDomainObj *vm,
                                                       unsigned long long actual,
                                                       void *opaque);
typedef void (*qemuMonitorDomainPMSuspendDiskCallback)(qemuMonitor *mon,
                                                       virDomainObj *vm,
                                                       void *opaque);
typedef void (*qemuMonitorDomainGuestPanicCallback)(qemuMonitor *mon,
                                                    virDomainObj *vm,
                                                    qemuMonitorEventPanicInfo *info,
                                                    void *opaque);
typedef void (*qemuMonitorDomainDeviceDeletedCallback)(qemuMonitor *mon,
                                                       virDomainObj *vm,
                                                       const char *devAlias,
                                                       void *opaque);
typedef void (*qemuMonitorDomainDeviceUnplugErrCallback)(qemuMonitor *mon,
                                                         virDomainObj *vm,
                                                         const char *devPath,
                                                         const char *devAlias,
                                                         void *opaque);
typedef void (*qemuMonitorDomainNicRxFilterChangedCallback)(qemuMonitor *mon,
                                                            virDomainObj *vm,
                                                            const char *devAlias,
                                                            void *opaque);

typedef void (*qemuMonitorDomainSerialChangeCallback)(qemuMonitor *mon,
                                                      virDomainObj *vm,
                                                      const char *devAlias,
                                                      bool connected,
                                                      void *opaque);

typedef void (*qemuMonitorDomainSpiceMigratedCallback)(qemuMonitor *mon,
                                                       virDomainObj *vm,
                                                       void *opaque);

typedef void (*qemuMonitorDomainMigrationStatusCallback)(qemuMonitor *mon,
                                                         virDomainObj *vm,
                                                         int status,
                                                         void *opaque);

typedef void (*qemuMonitorDomainMigrationPassCallback)(qemuMonitor *mon,
                                                       virDomainObj *vm,
                                                       int pass,
                                                       void *opaque);

typedef void (*qemuMonitorDomainAcpiOstInfoCallback)(qemuMonitor *mon,
                                                     virDomainObj *vm,
                                                     const char *alias,
                                                     const char *slotType,
                                                     const char *slot,
                                                     unsigned int source,
                                                     unsigned int status,
                                                     void *opaque);


typedef void (*qemuMonitorDomainBlockThresholdCallback)(qemuMonitor *mon,
                                                        virDomainObj *vm,
                                                        const char *nodename,
                                                        unsigned long long threshold,
                                                        unsigned long long excess,
                                                        void *opaque);


typedef enum {
    QEMU_MONITOR_DUMP_STATUS_NONE,
    QEMU_MONITOR_DUMP_STATUS_ACTIVE,
    QEMU_MONITOR_DUMP_STATUS_COMPLETED,
    QEMU_MONITOR_DUMP_STATUS_FAILED,

    QEMU_MONITOR_DUMP_STATUS_LAST,
} qemuMonitorDumpStatus;

VIR_ENUM_DECL(qemuMonitorDumpStatus);

typedef struct _qemuMonitorDumpStats qemuMonitorDumpStats;
struct _qemuMonitorDumpStats {
    int status; /* qemuMonitorDumpStatus */
    unsigned long long completed; /* bytes written */
    unsigned long long total; /* total bytes to be written */
};

typedef void (*qemuMonitorDomainDumpCompletedCallback)(qemuMonitor *mon,
                                                       virDomainObj *vm,
                                                       int status,
                                                       qemuMonitorDumpStats *stats,
                                                       const char *error,
                                                       void *opaque);

typedef void (*qemuMonitorDomainPRManagerStatusChangedCallback)(qemuMonitor *mon,
                                                                virDomainObj *vm,
                                                                const char *prManager,
                                                                bool connected,
                                                                void *opaque);

typedef void (*qemuMonitorDomainRdmaGidStatusChangedCallback)(qemuMonitor *mon,
                                                              virDomainObj *vm,
                                                              const char *netdev,
                                                              bool gid_status,
                                                              unsigned long long subnet_prefix,
                                                              unsigned long long interface_id,
                                                              void *opaque);

typedef void (*qemuMonitorDomainGuestCrashloadedCallback)(qemuMonitor *mon,
                                                          virDomainObj *vm,
                                                          void *opaque);

typedef enum {
    QEMU_MONITOR_MEMORY_FAILURE_RECIPIENT_HYPERVISOR,
    QEMU_MONITOR_MEMORY_FAILURE_RECIPIENT_GUEST,

    QEMU_MONITOR_MEMORY_FAILURE_RECIPIENT_LAST
} qemuMonitorMemoryFailureRecipient;

VIR_ENUM_DECL(qemuMonitorMemoryFailureRecipient);

typedef enum {
    QEMU_MONITOR_MEMORY_FAILURE_ACTION_IGNORE,
    QEMU_MONITOR_MEMORY_FAILURE_ACTION_INJECT,
    QEMU_MONITOR_MEMORY_FAILURE_ACTION_FATAL,
    QEMU_MONITOR_MEMORY_FAILURE_ACTION_RESET,

    QEMU_MONITOR_MEMORY_FAILURE_ACTION_LAST
} qemuMonitorMemoryFailureAction;

VIR_ENUM_DECL(qemuMonitorMemoryFailureAction);

typedef struct _qemuMonitorEventMemoryFailure qemuMonitorEventMemoryFailure;
struct _qemuMonitorEventMemoryFailure {
    qemuMonitorMemoryFailureRecipient recipient;
    qemuMonitorMemoryFailureAction action;
    bool action_required;
    bool recursive;
};

typedef void (*qemuMonitorDomainMemoryFailureCallback)(qemuMonitor *mon,
                                                       virDomainObj *vm,
                                                       qemuMonitorEventMemoryFailure *mfp,
                                                       void *opaque);

typedef void (*qemuMonitorDomainMemoryDeviceSizeChange)(qemuMonitor *mon,
                                                        virDomainObj *vm,
                                                        const char *alias,
                                                        unsigned long long size,
                                                        void *opaque);

typedef struct _qemuMonitorCallbacks qemuMonitorCallbacks;
struct _qemuMonitorCallbacks {
    qemuMonitorEofNotifyCallback eofNotify;
    qemuMonitorErrorNotifyCallback errorNotify;
    qemuMonitorDomainEventCallback domainEvent;
    qemuMonitorDomainShutdownCallback domainShutdown;
    qemuMonitorDomainResetCallback domainReset;
    qemuMonitorDomainStopCallback domainStop;
    qemuMonitorDomainResumeCallback domainResume;
    qemuMonitorDomainRTCChangeCallback domainRTCChange;
    qemuMonitorDomainWatchdogCallback domainWatchdog;
    qemuMonitorDomainIOErrorCallback domainIOError;
    qemuMonitorDomainGraphicsCallback domainGraphics;
    qemuMonitorDomainBlockJobCallback domainBlockJob;
    qemuMonitorDomainJobStatusChangeCallback jobStatusChange;
    qemuMonitorDomainTrayChangeCallback domainTrayChange;
    qemuMonitorDomainPMWakeupCallback domainPMWakeup;
    qemuMonitorDomainPMSuspendCallback domainPMSuspend;
    qemuMonitorDomainBalloonChangeCallback domainBalloonChange;
    qemuMonitorDomainPMSuspendDiskCallback domainPMSuspendDisk;
    qemuMonitorDomainGuestPanicCallback domainGuestPanic;
    qemuMonitorDomainDeviceDeletedCallback domainDeviceDeleted;
    qemuMonitorDomainNicRxFilterChangedCallback domainNicRxFilterChanged;
    qemuMonitorDomainSerialChangeCallback domainSerialChange;
    qemuMonitorDomainSpiceMigratedCallback domainSpiceMigrated;
    qemuMonitorDomainMigrationStatusCallback domainMigrationStatus;
    qemuMonitorDomainMigrationPassCallback domainMigrationPass;
    qemuMonitorDomainAcpiOstInfoCallback domainAcpiOstInfo;
    qemuMonitorDomainBlockThresholdCallback domainBlockThreshold;
    qemuMonitorDomainDumpCompletedCallback domainDumpCompleted;
    qemuMonitorDomainPRManagerStatusChangedCallback domainPRManagerStatusChanged;
    qemuMonitorDomainRdmaGidStatusChangedCallback domainRdmaGidStatusChanged;
    qemuMonitorDomainGuestCrashloadedCallback domainGuestCrashloaded;
    qemuMonitorDomainMemoryFailureCallback domainMemoryFailure;
    qemuMonitorDomainMemoryDeviceSizeChange domainMemoryDeviceSizeChange;
    qemuMonitorDomainDeviceUnplugErrCallback domainDeviceUnplugError;
};

qemuMonitor *qemuMonitorOpen(virDomainObj *vm,
                               virDomainChrSourceDef *config,
                               bool retry,
                               unsigned long long timeout,
                               GMainContext *context,
                               qemuMonitorCallbacks *cb,
                               void *opaque)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);

void qemuMonitorWatchDispose(void);
bool qemuMonitorWasDisposed(void);

void qemuMonitorRegister(qemuMonitor *mon)
    ATTRIBUTE_NONNULL(1);
void qemuMonitorUnregister(qemuMonitor *mon)
    ATTRIBUTE_NONNULL(1);
void qemuMonitorClose(qemuMonitor *mon);

virErrorPtr qemuMonitorLastError(qemuMonitor *mon);

int qemuMonitorSetCapabilities(qemuMonitor *mon);

int qemuMonitorSetLink(qemuMonitor *mon,
                       const char *name,
                       virDomainNetInterfaceLinkState state)
    ATTRIBUTE_NONNULL(2);

/* These APIs are for use by the internal Text/JSON monitor impl code only */
char *qemuMonitorNextCommandID(qemuMonitor *mon);
int qemuMonitorSend(qemuMonitor *mon,
                    qemuMonitorMessage *msg) G_GNUC_NO_INLINE;
int qemuMonitorUpdateVideoMemorySize(qemuMonitor *mon,
                                     virDomainVideoDef *video,
                                     const char *videoName)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
int qemuMonitorUpdateVideoVram64Size(qemuMonitor *mon,
                                     virDomainVideoDef *video,
                                     const char *videoName)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

void qemuMonitorEmitEvent(qemuMonitor *mon, const char *event,
                          long long seconds, unsigned int micros,
                          const char *details);
void qemuMonitorEmitShutdown(qemuMonitor *mon, virTristateBool guest);
void qemuMonitorEmitReset(qemuMonitor *mon);
void qemuMonitorEmitStop(qemuMonitor *mon);
void qemuMonitorEmitResume(qemuMonitor *mon);
void qemuMonitorEmitRTCChange(qemuMonitor *mon, long long offset);
void qemuMonitorEmitWatchdog(qemuMonitor *mon, int action);
void qemuMonitorEmitIOError(qemuMonitor *mon,
                            const char *diskAlias,
                            const char *nodename,
                            int action,
                            const char *reason);
void qemuMonitorEmitGraphics(qemuMonitor *mon,
                             int phase,
                             int localFamily,
                             const char *localNode,
                             const char *localService,
                             int remoteFamily,
                             const char *remoteNode,
                             const char *remoteService,
                             const char *authScheme,
                             const char *x509dname,
                             const char *saslUsername);
void qemuMonitorEmitTrayChange(qemuMonitor *mon,
                               const char *devAlias,
                               const char *devid,
                               int reason);
void qemuMonitorEmitPMWakeup(qemuMonitor *mon);
void qemuMonitorEmitPMSuspend(qemuMonitor *mon);
void qemuMonitorEmitBlockJob(qemuMonitor *mon,
                             const char *diskAlias,
                             int type,
                             int status,
                             const char *error);
void qemuMonitorEmitJobStatusChange(qemuMonitor *mon,
                                    const char *jobname,
                                    qemuMonitorJobStatus status);
void qemuMonitorEmitBalloonChange(qemuMonitor *mon,
                                  unsigned long long actual);
void qemuMonitorEmitPMSuspendDisk(qemuMonitor *mon);
void qemuMonitorEmitGuestPanic(qemuMonitor *mon,
                               qemuMonitorEventPanicInfo *info);
void qemuMonitorEmitDeviceDeleted(qemuMonitor *mon,
                                  const char *devAlias);
void qemuMonitorEmitDeviceUnplugErr(qemuMonitor *mon,
                                    const char *devPath,
                                    const char *devAlias);
void qemuMonitorEmitNicRxFilterChanged(qemuMonitor *mon,
                                       const char *devAlias);
void qemuMonitorEmitSerialChange(qemuMonitor *mon,
                                 const char *devAlias,
                                 bool connected);
void qemuMonitorEmitSpiceMigrated(qemuMonitor *mon);

void qemuMonitorEmitMemoryDeviceSizeChange(qemuMonitor *mon,
                                           const char *devAlias,
                                           unsigned long long size);

void qemuMonitorEmitMemoryFailure(qemuMonitor *mon,
                                  qemuMonitorEventMemoryFailure *mfp);

void qemuMonitorEmitMigrationStatus(qemuMonitor *mon,
                                    int status);
void qemuMonitorEmitMigrationPass(qemuMonitor *mon,
                                  int pass);

void qemuMonitorEmitAcpiOstInfo(qemuMonitor *mon,
                                const char *alias,
                                const char *slotType,
                                const char *slot,
                                unsigned int source,
                                unsigned int status);

void qemuMonitorEmitBlockThreshold(qemuMonitor *mon,
                                   const char *nodename,
                                   unsigned long long threshold,
                                   unsigned long long excess);

void qemuMonitorEmitDumpCompleted(qemuMonitor *mon,
                                  int status,
                                  qemuMonitorDumpStats *stats,
                                  const char *error);

void qemuMonitorEmitPRManagerStatusChanged(qemuMonitor *mon,
                                           const char *prManager,
                                           bool connected);

void qemuMonitorEmitRdmaGidStatusChanged(qemuMonitor *mon,
                                         const char *netdev,
                                         bool gid_status,
                                         unsigned long long subnet_prefix,
                                         unsigned long long interface_id);

void qemuMonitorEmitGuestCrashloaded(qemuMonitor *mon);

int qemuMonitorStartCPUs(qemuMonitor *mon);
int qemuMonitorStopCPUs(qemuMonitor *mon);

typedef enum {
    QEMU_MONITOR_VM_STATUS_DEBUG,
    QEMU_MONITOR_VM_STATUS_INMIGRATE,
    QEMU_MONITOR_VM_STATUS_INTERNAL_ERROR,
    QEMU_MONITOR_VM_STATUS_IO_ERROR,
    QEMU_MONITOR_VM_STATUS_PAUSED,
    QEMU_MONITOR_VM_STATUS_POSTMIGRATE,
    QEMU_MONITOR_VM_STATUS_PRELAUNCH,
    QEMU_MONITOR_VM_STATUS_FINISH_MIGRATE,
    QEMU_MONITOR_VM_STATUS_RESTORE_VM,
    QEMU_MONITOR_VM_STATUS_RUNNING,
    QEMU_MONITOR_VM_STATUS_SAVE_VM,
    QEMU_MONITOR_VM_STATUS_SHUTDOWN,
    QEMU_MONITOR_VM_STATUS_WATCHDOG,
    QEMU_MONITOR_VM_STATUS_GUEST_PANICKED,

    QEMU_MONITOR_VM_STATUS_LAST
} qemuMonitorVMStatus;
VIR_ENUM_DECL(qemuMonitorVMStatus);
int qemuMonitorVMStatusToPausedReason(const char *status);

int qemuMonitorCheck(qemuMonitor *mon);
int qemuMonitorGetStatus(qemuMonitor *mon,
                         bool *running,
                         virDomainPausedReason *reason)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorSystemReset(qemuMonitor *mon);
int qemuMonitorSystemPowerdown(qemuMonitor *mon);

struct qemuMonitorQueryCpusEntry {
    int qemu_id; /* id of the cpu as reported by qemu */
    pid_t tid;
    char *qom_path;
    bool halted;
};
void qemuMonitorQueryCpusFree(struct qemuMonitorQueryCpusEntry *entries,
                              size_t nentries);


struct qemuMonitorQueryHotpluggableCpusEntry {
    char *type; /* name of the cpu to use with device_add */
    unsigned int vcpus; /* count of virtual cpus in the guest this entry adds */
    char *qom_path; /* full device qom path only present for online cpus */
    char *alias; /* device alias, may be NULL for non-hotpluggable entities */

    /* verbatim copy of the JSON data representing the CPU which must be used for hotplug */
    virJSONValue *props;

    /* topology information -1 if qemu didn't report given parameter */
    int node_id;
    int socket_id;
    int die_id;
    int core_id;
    int thread_id;

    /* internal data */
    int enable_id;
};
void qemuMonitorQueryHotpluggableCpusFree(struct qemuMonitorQueryHotpluggableCpusEntry *entries,
                                          size_t nentries);


struct _qemuMonitorCPUInfo {
    pid_t tid;
    int id; /* order of enabling of the given cpu */
    int qemu_id; /* identifier of the cpu as reported by query-cpus */

    /* state data */
    bool online;
    bool hotpluggable;

    /* topology info for hotplug purposes. Hotplug of given vcpu impossible if
     * all entries are -1 */
    int socket_id;
    int die_id;
    int core_id;
    int thread_id;
    int node_id;
    unsigned int vcpus; /* number of vcpus added if given entry is hotplugged */

    /* name of the qemu type to add in case of hotplug */
    char *type;

    /* verbatim copy of the returned data from qemu which should be used when plugging */
    virJSONValue *props;

    /* alias of an hotpluggable entry. Entries with alias can be hot-unplugged */
    char *alias;

    char *qom_path;

    bool halted;
};
typedef struct _qemuMonitorCPUInfo qemuMonitorCPUInfo;

void qemuMonitorCPUInfoFree(qemuMonitorCPUInfo *list,
                            size_t nitems);
int qemuMonitorGetCPUInfo(qemuMonitor *mon,
                          qemuMonitorCPUInfo **vcpus,
                          size_t maxvcpus,
                          bool hotplug,
                          bool fast);
virBitmap *qemuMonitorGetCpuHalted(qemuMonitor *mon,
                                     size_t maxvcpus,
                                     bool fast);

int qemuMonitorGetBalloonInfo(qemuMonitor *mon,
                              unsigned long long *currmem);
int qemuMonitorGetMemoryStats(qemuMonitor *mon,
                              virDomainMemballoonDef *balloon,
                              virDomainMemoryStatPtr stats,
                              unsigned int nr_stats);
int qemuMonitorSetMemoryStatsPeriod(qemuMonitor *mon,
                                    virDomainMemballoonDef *balloon,
                                    int period);

int qemuMonitorBlockIOStatusToError(const char *status);
GHashTable *qemuMonitorGetBlockInfo(qemuMonitor *mon);

virJSONValue *qemuMonitorQueryBlockstats(qemuMonitor *mon);

typedef struct _qemuBlockStats qemuBlockStats;
struct _qemuBlockStats {
    unsigned long long rd_req;
    unsigned long long rd_bytes;
    unsigned long long wr_req;
    unsigned long long wr_bytes;
    unsigned long long rd_total_times;
    unsigned long long wr_total_times;
    unsigned long long flush_req;
    unsigned long long flush_total_times;
    unsigned long long capacity;
    unsigned long long physical;

    /* value of wr_highest_offset is valid if it's non 0 or
     * if wr_highest_offset_valid is true */
    unsigned long long wr_highest_offset;
    bool wr_highest_offset_valid;

    /* write_threshold is valid only if it's non-zero, conforming to qemu semantics */
    unsigned long long write_threshold;
};

int qemuMonitorGetAllBlockStatsInfo(qemuMonitor *mon,
                                    GHashTable **ret_stats)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorBlockStatsUpdateCapacity(qemuMonitor *mon,
                                        GHashTable *stats)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorBlockStatsUpdateCapacityBlockdev(qemuMonitor *mon,
                                                GHashTable *stats)
    ATTRIBUTE_NONNULL(2);

typedef struct _qemuBlockNamedNodeDataBitmap qemuBlockNamedNodeDataBitmap;
struct _qemuBlockNamedNodeDataBitmap {
    char *name;
    bool recording;
    bool busy;
    bool persistent;
    bool inconsistent;

    unsigned long long dirtybytes;
    unsigned long long granularity;
};

typedef struct _qemuBlockNamedNodeData qemuBlockNamedNodeData;
struct _qemuBlockNamedNodeData {
    unsigned long long capacity;
    unsigned long long physical;

    qemuBlockNamedNodeDataBitmap **bitmaps;
    size_t nbitmaps;

    /* the cluster size of the image is valid only when > 0 */
    unsigned long long clusterSize;

    /* image version */
    bool qcow2v2;

    /* qcow2 subcluster allocation -> extended_l2 */
    bool qcow2extendedL2;
};

GHashTable *
qemuMonitorBlockGetNamedNodeData(qemuMonitor *mon,
                                 bool supports_flat);

int qemuMonitorBlockResize(qemuMonitor *mon,
                           const char *device,
                           const char *nodename,
                           unsigned long long size);
int qemuMonitorSetPassword(qemuMonitor *mon,
                           int type,
                           const char *password,
                           const char *action_if_connected);
int qemuMonitorExpirePassword(qemuMonitor *mon,
                              int type,
                              const char *expire_time);
int qemuMonitorSetBalloon(qemuMonitor *mon,
                          unsigned long long newmem);

int qemuMonitorEjectMedia(qemuMonitor *mon,
                          const char *dev_name,
                          bool force);
int qemuMonitorChangeMedia(qemuMonitor *mon,
                           const char *dev_name,
                           const char *newmedia,
                           const char *format);


int qemuMonitorSaveVirtualMemory(qemuMonitor *mon,
                                 unsigned long long offset,
                                 unsigned long long length,
                                 const char *path);
int qemuMonitorSavePhysicalMemory(qemuMonitor *mon,
                                  unsigned long long offset,
                                  unsigned long long length,
                                  const char *path);

int qemuMonitorSetDBusVMStateIdList(qemuMonitor *mon,
                                    GSList *list);

int qemuMonitorSetMigrationSpeed(qemuMonitor *mon,
                                 unsigned long bandwidth);

int qemuMonitorSetMigrationDowntime(qemuMonitor *mon,
                                    unsigned long long downtime);

int qemuMonitorGetMigrationCacheSize(qemuMonitor *mon,
                                     unsigned long long *cacheSize);
int qemuMonitorSetMigrationCacheSize(qemuMonitor *mon,
                                     unsigned long long cacheSize);

int qemuMonitorGetMigrationParams(qemuMonitor *mon,
                                  virJSONValue **params);
int qemuMonitorSetMigrationParams(qemuMonitor *mon,
                                  virJSONValue **params);

typedef enum {
    QEMU_MONITOR_MIGRATION_STATUS_INACTIVE,
    QEMU_MONITOR_MIGRATION_STATUS_SETUP,
    QEMU_MONITOR_MIGRATION_STATUS_ACTIVE,
    QEMU_MONITOR_MIGRATION_STATUS_PRE_SWITCHOVER,
    QEMU_MONITOR_MIGRATION_STATUS_DEVICE,
    QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY,
    QEMU_MONITOR_MIGRATION_STATUS_COMPLETED,
    QEMU_MONITOR_MIGRATION_STATUS_ERROR,
    QEMU_MONITOR_MIGRATION_STATUS_CANCELLING,
    QEMU_MONITOR_MIGRATION_STATUS_CANCELLED,
    QEMU_MONITOR_MIGRATION_STATUS_WAIT_UNPLUG,

    QEMU_MONITOR_MIGRATION_STATUS_LAST
} qemuMonitorMigrationStatus;

VIR_ENUM_DECL(qemuMonitorMigrationStatus);

typedef struct _qemuMonitorMigrationStats qemuMonitorMigrationStats;
struct _qemuMonitorMigrationStats {
    int status; /* qemuMonitorMigrationStatus */
    unsigned long long total_time;
    /* total or expected depending on status */
    bool downtime_set;
    unsigned long long downtime;
    /*
     * Duration of the QEMU 'setup' state.
     * for RDMA, this may be on the order of several seconds
     * if pinning support is requested before the migration begins.
     */
    bool setup_time_set;
    unsigned long long setup_time;

    unsigned long long ram_transferred;
    unsigned long long ram_remaining;
    unsigned long long ram_total;
    unsigned long long ram_bps;
    bool ram_duplicate_set;
    unsigned long long ram_duplicate;
    unsigned long long ram_normal;
    unsigned long long ram_normal_bytes;
    unsigned long long ram_dirty_rate;
    unsigned long long ram_page_size;
    unsigned long long ram_iteration;
    unsigned long long ram_postcopy_reqs;

    unsigned long long disk_transferred;
    unsigned long long disk_remaining;
    unsigned long long disk_total;
    unsigned long long disk_bps;

    bool xbzrle_set;
    unsigned long long xbzrle_cache_size;
    unsigned long long xbzrle_bytes;
    unsigned long long xbzrle_pages;
    unsigned long long xbzrle_cache_miss;
    unsigned long long xbzrle_overflow;

    int cpu_throttle_percentage;
};

int qemuMonitorGetMigrationStats(qemuMonitor *mon,
                                 qemuMonitorMigrationStats *stats,
                                 char **error);

int qemuMonitorGetMigrationCapabilities(qemuMonitor *mon,
                                        char ***capabilities);
int qemuMonitorSetMigrationCapabilities(qemuMonitor *mon,
                                        virJSONValue **caps);

int qemuMonitorGetGICCapabilities(qemuMonitor *mon,
                                  virGICCapability **capabilities);

int qemuMonitorGetSEVCapabilities(qemuMonitor *mon,
                                  virSEVCapability **capabilities);

typedef enum {
  QEMU_MONITOR_MIGRATE_BACKGROUND       = 1 << 0,
  QEMU_MONITOR_MIGRATE_NON_SHARED_DISK  = 1 << 1, /* migration with non-shared storage with full disk copy */
  QEMU_MONITOR_MIGRATE_NON_SHARED_INC   = 1 << 2, /* migration with non-shared storage with incremental copy */
  QEMU_MONITOR_MIGRATION_FLAGS_LAST
} QEMU_MONITOR_MIGRATE;

int qemuMonitorMigrateToFd(qemuMonitor *mon,
                           unsigned int flags,
                           int fd);

int qemuMonitorMigrateToHost(qemuMonitor *mon,
                             unsigned int flags,
                             const char *protocol,
                             const char *hostname,
                             int port);

int qemuMonitorMigrateToSocket(qemuMonitor *mon,
                               unsigned int flags,
                               const char *socketPath);

int qemuMonitorMigrateCancel(qemuMonitor *mon);

int qemuMonitorGetDumpGuestMemoryCapability(qemuMonitor *mon,
                                            const char *capability);

int qemuMonitorQueryDump(qemuMonitor *mon,
                         qemuMonitorDumpStats *stats);

int qemuMonitorDumpToFd(qemuMonitor *mon,
                        int fd,
                        const char *dumpformat,
                        bool detach);

int qemuMonitorGraphicsRelocate(qemuMonitor *mon,
                                int type,
                                const char *hostname,
                                int port,
                                int tlsPort,
                                const char *tlsSubject);

typedef struct _qemuMonitorAddFdInfo qemuMonitorAddFdInfo;
struct _qemuMonitorAddFdInfo {
    int fd;
    int fdset;
};
int
qemuMonitorAddFileHandleToSet(qemuMonitor *mon,
                              int fd,
                              int fdset,
                              const char *opaque,
                              qemuMonitorAddFdInfo *info);

int
qemuMonitorRemoveFdset(qemuMonitor *mon,
                       unsigned int fdset);

typedef struct _qemuMonitorFdsetFdInfo qemuMonitorFdsetFdInfo;
struct _qemuMonitorFdsetFdInfo {
    int fd;
    char *opaque;
};
typedef struct _qemuMonitorFdsetInfo qemuMonitorFdsetInfo;
struct _qemuMonitorFdsetInfo {
    unsigned int id;
    qemuMonitorFdsetFdInfo *fds;
    int nfds;
};
typedef struct _qemuMonitorFdsets qemuMonitorFdsets;
struct _qemuMonitorFdsets {
    qemuMonitorFdsetInfo *fdsets;
    int nfdsets;
};
void qemuMonitorFdsetsFree(qemuMonitorFdsets *fdsets);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuMonitorFdsets, qemuMonitorFdsetsFree);
int qemuMonitorQueryFdsets(qemuMonitor *mon,
                           qemuMonitorFdsets **fdsets);

int qemuMonitorSendFileHandle(qemuMonitor *mon,
                              const char *fdname,
                              int fd);

/* This function preserves previous error and only set their own
 * error if no error was set before.
 */
int qemuMonitorCloseFileHandle(qemuMonitor *mon,
                               const char *fdname);

int qemuMonitorAddNetdev(qemuMonitor *mon,
                         virJSONValue **props,
                         int *tapfd, char **tapfdName, int tapfdSize,
                         int *vhostfd, char **vhostfdName, int vhostfdSize,
                         int slirpfd, char *slirpfdName);

int qemuMonitorRemoveNetdev(qemuMonitor *mon,
                            const char *alias);

int qemuMonitorQueryRxFilter(qemuMonitor *mon, const char *alias,
                             virNetDevRxFilter **filter);

typedef struct _qemuMonitorChardevInfo qemuMonitorChardevInfo;
struct _qemuMonitorChardevInfo {
    char *ptyPath;
    virDomainChrDeviceState state;
};
void qemuMonitorChardevInfoFree(void *data);
int qemuMonitorGetChardevInfo(qemuMonitor *mon,
                              GHashTable **retinfo);

int qemuMonitorAttachPCIDiskController(qemuMonitor *mon,
                                       const char *bus,
                                       virPCIDeviceAddress *guestAddr);

int qemuMonitorAddDeviceProps(qemuMonitor *mon,
                              virJSONValue **props);

int qemuMonitorDelDevice(qemuMonitor *mon,
                         const char *devalias);

int qemuMonitorCreateObjectProps(virJSONValue **propsret,
                                 const char *type,
                                 const char *alias,
                                 ...);

int qemuMonitorAddObject(qemuMonitor *mon,
                         virJSONValue **props,
                         char **alias)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorDelObject(qemuMonitor *mon,
                         const char *objalias,
                         bool report_error);

int qemuMonitorAddDrive(qemuMonitor *mon,
                        const char *drivestr);

int qemuMonitorDriveDel(qemuMonitor *mon,
                        const char *drivestr);

int qemuMonitorCreateSnapshot(qemuMonitor *mon, const char *name);
int qemuMonitorDeleteSnapshot(qemuMonitor *mon, const char *name);

int qemuMonitorTransaction(qemuMonitor *mon, virJSONValue **actions)
    ATTRIBUTE_NONNULL(2);
int qemuMonitorDriveMirror(qemuMonitor *mon,
                           const char *device,
                           const char *file,
                           const char *format,
                           unsigned long long bandwidth,
                           unsigned int granularity,
                           unsigned long long buf_size,
                           bool shallow,
                           bool reuse)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
int qemuMonitorBlockdevMirror(qemuMonitor *mon,
                              const char *jobname,
                              bool persistjob,
                              const char *device,
                              const char *target,
                              unsigned long long bandwidth,
                              unsigned int granularity,
                              unsigned long long buf_size,
                              bool shallow,
                              bool syncWrite)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);
int qemuMonitorDrivePivot(qemuMonitor *mon,
                          const char *jobname)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorBlockCommit(qemuMonitor *mon,
                           const char *device,
                           const char *jobname,
                           bool persistjob,
                           const char *top,
                           const char *topNode,
                           const char *base,
                           const char *baseNode,
                           const char *backingName,
                           unsigned long long bandwidth)
    ATTRIBUTE_NONNULL(2);
char *qemuMonitorDiskNameLookup(qemuMonitor *mon,
                                const char *device,
                                virStorageSource *top,
                                virStorageSource *target)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int qemuMonitorArbitraryCommand(qemuMonitor *mon,
                                const char *cmd,
                                char **reply,
                                bool hmp);

int qemuMonitorInjectNMI(qemuMonitor *mon);

int qemuMonitorScreendump(qemuMonitor *mon,
                          const char *device,
                          unsigned int head,
                          const char *file);

int qemuMonitorSendKey(qemuMonitor *mon,
                       unsigned int holdtime,
                       unsigned int *keycodes,
                       unsigned int nkeycodes);

int qemuMonitorBlockStream(qemuMonitor *mon,
                           const char *device,
                           const char *jobname,
                           bool persistjob,
                           const char *base,
                           const char *baseNode,
                           const char *backingName,
                           unsigned long long bandwidth)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorBlockJobCancel(qemuMonitor *mon,
                              const char *jobname,
                              bool force)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorBlockJobSetSpeed(qemuMonitor *mon,
                                const char *jobname,
                                unsigned long long bandwidth);

typedef struct _qemuMonitorBlockJobInfo qemuMonitorBlockJobInfo;
struct _qemuMonitorBlockJobInfo {
    int type; /* virDomainBlockJobType */
    unsigned long long bandwidth; /* in bytes/s */
    virDomainBlockJobCursor cur;
    virDomainBlockJobCursor end;
    bool ready_present;
    bool ready;
};

GHashTable *qemuMonitorGetAllBlockJobInfo(qemuMonitor *mon,
                                              bool rawjobname);

int qemuMonitorJobDismiss(qemuMonitor *mon,
                          const char *jobname)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorJobComplete(qemuMonitor *mon,
                           const char *jobname)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorOpenGraphics(qemuMonitor *mon,
                            const char *protocol,
                            int fd,
                            const char *fdname,
                            bool skipauth);

int qemuMonitorSetBlockIoThrottle(qemuMonitor *mon,
                                  const char *drivealias,
                                  const char *qomid,
                                  virDomainBlockIoTuneInfo *info);

int qemuMonitorGetBlockIoThrottle(qemuMonitor *mon,
                                  const char *drivealias,
                                  const char *qdevid,
                                  virDomainBlockIoTuneInfo *reply);

int qemuMonitorSystemWakeup(qemuMonitor *mon);

int qemuMonitorGetVersion(qemuMonitor *mon,
                          int *major,
                          int *minor,
                          int *micro,
                          char **package)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);


typedef struct _qemuMonitorMachineInfo qemuMonitorMachineInfo;
struct _qemuMonitorMachineInfo {
    char *name;
    bool isDefault;
    char *alias;
    unsigned int maxCpus;
    bool hotplugCpus;
    char *defaultCPU;
    bool numaMemSupported;
    char *defaultRAMid;
    bool deprecated;
};

int qemuMonitorGetMachines(qemuMonitor *mon,
                           qemuMonitorMachineInfo ***machines);

void qemuMonitorMachineInfoFree(qemuMonitorMachineInfo *machine);

typedef struct _qemuMonitorCPUDefInfo qemuMonitorCPUDefInfo;
struct _qemuMonitorCPUDefInfo {
    virDomainCapsCPUUsable usable;
    char *name;
    char *type;
    char **blockers; /* NULL-terminated string list */
    bool deprecated;
};

typedef struct _qemuMonitorCPUDefs qemuMonitorCPUDefs;
struct _qemuMonitorCPUDefs {
    size_t ncpus;
    qemuMonitorCPUDefInfo *cpus;
};

int qemuMonitorGetCPUDefinitions(qemuMonitor *mon,
                                 qemuMonitorCPUDefs **cpuDefs);
qemuMonitorCPUDefs *qemuMonitorCPUDefsNew(size_t count);
qemuMonitorCPUDefs *qemuMonitorCPUDefsCopy(qemuMonitorCPUDefs *src);
void qemuMonitorCPUDefsFree(qemuMonitorCPUDefs *defs);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuMonitorCPUDefs, qemuMonitorCPUDefsFree);


typedef enum {
    QEMU_MONITOR_CPU_PROPERTY_BOOLEAN,
    QEMU_MONITOR_CPU_PROPERTY_STRING,
    QEMU_MONITOR_CPU_PROPERTY_NUMBER,

    QEMU_MONITOR_CPU_PROPERTY_LAST
} qemuMonitorCPUPropertyType;

VIR_ENUM_DECL(qemuMonitorCPUProperty);

typedef struct _qemuMonitorCPUProperty qemuMonitorCPUProperty;
struct _qemuMonitorCPUProperty {
    char *name;
    qemuMonitorCPUPropertyType type;
    union {
        bool boolean;
        char *string;
        long long number;
    } value;
    virTristateBool migratable;
};

typedef struct _qemuMonitorCPUModelInfo qemuMonitorCPUModelInfo;
struct _qemuMonitorCPUModelInfo {
    char *name;
    size_t nprops;
    qemuMonitorCPUProperty *props;
    bool migratability;
};

typedef enum {
    QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC,
    QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC_FULL,
    QEMU_MONITOR_CPU_MODEL_EXPANSION_FULL,
} qemuMonitorCPUModelExpansionType;

int qemuMonitorGetCPUModelExpansion(qemuMonitor *mon,
                                    qemuMonitorCPUModelExpansionType type,
                                    virCPUDef *cpu,
                                    bool migratable,
                                    bool fail_no_props,
                                    qemuMonitorCPUModelInfo **model_info);

void qemuMonitorCPUModelInfoFree(qemuMonitorCPUModelInfo *model_info);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuMonitorCPUModelInfo, qemuMonitorCPUModelInfoFree);

int qemuMonitorGetCPUModelBaseline(qemuMonitor *mon,
                                   virCPUDef *cpu_a,
                                   virCPUDef *cpu_b,
                                   qemuMonitorCPUModelInfo **baseline);

int qemuMonitorGetCPUModelComparison(qemuMonitor *mon,
                                     virCPUDef *cpu_a,
                                     virCPUDef *cpu_b,
                                     char **result);

qemuMonitorCPUModelInfo *
qemuMonitorCPUModelInfoCopy(const qemuMonitorCPUModelInfo *orig);

int qemuMonitorGetCommands(qemuMonitor *mon,
                           char ***commands);
GHashTable *qemuMonitorGetCommandLineOptions(qemuMonitor *mon);

int qemuMonitorGetKVMState(qemuMonitor *mon,
                           bool *enabled,
                           bool *present);

int qemuMonitorGetObjectTypes(qemuMonitor *mon,
                              char ***types);
GHashTable *qemuMonitorGetDeviceProps(qemuMonitor *mon,
                                          const char *device);
int qemuMonitorGetObjectProps(qemuMonitor *mon,
                              const char *object,
                              char ***props);
char *qemuMonitorGetTargetArch(qemuMonitor *mon);

int qemuMonitorNBDServerStart(qemuMonitor *mon,
                              const virStorageNetHostDef *server,
                              const char *tls_alias)
    ATTRIBUTE_NONNULL(2);
int qemuMonitorNBDServerAdd(qemuMonitor *mon,
                            const char *deviceID,
                            const char *export,
                            bool writable,
                            const char *bitmap);
int qemuMonitorNBDServerStop(qemuMonitor *);

int qemuMonitorBlockExportAdd(qemuMonitor *mon,
                              virJSONValue **props);

int qemuMonitorGetTPMModels(qemuMonitor *mon,
                            char ***tpmmodels);

int qemuMonitorGetTPMTypes(qemuMonitor *mon,
                           char ***tpmtypes);

int qemuMonitorAttachCharDev(qemuMonitor *mon,
                             const char *chrID,
                             virDomainChrSourceDef *chr);
int qemuMonitorDetachCharDev(qemuMonitor *mon,
                             const char *chrID);

int qemuMonitorGetDeviceAliases(qemuMonitor *mon,
                                char ***aliases);

typedef void (*qemuMonitorReportDomainLogError)(qemuMonitor *mon,
                                                const char *msg,
                                                void *opaque);
void qemuMonitorSetDomainLogLocked(qemuMonitor *mon,
                                   qemuMonitorReportDomainLogError func,
                                   void *opaque,
                                   virFreeCallback destroy);
void qemuMonitorSetDomainLog(qemuMonitor *mon,
                             qemuMonitorReportDomainLogError func,
                             void *opaque,
                             virFreeCallback destroy);

int qemuMonitorGetGuestCPUx86(qemuMonitor *mon,
                              const char *cpuQOMPath,
                              virCPUData **data,
                              virCPUData **disabled);

typedef const char *(*qemuMonitorCPUFeatureTranslationCallback)(const char *name,
                                                                void *opaque);

int qemuMonitorGetGuestCPU(qemuMonitor *mon,
                           virArch arch,
                           const char *cpuQOMPath,
                           qemuMonitorCPUFeatureTranslationCallback translate,
                           void *opaque,
                           virCPUData **enabled,
                           virCPUData **disabled);

int qemuMonitorRTCResetReinjection(qemuMonitor *mon);

typedef struct _qemuMonitorIOThreadInfo qemuMonitorIOThreadInfo;
struct _qemuMonitorIOThreadInfo {
    unsigned int iothread_id;
    int thread_id;
    bool poll_valid;
    unsigned long long poll_max_ns;
    unsigned int poll_grow;
    unsigned int poll_shrink;
    bool set_poll_max_ns;
    bool set_poll_grow;
    bool set_poll_shrink;
};
int qemuMonitorGetIOThreads(qemuMonitor *mon,
                            qemuMonitorIOThreadInfo ***iothreads,
                            int *niothreads);
int qemuMonitorSetIOThread(qemuMonitor *mon,
                           qemuMonitorIOThreadInfo *iothreadInfo);

typedef struct _qemuMonitorMemoryDeviceInfo qemuMonitorMemoryDeviceInfo;
struct _qemuMonitorMemoryDeviceInfo {
    /* For pc-dimm */
    unsigned long long address;
    unsigned int slot;
    bool hotplugged;
    bool hotpluggable;
    /* For virtio-mem */
    unsigned long long size; /* in bytes */
};

int qemuMonitorGetMemoryDeviceInfo(qemuMonitor *mon,
                                   GHashTable **info)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorMigrateIncoming(qemuMonitor *mon,
                               const char *uri);

int qemuMonitorMigrateStartPostCopy(qemuMonitor *mon);

int qemuMonitorMigrateContinue(qemuMonitor *mon,
                               qemuMonitorMigrationStatus status);

int qemuMonitorGetRTCTime(qemuMonitor *mon,
                          struct tm *tm);

virJSONValue *qemuMonitorQueryQMPSchema(qemuMonitor *mon);

int qemuMonitorSetBlockThreshold(qemuMonitor *mon,
                                 const char *nodename,
                                 unsigned long long threshold);

virJSONValue *qemuMonitorQueryNamedBlockNodes(qemuMonitor *mon);

int qemuMonitorSetWatchdogAction(qemuMonitor *mon,
                                 const char *action);

int qemuMonitorBlockdevCreate(qemuMonitor *mon,
                              const char *jobname,
                              virJSONValue **props);

int qemuMonitorBlockdevAdd(qemuMonitor *mon,
                           virJSONValue **props);

int qemuMonitorBlockdevReopen(qemuMonitor *mon,
                              virJSONValue **props);

int qemuMonitorBlockdevDel(qemuMonitor *mon,
                           const char *nodename);

int qemuMonitorBlockdevTrayOpen(qemuMonitor *mon,
                                const char *id,
                                bool force);

int qemuMonitorBlockdevTrayClose(qemuMonitor *mon,
                                 const char *id);

int qemuMonitorBlockdevMediumRemove(qemuMonitor *mon,
                                    const char *id);

int qemuMonitorBlockdevMediumInsert(qemuMonitor *mon,
                                    const char *id,
                                    const char *nodename);

char *
qemuMonitorGetSEVMeasurement(qemuMonitor *mon);

int
qemuMonitorGetSEVInfo(qemuMonitor *mon,
                      unsigned int *apiMajor,
                      unsigned int *apiMinor,
                      unsigned int *buildID,
                      unsigned int *policy)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);

int
qemuMonitorSetLaunchSecurityState(qemuMonitor *mon,
                                  const char *secrethdr,
                                  const char *secret,
                                  unsigned long long setaddr,
                                  bool hasSetaddr);

typedef struct _qemuMonitorPRManagerInfo qemuMonitorPRManagerInfo;
struct _qemuMonitorPRManagerInfo {
    bool connected;
};

int qemuMonitorGetPRManagerInfo(qemuMonitor *mon,
                                GHashTable **retinfo);

typedef struct  _qemuMonitorCurrentMachineInfo qemuMonitorCurrentMachineInfo;
struct _qemuMonitorCurrentMachineInfo {
    bool wakeupSuspendSupport;
};

int qemuMonitorGetCurrentMachineInfo(qemuMonitor *mon,
                                     qemuMonitorCurrentMachineInfo *info);
void qemuMonitorJobInfoFree(qemuMonitorJobInfo *job);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuMonitorJobInfo, qemuMonitorJobInfoFree);

int qemuMonitorGetJobInfo(qemuMonitor *mon,
                          qemuMonitorJobInfo ***jobs,
                          size_t *njobs);

int
qemuMonitorGetCPUMigratable(qemuMonitor *mon,
                            const char *cpuQOMPath,
                            bool *migratable);

int
qemuMonitorTransactionBitmapAdd(virJSONValue *actions,
                                const char *node,
                                const char *name,
                                bool persistent,
                                bool disabled,
                                unsigned long long granularity);
int
qemuMonitorTransactionBitmapRemove(virJSONValue *actions,
                                   const char *node,
                                   const char *name);

int
qemuMonitorBitmapRemove(qemuMonitor *mon,
                        const char *node,
                        const char *name);
int
qemuMonitorTransactionBitmapEnable(virJSONValue *actions,
                                   const char *node,
                                   const char *name);
int
qemuMonitorTransactionBitmapDisable(virJSONValue *actions,
                                    const char *node,
                                    const char *name);
int
qemuMonitorTransactionBitmapMerge(virJSONValue *actions,
                                  const char *node,
                                  const char *target,
                                  virJSONValue **sources);
int
qemuMonitorTransactionBitmapMergeSourceAddBitmap(virJSONValue *sources,
                                                 const char *sourcenode,
                                                 const char *sourcebitmap);

int
qemuMonitorTransactionSnapshotLegacy(virJSONValue *actions,
                                     const char *device,
                                     const char *path,
                                     const char *format,
                                     bool existing);
int
qemuMonitorTransactionSnapshotBlockdev(virJSONValue *actions,
                                       const char *node,
                                       const char *overlay);

typedef enum {
    QEMU_MONITOR_TRANSACTION_BACKUP_SYNC_MODE_NONE = 0,
    QEMU_MONITOR_TRANSACTION_BACKUP_SYNC_MODE_INCREMENTAL,
    QEMU_MONITOR_TRANSACTION_BACKUP_SYNC_MODE_FULL,
    QEMU_MONITOR_TRANSACTION_BACKUP_SYNC_MODE_LAST,
} qemuMonitorTransactionBackupSyncMode;

int
qemuMonitorTransactionBackup(virJSONValue *actions,
                             const char *device,
                             const char *jobname,
                             const char *target,
                             const char *bitmap,
                             qemuMonitorTransactionBackupSyncMode syncmode);

/**
 * qemuMonitorDirtyRateCalcMode:
 *
 * Dirty page rate calculation mode used during measurement.
 */
typedef enum {
    QEMU_MONITOR_DIRTYRATE_CALC_MODE_PAGE_SAMPLING = 0,
    QEMU_MONITOR_DIRTYRATE_CALC_MODE_DIRTY_BITMAP,
    QEMU_MONITOR_DIRTYRATE_CALC_MODE_DIRTY_RING,
    QEMU_MONITOR_DIRTYRATE_CALC_MODE_LAST,
} qemuMonitorDirtyRateCalcMode;

VIR_ENUM_DECL(qemuMonitorDirtyRateCalcMode);

int
qemuMonitorStartDirtyRateCalc(qemuMonitor *mon,
                              int seconds,
                              qemuMonitorDirtyRateCalcMode mode);

typedef struct _qemuMonitorDirtyRateInfo qemuMonitorDirtyRateInfo;
struct _qemuMonitorDirtyRateInfo {
    int status;             /* the status of last dirtyrate calculation,
                               one of virDomainDirtyRateStatus */
    int calcTime;           /* the period of dirtyrate calculation */
    long long startTime;    /* the start time of dirtyrate calculation */
    long long dirtyRate;    /* the dirtyrate in MiB/s */
};

int
qemuMonitorQueryDirtyRate(qemuMonitor *mon,
                          qemuMonitorDirtyRateInfo *info);

int
qemuMonitorSetAction(qemuMonitor *mon,
                     qemuMonitorActionShutdown shutdown,
                     qemuMonitorActionReboot reboot,
                     qemuMonitorActionWatchdog watchdog,
                     qemuMonitorActionPanic panic);

int
qemuMonitorChangeMemoryRequestedSize(qemuMonitor *mon,
                                     const char *alias,
                                     unsigned long long requestedsize);
