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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */


#ifndef QEMU_MONITOR_H
# define QEMU_MONITOR_H

# include "internal.h"

# include "domain_conf.h"
# include "virbitmap.h"
# include "virhash.h"
# include "virjson.h"
# include "virnetdev.h"
# include "device_conf.h"
# include "cpu/cpu.h"

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

    /* Used by the text monitor reply / error */
    char *rxBuffer;
    int rxLength;
    /* Used by the JSON monitor to hold reply / error */
    void *rxObject;

    /* True if rxBuffer / rxObject are ready, or a
     * fatal error occurred on the monitor channel
     */
    bool finished;

    qemuMonitorPasswordHandler passwordHandler;
    void *passwordOpaque;
};


typedef void (*qemuMonitorDestroyCallback)(qemuMonitorPtr mon,
                                           virDomainObjPtr vm,
                                           void *opaque);
typedef void (*qemuMonitorEofNotifyCallback)(qemuMonitorPtr mon,
                                             virDomainObjPtr vm,
                                             void *opaque);
typedef void (*qemuMonitorErrorNotifyCallback)(qemuMonitorPtr mon,
                                               virDomainObjPtr vm,
                                               void *opaque);
/* XXX we'd really like to avoid virConnectPtr here
 * It is required so the callback can find the active
 * secret driver. Need to change this to work like the
 * security drivers do, to avoid this
 */
typedef int (*qemuMonitorDiskSecretLookupCallback)(qemuMonitorPtr mon,
                                                   virConnectPtr conn,
                                                   virDomainObjPtr vm,
                                                   const char *path,
                                                   char **secret,
                                                   size_t *secretLen,
                                                   void *opaque);
typedef int (*qemuMonitorDomainEventCallback)(qemuMonitorPtr mon,
                                              virDomainObjPtr vm,
                                              const char *event,
                                              long long seconds,
                                              unsigned int micros,
                                              const char *details,
                                              void *opaque);
typedef int (*qemuMonitorDomainShutdownCallback)(qemuMonitorPtr mon,
                                                 virDomainObjPtr vm,
                                                 void *opaque);
typedef int (*qemuMonitorDomainResetCallback)(qemuMonitorPtr mon,
                                              virDomainObjPtr vm,
                                              void *opaque);
typedef int (*qemuMonitorDomainPowerdownCallback)(qemuMonitorPtr mon,
                                                  virDomainObjPtr vm,
                                                  void *opaque);
typedef int (*qemuMonitorDomainStopCallback)(qemuMonitorPtr mon,
                                             virDomainObjPtr vm,
                                             void *opaque);
typedef int (*qemuMonitorDomainResumeCallback)(qemuMonitorPtr mon,
                                               virDomainObjPtr vm,
                                               void *opaque);
typedef int (*qemuMonitorDomainRTCChangeCallback)(qemuMonitorPtr mon,
                                                  virDomainObjPtr vm,
                                                  long long offset,
                                                  void *opaque);
typedef int (*qemuMonitorDomainWatchdogCallback)(qemuMonitorPtr mon,
                                                 virDomainObjPtr vm,
                                                 int action,
                                                 void *opaque);
typedef int (*qemuMonitorDomainIOErrorCallback)(qemuMonitorPtr mon,
                                                virDomainObjPtr vm,
                                                const char *diskAlias,
                                                int action,
                                                const char *reason,
                                                void *opaque);
typedef int (*qemuMonitorDomainGraphicsCallback)(qemuMonitorPtr mon,
                                                 virDomainObjPtr vm,
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
typedef int (*qemuMonitorDomainBlockJobCallback)(qemuMonitorPtr mon,
                                                 virDomainObjPtr vm,
                                                 const char *diskAlias,
                                                 int type,
                                                 int status,
                                                 void *opaque);
typedef int (*qemuMonitorDomainTrayChangeCallback)(qemuMonitorPtr mon,
                                                   virDomainObjPtr vm,
                                                   const char *devAlias,
                                                   int reason,
                                                   void *opaque);
typedef int (*qemuMonitorDomainPMWakeupCallback)(qemuMonitorPtr mon,
                                                 virDomainObjPtr vm,
                                                 void *opaque);
typedef int (*qemuMonitorDomainPMSuspendCallback)(qemuMonitorPtr mon,
                                                  virDomainObjPtr vm,
                                                  void *opaque);
typedef int (*qemuMonitorDomainBalloonChangeCallback)(qemuMonitorPtr mon,
                                                      virDomainObjPtr vm,
                                                      unsigned long long actual,
                                                      void *opaque);
typedef int (*qemuMonitorDomainPMSuspendDiskCallback)(qemuMonitorPtr mon,
                                                      virDomainObjPtr vm,
                                                      void *opaque);
typedef int (*qemuMonitorDomainGuestPanicCallback)(qemuMonitorPtr mon,
                                                   virDomainObjPtr vm,
                                                   void *opaque);
typedef int (*qemuMonitorDomainDeviceDeletedCallback)(qemuMonitorPtr mon,
                                                      virDomainObjPtr vm,
                                                      const char *devAlias,
                                                      void *opaque);
typedef int (*qemuMonitorDomainNicRxFilterChangedCallback)(qemuMonitorPtr mon,
                                                           virDomainObjPtr vm,
                                                           const char *devAlias,
                                                           void *opaque);

typedef int (*qemuMonitorDomainSerialChangeCallback)(qemuMonitorPtr mon,
                                                     virDomainObjPtr vm,
                                                     const char *devAlias,
                                                     bool connected,
                                                     void *opaque);

typedef int (*qemuMonitorDomainSpiceMigratedCallback)(qemuMonitorPtr mon,
                                                      virDomainObjPtr vm,
                                                      void *opaque);

typedef int (*qemuMonitorDomainMigrationStatusCallback)(qemuMonitorPtr mon,
                                                        virDomainObjPtr vm,
                                                        int status,
                                                        void *opaque);

typedef int (*qemuMonitorDomainMigrationPassCallback)(qemuMonitorPtr mon,
                                                      virDomainObjPtr vm,
                                                      int pass,
                                                      void *opaque);

typedef struct _qemuMonitorCallbacks qemuMonitorCallbacks;
typedef qemuMonitorCallbacks *qemuMonitorCallbacksPtr;
struct _qemuMonitorCallbacks {
    qemuMonitorDestroyCallback destroy;
    qemuMonitorEofNotifyCallback eofNotify;
    qemuMonitorErrorNotifyCallback errorNotify;
    qemuMonitorDiskSecretLookupCallback diskSecretLookup;
    qemuMonitorDomainEventCallback domainEvent;
    qemuMonitorDomainShutdownCallback domainShutdown;
    qemuMonitorDomainResetCallback domainReset;
    qemuMonitorDomainPowerdownCallback domainPowerdown;
    qemuMonitorDomainStopCallback domainStop;
    qemuMonitorDomainResumeCallback domainResume;
    qemuMonitorDomainRTCChangeCallback domainRTCChange;
    qemuMonitorDomainWatchdogCallback domainWatchdog;
    qemuMonitorDomainIOErrorCallback domainIOError;
    qemuMonitorDomainGraphicsCallback domainGraphics;
    qemuMonitorDomainBlockJobCallback domainBlockJob;
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
};

char *qemuMonitorEscapeArg(const char *in);
char *qemuMonitorUnescapeArg(const char *in);

qemuMonitorPtr qemuMonitorOpen(virDomainObjPtr vm,
                               virDomainChrSourceDefPtr config,
                               bool json,
                               qemuMonitorCallbacksPtr cb,
                               void *opaque)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4);
qemuMonitorPtr qemuMonitorOpenFD(virDomainObjPtr vm,
                                 int sockfd,
                                 bool json,
                                 qemuMonitorCallbacksPtr cb,
                                 void *opaque)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);

void qemuMonitorUnregister(qemuMonitorPtr mon)
    ATTRIBUTE_NONNULL(1);
void qemuMonitorClose(qemuMonitorPtr mon);

virErrorPtr qemuMonitorLastError(qemuMonitorPtr mon);

int qemuMonitorSetCapabilities(qemuMonitorPtr mon);

int qemuMonitorSetLink(qemuMonitorPtr mon,
                       const char *name,
                       virDomainNetInterfaceLinkState state)
    ATTRIBUTE_NONNULL(2);

/* These APIs are for use by the internal Text/JSON monitor impl code only */
char *qemuMonitorNextCommandID(qemuMonitorPtr mon);
int qemuMonitorSend(qemuMonitorPtr mon,
                    qemuMonitorMessagePtr msg);
virJSONValuePtr qemuMonitorGetOptions(qemuMonitorPtr mon)
    ATTRIBUTE_NONNULL(1);
void qemuMonitorSetOptions(qemuMonitorPtr mon, virJSONValuePtr options)
    ATTRIBUTE_NONNULL(1);
int qemuMonitorUpdateVideoMemorySize(qemuMonitorPtr mon,
                                     virDomainVideoDefPtr video,
                                     const char *videoName)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
int qemuMonitorHMPCommandWithFd(qemuMonitorPtr mon,
                                const char *cmd,
                                int scm_fd,
                                char **reply);
# define qemuMonitorHMPCommand(mon, cmd, reply) \
    qemuMonitorHMPCommandWithFd(mon, cmd, -1, reply)

/* XXX same comment about virConnectPtr as above */
int qemuMonitorGetDiskSecret(qemuMonitorPtr mon,
                             virConnectPtr conn,
                             const char *path,
                             char **secret,
                             size_t *secretLen);

int qemuMonitorEmitEvent(qemuMonitorPtr mon, const char *event,
                         long long seconds, unsigned int micros,
                         const char *details);
int qemuMonitorEmitShutdown(qemuMonitorPtr mon);
int qemuMonitorEmitReset(qemuMonitorPtr mon);
int qemuMonitorEmitPowerdown(qemuMonitorPtr mon);
int qemuMonitorEmitStop(qemuMonitorPtr mon);
int qemuMonitorEmitResume(qemuMonitorPtr mon);
int qemuMonitorEmitRTCChange(qemuMonitorPtr mon, long long offset);
int qemuMonitorEmitWatchdog(qemuMonitorPtr mon, int action);
int qemuMonitorEmitIOError(qemuMonitorPtr mon,
                           const char *diskAlias,
                           int action,
                           const char *reason);
int qemuMonitorEmitGraphics(qemuMonitorPtr mon,
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
int qemuMonitorEmitTrayChange(qemuMonitorPtr mon,
                              const char *devAlias,
                              int reason);
int qemuMonitorEmitPMWakeup(qemuMonitorPtr mon);
int qemuMonitorEmitPMSuspend(qemuMonitorPtr mon);
int qemuMonitorEmitBlockJob(qemuMonitorPtr mon,
                            const char *diskAlias,
                            int type,
                            int status);
int qemuMonitorEmitBalloonChange(qemuMonitorPtr mon,
                                 unsigned long long actual);
int qemuMonitorEmitPMSuspendDisk(qemuMonitorPtr mon);
int qemuMonitorEmitGuestPanic(qemuMonitorPtr mon);
int qemuMonitorEmitDeviceDeleted(qemuMonitorPtr mon,
                                 const char *devAlias);
int qemuMonitorEmitNicRxFilterChanged(qemuMonitorPtr mon,
                                      const char *devAlias);
int qemuMonitorEmitSerialChange(qemuMonitorPtr mon,
                                const char *devAlias,
                                bool connected);
int qemuMonitorEmitSpiceMigrated(qemuMonitorPtr mon);
int qemuMonitorEmitMigrationStatus(qemuMonitorPtr mon,
                                   int status);
int qemuMonitorEmitMigrationPass(qemuMonitorPtr mon,
                                 int pass);

int qemuMonitorStartCPUs(qemuMonitorPtr mon,
                         virConnectPtr conn);
int qemuMonitorStopCPUs(qemuMonitorPtr mon);

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
VIR_ENUM_DECL(qemuMonitorVMStatus)
int qemuMonitorVMStatusToPausedReason(const char *status);

int qemuMonitorGetStatus(qemuMonitorPtr mon,
                         bool *running,
                         virDomainPausedReason *reason)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorSystemReset(qemuMonitorPtr mon);
int qemuMonitorSystemPowerdown(qemuMonitorPtr mon);

int qemuMonitorGetCPUInfo(qemuMonitorPtr mon,
                          int **pids);
int qemuMonitorGetVirtType(qemuMonitorPtr mon,
                           virDomainVirtType *virtType);
int qemuMonitorGetBalloonInfo(qemuMonitorPtr mon,
                              unsigned long long *currmem);
int qemuMonitorGetMemoryStats(qemuMonitorPtr mon,
                              virDomainMemoryStatPtr stats,
                              unsigned int nr_stats);
int qemuMonitorSetMemoryStatsPeriod(qemuMonitorPtr mon,
                                    int period);

int qemuMonitorBlockIOStatusToError(const char *status);
virHashTablePtr qemuMonitorGetBlockInfo(qemuMonitorPtr mon);
struct qemuDomainDiskInfo *
qemuMonitorBlockInfoLookup(virHashTablePtr blockInfo,
                           const char *dev_name);

typedef struct _qemuBlockStats qemuBlockStats;
typedef qemuBlockStats *qemuBlockStatsPtr;
struct _qemuBlockStats {
    long long rd_req;
    long long rd_bytes;
    long long wr_req;
    long long wr_bytes;
    long long rd_total_times;
    long long wr_total_times;
    long long flush_req;
    long long flush_total_times;
    unsigned long long capacity;
    unsigned long long physical;

    /* value of wr_highest_offset is valid if it's non 0 or
     * if wr_highest_offset_valid is true */
    unsigned long long wr_highest_offset;
    bool wr_highest_offset_valid;
};

int qemuMonitorGetAllBlockStatsInfo(qemuMonitorPtr mon,
                                    virHashTablePtr *ret_stats,
                                    bool backingChain)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorBlockStatsUpdateCapacity(qemuMonitorPtr mon,
                                        virHashTablePtr stats,
                                        bool backingChain)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorBlockResize(qemuMonitorPtr mon,
                           const char *dev_name,
                           unsigned long long size);
int qemuMonitorSetVNCPassword(qemuMonitorPtr mon,
                              const char *password);
int qemuMonitorSetPassword(qemuMonitorPtr mon,
                           int type,
                           const char *password,
                           const char *action_if_connected);
int qemuMonitorExpirePassword(qemuMonitorPtr mon,
                              int type,
                              const char *expire_time);
int qemuMonitorSetBalloon(qemuMonitorPtr mon,
                          unsigned long long newmem);
int qemuMonitorSetCPU(qemuMonitorPtr mon, int cpu, bool online);


/* XXX should we pass the virDomainDiskDefPtr instead
 * and hide dev_name details inside monitor. Reconsider
 * this when doing the QMP implementation
 */
int qemuMonitorEjectMedia(qemuMonitorPtr mon,
                          const char *dev_name,
                          bool force);
int qemuMonitorChangeMedia(qemuMonitorPtr mon,
                           const char *dev_name,
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

int qemuMonitorSetMigrationDowntime(qemuMonitorPtr mon,
                                    unsigned long long downtime);

int qemuMonitorGetMigrationCacheSize(qemuMonitorPtr mon,
                                     unsigned long long *cacheSize);
int qemuMonitorSetMigrationCacheSize(qemuMonitorPtr mon,
                                     unsigned long long cacheSize);

typedef enum {
    QEMU_MONITOR_MIGRATION_STATUS_INACTIVE,
    QEMU_MONITOR_MIGRATION_STATUS_SETUP,
    QEMU_MONITOR_MIGRATION_STATUS_ACTIVE,
    QEMU_MONITOR_MIGRATION_STATUS_COMPLETED,
    QEMU_MONITOR_MIGRATION_STATUS_ERROR,
    QEMU_MONITOR_MIGRATION_STATUS_CANCELLING,
    QEMU_MONITOR_MIGRATION_STATUS_CANCELLED,

    QEMU_MONITOR_MIGRATION_STATUS_LAST
} qemuMonitorMigrationStatus;

VIR_ENUM_DECL(qemuMonitorMigrationStatus)

typedef struct _qemuMonitorMigrationStats qemuMonitorMigrationStats;
typedef qemuMonitorMigrationStats *qemuMonitorMigrationStatsPtr;
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
    unsigned long long ram_iteration;

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
};

int qemuMonitorGetMigrationStats(qemuMonitorPtr mon,
                                 qemuMonitorMigrationStatsPtr stats);

typedef enum {
    QEMU_MONITOR_MIGRATION_CAPS_XBZRLE,
    QEMU_MONITOR_MIGRATION_CAPS_AUTO_CONVERGE,
    QEMU_MONITOR_MIGRATION_CAPS_RDMA_PIN_ALL,
    QEMU_MONITOR_MIGRATION_CAPS_EVENTS,

    QEMU_MONITOR_MIGRATION_CAPS_LAST
} qemuMonitorMigrationCaps;

VIR_ENUM_DECL(qemuMonitorMigrationCaps);

int qemuMonitorGetMigrationCapabilities(qemuMonitorPtr mon,
                                        char ***capabilities);
int qemuMonitorGetMigrationCapability(qemuMonitorPtr mon,
                                      qemuMonitorMigrationCaps capability);
int qemuMonitorSetMigrationCapability(qemuMonitorPtr mon,
                                      qemuMonitorMigrationCaps capability,
                                      bool state);

typedef enum {
  QEMU_MONITOR_MIGRATE_BACKGROUND	= 1 << 0,
  QEMU_MONITOR_MIGRATE_NON_SHARED_DISK  = 1 << 1, /* migration with non-shared storage with full disk copy */
  QEMU_MONITOR_MIGRATE_NON_SHARED_INC   = 1 << 2, /* migration with non-shared storage with incremental copy */
  QEMU_MONITOR_MIGRATION_FLAGS_LAST
} QEMU_MONITOR_MIGRATE;

int qemuMonitorMigrateToFd(qemuMonitorPtr mon,
                           unsigned int flags,
                           int fd);

int qemuMonitorMigrateToHost(qemuMonitorPtr mon,
                             unsigned int flags,
                             const char *protocol,
                             const char *hostname,
                             int port);

int qemuMonitorMigrateToCommand(qemuMonitorPtr mon,
                                unsigned int flags,
                                const char * const *argv);

int qemuMonitorMigrateToUnix(qemuMonitorPtr mon,
                             unsigned int flags,
                             const char *unixfile);

int qemuMonitorMigrateCancel(qemuMonitorPtr mon);

int qemuMonitorGetDumpGuestMemoryCapability(qemuMonitorPtr mon,
                                            const char *capability);

int qemuMonitorDumpToFd(qemuMonitorPtr mon,
                        int fd,
                        const char *dumpformat);

int qemuMonitorGraphicsRelocate(qemuMonitorPtr mon,
                                int type,
                                const char *hostname,
                                int port,
                                int tlsPort,
                                const char *tlsSubject);

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
                                virDevicePCIAddress *hostAddr,
                                virDevicePCIAddress *guestAddr);

/* XXX disk driver type eg,  qcow/etc.
 * XXX cache mode
 */
int qemuMonitorAddPCIDisk(qemuMonitorPtr mon,
                          const char *path,
                          const char *bus,
                          virDevicePCIAddress *guestAddr);

/* XXX do we really want to hardcode 'nicstr' as the
 * sendable item here
 */
int qemuMonitorAddPCINetwork(qemuMonitorPtr mon,
                             const char *nicstr,
                             virDevicePCIAddress *guestAddr);

int qemuMonitorRemovePCIDevice(qemuMonitorPtr mon,
                               virDevicePCIAddress *guestAddr);


int qemuMonitorSendFileHandle(qemuMonitorPtr mon,
                              const char *fdname,
                              int fd);
int qemuMonitorAddFd(qemuMonitorPtr mon, int fdset, int fd, const char *name);

/* These two functions preserve previous error and only set their own
 * error if no error was set before.
 */
int qemuMonitorCloseFileHandle(qemuMonitorPtr mon,
                               const char *fdname);
int qemuMonitorRemoveFd(qemuMonitorPtr mon, int fdset, int fd);

/* XXX do we really want to hardcode 'netstr' as the
 * sendable item here
 */
int qemuMonitorAddHostNetwork(qemuMonitorPtr mon,
                              const char *netstr,
                              int *tapfd, char **tapfdName, int tapfdSize,
                              int *vhostfd, char **vhostfdName, int vhostfdSize);

int qemuMonitorRemoveHostNetwork(qemuMonitorPtr mon,
                                 int vlan,
                                 const char *netname);

int qemuMonitorAddNetdev(qemuMonitorPtr mon,
                         const char *netdevstr,
                         int *tapfd, char **tapfdName, int tapfdSize,
                         int *vhostfd, char **vhostfdName, int vhostfdSize);

int qemuMonitorRemoveNetdev(qemuMonitorPtr mon,
                            const char *alias);

int qemuMonitorQueryRxFilter(qemuMonitorPtr mon, const char *alias,
                             virNetDevRxFilterPtr *filter);

typedef struct _qemuMonitorChardevInfo qemuMonitorChardevInfo;
typedef qemuMonitorChardevInfo *qemuMonitorChardevInfoPtr;
struct _qemuMonitorChardevInfo {
    char *ptyPath;
    virDomainChrDeviceState state;
};
void qemuMonitorChardevInfoFree(void *data, const void *name);
int qemuMonitorGetChardevInfo(qemuMonitorPtr mon,
                              virHashTablePtr *retinfo);

int qemuMonitorAttachPCIDiskController(qemuMonitorPtr mon,
                                       const char *bus,
                                       virDevicePCIAddress *guestAddr);

int qemuMonitorAttachDrive(qemuMonitorPtr mon,
                           const char *drivestr,
                           virDevicePCIAddress *controllerAddr,
                           virDomainDeviceDriveAddress *driveAddr);


typedef struct _qemuMonitorPCIAddress qemuMonitorPCIAddress;
struct _qemuMonitorPCIAddress {
    unsigned int vendor;
    unsigned int product;
    virDevicePCIAddress addr;
};

int qemuMonitorGetAllPCIAddresses(qemuMonitorPtr mon,
                                  qemuMonitorPCIAddress **addrs);

int qemuMonitorAddDevice(qemuMonitorPtr mon,
                         const char *devicestr);

int qemuMonitorAddDeviceWithFd(qemuMonitorPtr mon,
                               const char *devicestr,
                               int fd,
                               const char *fdname);

int qemuMonitorDelDevice(qemuMonitorPtr mon,
                         const char *devalias);

int qemuMonitorAddObject(qemuMonitorPtr mon,
                         const char *type,
                         const char *objalias,
                         virJSONValuePtr props);

int qemuMonitorDelObject(qemuMonitorPtr mon,
                         const char *objalias);

int qemuMonitorAddDrive(qemuMonitorPtr mon,
                        const char *drivestr);

int qemuMonitorDriveDel(qemuMonitorPtr mon,
                        const char *drivestr);

int qemuMonitorSetDrivePassphrase(qemuMonitorPtr mon,
                                  const char *alias,
                                  const char *passphrase);

int qemuMonitorCreateSnapshot(qemuMonitorPtr mon, const char *name);
int qemuMonitorLoadSnapshot(qemuMonitorPtr mon, const char *name);
int qemuMonitorDeleteSnapshot(qemuMonitorPtr mon, const char *name);

int qemuMonitorDiskSnapshot(qemuMonitorPtr mon,
                            virJSONValuePtr actions,
                            const char *device,
                            const char *file,
                            const char *format,
                            bool reuse);
int qemuMonitorTransaction(qemuMonitorPtr mon, virJSONValuePtr actions)
    ATTRIBUTE_NONNULL(2);
int qemuMonitorDriveMirror(qemuMonitorPtr mon,
                           const char *device,
                           const char *file,
                           const char *format,
                           unsigned long long bandwidth,
                           unsigned int granularity,
                           unsigned long long buf_size,
                           unsigned int flags)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
int qemuMonitorDrivePivot(qemuMonitorPtr mon,
                          const char *device)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorBlockCommit(qemuMonitorPtr mon,
                           const char *device,
                           const char *top,
                           const char *base,
                           const char *backingName,
                           unsigned long long bandwidth)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);
bool qemuMonitorSupportsActiveCommit(qemuMonitorPtr mon);
char *qemuMonitorDiskNameLookup(qemuMonitorPtr mon,
                                const char *device,
                                virStorageSourcePtr top,
                                virStorageSourcePtr target)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int qemuMonitorArbitraryCommand(qemuMonitorPtr mon,
                                const char *cmd,
                                char **reply,
                                bool hmp);

int qemuMonitorInjectNMI(qemuMonitorPtr mon);

int qemuMonitorScreendump(qemuMonitorPtr mon,
                          const char *file);

int qemuMonitorSendKey(qemuMonitorPtr mon,
                       unsigned int holdtime,
                       unsigned int *keycodes,
                       unsigned int nkeycodes);

int qemuMonitorBlockStream(qemuMonitorPtr mon,
                           const char *device,
                           const char *base,
                           const char *backingName,
                           unsigned long long bandwidth,
                           bool modern)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorBlockJobCancel(qemuMonitorPtr mon,
                              const char *device,
                              bool modern)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorBlockJobSetSpeed(qemuMonitorPtr mon,
                                const char *device,
                                unsigned long long bandwidth,
                                bool modern);

typedef struct _qemuMonitorBlockJobInfo qemuMonitorBlockJobInfo;
typedef qemuMonitorBlockJobInfo *qemuMonitorBlockJobInfoPtr;
struct _qemuMonitorBlockJobInfo {
    int type; /* virDomainBlockJobType */
    unsigned long long bandwidth; /* in bytes/s */
    virDomainBlockJobCursor cur;
    virDomainBlockJobCursor end;
    int ready; /* -1 if unknown, 0 if not ready, 1 if ready */
};

virHashTablePtr qemuMonitorGetAllBlockJobInfo(qemuMonitorPtr mon);
int qemuMonitorGetBlockJobInfo(qemuMonitorPtr mon,
                               const char *device,
                               qemuMonitorBlockJobInfoPtr info)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int qemuMonitorOpenGraphics(qemuMonitorPtr mon,
                            const char *protocol,
                            int fd,
                            const char *fdname,
                            bool skipauth);

int qemuMonitorSetBlockIoThrottle(qemuMonitorPtr mon,
                                  const char *device,
                                  virDomainBlockIoTuneInfoPtr info,
                                  bool supportMaxOptions);

int qemuMonitorGetBlockIoThrottle(qemuMonitorPtr mon,
                                  const char *device,
                                  virDomainBlockIoTuneInfoPtr reply,
                                  bool supportMaxOptions);

int qemuMonitorSystemWakeup(qemuMonitorPtr mon);

int qemuMonitorGetVersion(qemuMonitorPtr mon,
                          int *major,
                          int *minor,
                          int *micro,
                          char **package)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);


typedef struct _qemuMonitorMachineInfo qemuMonitorMachineInfo;
typedef qemuMonitorMachineInfo *qemuMonitorMachineInfoPtr;

struct _qemuMonitorMachineInfo {
    char *name;
    bool isDefault;
    char *alias;
    unsigned int maxCpus;
};

int qemuMonitorGetMachines(qemuMonitorPtr mon,
                           qemuMonitorMachineInfoPtr **machines);

void qemuMonitorMachineInfoFree(qemuMonitorMachineInfoPtr machine);

int qemuMonitorGetCPUDefinitions(qemuMonitorPtr mon,
                                 char ***cpus);

int qemuMonitorGetCommands(qemuMonitorPtr mon,
                           char ***commands);
int qemuMonitorGetEvents(qemuMonitorPtr mon,
                         char ***events);
int qemuMonitorGetCommandLineOptionParameters(qemuMonitorPtr mon,
                                              const char *option,
                                              char ***params,
                                              bool *found);

int qemuMonitorGetKVMState(qemuMonitorPtr mon,
                           bool *enabled,
                           bool *present);

int qemuMonitorGetObjectTypes(qemuMonitorPtr mon,
                              char ***types);
int qemuMonitorGetObjectProps(qemuMonitorPtr mon,
                              const char *type,
                              char ***props);
char *qemuMonitorGetTargetArch(qemuMonitorPtr mon);

int qemuMonitorNBDServerStart(qemuMonitorPtr mon,
                              const char *host,
                              unsigned int port);
int qemuMonitorNBDServerAdd(qemuMonitorPtr mon,
                            const char *deviceID,
                            bool writable);
int qemuMonitorNBDServerStop(qemuMonitorPtr);
int qemuMonitorGetTPMModels(qemuMonitorPtr mon,
                            char ***tpmmodels);

int qemuMonitorGetTPMTypes(qemuMonitorPtr mon,
                           char ***tpmtypes);

int qemuMonitorAttachCharDev(qemuMonitorPtr mon,
                             const char *chrID,
                             virDomainChrSourceDefPtr chr);
int qemuMonitorDetachCharDev(qemuMonitorPtr mon,
                             const char *chrID);

int qemuMonitorGetDeviceAliases(qemuMonitorPtr mon,
                                char ***aliases);

typedef void (*qemuMonitorReportDomainLogError)(qemuMonitorPtr mon,
                                                const char *msg,
                                                void *opaque);
void qemuMonitorSetDomainLog(qemuMonitorPtr mon,
                             qemuMonitorReportDomainLogError func,
                             void *opaque,
                             virFreeCallback destroy);

int qemuMonitorGetGuestCPU(qemuMonitorPtr mon,
                           virArch arch,
                           virCPUDataPtr *data);

int qemuMonitorRTCResetReinjection(qemuMonitorPtr mon);

typedef struct _qemuMonitorIOThreadInfo qemuMonitorIOThreadInfo;
typedef qemuMonitorIOThreadInfo *qemuMonitorIOThreadInfoPtr;

struct _qemuMonitorIOThreadInfo {
    unsigned int iothread_id;
    int thread_id;
};
int qemuMonitorGetIOThreads(qemuMonitorPtr mon,
                            qemuMonitorIOThreadInfoPtr **iothreads);

typedef struct _qemuMonitorMemoryDeviceInfo qemuMonitorMemoryDeviceInfo;
typedef qemuMonitorMemoryDeviceInfo *qemuMonitorMemoryDeviceInfoPtr;

struct _qemuMonitorMemoryDeviceInfo {
    unsigned long long address;
    unsigned int slot;
    bool hotplugged;
    bool hotpluggable;
};

int qemuMonitorGetMemoryDeviceInfo(qemuMonitorPtr mon,
                                   virHashTablePtr *info)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorMigrateIncoming(qemuMonitorPtr mon,
                               const char *uri);

#endif /* QEMU_MONITOR_H */
