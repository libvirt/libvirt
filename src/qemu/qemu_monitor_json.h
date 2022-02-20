/*
 * qemu_monitor_json.h: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2009, 2011-2015 Red Hat, Inc.
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

#include "qemu_monitor.h"
#include "virbitmap.h"
#include "cpu/cpu.h"
#include "util/virgic.h"

int
qemuMonitorJSONIOProcessLine(qemuMonitor *mon,
                             const char *line,
                             qemuMonitorMessage *msg)
    G_GNUC_NO_INLINE;

int
qemuMonitorJSONIOProcess(qemuMonitor *mon,
                         const char *data,
                         size_t len,
                         qemuMonitorMessage *msg);

int
qemuMonitorJSONHumanCommand(qemuMonitor *mon,
                            const char *cmd,
                            char **reply);

int
qemuMonitorJSONSetCapabilities(qemuMonitor *mon);

int
qemuMonitorJSONStartCPUs(qemuMonitor *mon);
int
qemuMonitorJSONStopCPUs(qemuMonitor *mon);
int
qemuMonitorJSONGetStatus(qemuMonitor *mon,
                         bool *running,
                         virDomainPausedReason *reason);

int
qemuMonitorJSONSystemPowerdown(qemuMonitor *mon);
int
qemuMonitorJSONSystemReset(qemuMonitor *mon);

int
qemuMonitorJSONQueryCPUs(qemuMonitor *mon,
                         struct qemuMonitorQueryCpusEntry **entries,
                         size_t *nentries,
                         bool force,
                         bool fast);
int
qemuMonitorJSONUpdateVideoMemorySize(qemuMonitor *mon,
                                     virDomainVideoDef *video,
                                     char *path);
int
qemuMonitorJSONUpdateVideoVram64Size(qemuMonitor *mon,
                                     virDomainVideoDef *video,
                                     char *path);
int
qemuMonitorJSONGetBalloonInfo(qemuMonitor *mon,
                              unsigned long long *currmem);
int
qemuMonitorJSONGetMemoryStats(qemuMonitor *mon,
                              char *balloonpath,
                              virDomainMemoryStatPtr stats,
                              unsigned int nr_stats);
int
qemuMonitorJSONSetMemoryStatsPeriod(qemuMonitor *mon,
                                    char *balloonpath,
                                    int period);
int
qemuMonitorJSONGetBlockInfo(qemuMonitor *mon,
                            GHashTable *table);

virJSONValue *
qemuMonitorJSONQueryBlockstats(qemuMonitor *mon,
                               bool queryNodes);
int
qemuMonitorJSONGetAllBlockStatsInfo(qemuMonitor *mon,
                                    GHashTable *hash);
int
qemuMonitorJSONBlockStatsUpdateCapacity(qemuMonitor *mon,
                                        GHashTable *stats);
int
qemuMonitorJSONBlockStatsUpdateCapacityBlockdev(qemuMonitor *mon,
                                                GHashTable *stats);

GHashTable *
qemuMonitorJSONBlockGetNamedNodeDataJSON(virJSONValue *nodes);

GHashTable *
qemuMonitorJSONBlockGetNamedNodeData(qemuMonitor *mon,
                                     bool supports_flat);

int
qemuMonitorJSONBlockResize(qemuMonitor *mon,
                           const char *device,
                           const char *nodename,
                           unsigned long long size);

int
qemuMonitorJSONSetPassword(qemuMonitor *mon,
                           const char *protocol,
                           const char *password,
                           const char *action_if_connected);
int
qemuMonitorJSONExpirePassword(qemuMonitor *mon,
                              const char *protocol,
                              const char *expire_time);
int
qemuMonitorJSONSetBalloon(qemuMonitor *mon,
                          unsigned long long newmem);

int
qemuMonitorJSONEjectMedia(qemuMonitor *mon,
                          const char *dev_name,
                          bool force);
int
qemuMonitorJSONChangeMedia(qemuMonitor *mon,
                           const char *dev_name,
                           const char *newmedia,
                           const char *format);

int
qemuMonitorJSONSaveVirtualMemory(qemuMonitor *mon,
                                 unsigned long long offset,
                                 unsigned long long length,
                                 const char *path);
int
qemuMonitorJSONSavePhysicalMemory(qemuMonitor *mon,
                                  unsigned long long offset,
                                  unsigned long long length,
                                  const char *path);

int
qemuMonitorJSONSetMigrationSpeed(qemuMonitor *mon,
                                 unsigned long bandwidth);

int
qemuMonitorJSONSetMigrationDowntime(qemuMonitor *mon,
                                    unsigned long long downtime);

int
qemuMonitorJSONGetMigrationCacheSize(qemuMonitor *mon,
                                     unsigned long long *cacheSize);
int
qemuMonitorJSONSetMigrationCacheSize(qemuMonitor *mon,
                                     unsigned long long cacheSize);

int
qemuMonitorJSONGetMigrationParams(qemuMonitor *mon,
                                  virJSONValue **params);
int
qemuMonitorJSONSetMigrationParams(qemuMonitor *mon,
                                  virJSONValue **params);

int
qemuMonitorJSONGetMigrationStats(qemuMonitor *mon,
                                 qemuMonitorMigrationStats *stats,
                                 char **error);

int
qemuMonitorJSONGetMigrationCapabilities(qemuMonitor *mon,
                                        char ***capabilities);
int
qemuMonitorJSONSetMigrationCapabilities(qemuMonitor *mon,
                                        virJSONValue **caps);

int
qemuMonitorJSONGetGICCapabilities(qemuMonitor *mon,
                                  virGICCapability **capabilities);

int
qemuMonitorJSONGetSEVCapabilities(qemuMonitor *mon,
                                  virSEVCapability **capabilities);

int
qemuMonitorJSONMigrate(qemuMonitor *mon,
                       unsigned int flags,
                       const char *uri);
int
qemuMonitorJSONGetSpiceMigrationStatus(qemuMonitor *mon,
                                       bool *spice_migrated);


int
qemuMonitorJSONMigrateCancel(qemuMonitor *mon);

int
qemuMonitorJSONQueryDump(qemuMonitor *mon,
                         qemuMonitorDumpStats *stats);

int
qemuMonitorJSONGetDumpGuestMemoryCapability(qemuMonitor *mon,
                                            const char *capability);

int
qemuMonitorJSONDump(qemuMonitor *mon,
                    const char *protocol,
                    const char *dumpformat,
                    bool detach);

int
qemuMonitorJSONGraphicsRelocate(qemuMonitor *mon,
                                int type,
                                const char *hostname,
                                int port,
                                int tlsPort,
                                const char *tlsSubject);

int
qemuMonitorJSONAddPCIHostDevice(qemuMonitor *mon,
                                virPCIDeviceAddress *hostAddr,
                                virPCIDeviceAddress *guestAddr);

int
qemuMonitorJSONAddPCIDisk(qemuMonitor *mon,
                          const char *path,
                          const char *bus,
                          virPCIDeviceAddress *guestAddr);

int
qemuMonitorJSONAddPCINetwork(qemuMonitor *mon,
                             const char *nicstr,
                             virPCIDeviceAddress *guestAddr);

int
qemuMonitorJSONRemovePCIDevice(qemuMonitor *mon,
                               virPCIDeviceAddress *guestAddr);

int
qemuMonitorJSONAddFileHandleToSet(qemuMonitor *mon,
                                  int fd,
                                  int fdset,
                                  const char *opaque,
                                  qemuMonitorAddFdInfo *info);

int
qemuMonitorJSONRemoveFdset(qemuMonitor *mon,
                           unsigned int fdset);

int
qemuMonitorJSONQueryFdsets(qemuMonitor *mon,
                           qemuMonitorFdsets **fdsets);

int
qemuMonitorJSONSendFileHandle(qemuMonitor *mon,
                              const char *fdname,
                              int fd);

int
qemuMonitorJSONCloseFileHandle(qemuMonitor *mon,
                               const char *fdname);

int
qemuMonitorJSONAddNetdev(qemuMonitor *mon,
                         virJSONValue **props);

int
qemuMonitorJSONRemoveNetdev(qemuMonitor *mon,
                            const char *alias);

int
qemuMonitorJSONQueryRxFilter(qemuMonitor *mon,
                             const char *alias,
                             virNetDevRxFilter **filter);

int
qemuMonitorJSONGetChardevInfo(qemuMonitor *mon,
                              GHashTable *info);

int
qemuMonitorJSONAttachPCIDiskController(qemuMonitor *mon,
                                       const char *bus,
                                       virPCIDeviceAddress *guestAddr);

int
qemuMonitorJSONAddDeviceProps(qemuMonitor *mon,
                              virJSONValue **props);

int
qemuMonitorJSONDelDevice(qemuMonitor *mon,
                         const char *devalias);

int
qemuMonitorJSONAddObject(qemuMonitor *mon,
                         virJSONValue **props);

int
qemuMonitorJSONDelObject(qemuMonitor *mon,
                         const char *objalias,
                         bool report_error);

int
qemuMonitorJSONTransaction(qemuMonitor *mon,
                           virJSONValue **actions)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int
qemuMonitorJSONDriveMirror(qemuMonitor *mon,
                           const char *device,
                           const char *file,
                           const char *format,
                           unsigned long long speed,
                           unsigned int granularity,
                           unsigned long long buf_size,
                           bool shallow,
                           bool reuse)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int
qemuMonitorJSONBlockdevMirror(qemuMonitor *mon,
                              const char *jobname,
                              bool persistjob,
                              const char *device,
                              const char *target,
                              unsigned long long speed,
                              unsigned int granularity,
                              unsigned long long buf_size,
                              bool shallow,
                              bool syncWrite)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);

int
qemuMonitorJSONDrivePivot(qemuMonitor *mon,
                          const char *jobname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONBlockCommit(qemuMonitor *mon,
                           const char *device,
                           const char *jobname,
                           bool persistjob,
                           const char *top,
                           const char *topNode,
                           const char *base,
                           const char *baseNode,
                           const char *backingName,
                           unsigned long long bandwidth)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

char *
qemuMonitorJSONDiskNameLookup(qemuMonitor *mon,
                              const char *device,
                              virStorageSource *top,
                              virStorageSource *target)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);

int
qemuMonitorJSONArbitraryCommand(qemuMonitor *mon,
                                const char *cmd_str,
                                char **reply_str);

int
qemuMonitorJSONInjectNMI(qemuMonitor *mon);

int
qemuMonitorJSONSendKey(qemuMonitor *mon,
                       unsigned int holdtime,
                       unsigned int *keycodes,
                       unsigned int nkeycodes);

int
qemuMonitorJSONScreendump(qemuMonitor *mon,
                          const char *device,
                          unsigned int head,
                          const char *file);

int
qemuMonitorJSONBlockStream(qemuMonitor *mon,
                           const char *device,
                           const char *jobname,
                           bool persistjob,
                           const char *base,
                           const char *baseNode,
                           const char *backingName,
                           unsigned long long speed)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONBlockJobCancel(qemuMonitor *mon,
                              const char *jobname,
                              bool force)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONGetJobInfo(qemuMonitor *mon,
                          qemuMonitorJobInfo ***jobs,
                          size_t *njobs);


int
qemuMonitorJSONBlockJobSetSpeed(qemuMonitor *mon,
                                const char *jobname,
                                unsigned long long speed)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

GHashTable *
qemuMonitorJSONGetAllBlockJobInfo(qemuMonitor *mon,
                                  bool rawjobname)
    ATTRIBUTE_NONNULL(1);

int
qemuMonitorJSONJobDismiss(qemuMonitor *mon,
                          const char *jobname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONJobComplete(qemuMonitor *mon,
                           const char *jobname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONSetLink(qemuMonitor *mon,
                       const char *name,
                       virDomainNetInterfaceLinkState state);

int
qemuMonitorJSONOpenGraphics(qemuMonitor *mon,
                            const char *protocol,
                            const char *fdname,
                            bool skipauth);

int
qemuMonitorJSONSetBlockIoThrottle(qemuMonitor *mon,
                                  const char *drivealias,
                                  const char *qomid,
                                  virDomainBlockIoTuneInfo *info);

int
qemuMonitorJSONGetBlockIoThrottle(qemuMonitor *mon,
                                  const char *drivealias,
                                  const char *qdevid,
                                  virDomainBlockIoTuneInfo *reply);

int
qemuMonitorJSONSystemWakeup(qemuMonitor *mon);

char *
qemuMonitorJSONGetSEVMeasurement(qemuMonitor *mon);

int
qemuMonitorJSONGetSEVInfo(qemuMonitor *mon,
                          unsigned int *apiMajor,
                          unsigned int *apiMinor,
                          unsigned int *buildID,
                          unsigned int *policy)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);

int
qemuMonitorJSONGetVersion(qemuMonitor *mon,
                          int *major,
                          int *minor,
                          int *micro,
                          char **package)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int qemuMonitorJSONSetLaunchSecurityState(qemuMonitor *mon,
                                          const char *secrethdr,
                                          const char *secret,
                                          unsigned long long setaddr,
                                          bool hasSetaddr);

int
qemuMonitorJSONGetMachines(qemuMonitor *mon,
                           qemuMonitorMachineInfo ***machines)
    ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONGetCPUDefinitions(qemuMonitor *mon,
                                 qemuMonitorCPUDefs **cpuDefs)
    ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONGetCPUModelExpansion(qemuMonitor *mon,
                                    qemuMonitorCPUModelExpansionType type,
                                    virCPUDef *cpu,
                                    bool migratable,
                                    bool fail_no_props,
                                    qemuMonitorCPUModelInfo **model_info)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(6);

int
qemuMonitorJSONGetCPUModelBaseline(qemuMonitor *mon,
                                   virCPUDef *cpu_a,
                                   virCPUDef *cpu_b,
                                   qemuMonitorCPUModelInfo **baseline)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int
qemuMonitorJSONGetCPUModelComparison(qemuMonitor *mon,
                                     virCPUDef *cpu_a,
                                     virCPUDef *cpu_b,
                                     char **result)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int
qemuMonitorJSONGetCommands(qemuMonitor *mon,
                           char ***commands)
    ATTRIBUTE_NONNULL(2);

GHashTable *
qemuMonitorJSONGetCommandLineOptions(qemuMonitor *mon);

int
qemuMonitorJSONGetKVMState(qemuMonitor *mon,
                           bool *enabled,
                           bool *present)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int
qemuMonitorJSONGetObjectTypes(qemuMonitor *mon,
                              char ***types)
    ATTRIBUTE_NONNULL(2);

/* ListPath structures and API's are public only for qemumonitorjsontest */
typedef struct _qemuMonitorJSONListPath qemuMonitorJSONListPath;
struct _qemuMonitorJSONListPath {
    char *name;
    char *type;
};

int
qemuMonitorJSONGetObjectListPaths(qemuMonitor *mon,
                                  const char *path,
                                  qemuMonitorJSONListPath ***paths)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

void
qemuMonitorJSONListPathFree(qemuMonitorJSONListPath *paths);

/* ObjectProperty structures and Get/Set API's are public only
 * for qemumonitorjsontest
 */
/* Flags for the 'type' field in _qemuMonitorJSONObjectProperty */
typedef enum {
    QEMU_MONITOR_OBJECT_PROPERTY_BOOLEAN=1,
    QEMU_MONITOR_OBJECT_PROPERTY_INT,
    QEMU_MONITOR_OBJECT_PROPERTY_LONG,
    QEMU_MONITOR_OBJECT_PROPERTY_UINT,
    QEMU_MONITOR_OBJECT_PROPERTY_ULONG,
    QEMU_MONITOR_OBJECT_PROPERTY_DOUBLE,
    QEMU_MONITOR_OBJECT_PROPERTY_STRING,

    QEMU_MONITOR_OBJECT_PROPERTY_LAST
} qemuMonitorJSONObjectPropertyType;

typedef struct _qemuMonitorJSONObjectProperty qemuMonitorJSONObjectProperty;
struct _qemuMonitorJSONObjectProperty {
    int type;    /* qemuMonitorJSONObjectPropertyType */
    union {
        bool b;
        int iv;
        long long l;
        unsigned int ui;
        unsigned long long ul;
        double d;
        char *str;
    } val;
};

int
qemuMonitorJSONGetObjectProperty(qemuMonitor *mon,
                                 const char *path,
                                 const char *property,
                                 qemuMonitorJSONObjectProperty *prop)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int
qemuMonitorJSONSetObjectProperty(qemuMonitor *mon,
                                 const char *path,
                                 const char *property,
                                 qemuMonitorJSONObjectProperty *prop)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

GHashTable *
qemuMonitorJSONGetDeviceProps(qemuMonitor *mon,
                              const char *device)
    ATTRIBUTE_NONNULL(2);
int
qemuMonitorJSONGetObjectProps(qemuMonitor *mon,
                              const char *object,
                              char ***props)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

char *
qemuMonitorJSONGetTargetArch(qemuMonitor *mon);

int
qemuMonitorJSONNBDServerStart(qemuMonitor *mon,
                              const virStorageNetHostDef *server,
                              const char *tls_alias);
int
qemuMonitorJSONNBDServerAdd(qemuMonitor *mon,
                            const char *deviceID,
                            const char *export,
                            bool writable,
                            const char *bitmap);
int
qemuMonitorJSONNBDServerStop(qemuMonitor *mon);

int
qemuMonitorJSONBlockExportAdd(qemuMonitor *mon,
                              virJSONValue **props);

int
qemuMonitorJSONGetTPMModels(qemuMonitor *mon,
                            char ***tpmmodels)
    ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONGetTPMTypes(qemuMonitor *mon,
                           char ***tpmtypes)
    ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONAttachCharDev(qemuMonitor *mon,
                             const char *chrID,
                             virDomainChrSourceDef *chr);
int
qemuMonitorJSONDetachCharDev(qemuMonitor *mon,
                             const char *chrID);

int
qemuMonitorJSONGetDeviceAliases(qemuMonitor *mon,
                                char ***aliases);

int
qemuMonitorJSONGetGuestCPUx86(qemuMonitor *mon,
                              const char *cpuQOMPath,
                              virCPUData **data,
                              virCPUData **disabled);

int
qemuMonitorJSONGetGuestCPU(qemuMonitor *mon,
                           virArch arch,
                           const char *cpuQOMPath,
                           qemuMonitorCPUFeatureTranslationCallback translate,
                           void *opaque,
                           virCPUData **enabled,
                           virCPUData **disabled);

int
qemuMonitorJSONRTCResetReinjection(qemuMonitor *mon);

int
qemuMonitorJSONGetIOThreads(qemuMonitor *mon,
                            qemuMonitorIOThreadInfo ***iothreads,
                            int *niothreads)
    ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONSetIOThread(qemuMonitor *mon,
                           qemuMonitorIOThreadInfo *iothreadInfo)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONGetMemoryDeviceInfo(qemuMonitor *mon,
                                   GHashTable *info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONFindLinkPath(qemuMonitor *mon,
                            const char *name,
                            const char *alias,
                            char **path)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4);

int
qemuMonitorJSONMigrateIncoming(qemuMonitor *mon,
                               const char *uri)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONMigrateStartPostCopy(qemuMonitor *mon)
    ATTRIBUTE_NONNULL(1);

int
qemuMonitorJSONMigrateContinue(qemuMonitor *mon,
                               qemuMonitorMigrationStatus status)
    ATTRIBUTE_NONNULL(1);

int
qemuMonitorJSONGetRTCTime(qemuMonitor *mon,
                          struct tm *tm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONGetHotpluggableCPUs(qemuMonitor *mon,
                                   struct qemuMonitorQueryHotpluggableCpusEntry **entries,
                                   size_t *nentries)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

virJSONValue *
qemuMonitorJSONQueryQMPSchema(qemuMonitor *mon)
    ATTRIBUTE_NONNULL(1);

int
qemuMonitorJSONSetBlockThreshold(qemuMonitor *mon,
                                 const char *nodename,
                                 unsigned long long threshold)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

virJSONValue *
qemuMonitorJSONQueryNamedBlockNodes(qemuMonitor *mon,
                                    bool flat)
    ATTRIBUTE_NONNULL(1);

int
qemuMonitorJSONSetWatchdogAction(qemuMonitor *mon,
                                 const char *action)
    ATTRIBUTE_NONNULL(1);

int
qemuMonitorJSONBlockdevCreate(qemuMonitor *mon,
                              const char *jobname,
                              virJSONValue **props)
    ATTRIBUTE_NONNULL(1);

int
qemuMonitorJSONBlockdevAdd(qemuMonitor *mon,
                           virJSONValue **props)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONBlockdevReopen(qemuMonitor *mon,
                              virJSONValue **props)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONBlockdevDel(qemuMonitor *mon,
                           const char *nodename)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONBlockdevTrayOpen(qemuMonitor *mon,
                                const char *id,
                                bool force)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONBlockdevTrayClose(qemuMonitor *mon,
                                 const char *id)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONBlockdevMediumRemove(qemuMonitor *mon,
                                    const char *id)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONBlockdevMediumInsert(qemuMonitor *mon,
                                    const char *id,
                                    const char *nodename)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int
qemuMonitorJSONGetPRManagerInfo(qemuMonitor *mon,
                                GHashTable *info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONGetCurrentMachineInfo(qemuMonitor *mon,
                                     qemuMonitorCurrentMachineInfo *info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONTransactionBitmapAdd(virJSONValue *actions,
                                    const char *node,
                                    const char *name,
                                    bool persistent,
                                    bool disabled,
                                    unsigned long long granularity);
int
qemuMonitorJSONTransactionBitmapRemove(virJSONValue *actions,
                                       const char *node,
                                       const char *name);

int
qemuMonitorJSONBitmapRemove(qemuMonitor *mon,
                            const char *node,
                            const char *name);

int
qemuMonitorJSONTransactionBitmapEnable(virJSONValue *actions,
                                       const char *node,
                                       const char *name);
int
qemuMonitorJSONTransactionBitmapDisable(virJSONValue *actions,
                                        const char *node,
                                        const char *name);
int
qemuMonitorJSONTransactionBitmapMerge(virJSONValue *actions,
                                      const char *node,
                                      const char *target,
                                      virJSONValue **sources);

int
qemuMonitorJSONTransactionBitmapMergeSourceAddBitmap(virJSONValue *sources,
                                                     const char *sourcenode,
                                                     const char *sourcebitmap);

int
qemuMonitorJSONTransactionSnapshotLegacy(virJSONValue *actions,
                                         const char *device,
                                         const char *path,
                                         const char *format,
                                         bool existing);
int
qemuMonitorJSONTransactionSnapshotBlockdev(virJSONValue *actions,
                                           const char *node,
                                           const char *overlay);

int
qemuMonitorJSONTransactionBackup(virJSONValue *actions,
                                 const char *device,
                                 const char *jobname,
                                 const char *target,
                                 const char *bitmap,
                                 qemuMonitorTransactionBackupSyncMode syncmode);

int
qemuMonitorJSONSetDBusVMStateIdList(qemuMonitor *mon,
                                    const char *vmstatepath,
                                    const char *idstr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int
qemuMonitorJSONGetCPUMigratable(qemuMonitor *mon,
                                const char *cpuQOMPath,
                                bool *migratable);

int
qemuMonitorJSONStartDirtyRateCalc(qemuMonitor *mon,
                                  int seconds,
                                  qemuMonitorDirtyRateCalcMode mode);

int
qemuMonitorJSONQueryDirtyRate(qemuMonitor *mon,
                              qemuMonitorDirtyRateInfo *info);

int
qemuMonitorJSONSetAction(qemuMonitor *mon,
                         qemuMonitorActionShutdown shutdown,
                         qemuMonitorActionReboot reboot,
                         qemuMonitorActionWatchdog watchdog,
                         qemuMonitorActionPanic panic);

int
qemuMonitorJSONChangeMemoryRequestedSize(qemuMonitor *mon,
                                         const char *alias,
                                         unsigned long long requestedsize);
