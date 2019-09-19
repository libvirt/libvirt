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

int qemuMonitorJSONTransactionAdd(virJSONValuePtr actions,
                                  const char *cmdname,
                                  ...);

int qemuMonitorJSONIOProcessLine(qemuMonitorPtr mon,
                                 const char *line,
                                 qemuMonitorMessagePtr msg);

int qemuMonitorJSONIOProcess(qemuMonitorPtr mon,
                             const char *data,
                             size_t len,
                             qemuMonitorMessagePtr msg);

int qemuMonitorJSONHumanCommand(qemuMonitorPtr mon,
                                const char *cmd,
                                char **reply);

int qemuMonitorJSONSetCapabilities(qemuMonitorPtr mon);

int qemuMonitorJSONStartCPUs(qemuMonitorPtr mon);
int qemuMonitorJSONStopCPUs(qemuMonitorPtr mon);
int qemuMonitorJSONGetStatus(qemuMonitorPtr mon,
                             bool *running,
                             virDomainPausedReason *reason);

int qemuMonitorJSONSystemPowerdown(qemuMonitorPtr mon);
int qemuMonitorJSONSystemReset(qemuMonitorPtr mon);

int qemuMonitorJSONQueryCPUs(qemuMonitorPtr mon,
                             struct qemuMonitorQueryCpusEntry **entries,
                             size_t *nentries,
                             bool force,
                             bool fast);
int qemuMonitorJSONGetVirtType(qemuMonitorPtr mon,
                               virDomainVirtType *virtType);
int qemuMonitorJSONUpdateVideoMemorySize(qemuMonitorPtr mon,
                                         virDomainVideoDefPtr video,
                                         char *path);
int qemuMonitorJSONUpdateVideoVram64Size(qemuMonitorPtr mon,
                                         virDomainVideoDefPtr video,
                                         char *path);
int qemuMonitorJSONGetBalloonInfo(qemuMonitorPtr mon,
                                  unsigned long long *currmem);
int qemuMonitorJSONGetMemoryStats(qemuMonitorPtr mon,
                                  char *balloonpath,
                                  virDomainMemoryStatPtr stats,
                                  unsigned int nr_stats);
int qemuMonitorJSONSetMemoryStatsPeriod(qemuMonitorPtr mon,
                                        char *balloonpath,
                                        int period);
int qemuMonitorJSONGetBlockInfo(qemuMonitorPtr mon,
                                virHashTablePtr table);

virJSONValuePtr qemuMonitorJSONQueryBlockstats(qemuMonitorPtr mon);
int qemuMonitorJSONGetAllBlockStatsInfo(qemuMonitorPtr mon,
                                        virHashTablePtr hash,
                                        bool backingChain);
int qemuMonitorJSONBlockStatsUpdateCapacity(qemuMonitorPtr mon,
                                            virHashTablePtr stats,
                                            bool backingChain);
int qemuMonitorJSONBlockStatsUpdateCapacityBlockdev(qemuMonitorPtr mon,
                                                    virHashTablePtr stats);

int qemuMonitorJSONBlockResize(qemuMonitorPtr mon,
                               const char *device,
                               const char *nodename,
                               unsigned long long size);

int qemuMonitorJSONSetPassword(qemuMonitorPtr mon,
                               const char *protocol,
                               const char *password,
                               const char *action_if_connected);
int qemuMonitorJSONExpirePassword(qemuMonitorPtr mon,
                                  const char *protocol,
                                  const char *expire_time);
int qemuMonitorJSONSetBalloon(qemuMonitorPtr mon,
                              unsigned long long newmem);
int qemuMonitorJSONSetCPU(qemuMonitorPtr mon, int cpu, bool online);

int qemuMonitorJSONEjectMedia(qemuMonitorPtr mon,
                              const char *dev_name,
                              bool force);
int qemuMonitorJSONChangeMedia(qemuMonitorPtr mon,
                               const char *dev_name,
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

int qemuMonitorJSONGetMigrationCacheSize(qemuMonitorPtr mon,
                                         unsigned long long *cacheSize);
int qemuMonitorJSONSetMigrationCacheSize(qemuMonitorPtr mon,
                                         unsigned long long cacheSize);

int qemuMonitorJSONGetMigrationParams(qemuMonitorPtr mon,
                                      virJSONValuePtr *params);
int qemuMonitorJSONSetMigrationParams(qemuMonitorPtr mon,
                                      virJSONValuePtr params);

int qemuMonitorJSONGetMigrationStats(qemuMonitorPtr mon,
                                     qemuMonitorMigrationStatsPtr stats,
                                     char **error);

int qemuMonitorJSONGetMigrationCapabilities(qemuMonitorPtr mon,
                                            char ***capabilities);
int qemuMonitorJSONSetMigrationCapabilities(qemuMonitorPtr mon,
                                            virJSONValuePtr caps);

int qemuMonitorJSONGetGICCapabilities(qemuMonitorPtr mon,
                                      virGICCapability **capabilities);

int qemuMonitorJSONGetSEVCapabilities(qemuMonitorPtr mon,
                                      virSEVCapability **capabilities);

int qemuMonitorJSONMigrate(qemuMonitorPtr mon,
                           unsigned int flags,
                           const char *uri);
int qemuMonitorJSONGetSpiceMigrationStatus(qemuMonitorPtr mon,
                                           bool *spice_migrated);


int qemuMonitorJSONMigrateCancel(qemuMonitorPtr mon);

int qemuMonitorJSONQueryDump(qemuMonitorPtr mon,
                             qemuMonitorDumpStatsPtr stats);

int qemuMonitorJSONGetDumpGuestMemoryCapability(qemuMonitorPtr mon,
                                                const char *capability);

int qemuMonitorJSONDump(qemuMonitorPtr mon,
                        const char *protocol,
                        const char *dumpformat,
                        bool detach);

int qemuMonitorJSONGraphicsRelocate(qemuMonitorPtr mon,
                                    int type,
                                    const char *hostname,
                                    int port,
                                    int tlsPort,
                                    const char *tlsSubject);

int qemuMonitorJSONAddPCIHostDevice(qemuMonitorPtr mon,
                                    virPCIDeviceAddress *hostAddr,
                                    virPCIDeviceAddress *guestAddr);

int qemuMonitorJSONAddPCIDisk(qemuMonitorPtr mon,
                              const char *path,
                              const char *bus,
                              virPCIDeviceAddress *guestAddr);

int qemuMonitorJSONAddPCINetwork(qemuMonitorPtr mon,
                                 const char *nicstr,
                                 virPCIDeviceAddress *guestAddr);

int qemuMonitorJSONRemovePCIDevice(qemuMonitorPtr mon,
                                   virPCIDeviceAddress *guestAddr);

int qemuMonitorJSONSendFileHandle(qemuMonitorPtr mon,
                                  const char *fdname,
                                  int fd);

int qemuMonitorJSONCloseFileHandle(qemuMonitorPtr mon,
                                   const char *fdname);

int qemuMonitorJSONAddNetdev(qemuMonitorPtr mon,
                             const char *netdevstr);

int qemuMonitorJSONRemoveNetdev(qemuMonitorPtr mon,
                                const char *alias);

int qemuMonitorJSONQueryRxFilter(qemuMonitorPtr mon, const char *alias,
                                 virNetDevRxFilterPtr *filter);

int qemuMonitorJSONGetChardevInfo(qemuMonitorPtr mon,
                                  virHashTablePtr info);

int qemuMonitorJSONAttachPCIDiskController(qemuMonitorPtr mon,
                                           const char *bus,
                                           virPCIDeviceAddress *guestAddr);

int qemuMonitorJSONAddDeviceArgs(qemuMonitorPtr mon,
                                 virJSONValuePtr args);
int qemuMonitorJSONAddDevice(qemuMonitorPtr mon,
                             const char *devicestr);

int qemuMonitorJSONDelDevice(qemuMonitorPtr mon,
                             const char *devalias);

int qemuMonitorJSONAddObject(qemuMonitorPtr mon,
                             virJSONValuePtr props);

int qemuMonitorJSONDelObject(qemuMonitorPtr mon,
                             const char *objalias);

int qemuMonitorJSONTransaction(qemuMonitorPtr mon, virJSONValuePtr *actions)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int qemuMonitorJSONDriveMirror(qemuMonitorPtr mon,
                               const char *device,
                               const char *file,
                               const char *format,
                               unsigned long long speed,
                               unsigned int granularity,
                               unsigned long long buf_size,
                               bool shallow,
                               bool reuse)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
int qemuMonitorJSONBlockdevMirror(qemuMonitorPtr mon,
                                  const char *jobname,
                                  bool persistjob,
                                  const char *device,
                                  const char *target,
                                  unsigned long long speed,
                                  unsigned int granularity,
                                  unsigned long long buf_size,
                                  bool shallow)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);
int qemuMonitorJSONDrivePivot(qemuMonitorPtr mon,
                              const char *jobname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool qemuMonitorJSONSupportsActiveCommit(qemuMonitorPtr mon)
    ATTRIBUTE_NONNULL(1);

int qemuMonitorJSONBlockCommit(qemuMonitorPtr mon,
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

char *qemuMonitorJSONDiskNameLookup(qemuMonitorPtr mon,
                                    const char *device,
                                    virStorageSourcePtr top,
                                    virStorageSourcePtr target)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);

int qemuMonitorJSONArbitraryCommand(qemuMonitorPtr mon,
                                    const char *cmd_str,
                                    char **reply_str,
                                    bool hmp);

int qemuMonitorJSONInjectNMI(qemuMonitorPtr mon);

int qemuMonitorJSONSendKey(qemuMonitorPtr mon,
                           unsigned int holdtime,
                           unsigned int *keycodes,
                           unsigned int nkeycodes);

int qemuMonitorJSONScreendump(qemuMonitorPtr mon,
                              const char *device,
                              unsigned int head,
                              const char *file);

int qemuMonitorJSONBlockStream(qemuMonitorPtr mon,
                               const char *device,
                               const char *jobname,
                               bool persistjob,
                               const char *base,
                               const char *baseNode,
                               const char *backingName,
                               unsigned long long speed)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONBlockJobCancel(qemuMonitorPtr mon,
                                  const char *jobname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONGetJobInfo(qemuMonitorPtr mon,
                          qemuMonitorJobInfoPtr **jobs,
                          size_t *njobs);


int qemuMonitorJSONBlockJobSetSpeed(qemuMonitorPtr mon,
                                    const char *jobname,
                                    unsigned long long speed)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

virHashTablePtr qemuMonitorJSONGetAllBlockJobInfo(qemuMonitorPtr mon,
                                                  bool rawjobname)
    ATTRIBUTE_NONNULL(1);

int qemuMonitorJSONJobDismiss(qemuMonitorPtr mon,
                              const char *jobname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONJobCancel(qemuMonitorPtr mon,
                             const char *jobname,
                             bool quiet)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONJobComplete(qemuMonitorPtr mon,
                               const char *jobname)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONSetLink(qemuMonitorPtr mon,
                           const char *name,
                           virDomainNetInterfaceLinkState state);

int qemuMonitorJSONOpenGraphics(qemuMonitorPtr mon,
                                const char *protocol,
                                const char *fdname,
                                bool skipauth);

int qemuMonitorJSONSetBlockIoThrottle(qemuMonitorPtr mon,
                                      const char *drivealias,
                                      const char *qomid,
                                      virDomainBlockIoTuneInfoPtr info,
                                      bool supportMaxOptions,
                                      bool supportGroupNameOption,
                                      bool supportMaxLengthOptions);

int qemuMonitorJSONGetBlockIoThrottle(qemuMonitorPtr mon,
                                      const char *drivealias,
                                      const char *qdevid,
                                      virDomainBlockIoTuneInfoPtr reply);

int qemuMonitorJSONSystemWakeup(qemuMonitorPtr mon);

char *qemuMonitorJSONGetSEVMeasurement(qemuMonitorPtr mon);

int qemuMonitorJSONGetVersion(qemuMonitorPtr mon,
                              int *major,
                              int *minor,
                              int *micro,
                              char **package)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int qemuMonitorJSONGetMachines(qemuMonitorPtr mon,
                               qemuMonitorMachineInfoPtr **machines)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONGetCPUDefinitions(qemuMonitorPtr mon,
                                     qemuMonitorCPUDefInfoPtr **cpus)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONGetCPUModelExpansion(qemuMonitorPtr mon,
                                        qemuMonitorCPUModelExpansionType type,
                                        const char *model_name,
                                        bool migratable,
                                        qemuMonitorCPUModelInfoPtr *model_info)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(5);

int qemuMonitorJSONGetCommands(qemuMonitorPtr mon,
                               char ***commands)
    ATTRIBUTE_NONNULL(2);
int qemuMonitorJSONGetEvents(qemuMonitorPtr mon,
                             char ***events)
    ATTRIBUTE_NONNULL(2);
int qemuMonitorJSONGetCommandLineOptionParameters(qemuMonitorPtr mon,
                                                  const char *option,
                                                  char ***params,
                                                  bool *found)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int qemuMonitorJSONGetKVMState(qemuMonitorPtr mon,
                               bool *enabled,
                               bool *present)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int qemuMonitorJSONGetObjectTypes(qemuMonitorPtr mon,
                                  char ***types)
    ATTRIBUTE_NONNULL(2);

/* ListPath structures and API's are public only for qemumonitorjsontest */
typedef struct _qemuMonitorJSONListPath qemuMonitorJSONListPath;
typedef qemuMonitorJSONListPath *qemuMonitorJSONListPathPtr;

struct _qemuMonitorJSONListPath {
    char *name;
    char *type;
};

int qemuMonitorJSONGetObjectListPaths(qemuMonitorPtr mon,
                                      const char *path,
                                      qemuMonitorJSONListPathPtr **paths)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

void qemuMonitorJSONListPathFree(qemuMonitorJSONListPathPtr paths);

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
typedef qemuMonitorJSONObjectProperty *qemuMonitorJSONObjectPropertyPtr;
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

int qemuMonitorJSONGetObjectProperty(qemuMonitorPtr mon,
                                     const char *path,
                                     const char *property,
                                     qemuMonitorJSONObjectPropertyPtr prop)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int qemuMonitorJSONSetObjectProperty(qemuMonitorPtr mon,
                                     const char *path,
                                     const char *property,
                                     qemuMonitorJSONObjectPropertyPtr prop)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);

int qemuMonitorJSONGetDeviceProps(qemuMonitorPtr mon,
                                  const char *device,
                                  char ***props)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
int qemuMonitorJSONGetObjectProps(qemuMonitorPtr mon,
                                  const char *object,
                                  char ***props)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
char *qemuMonitorJSONGetTargetArch(qemuMonitorPtr mon);

int qemuMonitorJSONNBDServerStart(qemuMonitorPtr mon,
                                  const virStorageNetHostDef *server,
                                  const char *tls_alias);
int qemuMonitorJSONNBDServerAdd(qemuMonitorPtr mon,
                                const char *deviceID,
                                const char *export,
                                bool writable,
                                const char *bitmap);
int qemuMonitorJSONNBDServerStop(qemuMonitorPtr mon);
int qemuMonitorJSONGetTPMModels(qemuMonitorPtr mon,
                                char ***tpmmodels)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONGetTPMTypes(qemuMonitorPtr mon,
                               char ***tpmtypes)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONAttachCharDev(qemuMonitorPtr mon,
                                 const char *chrID,
                                 virDomainChrSourceDefPtr chr);
int qemuMonitorJSONDetachCharDev(qemuMonitorPtr mon,
                                 const char *chrID);

int qemuMonitorJSONGetDeviceAliases(qemuMonitorPtr mon,
                                    char ***aliases);

int qemuMonitorJSONGetCPUx86Data(qemuMonitorPtr mon,
                                 const char *property,
                                 virCPUDataPtr *cpudata);

int qemuMonitorJSONGetGuestCPUx86(qemuMonitorPtr mon,
                                  virCPUDataPtr *data,
                                  virCPUDataPtr *disabled);

int qemuMonitorJSONGetGuestCPU(qemuMonitorPtr mon,
                               virArch arch,
                               qemuMonitorCPUFeatureTranslationCallback translate,
                               void *opaque,
                               virCPUDataPtr *enabled,
                               virCPUDataPtr *disabled);

int qemuMonitorJSONRTCResetReinjection(qemuMonitorPtr mon);

int qemuMonitorJSONGetIOThreads(qemuMonitorPtr mon,
                                qemuMonitorIOThreadInfoPtr **iothreads)
    ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONSetIOThread(qemuMonitorPtr mon,
                               qemuMonitorIOThreadInfoPtr iothreadInfo)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONGetMemoryDeviceInfo(qemuMonitorPtr mon,
                                       virHashTablePtr info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONFindLinkPath(qemuMonitorPtr mon,
                                const char *name,
                                const char *alias,
                                char **path)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4);

int qemuMonitorJSONMigrateIncoming(qemuMonitorPtr mon,
                                   const char *uri)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONMigrateStartPostCopy(qemuMonitorPtr mon)
    ATTRIBUTE_NONNULL(1);

int qemuMonitorJSONMigrateContinue(qemuMonitorPtr mon,
                                   qemuMonitorMigrationStatus status)
    ATTRIBUTE_NONNULL(1);

int qemuMonitorJSONGetRTCTime(qemuMonitorPtr mon,
                              struct tm *tm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONGetHotpluggableCPUs(qemuMonitorPtr mon,
                                       struct qemuMonitorQueryHotpluggableCpusEntry **entries,
                                       size_t *nentries)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

virJSONValuePtr qemuMonitorJSONQueryQMPSchema(qemuMonitorPtr mon)
    ATTRIBUTE_NONNULL(1);

int qemuMonitorJSONSetBlockThreshold(qemuMonitorPtr mon,
                                     const char *nodename,
                                     unsigned long long threshold)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

virJSONValuePtr qemuMonitorJSONQueryNamedBlockNodes(qemuMonitorPtr mon)
    ATTRIBUTE_NONNULL(1);

int qemuMonitorJSONSetWatchdogAction(qemuMonitorPtr mon,
                                     const char *action)
    ATTRIBUTE_NONNULL(1);

int qemuMonitorJSONBlockdevCreate(qemuMonitorPtr mon,
                                  const char *jobname,
                                  virJSONValuePtr props)
    ATTRIBUTE_NONNULL(1);

int qemuMonitorJSONBlockdevAdd(qemuMonitorPtr mon,
                               virJSONValuePtr props)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONBlockdevDel(qemuMonitorPtr mon,
                               const char *nodename)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONBlockdevTrayOpen(qemuMonitorPtr mon,
                                    const char *id,
                                    bool force)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONBlockdevTrayClose(qemuMonitorPtr mon,
                                     const char *id)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONBlockdevMediumRemove(qemuMonitorPtr mon,
                                        const char *id)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuMonitorJSONBlockdevMediumInsert(qemuMonitorPtr mon,
                                        const char *id,
                                        const char *nodename)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int qemuMonitorJSONGetPRManagerInfo(qemuMonitorPtr mon,
                                    virHashTablePtr info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
qemuMonitorJSONGetCurrentMachineInfo(qemuMonitorPtr mon,
                                     qemuMonitorCurrentMachineInfoPtr info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int qemuMonitorJSONAddBitmap(qemuMonitorPtr mon,
                             const char *node,
                             const char *bitmap,
                             bool persistent);

int qemuMonitorJSONEnableBitmap(qemuMonitorPtr mon,
                                const char *node,
                                const char *bitmap);

int qemuMonitorJSONMergeBitmaps(qemuMonitorPtr mon,
                                const char *node,
                                const char *dst,
                                virJSONValuePtr *src);

int qemuMonitorJSONDeleteBitmap(qemuMonitorPtr mon,
                                const char *node,
                                const char *bitmap);
