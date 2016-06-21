/*
 * driver-hypervisor.h: entry points for hypervisor drivers
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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

#ifndef __VIR_DRIVER_HYPERVISOR_H__
# define __VIR_DRIVER_HYPERVISOR_H__

# ifndef __VIR_DRIVER_H_INCLUDES___
#  error "Don't include this file directly, only use driver.h"
# endif

typedef virDrvOpenStatus
(*virDrvConnectOpen)(virConnectPtr conn,
                     virConnectAuthPtr auth,
                     virConfPtr conf,
                     unsigned int flags);

typedef int
(*virDrvConnectClose)(virConnectPtr conn);

typedef int
(*virDrvConnectSupportsFeature)(virConnectPtr conn,
                                int feature);

typedef const char *
(*virDrvConnectGetType)(virConnectPtr conn);

typedef int
(*virDrvConnectGetVersion)(virConnectPtr conn,
                           unsigned long *hvVer);

typedef int
(*virDrvConnectGetLibVersion)(virConnectPtr conn,
                              unsigned long *libVer);

typedef char *
(*virDrvConnectGetHostname)(virConnectPtr conn);

typedef char *
(*virDrvConnectGetURI)(virConnectPtr conn);

typedef char *
(*virDrvConnectGetSysinfo)(virConnectPtr conn,
                           unsigned int flags);

typedef int
(*virDrvConnectGetMaxVcpus)(virConnectPtr conn,
                            const char *type);

typedef int
(*virDrvNodeGetInfo)(virConnectPtr conn,
                     virNodeInfoPtr info);

typedef char *
(*virDrvConnectGetCapabilities)(virConnectPtr conn);

typedef char *
(*virDrvConnectGetDomainCapabilities)(virConnectPtr conn,
                                      const char *emulatorbin,
                                      const char *arch,
                                      const char *machine,
                                      const char *virttype,
                                      unsigned int flags);

typedef int
(*virDrvConnectListDomains)(virConnectPtr conn,
                            int *ids,
                            int maxids);

typedef int
(*virDrvConnectNumOfDomains)(virConnectPtr conn);

typedef virDomainPtr
(*virDrvDomainCreateXML)(virConnectPtr conn,
                         const char *xmlDesc,
                         unsigned int flags);
typedef virDomainPtr
(*virDrvDomainCreateXMLWithFiles)(virConnectPtr conn,
                                  const char *xmlDesc,
                                  unsigned int nfiles,
                                  int *files,
                                  unsigned int flags);

typedef virDomainPtr
(*virDrvDomainLookupByID)(virConnectPtr conn,
                          int id);

typedef virDomainPtr
(*virDrvDomainLookupByUUID)(virConnectPtr conn,
                            const unsigned char *uuid);

typedef virDomainPtr
(*virDrvDomainLookupByName)(virConnectPtr conn,
                            const char *name);

typedef int
(*virDrvDomainSuspend)(virDomainPtr domain);

typedef int
(*virDrvDomainResume)(virDomainPtr domain);

typedef int
 (*virDrvDomainPMSuspendForDuration)(virDomainPtr,
                                     unsigned int target,
                                     unsigned long long duration,
                                     unsigned int flags);

typedef int
(*virDrvDomainPMWakeup)(virDomainPtr domain,
                        unsigned int flags);

typedef int
(*virDrvDomainShutdown)(virDomainPtr domain);

typedef int
(*virDrvDomainReboot)(virDomainPtr domain,
                      unsigned int flags);

typedef int
(*virDrvDomainReset)(virDomainPtr domain,
                     unsigned int flags);

typedef int
(*virDrvDomainDestroy)(virDomainPtr domain);

typedef int
(*virDrvDomainDestroyFlags)(virDomainPtr domain,
                            unsigned int flags);

typedef char *
(*virDrvDomainGetOSType)(virDomainPtr domain);

typedef char *
(*virDrvDomainGetHostname)(virDomainPtr domain,
                           unsigned int flags);

typedef unsigned long long
(*virDrvDomainGetMaxMemory)(virDomainPtr domain);

typedef int
(*virDrvDomainSetMaxMemory)(virDomainPtr domain,
                            unsigned long memory);

typedef int
(*virDrvDomainSetMemory)(virDomainPtr domain,
                         unsigned long memory);

typedef int
(*virDrvDomainSetMemoryFlags)(virDomainPtr domain,
                              unsigned long memory,
                              unsigned int flags);

typedef int
(*virDrvDomainSetMemoryStatsPeriod)(virDomainPtr domain,
                                    int period,
                                    unsigned int flags);

typedef int
(*virDrvDomainSetMemoryParameters)(virDomainPtr domain,
                                   virTypedParameterPtr params,
                                   int nparams,
                                   unsigned int flags);

typedef int
(*virDrvDomainGetMemoryParameters)(virDomainPtr domain,
                                   virTypedParameterPtr params,
                                   int *nparams,
                                   unsigned int flags);

typedef int
(*virDrvDomainSetNumaParameters)(virDomainPtr domain,
                                 virTypedParameterPtr params,
                                 int nparams,
                                 unsigned int flags);

typedef int
(*virDrvDomainGetNumaParameters)(virDomainPtr domain,
                                 virTypedParameterPtr params,
                                 int *nparams,
                                 unsigned int flags);

typedef int
(*virDrvDomainSetBlkioParameters)(virDomainPtr domain,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  unsigned int flags);

typedef int
(*virDrvDomainGetBlkioParameters)(virDomainPtr domain,
                                  virTypedParameterPtr params,
                                  int *nparams,
                                  unsigned int flags);

typedef int
(*virDrvDomainGetInfo)(virDomainPtr domain,
                       virDomainInfoPtr info);

typedef int
(*virDrvDomainGetState)(virDomainPtr domain,
                        int *state,
                        int *reason,
                        unsigned int flags);

typedef int
(*virDrvDomainGetControlInfo)(virDomainPtr domain,
                              virDomainControlInfoPtr info,
                              unsigned int flags);

typedef int
(*virDrvDomainSave)(virDomainPtr domain,
                    const char *to);

typedef int
(*virDrvDomainSaveFlags)(virDomainPtr domain,
                         const char *to,
                         const char *dxml,
                         unsigned int flags);

typedef int
(*virDrvDomainRestore)(virConnectPtr conn,
                       const char *from);

typedef int
(*virDrvDomainRestoreFlags)(virConnectPtr conn,
                            const char *from,
                            const char *dxml,
                            unsigned int flags);

typedef char *
(*virDrvDomainSaveImageGetXMLDesc)(virConnectPtr conn,
                                   const char *file,
                                   unsigned int flags);

typedef int
(*virDrvDomainSaveImageDefineXML)(virConnectPtr conn,
                                  const char *file,
                                  const char *dxml,
                                  unsigned int flags);

typedef int
(*virDrvDomainCoreDump)(virDomainPtr domain,
                        const char *to,
                        unsigned int flags);

typedef int
(*virDrvDomainCoreDumpWithFormat)(virDomainPtr domain,
                                  const char *to,
                                  unsigned int dumpformat,
                                  unsigned int flags);

typedef char *
(*virDrvDomainScreenshot)(virDomainPtr domain,
                          virStreamPtr stream,
                          unsigned int screen,
                          unsigned int flags);

typedef char *
(*virDrvDomainGetXMLDesc)(virDomainPtr dom,
                          unsigned int flags);

typedef char *
(*virDrvConnectDomainXMLFromNative)(virConnectPtr conn,
                                    const char *nativeFormat,
                                    const char *nativeConfig,
                                    unsigned int flags);

typedef char *
(*virDrvConnectDomainXMLToNative)(virConnectPtr conn,
                                  const char *nativeFormat,
                                  const char *domainXml,
                                  unsigned int flags);

typedef int
(*virDrvConnectListDefinedDomains)(virConnectPtr conn,
                                   char **const names,
                                   int maxnames);

typedef int
(*virDrvConnectListAllDomains)(virConnectPtr conn,
                               virDomainPtr **domains,
                               unsigned int flags);

typedef int
(*virDrvConnectNumOfDefinedDomains)(virConnectPtr conn);

typedef int
(*virDrvDomainCreate)(virDomainPtr dom);

typedef int
(*virDrvDomainCreateWithFlags)(virDomainPtr dom,
                               unsigned int flags);
typedef int
(*virDrvDomainCreateWithFiles)(virDomainPtr dom,
                               unsigned int nfiles,
                               int *files,
                               unsigned int flags);

typedef virDomainPtr
(*virDrvDomainDefineXML)(virConnectPtr conn,
                         const char *xml);
typedef virDomainPtr
(*virDrvDomainDefineXMLFlags)(virConnectPtr conn,
                              const char *xml,
                              unsigned int flags);

typedef int
(*virDrvDomainUndefine)(virDomainPtr dom);

typedef int
(*virDrvDomainUndefineFlags)(virDomainPtr dom,
                             unsigned int flags);

typedef int
(*virDrvDomainSetVcpus)(virDomainPtr domain,
                        unsigned int nvcpus);

typedef int
(*virDrvDomainSetVcpusFlags)(virDomainPtr domain,
                             unsigned int nvcpus,
                             unsigned int flags);

typedef int
(*virDrvDomainGetVcpusFlags)(virDomainPtr domain,
                             unsigned int flags);

typedef int
(*virDrvDomainPinVcpu)(virDomainPtr domain,
                       unsigned int vcpu,
                       unsigned char *cpumap,
                       int maplen);

typedef int
(*virDrvDomainPinVcpuFlags)(virDomainPtr domain,
                            unsigned int vcpu,
                            unsigned char *cpumap,
                            int maplen,
                            unsigned int flags);

typedef int
(*virDrvDomainGetVcpuPinInfo)(virDomainPtr domain,
                              int ncpumaps,
                              unsigned char *cpumaps,
                              int maplen,
                              unsigned int flags);

typedef int
(*virDrvDomainPinEmulator)(virDomainPtr domain,
                           unsigned char *cpumap,
                           int maplen,
                           unsigned int flags);

typedef int
(*virDrvDomainGetEmulatorPinInfo)(virDomainPtr domain,
                                  unsigned char *cpumaps,
                                  int maplen,
                                  unsigned int flags);

typedef int
(*virDrvDomainGetVcpus)(virDomainPtr domain,
                        virVcpuInfoPtr info,
                        int maxinfo,
                        unsigned char *cpumaps,
                        int maplen);

typedef int
(*virDrvDomainGetMaxVcpus)(virDomainPtr domain);

typedef int
(*virDrvDomainGetIOThreadInfo)(virDomainPtr domain,
                               virDomainIOThreadInfoPtr **info,
                               unsigned int flags);

typedef int
(*virDrvDomainPinIOThread)(virDomainPtr domain,
                           unsigned int iothread_id,
                           unsigned char *cpumap,
                           int maplen,
                           unsigned int flags);

typedef int
(*virDrvDomainAddIOThread)(virDomainPtr domain,
                           unsigned int iothread_id,
                           unsigned int flags);

typedef int
(*virDrvDomainDelIOThread)(virDomainPtr domain,
                           unsigned int iothread_id,
                           unsigned int flags);

typedef int
(*virDrvDomainGetSecurityLabel)(virDomainPtr domain,
                                virSecurityLabelPtr seclabel);

typedef int
(*virDrvDomainGetSecurityLabelList)(virDomainPtr domain,
                                    virSecurityLabelPtr* seclabels);

typedef int
(*virDrvNodeGetSecurityModel)(virConnectPtr conn,
                              virSecurityModelPtr secmodel);

typedef int
(*virDrvDomainAttachDevice)(virDomainPtr domain,
                            const char *xml);

typedef int
(*virDrvDomainAttachDeviceFlags)(virDomainPtr domain,
                                 const char *xml,
                                 unsigned int flags);

typedef int
(*virDrvDomainDetachDevice)(virDomainPtr domain,
                            const char *xml);

typedef int
(*virDrvDomainDetachDeviceFlags)(virDomainPtr domain,
                                 const char *xml,
                                 unsigned int flags);

typedef int
(*virDrvDomainUpdateDeviceFlags)(virDomainPtr domain,
                                 const char *xml,
                                 unsigned int flags);

typedef int
(*virDrvDomainGetAutostart)(virDomainPtr domain,
                            int *autostart);

typedef int
(*virDrvDomainSetAutostart)(virDomainPtr domain,
                            int autostart);

typedef char *
(*virDrvDomainGetSchedulerType)(virDomainPtr domain,
                                int *nparams);

typedef int
(*virDrvDomainGetSchedulerParameters)(virDomainPtr domain,
                                      virTypedParameterPtr params,
                                      int *nparams);

typedef int
(*virDrvDomainGetSchedulerParametersFlags)(virDomainPtr domain,
                                           virTypedParameterPtr params,
                                           int *nparams,
                                           unsigned int flags);

typedef int
(*virDrvDomainSetSchedulerParameters)(virDomainPtr domain,
                                      virTypedParameterPtr params,
                                      int nparams);

typedef int
(*virDrvDomainSetSchedulerParametersFlags)(virDomainPtr domain,
                                           virTypedParameterPtr params,
                                           int nparams,
                                           unsigned int flags);

typedef int
(*virDrvDomainBlockStats)(virDomainPtr domain,
                          const char *path,
                          virDomainBlockStatsPtr stats);

typedef int
(*virDrvDomainBlockStatsFlags)(virDomainPtr domain,
                               const char *path,
                               virTypedParameterPtr params,
                               int *nparams,
                               unsigned int flags);

typedef int
(*virDrvDomainInterfaceStats)(virDomainPtr domain,
                              const char *path,
                              virDomainInterfaceStatsPtr stats);

typedef int
(*virDrvDomainSetInterfaceParameters)(virDomainPtr dom,
                                      const char *device,
                                      virTypedParameterPtr params,
                                      int nparams,
                                      unsigned int flags);

typedef int
(*virDrvDomainGetInterfaceParameters)(virDomainPtr dom,
                                      const char *device,
                                      virTypedParameterPtr params,
                                      int *nparams,
                                      unsigned int flags);

typedef int
(*virDrvDomainMemoryStats)(virDomainPtr domain,
                           virDomainMemoryStatPtr stats,
                           unsigned int nr_stats,
                           unsigned int flags);

typedef int
(*virDrvDomainBlockPeek)(virDomainPtr domain,
                         const char *path,
                         unsigned long long offset,
                         size_t size,
                         void *buffer,
                         unsigned int flags);

typedef int
(*virDrvDomainBlockResize)(virDomainPtr domain,
                           const char *path,
                           unsigned long long size,
                           unsigned int flags);

typedef int
(*virDrvDomainMemoryPeek)(virDomainPtr domain,
                          unsigned long long start,
                          size_t size,
                          void *buffer,
                          unsigned int flags);

typedef int
(*virDrvDomainGetBlockInfo)(virDomainPtr domain,
                            const char *path,
                            virDomainBlockInfoPtr info,
                            unsigned int flags);

typedef int
(*virDrvDomainMigratePrepare)(virConnectPtr dconn,
                              char **cookie,
                              int *cookielen,
                              const char *uri_in,
                              char **uri_out,
                              unsigned long flags,
                              const char *dname,
                              unsigned long resource);

typedef int
(*virDrvDomainMigratePerform)(virDomainPtr domain,
                              const char *cookie,
                              int cookielen,
                              const char *uri,
                              unsigned long flags,
                              const char *dname,
                              unsigned long resource);

typedef virDomainPtr
(*virDrvDomainMigrateFinish)(virConnectPtr dconn,
                             const char *dname,
                             const char *cookie,
                             int cookielen,
                             const char *uri,
                             unsigned long flags);

typedef int
(*virDrvNodeGetCPUStats)(virConnectPtr conn,
                         int cpuNum,
                         virNodeCPUStatsPtr params,
                         int *nparams,
                         unsigned int flags);

typedef int
(*virDrvNodeGetMemoryStats)(virConnectPtr conn,
                            int cellNum,
                            virNodeMemoryStatsPtr params,
                            int *nparams,
                            unsigned int flags);

typedef int
(*virDrvNodeGetCellsFreeMemory)(virConnectPtr conn,
                                unsigned long long *freeMems,
                                int startCell,
                                int maxCells);

typedef unsigned long long
(*virDrvNodeGetFreeMemory)(virConnectPtr conn);

typedef int
(*virDrvConnectDomainEventRegister)(virConnectPtr conn,
                                    virConnectDomainEventCallback cb,
                                    void *opaque,
                                    virFreeCallback freecb);

typedef int
(*virDrvConnectDomainEventDeregister)(virConnectPtr conn,
                                      virConnectDomainEventCallback cb);

typedef int
(*virDrvDomainMigratePrepare2)(virConnectPtr dconn,
                               char **cookie,
                               int *cookielen,
                               const char *uri_in,
                               char **uri_out,
                               unsigned long flags,
                               const char *dname,
                               unsigned long resource,
                               const char *dom_xml);

typedef virDomainPtr
(*virDrvDomainMigrateFinish2)(virConnectPtr dconn,
                              const char *dname,
                              const char *cookie,
                              int cookielen,
                              const char *uri,
                              unsigned long flags,
                              int retcode);

typedef int
(*virDrvNodeDeviceDettach)(virNodeDevicePtr dev);

typedef int
(*virDrvNodeDeviceDetachFlags)(virNodeDevicePtr dev,
                               const char *driverName,
                               unsigned int flags);

typedef int
(*virDrvNodeDeviceReAttach)(virNodeDevicePtr dev);

typedef int
(*virDrvNodeDeviceReset)(virNodeDevicePtr dev);

typedef int
(*virDrvDomainMigratePrepareTunnel)(virConnectPtr dconn,
                                    virStreamPtr st,
                                    unsigned long flags,
                                    const char *dname,
                                    unsigned long resource,
                                    const char *dom_xml);

typedef int
(*virDrvDomainMigrateStartPostCopy)(virDomainPtr domain,
                                    unsigned int flags);

typedef int
(*virDrvConnectIsEncrypted)(virConnectPtr conn);

typedef int
(*virDrvConnectIsSecure)(virConnectPtr conn);

typedef int
(*virDrvConnectIsAlive)(virConnectPtr conn);

typedef int
(*virDrvDomainIsActive)(virDomainPtr dom);

typedef int
(*virDrvDomainRename)(virDomainPtr dom,
                      const char *new_name,
                      unsigned int flags);

typedef int
(*virDrvDomainIsPersistent)(virDomainPtr dom);

typedef int
(*virDrvDomainIsUpdated)(virDomainPtr dom);

typedef int
(*virDrvConnectCompareCPU)(virConnectPtr conn,
                           const char *cpu,
                           unsigned int flags);

typedef char *
(*virDrvConnectBaselineCPU)(virConnectPtr conn,
                            const char **xmlCPUs,
                            unsigned int ncpus,
                            unsigned int flags);

typedef int
(*virDrvConnectGetCPUModelNames)(virConnectPtr conn,
                                 const char *archName,
                                 char ***models,
                                 unsigned int flags);

typedef int
(*virDrvDomainGetJobInfo)(virDomainPtr domain,
                          virDomainJobInfoPtr info);

typedef int
(*virDrvDomainGetJobStats)(virDomainPtr domain,
                           int *type,
                           virTypedParameterPtr *params,
                           int *nparams,
                           unsigned int flags);

typedef int
(*virDrvDomainAbortJob)(virDomainPtr domain);

typedef int
(*virDrvDomainMigrateSetMaxDowntime)(virDomainPtr domain,
                                     unsigned long long downtime,
                                     unsigned int flags);

typedef int
(*virDrvDomainMigrateGetCompressionCache)(virDomainPtr domain,
                                          unsigned long long *cacheSize,
                                          unsigned int flags);

typedef int
(*virDrvDomainMigrateSetCompressionCache)(virDomainPtr domain,
                                          unsigned long long cacheSize,
                                          unsigned int flags);

typedef int
(*virDrvDomainMigrateSetMaxSpeed)(virDomainPtr domain,
                                  unsigned long bandwidth,
                                  unsigned int flags);

typedef int
(*virDrvDomainMigrateGetMaxSpeed)(virDomainPtr domain,
                                  unsigned long *bandwidth,
                                  unsigned int flags);

typedef int
(*virDrvConnectDomainEventRegisterAny)(virConnectPtr conn,
                                       virDomainPtr dom,
                                       int eventID,
                                       virConnectDomainEventGenericCallback cb,
                                       void *opaque,
                                       virFreeCallback freecb);

typedef int
(*virDrvConnectDomainEventDeregisterAny)(virConnectPtr conn,
                                         int callbackID);

typedef int
(*virDrvDomainManagedSave)(virDomainPtr domain,
                           unsigned int flags);

typedef int
(*virDrvDomainHasManagedSaveImage)(virDomainPtr domain,
                                   unsigned int flags);

typedef int
(*virDrvDomainManagedSaveRemove)(virDomainPtr domain,
                                 unsigned int flags);

typedef virDomainSnapshotPtr
(*virDrvDomainSnapshotCreateXML)(virDomainPtr domain,
                                 const char *xmlDesc,
                                 unsigned int flags);

typedef char *
(*virDrvDomainSnapshotGetXMLDesc)(virDomainSnapshotPtr snapshot,
                                  unsigned int flags);

typedef int
(*virDrvDomainSnapshotNum)(virDomainPtr domain,
                           unsigned int flags);

typedef int
(*virDrvDomainSnapshotListNames)(virDomainPtr domain,
                                 char **names,
                                 int nameslen,
                                 unsigned int flags);

typedef int
(*virDrvDomainListAllSnapshots)(virDomainPtr domain,
                                virDomainSnapshotPtr **snaps,
                                unsigned int flags);

typedef int
(*virDrvDomainSnapshotNumChildren)(virDomainSnapshotPtr snapshot,
                                   unsigned int flags);

typedef int
(*virDrvDomainSnapshotListChildrenNames)(virDomainSnapshotPtr snapshot,
                                         char **names,
                                         int nameslen,
                                         unsigned int flags);

typedef int
(*virDrvDomainSnapshotListAllChildren)(virDomainSnapshotPtr snapshot,
                                       virDomainSnapshotPtr **snaps,
                                       unsigned int flags);

typedef virDomainSnapshotPtr
(*virDrvDomainSnapshotLookupByName)(virDomainPtr domain,
                                    const char *name,
                                    unsigned int flags);

typedef int
(*virDrvDomainHasCurrentSnapshot)(virDomainPtr domain,
                                  unsigned int flags);

typedef virDomainSnapshotPtr
(*virDrvDomainSnapshotGetParent)(virDomainSnapshotPtr snapshot,
                                 unsigned int flags);

typedef virDomainSnapshotPtr
(*virDrvDomainSnapshotCurrent)(virDomainPtr domain,
                               unsigned int flags);

typedef int
(*virDrvDomainSnapshotIsCurrent)(virDomainSnapshotPtr snapshot,
                                 unsigned int flags);

typedef int
(*virDrvDomainSnapshotHasMetadata)(virDomainSnapshotPtr snapshot,
                                   unsigned int flags);

typedef int
(*virDrvDomainRevertToSnapshot)(virDomainSnapshotPtr snapshot,
                                unsigned int flags);

typedef int
(*virDrvDomainSnapshotDelete)(virDomainSnapshotPtr snapshot,
                              unsigned int flags);

typedef int
(*virDrvDomainQemuMonitorCommand)(virDomainPtr domain,
                                  const char *cmd,
                                  char **result,
                                  unsigned int flags);

typedef char *
(*virDrvDomainQemuAgentCommand)(virDomainPtr domain,
                                const char *cmd,
                                int timeout,
                                unsigned int flags);

/* Choice of unsigned int rather than pid_t is intentional.  */
typedef virDomainPtr
(*virDrvDomainQemuAttach)(virConnectPtr conn,
                          unsigned int pid_value,
                          unsigned int flags);

typedef int
(*virDrvConnectDomainQemuMonitorEventRegister)(virConnectPtr conn,
                                               virDomainPtr dom,
                                               const char *event,
                                               virConnectDomainQemuMonitorEventCallback cb,
                                               void *opaque,
                                               virFreeCallback freecb,
                                               unsigned int flags);

typedef int
(*virDrvConnectDomainQemuMonitorEventDeregister)(virConnectPtr conn,
                                                 int callbackID);

typedef int
(*virDrvDomainOpenConsole)(virDomainPtr dom,
                           const char *dev_name,
                           virStreamPtr st,
                           unsigned int flags);

typedef int
(*virDrvDomainOpenChannel)(virDomainPtr dom,
                           const char *name,
                           virStreamPtr st,
                           unsigned int flags);

typedef int
(*virDrvDomainOpenGraphics)(virDomainPtr dom,
                            unsigned int idx,
                            int fd,
                            unsigned int flags);

typedef int
(*virDrvDomainOpenGraphicsFD)(virDomainPtr dom,
                              unsigned int idx,
                              unsigned int flags);

typedef int
(*virDrvDomainInjectNMI)(virDomainPtr dom,
                         unsigned int flags);

typedef int
(*virDrvDomainSendKey)(virDomainPtr dom,
                       unsigned int codeset,
                       unsigned int holdtime,
                       unsigned int *keycodes,
                       int nkeycodes,
                       unsigned int flags);

typedef int
(*virDrvDomainSendProcessSignal)(virDomainPtr dom,
                                 long long pid_value,
                                 unsigned int signum,
                                 unsigned int flags);

typedef char *
(*virDrvDomainMigrateBegin3)(virDomainPtr domain,
                             const char *xmlin,
                             char **cookieout,
                             int *cookieoutlen,
                             unsigned long flags,
                             const char *dname,
                             unsigned long resource);

typedef int
(*virDrvDomainMigratePrepare3)(virConnectPtr dconn,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               const char *uri_in,
                               char **uri_out,
                               unsigned long flags,
                               const char *dname,
                               unsigned long resource,
                               const char *dom_xml);

typedef int
(*virDrvDomainMigratePrepareTunnel3)(virConnectPtr dconn,
                                     virStreamPtr st,
                                     const char *cookiein,
                                     int cookieinlen,
                                     char **cookieout,
                                     int *cookieoutlen,
                                     unsigned long flags,
                                     const char *dname,
                                     unsigned long resource,
                                     const char *dom_xml);


typedef int
(*virDrvDomainMigratePerform3)(virDomainPtr dom,
                               const char *xmlin,
                               const char *cookiein,
                               int cookieinlen,
                               char **cookieout,
                               int *cookieoutlen,
                               const char *dconnuri,
                               const char *uri,
                               unsigned long flags,
                               const char *dname,
                               unsigned long resource);

typedef virDomainPtr
(*virDrvDomainMigrateFinish3)(virConnectPtr dconn,
                              const char *dname,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              const char *dconnuri,
                              const char *uri,
                              unsigned long flags,
                              int cancelled);

typedef int
(*virDrvDomainMigrateConfirm3)(virDomainPtr domain,
                               const char *cookiein,
                               int cookieinlen,
                               unsigned long flags,
                               int cancelled);

typedef int
(*virDrvNodeSuspendForDuration)(virConnectPtr conn,
                                unsigned int target,
                                unsigned long long duration,
                                unsigned int flags);

typedef int
(*virDrvDomainGetPerfEvents)(virDomainPtr dom,
                             virTypedParameterPtr *params,
                             int *nparams,
                             unsigned int flags);

typedef int
(*virDrvDomainSetPerfEvents)(virDomainPtr dom,
                             virTypedParameterPtr params,
                             int nparams,
                             unsigned int flags);

typedef int
(*virDrvDomainBlockJobAbort)(virDomainPtr dom,
                             const char *path,
                             unsigned int flags);

typedef int
(*virDrvDomainGetBlockJobInfo)(virDomainPtr dom,
                               const char *path,
                               virDomainBlockJobInfoPtr info,
                               unsigned int flags);

typedef int
(*virDrvDomainBlockJobSetSpeed)(virDomainPtr dom,
                                const char *path,
                                unsigned long bandwidth,
                                unsigned int flags);

typedef int
(*virDrvDomainBlockPull)(virDomainPtr dom,
                         const char *path,
                         unsigned long bandwidth,
                         unsigned int flags);

typedef int
(*virDrvDomainBlockRebase)(virDomainPtr dom,
                           const char *path,
                           const char *base,
                           unsigned long bandwidth,
                           unsigned int flags);

typedef int
(*virDrvDomainBlockCopy)(virDomainPtr dom,
                         const char *path,
                         const char *destxml,
                         virTypedParameterPtr params,
                         int nparams,
                         unsigned int flags);

typedef int
(*virDrvDomainBlockCommit)(virDomainPtr dom,
                           const char *disk,
                           const char *base,
                           const char *top,
                           unsigned long bandwidth,
                           unsigned int flags);

typedef int
(*virDrvConnectSetKeepAlive)(virConnectPtr conn,
                             int interval,
                             unsigned int count);

typedef int
(*virDrvDomainSetBlockIoTune)(virDomainPtr dom,
                              const char *disk,
                              virTypedParameterPtr params,
                              int nparams,
                              unsigned int flags);

typedef int
(*virDrvDomainGetBlockIoTune)(virDomainPtr dom,
                              const char *disk,
                              virTypedParameterPtr params,
                              int *nparams,
                              unsigned int flags);

typedef int
(*virDrvDomainShutdownFlags)(virDomainPtr domain,
                             unsigned int flags);

typedef int
(*virDrvDomainGetCPUStats)(virDomainPtr domain,
                           virTypedParameterPtr params,
                           unsigned int nparams,
                           int start_cpu,
                           unsigned int ncpus,
                           unsigned int flags);

typedef int
(*virDrvDomainGetDiskErrors)(virDomainPtr dom,
                             virDomainDiskErrorPtr errors,
                             unsigned int maxerrors,
                             unsigned int flags);

typedef int
(*virDrvDomainSetMetadata)(virDomainPtr dom,
                           int type,
                           const char *metadata,
                           const char *key,
                           const char *uri,
                           unsigned int flags);

typedef char *
(*virDrvDomainGetMetadata)(virDomainPtr dom,
                           int type,
                           const char *uri,
                           unsigned int flags);

typedef int
(*virDrvNodeGetMemoryParameters)(virConnectPtr conn,
                                 virTypedParameterPtr params,
                                 int *nparams,
                                 unsigned int flags);

typedef int
(*virDrvNodeSetMemoryParameters)(virConnectPtr conn,
                                 virTypedParameterPtr params,
                                 int nparams,
                                 unsigned int flags);

typedef int
(*virDrvNodeGetCPUMap)(virConnectPtr conn,
                       unsigned char **cpumap,
                       unsigned int *online,
                       unsigned int flags);

typedef int
(*virDrvDomainFSTrim)(virDomainPtr dom,
                      const char *mountPoint,
                      unsigned long long minimum,
                      unsigned int flags);

typedef int
(*virDrvDomainGetTime)(virDomainPtr dom,
                       long long *seconds,
                       unsigned int *nseconds,
                       unsigned int flags);

typedef int
(*virDrvDomainSetTime)(virDomainPtr dom,
                       long long seconds,
                       unsigned int nseconds,
                       unsigned int flags);

typedef int
(*virDrvDomainLxcOpenNamespace)(virDomainPtr dom,
                                int **fdlist,
                                unsigned int flags);

typedef char *
(*virDrvDomainMigrateBegin3Params)(virDomainPtr domain,
                                   virTypedParameterPtr params,
                                   int nparams,
                                   char **cookieout,
                                   int *cookieoutlen,
                                   unsigned int flags);

typedef int
(*virDrvDomainMigratePrepare3Params)(virConnectPtr dconn,
                                     virTypedParameterPtr params,
                                     int nparams,
                                     const char *cookiein,
                                     int cookieinlen,
                                     char **cookieout,
                                     int *cookieoutlen,
                                     char **uri_out,
                                     unsigned int flags);

typedef int
(*virDrvDomainMigratePrepareTunnel3Params)(virConnectPtr dconn,
                                           virStreamPtr st,
                                           virTypedParameterPtr params,
                                           int nparams,
                                           const char *cookiein,
                                           int cookieinlen,
                                           char **cookieout,
                                           int *cookieoutlen,
                                           unsigned int flags);

typedef int
(*virDrvDomainMigratePerform3Params)(virDomainPtr dom,
                                     const char *dconnuri,
                                     virTypedParameterPtr params,
                                     int nparams,
                                     const char *cookiein,
                                     int cookieinlen,
                                     char **cookieout,
                                     int *cookieoutlen,
                                     unsigned int flags);

typedef virDomainPtr
(*virDrvDomainMigrateFinish3Params)(virConnectPtr dconn,
                                    virTypedParameterPtr params,
                                    int nparams,
                                    const char *cookiein,
                                    int cookieinlen,
                                    char **cookieout,
                                    int *cookieoutlen,
                                    unsigned int flags,
                                    int cancelled);

typedef int
(*virDrvDomainMigrateConfirm3Params)(virDomainPtr domain,
                                     virTypedParameterPtr params,
                                     int nparams,
                                     const char *cookiein,
                                     int cookieinlen,
                                     unsigned int flags,
                                     int cancelled);

typedef int
(*virDrvDomainFSFreeze)(virDomainPtr dom,
                        const char **mountpoints,
                        unsigned int nmountpoints,
                        unsigned int flags);

typedef int
(*virDrvDomainFSThaw)(virDomainPtr dom,
                      const char **mountpoints,
                      unsigned int nmountpoints,
                      unsigned int flags);

typedef int
(*virDrvDomainGetFSInfo)(virDomainPtr dom,
                         virDomainFSInfoPtr **info,
                         unsigned int flags);

typedef int
(*virDrvNodeGetFreePages)(virConnectPtr conn,
                          unsigned int npages,
                          unsigned int *pages,
                          int startCell,
                          unsigned int cellCount,
                          unsigned long long *counts,
                          unsigned int flags);


typedef int
(*virDrvConnectGetAllDomainStats)(virConnectPtr conn,
                                  virDomainPtr *doms,
                                  unsigned int ndoms,
                                  unsigned int stats,
                                  virDomainStatsRecordPtr **retStats,
                                  unsigned int flags);

typedef int
(*virDrvNodeAllocPages)(virConnectPtr conn,
                        unsigned int npages,
                        unsigned int *pageSizes,
                        unsigned long long *pageCounts,
                        int startCell,
                        unsigned int cellCount,
                        unsigned int flags);

typedef int
(*virDrvDomainInterfaceAddresses)(virDomainPtr dom,
                                  virDomainInterfacePtr **ifaces,
                                  unsigned int source,
                                  unsigned int flags);

typedef int
(*virDrvDomainSetUserPassword)(virDomainPtr dom,
                               const char *user,
                               const char *password,
                               unsigned int flags);

typedef int
(*virDrvConnectRegisterCloseCallback)(virConnectPtr conn,
                                      virConnectCloseFunc cb,
                                      void *opaque,
                                      virFreeCallback freecb);

typedef int
(*virDrvConnectUnregisterCloseCallback)(virConnectPtr conn,
                                        virConnectCloseFunc cb);

typedef int
(*virDrvDomainGetGuestVcpus)(virDomainPtr domain,
                             virTypedParameterPtr *params,
                             unsigned int *nparams,
                             unsigned int flags);

typedef int
(*virDrvDomainSetGuestVcpus)(virDomainPtr domain,
                             const char *cpumap,
                             int state,
                             unsigned int flags);

typedef int
(*virDrvDomainSetVcpu)(virDomainPtr domain,
                       const char *cpumap,
                       int state,
                       unsigned int flags);

typedef struct _virHypervisorDriver virHypervisorDriver;
typedef virHypervisorDriver *virHypervisorDriverPtr;

/**
 * _virHypervisorDriver:
 *
 * Structure associated to a virtualization driver, defining the various
 * entry points for it.
 *
 * All drivers must support the following fields/methods:
 *  - name
 *  - open
 *  - close
 */
struct _virHypervisorDriver {
    const char *name; /* the name of the driver */
    virDrvConnectOpen connectOpen;
    virDrvConnectClose connectClose;
    virDrvConnectSupportsFeature connectSupportsFeature;
    virDrvConnectGetType connectGetType;
    virDrvConnectGetVersion connectGetVersion;
    virDrvConnectGetLibVersion connectGetLibVersion;
    virDrvConnectGetHostname connectGetHostname;
    virDrvConnectGetSysinfo connectGetSysinfo;
    virDrvConnectGetMaxVcpus connectGetMaxVcpus;
    virDrvNodeGetInfo nodeGetInfo;
    virDrvConnectGetCapabilities connectGetCapabilities;
    virDrvConnectListDomains connectListDomains;
    virDrvConnectNumOfDomains connectNumOfDomains;
    virDrvConnectListAllDomains connectListAllDomains;
    virDrvDomainCreateXML domainCreateXML;
    virDrvDomainCreateXMLWithFiles domainCreateXMLWithFiles;
    virDrvDomainLookupByID domainLookupByID;
    virDrvDomainLookupByUUID domainLookupByUUID;
    virDrvDomainLookupByName domainLookupByName;
    virDrvDomainSuspend domainSuspend;
    virDrvDomainResume domainResume;
    virDrvDomainPMSuspendForDuration domainPMSuspendForDuration;
    virDrvDomainPMWakeup domainPMWakeup;
    virDrvDomainShutdown domainShutdown;
    virDrvDomainShutdownFlags domainShutdownFlags;
    virDrvDomainReboot domainReboot;
    virDrvDomainReset domainReset;
    virDrvDomainDestroy domainDestroy;
    virDrvDomainDestroyFlags domainDestroyFlags;
    virDrvDomainGetOSType domainGetOSType;
    virDrvDomainGetHostname domainGetHostname;
    virDrvDomainGetMaxMemory domainGetMaxMemory;
    virDrvDomainSetMaxMemory domainSetMaxMemory;
    virDrvDomainSetMemory domainSetMemory;
    virDrvDomainSetMemoryFlags domainSetMemoryFlags;
    virDrvDomainSetMemoryStatsPeriod domainSetMemoryStatsPeriod;
    virDrvDomainSetMemoryParameters domainSetMemoryParameters;
    virDrvDomainGetMemoryParameters domainGetMemoryParameters;
    virDrvDomainSetNumaParameters domainSetNumaParameters;
    virDrvDomainGetNumaParameters domainGetNumaParameters;
    virDrvDomainSetBlkioParameters domainSetBlkioParameters;
    virDrvDomainGetBlkioParameters domainGetBlkioParameters;
    virDrvDomainGetInfo domainGetInfo;
    virDrvDomainGetState domainGetState;
    virDrvDomainGetControlInfo domainGetControlInfo;
    virDrvDomainSave domainSave;
    virDrvDomainSaveFlags domainSaveFlags;
    virDrvDomainRestore domainRestore;
    virDrvDomainRestoreFlags domainRestoreFlags;
    virDrvDomainSaveImageGetXMLDesc domainSaveImageGetXMLDesc;
    virDrvDomainSaveImageDefineXML domainSaveImageDefineXML;
    virDrvDomainCoreDump domainCoreDump;
    virDrvDomainCoreDumpWithFormat domainCoreDumpWithFormat;
    virDrvDomainScreenshot domainScreenshot;
    virDrvDomainSetVcpus domainSetVcpus;
    virDrvDomainSetVcpusFlags domainSetVcpusFlags;
    virDrvDomainGetVcpusFlags domainGetVcpusFlags;
    virDrvDomainPinVcpu domainPinVcpu;
    virDrvDomainPinVcpuFlags domainPinVcpuFlags;
    virDrvDomainGetVcpuPinInfo domainGetVcpuPinInfo;
    virDrvDomainPinEmulator domainPinEmulator;
    virDrvDomainGetEmulatorPinInfo domainGetEmulatorPinInfo;
    virDrvDomainGetVcpus domainGetVcpus;
    virDrvDomainGetMaxVcpus domainGetMaxVcpus;
    virDrvDomainGetIOThreadInfo domainGetIOThreadInfo;
    virDrvDomainPinIOThread domainPinIOThread;
    virDrvDomainAddIOThread domainAddIOThread;
    virDrvDomainDelIOThread domainDelIOThread;
    virDrvDomainGetSecurityLabel domainGetSecurityLabel;
    virDrvDomainGetSecurityLabelList domainGetSecurityLabelList;
    virDrvNodeGetSecurityModel nodeGetSecurityModel;
    virDrvDomainGetXMLDesc domainGetXMLDesc;
    virDrvConnectDomainXMLFromNative connectDomainXMLFromNative;
    virDrvConnectDomainXMLToNative connectDomainXMLToNative;
    virDrvConnectListDefinedDomains connectListDefinedDomains;
    virDrvConnectNumOfDefinedDomains connectNumOfDefinedDomains;
    virDrvDomainCreate domainCreate;
    virDrvDomainCreateWithFlags domainCreateWithFlags;
    virDrvDomainCreateWithFiles domainCreateWithFiles;
    virDrvDomainDefineXML domainDefineXML;
    virDrvDomainDefineXMLFlags domainDefineXMLFlags;
    virDrvDomainUndefine domainUndefine;
    virDrvDomainUndefineFlags domainUndefineFlags;
    virDrvDomainAttachDevice domainAttachDevice;
    virDrvDomainAttachDeviceFlags domainAttachDeviceFlags;
    virDrvDomainDetachDevice domainDetachDevice;
    virDrvDomainDetachDeviceFlags domainDetachDeviceFlags;
    virDrvDomainUpdateDeviceFlags domainUpdateDeviceFlags;
    virDrvDomainGetAutostart domainGetAutostart;
    virDrvDomainSetAutostart domainSetAutostart;
    virDrvDomainGetSchedulerType domainGetSchedulerType;
    virDrvDomainGetSchedulerParameters domainGetSchedulerParameters;
    virDrvDomainGetSchedulerParametersFlags domainGetSchedulerParametersFlags;
    virDrvDomainSetSchedulerParameters domainSetSchedulerParameters;
    virDrvDomainSetSchedulerParametersFlags domainSetSchedulerParametersFlags;
    virDrvDomainMigratePrepare domainMigratePrepare;
    virDrvDomainMigratePerform domainMigratePerform;
    virDrvDomainMigrateFinish domainMigrateFinish;
    virDrvDomainBlockResize domainBlockResize;
    virDrvDomainBlockStats domainBlockStats;
    virDrvDomainBlockStatsFlags domainBlockStatsFlags;
    virDrvDomainInterfaceStats domainInterfaceStats;
    virDrvDomainSetInterfaceParameters domainSetInterfaceParameters;
    virDrvDomainGetInterfaceParameters domainGetInterfaceParameters;
    virDrvDomainMemoryStats domainMemoryStats;
    virDrvDomainBlockPeek domainBlockPeek;
    virDrvDomainMemoryPeek domainMemoryPeek;
    virDrvDomainGetBlockInfo domainGetBlockInfo;
    virDrvNodeGetCPUStats nodeGetCPUStats;
    virDrvNodeGetMemoryStats nodeGetMemoryStats;
    virDrvNodeGetCellsFreeMemory nodeGetCellsFreeMemory;
    virDrvNodeGetFreeMemory nodeGetFreeMemory;
    virDrvConnectDomainEventRegister connectDomainEventRegister;
    virDrvConnectDomainEventDeregister connectDomainEventDeregister;
    virDrvDomainMigratePrepare2 domainMigratePrepare2;
    virDrvDomainMigrateFinish2 domainMigrateFinish2;
    virDrvNodeDeviceDettach nodeDeviceDettach;
    virDrvNodeDeviceDetachFlags nodeDeviceDetachFlags;
    virDrvNodeDeviceReAttach nodeDeviceReAttach;
    virDrvNodeDeviceReset nodeDeviceReset;
    virDrvDomainMigratePrepareTunnel domainMigratePrepareTunnel;
    virDrvConnectIsEncrypted connectIsEncrypted;
    virDrvConnectIsSecure connectIsSecure;
    virDrvDomainIsActive domainIsActive;
    virDrvDomainRename domainRename;
    virDrvDomainIsPersistent domainIsPersistent;
    virDrvDomainIsUpdated domainIsUpdated;
    virDrvConnectCompareCPU connectCompareCPU;
    virDrvConnectBaselineCPU connectBaselineCPU;
    virDrvDomainGetJobInfo domainGetJobInfo;
    virDrvDomainGetJobStats domainGetJobStats;
    virDrvDomainAbortJob domainAbortJob;
    virDrvDomainMigrateSetMaxDowntime domainMigrateSetMaxDowntime;
    virDrvDomainMigrateGetCompressionCache domainMigrateGetCompressionCache;
    virDrvDomainMigrateSetCompressionCache domainMigrateSetCompressionCache;
    virDrvDomainMigrateGetMaxSpeed domainMigrateGetMaxSpeed;
    virDrvDomainMigrateSetMaxSpeed domainMigrateSetMaxSpeed;
    virDrvConnectDomainEventRegisterAny connectDomainEventRegisterAny;
    virDrvConnectDomainEventDeregisterAny connectDomainEventDeregisterAny;
    virDrvDomainManagedSave domainManagedSave;
    virDrvDomainHasManagedSaveImage domainHasManagedSaveImage;
    virDrvDomainManagedSaveRemove domainManagedSaveRemove;
    virDrvDomainSnapshotCreateXML domainSnapshotCreateXML;
    virDrvDomainSnapshotGetXMLDesc domainSnapshotGetXMLDesc;
    virDrvDomainSnapshotNum domainSnapshotNum;
    virDrvDomainSnapshotListNames domainSnapshotListNames;
    virDrvDomainListAllSnapshots domainListAllSnapshots;
    virDrvDomainSnapshotNumChildren domainSnapshotNumChildren;
    virDrvDomainSnapshotListChildrenNames domainSnapshotListChildrenNames;
    virDrvDomainSnapshotListAllChildren domainSnapshotListAllChildren;
    virDrvDomainSnapshotLookupByName domainSnapshotLookupByName;
    virDrvDomainHasCurrentSnapshot domainHasCurrentSnapshot;
    virDrvDomainSnapshotGetParent domainSnapshotGetParent;
    virDrvDomainSnapshotCurrent domainSnapshotCurrent;
    virDrvDomainSnapshotIsCurrent domainSnapshotIsCurrent;
    virDrvDomainSnapshotHasMetadata domainSnapshotHasMetadata;
    virDrvDomainRevertToSnapshot domainRevertToSnapshot;
    virDrvDomainSnapshotDelete domainSnapshotDelete;
    virDrvDomainQemuMonitorCommand domainQemuMonitorCommand;
    virDrvDomainQemuAttach domainQemuAttach;
    virDrvDomainQemuAgentCommand domainQemuAgentCommand;
    virDrvConnectDomainQemuMonitorEventRegister connectDomainQemuMonitorEventRegister;
    virDrvConnectDomainQemuMonitorEventDeregister connectDomainQemuMonitorEventDeregister;
    virDrvDomainOpenConsole domainOpenConsole;
    virDrvDomainOpenChannel domainOpenChannel;
    virDrvDomainOpenGraphics domainOpenGraphics;
    virDrvDomainOpenGraphicsFD domainOpenGraphicsFD;
    virDrvDomainInjectNMI domainInjectNMI;
    virDrvDomainMigrateBegin3 domainMigrateBegin3;
    virDrvDomainMigratePrepare3 domainMigratePrepare3;
    virDrvDomainMigratePrepareTunnel3 domainMigratePrepareTunnel3;
    virDrvDomainMigratePerform3 domainMigratePerform3;
    virDrvDomainMigrateFinish3 domainMigrateFinish3;
    virDrvDomainMigrateConfirm3 domainMigrateConfirm3;
    virDrvDomainSendKey domainSendKey;
    virDrvDomainBlockJobAbort domainBlockJobAbort;
    virDrvDomainGetBlockJobInfo domainGetBlockJobInfo;
    virDrvDomainBlockJobSetSpeed domainBlockJobSetSpeed;
    virDrvDomainBlockPull domainBlockPull;
    virDrvDomainBlockRebase domainBlockRebase;
    virDrvDomainBlockCopy domainBlockCopy;
    virDrvDomainBlockCommit domainBlockCommit;
    virDrvConnectSetKeepAlive connectSetKeepAlive;
    virDrvConnectIsAlive connectIsAlive;
    virDrvNodeSuspendForDuration nodeSuspendForDuration;
    virDrvDomainGetPerfEvents domainGetPerfEvents;
    virDrvDomainSetPerfEvents domainSetPerfEvents;
    virDrvDomainSetBlockIoTune domainSetBlockIoTune;
    virDrvDomainGetBlockIoTune domainGetBlockIoTune;
    virDrvDomainGetCPUStats domainGetCPUStats;
    virDrvDomainGetDiskErrors domainGetDiskErrors;
    virDrvDomainSetMetadata domainSetMetadata;
    virDrvDomainGetMetadata domainGetMetadata;
    virDrvNodeGetMemoryParameters nodeGetMemoryParameters;
    virDrvNodeSetMemoryParameters nodeSetMemoryParameters;
    virDrvNodeGetCPUMap nodeGetCPUMap;
    virDrvDomainFSTrim domainFSTrim;
    virDrvDomainSendProcessSignal domainSendProcessSignal;
    virDrvDomainLxcOpenNamespace domainLxcOpenNamespace;
    virDrvDomainMigrateBegin3Params domainMigrateBegin3Params;
    virDrvDomainMigratePrepare3Params domainMigratePrepare3Params;
    virDrvDomainMigratePrepareTunnel3Params domainMigratePrepareTunnel3Params;
    virDrvDomainMigratePerform3Params domainMigratePerform3Params;
    virDrvDomainMigrateFinish3Params domainMigrateFinish3Params;
    virDrvDomainMigrateConfirm3Params domainMigrateConfirm3Params;
    virDrvConnectGetCPUModelNames connectGetCPUModelNames;
    virDrvDomainFSFreeze domainFSFreeze;
    virDrvDomainFSThaw domainFSThaw;
    virDrvDomainGetTime domainGetTime;
    virDrvDomainSetTime domainSetTime;
    virDrvNodeGetFreePages nodeGetFreePages;
    virDrvConnectGetDomainCapabilities connectGetDomainCapabilities;
    virDrvConnectGetAllDomainStats connectGetAllDomainStats;
    virDrvNodeAllocPages nodeAllocPages;
    virDrvDomainGetFSInfo domainGetFSInfo;
    virDrvDomainInterfaceAddresses domainInterfaceAddresses;
    virDrvDomainSetUserPassword domainSetUserPassword;
    virDrvConnectRegisterCloseCallback connectRegisterCloseCallback;
    virDrvConnectUnregisterCloseCallback connectUnregisterCloseCallback;
    virDrvDomainMigrateStartPostCopy domainMigrateStartPostCopy;
    virDrvDomainGetGuestVcpus domainGetGuestVcpus;
    virDrvDomainSetGuestVcpus domainSetGuestVcpus;
    virDrvDomainSetVcpu domainSetVcpu;
};


#endif /* __VIR_DRIVER_HYPERVISOR_H__ */
