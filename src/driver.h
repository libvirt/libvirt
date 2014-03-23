/*
 * driver.h: description of the set of interfaces provided by a
 *           entry point to the virtualization engine
 *
 * Copyright (C) 2006-2013 Red Hat, Inc.
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

#ifndef __VIR_DRIVER_H__
# define __VIR_DRIVER_H__

# include <unistd.h>

# include "internal.h"
# include "libvirt_internal.h"
# include "viruri.h"
/*
 * List of registered drivers numbers
 */
typedef enum {
    VIR_DRV_XEN_UNIFIED = 1,
    VIR_DRV_TEST = 2,
    VIR_DRV_QEMU = 3,
    VIR_DRV_REMOTE = 4,
    VIR_DRV_OPENVZ = 5,
    VIR_DRV_LXC = 6,
    VIR_DRV_UML = 7,
    VIR_DRV_VBOX = 8,
    VIR_DRV_ONE = 9,
    VIR_DRV_ESX = 10,
    VIR_DRV_PHYP = 11,
    VIR_DRV_XENAPI = 12,
    VIR_DRV_VMWARE = 13,
    VIR_DRV_LIBXL = 14,
    VIR_DRV_HYPERV = 15,
    VIR_DRV_PARALLELS = 16,
    VIR_DRV_BHYVE = 17,
} virDrvNo;


/* Status codes returned from driver open call. */
typedef enum {
    /* Opened successfully. */
    VIR_DRV_OPEN_SUCCESS = 0,

    /* 'name' is not for us. */
    VIR_DRV_OPEN_DECLINED = -1,

    /* 'name' is for us, but there was some error.  virConnectOpen will
     * return an error rather than continue probing the other drivers.
     */
    VIR_DRV_OPEN_ERROR = -2,
} virDrvOpenStatus;


/* Internal feature-detection macro.  Don't call drv->supports_feature
 * directly if you don't have to, because it may be NULL, use this macro
 * instead.
 *
 * Note that this treats a possible error returned by drv->supports_feature
 * the same as not supported. If you care about the error, call
 * drv->supports_feature directly.
 *
 * Returns:
 *   != 0  Feature is supported.
 *   0     Feature is not supported.
 */
# define VIR_DRV_SUPPORTS_FEATURE(drv,conn,feature)                     \
    ((drv)->connectSupportsFeature ?                                    \
        (drv)->connectSupportsFeature((conn), (feature)) > 0 : 0)

typedef virDrvOpenStatus
(*virDrvConnectOpen)(virConnectPtr conn,
                     virConnectAuthPtr auth,
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
                          struct _virDomainBlockStats *stats);

typedef int
(*virDrvDomainBlockStatsFlags)(virDomainPtr domain,
                               const char *path,
                               virTypedParameterPtr params,
                               int *nparams,
                               unsigned int flags);

typedef int
(*virDrvDomainInterfaceStats)(virDomainPtr domain,
                              const char *path,
                              struct _virDomainInterfaceStats *stats);

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
                           struct _virDomainMemoryStat *stats,
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
(*virDrvConnectIsEncrypted)(virConnectPtr conn);

typedef int
(*virDrvConnectIsSecure)(virConnectPtr conn);

typedef int
(*virDrvConnectIsAlive)(virConnectPtr conn);

typedef int
(*virDrvDomainIsActive)(virDomainPtr dom);

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
                                 const char *args,
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

typedef struct _virDriver virDriver;
typedef virDriver *virDriverPtr;

/**
 * _virDriver:
 *
 * Structure associated to a virtualization driver, defining the various
 * entry points for it.
 *
 * All drivers must support the following fields/methods:
 *  - no
 *  - name
 *  - open
 *  - close
 */
struct _virDriver {
    int no; /* the number virDrvNo */
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
    virDrvDomainBlockCommit domainBlockCommit;
    virDrvConnectSetKeepAlive connectSetKeepAlive;
    virDrvConnectIsAlive connectIsAlive;
    virDrvNodeSuspendForDuration nodeSuspendForDuration;
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
};


typedef virDrvConnectOpen virDrvNetworkOpen;
typedef virDrvConnectClose virDrvNetworkClose;

typedef int
(*virDrvConnectNumOfNetworks)(virConnectPtr conn);

typedef int
(*virDrvConnectListNetworks)(virConnectPtr conn,
                             char **const names,
                             int maxnames);

typedef int
(*virDrvConnectNumOfDefinedNetworks)(virConnectPtr conn);

typedef int
(*virDrvConnectListDefinedNetworks)(virConnectPtr conn,
                                    char **const names,
                                    int maxnames);

typedef int
(*virDrvConnectListAllNetworks)(virConnectPtr conn,
                                virNetworkPtr **nets,
                                unsigned int flags);

typedef int
(*virDrvConnectNetworkEventRegisterAny)(virConnectPtr conn,
                                        virNetworkPtr dom,
                                        int eventID,
                                        virConnectNetworkEventGenericCallback cb,
                                        void *opaque,
                                        virFreeCallback freecb);

typedef int
(*virDrvConnectNetworkEventDeregisterAny)(virConnectPtr conn,
                                          int callbackID);

typedef virNetworkPtr
(*virDrvNetworkLookupByUUID)(virConnectPtr conn,
                             const unsigned char *uuid);

typedef virNetworkPtr
(*virDrvNetworkLookupByName)(virConnectPtr conn,
                             const char *name);

typedef virNetworkPtr
(*virDrvNetworkCreateXML)(virConnectPtr conn,
                          const char *xmlDesc);

typedef virNetworkPtr
(*virDrvNetworkDefineXML)(virConnectPtr conn,
                          const char *xml);

typedef int
(*virDrvNetworkUndefine)(virNetworkPtr network);

typedef int
(*virDrvNetworkUpdate)(virNetworkPtr network,
                       unsigned int command, /* virNetworkUpdateCommand */
                       unsigned int section, /* virNetworkUpdateSection */
                       int parentIndex,
                       const char *xml,
                       unsigned int flags);

typedef int
(*virDrvNetworkCreate)(virNetworkPtr network);

typedef int
(*virDrvNetworkDestroy)(virNetworkPtr network);

typedef char *
(*virDrvNetworkGetXMLDesc)(virNetworkPtr network,
                           unsigned int flags);

typedef char *
(*virDrvNetworkGetBridgeName)(virNetworkPtr network);

typedef int
(*virDrvNetworkGetAutostart)(virNetworkPtr network,
                             int *autostart);

typedef int
(*virDrvNetworkSetAutostart)(virNetworkPtr network,
                             int autostart);

typedef int
(*virDrvNetworkIsActive)(virNetworkPtr net);

typedef int
(*virDrvNetworkIsPersistent)(virNetworkPtr net);



typedef struct _virNetworkDriver virNetworkDriver;
typedef virNetworkDriver *virNetworkDriverPtr;

/**
 * _virNetworkDriver:
 *
 * Structure associated to a network virtualization driver, defining the various
 * entry points for it.
 *
 * All drivers must support the following fields/methods:
 *  - open
 *  - close
 */
struct _virNetworkDriver {
    const char * name; /* the name of the driver */
    virDrvNetworkOpen networkOpen;
    virDrvNetworkClose networkClose;
    virDrvConnectNumOfNetworks connectNumOfNetworks;
    virDrvConnectListNetworks connectListNetworks;
    virDrvConnectNumOfDefinedNetworks connectNumOfDefinedNetworks;
    virDrvConnectListDefinedNetworks connectListDefinedNetworks;
    virDrvConnectListAllNetworks connectListAllNetworks;
    virDrvConnectNetworkEventRegisterAny connectNetworkEventRegisterAny;
    virDrvConnectNetworkEventDeregisterAny connectNetworkEventDeregisterAny;
    virDrvNetworkLookupByUUID networkLookupByUUID;
    virDrvNetworkLookupByName networkLookupByName;
    virDrvNetworkCreateXML networkCreateXML;
    virDrvNetworkDefineXML networkDefineXML;
    virDrvNetworkUndefine networkUndefine;
    virDrvNetworkUpdate networkUpdate;
    virDrvNetworkCreate networkCreate;
    virDrvNetworkDestroy networkDestroy;
    virDrvNetworkGetXMLDesc networkGetXMLDesc;
    virDrvNetworkGetBridgeName networkGetBridgeName;
    virDrvNetworkGetAutostart networkGetAutostart;
    virDrvNetworkSetAutostart networkSetAutostart;
    virDrvNetworkIsActive networkIsActive;
    virDrvNetworkIsPersistent networkIsPersistent;
};


typedef virDrvConnectOpen virDrvInterfaceOpen;
typedef virDrvConnectClose virDrvInterfaceClose;

typedef int
(*virDrvConnectNumOfInterfaces)(virConnectPtr conn);

typedef int
(*virDrvConnectListInterfaces)(virConnectPtr conn,
                               char **const names,
                               int maxnames);

typedef int
(*virDrvConnectNumOfDefinedInterfaces)(virConnectPtr conn);

typedef int
(*virDrvConnectListDefinedInterfaces)(virConnectPtr conn,
                                      char **const names,
                                      int maxnames);

typedef int
(*virDrvConnectListAllInterfaces)(virConnectPtr conn,
                                  virInterfacePtr **ifaces,
                                  unsigned int flags);

typedef virInterfacePtr
(*virDrvInterfaceLookupByName)(virConnectPtr conn,
                               const char *name);

typedef virInterfacePtr
(*virDrvInterfaceLookupByMACString)(virConnectPtr conn,
                                    const char *mac);

typedef char *
(*virDrvInterfaceGetXMLDesc)(virInterfacePtr iface,
                             unsigned int flags);

typedef virInterfacePtr
(*virDrvInterfaceDefineXML)(virConnectPtr conn,
                            const char *xmlDesc,
                            unsigned int flags);

typedef int
(*virDrvInterfaceUndefine)(virInterfacePtr iface);

typedef int
(*virDrvInterfaceCreate)(virInterfacePtr iface,
                         unsigned int flags);

typedef int
(*virDrvInterfaceDestroy)(virInterfacePtr iface,
                          unsigned int flags);

typedef int
(*virDrvInterfaceIsActive)(virInterfacePtr iface);

typedef int
(*virDrvInterfaceChangeBegin)(virConnectPtr conn,
                              unsigned int flags);

typedef int
(*virDrvInterfaceChangeCommit)(virConnectPtr conn,
                               unsigned int flags);

typedef int
(*virDrvInterfaceChangeRollback)(virConnectPtr conn,
                                 unsigned int flags);

typedef struct _virInterfaceDriver virInterfaceDriver;
typedef virInterfaceDriver *virInterfaceDriverPtr;

/**
 * _virInterfaceDriver:
 *
 * Structure associated to a network interface driver, defining the various
 * entry points for it.
 *
 * All drivers must support the following fields/methods:
 *  - open
 *  - close
 */
struct _virInterfaceDriver {
    const char *name; /* the name of the driver */
    virDrvInterfaceOpen interfaceOpen;
    virDrvInterfaceClose interfaceClose;
    virDrvConnectNumOfInterfaces connectNumOfInterfaces;
    virDrvConnectListInterfaces connectListInterfaces;
    virDrvConnectNumOfDefinedInterfaces connectNumOfDefinedInterfaces;
    virDrvConnectListDefinedInterfaces connectListDefinedInterfaces;
    virDrvConnectListAllInterfaces connectListAllInterfaces;
    virDrvInterfaceLookupByName interfaceLookupByName;
    virDrvInterfaceLookupByMACString interfaceLookupByMACString;
    virDrvInterfaceGetXMLDesc interfaceGetXMLDesc;
    virDrvInterfaceDefineXML interfaceDefineXML;
    virDrvInterfaceUndefine interfaceUndefine;
    virDrvInterfaceCreate interfaceCreate;
    virDrvInterfaceDestroy interfaceDestroy;
    virDrvInterfaceIsActive interfaceIsActive;
    virDrvInterfaceChangeBegin interfaceChangeBegin;
    virDrvInterfaceChangeCommit interfaceChangeCommit;
    virDrvInterfaceChangeRollback interfaceChangeRollback;
};


typedef virDrvConnectOpen virDrvStorageOpen;
typedef virDrvConnectClose virDrvStorageClose;


typedef int
(*virDrvConnectNumOfStoragePools)(virConnectPtr conn);

typedef int
(*virDrvConnectListStoragePools)(virConnectPtr conn,
                                 char **const names,
                                 int maxnames);

typedef int
(*virDrvConnectNumOfDefinedStoragePools)(virConnectPtr conn);

typedef int
(*virDrvConnectListDefinedStoragePools)(virConnectPtr conn,
                                        char **const names,
                                        int maxnames);

typedef int
(*virDrvConnectListAllStoragePools)(virConnectPtr conn,
                                    virStoragePoolPtr **pools,
                                    unsigned int flags);

typedef char *
(*virDrvConnectFindStoragePoolSources)(virConnectPtr conn,
                                       const char *type,
                                       const char *srcSpec,
                                       unsigned int flags);

typedef virStoragePoolPtr
(*virDrvStoragePoolLookupByName)(virConnectPtr conn,
                                 const char *name);

typedef virStoragePoolPtr
(*virDrvStoragePoolLookupByUUID)(virConnectPtr conn,
                                 const unsigned char *uuid);

typedef virStoragePoolPtr
(*virDrvStoragePoolLookupByVolume)(virStorageVolPtr vol);

typedef virStoragePoolPtr
(*virDrvStoragePoolCreateXML)(virConnectPtr conn,
                              const char *xmlDesc,
                              unsigned int flags);

typedef virStoragePoolPtr
(*virDrvStoragePoolDefineXML)(virConnectPtr conn,
                              const char *xmlDesc,
                              unsigned int flags);

typedef int
(*virDrvStoragePoolUndefine)(virStoragePoolPtr pool);

typedef int
(*virDrvStoragePoolBuild)(virStoragePoolPtr pool,
                          unsigned int flags);

typedef int
(*virDrvStoragePoolCreate)(virStoragePoolPtr pool,
                           unsigned int flags);

typedef int
(*virDrvStoragePoolDestroy)(virStoragePoolPtr pool);

typedef int
(*virDrvStoragePoolDelete)(virStoragePoolPtr pool,
                           unsigned int flags);

typedef int
(*virDrvStoragePoolRefresh)(virStoragePoolPtr pool,
                            unsigned int flags);

typedef int
(*virDrvStoragePoolGetInfo)(virStoragePoolPtr vol,
                            virStoragePoolInfoPtr info);

typedef char *
(*virDrvStoragePoolGetXMLDesc)(virStoragePoolPtr pool,
                               unsigned int flags);

typedef int
(*virDrvStoragePoolGetAutostart)(virStoragePoolPtr pool,
                                 int *autostart);

typedef int
(*virDrvStoragePoolSetAutostart)(virStoragePoolPtr pool,
                                 int autostart);

typedef int
(*virDrvStoragePoolNumOfVolumes)(virStoragePoolPtr pool);

typedef int
(*virDrvStoragePoolListVolumes)(virStoragePoolPtr pool,
                                char **const names,
                                int maxnames);

typedef int
(*virDrvStoragePoolListAllVolumes)(virStoragePoolPtr pool,
                                   virStorageVolPtr **vols,
                                   unsigned int flags);

typedef virStorageVolPtr
(*virDrvStorageVolLookupByName)(virStoragePoolPtr pool,
                                const char *name);

typedef virStorageVolPtr
(*virDrvStorageVolLookupByKey)(virConnectPtr pool,
                               const char *key);

typedef virStorageVolPtr
(*virDrvStorageVolLookupByPath)(virConnectPtr pool,
                                const char *path);

typedef virStorageVolPtr
(*virDrvStorageVolCreateXML)(virStoragePoolPtr pool,
                             const char *xmldesc,
                             unsigned int flags);

typedef int
(*virDrvStorageVolDelete)(virStorageVolPtr vol,
                          unsigned int flags);

typedef int
(*virDrvStorageVolWipe)(virStorageVolPtr vol,
                        unsigned int flags);

typedef int
(*virDrvStorageVolWipePattern)(virStorageVolPtr vol,
                               unsigned int algorithm,
                               unsigned int flags);

typedef int
(*virDrvStorageVolGetInfo)(virStorageVolPtr vol,
                           virStorageVolInfoPtr info);

typedef char *
(*virDrvStorageVolGetXMLDesc)(virStorageVolPtr pool,
                              unsigned int flags);

typedef char *
(*virDrvStorageVolGetPath)(virStorageVolPtr vol);

typedef virStorageVolPtr
(*virDrvStorageVolCreateXMLFrom)(virStoragePoolPtr pool,
                                 const char *xmldesc,
                                 virStorageVolPtr clonevol,
                                 unsigned int flags);

typedef int
(*virDrvStorageVolDownload)(virStorageVolPtr vol,
                            virStreamPtr stream,
                            unsigned long long offset,
                            unsigned long long length,
                            unsigned int flags);

typedef int
(*virDrvStorageVolUpload)(virStorageVolPtr vol,
                          virStreamPtr stream,
                          unsigned long long offset,
                          unsigned long long length,
                          unsigned int flags);

typedef int
(*virDrvStorageVolResize)(virStorageVolPtr vol,
                          unsigned long long capacity,
                          unsigned int flags);

typedef int
(*virDrvStoragePoolIsActive)(virStoragePoolPtr pool);

typedef int
(*virDrvStoragePoolIsPersistent)(virStoragePoolPtr pool);



typedef struct _virStorageDriver virStorageDriver;
typedef virStorageDriver *virStorageDriverPtr;

/**
 * _virStorageDriver:
 *
 * Structure associated to a storage driver, defining the various
 * entry points for it.
 *
 * All drivers must support the following fields/methods:
 *  - open
 *  - close
 */
struct _virStorageDriver {
    const char * name; /* the name of the driver */
    virDrvStorageOpen storageOpen;
    virDrvStorageClose storageClose;
    virDrvConnectNumOfStoragePools connectNumOfStoragePools;
    virDrvConnectListStoragePools connectListStoragePools;
    virDrvConnectNumOfDefinedStoragePools connectNumOfDefinedStoragePools;
    virDrvConnectListDefinedStoragePools connectListDefinedStoragePools;
    virDrvConnectListAllStoragePools connectListAllStoragePools;
    virDrvConnectFindStoragePoolSources connectFindStoragePoolSources;
    virDrvStoragePoolLookupByName storagePoolLookupByName;
    virDrvStoragePoolLookupByUUID storagePoolLookupByUUID;
    virDrvStoragePoolLookupByVolume storagePoolLookupByVolume;
    virDrvStoragePoolCreateXML storagePoolCreateXML;
    virDrvStoragePoolDefineXML storagePoolDefineXML;
    virDrvStoragePoolBuild storagePoolBuild;
    virDrvStoragePoolUndefine storagePoolUndefine;
    virDrvStoragePoolCreate storagePoolCreate;
    virDrvStoragePoolDestroy storagePoolDestroy;
    virDrvStoragePoolDelete storagePoolDelete;
    virDrvStoragePoolRefresh storagePoolRefresh;
    virDrvStoragePoolGetInfo storagePoolGetInfo;
    virDrvStoragePoolGetXMLDesc storagePoolGetXMLDesc;
    virDrvStoragePoolGetAutostart storagePoolGetAutostart;
    virDrvStoragePoolSetAutostart storagePoolSetAutostart;
    virDrvStoragePoolNumOfVolumes storagePoolNumOfVolumes;
    virDrvStoragePoolListVolumes storagePoolListVolumes;
    virDrvStoragePoolListAllVolumes storagePoolListAllVolumes;
    virDrvStorageVolLookupByName storageVolLookupByName;
    virDrvStorageVolLookupByKey storageVolLookupByKey;
    virDrvStorageVolLookupByPath storageVolLookupByPath;
    virDrvStorageVolCreateXML storageVolCreateXML;
    virDrvStorageVolCreateXMLFrom storageVolCreateXMLFrom;
    virDrvStorageVolDownload storageVolDownload;
    virDrvStorageVolUpload storageVolUpload;
    virDrvStorageVolDelete storageVolDelete;
    virDrvStorageVolWipe storageVolWipe;
    virDrvStorageVolWipePattern storageVolWipePattern;
    virDrvStorageVolGetInfo storageVolGetInfo;
    virDrvStorageVolGetXMLDesc storageVolGetXMLDesc;
    virDrvStorageVolGetPath storageVolGetPath;
    virDrvStorageVolResize storageVolResize;
    virDrvStoragePoolIsActive storagePoolIsActive;
    virDrvStoragePoolIsPersistent storagePoolIsPersistent;
};

# ifdef WITH_LIBVIRTD

typedef int
(*virDrvStateInitialize)(bool privileged,
                         virStateInhibitCallback callback,
                         void *opaque);

typedef void
(*virDrvStateAutoStart)(void);

typedef int
(*virDrvStateCleanup)(void);

typedef int
(*virDrvStateReload)(void);

typedef int
(*virDrvStateStop)(void);

typedef struct _virStateDriver virStateDriver;
typedef virStateDriver *virStateDriverPtr;

struct _virStateDriver {
    const char *name;
    virDrvStateInitialize stateInitialize;
    virDrvStateAutoStart stateAutoStart;
    virDrvStateCleanup stateCleanup;
    virDrvStateReload stateReload;
    virDrvStateStop stateStop;
};
# endif


typedef virDrvConnectOpen virDrvNodeDeviceOpen;
typedef virDrvConnectClose virDrvNodeDeviceClose;


typedef int
(*virDrvNodeNumOfDevices)(virConnectPtr conn,
                          const char *cap,
                          unsigned int flags);

typedef int
(*virDrvNodeListDevices)(virConnectPtr conn,
                         const char *cap,
                         char **const names,
                         int maxnames,
                         unsigned int flags);

typedef int
(*virDrvConnectListAllNodeDevices)(virConnectPtr conn,
                                   virNodeDevicePtr **devices,
                                   unsigned int flags);

typedef virNodeDevicePtr
(*virDrvNodeDeviceLookupByName)(virConnectPtr conn,
                                const char *name);

typedef virNodeDevicePtr
(*virDrvNodeDeviceLookupSCSIHostByWWN)(virConnectPtr conn,
                                       const char *wwnn,
                                       const char *wwpn,
                                       unsigned int flags);

typedef char *
(*virDrvNodeDeviceGetXMLDesc)(virNodeDevicePtr dev,
                              unsigned int flags);

typedef char *
(*virDrvNodeDeviceGetParent)(virNodeDevicePtr dev);

typedef int
(*virDrvNodeDeviceNumOfCaps)(virNodeDevicePtr dev);

typedef int
(*virDrvNodeDeviceListCaps)(virNodeDevicePtr dev,
                            char **const names,
                            int maxnames);

typedef virNodeDevicePtr
(*virDrvNodeDeviceCreateXML)(virConnectPtr conn,
                             const char *xmlDesc,
                             unsigned int flags);

typedef int
(*virDrvNodeDeviceDestroy)(virNodeDevicePtr dev);



typedef struct _virNodeDeviceDriver virNodeDeviceDriver;
typedef virNodeDeviceDriver *virNodeDeviceDriverPtr;

/**
 * _virNodeDeviceDriver:
 *
 * Structure associated with monitoring the devices
 * on a virtualized node.
 *
 */
struct _virNodeDeviceDriver {
    const char * name; /* the name of the driver */
    virDrvNodeDeviceOpen nodeDeviceOpen;
    virDrvNodeDeviceClose nodeDeviceClose;
    virDrvNodeNumOfDevices nodeNumOfDevices;
    virDrvNodeListDevices nodeListDevices;
    virDrvConnectListAllNodeDevices connectListAllNodeDevices;
    virDrvNodeDeviceLookupByName nodeDeviceLookupByName;
    virDrvNodeDeviceLookupSCSIHostByWWN nodeDeviceLookupSCSIHostByWWN;
    virDrvNodeDeviceGetXMLDesc nodeDeviceGetXMLDesc;
    virDrvNodeDeviceGetParent nodeDeviceGetParent;
    virDrvNodeDeviceNumOfCaps nodeDeviceNumOfCaps;
    virDrvNodeDeviceListCaps nodeDeviceListCaps;
    virDrvNodeDeviceCreateXML nodeDeviceCreateXML;
    virDrvNodeDeviceDestroy nodeDeviceDestroy;
};

enum {
    /* This getValue call is inside libvirt, override the "private" flag.
       This flag cannot be set by outside callers. */
    VIR_SECRET_GET_VALUE_INTERNAL_CALL = 1 << 0,
};

typedef virDrvConnectOpen virDrvSecretOpen;
typedef virDrvConnectClose virDrvSecretClose;


typedef virSecretPtr
(*virDrvSecretLookupByUUID)(virConnectPtr conn,
                            const unsigned char *uuid);

typedef virSecretPtr
(*virDrvSecretLookupByUsage)(virConnectPtr conn,
                             int usageType,
                             const char *usageID);

typedef virSecretPtr
(*virDrvSecretDefineXML)(virConnectPtr conn,
                         const char *xml,
                         unsigned int flags);

typedef char *
(*virDrvSecretGetXMLDesc)(virSecretPtr secret,
                          unsigned int flags);

typedef int
(*virDrvSecretSetValue)(virSecretPtr secret,
                        const unsigned char *value,
                        size_t value_size,
                        unsigned int flags);

typedef unsigned char *
(*virDrvSecretGetValue)(virSecretPtr secret,
                        size_t *value_size,
                        unsigned int flags,
                        unsigned int internalFlags);

typedef int
(*virDrvSecretUndefine)(virSecretPtr secret);

typedef int
(*virDrvConnectNumOfSecrets)(virConnectPtr conn);

typedef int
(*virDrvConnectListSecrets)(virConnectPtr conn,
                            char **uuids,
                            int maxuuids);

typedef int
(*virDrvConnectListAllSecrets)(virConnectPtr conn,
                               virSecretPtr **secrets,
                               unsigned int flags);

typedef struct _virSecretDriver virSecretDriver;
typedef virSecretDriver *virSecretDriverPtr;

/**
 * _virSecretDriver:
 *
 * Structure associated to a driver for storing secrets, defining the various
 * entry points for it.
 *
 * All drivers must support the following fields/methods:
 *  - open
 *  - close
 */
struct _virSecretDriver {
    const char *name;
    virDrvSecretOpen secretOpen;
    virDrvSecretClose secretClose;
    virDrvConnectNumOfSecrets connectNumOfSecrets;
    virDrvConnectListSecrets connectListSecrets;
    virDrvConnectListAllSecrets connectListAllSecrets;
    virDrvSecretLookupByUUID secretLookupByUUID;
    virDrvSecretLookupByUsage secretLookupByUsage;
    virDrvSecretDefineXML secretDefineXML;
    virDrvSecretGetXMLDesc secretGetXMLDesc;
    virDrvSecretSetValue secretSetValue;
    virDrvSecretGetValue secretGetValue;
    virDrvSecretUndefine secretUndefine;
};


typedef int
(*virDrvStreamSend)(virStreamPtr st,
                    const char *data,
                    size_t nbytes);

typedef int
(*virDrvStreamRecv)(virStreamPtr st,
                    char *data,
                    size_t nbytes);

typedef int
(*virDrvStreamEventAddCallback)(virStreamPtr stream,
                                int events,
                                virStreamEventCallback cb,
                                void *opaque,
                                virFreeCallback ff);

typedef int
(*virDrvStreamEventUpdateCallback)(virStreamPtr stream,
                                   int events);

typedef int
(*virDrvStreamEventRemoveCallback)(virStreamPtr stream);

typedef int
(*virDrvStreamFinish)(virStreamPtr st);

typedef int
(*virDrvStreamAbort)(virStreamPtr st);

typedef struct _virStreamDriver virStreamDriver;
typedef virStreamDriver *virStreamDriverPtr;

struct _virStreamDriver {
    virDrvStreamSend streamSend;
    virDrvStreamRecv streamRecv;
    virDrvStreamEventAddCallback streamEventAddCallback;
    virDrvStreamEventUpdateCallback streamEventUpdateCallback;
    virDrvStreamEventRemoveCallback streamEventRemoveCallback;
    virDrvStreamFinish streamFinish;
    virDrvStreamAbort streamAbort;
};


typedef virDrvConnectOpen virDrvNWFilterOpen;
typedef virDrvConnectClose virDrvNWFilterClose;


typedef int
(*virDrvConnectNumOfNWFilters)(virConnectPtr conn);

typedef int
(*virDrvConnectListNWFilters)(virConnectPtr conn,
                              char **const names,
                              int maxnames);

typedef int
(*virDrvConnectListAllNWFilters)(virConnectPtr conn,
                                 virNWFilterPtr **filters,
                                 unsigned int flags);

typedef virNWFilterPtr
(*virDrvNWFilterLookupByName)(virConnectPtr conn,
                              const char *name);

typedef virNWFilterPtr
(*virDrvNWFilterLookupByUUID)(virConnectPtr conn,
                              const unsigned char *uuid);

typedef virNWFilterPtr
(*virDrvNWFilterDefineXML)(virConnectPtr conn,
                           const char *xmlDesc);

typedef int
(*virDrvNWFilterUndefine)(virNWFilterPtr nwfilter);

typedef char *
(*virDrvNWFilterGetXMLDesc)(virNWFilterPtr nwfilter,
                            unsigned int flags);


typedef struct _virNWFilterDriver virNWFilterDriver;
typedef virNWFilterDriver *virNWFilterDriverPtr;

/**
 * _virNWFilterDriver:
 *
 * Structure associated to a network filter driver, defining the various
 * entry points for it.
 *
 * All drivers must support the following fields/methods:
 *  - open
 *  - close
 */
struct _virNWFilterDriver {
    const char * name; /* the name of the driver */
    virDrvNWFilterOpen nwfilterOpen;
    virDrvNWFilterClose nwfilterClose;
    virDrvConnectNumOfNWFilters connectNumOfNWFilters;
    virDrvConnectListNWFilters connectListNWFilters;
    virDrvConnectListAllNWFilters connectListAllNWFilters;
    virDrvNWFilterLookupByName nwfilterLookupByName;
    virDrvNWFilterLookupByUUID nwfilterLookupByUUID;
    virDrvNWFilterDefineXML nwfilterDefineXML;
    virDrvNWFilterUndefine nwfilterUndefine;
    virDrvNWFilterGetXMLDesc nwfilterGetXMLDesc;
};


/*
 * Registration
 * TODO: also need ways to (des)activate a given driver
 *       lookup based on the URI given in a virConnectOpen(ReadOnly)
 */
int virRegisterDriver(virDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterNetworkDriver(virNetworkDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterInterfaceDriver(virInterfaceDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterStorageDriver(virStorageDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterNodeDeviceDriver(virNodeDeviceDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterSecretDriver(virSecretDriverPtr) ATTRIBUTE_RETURN_CHECK;
int virRegisterNWFilterDriver(virNWFilterDriverPtr) ATTRIBUTE_RETURN_CHECK;
# ifdef WITH_LIBVIRTD
int virRegisterStateDriver(virStateDriverPtr) ATTRIBUTE_RETURN_CHECK;
# endif
void virDriverModuleInitialize(const char *defmoddir);
void *virDriverLoadModule(const char *name);

#endif /* __VIR_DRIVER_H__ */
