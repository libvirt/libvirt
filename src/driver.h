/*
 * driver.h: description of the set of interfaces provided by a
 *           entry point to the virtualization engine
 */

#ifndef __VIR_DRIVER_H__
# define __VIR_DRIVER_H__

# include "config.h"

# include <unistd.h>

# include "internal.h"
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
# define VIR_DRV_SUPPORTS_FEATURE(drv,conn,feature)                         \
    ((drv)->supports_feature ?                                              \
        (drv)->supports_feature((conn), (feature)) > 0 : 0)

typedef virDrvOpenStatus
        (*virDrvOpen)			(virConnectPtr conn,
                             virConnectAuthPtr auth,
                             unsigned int flags);
typedef int
        (*virDrvClose)			(virConnectPtr conn);
typedef int
    (*virDrvDrvSupportsFeature) (virConnectPtr conn, int feature);
typedef const char *
        (*virDrvGetType)		(virConnectPtr conn);
typedef int
        (*virDrvGetVersion)		(virConnectPtr conn,
                                         unsigned long *hvVer);
typedef int
        (*virDrvGetLibVersion)      (virConnectPtr conn,
                                     unsigned long *libVer);
typedef char *
    (*virDrvGetHostname)    (virConnectPtr conn);
typedef char *
    (*virDrvGetURI)         (virConnectPtr conn);
typedef char *
    (*virDrvGetSysinfo)     (virConnectPtr conn,
                             unsigned int flags);
typedef int
        (*virDrvGetMaxVcpus)		(virConnectPtr conn,
                                         const char *type);
typedef int
        (*virDrvNodeGetInfo)		(virConnectPtr conn,
                                         virNodeInfoPtr info);
typedef char *
        (*virDrvGetCapabilities) (virConnectPtr conn);
typedef int
        (*virDrvListDomains)		(virConnectPtr conn,
                                         int *ids,
                                         int maxids);
typedef int
        (*virDrvNumOfDomains)		(virConnectPtr conn);
typedef virDomainPtr
        (*virDrvDomainCreateXML)	(virConnectPtr conn,
                                         const char *xmlDesc,
                                         unsigned int flags);
typedef virDomainPtr
        (*virDrvDomainLookupByID)	(virConnectPtr conn,
                                         int id);
typedef virDomainPtr
        (*virDrvDomainLookupByUUID)	(virConnectPtr conn,
                                         const unsigned char *uuid);
typedef virDomainPtr
        (*virDrvDomainLookupByName)	(virConnectPtr conn,
                                         const char *name);
typedef int
        (*virDrvDomainSuspend)		(virDomainPtr domain);
typedef int
        (*virDrvDomainResume)		(virDomainPtr domain);
typedef int
        (*virDrvDomainPMSuspendForDuration) (virDomainPtr,
                                             unsigned int target,
                                             unsigned long long duration,
                                             unsigned int flags);
typedef int
        (*virDrvDomainPMWakeup)     (virDomainPtr domain,
                                     unsigned int flags);
typedef int
        (*virDrvDomainShutdown)		(virDomainPtr domain);
typedef int
        (*virDrvDomainReboot)		(virDomainPtr domain,
                                         unsigned int flags);
typedef int
        (*virDrvDomainReset)        (virDomainPtr domain,
                                         unsigned int flags);
typedef int
        (*virDrvDomainDestroy)		(virDomainPtr domain);
typedef int
        (*virDrvDomainDestroyFlags) (virDomainPtr domain,
                                         unsigned int flags);
typedef char *
        (*virDrvDomainGetOSType)	(virDomainPtr domain);
typedef unsigned long long
        (*virDrvDomainGetMaxMemory)	(virDomainPtr domain);
typedef int
        (*virDrvDomainSetMaxMemory)	(virDomainPtr domain,
                                         unsigned long memory);
typedef int
        (*virDrvDomainSetMemory)	(virDomainPtr domain,
                                         unsigned long memory);
typedef int
        (*virDrvDomainSetMemoryFlags)	(virDomainPtr domain,
                                         unsigned long memory,
                                         unsigned int flags);
typedef int
        (*virDrvDomainSetMemoryParameters)
                                        (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int nparams,
                                         unsigned int flags);
typedef int
        (*virDrvDomainGetMemoryParameters)
                                        (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int *nparams,
                                         unsigned int flags);
typedef int
        (*virDrvDomainSetNumaParameters)
                                        (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int nparams,
                                         unsigned int flags);
typedef int
        (*virDrvDomainGetNumaParameters)
                                        (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int *nparams,
                                         unsigned int flags);

typedef int
        (*virDrvDomainSetBlkioParameters)
                                        (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int nparams,
                                         unsigned int flags);
typedef int
        (*virDrvDomainGetBlkioParameters)
                                        (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int *nparams,
                                         unsigned int flags);
typedef int
        (*virDrvDomainGetInfo)		(virDomainPtr domain,
                                         virDomainInfoPtr info);
typedef int
        (*virDrvDomainGetState)         (virDomainPtr domain,
                                         int *state,
                                         int *reason,
                                         unsigned int flags);
typedef int
        (*virDrvDomainGetControlInfo)   (virDomainPtr domain,
                                         virDomainControlInfoPtr info,
                                         unsigned int flags);
typedef int
        (*virDrvDomainSave)		(virDomainPtr domain,
                                         const char *to);
typedef int
        (*virDrvDomainSaveFlags)	(virDomainPtr domain,
                                         const char *to,
                                         const char *dxml,
                                         unsigned int flags);
typedef int
        (*virDrvDomainRestore)		(virConnectPtr conn,
                                         const char *from);
typedef int
        (*virDrvDomainRestoreFlags)	(virConnectPtr conn,
                                         const char *from,
                                         const char *dxml,
                                         unsigned int flags);
typedef char *
        (*virDrvDomainSaveImageGetXMLDesc)      (virConnectPtr conn,
                                                 const char *file,
                                                 unsigned int flags);
typedef int
        (*virDrvDomainSaveImageDefineXML)       (virConnectPtr conn,
                                                 const char *file,
                                                 const char *dxml,
                                                 unsigned int flags);
typedef int
        (*virDrvDomainCoreDump)		(virDomainPtr domain,
                                         const char *to,
                                         unsigned int flags);
typedef char *
        (*virDrvDomainScreenshot)   (virDomainPtr domain,
                                         virStreamPtr stream,
                                         unsigned int screen,
                                         unsigned int flags);
typedef char *
        (*virDrvDomainGetXMLDesc)		(virDomainPtr dom,
                                                 unsigned int flags);
typedef char *
        (*virDrvConnectDomainXMLFromNative) (virConnectPtr conn,
                                             const char *nativeFormat,
                                             const char *nativeConfig,
                                             unsigned int flags);
typedef char *
        (*virDrvConnectDomainXMLToNative) (virConnectPtr conn,
                                           const char *nativeFormat,
                                           const char *domainXml,
                                           unsigned int flags);
typedef int
        (*virDrvListDefinedDomains)	(virConnectPtr conn,
                                         char **const names,
                                         int maxnames);
typedef int
        (*virDrvNumOfDefinedDomains)	(virConnectPtr conn);
typedef int
        (*virDrvDomainCreate)		(virDomainPtr dom);
typedef int
        (*virDrvDomainCreateWithFlags)	(virDomainPtr dom,
                                         unsigned int flags);
typedef virDomainPtr
        (*virDrvDomainDefineXML)	(virConnectPtr conn,
                                         const char *xml);
typedef int
        (*virDrvDomainUndefine)		(virDomainPtr dom);
typedef int
        (*virDrvDomainUndefineFlags)	(virDomainPtr dom,
                                         unsigned int flags);
typedef int
        (*virDrvDomainSetVcpus)		(virDomainPtr domain,
                                         unsigned int nvcpus);
typedef int
        (*virDrvDomainSetVcpusFlags)	(virDomainPtr domain,
                                         unsigned int nvcpus,
                                         unsigned int flags);
typedef int
        (*virDrvDomainGetVcpusFlags)	(virDomainPtr domain,
                                         unsigned int flags);
typedef int
        (*virDrvDomainPinVcpu)		(virDomainPtr domain,
                                         unsigned int vcpu,
                                         unsigned char *cpumap,
                                         int maplen);
typedef int
        (*virDrvDomainPinVcpuFlags)     (virDomainPtr domain,
                                         unsigned int vcpu,
                                         unsigned char *cpumap,
                                         int maplen,
                                         unsigned int flags);
typedef int
        (*virDrvDomainGetVcpuPinInfo)   (virDomainPtr domain,
                                         int ncpumaps,
                                         unsigned char *cpumaps,
                                         int maplen,
                                         unsigned int flags);

typedef int
        (*virDrvDomainGetVcpus)		(virDomainPtr domain,
                                         virVcpuInfoPtr info,
                                         int maxinfo,
                                         unsigned char *cpumaps,
                                         int maplen);
typedef int
        (*virDrvDomainGetMaxVcpus)	(virDomainPtr domain);

typedef int
        (*virDrvDomainGetSecurityLabel)	(virDomainPtr domain,
                                         virSecurityLabelPtr seclabel);
typedef int
        (*virDrvNodeGetSecurityModel)	(virConnectPtr conn,
                                         virSecurityModelPtr secmodel);
typedef int
        (*virDrvDomainAttachDevice)	(virDomainPtr domain,
                                         const char *xml);
typedef int
        (*virDrvDomainAttachDeviceFlags) (virDomainPtr domain,
                                          const char *xml,
                                          unsigned int flags);
typedef int
        (*virDrvDomainDetachDevice)	(virDomainPtr domain,
                                         const char *xml);
typedef int
        (*virDrvDomainDetachDeviceFlags) (virDomainPtr domain,
                                          const char *xml,
                                          unsigned int flags);
typedef int
        (*virDrvDomainUpdateDeviceFlags) (virDomainPtr domain,
                                          const char *xml,
                                          unsigned int flags);
typedef int
        (*virDrvDomainGetAutostart)	(virDomainPtr domain,
                                         int *autostart);
typedef int
        (*virDrvDomainSetAutostart)	(virDomainPtr domain,
                                         int autostart);

typedef char *
        (*virDrvDomainGetSchedulerType)	(virDomainPtr domain,
                                         int *nparams);

typedef int
        (*virDrvDomainGetSchedulerParameters)
                                        (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int *nparams);

typedef int
        (*virDrvDomainGetSchedulerParametersFlags)
                                        (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int *nparams,
                                         unsigned int flags);

typedef int
        (*virDrvDomainSetSchedulerParameters)
                                        (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int nparams);

typedef int
        (*virDrvDomainSetSchedulerParametersFlags)
                                        (virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int nparams,
                                         unsigned int flags);

typedef int
    (*virDrvDomainBlockStats)
                    (virDomainPtr domain,
                     const char *path,
                     struct _virDomainBlockStats *stats);
typedef int
    (*virDrvDomainBlockStatsFlags)
                    (virDomainPtr domain,
                     const char *path,
                     virTypedParameterPtr params,
                     int *nparams,
                     unsigned int flags);
typedef int
    (*virDrvDomainInterfaceStats)
                    (virDomainPtr domain,
                     const char *path,
                     struct _virDomainInterfaceStats *stats);
typedef int
    (*virDrvDomainSetInterfaceParameters) (virDomainPtr dom,
                                          const char *device,
                                          virTypedParameterPtr params,
                                          int nparams, unsigned int flags);
typedef int
    (*virDrvDomainGetInterfaceParameters) (virDomainPtr dom,
                                          const char *device,
                                          virTypedParameterPtr params,
                                          int *nparams, unsigned int flags);

typedef int
    (*virDrvDomainMemoryStats)
                    (virDomainPtr domain,
                     struct _virDomainMemoryStat *stats,
                     unsigned int nr_stats,
                     unsigned int flags);

typedef int
    (*virDrvDomainBlockPeek)
                    (virDomainPtr domain,
                     const char *path,
                     unsigned long long offset, size_t size,
                     void *buffer,
                     unsigned int flags);
typedef int
    (*virDrvDomainBlockResize)
                    (virDomainPtr domain,
                     const char *path,
                     unsigned long long size,
                     unsigned int flags);
typedef int
    (*virDrvDomainMemoryPeek)
                    (virDomainPtr domain,
                     unsigned long long start, size_t size,
                     void *buffer,
                     unsigned int flags);
typedef int
    (*virDrvDomainGetBlockInfo)
                    (virDomainPtr domain,
                     const char *path,
                     virDomainBlockInfoPtr info,
                     unsigned int flags);

typedef int
    (*virDrvDomainMigratePrepare)
                    (virConnectPtr dconn,
                     char **cookie,
                     int *cookielen,
                     const char *uri_in,
                     char **uri_out,
                     unsigned long flags,
                     const char *dname,
                     unsigned long resource);

typedef int
    (*virDrvDomainMigratePerform)
                    (virDomainPtr domain,
                     const char *cookie,
                     int cookielen,
                     const char *uri,
                     unsigned long flags,
                     const char *dname,
                     unsigned long resource);

typedef virDomainPtr
    (*virDrvDomainMigrateFinish)
                    (virConnectPtr dconn,
                     const char *dname,
                     const char *cookie,
                     int cookielen,
                     const char *uri,
                     unsigned long flags);

typedef struct _virDriver virDriver;
typedef virDriver *virDriverPtr;

typedef int
    (*virDrvNodeGetCPUStats)
                    (virConnectPtr conn,
                     int cpuNum,
                     virNodeCPUStatsPtr params,
                     int *nparams,
                     unsigned int flags);

typedef int
    (*virDrvNodeGetMemoryStats)
                    (virConnectPtr conn,
                     int cellNum,
                     virNodeMemoryStatsPtr params,
                     int *nparams,
                     unsigned int flags);

typedef int
    (*virDrvNodeGetCellsFreeMemory)
                    (virConnectPtr conn,
                     unsigned long long *freeMems,
                     int startCell,
                     int maxCells);

typedef unsigned long long
    (*virDrvNodeGetFreeMemory)
                    (virConnectPtr conn);

typedef int
    (*virDrvDomainEventRegister)
                    (virConnectPtr conn,
                     virConnectDomainEventCallback cb,
                     void *opaque,
                     virFreeCallback freecb);

typedef int
    (*virDrvDomainEventDeregister)
                    (virConnectPtr conn,
                     virConnectDomainEventCallback cb);

typedef int
    (*virDrvDomainMigratePrepare2)
                    (virConnectPtr dconn,
                     char **cookie,
                     int *cookielen,
                     const char *uri_in,
                     char **uri_out,
                     unsigned long flags,
                     const char *dname,
                     unsigned long resource,
                     const char *dom_xml);

typedef virDomainPtr
    (*virDrvDomainMigrateFinish2)
                    (virConnectPtr dconn,
                     const char *dname,
                     const char *cookie,
                     int cookielen,
                     const char *uri,
                     unsigned long flags,
                     int retcode);

typedef int
    (*virDrvNodeDeviceDettach)
                    (virNodeDevicePtr dev);
typedef int
    (*virDrvNodeDeviceReAttach)
                    (virNodeDevicePtr dev);
typedef int
    (*virDrvNodeDeviceReset)
                    (virNodeDevicePtr dev);

typedef int
    (*virDrvDomainMigratePrepareTunnel)
                    (virConnectPtr dconn,
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
    (*virDrvCompareCPU)(virConnectPtr conn,
                        const char *cpu,
                        unsigned int flags);
typedef char *
    (*virDrvBaselineCPU)(virConnectPtr conn,
                         const char **xmlCPUs,
                         unsigned int ncpus,
                         unsigned int flags);

typedef int
    (*virDrvDomainGetJobInfo)(virDomainPtr domain,
                              virDomainJobInfoPtr info);

typedef int
    (*virDrvDomainAbortJob)(virDomainPtr domain);

typedef int
    (*virDrvDomainMigrateSetMaxDowntime)(virDomainPtr domain,
                                         unsigned long long downtime,
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
    (*virDrvDomainEventRegisterAny)(virConnectPtr conn,
                                    virDomainPtr dom,
                                    int eventID,
                                    virConnectDomainEventGenericCallback cb,
                                    void *opaque,
                                    virFreeCallback freecb);

typedef int
    (*virDrvDomainEventDeregisterAny)(virConnectPtr conn,
                                      int callbackID);

typedef int
    (*virDrvDomainManagedSave)(virDomainPtr domain, unsigned int flags);

typedef int
    (*virDrvDomainHasManagedSaveImage)(virDomainPtr domain, unsigned int flags);

typedef int
    (*virDrvDomainManagedSaveRemove)(virDomainPtr domain, unsigned int flags);

typedef virDomainSnapshotPtr
    (*virDrvDomainSnapshotCreateXML)(virDomainPtr domain,
                                     const char *xmlDesc,
                                     unsigned int flags);

typedef char *
    (*virDrvDomainSnapshotGetXMLDesc)(virDomainSnapshotPtr snapshot,
                                      unsigned int flags);

typedef int
    (*virDrvDomainSnapshotNum)(virDomainPtr domain, unsigned int flags);

typedef int
    (*virDrvDomainSnapshotListNames)(virDomainPtr domain, char **names,
                                     int nameslen,
                                     unsigned int flags);

typedef int
    (*virDrvDomainSnapshotNumChildren)(virDomainSnapshotPtr snapshot,
                                       unsigned int flags);

typedef int
    (*virDrvDomainSnapshotListChildrenNames)(virDomainSnapshotPtr snapshot,
                                             char **names,
                                             int nameslen,
                                             unsigned int flags);

typedef virDomainSnapshotPtr
    (*virDrvDomainSnapshotLookupByName)(virDomainPtr domain,
                                        const char *name,
                                        unsigned int flags);

typedef int
    (*virDrvDomainHasCurrentSnapshot)(virDomainPtr domain, unsigned int flags);

typedef virDomainSnapshotPtr
    (*virDrvDomainSnapshotGetParent)(virDomainSnapshotPtr snapshot,
                                     unsigned int flags);

typedef virDomainSnapshotPtr
    (*virDrvDomainSnapshotCurrent)(virDomainPtr domain,
                                   unsigned int flags);

typedef int
    (*virDrvDomainRevertToSnapshot)(virDomainSnapshotPtr snapshot,
                                    unsigned int flags);

typedef int
    (*virDrvDomainSnapshotDelete)(virDomainSnapshotPtr snapshot,
                                  unsigned int flags);

typedef int
    (*virDrvDomainQemuMonitorCommand)(virDomainPtr domain, const char *cmd,
                                      char **result, unsigned int flags);

/* Choice of unsigned int rather than pid_t is intentional.  */
typedef virDomainPtr
    (*virDrvDomainQemuAttach)(virConnectPtr conn,
                              unsigned int pid_value,
                              unsigned int flags);

typedef int
    (*virDrvDomainOpenConsole)(virDomainPtr dom,
                               const char *dev_name,
                               virStreamPtr st,
                               unsigned int flags);
typedef int
    (*virDrvDomainOpenGraphics)(virDomainPtr dom,
                                unsigned int idx,
                                int fd,
                                unsigned int flags);

typedef int
    (*virDrvDomainInjectNMI)(virDomainPtr dom, unsigned int flags);

typedef int
    (*virDrvDomainSendKey)(virDomainPtr dom, unsigned int codeset,
                           unsigned int holdtime,
                           unsigned int *keycodes,
                           int nkeycodes,
                           unsigned int flags);

typedef char *
    (*virDrvDomainMigrateBegin3)
                    (virDomainPtr domain,
                     const char *xmlin,
                     char **cookieout,
                     int *cookieoutlen,
                     unsigned long flags,
                     const char *dname,
                     unsigned long resource);

typedef int
    (*virDrvDomainMigratePrepare3)
                    (virConnectPtr dconn,
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
    (*virDrvDomainMigratePrepareTunnel3)
                    (virConnectPtr dconn,
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
    (*virDrvDomainMigratePerform3)
                    (virDomainPtr dom,
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
    (*virDrvDomainMigrateFinish3)
                    (virConnectPtr dconn,
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
    (*virDrvDomainMigrateConfirm3)
                    (virDomainPtr domain,
                     const char *cookiein,
                     int cookieinlen,
                     unsigned long flags,
                     int cancelled);

typedef int
    (*virDrvNodeSuspendForDuration)(virConnectPtr conn, unsigned int target,
                                     unsigned long long duration,
                                     unsigned int flags);


typedef int
    (*virDrvDomainBlockJobAbort)(virDomainPtr dom, const char *path,
                                 unsigned int flags);

typedef int
    (*virDrvDomainGetBlockJobInfo)(virDomainPtr dom, const char *path,
                                   virDomainBlockJobInfoPtr info,
                                   unsigned int flags);

typedef int
    (*virDrvDomainBlockJobSetSpeed)(virDomainPtr dom,
                                    const char *path, unsigned long bandwidth,
                                    unsigned int flags);

typedef int
    (*virDrvDomainBlockPull)(virDomainPtr dom, const char *path,
                             unsigned long bandwidth, unsigned int flags);
typedef int
    (*virDrvDomainBlockRebase)(virDomainPtr dom, const char *path,
                               const char *base, unsigned long bandwidth,
                               unsigned int flags);

typedef int
    (*virDrvSetKeepAlive)(virConnectPtr conn,
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
    int        no;	/* the number virDrvNo */
    const char * name;	/* the name of the driver */
    virDrvOpen			open;
    virDrvClose			close;
    virDrvDrvSupportsFeature   supports_feature;
    virDrvGetType			type;
    virDrvGetVersion		version;
    virDrvGetLibVersion		libvirtVersion;
    virDrvGetHostname       getHostname;
    virDrvGetSysinfo            getSysinfo;
    virDrvGetMaxVcpus		getMaxVcpus;
    virDrvNodeGetInfo		nodeGetInfo;
    virDrvGetCapabilities		getCapabilities;
    virDrvListDomains		listDomains;
    virDrvNumOfDomains		numOfDomains;
    virDrvDomainCreateXML		domainCreateXML;
    virDrvDomainLookupByID		domainLookupByID;
    virDrvDomainLookupByUUID	domainLookupByUUID;
    virDrvDomainLookupByName	domainLookupByName;
    virDrvDomainSuspend		domainSuspend;
    virDrvDomainResume		domainResume;
    virDrvDomainPMSuspendForDuration domainPMSuspendForDuration;
    virDrvDomainPMWakeup    domainPMWakeup;
    virDrvDomainShutdown		domainShutdown;
    virDrvDomainShutdownFlags   domainShutdownFlags;
    virDrvDomainReboot		domainReboot;
    virDrvDomainReset       domainReset;
    virDrvDomainDestroy		domainDestroy;
    virDrvDomainDestroyFlags    domainDestroyFlags;
    virDrvDomainGetOSType		domainGetOSType;
    virDrvDomainGetMaxMemory	domainGetMaxMemory;
    virDrvDomainSetMaxMemory	domainSetMaxMemory;
    virDrvDomainSetMemory		domainSetMemory;
    virDrvDomainSetMemoryFlags  domainSetMemoryFlags;
    virDrvDomainSetMemoryParameters domainSetMemoryParameters;
    virDrvDomainGetMemoryParameters domainGetMemoryParameters;
    virDrvDomainSetNumaParameters domainSetNumaParameters;
    virDrvDomainGetNumaParameters domainGetNumaParameters;
    virDrvDomainSetBlkioParameters domainSetBlkioParameters;
    virDrvDomainGetBlkioParameters domainGetBlkioParameters;
    virDrvDomainGetInfo		domainGetInfo;
    virDrvDomainGetState	domainGetState;
    virDrvDomainGetControlInfo  domainGetControlInfo;
    virDrvDomainSave		domainSave;
    virDrvDomainSaveFlags	domainSaveFlags;
    virDrvDomainRestore		domainRestore;
    virDrvDomainRestoreFlags	domainRestoreFlags;
    virDrvDomainSaveImageGetXMLDesc domainSaveImageGetXMLDesc;
    virDrvDomainSaveImageDefineXML domainSaveImageDefineXML;
    virDrvDomainCoreDump        domainCoreDump;
    virDrvDomainScreenshot      domainScreenshot;
    virDrvDomainSetVcpus		domainSetVcpus;
    virDrvDomainSetVcpusFlags		domainSetVcpusFlags;
    virDrvDomainGetVcpusFlags		domainGetVcpusFlags;
    virDrvDomainPinVcpu		domainPinVcpu;
    virDrvDomainPinVcpuFlags    domainPinVcpuFlags;
    virDrvDomainGetVcpuPinInfo  domainGetVcpuPinInfo;
    virDrvDomainGetVcpus		domainGetVcpus;
    virDrvDomainGetMaxVcpus		domainGetMaxVcpus;
    virDrvDomainGetSecurityLabel     domainGetSecurityLabel;
    virDrvNodeGetSecurityModel  nodeGetSecurityModel;
    virDrvDomainGetXMLDesc		domainGetXMLDesc;
    virDrvConnectDomainXMLFromNative domainXMLFromNative;
    virDrvConnectDomainXMLToNative domainXMLToNative;
    virDrvListDefinedDomains	listDefinedDomains;
    virDrvNumOfDefinedDomains	numOfDefinedDomains;
    virDrvDomainCreate		domainCreate;
    virDrvDomainCreateWithFlags	domainCreateWithFlags;
    virDrvDomainDefineXML           domainDefineXML;
    virDrvDomainUndefine            domainUndefine;
    virDrvDomainUndefineFlags       domainUndefineFlags;
    virDrvDomainAttachDevice	domainAttachDevice;
    virDrvDomainAttachDeviceFlags	domainAttachDeviceFlags;
    virDrvDomainDetachDevice	domainDetachDevice;
    virDrvDomainDetachDeviceFlags	domainDetachDeviceFlags;
    virDrvDomainUpdateDeviceFlags	domainUpdateDeviceFlags;
    virDrvDomainGetAutostart	domainGetAutostart;
    virDrvDomainSetAutostart	domainSetAutostart;
    virDrvDomainGetSchedulerType	domainGetSchedulerType;
    virDrvDomainGetSchedulerParameters domainGetSchedulerParameters;
    virDrvDomainGetSchedulerParametersFlags domainGetSchedulerParametersFlags;
    virDrvDomainSetSchedulerParameters domainSetSchedulerParameters;
    virDrvDomainSetSchedulerParametersFlags domainSetSchedulerParametersFlags;
    virDrvDomainMigratePrepare	domainMigratePrepare;
    virDrvDomainMigratePerform	domainMigratePerform;
    virDrvDomainMigrateFinish	domainMigrateFinish;
    virDrvDomainBlockResize     domainBlockResize;
    virDrvDomainBlockStats      domainBlockStats;
    virDrvDomainBlockStatsFlags domainBlockStatsFlags;
    virDrvDomainInterfaceStats  domainInterfaceStats;
    virDrvDomainSetInterfaceParameters domainSetInterfaceParameters;
    virDrvDomainGetInterfaceParameters domainGetInterfaceParameters;
    virDrvDomainMemoryStats     domainMemoryStats;
    virDrvDomainBlockPeek	domainBlockPeek;
    virDrvDomainMemoryPeek      domainMemoryPeek;
    virDrvDomainGetBlockInfo    domainGetBlockInfo;
    virDrvNodeGetCPUStats       nodeGetCPUStats;
    virDrvNodeGetMemoryStats	nodeGetMemoryStats;
    virDrvNodeGetCellsFreeMemory	nodeGetCellsFreeMemory;
    virDrvNodeGetFreeMemory		nodeGetFreeMemory;
    virDrvDomainEventRegister         domainEventRegister;
    virDrvDomainEventDeregister       domainEventDeregister;
    virDrvDomainMigratePrepare2	domainMigratePrepare2;
    virDrvDomainMigrateFinish2	domainMigrateFinish2;
    virDrvNodeDeviceDettach     nodeDeviceDettach;
    virDrvNodeDeviceReAttach    nodeDeviceReAttach;
    virDrvNodeDeviceReset       nodeDeviceReset;
    virDrvDomainMigratePrepareTunnel domainMigratePrepareTunnel;
    virDrvConnectIsEncrypted   isEncrypted;
    virDrvConnectIsSecure      isSecure;
    virDrvDomainIsActive       domainIsActive;
    virDrvDomainIsPersistent   domainIsPersistent;
    virDrvDomainIsUpdated      domainIsUpdated;
    virDrvCompareCPU            cpuCompare;
    virDrvBaselineCPU           cpuBaseline;
    virDrvDomainGetJobInfo     domainGetJobInfo;
    virDrvDomainAbortJob     domainAbortJob;
    virDrvDomainMigrateSetMaxDowntime  domainMigrateSetMaxDowntime;
    virDrvDomainMigrateGetMaxSpeed  domainMigrateGetMaxSpeed;
    virDrvDomainMigrateSetMaxSpeed  domainMigrateSetMaxSpeed;
    virDrvDomainEventRegisterAny domainEventRegisterAny;
    virDrvDomainEventDeregisterAny domainEventDeregisterAny;
    virDrvDomainManagedSave domainManagedSave;
    virDrvDomainHasManagedSaveImage domainHasManagedSaveImage;
    virDrvDomainManagedSaveRemove domainManagedSaveRemove;
    virDrvDomainSnapshotCreateXML domainSnapshotCreateXML;
    virDrvDomainSnapshotGetXMLDesc domainSnapshotGetXMLDesc;
    virDrvDomainSnapshotNum domainSnapshotNum;
    virDrvDomainSnapshotListNames domainSnapshotListNames;
    virDrvDomainSnapshotNumChildren domainSnapshotNumChildren;
    virDrvDomainSnapshotListChildrenNames domainSnapshotListChildrenNames;
    virDrvDomainSnapshotLookupByName domainSnapshotLookupByName;
    virDrvDomainHasCurrentSnapshot domainHasCurrentSnapshot;
    virDrvDomainSnapshotGetParent domainSnapshotGetParent;
    virDrvDomainSnapshotCurrent domainSnapshotCurrent;
    virDrvDomainRevertToSnapshot domainRevertToSnapshot;
    virDrvDomainSnapshotDelete domainSnapshotDelete;
    virDrvDomainQemuMonitorCommand qemuDomainMonitorCommand;
    virDrvDomainQemuAttach qemuDomainAttach;
    virDrvDomainOpenConsole domainOpenConsole;
    virDrvDomainOpenGraphics domainOpenGraphics;
    virDrvDomainInjectNMI domainInjectNMI;
    virDrvDomainMigrateBegin3	domainMigrateBegin3;
    virDrvDomainMigratePrepare3	domainMigratePrepare3;
    virDrvDomainMigratePrepareTunnel3	domainMigratePrepareTunnel3;
    virDrvDomainMigratePerform3	domainMigratePerform3;
    virDrvDomainMigrateFinish3	domainMigrateFinish3;
    virDrvDomainMigrateConfirm3	domainMigrateConfirm3;
    virDrvDomainSendKey domainSendKey;
    virDrvDomainBlockJobAbort domainBlockJobAbort;
    virDrvDomainGetBlockJobInfo domainGetBlockJobInfo;
    virDrvDomainBlockJobSetSpeed domainBlockJobSetSpeed;
    virDrvDomainBlockPull domainBlockPull;
    virDrvDomainBlockRebase domainBlockRebase;
    virDrvSetKeepAlive setKeepAlive;
    virDrvConnectIsAlive isAlive;
    virDrvNodeSuspendForDuration nodeSuspendForDuration;
    virDrvDomainSetBlockIoTune domainSetBlockIoTune;
    virDrvDomainGetBlockIoTune domainGetBlockIoTune;
    virDrvDomainGetCPUStats domainGetCPUStats;
    virDrvDomainGetDiskErrors domainGetDiskErrors;
    virDrvDomainSetMetadata domainSetMetadata;
    virDrvDomainGetMetadata domainGetMetadata;
};

typedef int
        (*virDrvNumOfNetworks)		(virConnectPtr conn);
typedef int
        (*virDrvListNetworks)		(virConnectPtr conn,
                                         char **const names,
                                         int maxnames);
typedef int
        (*virDrvNumOfDefinedNetworks)	(virConnectPtr conn);
typedef int
        (*virDrvListDefinedNetworks)	(virConnectPtr conn,
                                         char **const names,
                                         int maxnames);
typedef virNetworkPtr
        (*virDrvNetworkLookupByUUID)	(virConnectPtr conn,
                                         const unsigned char *uuid);
typedef virNetworkPtr
        (*virDrvNetworkLookupByName)	(virConnectPtr conn,
                                         const char *name);
typedef virNetworkPtr
        (*virDrvNetworkCreateXML)	(virConnectPtr conn,
                                         const char *xmlDesc);
typedef virNetworkPtr
        (*virDrvNetworkDefineXML)	(virConnectPtr conn,
                                         const char *xml);
typedef int
        (*virDrvNetworkUndefine)	(virNetworkPtr network);
typedef int
        (*virDrvNetworkCreate)		(virNetworkPtr network);
typedef int
        (*virDrvNetworkDestroy)		(virNetworkPtr network);
typedef char *
        (*virDrvNetworkGetXMLDesc)		(virNetworkPtr network,
                                         unsigned int flags);
typedef char *
        (*virDrvNetworkGetBridgeName)	(virNetworkPtr network);
typedef int
        (*virDrvNetworkGetAutostart)	(virNetworkPtr network,
                                         int *autostart);
typedef int
        (*virDrvNetworkSetAutostart)	(virNetworkPtr network,
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
        const char * name;	/* the name of the driver */
        virDrvOpen			open;
        virDrvClose			close;
        virDrvNumOfNetworks		numOfNetworks;
        virDrvListNetworks		listNetworks;
        virDrvNumOfDefinedNetworks	numOfDefinedNetworks;
        virDrvListDefinedNetworks	listDefinedNetworks;
        virDrvNetworkLookupByUUID	networkLookupByUUID;
        virDrvNetworkLookupByName	networkLookupByName;
        virDrvNetworkCreateXML		networkCreateXML;
        virDrvNetworkDefineXML		networkDefineXML;
        virDrvNetworkUndefine		networkUndefine;
        virDrvNetworkCreate		networkCreate;
        virDrvNetworkDestroy		networkDestroy;
        virDrvNetworkGetXMLDesc		networkGetXMLDesc;
        virDrvNetworkGetBridgeName	networkGetBridgeName;
        virDrvNetworkGetAutostart	networkGetAutostart;
        virDrvNetworkSetAutostart	networkSetAutostart;
        virDrvNetworkIsActive           networkIsActive;
        virDrvNetworkIsPersistent       networkIsPersistent;
};

/*-------*/
typedef int
        (*virDrvNumOfInterfaces)        (virConnectPtr conn);
typedef int
        (*virDrvListInterfaces)         (virConnectPtr conn,
                                         char **const names,
                                         int maxnames);
typedef int
        (*virDrvNumOfDefinedInterfaces) (virConnectPtr conn);
typedef int
        (*virDrvListDefinedInterfaces)  (virConnectPtr conn,
                                         char **const names,
                                         int maxnames);
typedef virInterfacePtr
        (*virDrvInterfaceLookupByName)  (virConnectPtr conn,
                                         const char *name);
typedef virInterfacePtr
        (*virDrvInterfaceLookupByMACString)   (virConnectPtr conn,
                                               const char *mac);

typedef char *
        (*virDrvInterfaceGetXMLDesc)    (virInterfacePtr iface,
                                         unsigned int flags);

typedef virInterfacePtr
        (*virDrvInterfaceDefineXML)     (virConnectPtr conn,
                                         const char *xmlDesc,
                                         unsigned int flags);
typedef int
        (*virDrvInterfaceUndefine)      (virInterfacePtr iface);
typedef int
        (*virDrvInterfaceCreate)        (virInterfacePtr iface,
                                         unsigned int flags);
typedef int
        (*virDrvInterfaceDestroy)       (virInterfacePtr iface,
                                         unsigned int flags);

typedef int
        (*virDrvInterfaceIsActive)(virInterfacePtr iface);

typedef int
        (*virDrvInterfaceChangeBegin)   (virConnectPtr conn,
                                         unsigned int flags);
typedef int
        (*virDrvInterfaceChangeCommit)  (virConnectPtr conn,
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
    const char                      *name; /* the name of the driver */
    virDrvOpen                       open;
    virDrvClose                      close;
    virDrvNumOfInterfaces            numOfInterfaces;
    virDrvListInterfaces             listInterfaces;
    virDrvNumOfDefinedInterfaces     numOfDefinedInterfaces;
    virDrvListDefinedInterfaces      listDefinedInterfaces;
    virDrvInterfaceLookupByName      interfaceLookupByName;
    virDrvInterfaceLookupByMACString interfaceLookupByMACString;
    virDrvInterfaceGetXMLDesc        interfaceGetXMLDesc;
    virDrvInterfaceDefineXML         interfaceDefineXML;
    virDrvInterfaceUndefine          interfaceUndefine;
    virDrvInterfaceCreate            interfaceCreate;
    virDrvInterfaceDestroy           interfaceDestroy;
    virDrvInterfaceIsActive          interfaceIsActive;
    virDrvInterfaceChangeBegin       interfaceChangeBegin;
    virDrvInterfaceChangeCommit      interfaceChangeCommit;
    virDrvInterfaceChangeRollback    interfaceChangeRollback;
};


typedef int
    (*virDrvConnectNumOfStoragePools)        (virConnectPtr conn);
typedef int
    (*virDrvConnectListStoragePools)         (virConnectPtr conn,
                                              char **const names,
                                              int maxnames);
typedef int
    (*virDrvConnectNumOfDefinedStoragePools) (virConnectPtr conn);
typedef int
    (*virDrvConnectListDefinedStoragePools)  (virConnectPtr conn,
                                              char **const names,
                                              int maxnames);
typedef char *
    (*virDrvConnectFindStoragePoolSources)   (virConnectPtr conn,
                                              const char *type,
                                              const char *srcSpec,
                                              unsigned int flags);
typedef virStoragePoolPtr
    (*virDrvStoragePoolLookupByName)         (virConnectPtr conn,
                                              const char *name);
typedef virStoragePoolPtr
    (*virDrvStoragePoolLookupByUUID)         (virConnectPtr conn,
                                              const unsigned char *uuid);
typedef virStoragePoolPtr
    (*virDrvStoragePoolLookupByVolume)       (virStorageVolPtr vol);
typedef virStoragePoolPtr
    (*virDrvStoragePoolCreateXML)            (virConnectPtr conn,
                                              const char *xmlDesc,
                                              unsigned int flags);
typedef virStoragePoolPtr
    (*virDrvStoragePoolDefineXML)            (virConnectPtr conn,
                                              const char *xmlDesc,
                                              unsigned int flags);
typedef int
    (*virDrvStoragePoolUndefine)             (virStoragePoolPtr pool);
typedef int
    (*virDrvStoragePoolBuild)                (virStoragePoolPtr pool,
                                              unsigned int flags);
typedef int
    (*virDrvStoragePoolCreate)               (virStoragePoolPtr pool,
                                              unsigned int flags);
typedef int
    (*virDrvStoragePoolDestroy)              (virStoragePoolPtr pool);
typedef int
    (*virDrvStoragePoolDelete)               (virStoragePoolPtr pool,
                                              unsigned int flags);
typedef int
    (*virDrvStoragePoolRefresh)              (virStoragePoolPtr pool,
                                              unsigned int flags);
typedef int
    (*virDrvStoragePoolGetInfo)              (virStoragePoolPtr vol,
                                              virStoragePoolInfoPtr info);
typedef char *
    (*virDrvStoragePoolGetXMLDesc)           (virStoragePoolPtr pool,
                                              unsigned int flags);
typedef int
    (*virDrvStoragePoolGetAutostart)         (virStoragePoolPtr pool,
                                              int *autostart);
typedef int
    (*virDrvStoragePoolSetAutostart)         (virStoragePoolPtr pool,
                                              int autostart);
typedef int
    (*virDrvStoragePoolNumOfVolumes)         (virStoragePoolPtr pool);
typedef int
    (*virDrvStoragePoolListVolumes)          (virStoragePoolPtr pool,
                                              char **const names,
                                              int maxnames);


typedef virStorageVolPtr
    (*virDrvStorageVolLookupByName)          (virStoragePoolPtr pool,
                                              const char *name);
typedef virStorageVolPtr
    (*virDrvStorageVolLookupByKey)           (virConnectPtr pool,
                                              const char *key);
typedef virStorageVolPtr
    (*virDrvStorageVolLookupByPath)          (virConnectPtr pool,
                                              const char *path);


typedef virStorageVolPtr
    (*virDrvStorageVolCreateXML)             (virStoragePoolPtr pool,
                                              const char *xmldesc,
                                              unsigned int flags);
typedef int
    (*virDrvStorageVolDelete)               (virStorageVolPtr vol,
                                             unsigned int flags);

typedef int
    (*virDrvStorageVolWipe)                  (virStorageVolPtr vol,
                                              unsigned int flags);
typedef int
    (*virDrvStorageVolWipePattern)           (virStorageVolPtr vol,
                                              unsigned int algorithm,
                                              unsigned int flags);

typedef int
    (*virDrvStorageVolGetInfo)               (virStorageVolPtr vol,
                                              virStorageVolInfoPtr info);
typedef char *
    (*virDrvStorageVolGetXMLDesc)            (virStorageVolPtr pool,
                                              unsigned int flags);
typedef char *
    (*virDrvStorageVolGetPath)               (virStorageVolPtr vol);

typedef virStorageVolPtr
    (*virDrvStorageVolCreateXMLFrom)         (virStoragePoolPtr pool,
                                              const char *xmldesc,
                                              virStorageVolPtr clone,
                                              unsigned int flags);
typedef int
    (*virDrvStorageVolDownload) (virStorageVolPtr vol,
                                 virStreamPtr stream,
                                 unsigned long long offset,
                                 unsigned long long length,
                                 unsigned int flags);
typedef int
    (*virDrvStorageVolUpload) (virStorageVolPtr vol,
                               virStreamPtr stream,
                               unsigned long long offset,
                               unsigned long long length,
                               unsigned int flags);
typedef int
        (*virDrvStorageVolResize) (virStorageVolPtr vol,
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
    const char * name;    /* the name of the driver */
    virDrvOpen            open;
    virDrvClose           close;

    virDrvConnectNumOfStoragePools numOfPools;
    virDrvConnectListStoragePools listPools;
    virDrvConnectNumOfDefinedStoragePools numOfDefinedPools;
    virDrvConnectListDefinedStoragePools listDefinedPools;
    virDrvConnectFindStoragePoolSources findPoolSources;
    virDrvStoragePoolLookupByName poolLookupByName;
    virDrvStoragePoolLookupByUUID poolLookupByUUID;
    virDrvStoragePoolLookupByVolume poolLookupByVolume;
    virDrvStoragePoolCreateXML poolCreateXML;
    virDrvStoragePoolDefineXML poolDefineXML;
    virDrvStoragePoolBuild poolBuild;
    virDrvStoragePoolUndefine poolUndefine;
    virDrvStoragePoolCreate poolCreate;
    virDrvStoragePoolDestroy poolDestroy;
    virDrvStoragePoolDelete poolDelete;
    virDrvStoragePoolRefresh poolRefresh;
    virDrvStoragePoolGetInfo poolGetInfo;
    virDrvStoragePoolGetXMLDesc poolGetXMLDesc;
    virDrvStoragePoolGetAutostart poolGetAutostart;
    virDrvStoragePoolSetAutostart poolSetAutostart;
    virDrvStoragePoolNumOfVolumes poolNumOfVolumes;
    virDrvStoragePoolListVolumes poolListVolumes;

    virDrvStorageVolLookupByName volLookupByName;
    virDrvStorageVolLookupByKey volLookupByKey;
    virDrvStorageVolLookupByPath volLookupByPath;
    virDrvStorageVolCreateXML volCreateXML;
    virDrvStorageVolCreateXMLFrom volCreateXMLFrom;
    virDrvStorageVolDownload volDownload;
    virDrvStorageVolUpload volUpload;
    virDrvStorageVolDelete volDelete;
    virDrvStorageVolWipe volWipe;
    virDrvStorageVolWipePattern volWipePattern;
    virDrvStorageVolGetInfo volGetInfo;
    virDrvStorageVolGetXMLDesc volGetXMLDesc;
    virDrvStorageVolGetPath volGetPath;
    virDrvStorageVolResize volResize;
    virDrvStoragePoolIsActive   poolIsActive;
    virDrvStoragePoolIsPersistent   poolIsPersistent;
};

# ifdef WITH_LIBVIRTD
typedef int (*virDrvStateInitialize) (int privileged);
typedef int (*virDrvStateCleanup) (void);
typedef int (*virDrvStateReload) (void);
typedef int (*virDrvStateActive) (void);

typedef struct _virStateDriver virStateDriver;
typedef virStateDriver *virStateDriverPtr;

struct _virStateDriver {
    const char *name;
    virDrvStateInitialize  initialize;
    virDrvStateCleanup     cleanup;
    virDrvStateReload      reload;
    virDrvStateActive      active;
};
# endif


typedef struct _virDeviceMonitor virDeviceMonitor;
typedef virDeviceMonitor *virDeviceMonitorPtr;

typedef int (*virDevMonNumOfDevices)(virConnectPtr conn,
                                     const char *cap,
                                     unsigned int flags);

typedef int (*virDevMonListDevices)(virConnectPtr conn,
                                    const char *cap,
                                    char **const names,
                                    int maxnames,
                                    unsigned int flags);

typedef virNodeDevicePtr (*virDevMonDeviceLookupByName)(virConnectPtr conn,
                                                        const char *name);

typedef char * (*virDevMonDeviceGetXMLDesc)(virNodeDevicePtr dev,
                                            unsigned int flags);

typedef char * (*virDevMonDeviceGetParent)(virNodeDevicePtr dev);

typedef int (*virDevMonDeviceNumOfCaps)(virNodeDevicePtr dev);

typedef int (*virDevMonDeviceListCaps)(virNodeDevicePtr dev,
                                       char **const names,
                                       int maxnames);

typedef virNodeDevicePtr (*virDrvNodeDeviceCreateXML)(virConnectPtr conn,
                                                      const char *xmlDesc,
                                                      unsigned int flags);
typedef int (*virDrvNodeDeviceDestroy)(virNodeDevicePtr dev);

/**
 * _virDeviceMonitor:
 *
 * Structure associated with monitoring the devices
 * on a virtualized node.
 *
 */
struct _virDeviceMonitor {
    const char * name;    /* the name of the driver */
    virDrvOpen open;
    virDrvClose close;
    virDevMonNumOfDevices numOfDevices;
    virDevMonListDevices listDevices;
    virDevMonDeviceLookupByName deviceLookupByName;
    virDevMonDeviceGetXMLDesc deviceGetXMLDesc;
    virDevMonDeviceGetParent deviceGetParent;
    virDevMonDeviceNumOfCaps deviceNumOfCaps;
    virDevMonDeviceListCaps deviceListCaps;
    virDrvNodeDeviceCreateXML deviceCreateXML;
    virDrvNodeDeviceDestroy deviceDestroy;
};

enum {
    /* This getValue call is inside libvirt, override the "private" flag.
       This flag cannot be set by outside callers. */
    VIR_SECRET_GET_VALUE_INTERNAL_CALL = 1 << 0,
};

typedef virSecretPtr
    (*virDrvSecretLookupByUUID)        (virConnectPtr conn,
                                        const unsigned char *uuid);
typedef virSecretPtr
    (*virDrvSecretLookupByUsage)       (virConnectPtr conn,
                                        int usageType,
                                        const char *usageID);
typedef virSecretPtr
    (*virDrvSecretDefineXML)                 (virConnectPtr conn,
                                              const char *xml,
                                              unsigned int flags);
typedef char *
    (*virDrvSecretGetXMLDesc)                (virSecretPtr secret,
                                              unsigned int flags);
typedef int
    (*virDrvSecretSetValue)                  (virSecretPtr secret,
                                              const unsigned char *value,
                                              size_t value_size,
                                              unsigned int flags);
typedef unsigned char *
    (*virDrvSecretGetValue)                  (virSecretPtr secret,
                                              size_t *value_size,
                                              unsigned int flags,
                                              unsigned int internalFlags);
typedef int
    (*virDrvSecretUndefine)                  (virSecretPtr secret);
typedef int
    (*virDrvNumOfSecrets)              (virConnectPtr conn);
typedef int
    (*virDrvListSecrets)               (virConnectPtr conn,
                                              char **uuids,
                                              int maxuuids);

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
    virDrvOpen open;
    virDrvClose close;

    virDrvNumOfSecrets numOfSecrets;
    virDrvListSecrets listSecrets;
    virDrvSecretLookupByUUID lookupByUUID;
    virDrvSecretLookupByUsage lookupByUsage;
    virDrvSecretDefineXML defineXML;
    virDrvSecretGetXMLDesc getXMLDesc;
    virDrvSecretSetValue setValue;
    virDrvSecretGetValue getValue;
    virDrvSecretUndefine undefine;
};


typedef struct _virStreamDriver virStreamDriver;
typedef virStreamDriver *virStreamDriverPtr;

typedef int (*virDrvStreamSend)(virStreamPtr st,
                                const char *data,
                                size_t nbytes);
typedef int (*virDrvStreamRecv)(virStreamPtr st,
                                char *data,
                                size_t nbytes);

typedef int (*virDrvStreamEventAddCallback)(virStreamPtr stream,
                                            int events,
                                            virStreamEventCallback cb,
                                            void *opaque,
                                            virFreeCallback ff);

typedef int (*virDrvStreamEventUpdateCallback)(virStreamPtr stream,
                                               int events);
typedef int (*virDrvStreamEventRemoveCallback)(virStreamPtr stream);
typedef int (*virDrvStreamFinish)(virStreamPtr st);
typedef int (*virDrvStreamAbort)(virStreamPtr st);


struct _virStreamDriver {
    virDrvStreamSend streamSend;
    virDrvStreamRecv streamRecv;
    virDrvStreamEventAddCallback streamAddCallback;
    virDrvStreamEventUpdateCallback streamUpdateCallback;
    virDrvStreamEventRemoveCallback streamRemoveCallback;
    virDrvStreamFinish streamFinish;
    virDrvStreamAbort streamAbort;
};


typedef int
    (*virDrvConnectNumOfNWFilters)        (virConnectPtr conn);
typedef int
    (*virDrvConnectListNWFilters)         (virConnectPtr conn,
                                           char **const names,
                                           int maxnames);
typedef virNWFilterPtr
    (*virDrvNWFilterLookupByName)             (virConnectPtr conn,
                                               const char *name);
typedef virNWFilterPtr
    (*virDrvNWFilterLookupByUUID)             (virConnectPtr conn,
                                               const unsigned char *uuid);
typedef virNWFilterPtr
    (*virDrvNWFilterDefineXML)                (virConnectPtr conn,
                                               const char *xmlDesc);
typedef int
    (*virDrvNWFilterUndefine)                 (virNWFilterPtr nwfilter);

typedef char *
    (*virDrvNWFilterGetXMLDesc)              (virNWFilterPtr nwfilter,
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
    const char * name;    /* the name of the driver */
    virDrvOpen            open;
    virDrvClose           close;

    virDrvConnectNumOfNWFilters numOfNWFilters;
    virDrvConnectListNWFilters listNWFilters;
    virDrvNWFilterLookupByName nwfilterLookupByName;
    virDrvNWFilterLookupByUUID nwfilterLookupByUUID;
    virDrvNWFilterDefineXML defineXML;
    virDrvNWFilterUndefine undefine;
    virDrvNWFilterGetXMLDesc getXMLDesc;
};


/*
 * Registration
 * TODO: also need ways to (des)activate a given driver
 *       lookup based on the URI given in a virConnectOpen(ReadOnly)
 */
int virRegisterDriver(virDriverPtr);
int virRegisterNetworkDriver(virNetworkDriverPtr);
int virRegisterInterfaceDriver(virInterfaceDriverPtr);
int virRegisterStorageDriver(virStorageDriverPtr);
int virRegisterDeviceMonitor(virDeviceMonitorPtr);
int virRegisterSecretDriver(virSecretDriverPtr);
int virRegisterNWFilterDriver(virNWFilterDriverPtr);
# ifdef WITH_LIBVIRTD
int virRegisterStateDriver(virStateDriverPtr);
# endif
void *virDriverLoadModule(const char *name);

#endif /* __VIR_DRIVER_H__ */
