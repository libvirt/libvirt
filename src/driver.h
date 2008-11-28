/*
 * driver.h: description of the set of interfaces provided by a
 *           entry point to the virtualization engine
 */

#ifndef __VIR_DRIVER_H__
#define __VIR_DRIVER_H__

#include <libxml/uri.h>

#include "internal.h"
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

/* Feature detection.  This is a libvirt-private interface for determining
 * what features are supported by the driver.
 *
 * The remote driver passes features through to the real driver at the
 * remote end unmodified, except if you query a VIR_DRV_FEATURE_REMOTE*
 * feature.
 */
    /* Driver supports V1-style virDomainMigrate, ie. domainMigratePrepare/
     * domainMigratePerform/domainMigrateFinish.
     */
#define VIR_DRV_FEATURE_MIGRATION_V1 1

    /* Driver is not local. */
#define VIR_DRV_FEATURE_REMOTE 2

    /* Driver supports V2-style virDomainMigrate, ie. domainMigratePrepare2/
     * domainMigratePerform/domainMigrateFinish2.
     */
#define VIR_DRV_FEATURE_MIGRATION_V2 3

/* Internal feature-detection macro.  Don't call drv->supports_feature
 * directly, because it may be NULL, use this macro instead.
 *
 * Note that you must check for errors.
 *
 * Returns:
 *   >= 1  Feature is supported.
 *   0     Feature is not supported.
 *   -1    Error.
 */
#define VIR_DRV_SUPPORTS_FEATURE(drv,conn,feature)                      \
    ((drv)->supports_feature ? (drv)->supports_feature((conn),(feature)) : 0)

typedef virDrvOpenStatus
        (*virDrvOpen)			(virConnectPtr conn,
                             virConnectAuthPtr auth,
                             int flags);
typedef int
        (*virDrvClose)			(virConnectPtr conn);
typedef int
    (*virDrvDrvSupportsFeature) (virConnectPtr conn, int feature);
typedef const char *
        (*virDrvGetType)		(virConnectPtr conn);
typedef int
        (*virDrvGetVersion)		(virConnectPtr conn,
                                         unsigned long *hvVer);
typedef char *
    (*virDrvGetHostname)    (virConnectPtr conn);
typedef char *
    (*virDrvGetURI)         (virConnectPtr conn);
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
        (*virDrvDomainShutdown)		(virDomainPtr domain);
typedef int
        (*virDrvDomainReboot)		(virDomainPtr domain,
                                         unsigned int flags);
typedef int
        (*virDrvDomainDestroy)		(virDomainPtr domain);
typedef char *
        (*virDrvDomainGetOSType)	(virDomainPtr domain);
typedef unsigned long
        (*virDrvDomainGetMaxMemory)	(virDomainPtr domain);
typedef int
        (*virDrvDomainSetMaxMemory)	(virDomainPtr domain,
                                         unsigned long memory);
typedef int
        (*virDrvDomainSetMemory)	(virDomainPtr domain,
                                         unsigned long memory);
typedef int
        (*virDrvDomainGetInfo)		(virDomainPtr domain,
                                         virDomainInfoPtr info);
typedef int
        (*virDrvDomainSave)		(virDomainPtr domain,
                                         const char *to);
typedef int
        (*virDrvDomainRestore)		(virConnectPtr conn,
                                         const char *from);
typedef int
        (*virDrvDomainCoreDump)		(virDomainPtr domain,
                                         const char *to,
                                         int flags);
typedef char *
        (*virDrvDomainDumpXML)		(virDomainPtr dom,
                                         int flags);
typedef int
        (*virDrvListDefinedDomains)	(virConnectPtr conn,
                                         char **const names,
                                         int maxnames);
typedef int
        (*virDrvNumOfDefinedDomains)	(virConnectPtr conn);
typedef int
        (*virDrvDomainCreate)		(virDomainPtr dom);
typedef virDomainPtr
        (*virDrvDomainDefineXML)	(virConnectPtr conn,
                                         const char *xml);
typedef int
        (*virDrvDomainUndefine)		(virDomainPtr dom);
typedef int
        (*virDrvDomainSetVcpus)		(virDomainPtr domain,
                                         unsigned int nvcpus);
typedef int
        (*virDrvDomainPinVcpu)		(virDomainPtr domain,
                                         unsigned int vcpu,
                                         unsigned char *cpumap,
                                         int maplen);
typedef int
        (*virDrvDomainGetVcpus)		(virDomainPtr domain,
                                         virVcpuInfoPtr info,
                                         int maxinfo,
                                         unsigned char *cpumaps,
                                         int maplen);
typedef int
        (*virDrvDomainGetMaxVcpus)	(virDomainPtr domain);
typedef int
        (*virDrvDomainAttachDevice)	(virDomainPtr domain,
                                         const char *xml);
typedef int
        (*virDrvDomainDetachDevice)	(virDomainPtr domain,
                                         const char *xml);
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
                                         virSchedParameterPtr params,
                                         int *nparams);

typedef int
        (*virDrvDomainSetSchedulerParameters)
                                        (virDomainPtr domain,
                                         virSchedParameterPtr params,
                                         int nparams);

typedef int
    (*virDrvDomainBlockStats)
                    (virDomainPtr domain,
                     const char *path,
                     struct _virDomainBlockStats *stats);
typedef int
    (*virDrvDomainInterfaceStats)
                    (virDomainPtr domain,
                     const char *path,
                     struct _virDomainInterfaceStats *stats);

typedef int
    (*virDrvDomainBlockPeek)
                    (virDomainPtr domain,
                     const char *path,
                     unsigned long long offset, size_t size,
                     void *buffer,
                     unsigned int flags);

typedef int
    (*virDrvDomainMemoryPeek)
                    (virDomainPtr domain,
                     unsigned long long start, size_t size,
                     void *buffer,
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
                     void *callback,
                     void *opaque,
                     virFreeCallback freecb);

typedef int
    (*virDrvDomainEventDeregister)
                    (virConnectPtr conn,
                     void *callback);

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
    int	       no;	/* the number virDrvNo */
    const char * name;	/* the name of the driver */
    virDrvOpen			open;
    virDrvClose			close;
    virDrvDrvSupportsFeature   supports_feature;
    virDrvGetType			type;
    virDrvGetVersion		version;
    virDrvGetHostname       getHostname;
    virDrvGetURI            getURI;
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
    virDrvDomainShutdown		domainShutdown;
    virDrvDomainReboot		domainReboot;
    virDrvDomainDestroy		domainDestroy;
    virDrvDomainGetOSType		domainGetOSType;
    virDrvDomainGetMaxMemory	domainGetMaxMemory;
    virDrvDomainSetMaxMemory	domainSetMaxMemory;
    virDrvDomainSetMemory		domainSetMemory;
    virDrvDomainGetInfo		domainGetInfo;
    virDrvDomainSave		domainSave;
    virDrvDomainRestore		domainRestore;
    virDrvDomainCoreDump		domainCoreDump;
    virDrvDomainSetVcpus		domainSetVcpus;
    virDrvDomainPinVcpu		domainPinVcpu;
    virDrvDomainGetVcpus		domainGetVcpus;
    virDrvDomainGetMaxVcpus		domainGetMaxVcpus;
    virDrvDomainDumpXML		domainDumpXML;
    virDrvListDefinedDomains	listDefinedDomains;
    virDrvNumOfDefinedDomains	numOfDefinedDomains;
    virDrvDomainCreate		domainCreate;
    virDrvDomainDefineXML           domainDefineXML;
    virDrvDomainUndefine            domainUndefine;
    virDrvDomainAttachDevice	domainAttachDevice;
    virDrvDomainDetachDevice	domainDetachDevice;
    virDrvDomainGetAutostart	domainGetAutostart;
    virDrvDomainSetAutostart	domainSetAutostart;
    virDrvDomainGetSchedulerType	domainGetSchedulerType;
    virDrvDomainGetSchedulerParameters domainGetSchedulerParameters;
    virDrvDomainSetSchedulerParameters domainSetSchedulerParameters;
    virDrvDomainMigratePrepare	domainMigratePrepare;
    virDrvDomainMigratePerform	domainMigratePerform;
    virDrvDomainMigrateFinish	domainMigrateFinish;
    virDrvDomainBlockStats      domainBlockStats;
    virDrvDomainInterfaceStats  domainInterfaceStats;
    virDrvDomainBlockPeek	domainBlockPeek;
    virDrvDomainMemoryPeek      domainMemoryPeek;
    virDrvNodeGetCellsFreeMemory	nodeGetCellsFreeMemory;
    virDrvNodeGetFreeMemory		getFreeMemory;
    virDrvDomainEventRegister         domainEventRegister;
    virDrvDomainEventDeregister       domainEventDeregister;
    virDrvDomainMigratePrepare2	domainMigratePrepare2;
    virDrvDomainMigrateFinish2	domainMigrateFinish2;
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
        (*virDrvNetworkDumpXML)		(virNetworkPtr network,
                                         int flags);
typedef char *
        (*virDrvNetworkGetBridgeName)	(virNetworkPtr network);
typedef int
        (*virDrvNetworkGetAutostart)	(virNetworkPtr network,
                                         int *autostart);
typedef int
        (*virDrvNetworkSetAutostart)	(virNetworkPtr network,
                                         int autostart);


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
        virDrvNetworkDumpXML		networkDumpXML;
        virDrvNetworkGetBridgeName	networkGetBridgeName;
        virDrvNetworkGetAutostart	networkGetAutostart;
        virDrvNetworkSetAutostart	networkSetAutostart;
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
    (*virDrvStorageVolGetInfo)               (virStorageVolPtr vol,
                                              virStorageVolInfoPtr info);
typedef char *
    (*virDrvStorageVolGetXMLDesc)            (virStorageVolPtr pool,
                                              unsigned int flags);
typedef char *
    (*virDrvStorageVolGetPath)               (virStorageVolPtr vol);



typedef struct _virStorageDriver virStorageDriver;
typedef virStorageDriver *virStorageDriverPtr;

/**
 * _virStorageDriver:
 *
 * Structure associated to a network virtualization driver, defining the various
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
    virDrvStorageVolDelete volDelete;
    virDrvStorageVolGetInfo volGetInfo;
    virDrvStorageVolGetXMLDesc volGetXMLDesc;
    virDrvStorageVolGetPath volGetPath;
};

#ifdef WITH_LIBVIRTD
typedef int (*virDrvStateInitialize) (void);
typedef int (*virDrvStateCleanup) (void);
typedef int (*virDrvStateReload) (void);
typedef int (*virDrvStateActive) (void);

typedef struct _virStateDriver virStateDriver;
typedef virStateDriver *virStateDriverPtr;

struct _virStateDriver {
    virDrvStateInitialize  initialize;
    virDrvStateCleanup     cleanup;
    virDrvStateReload      reload;
    virDrvStateActive      active;
};
#endif


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

typedef char * (*virDevMonDeviceDumpXML)(virNodeDevicePtr dev,
                                         unsigned int flags);

typedef char * (*virDevMonDeviceGetParent)(virNodeDevicePtr dev);

typedef int (*virDevMonDeviceNumOfCaps)(virNodeDevicePtr dev);

typedef int (*virDevMonDeviceListCaps)(virNodeDevicePtr dev,
                                       char **const names,
                                       int maxnames);

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
    virDevMonDeviceDumpXML deviceDumpXML;
    virDevMonDeviceGetParent deviceGetParent;
    virDevMonDeviceNumOfCaps deviceNumOfCaps;
    virDevMonDeviceListCaps deviceListCaps;
};

/*
 * Registration
 * TODO: also need ways to (des)activate a given driver
 *       lookup based on the URI given in a virConnectOpen(ReadOnly)
 */
int virRegisterDriver(virDriverPtr);
int virRegisterNetworkDriver(virNetworkDriverPtr);
int virRegisterStorageDriver(virStorageDriverPtr);
int virRegisterDeviceMonitor(virDeviceMonitorPtr);
#ifdef WITH_LIBVIRTD
int virRegisterStateDriver(virStateDriverPtr);
#endif
void *virDriverLoadModule(const char *name);

#endif /* __VIR_DRIVER_H__ */
