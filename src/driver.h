/*
 * driver.h: description of the set of interfaces provided by a 
 *           entry point to the virtualization engine
 */

#ifndef __VIR_DRIVER_H__
#define __VIR_DRIVER_H__

#include "libvirt.h"
#include "virterror.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VIR_DRV_OPEN_QUIET = 1,
    VIR_DRV_OPEN_RO = 2
} virDrvOpenFlag;

typedef int
	(*virDrvInit)			(void);
typedef int
	(*virDrvOpen)			(virConnectPtr conn,
					 const char *name,
					 int flags);
typedef int
	(*virDrvClose)			(virConnectPtr conn);
typedef const char *
	(*virDrvGetType)		(virConnectPtr conn);
typedef int
	(*virDrvGetVersion)		(virConnectPtr conn,
					 unsigned long *hvVer);
typedef int
	(*virDrvNodeGetInfo)		(virConnectPtr conn,
					 virNodeInfoPtr info);
typedef int
	(*virDrvListDomains)		(virConnectPtr conn,
					 int *ids,
					 int maxids);
typedef int
	(*virDrvNumOfDomains)		(virConnectPtr conn);
typedef virDomainPtr
	(*virDrvDomainCreateLinux)	(virConnectPtr conn,
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
typedef int
	(*virDrvDomainFree)		(virDomainPtr domain);
typedef const char *
	(*virDrvDomainGetName)		(virDomainPtr domain);
typedef int
	(*virDrvDomainGetID)		(virDomainPtr domain);
typedef int
	(*virDrvDomainGetUUID)		(virDomainPtr domain,
					 unsigned char *uuid);
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

typedef struct _virDriver virDriver;
typedef virDriver *virDriverPtr;

/**
 * _virDriver:
 *
 * Structure associated to a virtualization driver, defining the various
 * entry points for it.
 */
struct _virDriver {
	const char *name;
	unsigned long ver;
	virDrvInit			init;
	virDrvOpen			open;
	virDrvClose			close;
	virDrvGetType			type;
	virDrvGetVersion		version;
	virDrvNodeGetInfo		nodeGetInfo;
	virDrvListDomains		listDomains;
	virDrvNumOfDomains		numOfDomains;
	virDrvDomainCreateLinux		domainCreateLinux;
	virDrvDomainLookupByID		domainLookupByID;
	virDrvDomainLookupByUUID	domainLookupByUUID;
	virDrvDomainLookupByName	domainLookupByName;
	virDrvDomainSuspend		domainSuspend;
	virDrvDomainResume		domainResume;
	virDrvDomainShutdown		domainShutdown;
	virDrvDomainReboot		domainReboot;
	virDrvDomainDestroy		domainDestroy;
	virDrvDomainFree		domainFree;
	virDrvDomainGetName		domainGetName;
	virDrvDomainGetID		domainGetID;
	virDrvDomainGetUUID		domainGetUUID;
	virDrvDomainGetOSType		domainGetOSType;
	virDrvDomainGetMaxMemory	domainGetMaxMemory;
	virDrvDomainSetMaxMemory	domainSetMaxMemory;
	virDrvDomainSetMemory		domainSetMemory;
	virDrvDomainGetInfo		domainGetInfo;
	virDrvDomainSave		domainSave;
	virDrvDomainRestore		domainRestore;
};


/*
 * Registration
 * TODO: also need ways to (des)activate a given driver
 *       lookup based on the URI given in a virConnectOpen(ReadOnly)
 */
int virRegisterDriver(virDriverPtr);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* __VIR_DRIVER_H__ */
