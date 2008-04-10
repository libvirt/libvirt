/*
 * xen_unified.c: Unified Xen driver.
 *
 * Copyright (C) 2007 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#ifndef __VIR_XEN_UNIFIED_H__
#define __VIR_XEN_UNIFIED_H__

#include "internal.h"

#ifndef HAVE_WINSOCK2_H
#include <sys/un.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern int xenUnifiedRegister (void);

#define XEN_UNIFIED_HYPERVISOR_OFFSET 0
#define XEN_UNIFIED_PROXY_OFFSET 1
#define XEN_UNIFIED_XEND_OFFSET 2
#define XEN_UNIFIED_XS_OFFSET 3
#define XEN_UNIFIED_XM_OFFSET 4
#define XEN_UNIFIED_NR_DRIVERS 5

/* _xenUnifiedDriver:
 *
 * Entry points into the underlying Xen drivers.  This structure
 * will eventually go away and instead xen unified will make direct
 * calls to the underlying Xen drivers.
 *
 * To reiterate - the goal is to remove elements from this structure
 * until it is empty, replacing indirect calls through this
 * structure with direct calls in xen_unified.c.
 */
struct xenUnifiedDriver {
        virDrvOpen			open;
        virDrvClose			close;
        virDrvGetVersion		version;
    virDrvGetHostname       getHostname;
    virDrvGetURI            getURI;
        virDrvNodeGetInfo		nodeGetInfo;
        virDrvGetCapabilities		getCapabilities;
        virDrvListDomains		listDomains;
        virDrvNumOfDomains		numOfDomains;
        virDrvDomainCreateLinux		domainCreateLinux;
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
};

/* xenUnifiedPrivatePtr:
 *
 * Per-connection private data, stored in conn->privateData.  All Xen
 * low-level drivers access parts of this structure.
 */
struct _xenUnifiedPrivate {
#ifdef WITH_XEN
    int handle;			/* Xen hypervisor handle */

    int xendConfigVersion;      /* XenD config version */

    /* XXX This code is not IPv6 aware. */
    /* connection to xend */
    int type;                   /* PF_UNIX or PF_INET */
    int len;                    /* length of addr */
    struct sockaddr *addr;      /* type of address used */
    struct sockaddr_un addr_un; /* the unix address */
    struct sockaddr_in addr_in; /* the inet address */

    struct xs_handle *xshandle; /* handle to talk to the xenstore */
#endif /* WITH_XEN */

    int proxy;                  /* fd of proxy. */

    /* Keep track of the drivers which opened.  We keep a yes/no flag
     * here for each driver, corresponding to the array drivers in
     * xen_unified.c.
     */
    int opened[XEN_UNIFIED_NR_DRIVERS];
};

typedef struct _xenUnifiedPrivate *xenUnifiedPrivatePtr;


int xenNbCells(virConnectPtr conn);
int xenNbCpus(virConnectPtr conn);
char *xenDomainUsedCpus(virDomainPtr dom);
#ifdef __cplusplus
}
#endif

#endif /* __VIR_XEN_UNIFIED_H__ */
