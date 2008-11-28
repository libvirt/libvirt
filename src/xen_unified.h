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
#include "capabilities.h"
#include "driver.h"
#include "domain_conf.h"
#include "xs_internal.h"
#if WITH_XEN_INOTIFY
#include "xen_inotify.h"
#endif
#include "domain_event.h"

#ifndef HAVE_WINSOCK2_H
#include <sys/un.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

extern int xenRegister (void);

#define XEN_UNIFIED_HYPERVISOR_OFFSET 0
#define XEN_UNIFIED_PROXY_OFFSET 1
#define XEN_UNIFIED_XEND_OFFSET 2
#define XEN_UNIFIED_XS_OFFSET 3
#define XEN_UNIFIED_XM_OFFSET 4

#if WITH_XEN_INOTIFY
#define XEN_UNIFIED_INOTIFY_OFFSET 5
#define XEN_UNIFIED_NR_DRIVERS 6
#else
#define XEN_UNIFIED_NR_DRIVERS 5
#endif

#define MIN_XEN_GUEST_SIZE 64  /* 64 megabytes */

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
        virDrvDomainCreateXML		domainCreateXML;
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

typedef struct xenXMConfCache *xenXMConfCachePtr;
typedef struct xenXMConfCache {
    time_t refreshedAt;
    char filename[PATH_MAX];
    virDomainDefPtr def;
} xenXMConfCache;

/* xenUnifiedDomainInfoPtr:
 * The minimal state we have about active domains
 * This is the minmal info necessary to still get a
 * virDomainPtr when the domain goes away
 */
struct _xenUnifiedDomainInfo {
    int  id;
    char *name;
    unsigned char uuid[VIR_UUID_BUFLEN];
};
typedef struct _xenUnifiedDomainInfo xenUnifiedDomainInfo;
typedef xenUnifiedDomainInfo *xenUnifiedDomainInfoPtr;

struct _xenUnifiedDomainInfoList {
    unsigned int count;
    xenUnifiedDomainInfoPtr *doms;
};
typedef struct _xenUnifiedDomainInfoList xenUnifiedDomainInfoList;
typedef xenUnifiedDomainInfoList *xenUnifiedDomainInfoListPtr;

/* xenUnifiedPrivatePtr:
 *
 * Per-connection private data, stored in conn->privateData.  All Xen
 * low-level drivers access parts of this structure.
 */
struct _xenUnifiedPrivate {
    virCapsPtr caps;
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

    int proxy;                  /* fd of proxy. */

    /* Keep track of the drivers which opened.  We keep a yes/no flag
     * here for each driver, corresponding to the array drivers in
     * xen_unified.c.
     */
    int opened[XEN_UNIFIED_NR_DRIVERS];

    /* A list of xenstore watches */
    xenStoreWatchListPtr xsWatchList;
    int xsWatch;

    /* An list of callbacks */
    virDomainEventCallbackListPtr domainEventCallbacks;

#if WITH_XEN_INOTIFY
    /* The inotify fd */
    int inotifyFD;
    int inotifyWatch;
#endif
};

typedef struct _xenUnifiedPrivate *xenUnifiedPrivatePtr;


int xenNbCells(virConnectPtr conn);
int xenNbCpus(virConnectPtr conn);
char *xenDomainUsedCpus(virDomainPtr dom);

void xenUnifiedDomainInfoListFree(xenUnifiedDomainInfoListPtr info);
int  xenUnifiedAddDomainInfo(xenUnifiedDomainInfoListPtr info,
                             int id, char *name,
                             unsigned char *uuid);
int  xenUnifiedRemoveDomainInfo(xenUnifiedDomainInfoListPtr info,
                                int id, char *name,
                                unsigned char *uuid);
void xenUnifiedDomainEventDispatch (xenUnifiedPrivatePtr priv,
                                    virDomainPtr dom,
                                    int event,
                                    int detail);
unsigned long xenUnifiedVersion(void);

#endif /* __VIR_XEN_UNIFIED_H__ */
