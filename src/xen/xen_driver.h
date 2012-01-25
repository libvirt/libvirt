/*
 * xen_unified.c: Unified Xen driver.
 *
 * Copyright (C) 2007, 2010-2011 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#ifndef __VIR_XEN_UNIFIED_H__
# define __VIR_XEN_UNIFIED_H__

# include "internal.h"
# include "capabilities.h"
# include "driver.h"
# include "domain_conf.h"
# include "xs_internal.h"
# if WITH_XEN_INOTIFY
#  include "xen_inotify.h"
# endif
# include "domain_event.h"
# include "virhash.h"

# ifndef HAVE_WINSOCK2_H
#  include <sys/un.h>
#  include <netinet/in.h>
# else
#  include <winsock2.h>
# endif

# include <xen/xen.h>

/* xen-unstable changeset 19788 removed MAX_VIRT_CPUS from public
 * headers.  Its semantic was retained with XEN_LEGACY_MAX_VCPUS.
 * Ensure MAX_VIRT_CPUS is defined accordingly.
 */
# if !defined(MAX_VIRT_CPUS) && defined(XEN_LEGACY_MAX_VCPUS)
#  define MAX_VIRT_CPUS XEN_LEGACY_MAX_VCPUS
# endif

extern int xenRegister (void);

# define XEN_UNIFIED_HYPERVISOR_OFFSET 0
# define XEN_UNIFIED_XEND_OFFSET 1
# define XEN_UNIFIED_XS_OFFSET 2
# define XEN_UNIFIED_XM_OFFSET 3

# if WITH_XEN_INOTIFY
#  define XEN_UNIFIED_INOTIFY_OFFSET 4
#  define XEN_UNIFIED_NR_DRIVERS 5
# else
#  define XEN_UNIFIED_NR_DRIVERS 4
# endif

# define MIN_XEN_GUEST_SIZE 64  /* 64 megabytes */

# define XEN_CONFIG_FORMAT_XM    "xen-xm"
# define XEN_CONFIG_FORMAT_SEXPR "xen-sxpr"

# define XEND_DOMAINS_DIR "/var/lib/xend/domains"

# define XEN_SCHED_SEDF_NPARAM   6
# define XEN_SCHED_CRED_NPARAM   2

/* The set of migration flags explicitly supported by xen.  */
# define XEN_MIGRATION_FLAGS                    \
    (VIR_MIGRATE_LIVE |                         \
     VIR_MIGRATE_UNDEFINE_SOURCE |              \
     VIR_MIGRATE_PAUSED |                       \
     VIR_MIGRATE_PERSIST_DEST)

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
    virDrvClose xenClose; /* Only mandatory callback; all others may be NULL */
    virDrvGetVersion  xenVersion;
    virDrvGetHostname xenGetHostname;
    virDrvDomainSuspend xenDomainSuspend;
    virDrvDomainResume xenDomainResume;
    virDrvDomainShutdown xenDomainShutdown;
    virDrvDomainReboot xenDomainReboot;
    virDrvDomainDestroyFlags xenDomainDestroyFlags;
    virDrvDomainGetOSType xenDomainGetOSType;
    virDrvDomainGetMaxMemory xenDomainGetMaxMemory;
    virDrvDomainSetMaxMemory xenDomainSetMaxMemory;
    virDrvDomainSetMemory xenDomainSetMemory;
    virDrvDomainGetInfo xenDomainGetInfo;
    virDrvDomainPinVcpu xenDomainPinVcpu;
    virDrvDomainGetVcpus xenDomainGetVcpus;
    virDrvListDefinedDomains xenListDefinedDomains;
    virDrvNumOfDefinedDomains xenNumOfDefinedDomains;
    virDrvDomainCreate xenDomainCreate;
    virDrvDomainDefineXML xenDomainDefineXML;
    virDrvDomainUndefine xenDomainUndefine;
    virDrvDomainAttachDeviceFlags xenDomainAttachDeviceFlags;
    virDrvDomainDetachDeviceFlags xenDomainDetachDeviceFlags;
    virDrvDomainGetSchedulerType xenDomainGetSchedulerType;
    virDrvDomainGetSchedulerParameters xenDomainGetSchedulerParameters;
    virDrvDomainSetSchedulerParameters xenDomainSetSchedulerParameters;
};

typedef struct xenXMConfCache *xenXMConfCachePtr;
typedef struct xenXMConfCache {
    time_t refreshedAt;
    char *filename;
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
    virMutex lock;

    /* These initial vars are initialized in Open method
     * and readonly thereafter, so can be used without
     * holding the lock
     */
    virCapsPtr caps;
    int handle;			/* Xen hypervisor handle */

    int xendConfigVersion;      /* XenD config version */

    /* connection to xend */
    struct sockaddr_storage addr;
    socklen_t addrlen;
    int addrfamily;
    int addrprotocol;

    /* Keep track of the drivers which opened.  We keep a yes/no flag
     * here for each driver, corresponding to the array drivers in
     * xen_unified.c.
     */
    int opened[XEN_UNIFIED_NR_DRIVERS];


    /*
     * Everything from this point onwards must be protected
     * by the lock when used
     */

    struct xs_handle *xshandle; /* handle to talk to the xenstore */


    /* A list of xenstore watches */
    xenStoreWatchListPtr xsWatchList;
    int xsWatch;
    /* A list of active domain name/uuids */
    xenUnifiedDomainInfoListPtr activeDomainList;

    /* NUMA topology info cache */
    int nbNodeCells;
    int nbNodeCpus;

    virDomainEventStatePtr domainEvents;

    /* Location of config files, either /etc
     * or /var/lib/xen */
    const char *configDir;

# if WITH_XEN_INOTIFY
    /* The inotify fd */
    int inotifyFD;
    int inotifyWatch;

    int  useXenConfigCache ;
    xenUnifiedDomainInfoListPtr configInfoList;
# endif

    /* For the 'xm' driver */
    /* Primary config file name -> virDomainDef map */
    virHashTablePtr configCache;
    /* Domain name to config file name */
    virHashTablePtr nameConfigMap;
    /* So we don't refresh too often */
    time_t lastRefresh;
};

typedef struct _xenUnifiedPrivate *xenUnifiedPrivatePtr;

char *xenDomainUsedCpus(virDomainPtr dom);

void xenUnifiedDomainInfoListFree(xenUnifiedDomainInfoListPtr info);
int  xenUnifiedAddDomainInfo(xenUnifiedDomainInfoListPtr info,
                             int id, char *name,
                             unsigned char *uuid);
int  xenUnifiedRemoveDomainInfo(xenUnifiedDomainInfoListPtr info,
                                int id, char *name,
                                unsigned char *uuid);
void xenUnifiedDomainEventDispatch (xenUnifiedPrivatePtr priv,
                                    virDomainEventPtr event);
unsigned long xenUnifiedVersion(void);
int xenUnifiedGetMaxVcpus(virConnectPtr conn, const char *type);

void xenUnifiedLock(xenUnifiedPrivatePtr priv);
void xenUnifiedUnlock(xenUnifiedPrivatePtr priv);

#endif /* __VIR_XEN_UNIFIED_H__ */
