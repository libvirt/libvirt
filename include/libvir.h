/*
 * libvir.h: interface for the libvir library to handle Xen domains
 *           from a process running in domain 0
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_VIRLIB_H__
#define __VIR_VIRLIB_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * virConnect:
 *
 * a virConnect is a private structure representing a connection to
 * the Xen Hypervisor.
 */
typedef struct _virConnect virConnect;

/**
 * virConnectPtr:
 *
 * a virConnectPtr is pointer to a virConnect private structure, this is the
 * type used to reference a connection to the Xen Hypervisor in the API.
 */
typedef virConnect *virConnectPtr;

/**
 * virDomain:
 *
 * a virDomain is a private structure representing a Xen domain.
 */
typedef struct _virDomain virDomain;

/**
 * virDomainPtr:
 *
 * a virDomainPtr is pointer to a virDomain private structure, this is the
 * type used to reference a Xen domain in the API.
 */
typedef virDomain *virDomainPtr;

/**
 * virDomainState:
 *
 * A domain may be in different states at a given point in time
 */
typedef enum {
     VIR_DOMAIN_NOSTATE	= 0, /* no state */
     VIR_DOMAIN_RUNNING	= 1, /* the domain is running */
     VIR_DOMAIN_BLOCKED	= 2, /* the domain is blocked on resource */
     VIR_DOMAIN_PAUSED	= 3, /* the domain is paused by user */
     VIR_DOMAIN_SHUTDOWN= 4, /* the domain is being shut down */
     VIR_DOMAIN_SHUTOFF	= 5  /* the domain is shut off */
} virDomainState;

/**
 * virDomainInfoPtr:
 *
 * a virDomainInfo is a structure filled by virDomainGetInfo()
 */

typedef struct _virDomainInfo virDomainInfo;

struct _virDomainInfo {
    unsigned char state;	/* the running state, one of virDomainFlags */
    unsigned long maxMem;	/* the maximum memory in KBytes allowed */
    unsigned long memory;	/* the memory in KBytes used by the domain */
    unsigned short nrVirtCpu;	/* the number of virtual CPUs for the domain */

    /*
     * Informations below are only available to clients with a connection
     * with full access to the hypervisor
     */
    unsigned long long cpuTime;	/* the CPU time used in nanoseconds */
    
    /*
     * TODO:
     * - check what can be extracted publicly from xenstore
     *   and what's private limited to the hypervisor call.
     * - add padding to this structure for ABI long term protection
     */
};

/**
 * virDomainInfoPtr:
 *
 * a virDomainInfoPtr is a pointer to a virDomainInfo structure.
 */

typedef virDomainInfo *virDomainInfoPtr;

/**
 * virDomainFlags:
 *
 * Flags OR'ed together to provide specific behaviour when creating a
 * Domain.
 */
typedef enum {
     VIR_DOMAIN_NONE = 0
} virDomainFlags;

/*
 * Connection and disconnections to the Hypervisor
 */
virConnectPtr		virConnectOpen		(const char *name);
virConnectPtr		virConnectOpenReadOnly	(const char *name);
int			virConnectClose		(virConnectPtr conn);
unsigned long		virConnectGetVersion	(virConnectPtr conn);

/*
 * Gather list of running domains
 */
int			virConnectListDomains	(virConnectPtr conn,
						 int *ids,
						 int maxids);

/*
 * Domain creation and destruction
 */
virDomainPtr		virDomainCreateLinux	(virConnectPtr conn,
						 const char *kernel_path,
						 const char *initrd_path,
						 const char *cmdline,
						 unsigned long memory,
						 unsigned int flags);
virDomainPtr		virDomainLookupByName	(virConnectPtr conn,
						 const char *name);
virDomainPtr		virDomainLookupByID	(virConnectPtr conn,
						 int id);
int			virDomainDestroy	(virDomainPtr domain);

/*
 * Domain suspend/resume
 */
int			virDomainSuspend	(virDomainPtr domain);
int			virDomainResume		(virDomainPtr domain);

/*
 * Domain runtime informations
 */
int			virDomainGetInfo	(virDomainPtr domain,
						 virDomainInfoPtr info);
						 
/*
 * Dynamic control of domains
 */
const char *		virDomainGetName	(virDomainPtr domain);
unsigned int		virDomainGetID		(virDomainPtr domain);
unsigned long		virDomainGetMaxMemory	(virDomainPtr domain);
int			virDomainSetMaxMemory	(virDomainPtr domain,
						 unsigned long memory);

#ifdef __cplusplus
}
#endif

#endif /* __VIR_VIRLIB_H__ */
