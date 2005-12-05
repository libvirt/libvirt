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
