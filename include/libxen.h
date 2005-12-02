/*
 * libxen.h: interface for the libxen library to handle Xen domains
 *           from a process running in domain 0
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __XEN_XENLIB_H__
#define __XEN_XENLIB_H__

#ifdef __cplusplus
extern "C" {
#endif

/**
 * xenConnect:
 *
 * a xenConnect is a private structure representing a connection to
 * the Xen Hypervisor.
 */
typedef struct _xenConnect xenConnect;

/**
 * xenConnectPtr:
 *
 * a xenConnectPtr is pointer to a xenConnect private structure, this is the
 * type used to reference a connection to the Xen Hypervisor in the API.
 */
typedef xenConnect *xenConnectPtr;

/**
 * xenDomain:
 *
 * a xenDomain is a private structure representing a Xen domain.
 */
typedef struct _xenDomain xenDomain;

/**
 * xenDomainPtr:
 *
 * a xenDomainPtr is pointer to a xenDomain private structure, this is the
 * type used to reference a Xen domain in the API.
 */
typedef xenDomain *xenDomainPtr;

/**
 * xenDomainFlags:
 *
 * Flags OR'ed together to provide specific behaviour when creating a
 * Domain.
 */
typedef enum {
     XEN_DOMAIN_NONE = 0
} xenDomainFlags;

/*
 * Connection and disconnections to the Hypervisor
 */
xenConnectPtr		xenConnectOpen		(const char *name);
xenConnectPtr		xenConnectOpenReadOnly	(const char *name);
int			xenConnectClose		(xenConnectPtr conn);
unsigned long		xenConnectGetVersion	(xenConnectPtr conn);

/*
 * Gather list of running domains
 */
int			xenConnectListDomains	(xenConnectPtr conn,
						 int *ids,
						 int maxids);

/*
 * Domain creation and destruction
 */
xenDomainPtr		xenDomainCreateLinux	(xenConnectPtr conn,
						 const char *kernel_path,
						 const char *initrd_path,
						 const char *cmdline,
						 unsigned long memory,
						 unsigned int flags);
xenDomainPtr		xenDomainLookupByName	(xenConnectPtr conn,
						 const char *name);
xenDomainPtr		xenDomainLookupByID	(xenConnectPtr conn,
						 int id);
int			xenDomainDestroy	(xenDomainPtr domain);

/*
 * Domain suspend/resume
 */
int			xenDomainSuspend	(xenDomainPtr domain);
int			xenDomainResume		(xenDomainPtr domain);

/*
 * Dynamic control of domains
 */
const char *		xenDomainGetName	(xenDomainPtr domain);
unsigned int		xenDomainGetID		(xenDomainPtr domain);
unsigned long		xenDomainGetMaxMemory	(xenDomainPtr domain);
int			xenDomainSetMaxMemory	(xenDomainPtr domain,
						 unsigned long memory);

#ifdef __cplusplus
}
#endif

#endif /* __XEN_XENLIB_H__ */
