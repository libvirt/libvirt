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
xenConnectPtr		xenOpenConnect		(const char *name);
int			xenCloseConnect		(xenConnectPtr conn);
unsigned long		xenGetVersion		(xenConnectPtr conn);

/*
 * Domain creation and destruction
 */
xenDomainPtr		xenCreateLinuxDomain	(xenConnectPtr conn,
						 const char *kernel_path,
						 const char *initrd_path,
						 const char *cmdline,
						 unsigned long memory,
						 unsigned int flags);
xenDomainPtr		xenLookupDomain		(xenConnectPtr conn,
						 const char *name);
int			xenDestroyDomain	(xenDomainPtr domain);

/*
 * Domain suspend/resume
 */
int			xenSuspendDomain	(xenDomainPtr domain);
int			xenResumeDomain		(xenDomainPtr domain);

/*
 * Dynamic control of domains
 */
const char *		xenGetName		(xenDomainPtr domain);
unsigned long		xenGetMaxMemory		(xenDomainPtr domain);
int			xenSetMaxMemory		(xenDomainPtr domain,
						 unsigned long memory);

#ifdef __cplusplus
}
#endif

#endif /* __XEN_XENLIB_H__ */
