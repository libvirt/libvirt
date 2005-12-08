/*
 * xen_internal.h: internal API for direct access to Xen hypervisor level
 *
 * Copyright (C) 2005 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_XEN_INTERNAL_H__
#define __VIR_XEN_INTERNAL_H__

/* required for uint8_t, uint32_t, etc ... */
#include <stdint.h>
/* required for dom0_getdomaininfo_t */
#include <xen/dom0_ops.h>

#ifdef __cplusplus
extern "C" {
#endif

int		xenHypervisorOpen		(void);
int		xenHypervisorClose		(int handle);
unsigned long	xenHypervisorGetVersion		(int handle);
int		xenHypervisorDestroyDomain	(int handle,
						 int domain);
int		xenHypervisorResumeDomain	(int handle,
						 int domain);
int		xenHypervisorPauseDomain	(int handle,
						 int domain);
int		xenHypervisorGetDomainInfo	(int handle,
						 int domain,
						 dom0_getdomaininfo_t *info);

#ifdef __cplusplus
}
#endif
#endif /* __VIR_XEN_INTERNAL_H__ */
