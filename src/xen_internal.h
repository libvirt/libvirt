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

int	xenHypervisorOpen		(virConnectPtr conn,
					 const char *name,
					 int flags);
int	xenHypervisorClose		(virConnectPtr conn);
int	xenHypervisorGetVersion		(virConnectPtr conn,
				 	 unsigned long *hvVer);
int	xenHypervisorDestroyDomain	(virDomainPtr domain);
int	xenHypervisorResumeDomain	(virDomainPtr domain);
int	xenHypervisorPauseDomain	(virDomainPtr domain);
int	xenHypervisorGetDomainInfo	(virDomainPtr domain,
				   	 virDomainInfoPtr info);
int	xenHypervisorSetMaxMemory	(virDomainPtr domain,
		      		  	 unsigned long memory);

#ifdef __cplusplus
}
#endif
#endif                          /* __VIR_XEN_INTERNAL_H__ */
