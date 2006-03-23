/*
 * xs_internal.h: internal API for access to XenStore
 *
 * Copyright (C) 2006 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_XS_INTERNAL_H__
#define __VIR_XS_INTERNAL_H__

#ifdef __cplusplus
extern "C" {
#endif

int	xenStoreOpen		(virConnectPtr conn,
				 const char *name,
				 int flags);
int	xenStoreClose		(virConnectPtr conn);
int	xenStoreGetDomainInfo	(virDomainPtr domain,
			   	 virDomainInfoPtr info);
int	xenStoreNumOfDomains	(virConnectPtr conn);
int     xenStoreListDomains	(virConnectPtr conn,
				 int *ids,
				 int maxids);
virDomainPtr xenStoreDomainLookupByName(virConnectPtr conn, const char *name);
unsigned long xenStoreGetMaxMemory(virDomainPtr domain);
int	xenStoreDomainSetMaxMemory	(virDomainPtr domain,
		      	  	 unsigned long memory);
unsigned long xenStoreDomainGetMaxMemory(virDomainPtr domain);
int xenStoreDomainShutdown(virDomainPtr domain);
#ifdef __cplusplus
}
#endif
#endif /* __VIR_XS_INTERNAL_H__ */
