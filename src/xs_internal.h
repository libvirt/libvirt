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

#include "internal.h"

extern struct xenUnifiedDriver xenStoreDriver;
int xenStoreInit (void);

int		xenStoreOpen		(virConnectPtr conn,
					 const char *name,
					 int flags);
int		xenStoreClose		(virConnectPtr conn);
int		xenStoreGetDomainInfo	(virDomainPtr domain,
			   		 virDomainInfoPtr info);
int		xenStoreNumOfDomains	(virConnectPtr conn);
int     	xenStoreListDomains	(virConnectPtr conn,
					 int *ids,
					 int maxids);
virDomainPtr 	xenStoreLookupByName(virConnectPtr conn,
					 const char *name);
unsigned long 	xenStoreGetMaxMemory	(virDomainPtr domain);
int		xenStoreDomainSetMemory	(virDomainPtr domain,
		      	  	 	 unsigned long memory);
unsigned long 	xenStoreDomainGetMaxMemory(virDomainPtr domain);
int 		xenStoreDomainShutdown	(virDomainPtr domain);
int 		xenStoreDomainReboot	(virDomainPtr domain,
					 unsigned int flags);

/* those are entry point for the proxy */
int             xenStoreDomainGetVNCPort(virConnectPtr conn,
					 int domid);
char *          xenStoreDomainGetConsolePath(virConnectPtr conn,
					 int domid);
char *		xenStoreDomainGetOSTypeID(virConnectPtr conn,
					 int id);
char *		xenStoreDomainGetNetworkID(virConnectPtr conn,
					 int id,
					 const char *mac);
char *          xenStoreDomainGetName(virConnectPtr conn,
				      int id);

#ifdef __cplusplus
}
#endif
#endif /* __VIR_XS_INTERNAL_H__ */
