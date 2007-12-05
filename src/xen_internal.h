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

#ifdef __cplusplus
extern "C" {
#endif

extern struct xenUnifiedDriver xenHypervisorDriver;
int	xenHypervisorInit		(void);

/* The following calls are made directly by the Xen proxy: */

virDomainPtr
        xenHypervisorLookupDomainByID   (virConnectPtr conn,
					 int id);
virDomainPtr
xenHypervisorLookupDomainByUUID(virConnectPtr conn,
                                const unsigned char *uuid);
char *
        xenHypervisorDomainGetOSType (virDomainPtr dom);

int	xenHypervisorOpen		(virConnectPtr conn,
					 xmlURIPtr uri,
					 virConnectAuthPtr auth,
					 int flags);
int	xenHypervisorClose		(virConnectPtr conn);
int	xenHypervisorGetVersion		(virConnectPtr conn,
				 	 unsigned long *hvVer);
char *
        xenHypervisorMakeCapabilitiesXML (virConnectPtr conn,
					  const char *hostmachine,
					  FILE *cpuinfo,
					  FILE *capabilities);
char *
        xenHypervisorGetCapabilities    (virConnectPtr conn);
unsigned long
        xenHypervisorGetDomMaxMemory	(virConnectPtr conn,
					 int id);
int	xenHypervisorNumOfDomains	(virConnectPtr conn);
int	xenHypervisorListDomains	(virConnectPtr conn,
					 int *ids,
					 int maxids);
  int	xenHypervisorGetMaxVcpus	(virConnectPtr conn, const char *type);
int	xenHypervisorDestroyDomain	(virDomainPtr domain);
int	xenHypervisorResumeDomain	(virDomainPtr domain);
int	xenHypervisorPauseDomain	(virDomainPtr domain);
int	xenHypervisorGetDomainInfo	(virDomainPtr domain,
				   	 virDomainInfoPtr info);
int	xenHypervisorGetDomInfo		(virConnectPtr conn,
					 int id,
					 virDomainInfoPtr info);
int	xenHypervisorSetMaxMemory	(virDomainPtr domain,
		      		  	 unsigned long memory);
int	xenHypervisorCheckID		(virConnectPtr conn,
					 int id);
int	xenHypervisorSetVcpus		(virDomainPtr domain,
					 unsigned int nvcpus);
int	xenHypervisorPinVcpu		(virDomainPtr domain,
					 unsigned int vcpu,
					 unsigned char *cpumap,
					 int maplen);
int	xenHypervisorGetVcpus		(virDomainPtr domain,
					 virVcpuInfoPtr info,
					 int maxinfo,
					 unsigned char *cpumaps,
					 int maplen);
int	xenHypervisorGetVcpuMax		(virDomainPtr domain);

char *	xenHypervisorGetSchedulerType	(virDomainPtr domain,
					 int *nparams);

int	xenHypervisorGetSchedulerParameters		(virDomainPtr domain,
					 virSchedParameterPtr params,
					 int *nparams);

int	xenHypervisorSetSchedulerParameters		(virDomainPtr domain,
					 virSchedParameterPtr params,
					 int nparams);

int     xenHypervisorDomainBlockStats   (virDomainPtr domain,
					 const char *path,
					 struct _virDomainBlockStats *stats);
int     xenHypervisorDomainInterfaceStats (virDomainPtr domain,
					 const char *path,
					 struct _virDomainInterfaceStats *stats);

int	xenHypervisorNodeGetCellsFreeMemory(virConnectPtr conn,
					  unsigned long long *freeMems,
					  int startCell,
					  int maxCells);
#ifdef __cplusplus
}
#endif
#endif                          /* __VIR_XEN_INTERNAL_H__ */
