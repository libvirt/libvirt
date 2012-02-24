/*
 * xen_internal.h: internal API for direct access to Xen hypervisor level
 *
 * Copyright (C) 2005, 2010-2011 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_XEN_INTERNAL_H__
# define __VIR_XEN_INTERNAL_H__

# include "internal.h"
# include "capabilities.h"
# include "driver.h"
# include "viruri.h"

/* See xenHypervisorInit() for details. */
struct xenHypervisorVersions {
    int hv; /* u16 major,minor hypervisor version */
    int hypervisor; /* -1,0,1,2,3 */
    int sys_interface; /* -1,2,3,4,6,7,8 */
    int dom_interface; /* -1,3,4,5,6,7 */
};

extern struct xenUnifiedDriver xenHypervisorDriver;
int xenHypervisorInit(struct xenHypervisorVersions *override_versions);

virCapsPtr xenHypervisorMakeCapabilities (virConnectPtr conn);

int
        xenHypervisorHasDomain(virConnectPtr conn,
                               int id);
virDomainPtr
        xenHypervisorLookupDomainByID   (virConnectPtr conn,
                                         int id);
virDomainPtr
        xenHypervisorLookupDomainByUUID (virConnectPtr conn,
                                         const unsigned char *uuid);
char *
        xenHypervisorDomainGetOSType    (virDomainPtr dom);

virDrvOpenStatus
        xenHypervisorOpen               (virConnectPtr conn,
                                         virConnectAuthPtr auth,
                                         unsigned int flags);
int     xenHypervisorClose              (virConnectPtr conn);
int     xenHypervisorGetVersion         (virConnectPtr conn,
                                         unsigned long *hvVer);
virCapsPtr
        xenHypervisorMakeCapabilitiesInternal(virConnectPtr conn,
                                              const char *hostmachine,
                                              FILE *cpuinfo,
                                              FILE *capabilities);
char *
        xenHypervisorGetCapabilities    (virConnectPtr conn);
unsigned long
        xenHypervisorGetDomMaxMemory    (virConnectPtr conn,
                                         int id);
int     xenHypervisorNumOfDomains       (virConnectPtr conn);
int     xenHypervisorListDomains        (virConnectPtr conn,
                                         int *ids,
                                         int maxids);
int     xenHypervisorGetMaxVcpus        (virConnectPtr conn,
                                         const char *type);
int     xenHypervisorDestroyDomain      (virDomainPtr domain)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorDestroyDomainFlags (virDomainPtr domain,
                                         unsigned int flags)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorResumeDomain       (virDomainPtr domain)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorPauseDomain        (virDomainPtr domain)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorGetDomainInfo        (virDomainPtr domain,
                                           virDomainInfoPtr info)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorGetDomainState     (virDomainPtr domain,
                                         int *state,
                                         int *reason,
                                         unsigned int flags)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorGetDomInfo         (virConnectPtr conn,
                                         int id,
                                         virDomainInfoPtr info);
int     xenHypervisorSetMaxMemory       (virDomainPtr domain,
                                         unsigned long memory)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorCheckID            (virConnectPtr conn,
                                         int id);
int     xenHypervisorSetVcpus           (virDomainPtr domain,
                                         unsigned int nvcpus)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorPinVcpu            (virDomainPtr domain,
                                         unsigned int vcpu,
                                         unsigned char *cpumap,
                                         int maplen)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorGetVcpus           (virDomainPtr domain,
                                         virVcpuInfoPtr info,
                                         int maxinfo,
                                         unsigned char *cpumaps,
                                         int maplen)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorGetVcpuMax         (virDomainPtr domain)
          ATTRIBUTE_NONNULL (1);

char *  xenHypervisorGetSchedulerType   (virDomainPtr domain,
                                         int *nparams)
          ATTRIBUTE_NONNULL (1);

int     xenHypervisorGetSchedulerParameters(virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int *nparams)
          ATTRIBUTE_NONNULL (1);

int     xenHypervisorSetSchedulerParameters(virDomainPtr domain,
                                         virTypedParameterPtr params,
                                         int nparams)
          ATTRIBUTE_NONNULL (1);

int     xenHypervisorDomainBlockStats   (virDomainPtr domain,
                                         const char *path,
                                         struct _virDomainBlockStats *stats)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorDomainInterfaceStats (virDomainPtr domain,
                                         const char *path,
                                         struct _virDomainInterfaceStats *stats)
          ATTRIBUTE_NONNULL (1);

int     xenHypervisorNodeGetCellsFreeMemory(virConnectPtr conn,
                                          unsigned long long *freeMems,
                                          int startCell,
                                          int maxCells);

int	xenHavePrivilege(void);

#endif                          /* __VIR_XEN_INTERNAL_H__ */
