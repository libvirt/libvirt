/*
 * xen_hypervisor.h: internal API for direct access to Xen hypervisor level
 *
 * Copyright (C) 2005, 2010-2011 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_XEN_INTERNAL_H__
# define __VIR_XEN_INTERNAL_H__

# include "internal.h"
# include "capabilities.h"
# include "driver.h"
# include "viruri.h"
# include "domain_conf.h"

/* See xenHypervisorInit() for details. */
struct xenHypervisorVersions {
    int hv; /* u16 major,minor hypervisor version */
    int hypervisor; /* -1,0,1,2,3 */
    int sys_interface; /* -1,2,3,4,6,7,8 */
    int dom_interface; /* -1,3,4,5,6,7 */
};

int xenHypervisorInit(struct xenHypervisorVersions *override_versions);

virCapsPtr xenHypervisorMakeCapabilities (virConnectPtr conn);

int
        xenHypervisorHasDomain(virConnectPtr conn,
                               int id);
virDomainDefPtr
        xenHypervisorLookupDomainByID   (virConnectPtr conn, int id);
virDomainDefPtr
        xenHypervisorLookupDomainByUUID (virConnectPtr conn,
                                         const unsigned char *uuid);
char *
        xenHypervisorDomainGetOSType    (virConnectPtr conn,
                                         virDomainDefPtr def);

int
        xenHypervisorOpen               (virConnectPtr conn,
                                         virConnectAuthPtr auth,
                                         unsigned int flags);
int     xenHypervisorClose              (virConnectPtr conn);
int     xenHypervisorGetVersion         (virConnectPtr conn,
                                         unsigned long *hvVer);
virCapsPtr
        xenHypervisorMakeCapabilitiesInternal(virConnectPtr conn,
                                              virArch hostarch,
                                              FILE *cpuinfo,
                                              FILE *capabilities);
char * xenHypervisorGetCapabilities    (virConnectPtr conn);
unsigned long
        xenHypervisorGetMaxMemory(virConnectPtr conn,
                                  virDomainDefPtr def);
int     xenHypervisorGetMaxVcpus        (virConnectPtr conn,
                                         const char *type);
int     xenHypervisorGetDomainInfo        (virConnectPtr conn,
                                           virDomainDefPtr def,
                                           virDomainInfoPtr info)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorGetDomainState     (virConnectPtr conn,
                                         virDomainDefPtr def,
                                         int *state,
                                         int *reason)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorGetDomInfo         (virConnectPtr conn,
                                         int id,
                                         virDomainInfoPtr info);
int     xenHypervisorSetMaxMemory       (virConnectPtr conn,
                                         virDomainDefPtr def,
                                         unsigned long memory)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorCheckID            (virConnectPtr conn,
                                         int id);
int     xenHypervisorPinVcpu            (virConnectPtr conn,
                                         virDomainDefPtr def,
                                         unsigned int vcpu,
                                         unsigned char *cpumap,
                                         int maplen)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorGetVcpus           (virConnectPtr conn,
                                         virDomainDefPtr def,
                                         virVcpuInfoPtr info,
                                         int maxinfo,
                                         unsigned char *cpumaps,
                                         int maplen)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorGetVcpuMax         (virConnectPtr conn,
                                         virDomainDefPtr def)
          ATTRIBUTE_NONNULL (1);

char *  xenHypervisorGetSchedulerType   (virConnectPtr conn,
                                         int *nparams)
          ATTRIBUTE_NONNULL (1);

int     xenHypervisorGetSchedulerParameters(virConnectPtr conn,
                                            virDomainDefPtr def,
                                            virTypedParameterPtr params,
                                            int *nparams)
          ATTRIBUTE_NONNULL (1);

int     xenHypervisorSetSchedulerParameters(virConnectPtr conn,
                                            virDomainDefPtr def,
                                            virTypedParameterPtr params,
                                            int nparams)
          ATTRIBUTE_NONNULL (1);

int     xenHypervisorDomainBlockStats   (virConnectPtr conn,
                                         virDomainDefPtr def,
                                         const char *path,
                                         struct _virDomainBlockStats *stats)
          ATTRIBUTE_NONNULL (1);
int     xenHypervisorDomainInterfaceStats (virDomainDefPtr def,
                                           const char *path,
                                           struct _virDomainInterfaceStats *stats)
          ATTRIBUTE_NONNULL (1);

int     xenHypervisorNodeGetCellsFreeMemory(virConnectPtr conn,
                                          unsigned long long *freeMems,
                                          int startCell,
                                          int maxCells);

int	xenHavePrivilege(void);

#endif                          /* __VIR_XEN_INTERNAL_H__ */
