/*
 * xm_internal.h: helper routines for dealing with inactive domains
 *
 * Copyright (C) 2006-2007, 2010-2012 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 *
 */

#ifndef _LIBVIRT_XM_INTERNAL_H_
# define _LIBVIRT_XM_INTERNAL_H_

# include "internal.h"
# include "driver.h"
# include "conf.h"
# include "domain_conf.h"

extern struct xenUnifiedDriver xenXMDriver;

int xenXMConfigCacheRefresh (virConnectPtr conn);
int xenXMConfigCacheAddFile(virConnectPtr conn, const char *filename);
int xenXMConfigCacheRemoveFile(virConnectPtr conn, const char *filename);

virDrvOpenStatus xenXMOpen(virConnectPtr conn, virConnectAuthPtr auth,
                           unsigned int flags);
int xenXMClose(virConnectPtr conn);
const char *xenXMGetType(virConnectPtr conn);
int xenXMDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info);
int xenXMDomainGetState(virDomainPtr domain,
                        int *state,
                        int *reason,
                        unsigned int flags);
char *xenXMDomainGetXMLDesc(virDomainPtr domain, unsigned int flags);
int xenXMDomainSetMemory(virDomainPtr domain, unsigned long memory);
int xenXMDomainSetMaxMemory(virDomainPtr domain, unsigned long memory);
unsigned long long xenXMDomainGetMaxMemory(virDomainPtr domain);
int xenXMDomainSetVcpus(virDomainPtr domain, unsigned int vcpus);
int xenXMDomainSetVcpusFlags(virDomainPtr domain, unsigned int vcpus,
                             unsigned int flags);
int xenXMDomainGetVcpusFlags(virDomainPtr domain, unsigned int flags);
int xenXMDomainPinVcpu(virDomainPtr domain, unsigned int vcpu,
                       unsigned char *cpumap, int maplen);
virDomainPtr xenXMDomainLookupByName(virConnectPtr conn, const char *domname);
virDomainPtr xenXMDomainLookupByUUID(virConnectPtr conn,
                                     const unsigned char *uuid);

int xenXMListDefinedDomains(virConnectPtr conn, char ** const names, int maxnames);
int xenXMNumOfDefinedDomains(virConnectPtr conn);

int xenXMDomainCreate(virDomainPtr domain);
virDomainPtr xenXMDomainDefineXML(virConnectPtr con, const char *xml);
int xenXMDomainUndefine(virDomainPtr domain);

int xenXMDomainBlockPeek (virDomainPtr dom, const char *path, unsigned long long offset, size_t size, void *buffer);

int xenXMDomainGetAutostart(virDomainPtr dom, int *autostart);
int xenXMDomainSetAutostart(virDomainPtr dom, int autostart);

#endif
