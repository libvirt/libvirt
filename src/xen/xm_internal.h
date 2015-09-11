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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 *
 */

#ifndef _LIBVIRT_XM_INTERNAL_H_
# define _LIBVIRT_XM_INTERNAL_H_

# include "internal.h"
# include "driver.h"
# include "virconf.h"
# include "domain_conf.h"

int xenXMConfigCacheRefresh (virConnectPtr conn);
int xenXMConfigCacheAddFile(virConnectPtr conn, const char *filename, time_t now);
int xenXMConfigCacheRemoveFile(virConnectPtr conn, const char *filename);

int xenXMOpen(virConnectPtr conn, virConnectAuthPtr auth, unsigned int flags);
int xenXMClose(virConnectPtr conn);
const char *xenXMGetType(virConnectPtr conn);
int xenXMDomainGetInfo(virConnectPtr conn,
                       virDomainDefPtr def,
                       virDomainInfoPtr info);
int xenXMDomainGetState(virConnectPtr conn,
                        virDomainDefPtr def,
                        int *state,
                        int *reason);
virDomainDefPtr xenXMDomainGetXMLDesc(virConnectPtr conn,
                                      virDomainDefPtr def);
int xenXMDomainSetMemory(virConnectPtr conn,
                         virDomainDefPtr def,
                         unsigned long memory);
int xenXMDomainSetMaxMemory(virConnectPtr conn,
                            virDomainDefPtr def,
                            unsigned long memory);
unsigned long long xenXMDomainGetMaxMemory(virConnectPtr conn,
                                           virDomainDefPtr def);
int xenXMDomainSetVcpus(virConnectPtr conn,
                        virDomainDefPtr def,
                        unsigned int vcpus);
int xenXMDomainSetVcpusFlags(virConnectPtr conn,
                             virDomainDefPtr def,
                             unsigned int vcpus,
                             unsigned int flags);
int xenXMDomainGetVcpusFlags(virConnectPtr conn,
                             virDomainDefPtr def,
                             unsigned int flags);
int xenXMDomainPinVcpu(virConnectPtr conn,
                       virDomainDefPtr def,
                       unsigned int vcpu,
                       unsigned char *cpumap,
                       int maplen);
virDomainDefPtr xenXMDomainLookupByName(virConnectPtr conn, const char *domname);
virDomainDefPtr xenXMDomainLookupByUUID(virConnectPtr conn, const unsigned char *uuid);

int xenXMListDefinedDomains(virConnectPtr conn, char ** const names, int maxnames);
int xenXMNumOfDefinedDomains(virConnectPtr conn);

int xenXMDomainCreate(virConnectPtr conn,
                      virDomainDefPtr def);
int xenXMDomainDefineXML(virConnectPtr con, virDomainDefPtr def);
int xenXMDomainUndefine(virConnectPtr conn, virDomainDefPtr def);

int xenXMDomainBlockPeek(virConnectPtr conn,
                         virDomainDefPtr def,
                         const char *path,
                         unsigned long long offset,
                         size_t size,
                         void *buffer);

int xenXMDomainGetAutostart(virDomainDefPtr def,
                            int *autostart);
int xenXMDomainSetAutostart(virDomainDefPtr def,
                            int autostart);

int xenXMDomainAttachDeviceFlags(virConnectPtr conn,
                                 virDomainDefPtr def,
                                 const char *xml,
                                 unsigned int flags);

int xenXMDomainDetachDeviceFlags(virConnectPtr conn,
                                 virDomainDefPtr def,
                                 const char *xml,
                                 unsigned int flags);

#endif
