/*
 * xm_internal.h: helper routines for dealing with inactive domains
 *
 * Copyright (C) 2006
 *
 *      Daniel Berrange <berrange@redhat.com>
 *
 *  This file is subject to the terms and conditions of the GNU Lesser General
 *  Public License. See the file COPYING.LIB in the main directory of this
 *  archive for more details.
 */

#ifndef _LIBVIRT_XM_INTERNAL_H_
#define _LIBVIRT_XM_INTERNAL_H_

#include "libvirt/libvirt.h"

#ifdef __cplusplus
extern "C" {
#endif

void xenXMRegister(void);
int xenXMOpen(virConnectPtr conn, const char *name, int flags);
int xenXMClose(virConnectPtr conn);
const char *xenXMGetType(virConnectPtr conn);
int xenXMDomainGetInfo(virDomainPtr domain, virDomainInfoPtr info);
char *xenXMDomainDumpXML(virDomainPtr domain, int flags);
int xenXMDomainSetMemory(virDomainPtr domain, unsigned long memory);
int xenXMDomainSetMaxMemory(virDomainPtr domain, unsigned long memory);
unsigned long xenXMDomainGetMaxMemory(virDomainPtr domain);
int xenXMDomainSetVcpus(virDomainPtr domain, unsigned int vcpus);
virDomainPtr xenXMDomainLookupByName(virConnectPtr conn, const char *domname);
virDomainPtr xenXMDomainLookupByUUID(virConnectPtr conn,
				     const unsigned char *uuid);

int xenXMListDefinedDomains(virConnectPtr conn, const char **names, int maxnames);
int xenXMNumOfDefinedDomains(virConnectPtr conn);

int xenXMDomainCreate(virDomainPtr domain);
virDomainPtr xenXMDomainDefineXML(virConnectPtr con, const char *xml);
int xenXMDomainUndefine(virDomainPtr domain);


#ifdef __cplusplus
}
#endif
#endif
