/*
 * driver.h: core driver methods for managing qemu guests
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
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
 */


#ifndef QEMUD_DRIVER_H
#define QEMUD_DRIVER_H

#include "internal.h"
#include "../src/internal.h"

int qemudStartup(void);
int qemudReload(void);
int qemudShutdown(void);
int qemudActive(void);


virDrvOpenStatus qemudOpen(virConnectPtr conn,
                           const char *name,
                           int flags);

int qemudGetNodeInfo(virConnectPtr conn,
                     virNodeInfoPtr info);

char *qemudGetCapabilities(virConnectPtr conn);

virDomainPtr qemudDomainLookupByID(virConnectPtr conn,
                                   int id);
virDomainPtr qemudDomainLookupByUUID(virConnectPtr conn,
                                     const unsigned char *uuid);
virDomainPtr qemudDomainLookupByName(virConnectPtr conn,
                                     const char *name);

int qemudGetVersion(virConnectPtr conn, unsigned long *version);
int qemudListDomains(virConnectPtr conn,
                     int *ids,
                     int nids);
int qemudNumDomains(virConnectPtr conn);
virDomainPtr qemudDomainCreate(virConnectPtr conn,
                               const char *xml,
                               unsigned int flags);
int qemudDomainSuspend(virDomainPtr dom);
int qemudDomainResume(virDomainPtr dom);
int qemudDomainDestroy(virDomainPtr dom);
int qemudDomainGetInfo(virDomainPtr dom,
                       virDomainInfoPtr info);
int qemudDomainSave(virDomainPtr dom,
                    const char *path);
int qemudDomainRestore(virConnectPtr conn,
                       const char *path);
char *qemudDomainDumpXML(virDomainPtr dom,
                         int flags);
int qemudListDefinedDomains(virConnectPtr conn,
                            char **const names,
                            int nnames);
int qemudNumDefinedDomains(virConnectPtr conn);
int qemudDomainStart(virDomainPtr dom);
virDomainPtr qemudDomainDefine(virConnectPtr conn,
                               const char *xml);
int qemudDomainUndefine(virDomainPtr dom);
int qemudDomainGetAutostart(virDomainPtr dom,
                            int *autostart);
int qemudDomainSetAutostart(virDomainPtr dom,
                              int autostart);


virNetworkPtr qemudNetworkLookupByUUID(virConnectPtr conn,
                                       const unsigned char *uuid);
virNetworkPtr qemudNetworkLookupByName(virConnectPtr conn,
                                       const char *name);

int qemudNumNetworks(virConnectPtr conn);
int qemudListNetworks(virConnectPtr conn,
                      char **const names,
                      int nnames);
int qemudNumDefinedNetworks(virConnectPtr conn);
int qemudListDefinedNetworks(virConnectPtr conn,
                             char **const names,
                             int nnames);
virNetworkPtr qemudNetworkCreate(virConnectPtr conn,
                                 const char *xml);
virNetworkPtr qemudNetworkDefine(virConnectPtr conn,
                                 const char *xml);
int qemudNetworkStart(virNetworkPtr net);
int qemudNetworkUndefine(virNetworkPtr net);
int qemudNetworkDestroy(virNetworkPtr net);
char *qemudNetworkDumpXML(virNetworkPtr net,
                          int flags);
char *qemudNetworkGetBridgeName(virNetworkPtr net);
int qemudNetworkGetAutostart(virNetworkPtr net,
                             int *autostart);
int qemudNetworkSetAutostart(virNetworkPtr net,
                             int autostart);

#endif


/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
