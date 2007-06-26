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
#include "conf.h"

int qemudStartVMDaemon(struct qemud_driver *driver,
                       struct qemud_vm *vm);

int qemudShutdownVMDaemon(struct qemud_driver *driver,
                          struct qemud_vm *vm);

int qemudStartNetworkDaemon(struct qemud_driver *driver,
                            struct qemud_network *network);

int qemudShutdownNetworkDaemon(struct qemud_driver *driver,
                               struct qemud_network *network);

int qemudStartup(void);
void qemudReload(void);
void qemudShutdown(void);

int qemudGetNodeInfo(unsigned int *memory,
                     char *cpuModel, int cpuModelLength,
                     unsigned int *cpus, unsigned int *mhz,
                     unsigned int *nodes, unsigned int *sockets,
                     unsigned int *cores, unsigned int *threads);

char *qemudGetCapabilities(struct qemud_driver *driver);
int qemudMonitorCommand(struct qemud_driver *driver,
                        struct qemud_vm *vm,
                        const char *cmd,
                        char **reply);

int qemudGetVersion(struct qemud_driver *driver);
int qemudListDomains(struct qemud_driver *driver,
                     int *ids,
                     int nids);
int qemudNumDomains(struct qemud_driver *driver);
struct qemud_vm *qemudDomainCreate(struct qemud_driver *driver,
                                   const char *xml);
int qemudDomainSuspend(struct qemud_driver *driver,
                       int id);
int qemudDomainResume(struct qemud_driver *driver,
                      int id);
int qemudDomainDestroy(struct qemud_driver *driver,
                       int id);
int qemudDomainGetInfo(struct qemud_driver *driver,
                       const unsigned char *uuid,
                       int *runstate,
                       unsigned long long *cputime,
                       unsigned long *maxmem,
                       unsigned long *memory,
                       unsigned int *nrVirtCpu);
int qemudDomainSave(struct qemud_driver *driver,
                    int id,
                    const char *path);
int qemudDomainRestore(struct qemud_driver *driver,
                       const char *path);
int qemudDomainDumpXML(struct qemud_driver *driver,
                       const unsigned char *uuid,
                       char *xml,
                       int xmllen);
int qemudListDefinedDomains(struct qemud_driver *driver,
                            char *const*names,
                            int nnames);
int qemudNumDefinedDomains(struct qemud_driver *driver);
struct qemud_vm *qemudDomainStart(struct qemud_driver *driver,
                                  const unsigned char *uuid);
struct qemud_vm *qemudDomainDefine(struct qemud_driver *driver,
                                   const char *xml);
int qemudDomainUndefine(struct qemud_driver *driver,
                        const unsigned char *uuid);
int qemudDomainGetAutostart(struct qemud_driver *driver,
                            const unsigned char *uuid,
                            int *autostart);
int qemudDomainSetAutostart(struct qemud_driver *driver,
                            const unsigned char *uuid,
                            int autostart);


int qemudNumNetworks(struct qemud_driver *driver);
int qemudListNetworks(struct qemud_driver *driver,
                      char *const*names,
                      int nnames);
int qemudNumDefinedNetworks(struct qemud_driver *driver);
int qemudListDefinedNetworks(struct qemud_driver *driver,
                             char *const*names,
                             int nnames);
struct qemud_network *qemudNetworkCreate(struct qemud_driver *driver,
                                         const char *xml);
struct qemud_network *qemudNetworkDefine(struct qemud_driver *driver,
                                         const char *xml);
struct qemud_network *qemudNetworkStart(struct qemud_driver *driver,
                                        const unsigned char *uuid);
int qemudNetworkUndefine(struct qemud_driver *driver,
                         const unsigned char *uuid);
int qemudNetworkDestroy(struct qemud_driver *driver,
                        const unsigned char *uuid);
int qemudNetworkDumpXML(struct qemud_driver *driver,
                        const unsigned char *uuid,
                        char *xml,
                        int xmllen);
int qemudNetworkGetBridgeName(struct qemud_driver *driver,
                              const unsigned char *uuid,
                              char *ifname,
                              int ifnamelen);
int qemudNetworkGetAutostart(struct qemud_driver *driver,
                             const unsigned char *uuid,
                             int *autostart);
int qemudNetworkSetAutostart(struct qemud_driver *driver,
                             const unsigned char *uuid,
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
