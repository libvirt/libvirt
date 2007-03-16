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

void qemudReportError(struct qemud_server *server,
                      int code, const char *fmt, ...)
    ATTRIBUTE_FORMAT(printf,3,4);

int qemudGetCPUInfo(unsigned int *cpus, unsigned int *mhz,
                    unsigned int *nodes, unsigned int *sockets,
                    unsigned int *cores, unsigned int *threads);
int qemudGetMemInfo(unsigned int *memory);
int qemudMonitorCommand(struct qemud_server *server,
                        struct qemud_vm *vm,
                        const char *cmd,
                        char **reply);

struct qemud_vm *qemudFindVMByID(const struct qemud_server *server,
                                 int id);
struct qemud_vm *qemudFindVMByUUID(const struct qemud_server *server,
                                   const unsigned char *uuid);
struct qemud_vm *qemudFindVMByName(const struct qemud_server *server,
                                   const char *name);

int qemudGetVersion(struct qemud_server *server);
int qemudListDomains(struct qemud_server *server,
                     int *ids,
                     int nids);
int qemudNumDomains(struct qemud_server *server);
struct qemud_vm *qemudDomainCreate(struct qemud_server *server,
                                   const char *xml);
int qemudDomainSuspend(struct qemud_server *server,
                       int id);
int qemudDomainResume(struct qemud_server *server,
                      int id);
int qemudDomainDestroy(struct qemud_server *server,
                       int id);
int qemudDomainGetInfo(struct qemud_server *server,
                       const unsigned char *uuid,
                       int *runstate,
                       unsigned long long *cputime,
                       unsigned long *maxmem,
                       unsigned long *memory,
                       unsigned int *nrVirtCpu);
int qemudDomainSave(struct qemud_server *server,
                    int id,
                    const char *path);
int qemudDomainRestore(struct qemud_server *server,
                       const char *path);
int qemudDomainDumpXML(struct qemud_server *server,
                       const unsigned char *uuid,
                       char *xml,
                       int xmllen);
int qemudListDefinedDomains(struct qemud_server *server,
                            char *const*names,
                            int nnames);
int qemudNumDefinedDomains(struct qemud_server *server);
struct qemud_vm *qemudDomainStart(struct qemud_server *server,
                                  const unsigned char *uuid);
struct qemud_vm *qemudDomainDefine(struct qemud_server *server,
                                   const char *xml);
int qemudDomainUndefine(struct qemud_server *server,
                        const unsigned char *uuid);
int qemudDomainGetAutostart(struct qemud_server *server,
                            const unsigned char *uuid,
                            int *autostart);
int qemudDomainSetAutostart(struct qemud_server *server,
                            const unsigned char *uuid,
                            int autostart);

struct qemud_network *qemudFindNetworkByUUID(const struct qemud_server *server,
                                             const unsigned char *uuid);
struct qemud_network *qemudFindNetworkByName(const struct qemud_server *server,
                                             const char *name);

int qemudNumNetworks(struct qemud_server *server);
int qemudListNetworks(struct qemud_server *server,
                      char *const*names,
                      int nnames);
int qemudNumDefinedNetworks(struct qemud_server *server);
int qemudListDefinedNetworks(struct qemud_server *server,
                             char *const*names,
                             int nnames);
struct qemud_network *qemudNetworkCreate(struct qemud_server *server,
                                         const char *xml);
struct qemud_network *qemudNetworkDefine(struct qemud_server *server,
                                         const char *xml);
struct qemud_network *qemudNetworkStart(struct qemud_server *server,
                                        const unsigned char *uuid);
int qemudNetworkUndefine(struct qemud_server *server,
                         const unsigned char *uuid);
int qemudNetworkDestroy(struct qemud_server *server,
                        const unsigned char *uuid);
int qemudNetworkDumpXML(struct qemud_server *server,
                        const unsigned char *uuid,
                        char *xml,
                        int xmllen);
int qemudNetworkGetBridgeName(struct qemud_server *server,
                              const unsigned char *uuid,
                              char *ifname,
                              int ifnamelen);
int qemudNetworkGetAutostart(struct qemud_server *server,
                             const unsigned char *uuid,
                             int *autostart);
int qemudNetworkSetAutostart(struct qemud_server *server,
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
