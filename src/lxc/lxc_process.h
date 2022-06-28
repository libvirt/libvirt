/*
 * Copyright (C) 2010-2012, 2016 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_process.h: LXC process lifecycle management
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
 */

#pragma once

#include "lxc_conf.h"

int virLXCProcessStart(virLXCDriver * driver,
                       virDomainObj *vm,
                       unsigned int nfiles, int *files,
                       virConnectPtr autoDestroyConn,
                       virDomainRunningReason reason);
int virLXCProcessStop(virLXCDriver *driver,
                      virDomainObj *vm,
                      virDomainShutoffReason reason,
                      unsigned int cleanupFlags);

void virLXCProcessAutoDestroyRun(virLXCDriver *driver,
                                 virConnectPtr conn);
void virLXCProcessAutoDestroyShutdown(virLXCDriver *driver);
int virLXCProcessAutoDestroyAdd(virLXCDriver *driver,
                                virDomainObj *vm,
                                virConnectPtr conn);
int virLXCProcessAutoDestroyRemove(virLXCDriver *driver,
                                   virDomainObj *vm);

void virLXCProcessAutostartAll(virLXCDriver *driver);
int virLXCProcessReconnectAll(virLXCDriver *driver,
                              virDomainObjList *doms);

int virLXCProcessValidateInterface(virDomainNetDef *net);
char *virLXCProcessSetupInterfaceTap(virDomainDef *vm,
                                     virDomainNetDef *net,
                                     const char *brname);
char *virLXCProcessSetupInterfaceDirect(virLXCDriver *driver,
                                        virDomainDef *def,
                                        virDomainNetDef *net);
