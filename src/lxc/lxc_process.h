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

int virLXCProcessStart(virConnectPtr conn,
                       virLXCDriverPtr  driver,
                       virDomainObjPtr vm,
                       unsigned int nfiles, int *files,
                       bool autoDestroy,
                       virDomainRunningReason reason);
int virLXCProcessStop(virLXCDriverPtr driver,
                      virDomainObjPtr vm,
                      virDomainShutoffReason reason);

void virLXCProcessAutoDestroyRun(virLXCDriverPtr driver,
                                 virConnectPtr conn);
void virLXCProcessAutoDestroyShutdown(virLXCDriverPtr driver);
int virLXCProcessAutoDestroyAdd(virLXCDriverPtr driver,
                                virDomainObjPtr vm,
                                virConnectPtr conn);
int virLXCProcessAutoDestroyRemove(virLXCDriverPtr driver,
                                   virDomainObjPtr vm);

void virLXCProcessAutostartAll(virLXCDriverPtr driver);
int virLXCProcessReconnectAll(virLXCDriverPtr driver,
                              virDomainObjListPtr doms);

int virLXCProcessValidateInterface(virDomainNetDefPtr net);
char *virLXCProcessSetupInterfaceTap(virDomainDefPtr vm,
                                     virDomainNetDefPtr net,
                                     const char *brname);
char *virLXCProcessSetupInterfaceDirect(virConnectPtr conn,
                                        virDomainDefPtr def,
                                        virDomainNetDefPtr net);
