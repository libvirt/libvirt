/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef __LXC_PROCESS_H__
# define __LXC_PROCESS_H__

# include "lxc_conf.h"

int virLXCProcessStart(virConnectPtr conn,
                       lxc_driver_t * driver,
                       virDomainObjPtr vm,
                       bool autoDestroy,
                       virDomainRunningReason reason);
int virLXCProcessStop(lxc_driver_t *driver,
                      virDomainObjPtr vm,
                      virDomainShutoffReason reason);

int virLXCProcessAutoDestroyInit(lxc_driver_t *driver);
void virLXCProcessAutoDestroyRun(lxc_driver_t *driver,
                                 virConnectPtr conn);
void virLXCProcessAutoDestroyShutdown(lxc_driver_t *driver);
int virLXCProcessAutoDestroyAdd(lxc_driver_t *driver,
                                virDomainObjPtr vm,
                                virConnectPtr conn);
int virLXCProcessAutoDestroyRemove(lxc_driver_t *driver,
                                   virDomainObjPtr vm);

void virLXCProcessAutostartAll(lxc_driver_t *driver);
int virLXCProcessReconnectAll(lxc_driver_t *driver,
                              virDomainObjListPtr doms);

#endif /* __LXC_PROCESS_H__ */
