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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef __LXC_PROCESS_H__
# define __LXC_PROCESS_H__

# include "lxc_conf.h"

int lxcVmStart(virConnectPtr conn,
               lxc_driver_t * driver,
               virDomainObjPtr vm,
               bool autoDestroy,
               virDomainRunningReason reason);
int lxcVmTerminate(lxc_driver_t *driver,
                   virDomainObjPtr vm,
                   virDomainShutoffReason reason);
int lxcProcessAutoDestroyInit(lxc_driver_t *driver);
void lxcProcessAutoDestroyRun(lxc_driver_t *driver,
                              virConnectPtr conn);
void lxcProcessAutoDestroyShutdown(lxc_driver_t *driver);
int lxcProcessAutoDestroyAdd(lxc_driver_t *driver,
                             virDomainObjPtr vm,
                             virConnectPtr conn);
int lxcProcessAutoDestroyRemove(lxc_driver_t *driver,
                                virDomainObjPtr vm);

void lxcAutostartConfigs(lxc_driver_t *driver);
int lxcReconnectAll(lxc_driver_t *driver,
                    virDomainObjListPtr doms);

#endif /* __LXC_PROCESS_H__ */
