
/*
 * esx_vi_methods.h: client for the VMware VI API 2.5 to manage ESX hosts
 *
 * Copyright (C) 2009 Matthias Bolte <matthias.bolte@googlemail.com>
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
 */

#ifndef __ESX_VI_METHODS_H__
#define __ESX_VI_METHODS_H__

#include "esx_vi.h"
#include "esx_vi_types.h"



/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * VI Methods
 */

int esxVI_RetrieveServiceContent(virConnectPtr conn, esxVI_Context *ctx,
                                 esxVI_ServiceContent **serviceContent);

int esxVI_Login(virConnectPtr conn, esxVI_Context *ctx,
                const char *userName, const char *password,
                esxVI_UserSession **userSession);

int esxVI_Logout(virConnectPtr conn, esxVI_Context *ctx);

int esxVI_SessionIsActive(virConnectPtr conn, esxVI_Context *ctx,
                          const char *sessionID, const char *userName,
                          esxVI_Boolean *active);

int esxVI_RetrieveProperties(virConnectPtr conn, esxVI_Context *ctx,
                             esxVI_PropertyFilterSpec *propertyFilterSpecList,
                             esxVI_ObjectContent **objectContentList);

int esxVI_PowerOnVM_Task(virConnectPtr conn, esxVI_Context *ctx,
                         esxVI_ManagedObjectReference *virtualMachine,
                         esxVI_ManagedObjectReference **task);

int esxVI_PowerOffVM_Task(virConnectPtr conn, esxVI_Context *ctx,
                          esxVI_ManagedObjectReference *virtualMachine,
                          esxVI_ManagedObjectReference **task);

int esxVI_SuspendVM_Task(virConnectPtr conn, esxVI_Context *ctx,
                         esxVI_ManagedObjectReference *virtualMachine,
                         esxVI_ManagedObjectReference **task);

int esxVI_MigrateVM_Task(virConnectPtr conn, esxVI_Context *ctx,
                         esxVI_ManagedObjectReference *virtualMachine,
                         esxVI_ManagedObjectReference *resourcePool,
                         esxVI_ManagedObjectReference *hostSystem,
                         esxVI_ManagedObjectReference **task);

int esxVI_ReconfigVM_Task(virConnectPtr conn, esxVI_Context *ctx,
                          esxVI_ManagedObjectReference *virtualMachine,
                          esxVI_VirtualMachineConfigSpec *spec,
                          esxVI_ManagedObjectReference **task);

int esxVI_CreateFilter(virConnectPtr conn, esxVI_Context *ctx,
                       esxVI_PropertyFilterSpec *propertyFilterSpec,
                       esxVI_Boolean partialUpdates,
                       esxVI_ManagedObjectReference **propertyFilter);

int esxVI_DestroyPropertyFilter(virConnectPtr conn, esxVI_Context *ctx,
                                esxVI_ManagedObjectReference *propertyFilter);

int esxVI_WaitForUpdates(virConnectPtr conn, esxVI_Context *ctx,
                         const char *version, esxVI_UpdateSet **updateSet);

int esxVI_RebootGuest(virConnectPtr conn, esxVI_Context *ctx,
                      esxVI_ManagedObjectReference *virtualMachine);

int esxVI_ShutdownGuest(virConnectPtr conn, esxVI_Context *ctx,
                        esxVI_ManagedObjectReference *virtualMachine);

int esxVI_ValidateMigration(virConnectPtr conn, esxVI_Context *ctx,
                            esxVI_ManagedObjectReference *virtualMachineList,
                            esxVI_VirtualMachinePowerState powerState,
                            esxVI_String *testTypeList, // FIXME: see ValidateMigrationTestType
                            esxVI_ManagedObjectReference *resourcePool,
                            esxVI_ManagedObjectReference *hostSystem,
                            esxVI_Event **eventList);

int esxVI_FindByIp(virConnectPtr conn, esxVI_Context *ctx,
                   esxVI_ManagedObjectReference *datacenter,
                   const char *ip, esxVI_Boolean vmSearch,
                   esxVI_ManagedObjectReference **managedObjectReference);

int esxVI_FindByUuid(virConnectPtr conn, esxVI_Context *ctx,
                     esxVI_ManagedObjectReference *datacenter,
                     const unsigned char *uuid, esxVI_Boolean vmSearch,
                     esxVI_ManagedObjectReference **managedObjectReference);

int esxVI_QueryAvailablePerfMetric(virConnectPtr conn, esxVI_Context *ctx,
                                   esxVI_ManagedObjectReference *entity,
                                   esxVI_DateTime *beginTime,
                                   esxVI_DateTime *endTime,
                                   esxVI_Int *intervalId,
                                   esxVI_PerfMetricId **perfMetricIdList);

int esxVI_QueryPerfCounter(virConnectPtr conn, esxVI_Context *ctx,
                           esxVI_Int *counterIdList,
                           esxVI_PerfCounterInfo **perfCounterInfoList);

int esxVI_QueryPerf(virConnectPtr conn, esxVI_Context *ctx,
                    esxVI_PerfQuerySpec *querySpecList,
                    esxVI_PerfEntityMetric **perfEntityMetricList);

#endif /* __ESX_VI_METHODS_H__ */
