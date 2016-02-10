/*
 * vz_sdk.h: core driver functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2014 Parallels, Inc.
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
 */

#include <Parallels.h>

#include "vz_utils.h"

int prlsdkInit(void);
void prlsdkDeinit(void);
int prlsdkConnect(vzConnPtr privconn);
void prlsdkDisconnect(vzConnPtr privconn);
int
prlsdkLoadDomains(vzConnPtr privconn);
int prlsdkUpdateDomain(vzConnPtr privconn, virDomainObjPtr dom);
int
prlsdkLoadDomain(vzConnPtr privconn,
                 virDomainObjPtr dom);
int prlsdkSubscribeToPCSEvents(vzConnPtr privconn);
void prlsdkUnsubscribeFromPCSEvents(vzConnPtr privconn);
PRL_RESULT prlsdkStart(PRL_HANDLE sdkdom);
PRL_RESULT prlsdkKill(PRL_HANDLE sdkdom);
PRL_RESULT prlsdkStop(PRL_HANDLE sdkdom);
PRL_RESULT prlsdkPause(PRL_HANDLE sdkdom);
PRL_RESULT prlsdkResume(PRL_HANDLE sdkdom);
PRL_RESULT prlsdkSuspend(PRL_HANDLE sdkdom);
PRL_RESULT prlsdkRestart(PRL_HANDLE sdkdom);

typedef PRL_RESULT (*prlsdkChangeStateFunc)(PRL_HANDLE sdkdom);
int
prlsdkDomainChangeState(virDomainPtr domain,
                        prlsdkChangeStateFunc chstate);
int
prlsdkDomainChangeStateLocked(vzConnPtr privconn,
                              virDomainObjPtr dom,
                              prlsdkChangeStateFunc chstate);
int
prlsdkApplyConfig(virConnectPtr conn,
                  virDomainObjPtr dom,
                  virDomainDefPtr new);
int prlsdkCreateVm(virConnectPtr conn, virDomainDefPtr def);
int prlsdkCreateCt(virConnectPtr conn, virDomainDefPtr def);
int
prlsdkUnregisterDomain(vzConnPtr privconn, virDomainObjPtr dom, unsigned int flags);
int
prlsdkDomainManagedSaveRemove(virDomainObjPtr dom);
int
prlsdkAttachVolume(virDomainObjPtr dom, virDomainDiskDefPtr disk);
int
prlsdkDetachVolume(virDomainObjPtr dom, virDomainDiskDefPtr disk);
int
prlsdkGetBlockStats(virDomainObjPtr dom, virDomainDiskDefPtr disk, virDomainBlockStatsPtr stats);
int
prlsdkAttachNet(virDomainObjPtr dom, vzConnPtr privconn, virDomainNetDefPtr net);
int
prlsdkDetachNet(virDomainObjPtr dom, vzConnPtr privconn, virDomainNetDefPtr net);
int
prlsdkGetNetStats(virDomainObjPtr dom, const char *path, virDomainInterfaceStatsPtr stats);
int
prlsdkGetVcpuStats(virDomainObjPtr dom, int idx, unsigned long long *time);
int
prlsdkGetMemoryStats(virDomainObjPtr dom, virDomainMemoryStatPtr stats, unsigned int nr_stats);
void
prlsdkDomObjFreePrivate(void *p);
