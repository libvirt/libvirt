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
int prlsdkConnect(vzDriverPtr driver);
void prlsdkDisconnect(vzDriverPtr driver);
int
prlsdkLoadDomains(vzDriverPtr driver);
int prlsdkUpdateDomain(vzDriverPtr driver, virDomainObjPtr dom);
int
prlsdkLoadDomain(vzDriverPtr driver,
                 virDomainObjPtr dom);
int prlsdkSubscribeToPCSEvents(vzDriverPtr driver);
void prlsdkUnsubscribeFromPCSEvents(vzDriverPtr driver);
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
prlsdkDomainChangeStateLocked(vzDriverPtr driver,
                              virDomainObjPtr dom,
                              prlsdkChangeStateFunc chstate);
int
prlsdkApplyConfig(vzDriverPtr driver,
                  virDomainObjPtr dom,
                  virDomainDefPtr new);
int prlsdkCreateVm(vzDriverPtr driver, virDomainDefPtr def);
int prlsdkCreateCt(vzDriverPtr driver, virDomainDefPtr def);
int
prlsdkUnregisterDomain(vzDriverPtr driver, virDomainObjPtr dom, unsigned int flags);
int
prlsdkDomainManagedSaveRemove(virDomainObjPtr dom);
int
prlsdkAttachDevice(vzDriverPtr driver, virDomainObjPtr dom, virDomainDeviceDefPtr dev);
int
prlsdkDetachDevice(vzDriverPtr driver, virDomainObjPtr dom, virDomainDeviceDefPtr dev);
int
prlsdkUpdateDevice(vzDriverPtr driver, virDomainObjPtr dom, virDomainDeviceDefPtr dev);
int
prlsdkGetBlockStats(PRL_HANDLE sdkstats, virDomainDiskDefPtr disk, virDomainBlockStatsPtr stats);
int
prlsdkGetNetStats(PRL_HANDLE sdkstas, PRL_HANDLE sdkdom, const char *path, virDomainInterfaceStatsPtr stats);
int
prlsdkGetVcpuStats(PRL_HANDLE sdkstas, int idx, unsigned long long *time);
int
prlsdkGetMemoryStats(PRL_HANDLE sdkstas, virDomainMemoryStatPtr stats, unsigned int nr_stats);
void
prlsdkDomObjFreePrivate(void *p);
/* memsize is in MiB */
int prlsdkSetMemsize(virDomainObjPtr dom, unsigned int memsize);
int
prlsdkDomainSetUserPassword(virDomainObjPtr dom,
                            const char *user,
                            const char *password);
virDomainSnapshotObjListPtr prlsdkLoadSnapshots(virDomainObjPtr dom);
int prlsdkCreateSnapshot(virDomainObjPtr dom, const char *description);
int prlsdkDeleteSnapshot(virDomainObjPtr dom, const char *uuid, bool children);
int prlsdkSwitchToSnapshot(virDomainObjPtr dom, const char *uuid, bool paused);
int
prlsdkMigrate(virDomainObjPtr dom,
              virURIPtr uri,
              const char unsigned *session_uuid,
              const char *dname,
              unsigned int flags);
