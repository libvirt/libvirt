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

#pragma once

#include <Parallels.h>

#include "vz_utils.h"

int prlsdkInit(void);
void prlsdkDeinit(void);
int prlsdkConnect(struct _vzDriver *driver);
void prlsdkDisconnect(struct _vzDriver *driver);
int
prlsdkLoadDomains(struct _vzDriver *driver);
virDomainObj *
prlsdkAddDomainByUUID(struct _vzDriver *driver, const unsigned char *uuid);
virDomainObj *
prlsdkAddDomainByName(struct _vzDriver *driver, const char *name);
int prlsdkUpdateDomain(struct _vzDriver *driver, virDomainObj *dom);

int prlsdkStart(virDomainObj *dom);
int prlsdkKill(virDomainObj *dom);
int prlsdkStop(virDomainObj *dom);
int prlsdkPause(virDomainObj *dom);
int prlsdkResume(virDomainObj *dom);
int prlsdkSuspend(virDomainObj *dom);
int prlsdkRestart(virDomainObj *dom);
int prlsdkReset(virDomainObj *dom);

int
prlsdkApplyConfig(struct _vzDriver *driver,
                  virDomainObj *dom,
                  virDomainDef *new);
int prlsdkCreateVm(struct _vzDriver *driver, virDomainDef *def);
int prlsdkCreateCt(virConnectPtr conn, virDomainDef *def);
int
prlsdkUnregisterDomain(struct _vzDriver *driver, virDomainObj *dom, unsigned int flags);
int
prlsdkDomainManagedSaveRemove(virDomainObj *dom);
int
prlsdkAttachDevice(struct _vzDriver *driver, virDomainObj *dom, virDomainDeviceDef *dev);
int
prlsdkDetachDevice(struct _vzDriver *driver, virDomainObj *dom, virDomainDeviceDef *dev);
int
prlsdkUpdateDevice(struct _vzDriver *driver, virDomainObj *dom, virDomainDeviceDef *dev);
int
prlsdkGetBlockStats(PRL_HANDLE sdkstats, virDomainDiskDef *disk, virDomainBlockStatsPtr stats, bool isCt);
int
prlsdkGetNetStats(PRL_HANDLE sdkstas, PRL_HANDLE sdkdom, const char *path, virDomainInterfaceStatsPtr stats);
int
prlsdkGetVcpuStats(PRL_HANDLE sdkstas, int idx, unsigned long long *time);
int
prlsdkGetMemoryStats(PRL_HANDLE sdkstas, virDomainMemoryStatPtr stats, unsigned int nr_stats);
/* memsize is in MiB */
int prlsdkSetMemsize(virDomainObj *dom, unsigned int memsize);
int prlsdkSetCpuCount(virDomainObj *dom, unsigned int count);
int
prlsdkDomainSetUserPassword(virDomainObj *dom,
                            const char *user,
                            const char *password);
virDomainSnapshotObjList *prlsdkLoadSnapshots(virDomainObj *dom);
int prlsdkCreateSnapshot(virDomainObj *dom, const char *description);
int prlsdkDeleteSnapshot(virDomainObj *dom, const char *uuid, bool children);
int prlsdkSwitchToSnapshot(virDomainObj *dom, const char *uuid, bool paused);
int
prlsdkMigrate(virDomainObj *dom,
              virURI *uri,
              const char unsigned *session_uuid,
              const char *dname,
              unsigned int flags);

PRL_HANDLE
prlsdkSdkDomainLookupByName(struct _vzDriver *driver, const char *name);
int prlsdkCancelJob(virDomainObj *dom);
int prlsdkResizeImage(virDomainObj *dom, virDomainDiskDef *disk, unsigned long long newsize);
