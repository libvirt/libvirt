/*
 * bhyve_process.h: bhyve process management
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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

#include "bhyve_utils.h"

int
bhyveProcessPrepareDomain(bhyveConn *driver,
                          virDomainObj *vm,
                          unsigned int flags);

int virBhyveProcessStart(virConnect *conn,
                         virDomainObj *vm,
                         virDomainRunningReason reason,
                         unsigned int flags);

int virBhyveProcessStop(struct _bhyveConn *driver,
                        virDomainObj *vm,
                        virDomainShutoffReason reason);

int virBhyveProcessRestart(struct _bhyveConn *driver,
                           virDomainObj *vm);

int virBhyveProcessShutdown(virDomainObj *vm);

int virBhyveGetDomainTotalCpuStats(virDomainObj *vm,
                                   unsigned long long *cpustats);

void virBhyveProcessReconnectAll(struct _bhyveConn *driver);

typedef enum {
    VIR_BHYVE_PROCESS_START_AUTODESTROY = 1 << 0,
} bhyveProcessStartFlags;
