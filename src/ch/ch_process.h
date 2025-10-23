/*
 * Copyright Intel Corp. 2020-2021
 *
 * ch_process.h: header file for Cloud-Hypervisor's process controller
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

#include "ch_conf.h"
#include "internal.h"

int virCHProcessStart(virCHDriver *driver,
                      virDomainObj *vm,
                      virDomainRunningReason reason);

typedef enum {
    VIR_CH_PROCESS_STOP_FORCE = 1 << 0,
} virCHProcessStopFlags;

int virCHProcessStop(virCHDriver *driver,
                     virDomainObj *vm,
                     virDomainShutoffReason reason,
                     unsigned int flags);

int virCHProcessStartRestore(virCHDriver *driver,
                         virDomainObj *vm,
                         const char *from);

int virCHProcessUpdateInfo(virDomainObj *vm);

int
chProcessAddNetworkDevice(virCHDriver *driver,
                          virCHMonitor *mon,
                          virDomainDef *vmdef,
                          virDomainNetDef *net,
                          int **nicindexes,
                          size_t *nnicindexes);
