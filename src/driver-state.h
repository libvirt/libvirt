/*
 * driver-state.h: entry points for state drivers
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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

#ifndef __VIR_DRIVER_H_INCLUDES___
# error "Don't include this file directly, only use driver.h"
#endif

typedef enum {
    VIR_DRV_STATE_INIT_ERROR = -1,
    VIR_DRV_STATE_INIT_SKIPPED,
    VIR_DRV_STATE_INIT_COMPLETE,
} virDrvStateInitResult;

typedef virDrvStateInitResult
(*virDrvStateInitialize)(bool privileged,
                         const char *root,
                         bool monolithic,
                         virStateInhibitCallback callback,
                         void *opaque);

typedef int
(*virDrvStateCleanup)(void);

typedef int
(*virDrvStateReload)(void);

typedef int
(*virDrvStateStop)(void);

typedef int
(*virDrvStateShutdownPrepare)(void);

typedef int
(*virDrvStateShutdownWait)(void);

typedef struct _virStateDriver virStateDriver;
struct _virStateDriver {
    const char *name;
    bool initialized;
    virDrvStateInitialize stateInitialize;
    virDrvStateCleanup stateCleanup;
    virDrvStateReload stateReload;
    virDrvStateStop stateStop;
    virDrvStateShutdownPrepare stateShutdownPrepare;
    virDrvStateShutdownWait stateShutdownWait;
};
