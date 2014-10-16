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

#ifndef __VIR_DRIVER_STATE_H__
# define __VIR_DRIVER_STATE_H__

# ifndef __VIR_DRIVER_H_INCLUDES___
#  error "Don't include this file directly, only use driver.h"
# endif

typedef int
(*virDrvStateInitialize)(bool privileged,
                         virStateInhibitCallback callback,
                         void *opaque);

typedef void
(*virDrvStateAutoStart)(void);

typedef int
(*virDrvStateCleanup)(void);

typedef int
(*virDrvStateReload)(void);

typedef int
(*virDrvStateStop)(void);

typedef struct _virStateDriver virStateDriver;
typedef virStateDriver *virStateDriverPtr;

struct _virStateDriver {
    const char *name;
    virDrvStateInitialize stateInitialize;
    virDrvStateAutoStart stateAutoStart;
    virDrvStateCleanup stateCleanup;
    virDrvStateReload stateReload;
    virDrvStateStop stateStop;
};


#endif /* __VIR_DRIVER_STATE_H__ */
