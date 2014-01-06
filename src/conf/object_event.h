/*
 * object_event.h: object event queue processing helpers
 *
 * Copyright (C) 2012-2014 Red Hat, Inc.
 * Copyright (C) 2008 VirtualIron
 * Copyright (C) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Ben Guthro
 */

#include "internal.h"

#include "virobject.h"

#ifndef __OBJECT_EVENT_H__
# define __OBJECT_EVENT_H__

typedef struct _virObjectEventCallback virObjectEventCallback;
typedef virObjectEventCallback *virObjectEventCallbackPtr;

/**
 * Dispatching domain events that come in while
 * in a call / response rpc
 */
typedef struct _virObjectEvent virObjectEvent;
typedef virObjectEvent *virObjectEventPtr;

typedef struct _virObjectEventState virObjectEventState;
typedef virObjectEventState *virObjectEventStatePtr;


void virObjectEventStateFree(virObjectEventStatePtr state);
virObjectEventStatePtr
virObjectEventStateNew(void);

/**
 * virConnectObjectEventGenericCallback:
 * @conn: the connection pointer
 * @obj: the object pointer
 * @opaque: application specified data
 *
 * A generic object event callback handler. Specific events usually
 * have a customization with extra parameters
 */
typedef void (*virConnectObjectEventGenericCallback)(virConnectPtr conn,
                                                     void *obj,
                                                     void *opaque);

# define VIR_OBJECT_EVENT_CALLBACK(cb) \
    ((virConnectObjectEventGenericCallback)(cb))

void
virObjectEventStateQueue(virObjectEventStatePtr state,
                         virObjectEventPtr event)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void
virObjectEventStateQueueRemote(virObjectEventStatePtr state,
                               virObjectEventPtr event,
                               int remoteID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
virObjectEventStateDeregisterID(virConnectPtr conn,
                                virObjectEventStatePtr state,
                                int callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
virObjectEventStateEventID(virConnectPtr conn,
                           virObjectEventStatePtr state,
                           int callbackID,
                           int *remoteID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void
virObjectEventStateSetRemote(virConnectPtr conn,
                             virObjectEventStatePtr state,
                             int callbackID,
                             int remoteID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

#endif
