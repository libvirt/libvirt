/*
 * object_event_private.h: object event queue processing helpers
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

#include "datatypes.h"

#ifndef __OBJECT_EVENT_PRIVATE_H__
# define __OBJECT_EVENT_PRIVATE_H__

struct _virObjectMeta {
    int id;
    char *name;
    unsigned char uuid[VIR_UUID_BUFLEN];
};
typedef struct _virObjectMeta virObjectMeta;
typedef virObjectMeta *virObjectMetaPtr;

typedef struct _virObjectEventCallbackList virObjectEventCallbackList;
typedef virObjectEventCallbackList *virObjectEventCallbackListPtr;

typedef void
(*virObjectEventDispatchFunc)(virConnectPtr conn,
                              virObjectEventPtr event,
                              virConnectObjectEventGenericCallback cb,
                              void *cbopaque);

struct _virObjectEvent {
    virObject parent;
    int eventID;
    virObjectMeta meta;
    int remoteID;
    virObjectEventDispatchFunc dispatch;
};

/**
 * virObjectEventCallbackFilter:
 * @conn: the connection pointer
 * @event: the event about to be dispatched
 * @opaque: opaque data registered with the filter
 *
 * Callback to do final filtering for a reason not tracked directly by
 * virObjectEventStateRegisterID().  Return false if @event must not
 * be sent to @conn.
 */
typedef bool (*virObjectEventCallbackFilter)(virConnectPtr conn,
                                             virObjectEventPtr event,
                                             void *opaque);

virClassPtr
virClassForObjectEvent(void);

int
virObjectEventStateRegisterID(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              unsigned char *uuid,
                              virObjectEventCallbackFilter filter,
                              void *filter_opaque,
                              virClassPtr klass,
                              int eventID,
                              virConnectObjectEventGenericCallback cb,
                              void *opaque,
                              virFreeCallback freecb,
                              bool legacy,
                              int *callbackID,
                              bool remoteFilter)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(6)
    ATTRIBUTE_NONNULL(8) ATTRIBUTE_NONNULL(12);

int
virObjectEventStateCallbackID(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              virClassPtr klass,
                              int eventID,
                              virConnectObjectEventGenericCallback callback,
                              int *remoteID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(5);

void *
virObjectEventNew(virClassPtr klass,
                  virObjectEventDispatchFunc dispatcher,
                  int eventID,
                  int id,
                  const char *name,
                  const unsigned char *uuid)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5)
    ATTRIBUTE_NONNULL(6);

#endif
