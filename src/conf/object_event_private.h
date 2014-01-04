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
    virObjectEventDispatchFunc dispatch;
};

virClassPtr
virClassForObjectEvent(void);

int
virObjectEventStateCallbackID(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              virClassPtr klass,
                              int eventID,
                              virConnectObjectEventGenericCallback callback)
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
