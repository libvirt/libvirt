/*
 * object_event_private.h: object event queue processing helpers
 *
 * Copyright (C) 2012 Red Hat, Inc.
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

struct _virObjectEventCallbackList {
    unsigned int nextID;
    unsigned int count;
    virObjectEventCallbackPtr *callbacks;
};
typedef struct _virObjectEventCallbackList virObjectEventCallbackList;
typedef virObjectEventCallbackList *virObjectEventCallbackListPtr;

typedef struct _virObjectEventQueue virObjectEventQueue;
typedef virObjectEventQueue *virObjectEventQueuePtr;

struct _virObjectEventState {
    /* The list of domain event callbacks */
    virObjectEventCallbackListPtr callbacks;
    /* The queue of object events */
    virObjectEventQueuePtr queue;
    /* Timer for flushing events queue */
    int timer;
    /* Flag if we're in process of dispatching */
    bool isDispatching;
    virMutex lock;
};

struct _virObjectEventCallback {
    int callbackID;
    int eventID;
    virConnectPtr conn;
    virObjectMetaPtr meta;
    virConnectObjectEventGenericCallback cb;
    void *opaque;
    virFreeCallback freecb;
    int deleted;
};

struct _virObjectEvent {
    virObject parent;
    int eventID;
    virObjectMeta meta;
};

virClassPtr virClassForObjectEvent(void);

int virObjectEventGetEventID(void *anyobj);

int
virObjectEventCallbackListAddID(virConnectPtr conn,
                                virObjectEventCallbackListPtr cbList,
                                unsigned char *uuid,
                                const char *name,
                                int id,
                                int eventID,
                                virConnectObjectEventGenericCallback callback,
                                void *opaque,
                                virFreeCallback freecb,
                                int *callbackID);

void
virObjectEventQueueClear(virObjectEventQueuePtr queue);

void
virObjectEventStateLock(virObjectEventStatePtr state);

void
virObjectEventStateUnlock(virObjectEventStatePtr state);

void
virObjectEventTimer(int timer, void *opaque);

void *virObjectEventNew(virClassPtr klass,
                        int eventID,
                        int id,
                        const char *name,
                        const unsigned char *uuid);


#endif
