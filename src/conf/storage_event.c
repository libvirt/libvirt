/*
 * storage_event.c: storage event queue processing helpers
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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
*/

#include <config.h>

#include "storage_event.h"
#include "object_event.h"
#include "object_event_private.h"
#include "datatypes.h"
#include "virlog.h"

VIR_LOG_INIT("conf.storage_event");

struct _virStoragePoolEvent {
    virObjectEvent parent;

    /* Unused attribute to allow for subclass creation */
    bool dummy;
};
typedef struct _virStoragePoolEvent virStoragePoolEvent;
typedef virStoragePoolEvent *virStoragePoolEventPtr;

struct _virStoragePoolEventLifecycle {
    virStoragePoolEvent parent;

    int type;
    int detail;
};
typedef struct _virStoragePoolEventLifecycle virStoragePoolEventLifecycle;
typedef virStoragePoolEventLifecycle *virStoragePoolEventLifecyclePtr;

struct _virStoragePoolEventRefresh {
    virStoragePoolEvent parent;

    bool dummy;
};
typedef struct _virStoragePoolEventRefresh virStoragePoolEventRefresh;
typedef virStoragePoolEventRefresh *virStoragePoolEventRefreshPtr;

static virClassPtr virStoragePoolEventClass;
static virClassPtr virStoragePoolEventLifecycleClass;
static virClassPtr virStoragePoolEventRefreshClass;
static void virStoragePoolEventDispose(void *obj);
static void virStoragePoolEventLifecycleDispose(void *obj);
static void virStoragePoolEventRefreshDispose(void *obj);

static int
virStoragePoolEventsOnceInit(void)
{
    if (!(virStoragePoolEventClass =
          virClassNew(virClassForObjectEvent(),
                      "virStoragePoolEvent",
                      sizeof(virStoragePoolEvent),
                      virStoragePoolEventDispose)))
        return -1;
    if (!(virStoragePoolEventLifecycleClass =
          virClassNew(virStoragePoolEventClass,
                      "virStoragePoolEventLifecycle",
                      sizeof(virStoragePoolEventLifecycle),
                      virStoragePoolEventLifecycleDispose)))
        return -1;
    if (!(virStoragePoolEventRefreshClass =
          virClassNew(virStoragePoolEventClass,
                      "virStoragePoolEventRefresh",
                      sizeof(virStoragePoolEventRefresh),
                      virStoragePoolEventRefreshDispose)))
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virStoragePoolEvents)

static void
virStoragePoolEventDispose(void *obj)
{
    virStoragePoolEventPtr event = obj;
    VIR_DEBUG("obj=%p", event);
}


static void
virStoragePoolEventLifecycleDispose(void *obj)
{
    virStoragePoolEventLifecyclePtr event = obj;
    VIR_DEBUG("obj=%p", event);
}


static void
virStoragePoolEventRefreshDispose(void *obj)
{
    virStoragePoolEventRefreshPtr event = obj;
    VIR_DEBUG("obj=%p", event);
}


static void
virStoragePoolEventDispatchDefaultFunc(virConnectPtr conn,
                                       virObjectEventPtr event,
                                       virConnectObjectEventGenericCallback cb,
                                       void *cbopaque)
{
    virStoragePoolPtr pool = virGetStoragePool(conn,
                                               event->meta.name,
                                               event->meta.uuid,
                                               NULL, NULL);
    if (!pool)
        return;

    switch ((virStoragePoolEventID)event->eventID) {
    case VIR_STORAGE_POOL_EVENT_ID_LIFECYCLE:
        {
            virStoragePoolEventLifecyclePtr storagePoolLifecycleEvent;

            storagePoolLifecycleEvent = (virStoragePoolEventLifecyclePtr)event;
            ((virConnectStoragePoolEventLifecycleCallback)cb)(conn, pool,
                                                              storagePoolLifecycleEvent->type,
                                                              storagePoolLifecycleEvent->detail,
                                                              cbopaque);
            goto cleanup;
        }

    case VIR_STORAGE_POOL_EVENT_ID_REFRESH:
        {
            ((virConnectStoragePoolEventGenericCallback)cb)(conn, pool,
                                                            cbopaque);
            goto cleanup;
        }

    case VIR_STORAGE_POOL_EVENT_ID_LAST:
        break;
    }
    VIR_WARN("Unexpected event ID %d", event->eventID);

 cleanup:
    virObjectUnref(pool);
}


/**
 * virStoragePoolEventStateRegisterID:
 * @conn: connection to associate with callback
 * @state: object event state
 * @pool: storage pool to filter on or NULL for all storage pools
 * @eventID: ID of the event type to register for
 * @cb: function to invoke when event occurs
 * @opaque: data blob to pass to @callback
 * @freecb: callback to free @opaque
 * @callbackID: filled with callback ID
 *
 * Register the function @cb with connection @conn, from @state, for
 * events of type @eventID, and return the registration handle in
 * @callbackID.
 *
 * Returns: the number of callbacks now registered, or -1 on error
 */
int
virStoragePoolEventStateRegisterID(virConnectPtr conn,
                                   virObjectEventStatePtr state,
                                   virStoragePoolPtr pool,
                                   int eventID,
                                   virConnectStoragePoolEventGenericCallback cb,
                                   void *opaque,
                                   virFreeCallback freecb,
                                   int *callbackID)
{
    if (virStoragePoolEventsInitialize() < 0)
        return -1;

    return virObjectEventStateRegisterID(conn, state, pool ? pool->uuid : NULL,
                                         NULL, NULL,
                                         virStoragePoolEventClass, eventID,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         opaque, freecb,
                                         false, callbackID, false);
}


/**
 * virStoragePoolEventStateRegisterClient:
 * @conn: connection to associate with callback
 * @state: object event state
 * @pool: storage pool to filter on or NULL for all storage pools
 * @eventID: ID of the event type to register for
 * @cb: function to invoke when event occurs
 * @opaque: data blob to pass to @callback
 * @freecb: callback to free @opaque
 * @callbackID: filled with callback ID
 *
 * Register the function @cb with connection @conn, from @state, for
 * events of type @eventID, and return the registration handle in
 * @callbackID.  This version is intended for use on the client side
 * of RPC.
 *
 * Returns: the number of callbacks now registered, or -1 on error
 */
int
virStoragePoolEventStateRegisterClient(virConnectPtr conn,
                                       virObjectEventStatePtr state,
                                       virStoragePoolPtr pool,
                                       int eventID,
                                       virConnectStoragePoolEventGenericCallback cb,
                                       void *opaque,
                                       virFreeCallback freecb,
                                       int *callbackID)
{
    if (virStoragePoolEventsInitialize() < 0)
        return -1;

    return virObjectEventStateRegisterID(conn, state,  pool ? pool->uuid : NULL,
                                         NULL, NULL,
                                         virStoragePoolEventClass, eventID,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         opaque, freecb,
                                         false, callbackID, true);
}


/**
 * virStoragePoolEventLifecycleNew:
 * @name: name of the storage pool object the event describes
 * @uuid: uuid of the storage pool object the event describes
 * @type: type of lifecycle event
 * @detail: more details about @type
 *
 * Create a new storage pool lifecycle event.
 */
virObjectEventPtr
virStoragePoolEventLifecycleNew(const char *name,
                                const unsigned char *uuid,
                                int type,
                                int detail)
{
    virStoragePoolEventLifecyclePtr event;

    if (virStoragePoolEventsInitialize() < 0)
        return NULL;

    if (!(event = virObjectEventNew(virStoragePoolEventLifecycleClass,
                                    virStoragePoolEventDispatchDefaultFunc,
                                    VIR_STORAGE_POOL_EVENT_ID_LIFECYCLE,
                                    0, name, uuid)))
        return NULL;

    event->type = type;
    event->detail = detail;

    return (virObjectEventPtr)event;
}


/**
 * virStoragePoolEventRefreshNew:
 * @name: name of the storage pool object the event describes
 * @uuid: uuid of the storage pool object the event describes
 *
 * Create a new storage pool refresh event.
 */
virObjectEventPtr
virStoragePoolEventRefreshNew(const char *name,
                              const unsigned char *uuid)
{
    virStoragePoolEventRefreshPtr event;

    if (virStoragePoolEventsInitialize() < 0)
        return NULL;

    if (!(event = virObjectEventNew(virStoragePoolEventRefreshClass,
                                    virStoragePoolEventDispatchDefaultFunc,
                                    VIR_STORAGE_POOL_EVENT_ID_REFRESH,
                                    0, name, uuid)))
        return NULL;

    return (virObjectEventPtr)event;
}
