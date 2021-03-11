/*
 * node_device_event.c: node device event queue processing helpers
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

#include "node_device_event.h"
#include "object_event.h"
#include "object_event_private.h"
#include "datatypes.h"
#include "virlog.h"

VIR_LOG_INIT("conf.node_device_event");

struct _virNodeDeviceEvent {
    virObjectEvent parent;

    /* Unused attribute to allow for subclass creation */
    bool dummy;
};
typedef struct _virNodeDeviceEvent virNodeDeviceEvent;

struct _virNodeDeviceEventLifecycle {
    virNodeDeviceEvent parent;

    int type;
    int detail;
};
typedef struct _virNodeDeviceEventLifecycle virNodeDeviceEventLifecycle;

struct _virNodeDeviceEventUpdate {
    virNodeDeviceEvent parent;

    bool dummy;
};
typedef struct _virNodeDeviceEventUpdate virNodeDeviceEventUpdate;

static virClass *virNodeDeviceEventClass;
static virClass *virNodeDeviceEventLifecycleClass;
static virClass *virNodeDeviceEventUpdateClass;
static void virNodeDeviceEventDispose(void *obj);
static void virNodeDeviceEventLifecycleDispose(void *obj);
static void virNodeDeviceEventUpdateDispose(void *obj);

static int
virNodeDeviceEventsOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNodeDeviceEvent, virClassForObjectEvent()))
        return -1;

    if (!VIR_CLASS_NEW(virNodeDeviceEventLifecycle, virNodeDeviceEventClass))
        return -1;

    if (!VIR_CLASS_NEW(virNodeDeviceEventUpdate, virNodeDeviceEventClass))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNodeDeviceEvents);

static void
virNodeDeviceEventDispose(void *obj)
{
    virNodeDeviceEvent *event = obj;
    VIR_DEBUG("obj=%p", event);
}


static void
virNodeDeviceEventLifecycleDispose(void *obj)
{
    virNodeDeviceEventLifecycle *event = obj;
    VIR_DEBUG("obj=%p", event);
}


static void
virNodeDeviceEventUpdateDispose(void *obj)
{
    virNodeDeviceEventUpdate *event = obj;
    VIR_DEBUG("obj=%p", event);
}


static void
virNodeDeviceEventDispatchDefaultFunc(virConnectPtr conn,
                                      virObjectEvent *event,
                                      virConnectObjectEventGenericCallback cb,
                                      void *cbopaque)
{
    virNodeDevicePtr dev = virGetNodeDevice(conn,
                                            event->meta.name);

    if (!dev)
        return;

    switch ((virNodeDeviceEventID)event->eventID) {
    case VIR_NODE_DEVICE_EVENT_ID_LIFECYCLE:
        {
            virNodeDeviceEventLifecycle *nodeDeviceLifecycleEvent;

            nodeDeviceLifecycleEvent = (virNodeDeviceEventLifecycle *)event;
            ((virConnectNodeDeviceEventLifecycleCallback)cb)(conn, dev,
                                                             nodeDeviceLifecycleEvent->type,
                                                             nodeDeviceLifecycleEvent->detail,
                                                             cbopaque);
            goto cleanup;
        }

    case VIR_NODE_DEVICE_EVENT_ID_UPDATE:
        {
            ((virConnectNodeDeviceEventGenericCallback)cb)(conn, dev,
                                                           cbopaque);
            goto cleanup;
        }

    case VIR_NODE_DEVICE_EVENT_ID_LAST:
        break;
    }
    VIR_WARN("Unexpected event ID %d", event->eventID);

 cleanup:
    virObjectUnref(dev);
}


/**
 * virNodeDeviceEventStateRegisterID:
 * @conn: connection to associate with callback
 * @state: object event state
 * @dev: node device to filter on or NULL for all node devices
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
virNodeDeviceEventStateRegisterID(virConnectPtr conn,
                                  virObjectEventState *state,
                                  virNodeDevicePtr dev,
                                  int eventID,
                                  virConnectNodeDeviceEventGenericCallback cb,
                                  void *opaque,
                                  virFreeCallback freecb,
                                  int *callbackID)
{
    if (virNodeDeviceEventsInitialize() < 0)
        return -1;

    return virObjectEventStateRegisterID(conn, state, dev ? dev->name : NULL,
                                         NULL, NULL,
                                         virNodeDeviceEventClass, eventID,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         opaque, freecb,
                                         false, callbackID, false);
}


/**
 * virNodeDeviceEventStateRegisterClient:
 * @conn: connection to associate with callback
 * @state: object event state
 * @dev: node device to filter on or NULL for all node devices
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
virNodeDeviceEventStateRegisterClient(virConnectPtr conn,
                                      virObjectEventState *state,
                                      virNodeDevicePtr dev,
                                      int eventID,
                                      virConnectNodeDeviceEventGenericCallback cb,
                                      void *opaque,
                                      virFreeCallback freecb,
                                      int *callbackID)
{
    if (virNodeDeviceEventsInitialize() < 0)
        return -1;

    return virObjectEventStateRegisterID(conn, state,  dev ? dev->name : NULL,
                                         NULL, NULL,
                                         virNodeDeviceEventClass, eventID,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         opaque, freecb,
                                         false, callbackID, true);
}


/**
 * virNodeDeviceEventLifecycleNew:
 * @name: name of the node device object the event describes
 * @type: type of lifecycle event
 * @detail: more details about @type
 *
 * Create a new node device lifecycle event.
 */
virObjectEvent *
virNodeDeviceEventLifecycleNew(const char *name,
                               int type,
                               int detail)
{
    virNodeDeviceEventLifecycle *event;

    if (virNodeDeviceEventsInitialize() < 0)
        return NULL;

    if (!(event = virObjectEventNew(virNodeDeviceEventLifecycleClass,
                                    virNodeDeviceEventDispatchDefaultFunc,
                                    VIR_NODE_DEVICE_EVENT_ID_LIFECYCLE,
                                    0, name, NULL, name)))
        return NULL;

    event->type = type;
    event->detail = detail;

    return (virObjectEvent *)event;
}


/**
 * virNodeDeviceEventUpdateNew:
 * @name: name of the node device object the event describes
 *
 * Create a new node device update event.
 */
virObjectEvent *
virNodeDeviceEventUpdateNew(const char *name)
{
    virNodeDeviceEventUpdate *event;

    if (virNodeDeviceEventsInitialize() < 0)
        return NULL;

    if (!(event = virObjectEventNew(virNodeDeviceEventUpdateClass,
                                    virNodeDeviceEventDispatchDefaultFunc,
                                    VIR_NODE_DEVICE_EVENT_ID_UPDATE,
                                    0, name, NULL, name)))
        return NULL;

    return (virObjectEvent *)event;
}
