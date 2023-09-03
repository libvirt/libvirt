/*
 * network_event.c: network event queue processing helpers
 *
 * Copyright (C) 2014 Red Hat, Inc.
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

#include "network_event.h"
#include "object_event.h"
#include "object_event_private.h"
#include "datatypes.h"
#include "virlog.h"

VIR_LOG_INIT("conf.network_event");

struct _virNetworkEvent {
    virObjectEvent parent;

    /* Unused attribute to allow for subclass creation */
    bool dummy;
};
typedef struct _virNetworkEvent virNetworkEvent;

struct _virNetworkEventLifecycle {
    virNetworkEvent parent;

    int type;
    int detail;
};
typedef struct _virNetworkEventLifecycle virNetworkEventLifecycle;

struct _virNetworkEventMetadataChange {
    virNetworkEvent parent;

    int type;
    char *nsuri;
};
typedef struct _virNetworkEventMetadataChange virNetworkEventMetadataChange;

static virClass *virNetworkEventClass;
static virClass *virNetworkEventLifecycleClass;
static virClass *virNetworkEventMetadataChangeClass;

static void virNetworkEventDispose(void *obj);
static void virNetworkEventLifecycleDispose(void *obj);
static void virNetworkEventMetadataChangeDispose(void *obj);

static int
virNetworkEventsOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetworkEvent, virClassForObjectEvent()))
        return -1;

    if (!VIR_CLASS_NEW(virNetworkEventLifecycle, virNetworkEventClass))
        return -1;

    if (!VIR_CLASS_NEW(virNetworkEventMetadataChange, virNetworkEventClass))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetworkEvents);

static void
virNetworkEventDispose(void *obj)
{
    virNetworkEvent *event = obj;
    VIR_DEBUG("obj=%p", event);
}


static void
virNetworkEventLifecycleDispose(void *obj)
{
    virNetworkEventLifecycle *event = obj;
    VIR_DEBUG("obj=%p", event);
}


static void
virNetworkEventDispatchDefaultFunc(virConnectPtr conn,
                                   virObjectEvent *event,
                                   virConnectObjectEventGenericCallback cb,
                                   void *cbopaque)
{
    g_autoptr(virNetwork) net = NULL;

    if (!(net = virGetNetwork(conn, event->meta.name, event->meta.uuid)))
        return;

    switch ((virNetworkEventID)event->eventID) {
    case VIR_NETWORK_EVENT_ID_LIFECYCLE:
        {
            virNetworkEventLifecycle *networkLifecycleEvent;

            networkLifecycleEvent = (virNetworkEventLifecycle *)event;
            ((virConnectNetworkEventLifecycleCallback)cb)(conn, net,
                                                          networkLifecycleEvent->type,
                                                          networkLifecycleEvent->detail,
                                                          cbopaque);
            return;
        }

    case VIR_NETWORK_EVENT_ID_METADATA_CHANGE:
        {
            virNetworkEventMetadataChange *metadataChangeEvent;

            metadataChangeEvent = (virNetworkEventMetadataChange *)event;
            ((virConnectNetworkEventMetadataChangeCallback)cb)(conn, net,
                                                               metadataChangeEvent->type,
                                                               metadataChangeEvent->nsuri,
                                                               cbopaque);
            return;
        }

    case VIR_NETWORK_EVENT_ID_LAST:
        break;
    }
    VIR_WARN("Unexpected event ID %d", event->eventID);
}


/**
 * virNetworkEventStateRegisterID:
 * @conn: connection to associate with callback
 * @state: object event state
 * @net: network to filter on or NULL for all networks
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
virNetworkEventStateRegisterID(virConnectPtr conn,
                               virObjectEventState *state,
                               virNetworkPtr net,
                               int eventID,
                               virConnectNetworkEventGenericCallback cb,
                               void *opaque,
                               virFreeCallback freecb,
                               int *callbackID)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virNetworkEventsInitialize() < 0)
        return -1;

    if (net)
        virUUIDFormat(net->uuid, uuidstr);
    return virObjectEventStateRegisterID(conn, state, net ? uuidstr : NULL,
                                         NULL, NULL,
                                         virNetworkEventClass, eventID,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         opaque, freecb,
                                         false, callbackID, false);
}


/**
 * virNetworkEventStateRegisterClient:
 * @conn: connection to associate with callback
 * @state: object event state
 * @net: network to filter on or NULL for all networks
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
virNetworkEventStateRegisterClient(virConnectPtr conn,
                                   virObjectEventState *state,
                                   virNetworkPtr net,
                                   int eventID,
                                   virConnectNetworkEventGenericCallback cb,
                                   void *opaque,
                                   virFreeCallback freecb,
                                   int *callbackID)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virNetworkEventsInitialize() < 0)
        return -1;

    if (net)
        virUUIDFormat(net->uuid, uuidstr);
    return virObjectEventStateRegisterID(conn, state, net ? uuidstr : NULL,
                                         NULL, NULL,
                                         virNetworkEventClass, eventID,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         opaque, freecb,
                                         false, callbackID, true);
}


/**
 * virNetworkEventLifecycleNew:
 * @name: name of the network object the event describes
 * @uuid: uuid of the network object the event describes
 * @type: type of lifecycle event
 * @detail: more details about @type
 *
 * Create a new network lifecycle event.
 */
virObjectEvent *
virNetworkEventLifecycleNew(const char *name,
                            const unsigned char *uuid,
                            int type,
                            int detail)
{
    virNetworkEventLifecycle *event;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virNetworkEventsInitialize() < 0)
        return NULL;

    virUUIDFormat(uuid, uuidstr);
    if (!(event = virObjectEventNew(virNetworkEventLifecycleClass,
                                    virNetworkEventDispatchDefaultFunc,
                                    VIR_NETWORK_EVENT_ID_LIFECYCLE,
                                    0, name, uuid, uuidstr)))
        return NULL;

    event->type = type;
    event->detail = detail;

    return (virObjectEvent *)event;
}


static void
virNetworkEventMetadataChangeDispose(void *obj)
{
    virNetworkEventMetadataChange *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->nsuri);
}


static virObjectEvent *
virNetworkEventMetadataChangeNew(const char *name,
                                 unsigned char *uuid,
                                 int type,
                                 const char *nsuri)
{
    virNetworkEventMetadataChange *event;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virNetworkEventsInitialize() < 0)
        return NULL;

    virUUIDFormat(uuid, uuidstr);
    if (!(event = virObjectEventNew(virNetworkEventMetadataChangeClass,
                                    virNetworkEventDispatchDefaultFunc,
                                    VIR_NETWORK_EVENT_ID_METADATA_CHANGE,
                                    0, name, uuid, uuidstr)))
        return NULL;

    event->type = type;
    event->nsuri = g_strdup(nsuri);

    return (virObjectEvent *)event;
}


virObjectEvent *
virNetworkEventMetadataChangeNewFromObj(virNetworkObj *obj,
                                        int type,
                                        const char *nsuri)
{
    virNetworkDef *def = virNetworkObjGetDef(obj);
    return virNetworkEventMetadataChangeNew(def->name, def->uuid,
                                            type, nsuri);
}


virObjectEvent *
virNetworkEventMetadataChangeNewFromNet(virNetworkPtr net,
                                        int type,
                                        const char *nsuri)
{
    return virNetworkEventMetadataChangeNew(net->name, net->uuid,
                                            type, nsuri);
}
