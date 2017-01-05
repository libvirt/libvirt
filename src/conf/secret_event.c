/*
 * secret_event.c: node device event queue processing helpers
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

#include "secret_event.h"
#include "object_event.h"
#include "object_event_private.h"
#include "datatypes.h"
#include "virlog.h"

VIR_LOG_INIT("conf.secret_event");

struct _virSecretEvent {
    virObjectEvent parent;

    /* Unused attribute to allow for subclass creation */
    bool dummy;
};
typedef struct _virSecretEvent virSecretEvent;
typedef virSecretEvent *virSecretEventPtr;

struct _virSecretEventLifecycle {
    virSecretEvent parent;

    int type;
    int detail;
};
typedef struct _virSecretEventLifecycle virSecretEventLifecycle;
typedef virSecretEventLifecycle *virSecretEventLifecyclePtr;

struct _virSecretEventValueChanged {
    virSecretEvent parent;
    bool dummy;
};
typedef struct _virSecretEventValueChanged virSecretEventValueChanged;
typedef virSecretEventValueChanged *virSecretEventValueChangedPtr;

static virClassPtr virSecretEventClass;
static virClassPtr virSecretEventLifecycleClass;
static virClassPtr virSecretEventValueChangedClass;
static void virSecretEventDispose(void *obj);
static void virSecretEventLifecycleDispose(void *obj);
static void virSecretEventValueChangedDispose(void *obj);

static int
virSecretEventsOnceInit(void)
{
    if (!(virSecretEventClass =
          virClassNew(virClassForObjectEvent(),
                      "virSecretEvent",
                      sizeof(virSecretEvent),
                      virSecretEventDispose)))
        return -1;
    if (!(virSecretEventLifecycleClass =
          virClassNew(virSecretEventClass,
                      "virSecretEventLifecycle",
                      sizeof(virSecretEventLifecycle),
                      virSecretEventLifecycleDispose)))
        return -1;
    if (!(virSecretEventValueChangedClass =
          virClassNew(virSecretEventClass,
                      "virSecretEventValueChanged",
                      sizeof(virSecretEventValueChanged),
                      virSecretEventValueChangedDispose)))
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virSecretEvents)

static void
virSecretEventDispose(void *obj)
{
    virSecretEventPtr event = obj;
    VIR_DEBUG("obj=%p", event);
}


static void
virSecretEventLifecycleDispose(void *obj)
{
    virSecretEventLifecyclePtr event = obj;
    VIR_DEBUG("obj=%p", event);
}


static void
virSecretEventValueChangedDispose(void *obj)
{
    virSecretEventValueChangedPtr event = obj;
    VIR_DEBUG("obj=%p", event);
}


static void
virSecretEventDispatchDefaultFunc(virConnectPtr conn,
                                  virObjectEventPtr event,
                                  virConnectObjectEventGenericCallback cb,
                                  void *cbopaque)
{
    virSecretPtr secret = virGetSecret(conn,
                                       event->meta.uuid,
                                       event->meta.id,
                                       event->meta.name);

    if (!secret)
        return;

    switch ((virSecretEventID)event->eventID) {
    case VIR_SECRET_EVENT_ID_LIFECYCLE:
        {
            virSecretEventLifecyclePtr secretLifecycleEvent;

            secretLifecycleEvent = (virSecretEventLifecyclePtr)event;
            ((virConnectSecretEventLifecycleCallback)cb)(conn, secret,
                                                         secretLifecycleEvent->type,
                                                         secretLifecycleEvent->detail,
                                                         cbopaque);
            goto cleanup;
        }

    case VIR_SECRET_EVENT_ID_VALUE_CHANGED:
        {
            ((virConnectSecretEventGenericCallback)cb)(conn, secret,
                                                       cbopaque);
            goto cleanup;
        }

    case VIR_SECRET_EVENT_ID_LAST:
        break;
    }
    VIR_WARN("Unexpected event ID %d", event->eventID);

 cleanup:
    virObjectUnref(secret);
}


/**
 * virSecretEventStateRegisterID:
 * @conn: connection to associate with callback
 * @state: object event state
 * @secret: secret to filter on or NULL for all node secrets
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
virSecretEventStateRegisterID(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              virSecretPtr secret,
                              int eventID,
                              virConnectSecretEventGenericCallback cb,
                              void *opaque,
                              virFreeCallback freecb,
                              int *callbackID)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virSecretEventsInitialize() < 0)
        return -1;

    if (secret)
        virUUIDFormat(secret->uuid, uuidstr);
    return virObjectEventStateRegisterID(conn, state, secret ? uuidstr : NULL,
                                         NULL, NULL,
                                         virSecretEventClass, eventID,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         opaque, freecb,
                                         false, callbackID, false);
}


/**
 * virSecretEventStateRegisterClient:
 * @conn: connection to associate with callback
 * @state: object event state
 * @secret: secret to filter on or NULL for all node secrets
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
virSecretEventStateRegisterClient(virConnectPtr conn,
                                  virObjectEventStatePtr state,
                                  virSecretPtr secret,
                                  int eventID,
                                  virConnectSecretEventGenericCallback cb,
                                  void *opaque,
                                  virFreeCallback freecb,
                                  int *callbackID)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virSecretEventsInitialize() < 0)
        return -1;

    if (secret)
        virUUIDFormat(secret->uuid, uuidstr);

    return virObjectEventStateRegisterID(conn, state,  secret ? uuidstr : NULL,
                                         NULL, NULL,
                                         virSecretEventClass, eventID,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         opaque, freecb,
                                         false, callbackID, true);
}


/**
 * virSecretEventLifecycleNew:
 * @uuid: UUID of the secret object the event describes
 * @usage_type: type of usage for the secret
 * @usage_id: usage specific identifier for the secret
 * @type: type of lifecycle event
 * @detail: more details about @type
 *
 * Create a new secret lifecycle event.
 */
virObjectEventPtr
virSecretEventLifecycleNew(const unsigned char *uuid,
                           int usage_type,
                           const char *usage_id,
                           int type,
                           int detail)
{
    virSecretEventLifecyclePtr event;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virSecretEventsInitialize() < 0)
        return NULL;

    virUUIDFormat(uuid, uuidstr);
    VIR_DEBUG("Event %s %d %s %d %d", uuidstr, usage_type, usage_id, type, detail);
    if (!(event = virObjectEventNew(virSecretEventLifecycleClass,
                                    virSecretEventDispatchDefaultFunc,
                                    VIR_SECRET_EVENT_ID_LIFECYCLE,
                                    usage_type, usage_id, uuid, uuidstr)))
        return NULL;

    event->type = type;
    event->detail = detail;

    return (virObjectEventPtr)event;
}


/**
 * virSecretEventValueChangedNew:
 * @uuid: UUID of the secret object the event describes
 *
 * Create a new secret lifecycle event.
 */
virObjectEventPtr
virSecretEventValueChangedNew(const unsigned char *uuid,
                              int usage_type,
                              const char *usage_id)
{
    virSecretEventValueChangedPtr event;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virSecretEventsInitialize() < 0)
        return NULL;

    virUUIDFormat(uuid, uuidstr);
    VIR_DEBUG("Event %s %d %s", uuidstr, usage_type, usage_id);
    if (!(event = virObjectEventNew(virSecretEventValueChangedClass,
                                    virSecretEventDispatchDefaultFunc,
                                    VIR_SECRET_EVENT_ID_VALUE_CHANGED,
                                    usage_type, usage_id, uuid, uuidstr)))
        return NULL;

    return (virObjectEventPtr)event;
}
