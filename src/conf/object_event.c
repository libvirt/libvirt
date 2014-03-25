/*
 * object_event.c: object event queue processing helpers
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
 *
 * Author: Ben Guthro
 */

#include <config.h>

#include "domain_event.h"
#include "network_event.h"
#include "object_event.h"
#include "object_event_private.h"
#include "virlog.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("conf.object_event");

struct _virObjectEventCallbackList {
    unsigned int nextID;
    size_t count;
    virObjectEventCallbackPtr *callbacks;
};

struct _virObjectEventQueue {
    size_t count;
    virObjectEventPtr *events;
};
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
    virClassPtr klass;
    int eventID;
    virConnectPtr conn;
    int remoteID;
    bool uuid_filter;
    unsigned char uuid[VIR_UUID_BUFLEN];
    virObjectEventCallbackFilter filter;
    void *filter_opaque;
    virConnectObjectEventGenericCallback cb;
    void *opaque;
    virFreeCallback freecb;
    bool deleted;
    bool legacy; /* true if end user does not know callbackID */
};

static virClassPtr virObjectEventClass;

static void virObjectEventDispose(void *obj);

static int
virObjectEventOnceInit(void)
{
    if (!(virObjectEventClass =
          virClassNew(virClassForObject(),
                      "virObjectEvent",
                      sizeof(virObjectEvent),
                      virObjectEventDispose)))
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virObjectEvent)

/**
 * virClassForObjectEvent:
 *
 * Return the class object to be used as a parent when creating an
 * event subclass.
 */
virClassPtr
virClassForObjectEvent(void)
{
    if (virObjectEventInitialize() < 0)
        return NULL;
    return virObjectEventClass;
}


static void
virObjectEventDispose(void *obj)
{
    virObjectEventPtr event = obj;

    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->meta.name);
}

/**
 * virObjectEventCallbackListFree:
 * @list: event callback list head
 *
 * Free the memory in the domain event callback list
 */
static void
virObjectEventCallbackListFree(virObjectEventCallbackListPtr list)
{
    size_t i;
    if (!list)
        return;

    for (i = 0; i < list->count; i++) {
        virFreeCallback freecb = list->callbacks[i]->freecb;
        if (freecb)
            (*freecb)(list->callbacks[i]->opaque);
        VIR_FREE(list->callbacks[i]);
    }
    VIR_FREE(list->callbacks);
    VIR_FREE(list);
}


/**
 * virObjectEventCallbackListCount:
 * @conn: pointer to the connection
 * @cbList: the list
 * @klass: the base event class
 * @eventID: the event ID
 * @uuid: optional uuid of per-object filtering
 * @serverFilter: true if server supports object filtering
 *
 * Internal function to count how many callbacks remain registered for
 * the given @eventID and @uuid; knowing this allows the client side
 * of the remote driver know when it must send an RPC to adjust the
 * callbacks on the server.  When @serverFilter is false, this function
 * returns a count that includes both global and per-object callbacks,
 * since the remote side will use a single global event to feed both.
 * When true, the count is limited to the callbacks with the same
 * @uuid, and where a remoteID has already been set on the callback
 * with virObjectEventStateSetRemote().  Note that this function
 * intentionally ignores the legacy field, since RPC calls use only a
 * single callback on the server to manage both legacy and modern
 * global domain lifecycle events.
 */
static int
virObjectEventCallbackListCount(virConnectPtr conn,
                                virObjectEventCallbackListPtr cbList,
                                virClassPtr klass,
                                int eventID,
                                unsigned char uuid[VIR_UUID_BUFLEN],
                                bool serverFilter)
{
    size_t i;
    int ret = 0;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->filter)
            continue;
        if (cb->klass == klass &&
            cb->eventID == eventID &&
            cb->conn == conn &&
            !cb->deleted &&
            (!serverFilter ||
             (cb->remoteID >= 0 &&
              ((uuid && cb->uuid_filter &&
                memcmp(cb->uuid, uuid, VIR_UUID_BUFLEN) == 0) ||
               (!uuid && !cb->uuid_filter)))))
            ret++;
    }
    return ret;
}

/**
 * virObjectEventCallbackListRemoveID:
 * @conn: pointer to the connection
 * @cbList: the list
 * @callback: the callback to remove
 *
 * Internal function to remove a callback from a virObjectEventCallbackListPtr
 */
static int
virObjectEventCallbackListRemoveID(virConnectPtr conn,
                                   virObjectEventCallbackListPtr cbList,
                                   int callbackID)
{
    size_t i;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->callbackID == callbackID && cb->conn == conn) {
            int ret;

            ret = cb->filter ? 0 :
                (virObjectEventCallbackListCount(conn, cbList, cb->klass,
                                                 cb->eventID,
                                                 cb->uuid_filter ? cb->uuid : NULL,
                                                 cb->remoteID >= 0) - 1);

            if (cb->freecb)
                (*cb->freecb)(cb->opaque);
            virObjectUnref(cb->conn);
            VIR_FREE(cb);
            VIR_DELETE_ELEMENT(cbList->callbacks, i, cbList->count);
            return ret;
        }
    }

    virReportError(VIR_ERR_INVALID_ARG,
                   _("could not find event callback %d for deletion"),
                   callbackID);
    return -1;
}


static int
virObjectEventCallbackListMarkDeleteID(virConnectPtr conn,
                                       virObjectEventCallbackListPtr cbList,
                                       int callbackID)
{
    size_t i;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->callbackID == callbackID && cb->conn == conn) {
            cb->deleted = true;
            return cb->filter ? 0 :
                virObjectEventCallbackListCount(conn, cbList, cb->klass,
                                                cb->eventID,
                                                cb->uuid_filter ? cb->uuid : NULL,
                                                cb->remoteID >= 0);
        }
    }

    virReportError(VIR_ERR_INVALID_ARG,
                   _("could not find event callback %d for deletion"),
                   callbackID);
    return -1;
}


static int
virObjectEventCallbackListPurgeMarked(virObjectEventCallbackListPtr cbList)
{
    size_t n;
    for (n = 0; n < cbList->count; n++) {
        if (cbList->callbacks[n]->deleted) {
            virFreeCallback freecb = cbList->callbacks[n]->freecb;
            if (freecb)
                (*freecb)(cbList->callbacks[n]->opaque);
            virObjectUnref(cbList->callbacks[n]->conn);
            VIR_FREE(cbList->callbacks[n]);

            VIR_DELETE_ELEMENT(cbList->callbacks, n, cbList->count);
            n--;
        }
    }
    return 0;
}


/**
 * virObjectEventCallbackLookup:
 * @conn: pointer to the connection
 * @cbList: the list
 * @uuid: the uuid of the object to filter on
 * @klass: the base event class
 * @eventID: the event ID
 * @callback: the callback to locate
 * @legacy: true if callback is tracked by function instead of callbackID
 * @remoteID: optionally return a known remoteID
 *
 * Internal function to determine if @callback already has a
 * callbackID in @cbList for the given @conn and other filters.  If
 * @remoteID is non-NULL, and another callback exists that can be
 * serviced by the same remote event, then set it to that remote ID.
 *
 * Return the id if found, or -1 with no error issued if not present.
 */
static int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
virObjectEventCallbackLookup(virConnectPtr conn,
                             virObjectEventCallbackListPtr cbList,
                             unsigned char uuid[VIR_UUID_BUFLEN],
                             virClassPtr klass,
                             int eventID,
                             virConnectObjectEventGenericCallback callback,
                             bool legacy,
                             int *remoteID)
{
    size_t i;

    if (remoteID)
        *remoteID = -1;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->deleted)
            continue;
        if (cb->klass == klass &&
            cb->eventID == eventID &&
            cb->conn == conn &&
            ((uuid && cb->uuid_filter &&
              memcmp(cb->uuid, uuid, VIR_UUID_BUFLEN) == 0) ||
             (!uuid && !cb->uuid_filter))) {
            if (remoteID)
                *remoteID = cb->remoteID;
            if (cb->legacy == legacy &&
                cb->cb == callback)
                return cb->callbackID;
        }
    }
    return -1;
}


/**
 * virObjectEventCallbackListAddID:
 * @conn: pointer to the connection
 * @cbList: the list
 * @uuid: the optional uuid of the object to filter on
 * @filter: optional last-ditch filter callback
 * @filter_opaque: opaque data to pass to @filter
 * @klass: the base event class
 * @eventID: the event ID
 * @callback: the callback to add
 * @opaque: opaque data to pass to @callback
 * @freecb: callback to free @opaque
 * @legacy: true if callback is tracked by function instead of callbackID
 * @callbackID: filled with callback ID
 * @serverFilter: true if server supports object filtering
 *
 * Internal function to add a callback from a virObjectEventCallbackListPtr
 */
static int
virObjectEventCallbackListAddID(virConnectPtr conn,
                                virObjectEventCallbackListPtr cbList,
                                unsigned char uuid[VIR_UUID_BUFLEN],
                                virObjectEventCallbackFilter filter,
                                void *filter_opaque,
                                virClassPtr klass,
                                int eventID,
                                virConnectObjectEventGenericCallback callback,
                                void *opaque,
                                virFreeCallback freecb,
                                bool legacy,
                                int *callbackID,
                                bool serverFilter)
{
    virObjectEventCallbackPtr event;
    int ret = -1;
    int remoteID = -1;

    VIR_DEBUG("conn=%p cblist=%p uuid=%p filter=%p filter_opaque=%p "
              "klass=%p eventID=%d callback=%p opaque=%p "
              "legacy=%d callbackID=%p serverFilter=%d",
              conn, cbList, uuid, filter, filter_opaque, klass, eventID,
              callback, opaque, legacy, callbackID, serverFilter);

    /* Check incoming */
    if (!cbList) {
        return -1;
    }

    /* If there is no additional filtering, then check if we already
     * have this callback on our list.  */
    if (!filter &&
        virObjectEventCallbackLookup(conn, cbList, uuid,
                                     klass, eventID, callback, legacy,
                                     serverFilter ? &remoteID : NULL) != -1) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("event callback already tracked"));
        return -1;
    }
    /* Allocate new event */
    if (VIR_ALLOC(event) < 0)
        goto cleanup;
    event->conn = virObjectRef(conn);
    *callbackID = event->callbackID = cbList->nextID++;
    event->cb = callback;
    event->klass = klass;
    event->eventID = eventID;
    event->opaque = opaque;
    event->freecb = freecb;
    event->remoteID = remoteID;

    /* Only need 'uuid' for matching; 'id' can change as domain
     * switches between running and shutoff, and 'name' can change in
     * Xen migration.  */
    if (uuid) {
        event->uuid_filter = true;
        memcpy(event->uuid, uuid, VIR_UUID_BUFLEN);
    }
    event->filter = filter;
    event->filter_opaque = filter_opaque;
    event->legacy = legacy;

    if (VIR_APPEND_ELEMENT(cbList->callbacks, cbList->count, event) < 0)
        goto cleanup;

    /* When additional filtering is being done, every client callback
     * is matched to exactly one server callback.  */
    if (filter) {
        ret = 1;
    } else {
        ret = virObjectEventCallbackListCount(conn, cbList, klass, eventID,
                                              uuid, serverFilter);
        if (serverFilter && remoteID < 0)
            ret++;
    }

 cleanup:
    if (event)
        virObjectUnref(event->conn);
    VIR_FREE(event);
    return ret;
}


/**
 * virObjectEventQueueClear:
 * @queue: pointer to the queue
 *
 * Removes all elements from the queue
 */
static void
virObjectEventQueueClear(virObjectEventQueuePtr queue)
{
    size_t i;
    if (!queue)
        return;

    for (i = 0; i < queue->count; i++) {
        virObjectUnref(queue->events[i]);
    }
    VIR_FREE(queue->events);
    queue->count = 0;
}

/**
 * virObjectEventQueueFree:
 * @queue: pointer to the queue
 *
 * Free the memory in the queue. We process this like a list here
 */
static void
virObjectEventQueueFree(virObjectEventQueuePtr queue)
{
    if (!queue)
        return;

    virObjectEventQueueClear(queue);
    VIR_FREE(queue);
}

static virObjectEventQueuePtr
virObjectEventQueueNew(void)
{
    virObjectEventQueuePtr ret;

    ignore_value(VIR_ALLOC(ret));
    return ret;
}


/**
 * virObjectEventStateLock:
 * @state: the event state object
 *
 * Lock event state before calling functions from object_event_private.h.
 */
static void
virObjectEventStateLock(virObjectEventStatePtr state)
{
    virMutexLock(&state->lock);
}


/**
 * virObjectEventStateUnlock:
 * @state: the event state object
 *
 * Unlock event state after calling functions from object_event_private.h.
 */
static void
virObjectEventStateUnlock(virObjectEventStatePtr state)
{
    virMutexUnlock(&state->lock);
}


/**
 * virObjectEventStateFree:
 * @list: virObjectEventStatePtr to free
 *
 * Free a virObjectEventStatePtr and its members, and unregister the timer.
 */
void
virObjectEventStateFree(virObjectEventStatePtr state)
{
    if (!state)
        return;

    virObjectEventCallbackListFree(state->callbacks);
    virObjectEventQueueFree(state->queue);

    if (state->timer != -1)
        virEventRemoveTimeout(state->timer);

    virMutexDestroy(&state->lock);
    VIR_FREE(state);
}


static void virObjectEventStateFlush(virObjectEventStatePtr state);


/**
 * virObjectEventTimer:
 * @timer: id of the event loop timer
 * @opaque: the event state object
 *
 * Register this function with the event state as its opaque data as
 * the callback of a periodic timer on the event loop, in order to
 * flush the callback queue.
 */
static void
virObjectEventTimer(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virObjectEventStatePtr state = opaque;

    virObjectEventStateFlush(state);
}


/**
 * virObjectEventStateNew:
 *
 * Allocate a new event state object.
 */
virObjectEventStatePtr
virObjectEventStateNew(void)
{
    virObjectEventStatePtr state = NULL;

    if (VIR_ALLOC(state) < 0)
        goto error;

    if (virMutexInit(&state->lock) < 0) {
        virReportSystemError(errno, "%s",
                             _("unable to initialize state mutex"));
        VIR_FREE(state);
        goto error;
    }

    if (VIR_ALLOC(state->callbacks) < 0)
        goto error;

    if (!(state->queue = virObjectEventQueueNew()))
        goto error;

    state->timer = -1;

    return state;

 error:
    virObjectEventStateFree(state);
    return NULL;
}


/**
 * virObjectEventNew:
 * @klass: subclass of event to be created
 * @dispatcher: callback for dispatching the particular subclass of event
 * @eventID: id of the event
 * @id: id of the object the event describes, or 0
 * @name: name of the object the event describes
 * @uuid: uuid of the object the event describes
 *
 * Create a new event, with the information common to all events.
 */
void *
virObjectEventNew(virClassPtr klass,
                  virObjectEventDispatchFunc dispatcher,
                  int eventID,
                  int id,
                  const char *name,
                  const unsigned char *uuid)
{
    virObjectEventPtr event;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!virClassIsDerivedFrom(klass, virObjectEventClass)) {
        virReportInvalidArg(klass,
                            _("Class %s must derive from virObjectEvent"),
                            virClassName(klass));
        return NULL;
    }

    if (!(event = virObjectNew(klass)))
        return NULL;

    event->dispatch = dispatcher;
    event->eventID = eventID;
    event->remoteID = -1;

    if (VIR_STRDUP(event->meta.name, name) < 0) {
        VIR_FREE(event);
        return NULL;
    }
    event->meta.id = id;
    memcpy(event->meta.uuid, uuid, VIR_UUID_BUFLEN);

    VIR_DEBUG("obj=%p", event);
    return event;
}


/**
 * virObjectEventQueuePush:
 * @evtQueue: the object event queue
 * @event: the event to add
 *
 * Internal function to push to the back of a virObjectEventQueue
 *
 * Returns: 0 on success, -1 on failure
 */
static int
virObjectEventQueuePush(virObjectEventQueuePtr evtQueue,
                        virObjectEventPtr event)
{
    if (!evtQueue)
        return -1;

    if (VIR_APPEND_ELEMENT(evtQueue->events, evtQueue->count, event) < 0)
        return -1;
    return 0;
}


static bool
virObjectEventDispatchMatchCallback(virObjectEventPtr event,
                                    virObjectEventCallbackPtr cb)
{
    if (!cb)
        return false;
    if (cb->deleted)
        return false;
    if (!virObjectIsClass(event, cb->klass))
        return false;
    if (cb->eventID != event->eventID)
        return false;
    if (cb->remoteID != event->remoteID)
        return false;

    if (cb->filter && !(cb->filter)(cb->conn, event, cb->filter_opaque))
        return false;

    if (cb->uuid_filter) {
        /* Deliberately ignoring 'id' for matching, since that
         * will cause problems when a domain switches between
         * running & shutoff states & ignoring 'name' since
         * Xen sometimes renames guests during migration, thus
         * leaving 'uuid' as the only truly reliable ID we can use. */

        return memcmp(event->meta.uuid, cb->uuid, VIR_UUID_BUFLEN) == 0;
    }
    return true;
}


static void
virObjectEventStateDispatchCallbacks(virObjectEventStatePtr state,
                                     virObjectEventPtr event,
                                     virObjectEventCallbackListPtr callbacks)
{
    size_t i;
    /* Cache this now, since we may be dropping the lock,
       and have more callbacks added. We're guaranteed not
       to have any removed */
    size_t cbCount = callbacks->count;

    for (i = 0; i < cbCount; i++) {
        virObjectEventCallbackPtr cb = callbacks->callbacks[i];

        if (!virObjectEventDispatchMatchCallback(event, cb))
            continue;

        /* Drop the lock whle dispatching, for sake of re-entrancy */
        virObjectEventStateUnlock(state);
        event->dispatch(cb->conn, event, cb->cb, cb->opaque);
        virObjectEventStateLock(state);
    }
}


static void
virObjectEventStateQueueDispatch(virObjectEventStatePtr state,
                                 virObjectEventQueuePtr queue,
                                 virObjectEventCallbackListPtr callbacks)
{
    size_t i;

    for (i = 0; i < queue->count; i++) {
        virObjectEventStateDispatchCallbacks(state, queue->events[i],
                                             callbacks);
        virObjectUnref(queue->events[i]);
    }
    VIR_FREE(queue->events);
    queue->count = 0;
}


/**
 * virObjectEventStateQueueRemote:
 * @state: the event state object
 * @event: event to add to the queue
 * @remoteID: limit dispatch to callbacks with the same remote id
 *
 * Adds @event to the queue of events to be dispatched at the next
 * safe moment.  The caller should no longer use @event after this
 * call.  If @remoteID is non-negative, the event will only be sent to
 * callbacks where virObjectEventStateSetRemote() registered a remote
 * id.
 */
void
virObjectEventStateQueueRemote(virObjectEventStatePtr state,
                               virObjectEventPtr event,
                               int remoteID)
{
    if (state->timer < 0) {
        virObjectUnref(event);
        return;
    }

    virObjectEventStateLock(state);

    event->remoteID = remoteID;
    if (virObjectEventQueuePush(state->queue, event) < 0) {
        VIR_DEBUG("Error adding event to queue");
        virObjectUnref(event);
    }

    if (state->queue->count == 1)
        virEventUpdateTimeout(state->timer, 0);
    virObjectEventStateUnlock(state);
}


/**
 * virObjectEventStateQueue:
 * @state: the event state object
 * @event: event to add to the queue
 *
 * Adds @event to the queue of events to be dispatched at the next
 * safe moment.  The caller should no longer use @event after this
 * call.
 */
void
virObjectEventStateQueue(virObjectEventStatePtr state,
                         virObjectEventPtr event)
{
    virObjectEventStateQueueRemote(state, event, -1);
}


static void
virObjectEventStateFlush(virObjectEventStatePtr state)
{
    virObjectEventQueue tempQueue;

    virObjectEventStateLock(state);
    state->isDispatching = true;

    /* Copy the queue, so we're reentrant safe when dispatchFunc drops the
     * driver lock */
    tempQueue.count = state->queue->count;
    tempQueue.events = state->queue->events;
    state->queue->count = 0;
    state->queue->events = NULL;
    virEventUpdateTimeout(state->timer, -1);

    virObjectEventStateQueueDispatch(state,
                                     &tempQueue,
                                     state->callbacks);

    /* Purge any deleted callbacks */
    virObjectEventCallbackListPurgeMarked(state->callbacks);

    state->isDispatching = false;
    virObjectEventStateUnlock(state);
}


/**
 * virObjectEventStateRegisterID:
 * @conn: connection to associate with callback
 * @state: domain event state
 * @uuid: uuid of the object for event filtering
 * @klass: the base event class
 * @eventID: ID of the event type to register for
 * @cb: function to invoke when event occurs
 * @opaque: data blob to pass to @callback
 * @freecb: callback to free @opaque
 * @legacy: true if callback is tracked by function instead of callbackID
 * @callbackID: filled with callback ID
 * @serverFilter: true if server supports object filtering
 *
 * Register the function @cb with connection @conn, from @state, for
 * events of type @eventID, and return the registration handle in
 * @callbackID.
 *
 * The return value is only important when registering client-side
 * mirroring of remote events (since the public API is documented to
 * return the callbackID rather than a count).  A return of 1 means
 * that this is the first use of this type of event, so a remote event
 * must be enabled; a return larger than 1 means that an existing
 * remote event can already feed this callback.  If @serverFilter is
 * false, the return count assumes that a single global remote feeds
 * both generic and per-object callbacks, and that the event queue
 * will be fed with virObjectEventStateQueue().  If it is true, then
 * the return count assumes that the remote side is capable of per-
 * object filtering; the user must call virObjectEventStateSetRemote()
 * to record the remote id, and queue events with
 * virObjectEventStateQueueRemote().
 *
 * Returns: the number of callbacks now registered, or -1 on error.
 */
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
                              bool serverFilter)
{
    int ret = -1;

    virObjectEventStateLock(state);

    if ((state->callbacks->count == 0) &&
        (state->timer == -1) &&
        (state->timer = virEventAddTimeout(-1,
                                           virObjectEventTimer,
                                           state,
                                           NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not initialize domain event timer"));
        goto cleanup;
    }

    ret = virObjectEventCallbackListAddID(conn, state->callbacks,
                                          uuid, filter, filter_opaque,
                                          klass, eventID,
                                          cb, opaque, freecb,
                                          legacy, callbackID, serverFilter);

    if (ret == -1 &&
        state->callbacks->count == 0 &&
        state->timer != -1) {
        virEventRemoveTimeout(state->timer);
        state->timer = -1;
    }

 cleanup:
    virObjectEventStateUnlock(state);
    return ret;
}


/**
 * virObjectEventStateDeregisterID:
 * @conn: connection to associate with callback
 * @state: object event state
 * @callbackID: ID of the function to remove from event
 *
 * Unregister the function @callbackID with connection @conn,
 * from @state, for events.
 *
 * Returns: the number of callbacks still registered, or -1 on error
 */
int
virObjectEventStateDeregisterID(virConnectPtr conn,
                                virObjectEventStatePtr state,
                                int callbackID)
{
    int ret;

    virObjectEventStateLock(state);
    if (state->isDispatching)
        ret = virObjectEventCallbackListMarkDeleteID(conn,
                                                     state->callbacks,
                                                     callbackID);
    else
        ret = virObjectEventCallbackListRemoveID(conn,
                                                 state->callbacks, callbackID);

    if (state->callbacks->count == 0 &&
        state->timer != -1) {
        virEventRemoveTimeout(state->timer);
        state->timer = -1;
        virObjectEventQueueClear(state->queue);
    }

    virObjectEventStateUnlock(state);
    return ret;
}

/**
 * virObjectEventStateCallbackID:
 * @conn: connection associated with callback
 * @state: object event state
 * @klass: the base event class
 * @eventID: the event ID
 * @callback: function registered as a callback
 * @remoteID: optional output, containing resulting remote id
 *
 * Returns the callbackID of @callback, or -1 with an error issued if the
 * function is not currently registered.  This only finds functions
 * registered via virConnectDomainEventRegister, even if modern style
 * virConnectDomainEventRegisterAny also registers the same callback.
 */
int
virObjectEventStateCallbackID(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              virClassPtr klass,
                              int eventID,
                              virConnectObjectEventGenericCallback callback,
                              int *remoteID)
{
    int ret = -1;

    virObjectEventStateLock(state);
    ret = virObjectEventCallbackLookup(conn, state->callbacks, NULL,
                                       klass, eventID, callback, true,
                                       remoteID);
    virObjectEventStateUnlock(state);

    if (ret < 0)
        virReportError(VIR_ERR_INVALID_ARG,
                       _("event callback function %p not registered"),
                       callback);
    return ret;
}


/**
 * virObjectEventStateEventID:
 * @conn: connection associated with the callback
 * @state: object event state
 * @callbackID: the callback to query
 * @remoteID: optionally output remote ID of the callback
 *
 * Query what event ID type is associated with the callback
 * @callbackID for connection @conn.  If @remoteID is non-null, it
 * will be set to the remote id previously registered with
 * virObjectEventStateSetRemote().
 *
 * Returns 0 on success, -1 on error
 */
int
virObjectEventStateEventID(virConnectPtr conn,
                           virObjectEventStatePtr state,
                           int callbackID,
                           int *remoteID)
{
    int ret = -1;
    size_t i;
    virObjectEventCallbackListPtr cbList = state->callbacks;

    virObjectEventStateLock(state);
    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->deleted)
            continue;

        if (cb->callbackID == callbackID && cb->conn == conn) {
            if (remoteID)
                *remoteID = cb->remoteID;
            ret = cb->eventID;
            break;
        }
    }
    virObjectEventStateUnlock(state);

    if (ret < 0)
        virReportError(VIR_ERR_INVALID_ARG,
                       _("event callback id %d not registered"),
                       callbackID);
    return ret;
}


/**
 * virObjectEventStateSetRemote:
 * @conn: connection associated with the callback
 * @state: object event state
 * @callbackID: the callback to adjust
 * @remoteID: the remote ID to associate with the callback
 *
 * Update @callbackID for connection @conn to record that it is now
 * tied to @remoteID, and will therefore only match events that are
 * sent with virObjectEventStateQueueRemote() with the same remote ID.
 * Silently does nothing if @callbackID is invalid.
 */
void
virObjectEventStateSetRemote(virConnectPtr conn,
                             virObjectEventStatePtr state,
                             int callbackID,
                             int remoteID)
{
    size_t i;

    virObjectEventStateLock(state);
    for (i = 0; i < state->callbacks->count; i++) {
        virObjectEventCallbackPtr cb = state->callbacks->callbacks[i];

        if (cb->deleted)
            continue;

        if (cb->callbackID == callbackID && cb->conn == conn) {
            cb->remoteID = remoteID;
            break;
        }
    }
    virObjectEventStateUnlock(state);
}
