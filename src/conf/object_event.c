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

struct _virObjectEventQueue {
    size_t count;
    virObjectEventPtr *events;
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
    int ret = 0;
    size_t i;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->callbackID == callbackID && cb->conn == conn) {
            if (cb->freecb)
                (*cb->freecb)(cb->opaque);
            virObjectUnref(cb->conn);
            if (cb->meta)
                VIR_FREE(cb->meta->name);
            VIR_FREE(cb->meta);
            VIR_FREE(cb);
            VIR_DELETE_ELEMENT(cbList->callbacks, i, cbList->count);

            for (i = 0; i < cbList->count; i++) {
                if (!cbList->callbacks[i]->deleted)
                    ret++;
            }
            return ret;
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("could not find event callback for removal"));
    return -1;
}


static int
virObjectEventCallbackListMarkDeleteID(virConnectPtr conn,
                                       virObjectEventCallbackListPtr cbList,
                                       int callbackID)
{
    int ret = 0;
    size_t i;

    for (i = 0; i < cbList->count; i++) {
        if (cbList->callbacks[i]->callbackID == callbackID &&
            cbList->callbacks[i]->conn == conn) {
            cbList->callbacks[i]->deleted = true;
            for (i = 0; i < cbList->count; i++) {
                if (!cbList->callbacks[i]->deleted)
                    ret++;
            }
            return ret;
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("could not find event callback for deletion"));
    return -1;
}


static int
virObjectEventCallbackListPurgeMarked(virObjectEventCallbackListPtr cbList)
{
    int old_count = cbList->count;
    int n;
    for (n = 0; n < cbList->count; n++) {
        if (cbList->callbacks[n]->deleted) {
            virFreeCallback freecb = cbList->callbacks[n]->freecb;
            if (freecb)
                (*freecb)(cbList->callbacks[n]->opaque);
            virObjectUnref(cbList->callbacks[n]->conn);
            VIR_FREE(cbList->callbacks[n]);

            if (n < (cbList->count - 1))
                memmove(cbList->callbacks + n,
                        cbList->callbacks + n + 1,
                        sizeof(*(cbList->callbacks)) *
                                (cbList->count - (n + 1)));
            cbList->count--;
            n--;
        }
    }
    if (cbList->count < old_count &&
        VIR_REALLOC_N(cbList->callbacks, cbList->count) < 0) {
        ; /* Failure to reduce memory allocation isn't fatal */
    }
    return 0;
}


/**
 * virObjectEventCallbackListAddID:
 * @conn: pointer to the connection
 * @cbList: the list
 * @uuid: the uuid of the object to filter on
 * @name: the name of the object to filter on
 * @id: the ID of the object to filter on
 * @klass: the base event class
 * @eventID: the event ID
 * @callback: the callback to add
 * @opaque: opaque data to pass to @callback
 * @freecb: callback to free @opaque
 * @callbackID: filled with callback ID
 *
 * Internal function to add a callback from a virObjectEventCallbackListPtr
 */
int
virObjectEventCallbackListAddID(virConnectPtr conn,
                                virObjectEventCallbackListPtr cbList,
                                unsigned char uuid[VIR_UUID_BUFLEN],
                                const char *name,
                                int id,
                                virClassPtr klass,
                                int eventID,
                                virConnectObjectEventGenericCallback callback,
                                void *opaque,
                                virFreeCallback freecb,
                                int *callbackID)
{
    virObjectEventCallbackPtr event;
    size_t i;
    int ret = -1;

    VIR_DEBUG("conn=%p cblist=%p uuid=%p name=%s id=%d "
              "klass=%p eventID=%d callback=%p opaque=%p",
              conn, cbList, uuid, name, id, klass, eventID,
              callback, opaque);

    /* Check incoming */
    if (!cbList) {
        return -1;
    }

    /* check if we already have this callback on our list */
    for (i = 0; i < cbList->count; i++) {
        if (cbList->callbacks[i]->cb == VIR_OBJECT_EVENT_CALLBACK(callback) &&
            cbList->callbacks[i]->klass == klass &&
            cbList->callbacks[i]->eventID == eventID &&
            cbList->callbacks[i]->conn == conn &&
            ((uuid && cbList->callbacks[i]->meta &&
              memcmp(cbList->callbacks[i]->meta->uuid,
                     uuid, VIR_UUID_BUFLEN) == 0) ||
             (!uuid && !cbList->callbacks[i]->meta))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("event callback already tracked"));
            return -1;
        }
    }
    /* Allocate new event */
    if (VIR_ALLOC(event) < 0)
        goto cleanup;
    event->conn = virObjectRef(conn);
    event->callbackID = cbList->nextID++;
    event->cb = callback;
    event->klass = klass;
    event->eventID = eventID;
    event->opaque = opaque;
    event->freecb = freecb;

    if (name && uuid && id > 0) {
        if (VIR_ALLOC(event->meta) < 0)
            goto cleanup;
        if (VIR_STRDUP(event->meta->name, name) < 0)
            goto cleanup;
        memcpy(event->meta->uuid, uuid, VIR_UUID_BUFLEN);
        event->meta->id = id;
    }

    if (callbackID)
        *callbackID = event->callbackID;

    if (VIR_APPEND_ELEMENT(cbList->callbacks, cbList->count, event) < 0)
        goto cleanup;

    for (ret = 0, i = 0; i < cbList->count; i++) {
        if (cbList->callbacks[i]->klass == klass &&
            cbList->callbacks[i]->eventID == eventID &&
            cbList->callbacks[i]->conn == conn &&
            !cbList->callbacks[i]->deleted)
            ret++;
    }

cleanup:
    if (event) {
        virObjectUnref(event->conn);
        if (event->meta)
            VIR_FREE(event->meta->name);
        VIR_FREE(event->meta);
    }
    VIR_FREE(event);
    return ret;
}


static int
virObjectEventCallbackListEventID(virConnectPtr conn,
                                  virObjectEventCallbackListPtr cbList,
                                  int callbackID)
{
    size_t i;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallbackPtr cb = cbList->callbacks[i];

        if (cb->deleted)
            continue;

        if (cb->callbackID == callbackID && cb->conn == conn)
            return cb->eventID;
    }

    return -1;
}


/**
 * virObjectEventQueueClear:
 * @queue: pointer to the queue
 *
 * Removes all elements from the queue
 */
void
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
void
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
void
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
void
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

    if (cb->meta) {
        /* Deliberately ignoring 'id' for matching, since that
         * will cause problems when a domain switches between
         * running & shutoff states & ignoring 'name' since
         * Xen sometimes renames guests during migration, thus
         * leaving 'uuid' as the only truly reliable ID we can use. */

        return memcmp(event->meta.uuid, cb->meta->uuid, VIR_UUID_BUFLEN) == 0;
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
    if (state->timer < 0) {
        virObjectUnref(event);
        return;
    }

    virObjectEventStateLock(state);

    if (virObjectEventQueuePush(state->queue, event) < 0) {
        VIR_DEBUG("Error adding event to queue");
        virObjectUnref(event);
    }

    if (state->queue->count == 1)
        virEventUpdateTimeout(state->timer, 0);
    virObjectEventStateUnlock(state);
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
 * @name: name of the object for event filtering
 * @id: id of the object for event filtering, or 0
 * @klass: the base event class
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
virObjectEventStateRegisterID(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              unsigned char *uuid,
                              const char *name,
                              int id,
                              virClassPtr klass,
                              int eventID,
                              virConnectObjectEventGenericCallback cb,
                              void *opaque,
                              virFreeCallback freecb,
                              int *callbackID)
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
                                          uuid, name, id, klass, eventID,
                                          cb, opaque, freecb,
                                          callbackID);

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
 * virObjectEventStateEventID:
 * @conn: connection associated with the callback
 * @state: object event state
 * @callbackID: the callback to query
 *
 * Query what event ID type is associated with the
 * callback @callbackID for connection @conn
 *
 * Returns 0 on success, -1 on error
 */
int
virObjectEventStateEventID(virConnectPtr conn,
                           virObjectEventStatePtr state,
                           int callbackID)
{
    int ret;

    virObjectEventStateLock(state);
    ret = virObjectEventCallbackListEventID(conn,
                                            state->callbacks, callbackID);
    virObjectEventStateUnlock(state);
    return ret;
}
