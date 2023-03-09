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
 */

#include <config.h>

#include "object_event.h"
#include "object_event_private.h"
#include "virlog.h"
#include "viralloc.h"
#include "virerror.h"
#include "virobject.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("conf.object_event");

struct _virObjectEventCallback {
    int callbackID;
    virClass *klass;
    int eventID;
    virConnectPtr conn;
    int remoteID;
    bool key_filter;
    char *key;
    virObjectEventCallbackFilter filter;
    void *filter_opaque;
    virConnectObjectEventGenericCallback cb;
    void *opaque;
    virFreeCallback freecb;
    bool deleted;
    bool legacy; /* true if end user does not know callbackID */
};
typedef struct _virObjectEventCallback virObjectEventCallback;

struct _virObjectEventCallbackList {
    unsigned int nextID;
    size_t count;
    virObjectEventCallback **callbacks;
};

struct _virObjectEventQueue {
    size_t count;
    virObjectEvent **events;
};
typedef struct _virObjectEventQueue virObjectEventQueue;

struct _virObjectEventState {
    virObjectLockable parent;
    /* The list of domain event callbacks */
    virObjectEventCallbackList *callbacks;
    /* The queue of object events */
    virObjectEventQueue *queue;
    /* Timer for flushing events queue */
    int timer;
    /* Flag if we're in process of dispatching */
    bool isDispatching;
};

static virClass *virObjectEventClass;
static virClass *virObjectEventStateClass;

static void virObjectEventDispose(void *obj);
static void virObjectEventStateDispose(void *obj);

static int
virObjectEventOnceInit(void)
{
    if (!VIR_CLASS_NEW(virObjectEventState, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virObjectEvent, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virObjectEvent);

/**
 * virClassForObjectEvent:
 *
 * Return the class object to be used as a parent when creating an
 * event subclass.
 */
virClass *
virClassForObjectEvent(void)
{
    if (virObjectEventInitialize() < 0)
        return NULL;
    return virObjectEventClass;
}


static void
virObjectEventDispose(void *obj)
{
    virObjectEvent *event = obj;

    VIR_DEBUG("obj=%p", event);

    g_free(event->meta.name);
    g_free(event->meta.key);
}

/**
 * virObjectEventCallbackFree:
 * @list: event callback to free
 *
 * Free the memory in the domain event callback
 */
static void
virObjectEventCallbackFree(virObjectEventCallback *cb)
{
    if (!cb)
        return;

    virObjectUnref(cb->conn);
    g_free(cb->key);
    g_free(cb);
}

/**
 * virObjectEventCallbackListFree:
 * @list: event callback list head
 *
 * Free the memory in the domain event callback list
 */
static void
virObjectEventCallbackListFree(virObjectEventCallbackList *list)
{
    size_t i;
    if (!list)
        return;

    for (i = 0; i < list->count; i++) {
        virFreeCallback freecb = list->callbacks[i]->freecb;
        if (freecb)
            (*freecb)(list->callbacks[i]->opaque);
        g_free(list->callbacks[i]);
    }
    g_free(list->callbacks);
    g_free(list);
}


/**
 * virObjectEventCallbackListCount:
 * @conn: pointer to the connection
 * @cbList: the list
 * @klass: the base event class
 * @eventID: the event ID
 * @key: optional key of per-object filtering
 * @serverFilter: true if server supports object filtering
 *
 * Internal function to count how many callbacks remain registered for
 * the given @eventID and @key; knowing this allows the client side
 * of the remote driver know when it must send an RPC to adjust the
 * callbacks on the server.  When @serverFilter is false, this function
 * returns a count that includes both global and per-object callbacks,
 * since the remote side will use a single global event to feed both.
 * When true, the count is limited to the callbacks with the same
 * @key, and where a remoteID has already been set on the callback
 * with virObjectEventStateSetRemote().  Note that this function
 * intentionally ignores the legacy field, since RPC calls use only a
 * single callback on the server to manage both legacy and modern
 * global domain lifecycle events.
 */
static int
virObjectEventCallbackListCount(virConnectPtr conn,
                                virObjectEventCallbackList *cbList,
                                virClass *klass,
                                int eventID,
                                const char *key,
                                bool serverFilter)
{
    size_t i;
    int ret = 0;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallback *cb = cbList->callbacks[i];

        if (cb->filter)
            continue;
        if (cb->klass == klass &&
            cb->eventID == eventID &&
            cb->conn == conn &&
            !cb->deleted &&
            (!serverFilter ||
             (cb->remoteID >= 0 &&
              ((key && cb->key_filter && STREQ(cb->key, key)) ||
               (!key && !cb->key_filter)))))
            ret++;
    }
    return ret;
}

/**
 * virObjectEventCallbackListRemoveID:
 * @conn: pointer to the connection
 * @cbList: the list
 * @callback: the callback to remove
 * @doFreeCb: Inhibit calling the freecb
 *
 * Internal function to remove a callback from a virObjectEventCallbackList *
 */
static int
virObjectEventCallbackListRemoveID(virConnectPtr conn,
                                   virObjectEventCallbackList *cbList,
                                   int callbackID,
                                   bool doFreeCb)
{
    size_t i;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallback *cb = cbList->callbacks[i];

        if (cb->callbackID == callbackID && cb->conn == conn) {
            int ret;

            ret = cb->filter ? 0 :
                (virObjectEventCallbackListCount(conn, cbList, cb->klass,
                                                 cb->eventID,
                                                 cb->key_filter ? cb->key : NULL,
                                                 cb->remoteID >= 0) - 1);

            /* @doFreeCb inhibits calling @freecb from error paths in
             * register functions to ensure the caller of a failed register
             * function won't end up with a double free error */
            if (doFreeCb && cb->freecb)
                (*cb->freecb)(cb->opaque);
            virObjectEventCallbackFree(cb);
            VIR_DELETE_ELEMENT(cbList->callbacks, i, cbList->count);
            return ret;
        }
    }

    virReportError(VIR_ERR_INVALID_ARG,
                   _("could not find event callback %1$d for deletion"),
                   callbackID);
    return -1;
}


static int
virObjectEventCallbackListMarkDeleteID(virConnectPtr conn,
                                       virObjectEventCallbackList *cbList,
                                       int callbackID)
{
    size_t i;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallback *cb = cbList->callbacks[i];

        if (cb->callbackID == callbackID && cb->conn == conn) {
            cb->deleted = true;
            return cb->filter ? 0 :
                virObjectEventCallbackListCount(conn, cbList, cb->klass,
                                                cb->eventID,
                                                cb->key_filter ? cb->key : NULL,
                                                cb->remoteID >= 0);
        }
    }

    virReportError(VIR_ERR_INVALID_ARG,
                   _("could not find event callback %1$d for deletion"),
                   callbackID);
    return -1;
}


static int
virObjectEventCallbackListPurgeMarked(virObjectEventCallbackList *cbList)
{
    size_t n;
    for (n = 0; n < cbList->count; n++) {
        if (cbList->callbacks[n]->deleted) {
            virFreeCallback freecb = cbList->callbacks[n]->freecb;
            if (freecb)
                (*freecb)(cbList->callbacks[n]->opaque);
            virObjectEventCallbackFree(cbList->callbacks[n]);

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
 * @key: the key of the object to filter on
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
                             virObjectEventCallbackList *cbList,
                             const char *key,
                             virClass *klass,
                             int eventID,
                             virConnectObjectEventGenericCallback callback,
                             bool legacy,
                             int *remoteID)
{
    size_t i;

    if (remoteID)
        *remoteID = -1;

    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallback *cb = cbList->callbacks[i];

        if (cb->deleted)
            continue;
        if (cb->klass == klass &&
            cb->eventID == eventID &&
            cb->conn == conn &&
            ((key && cb->key_filter && STREQ(cb->key, key)) ||
             (!key && !cb->key_filter))) {
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
 * @key: the optional key of the object to filter on
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
 * Internal function to add a callback from a virObjectEventCallbackList *
 */
static int
virObjectEventCallbackListAddID(virConnectPtr conn,
                                virObjectEventCallbackList *cbList,
                                const char *key,
                                virObjectEventCallbackFilter filter,
                                void *filter_opaque,
                                virClass *klass,
                                int eventID,
                                virConnectObjectEventGenericCallback callback,
                                void *opaque,
                                virFreeCallback freecb,
                                bool legacy,
                                int *callbackID,
                                bool serverFilter)
{
    virObjectEventCallback *cb;
    int ret = -1;
    int remoteID = -1;

    VIR_DEBUG("conn=%p cblist=%p key=%p filter=%p filter_opaque=%p "
              "klass=%p eventID=%d callback=%p opaque=%p "
              "legacy=%d callbackID=%p serverFilter=%d",
              conn, cbList, key, filter, filter_opaque, klass, eventID,
              callback, opaque, legacy, callbackID, serverFilter);

    /* Check incoming */
    if (!cbList)
        return -1;

    /* If there is no additional filtering, then check if we already
     * have this callback on our list.  */
    if (!filter &&
        virObjectEventCallbackLookup(conn, cbList, key,
                                     klass, eventID, callback, legacy,
                                     serverFilter ? &remoteID : NULL) != -1) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("event callback already tracked"));
        return -1;
    }
    /* Allocate new cb */
    cb = g_new0(virObjectEventCallback, 1);
    cb->conn = virObjectRef(conn);
    *callbackID = cb->callbackID = cbList->nextID++;
    cb->cb = callback;
    cb->klass = klass;
    cb->eventID = eventID;
    cb->opaque = opaque;
    cb->freecb = freecb;
    cb->remoteID = remoteID;

    if (key) {
        cb->key_filter = true;
        cb->key = g_strdup(key);
    }
    cb->filter = filter;
    cb->filter_opaque = filter_opaque;
    cb->legacy = legacy;

    VIR_APPEND_ELEMENT(cbList->callbacks, cbList->count, cb);

    /* When additional filtering is being done, every client callback
     * is matched to exactly one server callback.  */
    if (filter) {
        ret = 1;
    } else {
        ret = virObjectEventCallbackListCount(conn, cbList, klass, eventID,
                                              key, serverFilter);
        if (serverFilter && remoteID < 0)
            ret++;
    }

    return ret;
}


/**
 * virObjectEventQueueClear:
 * @queue: pointer to the queue
 *
 * Removes all elements from the queue
 */
static void
virObjectEventQueueClear(virObjectEventQueue *queue)
{
    size_t i;
    if (!queue)
        return;

    for (i = 0; i < queue->count; i++)
        virObjectUnref(queue->events[i]);
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
virObjectEventQueueFree(virObjectEventQueue *queue)
{
    if (!queue)
        return;

    virObjectEventQueueClear(queue);
    g_free(queue);
}

static virObjectEventQueue *
virObjectEventQueueNew(void)
{
    return g_new0(virObjectEventQueue, 1);
}


/**
 * virObjectEventStateDispose:
 * @list: virObjectEventState * to free
 *
 * Free a virObjectEventState * and its members, and unregister the timer.
 */
static void
virObjectEventStateDispose(void *obj)
{
    virObjectEventState *state = obj;

    VIR_DEBUG("obj=%p", state);

    virObjectEventCallbackListFree(state->callbacks);
    virObjectEventQueueFree(state->queue);

    if (state->timer != -1)
        virEventRemoveTimeout(state->timer);
}


static void virObjectEventStateFlush(virObjectEventState *state);


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
virObjectEventTimer(int timer G_GNUC_UNUSED, void *opaque)
{
    virObjectEventState *state = opaque;

    virObjectEventStateFlush(state);
}


/**
 * virObjectEventStateNew:
 *
 * Allocate a new event state object.
 */
virObjectEventState *
virObjectEventStateNew(void)
{
    virObjectEventState *state = NULL;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(state = virObjectLockableNew(virObjectEventStateClass)))
        return NULL;

    state->callbacks = g_new0(virObjectEventCallbackList, 1);

    if (!(state->queue = virObjectEventQueueNew()))
        goto error;

    state->timer = -1;

    return state;

 error:
    virObjectUnref(state);
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
 * @key: key for per-object filtering
 *
 * Create a new event, with the information common to all events.
 */
void *
virObjectEventNew(virClass *klass,
                  virObjectEventDispatchFunc dispatcher,
                  int eventID,
                  int id,
                  const char *name,
                  const unsigned char *uuid,
                  const char *key)
{
    virObjectEvent *event;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!virClassIsDerivedFrom(klass, virObjectEventClass)) {
        virReportInvalidArg(klass,
                            _("Class %1$s must derive from virObjectEvent"),
                            virClassName(klass));
        return NULL;
    }

    if (!(event = virObjectNew(klass)))
        return NULL;

    event->dispatch = dispatcher;
    event->eventID = eventID;
    event->remoteID = -1;

    event->meta.name = g_strdup(name);
    event->meta.key = g_strdup(key);
    event->meta.id = id;
    if (uuid)
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
virObjectEventQueuePush(virObjectEventQueue *evtQueue,
                        virObjectEvent *event)
{
    if (!evtQueue)
        return -1;

    VIR_APPEND_ELEMENT(evtQueue->events, evtQueue->count, event);

    return 0;
}


static bool
virObjectEventDispatchMatchCallback(virObjectEvent *event,
                                    virObjectEventCallback *cb)
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

    if (cb->key_filter)
        return STREQ(event->meta.key, cb->key);
    return true;
}


static void
virObjectEventStateDispatchCallbacks(virObjectEventState *state,
                                     virObjectEvent *event,
                                     virObjectEventCallbackList *callbacks)
{
    size_t i;
    /* Cache this now, since we may be dropping the lock,
       and have more callbacks added. We're guaranteed not
       to have any removed */
    size_t cbCount = callbacks->count;

    for (i = 0; i < cbCount; i++) {
        virObjectEventCallback *cb = callbacks->callbacks[i];

        if (!virObjectEventDispatchMatchCallback(event, cb))
            continue;

        /* Drop the lock while dispatching, for sake of re-entrance */
        virObjectUnlock(state);
        event->dispatch(cb->conn, event, cb->cb, cb->opaque);
        virObjectLock(state);
    }
}


static void
virObjectEventStateQueueDispatch(virObjectEventState *state,
                                 virObjectEventQueue *queue,
                                 virObjectEventCallbackList *callbacks)
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
virObjectEventStateQueueRemote(virObjectEventState *state,
                               virObjectEvent *event,
                               int remoteID)
{
    if (!event)
        return;

    if (state->timer < 0) {
        virObjectUnref(event);
        return;
    }

    virObjectLock(state);

    event->remoteID = remoteID;
    if (virObjectEventQueuePush(state->queue, event) < 0) {
        VIR_DEBUG("Error adding event to queue");
        virObjectUnref(event);
    }

    if (state->queue->count == 1)
        virEventUpdateTimeout(state->timer, 0);
    virObjectUnlock(state);
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
virObjectEventStateQueue(virObjectEventState *state,
                         virObjectEvent *event)
{
    virObjectEventStateQueueRemote(state, event, -1);
}


static void
virObjectEventStateCleanupTimer(virObjectEventState *state, bool clear_queue)
{
    /* There are still some callbacks, keep the timer. */
    if (state->callbacks->count)
        return;

    /* The timer is not registered, nothing to do. */
    if (state->timer == -1)
        return;

    virEventRemoveTimeout(state->timer);
    state->timer = -1;

    if (clear_queue)
        virObjectEventQueueClear(state->queue);
}


static void
virObjectEventStateFlush(virObjectEventState *state)
{
    virObjectEventQueue tempQueue;

    /* We need to lock as well as ref due to the fact that we might
     * unref the state we're working on in this very function */
    virObjectRef(state);
    virObjectLock(state);
    state->isDispatching = true;

    /* Copy the queue, so we're reentrant safe when dispatchFunc drops the
     * driver lock */
    tempQueue.count = state->queue->count;
    tempQueue.events = g_steal_pointer(&state->queue->events);
    state->queue->count = 0;
    if (state->timer != -1)
        virEventUpdateTimeout(state->timer, -1);

    virObjectEventStateQueueDispatch(state,
                                     &tempQueue,
                                     state->callbacks);

    /* Purge any deleted callbacks */
    virObjectEventCallbackListPurgeMarked(state->callbacks);

    /* If we purged all callbacks, we need to remove the timeout as
     * well like virObjectEventStateDeregisterID() would do. */
    virObjectEventStateCleanupTimer(state, true);

    state->isDispatching = false;
    virObjectUnlock(state);
    virObjectUnref(state);
}


/**
 * virObjectEventStateRegisterID:
 * @conn: connection to associate with callback
 * @state: domain event state
 * @key: key of the object for event filtering
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
                              virObjectEventState *state,
                              const char *key,
                              virObjectEventCallbackFilter filter,
                              void *filter_opaque,
                              virClass *klass,
                              int eventID,
                              virConnectObjectEventGenericCallback cb,
                              void *opaque,
                              virFreeCallback freecb,
                              bool legacy,
                              int *callbackID,
                              bool serverFilter)
{
    int ret = -1;

    virObjectLock(state);

    if ((state->callbacks->count == 0) &&
        (state->timer == -1)) {
        if ((state->timer = virEventAddTimeout(-1,
                                               virObjectEventTimer,
                                               state,
                                               virObjectUnref)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("could not initialize domain event timer"));
            goto cleanup;
        }

        /* event loop has one reference, but we need one more for the
         * timer's opaque argument */
        virObjectRef(state);
    }

    ret = virObjectEventCallbackListAddID(conn, state->callbacks,
                                          key, filter, filter_opaque,
                                          klass, eventID,
                                          cb, opaque, freecb,
                                          legacy, callbackID, serverFilter);

    if (ret < 0)
        virObjectEventStateCleanupTimer(state, false);

 cleanup:
    virObjectUnlock(state);
    return ret;
}


/**
 * virObjectEventStateDeregisterID:
 * @conn: connection to associate with callback
 * @state: object event state
 * @callbackID: ID of the function to remove from event
 * @doFreeCb: Allow the calling of a freecb
 *
 * Unregister the function @callbackID with connection @conn,
 * from @state, for events. If @doFreeCb is false, then we
 * are being called from a remote call failure path for the
 * Event registration indicating a -1 return to the caller. The
 * caller wouldn't expect us to run their freecb function if it
 * exists, so we cannot do so.
 *
 * Returns: the number of callbacks still registered, or -1 on error
 */
int
virObjectEventStateDeregisterID(virConnectPtr conn,
                                virObjectEventState *state,
                                int callbackID,
                                bool doFreeCb)
{
    int ret;

    virObjectLock(state);
    if (state->isDispatching)
        ret = virObjectEventCallbackListMarkDeleteID(conn,
                                                     state->callbacks,
                                                     callbackID);
    else
        ret = virObjectEventCallbackListRemoveID(conn, state->callbacks,
                                                 callbackID, doFreeCb);

    virObjectEventStateCleanupTimer(state, true);

    virObjectUnlock(state);
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
                              virObjectEventState *state,
                              virClass *klass,
                              int eventID,
                              virConnectObjectEventGenericCallback callback,
                              int *remoteID)
{
    int ret = -1;

    virObjectLock(state);
    ret = virObjectEventCallbackLookup(conn, state->callbacks, NULL,
                                       klass, eventID, callback, true,
                                       remoteID);
    virObjectUnlock(state);

    if (ret < 0)
        virReportError(VIR_ERR_INVALID_ARG,
                       _("event callback function %1$p not registered"),
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
                           virObjectEventState *state,
                           int callbackID,
                           int *remoteID)
{
    int ret = -1;
    size_t i;
    virObjectEventCallbackList *cbList = state->callbacks;

    virObjectLock(state);
    for (i = 0; i < cbList->count; i++) {
        virObjectEventCallback *cb = cbList->callbacks[i];

        if (cb->deleted)
            continue;

        if (cb->callbackID == callbackID && cb->conn == conn) {
            if (remoteID)
                *remoteID = cb->remoteID;
            ret = cb->eventID;
            break;
        }
    }
    virObjectUnlock(state);

    if (ret < 0)
        virReportError(VIR_ERR_INVALID_ARG,
                       _("event callback id %1$d not registered"),
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
                             virObjectEventState *state,
                             int callbackID,
                             int remoteID)
{
    size_t i;

    virObjectLock(state);
    for (i = 0; i < state->callbacks->count; i++) {
        virObjectEventCallback *cb = state->callbacks->callbacks[i];

        if (cb->deleted)
            continue;

        if (cb->callbackID == callbackID && cb->conn == conn) {
            cb->remoteID = remoteID;
            break;
        }
    }
    virObjectUnlock(state);
}
