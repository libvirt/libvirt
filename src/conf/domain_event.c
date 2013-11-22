/*
 * domain_event.c: domain event queue processing helpers
 *
 * Copyright (C) 2010-2013 Red Hat, Inc.
 * Copyright (C) 2008 VirtualIron
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
#include "virlog.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define VIR_OBJECT_EVENT_CALLBACK(cb) ((virConnectObjectEventGenericCallback)(cb))

struct _virObjectMeta {
    int id;
    char *name;
    unsigned char uuid[VIR_UUID_BUFLEN];
};
typedef struct _virObjectMeta virObjectMeta;
typedef virObjectMeta *virObjectMetaPtr;

typedef struct _virObjectEventQueue virObjectEventQueue;
typedef virObjectEventQueue *virObjectEventQueuePtr;

struct _virObjectEventCallbackList {
    unsigned int nextID;
    unsigned int count;
    virObjectEventCallbackPtr *callbacks;
};
typedef struct _virObjectEventCallbackList virObjectEventCallbackList;
typedef virObjectEventCallbackList *virObjectEventCallbackListPtr;

struct _virObjectEventQueue {
    unsigned int count;
    virDomainEventPtr *events;
};

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



static virClassPtr virObjectEventClass;
static virClassPtr virDomainEventClass;
static virClassPtr virDomainEventLifecycleClass;
static virClassPtr virDomainEventRTCChangeClass;
static virClassPtr virDomainEventWatchdogClass;
static virClassPtr virDomainEventIOErrorClass;
static virClassPtr virDomainEventGraphicsClass;
static virClassPtr virDomainEventBlockJobClass;
static virClassPtr virDomainEventDiskChangeClass;
static virClassPtr virDomainEventTrayChangeClass;

static void virObjectEventDispose(void *obj);
static void virDomainEventDispose(void *obj);
static void virDomainEventLifecycleDispose(void *obj);
static void virDomainEventRTCChangeDispose(void *obj);
static void virDomainEventWatchdogDispose(void *obj);
static void virDomainEventIOErrorDispose(void *obj);
static void virDomainEventGraphicsDispose(void *obj);
static void virDomainEventBlockJobDispose(void *obj);
static void virDomainEventDiskChangeDispose(void *obj);
static void virDomainEventTrayChangeDispose(void *obj);

struct _virObjectEvent {
    virObject parent;
    int eventID;
};

struct _virDomainEvent {
    virObjectEvent parent;

    virObjectMeta meta;

    union {
        struct {
            /* In unit of 1024 bytes */
            unsigned long long actual;
        } balloonChange;
        struct {
            char *devAlias;
        } deviceRemoved;
    } data;
};

struct _virDomainEventLifecycle {
    virDomainEvent parent;

    int type;
    int detail;
};
typedef struct _virDomainEventLifecycle virDomainEventLifecycle;
typedef virDomainEventLifecycle *virDomainEventLifecyclePtr;

struct _virDomainEventRTCChange {
    virDomainEvent parent;

    long long offset;
};
typedef struct _virDomainEventRTCChange virDomainEventRTCChange;
typedef virDomainEventRTCChange *virDomainEventRTCChangePtr;

struct _virDomainEventWatchdog {
    virDomainEvent parent;

    int action;
};
typedef struct _virDomainEventWatchdog virDomainEventWatchdog;
typedef virDomainEventWatchdog *virDomainEventWatchdogPtr;

struct _virDomainEventIOError {
    virDomainEvent parent;

    char *srcPath;
    char *devAlias;
    int action;
    char *reason;
};
typedef struct _virDomainEventIOError virDomainEventIOError;
typedef virDomainEventIOError *virDomainEventIOErrorPtr;

struct _virDomainEventBlockJob {
    virDomainEvent parent;

    char *path;
    int type;
    int status;
};
typedef struct _virDomainEventBlockJob virDomainEventBlockJob;
typedef virDomainEventBlockJob *virDomainEventBlockJobPtr;

struct _virDomainEventGraphics {
    virDomainEvent parent;

    int phase;
    virDomainEventGraphicsAddressPtr local;
    virDomainEventGraphicsAddressPtr remote;
    char *authScheme;
    virDomainEventGraphicsSubjectPtr subject;
};
typedef struct _virDomainEventGraphics virDomainEventGraphics;
typedef virDomainEventGraphics *virDomainEventGraphicsPtr;

struct _virDomainEventDiskChange {
    virDomainEvent parent;

    char *oldSrcPath;
    char *newSrcPath;
    char *devAlias;
    int reason;
};
typedef struct _virDomainEventDiskChange virDomainEventDiskChange;
typedef virDomainEventDiskChange *virDomainEventDiskChangePtr;

struct _virDomainEventTrayChange {
    virDomainEvent parent;

    char *devAlias;
    int reason;
};
typedef struct _virDomainEventTrayChange virDomainEventTrayChange;
typedef virDomainEventTrayChange *virDomainEventTrayChangePtr;


static int virObjectEventOnceInit(void)
{
    if (!(virObjectEventClass =
          virClassNew(virClassForObject(),
                      "virObjectEvent",
                      sizeof(virObjectEvent),
                      virObjectEventDispose)))
        return -1;
    if (!(virDomainEventClass =
          virClassNew(virObjectEventClass,
                      "virDomainEvent",
                      sizeof(virDomainEvent),
                      virDomainEventDispose)))
        return -1;
    if (!(virDomainEventLifecycleClass =
          virClassNew(virDomainEventClass,
                      "virDomainEventLifecycle",
                      sizeof(virDomainEventLifecycle),
                      virDomainEventLifecycleDispose)))
        return -1;
    if (!(virDomainEventRTCChangeClass =
          virClassNew(virDomainEventClass,
                      "virDomainEventRTCChange",
                      sizeof(virDomainEventRTCChange),
                      virDomainEventRTCChangeDispose)))
        return -1;
    if (!(virDomainEventWatchdogClass =
          virClassNew(virDomainEventClass,
                      "virDomainEventWatchdog",
                      sizeof(virDomainEventWatchdog),
                      virDomainEventWatchdogDispose)))
        return -1;
    if (!(virDomainEventIOErrorClass =
          virClassNew(virDomainEventClass,
                      "virDomainEventIOError",
                      sizeof(virDomainEventIOError),
                      virDomainEventIOErrorDispose)))
        return -1;
    if (!(virDomainEventGraphicsClass =
          virClassNew(virDomainEventClass,
                      "virDomainEventGraphics",
                      sizeof(virDomainEventGraphics),
                      virDomainEventGraphicsDispose)))
        return -1;
    if (!(virDomainEventBlockJobClass =
          virClassNew(virDomainEventClass,
                      "virDomainEventBlockJob",
                      sizeof(virDomainEventBlockJob),
                      virDomainEventBlockJobDispose)))
        return -1;
    if (!(virDomainEventDiskChangeClass =
          virClassNew(virDomainEventClass,
                      "virDomainEventDiskChange",
                      sizeof(virDomainEventDiskChange),
                      virDomainEventDiskChangeDispose)))
        return -1;
    if (!(virDomainEventTrayChangeClass =
          virClassNew(virDomainEventClass,
                      "virDomainEventTrayChange",
                      sizeof(virDomainEventTrayChange),
                      virDomainEventTrayChangeDispose)))
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virObjectEvent)

static int virObjectEventGetEventID(void *anyobj)
{
    virObjectEventPtr obj = anyobj;

    if (!virObjectIsClass(obj, virObjectEventClass)) {
        VIR_WARN("Object %p (%s) is not a virObjectEvent instance",
                 obj, obj ? virClassName(obj->parent.klass) : "(unknown)");
        return -1;
    }
    return obj->eventID;
}

static void virObjectEventDispose(void *obj)
{
    virObjectEventPtr event = obj;

    VIR_DEBUG("obj=%p", event);
}

static void virDomainEventDispose(void *obj)
{
    virDomainEventPtr event = obj;

    VIR_DEBUG("obj=%p", event);

    switch (virObjectEventGetEventID(event)) {

    case VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED:
        VIR_FREE(event->data.deviceRemoved.devAlias);
        break;
    }

    VIR_FREE(event->meta.name);
}

static void virDomainEventLifecycleDispose(void *obj)
{
    virDomainEventLifecyclePtr event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void virDomainEventRTCChangeDispose(void *obj)
{
    virDomainEventRTCChangePtr event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void virDomainEventWatchdogDispose(void *obj)
{
    virDomainEventWatchdogPtr event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void virDomainEventIOErrorDispose(void *obj)
{
    virDomainEventIOErrorPtr event = obj;
    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->srcPath);
    VIR_FREE(event->devAlias);
    VIR_FREE(event->reason);
}

static void virDomainEventGraphicsDispose(void *obj)
{
    virDomainEventGraphicsPtr event = obj;
    VIR_DEBUG("obj=%p", event);

    if (event->local) {
        VIR_FREE(event->local->node);
        VIR_FREE(event->local->service);
        VIR_FREE(event->local);
    }
    if (event->remote) {
        VIR_FREE(event->remote->node);
        VIR_FREE(event->remote->service);
        VIR_FREE(event->remote);
    }
    VIR_FREE(event->authScheme);
    if (event->subject) {
        size_t i;
        for (i = 0; i < event->subject->nidentity; i++) {
            VIR_FREE(event->subject->identities[i].type);
            VIR_FREE(event->subject->identities[i].name);
        }
        VIR_FREE(event->subject);
    }
}

static void virDomainEventBlockJobDispose(void *obj)
{
    virDomainEventBlockJobPtr event = obj;
    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->path);
}

static void virDomainEventDiskChangeDispose(void *obj)
{
    virDomainEventDiskChangePtr event = obj;
    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->oldSrcPath);
    VIR_FREE(event->newSrcPath);
    VIR_FREE(event->devAlias);
}

static void virDomainEventTrayChangeDispose(void *obj)
{
    virDomainEventTrayChangePtr event = obj;
    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->devAlias);
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

    for (i=0; i<list->count; i++) {
        virFreeCallback freecb = list->callbacks[i]->freecb;
        if (freecb)
            (*freecb)(list->callbacks[i]->opaque);
        VIR_FREE(list->callbacks[i]);
    }
    VIR_FREE(list->callbacks);
    VIR_FREE(list);
}


/**
 * virDomainEventCallbackListRemove:
 * @conn: pointer to the connection
 * @cbList: the list
 * @callback: the callback to remove
 *
 * Internal function to remove a callback from a virObjectEventCallbackListPtr
 */
static int
virDomainEventCallbackListRemove(virConnectPtr conn,
                                 virObjectEventCallbackListPtr cbList,
                                 virConnectDomainEventCallback callback)
{
    int ret = 0;
    size_t i;
    for (i = 0; i < cbList->count; i++) {
        if (cbList->callbacks[i]->cb == VIR_OBJECT_EVENT_CALLBACK(callback) &&
            cbList->callbacks[i]->eventID == VIR_DOMAIN_EVENT_ID_LIFECYCLE &&
            cbList->callbacks[i]->conn == conn) {
            virFreeCallback freecb = cbList->callbacks[i]->freecb;
            if (freecb)
                (*freecb)(cbList->callbacks[i]->opaque);
            virObjectUnref(cbList->callbacks[i]->conn);
            VIR_FREE(cbList->callbacks[i]);

            if (i < (cbList->count - 1))
                memmove(cbList->callbacks + i,
                        cbList->callbacks + i + 1,
                        sizeof(*(cbList->callbacks)) *
                                (cbList->count - (i + 1)));

            if (VIR_REALLOC_N(cbList->callbacks,
                              cbList->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            cbList->count--;

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
        if (cbList->callbacks[i]->callbackID == callbackID &&
            cbList->callbacks[i]->conn == conn) {
            virFreeCallback freecb = cbList->callbacks[i]->freecb;
            if (freecb)
                (*freecb)(cbList->callbacks[i]->opaque);
            virObjectUnref(cbList->callbacks[i]->conn);
            VIR_FREE(cbList->callbacks[i]);

            if (i < (cbList->count - 1))
                memmove(cbList->callbacks + i,
                        cbList->callbacks + i + 1,
                        sizeof(*(cbList->callbacks)) *
                                (cbList->count - (i + 1)));

            if (VIR_REALLOC_N(cbList->callbacks,
                              cbList->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            cbList->count--;

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
virDomainEventCallbackListMarkDelete(virConnectPtr conn,
                                     virObjectEventCallbackListPtr cbList,
                                     virConnectDomainEventCallback callback)
{
    int ret = 0;
    size_t i;
    for (i = 0; i < cbList->count; i++) {
        if (cbList->callbacks[i]->cb == VIR_OBJECT_EVENT_CALLBACK(callback) &&
            cbList->callbacks[i]->eventID == VIR_DOMAIN_EVENT_ID_LIFECYCLE &&
            cbList->callbacks[i]->conn == conn) {
            cbList->callbacks[i]->deleted = 1;
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
virObjectEventCallbackListMarkDeleteID(virConnectPtr conn,
                                       virObjectEventCallbackListPtr cbList,
                                       int callbackID)
{
    int ret = 0;
    size_t i;
    for (i = 0; i < cbList->count; i++) {
        if (cbList->callbacks[i]->callbackID == callbackID &&
            cbList->callbacks[i]->conn == conn) {
            cbList->callbacks[i]->deleted = 1;
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
 * @eventID: the event ID
 * @callback: the callback to add
 * @opaque: opaque data tio pass to callback
 * @callbackID: filled with callback ID
 *
 * Internal function to add a callback from a virObjectEventCallbackListPtr
 */
static int
virObjectEventCallbackListAddID(virConnectPtr conn,
                                virObjectEventCallbackListPtr cbList,
                                unsigned char uuid[VIR_UUID_BUFLEN],
                                const char *name,
                                int id,
                                int eventID,
                                virConnectObjectEventGenericCallback callback,
                                void *opaque,
                                virFreeCallback freecb,
                                int *callbackID)
{
    virObjectEventCallbackPtr event;
    size_t i;
    int ret = 0;

    /* Check incoming */
    if (!cbList) {
        return -1;
    }

    /* check if we already have this callback on our list */
    for (i = 0; i < cbList->count; i++) {
        if (cbList->callbacks[i]->cb == VIR_OBJECT_EVENT_CALLBACK(callback) &&
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
        goto error;
    event->conn = conn;
    event->cb = callback;
    event->eventID = eventID;
    event->opaque = opaque;
    event->freecb = freecb;

    if (name && uuid && id > 0) {
        if (VIR_ALLOC(event->meta) < 0)
            goto error;
        if (VIR_STRDUP(event->meta->name, name) < 0)
            goto error;
        memcpy(event->meta->uuid, uuid, VIR_UUID_BUFLEN);
        event->meta->id = id;
    }

    /* Make space on list */
    if (VIR_REALLOC_N(cbList->callbacks, cbList->count + 1) < 0)
        goto error;

    virObjectRef(event->conn);

    cbList->callbacks[cbList->count] = event;
    cbList->count++;

    event->callbackID = cbList->nextID++;

    for (i = 0; i < cbList->count; i++) {
        if (cbList->callbacks[i]->eventID == eventID &&
            cbList->callbacks[i]->conn == conn &&
            !cbList->callbacks[i]->deleted)
            ret++;
    }

    if (callbackID)
        *callbackID = event->callbackID;

    return ret;

error:
    if (event) {
        if (event->meta)
            VIR_FREE(event->meta->name);
        VIR_FREE(event->meta);
    }
    VIR_FREE(event);
    return -1;
}


/**
 * virDomainEventCallbackListAdd:
 * @conn: pointer to the connection
 * @cbList: the list
 * @callback: the callback to add
 * @opaque: opaque data tio pass to callback
 *
 * Internal function to add a callback from a virObjectEventCallbackListPtr
 */
static int
virDomainEventCallbackListAdd(virConnectPtr conn,
                              virObjectEventCallbackListPtr cbList,
                              virConnectDomainEventCallback callback,
                              void *opaque,
                              virFreeCallback freecb)
{
    return virObjectEventCallbackListAddID(conn, cbList, NULL, NULL, 0,
                                           VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                           VIR_OBJECT_EVENT_CALLBACK(callback),
                                           opaque, freecb, NULL);
}



static int
virObjectEventCallbackListEventID(virConnectPtr conn,
                                  virObjectEventCallbackListPtr cbList,
                                  int callbackID)
{
    size_t i;

    for (i = 0; i < cbList->count; i++) {
        if (cbList->callbacks[i]->deleted)
            continue;

        if (cbList->callbacks[i]->callbackID == callbackID &&
            cbList->callbacks[i]->conn == conn)
            return cbList->callbacks[i]->eventID;
    }

    return -1;
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

static void
virObjectEventStateLock(virObjectEventStatePtr state)
{
    virMutexLock(&state->lock);
}

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

static void
virDomainEventTimer(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virObjectEventStatePtr state = opaque;

    virObjectEventStateFlush(state);
}

/**
 * virObjectEventStateNew:
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

static void *virObjectEventNew(virClassPtr klass,
                               int eventID)
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

    event->eventID = eventID;

    VIR_DEBUG("obj=%p", event);
    return event;
}

static void *virDomainEventNew(virClassPtr klass,
                               int eventID,
                               int id,
                               const char *name,
                               const unsigned char *uuid)
{
    virDomainEventPtr event;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!virClassIsDerivedFrom(klass, virDomainEventClass)) {
        virReportInvalidArg(klass,
                            _("Class %s must derive from virDomainEvent"),
                            virClassName(klass));
        return NULL;
    }

    if (!(event = virObjectEventNew(klass, eventID)))
        return NULL;

    if (VIR_STRDUP(event->meta.name, name) < 0) {
        VIR_FREE(event);
        return NULL;
    }
    event->meta.id = id;
    memcpy(event->meta.uuid, uuid, VIR_UUID_BUFLEN);

    return event;
}

virDomainEventPtr virDomainEventLifecycleNew(int id, const char *name,
                                    const unsigned char *uuid,
                                    int type, int detail)
{
    virDomainEventLifecyclePtr event;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(event = virDomainEventNew(virDomainEventLifecycleClass,
                                    VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                    id, name, uuid)))
        return NULL;

    event->type = type;
    event->detail = detail;

    return (virDomainEventPtr)event;
}

virDomainEventPtr virDomainEventLifecycleNewFromDom(virDomainPtr dom, int type, int detail)
{
    return virDomainEventLifecycleNew(dom->id, dom->name, dom->uuid,
                                      type, detail);
}

virDomainEventPtr virDomainEventLifecycleNewFromObj(virDomainObjPtr obj, int type, int detail)
{
    return virDomainEventLifecycleNewFromDef(obj->def, type, detail);
}

virDomainEventPtr virDomainEventLifecycleNewFromDef(virDomainDefPtr def, int type, int detail)
{
    return virDomainEventLifecycleNew(def->id, def->name, def->uuid,
                                      type, detail);
}

virDomainEventPtr virDomainEventRebootNew(int id, const char *name,
                                          const unsigned char *uuid)
{
    if (virObjectEventInitialize() < 0)
        return NULL;

    return virDomainEventNew(virDomainEventClass,
                             VIR_DOMAIN_EVENT_ID_REBOOT,
                             id, name, uuid);
}

virDomainEventPtr virDomainEventRebootNewFromDom(virDomainPtr dom)
{
    if (virObjectEventInitialize() < 0)
        return NULL;

    return virDomainEventNew(virDomainEventClass,
                             VIR_DOMAIN_EVENT_ID_REBOOT,
                             dom->id, dom->name, dom->uuid);
}

virDomainEventPtr virDomainEventRebootNewFromObj(virDomainObjPtr obj)
{
    if (virObjectEventInitialize() < 0)
        return NULL;

    return virDomainEventNew(virDomainEventClass,
                             VIR_DOMAIN_EVENT_ID_REBOOT,
                             obj->def->id, obj->def->name, obj->def->uuid);
}

virDomainEventPtr virDomainEventRTCChangeNewFromDom(virDomainPtr dom,
                                                    long long offset)
{
    virDomainEventRTCChangePtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventRTCChangeClass,
                                 VIR_DOMAIN_EVENT_ID_RTC_CHANGE,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->offset = offset;

    return (virDomainEventPtr)ev;
}
virDomainEventPtr virDomainEventRTCChangeNewFromObj(virDomainObjPtr obj,
                                                    long long offset)
{
    virDomainEventRTCChangePtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventRTCChangeClass,
                                 VIR_DOMAIN_EVENT_ID_RTC_CHANGE,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;

    ev->offset = offset;

    return (virDomainEventPtr)ev;
}

virDomainEventPtr virDomainEventWatchdogNewFromDom(virDomainPtr dom, int action)
{
    virDomainEventWatchdogPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventWatchdogClass,
                                 VIR_DOMAIN_EVENT_ID_WATCHDOG,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->action = action;

    return (virDomainEventPtr)ev;
}
virDomainEventPtr virDomainEventWatchdogNewFromObj(virDomainObjPtr obj, int action)
{
    virDomainEventWatchdogPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventWatchdogClass,
                                 VIR_DOMAIN_EVENT_ID_WATCHDOG,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;

    ev->action = action;

    return (virDomainEventPtr)ev;
}

static virDomainEventPtr virDomainEventIOErrorNewFromDomImpl(int event,
                                                             virDomainPtr dom,
                                                             const char *srcPath,
                                                             const char *devAlias,
                                                             int action,
                                                             const char *reason)
{
    virDomainEventIOErrorPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventIOErrorClass, event,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->action = action;
    if (VIR_STRDUP(ev->srcPath, srcPath) < 0 ||
        VIR_STRDUP(ev->devAlias, devAlias) < 0 ||
        VIR_STRDUP(ev->reason, reason) < 0) {
        virObjectUnref(ev);
        ev = NULL;
    }

    return (virDomainEventPtr)ev;
}

static virDomainEventPtr virDomainEventIOErrorNewFromObjImpl(int event,
                                                             virDomainObjPtr obj,
                                                             const char *srcPath,
                                                             const char *devAlias,
                                                             int action,
                                                             const char *reason)
{
    virDomainEventIOErrorPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventIOErrorClass, event,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;

    ev->action = action;
    if (VIR_STRDUP(ev->srcPath, srcPath) < 0 ||
        VIR_STRDUP(ev->devAlias, devAlias) < 0 ||
        VIR_STRDUP(ev->reason, reason) < 0) {
        virObjectUnref(ev);
        ev = NULL;
    }

    return (virDomainEventPtr)ev;
}

virDomainEventPtr virDomainEventIOErrorNewFromDom(virDomainPtr dom,
                                                  const char *srcPath,
                                                  const char *devAlias,
                                                  int action)
{
    return virDomainEventIOErrorNewFromDomImpl(VIR_DOMAIN_EVENT_ID_IO_ERROR,
                                               dom, srcPath, devAlias,
                                               action, NULL);
}

virDomainEventPtr virDomainEventIOErrorNewFromObj(virDomainObjPtr obj,
                                                  const char *srcPath,
                                                  const char *devAlias,
                                                  int action)
{
    return virDomainEventIOErrorNewFromObjImpl(VIR_DOMAIN_EVENT_ID_IO_ERROR,
                                               obj, srcPath, devAlias,
                                               action, NULL);
}

virDomainEventPtr virDomainEventIOErrorReasonNewFromDom(virDomainPtr dom,
                                                        const char *srcPath,
                                                        const char *devAlias,
                                                        int action,
                                                        const char *reason)
{
    return virDomainEventIOErrorNewFromDomImpl(VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON,
                                               dom, srcPath, devAlias,
                                               action, reason);
}

virDomainEventPtr virDomainEventIOErrorReasonNewFromObj(virDomainObjPtr obj,
                                                        const char *srcPath,
                                                        const char *devAlias,
                                                        int action,
                                                        const char *reason)
{
    return virDomainEventIOErrorNewFromObjImpl(VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON,
                                               obj, srcPath, devAlias,
                                               action, reason);
}


virDomainEventPtr virDomainEventGraphicsNewFromDom(virDomainPtr dom,
                                       int phase,
                                       virDomainEventGraphicsAddressPtr local,
                                       virDomainEventGraphicsAddressPtr remote,
                                       const char *authScheme,
                                       virDomainEventGraphicsSubjectPtr subject)
{
    virDomainEventGraphicsPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventGraphicsClass,
                                 VIR_DOMAIN_EVENT_ID_GRAPHICS,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->phase = phase;
    if (VIR_STRDUP(ev->authScheme, authScheme) < 0) {
        virObjectUnref(ev);
        return NULL;
    }
    ev->local = local;
    ev->remote = remote;
    ev->subject = subject;

    return (virDomainEventPtr)ev;
}

virDomainEventPtr virDomainEventGraphicsNewFromObj(virDomainObjPtr obj,
                                       int phase,
                                       virDomainEventGraphicsAddressPtr local,
                                       virDomainEventGraphicsAddressPtr remote,
                                       const char *authScheme,
                                       virDomainEventGraphicsSubjectPtr subject)
{
    virDomainEventGraphicsPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventGraphicsClass,
                                 VIR_DOMAIN_EVENT_ID_GRAPHICS,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;

    ev->phase = phase;
    if (VIR_STRDUP(ev->authScheme, authScheme) < 0) {
        virObjectUnref(ev);
        return NULL;
    }
    ev->local = local;
    ev->remote = remote;
    ev->subject = subject;

    return (virDomainEventPtr)ev;
}

static
virDomainEventPtr  virDomainEventBlockJobNew(int id,
                                             const char *name,
                                             unsigned char *uuid,
                                             const char *path,
                                             int type,
                                             int status)
{
    virDomainEventBlockJobPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventBlockJobClass,
                                 VIR_DOMAIN_EVENT_ID_BLOCK_JOB,
                                 id, name, uuid)))
        return NULL;

    if (VIR_STRDUP(ev->path, path) < 0) {
        virObjectUnref(ev);
        return NULL;
    }
    ev->type = type;
    ev->status = status;

    return (virDomainEventPtr)ev;
}

virDomainEventPtr virDomainEventBlockJobNewFromObj(virDomainObjPtr obj,
                                       const char *path,
                                       int type,
                                       int status)
{
    return virDomainEventBlockJobNew(obj->def->id, obj->def->name,
                                     obj->def->uuid, path, type, status);
}

virDomainEventPtr virDomainEventBlockJobNewFromDom(virDomainPtr dom,
                                       const char *path,
                                       int type,
                                       int status)
{
    return virDomainEventBlockJobNew(dom->id, dom->name, dom->uuid,
                                     path, type, status);
}

virDomainEventPtr virDomainEventControlErrorNewFromDom(virDomainPtr dom)
{
    virDomainEventPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_CONTROL_ERROR,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;
    return ev;
}


virDomainEventPtr virDomainEventControlErrorNewFromObj(virDomainObjPtr obj)
{
    virDomainEventPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_CONTROL_ERROR,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;
    return ev;
}

static
virDomainEventPtr virDomainEventDiskChangeNew(int id, const char *name,
                                              unsigned char *uuid,
                                              const char *oldSrcPath,
                                              const char *newSrcPath,
                                              const char *devAlias, int reason)
{
    virDomainEventDiskChangePtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventDiskChangeClass,
                                 VIR_DOMAIN_EVENT_ID_DISK_CHANGE,
                                 id, name, uuid)))
        return NULL;

    if (VIR_STRDUP(ev->devAlias, devAlias) < 0)
        goto error;

    if (VIR_STRDUP(ev->oldSrcPath, oldSrcPath) < 0)
        goto error;

    if (VIR_STRDUP(ev->newSrcPath, newSrcPath) < 0)
        goto error;

    ev->reason = reason;

    return (virDomainEventPtr)ev;

error:
    virObjectUnref(ev);
    return NULL;
}

virDomainEventPtr virDomainEventDiskChangeNewFromObj(virDomainObjPtr obj,
                                                     const char *oldSrcPath,
                                                     const char *newSrcPath,
                                                     const char *devAlias,
                                                     int reason)
{
    return virDomainEventDiskChangeNew(obj->def->id, obj->def->name,
                                       obj->def->uuid, oldSrcPath,
                                       newSrcPath, devAlias, reason);
}

virDomainEventPtr virDomainEventDiskChangeNewFromDom(virDomainPtr dom,
                                                     const char *oldSrcPath,
                                                     const char *newSrcPath,
                                                     const char *devAlias,
                                                     int reason)
{
    return virDomainEventDiskChangeNew(dom->id, dom->name, dom->uuid,
                                       oldSrcPath, newSrcPath,
                                       devAlias, reason);
}

static virDomainEventPtr
virDomainEventTrayChangeNew(int id, const char *name,
                            unsigned char *uuid,
                            const char *devAlias,
                            int reason)
{
    virDomainEventTrayChangePtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventTrayChangeClass,
                                 VIR_DOMAIN_EVENT_ID_TRAY_CHANGE,
                                 id, name, uuid)))
        return NULL;

    if (VIR_STRDUP(ev->devAlias, devAlias) < 0)
        goto error;

    ev->reason = reason;

    return (virDomainEventPtr)ev;

error:
    virObjectUnref(ev);
    return NULL;
}

virDomainEventPtr virDomainEventTrayChangeNewFromObj(virDomainObjPtr obj,
                                                     const char *devAlias,
                                                     int reason)
{
    return virDomainEventTrayChangeNew(obj->def->id,
                                       obj->def->name,
                                       obj->def->uuid,
                                       devAlias,
                                       reason);
}

virDomainEventPtr virDomainEventTrayChangeNewFromDom(virDomainPtr dom,
                                                     const char *devAlias,
                                                     int reason)
{
    return virDomainEventTrayChangeNew(dom->id, dom->name, dom->uuid,
                                       devAlias, reason);
}

static virDomainEventPtr
virDomainEventPMWakeupNew(int id, const char *name,
                          unsigned char *uuid)
{
    virDomainEventPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_PMWAKEUP,
                                 id, name, uuid)))
        return NULL;

    return ev;
}

virDomainEventPtr
virDomainEventPMWakeupNewFromObj(virDomainObjPtr obj)
{
    return virDomainEventPMWakeupNew(obj->def->id,
                                     obj->def->name,
                                     obj->def->uuid);
}

virDomainEventPtr
virDomainEventPMWakeupNewFromDom(virDomainPtr dom)
{
    return virDomainEventPMWakeupNew(dom->id, dom->name, dom->uuid);
}

static virDomainEventPtr
virDomainEventPMSuspendNew(int id, const char *name,
                           unsigned char *uuid)
{
    virDomainEventPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_PMSUSPEND,
                                 id, name, uuid)))
        return NULL;

    return ev;
}

virDomainEventPtr
virDomainEventPMSuspendNewFromObj(virDomainObjPtr obj)
{
    return virDomainEventPMSuspendNew(obj->def->id,
                                      obj->def->name,
                                      obj->def->uuid);
}

virDomainEventPtr
virDomainEventPMSuspendNewFromDom(virDomainPtr dom)
{
    return virDomainEventPMSuspendNew(dom->id, dom->name, dom->uuid);
}

static virDomainEventPtr
virDomainEventPMSuspendDiskNew(int id, const char *name,
                               unsigned char *uuid)
{
    virDomainEventPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK,
                                 id, name, uuid)))
        return NULL;
    return ev;
}

virDomainEventPtr
virDomainEventPMSuspendDiskNewFromObj(virDomainObjPtr obj)
{
    return virDomainEventPMSuspendDiskNew(obj->def->id,
                                          obj->def->name,
                                          obj->def->uuid);
}

virDomainEventPtr
virDomainEventPMSuspendDiskNewFromDom(virDomainPtr dom)
{
    return virDomainEventPMSuspendDiskNew(dom->id, dom->name, dom->uuid);
}

virDomainEventPtr virDomainEventBalloonChangeNewFromDom(virDomainPtr dom,
                                                        unsigned long long actual)
{
    virDomainEventPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->data.balloonChange.actual = actual;

    return ev;
}
virDomainEventPtr virDomainEventBalloonChangeNewFromObj(virDomainObjPtr obj,
                                                        unsigned long long actual)
{
    virDomainEventPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE,
                                 obj->def->id, obj->def->name, obj->def->uuid)))
        return NULL;

    ev->data.balloonChange.actual = actual;

    return ev;
}

static virDomainEventPtr
virDomainEventDeviceRemovedNew(int id,
                               const char *name,
                               unsigned char *uuid,
                               const char *devAlias)
{
    virDomainEventPtr ev;

    if (virObjectEventInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED,
                                 id, name, uuid)))
        return NULL;

    if (VIR_STRDUP(ev->data.deviceRemoved.devAlias, devAlias) < 0)
        goto error;

    return ev;

error:
    virObjectUnref(ev);
    return NULL;
}

virDomainEventPtr
virDomainEventDeviceRemovedNewFromObj(virDomainObjPtr obj,
                                      const char *devAlias)
{
    return virDomainEventDeviceRemovedNew(obj->def->id, obj->def->name,
                                          obj->def->uuid, devAlias);
}

virDomainEventPtr
virDomainEventDeviceRemovedNewFromDom(virDomainPtr dom,
                                      const char *devAlias)
{
    return virDomainEventDeviceRemovedNew(dom->id, dom->name, dom->uuid,
                                          devAlias);
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
                        virDomainEventPtr event)
{
    if (!evtQueue) {
        return -1;
    }

    /* Make space on queue */
    if (VIR_REALLOC_N(evtQueue->events,
                      evtQueue->count + 1) < 0)
        return -1;

    evtQueue->events[evtQueue->count] = event;
    evtQueue->count++;
    return 0;
}


typedef void (*virObjectEventDispatchFunc)(virConnectPtr conn,
                                           virDomainEventPtr event,
                                           virConnectObjectEventGenericCallback cb,
                                           void *cbopaque,
                                           void *opaque);


static void
virDomainEventDispatchDefaultFunc(virConnectPtr conn,
                                  virDomainEventPtr event,
                                  virConnectDomainEventGenericCallback cb,
                                  void *cbopaque,
                                  void *opaque ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = virGetDomain(conn, event->meta.name, event->meta.uuid);
    int eventID = virObjectEventGetEventID(event);
    if (!dom)
        return;
    dom->id = event->meta.id;

    switch ((virDomainEventID) eventID) {
    case VIR_DOMAIN_EVENT_ID_LIFECYCLE:
        {
            virDomainEventLifecyclePtr lifecycleEvent;

            lifecycleEvent = (virDomainEventLifecyclePtr)event;
            ((virConnectDomainEventCallback)cb)(conn, dom,
                                                lifecycleEvent->type,
                                                lifecycleEvent->detail,
                                                cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_REBOOT:
        (cb)(conn, dom,
             cbopaque);
        goto cleanup;

    case VIR_DOMAIN_EVENT_ID_RTC_CHANGE:
        {
            virDomainEventRTCChangePtr rtcChangeEvent;

            rtcChangeEvent = (virDomainEventRTCChangePtr)event;
            ((virConnectDomainEventRTCChangeCallback)cb)(conn, dom,
                                                         rtcChangeEvent->offset,
                                                         cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_WATCHDOG:
        {
            virDomainEventWatchdogPtr watchdogEvent;

            watchdogEvent = (virDomainEventWatchdogPtr)event;
            ((virConnectDomainEventWatchdogCallback)cb)(conn, dom,
                                                        watchdogEvent->action,
                                                        cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_IO_ERROR:
        {
            virDomainEventIOErrorPtr ioErrorEvent;

            ioErrorEvent = (virDomainEventIOErrorPtr)event;
            ((virConnectDomainEventIOErrorCallback)cb)(conn, dom,
                                                       ioErrorEvent->srcPath,
                                                       ioErrorEvent->devAlias,
                                                       ioErrorEvent->action,
                                                       cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON:
        {
            virDomainEventIOErrorPtr ioErrorEvent;

            ioErrorEvent = (virDomainEventIOErrorPtr)event;
            ((virConnectDomainEventIOErrorReasonCallback)cb)(conn, dom,
                                                             ioErrorEvent->srcPath,
                                                             ioErrorEvent->devAlias,
                                                             ioErrorEvent->action,
                                                             ioErrorEvent->reason,
                                                             cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_GRAPHICS:
        {
            virDomainEventGraphicsPtr graphicsEvent;

            graphicsEvent = (virDomainEventGraphicsPtr)event;
            ((virConnectDomainEventGraphicsCallback)cb)(conn, dom,
                                                        graphicsEvent->phase,
                                                        graphicsEvent->local,
                                                        graphicsEvent->remote,
                                                        graphicsEvent->authScheme,
                                                        graphicsEvent->subject,
                                                        cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_CONTROL_ERROR:
        (cb)(conn, dom,
             cbopaque);
        goto cleanup;

    case VIR_DOMAIN_EVENT_ID_BLOCK_JOB:
        {
            virDomainEventBlockJobPtr blockJobEvent;

            blockJobEvent = (virDomainEventBlockJobPtr)event;
            ((virConnectDomainEventBlockJobCallback)cb)(conn, dom,
                                                        blockJobEvent->path,
                                                        blockJobEvent->type,
                                                        blockJobEvent->status,
                                                        cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_DISK_CHANGE:
        {
            virDomainEventDiskChangePtr diskChangeEvent;

            diskChangeEvent = (virDomainEventDiskChangePtr)event;
            ((virConnectDomainEventDiskChangeCallback)cb)(conn, dom,
                                                          diskChangeEvent->oldSrcPath,
                                                          diskChangeEvent->newSrcPath,
                                                          diskChangeEvent->devAlias,
                                                          diskChangeEvent->reason,
                                                          cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_TRAY_CHANGE:
        {
            virDomainEventTrayChangePtr trayChangeEvent;

            trayChangeEvent = (virDomainEventTrayChangePtr)event;
            ((virConnectDomainEventTrayChangeCallback)cb)(conn, dom,
                                                          trayChangeEvent->devAlias,
                                                          trayChangeEvent->reason,
                                                          cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_PMWAKEUP:
        ((virConnectDomainEventPMWakeupCallback)cb)(conn, dom, 0, cbopaque);
        goto cleanup;

    case VIR_DOMAIN_EVENT_ID_PMSUSPEND:
        ((virConnectDomainEventPMSuspendCallback)cb)(conn, dom, 0, cbopaque);
        goto cleanup;

    case VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE:
        ((virConnectDomainEventBalloonChangeCallback)cb)(conn, dom,
                                                         event->data.balloonChange.actual,
                                                         cbopaque);
        goto cleanup;

    case VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK:
        ((virConnectDomainEventPMSuspendDiskCallback)cb)(conn, dom, 0, cbopaque);
        goto cleanup;

    case VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED:
        ((virConnectDomainEventDeviceRemovedCallback)cb)(conn, dom,
                                                         event->data.deviceRemoved.devAlias,
                                                         cbopaque);
        goto cleanup;

    case VIR_DOMAIN_EVENT_ID_LAST:
        break;
    }

    VIR_WARN("Unexpected event ID %d", eventID);

cleanup:
    virDomainFree(dom);
}


static int virDomainEventDispatchMatchCallback(virDomainEventPtr event,
                                               virObjectEventCallbackPtr cb)
{
    if (!cb)
        return 0;
    if (cb->deleted)
        return 0;
    if (cb->eventID != virObjectEventGetEventID(event))
        return 0;

    if (cb->meta) {
        /* Deliberately ignoring 'id' for matching, since that
         * will cause problems when a domain switches between
         * running & shutoff states & ignoring 'name' since
         * Xen sometimes renames guests during migration, thus
         * leaving 'uuid' as the only truly reliable ID we can use*/

        if (memcmp(event->meta.uuid, cb->meta->uuid, VIR_UUID_BUFLEN) == 0)
            return 1;

        return 0;
    } else {
        return 1;
    }
}


static void
virDomainEventDispatch(virDomainEventPtr event,
                       virObjectEventCallbackListPtr callbacks,
                       virObjectEventDispatchFunc dispatch,
                       void *opaque)
{
    size_t i;
    /* Cache this now, since we may be dropping the lock,
       and have more callbacks added. We're guaranteed not
       to have any removed */
    int cbCount = callbacks->count;

    for (i = 0; i < cbCount; i++) {
        if (!virDomainEventDispatchMatchCallback(event, callbacks->callbacks[i]))
            continue;

        (*dispatch)(callbacks->callbacks[i]->conn,
                    event,
                    callbacks->callbacks[i]->cb,
                    callbacks->callbacks[i]->opaque,
                    opaque);
    }
}


static void
virObjectEventQueueDispatch(virObjectEventQueuePtr queue,
                            virObjectEventCallbackListPtr callbacks,
                            virObjectEventDispatchFunc dispatch,
                            void *opaque)
{
    size_t i;

    for (i = 0; i < queue->count; i++) {
        virDomainEventDispatch(queue->events[i], callbacks, dispatch, opaque);
        virObjectUnref(queue->events[i]);
    }
    VIR_FREE(queue->events);
    queue->count = 0;
}

void
virObjectEventStateQueue(virObjectEventStatePtr state,
                         virDomainEventPtr event)
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
virObjectEventStateDispatchFunc(virConnectPtr conn,
                                virDomainEventPtr event,
                                virConnectObjectEventGenericCallback cb,
                                void *cbopaque,
                                void *opaque)
{
    virObjectEventStatePtr state = opaque;

    /* Drop the lock whle dispatching, for sake of re-entrancy */
    virObjectEventStateUnlock(state);
    virDomainEventDispatchDefaultFunc(conn, event,
            VIR_DOMAIN_EVENT_CALLBACK(cb), cbopaque, NULL);
    virObjectEventStateLock(state);
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

    virObjectEventQueueDispatch(&tempQueue,
                                state->callbacks,
                                virObjectEventStateDispatchFunc,
                                state);

    /* Purge any deleted callbacks */
    virObjectEventCallbackListPurgeMarked(state->callbacks);

    state->isDispatching = false;
    virObjectEventStateUnlock(state);
}


/**
 * virObjectEventStateRegisterID:
 * @conn: connection to associate with callback
 * @state: domain event state
 * @eventID: ID of the event type to register for
 * @cb: function to remove from event
 * @opaque: data blob to pass to callback
 * @freecb: callback to free @opaque
 * @callbackID: filled with callback ID
 *
 * Register the function @callbackID with connection @conn,
 * from @state, for events of type @eventID.
 *
 * Returns: the number of callbacks now registered, or -1 on error
 */
int
virObjectEventStateRegisterID(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              unsigned char *uuid,
                              const char *name,
                              int id,
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
                                           virDomainEventTimer,
                                           state,
                                           NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not initialize domain event timer"));
        goto cleanup;
    }

    ret = virObjectEventCallbackListAddID(conn, state->callbacks,
                                          uuid, name, id, eventID, cb, opaque, freecb,
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
 * virDomainEventStateRegister:
 * @conn: connection to associate with callback
 * @state: object event state
 * @callback: function to remove from event
 * @opaque: data blob to pass to callback
 * @freecb: callback to free @opaque
 *
 * Register the function @callback with connection @conn,
 * from @state, for lifecycle events.
 *
 * Returns: the number of lifecycle callbacks now registered, or -1 on error
 */
int
virDomainEventStateRegister(virConnectPtr conn,
                            virObjectEventStatePtr state,
                            virConnectDomainEventCallback callback,
                            void *opaque,
                            virFreeCallback freecb)
{
    int ret = -1;

    virObjectEventStateLock(state);

    if ((state->callbacks->count == 0) &&
        (state->timer == -1) &&
        (state->timer = virEventAddTimeout(-1,
                                           virDomainEventTimer,
                                           state,
                                           NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("could not initialize domain event timer"));
        goto cleanup;
    }

    ret = virDomainEventCallbackListAdd(conn, state->callbacks,
                                        callback, opaque, freecb);

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
 * virDomainEventStateRegisterID:
 * @conn: connection to associate with callback
 * @state: object event state
 * @eventID: ID of the event type to register for
 * @cb: function to remove from event
 * @opaque: data blob to pass to callback
 * @freecb: callback to free @opaque
 * @callbackID: filled with callback ID
 *
 * Register the function @callbackID with connection @conn,
 * from @state, for events of type @eventID.
 *
 * Returns: the number of callbacks now registered, or -1 on error
 */
int
virDomainEventStateRegisterID(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              virDomainPtr dom,
                              int eventID,
                              virConnectDomainEventGenericCallback cb,
                              void *opaque,
                              virFreeCallback freecb,
                              int *callbackID)
{
    if (dom)
        return virObjectEventStateRegisterID(conn, state, dom->uuid, dom->name,
                                             dom->id, eventID,
                                             VIR_OBJECT_EVENT_CALLBACK(cb),
                                             opaque, freecb, callbackID);
     else
        return virObjectEventStateRegisterID(conn, state, NULL, NULL, 0,
                                             eventID,
                                             VIR_OBJECT_EVENT_CALLBACK(cb),
                                             opaque, freecb, callbackID);
}


/**
 * virDomainEventStateDeregister:
 * @conn: connection to associate with callback
 * @state: object event state
 * @callback: function to remove from event
 *
 * Unregister the function @callback with connection @conn,
 * from @state, for lifecycle events.
 *
 * Returns: the number of lifecycle callbacks still registered, or -1 on error
 */
int
virDomainEventStateDeregister(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              virConnectDomainEventCallback callback)
{
    int ret;

    virObjectEventStateLock(state);
    if (state->isDispatching)
        ret = virDomainEventCallbackListMarkDelete(conn,
                                                   state->callbacks, callback);
    else
        ret = virDomainEventCallbackListRemove(conn, state->callbacks, callback);

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
                                                     state->callbacks, callbackID);
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
