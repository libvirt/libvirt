/*
 * domain_event.c: domain event queue processing helpers
 *
 * Copyright (C) 2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Ben Guthro
 */

#include <config.h>

#include "domain_event.h"
#include "logging.h"
#include "datatypes.h"
#include "memory.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define eventReportError(code, ...)                                 \
    virReportErrorHelper(NULL, VIR_FROM_THIS, code, __FILE__,       \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

struct _virDomainMeta {
    int id;
    char *name;
    unsigned char uuid[VIR_UUID_BUFLEN];
};
typedef struct _virDomainMeta virDomainMeta;
typedef virDomainMeta *virDomainMetaPtr;

struct _virDomainEventCallback {
    int callbackID;
    int eventID;
    virConnectPtr conn;
    virDomainMetaPtr dom;
    virConnectDomainEventGenericCallback cb;
    void *opaque;
    virFreeCallback freecb;
    int deleted;
};

struct _virDomainEvent {
    int eventID;

    virDomainMeta dom;

    union {
        struct {
            int type;
            int detail;
        } lifecycle;
        struct {
            long long offset;
        } rtcChange;
        struct {
            int action;
        } watchdog;
        struct {
            char *srcPath;
            char *devAlias;
            int action;
            char *reason;
        } ioError;
        struct {
            int phase;
            virDomainEventGraphicsAddressPtr local;
            virDomainEventGraphicsAddressPtr remote;
            char *authScheme;
            virDomainEventGraphicsSubjectPtr subject;
        } graphics;
    } data;
};

/**
 * virDomainEventCallbackListFree:
 * @list: event callback list head
 *
 * Free the memory in the domain event callback list
 */
void
virDomainEventCallbackListFree(virDomainEventCallbackListPtr list)
{
    int i;
    if (!list)
        return;

    for (i=0; i<list->count; i++) {
        virFreeCallback freecb = list->callbacks[i]->freecb;
        if (freecb)
            (*freecb)(list->callbacks[i]->opaque);
        VIR_FREE(list->callbacks[i]);
    }
    VIR_FREE(list);
}


/**
 * virDomainEventCallbackListRemove:
 * @conn: pointer to the connection
 * @cbList: the list
 * @callback: the callback to remove
 *
 * Internal function to remove a callback from a virDomainEventCallbackListPtr
 */
int
virDomainEventCallbackListRemove(virConnectPtr conn,
                                 virDomainEventCallbackListPtr cbList,
                                 virConnectDomainEventCallback callback)
{
    int i;
    for (i = 0 ; i < cbList->count ; i++) {
        if (cbList->callbacks[i]->cb == VIR_DOMAIN_EVENT_CALLBACK(callback) &&
            cbList->callbacks[i]->eventID == VIR_DOMAIN_EVENT_ID_LIFECYCLE &&
            cbList->callbacks[i]->conn == conn) {
            virFreeCallback freecb = cbList->callbacks[i]->freecb;
            if (freecb)
                (*freecb)(cbList->callbacks[i]->opaque);
            virUnrefConnect(cbList->callbacks[i]->conn);
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

            return 0;
        }
    }

    eventReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("could not find event callback for removal"));
    return -1;
}


/**
 * virDomainEventCallbackListRemoveID:
 * @conn: pointer to the connection
 * @cbList: the list
 * @callback: the callback to remove
 *
 * Internal function to remove a callback from a virDomainEventCallbackListPtr
 */
int
virDomainEventCallbackListRemoveID(virConnectPtr conn,
                                   virDomainEventCallbackListPtr cbList,
                                   int callbackID)
{
    int i;
    for (i = 0 ; i < cbList->count ; i++) {
        if (cbList->callbacks[i]->callbackID == callbackID &&
            cbList->callbacks[i]->conn == conn) {
            virFreeCallback freecb = cbList->callbacks[i]->freecb;
            if (freecb)
                (*freecb)(cbList->callbacks[i]->opaque);
            virUnrefConnect(cbList->callbacks[i]->conn);
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

            return 0;
        }
    }

    eventReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("could not find event callback for removal"));
    return -1;
}


/**
 * virDomainEventCallbackListRemoveConn:
 * @conn: pointer to the connection
 * @cbList: the list
 *
 * Internal function to remove all of a given connection's callback
 * from a virDomainEventCallbackListPtr
 */
int
virDomainEventCallbackListRemoveConn(virConnectPtr conn,
                                     virDomainEventCallbackListPtr cbList)
{
    int old_count = cbList->count;
    int i;
    for (i = 0 ; i < cbList->count ; i++) {
        if (cbList->callbacks[i]->conn == conn) {
            virFreeCallback freecb = cbList->callbacks[i]->freecb;
            if (freecb)
                (*freecb)(cbList->callbacks[i]->opaque);
            virUnrefConnect(cbList->callbacks[i]->conn);
            VIR_FREE(cbList->callbacks[i]);

            if (i < (cbList->count - 1))
                memmove(cbList->callbacks + i,
                        cbList->callbacks + i + 1,
                        sizeof(*(cbList->callbacks)) *
                                (cbList->count - (i + 1)));
            cbList->count--;
            i--;
        }
    }
    if (cbList->count < old_count &&
        VIR_REALLOC_N(cbList->callbacks, cbList->count) < 0) {
        ; /* Failure to reduce memory allocation isn't fatal */
    }
    return 0;
}


int virDomainEventCallbackListMarkDelete(virConnectPtr conn,
                                         virDomainEventCallbackListPtr cbList,
                                         virConnectDomainEventCallback callback)
{
    int i;
    for (i = 0 ; i < cbList->count ; i++) {
        if (cbList->callbacks[i]->cb == VIR_DOMAIN_EVENT_CALLBACK(callback) &&
            cbList->callbacks[i]->eventID == VIR_DOMAIN_EVENT_ID_LIFECYCLE &&
            cbList->callbacks[i]->conn == conn) {
            cbList->callbacks[i]->deleted = 1;
            return 0;
        }
    }

    eventReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("could not find event callback for deletion"));
    return -1;
}


int virDomainEventCallbackListMarkDeleteID(virConnectPtr conn,
                                           virDomainEventCallbackListPtr cbList,
                                           int callbackID)
{
    int i;
    for (i = 0 ; i < cbList->count ; i++) {
        if (cbList->callbacks[i]->callbackID == callbackID &&
            cbList->callbacks[i]->conn == conn) {
            cbList->callbacks[i]->deleted = 1;
            return 0;
        }
    }

    eventReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("could not find event callback for deletion"));
    return -1;
}


int virDomainEventCallbackListPurgeMarked(virDomainEventCallbackListPtr cbList)
{
    int old_count = cbList->count;
    int i;
    for (i = 0 ; i < cbList->count ; i++) {
        if (cbList->callbacks[i]->deleted) {
            virFreeCallback freecb = cbList->callbacks[i]->freecb;
            if (freecb)
                (*freecb)(cbList->callbacks[i]->opaque);
            virUnrefConnect(cbList->callbacks[i]->conn);
            VIR_FREE(cbList->callbacks[i]);

            if (i < (cbList->count - 1))
                memmove(cbList->callbacks + i,
                        cbList->callbacks + i + 1,
                        sizeof(*(cbList->callbacks)) *
                                (cbList->count - (i + 1)));
            cbList->count--;
            i--;
        }
    }
    if (cbList->count < old_count &&
        VIR_REALLOC_N(cbList->callbacks, cbList->count) < 0) {
        ; /* Failure to reduce memory allocation isn't fatal */
    }
    return 0;
}


/**
 * virDomainEventCallbackListAdd:
 * @conn: pointer to the connection
 * @cbList: the list
 * @callback: the callback to add
 * @opaque: opaque data tio pass to callback
 *
 * Internal function to add a callback from a virDomainEventCallbackListPtr
 */
int
virDomainEventCallbackListAdd(virConnectPtr conn,
                              virDomainEventCallbackListPtr cbList,
                              virConnectDomainEventCallback callback,
                              void *opaque,
                              virFreeCallback freecb)
{
    return virDomainEventCallbackListAddID(conn, cbList, NULL,
                                           VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                           VIR_DOMAIN_EVENT_CALLBACK(callback),
                                           opaque, freecb);
}


/**
 * virDomainEventCallbackListAddID:
 * @conn: pointer to the connection
 * @cbList: the list
 * @eventID: the event ID
 * @callback: the callback to add
 * @opaque: opaque data tio pass to callback
 *
 * Internal function to add a callback from a virDomainEventCallbackListPtr
 */
int
virDomainEventCallbackListAddID(virConnectPtr conn,
                                virDomainEventCallbackListPtr cbList,
                                virDomainPtr dom,
                                int eventID,
                                virConnectDomainEventGenericCallback callback,
                                void *opaque,
                                virFreeCallback freecb)
{
    virDomainEventCallbackPtr event;
    int i;

    /* Check incoming */
    if ( !cbList ) {
        return -1;
    }

    /* check if we already have this callback on our list */
    for (i = 0 ; i < cbList->count ; i++) {
        if (cbList->callbacks[i]->cb == VIR_DOMAIN_EVENT_CALLBACK(callback) &&
            cbList->callbacks[i]->eventID == VIR_DOMAIN_EVENT_ID_LIFECYCLE &&
            cbList->callbacks[i]->conn == conn) {
            eventReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                             _("event callback already tracked"));
            return -1;
        }
    }
    /* Allocate new event */
    if (VIR_ALLOC(event) < 0)
        goto no_memory;
    event->conn = conn;
    event->cb = callback;
    event->eventID = eventID;
    event->opaque = opaque;
    event->freecb = freecb;

    if (dom) {
        if (VIR_ALLOC(event->dom) < 0)
            goto no_memory;
        if (!(event->dom->name = strdup(dom->name)))
            goto no_memory;
        memcpy(event->dom->uuid, dom->uuid, VIR_UUID_BUFLEN);
        event->dom->id = dom->id;
    }

    /* Make space on list */
    if (VIR_REALLOC_N(cbList->callbacks, cbList->count + 1) < 0)
        goto no_memory;

    event->conn->refs++;

    cbList->callbacks[cbList->count] = event;
    cbList->count++;

    event->callbackID = cbList->nextID++;

    return event->callbackID;

no_memory:
    virReportOOMError();

    if (event) {
        if (event->dom)
            VIR_FREE(event->dom->name);
        VIR_FREE(event->dom);
    }
    VIR_FREE(event);
    return -1;
}


int virDomainEventCallbackListCountID(virConnectPtr conn,
                                      virDomainEventCallbackListPtr cbList,
                                      int eventID)
{
    int i;
    int count = 0;

    for (i = 0 ; i < cbList->count ; i++) {
        if (cbList->callbacks[i]->deleted)
            continue;

        if (cbList->callbacks[i]->eventID == eventID &&
            cbList->callbacks[i]->conn == conn)
            count++;
    }

    return count;
}


int virDomainEventCallbackListEventID(virConnectPtr conn,
                                      virDomainEventCallbackListPtr cbList,
                                      int callbackID)
{
    int i;

    for (i = 0 ; i < cbList->count ; i++) {
        if (cbList->callbacks[i]->deleted)
            continue;

        if (cbList->callbacks[i]->callbackID == callbackID &&
            cbList->callbacks[i]->conn == conn)
            return cbList->callbacks[i]->eventID;
    }

    return -1;
}


int virDomainEventCallbackListCount(virDomainEventCallbackListPtr cbList)
{
    int i;
    int count = 0;

    for (i = 0 ; i < cbList->count ; i++) {
        if (cbList->callbacks[i]->deleted)
            continue;
        if (cbList->callbacks[i]->eventID == VIR_DOMAIN_EVENT_ID_LIFECYCLE)
            count++;
    }

    return count;
}


void virDomainEventFree(virDomainEventPtr event)
{
    if (!event)
        return;

    switch (event->eventID) {
    case VIR_DOMAIN_EVENT_ID_IO_ERROR:
        VIR_FREE(event->data.ioError.srcPath);
        VIR_FREE(event->data.ioError.devAlias);
        VIR_FREE(event->data.ioError.reason);
        break;

    case VIR_DOMAIN_EVENT_ID_GRAPHICS:
        if (event->data.graphics.local) {
            VIR_FREE(event->data.graphics.local->node);
            VIR_FREE(event->data.graphics.local->service);
            VIR_FREE(event->data.graphics.local);
        }
        if (event->data.graphics.remote) {
            VIR_FREE(event->data.graphics.remote->node);
            VIR_FREE(event->data.graphics.remote->service);
            VIR_FREE(event->data.graphics.remote);
        }
        VIR_FREE(event->data.graphics.authScheme);
        if (event->data.graphics.subject) {
            int i;
            for (i = 0 ; i < event->data.graphics.subject->nidentity ; i++) {
                VIR_FREE(event->data.graphics.subject->identities[i].type);
                VIR_FREE(event->data.graphics.subject->identities[i].name);
            }
            VIR_FREE(event->data.graphics.subject);
        }
    }

    VIR_FREE(event->dom.name);
    VIR_FREE(event);
}


virDomainEventQueuePtr virDomainEventQueueNew(void)
{
    virDomainEventQueuePtr ret;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        return NULL;
    }

    return ret;
}

static virDomainEventPtr virDomainEventNewInternal(int eventID,
                                                   int id,
                                                   const char *name,
                                                   const unsigned char *uuid)
{
    virDomainEventPtr event;

    if (VIR_ALLOC(event) < 0) {
        virReportOOMError();
        return NULL;
    }

    event->eventID = eventID;
    if (!(event->dom.name = strdup(name))) {
        virReportOOMError();
        VIR_FREE(event);
        return NULL;
    }
    event->dom.id = id;
    memcpy(event->dom.uuid, uuid, VIR_UUID_BUFLEN);

    return event;
}

virDomainEventPtr virDomainEventNew(int id, const char *name,
                                    const unsigned char *uuid,
                                    int type, int detail)
{
    virDomainEventPtr event = virDomainEventNewInternal(VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                                        id, name, uuid);

    if (event) {
        event->data.lifecycle.type = type;
        event->data.lifecycle.detail = detail;
    }

    return event;
}

virDomainEventPtr virDomainEventNewFromDom(virDomainPtr dom, int type, int detail)
{
    return virDomainEventNew(dom->id, dom->name, dom->uuid, type, detail);
}

virDomainEventPtr virDomainEventNewFromObj(virDomainObjPtr obj, int type, int detail)
{
    return virDomainEventNewFromDef(obj->def, type, detail);
}

virDomainEventPtr virDomainEventNewFromDef(virDomainDefPtr def, int type, int detail)
{
    return virDomainEventNew(def->id, def->name, def->uuid, type, detail);
}

virDomainEventPtr virDomainEventRebootNewFromDom(virDomainPtr dom)
{
    return virDomainEventNewInternal(VIR_DOMAIN_EVENT_ID_REBOOT,
                                     dom->id, dom->name, dom->uuid);
}
virDomainEventPtr virDomainEventRebootNewFromObj(virDomainObjPtr obj)
{
    return virDomainEventNewInternal(VIR_DOMAIN_EVENT_ID_REBOOT,
                                     obj->def->id, obj->def->name, obj->def->uuid);
}

virDomainEventPtr virDomainEventRTCChangeNewFromDom(virDomainPtr dom,
                                                    long long offset)
{
    virDomainEventPtr ev =
        virDomainEventNewInternal(VIR_DOMAIN_EVENT_ID_RTC_CHANGE,
                                  dom->id, dom->name, dom->uuid);

    if (ev)
        ev->data.rtcChange.offset = offset;

    return ev;
}
virDomainEventPtr virDomainEventRTCChangeNewFromObj(virDomainObjPtr obj,
                                                    long long offset)
{
    virDomainEventPtr ev =
        virDomainEventNewInternal(VIR_DOMAIN_EVENT_ID_RTC_CHANGE,
                                  obj->def->id, obj->def->name, obj->def->uuid);

    if (ev)
        ev->data.rtcChange.offset = offset;

    return ev;
}

virDomainEventPtr virDomainEventWatchdogNewFromDom(virDomainPtr dom,
                                                   int action)
{
    virDomainEventPtr ev =
        virDomainEventNewInternal(VIR_DOMAIN_EVENT_ID_WATCHDOG,
                                  dom->id, dom->name, dom->uuid);

    if (ev)
        ev->data.watchdog.action = action;

    return ev;
}
virDomainEventPtr virDomainEventWatchdogNewFromObj(virDomainObjPtr obj,
                                                   int action)
{
    virDomainEventPtr ev =
        virDomainEventNewInternal(VIR_DOMAIN_EVENT_ID_WATCHDOG,
                                  obj->def->id, obj->def->name, obj->def->uuid);

    if (ev)
        ev->data.watchdog.action = action;

    return ev;
}

static virDomainEventPtr virDomainEventIOErrorNewFromDomImpl(int event,
                                                             virDomainPtr dom,
                                                             const char *srcPath,
                                                             const char *devAlias,
                                                             int action,
                                                             const char *reason)
{
    virDomainEventPtr ev =
        virDomainEventNewInternal(event,
                                  dom->id, dom->name, dom->uuid);

    if (ev) {
        ev->data.ioError.action = action;
        if (!(ev->data.ioError.srcPath = strdup(srcPath)) ||
            !(ev->data.ioError.devAlias = strdup(devAlias)) ||
            (reason && !(ev->data.ioError.reason = strdup(reason)))) {
            virDomainEventFree(ev);
            ev = NULL;
        }
    }

    return ev;
}

static virDomainEventPtr virDomainEventIOErrorNewFromObjImpl(int event,
                                                             virDomainObjPtr obj,
                                                             const char *srcPath,
                                                             const char *devAlias,
                                                             int action,
                                                             const char *reason)
{
    virDomainEventPtr ev =
        virDomainEventNewInternal(event,
                                  obj->def->id, obj->def->name, obj->def->uuid);

    if (ev) {
        ev->data.ioError.action = action;
        if (!(ev->data.ioError.srcPath = strdup(srcPath)) ||
            !(ev->data.ioError.devAlias = strdup(devAlias)) ||
            !(ev->data.ioError.reason = strdup(reason))) {
            virDomainEventFree(ev);
            ev = NULL;
        }
    }

    return ev;
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
    virDomainEventPtr ev =
        virDomainEventNewInternal(VIR_DOMAIN_EVENT_ID_GRAPHICS,
                                  dom->id, dom->name, dom->uuid);

    if (ev) {
        ev->data.graphics.phase = phase;
        if (!(ev->data.graphics.authScheme = strdup(authScheme))) {
            virDomainEventFree(ev);
            return NULL;
        }
        ev->data.graphics.local = local;
        ev->data.graphics.remote = remote;
        ev->data.graphics.subject = subject;
    }

    return ev;
}

virDomainEventPtr virDomainEventGraphicsNewFromObj(virDomainObjPtr obj,
                                                   int phase,
                                                   virDomainEventGraphicsAddressPtr local,
                                                   virDomainEventGraphicsAddressPtr remote,
                                                   const char *authScheme,
                                                   virDomainEventGraphicsSubjectPtr subject)
{
    virDomainEventPtr ev =
        virDomainEventNewInternal(VIR_DOMAIN_EVENT_ID_GRAPHICS,
                                  obj->def->id, obj->def->name, obj->def->uuid);

    if (ev) {
        ev->data.graphics.phase = phase;
        if (!(ev->data.graphics.authScheme = strdup(authScheme))) {
            virDomainEventFree(ev);
            return NULL;
        }
        ev->data.graphics.local = local;
        ev->data.graphics.remote = remote;
        ev->data.graphics.subject = subject;
    }

    return ev;
}


/**
 * virDomainEventQueueFree:
 * @queue: pointer to the queue
 *
 * Free the memory in the queue. We process this like a list here
 */
void
virDomainEventQueueFree(virDomainEventQueuePtr queue)
{
    int i;
    if (!queue)
        return;

    for (i = 0; i < queue->count ; i++) {
        virDomainEventFree(queue->events[i]);
    }
    VIR_FREE(queue->events);
    VIR_FREE(queue);
}

/**
 * virDomainEventQueuePop:
 * @evtQueue: the queue of events
 *
 * Internal function to pop off, and return the front of the queue
 * NOTE: The caller is responsible for freeing the returned object
 *
 * Returns: virDomainEventPtr on success NULL on failure.
 */
virDomainEventPtr
virDomainEventQueuePop(virDomainEventQueuePtr evtQueue)
{
    virDomainEventPtr ret;

    if (!evtQueue || evtQueue->count == 0 ) {
        eventReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                         _("event queue is empty, nothing to pop"));
        return NULL;
    }

    ret = evtQueue->events[0];

    memmove(evtQueue->events,
            evtQueue->events + 1,
            sizeof(*(evtQueue->events)) *
                    (evtQueue->count - 1));

    if (VIR_REALLOC_N(evtQueue->events,
                        evtQueue->count - 1) < 0) {
        ; /* Failure to reduce memory allocation isn't fatal */
    }
    evtQueue->count--;

    return ret;
}

/**
 * virDomainEventQueuePush:
 * @evtQueue: the dom event queue
 * @event: the event to add
 *
 * Internal function to push onto the back of an virDomainEventQueue
 *
 * Returns: 0 on success, -1 on failure
 */
int
virDomainEventQueuePush(virDomainEventQueuePtr evtQueue,
                        virDomainEventPtr event)
{
    if (!evtQueue) {
        return -1;
    }

    /* Make space on queue */
    if (VIR_REALLOC_N(evtQueue->events,
                      evtQueue->count + 1) < 0) {
        virReportOOMError();
        return -1;
    }

    evtQueue->events[evtQueue->count] = event;
    evtQueue->count++;
    return 0;
}


void virDomainEventDispatchDefaultFunc(virConnectPtr conn,
                                       virDomainEventPtr event,
                                       virConnectDomainEventGenericCallback cb,
                                       void *cbopaque,
                                       void *opaque ATTRIBUTE_UNUSED)
{
    virDomainPtr dom = virGetDomain(conn, event->dom.name, event->dom.uuid);
    if (!dom)
        return;
    dom->id = event->dom.id;

    switch (event->eventID) {
    case VIR_DOMAIN_EVENT_ID_LIFECYCLE:
        ((virConnectDomainEventCallback)cb)(conn, dom,
                                            event->data.lifecycle.type,
                                            event->data.lifecycle.detail,
                                            cbopaque);
        break;

    case VIR_DOMAIN_EVENT_ID_REBOOT:
        (cb)(conn, dom,
             cbopaque);
        break;

    case VIR_DOMAIN_EVENT_ID_RTC_CHANGE:
        ((virConnectDomainEventRTCChangeCallback)cb)(conn, dom,
                                                     event->data.rtcChange.offset,
                                                     cbopaque);
        break;

    case VIR_DOMAIN_EVENT_ID_WATCHDOG:
        ((virConnectDomainEventWatchdogCallback)cb)(conn, dom,
                                                    event->data.watchdog.action,
                                                    cbopaque);
        break;

    case VIR_DOMAIN_EVENT_ID_IO_ERROR:
        ((virConnectDomainEventIOErrorCallback)cb)(conn, dom,
                                                   event->data.ioError.srcPath,
                                                   event->data.ioError.devAlias,
                                                   event->data.ioError.action,
                                                   cbopaque);
        break;

    case VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON:
        ((virConnectDomainEventIOErrorReasonCallback)cb)(conn, dom,
                                                         event->data.ioError.srcPath,
                                                         event->data.ioError.devAlias,
                                                         event->data.ioError.action,
                                                         event->data.ioError.reason,
                                                         cbopaque);
        break;

    case VIR_DOMAIN_EVENT_ID_GRAPHICS:
        ((virConnectDomainEventGraphicsCallback)cb)(conn, dom,
                                                    event->data.graphics.phase,
                                                    event->data.graphics.local,
                                                    event->data.graphics.remote,
                                                    event->data.graphics.authScheme,
                                                    event->data.graphics.subject,
                                                    cbopaque);
        break;

    default:
        VIR_WARN("Unexpected event ID %d", event->eventID);
        break;
    }

    virDomainFree(dom);
}


static int virDomainEventDispatchMatchCallback(virDomainEventPtr event,
                                               virDomainEventCallbackPtr cb)
{
    if (!cb)
        return 0;
    if (cb->deleted)
        return 0;
    if (cb->eventID != event->eventID)
        return 0;

    if (cb->dom) {
        /* Delibrately ignoring 'id' for matching, since that
         * will cause problems when a domain switches between
         * running & shutoff states & ignoring 'name' since
         * Xen sometimes renames guests during migration, thus
         * leaving 'uuid' as the only truely reliable ID we can use*/

        if (memcmp(event->dom.uuid, cb->dom->uuid, VIR_UUID_BUFLEN) == 0)
            return 1;

        return 0;
    } else {
        return 1;
    }
}

void virDomainEventDispatch(virDomainEventPtr event,
                            virDomainEventCallbackListPtr callbacks,
                            virDomainEventDispatchFunc dispatch,
                            void *opaque)
{
    int i;
    /* Cache this now, since we may be dropping the lock,
       and have more callbacks added. We're guarenteed not
       to have any removed */
    int cbCount = callbacks->count;

    for (i = 0 ; i < cbCount ; i++) {
        if (!virDomainEventDispatchMatchCallback(event, callbacks->callbacks[i]))
            continue;

        (*dispatch)(callbacks->callbacks[i]->conn,
                    event,
                    callbacks->callbacks[i]->cb,
                    callbacks->callbacks[i]->opaque,
                    opaque);
    }
}


void virDomainEventQueueDispatch(virDomainEventQueuePtr queue,
                                 virDomainEventCallbackListPtr callbacks,
                                 virDomainEventDispatchFunc dispatch,
                                 void *opaque)
{
    int i;

    for (i = 0 ; i < queue->count ; i++) {
        virDomainEventDispatch(queue->events[i], callbacks, dispatch, opaque);
        virDomainEventFree(queue->events[i]);
    }
    VIR_FREE(queue->events);
    queue->count = 0;
}
