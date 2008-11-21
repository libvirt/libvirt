/*
 * domain_event.c: domain event queue processing helpers
 *
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
        if(cbList->callbacks[i]->cb == callback &&
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
        if(cbList->callbacks[i]->conn == conn) {
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
    virDomainEventCallbackPtr event;
    int n;

    /* Check incoming */
    if ( !cbList ) {
        return -1;
    }

    /* check if we already have this callback on our list */
    for (n=0; n < cbList->count; n++) {
        if(cbList->callbacks[n]->cb == callback &&
           conn == cbList->callbacks[n]->conn) {
            DEBUG0("WARNING: Callback already tracked");
            return -1;
        }
    }
    /* Allocate new event */
    if (VIR_ALLOC(event) < 0) {
        DEBUG0("Error allocating event");
        return -1;
    }
    event->conn = conn;
    event->cb = callback;
    event->opaque = opaque;
    event->freecb = freecb;

    /* Make space on list */
    n = cbList->count;
    if (VIR_REALLOC_N(cbList->callbacks, n + 1) < 0) {
        DEBUG0("Error reallocating list");
        VIR_FREE(event);
        return -1;
    }

    event->conn->refs++;

    cbList->callbacks[n] = event;
    cbList->count++;
    return 0;
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
    for ( i=0 ; i<queue->count ; i++ ) {
        VIR_FREE(queue->events[i]);
    }
    VIR_FREE(queue);
}

/**
 * virDomainEventCallbackQueuePop:
 * @evtQueue: the queue of events
 *
 * Internal function to pop off, and return the front of the queue
 * NOTE: The caller is responsible for freeing the returned object
 *
 * Returns: virDomainEventPtr on success NULL on failure.
 */
virDomainEventPtr
virDomainEventCallbackQueuePop(virDomainEventQueuePtr evtQueue)
{
    virDomainEventPtr ret;

    if(!evtQueue || evtQueue->count == 0 )
        return NULL;

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
 * virDomainEventCallbackQueuePush:
 * @evtQueue: the dom event queue
 * @dom: the domain to add
 * @event: the event to add
 *
 * Internal function to push onto the back of an virDomainEventQueue
 *
 * Returns: 0 on success, -1 on failure
 */
int
virDomainEventCallbackQueuePush(virDomainEventQueuePtr evtQueue,
                                virDomainPtr dom,
                                int event,
                                int detail)
{
    virDomainEventPtr domEvent;

    /* Check incoming */
    if ( !evtQueue ) {
        return -1;
    }

    /* Allocate new event */
    if (VIR_ALLOC(domEvent) < 0) {
        DEBUG0("Error allocating event");
        return -1;
    }
    domEvent->dom = dom;
    domEvent->event = event;
    domEvent->detail = detail;

    /* Make space on queue */
    if (VIR_REALLOC_N(evtQueue->events,
                      evtQueue->count + 1) < 0) {
        DEBUG0("Error reallocating queue");
        VIR_FREE(domEvent);
        return -1;
    }

    evtQueue->events[evtQueue->count] = domEvent;
    evtQueue->count++;
    return 0;
}

