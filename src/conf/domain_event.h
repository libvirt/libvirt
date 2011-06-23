/*
 * domain_event.h: domain event queue processing helpers
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

#include "internal.h"

#ifndef __DOMAIN_EVENT_H__
# define __DOMAIN_EVENT_H__

# include "domain_conf.h"

typedef struct _virDomainEventCallback virDomainEventCallback;
typedef virDomainEventCallback *virDomainEventCallbackPtr;

struct _virDomainEventCallbackList {
    unsigned int nextID;
    unsigned int count;
    virDomainEventCallbackPtr *callbacks;
};
typedef struct _virDomainEventCallbackList virDomainEventCallbackList;
typedef virDomainEventCallbackList *virDomainEventCallbackListPtr;

/**
 * Dispatching domain events that come in while
 * in a call / response rpc
 */
typedef struct _virDomainEvent virDomainEvent;
typedef virDomainEvent *virDomainEventPtr;

struct _virDomainEventQueue {
    unsigned int count;
    virDomainEventPtr *events;
};
typedef struct _virDomainEventQueue virDomainEventQueue;
typedef virDomainEventQueue *virDomainEventQueuePtr;

struct _virDomainEventState {
    /* The list of domain event callbacks */
    virDomainEventCallbackListPtr callbacks;
    /* The queue of domain events */
    virDomainEventQueuePtr queue;
    /* Timer for flushing events queue */
    int timer;
    /* Flag if we're in process of dispatching */
    bool isDispatching;
};
typedef struct _virDomainEventState virDomainEventState;
typedef virDomainEventState *virDomainEventStatePtr;

void virDomainEventCallbackListFree(virDomainEventCallbackListPtr list);

int virDomainEventCallbackListAdd(virConnectPtr conn,
                                  virDomainEventCallbackListPtr cbList,
                                  virConnectDomainEventCallback callback,
                                  void *opaque,
                                  virFreeCallback freecb)
    ATTRIBUTE_NONNULL(1);
int virDomainEventCallbackListAddID(virConnectPtr conn,
                                    virDomainEventCallbackListPtr cbList,
                                    virDomainPtr dom,
                                    int eventID,
                                    virConnectDomainEventGenericCallback cb,
                                    void *opaque,
                                    virFreeCallback freecb)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(5);


int virDomainEventCallbackListRemove(virConnectPtr conn,
                                     virDomainEventCallbackListPtr cbList,
                                     virConnectDomainEventCallback callback)
    ATTRIBUTE_NONNULL(1);
int virDomainEventCallbackListRemoveID(virConnectPtr conn,
                                       virDomainEventCallbackListPtr cbList,
                                       int callbackID)
    ATTRIBUTE_NONNULL(1);
int virDomainEventCallbackListRemoveConn(virConnectPtr conn,
                                         virDomainEventCallbackListPtr cbList)
    ATTRIBUTE_NONNULL(1);


int virDomainEventCallbackListMarkDelete(virConnectPtr conn,
                                         virDomainEventCallbackListPtr cbList,
                                         virConnectDomainEventCallback callback)
    ATTRIBUTE_NONNULL(1);
int virDomainEventCallbackListMarkDeleteID(virConnectPtr conn,
                                           virDomainEventCallbackListPtr cbList,
                                           int callbackID)
    ATTRIBUTE_NONNULL(1);


int virDomainEventCallbackListPurgeMarked(virDomainEventCallbackListPtr cbList);

int virDomainEventCallbackListCount(virDomainEventCallbackListPtr cbList);
int virDomainEventCallbackListCountID(virConnectPtr conn,
                                      virDomainEventCallbackListPtr cbList,
                                      int eventID)
    ATTRIBUTE_NONNULL(1);
int virDomainEventCallbackListEventID(virConnectPtr conn,
                                      virDomainEventCallbackListPtr cbList,
                                      int callbackID)
    ATTRIBUTE_NONNULL(1);

virDomainEventQueuePtr virDomainEventQueueNew(void);

virDomainEventPtr virDomainEventNew(int id, const char *name, const unsigned char *uuid, int type, int detail);
virDomainEventPtr virDomainEventNewFromDom(virDomainPtr dom, int type, int detail);
virDomainEventPtr virDomainEventNewFromObj(virDomainObjPtr obj, int type, int detail);
virDomainEventPtr virDomainEventNewFromDef(virDomainDefPtr def, int type, int detail);

virDomainEventPtr virDomainEventRebootNew(int id, const char *name, const unsigned char *uuid);
virDomainEventPtr virDomainEventRebootNewFromDom(virDomainPtr dom);
virDomainEventPtr virDomainEventRebootNewFromObj(virDomainObjPtr obj);

virDomainEventPtr virDomainEventRTCChangeNewFromDom(virDomainPtr dom, long long offset);
virDomainEventPtr virDomainEventRTCChangeNewFromObj(virDomainObjPtr obj, long long offset);

virDomainEventPtr virDomainEventWatchdogNewFromDom(virDomainPtr dom, int action);
virDomainEventPtr virDomainEventWatchdogNewFromObj(virDomainObjPtr obj, int action);

virDomainEventPtr virDomainEventIOErrorNewFromDom(virDomainPtr dom,
                                                  const char *srcPath,
                                                  const char *devAlias,
                                                  int action);
virDomainEventPtr virDomainEventIOErrorNewFromObj(virDomainObjPtr obj,
                                                  const char *srcPath,
                                                  const char *devAlias,
                                                  int action);
virDomainEventPtr virDomainEventIOErrorReasonNewFromDom(virDomainPtr dom,
                                                        const char *srcPath,
                                                        const char *devAlias,
                                                        int action,
                                                        const char *reason);
virDomainEventPtr virDomainEventIOErrorReasonNewFromObj(virDomainObjPtr obj,
                                                        const char *srcPath,
                                                        const char *devAlias,
                                                        int action,
                                                        const char *reason);

virDomainEventPtr virDomainEventGraphicsNewFromDom(virDomainPtr dom,
                                                   int phase,
                                                   virDomainEventGraphicsAddressPtr local,
                                                   virDomainEventGraphicsAddressPtr remote,
                                                   const char *authScheme,
                                                   virDomainEventGraphicsSubjectPtr subject);
virDomainEventPtr virDomainEventGraphicsNewFromObj(virDomainObjPtr obj,
                                                   int phase,
                                                   virDomainEventGraphicsAddressPtr local,
                                                   virDomainEventGraphicsAddressPtr remote,
                                                   const char *authScheme,
                                                   virDomainEventGraphicsSubjectPtr subject);
virDomainEventPtr virDomainEventControlErrorNewFromDom(virDomainPtr dom);
virDomainEventPtr virDomainEventControlErrorNewFromObj(virDomainObjPtr obj);



int virDomainEventQueuePush(virDomainEventQueuePtr evtQueue,
                            virDomainEventPtr event);

virDomainEventPtr
virDomainEventQueuePop(virDomainEventQueuePtr evtQueue);

void virDomainEventFree(virDomainEventPtr event);
void virDomainEventQueueFree(virDomainEventQueuePtr queue);
void virDomainEventStateFree(virDomainEventStatePtr state);
virDomainEventStatePtr
virDomainEventStateNew(virEventTimeoutCallback timeout_cb,
                       void *timeout_opaque,
                       virFreeCallback timeout_free,
                       bool requireTimer)
    ATTRIBUTE_NONNULL(1);

typedef void (*virDomainEventDispatchFunc)(virConnectPtr conn,
                                           virDomainEventPtr event,
                                           virConnectDomainEventGenericCallback cb,
                                           void *cbopaque,
                                           void *opaque);
void virDomainEventDispatchDefaultFunc(virConnectPtr conn,
                                       virDomainEventPtr event,
                                       virConnectDomainEventGenericCallback cb,
                                       void *cbopaque,
                                       void *opaque);

void virDomainEventDispatch(virDomainEventPtr event,
                            virDomainEventCallbackListPtr cbs,
                            virDomainEventDispatchFunc dispatch,
                            void *opaque);
void virDomainEventQueueDispatch(virDomainEventQueuePtr queue,
                                 virDomainEventCallbackListPtr cbs,
                                 virDomainEventDispatchFunc dispatch,
                                 void *opaque);


void
virDomainEventStateQueue(virDomainEventStatePtr state,
                         virDomainEventPtr event)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void
virDomainEventStateFlush(virDomainEventStatePtr state,
                         virDomainEventDispatchFunc dispatchFunc,
                         void *opaque)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int
virDomainEventStateDeregister(virConnectPtr conn,
                              virDomainEventStatePtr state,
                              virConnectDomainEventCallback callback)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
int
virDomainEventStateDeregisterAny(virConnectPtr conn,
                                 virDomainEventStatePtr state,
                                 int callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

#endif
