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

typedef struct _virDomainEventCallbackList virDomainEventCallbackList;
typedef virDomainEventCallbackList *virDomainEventCallbackListPtr;

/**
 * Dispatching domain events that come in while
 * in a call / response rpc
 */
typedef struct _virDomainEvent virDomainEvent;
typedef virDomainEvent *virDomainEventPtr;

typedef struct _virDomainEventQueue virDomainEventQueue;
typedef virDomainEventQueue *virDomainEventQueuePtr;

typedef struct _virDomainEventState virDomainEventState;
typedef virDomainEventState *virDomainEventStatePtr;

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

virDomainEventPtr virDomainEventBlockJobNewFromObj(virDomainObjPtr obj,
                                                    const char *path,
                                                    int type,
                                                    int status);
virDomainEventPtr virDomainEventBlockJobNewFromDom(virDomainPtr dom,
                                                    const char *path,
                                                    int type,
                                                    int status);

virDomainEventPtr virDomainEventDiskChangeNewFromObj(virDomainObjPtr obj,
                                                     const char *oldSrcPath,
                                                     const char *newSrcPath,
                                                     const char *devAlias,
                                                     int reason);
virDomainEventPtr virDomainEventDiskChangeNewFromDom(virDomainPtr dom,
                                                     const char *oldSrcPath,
                                                     const char *newSrcPath,
                                                     const char *devAlias,
                                                     int reason);
virDomainEventPtr virDomainEventTrayChangeNewFromObj(virDomainObjPtr obj,
                                                     const char *devAlias,
                                                     int reason);
virDomainEventPtr virDomainEventTrayChangeNewFromDom(virDomainPtr dom,
                                                     const char *devAlias,
                                                     int reason);
virDomainEventPtr virDomainEventPMWakeupNewFromObj(virDomainObjPtr obj);
virDomainEventPtr virDomainEventPMWakeupNewFromDom(virDomainPtr dom);
virDomainEventPtr virDomainEventPMSuspendNewFromObj(virDomainObjPtr obj);
virDomainEventPtr virDomainEventPMSuspendNewFromDom(virDomainPtr dom);

void virDomainEventFree(virDomainEventPtr event);

void virDomainEventStateFree(virDomainEventStatePtr state);
virDomainEventStatePtr
virDomainEventStateNew(void);

void
virDomainEventStateQueue(virDomainEventStatePtr state,
                         virDomainEventPtr event)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int virDomainEventStateRegister(virConnectPtr conn,
                                virDomainEventStatePtr state,
                                virConnectDomainEventCallback callback,
                                void *opaque,
                                virFreeCallback freecb)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
int virDomainEventStateRegisterID(virConnectPtr conn,
                                  virDomainEventStatePtr state,
                                  virDomainPtr dom,
                                  int eventID,
                                  virConnectDomainEventGenericCallback cb,
                                  void *opaque,
                                  virFreeCallback freecb,
                                  int *callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);
int
virDomainEventStateDeregister(virConnectPtr conn,
                              virDomainEventStatePtr state,
                              virConnectDomainEventCallback callback)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
int
virDomainEventStateDeregisterID(virConnectPtr conn,
                                virDomainEventStatePtr state,
                                int callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int
virDomainEventStateDeregisterConn(virConnectPtr conn,
                                  virDomainEventStatePtr state)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int
virDomainEventStateEventID(virConnectPtr conn,
                           virDomainEventStatePtr state,
                           int callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

#endif
