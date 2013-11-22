/*
 * domain_event.h: domain event queue processing helpers
 *
 * Copyright (C) 2012 Red Hat, Inc.
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

#include "internal.h"

#ifndef __DOMAIN_EVENT_H__
# define __DOMAIN_EVENT_H__

# include "domain_conf.h"

typedef struct _virObjectEventCallback virObjectEventCallback;
typedef virObjectEventCallback *virObjectEventCallbackPtr;

/**
 * Dispatching domain events that come in while
 * in a call / response rpc
 */
typedef struct _virObjectEvent virObjectEvent;
typedef virObjectEvent *virObjectEventPtr;

typedef struct _virObjectEventState virObjectEventState;
typedef virObjectEventState *virObjectEventStatePtr;

virObjectEventPtr virDomainEventLifecycleNew(int id,
                                             const char *name,
                                             const unsigned char *uuid,
                                             int type,
                                             int detail);
virObjectEventPtr virDomainEventLifecycleNewFromDom(virDomainPtr dom,
                                                    int type,
                                                    int detail);
virObjectEventPtr virDomainEventLifecycleNewFromObj(virDomainObjPtr obj,
                                                    int type,
                                                    int detail);
virObjectEventPtr virDomainEventLifecycleNewFromDef(virDomainDefPtr def,
                                                    int type,
                                                    int detail);

virObjectEventPtr virDomainEventRebootNew(int id, const char *name, const unsigned char *uuid);
virObjectEventPtr virDomainEventRebootNewFromDom(virDomainPtr dom);
virObjectEventPtr virDomainEventRebootNewFromObj(virDomainObjPtr obj);

virObjectEventPtr virDomainEventRTCChangeNewFromDom(virDomainPtr dom, long long offset);
virObjectEventPtr virDomainEventRTCChangeNewFromObj(virDomainObjPtr obj, long long offset);

virObjectEventPtr virDomainEventWatchdogNewFromDom(virDomainPtr dom, int action);
virObjectEventPtr virDomainEventWatchdogNewFromObj(virDomainObjPtr obj, int action);

virObjectEventPtr virDomainEventIOErrorNewFromDom(virDomainPtr dom,
                                                  const char *srcPath,
                                                  const char *devAlias,
                                                  int action);
virObjectEventPtr virDomainEventIOErrorNewFromObj(virDomainObjPtr obj,
                                                  const char *srcPath,
                                                  const char *devAlias,
                                                  int action);
virObjectEventPtr virDomainEventIOErrorReasonNewFromDom(virDomainPtr dom,
                                                        const char *srcPath,
                                                        const char *devAlias,
                                                        int action,
                                                        const char *reason);
virObjectEventPtr virDomainEventIOErrorReasonNewFromObj(virDomainObjPtr obj,
                                                        const char *srcPath,
                                                        const char *devAlias,
                                                        int action,
                                                        const char *reason);

virObjectEventPtr virDomainEventGraphicsNewFromDom(virDomainPtr dom,
                                       int phase,
                                       virDomainEventGraphicsAddressPtr local,
                                       virDomainEventGraphicsAddressPtr remote,
                                       const char *authScheme,
                                       virDomainEventGraphicsSubjectPtr subject);
virObjectEventPtr virDomainEventGraphicsNewFromObj(virDomainObjPtr obj,
                                       int phase,
                                       virDomainEventGraphicsAddressPtr local,
                                       virDomainEventGraphicsAddressPtr remote,
                                       const char *authScheme,
                                       virDomainEventGraphicsSubjectPtr subject);
virObjectEventPtr virDomainEventControlErrorNewFromDom(virDomainPtr dom);
virObjectEventPtr virDomainEventControlErrorNewFromObj(virDomainObjPtr obj);

virObjectEventPtr virDomainEventBlockJobNewFromObj(virDomainObjPtr obj,
                                                   const char *path,
                                                   int type,
                                                   int status);
virObjectEventPtr virDomainEventBlockJobNewFromDom(virDomainPtr dom,
                                                   const char *path,
                                                   int type,
                                                   int status);

virObjectEventPtr virDomainEventDiskChangeNewFromObj(virDomainObjPtr obj,
                                                     const char *oldSrcPath,
                                                     const char *newSrcPath,
                                                     const char *devAlias,
                                                     int reason);
virObjectEventPtr virDomainEventDiskChangeNewFromDom(virDomainPtr dom,
                                                     const char *oldSrcPath,
                                                     const char *newSrcPath,
                                                     const char *devAlias,
                                                     int reason);
virObjectEventPtr virDomainEventTrayChangeNewFromObj(virDomainObjPtr obj,
                                                     const char *devAlias,
                                                     int reason);
virObjectEventPtr virDomainEventTrayChangeNewFromDom(virDomainPtr dom,
                                                     const char *devAlias,
                                                     int reason);
virObjectEventPtr virDomainEventPMWakeupNewFromObj(virDomainObjPtr obj);
virObjectEventPtr virDomainEventPMWakeupNewFromDom(virDomainPtr dom);
virObjectEventPtr virDomainEventPMSuspendNewFromObj(virDomainObjPtr obj);
virObjectEventPtr virDomainEventPMSuspendNewFromDom(virDomainPtr dom);

virObjectEventPtr virDomainEventBalloonChangeNewFromDom(virDomainPtr dom, unsigned long long actual);
virObjectEventPtr virDomainEventBalloonChangeNewFromObj(virDomainObjPtr obj, unsigned long long actual);

virObjectEventPtr virDomainEventPMSuspendDiskNewFromObj(virDomainObjPtr obj);
virObjectEventPtr virDomainEventPMSuspendDiskNewFromDom(virDomainPtr dom);

virObjectEventPtr virDomainEventDeviceRemovedNewFromObj(virDomainObjPtr obj,
                                                        const char *devAlias);
virObjectEventPtr virDomainEventDeviceRemovedNewFromDom(virDomainPtr dom,
                                                        const char *devAlias);

void virObjectEventStateFree(virObjectEventStatePtr state);
virObjectEventStatePtr
virObjectEventStateNew(void);

/*
 * virConnectObjectEventGenericCallback:
 * @conn: the connection pointer
 * @obj: the object pointer
 * @opaque: application specified data
 *
 * A generic object event callback handler. Specific events usually
 * have a customization with extra parameters
 */
typedef void (*virConnectObjectEventGenericCallback)(virConnectPtr conn,
                                                     void *obj,
                                                     void *opaque);

void
virObjectEventStateQueue(virObjectEventStatePtr state,
                         virObjectEventPtr event)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int virDomainEventStateRegister(virConnectPtr conn,
                                virObjectEventStatePtr state,
                                virConnectDomainEventCallback callback,
                                void *opaque,
                                virFreeCallback freecb)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
int virDomainEventStateRegisterID(virConnectPtr conn,
                                  virObjectEventStatePtr state,
                                  virDomainPtr dom,
                                  int eventID,
                                  virConnectDomainEventGenericCallback cb,
                                  void *opaque,
                                  virFreeCallback freecb,
                                  int *callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);
int
virDomainEventStateDeregister(virConnectPtr conn,
                              virObjectEventStatePtr state,
                              virConnectDomainEventCallback callback)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
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
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(7);
int
virObjectEventStateDeregisterID(virConnectPtr conn,
                                virObjectEventStatePtr state,
                                int callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int
virObjectEventStateEventID(virConnectPtr conn,
                           virObjectEventStatePtr state,
                           int callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

#endif
