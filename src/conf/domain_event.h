/*
 * domain_event.h: domain event queue processing helpers
 *
 * Copyright (C) 2012-2014 Red Hat, Inc.
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

#pragma once

#include "internal.h"
#include "object_event.h"
#include "domain_conf.h"


virObjectEvent *
virDomainEventLifecycleNew(int id,
                           const char *name,
                           const unsigned char *uuid,
                           int type,
                           int detail);
virObjectEvent *
virDomainEventLifecycleNewFromDom(virDomainPtr dom,
                                  int type,
                                  int detail);
virObjectEvent *
virDomainEventLifecycleNewFromObj(virDomainObj *obj,
                                  int type,
                                  int detail);
virObjectEvent *
virDomainEventLifecycleNewFromDef(virDomainDef *def,
                                  int type,
                                  int detail);

virObjectEvent *
virDomainEventRebootNew(int id,
                        const char *name,
                        const unsigned char *uuid);
virObjectEvent *
virDomainEventRebootNewFromDom(virDomainPtr dom);
virObjectEvent *
virDomainEventRebootNewFromObj(virDomainObj *obj);

virObjectEvent *
virDomainEventRTCChangeNewFromDom(virDomainPtr dom,
                                  long long offset);
virObjectEvent *
virDomainEventRTCChangeNewFromObj(virDomainObj *obj,
                                  long long offset);

virObjectEvent *
virDomainEventWatchdogNewFromDom(virDomainPtr dom,
                                 int action);
virObjectEvent *
virDomainEventWatchdogNewFromObj(virDomainObj *obj,
                                 int action);

virObjectEvent *
virDomainEventIOErrorNewFromDom(virDomainPtr dom,
                                const char *srcPath,
                                const char *devAlias,
                                int action);
virObjectEvent *
virDomainEventIOErrorNewFromObj(virDomainObj *obj,
                                const char *srcPath,
                                const char *devAlias,
                                int action);
virObjectEvent *
virDomainEventIOErrorReasonNewFromDom(virDomainPtr dom,
                                      const char *srcPath,
                                      const char *devAlias,
                                      int action,
                                      const char *reason);
virObjectEvent *
virDomainEventIOErrorReasonNewFromObj(virDomainObj *obj,
                                      const char *srcPath,
                                      const char *devAlias,
                                      int action,
                                      const char *reason);

virObjectEvent *
virDomainEventGraphicsNewFromDom(virDomainPtr dom,
                                 int phase,
                                 virDomainEventGraphicsAddressPtr local,
                                 virDomainEventGraphicsAddressPtr remote,
                                 const char *authScheme,
                                 virDomainEventGraphicsSubjectPtr subject);
virObjectEvent *
virDomainEventGraphicsNewFromObj(virDomainObj *obj,
                                int phase,
                                virDomainEventGraphicsAddressPtr local,
                                virDomainEventGraphicsAddressPtr remote,
                                const char *authScheme,
                                virDomainEventGraphicsSubjectPtr subject);
virObjectEvent *
virDomainEventControlErrorNewFromDom(virDomainPtr dom);
virObjectEvent *
virDomainEventControlErrorNewFromObj(virDomainObj *obj);

virObjectEvent *
virDomainEventBlockJobNewFromObj(virDomainObj *obj,
                                 const char *path,
                                 int type,
                                 int status);
virObjectEvent *
virDomainEventBlockJobNewFromDom(virDomainPtr dom,
                                 const char *path,
                                 int type,
                                 int status);

virObjectEvent *
virDomainEventBlockJob2NewFromObj(virDomainObj *obj,
                                  const char *dst,
                                  int type,
                                  int status);
virObjectEvent *
virDomainEventBlockJob2NewFromDom(virDomainPtr dom,
                                  const char *dst,
                                  int type,
                                  int status);

virObjectEvent *
virDomainEventDiskChangeNewFromObj(virDomainObj *obj,
                                   const char *oldSrcPath,
                                   const char *newSrcPath,
                                   const char *devAlias,
                                   int reason);
virObjectEvent *
virDomainEventDiskChangeNewFromDom(virDomainPtr dom,
                                   const char *oldSrcPath,
                                   const char *newSrcPath,
                                   const char *devAlias,
                                   int reason);
virObjectEvent *
virDomainEventTrayChangeNewFromObj(virDomainObj *obj,
                                   const char *devAlias,
                                   int reason);
virObjectEvent *
virDomainEventTrayChangeNewFromDom(virDomainPtr dom,
                                   const char *devAlias,
                                   int reason);
virObjectEvent *
virDomainEventPMWakeupNewFromObj(virDomainObj *obj);
virObjectEvent *
virDomainEventPMWakeupNewFromDom(virDomainPtr dom, int reason);
virObjectEvent *
virDomainEventPMSuspendNewFromObj(virDomainObj *obj);
virObjectEvent *
virDomainEventPMSuspendNewFromDom(virDomainPtr dom, int reason);

virObjectEvent *
virDomainEventBalloonChangeNewFromDom(virDomainPtr dom,
                                      unsigned long long actual);
virObjectEvent *
virDomainEventBalloonChangeNewFromObj(virDomainObj *obj,
                                      unsigned long long actual);

virObjectEvent *
virDomainEventPMSuspendDiskNewFromObj(virDomainObj *obj);
virObjectEvent *
virDomainEventPMSuspendDiskNewFromDom(virDomainPtr dom, int reason);

virObjectEvent *
virDomainEventDeviceRemovedNewFromObj(virDomainObj *obj,
                                      const char *devAlias);
virObjectEvent *
virDomainEventDeviceRemovedNewFromDom(virDomainPtr dom,
                                      const char *devAlias);
virObjectEvent *
virDomainEventDeviceAddedNewFromObj(virDomainObj *obj,
                                    const char *devAlias);
virObjectEvent *
virDomainEventDeviceAddedNewFromDom(virDomainPtr dom,
                                    const char *devAlias);
virObjectEvent *
virDomainEventDeviceRemovalFailedNewFromObj(virDomainObj *obj,
                                            const char *devAlias);
virObjectEvent *
virDomainEventDeviceRemovalFailedNewFromDom(virDomainPtr dom,
                                            const char *devAlias);

virObjectEvent *
virDomainEventTunableNewFromObj(virDomainObj *obj,
                                virTypedParameterPtr *params,
                                int nparams);
virObjectEvent *
virDomainEventTunableNewFromDom(virDomainPtr dom,
                                virTypedParameterPtr *params,
                                int nparams);

virObjectEvent *
virDomainEventAgentLifecycleNewFromObj(virDomainObj *obj,
                                       int state,
                                       int reason);

virObjectEvent *
virDomainEventAgentLifecycleNewFromDom(virDomainPtr dom,
                                       int state,
                                       int reason);

virObjectEvent *
virDomainEventMigrationIterationNewFromObj(virDomainObj *obj,
                                           int iteration);

virObjectEvent *
virDomainEventMigrationIterationNewFromDom(virDomainPtr dom,
                                           int iteration);

virObjectEvent *
virDomainEventJobCompletedNewFromObj(virDomainObj *obj,
                                     virTypedParameterPtr params,
                                     int nparams);

virObjectEvent *
virDomainEventJobCompletedNewFromDom(virDomainPtr dom,
                                     virTypedParameterPtr params,
                                     int nparams);

virObjectEvent *
virDomainEventMetadataChangeNewFromObj(virDomainObj *obj,
                                       int type,
                                       const char *nsuri);

virObjectEvent *
virDomainEventMetadataChangeNewFromDom(virDomainPtr dom,
                                       int type,
                                       const char *nsuri);


virObjectEvent *
virDomainEventBlockThresholdNewFromObj(virDomainObj *obj,
                                       const char *dev,
                                       const char *path,
                                       unsigned long long threshold,
                                       unsigned long long excess);

virObjectEvent *
virDomainEventBlockThresholdNewFromDom(virDomainPtr dom,
                                       const char *dev,
                                       const char *path,
                                       unsigned long long threshold,
                                       unsigned long long excess);

virObjectEvent *
virDomainEventMemoryFailureNewFromObj(virDomainObj *obj,
                                      int recipient,
                                      int action,
                                      unsigned int flags);

virObjectEvent *
virDomainEventMemoryFailureNewFromDom(virDomainPtr dom,
                                      int recipient,
                                      int action,
                                      unsigned int flags);

virObjectEvent *
virDomainEventMemoryDeviceSizeChangeNewFromObj(virDomainObj *obj,
                                               const char *alias,
                                               unsigned long long size);

virObjectEvent *
virDomainEventMemoryDeviceSizeChangeNewFromDom(virDomainPtr dom,
                                               const char *alias,
                                               unsigned long long size);

int
virDomainEventStateRegister(virConnectPtr conn,
                            virObjectEventState *state,
                            virConnectDomainEventCallback callback,
                            void *opaque,
                            virFreeCallback freecb)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
int
virDomainEventStateRegisterID(virConnectPtr conn,
                              virObjectEventState *state,
                              virDomainPtr dom,
                              int eventID,
                              virConnectDomainEventGenericCallback cb,
                              void *opaque,
                              virFreeCallback freecb,
                              int *callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5);
int
virDomainEventStateRegisterClient(virConnectPtr conn,
                                  virObjectEventState *state,
                                  virDomainPtr dom,
                                  int eventID,
                                  virConnectDomainEventGenericCallback cb,
                                  void *opaque,
                                  virFreeCallback freecb,
                                  bool legacy,
                                  int *callbackID,
                                  bool remoteID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5)
    ATTRIBUTE_NONNULL(9);

int
virDomainEventStateCallbackID(virConnectPtr conn,
                              virObjectEventState *state,
                              virConnectDomainEventCallback callback,
                              int *remoteID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);

int
virDomainEventStateDeregister(virConnectPtr conn,
                              virObjectEventState *state,
                              virConnectDomainEventCallback callback)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int
virDomainQemuMonitorEventStateRegisterID(virConnectPtr conn,
                                         virObjectEventState *state,
                                         virDomainPtr dom,
                                         const char *event,
                                         virConnectDomainQemuMonitorEventCallback cb,
                                         void *opaque,
                                         virFreeCallback freecb,
                                         unsigned int flags,
                                         int *callbackID)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(5)
    ATTRIBUTE_NONNULL(9);

virObjectEvent *
virDomainQemuMonitorEventNew(int id,
                             const char *name,
                             const unsigned char *uuid,
                             const char *event,
                             long long seconds,
                             unsigned int micros,
                             const char *details)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4);
