/*
 * domain_event.c: domain event queue processing helpers
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

#include "domain_event.h"
#include "object_event.h"
#include "object_event_private.h"
#include "virlog.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.domain_event");

static virClass *virDomainEventClass;
static virClass *virDomainEventLifecycleClass;
static virClass *virDomainEventRTCChangeClass;
static virClass *virDomainEventWatchdogClass;
static virClass *virDomainEventIOErrorClass;
static virClass *virDomainEventGraphicsClass;
static virClass *virDomainEventBlockJobClass;
static virClass *virDomainEventDiskChangeClass;
static virClass *virDomainEventTrayChangeClass;
static virClass *virDomainEventBalloonChangeClass;
static virClass *virDomainEventDeviceRemovedClass;
static virClass *virDomainEventPMClass;
static virClass *virDomainQemuMonitorEventClass;
static virClass *virDomainEventTunableClass;
static virClass *virDomainEventAgentLifecycleClass;
static virClass *virDomainEventDeviceAddedClass;
static virClass *virDomainEventMigrationIterationClass;
static virClass *virDomainEventJobCompletedClass;
static virClass *virDomainEventDeviceRemovalFailedClass;
static virClass *virDomainEventMetadataChangeClass;
static virClass *virDomainEventBlockThresholdClass;
static virClass *virDomainEventMemoryFailureClass;
static virClass *virDomainEventMemoryDeviceSizeChangeClass;

static void virDomainEventDispose(void *obj);
static void virDomainEventLifecycleDispose(void *obj);
static void virDomainEventRTCChangeDispose(void *obj);
static void virDomainEventWatchdogDispose(void *obj);
static void virDomainEventIOErrorDispose(void *obj);
static void virDomainEventGraphicsDispose(void *obj);
static void virDomainEventBlockJobDispose(void *obj);
static void virDomainEventDiskChangeDispose(void *obj);
static void virDomainEventTrayChangeDispose(void *obj);
static void virDomainEventBalloonChangeDispose(void *obj);
static void virDomainEventDeviceRemovedDispose(void *obj);
static void virDomainEventPMDispose(void *obj);
static void virDomainQemuMonitorEventDispose(void *obj);
static void virDomainEventTunableDispose(void *obj);
static void virDomainEventAgentLifecycleDispose(void *obj);
static void virDomainEventDeviceAddedDispose(void *obj);
static void virDomainEventMigrationIterationDispose(void *obj);
static void virDomainEventJobCompletedDispose(void *obj);
static void virDomainEventDeviceRemovalFailedDispose(void *obj);
static void virDomainEventMetadataChangeDispose(void *obj);
static void virDomainEventBlockThresholdDispose(void *obj);
static void virDomainEventMemoryFailureDispose(void *obj);
static void virDomainEventMemoryDeviceSizeChangeDispose(void *obj);

static void
virDomainEventDispatchDefaultFunc(virConnectPtr conn,
                                  virObjectEvent *event,
                                  virConnectObjectEventGenericCallback cb,
                                  void *cbopaque);

static void
virDomainQemuMonitorEventDispatchFunc(virConnectPtr conn,
                                      virObjectEvent *event,
                                      virConnectObjectEventGenericCallback cb,
                                      void *cbopaque);

struct _virDomainEvent {
    virObjectEvent parent;

    /* Unused attribute to allow for subclass creation */
    bool dummy;
};
typedef struct _virDomainEvent virDomainEvent;

struct _virDomainEventLifecycle {
    virDomainEvent parent;

    int type;
    int detail;
};
typedef struct _virDomainEventLifecycle virDomainEventLifecycle;

struct _virDomainEventRTCChange {
    virDomainEvent parent;

    long long offset;
};
typedef struct _virDomainEventRTCChange virDomainEventRTCChange;

struct _virDomainEventWatchdog {
    virDomainEvent parent;

    int action;
};
typedef struct _virDomainEventWatchdog virDomainEventWatchdog;

struct _virDomainEventIOError {
    virDomainEvent parent;

    char *srcPath;
    char *devAlias;
    int action;
    char *reason;
};
typedef struct _virDomainEventIOError virDomainEventIOError;

struct _virDomainEventBlockJob {
    virDomainEvent parent;

    char *disk; /* path or dst, depending on event id */
    int type;
    int status;
};
typedef struct _virDomainEventBlockJob virDomainEventBlockJob;

struct _virDomainEventGraphics {
    virDomainEvent parent;

    int phase;
    virDomainEventGraphicsAddressPtr local;
    virDomainEventGraphicsAddressPtr remote;
    char *authScheme;
    virDomainEventGraphicsSubjectPtr subject;
};
typedef struct _virDomainEventGraphics virDomainEventGraphics;

struct _virDomainEventDiskChange {
    virDomainEvent parent;

    char *oldSrcPath;
    char *newSrcPath;
    char *devAlias;
    int reason;
};
typedef struct _virDomainEventDiskChange virDomainEventDiskChange;

struct _virDomainEventTrayChange {
    virDomainEvent parent;

    char *devAlias;
    int reason;
};
typedef struct _virDomainEventTrayChange virDomainEventTrayChange;

struct _virDomainEventBalloonChange {
    virDomainEvent parent;

    /* In unit of 1024 bytes */
    unsigned long long actual;
};
typedef struct _virDomainEventBalloonChange virDomainEventBalloonChange;

struct _virDomainEventDeviceRemoved {
    virDomainEvent parent;

    char *devAlias;
};
typedef struct _virDomainEventDeviceRemoved virDomainEventDeviceRemoved;

struct _virDomainEventDeviceAdded {
    virDomainEvent parent;

    char *devAlias;
};
typedef struct _virDomainEventDeviceAdded virDomainEventDeviceAdded;

struct _virDomainEventPM {
    virDomainEvent parent;

    int reason;
};
typedef struct _virDomainEventPM virDomainEventPM;

struct _virDomainQemuMonitorEvent {
    virObjectEvent parent;

    char *event;
    long long seconds;
    unsigned int micros;
    char *details;
};
typedef struct _virDomainQemuMonitorEvent virDomainQemuMonitorEvent;

struct _virDomainEventTunable {
    virDomainEvent parent;

    virTypedParameterPtr params;
    int nparams;
};
typedef struct _virDomainEventTunable virDomainEventTunable;

struct _virDomainEventAgentLifecycle {
    virDomainEvent parent;

    int state;
    int reason;
};
typedef struct _virDomainEventAgentLifecycle virDomainEventAgentLifecycle;

struct _virDomainEventMigrationIteration {
    virDomainEvent parent;

    int iteration;
};
typedef struct _virDomainEventMigrationIteration virDomainEventMigrationIteration;

struct _virDomainEventJobCompleted {
    virDomainEvent parent;

    virTypedParameterPtr params;
    int nparams;
};
typedef struct _virDomainEventJobCompleted virDomainEventJobCompleted;

struct _virDomainEventDeviceRemovalFailed {
    virDomainEvent parent;

    char *devAlias;
};
typedef struct _virDomainEventDeviceRemovalFailed virDomainEventDeviceRemovalFailed;

struct _virDomainEventMetadataChange {
    virDomainEvent parent;

    int type;
    char *nsuri;
};
typedef struct _virDomainEventMetadataChange virDomainEventMetadataChange;

struct _virDomainEventBlockThreshold {
    virDomainEvent parent;

    char *dev;
    char *path;

    unsigned long long threshold;
    unsigned long long excess;
};
typedef struct _virDomainEventBlockThreshold virDomainEventBlockThreshold;

struct _virDomainEventMemoryFailure {
    virDomainEvent parent;

    int recipient;
    int action;
    unsigned int flags;
};
typedef struct _virDomainEventMemoryFailure virDomainEventMemoryFailure;

struct _virDomainEventMemoryDeviceSizeChange {
    virDomainEvent parent;

    char *alias;
    unsigned long long size;
};
typedef struct _virDomainEventMemoryDeviceSizeChange virDomainEventMemoryDeviceSizeChange;

static int
virDomainEventsOnceInit(void)
{
    if (!VIR_CLASS_NEW(virDomainEvent, virClassForObjectEvent()))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventLifecycle, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventRTCChange, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventWatchdog, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventIOError, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventGraphics, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventBlockJob, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventDiskChange, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventTrayChange, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventBalloonChange, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventDeviceRemoved, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventDeviceAdded, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventPM, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainQemuMonitorEvent, virClassForObjectEvent()))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventTunable, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventAgentLifecycle, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventMigrationIteration, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventJobCompleted, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventDeviceRemovalFailed, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventMetadataChange, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventBlockThreshold, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventMemoryFailure, virDomainEventClass))
        return -1;
    if (!VIR_CLASS_NEW(virDomainEventMemoryDeviceSizeChange, virDomainEventClass))
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDomainEvents);


static void
virDomainEventDispose(void *obj)
{
    virDomainEvent *event = obj;

    VIR_DEBUG("obj=%p", event);
}

static void
virDomainEventLifecycleDispose(void *obj)
{
    virDomainEventLifecycle *event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void
virDomainEventRTCChangeDispose(void *obj)
{
    virDomainEventRTCChange *event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void
virDomainEventWatchdogDispose(void *obj)
{
    virDomainEventWatchdog *event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void
virDomainEventIOErrorDispose(void *obj)
{
    virDomainEventIOError *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->srcPath);
    g_free(event->devAlias);
    g_free(event->reason);
}

static void
virDomainEventGraphicsDispose(void *obj)
{
    virDomainEventGraphics *event = obj;
    VIR_DEBUG("obj=%p", event);

    if (event->local) {
        g_free(event->local->node);
        g_free(event->local->service);
        g_free(event->local);
    }
    if (event->remote) {
        g_free(event->remote->node);
        g_free(event->remote->service);
        g_free(event->remote);
    }
    g_free(event->authScheme);
    if (event->subject) {
        size_t i;
        for (i = 0; i < event->subject->nidentity; i++) {
            g_free(event->subject->identities[i].type);
            g_free(event->subject->identities[i].name);
        }
        g_free(event->subject);
    }
}

static void
virDomainEventBlockJobDispose(void *obj)
{
    virDomainEventBlockJob *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->disk);
}

static void
virDomainEventDiskChangeDispose(void *obj)
{
    virDomainEventDiskChange *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->oldSrcPath);
    g_free(event->newSrcPath);
    g_free(event->devAlias);
}

static void
virDomainEventTrayChangeDispose(void *obj)
{
    virDomainEventTrayChange *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->devAlias);
}

static void
virDomainEventBalloonChangeDispose(void *obj)
{
    virDomainEventBalloonChange *event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void
virDomainEventDeviceRemovedDispose(void *obj)
{
    virDomainEventDeviceRemoved *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->devAlias);
}

static void
virDomainEventDeviceAddedDispose(void *obj)
{
    virDomainEventDeviceAdded *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->devAlias);
}


static void
virDomainEventDeviceRemovalFailedDispose(void *obj)
{
    virDomainEventDeviceRemovalFailed *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->devAlias);
}


static void
virDomainEventPMDispose(void *obj)
{
    virDomainEventPM *event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void
virDomainQemuMonitorEventDispose(void *obj)
{
    virDomainQemuMonitorEvent *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->event);
    g_free(event->details);
}

static void
virDomainEventTunableDispose(void *obj)
{
    virDomainEventTunable *event = obj;
    VIR_DEBUG("obj=%p", event);

    virTypedParamsFree(event->params, event->nparams);
}

static void
virDomainEventAgentLifecycleDispose(void *obj)
{
    virDomainEventAgentLifecycle *event = obj;
    VIR_DEBUG("obj=%p", event);
};

static void
virDomainEventMigrationIterationDispose(void *obj)
{
    virDomainEventMigrationIteration *event = obj;
    VIR_DEBUG("obj=%p", event);
};

static void
virDomainEventJobCompletedDispose(void *obj)
{
    virDomainEventJobCompleted *event = obj;
    VIR_DEBUG("obj=%p", event);

    virTypedParamsFree(event->params, event->nparams);
}


static void
virDomainEventMetadataChangeDispose(void *obj)
{
    virDomainEventMetadataChange *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->nsuri);
}


static void
virDomainEventBlockThresholdDispose(void *obj)
{
    virDomainEventBlockThreshold *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->dev);
    g_free(event->path);
}


static void
virDomainEventMemoryFailureDispose(void *obj)
{
    virDomainEventMemoryFailure *event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void
virDomainEventMemoryDeviceSizeChangeDispose(void *obj)
{
    virDomainEventMemoryDeviceSizeChange *event = obj;
    VIR_DEBUG("obj=%p", event);

    g_free(event->alias);
}

static void *
virDomainEventNew(virClass *klass,
                  int eventID,
                  int id,
                  const char *name,
                  const unsigned char *uuid)
{
    virDomainEvent *event;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!virClassIsDerivedFrom(klass, virDomainEventClass)) {
        virReportInvalidArg(klass,
                            _("Class %1$s must derive from virDomainEvent"),
                            virClassName(klass));
        return NULL;
    }

    /* We use uuid for matching key. We ignore 'name' because
     * Xen sometimes renames guests during migration, thus
     * 'uuid' is the only truly reliable key we can use. */
    virUUIDFormat(uuid, uuidstr);
    if (!(event = virObjectEventNew(klass,
                                    virDomainEventDispatchDefaultFunc,
                                    eventID,
                                    id, name, uuid, uuidstr)))
        return NULL;

    return (virObjectEvent *)event;
}

virObjectEvent *
virDomainEventLifecycleNew(int id,
                           const char *name,
                           const unsigned char *uuid,
                           int type,
                           int detail)
{
    virDomainEventLifecycle *event;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(event = virDomainEventNew(virDomainEventLifecycleClass,
                                    VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                    id, name, uuid)))
        return NULL;

    event->type = type;
    event->detail = detail;

    return (virObjectEvent *)event;
}

virObjectEvent *
virDomainEventLifecycleNewFromDom(virDomainPtr dom,
                                  int type,
                                  int detail)
{
    return virDomainEventLifecycleNew(dom->id, dom->name, dom->uuid,
                                      type, detail);
}

virObjectEvent *
virDomainEventLifecycleNewFromObj(virDomainObj *obj,
                                  int type,
                                  int detail)
{
    return virDomainEventLifecycleNewFromDef(obj->def, type, detail);
}

virObjectEvent *
virDomainEventLifecycleNewFromDef(virDomainDef *def,
                                  int type,
                                  int detail)
{
    return virDomainEventLifecycleNew(def->id, def->name, def->uuid,
                                      type, detail);
}

virObjectEvent *
virDomainEventRebootNew(int id,
                        const char *name,
                        const unsigned char *uuid)
{
    if (virDomainEventsInitialize() < 0)
        return NULL;

    return virDomainEventNew(virDomainEventClass,
                             VIR_DOMAIN_EVENT_ID_REBOOT,
                             id, name, uuid);
}

virObjectEvent *
virDomainEventRebootNewFromDom(virDomainPtr dom)
{
    if (virDomainEventsInitialize() < 0)
        return NULL;

    return virDomainEventNew(virDomainEventClass,
                             VIR_DOMAIN_EVENT_ID_REBOOT,
                             dom->id, dom->name, dom->uuid);
}

virObjectEvent *
virDomainEventRebootNewFromObj(virDomainObj *obj)
{
    if (virDomainEventsInitialize() < 0)
        return NULL;

    return virDomainEventNew(virDomainEventClass,
                             VIR_DOMAIN_EVENT_ID_REBOOT,
                             obj->def->id, obj->def->name, obj->def->uuid);
}

virObjectEvent *
virDomainEventRTCChangeNewFromDom(virDomainPtr dom,
                                  long long offset)
{
    virDomainEventRTCChange *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventRTCChangeClass,
                                 VIR_DOMAIN_EVENT_ID_RTC_CHANGE,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->offset = offset;

    return (virObjectEvent *)ev;
}
virObjectEvent *
virDomainEventRTCChangeNewFromObj(virDomainObj *obj,
                                  long long offset)
{
    virDomainEventRTCChange *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventRTCChangeClass,
                                 VIR_DOMAIN_EVENT_ID_RTC_CHANGE,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;

    ev->offset = offset;

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventWatchdogNewFromDom(virDomainPtr dom,
                                 int action)
{
    virDomainEventWatchdog *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventWatchdogClass,
                                 VIR_DOMAIN_EVENT_ID_WATCHDOG,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->action = action;

    return (virObjectEvent *)ev;
}
virObjectEvent *
virDomainEventWatchdogNewFromObj(virDomainObj *obj,
                                 int action)
{
    virDomainEventWatchdog *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventWatchdogClass,
                                 VIR_DOMAIN_EVENT_ID_WATCHDOG,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;

    ev->action = action;

    return (virObjectEvent *)ev;
}

static virObjectEvent *
virDomainEventIOErrorNewFromDomImpl(int event,
                                    virDomainPtr dom,
                                    const char *srcPath,
                                    const char *devAlias,
                                    int action,
                                    const char *reason)
{
    virDomainEventIOError *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventIOErrorClass, event,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->action = action;
    ev->srcPath = g_strdup(srcPath);
    ev->devAlias = g_strdup(devAlias);
    ev->reason = g_strdup(reason);

    return (virObjectEvent *)ev;
}

static virObjectEvent *
virDomainEventIOErrorNewFromObjImpl(int event,
                                    virDomainObj *obj,
                                    const char *srcPath,
                                    const char *devAlias,
                                    int action,
                                    const char *reason)
{
    virDomainEventIOError *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventIOErrorClass, event,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;

    ev->action = action;
    ev->srcPath = g_strdup(srcPath);
    ev->devAlias = g_strdup(devAlias);
    ev->reason = g_strdup(reason);

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventIOErrorNewFromDom(virDomainPtr dom,
                                const char *srcPath,
                                const char *devAlias,
                                int action)
{
    return virDomainEventIOErrorNewFromDomImpl(VIR_DOMAIN_EVENT_ID_IO_ERROR,
                                               dom, srcPath, devAlias,
                                               action, NULL);
}

virObjectEvent *
virDomainEventIOErrorNewFromObj(virDomainObj *obj,
                                const char *srcPath,
                                const char *devAlias,
                                int action)
{
    return virDomainEventIOErrorNewFromObjImpl(VIR_DOMAIN_EVENT_ID_IO_ERROR,
                                               obj, srcPath, devAlias,
                                               action, NULL);
}

virObjectEvent *
virDomainEventIOErrorReasonNewFromDom(virDomainPtr dom,
                                      const char *srcPath,
                                      const char *devAlias,
                                      int action,
                                      const char *reason)
{
    return virDomainEventIOErrorNewFromDomImpl(VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON,
                                               dom, srcPath, devAlias,
                                               action, reason);
}

virObjectEvent *
virDomainEventIOErrorReasonNewFromObj(virDomainObj *obj,
                                      const char *srcPath,
                                      const char *devAlias,
                                      int action,
                                      const char *reason)
{
    return virDomainEventIOErrorNewFromObjImpl(VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON,
                                               obj, srcPath, devAlias,
                                               action, reason);
}


virObjectEvent *
virDomainEventGraphicsNewFromDom(virDomainPtr dom,
                                 int phase,
                                 virDomainEventGraphicsAddressPtr local,
                                 virDomainEventGraphicsAddressPtr remote,
                                 const char *authScheme,
                                 virDomainEventGraphicsSubjectPtr subject)
{
    virDomainEventGraphics *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventGraphicsClass,
                                 VIR_DOMAIN_EVENT_ID_GRAPHICS,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->phase = phase;
    ev->authScheme = g_strdup(authScheme);
    ev->local = local;
    ev->remote = remote;
    ev->subject = subject;

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventGraphicsNewFromObj(virDomainObj *obj,
                                 int phase,
                                 virDomainEventGraphicsAddressPtr local,
                                 virDomainEventGraphicsAddressPtr remote,
                                 const char *authScheme,
                                 virDomainEventGraphicsSubjectPtr subject)
{
    virDomainEventGraphics *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventGraphicsClass,
                                 VIR_DOMAIN_EVENT_ID_GRAPHICS,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;

    ev->phase = phase;
    ev->authScheme = g_strdup(authScheme);
    ev->local = local;
    ev->remote = remote;
    ev->subject = subject;

    return (virObjectEvent *)ev;
}

static virObjectEvent *
virDomainEventBlockJobNew(int event,
                          int id,
                          const char *name,
                          unsigned char *uuid,
                          const char *disk,
                          int type,
                          int status)
{
    virDomainEventBlockJob *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventBlockJobClass,
                                 event,
                                 id, name, uuid)))
        return NULL;

    ev->disk = g_strdup(disk);
    ev->type = type;
    ev->status = status;

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventBlockJobNewFromObj(virDomainObj *obj,
                                 const char *path,
                                 int type,
                                 int status)
{
    return virDomainEventBlockJobNew(VIR_DOMAIN_EVENT_ID_BLOCK_JOB,
                                     obj->def->id, obj->def->name,
                                     obj->def->uuid, path, type, status);
}

virObjectEvent *
virDomainEventBlockJobNewFromDom(virDomainPtr dom,
                                 const char *path,
                                 int type,
                                 int status)
{
    return virDomainEventBlockJobNew(VIR_DOMAIN_EVENT_ID_BLOCK_JOB,
                                     dom->id, dom->name, dom->uuid,
                                     path, type, status);
}

virObjectEvent *
virDomainEventBlockJob2NewFromObj(virDomainObj *obj,
                                  const char *dst,
                                  int type,
                                  int status)
{
    return virDomainEventBlockJobNew(VIR_DOMAIN_EVENT_ID_BLOCK_JOB_2,
                                     obj->def->id, obj->def->name,
                                     obj->def->uuid, dst, type, status);
}

virObjectEvent *
virDomainEventBlockJob2NewFromDom(virDomainPtr dom,
                                  const char *dst,
                                  int type,
                                  int status)
{
    return virDomainEventBlockJobNew(VIR_DOMAIN_EVENT_ID_BLOCK_JOB_2,
                                     dom->id, dom->name, dom->uuid,
                                     dst, type, status);
}

virObjectEvent *
virDomainEventControlErrorNewFromDom(virDomainPtr dom)
{
    virObjectEvent *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_CONTROL_ERROR,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;
    return ev;
}


virObjectEvent *
virDomainEventControlErrorNewFromObj(virDomainObj *obj)
{
    virObjectEvent *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_CONTROL_ERROR,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;
    return ev;
}

static virObjectEvent *
virDomainEventDiskChangeNew(int id,
                            const char *name,
                            unsigned char *uuid,
                            const char *oldSrcPath,
                            const char *newSrcPath,
                            const char *devAlias,
                            int reason)
{
    virDomainEventDiskChange *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventDiskChangeClass,
                                 VIR_DOMAIN_EVENT_ID_DISK_CHANGE,
                                 id, name, uuid)))
        return NULL;

    ev->devAlias = g_strdup(devAlias);
    ev->oldSrcPath = g_strdup(oldSrcPath);
    ev->newSrcPath = g_strdup(newSrcPath);

    ev->reason = reason;

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventDiskChangeNewFromObj(virDomainObj *obj,
                                   const char *oldSrcPath,
                                   const char *newSrcPath,
                                   const char *devAlias,
                                   int reason)
{
    return virDomainEventDiskChangeNew(obj->def->id, obj->def->name,
                                       obj->def->uuid, oldSrcPath,
                                       newSrcPath, devAlias, reason);
}

virObjectEvent *
virDomainEventDiskChangeNewFromDom(virDomainPtr dom,
                                   const char *oldSrcPath,
                                   const char *newSrcPath,
                                   const char *devAlias,
                                   int reason)
{
    return virDomainEventDiskChangeNew(dom->id, dom->name, dom->uuid,
                                       oldSrcPath, newSrcPath,
                                       devAlias, reason);
}

static virObjectEvent *
virDomainEventTrayChangeNew(int id,
                            const char *name,
                            unsigned char *uuid,
                            const char *devAlias,
                            int reason)
{
    virDomainEventTrayChange *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventTrayChangeClass,
                                 VIR_DOMAIN_EVENT_ID_TRAY_CHANGE,
                                 id, name, uuid)))
        return NULL;

    ev->devAlias = g_strdup(devAlias);

    ev->reason = reason;

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventTrayChangeNewFromObj(virDomainObj *obj,
                                  const char *devAlias,
                                  int reason)
{
    return virDomainEventTrayChangeNew(obj->def->id,
                                       obj->def->name,
                                       obj->def->uuid,
                                       devAlias,
                                       reason);
}

virObjectEvent *
virDomainEventTrayChangeNewFromDom(virDomainPtr dom,
                                   const char *devAlias,
                                   int reason)
{
    return virDomainEventTrayChangeNew(dom->id, dom->name, dom->uuid,
                                       devAlias, reason);
}

static virObjectEvent *
virDomainEventPMWakeupNew(int id,
                          const char *name,
                          unsigned char *uuid,
                          int reason)
{
    virDomainEventPM *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventPMClass,
                                 VIR_DOMAIN_EVENT_ID_PMWAKEUP,
                                 id, name, uuid)))
        return NULL;

    ev->reason = reason;
    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventPMWakeupNewFromObj(virDomainObj *obj)
{
    return virDomainEventPMWakeupNew(obj->def->id,
                                     obj->def->name,
                                     obj->def->uuid,
                                     0);
}

virObjectEvent *
virDomainEventPMWakeupNewFromDom(virDomainPtr dom, int reason)
{
    return virDomainEventPMWakeupNew(dom->id, dom->name, dom->uuid, reason);
}

static virObjectEvent *
virDomainEventPMSuspendNew(int id,
                           const char *name,
                           unsigned char *uuid,
                           int reason)
{
    virDomainEventPM *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventPMClass,
                                 VIR_DOMAIN_EVENT_ID_PMSUSPEND,
                                 id, name, uuid)))
        return NULL;

    ev->reason = reason;
    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventPMSuspendNewFromObj(virDomainObj *obj)
{
    return virDomainEventPMSuspendNew(obj->def->id,
                                      obj->def->name,
                                      obj->def->uuid,
                                      0);
}

virObjectEvent *
virDomainEventPMSuspendNewFromDom(virDomainPtr dom, int reason)
{
    return virDomainEventPMSuspendNew(dom->id, dom->name, dom->uuid, reason);
}

static virObjectEvent *
virDomainEventPMSuspendDiskNew(int id,
                               const char *name,
                               unsigned char *uuid,
                               int reason)
{
    virDomainEventPM *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventPMClass,
                                 VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK,
                                 id, name, uuid)))
        return NULL;

    ev->reason = reason;
    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventPMSuspendDiskNewFromObj(virDomainObj *obj)
{
    return virDomainEventPMSuspendDiskNew(obj->def->id,
                                          obj->def->name,
                                          obj->def->uuid,
                                          0);
}

virObjectEvent *
virDomainEventPMSuspendDiskNewFromDom(virDomainPtr dom, int reason)
{
    return virDomainEventPMSuspendDiskNew(dom->id, dom->name, dom->uuid,
                                          reason);
}

virObjectEvent *
virDomainEventBalloonChangeNewFromDom(virDomainPtr dom,
                                      unsigned long long actual)
{
    virDomainEventBalloonChange *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventBalloonChangeClass,
                                 VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->actual = actual;

    return (virObjectEvent *)ev;
}
virObjectEvent *
virDomainEventBalloonChangeNewFromObj(virDomainObj *obj,
                                      unsigned long long actual)
{
    virDomainEventBalloonChange *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventBalloonChangeClass,
                                 VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE,
                                 obj->def->id, obj->def->name, obj->def->uuid)))
        return NULL;

    ev->actual = actual;

    return (virObjectEvent *)ev;
}

static virObjectEvent *
virDomainEventDeviceRemovedNew(int id,
                               const char *name,
                               unsigned char *uuid,
                               const char *devAlias)
{
    virDomainEventDeviceRemoved *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventDeviceRemovedClass,
                                 VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED,
                                 id, name, uuid)))
        return NULL;

    ev->devAlias = g_strdup(devAlias);

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventDeviceRemovedNewFromObj(virDomainObj *obj,
                                      const char *devAlias)
{
    return virDomainEventDeviceRemovedNew(obj->def->id, obj->def->name,
                                          obj->def->uuid, devAlias);
}

virObjectEvent *
virDomainEventDeviceRemovedNewFromDom(virDomainPtr dom,
                                      const char *devAlias)
{
    return virDomainEventDeviceRemovedNew(dom->id, dom->name, dom->uuid,
                                          devAlias);
}

static virObjectEvent *
virDomainEventDeviceAddedNew(int id,
                             const char *name,
                             unsigned char *uuid,
                             const char *devAlias)
{
    virDomainEventDeviceAdded *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventDeviceAddedClass,
                                 VIR_DOMAIN_EVENT_ID_DEVICE_ADDED,
                                 id, name, uuid)))
        return NULL;

    ev->devAlias = g_strdup(devAlias);

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventDeviceAddedNewFromObj(virDomainObj *obj,
                                    const char *devAlias)
{
    return virDomainEventDeviceAddedNew(obj->def->id, obj->def->name,
                                           obj->def->uuid, devAlias);
}

virObjectEvent *
virDomainEventDeviceAddedNewFromDom(virDomainPtr dom,
                                    const char *devAlias)
{
    return virDomainEventDeviceAddedNew(dom->id, dom->name, dom->uuid,
                                          devAlias);
}


static virObjectEvent *
virDomainEventDeviceRemovalFailedNew(int id,
                                     const char *name,
                                     unsigned char *uuid,
                                     const char *devAlias)
{
    virDomainEventDeviceRemovalFailed *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventDeviceRemovalFailedClass,
                                 VIR_DOMAIN_EVENT_ID_DEVICE_REMOVAL_FAILED,
                                 id, name, uuid)))
        return NULL;

    ev->devAlias = g_strdup(devAlias);

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventDeviceRemovalFailedNewFromObj(virDomainObj *obj,
                                            const char *devAlias)
{
    return virDomainEventDeviceRemovalFailedNew(obj->def->id, obj->def->name,
                                                obj->def->uuid, devAlias);
}

virObjectEvent *
virDomainEventDeviceRemovalFailedNewFromDom(virDomainPtr dom,
                                            const char *devAlias)
{
    return virDomainEventDeviceRemovalFailedNew(dom->id, dom->name, dom->uuid,
                                                devAlias);
}


static virObjectEvent *
virDomainEventAgentLifecycleNew(int id,
                                const char *name,
                                const unsigned char *uuid,
                                int state,
                                int reason)
{
    virDomainEventAgentLifecycle *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventAgentLifecycleClass,
                                 VIR_DOMAIN_EVENT_ID_AGENT_LIFECYCLE,
                                 id, name, uuid)))
        return NULL;

    ev->state = state;
    ev->reason = reason;

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventAgentLifecycleNewFromObj(virDomainObj *obj,
                                       int state,
                                       int reason)
{
    return virDomainEventAgentLifecycleNew(obj->def->id, obj->def->name,
                                           obj->def->uuid, state, reason);
}

virObjectEvent *
virDomainEventAgentLifecycleNewFromDom(virDomainPtr dom,
                                       int state,
                                       int reason)
{
    return virDomainEventAgentLifecycleNew(dom->id, dom->name, dom->uuid,
                                           state, reason);
}

static virObjectEvent *
virDomainEventMigrationIterationNew(int id,
                                    const char *name,
                                    const unsigned char *uuid,
                                    int iteration)
{
    virDomainEventMigrationIteration *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventMigrationIterationClass,
                                 VIR_DOMAIN_EVENT_ID_MIGRATION_ITERATION,
                                 id, name, uuid)))
        return NULL;

    ev->iteration = iteration;

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventMigrationIterationNewFromObj(virDomainObj *obj,
                                           int iteration)
{
    return virDomainEventMigrationIterationNew(obj->def->id, obj->def->name,
                                               obj->def->uuid, iteration);
}

virObjectEvent *
virDomainEventMigrationIterationNewFromDom(virDomainPtr dom,
                                           int iteration)
{
    return virDomainEventMigrationIterationNew(dom->id, dom->name, dom->uuid,
                                               iteration);
}

/* This function consumes @params, the caller must not free it.
 */
static virObjectEvent *
virDomainEventJobCompletedNew(int id,
                              const char *name,
                              const unsigned char *uuid,
                              virTypedParameterPtr params,
                              int nparams)
{
    virDomainEventJobCompleted *ev;

    if (virDomainEventsInitialize() < 0)
        goto error;

    if (!(ev = virDomainEventNew(virDomainEventJobCompletedClass,
                                 VIR_DOMAIN_EVENT_ID_JOB_COMPLETED,
                                 id, name, uuid)))
        goto error;

    ev->params = params;
    ev->nparams = nparams;

    return (virObjectEvent *) ev;

 error:
    virTypedParamsFree(params, nparams);
    return NULL;
}

virObjectEvent *
virDomainEventJobCompletedNewFromObj(virDomainObj *obj,
                                     virTypedParameterPtr params,
                                     int nparams)
{
    return virDomainEventJobCompletedNew(obj->def->id, obj->def->name,
                                         obj->def->uuid, params, nparams);
}

virObjectEvent *
virDomainEventJobCompletedNewFromDom(virDomainPtr dom,
                                     virTypedParameterPtr params,
                                     int nparams)
{
    return virDomainEventJobCompletedNew(dom->id, dom->name, dom->uuid,
                                         params, nparams);
}


/* This function consumes the params so caller don't have to care about
 * freeing it even if error occurs. The reason is to not have to do deep
 * copy of params.
 */
static virObjectEvent *
virDomainEventTunableNew(int id,
                         const char *name,
                         unsigned char *uuid,
                         virTypedParameterPtr *params,
                         int nparams)
{
    virDomainEventTunable *ev;

    if (virDomainEventsInitialize() < 0)
        goto error;

    if (!(ev = virDomainEventNew(virDomainEventTunableClass,
                                 VIR_DOMAIN_EVENT_ID_TUNABLE,
                                 id, name, uuid)))
        goto error;

    ev->params = *params;
    ev->nparams = nparams;
    *params = NULL;
    return (virObjectEvent *)ev;

 error:
    virTypedParamsFree(*params, nparams);
    *params = NULL;
    return NULL;
}

virObjectEvent *
virDomainEventTunableNewFromObj(virDomainObj *obj,
                                virTypedParameterPtr *params,
                                int nparams)
{
    return virDomainEventTunableNew(obj->def->id,
                                    obj->def->name,
                                    obj->def->uuid,
                                    params,
                                    nparams);
}

virObjectEvent *
virDomainEventTunableNewFromDom(virDomainPtr dom,
                                virTypedParameterPtr *params,
                                int nparams)
{
    return virDomainEventTunableNew(dom->id,
                                    dom->name,
                                    dom->uuid,
                                    params,
                                    nparams);
}


static virObjectEvent *
virDomainEventMetadataChangeNew(int id,
                                const char *name,
                                unsigned char *uuid,
                                int type,
                                const char *nsuri)
{
    virDomainEventMetadataChange *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventMetadataChangeClass,
                                 VIR_DOMAIN_EVENT_ID_METADATA_CHANGE,
                                 id, name, uuid)))
        return NULL;

    ev->type = type;
    ev->nsuri = g_strdup(nsuri);

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventMetadataChangeNewFromObj(virDomainObj *obj,
                                       int type,
                                       const char *nsuri)
{
    return virDomainEventMetadataChangeNew(obj->def->id, obj->def->name,
                                           obj->def->uuid, type, nsuri);
}

virObjectEvent *
virDomainEventMetadataChangeNewFromDom(virDomainPtr dom,
                                       int type,
                                       const char *nsuri)
{
    return virDomainEventMetadataChangeNew(dom->id, dom->name, dom->uuid,
                                           type, nsuri);
}


static virObjectEvent *
virDomainEventBlockThresholdNew(int id,
                                const char *name,
                                unsigned char *uuid,
                                const char *dev,
                                const char *path,
                                unsigned long long threshold,
                                unsigned long long excess)
{
    virDomainEventBlockThreshold *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventBlockThresholdClass,
                                 VIR_DOMAIN_EVENT_ID_BLOCK_THRESHOLD,
                                 id, name, uuid)))
        return NULL;

    ev->dev = g_strdup(dev);
    ev->path = g_strdup(path);
    ev->threshold = threshold;
    ev->excess = excess;

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventBlockThresholdNewFromObj(virDomainObj *obj,
                                       const char *dev,
                                       const char *path,
                                       unsigned long long threshold,
                                       unsigned long long excess)
{
    return virDomainEventBlockThresholdNew(obj->def->id, obj->def->name,
                                           obj->def->uuid, dev, path,
                                           threshold, excess);
}

virObjectEvent *
virDomainEventBlockThresholdNewFromDom(virDomainPtr dom,
                                       const char *dev,
                                       const char *path,
                                       unsigned long long threshold,
                                       unsigned long long excess)
{
    return virDomainEventBlockThresholdNew(dom->id, dom->name, dom->uuid,
                                           dev, path, threshold, excess);
}


static virObjectEvent *
virDomainEventMemoryFailureNew(int id,
                               const char *name,
                               unsigned char *uuid,
                               int recipient,
                               int action,
                               unsigned int flags)
{
    virDomainEventMemoryFailure *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventMemoryFailureClass,
                                 VIR_DOMAIN_EVENT_ID_MEMORY_FAILURE,
                                 id, name, uuid)))
        return NULL;

    ev->recipient = recipient;
    ev->action = action;
    ev->flags = flags;

    return (virObjectEvent *)ev;
}

virObjectEvent *
virDomainEventMemoryFailureNewFromObj(virDomainObj *obj,
                                      int recipient,
                                      int action,
                                      unsigned int flags)
{
    return virDomainEventMemoryFailureNew(obj->def->id, obj->def->name,
                                          obj->def->uuid, recipient, action,
                                          flags);
}

virObjectEvent *
virDomainEventMemoryFailureNewFromDom(virDomainPtr dom,
                                      int recipient,
                                      int action,
                                      unsigned int flags)
{
    return virDomainEventMemoryFailureNew(dom->id, dom->name, dom->uuid,
                                          recipient, action, flags);
}


static virObjectEvent *
virDomainEventMemoryDeviceSizeChangeNew(int id,
                                        const char *name,
                                        unsigned char *uuid,
                                        const char *alias,
                                        unsigned long long size)
{
    virDomainEventMemoryDeviceSizeChange *ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventMemoryDeviceSizeChangeClass,
                                 VIR_DOMAIN_EVENT_ID_MEMORY_DEVICE_SIZE_CHANGE,
                                 id, name, uuid)))
        return NULL;

    ev->alias = g_strdup(alias);
    ev->size = size;

    return (virObjectEvent *)ev;
}


virObjectEvent *
virDomainEventMemoryDeviceSizeChangeNewFromObj(virDomainObj *obj,
                                               const char *alias,
                                               unsigned long long size)
{
    return virDomainEventMemoryDeviceSizeChangeNew(obj->def->id,
                                                   obj->def->name,
                                                   obj->def->uuid,
                                                   alias,
                                                   size);
}


virObjectEvent *
virDomainEventMemoryDeviceSizeChangeNewFromDom(virDomainPtr dom,
                                               const char *alias,
                                               unsigned long long size)
{
    return virDomainEventMemoryDeviceSizeChangeNew(dom->id,
                                                   dom->name,
                                                   dom->uuid,
                                                   alias,
                                                   size);
}


static void
virDomainEventDispatchDefaultFunc(virConnectPtr conn,
                                  virObjectEvent *event,
                                  virConnectObjectEventGenericCallback cb,
                                  void *cbopaque)
{
    virDomainPtr dom = virGetDomain(conn, event->meta.name,
                                    event->meta.uuid, event->meta.id);

    if (!dom)
        return;

    switch ((virDomainEventID) event->eventID) {
    case VIR_DOMAIN_EVENT_ID_LIFECYCLE:
        {
            virDomainEventLifecycle *lifecycleEvent;

            lifecycleEvent = (virDomainEventLifecycle *)event;
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
            virDomainEventRTCChange *rtcChangeEvent;

            rtcChangeEvent = (virDomainEventRTCChange *)event;
            ((virConnectDomainEventRTCChangeCallback)cb)(conn, dom,
                                                         rtcChangeEvent->offset,
                                                         cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_WATCHDOG:
        {
            virDomainEventWatchdog *watchdogEvent;

            watchdogEvent = (virDomainEventWatchdog *)event;
            ((virConnectDomainEventWatchdogCallback)cb)(conn, dom,
                                                        watchdogEvent->action,
                                                        cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_IO_ERROR:
        {
            virDomainEventIOError *ioErrorEvent;

            ioErrorEvent = (virDomainEventIOError *)event;
            ((virConnectDomainEventIOErrorCallback)cb)(conn, dom,
                                                       ioErrorEvent->srcPath,
                                                       ioErrorEvent->devAlias,
                                                       ioErrorEvent->action,
                                                       cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON:
        {
            virDomainEventIOError *ioErrorEvent;

            ioErrorEvent = (virDomainEventIOError *)event;
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
            virDomainEventGraphics *graphicsEvent;

            graphicsEvent = (virDomainEventGraphics *)event;
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
    case VIR_DOMAIN_EVENT_ID_BLOCK_JOB_2:
        {
            virDomainEventBlockJob *blockJobEvent;

            blockJobEvent = (virDomainEventBlockJob *)event;
            ((virConnectDomainEventBlockJobCallback)cb)(conn, dom,
                                                        blockJobEvent->disk,
                                                        blockJobEvent->type,
                                                        blockJobEvent->status,
                                                        cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_DISK_CHANGE:
        {
            virDomainEventDiskChange *diskChangeEvent;

            diskChangeEvent = (virDomainEventDiskChange *)event;
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
            virDomainEventTrayChange *trayChangeEvent;

            trayChangeEvent = (virDomainEventTrayChange *)event;
            ((virConnectDomainEventTrayChangeCallback)cb)(conn, dom,
                                                          trayChangeEvent->devAlias,
                                                          trayChangeEvent->reason,
                                                          cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_PMWAKEUP:
        {
            virDomainEventPM *pmEvent = (virDomainEventPM *)event;

            ((virConnectDomainEventPMWakeupCallback)cb)(conn, dom,
                                                        pmEvent->reason,
                                                        cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_PMSUSPEND:
        {
            virDomainEventPM *pmEvent = (virDomainEventPM *)event;

            ((virConnectDomainEventPMSuspendCallback)cb)(conn, dom,
                                                         pmEvent->reason,
                                                         cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE:
        {
            virDomainEventBalloonChange *balloonChangeEvent;

            balloonChangeEvent = (virDomainEventBalloonChange *)event;
            ((virConnectDomainEventBalloonChangeCallback)cb)(conn, dom,
                                                             balloonChangeEvent->actual,
                                                             cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK:
        {
            virDomainEventPM *pmEvent = (virDomainEventPM *)event;

            ((virConnectDomainEventPMSuspendDiskCallback)cb)(conn, dom,
                                                             pmEvent->reason,
                                                             cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED:
        {
            virDomainEventDeviceRemoved *deviceRemovedEvent;

            deviceRemovedEvent = (virDomainEventDeviceRemoved *)event;
            ((virConnectDomainEventDeviceRemovedCallback)cb)(conn, dom,
                                                             deviceRemovedEvent->devAlias,
                                                             cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_TUNABLE:
        {
            virDomainEventTunable *tunableEvent;
            tunableEvent = (virDomainEventTunable *)event;
            ((virConnectDomainEventTunableCallback)cb)(conn, dom,
                                                       tunableEvent->params,
                                                       tunableEvent->nparams,
                                                       cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_AGENT_LIFECYCLE:
        {
            virDomainEventAgentLifecycle *agentLifecycleEvent;
            agentLifecycleEvent = (virDomainEventAgentLifecycle *)event;
            ((virConnectDomainEventAgentLifecycleCallback)cb)(conn, dom,
                                                              agentLifecycleEvent->state,
                                                              agentLifecycleEvent->reason,
                                                              cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_DEVICE_ADDED:
        {
            virDomainEventDeviceAdded *deviceAddedEvent;

            deviceAddedEvent = (virDomainEventDeviceAdded *)event;
            ((virConnectDomainEventDeviceAddedCallback)cb)(conn, dom,
                                                           deviceAddedEvent->devAlias,
                                                           cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_MIGRATION_ITERATION:
        {
            virDomainEventMigrationIteration *ev;

            ev = (virDomainEventMigrationIteration *) event;
            ((virConnectDomainEventMigrationIterationCallback)cb)(conn, dom,
                                                                  ev->iteration,
                                                                  cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_JOB_COMPLETED:
        {
            virDomainEventJobCompleted *ev;

            ev = (virDomainEventJobCompleted *) event;
            ((virConnectDomainEventJobCompletedCallback) cb)(conn, dom,
                                                             ev->params,
                                                             ev->nparams,
                                                             cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_DEVICE_REMOVAL_FAILED:
        {
            virDomainEventDeviceRemovalFailed *deviceRemovalFailedEvent;

            deviceRemovalFailedEvent = (virDomainEventDeviceRemovalFailed *)event;
            ((virConnectDomainEventDeviceRemovalFailedCallback)cb)(conn, dom,
                                                                   deviceRemovalFailedEvent->devAlias,
                                                                   cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_METADATA_CHANGE:
        {
            virDomainEventMetadataChange *metadataChangeEvent;

            metadataChangeEvent = (virDomainEventMetadataChange *)event;
            ((virConnectDomainEventMetadataChangeCallback)cb)(conn, dom,
                                                              metadataChangeEvent->type,
                                                              metadataChangeEvent->nsuri,
                                                              cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_BLOCK_THRESHOLD:
        {
            virDomainEventBlockThreshold *blockThresholdEvent;

            blockThresholdEvent = (virDomainEventBlockThreshold *)event;
            ((virConnectDomainEventBlockThresholdCallback)cb)(conn, dom,
                                                              blockThresholdEvent->dev,
                                                              blockThresholdEvent->path,
                                                              blockThresholdEvent->threshold,
                                                              blockThresholdEvent->excess,
                                                              cbopaque);
            goto cleanup;
        }
    case VIR_DOMAIN_EVENT_ID_MEMORY_FAILURE:
        {
            virDomainEventMemoryFailure *memoryFailureEvent;

            memoryFailureEvent = (virDomainEventMemoryFailure *)event;
            ((virConnectDomainEventMemoryFailureCallback)cb)(conn, dom,
                                                             memoryFailureEvent->recipient,
                                                             memoryFailureEvent->action,
                                                             memoryFailureEvent->flags,
                                                             cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_MEMORY_DEVICE_SIZE_CHANGE:
        {
            virDomainEventMemoryDeviceSizeChange *memoryDeviceSizeChangeEvent;

            memoryDeviceSizeChangeEvent = (virDomainEventMemoryDeviceSizeChange *)event;
            ((virConnectDomainEventMemoryDeviceSizeChangeCallback)cb)(conn, dom,
                                                                      memoryDeviceSizeChangeEvent->alias,
                                                                      memoryDeviceSizeChangeEvent->size,
                                                                      cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_LAST:
        break;
    }

    VIR_WARN("Unexpected event ID %d", event->eventID);

 cleanup:
    virObjectUnref(dom);
}


virObjectEvent *
virDomainQemuMonitorEventNew(int id,
                             const char *name,
                             const unsigned char *uuid,
                             const char *event,
                             long long seconds,
                             unsigned int micros,
                             const char *details)
{
    virDomainQemuMonitorEvent *ev;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virDomainEventsInitialize() < 0)
        return NULL;

    virUUIDFormat(uuid, uuidstr);
    if (!(ev = virObjectEventNew(virDomainQemuMonitorEventClass,
                                 virDomainQemuMonitorEventDispatchFunc,
                                 0, id, name, uuid, uuidstr)))
        return NULL;

    ev->event = g_strdup(event);
    ev->seconds = seconds;
    ev->micros = micros;
    ev->details = g_strdup(details);

    return (virObjectEvent *)ev;
}


/* In order to filter by event name, we need to store a copy of the
 * name to filter on.  By wrapping the caller's freecb, we can
 * piggyback our cleanup to happen at the same time the caller
 * deregisters.  */
struct virDomainQemuMonitorEventData {
    char *event;
    GRegex *regex;
    unsigned int flags;
    void *opaque;
    virFreeCallback freecb;
};
typedef struct virDomainQemuMonitorEventData virDomainQemuMonitorEventData;


static void
virDomainQemuMonitorEventDispatchFunc(virConnectPtr conn,
                                      virObjectEvent *event,
                                      virConnectObjectEventGenericCallback cb,
                                      void *cbopaque)
{
    virDomainPtr dom;
    virDomainQemuMonitorEvent *qemuMonitorEvent;
    virDomainQemuMonitorEventData *data = cbopaque;

    if (!(dom = virGetDomain(conn, event->meta.name,
                             event->meta.uuid, event->meta.id)))
        return;

    qemuMonitorEvent = (virDomainQemuMonitorEvent *)event;
    ((virConnectDomainQemuMonitorEventCallback)cb)(conn, dom,
                                                   qemuMonitorEvent->event,
                                                   qemuMonitorEvent->seconds,
                                                   qemuMonitorEvent->micros,
                                                   qemuMonitorEvent->details,
                                                   data->opaque);
    virObjectUnref(dom);
}


/**
 * virDomainEventStateRegister:
 * @conn: connection to associate with callback
 * @state: object event state
 * @callback: the callback to add
 * @opaque: data blob to pass to @callback
 * @freecb: callback to free @opaque
 *
 * Register the function @callback with connection @conn,
 * from @state, for lifecycle events.
 *
 * Returns: the number of lifecycle callbacks now registered, or -1 on error
 */
int
virDomainEventStateRegister(virConnectPtr conn,
                            virObjectEventState *state,
                            virConnectDomainEventCallback callback,
                            void *opaque,
                            virFreeCallback freecb)
{
    int callbackID;

    if (virDomainEventsInitialize() < 0)
        return -1;

    return virObjectEventStateRegisterID(conn, state, NULL,
                                         NULL, NULL, virDomainEventClass,
                                         VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                         VIR_OBJECT_EVENT_CALLBACK(callback),
                                         opaque, freecb,
                                         true, &callbackID, false);
}


/**
 * virDomainEventStateRegisterID:
 * @conn: connection to associate with callback
 * @state: object event state
 * @dom: optional domain for filtering the event
 * @eventID: ID of the event type to register for
 * @cb: function to invoke when event fires
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
virDomainEventStateRegisterID(virConnectPtr conn,
                              virObjectEventState *state,
                              virDomainPtr dom,
                              int eventID,
                              virConnectDomainEventGenericCallback cb,
                              void *opaque,
                              virFreeCallback freecb,
                              int *callbackID)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virDomainEventsInitialize() < 0)
        return -1;

    if (dom)
        virUUIDFormat(dom->uuid, uuidstr);
    return virObjectEventStateRegisterID(conn, state, dom ? uuidstr : NULL,
                                         NULL, NULL,
                                         virDomainEventClass, eventID,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         opaque, freecb,
                                         false, callbackID, false);
}


/**
 * virDomainEventStateRegisterClient:
 * @conn: connection to associate with callback
 * @state: object event state
 * @dom: optional domain for filtering the event
 * @eventID: ID of the event type to register for
 * @cb: function to invoke when event fires
 * @opaque: data blob to pass to @callback
 * @freecb: callback to free @opaque
 * @legacy: true if callback is tracked by function instead of callbackID
 * @callbackID: filled with callback ID
 * @remoteID: true if server supports filtering
 *
 * Register the function @cb with connection @conn, from @state, for
 * events of type @eventID, and return the registration handle in
 * @callbackID.  This version is intended for use on the client side
 * of RPC.
 *
 * Returns: the number of callbacks now registered, or -1 on error
 */
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
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virDomainEventsInitialize() < 0)
        return -1;

    if (dom)
        virUUIDFormat(dom->uuid, uuidstr);
    return virObjectEventStateRegisterID(conn, state, dom ? uuidstr : NULL,
                                         NULL, NULL,
                                         virDomainEventClass, eventID,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         opaque, freecb,
                                         legacy, callbackID, remoteID);
}


/**
 * virDomainEventStateCallbackID:
 * @conn: connection associated with callback
 * @state: object event state
 * @cb: function registered as a callback with virDomainEventStateRegister()
 * @remoteID: associated remote id of the callback
 *
 * Returns the callbackID of @cb, or -1 with an error issued if the
 * function is not currently registered.
 */
int
virDomainEventStateCallbackID(virConnectPtr conn,
                              virObjectEventState *state,
                              virConnectDomainEventCallback cb,
                              int *remoteID)
{
    return virObjectEventStateCallbackID(conn, state, virDomainEventClass,
                                         VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         remoteID);
}


/**
 * virDomainEventStateDeregister:
 * @conn: connection to associate with callback
 * @state: object event state
 * @cb: function to remove from event
 *
 * Unregister the function @cb with connection @conn, from @state, for
 * lifecycle events.
 *
 * Returns: the number of lifecycle callbacks still registered, or -1 on error
 */
int
virDomainEventStateDeregister(virConnectPtr conn,
                              virObjectEventState *state,
                              virConnectDomainEventCallback cb)
{
    int callbackID;

    callbackID = virObjectEventStateCallbackID(conn, state,
                                               virDomainEventClass,
                                               VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                               VIR_OBJECT_EVENT_CALLBACK(cb),
                                               NULL);
    if (callbackID < 0)
        return -1;
    return virObjectEventStateDeregisterID(conn, state, callbackID, true);
}


/**
 * virDomainQemuMonitorEventFilter:
 * @conn: the connection pointer
 * @event: the event about to be dispatched
 * @opaque: the opaque data registered with the filter
 *
 * Callback for filtering based on event names.  Returns true if the
 * event should be dispatched.
 */
static bool
virDomainQemuMonitorEventFilter(virConnectPtr conn G_GNUC_UNUSED,
                                virObjectEvent *event,
                                void *opaque)
{
    virDomainQemuMonitorEventData *data = opaque;
    virDomainQemuMonitorEvent *monitorEvent;

    monitorEvent = (virDomainQemuMonitorEvent *) event;

    if (data->flags == -1)
        return true;
    if (data->flags & VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_REGEX)
        return g_regex_match(data->regex, monitorEvent->event, 0, NULL) == TRUE;
    if (data->flags & VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_NOCASE)
        return STRCASEEQ(monitorEvent->event, data->event);
    return STREQ(monitorEvent->event, data->event);
}


static void
virDomainQemuMonitorEventCleanup(void *opaque)
{
    virDomainQemuMonitorEventData *data = opaque;

    VIR_FREE(data->event);
    if (data->regex)
        g_regex_unref(data->regex);
    if (data->freecb)
        (data->freecb)(data->opaque);
    VIR_FREE(data);
}


/**
 * virDomainQemuMonitorEventStateRegisterID:
 * @conn: connection to associate with callback
 * @state: object event state
 * @dom: optional domain where event must occur
 * @event: optional name of event to register for
 * @cb: function to invoke when event occurs
 * @opaque: data blob to pass to callback
 * @freecb: callback to free @opaque
 * @flags: -1 for client, valid virConnectDomainQemuMonitorEventRegisterFlags
 *         for server
 * @callbackID: filled with callback ID
 *
 * Register the function @cb with connection @conn, from @state, for
 * events of type @eventID.
 *
 * Returns: the number of callbacks now registered, or -1 on error
 */
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
{
    virDomainQemuMonitorEventData *data = NULL;
    virObjectEventCallbackFilter filter = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (virDomainEventsInitialize() < 0)
        return -1;

    if (flags != -1)
        virCheckFlags(VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_REGEX |
                      VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_NOCASE,
                      -1);
    data = g_new0(virDomainQemuMonitorEventData, 1);
    data->flags = flags;
    if (event && flags != -1) {
        if (flags & VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_REGEX) {
            int cflags = G_REGEX_OPTIMIZE;
            g_autoptr(GError) err = NULL;

            if (flags & VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_NOCASE)
                cflags |= G_REGEX_CASELESS;
            data->regex = g_regex_new(event, cflags, 0, &err);
            if (!data->regex) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("failed to compile regex '%1$s': %2$s"),
                               event, err->message);
                VIR_FREE(data);
                return -1;
            }
        } else {
            data->event = g_strdup(event);
        }
    }
    data->opaque = opaque;
    data->freecb = freecb;
    if (event)
        filter = virDomainQemuMonitorEventFilter;
    freecb = virDomainQemuMonitorEventCleanup;

    if (dom)
        virUUIDFormat(dom->uuid, uuidstr);
    return virObjectEventStateRegisterID(conn, state, dom ? uuidstr : NULL,
                                         filter, data,
                                         virDomainQemuMonitorEventClass, 0,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         data, freecb,
                                         false, callbackID, false);
}
