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
 *
 * Author: Ben Guthro
 */

#include <config.h>

#include <regex.h>

#include "domain_event.h"
#include "object_event.h"
#include "object_event_private.h"
#include "virlog.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.domain_event");

static virClassPtr virDomainEventClass;
static virClassPtr virDomainEventLifecycleClass;
static virClassPtr virDomainEventRTCChangeClass;
static virClassPtr virDomainEventWatchdogClass;
static virClassPtr virDomainEventIOErrorClass;
static virClassPtr virDomainEventGraphicsClass;
static virClassPtr virDomainEventBlockJobClass;
static virClassPtr virDomainEventDiskChangeClass;
static virClassPtr virDomainEventTrayChangeClass;
static virClassPtr virDomainEventBalloonChangeClass;
static virClassPtr virDomainEventDeviceRemovedClass;
static virClassPtr virDomainEventPMClass;
static virClassPtr virDomainQemuMonitorEventClass;


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

static void
virDomainEventDispatchDefaultFunc(virConnectPtr conn,
                                  virObjectEventPtr event,
                                  virConnectObjectEventGenericCallback cb,
                                  void *cbopaque);

static void
virDomainQemuMonitorEventDispatchFunc(virConnectPtr conn,
                                      virObjectEventPtr event,
                                      virConnectObjectEventGenericCallback cb,
                                      void *cbopaque);

struct _virDomainEvent {
    virObjectEvent parent;

    /* Unused attribute to allow for subclass creation */
    bool dummy;
};
typedef struct _virDomainEvent virDomainEvent;
typedef virDomainEvent *virDomainEventPtr;

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

struct _virDomainEventBalloonChange {
    virDomainEvent parent;

    /* In unit of 1024 bytes */
    unsigned long long actual;
};
typedef struct _virDomainEventBalloonChange virDomainEventBalloonChange;
typedef virDomainEventBalloonChange *virDomainEventBalloonChangePtr;

struct _virDomainEventDeviceRemoved {
    virDomainEvent parent;

    char *devAlias;
};
typedef struct _virDomainEventDeviceRemoved virDomainEventDeviceRemoved;
typedef virDomainEventDeviceRemoved *virDomainEventDeviceRemovedPtr;

struct _virDomainEventPM {
    virDomainEvent parent;

    int reason;
};
typedef struct _virDomainEventPM virDomainEventPM;
typedef virDomainEventPM *virDomainEventPMPtr;

struct _virDomainQemuMonitorEvent {
    virObjectEvent parent;

    char *event;
    long long seconds;
    unsigned int micros;
    char *details;
};
typedef struct _virDomainQemuMonitorEvent virDomainQemuMonitorEvent;
typedef virDomainQemuMonitorEvent *virDomainQemuMonitorEventPtr;


static int
virDomainEventsOnceInit(void)
{
    if (!(virDomainEventClass =
          virClassNew(virClassForObjectEvent(),
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
    if (!(virDomainEventBalloonChangeClass =
          virClassNew(virDomainEventClass,
                      "virDomainEventBalloonChange",
                      sizeof(virDomainEventBalloonChange),
                      virDomainEventBalloonChangeDispose)))
        return -1;
    if (!(virDomainEventDeviceRemovedClass =
          virClassNew(virDomainEventClass,
                      "virDomainEventDeviceRemoved",
                      sizeof(virDomainEventDeviceRemoved),
                      virDomainEventDeviceRemovedDispose)))
        return -1;
    if (!(virDomainEventPMClass =
          virClassNew(virDomainEventClass,
                      "virDomainEventPM",
                      sizeof(virDomainEventPM),
                      virDomainEventPMDispose)))
        return -1;
    if (!(virDomainQemuMonitorEventClass =
          virClassNew(virClassForObjectEvent(),
                      "virDomainQemuMonitorEvent",
                      sizeof(virDomainQemuMonitorEvent),
                      virDomainQemuMonitorEventDispose)))
        return -1;
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDomainEvents)


static void
virDomainEventDispose(void *obj)
{
    virDomainEventPtr event = obj;

    VIR_DEBUG("obj=%p", event);
}

static void
virDomainEventLifecycleDispose(void *obj)
{
    virDomainEventLifecyclePtr event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void
virDomainEventRTCChangeDispose(void *obj)
{
    virDomainEventRTCChangePtr event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void
virDomainEventWatchdogDispose(void *obj)
{
    virDomainEventWatchdogPtr event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void
virDomainEventIOErrorDispose(void *obj)
{
    virDomainEventIOErrorPtr event = obj;
    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->srcPath);
    VIR_FREE(event->devAlias);
    VIR_FREE(event->reason);
}

static void
virDomainEventGraphicsDispose(void *obj)
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

static void
virDomainEventBlockJobDispose(void *obj)
{
    virDomainEventBlockJobPtr event = obj;
    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->path);
}

static void
virDomainEventDiskChangeDispose(void *obj)
{
    virDomainEventDiskChangePtr event = obj;
    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->oldSrcPath);
    VIR_FREE(event->newSrcPath);
    VIR_FREE(event->devAlias);
}

static void
virDomainEventTrayChangeDispose(void *obj)
{
    virDomainEventTrayChangePtr event = obj;
    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->devAlias);
}

static void
virDomainEventBalloonChangeDispose(void *obj)
{
    virDomainEventBalloonChangePtr event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void
virDomainEventDeviceRemovedDispose(void *obj)
{
    virDomainEventDeviceRemovedPtr event = obj;
    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->devAlias);
}

static void
virDomainEventPMDispose(void *obj)
{
    virDomainEventPMPtr event = obj;
    VIR_DEBUG("obj=%p", event);
}

static void
virDomainQemuMonitorEventDispose(void *obj)
{
    virDomainQemuMonitorEventPtr event = obj;
    VIR_DEBUG("obj=%p", event);

    VIR_FREE(event->event);
    VIR_FREE(event->details);
}


static void *
virDomainEventNew(virClassPtr klass,
                  int eventID,
                  int id,
                  const char *name,
                  const unsigned char *uuid)
{
    virDomainEventPtr event;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!virClassIsDerivedFrom(klass, virDomainEventClass)) {
        virReportInvalidArg(klass,
                            _("Class %s must derive from virDomainEvent"),
                            virClassName(klass));
        return NULL;
    }

    if (!(event = virObjectEventNew(klass,
                                    virDomainEventDispatchDefaultFunc,
                                    eventID,
                                    id, name, uuid)))
        return NULL;

    return (virObjectEventPtr)event;
}

virObjectEventPtr
virDomainEventLifecycleNew(int id,
                           const char *name,
                           const unsigned char *uuid,
                           int type,
                           int detail)
{
    virDomainEventLifecyclePtr event;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(event = virDomainEventNew(virDomainEventLifecycleClass,
                                    VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                    id, name, uuid)))
        return NULL;

    event->type = type;
    event->detail = detail;

    return (virObjectEventPtr)event;
}

virObjectEventPtr
virDomainEventLifecycleNewFromDom(virDomainPtr dom,
                                  int type,
                                  int detail)
{
    return virDomainEventLifecycleNew(dom->id, dom->name, dom->uuid,
                                      type, detail);
}

virObjectEventPtr
virDomainEventLifecycleNewFromObj(virDomainObjPtr obj,
                                  int type,
                                  int detail)
{
    return virDomainEventLifecycleNewFromDef(obj->def, type, detail);
}

virObjectEventPtr
virDomainEventLifecycleNewFromDef(virDomainDefPtr def,
                                  int type,
                                  int detail)
{
    return virDomainEventLifecycleNew(def->id, def->name, def->uuid,
                                      type, detail);
}

virObjectEventPtr
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

virObjectEventPtr
virDomainEventRebootNewFromDom(virDomainPtr dom)
{
    if (virDomainEventsInitialize() < 0)
        return NULL;

    return virDomainEventNew(virDomainEventClass,
                             VIR_DOMAIN_EVENT_ID_REBOOT,
                             dom->id, dom->name, dom->uuid);
}

virObjectEventPtr
virDomainEventRebootNewFromObj(virDomainObjPtr obj)
{
    if (virDomainEventsInitialize() < 0)
        return NULL;

    return virDomainEventNew(virDomainEventClass,
                             VIR_DOMAIN_EVENT_ID_REBOOT,
                             obj->def->id, obj->def->name, obj->def->uuid);
}

virObjectEventPtr
virDomainEventRTCChangeNewFromDom(virDomainPtr dom,
                                  long long offset)
{
    virDomainEventRTCChangePtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventRTCChangeClass,
                                 VIR_DOMAIN_EVENT_ID_RTC_CHANGE,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->offset = offset;

    return (virObjectEventPtr)ev;
}
virObjectEventPtr
virDomainEventRTCChangeNewFromObj(virDomainObjPtr obj,
                                  long long offset)
{
    virDomainEventRTCChangePtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventRTCChangeClass,
                                 VIR_DOMAIN_EVENT_ID_RTC_CHANGE,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;

    ev->offset = offset;

    return (virObjectEventPtr)ev;
}

virObjectEventPtr
virDomainEventWatchdogNewFromDom(virDomainPtr dom,
                                 int action)
{
    virDomainEventWatchdogPtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventWatchdogClass,
                                 VIR_DOMAIN_EVENT_ID_WATCHDOG,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->action = action;

    return (virObjectEventPtr)ev;
}
virObjectEventPtr
virDomainEventWatchdogNewFromObj(virDomainObjPtr obj,
                                 int action)
{
    virDomainEventWatchdogPtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventWatchdogClass,
                                 VIR_DOMAIN_EVENT_ID_WATCHDOG,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;

    ev->action = action;

    return (virObjectEventPtr)ev;
}

static virObjectEventPtr
virDomainEventIOErrorNewFromDomImpl(int event,
                                    virDomainPtr dom,
                                    const char *srcPath,
                                    const char *devAlias,
                                    int action,
                                    const char *reason)
{
    virDomainEventIOErrorPtr ev;

    if (virDomainEventsInitialize() < 0)
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

    return (virObjectEventPtr)ev;
}

static virObjectEventPtr
virDomainEventIOErrorNewFromObjImpl(int event,
                                    virDomainObjPtr obj,
                                    const char *srcPath,
                                    const char *devAlias,
                                    int action,
                                    const char *reason)
{
    virDomainEventIOErrorPtr ev;

    if (virDomainEventsInitialize() < 0)
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

    return (virObjectEventPtr)ev;
}

virObjectEventPtr
virDomainEventIOErrorNewFromDom(virDomainPtr dom,
                                const char *srcPath,
                                const char *devAlias,
                                int action)
{
    return virDomainEventIOErrorNewFromDomImpl(VIR_DOMAIN_EVENT_ID_IO_ERROR,
                                               dom, srcPath, devAlias,
                                               action, NULL);
}

virObjectEventPtr
virDomainEventIOErrorNewFromObj(virDomainObjPtr obj,
                                const char *srcPath,
                                const char *devAlias,
                                int action)
{
    return virDomainEventIOErrorNewFromObjImpl(VIR_DOMAIN_EVENT_ID_IO_ERROR,
                                               obj, srcPath, devAlias,
                                               action, NULL);
}

virObjectEventPtr
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

virObjectEventPtr
virDomainEventIOErrorReasonNewFromObj(virDomainObjPtr obj,
                                      const char *srcPath,
                                      const char *devAlias,
                                      int action,
                                      const char *reason)
{
    return virDomainEventIOErrorNewFromObjImpl(VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON,
                                               obj, srcPath, devAlias,
                                               action, reason);
}


virObjectEventPtr
virDomainEventGraphicsNewFromDom(virDomainPtr dom,
                                 int phase,
                                 virDomainEventGraphicsAddressPtr local,
                                 virDomainEventGraphicsAddressPtr remote,
                                 const char *authScheme,
                                 virDomainEventGraphicsSubjectPtr subject)
{
    virDomainEventGraphicsPtr ev;

    if (virDomainEventsInitialize() < 0)
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

    return (virObjectEventPtr)ev;
}

virObjectEventPtr
virDomainEventGraphicsNewFromObj(virDomainObjPtr obj,
                                 int phase,
                                 virDomainEventGraphicsAddressPtr local,
                                 virDomainEventGraphicsAddressPtr remote,
                                 const char *authScheme,
                                 virDomainEventGraphicsSubjectPtr subject)
{
    virDomainEventGraphicsPtr ev;

    if (virDomainEventsInitialize() < 0)
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

    return (virObjectEventPtr)ev;
}

static virObjectEventPtr
virDomainEventBlockJobNew(int id,
                          const char *name,
                          unsigned char *uuid,
                          const char *path,
                          int type,
                          int status)
{
    virDomainEventBlockJobPtr ev;

    if (virDomainEventsInitialize() < 0)
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

    return (virObjectEventPtr)ev;
}

virObjectEventPtr
virDomainEventBlockJobNewFromObj(virDomainObjPtr obj,
                                 const char *path,
                                 int type,
                                 int status)
{
    return virDomainEventBlockJobNew(obj->def->id, obj->def->name,
                                     obj->def->uuid, path, type, status);
}

virObjectEventPtr
virDomainEventBlockJobNewFromDom(virDomainPtr dom,
                                 const char *path,
                                 int type,
                                 int status)
{
    return virDomainEventBlockJobNew(dom->id, dom->name, dom->uuid,
                                     path, type, status);
}

virObjectEventPtr
virDomainEventControlErrorNewFromDom(virDomainPtr dom)
{
    virObjectEventPtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_CONTROL_ERROR,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;
    return ev;
}


virObjectEventPtr
virDomainEventControlErrorNewFromObj(virDomainObjPtr obj)
{
    virObjectEventPtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventClass,
                                 VIR_DOMAIN_EVENT_ID_CONTROL_ERROR,
                                 obj->def->id, obj->def->name,
                                 obj->def->uuid)))
        return NULL;
    return ev;
}

static virObjectEventPtr
virDomainEventDiskChangeNew(int id,
                            const char *name,
                            unsigned char *uuid,
                            const char *oldSrcPath,
                            const char *newSrcPath,
                            const char *devAlias,
                            int reason)
{
    virDomainEventDiskChangePtr ev;

    if (virDomainEventsInitialize() < 0)
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

    return (virObjectEventPtr)ev;

 error:
    virObjectUnref(ev);
    return NULL;
}

virObjectEventPtr
virDomainEventDiskChangeNewFromObj(virDomainObjPtr obj,
                                   const char *oldSrcPath,
                                   const char *newSrcPath,
                                   const char *devAlias,
                                   int reason)
{
    return virDomainEventDiskChangeNew(obj->def->id, obj->def->name,
                                       obj->def->uuid, oldSrcPath,
                                       newSrcPath, devAlias, reason);
}

virObjectEventPtr
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

static virObjectEventPtr
virDomainEventTrayChangeNew(int id,
                            const char *name,
                            unsigned char *uuid,
                            const char *devAlias,
                            int reason)
{
    virDomainEventTrayChangePtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventTrayChangeClass,
                                 VIR_DOMAIN_EVENT_ID_TRAY_CHANGE,
                                 id, name, uuid)))
        return NULL;

    if (VIR_STRDUP(ev->devAlias, devAlias) < 0)
        goto error;

    ev->reason = reason;

    return (virObjectEventPtr)ev;

 error:
    virObjectUnref(ev);
    return NULL;
}

virObjectEventPtr
virDomainEventTrayChangeNewFromObj(virDomainObjPtr obj,
                                  const char *devAlias,
                                  int reason)
{
    return virDomainEventTrayChangeNew(obj->def->id,
                                       obj->def->name,
                                       obj->def->uuid,
                                       devAlias,
                                       reason);
}

virObjectEventPtr
virDomainEventTrayChangeNewFromDom(virDomainPtr dom,
                                   const char *devAlias,
                                   int reason)
{
    return virDomainEventTrayChangeNew(dom->id, dom->name, dom->uuid,
                                       devAlias, reason);
}

static virObjectEventPtr
virDomainEventPMWakeupNew(int id,
                          const char *name,
                          unsigned char *uuid,
                          int reason)
{
    virDomainEventPMPtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventPMClass,
                                 VIR_DOMAIN_EVENT_ID_PMWAKEUP,
                                 id, name, uuid)))
        return NULL;

    ev->reason = reason;
    return (virObjectEventPtr)ev;
}

virObjectEventPtr
virDomainEventPMWakeupNewFromObj(virDomainObjPtr obj)
{
    return virDomainEventPMWakeupNew(obj->def->id,
                                     obj->def->name,
                                     obj->def->uuid,
                                     0);
}

virObjectEventPtr
virDomainEventPMWakeupNewFromDom(virDomainPtr dom, int reason)
{
    return virDomainEventPMWakeupNew(dom->id, dom->name, dom->uuid, reason);
}

static virObjectEventPtr
virDomainEventPMSuspendNew(int id,
                           const char *name,
                           unsigned char *uuid,
                           int reason)
{
    virDomainEventPMPtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventPMClass,
                                 VIR_DOMAIN_EVENT_ID_PMSUSPEND,
                                 id, name, uuid)))
        return NULL;

    ev->reason = reason;
    return (virObjectEventPtr)ev;
}

virObjectEventPtr
virDomainEventPMSuspendNewFromObj(virDomainObjPtr obj)
{
    return virDomainEventPMSuspendNew(obj->def->id,
                                      obj->def->name,
                                      obj->def->uuid,
                                      0);
}

virObjectEventPtr
virDomainEventPMSuspendNewFromDom(virDomainPtr dom, int reason)
{
    return virDomainEventPMSuspendNew(dom->id, dom->name, dom->uuid, reason);
}

static virObjectEventPtr
virDomainEventPMSuspendDiskNew(int id,
                               const char *name,
                               unsigned char *uuid,
                               int reason)
{
    virDomainEventPMPtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventPMClass,
                                 VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK,
                                 id, name, uuid)))
        return NULL;

    ev->reason = reason;
    return (virObjectEventPtr)ev;
}

virObjectEventPtr
virDomainEventPMSuspendDiskNewFromObj(virDomainObjPtr obj)
{
    return virDomainEventPMSuspendDiskNew(obj->def->id,
                                          obj->def->name,
                                          obj->def->uuid,
                                          0);
}

virObjectEventPtr
virDomainEventPMSuspendDiskNewFromDom(virDomainPtr dom, int reason)
{
    return virDomainEventPMSuspendDiskNew(dom->id, dom->name, dom->uuid,
                                          reason);
}

virObjectEventPtr
virDomainEventBalloonChangeNewFromDom(virDomainPtr dom,
                                      unsigned long long actual)
{
    virDomainEventBalloonChangePtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventBalloonChangeClass,
                                 VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE,
                                 dom->id, dom->name, dom->uuid)))
        return NULL;

    ev->actual = actual;

    return (virObjectEventPtr)ev;
}
virObjectEventPtr
virDomainEventBalloonChangeNewFromObj(virDomainObjPtr obj,
                                      unsigned long long actual)
{
    virDomainEventBalloonChangePtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventBalloonChangeClass,
                                 VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE,
                                 obj->def->id, obj->def->name, obj->def->uuid)))
        return NULL;

    ev->actual = actual;

    return (virObjectEventPtr)ev;
}

static virObjectEventPtr
virDomainEventDeviceRemovedNew(int id,
                               const char *name,
                               unsigned char *uuid,
                               const char *devAlias)
{
    virDomainEventDeviceRemovedPtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virDomainEventNew(virDomainEventDeviceRemovedClass,
                                 VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED,
                                 id, name, uuid)))
        return NULL;

    if (VIR_STRDUP(ev->devAlias, devAlias) < 0)
        goto error;

    return (virObjectEventPtr)ev;

 error:
    virObjectUnref(ev);
    return NULL;
}

virObjectEventPtr
virDomainEventDeviceRemovedNewFromObj(virDomainObjPtr obj,
                                      const char *devAlias)
{
    return virDomainEventDeviceRemovedNew(obj->def->id, obj->def->name,
                                          obj->def->uuid, devAlias);
}

virObjectEventPtr
virDomainEventDeviceRemovedNewFromDom(virDomainPtr dom,
                                      const char *devAlias)
{
    return virDomainEventDeviceRemovedNew(dom->id, dom->name, dom->uuid,
                                          devAlias);
}


static void
virDomainEventDispatchDefaultFunc(virConnectPtr conn,
                                  virObjectEventPtr event,
                                  virConnectObjectEventGenericCallback cb,
                                  void *cbopaque)
{
    virDomainPtr dom = virGetDomain(conn, event->meta.name, event->meta.uuid);
    if (!dom)
        return;
    dom->id = event->meta.id;

    switch ((virDomainEventID) event->eventID) {
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
        {
            virDomainEventPMPtr pmEvent = (virDomainEventPMPtr)event;

            ((virConnectDomainEventPMWakeupCallback)cb)(conn, dom,
                                                        pmEvent->reason,
                                                        cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_PMSUSPEND:
        {
            virDomainEventPMPtr pmEvent = (virDomainEventPMPtr)event;

            ((virConnectDomainEventPMSuspendCallback)cb)(conn, dom,
                                                         pmEvent->reason,
                                                         cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE:
        {
            virDomainEventBalloonChangePtr balloonChangeEvent;

            balloonChangeEvent = (virDomainEventBalloonChangePtr)event;
            ((virConnectDomainEventBalloonChangeCallback)cb)(conn, dom,
                                                             balloonChangeEvent->actual,
                                                             cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK:
        {
            virDomainEventPMPtr pmEvent = (virDomainEventPMPtr)event;

            ((virConnectDomainEventPMSuspendDiskCallback)cb)(conn, dom,
                                                             pmEvent->reason,
                                                             cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED:
        {
            virDomainEventDeviceRemovedPtr deviceRemovedEvent;

            deviceRemovedEvent = (virDomainEventDeviceRemovedPtr)event;
            ((virConnectDomainEventDeviceRemovedCallback)cb)(conn, dom,
                                                             deviceRemovedEvent->devAlias,
                                                             cbopaque);
            goto cleanup;
        }

    case VIR_DOMAIN_EVENT_ID_LAST:
        break;
    }

    VIR_WARN("Unexpected event ID %d", event->eventID);

 cleanup:
    virDomainFree(dom);
}


virObjectEventPtr
virDomainQemuMonitorEventNew(int id,
                             const char *name,
                             const unsigned char *uuid,
                             const char *event,
                             long long seconds,
                             unsigned int micros,
                             const char *details)
{
    virDomainQemuMonitorEventPtr ev;

    if (virDomainEventsInitialize() < 0)
        return NULL;

    if (!(ev = virObjectEventNew(virDomainQemuMonitorEventClass,
                                 virDomainQemuMonitorEventDispatchFunc,
                                 0, id, name, uuid)))
        return NULL;

    /* event is mandatory, details are optional */
    if (VIR_STRDUP(ev->event, event) <= 0)
        goto error;
    ev->seconds = seconds;
    ev->micros = micros;
    if (VIR_STRDUP(ev->details, details) < 0)
        goto error;

    return (virObjectEventPtr)ev;

 error:
    virObjectUnref(ev);
    return NULL;
}


/* In order to filter by event name, we need to store a copy of the
 * name to filter on.  By wrapping the caller's freecb, we can
 * piggyback our cleanup to happen at the same time the caller
 * deregisters.  */
struct virDomainQemuMonitorEventData {
    char *event;
    regex_t regex;
    unsigned int flags;
    void *opaque;
    virFreeCallback freecb;
};
typedef struct virDomainQemuMonitorEventData virDomainQemuMonitorEventData;


static void
virDomainQemuMonitorEventDispatchFunc(virConnectPtr conn,
                                      virObjectEventPtr event,
                                      virConnectObjectEventGenericCallback cb,
                                      void *cbopaque)
{
    virDomainPtr dom = virGetDomain(conn, event->meta.name, event->meta.uuid);
    virDomainQemuMonitorEventPtr qemuMonitorEvent;
    virDomainQemuMonitorEventData *data = cbopaque;

    if (!dom)
        return;
    dom->id = event->meta.id;

    qemuMonitorEvent = (virDomainQemuMonitorEventPtr)event;
    ((virConnectDomainQemuMonitorEventCallback)cb)(conn, dom,
                                                   qemuMonitorEvent->event,
                                                   qemuMonitorEvent->seconds,
                                                   qemuMonitorEvent->micros,
                                                   qemuMonitorEvent->details,
                                                   data->opaque);
    virDomainFree(dom);
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
                            virObjectEventStatePtr state,
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
                              virObjectEventStatePtr state,
                              virDomainPtr dom,
                              int eventID,
                              virConnectDomainEventGenericCallback cb,
                              void *opaque,
                              virFreeCallback freecb,
                              int *callbackID)
{
    if (virDomainEventsInitialize() < 0)
        return -1;

    return virObjectEventStateRegisterID(conn, state, dom ? dom->uuid : NULL,
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
                                  virObjectEventStatePtr state,
                                  virDomainPtr dom,
                                  int eventID,
                                  virConnectDomainEventGenericCallback cb,
                                  void *opaque,
                                  virFreeCallback freecb,
                                  bool legacy,
                                  int *callbackID,
                                  bool remoteID)
{
    if (virDomainEventsInitialize() < 0)
        return -1;

    return virObjectEventStateRegisterID(conn, state, dom ? dom->uuid : NULL,
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
                              virObjectEventStatePtr state,
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
                              virObjectEventStatePtr state,
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
    return virObjectEventStateDeregisterID(conn, state, callbackID);
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
virDomainQemuMonitorEventFilter(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virObjectEventPtr event,
                                void *opaque)
{
    virDomainQemuMonitorEventData *data = opaque;
    virDomainQemuMonitorEventPtr monitorEvent;

    monitorEvent = (virDomainQemuMonitorEventPtr) event;

    if (data->flags == -1)
        return true;
    if (data->flags & VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_REGEX)
        return regexec(&data->regex, monitorEvent->event, 0, NULL, 0) == 0;
    if (data->flags & VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_NOCASE)
        return STRCASEEQ(monitorEvent->event, data->event);
    return STREQ(monitorEvent->event, data->event);
}


static void
virDomainQemuMonitorEventCleanup(void *opaque)
{
    virDomainQemuMonitorEventData *data = opaque;

    VIR_FREE(data->event);
    if (data->flags & VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_REGEX)
        regfree(&data->regex);
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
                                         virObjectEventStatePtr state,
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

    if (virDomainEventsInitialize() < 0)
        return -1;

    if (flags != -1)
        virCheckFlags(VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_REGEX |
                      VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_NOCASE,
                      -1);
    if (VIR_ALLOC(data) < 0)
        return -1;
    data->flags = flags;
    if (flags != -1) {
        int rflags = REG_NOSUB;

        if (flags & VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_NOCASE)
            rflags |= REG_ICASE;
        if (flags & VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_REGEX) {
            int err = regcomp(&data->regex, event, rflags);

            if (err) {
                char error[100];
                regerror(err, &data->regex, error, sizeof(error));
                virReportError(VIR_ERR_INVALID_ARG,
                               _("failed to compile regex '%s': %s"),
                               event, error);
                regfree(&data->regex);
                VIR_FREE(data);
                return -1;
            }
        } else if (VIR_STRDUP(data->event, event) < 0) {
            VIR_FREE(data);
            return -1;
        }
    }
    data->opaque = opaque;
    data->freecb = freecb;
    if (event)
        filter = virDomainQemuMonitorEventFilter;
    freecb = virDomainQemuMonitorEventCleanup;

    return virObjectEventStateRegisterID(conn, state, dom ? dom->uuid : NULL,
                                         filter, data,
                                         virDomainQemuMonitorEventClass, 0,
                                         VIR_OBJECT_EVENT_CALLBACK(cb),
                                         data, freecb,
                                         false, callbackID, false);
}
