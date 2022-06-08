/*
 * virsh-domain-event.c: Domain event listening commands
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
#include "virsh-util.h"

#include "internal.h"
#include "viralloc.h"
#include "virenum.h"
#include "virtime.h"
#include "virtypedparam.h"

/*
 * "event" command
 */

VIR_ENUM_DECL(virshDomainEvent);
VIR_ENUM_IMPL(virshDomainEvent,
              VIR_DOMAIN_EVENT_LAST,
              N_("Defined"),
              N_("Undefined"),
              N_("Started"),
              N_("Suspended"),
              N_("Resumed"),
              N_("Stopped"),
              N_("Shutdown"),
              N_("PMSuspended"),
              N_("Crashed"));

static const char *
virshDomainEventToString(int event)
{
    const char *str = virshDomainEventTypeToString(event);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainEventDefined);
VIR_ENUM_IMPL(virshDomainEventDefined,
              VIR_DOMAIN_EVENT_DEFINED_LAST,
              N_("Added"),
              N_("Updated"),
              N_("Renamed"),
              N_("Snapshot"));

VIR_ENUM_DECL(virshDomainEventUndefined);
VIR_ENUM_IMPL(virshDomainEventUndefined,
              VIR_DOMAIN_EVENT_UNDEFINED_LAST,
              N_("Removed"),
              N_("Renamed"));

VIR_ENUM_DECL(virshDomainEventStarted);
VIR_ENUM_IMPL(virshDomainEventStarted,
              VIR_DOMAIN_EVENT_STARTED_LAST,
              N_("Booted"),
              N_("Migrated"),
              N_("Restored"),
              N_("Snapshot"),
              N_("Event wakeup"));

VIR_ENUM_DECL(virshDomainEventSuspended);
VIR_ENUM_IMPL(virshDomainEventSuspended,
              VIR_DOMAIN_EVENT_SUSPENDED_LAST,
              N_("Paused"),
              N_("Migrated"),
              N_("I/O Error"),
              N_("Watchdog"),
              N_("Restored"),
              N_("Snapshot"),
              N_("API error"),
              N_("Post-copy"),
              N_("Post-copy Error"));

VIR_ENUM_DECL(virshDomainEventResumed);
VIR_ENUM_IMPL(virshDomainEventResumed,
              VIR_DOMAIN_EVENT_RESUMED_LAST,
              N_("Unpaused"),
              N_("Migrated"),
              N_("Snapshot"),
              N_("Post-copy"),
              N_("Post-copy Error"));

VIR_ENUM_DECL(virshDomainEventStopped);
VIR_ENUM_IMPL(virshDomainEventStopped,
              VIR_DOMAIN_EVENT_STOPPED_LAST,
              N_("Shutdown"),
              N_("Destroyed"),
              N_("Crashed"),
              N_("Migrated"),
              N_("Saved"),
              N_("Failed"),
              N_("Snapshot"));

VIR_ENUM_DECL(virshDomainEventShutdown);
VIR_ENUM_IMPL(virshDomainEventShutdown,
              VIR_DOMAIN_EVENT_SHUTDOWN_LAST,
              N_("Finished"),
              N_("Finished after guest request"),
              N_("Finished after host request"));

VIR_ENUM_DECL(virshDomainEventPMSuspended);
VIR_ENUM_IMPL(virshDomainEventPMSuspended,
              VIR_DOMAIN_EVENT_PMSUSPENDED_LAST,
              N_("Memory"),
              N_("Disk"));

VIR_ENUM_DECL(virshDomainEventCrashed);
VIR_ENUM_IMPL(virshDomainEventCrashed,
              VIR_DOMAIN_EVENT_CRASHED_LAST,
              N_("Panicked"),
              N_("Crashloaded"));

static const char *
virshDomainEventDetailToString(int event, int detail)
{
    const char *str = NULL;
    switch ((virDomainEventType) event) {
    case VIR_DOMAIN_EVENT_DEFINED:
        str = virshDomainEventDefinedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_UNDEFINED:
        str = virshDomainEventUndefinedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_STARTED:
        str = virshDomainEventStartedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_SUSPENDED:
        str = virshDomainEventSuspendedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_RESUMED:
        str = virshDomainEventResumedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_STOPPED:
        str = virshDomainEventStoppedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_SHUTDOWN:
        str = virshDomainEventShutdownTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_PMSUSPENDED:
        str = virshDomainEventPMSuspendedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_CRASHED:
        str = virshDomainEventCrashedTypeToString(detail);
        break;
    case VIR_DOMAIN_EVENT_LAST:
        break;
    }
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainEventWatchdog);
VIR_ENUM_IMPL(virshDomainEventWatchdog,
              VIR_DOMAIN_EVENT_WATCHDOG_LAST,
              N_("none"),
              N_("pause"),
              N_("reset"),
              N_("poweroff"),
              N_("shutdown"),
              N_("debug"),
              N_("inject-nmi"));

static const char *
virshDomainEventWatchdogToString(int action)
{
    const char *str = virshDomainEventWatchdogTypeToString(action);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainEventIOError);
VIR_ENUM_IMPL(virshDomainEventIOError,
              VIR_DOMAIN_EVENT_IO_ERROR_LAST,
              N_("none"),
              N_("pause"),
              N_("report"));

static const char *
virshDomainEventIOErrorToString(int action)
{
    const char *str = virshDomainEventIOErrorTypeToString(action);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshGraphicsPhase);
VIR_ENUM_IMPL(virshGraphicsPhase,
              VIR_DOMAIN_EVENT_GRAPHICS_LAST,
              N_("connect"),
              N_("initialize"),
              N_("disconnect"));

static const char *
virshGraphicsPhaseToString(int phase)
{
    const char *str = virshGraphicsPhaseTypeToString(phase);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshGraphicsAddress);
VIR_ENUM_IMPL(virshGraphicsAddress,
              VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_LAST,
              N_("IPv4"),
              N_("IPv6"),
              N_("unix"));

static const char *
virshGraphicsAddressToString(int family)
{
    const char *str = virshGraphicsAddressTypeToString(family);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainBlockJobStatus);
VIR_ENUM_IMPL(virshDomainBlockJobStatus,
              VIR_DOMAIN_BLOCK_JOB_LAST,
              N_("completed"),
              N_("failed"),
              N_("canceled"),
              N_("ready"));

static const char *
virshDomainBlockJobStatusToString(int status)
{
    const char *str = virshDomainBlockJobStatusTypeToString(status);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainEventDiskChange);
VIR_ENUM_IMPL(virshDomainEventDiskChange,
              VIR_DOMAIN_EVENT_DISK_CHANGE_LAST,
              N_("changed"),
              N_("dropped"));

static const char *
virshDomainEventDiskChangeToString(int reason)
{
    const char *str = virshDomainEventDiskChangeTypeToString(reason);
    return str ? _(str) : _("unknown");
}

VIR_ENUM_DECL(virshDomainEventTrayChange);
VIR_ENUM_IMPL(virshDomainEventTrayChange,
              VIR_DOMAIN_EVENT_TRAY_CHANGE_LAST,
              N_("opened"),
              N_("closed"));

static const char *
virshDomainEventTrayChangeToString(int reason)
{
    const char *str = virshDomainEventTrayChangeTypeToString(reason);
    return str ? _(str) : _("unknown");
}


struct virshDomainEventCallback {
    const char *name;
    virConnectDomainEventGenericCallback cb;
};
typedef struct virshDomainEventCallback virshDomainEventCallback;


struct virshDomEventData {
    vshControl *ctl;
    int event;
    bool loop;
    int *count;
    bool timestamp;
    virshDomainEventCallback *cb;
    int id;
};
typedef struct virshDomEventData virshDomEventData;

/**
 * virshEventPrint:
 *
 * @data: opaque data passed to all event callbacks
 * @buf: string buffer describing the event
 *
 * Print the event description found in @buf and update virshDomEventData.
 *
 * This function resets @buf and frees all memory consumed by its content.
 */
static void
virshEventPrint(virshDomEventData *data,
                virBuffer *buf)
{
    g_autofree char *msg = NULL;

    if (!(msg = virBufferContentAndReset(buf)))
        return;

    if (!data->loop && *data->count)
        return;

    if (data->timestamp) {
        char timestamp[VIR_TIME_STRING_BUFLEN];

        if (virTimeStringNowRaw(timestamp) < 0)
            timestamp[0] = '\0';

        vshPrint(data->ctl, "%s: %s", timestamp, msg);
    } else {
        vshPrint(data->ctl, "%s", msg);
    }

    (*data->count)++;
    if (!data->loop)
        vshEventDone(data->ctl);
}

static void
virshEventGenericPrint(virConnectPtr conn G_GNUC_UNUSED,
                       virDomainPtr dom,
                       void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event '%s' for domain '%s'\n"),
                      ((virshDomEventData *) opaque)->cb->name,
                      virDomainGetName(dom));
    virshEventPrint(opaque, &buf);
}

static void
virshEventLifecyclePrint(virConnectPtr conn G_GNUC_UNUSED,
                         virDomainPtr dom,
                         int event,
                         int detail,
                         void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'lifecycle' for domain '%s': %s %s\n"),
                      virDomainGetName(dom),
                      virshDomainEventToString(event),
                      virshDomainEventDetailToString(event, detail));
    virshEventPrint(opaque, &buf);
}

static void
virshEventRTCChangePrint(virConnectPtr conn G_GNUC_UNUSED,
                         virDomainPtr dom,
                         long long utcoffset,
                         void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'rtc-change' for domain '%s': %lld\n"),
                      virDomainGetName(dom),
                      utcoffset);
    virshEventPrint(opaque, &buf);
}

static void
virshEventWatchdogPrint(virConnectPtr conn G_GNUC_UNUSED,
                        virDomainPtr dom,
                        int action,
                        void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'watchdog' for domain '%s': %s\n"),
                      virDomainGetName(dom),
                      virshDomainEventWatchdogToString(action));
    virshEventPrint(opaque, &buf);
}

static void
virshEventIOErrorPrint(virConnectPtr conn G_GNUC_UNUSED,
                       virDomainPtr dom,
                       const char *srcPath,
                       const char *devAlias,
                       int action,
                       void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'io-error' for domain '%s': %s (%s) %s\n"),
                      virDomainGetName(dom),
                      srcPath,
                      devAlias,
                      virshDomainEventIOErrorToString(action));
    virshEventPrint(opaque, &buf);
}

static void
virshEventGraphicsPrint(virConnectPtr conn G_GNUC_UNUSED,
                        virDomainPtr dom,
                        int phase,
                        const virDomainEventGraphicsAddress *local,
                        const virDomainEventGraphicsAddress *remote,
                        const char *authScheme,
                        const virDomainEventGraphicsSubject *subject,
                        void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    virBufferAsprintf(&buf, _("event 'graphics' for domain '%s': "
                              "%s local[%s %s %s] remote[%s %s %s] %s\n"),
                      virDomainGetName(dom),
                      virshGraphicsPhaseToString(phase),
                      virshGraphicsAddressToString(local->family),
                      local->node,
                      local->service,
                      virshGraphicsAddressToString(remote->family),
                      remote->node,
                      remote->service,
                      authScheme);
    for (i = 0; i < subject->nidentity; i++) {
        virBufferAsprintf(&buf, "\t%s=%s\n",
                          subject->identities[i].type,
                          subject->identities[i].name);
    }
    virshEventPrint(opaque, &buf);
}

static void
virshEventIOErrorReasonPrint(virConnectPtr conn G_GNUC_UNUSED,
                             virDomainPtr dom,
                             const char *srcPath,
                             const char *devAlias,
                             int action,
                             const char *reason,
                             void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'io-error-reason' for domain '%s': "
                              "%s (%s) %s due to %s\n"),
                      virDomainGetName(dom),
                      srcPath,
                      devAlias,
                      virshDomainEventIOErrorToString(action),
                      reason);
    virshEventPrint(opaque, &buf);
}

static void
virshEventBlockJobPrint(virConnectPtr conn G_GNUC_UNUSED,
                        virDomainPtr dom,
                        const char *disk,
                        int type,
                        int status,
                        void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event '%s' for domain '%s': %s for %s %s\n"),
                      ((virshDomEventData *) opaque)->cb->name,
                      virDomainGetName(dom),
                      virshDomainBlockJobToString(type),
                      disk,
                      virshDomainBlockJobStatusToString(status));
    virshEventPrint(opaque, &buf);
}

static void
virshEventDiskChangePrint(virConnectPtr conn G_GNUC_UNUSED,
                          virDomainPtr dom,
                          const char *oldSrc,
                          const char *newSrc,
                          const char *alias,
                          int reason,
                          void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'disk-change' for domain '%s' disk %s: "
                              "%s -> %s: %s\n"),
                      virDomainGetName(dom),
                      alias,
                      NULLSTR(oldSrc),
                      NULLSTR(newSrc),
                      virshDomainEventDiskChangeToString(reason));
    virshEventPrint(opaque, &buf);
}

static void
virshEventTrayChangePrint(virConnectPtr conn G_GNUC_UNUSED,
                          virDomainPtr dom,
                          const char *alias,
                          int reason,
                          void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'tray-change' for domain '%s' disk %s: %s\n"),
                      virDomainGetName(dom),
                      alias,
                      virshDomainEventTrayChangeToString(reason));
    virshEventPrint(opaque, &buf);
}

static void
virshEventPMChangePrint(virConnectPtr conn G_GNUC_UNUSED,
                        virDomainPtr dom,
                        int reason G_GNUC_UNUSED,
                        void *opaque)
{
    /* As long as libvirt.h doesn't define any reasons, we might as
     * well treat all PM state changes as generic events.  */
    virshEventGenericPrint(conn, dom, opaque);
}

static void
virshEventBalloonChangePrint(virConnectPtr conn G_GNUC_UNUSED,
                             virDomainPtr dom,
                             unsigned long long actual,
                             void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'balloon-change' for domain '%s': %lluKiB\n"),
                      virDomainGetName(dom),
                      actual);
    virshEventPrint(opaque, &buf);
}

static void
virshEventDeviceRemovedPrint(virConnectPtr conn G_GNUC_UNUSED,
                             virDomainPtr dom,
                             const char *alias,
                             void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'device-removed' for domain '%s': %s\n"),
                      virDomainGetName(dom),
                      alias);
    virshEventPrint(opaque, &buf);
}

static void
virshEventDeviceAddedPrint(virConnectPtr conn G_GNUC_UNUSED,
                           virDomainPtr dom,
                           const char *alias,
                           void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'device-added' for domain '%s': %s\n"),
                      virDomainGetName(dom),
                      alias);
    virshEventPrint(opaque, &buf);
}

static void
virshEventTunablePrint(virConnectPtr conn G_GNUC_UNUSED,
                       virDomainPtr dom,
                       virTypedParameterPtr params,
                       int nparams,
                       void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;
    char *value;

    virBufferAsprintf(&buf, _("event 'tunable' for domain '%s':\n"),
                      virDomainGetName(dom));
    for (i = 0; i < nparams; i++) {
        value = virTypedParameterToString(&params[i]);
        if (value) {
            virBufferAsprintf(&buf, "\t%s: %s\n", params[i].field, value);
            VIR_FREE(value);
        }
    }
    virshEventPrint(opaque, &buf);
}

VIR_ENUM_DECL(virshEventAgentLifecycleState);
VIR_ENUM_IMPL(virshEventAgentLifecycleState,
              VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_STATE_LAST,
              N_("unknown"),
              N_("connected"),
              N_("disconnected"));

VIR_ENUM_DECL(virshEventAgentLifecycleReason);
VIR_ENUM_IMPL(virshEventAgentLifecycleReason,
              VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_LAST,
              N_("unknown"),
              N_("domain started"),
              N_("channel event"));

#define UNKNOWNSTR(str) (str ? str : N_("unsupported value"))
static void
virshEventAgentLifecyclePrint(virConnectPtr conn G_GNUC_UNUSED,
                              virDomainPtr dom,
                              int state,
                              int reason,
                              void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'agent-lifecycle' for domain '%s': state: "
                              "'%s' reason: '%s'\n"),
                      virDomainGetName(dom),
                      UNKNOWNSTR(virshEventAgentLifecycleStateTypeToString(state)),
                      UNKNOWNSTR(virshEventAgentLifecycleReasonTypeToString(reason)));
    virshEventPrint(opaque, &buf);
}

static void
virshEventMigrationIterationPrint(virConnectPtr conn G_GNUC_UNUSED,
                                  virDomainPtr dom,
                                  int iteration,
                                  void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'migration-iteration' for domain '%s': "
                              "iteration: '%d'\n"),
                      virDomainGetName(dom),
                      iteration);

    virshEventPrint(opaque, &buf);
}

static void
virshEventJobCompletedPrint(virConnectPtr conn G_GNUC_UNUSED,
                            virDomainPtr dom,
                            virTypedParameterPtr params,
                            int nparams,
                            void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    virBufferAsprintf(&buf, _("event 'job-completed' for domain '%s':\n"),
                      virDomainGetName(dom));
    for (i = 0; i < nparams; i++) {
        g_autofree char *value = virTypedParameterToString(&params[i]);
        if (value)
            virBufferAsprintf(&buf, "\t%s: %s\n", params[i].field, value);
    }
    virshEventPrint(opaque, &buf);
}


static void
virshEventDeviceRemovalFailedPrint(virConnectPtr conn G_GNUC_UNUSED,
                                   virDomainPtr dom,
                                   const char *alias,
                                   void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'device-removal-failed' for domain '%s': %s\n"),
                      virDomainGetName(dom),
                      alias);
    virshEventPrint(opaque, &buf);
}

VIR_ENUM_DECL(virshEventMetadataChangeType);
VIR_ENUM_IMPL(virshEventMetadataChangeType,
              VIR_DOMAIN_METADATA_LAST,
              N_("description"),
              N_("title"),
              N_("element"));

static void
virshEventMetadataChangePrint(virConnectPtr conn G_GNUC_UNUSED,
                              virDomainPtr dom,
                              int type,
                              const char *nsuri,
                              void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'metadata-change' for domain '%s': type %s, uri %s\n"),
                      virDomainGetName(dom),
                      UNKNOWNSTR(virshEventMetadataChangeTypeTypeToString(type)),
                      NULLSTR(nsuri));
    virshEventPrint(opaque, &buf);
}


static void
virshEventBlockThresholdPrint(virConnectPtr conn G_GNUC_UNUSED,
                              virDomainPtr dom,
                              const char *dev,
                              const char *path,
                              unsigned long long threshold,
                              unsigned long long excess,
                              void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'block-threshold' for domain '%s': "
                              "dev: %s(%s) %llu %llu\n"),
                      virDomainGetName(dom),
                      dev, NULLSTR(path), threshold, excess);
    virshEventPrint(opaque, &buf);
}


VIR_ENUM_DECL(virshEventMemoryFailureRecipientType);
VIR_ENUM_IMPL(virshEventMemoryFailureRecipientType,
              VIR_DOMAIN_EVENT_MEMORY_FAILURE_RECIPIENT_LAST,
              N_("hypervisor"),
              N_("guest"));

VIR_ENUM_DECL(virshEventMemoryFailureActionType);
VIR_ENUM_IMPL(virshEventMemoryFailureActionType,
              VIR_DOMAIN_EVENT_MEMORY_FAILURE_ACTION_LAST,
              N_("ignore"),
              N_("inject"),
              N_("fatal"),
              N_("reset"));

static void
virshEventMemoryFailurePrint(virConnectPtr conn G_GNUC_UNUSED,
                             virDomainPtr dom,
                             int recipient,
                             int action,
                             unsigned int flags,
                             void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, _("event 'memory-failure' for domain '%s':\n"
                              "recipient: %s\naction: %s\n"),
                      virDomainGetName(dom),
                      UNKNOWNSTR(virshEventMemoryFailureRecipientTypeTypeToString(recipient)),
                      UNKNOWNSTR(virshEventMemoryFailureActionTypeTypeToString(action)));
    virBufferAsprintf(&buf, _("flags:\n"
                              "\taction required: %d\n\trecursive: %d\n"),
                      !!(flags & VIR_DOMAIN_MEMORY_FAILURE_ACTION_REQUIRED),
                      !!(flags & VIR_DOMAIN_MEMORY_FAILURE_RECURSIVE));

    virshEventPrint(opaque, &buf);
}


static void
virshEventMemoryDeviceSizeChangePrint(virConnectPtr conn G_GNUC_UNUSED,
                                      virDomainPtr dom,
                                      const char *alias,
                                      unsigned long long size,
                                      void *opaque)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf,
                      _("event 'memory-device-size-change' for domain '%s':\n"
                        "alias: %s\nsize: %llu\n"),
                      virDomainGetName(dom), alias, size);

    virshEventPrint(opaque, &buf);
}


virshDomainEventCallback virshDomainEventCallbacks[] = {
    { "lifecycle",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventLifecyclePrint), },
    { "reboot", virshEventGenericPrint, },
    { "rtc-change",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventRTCChangePrint), },
    { "watchdog",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventWatchdogPrint), },
    { "io-error",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventIOErrorPrint), },
    { "graphics",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventGraphicsPrint), },
    { "io-error-reason",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventIOErrorReasonPrint), },
    { "control-error", virshEventGenericPrint, },
    { "block-job",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventBlockJobPrint), },
    { "disk-change",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventDiskChangePrint), },
    { "tray-change",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventTrayChangePrint), },
    { "pm-wakeup",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventPMChangePrint), },
    { "pm-suspend",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventPMChangePrint), },
    { "balloon-change",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventBalloonChangePrint), },
    { "pm-suspend-disk",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventPMChangePrint), },
    { "device-removed",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventDeviceRemovedPrint), },
    { "block-job-2",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventBlockJobPrint), },
    { "tunable",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventTunablePrint), },
    { "agent-lifecycle",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventAgentLifecyclePrint), },
    { "device-added",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventDeviceAddedPrint), },
    { "migration-iteration",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventMigrationIterationPrint), },
    { "job-completed",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventJobCompletedPrint), },
    { "device-removal-failed",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventDeviceRemovalFailedPrint), },
    { "metadata-change",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventMetadataChangePrint), },
    { "block-threshold",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventBlockThresholdPrint), },
    { "memory-failure",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventMemoryFailurePrint), },
    { "memory-device-size-change",
      VIR_DOMAIN_EVENT_CALLBACK(virshEventMemoryDeviceSizeChangePrint), },
};
G_STATIC_ASSERT(VIR_DOMAIN_EVENT_ID_LAST == G_N_ELEMENTS(virshDomainEventCallbacks));


static char **
virshDomainEventNameCompleter(vshControl *ctl G_GNUC_UNUSED,
                              const vshCmd *cmd G_GNUC_UNUSED,
                              unsigned int flags)
{
    size_t i = 0;
    g_auto(GStrv) tmp = NULL;

    virCheckFlags(0, NULL);

    tmp = g_new0(char *, VIR_DOMAIN_EVENT_ID_LAST + 1);

    for (i = 0; i < VIR_DOMAIN_EVENT_ID_LAST; i++)
        tmp[i] = g_strdup(virshDomainEventCallbacks[i].name);

    return g_steal_pointer(&tmp);
}


static const vshCmdInfo info_event[] = {
    {.name = "help",
     .data = N_("Domain Events")
    },
    {.name = "desc",
     .data = N_("List event types, or wait for domain events to occur")
    },
    {.name = NULL}
};

static const vshCmdOptDef opts_event[] = {
    VIRSH_COMMON_OPT_DOMAIN_OT_STRING(N_("filter by domain name, id or uuid"),
                                      0, 0),
    {.name = "event",
     .type = VSH_OT_STRING,
     .completer = virshDomainEventNameCompleter,
     .help = N_("which event type to wait for")
    },
    {.name = "all",
     .type = VSH_OT_BOOL,
     .help = N_("wait for all events instead of just one type")
    },
    {.name = "loop",
     .type = VSH_OT_BOOL,
     .help = N_("loop until timeout or interrupt, rather than one-shot")
    },
    {.name = "timeout",
     .type = VSH_OT_INT,
     .help = N_("timeout seconds")
    },
    {.name = "list",
     .type = VSH_OT_BOOL,
     .help = N_("list valid event types")
    },
    {.name = "timestamp",
     .type = VSH_OT_BOOL,
     .help = N_("show timestamp for each printed event")
    },
    {.name = NULL}
};

static bool
cmdEvent(vshControl *ctl, const vshCmd *cmd)
{
    g_autoptr(virshDomain) dom = NULL;
    bool ret = false;
    int timeout = 0;
    g_autofree virshDomEventData *data = NULL;
    size_t ndata = 0;
    size_t i;
    const char *eventName = NULL;
    bool all = vshCommandOptBool(cmd, "all");
    bool loop = vshCommandOptBool(cmd, "loop");
    bool timestamp = vshCommandOptBool(cmd, "timestamp");
    int count = 0;
    virshControl *priv = ctl->privData;

    VSH_EXCLUSIVE_OPTIONS("all", "event");
    VSH_EXCLUSIVE_OPTIONS("list", "all");
    VSH_EXCLUSIVE_OPTIONS("list", "event");

    if (vshCommandOptBool(cmd, "list")) {
        for (i = 0; i < G_N_ELEMENTS(virshDomainEventCallbacks); i++)
            vshPrint(ctl, "%s\n", virshDomainEventCallbacks[i].name);
        return true;
    }

    if (vshCommandOptStringReq(ctl, cmd, "event", &eventName) < 0)
        return false;

    if (!eventName && !all) {
        vshError(ctl, "%s",
                 _("one of --list, --all, or --event <type> is required"));
        return false;
    }

    data = g_new0(virshDomEventData, G_N_ELEMENTS(virshDomainEventCallbacks));

    for (i = 0; i < G_N_ELEMENTS(virshDomainEventCallbacks); i++) {
        if (eventName &&
            STRNEQ(eventName, virshDomainEventCallbacks[i].name))
            continue;

        data[ndata].event = i;
        data[ndata].ctl = ctl;
        data[ndata].loop = loop;
        data[ndata].count = &count;
        data[ndata].timestamp = timestamp;
        data[ndata].cb = &virshDomainEventCallbacks[i];
        data[ndata].id = -1;
        ndata++;
    }

    if (ndata == 0) {
        vshError(ctl, _("unknown event type %s"), eventName);
        return false;
    }

    if (vshCommandOptTimeoutToMs(ctl, cmd, &timeout) < 0)
        goto cleanup;

    if (vshCommandOptBool(cmd, "domain")) {
        if (!(dom = virshCommandOptDomain(ctl, cmd, NULL)))
            goto cleanup;
    }

    if (vshEventStart(ctl, timeout) < 0)
        goto cleanup;

    for (i = 0; i < ndata; i++) {
        if ((data[i].id = virConnectDomainEventRegisterAny(priv->conn, dom,
                                                           data[i].event,
                                                           data[i].cb->cb,
                                                           &data[i],
                                                           NULL)) < 0) {
            /* When registering for all events: if the first
             * registration succeeds, silently ignore failures on all
             * later registrations on the assumption that the server
             * is older and didn't know quite as many events.  */
            if (i)
                vshResetLibvirtError();
            else
                goto cleanup;
        }
    }
    switch (vshEventWait(ctl)) {
    case VSH_EVENT_INTERRUPT:
        vshPrint(ctl, "%s", _("event loop interrupted\n"));
        break;
    case VSH_EVENT_TIMEOUT:
        vshPrint(ctl, "%s", _("event loop timed out\n"));
        break;
    case VSH_EVENT_DONE:
        break;
    default:
        goto cleanup;
    }
    vshPrint(ctl, _("events received: %d\n"), count);
    if (count)
        ret = true;

 cleanup:
    vshEventCleanup(ctl);
    if (data) {
        for (i = 0; i < ndata; i++) {
            if (data[i].id >= 0 &&
                virConnectDomainEventDeregisterAny(priv->conn, data[i].id) < 0)
                ret = false;
        }
    }
    return ret;
}


const vshCmdDef domEventCmds[] = {
    {.name = "event",
     .handler = cmdEvent,
     .opts = opts_event,
     .info = info_event,
     .flags = 0
    },
    {.name = NULL}
};
