#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

#include <verify.h>

#define VIR_ENUM_SENTINELS

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

#define ARRAY_CARDINALITY(Array) (sizeof(Array) / sizeof(*(Array)))
#define STREQ(a, b) (strcmp(a, b) == 0)
#define NULLSTR(s) ((s) ? (s) : "<null>")

#ifndef ATTRIBUTE_UNUSED
# define ATTRIBUTE_UNUSED __attribute__((__unused__))
#endif

int run = 1;

/* Callback functions */
static void
connectClose(virConnectPtr conn ATTRIBUTE_UNUSED,
             int reason,
             void *opaque ATTRIBUTE_UNUSED)
{
    run = 0;

    switch ((virConnectCloseReason) reason) {
    case VIR_CONNECT_CLOSE_REASON_ERROR:
        fprintf(stderr, "Connection closed due to I/O error\n");
        return;

    case VIR_CONNECT_CLOSE_REASON_EOF:
        fprintf(stderr, "Connection closed due to end of file\n");
        return;

    case VIR_CONNECT_CLOSE_REASON_KEEPALIVE:
        fprintf(stderr, "Connection closed due to keepalive timeout\n");
        return;

    case VIR_CONNECT_CLOSE_REASON_CLIENT:
        fprintf(stderr, "Connection closed due to client request\n");
        return;

    case VIR_CONNECT_CLOSE_REASON_LAST:
        break;
    };

    fprintf(stderr, "Connection closed due to unknown reason\n");
}


static const char *
eventToString(int event)
{
    switch ((virDomainEventType) event) {
        case VIR_DOMAIN_EVENT_DEFINED:
            return "Defined";

        case VIR_DOMAIN_EVENT_UNDEFINED:
            return "Undefined";

        case VIR_DOMAIN_EVENT_STARTED:
            return "Started";

        case VIR_DOMAIN_EVENT_SUSPENDED:
            return "Suspended";

        case VIR_DOMAIN_EVENT_RESUMED:
            return "Resumed";

        case VIR_DOMAIN_EVENT_STOPPED:
            return "Stopped";

        case VIR_DOMAIN_EVENT_SHUTDOWN:
            return "Shutdown";

        case VIR_DOMAIN_EVENT_PMSUSPENDED:
            return "PMSuspended";

        case VIR_DOMAIN_EVENT_CRASHED:
            return "Crashed";

        case VIR_DOMAIN_EVENT_LAST:
            break;
    }

    return "unknown";
}


static const char *
eventDetailToString(int event,
                    int detail)
{
    switch ((virDomainEventType) event) {
        case VIR_DOMAIN_EVENT_DEFINED:
            switch ((virDomainEventDefinedDetailType) detail) {
            case VIR_DOMAIN_EVENT_DEFINED_ADDED:
                return "Added";

            case VIR_DOMAIN_EVENT_DEFINED_UPDATED:
                return "Updated";

            case VIR_DOMAIN_EVENT_DEFINED_RENAMED:
                return "Renamed";

            case  VIR_DOMAIN_EVENT_DEFINED_FROM_SNAPSHOT:
                return "Snapshot";

            case VIR_DOMAIN_EVENT_DEFINED_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_EVENT_UNDEFINED:
            switch ((virDomainEventUndefinedDetailType) detail) {
            case VIR_DOMAIN_EVENT_UNDEFINED_REMOVED:
                return "Removed";

            case VIR_DOMAIN_EVENT_UNDEFINED_RENAMED:
                return "Renamed";

            case VIR_DOMAIN_EVENT_UNDEFINED_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_EVENT_STARTED:
            switch ((virDomainEventStartedDetailType) detail) {
            case VIR_DOMAIN_EVENT_STARTED_BOOTED:
                return "Booted";

            case VIR_DOMAIN_EVENT_STARTED_MIGRATED:
                return "Migrated";

            case VIR_DOMAIN_EVENT_STARTED_RESTORED:
                return "Restored";

            case VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT:
                return "Snapshot";

            case VIR_DOMAIN_EVENT_STARTED_WAKEUP:
                return "Event wakeup";

            case VIR_DOMAIN_EVENT_STARTED_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_EVENT_SUSPENDED:
            switch ((virDomainEventSuspendedDetailType) detail) {
            case VIR_DOMAIN_EVENT_SUSPENDED_PAUSED:
                return "Paused";

            case VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED:
                return "Migrated";

            case VIR_DOMAIN_EVENT_SUSPENDED_IOERROR:
                return "I/O Error";

            case VIR_DOMAIN_EVENT_SUSPENDED_WATCHDOG:
                return "Watchdog";

            case VIR_DOMAIN_EVENT_SUSPENDED_RESTORED:
                return "Restored";

            case VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT:
                return "Snapshot";

            case VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR:
                return "API error";

            case VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY:
                return "Post-copy";

            case VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY_FAILED:
                return "Post-copy Error";

            case VIR_DOMAIN_EVENT_SUSPENDED_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_EVENT_RESUMED:
            switch ((virDomainEventResumedDetailType) detail) {
            case VIR_DOMAIN_EVENT_RESUMED_UNPAUSED:
                return "Unpaused";

            case VIR_DOMAIN_EVENT_RESUMED_MIGRATED:
                return "Migrated";

            case VIR_DOMAIN_EVENT_RESUMED_FROM_SNAPSHOT:
                return "Snapshot";

            case VIR_DOMAIN_EVENT_RESUMED_POSTCOPY:
                return "Post-copy";

            case VIR_DOMAIN_EVENT_RESUMED_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_EVENT_STOPPED:
            switch ((virDomainEventStoppedDetailType) detail) {
            case VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN:
                return "Shutdown";

            case VIR_DOMAIN_EVENT_STOPPED_DESTROYED:
                return "Destroyed";

            case VIR_DOMAIN_EVENT_STOPPED_CRASHED:
                return "Crashed";

            case VIR_DOMAIN_EVENT_STOPPED_MIGRATED:
                return "Migrated";

            case VIR_DOMAIN_EVENT_STOPPED_SAVED:
                return "Saved";

            case VIR_DOMAIN_EVENT_STOPPED_FAILED:
                return "Failed";

            case VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT:
                return "Snapshot";

            case VIR_DOMAIN_EVENT_STOPPED_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_EVENT_SHUTDOWN:
            switch ((virDomainEventShutdownDetailType) detail) {
            case VIR_DOMAIN_EVENT_SHUTDOWN_FINISHED:
                return "Finished";

            case VIR_DOMAIN_EVENT_SHUTDOWN_GUEST:
                return "Guest request";

            case VIR_DOMAIN_EVENT_SHUTDOWN_HOST:
                return "Host request";

            case VIR_DOMAIN_EVENT_SHUTDOWN_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_EVENT_PMSUSPENDED:
            switch ((virDomainEventPMSuspendedDetailType) detail) {
            case VIR_DOMAIN_EVENT_PMSUSPENDED_MEMORY:
                return "Memory";

            case VIR_DOMAIN_EVENT_PMSUSPENDED_DISK:
                return "Disk";

            case VIR_DOMAIN_EVENT_PMSUSPENDED_LAST:
                break;
            }
            break;

        case VIR_DOMAIN_EVENT_CRASHED:
           switch ((virDomainEventCrashedDetailType) detail) {
           case VIR_DOMAIN_EVENT_CRASHED_PANICKED:
               return "Panicked";

           case VIR_DOMAIN_EVENT_CRASHED_LAST:
               break;
           }
           break;

        case VIR_DOMAIN_EVENT_LAST:
           break;
    }

    return "unknown";
}


static const char *
networkEventToString(int event)
{
    switch ((virNetworkEventLifecycleType) event) {
        case VIR_NETWORK_EVENT_DEFINED:
            return "Defined";

        case VIR_NETWORK_EVENT_UNDEFINED:
            return "Undefined";

        case VIR_NETWORK_EVENT_STARTED:
            return "Started";

        case VIR_NETWORK_EVENT_STOPPED:
            return "Stopped";

        case VIR_NETWORK_EVENT_LAST:
            break;
    }

    return "unknown";
}


static const char *
guestAgentLifecycleEventStateToString(int event)
{
    switch ((virConnectDomainEventAgentLifecycleState) event) {
    case VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_STATE_DISCONNECTED:
        return "Disconnected";

    case VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_STATE_CONNECTED:
        return "Connected";

    case VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_STATE_LAST:
        break;
    }

    return "unknown";
}


static const char *
guestAgentLifecycleEventReasonToString(int event)
{
    switch ((virConnectDomainEventAgentLifecycleReason) event) {
    case VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_UNKNOWN:
        return "Unknown";

    case VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_DOMAIN_STARTED:
        return "Domain started";

    case VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_CHANNEL:
        return "Channel event";

    case VIR_CONNECT_DOMAIN_EVENT_AGENT_LIFECYCLE_REASON_LAST:
        break;
    }

    return "unknown";
}

static const char *
storagePoolEventToString(int event)
{
    switch ((virStoragePoolEventLifecycleType) event) {
        case VIR_STORAGE_POOL_EVENT_DEFINED:
            return "Defined";
        case VIR_STORAGE_POOL_EVENT_UNDEFINED:
            return "Undefined";
        case VIR_STORAGE_POOL_EVENT_STARTED:
            return "Started";
        case VIR_STORAGE_POOL_EVENT_STOPPED:
            return "Stopped";
        case VIR_STORAGE_POOL_EVENT_LAST:
            break;
    }
    return "unknown";
}

static const char *
nodeDeviceEventToString(int event)
{
    switch ((virNodeDeviceEventLifecycleType) event) {
        case VIR_NODE_DEVICE_EVENT_CREATED:
            return "Created";
        case VIR_NODE_DEVICE_EVENT_DELETED:
            return "Deleted";
        case VIR_NODE_DEVICE_EVENT_LAST:
            break;
    }
    return "unknown";
}


static const char *
secretEventToString(int event)
{
    switch ((virSecretEventLifecycleType) event) {
        case VIR_SECRET_EVENT_DEFINED:
            return "Defined";

        case VIR_SECRET_EVENT_UNDEFINED:
            return "Undefined";

        case VIR_SECRET_EVENT_LAST:
            break;
    }

    return "unknown";
}


static int
myDomainEventCallback1(virConnectPtr conn ATTRIBUTE_UNUSED,
                       virDomainPtr dom,
                       int event,
                       int detail,
                       void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) %s %s\n", __func__, virDomainGetName(dom),
           virDomainGetID(dom), eventToString(event),
           eventDetailToString(event, detail));
    return 0;
}


static int
myDomainEventCallback2(virConnectPtr conn ATTRIBUTE_UNUSED,
                       virDomainPtr dom,
                       int event,
                       int detail,
                       void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) %s %s\n", __func__, virDomainGetName(dom),
           virDomainGetID(dom), eventToString(event),
           eventDetailToString(event, detail));
    return 0;
}


static int
myDomainEventRebootCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                            virDomainPtr dom,
                            void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) rebooted\n", __func__, virDomainGetName(dom),
           virDomainGetID(dom));

    return 0;
}


static int
myDomainEventRTCChangeCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virDomainPtr dom,
                               long long offset,
                               void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) rtc change %" PRIdMAX "\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom),
           (intmax_t)offset);

    return 0;
}


static int
myDomainEventBalloonChangeCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   virDomainPtr dom,
                                   unsigned long long actual,
                                   void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) balloon change %" PRIuMAX "KB\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom), (uintmax_t)actual);

    return 0;
}


static int
myDomainEventWatchdogCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                              virDomainPtr dom,
                              int action,
                              void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) watchdog action=%d\n", __func__,
           virDomainGetName(dom), virDomainGetID(dom), action);

    return 0;
}


static int
myDomainEventIOErrorCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                             virDomainPtr dom,
                             const char *srcPath,
                             const char *devAlias,
                             int action,
                             void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) io error path=%s alias=%s action=%d\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom),
           srcPath, devAlias, action);

    return 0;
}


static int
myDomainEventIOErrorReasonCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   virDomainPtr dom,
                                   const char *srcPath,
                                   const char *devAlias,
                                   int action,
                                   const char *reason,
                                   void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) io error (reason) path=%s alias=%s "
           "action=%d reason=%s\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom),
           srcPath, devAlias, action, reason);

    return 0;
}


static const char *
graphicsPhaseToStr(int phase)
{
    switch ((virDomainEventGraphicsPhase) phase) {
    case VIR_DOMAIN_EVENT_GRAPHICS_CONNECT:
        return "connected";

    case VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE:
        return "initialized";

    case VIR_DOMAIN_EVENT_GRAPHICS_DISCONNECT:
        return "disconnected";

    case VIR_DOMAIN_EVENT_GRAPHICS_LAST:
        break;
    }

    return "unknown";
}


static int
myDomainEventGraphicsCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                              virDomainPtr dom,
                              int phase,
                              virDomainEventGraphicsAddressPtr local,
                              virDomainEventGraphicsAddressPtr remote,
                              const char *authScheme,
                              virDomainEventGraphicsSubjectPtr subject,
                              void *opaque ATTRIBUTE_UNUSED)
{
    size_t i;
    printf("%s EVENT: Domain %s(%d) graphics ", __func__, virDomainGetName(dom),
           virDomainGetID(dom));

    printf("%s ", graphicsPhaseToStr(phase));

    printf("local: family=%d node=%s service=%s ",
           local->family, local->node, local->service);
    printf("remote: family=%d node=%s service=%s ",
           remote->family, remote->node, remote->service);

    printf("auth: %s ", authScheme);
    for (i = 0; i < subject->nidentity; i++) {
        printf(" identity: %s=%s",
               subject->identities[i].type,
               subject->identities[i].name);
    }
    printf("\n");

    return 0;
}


static int
myDomainEventControlErrorCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virDomainPtr dom,
                                  void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) control error\n", __func__,
           virDomainGetName(dom), virDomainGetID(dom));

    return 0;
}

static const char *
diskChangeReasonToStr(int reason)
{
    switch ((virConnectDomainEventDiskChangeReason) reason) {
    case VIR_DOMAIN_EVENT_DISK_CHANGE_MISSING_ON_START:
        return "disk empty due to startupPolicy";

    case VIR_DOMAIN_EVENT_DISK_DROP_MISSING_ON_START:
        return "disk dropped due to startupPolicy";

    case VIR_DOMAIN_EVENT_DISK_CHANGE_LAST:
        break;
    }

    return "unknown";
}


static int
myDomainEventDiskChangeCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virDomainPtr dom,
                                const char *oldSrcPath,
                                const char *newSrcPath,
                                const char *devAlias,
                                int reason,
                                void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) disk change oldSrcPath: %s newSrcPath: %s "
           "devAlias: %s reason: %s\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom),
           oldSrcPath, newSrcPath, devAlias, diskChangeReasonToStr(reason));
    return 0;
}

static const char *
trayChangeReasonToStr(int reason)
{
    switch ((virDomainEventTrayChangeReason) reason) {
    case VIR_DOMAIN_EVENT_TRAY_CHANGE_OPEN:
        return "open";

    case VIR_DOMAIN_EVENT_TRAY_CHANGE_CLOSE:
        return "close";

    case VIR_DOMAIN_EVENT_TRAY_CHANGE_LAST:
        break;
    }

    return "unknown";
};


static int
myDomainEventTrayChangeCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virDomainPtr dom,
                                const char *devAlias,
                                int reason,
                                void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) removable disk's tray change devAlias: %s "
           "reason: %s\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom),
           devAlias, trayChangeReasonToStr(reason));
    return 0;
}


static int
myDomainEventPMWakeupCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                              virDomainPtr dom,
                              int reason ATTRIBUTE_UNUSED,
                              void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) system pmwakeup\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom));
    return 0;
}


static int
myDomainEventPMSuspendCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                               virDomainPtr dom,
                               int reason ATTRIBUTE_UNUSED,
                               void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) system pmsuspend\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom));
    return 0;
}


static int
myDomainEventPMSuspendDiskCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   virDomainPtr dom,
                                   int reason ATTRIBUTE_UNUSED,
                                   void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) system pmsuspend-disk\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom));
    return 0;
}


static int
myDomainEventDeviceRemovedCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                   virDomainPtr dom,
                                   const char *devAlias,
                                   void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) device removed: %s\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom), devAlias);
    return 0;
}


static int
myNetworkEventCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                       virNetworkPtr dom,
                       int event,
                       int detail,
                       void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Network %s %s %d\n", __func__, virNetworkGetName(dom),
           networkEventToString(event), detail);
    return 0;
}

static int
myStoragePoolEventCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                           virStoragePoolPtr pool,
                           int event,
                           int detail,
                           void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Storage pool %s %s %d\n", __func__,
           virStoragePoolGetName(pool),
           storagePoolEventToString(event),
           detail);
    return 0;
}


static int
myStoragePoolEventRefreshCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virStoragePoolPtr pool,
                                  void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Storage pool %s refresh\n", __func__,
           virStoragePoolGetName(pool));
    return 0;
}


static int
myNodeDeviceEventCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                          virNodeDevicePtr dev,
                          int event,
                          int detail,
                          void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Node device %s %s %d\n", __func__,
           virNodeDeviceGetName(dev),
           nodeDeviceEventToString(event),
           detail);
    return 0;
}


static int
myNodeDeviceEventUpdateCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                virNodeDevicePtr dev,
                                void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Node device %s update\n", __func__,
           virNodeDeviceGetName(dev));
    return 0;
}


static int
mySecretEventCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                      virSecretPtr secret,
                      int event,
                      int detail,
                      void *opaque ATTRIBUTE_UNUSED)
{
    char uuid[VIR_UUID_STRING_BUFLEN];
    virSecretGetUUIDString(secret, uuid);
    printf("%s EVENT: Secret %s %s %d\n", __func__,
           uuid,
           secretEventToString(event),
           detail);
    return 0;
}


static int
mySecretEventValueChanged(virConnectPtr conn ATTRIBUTE_UNUSED,
                          virSecretPtr secret,
                          void *opaque ATTRIBUTE_UNUSED)
{
    char uuid[VIR_UUID_STRING_BUFLEN];
    virSecretGetUUIDString(secret, uuid);
    printf("%s EVENT: Secret %s\n", __func__, uuid);
    return 0;
}


static void
eventTypedParamsPrint(virTypedParameterPtr params,
                      int nparams)
{
    size_t i;

    for (i = 0; i < nparams; i++) {
        switch (params[i].type) {
        case VIR_TYPED_PARAM_INT:
            printf("\t%s: %d\n", params[i].field, params[i].value.i);
            break;
        case VIR_TYPED_PARAM_UINT:
            printf("\t%s: %u\n", params[i].field, params[i].value.ui);
            break;
        case VIR_TYPED_PARAM_LLONG:
            printf("\t%s: %" PRId64 "\n", params[i].field,
                   (int64_t) params[i].value.l);
            break;
        case VIR_TYPED_PARAM_ULLONG:
            printf("\t%s: %" PRIu64 "\n", params[i].field,
                   (uint64_t) params[i].value.ul);
            break;
        case VIR_TYPED_PARAM_DOUBLE:
            printf("\t%s: %g\n", params[i].field, params[i].value.d);
            break;
        case VIR_TYPED_PARAM_BOOLEAN:
            printf("\t%s: %d\n", params[i].field, params[i].value.b);
            break;
        case VIR_TYPED_PARAM_STRING:
            printf("\t%s: %s\n", params[i].field, params[i].value.s);
            break;
        default:
            printf("\t%s: unknown type\n", params[i].field);
        }
    }
}


static int
myDomainEventTunableCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                             virDomainPtr dom,
                             virTypedParameterPtr params,
                             int nparams,
                             void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) tunable updated:\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom));

    eventTypedParamsPrint(params, nparams);

    return 0;
}


static int
myDomainEventAgentLifecycleCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    virDomainPtr dom,
                                    int state,
                                    int reason,
                                    void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) guest agent state changed: %s reason: %s\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom),
           guestAgentLifecycleEventStateToString(state),
           guestAgentLifecycleEventReasonToString(reason));

    return 0;
}


static int
myDomainEventDeviceAddedCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                 virDomainPtr dom,
                                 const char *devAlias,
                                 void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) device added: %s\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom), devAlias);
    return 0;
}


static const char *
blockJobTypeToStr(int type)
{
    switch ((virDomainBlockJobType) type) {
    case VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN:
    case VIR_DOMAIN_BLOCK_JOB_TYPE_LAST:
        break;

    case VIR_DOMAIN_BLOCK_JOB_TYPE_PULL:
        return "block pull";

    case VIR_DOMAIN_BLOCK_JOB_TYPE_COPY:
        return "block copy";

    case VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT:
        return "block commit";

    case VIR_DOMAIN_BLOCK_JOB_TYPE_ACTIVE_COMMIT:
        return "active layer block commit";
    }

    return "unknown";
}


static const char *
blockJobStatusToStr(int status)
{
    switch ((virConnectDomainEventBlockJobStatus) status) {
    case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
        return "completed";

    case VIR_DOMAIN_BLOCK_JOB_FAILED:
        return "failed";

    case VIR_DOMAIN_BLOCK_JOB_CANCELED:
        return "cancelled";

    case VIR_DOMAIN_BLOCK_JOB_READY:
        return "ready";

    case VIR_DOMAIN_BLOCK_JOB_LAST:
        break;
    }

    return "unknown";
}


static int
myDomainEventBlockJobCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                              virDomainPtr dom,
                              const char *disk,
                              int type,
                              int status,
                              void *opaque)
{
    const char *eventName = opaque;

    printf("%s EVENT: Domain %s(%d) block job callback '%s' disk '%s', "
           "type '%s' status '%s'",
           __func__, virDomainGetName(dom), virDomainGetID(dom), eventName,
           disk, blockJobTypeToStr(type), blockJobStatusToStr(status));
    return 0;
}


static int
myDomainEventBlockThresholdCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    virDomainPtr dom,
                                    const char *dev,
                                    const char *path,
                                    unsigned long long threshold,
                                    unsigned long long excess,
                                    void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) block threshold callback dev '%s'(%s), "
           "threshold: '%llu', excess: '%llu'",
           __func__, virDomainGetName(dom), virDomainGetID(dom),
           dev, NULLSTR(path), threshold, excess);
    return 0;
}


static int
myDomainEventMigrationIterationCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                        virDomainPtr dom,
                                        int iteration,
                                        void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) migration iteration '%d'\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom), iteration);
    return 0;
}


static int
myDomainEventJobCompletedCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virDomainPtr dom,
                                  virTypedParameterPtr params,
                                  int nparams,
                                  void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) job completed:\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom));

    eventTypedParamsPrint(params, nparams);

    return 0;
}


static int
myDomainEventDeviceRemovalFailedCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                         virDomainPtr dom,
                                         const char *devAlias,
                                         void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) device removal failed: %s\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom), devAlias);
    return 0;
}


static const char *
metadataTypeToStr(int status)
{
    switch ((virDomainMetadataType) status) {
    case VIR_DOMAIN_METADATA_DESCRIPTION:
        return "description";

    case VIR_DOMAIN_METADATA_TITLE:
        return "title";

    case VIR_DOMAIN_METADATA_ELEMENT:
        return "element";

    case VIR_DOMAIN_METADATA_LAST:
        break;
    }

    return "unknown";
}

static int
myDomainEventMetadataChangeCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    virDomainPtr dom,
                                    int type,
                                    const char *nsuri,
                                    void *opaque ATTRIBUTE_UNUSED)
{
    const char *typestr = metadataTypeToStr(type);
    printf("%s EVENT: Domain %s(%d) metadata type: %s (%s)\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom), typestr, nsuri ? nsuri : "n/a");
    return 0;
}



static void
myFreeFunc(void *opaque)
{
    char *str = opaque;
    printf("%s: Freeing [%s]\n", __func__, str);
    free(str);
}


/* main test functions */
static void
stop(int sig)
{
    printf("Exiting on signal %d\n", sig);
    run = 0;
}


struct domainEventData {
    int event;
    int id;
    virConnectDomainEventGenericCallback cb;
    const char *name;
};


#define DOMAIN_EVENT(event, callback)                                          \
    {event, -1, VIR_DOMAIN_EVENT_CALLBACK(callback), #event}

struct domainEventData domainEvents[] = {
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_LIFECYCLE, myDomainEventCallback2),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_REBOOT, myDomainEventRebootCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_RTC_CHANGE, myDomainEventRTCChangeCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_WATCHDOG, myDomainEventWatchdogCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_IO_ERROR, myDomainEventIOErrorCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_GRAPHICS, myDomainEventGraphicsCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_IO_ERROR_REASON, myDomainEventIOErrorReasonCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_CONTROL_ERROR, myDomainEventControlErrorCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_BLOCK_JOB, myDomainEventBlockJobCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_DISK_CHANGE, myDomainEventDiskChangeCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_TRAY_CHANGE, myDomainEventTrayChangeCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_PMWAKEUP, myDomainEventPMWakeupCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_PMSUSPEND, myDomainEventPMSuspendCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE, myDomainEventBalloonChangeCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK, myDomainEventPMSuspendDiskCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED, myDomainEventDeviceRemovedCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_BLOCK_JOB_2, myDomainEventBlockJobCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_TUNABLE, myDomainEventTunableCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_AGENT_LIFECYCLE, myDomainEventAgentLifecycleCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_DEVICE_ADDED, myDomainEventDeviceAddedCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_MIGRATION_ITERATION, myDomainEventMigrationIterationCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_JOB_COMPLETED, myDomainEventJobCompletedCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_DEVICE_REMOVAL_FAILED, myDomainEventDeviceRemovalFailedCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_METADATA_CHANGE, myDomainEventMetadataChangeCallback),
    DOMAIN_EVENT(VIR_DOMAIN_EVENT_ID_BLOCK_THRESHOLD, myDomainEventBlockThresholdCallback),
};

struct storagePoolEventData {
    int event;
    int id;
    virConnectStoragePoolEventGenericCallback cb;
    const char *name;
};

#define STORAGE_POOL_EVENT(event, callback)                                          \
    {event, -1, VIR_STORAGE_POOL_EVENT_CALLBACK(callback), #event}

struct storagePoolEventData storagePoolEvents[] = {
    STORAGE_POOL_EVENT(VIR_STORAGE_POOL_EVENT_ID_LIFECYCLE, myStoragePoolEventCallback),
    STORAGE_POOL_EVENT(VIR_STORAGE_POOL_EVENT_ID_REFRESH, myStoragePoolEventRefreshCallback),
};

struct nodeDeviceEventData {
    int event;
    int id;
    virConnectNodeDeviceEventGenericCallback cb;
    const char *name;
};

#define NODE_DEVICE_EVENT(event, callback)                                          \
    {event, -1, VIR_NODE_DEVICE_EVENT_CALLBACK(callback), #event}

struct nodeDeviceEventData nodeDeviceEvents[] = {
    NODE_DEVICE_EVENT(VIR_NODE_DEVICE_EVENT_ID_LIFECYCLE, myNodeDeviceEventCallback),
    NODE_DEVICE_EVENT(VIR_NODE_DEVICE_EVENT_ID_UPDATE, myNodeDeviceEventUpdateCallback),
};

struct secretEventData {
    int event;
    int id;
    virConnectSecretEventGenericCallback cb;
    const char *name;
};

#define SECRET_EVENT(event, callback)                                          \
    {event, -1, VIR_SECRET_EVENT_CALLBACK(callback), #event}

struct secretEventData secretEvents[] = {
    SECRET_EVENT(VIR_SECRET_EVENT_ID_LIFECYCLE, mySecretEventCallback),
    SECRET_EVENT(VIR_SECRET_EVENT_ID_VALUE_CHANGED, mySecretEventValueChanged),
};

/* make sure that the events are kept in sync */
verify(ARRAY_CARDINALITY(domainEvents) == VIR_DOMAIN_EVENT_ID_LAST);
verify(ARRAY_CARDINALITY(storagePoolEvents) == VIR_STORAGE_POOL_EVENT_ID_LAST);
verify(ARRAY_CARDINALITY(nodeDeviceEvents) == VIR_NODE_DEVICE_EVENT_ID_LAST);
verify(ARRAY_CARDINALITY(secretEvents) == VIR_SECRET_EVENT_ID_LAST);

int
main(int argc, char **argv)
{
    int ret = EXIT_FAILURE;
    virConnectPtr dconn = NULL;
    int callback1ret = -1;
    int callback16ret = -1;
    struct sigaction action_stop;
    size_t i;

    memset(&action_stop, 0, sizeof(action_stop));

    action_stop.sa_handler = stop;

    if (argc > 1 && STREQ(argv[1], "--help")) {
        printf("%s uri\n", argv[0]);
        goto cleanup;
    }

    if (virInitialize() < 0) {
        fprintf(stderr, "Failed to initialize libvirt");
        goto cleanup;
    }

    if (virEventRegisterDefaultImpl() < 0) {
        fprintf(stderr, "Failed to register event implementation: %s\n",
                virGetLastErrorMessage());
        goto cleanup;
    }

    dconn = virConnectOpenAuth(argc > 1 ? argv[1] : NULL,
                               virConnectAuthPtrDefault,
                               VIR_CONNECT_RO);
    if (!dconn) {
        printf("error opening\n");
        goto cleanup;
    }

    if (virConnectRegisterCloseCallback(dconn,
                                        connectClose, NULL, NULL) < 0) {
        fprintf(stderr, "Unable to register close callback\n");
        goto cleanup;
    }

    sigaction(SIGTERM, &action_stop, NULL);
    sigaction(SIGINT, &action_stop, NULL);

    printf("Registering event callbacks\n");

    callback1ret = virConnectDomainEventRegister(dconn, myDomainEventCallback1,
                                                 strdup("callback 1"), myFreeFunc);

    /* register common domain callbacks */
    for (i = 0; i < ARRAY_CARDINALITY(domainEvents); i++) {
        struct domainEventData *event = domainEvents + i;

        event->id = virConnectDomainEventRegisterAny(dconn, NULL,
                                                     event->event,
                                                     event->cb,
                                                     strdup(event->name),
                                                     myFreeFunc);

        if (event->id < 0) {
            fprintf(stderr, "Failed to register event '%s'\n", event->name);
            goto cleanup;
        }
    }

    callback16ret = virConnectNetworkEventRegisterAny(dconn,
                                                      NULL,
                                                      VIR_NETWORK_EVENT_ID_LIFECYCLE,
                                                      VIR_NETWORK_EVENT_CALLBACK(myNetworkEventCallback),
                                                      strdup("net callback"), myFreeFunc);

    /* register common storage pool callbacks */
    for (i = 0; i < ARRAY_CARDINALITY(storagePoolEvents); i++) {
        struct storagePoolEventData *event = storagePoolEvents + i;

        event->id = virConnectStoragePoolEventRegisterAny(dconn, NULL,
                                                          event->event,
                                                          event->cb,
                                                          strdup(event->name),
                                                          myFreeFunc);

        if (event->id < 0) {
            fprintf(stderr, "Failed to register event '%s'\n", event->name);
            goto cleanup;
        }
    }

    /* register common node device callbacks */
    for (i = 0; i < ARRAY_CARDINALITY(nodeDeviceEvents); i++) {
        struct nodeDeviceEventData *event = nodeDeviceEvents + i;

        event->id = virConnectNodeDeviceEventRegisterAny(dconn, NULL,
                                                         event->event,
                                                         event->cb,
                                                         strdup(event->name),
                                                         myFreeFunc);

        if (event->id < 0) {
            fprintf(stderr, "Failed to register event '%s'\n", event->name);
            goto cleanup;
        }
    }

    /* register common secret callbacks */
    for (i = 0; i < ARRAY_CARDINALITY(secretEvents); i++) {
        struct secretEventData *event = secretEvents + i;

        event->id = virConnectSecretEventRegisterAny(dconn, NULL,
                                                     event->event,
                                                     event->cb,
                                                     strdup(event->name),
                                                     myFreeFunc);

        if (event->id < 0) {
            fprintf(stderr, "Failed to register event '%s'\n", event->name);
            goto cleanup;
        }
    }

    if ((callback1ret == -1) ||
        (callback16ret == -1))
        goto cleanup;

    if (virConnectSetKeepAlive(dconn, 5, 3) < 0) {
        fprintf(stderr, "Failed to start keepalive protocol: %s\n",
                virGetLastErrorMessage());
        run = 0;
    }

    while (run) {
        if (virEventRunDefaultImpl() < 0) {
            fprintf(stderr, "Failed to run event loop: %s\n",
                    virGetLastErrorMessage());
        }
    }

    printf("Deregistering event callbacks\n");
    virConnectDomainEventDeregister(dconn, myDomainEventCallback1);
    virConnectNetworkEventDeregisterAny(dconn, callback16ret);


    printf("Deregistering domain event callbacks\n");
    for (i = 0; i < ARRAY_CARDINALITY(domainEvents); i++) {
        if (domainEvents[i].id > 0)
            virConnectDomainEventDeregisterAny(dconn, domainEvents[i].id);
    }


    printf("Deregistering storage pool event callbacks\n");
    for (i = 0; i < ARRAY_CARDINALITY(storagePoolEvents); i++) {
        if (storagePoolEvents[i].id > 0)
            virConnectStoragePoolEventDeregisterAny(dconn, storagePoolEvents[i].id);
    }


    printf("Deregistering node device event callbacks\n");
    for (i = 0; i < ARRAY_CARDINALITY(nodeDeviceEvents); i++) {
        if (nodeDeviceEvents[i].id > 0)
            virConnectNodeDeviceEventDeregisterAny(dconn, nodeDeviceEvents[i].id);
    }

    printf("Deregistering secret event callbacks\n");
    for (i = 0; i < ARRAY_CARDINALITY(secretEvents); i++) {
        if (secretEvents[i].id > 0)
            virConnectSecretEventDeregisterAny(dconn, secretEvents[i].id);
    }


    virConnectUnregisterCloseCallback(dconn, connectClose);
    ret = EXIT_SUCCESS;


 cleanup:
    if (dconn) {
        printf("Closing connection: ");
        if (virConnectClose(dconn) < 0)
            printf("failed\n");
        printf("done\n");
    }

    return ret;
}
