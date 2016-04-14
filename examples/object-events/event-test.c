#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

#define VIR_ENUM_SENTINELS

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

#define STREQ(a, b) (strcmp(a, b) == 0)

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
myDomainEventTunableCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                             virDomainPtr dom,
                             virTypedParameterPtr params,
                             int nparams,
                             void *opaque ATTRIBUTE_UNUSED)
{
    size_t i;

    printf("%s EVENT: Domain %s(%d) tunable updated:\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom));

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


int
main(int argc, char **argv)
{
    int ret = EXIT_FAILURE;
    virConnectPtr dconn = NULL;
    int callback1ret = -1;
    int callback2ret = -1;
    int callback3ret = -1;
    int callback4ret = -1;
    int callback5ret = -1;
    int callback6ret = -1;
    int callback7ret = -1;
    int callback8ret = -1;
    int callback9ret = -1;
    int callback10ret = -1;
    int callback11ret = -1;
    int callback12ret = -1;
    int callback13ret = -1;
    int callback14ret = -1;
    int callback15ret = -1;
    int callback16ret = -1;
    int callback17ret = -1;
    int callback18ret = -1;
    int callback19ret = -1;
    struct sigaction action_stop;

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
        virErrorPtr err = virGetLastError();
        fprintf(stderr, "Failed to register event implementation: %s\n",
                err && err->message ? err->message: "Unknown error");
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

    /* Add 2 callbacks to prove this works with more than just one */
    callback1ret = virConnectDomainEventRegister(dconn, myDomainEventCallback1,
                                                 strdup("callback 1"), myFreeFunc);
    callback2ret = virConnectDomainEventRegisterAny(dconn,
                                                    NULL,
                                                    VIR_DOMAIN_EVENT_ID_LIFECYCLE,
                                                    VIR_DOMAIN_EVENT_CALLBACK(myDomainEventCallback2),
                                                    strdup("callback 2"), myFreeFunc);
    callback3ret = virConnectDomainEventRegisterAny(dconn,
                                                    NULL,
                                                    VIR_DOMAIN_EVENT_ID_REBOOT,
                                                    VIR_DOMAIN_EVENT_CALLBACK(myDomainEventRebootCallback),
                                                    strdup("callback reboot"), myFreeFunc);
    callback4ret = virConnectDomainEventRegisterAny(dconn,
                                                    NULL,
                                                    VIR_DOMAIN_EVENT_ID_RTC_CHANGE,
                                                    VIR_DOMAIN_EVENT_CALLBACK(myDomainEventRTCChangeCallback),
                                                    strdup("callback rtcchange"), myFreeFunc);
    callback5ret = virConnectDomainEventRegisterAny(dconn,
                                                    NULL,
                                                    VIR_DOMAIN_EVENT_ID_WATCHDOG,
                                                    VIR_DOMAIN_EVENT_CALLBACK(myDomainEventWatchdogCallback),
                                                    strdup("callback watchdog"), myFreeFunc);
    callback6ret = virConnectDomainEventRegisterAny(dconn,
                                                    NULL,
                                                    VIR_DOMAIN_EVENT_ID_IO_ERROR,
                                                    VIR_DOMAIN_EVENT_CALLBACK(myDomainEventIOErrorCallback),
                                                    strdup("callback io error"), myFreeFunc);
    callback7ret = virConnectDomainEventRegisterAny(dconn,
                                                    NULL,
                                                    VIR_DOMAIN_EVENT_ID_GRAPHICS,
                                                    VIR_DOMAIN_EVENT_CALLBACK(myDomainEventGraphicsCallback),
                                                    strdup("callback graphics"), myFreeFunc);
    callback8ret = virConnectDomainEventRegisterAny(dconn,
                                                    NULL,
                                                    VIR_DOMAIN_EVENT_ID_CONTROL_ERROR,
                                                    VIR_DOMAIN_EVENT_CALLBACK(myDomainEventControlErrorCallback),
                                                    strdup("callback control error"), myFreeFunc);
    callback9ret = virConnectDomainEventRegisterAny(dconn,
                                                    NULL,
                                                    VIR_DOMAIN_EVENT_ID_DISK_CHANGE,
                                                    VIR_DOMAIN_EVENT_CALLBACK(myDomainEventDiskChangeCallback),
                                                    strdup("disk change"), myFreeFunc);
    callback10ret = virConnectDomainEventRegisterAny(dconn,
                                                     NULL,
                                                     VIR_DOMAIN_EVENT_ID_TRAY_CHANGE,
                                                     VIR_DOMAIN_EVENT_CALLBACK(myDomainEventTrayChangeCallback),
                                                     strdup("tray change"), myFreeFunc);
    callback11ret = virConnectDomainEventRegisterAny(dconn,
                                                     NULL,
                                                     VIR_DOMAIN_EVENT_ID_PMWAKEUP,
                                                     VIR_DOMAIN_EVENT_CALLBACK(myDomainEventPMWakeupCallback),
                                                     strdup("pmwakeup"), myFreeFunc);
    callback12ret = virConnectDomainEventRegisterAny(dconn,
                                                     NULL,
                                                     VIR_DOMAIN_EVENT_ID_PMSUSPEND,
                                                     VIR_DOMAIN_EVENT_CALLBACK(myDomainEventPMSuspendCallback),
                                                     strdup("pmsuspend"), myFreeFunc);
    callback13ret = virConnectDomainEventRegisterAny(dconn,
                                                     NULL,
                                                     VIR_DOMAIN_EVENT_ID_BALLOON_CHANGE,
                                                     VIR_DOMAIN_EVENT_CALLBACK(myDomainEventBalloonChangeCallback),
                                                     strdup("callback balloonchange"), myFreeFunc);
    callback14ret = virConnectDomainEventRegisterAny(dconn,
                                                     NULL,
                                                     VIR_DOMAIN_EVENT_ID_PMSUSPEND_DISK,
                                                     VIR_DOMAIN_EVENT_CALLBACK(myDomainEventPMSuspendDiskCallback),
                                                     strdup("pmsuspend-disk"), myFreeFunc);
    callback15ret = virConnectDomainEventRegisterAny(dconn,
                                                     NULL,
                                                     VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED,
                                                     VIR_DOMAIN_EVENT_CALLBACK(myDomainEventDeviceRemovedCallback),
                                                     strdup("device removed"), myFreeFunc);
    callback16ret = virConnectNetworkEventRegisterAny(dconn,
                                                      NULL,
                                                      VIR_NETWORK_EVENT_ID_LIFECYCLE,
                                                      VIR_NETWORK_EVENT_CALLBACK(myNetworkEventCallback),
                                                      strdup("net callback"), myFreeFunc);
    callback17ret = virConnectDomainEventRegisterAny(dconn,
                                                     NULL,
                                                     VIR_DOMAIN_EVENT_ID_TUNABLE,
                                                     VIR_DOMAIN_EVENT_CALLBACK(myDomainEventTunableCallback),
                                                     strdup("tunable"), myFreeFunc);
    callback18ret = virConnectDomainEventRegisterAny(dconn,
                                                     NULL,
                                                     VIR_DOMAIN_EVENT_ID_AGENT_LIFECYCLE,
                                                     VIR_DOMAIN_EVENT_CALLBACK(myDomainEventAgentLifecycleCallback),
                                                     strdup("guest agent lifecycle"), myFreeFunc);
    callback19ret = virConnectDomainEventRegisterAny(dconn,
                                                     NULL,
                                                     VIR_DOMAIN_EVENT_ID_DEVICE_ADDED,
                                                     VIR_DOMAIN_EVENT_CALLBACK(myDomainEventDeviceAddedCallback),
                                                     strdup("device added"), myFreeFunc);

    if ((callback1ret == -1) ||
        (callback2ret == -1) ||
        (callback3ret == -1) ||
        (callback4ret == -1) ||
        (callback5ret == -1) ||
        (callback6ret == -1) ||
        (callback7ret == -1) ||
        (callback9ret == -1) ||
        (callback10ret == -1) ||
        (callback11ret == -1) ||
        (callback12ret == -1) ||
        (callback13ret == -1) ||
        (callback14ret == -1) ||
        (callback15ret == -1) ||
        (callback16ret == -1) ||
        (callback17ret == -1) ||
        (callback18ret == -1) ||
        (callback19ret == -1))
        goto cleanup;

    if (virConnectSetKeepAlive(dconn, 5, 3) < 0) {
        virErrorPtr err = virGetLastError();
        fprintf(stderr, "Failed to start keepalive protocol: %s\n",
                err && err->message ? err->message : "Unknown error");
        run = 0;
    }

    while (run) {
        if (virEventRunDefaultImpl() < 0) {
            virErrorPtr err = virGetLastError();
            fprintf(stderr, "Failed to run event loop: %s\n",
                    err && err->message ? err->message : "Unknown error");
        }
    }

    printf("Deregistering event callbacks\n");
    virConnectDomainEventDeregister(dconn, myDomainEventCallback1);
    virConnectDomainEventDeregisterAny(dconn, callback2ret);
    virConnectDomainEventDeregisterAny(dconn, callback3ret);
    virConnectDomainEventDeregisterAny(dconn, callback4ret);
    virConnectDomainEventDeregisterAny(dconn, callback5ret);
    virConnectDomainEventDeregisterAny(dconn, callback6ret);
    virConnectDomainEventDeregisterAny(dconn, callback7ret);
    virConnectDomainEventDeregisterAny(dconn, callback9ret);
    virConnectDomainEventDeregisterAny(dconn, callback10ret);
    virConnectDomainEventDeregisterAny(dconn, callback11ret);
    virConnectDomainEventDeregisterAny(dconn, callback12ret);
    virConnectDomainEventDeregisterAny(dconn, callback13ret);
    virConnectDomainEventDeregisterAny(dconn, callback14ret);
    virConnectDomainEventDeregisterAny(dconn, callback15ret);
    virConnectNetworkEventDeregisterAny(dconn, callback16ret);
    virConnectDomainEventDeregisterAny(dconn, callback17ret);
    virConnectDomainEventDeregisterAny(dconn, callback18ret);
    virConnectDomainEventDeregisterAny(dconn, callback19ret);

    if (callback8ret != -1)
        virConnectDomainEventDeregisterAny(dconn, callback8ret);

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
