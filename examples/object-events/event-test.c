#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

#define VIR_DEBUG(fmt) printf("%s:%d: " fmt "\n", __func__, __LINE__)
#define STREQ(a,b) (strcmp(a,b) == 0)

#ifndef ATTRIBUTE_UNUSED
# define ATTRIBUTE_UNUSED __attribute__((__unused__))
#endif

int run = 1;

/* Prototypes */
const char *eventToString(int event);
int myEventAddHandleFunc  (int fd, int event,
                           virEventHandleCallback cb,
                           void *opaque,
                           virFreeCallback ff);
void myEventUpdateHandleFunc(int watch, int event);
int  myEventRemoveHandleFunc(int watch);

int myEventAddTimeoutFunc(int timeout,
                          virEventTimeoutCallback cb,
                          void *opaque,
                          virFreeCallback ff);
void myEventUpdateTimeoutFunc(int timer, int timout);
int myEventRemoveTimeoutFunc(int timer);

int myEventHandleTypeToPollEvent(virEventHandleType events);
virEventHandleType myPollEventToEventHandleType(int events);

void usage(const char *pname);

/* Callback functions */


static void connectClose(virConnectPtr conn ATTRIBUTE_UNUSED,
                         int reason,
                         void *opaque ATTRIBUTE_UNUSED)
{
    switch (reason) {
    case VIR_CONNECT_CLOSE_REASON_ERROR:
        fprintf(stderr, "Connection closed due to I/O error\n");
        break;
    case VIR_CONNECT_CLOSE_REASON_EOF:
        fprintf(stderr, "Connection closed due to end of file\n");
        break;
    case VIR_CONNECT_CLOSE_REASON_KEEPALIVE:
        fprintf(stderr, "Connection closed due to keepalive timeout\n");
        break;
    case VIR_CONNECT_CLOSE_REASON_CLIENT:
        fprintf(stderr, "Connection closed due to client request\n");
        break;
    default:
        fprintf(stderr, "Connection closed due to unknown reason\n");
        break;
    };
    run = 0;
}

const char *eventToString(int event) {
    const char *ret = "";
    switch ((virDomainEventType) event) {
        case VIR_DOMAIN_EVENT_DEFINED:
            ret = "Defined";
            break;
        case VIR_DOMAIN_EVENT_UNDEFINED:
            ret = "Undefined";
            break;
        case VIR_DOMAIN_EVENT_STARTED:
            ret = "Started";
            break;
        case VIR_DOMAIN_EVENT_SUSPENDED:
            ret = "Suspended";
            break;
        case VIR_DOMAIN_EVENT_RESUMED:
            ret = "Resumed";
            break;
        case VIR_DOMAIN_EVENT_STOPPED:
            ret = "Stopped";
            break;
        case VIR_DOMAIN_EVENT_SHUTDOWN:
            ret = "Shutdown";
            break;
        case VIR_DOMAIN_EVENT_PMSUSPENDED:
            ret = "PMSuspended";
            break;
        case VIR_DOMAIN_EVENT_CRASHED:
            ret = "Crashed";
            break;
    }
    return ret;
}

static const char *eventDetailToString(int event, int detail) {
    const char *ret = "";
    switch ((virDomainEventType) event) {
        case VIR_DOMAIN_EVENT_DEFINED:
            if (detail == VIR_DOMAIN_EVENT_DEFINED_ADDED)
                ret = "Added";
            else if (detail == VIR_DOMAIN_EVENT_DEFINED_UPDATED)
                ret = "Updated";
            break;
        case VIR_DOMAIN_EVENT_UNDEFINED:
            if (detail == VIR_DOMAIN_EVENT_UNDEFINED_REMOVED)
                ret = "Removed";
            break;
        case VIR_DOMAIN_EVENT_STARTED:
            switch ((virDomainEventStartedDetailType) detail) {
            case VIR_DOMAIN_EVENT_STARTED_BOOTED:
                ret = "Booted";
                break;
            case VIR_DOMAIN_EVENT_STARTED_MIGRATED:
                ret = "Migrated";
                break;
            case VIR_DOMAIN_EVENT_STARTED_RESTORED:
                ret = "Restored";
                break;
            case VIR_DOMAIN_EVENT_STARTED_FROM_SNAPSHOT:
                ret = "Snapshot";
                break;
            case VIR_DOMAIN_EVENT_STARTED_WAKEUP:
                ret = "Event wakeup";
                break;
            }
            break;
        case VIR_DOMAIN_EVENT_SUSPENDED:
            switch ((virDomainEventSuspendedDetailType) detail) {
            case VIR_DOMAIN_EVENT_SUSPENDED_PAUSED:
                ret = "Paused";
                break;
            case VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED:
                ret = "Migrated";
                break;
            case VIR_DOMAIN_EVENT_SUSPENDED_IOERROR:
                ret = "I/O Error";
                break;
            case VIR_DOMAIN_EVENT_SUSPENDED_WATCHDOG:
                ret = "Watchdog";
                break;
            case VIR_DOMAIN_EVENT_SUSPENDED_RESTORED:
                ret = "Restored";
                break;
            case VIR_DOMAIN_EVENT_SUSPENDED_FROM_SNAPSHOT:
                ret = "Snapshot";
                break;
            case VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR:
                ret = "API error";
                break;
            }
            break;
        case VIR_DOMAIN_EVENT_RESUMED:
            switch ((virDomainEventResumedDetailType) detail) {
            case VIR_DOMAIN_EVENT_RESUMED_UNPAUSED:
                ret = "Unpaused";
                break;
            case VIR_DOMAIN_EVENT_RESUMED_MIGRATED:
                ret = "Migrated";
                break;
            case VIR_DOMAIN_EVENT_RESUMED_FROM_SNAPSHOT:
                ret = "Snapshot";
                break;
            }
            break;
        case VIR_DOMAIN_EVENT_STOPPED:
            switch ((virDomainEventStoppedDetailType) detail) {
            case VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN:
                ret = "Shutdown";
                break;
            case VIR_DOMAIN_EVENT_STOPPED_DESTROYED:
                ret = "Destroyed";
                break;
            case VIR_DOMAIN_EVENT_STOPPED_CRASHED:
                ret = "Crashed";
                break;
            case VIR_DOMAIN_EVENT_STOPPED_MIGRATED:
                ret = "Migrated";
                break;
            case VIR_DOMAIN_EVENT_STOPPED_SAVED:
                ret = "Saved";
                break;
            case VIR_DOMAIN_EVENT_STOPPED_FAILED:
                ret = "Failed";
                break;
            case VIR_DOMAIN_EVENT_STOPPED_FROM_SNAPSHOT:
                ret = "Snapshot";
                break;
            }
            break;
        case VIR_DOMAIN_EVENT_SHUTDOWN:
            switch ((virDomainEventShutdownDetailType) detail) {
            case VIR_DOMAIN_EVENT_SHUTDOWN_FINISHED:
                ret = "Finished";
                break;
            }
            break;
        case VIR_DOMAIN_EVENT_PMSUSPENDED:
            switch ((virDomainEventPMSuspendedDetailType) detail) {
            case VIR_DOMAIN_EVENT_PMSUSPENDED_MEMORY:
                ret = "Memory";
                break;
            case VIR_DOMAIN_EVENT_PMSUSPENDED_DISK:
                ret = "Disk";
                break;
            }
            break;
        case VIR_DOMAIN_EVENT_CRASHED:
           switch ((virDomainEventCrashedDetailType) detail) {
           case VIR_DOMAIN_EVENT_CRASHED_PANICKED:
               ret = "Panicked";
               break;
           }
           break;
    }
    return ret;
}

static const char *
networkEventToString(int event)
{
    const char *ret = "";
    switch ((virNetworkEventLifecycleType) event) {
        case VIR_NETWORK_EVENT_DEFINED:
            ret = "Defined";
            break;
        case VIR_NETWORK_EVENT_UNDEFINED:
            ret = "Undefined";
            break;
        case VIR_NETWORK_EVENT_STARTED:
            ret = "Started";
            break;
        case VIR_NETWORK_EVENT_STOPPED:
            ret = "Stopped";
            break;
    }
    return ret;
}

static int myDomainEventCallback1(virConnectPtr conn ATTRIBUTE_UNUSED,
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

static int myDomainEventCallback2(virConnectPtr conn ATTRIBUTE_UNUSED,
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

static int myDomainEventRebootCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                       virDomainPtr dom,
                                       void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) rebooted\n", __func__, virDomainGetName(dom),
           virDomainGetID(dom));

    return 0;
}

static int myDomainEventRTCChangeCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                          virDomainPtr dom,
                                          long long offset,
                                          void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) rtc change %" PRIdMAX "\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom),
           (intmax_t)offset);

    return 0;
}

static int myDomainEventBalloonChangeCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                              virDomainPtr dom,
                                              unsigned long long actual,
                                              void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) balloon change %" PRIuMAX "KB\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom), (uintmax_t)actual);

    return 0;
}

static int myDomainEventWatchdogCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                         virDomainPtr dom,
                                         int action,
                                         void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) watchdog action=%d\n", __func__, virDomainGetName(dom),
           virDomainGetID(dom), action);

    return 0;
}

static int myDomainEventIOErrorCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                        virDomainPtr dom,
                                        const char *srcPath,
                                        const char *devAlias,
                                        int action,
                                        void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) io error path=%s alias=%s action=%d\n", __func__, virDomainGetName(dom),
           virDomainGetID(dom), srcPath, devAlias, action);

    return 0;
}

static int myDomainEventGraphicsCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
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

    switch (phase) {
    case VIR_DOMAIN_EVENT_GRAPHICS_CONNECT:
        printf("connected ");
        break;
    case VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE:
        printf("initialized ");
        break;
    case VIR_DOMAIN_EVENT_GRAPHICS_DISCONNECT:
        printf("disconnected ");
        break;
    }

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

static int myDomainEventControlErrorCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                             virDomainPtr dom,
                                             void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) control error\n", __func__, virDomainGetName(dom),
           virDomainGetID(dom));

    return 0;
}


const char *diskChangeReasonStrings[] = {
    "startupPolicy", /* 0 */
    /* add new reason here */
};
static int myDomainEventDiskChangeCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                           virDomainPtr dom,
                                           const char *oldSrcPath,
                                           const char *newSrcPath,
                                           const char *devAlias,
                                           int reason,
                                           void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) disk change oldSrcPath: %s newSrcPath: %s devAlias: %s reason: %s\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom),
           oldSrcPath, newSrcPath, devAlias, diskChangeReasonStrings[reason]);
    return 0;
}

const char *trayChangeReasonStrings[] = {
    "open",
    "close",
};

static int myDomainEventTrayChangeCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                           virDomainPtr dom,
                                           const char *devAlias,
                                           int reason,
                                           void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) removable disk's tray change devAlias: %s reason: %s\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom),
           devAlias, trayChangeReasonStrings[reason]);
    return 0;
}

static int myDomainEventPMWakeupCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                         virDomainPtr dom,
                                         int reason ATTRIBUTE_UNUSED,
                                         void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) system pmwakeup\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom));
    return 0;
}

static int myDomainEventPMSuspendCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                          virDomainPtr dom,
                                          int reason ATTRIBUTE_UNUSED,
                                          void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) system pmsuspend\n",
           __func__, virDomainGetName(dom), virDomainGetID(dom));
    return 0;
}

static int myDomainEventPMSuspendDiskCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
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

static int myNetworkEventCallback(virConnectPtr conn ATTRIBUTE_UNUSED,
                                  virNetworkPtr dom,
                                  int event,
                                  int detail,
                                  void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Network %s %s %d\n", __func__, virNetworkGetName(dom),
           networkEventToString(event), detail);
    return 0;
}


static void myFreeFunc(void *opaque)
{
    char *str = opaque;
    printf("%s: Freeing [%s]\n", __func__, str);
    free(str);
}


/* main test functions */

void usage(const char *pname)
{
    printf("%s uri\n", pname);
}


static void stop(int sig)
{
    printf("Exiting on signal %d\n", sig);
    run = 0;
}


int main(int argc, char **argv)
{
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
    struct sigaction action_stop;

    memset(&action_stop, 0, sizeof(action_stop));

    action_stop.sa_handler = stop;

    if (argc > 1 && STREQ(argv[1], "--help")) {
        usage(argv[0]);
        return -1;
    }

    if (virInitialize() < 0) {
        fprintf(stderr, "Failed to initialize libvirt");
        return -1;
    }

    if (virEventRegisterDefaultImpl() < 0) {
        virErrorPtr err = virGetLastError();
        fprintf(stderr, "Failed to register event implementation: %s\n",
                err && err->message ? err->message: "Unknown error");
        return -1;
    }

    virConnectPtr dconn = NULL;
    dconn = virConnectOpenAuth(argc > 1 ? argv[1] : NULL,
                               virConnectAuthPtrDefault,
                               VIR_CONNECT_RO);
    if (!dconn) {
        printf("error opening\n");
        return -1;
    }

    virConnectRegisterCloseCallback(dconn,
                                    connectClose, NULL, NULL);

    sigaction(SIGTERM, &action_stop, NULL);
    sigaction(SIGINT, &action_stop, NULL);

    VIR_DEBUG("Registering event cbs");

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

    if ((callback1ret != -1) &&
        (callback2ret != -1) &&
        (callback3ret != -1) &&
        (callback4ret != -1) &&
        (callback5ret != -1) &&
        (callback6ret != -1) &&
        (callback7ret != -1) &&
        (callback9ret != -1) &&
        (callback10ret != -1) &&
        (callback11ret != -1) &&
        (callback12ret != -1) &&
        (callback13ret != -1) &&
        (callback14ret != -1) &&
        (callback15ret != -1) &&
        (callback16ret != -1)) {
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

        VIR_DEBUG("Deregistering event handlers");
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
        if (callback8ret != -1)
            virConnectDomainEventDeregisterAny(dconn, callback8ret);
    }

    virConnectUnregisterCloseCallback(dconn, connectClose);

    VIR_DEBUG("Closing connection");
    if (dconn && virConnectClose(dconn) < 0) {
        printf("error closing\n");
    }

    printf("done\n");
    return 0;
}
