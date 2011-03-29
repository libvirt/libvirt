#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>

#define VIR_DEBUG0(fmt) printf("%s:%d :: " fmt "\n", \
        __func__, __LINE__)
#define VIR_DEBUG(fmt, ...) printf("%s:%d: " fmt "\n", \
        __func__, __LINE__, __VA_ARGS__)
#define STREQ(a,b) (strcmp(a,b) == 0)

#ifndef ATTRIBUTE_UNUSED
# define ATTRIBUTE_UNUSED __attribute__((__unused__))
#endif

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

const char *eventToString(int event) {
    const char *ret = "";
    switch(event) {
        case VIR_DOMAIN_EVENT_DEFINED:
            ret ="Defined";
            break;
        case VIR_DOMAIN_EVENT_UNDEFINED:
            ret ="Undefined";
            break;
        case VIR_DOMAIN_EVENT_STARTED:
            ret ="Started";
            break;
        case VIR_DOMAIN_EVENT_SUSPENDED:
            ret ="Suspended";
            break;
        case VIR_DOMAIN_EVENT_RESUMED:
            ret ="Resumed";
            break;
        case VIR_DOMAIN_EVENT_STOPPED:
            ret ="Stopped";
            break;
    }
    return ret;
}

static const char *eventDetailToString(int event, int detail) {
    const char *ret = "";
    switch(event) {
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
            switch (detail) {
            case VIR_DOMAIN_EVENT_STARTED_BOOTED:
                ret = "Booted";
                break;
            case VIR_DOMAIN_EVENT_STARTED_MIGRATED:
                ret = "Migrated";
                break;
            case VIR_DOMAIN_EVENT_STARTED_RESTORED:
                ret = "Restored";
                break;
            }
            break;
        case VIR_DOMAIN_EVENT_SUSPENDED:
            if (detail == VIR_DOMAIN_EVENT_SUSPENDED_PAUSED)
                ret = "Paused";
            else if (detail == VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED)
                ret = "Migrated";
            break;
        case VIR_DOMAIN_EVENT_RESUMED:
            if (detail == VIR_DOMAIN_EVENT_RESUMED_UNPAUSED)
                ret = "Unpaused";
            else if (detail == VIR_DOMAIN_EVENT_RESUMED_MIGRATED)
                ret = "Migrated";
            break;
        case VIR_DOMAIN_EVENT_STOPPED:
            switch (detail) {
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
                ret = "Failed";
                break;
            case VIR_DOMAIN_EVENT_STOPPED_FAILED:
                ret = "Failed";
                break;
            }
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
    char *str = NULL;
    /* HACK: use asprintf since we have gnulib's wrapper for %lld on Win32
     * but don't have a printf() replacement with %lld */
    if (asprintf(&str, "%s EVENT: Domain %s(%d) rtc change %lld\n",
                 __func__, virDomainGetName(dom),
                 virDomainGetID(dom), offset) < 0)
        return 0;

    printf("%s", str);
    free(str);

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
    int i;
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
    for (i = 0 ; i < subject->nidentity ; i++) {
        printf(" identity: %s=%s",
               subject->identities[i].type,
               subject->identities[i].name);
    }
    printf("\n");

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

int run = 1;

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
    struct sigaction action_stop;

    memset(&action_stop, 0, sizeof action_stop);

    action_stop.sa_handler = stop;

    if (argc > 1 && STREQ(argv[1], "--help")) {
        usage(argv[0]);
        return -1;
    }

    virEventRegisterDefaultImpl();

    virConnectPtr dconn = NULL;
    dconn = virConnectOpenReadOnly (argv[1] ? argv[1] : NULL);
    if (!dconn) {
        printf("error opening\n");
        return -1;
    }

    sigaction(SIGTERM, &action_stop, NULL);
    sigaction(SIGINT, &action_stop, NULL);

    VIR_DEBUG0("Registering domain event cbs");

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

    if ((callback1ret != -1) &&
        (callback2ret != -1) &&
        (callback3ret != -1) &&
        (callback4ret != -1) &&
        (callback5ret != -1) &&
        (callback6ret != -1) &&
        (callback7ret != -1)) {
        while (run) {
            if (virEventRunDefaultImpl() < 0) {
                virErrorPtr err = virGetLastError();
                fprintf(stderr, "Failed to run event loop: %s\n",
                        err && err->message ? err->message : "Unknown error");
            }
        }

        VIR_DEBUG0("Deregistering event handlers");
        virConnectDomainEventDeregister(dconn, myDomainEventCallback1);
        virConnectDomainEventDeregisterAny(dconn, callback2ret);
        virConnectDomainEventDeregisterAny(dconn, callback3ret);
        virConnectDomainEventDeregisterAny(dconn, callback4ret);
        virConnectDomainEventDeregisterAny(dconn, callback5ret);
        virConnectDomainEventDeregisterAny(dconn, callback6ret);
        virConnectDomainEventDeregisterAny(dconn, callback7ret);
    }

    VIR_DEBUG0("Closing connection");
    if (dconn && virConnectClose(dconn) < 0) {
        printf("error closing\n");
    }

    printf("done\n");
    return 0;
}
