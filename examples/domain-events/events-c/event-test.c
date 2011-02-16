#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#if HAVE_SYS_POLL_H
# include <sys/types.h>
# include <sys/poll.h>
# include <libvirt/libvirt.h>

# define VIR_DEBUG0(fmt) printf("%s:%d :: " fmt "\n", \
        __func__, __LINE__)
# define VIR_DEBUG(fmt, ...) printf("%s:%d: " fmt "\n", \
        __func__, __LINE__, __VA_ARGS__)
# define STREQ(a,b) (strcmp(a,b) == 0)

# ifndef ATTRIBUTE_UNUSED
#  define ATTRIBUTE_UNUSED __attribute__((__unused__))
# endif

/* handle globals */
int h_fd = 0;
virEventHandleType h_event = 0;
virEventHandleCallback h_cb = NULL;
virFreeCallback h_ff = NULL;
void *h_opaque = NULL;

/* timeout globals */
# define TIMEOUT_MS 1000
int t_active = 0;
int t_timeout = -1;
virEventTimeoutCallback t_cb = NULL;
virFreeCallback t_ff = NULL;
void *t_opaque = NULL;


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
    printf("%s EVENT: Domain %s(%d) rtc change %lld\n", __func__, virDomainGetName(dom),
           virDomainGetID(dom), offset);

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


/* EventImpl Functions */
int myEventHandleTypeToPollEvent(virEventHandleType events)
{
    int ret = 0;
    if(events & VIR_EVENT_HANDLE_READABLE)
        ret |= POLLIN;
    if(events & VIR_EVENT_HANDLE_WRITABLE)
        ret |= POLLOUT;
    if(events & VIR_EVENT_HANDLE_ERROR)
        ret |= POLLERR;
    if(events & VIR_EVENT_HANDLE_HANGUP)
        ret |= POLLHUP;
    return ret;
}

virEventHandleType myPollEventToEventHandleType(int events)
{
    virEventHandleType ret = 0;
    if(events & POLLIN)
        ret |= VIR_EVENT_HANDLE_READABLE;
    if(events & POLLOUT)
        ret |= VIR_EVENT_HANDLE_WRITABLE;
    if(events & POLLERR)
        ret |= VIR_EVENT_HANDLE_ERROR;
    if(events & POLLHUP)
        ret |= VIR_EVENT_HANDLE_HANGUP;
    return ret;
}

int  myEventAddHandleFunc(int fd, int event,
                          virEventHandleCallback cb,
                          void *opaque,
                          virFreeCallback ff)
{
    VIR_DEBUG("Add handle %d %d %p %p", fd, event, cb, opaque);
    h_fd = fd;
    h_event = myEventHandleTypeToPollEvent(event);
    h_cb = cb;
    h_ff = ff;
    h_opaque = opaque;
    return 0;
}

void myEventUpdateHandleFunc(int fd, int event)
{
    VIR_DEBUG("Updated Handle %d %d", fd, event);
    h_event = myEventHandleTypeToPollEvent(event);
    return;
}

int  myEventRemoveHandleFunc(int fd)
{
    VIR_DEBUG("Removed Handle %d", fd);
    h_fd = 0;
    if (h_ff)
       (h_ff)(h_opaque);
    return 0;
}

int myEventAddTimeoutFunc(int timeout,
                          virEventTimeoutCallback cb,
                          void *opaque,
                          virFreeCallback ff)
{
    VIR_DEBUG("Adding Timeout %d %p %p", timeout, cb, opaque);
    t_active = 1;
    t_timeout = timeout;
    t_cb = cb;
    t_ff = ff;
    t_opaque = opaque;
    return 0;
}

void myEventUpdateTimeoutFunc(int timer ATTRIBUTE_UNUSED, int timeout)
{
    /*VIR_DEBUG("Timeout updated %d %d", timer, timeout);*/
    t_timeout = timeout;
}

int myEventRemoveTimeoutFunc(int timer)
{
   VIR_DEBUG("Timeout removed %d", timer);
   t_active = 0;
   if (t_ff)
       (t_ff)(t_opaque);
   return 0;
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
    int sts;
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

    if(argc > 1 && STREQ(argv[1],"--help")) {
        usage(argv[0]);
        return -1;
    }

    virEventRegisterImpl( myEventAddHandleFunc,
                          myEventUpdateHandleFunc,
                          myEventRemoveHandleFunc,
                          myEventAddTimeoutFunc,
                          myEventUpdateTimeoutFunc,
                          myEventRemoveTimeoutFunc);

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
        while(run) {
            struct pollfd pfd = { .fd = h_fd,
                              .events = h_event,
                              .revents = 0};

            sts = poll(&pfd, 1, TIMEOUT_MS);

            /* if t_timeout < 0 then t_cb must not be called */
            if (t_cb && t_active && t_timeout >= 0) {
                t_cb(t_timeout,t_opaque);
            }

            if (sts == 0) {
                /* VIR_DEBUG0("Poll timeout"); */
                continue;
            }
            if (sts < 0 ) {
                VIR_DEBUG0("Poll failed");
                continue;
            }
            if ( pfd.revents & POLLHUP ) {
                VIR_DEBUG0("Reset by peer");
                return -1;
            }

            if(h_cb) {
                h_cb(0,
                     h_fd,
                     myPollEventToEventHandleType(pfd.revents & h_event),
                     h_opaque);
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
    if( dconn && virConnectClose(dconn)<0 ) {
        printf("error closing\n");
    }

    printf("done\n");
    return 0;
}

#else
int main(void) {
    printf("event-test program not available without sys/poll.h support\n");
    return 1;
}
#endif
