#include <config.h>

#include <stdio.h>
#include <string.h>

#if HAVE_SYS_POLL_H
#include <sys/types.h>
#include <sys/poll.h>
#include <libvirt/libvirt.h>

#define DEBUG0(fmt) printf("%s:%d :: " fmt "\n", \
        __FUNCTION__, __LINE__)
#define DEBUG(fmt, ...) printf("%s:%d: " fmt "\n", \
        __FUNCTION__, __LINE__, __VA_ARGS__)
#define STREQ(a,b) (strcmp((a),(b)) == 0)

#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED __attribute__((__unused__))
#endif

/* handle globals */
int h_fd = 0;
virEventHandleType h_event = 0;
virEventHandleCallback h_cb = NULL;
void *h_opaque = NULL;

/* timeout globals */
#define TIMEOUT_MS 1000
int t_active = 0;
int t_timeout = -1;
virEventTimeoutCallback t_cb = NULL;
void *t_opaque = NULL;


/* Prototypes */
const char *eventToString(int event);
int myDomainEventCallback1 (virConnectPtr conn, virDomainPtr dom,
                            int event, void *opaque);
int myDomainEventCallback2 (virConnectPtr conn, virDomainPtr dom,
                            int event, void *opaque);
int myEventAddHandleFunc  (int fd, int event,
                           virEventHandleCallback cb, void *opaque);
void myEventUpdateHandleFunc(int fd, int event);
int  myEventRemoveHandleFunc(int fd);

int myEventAddTimeoutFunc(int timeout, virEventTimeoutCallback cb,
                          void *opaque);
void myEventUpdateTimeoutFunc(int timer, int timout);
int myEventRemoveTimeoutFunc(int timer);

int myEventHandleTypeToPollEvent(virEventHandleType events);
virEventHandleType myPollEventToEventHandleType(int events);

void usage(const char *pname);

/* Callback functions */

const char *eventToString(int event) {
    const char *ret = NULL;
    switch(event) {
        case VIR_DOMAIN_EVENT_ADDED:
            ret ="Added";
            break;
        case VIR_DOMAIN_EVENT_REMOVED:
            ret ="Removed";
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
        case VIR_DOMAIN_EVENT_SAVED:
            ret ="Saved";
            break;
        case VIR_DOMAIN_EVENT_RESTORED:
            ret ="Restored";
            break;
        default:
            ret ="Unknown Event";
    }
    return ret;
}

int myDomainEventCallback1 (virConnectPtr conn ATTRIBUTE_UNUSED,
                            virDomainPtr dom,
                            int event,
                            void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) %s\n", __FUNCTION__, virDomainGetName(dom),
           virDomainGetID(dom), eventToString(event));
    return 0;
}

int myDomainEventCallback2 (virConnectPtr conn ATTRIBUTE_UNUSED,
                            virDomainPtr dom,
                            int event,
                            void *opaque ATTRIBUTE_UNUSED)
{
    printf("%s EVENT: Domain %s(%d) %s\n", __FUNCTION__, virDomainGetName(dom),
           virDomainGetID(dom), eventToString(event));
    return 0;
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
                          virEventHandleCallback cb, void *opaque)
{
    DEBUG("Add handle %d %d %p %p", fd, event, cb, opaque);
    h_fd = fd;
    h_event = myEventHandleTypeToPollEvent(event);
    h_cb = cb;
    h_opaque = opaque;
    return 0;
}

void myEventUpdateHandleFunc(int fd, int event)
{
    DEBUG("Updated Handle %d %d", fd, event);
    h_event = myEventHandleTypeToPollEvent(event);
    return;
}

int  myEventRemoveHandleFunc(int fd)
{
    DEBUG("Removed Handle %d", fd);
    h_fd = 0;
    return 0;
}

int myEventAddTimeoutFunc(int timeout, virEventTimeoutCallback cb,
                          void *opaque)
{
    DEBUG("Adding Timeout %d %p %p", timeout, cb, opaque);
    t_active = 1;
    t_timeout = timeout;
    t_cb = cb;
    t_opaque = opaque;
    return 0;
}

void myEventUpdateTimeoutFunc(int timer ATTRIBUTE_UNUSED, int timeout)
{
    /*DEBUG("Timeout updated %d %d", timer, timeout);*/
    t_timeout = timeout;
}

int myEventRemoveTimeoutFunc(int timer)
{
   DEBUG("Timeout removed %d", timer);
   t_active = 0;
   return 0;
}

/* main test functions */

void usage(const char *pname)
{
    printf("%s uri\n", pname);
}

int main(int argc, char **argv)
{
    int run=1;
    int sts;

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
    dconn = virConnectOpen (argv[1] ? argv[1] : "qemu:///system");
    if (!dconn) {
        printf("error opening\n");
        return -1;
    }

    DEBUG0("Registering domain event cbs");

    /* Add 2 callbacks to prove this works with more than just one */
    virConnectDomainEventRegister(dconn, myDomainEventCallback1, NULL);
    virConnectDomainEventRegister(dconn, myDomainEventCallback2, NULL);

    while(run) {
        struct pollfd pfd = { .fd = h_fd,
                          .events = h_event,
                          .revents = 0};

        sts = poll(&pfd, 1, TIMEOUT_MS);

        /* We are assuming timeout of 0 here - so execute every time */
        if(t_cb && t_active)
            t_cb(t_timeout,t_opaque);

        if (sts == 0) {
            /* DEBUG0("Poll timeout"); */
            continue;
        }
        if (sts < 0 ) {
            DEBUG0("Poll failed");
            continue;
        }
        if ( pfd.revents & POLLHUP ) {
            DEBUG0("Reset by peer");
            return -1;
        }

        if(h_cb) {
            h_cb(h_fd,
                 myPollEventToEventHandleType(pfd.revents & h_event),
                 h_opaque);
        }

    }

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
