/*
 * event.c: event loop for monitoring file handles
 *
 * Copyright (C) 2007 Daniel P. Berrange
 * Copyright (C) 2007 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/time.h>
#include <errno.h>
#include <unistd.h>

#include "qemud.h"
#include "event.h"
#include "memory.h"
#include "util.h"

#define EVENT_DEBUG(fmt, ...) DEBUG(fmt, __VA_ARGS__)

static int virEventInterruptLocked(void);

/* State for a single file handle being monitored */
struct virEventHandle {
    int watch;
    int fd;
    int events;
    virEventHandleCallback cb;
    virFreeCallback ff;
    void *opaque;
    int deleted;
};

/* State for a single timer being generated */
struct virEventTimeout {
    int timer;
    int frequency;
    unsigned long long expiresAt;
    virEventTimeoutCallback cb;
    virFreeCallback ff;
    void *opaque;
    int deleted;
};

/* Allocate extra slots for virEventHandle/virEventTimeout
   records in this multiple */
#define EVENT_ALLOC_EXTENT 10

/* State for the main event loop */
struct virEventLoop {
    pthread_mutex_t lock;
    int running;
    pthread_t leader;
    int wakeupfd[2];
    int handlesCount;
    int handlesAlloc;
    struct virEventHandle *handles;
    int timeoutsCount;
    int timeoutsAlloc;
    struct virEventTimeout *timeouts;
};

/* Only have one event loop */
static struct virEventLoop eventLoop;

/* Unique ID for the next FD watch to be registered */
static int nextWatch = 0;

/* Unique ID for the next timer to be registered */
static int nextTimer = 0;

static void virEventLock(void)
{
    pthread_mutex_lock(&eventLoop.lock);
}

static void virEventUnlock(void)
{
    pthread_mutex_unlock(&eventLoop.lock);
}

/*
 * Register a callback for monitoring file handle events.
 * NB, it *must* be safe to call this from within a callback
 * For this reason we only ever append to existing list.
 */
int virEventAddHandleImpl(int fd, int events,
                          virEventHandleCallback cb,
                          void *opaque,
                          virFreeCallback ff) {
    int watch;
    EVENT_DEBUG("Add handle %d %d %p %p", fd, events, cb, opaque);
    virEventLock();
    if (eventLoop.handlesCount == eventLoop.handlesAlloc) {
        EVENT_DEBUG("Used %d handle slots, adding %d more",
                    eventLoop.handlesAlloc, EVENT_ALLOC_EXTENT);
        if (VIR_REALLOC_N(eventLoop.handles,
                          (eventLoop.handlesAlloc + EVENT_ALLOC_EXTENT)) < 0) {
            virEventUnlock();
            return -1;
        }
        eventLoop.handlesAlloc += EVENT_ALLOC_EXTENT;
    }

    watch = nextWatch++;

    eventLoop.handles[eventLoop.handlesCount].watch = watch;
    eventLoop.handles[eventLoop.handlesCount].fd = fd;
    eventLoop.handles[eventLoop.handlesCount].events =
                                         virEventHandleTypeToPollEvent(events);
    eventLoop.handles[eventLoop.handlesCount].cb = cb;
    eventLoop.handles[eventLoop.handlesCount].ff = ff;
    eventLoop.handles[eventLoop.handlesCount].opaque = opaque;
    eventLoop.handles[eventLoop.handlesCount].deleted = 0;

    eventLoop.handlesCount++;

    virEventInterruptLocked();
    virEventUnlock();

    return watch;
}

void virEventUpdateHandleImpl(int watch, int events) {
    int i;
    virEventLock();
    for (i = 0 ; i < eventLoop.handlesCount ; i++) {
        if (eventLoop.handles[i].watch == watch) {
            eventLoop.handles[i].events =
                    virEventHandleTypeToPollEvent(events);
            break;
        }
    }
    virEventInterruptLocked();
    virEventUnlock();
}

/*
 * Unregister a callback from a file handle
 * NB, it *must* be safe to call this from within a callback
 * For this reason we only ever set a flag in the existing list.
 * Actual deletion will be done out-of-band
 */
int virEventRemoveHandleImpl(int watch) {
    int i;
    EVENT_DEBUG("Remove handle %d", watch);
    virEventLock();
    for (i = 0 ; i < eventLoop.handlesCount ; i++) {
        if (eventLoop.handles[i].deleted)
            continue;

        if (eventLoop.handles[i].watch == watch) {
            EVENT_DEBUG("mark delete %d %d", i, eventLoop.handles[i].fd);
            eventLoop.handles[i].deleted = 1;
            virEventUnlock();
            return 0;
        }
    }
    virEventInterruptLocked();
    virEventUnlock();
    return -1;
}


/*
 * Register a callback for a timer event
 * NB, it *must* be safe to call this from within a callback
 * For this reason we only ever append to existing list.
 */
int virEventAddTimeoutImpl(int frequency,
                           virEventTimeoutCallback cb,
                           void *opaque,
                           virFreeCallback ff) {
    struct timeval now;
    int ret;
    EVENT_DEBUG("Adding timer %d with %d ms freq", nextTimer, frequency);
    if (gettimeofday(&now, NULL) < 0) {
        return -1;
    }

    virEventLock();
    if (eventLoop.timeoutsCount == eventLoop.timeoutsAlloc) {
        EVENT_DEBUG("Used %d timeout slots, adding %d more",
                    eventLoop.timeoutsAlloc, EVENT_ALLOC_EXTENT);
        if (VIR_REALLOC_N(eventLoop.timeouts,
                          (eventLoop.timeoutsAlloc + EVENT_ALLOC_EXTENT)) < 0) {
            virEventUnlock();
            return -1;
        }
        eventLoop.timeoutsAlloc += EVENT_ALLOC_EXTENT;
    }

    eventLoop.timeouts[eventLoop.timeoutsCount].timer = nextTimer++;
    eventLoop.timeouts[eventLoop.timeoutsCount].frequency = frequency;
    eventLoop.timeouts[eventLoop.timeoutsCount].cb = cb;
    eventLoop.timeouts[eventLoop.timeoutsCount].ff = ff;
    eventLoop.timeouts[eventLoop.timeoutsCount].opaque = opaque;
    eventLoop.timeouts[eventLoop.timeoutsCount].deleted = 0;
    eventLoop.timeouts[eventLoop.timeoutsCount].expiresAt =
        frequency >= 0 ? frequency +
        (((unsigned long long)now.tv_sec)*1000) +
        (((unsigned long long)now.tv_usec)/1000) : 0;

    eventLoop.timeoutsCount++;
    ret = nextTimer-1;
    virEventInterruptLocked();
    virEventUnlock();
    return ret;
}

void virEventUpdateTimeoutImpl(int timer, int frequency) {
    struct timeval tv;
    int i;
    EVENT_DEBUG("Updating timer %d timeout with %d ms freq", timer, frequency);
    if (gettimeofday(&tv, NULL) < 0) {
        return;
    }

    virEventLock();
    for (i = 0 ; i < eventLoop.timeoutsCount ; i++) {
        if (eventLoop.timeouts[i].timer == timer) {
            eventLoop.timeouts[i].frequency = frequency;
            eventLoop.timeouts[i].expiresAt =
                frequency >= 0 ? frequency +
                (((unsigned long long)tv.tv_sec)*1000) +
                (((unsigned long long)tv.tv_usec)/1000) : 0;
            break;
        }
    }
    virEventInterruptLocked();
    virEventUnlock();
}

/*
 * Unregister a callback for a timer
 * NB, it *must* be safe to call this from within a callback
 * For this reason we only ever set a flag in the existing list.
 * Actual deletion will be done out-of-band
 */
int virEventRemoveTimeoutImpl(int timer) {
    int i;
    EVENT_DEBUG("Remove timer %d", timer);
    virEventLock();
    for (i = 0 ; i < eventLoop.timeoutsCount ; i++) {
        if (eventLoop.timeouts[i].deleted)
            continue;

        if (eventLoop.timeouts[i].timer == timer) {
            eventLoop.timeouts[i].deleted = 1;
            virEventUnlock();
            return 0;
        }
    }
    virEventInterruptLocked();
    virEventUnlock();
    return -1;
}

/* Iterates over all registered timeouts and determine which
 * will be the first to expire.
 * @timeout: filled with expiry time of soonest timer, or -1 if
 *           no timeout is pending
 * returns: 0 on success, -1 on error
 */
static int virEventCalculateTimeout(int *timeout) {
    unsigned long long then = 0;
    int i;
    EVENT_DEBUG("Calculate expiry of %d timers", eventLoop.timeoutsCount);
    /* Figure out if we need a timeout */
    for (i = 0 ; i < eventLoop.timeoutsCount ; i++) {
        if (eventLoop.timeouts[i].deleted || eventLoop.timeouts[i].frequency < 0)
            continue;

        EVENT_DEBUG("Got a timeout scheduled for %llu", eventLoop.timeouts[i].expiresAt);
        if (then == 0 ||
            eventLoop.timeouts[i].expiresAt < then)
            then = eventLoop.timeouts[i].expiresAt;
    }

    /* Calculate how long we should wait for a timeout if needed */
    if (then > 0) {
        struct timeval tv;

        if (gettimeofday(&tv, NULL) < 0) {
            return -1;
        }

        *timeout = then -
            ((((unsigned long long)tv.tv_sec)*1000) +
             (((unsigned long long)tv.tv_usec)/1000));

        if (*timeout < 0)
            *timeout = 0;
    } else {
        *timeout = -1;
    }

    EVENT_DEBUG("Timeout at %llu due in %d ms", then, *timeout);

    return 0;
}

/*
 * Allocate a pollfd array containing data for all registered
 * file handles. The caller must free the returned data struct
 * returns: the pollfd array, or NULL on error
 */
static int virEventMakePollFDs(struct pollfd **retfds) {
    struct pollfd *fds;
    int i, nfds = 0;

    for (i = 0 ; i < eventLoop.handlesCount ; i++) {
        if (eventLoop.handles[i].deleted)
            continue;
        nfds++;
    }
    *retfds = NULL;
    /* Setup the poll file handle data structs */
    if (VIR_ALLOC_N(fds, nfds) < 0)
        return -1;

    for (i = 0, nfds = 0 ; i < eventLoop.handlesCount ; i++) {
        if (eventLoop.handles[i].deleted)
            continue;
        fds[nfds].fd = eventLoop.handles[i].fd;
        fds[nfds].events = eventLoop.handles[i].events;
        fds[nfds].revents = 0;
        //EVENT_DEBUG("Wait for %d %d", eventLoop.handles[i].fd, eventLoop.handles[i].events);
        nfds++;
    }

    *retfds = fds;
    return nfds;
}


/*
 * Iterate over all timers and determine if any have expired.
 * Invoke the user supplied callback for each timer whose
 * expiry time is met, and schedule the next timeout. Does
 * not try to 'catch up' on time if the actual expiry time
 * was later than the requested time.
 *
 * This method must cope with new timers being registered
 * by a callback, and must skip any timers marked as deleted.
 *
 * Returns 0 upon success, -1 if an error occurred
 */
static int virEventDispatchTimeouts(void) {
    struct timeval tv;
    unsigned long long now;
    int i;
    /* Save this now - it may be changed during dispatch */
    int ntimeouts = eventLoop.timeoutsCount;

    if (gettimeofday(&tv, NULL) < 0) {
        return -1;
    }
    now = (((unsigned long long)tv.tv_sec)*1000) +
        (((unsigned long long)tv.tv_usec)/1000);

    for (i = 0 ; i < ntimeouts ; i++) {
        if (eventLoop.timeouts[i].deleted || eventLoop.timeouts[i].frequency < 0)
            continue;

        if (eventLoop.timeouts[i].expiresAt <= now) {
            virEventTimeoutCallback cb = eventLoop.timeouts[i].cb;
            int timer = eventLoop.timeouts[i].timer;
            void *opaque = eventLoop.timeouts[i].opaque;
            eventLoop.timeouts[i].expiresAt =
                now + eventLoop.timeouts[i].frequency;

            virEventUnlock();
            (cb)(timer, opaque);
            virEventLock();
        }
    }
    return 0;
}


/* Iterate over all file handles and dispatch any which
 * have pending events listed in the poll() data. Invoke
 * the user supplied callback for each handle which has
 * pending events
 *
 * This method must cope with new handles being registered
 * by a callback, and must skip any handles marked as deleted.
 *
 * Returns 0 upon success, -1 if an error occurred
 */
static int virEventDispatchHandles(int nfds, struct pollfd *fds) {
    int i, n;

    for (i = 0, n = 0 ; i < eventLoop.handlesCount && n < nfds ; i++) {
        if (eventLoop.handles[i].deleted) {
            EVENT_DEBUG("Skip deleted %d", eventLoop.handles[i].fd);
            continue;
        }

        if (fds[n].revents) {
            virEventHandleCallback cb = eventLoop.handles[i].cb;
            void *opaque = eventLoop.handles[i].opaque;
            int hEvents = virPollEventToEventHandleType(fds[n].revents);
            EVENT_DEBUG("Dispatch %d %d %p", fds[n].fd,
                        fds[n].revents, eventLoop.handles[i].opaque);
            virEventUnlock();
            (cb)(eventLoop.handles[i].watch,
                 fds[n].fd, hEvents, opaque);
            virEventLock();
        }
        n++;
    }

    return 0;
}


/* Used post dispatch to actually remove any timers that
 * were previously marked as deleted. This asynchronous
 * cleanup is needed to make dispatch re-entrant safe.
 */
static int virEventCleanupTimeouts(void) {
    int i;

    /* Remove deleted entries, shuffling down remaining
     * entries as needed to form contiguous series
     */
    for (i = 0 ; i < eventLoop.timeoutsCount ; ) {
        if (!eventLoop.timeouts[i].deleted) {
            i++;
            continue;
        }

        EVENT_DEBUG("Purging timeout %d with id %d", i, eventLoop.timeouts[i].timer);
        if (eventLoop.timeouts[i].ff)
            (eventLoop.timeouts[i].ff)(eventLoop.timeouts[i].opaque);

        if ((i+1) < eventLoop.timeoutsCount) {
            memmove(eventLoop.timeouts+i,
                    eventLoop.timeouts+i+1,
                    sizeof(struct virEventTimeout)*(eventLoop.timeoutsCount-(i+1)));
        }
        eventLoop.timeoutsCount--;
    }

    /* Release some memory if we've got a big chunk free */
    if ((eventLoop.timeoutsAlloc - EVENT_ALLOC_EXTENT) > eventLoop.timeoutsCount) {
        EVENT_DEBUG("Releasing %d out of %d timeout slots used, releasing %d",
                   eventLoop.timeoutsCount, eventLoop.timeoutsAlloc, EVENT_ALLOC_EXTENT);
        if (VIR_REALLOC_N(eventLoop.timeouts,
                          (eventLoop.timeoutsAlloc - EVENT_ALLOC_EXTENT)) < 0)
            return -1;
        eventLoop.timeoutsAlloc -= EVENT_ALLOC_EXTENT;
    }
    return 0;
}

/* Used post dispatch to actually remove any handles that
 * were previously marked as deleted. This asynchronous
 * cleanup is needed to make dispatch re-entrant safe.
 */
static int virEventCleanupHandles(void) {
    int i;

    /* Remove deleted entries, shuffling down remaining
     * entries as needed to form contiguous series
     */
    for (i = 0 ; i < eventLoop.handlesCount ; ) {
        if (!eventLoop.handles[i].deleted) {
            i++;
            continue;
        }

        if (eventLoop.handles[i].ff)
            (eventLoop.handles[i].ff)(eventLoop.handles[i].opaque);

        if ((i+1) < eventLoop.handlesCount) {
            memmove(eventLoop.handles+i,
                    eventLoop.handles+i+1,
                    sizeof(struct virEventHandle)*(eventLoop.handlesCount-(i+1)));
        }
        eventLoop.handlesCount--;
    }

    /* Release some memory if we've got a big chunk free */
    if ((eventLoop.handlesAlloc - EVENT_ALLOC_EXTENT) > eventLoop.handlesCount) {
        EVENT_DEBUG("Releasing %d out of %d handles slots used, releasing %d",
                   eventLoop.handlesCount, eventLoop.handlesAlloc, EVENT_ALLOC_EXTENT);
        if (VIR_REALLOC_N(eventLoop.handles,
                          (eventLoop.handlesAlloc - EVENT_ALLOC_EXTENT)) < 0)
            return -1;
        eventLoop.handlesAlloc -= EVENT_ALLOC_EXTENT;
    }
    return 0;
}

/*
 * Run a single iteration of the event loop, blocking until
 * at least one file handle has an event, or a timer expires
 */
int virEventRunOnce(void) {
    struct pollfd *fds;
    int ret, timeout, nfds;

    virEventLock();
    eventLoop.running = 1;
    eventLoop.leader = pthread_self();
    if ((nfds = virEventMakePollFDs(&fds)) < 0) {
        virEventUnlock();
        return -1;
    }

    if (virEventCalculateTimeout(&timeout) < 0) {
        VIR_FREE(fds);
        virEventUnlock();
        return -1;
    }

    virEventUnlock();

 retry:
    EVENT_DEBUG("Poll on %d handles %p timeout %d", nfds, fds, timeout);
    ret = poll(fds, nfds, timeout);
    EVENT_DEBUG("Poll got %d event", ret);
    if (ret < 0) {
        if (errno == EINTR) {
            goto retry;
        }
        VIR_FREE(fds);
        return -1;
    }

    virEventLock();
    if (virEventDispatchTimeouts() < 0) {
        VIR_FREE(fds);
        virEventUnlock();
        return -1;
    }

    if (ret > 0 &&
        virEventDispatchHandles(nfds, fds) < 0) {
        VIR_FREE(fds);
        virEventUnlock();
        return -1;
    }
    VIR_FREE(fds);

    if (virEventCleanupTimeouts() < 0) {
        virEventUnlock();
        return -1;
    }

    if (virEventCleanupHandles() < 0) {
        virEventUnlock();
        return -1;
    }

    eventLoop.running = 0;
    virEventUnlock();
    return 0;
}

static void virEventHandleWakeup(int watch ATTRIBUTE_UNUSED,
                                 int fd,
                                 int events ATTRIBUTE_UNUSED,
                                 void *opaque ATTRIBUTE_UNUSED)
{
    char c;
    virEventLock();
    saferead(fd, &c, sizeof(c));
    virEventUnlock();
}

int virEventInit(void)
{
    if (pthread_mutex_init(&eventLoop.lock, NULL) != 0)
        return -1;

    if (pipe(eventLoop.wakeupfd) < 0 ||
        qemudSetNonBlock(eventLoop.wakeupfd[0]) < 0 ||
        qemudSetNonBlock(eventLoop.wakeupfd[1]) < 0 ||
        qemudSetCloseExec(eventLoop.wakeupfd[0]) < 0 ||
        qemudSetCloseExec(eventLoop.wakeupfd[1]) < 0)
        return -1;

    if (virEventAddHandleImpl(eventLoop.wakeupfd[0],
                              VIR_EVENT_HANDLE_READABLE,
                              virEventHandleWakeup, NULL, NULL) < 0)
        return -1;

    return 0;
}

static int virEventInterruptLocked(void)
{
    char c = '\0';

    if (!eventLoop.running ||
        pthread_self() == eventLoop.leader)
        return 0;

    if (safewrite(eventLoop.wakeupfd[1], &c, sizeof(c)) != sizeof(c))
        return -1;
    return 0;
}

int virEventInterrupt(void)
{
    int ret;
    virEventLock();
    ret = virEventInterruptLocked();
    virEventUnlock();
    return ret;
}

int
virEventHandleTypeToPollEvent(int events)
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

int
virPollEventToEventHandleType(int events)
{
    int ret = 0;
    if(events & POLLIN)
        ret |= VIR_EVENT_HANDLE_READABLE;
    if(events & POLLOUT)
        ret |= VIR_EVENT_HANDLE_WRITABLE;
    if(events & POLLERR)
        ret |= VIR_EVENT_HANDLE_ERROR;
    if(events & POLLNVAL) /* Treat NVAL as error, since libvirt doesn't distinguish */
        ret |= VIR_EVENT_HANDLE_ERROR;
    if(events & POLLHUP)
        ret |= VIR_EVENT_HANDLE_HANGUP;
    return ret;
}
