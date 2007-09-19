/*
 * event.h: event loop for monitoring file handles
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


#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/time.h>
#include <errno.h>

#include "internal.h"
#include "event.h"

#define EVENT_DEBUG(fmt, ...) qemudDebug("EVENT: " fmt, __VA_ARGS__)

/* State for a single file handle being monitored */
struct virEventHandle {
    int fd;
    int events;
    virEventHandleCallback cb;
    void *opaque;
    int deleted;
};

/* State for a single timer being generated */
struct virEventTimeout {
    int timer;
    int frequency;
    unsigned long long expiresAt;
    virEventTimeoutCallback cb;
    void *opaque;
    int deleted;
};

/* Allocate extra slots for virEventHandle/virEventTimeout
   records in this multiple */
#define EVENT_ALLOC_EXTENT 10

/* State for the main event loop */
struct virEventLoop {
    int handlesCount;
    int handlesAlloc;
    struct virEventHandle *handles;
    int timeoutsCount;
    int timeoutsAlloc;
    struct virEventTimeout *timeouts;
};

/* Only have one event loop */
static struct virEventLoop eventLoop;

/* Unique ID for the next timer to be registered */
static int nextTimer = 0;


/*
 * Register a callback for monitoring file handle events.
 * NB, it *must* be safe to call this from within a callback
 * For this reason we only ever append to existing list.
 */
int virEventAddHandleImpl(int fd, int events, virEventHandleCallback cb, void *opaque) {
    EVENT_DEBUG("Add handle %d %d %p %p", fd, events, cb, opaque);
    if (eventLoop.handlesCount == eventLoop.handlesAlloc) {
        struct virEventHandle *tmp;
        EVENT_DEBUG("Used %d handle slots, adding %d more",
                    eventLoop.handlesAlloc, EVENT_ALLOC_EXTENT);
        tmp = realloc(eventLoop.handles,
                      sizeof(struct virEventHandle) *
                      (eventLoop.handlesAlloc + EVENT_ALLOC_EXTENT));
        if (!tmp) {
            return -1;
        }
        eventLoop.handles = tmp;
        eventLoop.handlesAlloc += EVENT_ALLOC_EXTENT;
    }

    eventLoop.handles[eventLoop.handlesCount].fd = fd;
    eventLoop.handles[eventLoop.handlesCount].events = events;
    eventLoop.handles[eventLoop.handlesCount].cb = cb;
    eventLoop.handles[eventLoop.handlesCount].opaque = opaque;
    eventLoop.handles[eventLoop.handlesCount].deleted = 0;

    eventLoop.handlesCount++;

    return 0;
}

void virEventUpdateHandleImpl(int fd, int events) {
    int i;
    for (i = 0 ; i < eventLoop.handlesCount ; i++) {
        if (eventLoop.handles[i].fd == fd) {
            eventLoop.handles[i].events = events;
            break;
        }
    }
}

/*
 * Unregister a callback from a file handle
 * NB, it *must* be safe to call this from within a callback
 * For this reason we only ever set a flag in the existing list.
 * Actual deletion will be done out-of-band
 */
int virEventRemoveHandleImpl(int fd) {
    int i;
    EVENT_DEBUG("Remove handle %d", fd);
    for (i = 0 ; i < eventLoop.handlesCount ; i++) {
        if (eventLoop.handles[i].deleted)
            continue;

        if (eventLoop.handles[i].fd == fd) {
            EVENT_DEBUG("mark delete %d", i);
            eventLoop.handles[i].deleted = 1;
            return 0;
        }
    }
    return -1;
}


/*
 * Register a callback for a timer event
 * NB, it *must* be safe to call this from within a callback
 * For this reason we only ever append to existing list.
 */
int virEventAddTimeoutImpl(int frequency, virEventTimeoutCallback cb, void *opaque) {
    struct timeval now;
    EVENT_DEBUG("Adding timer %d with %d ms freq", nextTimer, frequency);
    if (gettimeofday(&now, NULL) < 0) {
        return -1;
    }

    if (eventLoop.timeoutsCount == eventLoop.timeoutsAlloc) {
        struct virEventTimeout *tmp;
        EVENT_DEBUG("Used %d timeout slots, adding %d more",
                    eventLoop.timeoutsAlloc, EVENT_ALLOC_EXTENT);
        tmp = realloc(eventLoop.timeouts,
                      sizeof(struct virEventTimeout) *
                      (eventLoop.timeoutsAlloc + EVENT_ALLOC_EXTENT));
        if (!tmp) {
            return -1;
        }
        eventLoop.timeouts = tmp;
        eventLoop.timeoutsAlloc += EVENT_ALLOC_EXTENT;
    }

    eventLoop.timeouts[eventLoop.timeoutsCount].timer = nextTimer++;
    eventLoop.timeouts[eventLoop.timeoutsCount].frequency = frequency;
    eventLoop.timeouts[eventLoop.timeoutsCount].cb = cb;
    eventLoop.timeouts[eventLoop.timeoutsCount].opaque = opaque;
    eventLoop.timeouts[eventLoop.timeoutsCount].deleted = 0;
    eventLoop.timeouts[eventLoop.timeoutsCount].expiresAt =
        frequency >= 0 ? frequency +
        (((unsigned long long)now.tv_sec)*1000) +
        (((unsigned long long)now.tv_usec)/1000) : 0;

    eventLoop.timeoutsCount++;

    return nextTimer-1;
}

void virEventUpdateTimeoutImpl(int timer, int frequency) {
    struct timeval tv;
    int i;
    EVENT_DEBUG("Updating timer %d timeout with %d ms freq", timer, frequency);
    if (gettimeofday(&tv, NULL) < 0) {
        return;
    }

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
    for (i = 0 ; i < eventLoop.timeoutsCount ; i++) {
        if (eventLoop.timeouts[i].deleted)
            continue;

        if (eventLoop.timeouts[i].timer == timer) {
            eventLoop.timeouts[i].deleted = 1;
            return 0;
        }
    }
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
    if (!(fds = malloc(sizeof(struct pollfd) * nfds)))
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
            (eventLoop.timeouts[i].cb)(eventLoop.timeouts[i].timer,
                                       eventLoop.timeouts[i].opaque);
            eventLoop.timeouts[i].expiresAt =
                now + eventLoop.timeouts[i].frequency;
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
static int virEventDispatchHandles(struct pollfd *fds) {
    int i;
    /* Save this now - it may be changed during dispatch */
    int nhandles = eventLoop.handlesCount;

    for (i = 0 ; i < nhandles ; i++) {
        if (eventLoop.handles[i].deleted) {
            EVENT_DEBUG("Skip deleted %d", eventLoop.handles[i].fd);
            continue;
        }

        if (fds[i].revents) {
            EVENT_DEBUG("Dispatch %d %d %p", fds[i].fd, fds[i].revents, eventLoop.handles[i].opaque);
            (eventLoop.handles[i].cb)(fds[i].fd, fds[i].revents,
                                      eventLoop.handles[i].opaque);
        }
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
     * entries as needed to form contigous series
     */
    for (i = 0 ; i < eventLoop.timeoutsCount ; ) {
        if (!eventLoop.timeouts[i].deleted) {
            i++;
            continue;
        }

        EVENT_DEBUG("Purging timeout %d with id %d", i, eventLoop.timeouts[i].timer);
        if ((i+1) < eventLoop.timeoutsCount) {
            memmove(eventLoop.timeouts+i,
                    eventLoop.timeouts+i+1,
                    sizeof(struct virEventTimeout)*(eventLoop.timeoutsCount-(i+1)));
        }
        eventLoop.timeoutsCount--;
    }

    /* Release some memory if we've got a big chunk free */
    if ((eventLoop.timeoutsAlloc - EVENT_ALLOC_EXTENT) > eventLoop.timeoutsCount) {
        struct virEventTimeout *tmp;
        EVENT_DEBUG("Releasing %d out of %d timeout slots used, releasing %d",
                   eventLoop.timeoutsCount, eventLoop.timeoutsAlloc, EVENT_ALLOC_EXTENT);
        tmp = realloc(eventLoop.timeouts,
                      sizeof(struct virEventTimeout) *
                      (eventLoop.timeoutsAlloc - EVENT_ALLOC_EXTENT));
        if (!tmp) {
            return -1;
        }
        eventLoop.timeouts = tmp;
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
     * entries as needed to form contigous series
     */
    for (i = 0 ; i < eventLoop.handlesCount ; ) {
        if (!eventLoop.handles[i].deleted) {
            i++;
            continue;
        }

        if ((i+1) < eventLoop.handlesCount) {
            memmove(eventLoop.handles+i,
                    eventLoop.handles+i+1,
                    sizeof(struct virEventHandle)*(eventLoop.handlesCount-(i+1)));
        }
        eventLoop.handlesCount--;
    }

    /* Release some memory if we've got a big chunk free */
    if ((eventLoop.handlesAlloc - EVENT_ALLOC_EXTENT) > eventLoop.handlesCount) {
        struct virEventHandle *tmp;
        EVENT_DEBUG("Releasing %d out of %d handles slots used, releasing %d",
                   eventLoop.handlesCount, eventLoop.handlesAlloc, EVENT_ALLOC_EXTENT);
        tmp = realloc(eventLoop.handles,
                      sizeof(struct virEventHandle) *
                      (eventLoop.handlesAlloc - EVENT_ALLOC_EXTENT));
        if (!tmp) {
            return -1;
        }
        eventLoop.handles = tmp;
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

    if ((nfds = virEventMakePollFDs(&fds)) < 0)
        return -1;

    if (virEventCalculateTimeout(&timeout) < 0) {
        free(fds);
        return -1;
    }

 retry:
    EVENT_DEBUG("Poll on %d handles %p timeout %d", nfds, fds, timeout);
    ret = poll(fds, nfds, timeout);
    EVENT_DEBUG("Poll got %d event", ret);
    if (ret < 0) {
        if (errno == EINTR) {
            goto retry;
        }
        free(fds);
        return -1;
    }
    if (virEventDispatchTimeouts() < 0) {
        free(fds);
        return -1;
    }

    if (ret > 0 &&
        virEventDispatchHandles(fds) < 0) {
        free(fds);
        return -1;
    }
    free(fds);

    if (virEventCleanupTimeouts() < 0)
        return -1;

    if (virEventCleanupHandles() < 0)
        return -1;

    return 0;
}
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
