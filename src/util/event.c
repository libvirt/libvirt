/*
 * event.c: event loop for monitoring file handles
 *
 * Copyright (C) 2007, 2011 Red Hat, Inc.
 * Copyright (C) 2007 Daniel P. Berrange
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

#include "event.h"
#include "event_poll.h"
#include "logging.h"
#include "virterror_internal.h"

#include <stdlib.h>

static virEventAddHandleFunc addHandleImpl = NULL;
static virEventUpdateHandleFunc updateHandleImpl = NULL;
static virEventRemoveHandleFunc removeHandleImpl = NULL;
static virEventAddTimeoutFunc addTimeoutImpl = NULL;
static virEventUpdateTimeoutFunc updateTimeoutImpl = NULL;
static virEventRemoveTimeoutFunc removeTimeoutImpl = NULL;

/**
 * virEventAddHandle: register a callback for monitoring file handle events
 *
 * @fd: file handle to monitor for events
 * @events: bitset of events to watch from virEventHandleType constants
 * @cb: callback to invoke when an event occurs
 * @opaque: user data to pass to callback
 *
 * returns -1 if the file handle cannot be registered, 0 upon success
 */
int virEventAddHandle(int fd,
                      int events,
                      virEventHandleCallback cb,
                      void *opaque,
                      virFreeCallback ff) {
    if (!addHandleImpl)
        return -1;

    return addHandleImpl(fd, events, cb, opaque, ff);
}

/**
 * virEventUpdateHandle: change event set for a monitored file handle
 *
 * @watch: watch whose file handle to update
 * @events: bitset of events to watch from virEventHandleType constants
 *
 * Will not fail if fd exists
 */
void virEventUpdateHandle(int watch, int events) {
    updateHandleImpl(watch, events);
}

/**
 * virEventRemoveHandle: unregister a callback from a file handle
 *
 * @watch: watch whose file handle to remove
 *
 * returns -1 if the file handle was not registered, 0 upon success
 */
int virEventRemoveHandle(int watch) {
    if (!removeHandleImpl)
        return -1;

    return removeHandleImpl(watch);
}

/**
 * virEventAddTimeout: register a callback for a timer event
 *
 * @timeout: time between events in milliseconds
 * @cb: callback to invoke when an event occurs
 * @opaque: user data to pass to callback
 *
 * Setting timeout to -1 will disable the timer. Setting the timeout
 * to zero will cause it to fire on every event loop iteration.
 *
 * returns -1 if the timer cannot be registered, a positive
 * integer timer id upon success
 */
int virEventAddTimeout(int timeout,
                       virEventTimeoutCallback cb,
                       void *opaque,
                       virFreeCallback ff) {
    if (!addTimeoutImpl)
        return -1;

    return addTimeoutImpl(timeout, cb, opaque, ff);
}

/**
 * virEventUpdateTimeoutImpl: change frequency for a timer
 *
 * @timer: timer id to change
 * @frequency: time between events in milliseconds
 *
 * Setting frequency to -1 will disable the timer. Setting the frequency
 * to zero will cause it to fire on every event loop iteration.
 *
 * Will not fail if timer exists
 */
void virEventUpdateTimeout(int timer, int timeout) {
    updateTimeoutImpl(timer, timeout);
}

/**
 * virEventRemoveTimeout: unregister a callback for a timer
 *
 * @timer: the timer id to remove
 *
 * returns -1 if the timer was not registered, 0 upon success
 */
int virEventRemoveTimeout(int timer) {
    if (!removeTimeoutImpl)
        return -1;

    return removeTimeoutImpl(timer);
}


/*****************************************************
 *
 * Below this point are 3  *PUBLIC*  APIs for event
 * loop integration with applications using libvirt.
 * These API contracts cannot be changed.
 *
 *****************************************************/

/**
 * virEventRegisterImpl:
 * @addHandle: the callback to add fd handles
 * @updateHandle: the callback to update fd handles
 * @removeHandle: the callback to remove fd handles
 * @addTimeout: the callback to add a timeout
 * @updateTimeout: the callback to update a timeout
 * @removeTimeout: the callback to remove a timeout
 *
 * Registers an event implementation, to allow integration
 * with an external event loop. Applications would use this
 * to integrate with the libglib2 event loop, or libevent
 * or the QT event loop.
 *
 * If an application does not need to integrate with an
 * existing event loop implementation, then the
 * virEventRegisterDefaultImpl method can be used to setup
 * the generic libvirt implementation.
 */
void virEventRegisterImpl(virEventAddHandleFunc addHandle,
                          virEventUpdateHandleFunc updateHandle,
                          virEventRemoveHandleFunc removeHandle,
                          virEventAddTimeoutFunc addTimeout,
                          virEventUpdateTimeoutFunc updateTimeout,
                          virEventRemoveTimeoutFunc removeTimeout)
{
    VIR_DEBUG("addHandle=%p updateHandle=%p removeHandle=%p "
              "addTimeout=%p updateTimeout=%p removeTimeout=%p",
              addHandle, updateHandle, removeHandle,
              addTimeout, updateTimeout, removeTimeout);

    addHandleImpl = addHandle;
    updateHandleImpl = updateHandle;
    removeHandleImpl = removeHandle;
    addTimeoutImpl = addTimeout;
    updateTimeoutImpl = updateTimeout;
    removeTimeoutImpl = removeTimeout;
}

/**
 * virEventRegisterDefaultImpl:
 *
 * Registers a default event implementation based on the
 * poll() system call. This is a generic implementation
 * that can be used by any client application which does
 * not have a need to integrate with an external event
 * loop impl.
 *
 * Once registered, the application has to invoke virEventRunDefaultImpl in
 * a loop to process events.  Failure to do so may result in connections being
 * closed unexpectedly as a result of keepalive timeout.
 *
 * Returns 0 on success, -1 on failure.
 */
int virEventRegisterDefaultImpl(void)
{
    VIR_DEBUG("registering default event implementation");

    virResetLastError();

    if (virEventPollInit() < 0) {
        virDispatchError(NULL);
        return -1;
    }

    virEventRegisterImpl(
        virEventPollAddHandle,
        virEventPollUpdateHandle,
        virEventPollRemoveHandle,
        virEventPollAddTimeout,
        virEventPollUpdateTimeout,
        virEventPollRemoveTimeout
        );

    return 0;
}


/**
 * virEventRunDefaultImpl:
 *
 * Run one iteration of the event loop. Applications
 * will generally want to have a thread which invokes
 * this method in an infinite loop
 *
 *  static bool quit = false;
 *
 *  while (!quit) {
 *    if (virEventRunDefaultImpl() < 0)
 *       ...print error...
 *  }
 *
 * Returns 0 on success, -1 on failure.
 */
int virEventRunDefaultImpl(void)
{
    VIR_DEBUG("running default event implementation");
    virResetLastError();

    if (virEventPollRunOnce() < 0) {
        virDispatchError(NULL);
        return -1;
    }

    return 0;
}
