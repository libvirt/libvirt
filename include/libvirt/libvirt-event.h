/*
 * libvirt-event.h
 * Summary: APIs for management of events
 * Description: Provides APIs for the management of events
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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

#ifndef LIBVIRT_EVENT_H
# define LIBVIRT_EVENT_H

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif


/**
 * virEventHandleType:
 *
 * a virEventHandleType is used similar to POLLxxx FD events, but is specific
 * to libvirt. A client app must translate to, and from POLL events when using
 * this construct.
 *
 * Since: 0.5.0
 */
typedef enum {
    VIR_EVENT_HANDLE_READABLE  = (1 << 0), /* (Since: 0.5.0) */
    VIR_EVENT_HANDLE_WRITABLE  = (1 << 1), /* (Since: 0.5.0) */
    VIR_EVENT_HANDLE_ERROR     = (1 << 2), /* (Since: 0.5.0) */
    VIR_EVENT_HANDLE_HANGUP    = (1 << 3), /* (Since: 0.5.0) */
} virEventHandleType;

/**
 * virEventHandleCallback:
 *
 * @watch: watch on which the event occurred
 * @fd: file handle on which the event occurred
 * @events: bitset of events from virEventHandleType constants
 * @opaque: user data registered with handle
 *
 * Callback for receiving file handle events. The callback will
 * be invoked once for each event which is pending.
 *
 * Since: 0.5.0
 */
typedef void (*virEventHandleCallback)(int watch, int fd, int events, void *opaque);

/**
 * virEventAddHandleFunc:
 * @fd: file descriptor to listen on
 * @event: bitset of events on which to fire the callback
 * @cb: the callback to be called when an event occurs
 * @opaque: user data to pass to the callback
 * @ff: the callback invoked to free opaque data blob
 *
 * Part of the EventImpl, this callback adds a file handle callback to
 * listen for specific events. The same file handle can be registered
 * multiple times provided the requested event sets are non-overlapping
 *
 * @fd will always be a C runtime file descriptor. On Windows
 * the _get_osfhandle() method can be used if a HANDLE is required
 * instead.
 *
 * If the opaque user data requires free'ing when the handle
 * is unregistered, then a 2nd callback can be supplied for
 * this purpose. This callback needs to be invoked from a clean stack.
 * If 'ff' callbacks are invoked directly from the virEventRemoveHandleFunc
 * they will likely deadlock in libvirt.
 *
 * Returns -1 if the file handle cannot be registered, otherwise a handle
 * watch number to be used for updating and unregistering for events
 *
 * Since: 0.5.0
 */
typedef int (*virEventAddHandleFunc)(int fd, int event,
                                     virEventHandleCallback cb,
                                     void *opaque,
                                     virFreeCallback ff);

/**
 * virEventUpdateHandleFunc:
 * @watch: file descriptor watch to modify
 * @event: new events to listen on
 *
 * Part of the EventImpl, this user-provided callback is notified when
 * events to listen on change
 *
 * Since: 0.5.0
 */
typedef void (*virEventUpdateHandleFunc)(int watch, int event);

/**
 * virEventRemoveHandleFunc:
 * @watch: file descriptor watch to stop listening on
 *
 * Part of the EventImpl, this user-provided callback is notified when
 * an fd is no longer being listened on.
 *
 * If a virEventHandleFreeFunc was supplied when the handle was
 * registered, it will be invoked some time during, or after this
 * function call, when it is safe to release the user data.
 *
 * Returns -1 if the file handle was not registered, 0 upon success
 *
 * Since: 0.5.0
 */
typedef int (*virEventRemoveHandleFunc)(int watch);

/**
 * virEventTimeoutCallback:
 *
 * @timer: timer id emitting the event
 * @opaque: user data registered with handle
 *
 * callback for receiving timer events
 *
 * Since: 0.5.0
 */
typedef void (*virEventTimeoutCallback)(int timer, void *opaque);

/**
 * virEventAddTimeoutFunc:
 * @timeout: The timeout to monitor
 * @cb: the callback to call when timeout has expired
 * @opaque: user data to pass to the callback
 * @ff: the callback invoked to free opaque data blob
 *
 * Part of the EventImpl, this user-defined callback handles adding an
 * event timeout.
 *
 * If the opaque user data requires free'ing when the handle
 * is unregistered, then a 2nd callback can be supplied for
 * this purpose.
 *
 * Returns a timer value
 *
 * Since: 0.5.0
 */
typedef int (*virEventAddTimeoutFunc)(int timeout,
                                      virEventTimeoutCallback cb,
                                      void *opaque,
                                      virFreeCallback ff);

/**
 * virEventUpdateTimeoutFunc:
 * @timer: the timer to modify
 * @timeout: the new timeout value
 *
 * Part of the EventImpl, this user-defined callback updates an
 * event timeout.
 *
 * Since: 0.5.0
 */
typedef void (*virEventUpdateTimeoutFunc)(int timer, int timeout);

/**
 * virEventRemoveTimeoutFunc:
 * @timer: the timer to remove
 *
 * Part of the EventImpl, this user-defined callback removes a timer
 *
 * If a virEventTimeoutFreeFunc was supplied when the handle was
 * registered, it will be invoked some time during, or after this
 * function call, when it is safe to release the user data.
 *
 * Returns 0 on success, -1 on failure
 *
 * Since: 0.5.0
 */
typedef int (*virEventRemoveTimeoutFunc)(int timer);

void virEventRegisterImpl(virEventAddHandleFunc addHandle,
                          virEventUpdateHandleFunc updateHandle,
                          virEventRemoveHandleFunc removeHandle,
                          virEventAddTimeoutFunc addTimeout,
                          virEventUpdateTimeoutFunc updateTimeout,
                          virEventRemoveTimeoutFunc removeTimeout);

int virEventRegisterDefaultImpl(void);
int virEventRunDefaultImpl(void);

int virEventAddHandle(int fd, int events,
                      virEventHandleCallback cb,
                      void *opaque,
                      virFreeCallback ff);
void virEventUpdateHandle(int watch, int events);
int virEventRemoveHandle(int watch);

int virEventAddTimeout(int frequency,
                       virEventTimeoutCallback cb,
                       void *opaque,
                       virFreeCallback ff);
void virEventUpdateTimeout(int timer, int frequency);
int virEventRemoveTimeout(int timer);


#endif /* LIBVIRT_EVENT_H */
