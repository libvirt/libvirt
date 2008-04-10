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

#ifndef __VIR_EVENT_H__
#define __VIR_EVENT_H__


/**
 * virEventHandleCallback: callback for receiving file handle events
 *
 * @fd: file handle on which the event occurred
 * @events: bitset of events from POLLnnn constants
 * @opaque: user data registered with handle
 */
typedef void (*virEventHandleCallback)(int fd, int events, void *opaque);

/**
 * virEventAddHandle: register a callback for monitoring file handle events
 *
 * @fd: file handle to monitor for events
 * @events: bitset of events to watch from POLLnnn constants
 * @cb: callback to invoke when an event occurs
 * @opaque: user data to pass to callback
 *
 * returns -1 if the file handle cannot be registered, 0 upon success
 */
int virEventAddHandle(int fd, int events, virEventHandleCallback cb, void *opaque);

/**
 * virEventUpdateHandle: change event set for a monitored file handle
 *
 * @fd: file handle to monitor for events
 * @events: bitset of events to watch from POLLnnn constants
 *
 * Will not fail if fd exists
 */
void virEventUpdateHandle(int fd, int events);

/**
 * virEventRemoveHandle: unregister a callback from a file handle
 *
 * @fd: file handle to stop monitoring for events
 *
 * returns -1 if the file handle was not registered, 0 upon success
 */
int virEventRemoveHandle(int fd);

/**
 * virEventTimeoutCallback: callback for receiving timer events
 *
 * @timer: timer id emitting the event
 * @opaque: user data registered with handle
 */
typedef void (*virEventTimeoutCallback)(int timer, void *opaque);

/**
 * virEventAddTimeout: register a callback for a timer event
 *
 * @frequency: time between events in milliseconds
 * @cb: callback to invoke when an event occurs
 * @opaque: user data to pass to callback
 *
 * Setting frequency to -1 will disable the timer. Setting the frequency
 * to zero will cause it to fire on every event loop iteration.
 *
 * returns -1 if the file handle cannot be registered, a positive
 * integer timer id upon success
 */
int virEventAddTimeout(int frequency, virEventTimeoutCallback cb, void *opaque);

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
void virEventUpdateTimeout(int timer, int frequency);

/**
 * virEventRemoveTimeout: unregister a callback for a timer
 *
 * @timer: the timer id to remove
 *
 * returns -1 if the timer was not registered, 0 upon success
 */
int virEventRemoveTimeout(int timer);

typedef int (*virEventAddHandleFunc)(int, int, virEventHandleCallback, void *);
typedef void (*virEventUpdateHandleFunc)(int, int);
typedef int (*virEventRemoveHandleFunc)(int);

typedef int (*virEventAddTimeoutFunc)(int, virEventTimeoutCallback, void *);
typedef void (*virEventUpdateTimeoutFunc)(int, int);
typedef int (*virEventRemoveTimeoutFunc)(int);

void __virEventRegisterImpl(virEventAddHandleFunc addHandle,
                            virEventUpdateHandleFunc updateHandle,
                            virEventRemoveHandleFunc removeHandle,
                            virEventAddTimeoutFunc addTimeout,
                            virEventUpdateTimeoutFunc updateTimeout,
                            virEventRemoveTimeoutFunc removeTimeout);

#define virEventRegisterImpl(ah,rh,at,rt) __virEventRegisterImpl(ah,rh,at,rt)

#endif /* __VIR_EVENT_H__ */
