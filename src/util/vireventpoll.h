/*
 * vireventpoll.h: Poll based event loop for monitoring file handles
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_EVENT_POLL_H__
# define __VIR_EVENT_POLL_H__

# include "internal.h"

/**
 * virEventPollAddHandle: register a callback for monitoring file handle events
 *
 * @fd: file handle to monitor for events
 * @events: bitset of events to watch from POLLnnn constants
 * @cb: callback to invoke when an event occurs
 * @opaque: user data to pass to callback
 *
 * returns -1 if the file handle cannot be registered, 0 upon success
 */
int virEventPollAddHandle(int fd, int events,
                          virEventHandleCallback cb,
                          void *opaque,
                          virFreeCallback ff);

/**
 * virEventPollUpdateHandle: change event set for a monitored file handle
 *
 * @watch: watch whose handle to update
 * @events: bitset of events to watch from POLLnnn constants
 *
 * Will not fail if fd exists
 */
void virEventPollUpdateHandle(int watch, int events);

/**
 * virEventPollRemoveHandle: unregister a callback from a file handle
 *
 * @watch: watch whose handle to remove
 *
 * returns -1 if the file handle was not registered, 0 upon success
 */
int virEventPollRemoveHandle(int watch);

/**
 * virEventPollAddTimeout: register a callback for a timer event
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
int virEventPollAddTimeout(int frequency,
                           virEventTimeoutCallback cb,
                           void *opaque,
                           virFreeCallback ff);

/**
 * virEventPollUpdateTimeout: change frequency for a timer
 *
 * @timer: timer id to change
 * @frequency: time between events in milliseconds
 *
 * Setting frequency to -1 will disable the timer. Setting the frequency
 * to zero will cause it to fire on every event loop iteration.
 *
 * Will not fail if timer exists
 */
void virEventPollUpdateTimeout(int timer, int frequency);

/**
 * virEventPollRemoveTimeout: unregister a callback for a timer
 *
 * @timer: the timer id to remove
 *
 * returns -1 if the timer was not registered, 0 upon success
 */
int virEventPollRemoveTimeout(int timer);

/**
 * virEventPollInit: Initialize the event loop
 *
 * returns -1 if initialization failed
 */
int virEventPollInit(void);

/**
 * virEventPollRunOnce: run a single iteration of the event loop.
 *
 * Blocks the caller until at least one file handle has an
 * event or the first timer expires.
 *
 * returns -1 if the event monitoring failed
 */
int virEventPollRunOnce(void);

int virEventPollFromNativeEvents(int events);
int virEventPollToNativeEvents(int events);


/**
 * virEventPollInterrupt: wakeup any thread waiting in poll()
 *
 * return -1 if wakeup failed
 */
int virEventPollInterrupt(void);


#endif /* __VIRTD_EVENT_H__ */
