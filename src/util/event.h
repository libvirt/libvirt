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
# define __VIR_EVENT_H__
# include "internal.h"
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
int virEventAddHandle(int fd, int events,
                      virEventHandleCallback cb,
                      void *opaque,
                      virFreeCallback ff);

/**
 * virEventUpdateHandle: change event set for a monitored file handle
 *
 * @watch: watch whose file handle to update
 * @events: bitset of events to watch from virEventHandleType constants
 *
 * Will not fail if fd exists
 */
void virEventUpdateHandle(int watch, int events);

/**
 * virEventRemoveHandle: unregister a callback from a file handle
 *
 * @watch: watch whose file handle to remove
 *
 * returns -1 if the file handle was not registered, 0 upon success
 */
int virEventRemoveHandle(int watch);

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
int virEventAddTimeout(int frequency,
                       virEventTimeoutCallback cb,
                       void *opaque,
                       virFreeCallback ff);

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

#endif /* __VIR_EVENT_H__ */
