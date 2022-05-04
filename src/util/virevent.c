/*
 * virevent.c: event loop for monitoring file handles
 *
 * Copyright (C) 2007, 2011-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "virevent.h"
#include "vireventglib.h"
#include "virlog.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_EVENT

VIR_LOG_INIT("util.event");

static virEventAddHandleFunc addHandleImpl;
static virEventUpdateHandleFunc updateHandleImpl;
static virEventRemoveHandleFunc removeHandleImpl;
static virEventAddTimeoutFunc addTimeoutImpl;
static virEventUpdateTimeoutFunc updateTimeoutImpl;
static virEventRemoveTimeoutFunc removeTimeoutImpl;


/*****************************************************
 *
 * Below this point are  *PUBLIC*  APIs for event
 * loop integration with applications using libvirt.
 * These API contracts cannot be changed.
 *
 *****************************************************/


/**
 * virEventAddHandle:
 *
 * @fd: file handle to monitor for events
 * @events: bitset of events to watch from virEventHandleType constants
 * @cb: callback to invoke when an event occurs
 * @opaque: user data to pass to callback
 * @ff: callback to free opaque when handle is removed
 *
 * Register a callback for monitoring file handle events.  This function
 * requires that an event loop has previously been registered with
 * virEventRegisterImpl() or virEventRegisterDefaultImpl().
 *
 * @fd must always always be a C runtime file descriptor. On Windows
 * if the caller only has a HANDLE, the _open_osfhandle() method can
 * be used to open an associated C runtime file descriptor for use
 * with this API. After opening a runtime file descriptor, CloseHandle()
 * must not be used, instead close() will close the runtime file
 * descriptor and its original associated HANDLE.
 *
 * Returns -1 if the file handle cannot be registered, otherwise a handle
 * watch number to be used for updating and unregistering for events.
 *
 * Since: 0.9.3
 */
int
virEventAddHandle(int fd,
                  int events,
                  virEventHandleCallback cb,
                  void *opaque,
                  virFreeCallback ff)
{
    if (!addHandleImpl)
        return -1;

    return addHandleImpl(fd, events, cb, opaque, ff);
}

/**
 * virEventUpdateHandle:
 *
 * @watch: watch whose file handle to update
 * @events: bitset of events to watch from virEventHandleType constants
 *
 * Change event set for a monitored file handle.  This function
 * requires that an event loop has previously been registered with
 * virEventRegisterImpl() or virEventRegisterDefaultImpl().
 *
 * Will not fail if fd exists.
 *
 * Since: 0.9.3
 */
void
virEventUpdateHandle(int watch, int events)
{
    if (updateHandleImpl)
        updateHandleImpl(watch, events);
}

/**
 * virEventRemoveHandle:
 *
 * @watch: watch whose file handle to remove
 *
 * Unregister a callback from a file handle.  This function
 * requires that an event loop has previously been registered with
 * virEventRegisterImpl() or virEventRegisterDefaultImpl().
 *
 * Returns -1 if the file handle was not registered, 0 upon success.
 *
 * Since: 0.9.3
 */
int
virEventRemoveHandle(int watch)
{
    if (!removeHandleImpl)
        return -1;

    return removeHandleImpl(watch);
}

/**
 * virEventAddTimeout:
 *
 * @timeout: time between events in milliseconds
 * @cb: callback to invoke when an event occurs
 * @opaque: user data to pass to callback
 * @ff: callback to free opaque when timeout is removed
 *
 * Register a callback for a timer event.  This function
 * requires that an event loop has previously been registered with
 * virEventRegisterImpl() or virEventRegisterDefaultImpl().
 *
 * Setting @timeout to -1 will disable the timer. Setting @timeout
 * to zero will cause it to fire on every event loop iteration.
 *
 * Returns -1 if the timer cannot be registered, a positive
 * integer timer id upon success.
 *
 * Since: 0.9.3
 */
int
virEventAddTimeout(int timeout,
                   virEventTimeoutCallback cb,
                   void *opaque,
                   virFreeCallback ff)
{
    if (!addTimeoutImpl)
        return -1;

    return addTimeoutImpl(timeout, cb, opaque, ff);
}

/**
 * virEventUpdateTimeout:
 *
 * @timer: timer id to change
 * @timeout: time between events in milliseconds
 *
 * Change frequency for a timer.  This function
 * requires that an event loop has previously been registered with
 * virEventRegisterImpl() or virEventRegisterDefaultImpl().
 *
 * Setting frequency to -1 will disable the timer. Setting the frequency
 * to zero will cause it to fire on every event loop iteration.
 *
 * Will not fail if timer exists.
 *
 * Since: 0.9.3
 */
void
virEventUpdateTimeout(int timer, int timeout)
{
    if (updateTimeoutImpl)
        updateTimeoutImpl(timer, timeout);
}

/**
 * virEventRemoveTimeout:
 *
 * @timer: the timer id to remove
 *
 * Unregister a callback for a timer.  This function
 * requires that an event loop has previously been registered with
 * virEventRegisterImpl() or virEventRegisterDefaultImpl().
 *
 * Returns -1 if the timer was not registered, 0 upon success.
 *
 * Since: 0.9.3
 */
int
virEventRemoveTimeout(int timer)
{
    if (!removeTimeoutImpl)
        return -1;

    return removeTimeoutImpl(timer);
}


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
 * For proper event handling, it is important that the event implementation
 * is registered before a connection to the Hypervisor is opened.
 *
 * Use of the virEventAddHandle() and similar APIs require that the
 * corresponding handler is registered.  Use of the
 * virConnectDomainEventRegisterAny() and similar APIs requires that
 * the three timeout handlers are registered.  Likewise, the three
 * timeout handlers must be registered if the remote server has been
 * configured to send keepalive messages, or if the client intends
 * to call virConnectSetKeepAlive(), to avoid either side from
 * unexpectedly closing the connection due to inactivity.
 *
 * If an application does not need to integrate with an
 * existing event loop implementation, then the
 * virEventRegisterDefaultImpl() method can be used to setup
 * the generic libvirt implementation.
 *
 * Once registered, the event loop implementation cannot be
 * changed, and must be run continuously. Note that callbacks
 * may remain registered for a short time even after calling
 * virConnectClose on all open connections, so it is not safe
 * to stop running the event loop immediately after closing
 * the connection.
 *
 * Since: 0.5.0
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

    if (addHandleImpl || updateHandleImpl || removeHandleImpl ||
        addTimeoutImpl || updateTimeoutImpl || removeTimeoutImpl) {
        VIR_WARN("Ignoring attempt to replace registered event loop");
        return;
    }

    addHandleImpl = addHandle;
    updateHandleImpl = updateHandle;
    removeHandleImpl = removeHandle;
    addTimeoutImpl = addTimeout;
    updateTimeoutImpl = updateTimeout;
    removeTimeoutImpl = removeTimeout;
}


/**
 * virEventRequireImpl:
 *
 * Require that there is an event loop implementation
 * registered.
 *
 * Returns: -1 if no event loop is registered, 0 otherwise
 */
int virEventRequireImpl(void)
{
    if (!addHandleImpl || !addTimeoutImpl) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("An event loop implementation must be registered"));
        return -1;
    }

    return 0;
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
 * For proper event handling, it is important that the event implementation
 * is registered before a connection to the Hypervisor is opened.
 *
 * Once registered, the application has to invoke virEventRunDefaultImpl() in
 * a loop to process events.  Failure to do so may result in connections being
 * closed unexpectedly as a result of keepalive timeout.  The default
 * event loop fully supports handle and timeout events, but only
 * wakes up on events registered by libvirt API calls such as
 * virEventAddHandle() or virConnectDomainEventRegisterAny().
 *
 * Returns 0 on success, -1 on failure.
 *
 * Since: 0.9.0
 */
int virEventRegisterDefaultImpl(void)
{
    VIR_DEBUG("registering default event implementation");

    if (virInitialize() < 0)
        return -1;

    virResetLastError();

    virEventGLibRegister();

    return 0;
}


/**
 * virEventRunDefaultImpl:
 *
 * Run one iteration of the event loop. Applications
 * will generally want to have a thread which invokes
 * this method in an infinite loop.  Furthermore, it is wise
 * to set up a pipe-to-self handler (via virEventAddHandle())
 * or a timeout (via virEventAddTimeout()) before calling this
 * function, as it will block forever if there are no
 * registered events.
 *
 *   static bool quit;
 *
 *   while (!quit) {
 *     if (virEventRunDefaultImpl() < 0)
 *       ...print error...
 *   }
 *
 * Returns 0 on success, -1 on failure.
 *
 * Since: 0.9.0
 */
int virEventRunDefaultImpl(void)
{
    VIR_DEBUG("running default event implementation");
    virResetLastError();

    return virEventGLibRunOnce();
}
