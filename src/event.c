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


#include "event.h"

#include <stdlib.h>

static virEventAddHandleFunc addHandleImpl = NULL;
static virEventRemoveHandleFunc removeHandleImpl = NULL;
static virEventAddTimeoutFunc addTimeoutImpl = NULL;
static virEventRemoveTimeoutFunc removeTimeoutImpl = NULL;

int virEventAddHandle(int fd, int events, virEventHandleCallback cb, void *opaque) {
    if (!addHandleImpl)
        return -1;

    return addHandleImpl(fd, events, cb, opaque);
}

int virEventRemoveHandle(int fd) {
    if (!removeHandleImpl)
        return -1;

    return removeHandleImpl(fd);
}

int virEventAddTimeout(int timeout, virEventTimeoutCallback cb, void *opaque) {
    if (!addTimeoutImpl)
        return -1;

    return addTimeoutImpl(timeout, cb, opaque);
}

int virEventRemoveTimeout(int timer) {
    if (!removeTimeoutImpl)
        return -1;

    return removeTimeoutImpl(timer);
}

void __virEventRegisterImpl(virEventAddHandleFunc addHandle,
                           virEventRemoveHandleFunc removeHandle,
                           virEventAddTimeoutFunc addTimeout,
                           virEventRemoveTimeoutFunc removeTimeout) {
    addHandleImpl = addHandle;
    removeHandleImpl = removeHandle;
    addTimeoutImpl = addTimeout;
    removeTimeoutImpl = removeTimeout;
}


/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
