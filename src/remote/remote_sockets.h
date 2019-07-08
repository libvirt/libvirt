/*
 * remote_sockets.h: helpers for getting remote driver socket paths
 *
 * Copyright (C) 2007-2020 Red Hat, Inc.
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

#pragma once

#include "virenum.h"
#include "viruri.h"

typedef enum {
    REMOTE_DRIVER_TRANSPORT_TLS,
    REMOTE_DRIVER_TRANSPORT_UNIX,
    REMOTE_DRIVER_TRANSPORT_SSH,
    REMOTE_DRIVER_TRANSPORT_LIBSSH2,
    REMOTE_DRIVER_TRANSPORT_EXT,
    REMOTE_DRIVER_TRANSPORT_TCP,
    REMOTE_DRIVER_TRANSPORT_LIBSSH,

    REMOTE_DRIVER_TRANSPORT_LAST,
} remoteDriverTransport;

VIR_ENUM_DECL(remoteDriverTransport);

typedef enum {
    /* Try to figure out the "best" choice magically */
    REMOTE_DRIVER_MODE_AUTO,
    /* Always use the legacy libvirtd */
    REMOTE_DRIVER_MODE_LEGACY,
    /* Always use the per-driver virt*d daemons */
    REMOTE_DRIVER_MODE_DIRECT,

    REMOTE_DRIVER_MODE_LAST
} remoteDriverMode;

VIR_ENUM_DECL(remoteDriverMode);

int
remoteSplitURIScheme(virURIPtr uri,
                     char **driver,
                     remoteDriverTransport *transport);

char *
remoteGetUNIXSocket(remoteDriverTransport transport,
                    remoteDriverMode mode,
                    const char *driver,
                    bool ro,
                    bool session,
                    char **daemon);

void
remoteGetURIDaemonInfo(virURIPtr uri,
                       remoteDriverTransport transport,
                       bool *session,
                       bool *autostart);
