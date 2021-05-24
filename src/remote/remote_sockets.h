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

typedef enum {
    REMOTE_DRIVER_OPEN_RO = (1 << 0), /* Use the read-only socket path */
    REMOTE_DRIVER_OPEN_USER = (1 << 1), /* Use the per-user socket path */
    REMOTE_DRIVER_OPEN_AUTOSTART = (1 << 2), /* Autostart a per-user daemon */
} remoteDriverOpenFlags;


VIR_ENUM_DECL(remoteDriverMode);

int
remoteSplitURIScheme(virURI *uri,
                     char **driver,
                     remoteDriverTransport *transport);

int
remoteProbeSessionDriverFromBinary(char **driver);
int
remoteProbeSystemDriverFromSocket(bool readonly, char **driver);
int
remoteProbeSessionDriverFromSocket(bool readonly, char **driver);

char *
remoteGetUNIXSocket(remoteDriverTransport transport,
                    remoteDriverMode mode,
                    const char *driver,
                    unsigned int flags, /* remoteDriverOpenFlags */
                    char **daemon_path);

void
remoteGetURIDaemonInfo(virURI *uri,
                       remoteDriverTransport transport,
                       unsigned int *flags); /* remoteDriverOpenFlags */
