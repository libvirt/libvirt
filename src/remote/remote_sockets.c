/*
 * remote_sockets.c: helpers for getting remote driver socket paths
 *
 * Copyright (C) 2007-2019 Red Hat, Inc.
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

#include "remote_sockets.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_REMOTE

VIR_ENUM_IMPL(remoteDriverTransport,
              REMOTE_DRIVER_TRANSPORT_LAST,
              "tls",
              "unix",
              "ssh",
              "libssh2",
              "ext",
              "tcp",
              "libssh");

VIR_ENUM_IMPL(remoteDriverMode,
              REMOTE_DRIVER_MODE_LAST,
              "auto",
              "legacy",
              "direct");


int
remoteSplitURIScheme(virURIPtr uri,
                     char **driver,
                     remoteDriverTransport *transport)
{
    char *p = strchr(uri->scheme, '+');

    if (p)
        *driver = g_strndup(uri->scheme, p - uri->scheme);
    else
        *driver = g_strdup(uri->scheme);

    if (p) {
        g_autofree char *tmp = g_strdup(p + 1);
        int val;

        p = tmp;
        while (*p) {
            *p = g_ascii_tolower(*p);
            p++;
        }

        if ((val = remoteDriverTransportTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("remote_open: transport in URL not recognised "
                             "(should be tls|unix|ssh|ext|tcp|libssh2|libssh)"));
            return -1;
        }

        if (val == REMOTE_DRIVER_TRANSPORT_UNIX &&
            uri->server) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("using unix socket and remote "
                             "server '%s' is not supported."),
                           uri->server);
            return -1;
        }

        *transport = val;
    } else {
        if (uri->server)
            *transport = REMOTE_DRIVER_TRANSPORT_TLS;
        else
            *transport = REMOTE_DRIVER_TRANSPORT_UNIX;
    }

    return 0;
}
