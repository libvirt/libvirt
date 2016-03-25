/*
 * admin_server.c: admin methods to manage daemons and clients
 *
 * Copyright (C) 2016 Red Hat, Inc.
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
 * Authors: Erik Skultety <eskultet@redhat.com>
 *          Martin Kletzander <mkletzan@redhat.com>
 */

#include <config.h>

#include "admin_server.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virnetdaemon.h"
#include "virnetserver.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_ADMIN

VIR_LOG_INIT("daemon.admin_server");

int
adminConnectListServers(virNetDaemonPtr dmn,
                        virNetServerPtr **servers,
                        unsigned int flags)
{
    int ret = -1;
    virNetServerPtr *srvs = NULL;

    virCheckFlags(0, -1);

    if ((ret = virNetDaemonGetServers(dmn, &srvs)) < 0)
        goto cleanup;

    if (servers) {
        *servers = srvs;
        srvs = NULL;
    }
 cleanup:
    if (ret > 0)
        virObjectListFreeCount(srvs, ret);
    return ret;
}

virNetServerPtr
adminConnectLookupServer(virNetDaemonPtr dmn,
                         const char *name,
                         unsigned int flags)
{
    virCheckFlags(flags, NULL);

    return virNetDaemonGetServer(dmn, name);
}
