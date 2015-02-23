/*
 * Copyright (C) 2015 Midokura, Sarl.
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
 * Authors:
 *     Antoni Segura Puimedon <toni@midokura.com>
 */

#include <config.h>

#include "virnetdevmidonet.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virerror.h"
#include "viruuid.h"

#define VIR_FROM_THIS VIR_FROM_NONE

/**
 * virNetDevMidonetBindPort:
 * @ifname: the network interface name
 * @virtualport: the midonet specific fields
 *
 * Bind an interface to a Midonet virtual port
 *
 * Returns 0 in case of success or -1 in case of failure.
 */
int
virNetDevMidonetBindPort(const char *ifname,
                         virNetDevVPortProfilePtr virtualport)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    char virtportuuid[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(virtualport->interfaceID, virtportuuid);

    cmd = virCommandNew(MMCTL);

    virCommandAddArgList(cmd, "--bind-port", virtportuuid, ifname, NULL);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to bind port %s to the virtual port %s"),
                       ifname, virtportuuid);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}

/**
 * virNetDevMidonetUnbindPort:
 * @virtualport: the midonet specific fields
 *
 * Unbinds a virtual port from the host
 *
 * Returns 0 in case of success or -1 in case of failure.
 */
int
virNetDevMidonetUnbindPort(virNetDevVPortProfilePtr virtualport)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    char virtportuuid[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(virtualport->interfaceID, virtportuuid);

    cmd = virCommandNew(MMCTL);
    virCommandAddArgList(cmd, "--unbind-port", virtportuuid, NULL);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to unbind the virtual port %s from Midonet"),
                       virtportuuid);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}
