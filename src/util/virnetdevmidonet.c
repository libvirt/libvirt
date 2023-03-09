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
 */

#include <config.h>

#include "virnetdevmidonet.h"
#include "vircommand.h"
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
                         const virNetDevVPortProfile *virtualport)
{
    g_autoptr(virCommand) cmd = NULL;
    char virtportuuid[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(virtualport->interfaceID, virtportuuid);

    cmd = virCommandNew(MM_CTL);

    virCommandAddArgList(cmd, "--bind-port", virtportuuid, ifname, NULL);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to bind port %1$s to the virtual port %2$s"),
                       ifname, virtportuuid);
        return -1;
    }

    return 0;
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
virNetDevMidonetUnbindPort(const virNetDevVPortProfile *virtualport)
{
    g_autoptr(virCommand) cmd = NULL;
    char virtportuuid[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(virtualport->interfaceID, virtportuuid);

    cmd = virCommandNew(MM_CTL);
    virCommandAddArgList(cmd, "--unbind-port", virtportuuid, NULL);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to unbind the virtual port %1$s from Midonet"),
                       virtportuuid);
        return -1;
    }

    return 0;
}
