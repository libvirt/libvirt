/*
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright IBM Corp. 2008
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

#include "virnetdevveth.h"
#include "viralloc.h"
#include "virlog.h"
#include "vircommand.h"
#include "virerror.h"
#include "virnetdev.h"
#include "virnetlink.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.netdevveth");


#if defined(WITH_LIBNL)
static int
virNetDevVethCreateInternal(const char *veth1, const char *veth2)
{
    int error = 0;
    virNetlinkNewLinkData data = { .veth_peer = veth2 };

    if (virNetlinkNewLink(veth1, "veth", &data, &error) < 0) {
        if (error != 0) {
            virReportSystemError(-error,
                                 _("unable to create %1$s <-> %2$s veth pair"),
                                 veth1, veth2);
        }
        return -1;
    }

    return 0;
}

static int
virNetDevVethDeleteInternal(const char *veth)
{
    return virNetlinkDelLink(veth, NULL);
}
#else
static int
virNetDevVethCreateInternal(const char *veth1, const char *veth2)
{
    g_autoptr(virCommand) cmd = virCommandNew("ip");
    virCommandAddArgList(cmd, "link", "add", veth1, "type", "veth",
                         "peer", "name", veth2, NULL);

    return virCommandRun(cmd, NULL);
}

static int
virNetDevVethDeleteInternal(const char *veth)
{
    int status;
    g_autoptr(virCommand) cmd = virCommandNewArgList("ip", "link",
                                                     "del", veth, NULL);

    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        if (!virNetDevExists(veth)) {
            VIR_DEBUG("Device %s already deleted (by kernel namespace cleanup)", veth);
            return 0;
        }
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to delete veth device %1$s"), veth);
        return -1;
    }

    return 0;
}
#endif /* WITH_LIBNL */

/**
 * virNetDevVethCreate:
 * @veth1: pointer to name for one end of veth pair
 * @veth2: pointer to name for another end of veth pair
 *
 * Creates a veth device pair.
 *
 * NOTE: If veth1 and veth2 names are not specified, ip will auto assign
 *       names.  There seems to be two problems here -
 *       1) There doesn't seem to be a way to determine the names of the
 *          devices that it creates.  They show up in ip link show and
 *          under /sys/class/net/ however there is no guarantee that they
 *          are the devices that this process just created.
 *       2) Once one of the veth devices is moved to another namespace, it
 *          is no longer visible in the parent namespace.  This seems to
 *          confuse the name assignment causing it to fail with File exists.
 *       Because of these issues, this function currently allocates names
 *       prior to using the ip command, and returns any allocated names
 *       to the caller.
 *
 * Returns 0 on success or -1 in case of error
 */
int virNetDevVethCreate(char **veth1, char **veth2)
{
    const char *orig1 = *veth1;
    const char *orig2 = *veth2;

    if (virNetDevGenerateName(veth1, VIR_NET_DEV_GEN_NAME_VNET) < 0)
        goto cleanup;

    if (virNetDevGenerateName(veth2, VIR_NET_DEV_GEN_NAME_VNET) < 0)
        goto cleanup;

    if (virNetDevVethCreateInternal(*veth1, *veth2) < 0)
        goto cleanup;

    VIR_DEBUG("Create Host: %s guest: %s", *veth1, *veth2);
    return 0;

 cleanup:
    if (orig1 == NULL)
        VIR_FREE(*veth1);

    if (orig2 == NULL)
        VIR_FREE(*veth2);

    return -1;
}

/**
 * virNetDevVethDelete:
 * @veth: name for one end of veth pair
 *
 * This will delete both veth devices in a pair.  Only one end needs to
 * be specified.  The ip command will identify and delete the other veth
 * device as well.
 * ip link del veth
 *
 * Returns 0 on success or -1 in case of error
 */
int virNetDevVethDelete(const char *veth)
{
    return virNetDevVethDeleteInternal(veth);
}
