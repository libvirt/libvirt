/* virhostdev.c: hostdev management
 *
 * Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 * Author: Chunyan Liu <cyliu@suse.com>
 */

#include <config.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "virhostdev.h"
#include "viralloc.h"
#include "virstring.h"
#include "virfile.h"
#include "virerror.h"
#include "virlog.h"
#include "virutil.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_NONE
#define HOSTDEV_STATE_DIR LOCALSTATEDIR "/run/libvirt/hostdevmgr"

static virHostdevManagerPtr hostdevMgr;

static void
virHostdevManagerCleanup(void)
{
    if (!hostdevMgr)
        return;

    virObjectUnref(hostdevMgr->activePciHostdevs);
    virObjectUnref(hostdevMgr->inactivePciHostdevs);
    virObjectUnref(hostdevMgr->activeUsbHostdevs);
    virObjectUnref(hostdevMgr->activeScsiHostdevs);
    VIR_FREE(hostdevMgr->stateDir);

    VIR_FREE(hostdevMgr);
}

static int
virHostdevOnceInit(void)
{
    if (VIR_ALLOC(hostdevMgr) < 0)
        goto error;

    if ((hostdevMgr->activePciHostdevs = virPCIDeviceListNew()) == NULL)
        goto error;

    if ((hostdevMgr->activeUsbHostdevs = virUSBDeviceListNew()) == NULL)
        goto error;

    if ((hostdevMgr->inactivePciHostdevs = virPCIDeviceListNew()) == NULL)
        goto error;

    if ((hostdevMgr->activeScsiHostdevs = virSCSIDeviceListNew()) == NULL)
        goto error;

    if (VIR_STRDUP(hostdevMgr->stateDir, HOSTDEV_STATE_DIR) < 0)
        goto error;

    if (virFileMakePath(hostdevMgr->stateDir) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to create state dir '%s'"),
                       hostdevMgr->stateDir);
        goto error;
    }

    return 0;

error:
    virHostdevManagerCleanup();
    return -1;
}

VIR_ONCE_GLOBAL_INIT(virHostdev)

virHostdevManagerPtr
virHostdevManagerGetDefault(void)
{
    if (virHostdevInitialize() < 0)
        return NULL;
    return hostdevMgr;
}
