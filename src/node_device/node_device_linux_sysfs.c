/*
 * node_device_linux_sysfs.c: Linux specific code to gather device data
 * not available through HAL.
 *
 * Copyright (C) 2009-2013 Red Hat, Inc.
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
 */

#include <config.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "node_device_driver.h"
#include "node_device_hal.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

#ifdef __linux__

VIR_LOG_INIT("node_device.node_device_linux_sysfs");

int
detect_scsi_host_caps(union _virNodeDevCapData *d)
{
    char *max_vports = NULL;
    char *vports = NULL;
    int ret = -1;

    VIR_DEBUG("Checking if host%d is an FC HBA", d->scsi_host.host);

    if (virIsCapableFCHost(NULL, d->scsi_host.host)) {
        d->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST;

        if (virReadFCHost(NULL,
                          d->scsi_host.host,
                          "port_name",
                          &d->scsi_host.wwpn) < 0) {
            VIR_ERROR(_("Failed to read WWPN for host%d"), d->scsi_host.host);
            goto cleanup;
        }

        if (virReadFCHost(NULL,
                          d->scsi_host.host,
                          "node_name",
                          &d->scsi_host.wwnn) < 0) {
            VIR_ERROR(_("Failed to read WWNN for host%d"), d->scsi_host.host);
            goto cleanup;
        }

        if (virReadFCHost(NULL,
                          d->scsi_host.host,
                          "fabric_name",
                          &d->scsi_host.fabric_wwn) < 0) {
            VIR_ERROR(_("Failed to read fabric WWN for host%d"),
                      d->scsi_host.host);
            goto cleanup;
        }
    }

    if (virIsCapableVport(NULL, d->scsi_host.host)) {
        d->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS;

        if (virReadFCHost(NULL,
                          d->scsi_host.host,
                          "max_npiv_vports",
                          &max_vports) < 0) {
            VIR_ERROR(_("Failed to read max_npiv_vports for host%d"),
                      d->scsi_host.host);
            goto cleanup;
        }

         if (virReadFCHost(NULL,
                          d->scsi_host.host,
                          "npiv_vports_inuse",
                          &vports) < 0) {
            VIR_ERROR(_("Failed to read npiv_vports_inuse for host%d"),
                      d->scsi_host.host);
            goto cleanup;
        }

        if (virStrToLong_i(max_vports, NULL, 10,
                           &d->scsi_host.max_vports) < 0) {
            VIR_ERROR(_("Failed to parse value of max_npiv_vports '%s'"),
                      max_vports);
            goto cleanup;
        }

        if (virStrToLong_i(vports, NULL, 10,
                           &d->scsi_host.vports) < 0) {
            VIR_ERROR(_("Failed to parse value of npiv_vports_inuse '%s'"),
                      vports);
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    if (ret < 0) {
        /* Clear the two flags in case of producing confusing XML output */
        d->scsi_host.flags &= ~(VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST |
                                VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS);

        VIR_FREE(d->scsi_host.wwnn);
        VIR_FREE(d->scsi_host.wwpn);
        VIR_FREE(d->scsi_host.fabric_wwn);
    }
    VIR_FREE(max_vports);
    VIR_FREE(vports);
    return ret;
}

#else

int
detect_scsi_host_caps(union _virNodeDevCapData *d ATTRIBUTE_UNUSED)
{
    return -1;
}

#endif /* __linux__ */
