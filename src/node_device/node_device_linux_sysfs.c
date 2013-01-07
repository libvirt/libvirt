/*
 * node_device_hal_linuc.c: Linux specific code to gather device data
 * not available through HAL.
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
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

#define VIR_FROM_THIS VIR_FROM_NODEDEV

#ifdef __linux__

int check_fc_host_linux(union _virNodeDevCapData *d)
{
    char *sysfs_path = NULL;
    int retval = 0;
    struct stat st;

    VIR_DEBUG("Checking if host%d is an FC HBA", d->scsi_host.host);

    if (virAsprintf(&sysfs_path, "%shost%d",
                    LINUX_SYSFS_FC_HOST_PREFIX,
                    d->scsi_host.host) < 0) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    if (stat(sysfs_path, &st) != 0) {
        /* Not an FC HBA; not an error, either. */
        goto out;
    }

    d->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST;

    if (virReadFCHost(NULL,
                      d->scsi_host.host,
                      "port_name",
                      &d->scsi_host.wwpn) == -1) {
        VIR_ERROR(_("Failed to read WWPN for host%d"),
                  d->scsi_host.host);
        retval = -1;
        goto out;
    }

    if (virReadFCHost(NULL,
                      d->scsi_host.host,
                      "node_name",
                      &d->scsi_host.wwnn) == -1) {
        VIR_ERROR(_("Failed to read WWNN for host%d"),
                  d->scsi_host.host);
        retval = -1;
    }

    if (virReadFCHost(NULL,
                      d->scsi_host.host,
                      "fabric_name",
                      &d->scsi_host.fabric_wwn) == -1) {
        VIR_ERROR(_("Failed to read fabric WWN for host%d"),
                  d->scsi_host.host);
        retval = -1;
        goto out;
    }

out:
    if (retval == -1) {
        VIR_FREE(d->scsi_host.wwnn);
        VIR_FREE(d->scsi_host.wwpn);
        VIR_FREE(d->scsi_host.fabric_wwn);
    }
    VIR_FREE(sysfs_path);
    return retval;
}


int check_vport_capable_linux(union _virNodeDevCapData *d)
{
    char *sysfs_path = NULL;
    struct stat st;
    int retval = 0;

    if (virAsprintf(&sysfs_path,
                    "%shost%d%s",
                    LINUX_SYSFS_FC_HOST_PREFIX,
                    d->scsi_host.host,
                    LINUX_SYSFS_VPORT_CREATE_POSTFIX) < 0) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    if (stat(sysfs_path, &st) == 0) {
        d->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS;
        goto out;
    }

    VIR_FREE(sysfs_path);
    if (virAsprintf(&sysfs_path,
                    "%shost%d%s",
                    LINUX_SYSFS_SCSI_HOST_PREFIX,
                    d->scsi_host.host,
                    LINUX_SYSFS_VPORT_CREATE_POSTFIX) < 0) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    if (stat(sysfs_path, &st) == 0) {
        d->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS;
    } else {
        /* Not a vport capable HBA; not an error, either. */
        VIR_DEBUG("No vport operation path found for host%d",
                  d->scsi_host.host);
    }

out:
    VIR_FREE(sysfs_path);
    return retval;
}

#endif /* __linux__ */
