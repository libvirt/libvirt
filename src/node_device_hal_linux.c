/*
 * node_device_hal_linuc.c: Linux specific code to gather device data
 * not available through HAL.
 *
 * Copyright (C) 2009 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include <fcntl.h>

#include "node_device.h"
#include "node_device_hal.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

#ifdef __linux__

int check_fc_host_linux(union _virNodeDevCapData *d)
{
    char *sysfs_path = NULL;
    char *wwnn_path = NULL;
    char *wwpn_path = NULL;
    char *p = NULL;
    int fd = -1, retval = 0;
    char buf[64];
    struct stat st;

    VIR_DEBUG(_("Checking if host%d is an FC HBA"), d->scsi_host.host);

    if (virAsprintf(&sysfs_path, "%s/host%d",
                    LINUX_SYSFS_FC_HOST_PREFIX,
                    d->scsi_host.host) < 0) {
        virReportOOMError(NULL);
        retval = -1;
        goto out;
    }

    if (stat(sysfs_path, &st) != 0) {
        /* Not an FC HBA; not an error, either. */
        goto out;
    }

    d->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST;

    if (virAsprintf(&wwnn_path, "%s/node_name",
                    sysfs_path) < 0) {
        virReportOOMError(NULL);
        retval = -1;
        goto out;
    }

    if ((fd = open(wwnn_path, O_RDONLY)) < 0) {
        retval = -1;
        VIR_ERROR(_("Failed to open WWNN path '%s' for reading"),
                  wwnn_path);
        goto out;
    }

    memset(buf, 0, sizeof(buf));
    if (saferead(fd, buf, sizeof(buf)) < 0) {
        retval = -1;
        VIR_ERROR(_("Failed to read WWNN from '%s'"),
                  wwnn_path);
        goto out;
    }

    close(fd);
    fd = -1;

    p = strstr(buf, "0x");
    if (p != NULL) {
        p += strlen("0x");
    } else {
        p = buf;
    }

    d->scsi_host.wwnn = strndup(p, sizeof(buf));
    if (d->scsi_host.wwnn == NULL) {
        virReportOOMError(NULL);
        retval = -1;
        goto out;
    }

    p = strchr(d->scsi_host.wwnn, '\n');
    if (p != NULL) {
        *p = '\0';
    }

    if (virAsprintf(&wwpn_path, "%s/port_name",
                    sysfs_path) < 0) {
        virReportOOMError(NULL);
        retval = -1;
        goto out;
    }

    if ((fd = open(wwpn_path, O_RDONLY)) < 0) {
        retval = -1;
        VIR_ERROR(_("Failed to open WWPN path '%s' for reading"),
                  wwpn_path);
        goto out;
    }

    memset(buf, 0, sizeof(buf));
    if (saferead(fd, buf, sizeof(buf)) < 0) {
        retval = -1;
        VIR_ERROR(_("Failed to read WWPN from '%s'"),
                  wwpn_path);
        goto out;
    }

    close(fd);
    fd = -1;

    p = strstr(buf, "0x");
    if (p != NULL) {
        p += strlen("0x");
    } else {
        p = buf;
    }

    d->scsi_host.wwpn = strndup(p, sizeof(buf));
    if (d->scsi_host.wwpn == NULL) {
        virReportOOMError(NULL);
        retval = -1;
        goto out;
    }

    p = strchr(d->scsi_host.wwpn, '\n');
    if (p != NULL) {
        *p = '\0';
    }

out:
    if (fd != -1) {
        close(fd);
    }
    VIR_FREE(sysfs_path);
    VIR_FREE(wwnn_path);
    VIR_FREE(wwpn_path);
    return 0;
}


int check_vport_capable_linux(union _virNodeDevCapData *d)
{
    char *sysfs_path = NULL;
    struct stat st;
    int retval = 0;

    if (virAsprintf(&sysfs_path, "%s/host%d/vport_create",
                    LINUX_SYSFS_FC_HOST_PREFIX,
                    d->scsi_host.host) < 0) {
        virReportOOMError(NULL);
        retval = -1;
        goto out;
    }

    if (stat(sysfs_path, &st) != 0) {
        /* Not a vport capable HBA; not an error, either. */
        goto out;
    }

    d->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS;

out:
    VIR_FREE(sysfs_path);
    return retval;
}

#endif /* __linux__ */
