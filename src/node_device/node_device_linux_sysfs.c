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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>

#include "node_device_driver.h"
#include "node_device_hal.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

#ifdef __linux__

static int open_wwn_file(const char *prefix,
                         int host,
                         const char *file,
                         int *fd)
{
    int retval = 0;
    char *wwn_path = NULL;

    if (virAsprintf(&wwn_path, "%s/host%d/%s", prefix, host, file) < 0) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    /* fd will be closed by caller */
    if ((*fd = open(wwn_path, O_RDONLY)) != -1) {
        VIR_DEBUG("Opened WWN path '%s' for reading",
                  wwn_path);
    } else {
        VIR_ERROR(_("Failed to open WWN path '%s' for reading"),
                  wwn_path);
    }

out:
    VIR_FREE(wwn_path);
    return retval;
}


int read_wwn_linux(int host, const char *file, char **wwn)
{
    char *p = NULL;
    int fd = -1, retval = 0;
    char buf[64];

    if (open_wwn_file(LINUX_SYSFS_FC_HOST_PREFIX, host, file, &fd) < 0) {
        goto out;
    }

    memset(buf, 0, sizeof(buf));
    if (saferead(fd, buf, sizeof(buf)) < 0) {
        retval = -1;
        VIR_DEBUG("Failed to read WWN for host%d '%s'",
                  host, file);
        goto out;
    }

    p = strstr(buf, "0x");
    if (p != NULL) {
        p += strlen("0x");
    } else {
        p = buf;
    }

    *wwn = strndup(p, sizeof(buf));
    if (*wwn == NULL) {
        virReportOOMError();
        retval = -1;
        goto out;
    }

    p = strchr(*wwn, '\n');
    if (p != NULL) {
        *p = '\0';
    }

out:
    VIR_FORCE_CLOSE(fd);
    return retval;
}


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

    if (read_wwn(d->scsi_host.host,
                 "port_name",
                 &d->scsi_host.wwpn) == -1) {
        VIR_ERROR(_("Failed to read WWPN for host%d"),
                  d->scsi_host.host);
        retval = -1;
        goto out;
    }

    if (read_wwn(d->scsi_host.host,
                 "node_name",
                 &d->scsi_host.wwnn) == -1) {
        VIR_ERROR(_("Failed to read WWNN for host%d"),
                  d->scsi_host.host);
        retval = -1;
    }

    if (read_wwn(d->scsi_host.host,
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
