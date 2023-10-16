/*
 * virfcp.c: Utility functions for the Fibre Channel Protocol
 *
 * Copyright (C) 2017 IBM Corporation
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

#include "internal.h"

#include "virfile.h"
#include "virerror.h"

#include "virfcp.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#ifdef __linux__

# define SYSFS_FC_RPORT_PATH "/sys/class/fc_remote_ports"

bool
virFCIsCapableRport(const char *rport)
{
    g_autofree char *path = NULL;

    path = g_build_filename(SYSFS_FC_RPORT_PATH, rport, NULL);

    return virFileExists(path);
}

int
virFCReadRportValue(const char *rport,
                    const char *entry,
                    char **result)
{
    g_autofree char *buf = NULL;
    char *p = NULL;

    if (virFileReadValueString(&buf, "%s/%s/%s",
                               SYSFS_FC_RPORT_PATH, rport, entry) < 0) {
        return -1;
    }

    if ((p = strchr(buf, '\n')))
        *p = '\0';

    *result = g_strdup(buf);

    return 0;
}

#else

bool
virFCIsCapableRport(const char *rport G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return false;
}

int
virFCReadRportValue(const char *rport G_GNUC_UNUSED,
                    const char *entry G_GNUC_UNUSED,
                    char **result G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s", _("Not supported on this platform"));
    return -1;
}

#endif
