/*
 * qemu_monitor_text.c: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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


#include "qemu_monitor_text.h"
#include "qemu_monitor_json.h"
#include "virlog.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_monitor_text");

int
qemuMonitorTextCreateSnapshot(qemuMonitor *mon,
                              const char *name)
{
    g_autofree char *cmd = NULL;
    g_autofree char *reply = NULL;

    cmd = g_strdup_printf("savevm \"%s\"", name);

    if (qemuMonitorJSONHumanCommand(mon, cmd, -1, &reply))
        return -1;

    if (strstr(reply, "Error while creating snapshot") ||
        strstr(reply, "Could not open VM state file") ||
        strstr(reply, "State blocked by non-migratable device") ||
        strstr(reply, "Error: ") ||
        (strstr(reply, "Error") && strstr(reply, "while writing VM"))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to take snapshot: %1$s"), reply);
        return -1;
    } else if (strstr(reply, "No block device can accept snapshots")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this domain does not have a device to take snapshots"));
        return -1;
    }

    return 0;
}

int qemuMonitorTextDeleteSnapshot(qemuMonitor *mon, const char *name)
{
    g_autofree char *cmd = NULL;
    g_autofree char *reply = NULL;

    cmd = g_strdup_printf("delvm \"%s\"", name);
    if (qemuMonitorJSONHumanCommand(mon, cmd, -1, &reply))
        return -1;

    if (strstr(reply, "No block device supports snapshots")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this domain does not have a device to delete snapshots"));
        return -1;
    } else if (strstr(reply, "Snapshots not supported on device")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", reply);
        return -1;
    } else if (strstr(reply, "Error: ") ||
               (strstr(reply, "Error") &&
                strstr(reply, "while deleting snapshot"))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to delete snapshot: %1$s"), reply);
        return -1;
    }

    return 0;
}
