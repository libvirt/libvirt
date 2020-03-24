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
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_monitor_text");

int qemuMonitorTextAddDrive(qemuMonitorPtr mon,
                            const char *drivestr)
{
    g_autofree char *cmd = NULL;
    g_autofree char *reply = NULL;

    /* 'dummy' here is just a placeholder since there is no PCI
     * address required when attaching drives to a controller */
    cmd = g_strdup_printf("drive_add dummy %s", drivestr);

    if (qemuMonitorJSONHumanCommand(mon, cmd, &reply) < 0)
        return -1;

    if (strstr(reply, "unknown command:")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("drive hotplug is not supported"));
        return -1;
    }

    if (strstr(reply, "could not open disk image")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("open disk image file failed"));
        return -1;
    }

    if (strstr(reply, "Could not open")) {
        size_t len = strlen(reply);
        if (reply[len - 1] == '\n')
            reply[len - 1] = '\0';

        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       reply);
        return -1;
    }

    if (strstr(reply, "Image is not in")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Incorrect disk format"));
        return -1;
    }

    if (strstr(reply, "IOMMU") ||
        strstr(reply, "VFIO")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       reply);
        return -1;
    }

    return 0;
}


int qemuMonitorTextDriveDel(qemuMonitorPtr mon,
                            const char *drivestr)
{
    g_autofree char *cmd = NULL;
    g_autofree char *reply = NULL;

    cmd = g_strdup_printf("drive_del %s", drivestr);

    if (qemuMonitorJSONHumanCommand(mon, cmd, &reply) < 0)
        return -1;

    if (strstr(reply, "unknown command:")) {
        VIR_ERROR(_("deleting drive is not supported.  "
                    "This may leak data if disk is reassigned"));
        return 1;

    /* (qemu) drive_del wark
     * Device 'wark' not found */
    } else if (strstr(reply, "Device '") && strstr(reply, "not found")) {
        /* NB: device not found errors mean the drive was auto-deleted and we
         * ignore the error */
    } else if (STRNEQ(reply, "")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("deleting %s drive failed: %s"), drivestr, reply);
        return -1;
    }

    return 0;
}

int
qemuMonitorTextCreateSnapshot(qemuMonitorPtr mon,
                              const char *name)
{
    g_autofree char *cmd = NULL;
    g_autofree char *reply = NULL;

    cmd = g_strdup_printf("savevm \"%s\"", name);

    if (qemuMonitorJSONHumanCommand(mon, cmd, &reply))
        return -1;

    if (strstr(reply, "Error while creating snapshot") ||
        strstr(reply, "Could not open VM state file") ||
        strstr(reply, "State blocked by non-migratable device") ||
        strstr(reply, "Error: ") ||
        (strstr(reply, "Error") && strstr(reply, "while writing VM"))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to take snapshot: %s"), reply);
        return -1;
    } else if (strstr(reply, "No block device can accept snapshots")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this domain does not have a device to take snapshots"));
        return -1;
    }

    return 0;
}

int qemuMonitorTextLoadSnapshot(qemuMonitorPtr mon, const char *name)
{
    g_autofree char *cmd = NULL;
    g_autofree char *reply = NULL;

    cmd = g_strdup_printf("loadvm \"%s\"", name);

    if (qemuMonitorJSONHumanCommand(mon, cmd, &reply))
        return -1;

    if (strstr(reply, "No block device supports snapshots")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this domain does not have a device to load snapshots"));
        return -1;
    } else if (strstr(reply, "Could not find snapshot")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("the snapshot '%s' does not exist, and was not loaded"),
                       name);
        return -1;
    } else if (strstr(reply, "Snapshots not supported on device")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Failed to load snapshot: %s"), reply);
        return -1;
    } else if (strstr(reply, "Could not open VM state file") ||
               strstr(reply, "Error: ") ||
               (strstr(reply, "Error") &&
                (strstr(reply, "while loading VM state") ||
                 strstr(reply, "while activating snapshot on")))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to load snapshot: %s"), reply);
        return -1;
    }

    return 0;
}

int qemuMonitorTextDeleteSnapshot(qemuMonitorPtr mon, const char *name)
{
    g_autofree char *cmd = NULL;
    g_autofree char *reply = NULL;

    cmd = g_strdup_printf("delvm \"%s\"", name);
    if (qemuMonitorJSONHumanCommand(mon, cmd, &reply))
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
                       _("Failed to delete snapshot: %s"), reply);
        return -1;
    }

    return 0;
}
