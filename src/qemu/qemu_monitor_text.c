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
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_monitor_text");

int qemuMonitorTextAddDrive(qemuMonitorPtr mon,
                            const char *drivestr)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;
    char *safe_str;

    safe_str = qemuMonitorEscapeArg(drivestr);
    if (!safe_str)
        return -1;

    /* 'dummy' here is just a placeholder since there is no PCI
     * address required when attaching drives to a controller */
    if (virAsprintf(&cmd, "drive_add dummy %s", safe_str) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (strstr(reply, "unknown command:")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("drive hotplug is not supported"));
        goto cleanup;
    }

    if (strstr(reply, "could not open disk image")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("open disk image file failed"));
        goto cleanup;
    }

    if (strstr(reply, "Could not open")) {
        size_t len = strlen(reply);
        if (reply[len - 1] == '\n')
            reply[len - 1] = '\0';

        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       reply);
        goto cleanup;
    }

    if (strstr(reply, "Image is not in")) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Incorrect disk format"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    VIR_FREE(safe_str);
    return ret;
}


int qemuMonitorTextDriveDel(qemuMonitorPtr mon,
                            const char *drivestr)
{
    char *cmd = NULL;
    char *reply = NULL;
    char *safedev;
    int ret = -1;

    if (!(safedev = qemuMonitorEscapeArg(drivestr)))
        goto cleanup;

    if (virAsprintf(&cmd, "drive_del %s", safedev) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (strstr(reply, "unknown command:")) {
        VIR_ERROR(_("deleting drive is not supported.  "
                    "This may leak data if disk is reassigned"));
        ret = 1;
        goto cleanup;

    /* (qemu) drive_del wark
     * Device 'wark' not found */
    } else if (strstr(reply, "Device '") && strstr(reply, "not found")) {
        /* NB: device not found errors mean the drive was auto-deleted and we
         * ignore the error */
    } else if (STRNEQ(reply, "")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("deleting %s drive failed: %s"), drivestr, reply);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cmd);
    VIR_FREE(reply);
    VIR_FREE(safedev);
    return ret;
}

int
qemuMonitorTextCreateSnapshot(qemuMonitorPtr mon,
                              const char *name)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;
    char *safename;

    if (!(safename = qemuMonitorEscapeArg(name)) ||
        virAsprintf(&cmd, "savevm \"%s\"", safename) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply))
        goto cleanup;

    if (strstr(reply, "Error while creating snapshot") ||
        strstr(reply, "Could not open VM state file") ||
        strstr(reply, "State blocked by non-migratable device") ||
        strstr(reply, "Error: ") ||
        (strstr(reply, "Error") && strstr(reply, "while writing VM"))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to take snapshot: %s"), reply);
        goto cleanup;
    } else if (strstr(reply, "No block device can accept snapshots")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this domain does not have a device to take snapshots"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(safename);
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}

int qemuMonitorTextLoadSnapshot(qemuMonitorPtr mon, const char *name)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;
    char *safename;

    if (!(safename = qemuMonitorEscapeArg(name)) ||
        virAsprintf(&cmd, "loadvm \"%s\"", safename) < 0)
        goto cleanup;

    if (qemuMonitorHMPCommand(mon, cmd, &reply))
        goto cleanup;

    if (strstr(reply, "No block device supports snapshots")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this domain does not have a device to load snapshots"));
        goto cleanup;
    } else if (strstr(reply, "Could not find snapshot")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("the snapshot '%s' does not exist, and was not loaded"),
                       name);
        goto cleanup;
    } else if (strstr(reply, "Snapshots not supported on device")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Failed to load snapshot: %s"), reply);
        goto cleanup;
    } else if (strstr(reply, "Could not open VM state file") ||
               strstr(reply, "Error: ") ||
               (strstr(reply, "Error") &&
                (strstr(reply, "while loading VM state") ||
                 strstr(reply, "while activating snapshot on")))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to load snapshot: %s"), reply);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(safename);
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}

int qemuMonitorTextDeleteSnapshot(qemuMonitorPtr mon, const char *name)
{
    char *cmd = NULL;
    char *reply = NULL;
    int ret = -1;
    char *safename;

    if (!(safename = qemuMonitorEscapeArg(name)) ||
        virAsprintf(&cmd, "delvm \"%s\"", safename) < 0)
        goto cleanup;
    if (qemuMonitorHMPCommand(mon, cmd, &reply))
        goto cleanup;

    if (strstr(reply, "No block device supports snapshots")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this domain does not have a device to delete snapshots"));
        goto cleanup;
    } else if (strstr(reply, "Snapshots not supported on device")) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s", reply);
        goto cleanup;
    } else if (strstr(reply, "Error: ") ||
               (strstr(reply, "Error") &&
                strstr(reply, "while deleting snapshot"))) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to delete snapshot: %s"), reply);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(safename);
    VIR_FREE(cmd);
    VIR_FREE(reply);
    return ret;
}
