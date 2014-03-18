/*
 * virhook.c: implementation of the synchronous hooks support
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2010 Daniel Veillard
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
 * Author: Daniel Veillard <veillard@redhat.com>
 */

#include <config.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "virerror.h"
#include "virhook.h"
#include "virutil.h"
#include "virlog.h"
#include "viralloc.h"
#include "virfile.h"
#include "configmake.h"
#include "vircommand.h"

#define VIR_FROM_THIS VIR_FROM_HOOK

VIR_LOG_INIT("util.hook");

#define LIBVIRT_HOOK_DIR SYSCONFDIR "/libvirt/hooks"

VIR_ENUM_DECL(virHookDriver)
VIR_ENUM_DECL(virHookDaemonOp)
VIR_ENUM_DECL(virHookSubop)
VIR_ENUM_DECL(virHookQemuOp)
VIR_ENUM_DECL(virHookLxcOp)
VIR_ENUM_DECL(virHookNetworkOp)

VIR_ENUM_IMPL(virHookDriver,
              VIR_HOOK_DRIVER_LAST,
              "daemon",
              "qemu",
              "lxc",
              "network")

VIR_ENUM_IMPL(virHookDaemonOp, VIR_HOOK_DAEMON_OP_LAST,
              "start",
              "shutdown",
              "reload")

VIR_ENUM_IMPL(virHookSubop, VIR_HOOK_SUBOP_LAST,
              "-",
              "begin",
              "end")

VIR_ENUM_IMPL(virHookQemuOp, VIR_HOOK_QEMU_OP_LAST,
              "start",
              "stopped",
              "prepare",
              "release",
              "migrate",
              "started",
              "reconnect",
              "attach")

VIR_ENUM_IMPL(virHookLxcOp, VIR_HOOK_LXC_OP_LAST,
              "start",
              "stopped",
              "prepare",
              "release",
              "started",
              "reconnect")

VIR_ENUM_IMPL(virHookNetworkOp, VIR_HOOK_NETWORK_OP_LAST,
              "start",
              "started",
              "stopped",
              "plugged",
              "unplugged")

static int virHooksFound = -1;

/**
 * virHookCheck:
 * @driver: the driver name "daemon", "qemu", "lxc"...
 *
 * Check is there is an installed hook for the given driver, if this
 * is the case register it. Then subsequent calls to virHookCall
 * will call the hook if found.
 *
 * Returns 1 if found, 0 if not found, and -1 in case of error
 */
static int
virHookCheck(int no, const char *driver)
{
    char *path;
    int ret;

    if (driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid hook name for #%d"), no);
        return -1;
    }

    ret = virBuildPath(&path, LIBVIRT_HOOK_DIR, driver);
    if ((ret < 0) || (path == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to build path for %s hook"),
                       driver);
        return -1;
    }

    if (!virFileExists(path)) {
        ret = 0;
        VIR_DEBUG("No hook script %s", path);
    } else if (!virFileIsExecutable(path)) {
        ret = 0;
        VIR_WARN("Non-executable hook script %s", path);
    } else {
        ret = 1;
        VIR_DEBUG("Found hook script %s", path);
    }

    VIR_FREE(path);
    return ret;
}

/*
 * virHookInitialize:
 *
 * Initialize synchronous hooks support.
 * Check is there is an installed hook for all the drivers
 *
 * Returns the number of hooks found or -1 in case of failure
 */
int
virHookInitialize(void)
{
    size_t i;
    int res, ret = 0;

    virHooksFound = 0;
    for (i = 0; i < VIR_HOOK_DRIVER_LAST; i++) {
        res = virHookCheck(i, virHookDriverTypeToString(i));
        if (res < 0)
            return -1;

        if (res == 1) {
            virHooksFound |= (1 << i);
            ret++;
        }
    }
    return ret;
}

/**
 * virHookPresent:
 * @driver: the driver number (from virHookDriver enum)
 *
 * Check if a hook exists for the given driver, this is needed
 * to avoid unnecessary work if the hook is not present
 *
 * Returns 1 if present, 0 otherwise
 */
int
virHookPresent(int driver)
{
    if ((driver < VIR_HOOK_DRIVER_DAEMON) ||
        (driver >= VIR_HOOK_DRIVER_LAST))
        return 0;
    if (virHooksFound == -1)
        return 0;

    if ((virHooksFound & (1 << driver)) == 0)
        return 0;
    return 1;
}

/**
 * virHookCall:
 * @driver: the driver number (from virHookDriver enum)
 * @id: an id for the object '-' if non available for example on daemon hooks
 * @op: the operation on the id e.g. VIR_HOOK_QEMU_OP_START
 * @sub_op: a sub_operation, currently unused
 * @extra: optional string information
 * @input: extra input given to the script on stdin
 * @output: optional address of variable to store malloced result buffer
 *
 * Implement a hook call, where the external script for the driver is
 * called with the given information. This is a synchronous call, we wait for
 * execution completion. If @output is non-NULL, *output is guaranteed to be
 * allocated after successful virHookCall, and is best-effort allocated after
 * failed virHookCall; the caller is responsible for freeing *output.
 *
 * Returns: 0 if the execution succeeded, 1 if the script was not found or
 *          invalid parameters, and -1 if script returned an error
 */
int
virHookCall(int driver,
            const char *id,
            int op,
            int sub_op,
            const char *extra,
            const char *input,
            char **output)
{
    int ret;
    char *path;
    virCommandPtr cmd;
    const char *drvstr;
    const char *opstr;
    const char *subopstr;

    if (output)
        *output = NULL;

    if ((driver < VIR_HOOK_DRIVER_DAEMON) ||
        (driver >= VIR_HOOK_DRIVER_LAST))
        return 1;

    /*
     * We cache the availability of the script to minimize impact at
     * runtime if no script is defined, this is being reset on SIGHUP
     */
    if ((virHooksFound == -1) ||
        ((driver == VIR_HOOK_DRIVER_DAEMON) &&
         (op == VIR_HOOK_DAEMON_OP_RELOAD ||
         op == VIR_HOOK_DAEMON_OP_SHUTDOWN)))
        virHookInitialize();

    if ((virHooksFound & (1 << driver)) == 0)
        return 1;

    drvstr = virHookDriverTypeToString(driver);

    opstr = NULL;
    switch (driver) {
        case VIR_HOOK_DRIVER_DAEMON:
            opstr = virHookDaemonOpTypeToString(op);
            break;
        case VIR_HOOK_DRIVER_QEMU:
            opstr = virHookQemuOpTypeToString(op);
            break;
        case VIR_HOOK_DRIVER_LXC:
            opstr = virHookLxcOpTypeToString(op);
            break;
        case VIR_HOOK_DRIVER_NETWORK:
            opstr = virHookNetworkOpTypeToString(op);
    }
    if (opstr == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Hook for %s, failed to find operation #%d"),
                       drvstr, op);
        return 1;
    }
    subopstr = virHookSubopTypeToString(sub_op);
    if (subopstr == NULL)
        subopstr = "-";
    if (extra == NULL)
        extra = "-";

    ret = virBuildPath(&path, LIBVIRT_HOOK_DIR, drvstr);
    if ((ret < 0) || (path == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to build path for %s hook"),
                       drvstr);
        return -1;
    }

    VIR_DEBUG("Calling hook opstr=%s subopstr=%s extra=%s",
              opstr, subopstr, extra);

    cmd = virCommandNewArgList(path, id, opstr, subopstr, extra, NULL);

    virCommandAddEnvPassCommon(cmd);

    if (input)
        virCommandSetInputBuffer(cmd, input);
    if (output)
        virCommandSetOutputBuffer(cmd, output);

    ret = virCommandRun(cmd, NULL);
    if (ret < 0) {
        /* Convert INTERNAL_ERROR into known error.  */
        virErrorPtr err = virGetLastError();
        virReportError(VIR_ERR_HOOK_SCRIPT_FAILED, "%s", err->message);
    }

    virCommandFree(cmd);

    VIR_FREE(path);

    return ret;
}
