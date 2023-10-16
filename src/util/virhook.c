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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "virerror.h"
#include "virhook.h"
#include "virlog.h"
#include "virfile.h"
#include "configmake.h"
#include "vircommand.h"
#include "virstring.h"
#include "virglibutil.h"

#define VIR_FROM_THIS VIR_FROM_HOOK

VIR_LOG_INIT("util.hook");

#define LIBVIRT_HOOK_DIR SYSCONFDIR "/libvirt/hooks"

VIR_ENUM_DECL(virHookDriver);
VIR_ENUM_DECL(virHookDaemonOp);
VIR_ENUM_DECL(virHookSubop);
VIR_ENUM_DECL(virHookQemuOp);
VIR_ENUM_DECL(virHookLxcOp);
VIR_ENUM_DECL(virHookNetworkOp);
VIR_ENUM_DECL(virHookLibxlOp);
VIR_ENUM_DECL(virHookBhyveOp);

VIR_ENUM_IMPL(virHookDriver,
              VIR_HOOK_DRIVER_LAST,
              "daemon",
              "qemu",
              "lxc",
              "network",
              "libxl",
              "bhyve",
);

VIR_ENUM_IMPL(virHookDaemonOp,
              VIR_HOOK_DAEMON_OP_LAST,
              "start",
              "shutdown",
              "reload",
);

VIR_ENUM_IMPL(virHookSubop,
              VIR_HOOK_SUBOP_LAST,
              "-",
              "begin",
              "end",
);

VIR_ENUM_IMPL(virHookQemuOp,
              VIR_HOOK_QEMU_OP_LAST,
              "start",
              "stopped",
              "prepare",
              "release",
              "migrate",
              "started",
              "reconnect",
              "attach",
              "restore",
);

VIR_ENUM_IMPL(virHookLxcOp,
              VIR_HOOK_LXC_OP_LAST,
              "start",
              "stopped",
              "prepare",
              "release",
              "started",
              "reconnect",
);

VIR_ENUM_IMPL(virHookNetworkOp,
              VIR_HOOK_NETWORK_OP_LAST,
              "start",
              "started",
              "stopped",
              "port-created",
              "port-deleted",
              "updated",
);

VIR_ENUM_IMPL(virHookLibxlOp,
              VIR_HOOK_LIBXL_OP_LAST,
              "start",
              "stopped",
              "prepare",
              "release",
              "migrate",
              "started",
              "reconnect",
);

VIR_ENUM_IMPL(virHookBhyveOp,
              VIR_HOOK_BHYVE_OP_LAST,
              "start",
              "stopped",
              "prepare",
              "release",
              "started",
);

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
    int ret;
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    g_autofree char *path = NULL;
    g_autofree char *dir_path = NULL;

    if (driver == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid hook name for #%1$d"), no);
        return -1;
    }

    path = g_build_filename(LIBVIRT_HOOK_DIR, driver, NULL);

    if (!virFileExists(path)) {
        VIR_DEBUG("No hook script %s", path);
    } else if (!virFileIsExecutable(path)) {
        VIR_WARN("Non-executable hook script %s", path);
    } else {
        VIR_DEBUG("Found hook script %s", path);
        return 1;
    }

    dir_path = g_strdup_printf("%s.d", path);

    if (!virFileIsExecutable(dir_path) && errno != EISDIR) {
        VIR_DEBUG("Hook dir %s is not accessible", dir_path);
        return 0;
    }

    if ((ret = virDirOpenIfExists(&dir, dir_path)) < 0)
        return -1;

    if (!ret) {
        VIR_DEBUG("No hook script dir %s", dir_path);
        return 0;
    }

    while ((ret = virDirRead(dir, &entry, dir_path)) > 0) {
        g_autofree char *entry_path = g_build_filename(dir_path,
                                                       entry->d_name,
                                                       NULL);
        if (!virFileIsExecutable(entry_path)) {
            VIR_WARN("Non-executable hook script %s", entry_path);
            continue;
        }

        VIR_DEBUG("Found hook script %s", entry_path);
        ret = 1;
        break;
    }

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
 * virRunScript:
 * @path: the script path
 * @id: an id for the object '-' if non available for example on daemon hooks
 * @op: the operation on the id
 * @subop: a sub_operation, currently unused
 * @extra: optional string information
 * @input: extra input given to the script on stdin
 * @output: optional address of variable to store malloced result buffer
 *
 * Implement a execution of script. This is a synchronous call, we wait for
 * execution completion. If @output is non-NULL, *output is guaranteed to be
 * allocated after successful virRunScript, and is best-effort allocated after
 * failed virRunScript; the caller is responsible for freeing *output.
 *
 * Returns: 0 if the execution succeeded, -1 if script returned an error
 */
static int
virRunScript(const char *path,
             const char *id,
             const char *op,
             const char *subop,
             const char *extra,
             const char *input,
             char **output)
{
    int ret;
    g_autoptr(virCommand) cmd = NULL;

    VIR_DEBUG("Calling hook %s id=%s op=%s subop=%s extra=%s",
              path, id, op, subop, extra);

    cmd = virCommandNewArgList(path, id, op, subop, extra, NULL);

    virCommandAddEnvPassCommon(cmd);

    if (input)
        virCommandSetInputBuffer(cmd, input);
    if (output)
        virCommandSetOutputBuffer(cmd, output);

    ret = virCommandRun(cmd, NULL);
    if (ret < 0) {
        /* Convert INTERNAL_ERROR into known error.  */
        virReportError(VIR_ERR_HOOK_SCRIPT_FAILED, "%s",
                       virGetLastErrorMessage());
    }

    return ret;
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
 * Implement a hook call, where the external scripts for the driver are
 * called with the given information. This is a synchronous call, we wait for
 * execution completion. If @output is non-NULL, *output is guaranteed to be
 * allocated after successful virHookCall, and is best-effort allocated after
 * failed virHookCall; the caller is responsible for freeing *output.
 *
 * The script from LIBVIRT_HOOK_DIR is executed the first, followed by scripts
 * found under "$driver.d/" directory (sorted alphabetically. If output from
 * the hook script is expected, then the output produced by LIBVIRT_HOOK_DIR
 * script is fed as input to the first script from the "$driver.d/" directory
 * and its output is fed as input to the second and so on.
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
    int ret, script_ret;
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    g_autofree char *path = NULL;
    g_autofree char *dir_path = NULL;
    g_autoptr(virGSListString) entries = NULL;
    const char *drvstr;
    const char *opstr;
    const char *subopstr;
    GSList *next;

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
        case VIR_HOOK_DRIVER_LIBXL:
            opstr = virHookLibxlOpTypeToString(op);
            break;
        case VIR_HOOK_DRIVER_NETWORK:
            opstr = virHookNetworkOpTypeToString(op);
            break;
        case VIR_HOOK_DRIVER_BHYVE:
            opstr = virHookBhyveOpTypeToString(op);
            break;
    }
    if (opstr == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Hook for %1$s, failed to find operation #%2$d"),
                       drvstr, op);
        return 1;
    }
    subopstr = virHookSubopTypeToString(sub_op);
    if (subopstr == NULL)
        subopstr = "-";
    if (extra == NULL)
        extra = "-";

    path = g_build_filename(LIBVIRT_HOOK_DIR, drvstr, NULL);

    script_ret = 1;

    if (virFileIsExecutable(path)) {
        script_ret = virRunScript(path, id, opstr, subopstr, extra,
                                  input, output);
    }

    dir_path = g_strdup_printf("%s.d", path);

    if ((ret = virDirOpenIfExists(&dir, dir_path)) < 0)
        return -1;

    if (!ret)
        return script_ret;

    while ((ret = virDirRead(dir, &entry, dir_path)) > 0) {
        g_autofree char *entry_path = g_build_filename(dir_path,
                                                       entry->d_name,
                                                       NULL);
        if (!virFileIsExecutable(entry_path))
            continue;

        entries = g_slist_prepend(entries, g_steal_pointer(&entry_path));
    }

    if (ret < 0)
        return -1;

    if (!entries)
        return script_ret;

    entries = g_slist_sort(entries, (GCompareFunc) strcmp);

    for (next = entries; next; next = next->next) {
        int entry_ret;
        const char *entry_input;
        g_autofree char *entry_output = NULL;
        const char *filename = next->data;

        /* Get input from previous output */
        entry_input = (!script_ret && output &&
                       !virStringIsEmpty(*output)) ? *output : input;
        entry_ret = virRunScript(filename, id, opstr,
                                 subopstr, extra, entry_input,
                                 (output) ? &entry_output : NULL);
        if (entry_ret < script_ret)
            script_ret = entry_ret;

        /* Replace output to new output from item */
        if (!entry_ret && output && !virStringIsEmpty(entry_output)) {
            g_free(*output);
            *output = g_steal_pointer(&entry_output);
        }
    }

    return script_ret;
}
