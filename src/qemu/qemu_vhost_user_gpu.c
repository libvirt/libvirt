/*
 * qemu_vhost_user_gpu.c: QEMU vhost-user GPU support
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#include "qemu_vhost_user_gpu.h"
#include "qemu_vhost_user.h"
#include "qemu_extdevice.h"

#include "conf/domain_conf.h"
#include "configmake.h"
#include "vircommand.h"
#include "virlog.h"
#include "virfile.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("qemu.vhost_user_gpu");


static char *
qemuVhostUserGPUCreatePidFilename(const char *stateDir,
                                  const char *shortName,
                                  const char *alias)
{
    g_autofree char *devicename = NULL;

    devicename = g_strdup_printf("%s-%s-vhost-user-gpu", shortName, alias);

    return virPidFileBuildPath(stateDir, devicename);
}


/*
 * qemuVhostUserGPUGetPid:
 * @stateDir: the directory where vhost-user-gpu writes the pidfile into
 * @shortName: short name of the domain
 * @alias: video device alias
 * @pid: pointer to pid
 *
 * Return -1 upon error, or zero on successful reading of the pidfile.
 * If the PID was not still alive, zero will be returned, and @pid will be
 * set to -1;
 */
static int
qemuVhostUserGPUGetPid(const char *stateDir,
                       const char *shortName,
                       const char *alias,
                       pid_t *pid)
{
    g_autofree char *pidfile = NULL;

    if (!(pidfile = qemuVhostUserGPUCreatePidFilename(stateDir, shortName, alias)))
        return -1;

    if (virPidFileReadPathIfLocked(pidfile, pid) < 0)
        return -1;

    return 0;
}


int qemuExtVhostUserGPUPrepareDomain(virQEMUDriver *driver,
                                     virDomainVideoDef *video)
{
    return qemuVhostUserFillDomainGPU(driver, video);
}


/*
 * qemuExtVhostUserGPUStart:
 * @driver: QEMU driver
 * @vm: the VM domain
 * @video: the video device
 *
 * Start the external vhost-user-gpu process:
 * - open a socketpair for vhost-user communication
 * - have the command line built
 * - start the external process and sync with it before QEMU start
 */
int qemuExtVhostUserGPUStart(virQEMUDriver *driver,
                             virDomainObj *vm,
                             virDomainVideoDef *video)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *shortname = NULL;
    g_autofree char *pidfile = NULL;
    g_autoptr(virCommand) cmd = NULL;
    int pair[2] = { -1, -1 };
    int rc;
    pid_t pid;
    int ret = -1;

    shortname = virDomainDefGetShortName(vm->def);
    if (!shortname)
        goto error;

    /* stop any left-over for this VM */
    qemuExtVhostUserGPUStop(driver, vm, video);

    if (!(pidfile = qemuVhostUserGPUCreatePidFilename(
              cfg->stateDir, shortname, video->info.alias)))
        goto error;

    if (qemuSecuritySetSocketLabel(driver->securityManager, vm->def) < 0)
        goto error;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
        virReportSystemError(errno, "%s", _("failed to create socket"));
        goto error;
    }

    if (qemuSecurityClearSocketLabel(driver->securityManager, vm->def) < 0)
        goto error;

    cmd = virCommandNew(video->driver->vhost_user_binary);

    virCommandClearCaps(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandDaemonize(cmd);

    if (qemuExtDeviceLogCommand(driver, vm, cmd, "vhost-user-gpu") < 0)
        goto error;

    virCommandAddArgFormat(cmd, "--fd=%d", pair[0]);
    virCommandPassFD(cmd, pair[0], VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    pair[0] = -1;

    if (video->accel) {
        if (video->accel->accel3d)
            virCommandAddArg(cmd, "--virgl");

        if (video->accel->rendernode)
            virCommandAddArgFormat(cmd, "--render-node=%s", video->accel->rendernode);
    }

    if (qemuSecurityCommandRun(driver, vm, cmd, -1, -1, false, NULL) < 0)
        goto error;

    rc = virPidFileReadPath(pidfile, &pid);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to read vhost-user-gpu pidfile '%1$s'"),
                             pidfile);
        goto cleanup;
    }

    ret = 0;
    QEMU_DOMAIN_VIDEO_PRIVATE(video)->vhost_user_fd = pair[1];
    pair[1] = -1;

 cleanup:
    VIR_FORCE_CLOSE(pair[0]);
    VIR_FORCE_CLOSE(pair[1]);

    return ret;

 error:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("vhost-user-gpu failed to start"));
    goto cleanup;
}


/*
 * qemuExtVhostUserGPUStop:
 *
 * @driver: QEMU driver
 * @vm: the VM domain
 * @video: the video device
 *
 * Check if vhost-user process pidfile is around, kill the process,
 * and remove the pidfile.
 */
void qemuExtVhostUserGPUStop(virQEMUDriver *driver,
                             virDomainObj *vm,
                             virDomainVideoDef *video)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *pidfile = NULL;
    g_autofree char *shortname = NULL;
    virErrorPtr orig_err;

    shortname = virDomainDefGetShortName(vm->def);
    if (!(pidfile = qemuVhostUserGPUCreatePidFilename(
              cfg->stateDir, shortname, video->info.alias))) {
        VIR_WARN("Unable to construct vhost-user-gpu pidfile path");
        return;
    }

    virErrorPreserveLast(&orig_err);
    if (virPidFileForceCleanupPath(pidfile) < 0)
        VIR_WARN("Unable to kill vhost-user-gpu process");
    virErrorRestore(&orig_err);
}


/*
 * qemuExtVhostUserGPUSetupCgroup:
 *
 * @driver: QEMU driver
 * @def: domain definition
 * @video: the video device
 * @cgroupe: a cgroup
 *
 * Add the vhost-user-gpu PID to the given cgroup.
 */
int
qemuExtVhostUserGPUSetupCgroup(virQEMUDriver *driver,
                               virDomainDef *def,
                               virDomainVideoDef *video,
                               virCgroup *cgroup)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *shortname = NULL;
    int rc;
    pid_t pid;

    shortname = virDomainDefGetShortName(def);
    if (!shortname)
        return -1;

    rc = qemuVhostUserGPUGetPid(cfg->stateDir, shortname, video->info.alias, &pid);
    if (rc < 0 || (rc == 0 && pid == (pid_t)-1)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not get process id of vhost-user-gpu"));
        return -1;
    }
    if (virCgroupAddProcess(cgroup, pid) < 0)
        return -1;

    return 0;
}
