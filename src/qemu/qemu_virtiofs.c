/*
 * qemu_virtiofs.c: virtiofs support
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
#include <fcntl.h>

#include "logging/log_manager.h"
#include "virlog.h"
#include "qemu_command.h"
#include "qemu_conf.h"
#include "qemu_extdevice.h"
#include "qemu_security.h"
#include "qemu_vhost_user.h"
#include "qemu_virtiofs.h"
#include "virpidfile.h"
#include "virqemu.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.virtiofs");


static char *
qemuVirtioFSCreatePidFilenameOld(virDomainObj *vm,
                                 const char *alias)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *name = NULL;

    name = g_strdup_printf("%s-fs", alias);

    return virPidFileBuildPath(priv->libDir, name);
}


char *
qemuVirtioFSCreatePidFilename(virDomainObj *vm,
                              const char *alias)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *domname = virDomainDefGetShortName(vm->def);
    g_autofree char *name = g_strdup_printf("%s-%s-fs", domname, alias);
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);

    return virPidFileBuildPath(cfg->stateDir, name);
}


char *
qemuVirtioFSCreateSocketFilename(virDomainObj *vm,
                                 const char *alias)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    return virFileBuildPath(priv->libDir, alias, "-fs.sock");
}


static char *
qemuVirtioFSCreateLogFilename(virQEMUDriverConfig *cfg,
                              const virDomainDef *def,
                              const char *alias)
{
    g_autofree char *name = NULL;

    name = g_strdup_printf("%s-%s", def->name, alias);

    return virFileBuildPath(cfg->logDir, name, "-virtiofsd.log");
}


static int
qemuVirtioFSOpenChardev(virQEMUDriver *driver,
                        virDomainObj *vm,
                        const char *socket_path)
{
    virDomainChrSourceDef *chrdev = virDomainChrSourceDefNew(NULL);
    virDomainChrDef chr = { .source = chrdev };
    VIR_AUTOCLOSE fd = -1;
    int ret = -1;

    chrdev->type = VIR_DOMAIN_CHR_TYPE_UNIX;
    chrdev->data.nix.listen = true;
    chrdev->data.nix.path = g_strdup(socket_path);

    if (qemuSecuritySetDaemonSocketLabel(driver->securityManager, vm->def) < 0)
        goto cleanup;
    fd = qemuOpenChrChardevUNIXSocket(chrdev);
    if (fd < 0) {
        ignore_value(qemuSecurityClearSocketLabel(driver->securityManager, vm->def));
        goto cleanup;
    }
    if (qemuSecurityClearSocketLabel(driver->securityManager, vm->def) < 0)
        goto cleanup;

    if (qemuSecuritySetChardevLabel(driver, vm, &chr) < 0)
        goto cleanup;

    ret = fd;
    fd = -1;

 cleanup:
    virObjectUnref(chrdev);
    return ret;
}


static virCommand *
qemuVirtioFSBuildCommandLine(virQEMUDriverConfig *cfg,
                             virDomainFSDef *fs,
                             int *fd)
{
    g_autoptr(virCommand) cmd = NULL;
    g_auto(virBuffer) opts = VIR_BUFFER_INITIALIZER;

    cmd = virCommandNew(fs->binary);

    virCommandAddArgFormat(cmd, "--fd=%d", *fd);
    virCommandPassFD(cmd, *fd, VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    *fd = -1;

    virCommandAddArg(cmd, "-o");
    virBufferAddLit(&opts, "source=");
    virQEMUBuildBufferEscapeComma(&opts, fs->src->path);
    if (fs->cache)
        virBufferAsprintf(&opts, ",cache=%s", virDomainFSCacheModeTypeToString(fs->cache));
    if (fs->sandbox)
        virBufferAsprintf(&opts, ",sandbox=%s", virDomainFSSandboxModeTypeToString(fs->sandbox));

    if (fs->xattr == VIR_TRISTATE_SWITCH_ON)
        virBufferAddLit(&opts, ",xattr");
    else if (fs->xattr == VIR_TRISTATE_SWITCH_OFF)
        virBufferAddLit(&opts, ",no_xattr");

    if (fs->flock == VIR_TRISTATE_SWITCH_ON)
        virBufferAddLit(&opts, ",flock");
    else if (fs->flock == VIR_TRISTATE_SWITCH_OFF)
        virBufferAddLit(&opts, ",no_flock");

    if (fs->posix_lock == VIR_TRISTATE_SWITCH_ON)
        virBufferAddLit(&opts, ",posix_lock");
    else if (fs->posix_lock == VIR_TRISTATE_SWITCH_OFF)
        virBufferAddLit(&opts, ",no_posix_lock");

    virCommandAddArgBuffer(cmd, &opts);

    if (fs->thread_pool_size >= 0)
        virCommandAddArgFormat(cmd, "--thread-pool-size=%i", fs->thread_pool_size);

    if (cfg->virtiofsdDebug)
        virCommandAddArg(cmd, "-d");

    return g_steal_pointer(&cmd);
}

int
qemuVirtioFSStart(virQEMUDriver *driver,
                  virDomainObj *vm,
                  virDomainFSDef *fs)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *socket_path = NULL;
    g_autofree char *pidfile = NULL;
    g_autofree char *logpath = NULL;
    pid_t pid = (pid_t) -1;
    VIR_AUTOCLOSE fd = -1;
    VIR_AUTOCLOSE logfd = -1;
    int rc;

    if (!virFileIsExecutable(fs->binary)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virtiofsd binary '%1$s' is not executable"),
                       fs->binary);
        return -1;
    }

    if (!virFileExists(fs->src->path)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("the virtiofs export directory '%1$s' does not exist"),
                       fs->src->path);
        return -1;
    }

    if (!(pidfile = qemuVirtioFSCreatePidFilename(vm, fs->info.alias)))
        goto error;

    socket_path = qemuDomainGetVHostUserFSSocketPath(vm->privateData, fs);

    if ((fd = qemuVirtioFSOpenChardev(driver, vm, socket_path)) < 0)
        goto error;

    logpath = qemuVirtioFSCreateLogFilename(cfg, vm->def, fs->info.alias);

    if (cfg->stdioLogD) {
        g_autoptr(virLogManager) logManager = virLogManagerNew(driver->privileged);

        if (!logManager)
            goto error;

        if ((logfd = virLogManagerDomainOpenLogFile(logManager,
                                                    "qemu",
                                                    vm->def->uuid,
                                                    vm->def->name,
                                                    logpath,
                                                    0,
                                                    NULL, NULL)) < 0)
            goto error;
    } else {
        if ((logfd = open(logpath, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR)) < 0) {
            virReportSystemError(errno, _("failed to create logfile %1$s"),
                                 logpath);
            goto error;
        }
        if (virSetCloseExec(logfd) < 0) {
            virReportSystemError(errno, _("failed to set close-on-exec flag on %1$s"),
                                 logpath);
            goto error;
        }
    }

    if (!(cmd = qemuVirtioFSBuildCommandLine(cfg, fs, &fd)))
        goto error;

    /* so far only running as root is supported */
    virCommandSetUID(cmd, 0);
    virCommandSetGID(cmd, 0);

    virCommandSetPidFile(cmd, pidfile);
    virCommandSetOutputFD(cmd, &logfd);
    virCommandSetErrorFD(cmd, &logfd);
    virCommandNonblockingFDs(cmd);
    virCommandDaemonize(cmd);

    if (cfg->schedCore == QEMU_SCHED_CORE_FULL) {
        pid_t cookie_pid = vm->pid;

        if (cookie_pid <= 0)
            cookie_pid = priv->schedCoreChildPID;

        virCommandSetRunAmong(cmd, cookie_pid);
    }


    if (qemuExtDeviceLogCommand(driver, vm, cmd, "virtiofsd") < 0)
        goto error;

    rc = virCommandRun(cmd, NULL);

    if (rc < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not start 'virtiofsd'"));
        goto error;
    }

    rc = virPidFileReadPath(pidfile, &pid);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to read virtiofsd pidfile '%1$s'"),
                             pidfile);
        goto error;
    }

    if (virProcessKill(pid, 0) != 0) {
        virReportSystemError(errno, "%s",
                             _("virtiofsd died unexpectedly"));
        goto error;
    }

    return 0;

 error:
    if (pid != -1)
        virProcessKillPainfully(pid, true);
    if (pidfile)
        unlink(pidfile);
    if (socket_path)
        unlink(socket_path);
    return -1;
}


void
qemuVirtioFSStop(virQEMUDriver *driver G_GNUC_UNUSED,
                    virDomainObj *vm,
                    virDomainFSDef *fs)
{
    g_autofree char *pidfile = NULL;
    virErrorPtr orig_err;

    virErrorPreserveLast(&orig_err);

    if (!(pidfile = qemuVirtioFSCreatePidFilename(vm, fs->info.alias)))
        goto cleanup;

    if (!virFileExists(pidfile)) {
        g_free(pidfile);
        if (!(pidfile = qemuVirtioFSCreatePidFilenameOld(vm, fs->info.alias)))
            goto cleanup;
    }

    if (virPidFileForceCleanupPathFull(pidfile, true) < 0) {
        VIR_WARN("Unable to kill virtiofsd process");
    } else {
        g_autofree char *socket_path = NULL;

        socket_path = qemuDomainGetVHostUserFSSocketPath(vm->privateData, fs);
        unlink(socket_path);
    }

 cleanup:
    virErrorRestore(&orig_err);
}


int
qemuVirtioFSSetupCgroup(virDomainObj *vm,
                        virDomainFSDef *fs,
                        virCgroup *cgroup)
{
    g_autofree char *pidfile = NULL;
    pid_t pid = -1;
    int rc;

    if (!(pidfile = qemuVirtioFSCreatePidFilename(vm, fs->info.alias)))
        return -1;

    rc = virPidFileReadPathIfAlive(pidfile, &pid, NULL);
    if (rc < 0 || pid == (pid_t) -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("virtiofsd died unexpectedly"));
        return -1;
    }

    if (virCgroupAddProcess(cgroup, pid) < 0)
        return -1;

    return 0;
}

int
qemuVirtioFSPrepareDomain(virQEMUDriver *driver,
                          virDomainFSDef *fs)
{
    if (fs->binary || fs->sock)
        return 0;

    return qemuVhostUserFillDomainFS(driver, fs);
}
