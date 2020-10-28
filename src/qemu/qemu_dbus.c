/*
 * qemu_dbus.c: QEMU dbus daemon
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

#include "qemu_extdevice.h"
#include "qemu_dbus.h"
#include "qemu_security.h"

#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"
#include "virtime.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("qemu.dbus");


static char *
qemuDBusCreatePidFilename(virQEMUDriverConfigPtr cfg,
                          const char *shortName)
{
    g_autofree char *name = g_strdup_printf("%s-dbus", shortName);

    return virPidFileBuildPath(cfg->dbusStateDir, name);
}


static char *
qemuDBusCreateFilename(const char *stateDir,
                       const char *shortName,
                       const char *ext)
{
    g_autofree char *name = g_strdup_printf("%s-dbus", shortName);

    return virFileBuildPath(stateDir, name,  ext);
}


static char *
qemuDBusCreateSocketPath(virQEMUDriverConfigPtr cfg,
                         const char *shortName)
{
    return qemuDBusCreateFilename(cfg->dbusStateDir, shortName, ".sock");
}


static char *
qemuDBusCreateConfPath(virQEMUDriverConfigPtr cfg,
                       const char *shortName)
{
    return qemuDBusCreateFilename(cfg->dbusStateDir, shortName, ".conf");
}


char *
qemuDBusGetAddress(virQEMUDriverPtr driver,
                   virDomainObjPtr vm)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *shortName = virDomainDefGetShortName(vm->def);
    g_autofree char *path = NULL;

    if (!shortName)
        return NULL;

    path = qemuDBusCreateSocketPath(cfg, shortName);

    return g_strdup_printf("unix:path=%s", path);
}


static int
qemuDBusWriteConfig(const char *filename, const char *path)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *config = NULL;

    virBufferAddLit(&buf, "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n");
    virBufferAddLit(&buf, "  \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n");
    virBufferAddLit(&buf, "<busconfig>\n");
    virBufferAdjustIndent(&buf, 2);

    virBufferAddLit(&buf, "<type>org.libvirt.qemu</type>\n");
    virBufferAsprintf(&buf, "<listen>unix:path=%s</listen>\n", path);
    virBufferAddLit(&buf, "<auth>EXTERNAL</auth>\n");

    virBufferAddLit(&buf, "<policy context='default'>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferAddLit(&buf, "<!-- Allow everything to be sent -->\n");
    virBufferAddLit(&buf, "<allow send_destination='*' eavesdrop='true'/>\n");
    virBufferAddLit(&buf, "<!-- Allow everything to be received -->\n");
    virBufferAddLit(&buf, "<allow eavesdrop='true'/>\n");
    virBufferAddLit(&buf, "<!-- Allow anyone to own anything -->\n");
    virBufferAddLit(&buf, "<allow own='*'/>\n");
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</policy>\n");

    virBufferAddLit(&buf, "<include if_selinux_enabled='yes' selinux_root_relative='yes'>contexts/dbus_contexts</include>\n");

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</busconfig>\n");

    config = virBufferContentAndReset(&buf);

    return virFileWriteStr(filename, config, 0600);
}


void
qemuDBusStop(virQEMUDriverPtr driver,
             virDomainObjPtr vm)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autofree char *shortName = NULL;
    g_autofree char *pidfile = NULL;

    if (!(shortName = virDomainDefGetShortName(vm->def)))
        return;

    pidfile = qemuDBusCreatePidFilename(cfg, shortName);

    if (virPidFileForceCleanupPath(pidfile) < 0) {
        VIR_WARN("Unable to kill dbus-daemon process");
    } else {
        priv->dbusDaemonRunning = false;
    }
}


int
qemuDBusSetupCgroup(virQEMUDriverPtr driver,
                    virDomainObjPtr vm,
                    virCgroupPtr cgroup)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autofree char *shortName = NULL;
    g_autofree char *pidfile = NULL;
    pid_t cpid = -1;

    if (!priv->dbusDaemonRunning)
        return 0;

    if (!(shortName = virDomainDefGetShortName(vm->def)))
        return -1;
    pidfile = qemuDBusCreatePidFilename(cfg, shortName);
    if (virPidFileReadPath(pidfile, &cpid) < 0) {
        VIR_WARN("Unable to get DBus PID");
        return -1;
    }

    return virCgroupAddProcess(cgroup, cpid);
}

int
qemuDBusStart(virQEMUDriverPtr driver,
              virDomainObjPtr vm)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *shortName = NULL;
    g_autofree char *pidfile = NULL;
    g_autofree char *configfile = NULL;
    g_autofree char *sockpath = NULL;
    virTimeBackOffVar timebackoff;
    const unsigned long long timeout = 500 * 1000; /* ms */
    VIR_AUTOCLOSE errfd = -1;
    int cmdret = 0;
    int exitstatus = 0;
    pid_t cpid = -1;
    int ret = -1;

    if (priv->dbusDaemonRunning)
        return 0;

    if (!virFileIsExecutable(cfg->dbusDaemonName)) {
        virReportSystemError(errno,
                             _("'%s' is not a suitable dbus-daemon"),
                             cfg->dbusDaemonName);
        return -1;
    }

    if (!(shortName = virDomainDefGetShortName(vm->def)))
        return -1;

    pidfile = qemuDBusCreatePidFilename(cfg, shortName);
    configfile = qemuDBusCreateConfPath(cfg, shortName);
    sockpath = qemuDBusCreateSocketPath(cfg, shortName);

    if (qemuDBusWriteConfig(configfile, sockpath) < 0) {
        virReportSystemError(errno, _("Failed to write '%s'"), configfile);
        return -1;
    }

    if (qemuSecurityDomainSetPathLabel(driver, vm, configfile, false) < 0)
        goto cleanup;

    cmd = virCommandNew(cfg->dbusDaemonName);
    virCommandClearCaps(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandSetErrorFD(cmd, &errfd);
    virCommandDaemonize(cmd);
    virCommandAddArgFormat(cmd, "--config-file=%s", configfile);

    if (qemuSecurityCommandRun(driver, vm, cmd, -1, -1,
                               &exitstatus, &cmdret) < 0)
        goto cleanup;

    if (cmdret < 0 || exitstatus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not start dbus-daemon. exitstatus: %d"), exitstatus);
        goto cleanup;
    }

    if (virPidFileReadPath(pidfile, &cpid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("dbus-daemon %s didn't show up"),
                       cfg->dbusDaemonName);
        goto cleanup;
    }

    if (virTimeBackOffStart(&timebackoff, 1, timeout) < 0)
        goto cleanup;
    while (virTimeBackOffWait(&timebackoff)) {
        char errbuf[1024] = { 0 };

        if (virFileExists(sockpath))
            break;

        if (virProcessKill(cpid, 0) == 0)
            continue;

        if (saferead(errfd, errbuf, sizeof(errbuf) - 1) < 0) {
            virReportSystemError(errno,
                                 _("dbus-daemon %s died unexpectedly"),
                                 cfg->dbusDaemonName);
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("dbus-daemon died and reported: %s"), errbuf);
        }

        goto cleanup;
    }

    if (!virFileExists(sockpath)) {
        virReportError(VIR_ERR_OPERATION_TIMEOUT,
                       _("DBus daemon %s didn't show up"),
                       cfg->dbusDaemonName);
        goto cleanup;
    }

    if (qemuSecurityDomainSetPathLabel(driver, vm, sockpath, false) < 0)
        goto cleanup;

    priv->dbusDaemonRunning = true;
    ret = 0;
 cleanup:
    if (ret < 0) {
        virCommandAbort(cmd);
        if (cpid >= 0)
            virProcessKillPainfully(cpid, true);
        unlink(pidfile);
        unlink(configfile);
        unlink(sockpath);
    }
    return ret;
}


int
qemuDBusVMStateAdd(virDomainObjPtr vm, const char *id)
{
    return virStringListAdd(&QEMU_DOMAIN_PRIVATE(vm)->dbusVMStateIds, id);
}


void
qemuDBusVMStateRemove(virDomainObjPtr vm, const char *id)
{
    virStringListRemove(&QEMU_DOMAIN_PRIVATE(vm)->dbusVMStateIds, id);
}
