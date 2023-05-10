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

#include "qemu_dbus.h"
#include "qemu_security.h"

#include "virlog.h"
#include "virtime.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("qemu.dbus");


static char *
qemuDBusCreatePidFilename(virQEMUDriverConfig *cfg,
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
qemuDBusCreateSocketPath(virQEMUDriverConfig *cfg,
                         const char *shortName)
{
    return qemuDBusCreateFilename(cfg->dbusStateDir, shortName, ".sock");
}


static char *
qemuDBusCreateConfPath(virQEMUDriverConfig *cfg,
                       const char *shortName)
{
    return qemuDBusCreateFilename(cfg->dbusStateDir, shortName, ".conf");
}


char *
qemuDBusGetAddress(virQEMUDriver *driver,
                   virDomainObj *vm)
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
qemuDBusStop(virQEMUDriver *driver,
             virDomainObj *vm)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
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
qemuDBusSetupCgroup(virQEMUDriver *driver,
                    virDomainObj *vm,
                    virCgroup *cgroup)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
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
qemuDBusStart(virQEMUDriver *driver,
              virDomainObj *vm)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *dbusDaemonPath = NULL;
    g_autofree char *shortName = NULL;
    g_autofree char *pidfile = NULL;
    g_autofree char *configfile = NULL;
    g_autofree char *sockpath = NULL;
    virTimeBackOffVar timebackoff;
    const unsigned long long timeout = 500 * 1000; /* ms */
    VIR_AUTOCLOSE errfd = -1;
    pid_t cpid = -1;
    int ret = -1;

    if (priv->dbusDaemonRunning)
        return 0;

    dbusDaemonPath = virFindFileInPath(cfg->dbusDaemonName);
    if (!dbusDaemonPath) {
        virReportSystemError(errno,
                             _("'%1$s' is not a suitable dbus-daemon"),
                             cfg->dbusDaemonName);
        return -1;
    }

    VIR_DEBUG("Using dbus-daemon: %s", dbusDaemonPath);

    if (!(shortName = virDomainDefGetShortName(vm->def)))
        return -1;

    pidfile = qemuDBusCreatePidFilename(cfg, shortName);
    configfile = qemuDBusCreateConfPath(cfg, shortName);
    sockpath = qemuDBusCreateSocketPath(cfg, shortName);

    if (qemuDBusWriteConfig(configfile, sockpath) < 0) {
        virReportSystemError(errno, _("Failed to write '%1$s'"), configfile);
        return -1;
    }

    if (qemuSecurityDomainSetPathLabel(driver, vm, configfile, false) < 0)
        goto cleanup;

    cmd = virCommandNew(dbusDaemonPath);
    virCommandClearCaps(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandSetErrorFD(cmd, &errfd);
    virCommandDaemonize(cmd);
    virCommandAddArgFormat(cmd, "--config-file=%s", configfile);

    if (qemuSecurityCommandRun(driver, vm, cmd, -1, -1, false, NULL) < 0)
        goto cleanup;

    if (virPidFileReadPath(pidfile, &cpid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("dbus-daemon %1$s didn't show up"),
                       dbusDaemonPath);
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
                                 _("dbus-daemon %1$s died unexpectedly"),
                                 dbusDaemonPath);
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("dbus-daemon died and reported: %1$s"), errbuf);
        }

        goto cleanup;
    }

    if (!virFileExists(sockpath)) {
        virReportError(VIR_ERR_OPERATION_TIMEOUT,
                       _("dbus-daemon %1$s didn't show up"),
                       dbusDaemonPath);
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


void
qemuDBusVMStateAdd(virDomainObj *vm, const char *id)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    priv->dbusVMStateIds = g_slist_append(priv->dbusVMStateIds, g_strdup(id));
}


void
qemuDBusVMStateRemove(virDomainObj *vm, const char *id)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    GSList *next;

    for (next = priv->dbusVMStateIds; next; next = next->next) {
        const char *elem = next->data;

        if (STREQ(id, elem)) {
            priv->dbusVMStateIds = g_slist_remove_link(priv->dbusVMStateIds, next);
            g_slist_free_full(next, g_free);
            break;
        }
    }
}
