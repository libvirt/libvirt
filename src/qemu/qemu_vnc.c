/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include <config.h>

#include <gio/gio.h>

#include "qemu_dbus.h"
#include "qemu_extdevice.h"
#include "qemu_security.h"
#include "qemu_vnc.h"
#include "virerror.h"
#include "virlog.h"
#include "virpidfile.h"
#include "virgdbus.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("qemu.vnc");

#define ORG_QEMU_VNC "org.qemu.vnc"
#define ORG_QEMU_VNC_PATH "/org/qemu/Vnc1/Server"
#define ORG_QEMU_VNC_IFACE "org.qemu.Vnc1.Server"


void
qemuVncFree(qemuVnc *vnc)
{
    if (!vnc)
        return;

    g_free(vnc);
}


qemuVnc *
qemuVncNew(void)
{
    g_autoptr(qemuVnc) vnc = g_new0(qemuVnc, 1);

    vnc->pid = -1;

    return g_steal_pointer(&vnc);
}


static char *
qemuVncCreatePidFilename(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autofree char *shortName = virDomainDefGetShortName(vm->def);
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *name = NULL;

    name = g_strdup_printf("%s-vnc", shortName);

    return virPidFileBuildPath(cfg->vncStateDir, name);
}


void
qemuVncStop(virDomainObj *vm,
            virDomainGraphicsDef *gfx)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainGraphicsPrivate *gfxpriv = QEMU_DOMAIN_GRAPHICS_PRIVATE(gfx);
    qemuVnc *vnc = gfxpriv->vnc;
    g_autofree char *pidfile = qemuVncCreatePidFilename(vm);
    virErrorPtr orig_err;

    if (!vnc)
        return;

    if (vnc->leaving_id) {
        g_dbus_connection_signal_unsubscribe(priv->dbusConnection, vnc->leaving_id);
        vnc->leaving_id = 0;
    }
    g_clear_handle_id(&vnc->name_watch, g_bus_unwatch_name);

    virErrorPreserveLast(&orig_err);

    if (virPidFileForceCleanupPath(pidfile) < 0) {
        VIR_WARN("Unable to kill qemu-vnc process");
    } else {
        vnc->pid = -1;
    }

    virErrorRestore(&orig_err);
}


int
qemuVncSetupCgroup(qemuVnc *vnc,
                   virCgroup *cgroup)
{
    return virCgroupAddProcess(cgroup, vnc->pid);
}


static void
on_leaving_signal(GDBusConnection *connection,
                  const gchar *sender_name G_GNUC_UNUSED,
                  const gchar *object_path G_GNUC_UNUSED,
                  const gchar *interface_name G_GNUC_UNUSED,
                  const gchar *signal_name G_GNUC_UNUSED,
                  GVariant *parameters,
                  gpointer user_data)
{
    qemuVnc *vnc = user_data;
    const gchar *reason;

    g_variant_get(parameters, "(&s)", &reason);
    VIR_DEBUG("%s.Leaving reason: '%s'", ORG_QEMU_VNC_IFACE, reason);
    g_dbus_connection_signal_unsubscribe(connection, vnc->leaving_id);
    vnc->leaving_id = 0;
}


static void
name_appeared_cb(GDBusConnection *connection,
                 const gchar *name G_GNUC_UNUSED,
                 const gchar *name_owner G_GNUC_UNUSED,
                 gpointer user_data)
{
    qemuVnc *vnc = user_data;

    VIR_DEBUG("'%s' appeared", name);
    vnc->name_appeared = true;

    if (!vnc->leaving_id) {
        vnc->leaving_id = g_dbus_connection_signal_subscribe(
            connection,
            ORG_QEMU_VNC,
            ORG_QEMU_VNC_IFACE,
            "Leaving",
            ORG_QEMU_VNC_PATH,
            NULL,
            G_DBUS_SIGNAL_FLAGS_NONE,
            on_leaving_signal,
            vnc,
            NULL);
    }
}


static void
name_vanished_cb(GDBusConnection *connection G_GNUC_UNUSED,
                 const gchar *name,
                 gpointer user_data)
{
    qemuVnc *vnc = user_data;

    if (vnc->name_appeared && vnc->leaving_id) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("'%1$s' vanished unexpectedly"), name);
    }
}


int
qemuVncStart(virDomainObj *vm, virDomainGraphicsDef *gfx)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    qemuDomainGraphicsPrivate *gfxpriv = QEMU_DOMAIN_GRAPHICS_PRIVATE(gfx);
    qemuVnc *vnc = gfxpriv->vnc;
    virDomainGraphicsListenDef *glisten = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *shortName = virDomainDefGetShortName(vm->def);
    g_autofree char *pidfile = NULL;
    g_autofree char *logname = NULL;
    g_autofree char *dbus_addr = qemuDBusGetAddress(driver, vm);
    g_auto(virBuffer) vnc_addr = VIR_BUFFER_INITIALIZER;
    pid_t pid = -1;
    int logfd = -1;
    g_autoptr(domainLogContext) logContext = NULL;

    if (vnc->pid != -1) {
        return 0;
    }

    if (!dbus_addr) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("no D-Bus address"));
        return -1;
    }

    if (!(pidfile = qemuVncCreatePidFilename(vm)))
        return -1;

    logname = g_strdup_printf("%s-qemu-vnc", shortName);
    if (!(logContext = domainLogContextNew(cfg->stdioLogD, cfg->logDir,
                                           QEMU_DRIVER_NAME,
                                           vm, driver->privileged,
                                           logname))) {
        virLastErrorPrefixMessage("%s", _("can't open log context"));
        return -1;
    }

    logfd = domainLogContextGetWriteFD(logContext);

    cmd = virCommandNew(cfg->qemuVncName);
    virCommandClearCaps(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandSetOutputFD(cmd, &logfd);
    virCommandSetErrorFD(cmd, &logfd);
    virCommandDaemonize(cmd);
    virCommandAddArgPair(cmd, "--dbus-address", dbus_addr);
    virCommandAddArgPair(cmd, "--bus-name", "org.qemu");
    virCommandAddArg(cmd, "--wait");

    /* Build VNC listen address */
    if ((glisten = virDomainGraphicsGetListen(gfx, 0))) {
        switch (glisten->type) {
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
            if (glisten->address) {
                bool escapeAddr = strchr(glisten->address, ':') != NULL;
                if (escapeAddr)
                    virBufferAsprintf(&vnc_addr, "[%s]", glisten->address);
                else
                    virBufferAdd(&vnc_addr, glisten->address, -1);
            } else {
                virBufferAddLit(&vnc_addr, "localhost");
            }
            virBufferAsprintf(&vnc_addr, ":%d",
                              gfx->data.vnc.port > 0
                              ? gfx->data.vnc.port - 5900 : 0);
            break;
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
            virBufferAsprintf(&vnc_addr, "unix:%s", glisten->socket);
            break;
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
            virBufferAddLit(&vnc_addr, "none");
            break;
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
        default:
            virBufferAddLit(&vnc_addr, "localhost:0");
            break;
        }

        virCommandAddArg(cmd, "--vnc-addr");
        virCommandAddArgBuffer(cmd, &vnc_addr);
    }

    if (gfx->data.vnc.websocket > 0) {
        g_autofree char *ws = g_strdup_printf("%d", gfx->data.vnc.websocket);
        virCommandAddArgPair(cmd, "--websocket", ws);
    }

    if (gfx->data.vnc.sharePolicy != VIR_DOMAIN_GRAPHICS_VNC_SHARE_DEFAULT) {
        virCommandAddArgPair(cmd, "--share",
                             virDomainGraphicsVNCSharePolicyTypeToString(
                                 gfx->data.vnc.sharePolicy));
    }

    if (gfx->data.vnc.keymap)
        virCommandAddArgPair(cmd, "--keyboard-layout", gfx->data.vnc.keymap);

    if (gfx->data.vnc.auth.passwd || cfg->vncPassword)
        virCommandAddArg(cmd, "--password");

    if (cfg->vncTLS && cfg->vncTLSx509certdir)
        virCommandAddArgPair(cmd, "--tls-creds", cfg->vncTLSx509certdir);

    if (cfg->vncSASL) {
        virCommandAddArg(cmd, "--sasl");

        if (cfg->vncSASLdir)
            virCommandAddEnvPair(cmd, "SASL_CONF_PATH", cfg->vncSASLdir);
    }

    vnc->name_watch = g_bus_watch_name_on_connection(priv->dbusConnection,
                                                     ORG_QEMU_VNC,
                                                     G_BUS_NAME_WATCHER_FLAGS_NONE,
                                                     name_appeared_cb,
                                                     name_vanished_cb,
                                                     vnc,
                                                     NULL);

    if (qemuExtDeviceLogCommand(driver, vm, cmd, "qemu-vnc") < 0)
        goto error;

    if (qemuSecurityCommandRun(driver, vm, cmd, -1, -1, false, NULL) < 0)
        goto error;

    if (virPidFileReadPath(pidfile, &pid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to read qemu-vnc pidfile '%1$s'"),
                       pidfile);
        goto error;
    }

    if (virProcessKill(pid, 0) != 0) {
        g_autofree char *msg = NULL;

        if (domainLogContextReadFiltered(logContext, &msg, 1024) < 0)
            VIR_WARN("Unable to read from qemu-vnc log");

        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("qemu-vnc died and reported:\n%1$s"),
                       NULLSTR(msg));
        goto error;
    }

    vnc->pid = pid;

    return 0;

 error:
    g_clear_handle_id(&vnc->name_watch, g_bus_unwatch_name);
    qemuVncStop(vm, gfx);
    return -1;
}


int
qemuVncSetPassword(virDomainObj *vm,
                   const char *password)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(GVariant) args = NULL;

    args = g_variant_new("(s)", password);

    return virGDBusCallMethod(priv->dbusConnection,
                              NULL,
                              G_VARIANT_TYPE("()"),
                              NULL,
                              ORG_QEMU_VNC,
                              ORG_QEMU_VNC_PATH,
                              ORG_QEMU_VNC_IFACE,
                              "SetPassword",
                              args);
}


int
qemuVncReloadCertificates(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    return virGDBusCallMethod(priv->dbusConnection,
                              NULL,
                              G_VARIANT_TYPE("()"),
                              NULL,
                              ORG_QEMU_VNC,
                              ORG_QEMU_VNC_PATH,
                              ORG_QEMU_VNC_IFACE,
                              "ReloadCertificates",
                              NULL);
}


int
qemuVncAddClient(virDomainObj *vm,
                 int fd,
                 bool skipauth)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(GUnixFDList) fdlist = NULL;
    g_autoptr(GVariant) args = NULL;
    gint fd_idx;

    fdlist = g_unix_fd_list_new();
    fd_idx = g_unix_fd_list_append(fdlist, fd, NULL);
    if (fd_idx < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to append FD to list"));
        return -1;
    }

    args = g_variant_new("(hb)", fd_idx, skipauth);

    return virGDBusCallMethodWithFD(priv->dbusConnection,
                                    NULL,
                                    G_VARIANT_TYPE("()"),
                                    NULL,
                                    NULL,
                                    ORG_QEMU_VNC,
                                    ORG_QEMU_VNC_PATH,
                                    ORG_QEMU_VNC_IFACE,
                                    "AddClient",
                                    args,
                                    fdlist);
}


/**
 * qemuVncAvailable:
 * @helper: name (or path to) 'qemu-vnc' binary
 *
 * Returns whether 'qemu-vnc' is available.
 *
 * Important:
 * This function is called from 'virQEMUDriverGetDomainCapabilities'. It must
 * not report any errors and must not add any additional checks.
 *
 * This function is mocked from 'tests/testutilsqemu.c'
 */
bool
qemuVncAvailable(const char *helper)
{
    g_autofree char *helperPath = NULL;

    return !!(helperPath = virFindFileInPath(helper));
}
