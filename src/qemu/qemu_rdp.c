/*
 * qemu_rdp.c: QEMU Rdp support
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

#include <gio/gio.h>

#include "qemu_dbus.h"
#include "qemu_extdevice.h"
#include "qemu_security.h"
#include "qemu_rdp.h"
#include "virenum.h"
#include "virerror.h"
#include "virjson.h"
#include "virlog.h"
#include "virpidfile.h"
#include "virutil.h"
#include "virgdbus.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("qemu.rdp");

VIR_ENUM_IMPL(qemuRdpFeature,
              QEMU_RDP_FEATURE_LAST,
              "",
              "dbus-address",
              "remotefx"
);

#define ORG_QEMUDISPLAY_RDP "org.QemuDisplay.RDP"
#define ORG_QEMUDISPLAY_RDP_PATH "/org/qemu_display/rdp"
#define ORG_QEMUDISPLAY_RDP_IFACE "org.QemuDisplay.RDP"


void
qemuRdpFree(qemuRdp *rdp)
{
    if (!rdp)
        return;

    virBitmapFree(rdp->features);
    g_free(rdp);
}


void
qemuRdpSetFeature(qemuRdp *rdp,
                  qemuRdpFeature feature)
{
    ignore_value(virBitmapSetBit(rdp->features, feature));
}


bool
qemuRdpHasFeature(const qemuRdp *rdp,
                  qemuRdpFeature feature)
{
    return virBitmapIsBitSet(rdp->features, feature);
}


qemuRdp *
qemuRdpNew(void)
{
    g_autoptr(qemuRdp) rdp = g_new0(qemuRdp, 1);

    rdp->features = virBitmapNew(QEMU_RDP_FEATURE_LAST);
    rdp->pid = -1;

    return g_steal_pointer(&rdp);
}


qemuRdp *
qemuRdpNewForHelper(const char *helper)
{
    g_autoptr(qemuRdp) rdp = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *output = NULL;
    g_autoptr(virJSONValue) doc = NULL;
    virJSONValue *featuresJSON;
    g_autofree char *helperPath = NULL;
    size_t i, nfeatures;

    helperPath = virFindFileInPath(helper);
    if (!helperPath) {
        virReportSystemError(errno,
                             _("'%1$s' is not a suitable qemu-rdp helper name"),
                             helper);
        return NULL;
    }

    rdp = qemuRdpNew();
    cmd = virCommandNewArgList(helperPath, "--print-capabilities", NULL);
    virCommandSetOutputBuffer(cmd, &output);
    if (virCommandRun(cmd, NULL) < 0)
        return NULL;

    if (!(doc = virJSONValueFromString(output)) ||
        !(featuresJSON = virJSONValueObjectGetArray(doc, "features"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse json capabilities '%1$s'"),
                       helper);
        return NULL;
    }

    nfeatures = virJSONValueArraySize(featuresJSON);
    for (i = 0; i < nfeatures; i++) {
        virJSONValue *item = virJSONValueArrayGet(featuresJSON, i);
        const char *tmpStr = virJSONValueGetString(item);
        int tmp;

        if ((tmp = qemuRdpFeatureTypeFromString(tmpStr)) <= 0) {
            VIR_WARN("unknown qemu-rdp feature %s", tmpStr);
            continue;
        }

        qemuRdpSetFeature(rdp, tmp);
    }

    return g_steal_pointer(&rdp);
}


static char *
qemuRdpCreatePidFilename(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autofree char *shortName = virDomainDefGetShortName(vm->def);
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *name = NULL;

    name = g_strdup_printf("%s-rdp", shortName);

    return virPidFileBuildPath(cfg->rdpStateDir, name);
}


void
qemuRdpStop(virDomainObj *vm, virDomainGraphicsDef *gfx)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainGraphicsPrivate *gfxpriv = QEMU_DOMAIN_GRAPHICS_PRIVATE(gfx);
    qemuRdp *rdp = gfxpriv->rdp;
    g_autofree char *pidfile = qemuRdpCreatePidFilename(vm);
    virErrorPtr orig_err;

    if (!rdp)
        return;

    if (rdp->leaving_id) {
        g_dbus_connection_signal_unsubscribe(priv->dbusConnection, rdp->leaving_id);
        rdp->leaving_id = 0;
    }
    g_clear_handle_id(&rdp->name_watch, g_bus_unwatch_name);

    virErrorPreserveLast(&orig_err);

    if (virPidFileForceCleanupPath(pidfile) < 0) {
        VIR_WARN("Unable to kill qemu-rdp process");
    } else {
        rdp->pid = -1;
    }

    virErrorRestore(&orig_err);
}


int
qemuRdpSetupCgroup(qemuRdp *rdp,
                   virCgroup *cgroup)
{
    return virCgroupAddProcess(cgroup, rdp->pid);
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
    qemuRdp *rdp = user_data;
    const gchar *reason;

    g_variant_get(parameters, "(&s)", &reason);
    VIR_DEBUG("%s.Leaving reason: '%s'", ORG_QEMUDISPLAY_RDP_IFACE, reason);
    g_dbus_connection_signal_unsubscribe(connection, rdp->leaving_id);
    rdp->leaving_id = 0;
}


static void
name_appeared_cb(GDBusConnection* connection,
                 const gchar* name G_GNUC_UNUSED,
                 const gchar* name_owner G_GNUC_UNUSED,
                 gpointer user_data G_GNUC_UNUSED)
{
    qemuRdp *rdp = user_data;

    VIR_DEBUG("'%s' appeared", name);
    rdp->name_appeared = true;

    if (!rdp->leaving_id) {
        rdp->leaving_id = g_dbus_connection_signal_subscribe(
            connection,
            ORG_QEMUDISPLAY_RDP,
            ORG_QEMUDISPLAY_RDP_IFACE,
            "Leaving",
            ORG_QEMUDISPLAY_RDP_PATH,
            NULL,
            G_DBUS_SIGNAL_FLAGS_NONE,
            on_leaving_signal,
            rdp,
            NULL);
    }
}


static void
name_vanished_cb(GDBusConnection* connection G_GNUC_UNUSED,
                 const gchar* name G_GNUC_UNUSED,
                 gpointer user_data G_GNUC_UNUSED)
{
    qemuRdp *rdp = user_data;

    if (rdp->name_appeared && rdp->leaving_id) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("'%1$s' vanished unexpectedly"), name);
    }
}


int
qemuRdpStart(virDomainObj *vm, virDomainGraphicsDef *gfx)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    qemuDomainGraphicsPrivate *gfxpriv = QEMU_DOMAIN_GRAPHICS_PRIVATE(gfx);
    qemuRdp *rdp = gfxpriv->rdp;
    virDomainGraphicsListenDef *glisten = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *shortName = virDomainDefGetShortName(vm->def);
    g_autofree char *pidfile = NULL;
    g_autofree char *logname = NULL;
    g_autofree char *certpath = NULL;
    g_autofree char *keypath = NULL;
    g_autofree char *dbus_addr = qemuDBusGetAddress(driver, vm);
    g_auto(virBuffer) bind_addr = VIR_BUFFER_INITIALIZER;
    pid_t pid = -1;
    int logfd = -1;
    g_autoptr(domainLogContext) logContext = NULL;

    if (rdp->pid != -1) {
        return 0;
    }

    if (!dbus_addr) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("no D-Bus address"));
        return -1;
    }

    if (!(glisten = virDomainGraphicsGetListen(gfx, 0))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing listen element"));
        return -1;
    }

    switch (glisten->type) {
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
        if (glisten->address) {
            bool escapeAddr = strchr(glisten->address, ':') != NULL;
            if (escapeAddr)
                virBufferAsprintf(&bind_addr, "[%s]", glisten->address);
            else
                virBufferAdd(&bind_addr, glisten->address, -1);
        }
        virBufferAsprintf(&bind_addr, ":%d",
                          gfx->data.rdp.port);
        break;
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NONE:
    case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unsupported qemu-rdp listen type"));
        return -1;
    }

    if (!(pidfile = qemuRdpCreatePidFilename(vm)))
        return -1;

    logname = g_strdup_printf("%s-qemu-rdp", shortName);
    if (!(logContext = domainLogContextNew(cfg->stdioLogD, cfg->logDir,
                                           QEMU_DRIVER_NAME,
                                           vm, driver->privileged,
                                           logname))) {
        virLastErrorPrefixMessage("%s", _("can't open log context"));
        return -1;
    }

    logfd = domainLogContextGetWriteFD(logContext);

    cmd = virCommandNew(cfg->qemuRdpName);
    virCommandClearCaps(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandSetOutputFD(cmd, &logfd);
    virCommandSetErrorFD(cmd, &logfd);
    virCommandDaemonize(cmd);
    virCommandAddArgPair(cmd, "--dbus-address", dbus_addr);
    virCommandAddArg(cmd, "serve");

    virCommandAddArg(cmd, "--bind-address");
    virCommandAddArgBuffer(cmd, &bind_addr);

    certpath = g_build_filename(cfg->rdpTLSx509certdir, "server-cert.pem", NULL);
    keypath = g_build_filename(cfg->rdpTLSx509certdir, "server-key.pem", NULL);
    if (!virFileExists((certpath))) {
        virReportError(VIR_ERR_OPERATION_FAILED, _("Missing certificate file '%1$s'"), certpath);
        return -1;
    }
    if (!virFileExists((keypath))) {
        virReportError(VIR_ERR_OPERATION_FAILED, _("Missing key file '%1$s'"), keypath);
        return -1;
    }
    virCommandAddArgPair(cmd, "--cert", certpath);
    virCommandAddArgPair(cmd, "--key", keypath);

    rdp->name_watch = g_bus_watch_name_on_connection(priv->dbusConnection,
                                                     ORG_QEMUDISPLAY_RDP,
                                                     G_BUS_NAME_WATCHER_FLAGS_NONE,
                                                     name_appeared_cb,
                                                     name_vanished_cb,
                                                     rdp,
                                                     NULL);

    if (qemuExtDeviceLogCommand(driver, vm, cmd, "qemu-rdp") < 0)
        return -1;

    if (qemuSecurityCommandRun(driver, vm, cmd, -1, -1, false, NULL) < 0)
        goto error;

    if (virPidFileReadPath(pidfile, &pid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to read qemu-rdp pidfile '%1$s'"),
                       pidfile);
        goto error;
    }

    if (virProcessKill(pid, 0) != 0) {
        g_autofree char *msg = NULL;

        if (domainLogContextReadFiltered(logContext, &msg, 1024) < 0)
            VIR_WARN("Unable to read from qemu-rdp log");

        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("qemu-rdp died and reported:\n%1$s"),
                       NULLSTR(msg));
        goto error;
    }

    rdp->pid = pid;

    return 0;

 error:
    g_clear_handle_id(&rdp->name_watch, g_bus_unwatch_name);
    qemuRdpStop(vm, gfx);
    return -1;
}


int
qemuRdpSetCredentials(virDomainObj *vm,
                      const char *username,
                      const char *password,
                      const char *domain)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(GVariant) args = NULL;

    args = g_variant_new("(sss)", username, password, domain);

    return virGDBusCallMethod(priv->dbusConnection,
                              NULL,
                              G_VARIANT_TYPE("()"),
                              NULL,
                              ORG_QEMUDISPLAY_RDP,
                              ORG_QEMUDISPLAY_RDP_PATH,
                              ORG_QEMUDISPLAY_RDP_IFACE,
                              "SetCredentials",
                              args);
}


bool
qemuRdpAvailable(const char *helper)
{
    g_autoptr(qemuRdp) rdp = NULL;

    rdp = qemuRdpNewForHelper(helper);

    return rdp && qemuRdpHasFeature(rdp, QEMU_RDP_FEATURE_DBUS_ADDRESS);
}
