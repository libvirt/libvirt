/*
 * qemu_slirp.c: QEMU Slirp support
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
#include "qemu_extdevice.h"
#include "qemu_security.h"
#include "qemu_slirp.h"
#include "virenum.h"
#include "virerror.h"
#include "virjson.h"
#include "virlog.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("qemu.slirp");

VIR_ENUM_IMPL(qemuSlirpFeature,
              QEMU_SLIRP_FEATURE_LAST,
              "",
              "ipv4",
              "ipv6",
              "tftp",
              "dbus-address",
              "dbus-p2p",
              "migrate",
              "restrict",
              "exit-with-parent",
);


void
qemuSlirpFree(qemuSlirp *slirp)
{
    if (!slirp)
        return;

    VIR_FORCE_CLOSE(slirp->fd[0]);
    VIR_FORCE_CLOSE(slirp->fd[1]);
    virBitmapFree(slirp->features);
    g_free(slirp);
}


void
qemuSlirpSetFeature(qemuSlirp *slirp,
                    qemuSlirpFeature feature)
{
    ignore_value(virBitmapSetBit(slirp->features, feature));
}


bool
qemuSlirpHasFeature(const qemuSlirp *slirp,
                    qemuSlirpFeature feature)
{
    return virBitmapIsBitSet(slirp->features, feature);
}


qemuSlirp *
qemuSlirpNew(void)
{
    g_autoptr(qemuSlirp) slirp = g_new0(qemuSlirp, 1);

    slirp->features = virBitmapNew(QEMU_SLIRP_FEATURE_LAST);
    slirp->pid = (pid_t)-1;
    slirp->fd[0] = slirp->fd[1] = -1;

    return g_steal_pointer(&slirp);
}


qemuSlirp *
qemuSlirpNewForHelper(const char *helper)
{
    g_autoptr(qemuSlirp) slirp = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *output = NULL;
    g_autoptr(virJSONValue) doc = NULL;
    virJSONValue *featuresJSON;
    size_t i, nfeatures;

    slirp = qemuSlirpNew();
    if (!slirp) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to allocate slirp for '%1$s'"), helper);
        return NULL;
    }

    cmd = virCommandNewArgList(helper, "--print-capabilities", NULL);
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

        if ((tmp = qemuSlirpFeatureTypeFromString(tmpStr)) <= 0) {
            VIR_WARN("unknown slirp feature %s", tmpStr);
            continue;
        }

        qemuSlirpSetFeature(slirp, tmp);
    }

    return g_steal_pointer(&slirp);
}


static char *
qemuSlirpCreatePidFilename(virQEMUDriverConfig *cfg,
                           const virDomainDef *def,
                           const char *alias)
{
    g_autofree char *shortName = NULL;
    g_autofree char *name = NULL;

    if (!(shortName = virDomainDefGetShortName(def)))
        return NULL;

    name = g_strdup_printf("%s-%s-slirp", shortName, alias);

    return virPidFileBuildPath(cfg->slirpStateDir, name);
}


static int
qemuSlirpOpen(qemuSlirp *slirp,
              virQEMUDriver *driver,
              virDomainDef *def)
{
    int rc, pair[2] = { -1, -1 };

    if (qemuSecuritySetSocketLabel(driver->securityManager, def) < 0)
        goto error;

    rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, pair);

    if (qemuSecurityClearSocketLabel(driver->securityManager, def) < 0)
        goto error;

    if (rc < 0) {
        virReportSystemError(errno, "%s", _("failed to create socketpair"));
        goto error;
    }

    slirp->fd[0] = pair[0];
    slirp->fd[1] = pair[1];

    return 0;

 error:
    VIR_FORCE_CLOSE(pair[0]);
    VIR_FORCE_CLOSE(pair[1]);
    return -1;
}


static char *
qemuSlirpGetDBusVMStateId(virDomainNetDef *net)
{
    char macstr[VIR_MAC_STRING_BUFLEN] = "";

    /* can't use alias, because it's not stable across restarts */
    return g_strdup_printf("slirp-%s", virMacAddrFormat(&net->mac, macstr));
}


void
qemuSlirpStop(qemuSlirp *slirp,
              virDomainObj *vm,
              virQEMUDriver *driver,
              virDomainNetDef *net)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *id = qemuSlirpGetDBusVMStateId(net);
    g_autofree char *pidfile = NULL;
    virErrorPtr orig_err;

    qemuDBusVMStateRemove(vm, id);

    if (!(pidfile = qemuSlirpCreatePidFilename(cfg, vm->def, net->info.alias))) {
        VIR_WARN("Unable to construct slirp pidfile path");
        return;
    }

    virErrorPreserveLast(&orig_err);
    if (virPidFileForceCleanupPath(pidfile) < 0) {
        VIR_WARN("Unable to kill slirp process");
    } else {
        slirp->pid = 0;
    }

    virErrorRestore(&orig_err);
}


int
qemuSlirpSetupCgroup(qemuSlirp *slirp,
                     virCgroup *cgroup)
{
    return virCgroupAddProcess(cgroup, slirp->pid);
}


int
qemuSlirpStart(virDomainObj *vm,
               virDomainNetDef *net,
               bool incoming)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    qemuDomainNetworkPrivate *netpriv = QEMU_DOMAIN_NETWORK_PRIVATE(net);
    qemuSlirp *slirp = netpriv->slirp;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *pidfile = NULL;
    size_t i;
    pid_t pid = (pid_t) -1;
    int rc;
    bool killDBusDaemon = false;
    g_autofree char *fdname = g_strdup_printf("slirpfd-%s", net->info.alias);

    if (!slirp)
        return 0;

    if (incoming &&
        !qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_MIGRATE)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("The slirp-helper doesn't support migration"));
    }

    if (qemuSlirpOpen(slirp, driver, vm->def) < 0)
        return -1;

    if (!(pidfile = qemuSlirpCreatePidFilename(cfg, vm->def, net->info.alias)))
        return -1;

    cmd = virCommandNew(cfg->slirpHelperName);

    virCommandClearCaps(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandDaemonize(cmd);

    virCommandAddArgFormat(cmd, "--fd=%d", slirp->fd[1]);
    virCommandPassFD(cmd, slirp->fd[1],
                     VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    slirp->fd[1] = -1;

    for (i = 0; i < net->guestIP.nips; i++) {
        const virNetDevIPAddr *ip = net->guestIP.ips[i];
        g_autofree char *addr = NULL;
        const char *opt = "";
        unsigned prefix = ip->prefix;

        if (!(addr = virSocketAddrFormat(&ip->address)))
            return -1;

        if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET)) {
            opt = "--net";
            prefix = prefix ?: 24;
        }
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET6)) {
            opt = "--net6";
            prefix = prefix ?: 64;
        }

        virCommandAddArgFormat(cmd, "%s=%s/%u", opt, addr, prefix);
    }

    if (qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_DBUS_ADDRESS)) {
        g_autofree char *id = qemuSlirpGetDBusVMStateId(net);
        g_autofree char *dbus_addr = qemuDBusGetAddress(driver, vm);

        /* If per VM DBus daemon is not running yet, start it
         * now. But if we fail later on, make sure to kill it. */
        killDBusDaemon = !QEMU_DOMAIN_PRIVATE(vm)->dbusDaemonRunning;
        if (qemuDBusStart(driver, vm) < 0)
            return -1;

        virCommandAddArgFormat(cmd, "--dbus-id=%s", id);

        virCommandAddArgFormat(cmd, "--dbus-address=%s", dbus_addr);

        if (qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_MIGRATE)) {
            qemuDBusVMStateAdd(vm, id);

            if (incoming)
                virCommandAddArg(cmd, "--dbus-incoming");
        }
    }

    if (qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_EXIT_WITH_PARENT))
        virCommandAddArg(cmd, "--exit-with-parent");

    if (qemuExtDeviceLogCommand(driver, vm, cmd, "slirp") < 0)
        goto error;

    if (qemuSecurityCommandRun(driver, vm, cmd, -1, -1, false, NULL) < 0)
        goto error;

    rc = virPidFileReadPath(pidfile, &pid);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to read slirp pidfile '%1$s'"),
                             pidfile);
        goto error;
    }

    slirp->pid = pid;

    netpriv->slirpfd = qemuFDPassDirectNew(fdname, &slirp->fd[0]);

    return 0;

 error:
    if (pid != -1)
        virProcessKillPainfully(pid, true);
    if (pidfile)
        unlink(pidfile);
    if (killDBusDaemon)
        qemuDBusStop(driver, vm);
    slirp->pid = 0;
    return -1;
}
