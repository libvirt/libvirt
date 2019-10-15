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
#include "viralloc.h"
#include "virenum.h"
#include "virerror.h"
#include "virjson.h"
#include "virlog.h"
#include "virpidfile.h"
#include "virstring.h"
#include "virtime.h"

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
qemuSlirpFree(qemuSlirpPtr slirp)
{
    if (!slirp)
        return;

    VIR_FORCE_CLOSE(slirp->fd[0]);
    VIR_FORCE_CLOSE(slirp->fd[1]);
    virBitmapFree(slirp->features);
    VIR_FREE(slirp);
}


void
qemuSlirpSetFeature(qemuSlirpPtr slirp,
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


qemuSlirpPtr
qemuSlirpNew(void)
{
    g_autoptr(qemuSlirp) slirp = NULL;

    if (VIR_ALLOC(slirp) < 0 ||
        !(slirp->features = virBitmapNew(QEMU_SLIRP_FEATURE_LAST)))
        return NULL;

    slirp->pid = (pid_t)-1;
    slirp->fd[0] = slirp->fd[1] = -1;

    VIR_RETURN_PTR(slirp);
}


qemuSlirpPtr
qemuSlirpNewForHelper(const char *helper)
{
    g_autoptr(qemuSlirp) slirp = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *output = NULL;
    g_autoptr(virJSONValue) doc = NULL;
    virJSONValuePtr featuresJSON;
    size_t i, nfeatures;

    if (!helper)
        return NULL;

    slirp = qemuSlirpNew();
    if (!slirp) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to allocate slirp for '%s'"), helper);
        return NULL;
    }

    cmd = virCommandNewArgList(helper, "--print-capabilities", NULL);
    virCommandSetOutputBuffer(cmd, &output);
    if (virCommandRun(cmd, NULL) < 0)
        return NULL;

    if (!(doc = virJSONValueFromString(output)) ||
        !(featuresJSON = virJSONValueObjectGetArray(doc, "features"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to parse json capabilities '%s'"),
                       helper);
        return NULL;
    }

    nfeatures = virJSONValueArraySize(featuresJSON);
    for (i = 0; i < nfeatures; i++) {
        virJSONValuePtr item = virJSONValueArrayGet(featuresJSON, i);
        const char *tmpStr = virJSONValueGetString(item);
        int tmp;

        if ((tmp = qemuSlirpFeatureTypeFromString(tmpStr)) <= 0) {
            VIR_WARN("unknown slirp feature %s", tmpStr);
            continue;
        }

        qemuSlirpSetFeature(slirp, tmp);
    }

    VIR_RETURN_PTR(slirp);
}


static char *
qemuSlirpCreatePidFilename(virQEMUDriverConfigPtr cfg,
                           const virDomainDef *def,
                           const char *alias)
{
    g_autofree char *shortName = NULL;
    g_autofree char *name = NULL;

    if (!(shortName = virDomainDefGetShortName(def)) ||
        virAsprintf(&name, "%s-%s-slirp", shortName, alias) < 0)
        return NULL;

    return virPidFileBuildPath(cfg->slirpStateDir, name);
}


int
qemuSlirpOpen(qemuSlirpPtr slirp,
              virQEMUDriverPtr driver,
              virDomainDefPtr def)
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


int
qemuSlirpGetFD(qemuSlirpPtr slirp)
{
    int fd = slirp->fd[0];
    slirp->fd[0] = -1;
    return fd;
}


static char *
qemuSlirpGetDBusVMStateId(virDomainNetDefPtr net)
{
    char macstr[VIR_MAC_STRING_BUFLEN] = "";
    char *id = NULL;

    /* can't use alias, because it's not stable across restarts */
    if (virAsprintf(&id, "slirp-%s", virMacAddrFormat(&net->mac, macstr)) < 0)
        return NULL;

    return id;
}


static char *
qemuSlirpGetDBusPath(virQEMUDriverConfigPtr cfg,
                     const virDomainDef *def,
                     const char *alias)
{
    g_autofree char *shortName = NULL;
    char *path = NULL;

    if (!(shortName = virDomainDefGetShortName(def)) ||
        virAsprintf(&path, "%s/%s-%s-slirp",
                    cfg->slirpStateDir, shortName, alias) < 0)
        return NULL;

    return path;
}


void
qemuSlirpStop(qemuSlirpPtr slirp,
              virDomainObjPtr vm,
              virQEMUDriverPtr driver,
              virDomainNetDefPtr net,
              bool hot)
{
    VIR_AUTOUNREF(virQEMUDriverConfigPtr) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *pidfile = NULL;
    g_autofree char *dbus_path = NULL;
    g_autofree char *id = qemuSlirpGetDBusVMStateId(net);
    virErrorPtr orig_err;
    pid_t pid;
    int rc;

    if (!(pidfile = qemuSlirpCreatePidFilename(cfg, vm->def, net->info.alias))) {
        VIR_WARN("Unable to construct slirp pidfile path");
        return;
    }

    if (id) {
        qemuDBusVMStateRemove(driver, vm, id, hot);
    } else {
        VIR_WARN("Unable to construct vmstate id");
    }

    virErrorPreserveLast(&orig_err);
    rc = virPidFileReadPathIfAlive(pidfile, &pid, cfg->slirpHelperName);
    if (rc >= 0 && pid != (pid_t) -1)
        virProcessKillPainfully(pid, true);

    if (unlink(pidfile) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to remove stale pidfile %s"),
                             pidfile);
    }
    slirp->pid = 0;

    dbus_path = qemuSlirpGetDBusPath(cfg, vm->def, net->info.alias);
    if (dbus_path) {
        if (unlink(dbus_path) < 0 &&
            errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to remove stale dbus socket %s"),
                                 dbus_path);
        }
    } else {
        VIR_WARN("Unable to construct dbus socket path");
    }

    virErrorRestore(&orig_err);
}


int
qemuSlirpStart(qemuSlirpPtr slirp,
               virDomainObjPtr vm,
               virQEMUDriverPtr driver,
               virDomainNetDefPtr net,
               bool hotplug,
               bool incoming)
{
    VIR_AUTOUNREF(virQEMUDriverConfigPtr) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *pidfile = NULL;
    g_autofree char *dbus_path = NULL;
    g_autofree char *dbus_addr = NULL;
    g_autofree char *id = NULL;
    size_t i;
    const unsigned long long timeout = 5 * 1000; /* ms */
    pid_t pid = (pid_t) -1;
    int rc;
    int exitstatus = 0;
    int cmdret = 0;
    VIR_AUTOCLOSE errfd = -1;

    if (incoming &&
        !qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_MIGRATE)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("The slirp-helper doesn't support migration"));
    }

    if (!(pidfile = qemuSlirpCreatePidFilename(cfg, vm->def, net->info.alias)))
        return -1;

    if (!(cmd = virCommandNew(cfg->slirpHelperName)))
        return -1;

    virCommandClearCaps(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandSetErrorFD(cmd, &errfd);
    virCommandDaemonize(cmd);

    virCommandAddArgFormat(cmd, "--fd=%d", slirp->fd[1]);
    virCommandPassFD(cmd, slirp->fd[1],
                     VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    slirp->fd[1] = -1;

    for (i = 0; i < net->guestIP.nips; i++) {
        const virNetDevIPAddr *ip = net->guestIP.ips[i];
        g_autofree char *addr = NULL;
        const char *opt = "";

        if (!(addr = virSocketAddrFormat(&ip->address)))
            return -1;

        if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET))
            opt = "--net";
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET6))
            opt = "--prefix-ipv6";

        virCommandAddArgFormat(cmd, "%s=%s", opt, addr);

        if (ip->prefix) {
            if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET)) {
                virSocketAddr netmask;
                g_autofree char *netmaskStr = NULL;

                if (virSocketAddrPrefixToNetmask(ip->prefix, &netmask, AF_INET) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Failed to translate prefix %d to netmask"),
                                   ip->prefix);
                    return -1;
                }
                if (!(netmaskStr = virSocketAddrFormat(&netmask)))
                    return -1;
                virCommandAddArgFormat(cmd, "--mask=%s", netmaskStr);
            }
            if (VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET6))
                virCommandAddArgFormat(cmd, "--prefix-length-ipv6=%u", ip->prefix);
        }
    }

    if (qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_DBUS_P2P)) {
        if (!(id = qemuSlirpGetDBusVMStateId(net)))
            return -1;

        if (!(dbus_path = qemuSlirpGetDBusPath(cfg, vm->def, net->info.alias)))
            return -1;

        if (unlink(dbus_path) < 0 && errno != ENOENT) {
            virReportSystemError(errno, _("Unable to unlink %s"), dbus_path);
            return -1;
        }

        if (virAsprintf(&dbus_addr, "unix:path=%s", dbus_path) < 0)
            return -1;

        virCommandAddArgFormat(cmd, "--dbus-id=%s", id);

        virCommandAddArgFormat(cmd, "--dbus-p2p=%s", dbus_addr);

        if (incoming &&
            qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_MIGRATE))
            virCommandAddArg(cmd, "--dbus-incoming");
    }

    if (qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_EXIT_WITH_PARENT))
        virCommandAddArg(cmd, "--exit-with-parent");

    if (qemuExtDeviceLogCommand(driver, vm, cmd, "slirp") < 0)
        return -1;

    if (qemuSecurityCommandRun(driver, vm, cmd, -1, -1, &exitstatus, &cmdret) < 0)
        return -1;

    if (cmdret < 0 || exitstatus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not start 'slirp'. exitstatus: %d"), exitstatus);
        goto error;
    }

    rc = virPidFileReadPath(pidfile, &pid);
    if (rc < 0) {
        virReportSystemError(-rc,
                             _("Unable to read slirp pidfile '%s'"),
                             pidfile);
        goto error;
    }

    if (dbus_path) {
        virTimeBackOffVar timebackoff;

        if (virTimeBackOffStart(&timebackoff, 1, timeout) < 0)
            goto error;

        while (virTimeBackOffWait(&timebackoff)) {
            char errbuf[1024] = { 0 };

            if (virFileExists(dbus_path))
                break;

            if (virProcessKill(pid, 0) == 0)
                continue;

            if (saferead(errfd, errbuf, sizeof(errbuf) - 1) < 0) {
                virReportSystemError(errno,
                                     _("slirp helper %s died unexpectedly"),
                                     cfg->prHelperName);
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("slirp helper died and reported: %s"), errbuf);
            }
            goto error;
        }

        if (!virFileExists(dbus_path)) {
            virReportError(VIR_ERR_OPERATION_TIMEOUT, "%s",
                           _("slirp dbus socket did not show up"));
            goto error;
        }
    }

    if (qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_MIGRATE) &&
        qemuDBusVMStateAdd(driver, vm, id, dbus_addr, hotplug) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to register slirp migration"));
        goto error;
    }

    slirp->pid = pid;
    return 0;

 error:
    if (pid != -1)
        virProcessKillPainfully(pid, true);
    if (pidfile)
        unlink(pidfile);
    if (dbus_path)
        unlink(dbus_path);
    return -1;
}
