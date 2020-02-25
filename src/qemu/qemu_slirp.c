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

    return g_steal_pointer(&slirp);
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

    return g_steal_pointer(&slirp);
}


static char *
qemuSlirpCreatePidFilename(virQEMUDriverConfigPtr cfg,
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

    /* can't use alias, because it's not stable across restarts */
    return g_strdup_printf("slirp-%s", virMacAddrFormat(&net->mac, macstr));
}


void
qemuSlirpStop(qemuSlirpPtr slirp,
              virDomainObjPtr vm,
              virQEMUDriverPtr driver,
              virDomainNetDefPtr net)
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
qemuSlirpStart(qemuSlirpPtr slirp,
               virDomainObjPtr vm,
               virQEMUDriverPtr driver,
               virDomainNetDefPtr net,
               bool incoming)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *pidfile = NULL;
    size_t i;
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

        if (qemuDBusStart(driver, vm) < 0)
            return -1;

        virCommandAddArgFormat(cmd, "--dbus-id=%s", id);

        virCommandAddArgFormat(cmd, "--dbus-address=%s", dbus_addr);

        if (qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_MIGRATE)) {
            if (qemuDBusVMStateAdd(vm, id) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Failed to register slirp migration"));
                goto error;
            }
            if (incoming)
                virCommandAddArg(cmd, "--dbus-incoming");
        }
    }

    if (qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_EXIT_WITH_PARENT))
        virCommandAddArg(cmd, "--exit-with-parent");

    if (qemuExtDeviceLogCommand(driver, vm, cmd, "slirp") < 0)
        goto error;

    if (qemuSecurityCommandRun(driver, vm, cmd, -1, -1, &exitstatus, &cmdret) < 0)
        goto error;

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

    slirp->pid = pid;
    return 0;

 error:
    if (pid != -1)
        virProcessKillPainfully(pid, true);
    if (pidfile)
        unlink(pidfile);
    qemuDBusStop(driver, vm);
    return -1;
}
