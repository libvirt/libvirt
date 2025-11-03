/*
 * qemu_passt.c: QEMU passt support
 *
 * Copyright (C) 2022 Red Hat, Inc.
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
#include "qemu_passt.h"
#include "virenum.h"
#include "virerror.h"
#include "virjson.h"
#include "virlog.h"
#include "virpidfile.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("qemu.passt");


#define PASST "passt"
#define QEMU_PASST_RECONNECT_TIMEOUT 5

static char *
qemuPasstCreatePidFilename(virDomainObj *vm,
                           virDomainNetDef *net)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autofree char *shortName = virDomainDefGetShortName(vm->def);
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *name = NULL;

    name = g_strdup_printf("%s-%s-passt", shortName, net->info.alias);

    return virPidFileBuildPath(cfg->passtStateDir, name);
}


char *
qemuPasstCreateSocketPath(virDomainObj *vm,
                          virDomainNetDef *net)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autofree char *shortName = virDomainDefGetShortName(vm->def);
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    return g_strdup_printf("%s/%s-%s.socket", cfg->passtStateDir,
                           shortName, net->info.alias);
}


static int
qemuPasstGetPid(virDomainObj *vm,
                virDomainNetDef *net,
                pid_t *pid)
{
    g_autofree char *pidfile = qemuPasstCreatePidFilename(vm, net);

    return virPidFileReadPath(pidfile, pid);
}


int
qemuPasstAddNetProps(virDomainObj *vm,
                     virDomainNetDef *net,
                     virJSONValue **netprops)
{
    g_autofree char *passtSocketName = qemuPasstCreateSocketPath(vm, net);
    g_autoptr(virJSONValue) addrprops = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUCaps *qemuCaps = priv->qemuCaps;

    if (virJSONValueObjectAdd(&addrprops,
                              "s:type", "unix",
                              "s:path", passtSocketName,
                              NULL) < 0) {
        return -1;
    }

    if (virJSONValueObjectAdd(netprops,
                              "s:type", "stream",
                              "a:addr", &addrprops,
                              "b:server", false,
                              NULL) < 0) {
        return -1;
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NETDEV_STREAM_RECONNECT_MILISECONDS)) {
        if (virJSONValueObjectAdd(netprops, "u:reconnect-ms",
                                  QEMU_PASST_RECONNECT_TIMEOUT * 1000, NULL) < 0) {
            return -1;
        }
    } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_NETDEV_STREAM_RECONNECT)) {
        if (virJSONValueObjectAdd(netprops, "u:reconnect",
                                  QEMU_PASST_RECONNECT_TIMEOUT, NULL) < 0) {
            return -1;
        }
    }

    return 0;
}


static void
qemuPasstKill(const char *pidfile, const char *passtSocketName)
{
    virErrorPtr orig_err;
    pid_t pid = 0;

    virErrorPreserveLast(&orig_err);

    ignore_value(virPidFileReadPath(pidfile, &pid));
    if (pid != 0)
        virProcessKillPainfully(pid, true);
    unlink(pidfile);

    unlink(passtSocketName);

    virErrorRestore(&orig_err);
}


void
qemuPasstStop(virDomainObj *vm,
              virDomainNetDef *net)
{
    g_autofree char *pidfile = qemuPasstCreatePidFilename(vm, net);
    g_autofree char *passtSocketName = qemuPasstCreateSocketPath(vm, net);

    qemuPasstKill(pidfile, passtSocketName);
}


int
qemuPasstSetupCgroup(virDomainObj *vm,
                     virDomainNetDef *net,
                     virCgroup *cgroup)
{
    pid_t pid = (pid_t) -1;

    if (qemuPasstGetPid(vm, net, &pid) < 0 || pid <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not get process ID of passt"));
        return -1;
    }

    return virCgroupAddProcess(cgroup, pid);
}


void
qemuPasstPrepareVhostUser(virDomainObj *vm,
                          virDomainNetDef *net)
{
    /* There are some options on the QEMU commandline for a vhost-user
     * chr device that are normally configurable, but when it is passt
     * speaking to the vhost-user device those things are
     * derived/fixed. This function, which is called prior to
     * generating the QEMU commandline, sets thos derived/fixed things
     * in the chr device object.
     */

    /* The socket path is not user-configurable for passt - it is
     * derived from other info
     */
    g_free(net->data.vhostuser->data.nix.path);
    net->data.vhostuser->data.nix.path = qemuPasstCreateSocketPath(vm, net);

    /* reconnect is always enabled, with timeout always at 5 seconds, when
     * using passt
     */
    net->data.vhostuser->data.nix.reconnect.enabled = VIR_TRISTATE_BOOL_YES;
    net->data.vhostuser->data.nix.reconnect.timeout = QEMU_PASST_RECONNECT_TIMEOUT;
}

virCommand *
qemuPasstBuildCommand(char **socketName,
                      char **pidfileRet,
                      virDomainObj *vm,
                      virDomainNetDef *net)
{
    g_autofree char *passtSocketName = qemuPasstCreateSocketPath(vm, net);
    g_autofree char *pidfile = qemuPasstCreatePidFilename(vm, net);
    g_autoptr(virCommand) cmd = NULL;
    size_t i;

    cmd = virCommandNew(PASST);

    virCommandClearCaps(cmd);

    if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_VHOSTUSER)
        virCommandAddArg(cmd, "--vhost-user");

    virCommandAddArgList(cmd,
                         "--one-off",
                         "--socket", passtSocketName,
                         "--pid", pidfile,
                         NULL);

    if (net->mtu) {
        virCommandAddArg(cmd, "--mtu");
        virCommandAddArgFormat(cmd, "%u", net->mtu);
    }

    if (net->sourceDev)
        virCommandAddArgList(cmd, "--interface", net->sourceDev, NULL);

    if (net->backend.logFile)
        virCommandAddArgList(cmd, "--log-file", net->backend.logFile, NULL);

    if (net->backend.hostname)
        virCommandAddArgList(cmd, "--hostname", net->backend.hostname, NULL);

    if (net->backend.fqdn)
        virCommandAddArgList(cmd, "--fqdn", net->backend.fqdn, NULL);

    /* Add IP address info */
    for (i = 0; i < net->guestIP.nips; i++) {
        const virNetDevIPAddr *ip = net->guestIP.ips[i];
        g_autofree char *addr = NULL;

        /* validation has already limited us to
         * a single IPv4 and single IPv6 address
         */
        if (!(addr = virSocketAddrFormat(&ip->address)))
            return NULL;

        virCommandAddArgList(cmd, "--address", addr, NULL);

        if (ip->prefix && VIR_SOCKET_ADDR_IS_FAMILY(&ip->address, AF_INET)) {
            /* validation already made sure no prefix is
             * specified for IPv6 (not allowed by passt)
             */
            virCommandAddArg(cmd, "--netmask");
            virCommandAddArgFormat(cmd, "%u", ip->prefix);
        }
    }

    /* Add port forwarding info */

    for (i = 0; i < net->nPortForwards; i++) {
        virDomainNetPortForward *pf = net->portForwards[i];
        g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
        bool emitsep = false;

        if (pf->proto == VIR_DOMAIN_NET_PROTO_TCP) {
            virCommandAddArg(cmd, "--tcp-ports");
        } else if (pf->proto == VIR_DOMAIN_NET_PROTO_UDP) {
            virCommandAddArg(cmd, "--udp-ports");
        } else {
            /* validation guarantees this will never happen */
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid portForward proto value %1$u"), pf->proto);
            return NULL;
        }

        if (VIR_SOCKET_ADDR_VALID(&pf->address)) {
            g_autofree char *addr = NULL;

            if (!(addr = virSocketAddrFormat(&pf->address)))
                return NULL;

            virBufferAddStr(&buf, addr);
            emitsep = true;
        }

        if (pf->dev) {
            virBufferAsprintf(&buf, "%%%s", pf->dev);
            emitsep = true;
        }

        if (emitsep)
            virBufferAddChar(&buf, '/');

        if (!pf->nRanges) {
            virBufferAddLit(&buf, "all");
        } else {
            size_t r;

            for (r = 0; r < pf->nRanges; r++) {
                virDomainNetPortForwardRange *range = pf->ranges[r];

                if (r > 0)
                    virBufferAddChar(&buf, ',');

                if (range->exclude == VIR_TRISTATE_BOOL_YES)
                    virBufferAddChar(&buf, '~');

                virBufferAsprintf(&buf, "%u", range->start);

                if (range->end)
                    virBufferAsprintf(&buf, "-%u", range->end);
                if (range->to) {
                    virBufferAsprintf(&buf, ":%u", range->to);
                    if (range->end) {
                        virBufferAsprintf(&buf, "-%u",
                                          range->end + range->to - range->start);
                    }
                }
            }
        }
        virCommandAddArg(cmd, virBufferCurrentContent(&buf));
    }

    if (socketName)
        *socketName = g_steal_pointer(&passtSocketName);
    if (pidfileRet)
        *pidfileRet = g_steal_pointer(&pidfile);

    return g_steal_pointer(&cmd);
}

int
qemuPasstStart(virDomainObj *vm,
               virDomainNetDef *net)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *passtSocketName = NULL;
    g_autofree char *pidfile = NULL;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(virCommand) cmd = NULL;

    if (!(cmd = qemuPasstBuildCommand(&passtSocketName, &pidfile, vm, net)))
        return -1;

    if (qemuExtDeviceLogCommand(driver, vm, cmd, "passt") < 0)
        return -1;

    if (qemuSecurityCommandRun(driver, vm, cmd, -1, -1, true, NULL) < 0)
        goto error;

    return 0;

 error:
    qemuPasstKill(pidfile, passtSocketName);
    return -1;
}
