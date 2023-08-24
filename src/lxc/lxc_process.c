/*
 * Copyright (C) 2010-2016 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_process.c: LXC process lifecycle management
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

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "lxc_process.h"
#include "lxc_domain.h"
#include "lxc_container.h"
#include "datatypes.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virnetdev.h"
#include "virnetdevveth.h"
#include "virnetdevbridge.h"
#include "virnetdevopenvswitch.h"
#include "virtime.h"
#include "domain_nwfilter.h"
#include "viralloc.h"
#include "domain_audit.h"
#include "domain_validate.h"
#include "virerror.h"
#include "virlog.h"
#include "vircommand.h"
#include "lxc_hostdev.h"
#include "virhook.h"
#include "virprocess.h"
#include "netdev_bandwidth_conf.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_process");

#define START_POSTFIX ": starting up\n"

typedef enum {
    VIR_LXC_PROCESS_CLEANUP_RELEASE_SECLABEL = (1 << 0),
    VIR_LXC_PROCESS_CLEANUP_RESTORE_SECLABEL = (1 << 1),
    VIR_LXC_PROCESS_CLEANUP_REMOVE_TRANSIENT = (1 << 2),
    VIR_LXC_PROCESS_CLEANUP_AUTODESTROY = (1 << 3),
} virLXCProcessCleanupFlags;

static void
lxcProcessAutoDestroy(virDomainObj *dom,
                      virConnectPtr conn)
{
    virObjectEvent *event = NULL;
    virLXCDomainObjPrivate *priv = dom->privateData;
    virLXCDriver *driver = priv->driver;

    VIR_DEBUG("driver=%p dom=%s conn=%p", driver, dom->def->name, conn);

    VIR_DEBUG("Killing domain");
    virLXCProcessStop(driver, dom, VIR_DOMAIN_SHUTOFF_DESTROYED, 0);
    virDomainAuditStop(dom, "destroyed");
    event = virDomainEventLifecycleNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    priv->doneStopEvent = true;

    if (!dom->persistent)
        virDomainObjListRemove(driver->domains, dom);

    virObjectEventStateQueue(driver->domainEventState, event);
}

/*
 * Precondition: driver is locked
 */
static int
virLXCProcessReboot(virLXCDriver *driver,
                    virDomainObj *vm)
{
    /* we want to keep the autodestroy callback registered */
    unsigned int stopFlags = ~(VIR_LXC_PROCESS_CLEANUP_AUTODESTROY);
    int reason = vm->state.reason;
    virDomainDef *savedDef;

    VIR_DEBUG("Faking reboot");

    /* In a reboot scenario, we need to make sure we continue
     * to use the current 'def', and not switch to 'newDef'.
     * So temporarily hide the newDef and then reinstate it
     */
    savedDef = g_steal_pointer(&vm->newDef);
    virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN, stopFlags);
    vm->newDef = savedDef;
    if (virLXCProcessStart(driver, vm, 0, NULL, NULL, reason) < 0) {
        VIR_WARN("Unable to handle reboot of vm %s", vm->def->name);
        return -1;
    }

    return 0;
}


static void
lxcProcessRemoveDomainStatus(virLXCDriverConfig *cfg,
                              virDomainObj *vm)
{
    g_autofree char *file = g_strdup_printf("%s/%s.xml",
                                            cfg->stateDir,
                                            vm->def->name);

    if (unlink(file) < 0 && errno != ENOENT && errno != ENOTDIR)
        VIR_WARN("Failed to remove domain XML for %s: %s",
                 vm->def->name, g_strerror(errno));
}


/**
 * virLXCProcessCleanup:
 * @driver: pointer to driver structure
 * @vm: pointer to VM to clean up
 * @reason: reason for switching the VM to shutoff state
 * @flags: allows to run selective cleanups only
 *
 * Clean out resources associated with the now dead VM.
 * If @flags is zero then whole cleanup process is done,
 * otherwise only selected sections are run.
 */
static void virLXCProcessCleanup(virLXCDriver *driver,
                                 virDomainObj *vm,
                                 virDomainShutoffReason reason,
                                 unsigned int flags)
{
    size_t i;
    virLXCDomainObjPrivate *priv = vm->privateData;
    const virNetDevVPortProfile *vport = NULL;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);
    g_autoptr(virConnect) conn = NULL;

    VIR_DEBUG("Cleanup VM name=%s pid=%d reason=%d flags=0x%x",
              vm->def->name, (int)vm->pid, (int)reason, flags);

    if (flags == 0)
        flags = ~0;

    /* now that we know it's stopped call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        g_autofree char *xml = virDomainDefFormat(vm->def, driver->xmlopt, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                    VIR_HOOK_LXC_OP_STOPPED, VIR_HOOK_SUBOP_END,
                    NULL, xml, NULL);
    }

    if (flags & VIR_LXC_PROCESS_CLEANUP_RESTORE_SECLABEL) {
        virSecurityManagerRestoreAllLabel(driver->securityManager,
                                          vm->def, false, false);
    }

    if (flags & VIR_LXC_PROCESS_CLEANUP_RELEASE_SECLABEL) {
        virSecurityManagerReleaseLabel(driver->securityManager, vm->def);
    }

    /* Clear out dynamically assigned labels */
    if (vm->def->nseclabels &&
        vm->def->seclabels[0]->type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        g_clear_pointer(&vm->def->seclabels[0]->model, g_free);
        g_clear_pointer(&vm->def->seclabels[0]->label, g_free);
        g_clear_pointer(&vm->def->seclabels[0]->imagelabel, g_free);
    }

    /* Stop autodestroy in case guest is restarted */
    if (flags & VIR_LXC_PROCESS_CLEANUP_AUTODESTROY) {
        virCloseCallbacksDomainRemove(vm, NULL, lxcProcessAutoDestroy);
    }

    if (priv->monitor) {
        virLXCMonitorClose(priv->monitor);
        g_clear_pointer(&priv->monitor, virObjectUnref);
    }

    virPidFileDelete(cfg->stateDir, vm->def->name);
    lxcProcessRemoveDomainStatus(cfg, vm);

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);
    vm->pid = 0;
    vm->def->id = -1;

    if (!!g_atomic_int_dec_and_test(&driver->nactive) && driver->inhibitCallback)
        driver->inhibitCallback(false, driver->inhibitOpaque);

    virLXCDomainReAttachHostDevices(driver, vm->def);

    for (i = 0; i < vm->def->nnets; i++) {
        virDomainNetDef *iface = vm->def->nets[i];
        vport = virDomainNetGetActualVirtPortProfile(iface);
        if (iface->ifname) {
            if (vport &&
                vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
                ignore_value(virNetDevOpenvswitchRemovePort(
                                virDomainNetGetActualBridgeName(iface),
                                iface->ifname));
            ignore_value(virNetDevVethDelete(iface->ifname));
        }
        if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            if (conn || (conn = virGetConnectNetwork()))
                virDomainNetReleaseActualDevice(conn, vm->def, iface);
            else
                VIR_WARN("Unable to release network device '%s'", NULLSTR(iface->ifname));
        }
    }

    virDomainConfVMNWFilterTeardown(vm);

    if (priv->cgroup) {
        virCgroupRemove(priv->cgroup);
        g_clear_pointer(&priv->cgroup, virCgroupFree);
    }

    /* Get machined to terminate the machine as it may not have cleaned it
     * properly. See https://bugs.freedesktop.org/show_bug.cgi?id=68370 for
     * the bug we are working around here.
     */
    virCgroupTerminateMachine(priv->machineName);
    g_clear_pointer(&priv->machineName, g_free);

    /* The "release" hook cleans up additional resources */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        g_autofree char *xml = virDomainDefFormat(vm->def, driver->xmlopt, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                    VIR_HOOK_LXC_OP_RELEASE, VIR_HOOK_SUBOP_END,
                    NULL, xml, NULL);
    }

    if (flags & VIR_LXC_PROCESS_CLEANUP_REMOVE_TRANSIENT)
        virDomainObjRemoveTransientDef(vm);
}


int
virLXCProcessValidateInterface(virDomainNetDef *net)
{
    if (net->script) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("scripts are not supported on LXC network interfaces"));
        return -1;
    }
    return 0;
}


char *
virLXCProcessSetupInterfaceTap(virDomainDef *vm,
                               virDomainNetDef *net,
                               const char *brname)
{
    g_autofree char *parentVeth = NULL;
    g_autofree char *containerVeth = NULL;
    const virNetDevVPortProfile *vport = virDomainNetGetActualVirtPortProfile(net);

    VIR_DEBUG("calling vethCreate()");
    parentVeth = g_strdup(net->ifname);

    if (virNetDevVethCreate(&parentVeth, &containerVeth) < 0)
        return NULL;
    VIR_DEBUG("parentVeth: %s, containerVeth: %s", parentVeth, containerVeth);

    if (virNetDevSetMAC(containerVeth, &net->mac) < 0)
        return NULL;

    if (brname) {
        if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
            if (virNetDevOpenvswitchAddPort(brname, parentVeth, &net->mac, vm->uuid,
                                            vport, virDomainNetGetActualVlan(net)) < 0)
                return NULL;
        } else {
            if (virNetDevBridgeAddPort(brname, parentVeth) < 0)
                return NULL;

            if (virDomainNetGetActualPortOptionsIsolated(net) == VIR_TRISTATE_BOOL_YES &&
                virNetDevBridgePortSetIsolated(brname, parentVeth, true) < 0) {
                virErrorPtr err;

                virErrorPreserveLast(&err);
                ignore_value(virNetDevBridgeRemovePort(brname, parentVeth));
                virErrorRestore(&err);
                return NULL;
            }
        }
    }

    if (virNetDevSetOnline(parentVeth, true) < 0)
        return NULL;

    if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_ETHERNET) {
        /* Set IP info for the host side, but only if the type is
         * 'ethernet'.
         */
        if (virNetDevIPInfoAddToDev(parentVeth, &net->hostIP) < 0)
            return NULL;
    }

    if (net->filter &&
        virDomainConfNWFilterInstantiate(vm->name, vm->uuid, net, false) < 0)
        return NULL;

    /* success is guaranteed, so update the interface object */
    g_free(net->ifname);
    net->ifname = g_steal_pointer(&parentVeth);

    return g_steal_pointer(&containerVeth);
}


char *
virLXCProcessSetupInterfaceDirect(virLXCDriver *driver,
                                  virDomainDef *def,
                                  virDomainNetDef *net)
{
    char *res_ifname = NULL;
    const virNetDevBandwidth *bw;
    const virNetDevVPortProfile *prof;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);
    const char *linkdev = virDomainNetGetActualDirectDev(net);
    unsigned int macvlan_create_flags = VIR_NETDEV_MACVLAN_CREATE_IFUP;

    /* XXX how todo bandwidth controls ?
     * Since the 'net-ifname' is about to be moved to a different
     * namespace & renamed, there will be no host side visible
     * interface for the container to attach rules to
     */
    bw = virDomainNetGetActualBandwidth(net);
    if (bw) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unable to set network bandwidth on direct interfaces"));
        return NULL;
    }

    /* XXX how todo port profiles ?
     * Although we can do the association during container
     * startup, at shutdown we are unable to disassociate
     * because the macvlan device was moved to the container
     * and automagically dies when the container dies. So
     * we have no dev to perform disassociation with.
     */
    prof = virDomainNetGetActualVirtPortProfile(net);
    if (prof) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unable to set port profile on direct interfaces"));
        return NULL;
    }

    if (virNetDevMacVLanCreateWithVPortProfile(
            net->ifname, &net->mac,
            linkdev,
            virDomainNetGetActualDirectMode(net),
            virDomainNetGetActualVlan(net),
            def->uuid,
            prof,
            &res_ifname,
            VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
            cfg->stateDir,
            NULL, 0,
            macvlan_create_flags) < 0)
        return NULL;

    return res_ifname;
}

static const char *nsInfoLocal[VIR_LXC_DOMAIN_NAMESPACE_LAST] = {
    [VIR_LXC_DOMAIN_NAMESPACE_SHARENET] = "net",
    [VIR_LXC_DOMAIN_NAMESPACE_SHAREIPC] = "ipc",
    [VIR_LXC_DOMAIN_NAMESPACE_SHAREUTS] = "uts",
};

static int virLXCProcessSetupNamespaceName(virLXCDriver *driver,
                                           int ns_type,
                                           const char *name)
{
    int fd = -1;
    virDomainObj *vm;
    virLXCDomainObjPrivate *priv;
    g_autofree char *path = NULL;

    vm = virDomainObjListFindByName(driver->domains, name);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching name '%1$s'"), name);
        return -1;
    }

    priv = vm->privateData;
    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Init pid is not yet available"));
        goto cleanup;
    }

    path = g_strdup_printf("/proc/%lld/ns/%s", (long long int)priv->initpid,
                           nsInfoLocal[ns_type]);

    if ((fd = open(path, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("failed to open ns %1$s"),
                             virLXCDomainNamespaceTypeToString(ns_type));
        goto cleanup;
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return fd;
}


static int virLXCProcessSetupNamespacePID(int ns_type, const char *name)
{
    g_autofree char *path = g_strdup_printf("/proc/%s/ns/%s",
                                            name, nsInfoLocal[ns_type]);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        virReportSystemError(errno,
                             _("failed to open ns %1$s"),
                             virLXCDomainNamespaceTypeToString(ns_type));
        return -1;
    }
    return fd;
}


static int virLXCProcessSetupNamespaceNet(int ns_type, const char *name)
{
    g_autofree char *path = NULL;
    int fd;
    if (ns_type != VIR_LXC_DOMAIN_NAMESPACE_SHARENET) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("'netns' namespace source can only be used with sharenet"));
        return -1;
    }

    path = g_strdup_printf("%s/netns/%s", RUNSTATEDIR, name);
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        virReportSystemError(errno,
                             _("failed to open netns %1$s"), name);
        return -1;
    }
    return fd;
}


/**
 * virLXCProcessSetupNamespaces:
 * @driver: pointer to driver structure
 * @def: pointer to virtual machines namespaceData
 * @nsFDs: out parameter to store the namespace FD
 *
 * Opens the specified namespace that needs to be shared and
 * will moved into the container namespace later after clone has been called.
 *
 * Returns 0 on success or -1 in case of error
 */
static int
virLXCProcessSetupNamespaces(virLXCDriver *driver,
                             lxcDomainDef *lxcDef,
                             int *nsFDs)
{
    size_t i;

    for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++)
        nsFDs[i] = -1;
    /* If there are no namespaces to be opened just return success */
    if (lxcDef == NULL)
        return 0;

    for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++) {
        switch (lxcDef->ns_source[i]) {
        case VIR_LXC_DOMAIN_NAMESPACE_SOURCE_NONE:
            continue;
        case VIR_LXC_DOMAIN_NAMESPACE_SOURCE_NAME:
            if ((nsFDs[i] = virLXCProcessSetupNamespaceName(driver, i,
                                                            lxcDef->ns_val[i])) < 0)
                return -1;
            break;
        case VIR_LXC_DOMAIN_NAMESPACE_SOURCE_PID:
            if ((nsFDs[i] = virLXCProcessSetupNamespacePID(i, lxcDef->ns_val[i])) < 0)
                return -1;
            break;
        case VIR_LXC_DOMAIN_NAMESPACE_SOURCE_NETNS:
            if ((nsFDs[i] = virLXCProcessSetupNamespaceNet(i, lxcDef->ns_val[i])) < 0)
                return -1;
            break;
        }
    }

    return 0;
}

/**
 * virLXCProcessSetupInterfaces:
 * @driver: pointer to driver structure
 * @def: pointer to virtual machine structure
 * @veths: string list of interface names
 *
 * Sets up the container interfaces by creating the veth device pairs and
 * attaching the parent end to the appropriate bridge.  The container end
 * will moved into the container namespace later after clone has been called.
 *
 * Returns 0 on success or -1 in case of error
 */
static int
virLXCProcessSetupInterfaces(virLXCDriver *driver,
                             virDomainDef *def,
                             char ***veths)
{
    int ret = -1;
    size_t i;
    size_t niface = 0;
    virDomainNetDef *net;
    virDomainNetType type;
    g_autoptr(virConnect) netconn = NULL;
    virErrorPtr save_err = NULL;

    *veths = g_new0(char *, def->nnets + 1);

    for (i = 0; i < def->nnets; i++) {
        char *veth = NULL;
        const virNetDevBandwidth *actualBandwidth;
        /* If appropriate, grab a physical device from the configured
         * network's pool of devices, or resolve bridge device name
         * to the one defined in the network definition.
         */
        net = def->nets[i];

        if (virLXCProcessValidateInterface(net) < 0)
            goto cleanup;

        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
            if (!netconn && !(netconn = virGetConnectNetwork()))
                goto cleanup;
            if (virDomainNetAllocateActualDevice(netconn, def, net) < 0)
                goto cleanup;
        }

        /* final validation now that actual type is known */
        if (virDomainActualNetDefValidate(net) < 0)
            return -1;

        type = virDomainNetGetActualType(net);
        switch (type) {
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        case VIR_DOMAIN_NET_TYPE_BRIDGE: {
            const char *brname = virDomainNetGetActualBridgeName(net);
            if (!brname) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("No bridge name specified"));
                goto cleanup;
            }
            if (!(veth = virLXCProcessSetupInterfaceTap(def, net, brname)))
                goto cleanup;
        }   break;
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            if (!(veth = virLXCProcessSetupInterfaceTap(def, net, NULL)))
                goto cleanup;
            break;
        case VIR_DOMAIN_NET_TYPE_DIRECT:
            if (!(veth = virLXCProcessSetupInterfaceDirect(driver, def, net)))
                goto cleanup;
            break;

        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_UDP:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        case VIR_DOMAIN_NET_TYPE_VDPA:
        case VIR_DOMAIN_NET_TYPE_NULL:
        case VIR_DOMAIN_NET_TYPE_VDS:
        case VIR_DOMAIN_NET_TYPE_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unsupported network type %1$s"),
                           virDomainNetTypeToString(type));
            goto cleanup;

        }

        /* Set bandwidth or warn if requested and not supported. */
        actualBandwidth = virDomainNetGetActualBandwidth(net);
        if (actualBandwidth) {
            if (virNetDevSupportsBandwidth(type)) {
                if (virNetDevBandwidthSet(net->ifname, actualBandwidth, false,
                                          !virDomainNetTypeSharesHostView(net)) < 0)
                    goto cleanup;
            } else {
                VIR_WARN("setting bandwidth on interfaces of "
                         "type '%s' is not implemented yet",
                         virDomainNetTypeToString(type));
            }
        }

        (*veths)[i] = veth;

        def->nets[i]->ifname_guest_actual = g_strdup(veth);

        /* Make sure all net definitions will have a name in the container */
        if (!net->ifname_guest) {
            net->ifname_guest = g_strdup_printf("eth%zu", niface);
            niface++;
        }
    }

    ret = 0;

 cleanup:
    if (ret < 0) {
        virErrorPreserveLast(&save_err);
        for (i = 0; i < def->nnets; i++) {
            virDomainNetDef *iface = def->nets[i];
            const virNetDevVPortProfile *vport = virDomainNetGetActualVirtPortProfile(iface);
            if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
                ignore_value(virNetDevOpenvswitchRemovePort(
                                virDomainNetGetActualBridgeName(iface),
                                iface->ifname));
            if (iface->type == VIR_DOMAIN_NET_TYPE_NETWORK && netconn)
                virDomainNetReleaseActualDevice(netconn, def, iface);
        }
        virErrorRestore(&save_err);
    }
    return ret;
}

static void
virLXCProcessCleanInterfaces(virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        g_clear_pointer(&def->nets[i]->ifname_guest_actual, g_free);
        VIR_DEBUG("Cleared net names: %s", def->nets[i]->ifname_guest);
    }
}


extern virLXCDriver *lxc_driver;
static void virLXCProcessMonitorEOFNotify(virLXCMonitor *mon,
                                          virDomainObj *vm)
{
    virLXCDriver *driver = lxc_driver;
    virObjectEvent *event = NULL;
    virLXCDomainObjPrivate *priv;

    VIR_DEBUG("mon=%p vm=%p", mon, vm);

    virObjectLock(vm);

    priv = vm->privateData;
    virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN, 0);
    if (!priv->wantReboot) {
        virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN, 0);
        if (!priv->doneStopEvent) {
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             priv->stopReason);
            virDomainAuditStop(vm, "shutdown");
        } else {
            VIR_DEBUG("Stop event has already been sent");
        }
        if (!vm->persistent)
            virDomainObjListRemove(driver->domains, vm);
    } else {
        int ret = virLXCProcessReboot(driver, vm);
        virDomainAuditStop(vm, "reboot");
        virDomainAuditStart(vm, "reboot", ret == 0);
        if (ret == 0) {
            event = virDomainEventRebootNewFromObj(vm);
        } else {
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             priv->stopReason);
            if (!vm->persistent)
                virDomainObjListRemove(driver->domains, vm);
        }
    }

    /* NB: virLXCProcessConnectMonitor will perform the virObjectRef(vm)
     * before adding monitorCallbacks. Since we are now done with the @vm
     * we can Unref/Unlock */
    virDomainObjEndAPI(&vm);
    virObjectEventStateQueue(driver->domainEventState, event);
}

static void virLXCProcessMonitorExitNotify(virLXCMonitor *mon G_GNUC_UNUSED,
                                           virLXCMonitorExitStatus status,
                                           virDomainObj *vm)
{
    virLXCDomainObjPrivate *priv = vm->privateData;

    virObjectLock(vm);

    switch (status) {
    case VIR_LXC_MONITOR_EXIT_STATUS_SHUTDOWN:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN;
        break;
    case VIR_LXC_MONITOR_EXIT_STATUS_ERROR:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_FAILED;
        break;
    case VIR_LXC_MONITOR_EXIT_STATUS_REBOOT:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN;
        priv->wantReboot = true;
        break;
    default:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_FAILED;
        break;
    }
    VIR_DEBUG("Domain shutoff reason %d (from status %d)",
              priv->stopReason, status);

    virObjectUnlock(vm);
}

static int
virLXCProcessGetNsInode(pid_t pid,
                        const char *nsname,
                        ino_t *inode)
{
    g_autofree char *path = NULL;
    struct stat sb;

    path = g_strdup_printf("/proc/%lld/ns/%s", (long long)pid, nsname);

    if (stat(path, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to stat %1$s"), path);
        return -1;
    }

    *inode = sb.st_ino;

    return 0;
}


/* XXX a little evil */
extern virLXCDriver *lxc_driver;
static void virLXCProcessMonitorInitNotify(virLXCMonitor *mon G_GNUC_UNUSED,
                                           pid_t initpid,
                                           virDomainObj *vm)
{
    virLXCDriver *driver = lxc_driver;
    virLXCDomainObjPrivate *priv;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);
    ino_t inode = 0;

    virObjectLock(vm);

    priv = vm->privateData;
    priv->initpid = initpid;

    if (virLXCProcessGetNsInode(initpid, "pid", &inode) < 0) {
        VIR_WARN("Cannot obtain pid NS inode for %lld: %s",
                 (long long)initpid,
                 virGetLastErrorMessage());
        virResetLastError();
    }
    virDomainAuditInit(vm, initpid, inode);

    if (virDomainObjSave(vm, lxc_driver->xmlopt, cfg->stateDir) < 0)
        VIR_WARN("Cannot update XML with PID for LXC %s", vm->def->name);

    virObjectUnlock(vm);
}

static virLXCMonitorCallbacks monitorCallbacks = {
    .eofNotify = virLXCProcessMonitorEOFNotify,
    .exitNotify = virLXCProcessMonitorExitNotify,
    .initNotify = virLXCProcessMonitorInitNotify,
};


static virLXCMonitor *virLXCProcessConnectMonitor(virLXCDriver *driver,
                                                    virDomainObj *vm)
{
    virLXCMonitor *monitor = NULL;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);

    if (virSecurityManagerSetSocketLabel(driver->securityManager, vm->def) < 0)
        return NULL;

    /* Hold an extra reference because we can't allow 'vm' to be
     * deleted while the monitor is active. This will be unreffed
     * during EOFNotify processing. */
    virObjectRef(vm);

    monitor = virLXCMonitorNew(vm, cfg->stateDir, &monitorCallbacks);

    if (monitor == NULL)
        virObjectUnref(vm);

    if (virSecurityManagerClearSocketLabel(driver->securityManager, vm->def) < 0) {
        if (monitor)
            virObjectUnref(monitor);
        return NULL;
    }

    return monitor;
}


int virLXCProcessStop(virLXCDriver *driver,
                      virDomainObj *vm,
                      virDomainShutoffReason reason,
                      unsigned int cleanupFlags)
{
    int rc;
    virLXCDomainObjPrivate *priv;

    VIR_DEBUG("Stopping VM name=%s pid=%d reason=%d",
              vm->def->name, (int)vm->pid, (int)reason);
    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("VM '%s' not active", vm->def->name);
        return 0;
    }

    priv = vm->privateData;

    /* If the LXC domain is suspended we send all processes a SIGKILL
     * and thaw them. Upon wakeup the process sees the pending signal
     * and dies immediately. It is guaranteed that priv->cgroup != NULL
     * here because the domain has already been suspended using the
     * freezer cgroup.
     */
    if (reason == VIR_DOMAIN_SHUTOFF_DESTROYED &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        if (virCgroupKillRecursive(priv->cgroup, SIGKILL) <= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to kill all processes"));
            return -1;
        }

        if (virCgroupSetFreezerState(priv->cgroup, "THAWED") < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Unable to thaw all processes"));

            return -1;
        }

        goto cleanup;
    }

    if (priv->cgroup) {
        rc = virCgroupKillPainfully(priv->cgroup);
        if (rc < 0)
            return -1;
        if (rc > 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Some processes refused to die"));
            return -1;
        }
    } else if (vm->pid != 0) {
        /* If cgroup doesn't exist, just try cleaning up the
         * libvirt_lxc process */
        if (virProcessKillPainfully(vm->pid, true) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Processes %1$d refused to die"), (int)vm->pid);
            return -1;
        }
    }

 cleanup:
    virLXCProcessCleanup(driver, vm, reason, cleanupFlags);

    return 0;
}


static virCommand *
virLXCProcessBuildControllerCmd(virLXCDriver *driver,
                                virDomainObj *vm,
                                char **veths,
                                int *ttyFDs,
                                size_t nttyFDs,
                                int *nsInheritFDs,
                                int *files,
                                size_t nfiles,
                                int handshakefdW,
                                int handshakefdR,
                                int * const logfd,
                                const char *pidfile)
{
    size_t i;
    g_autofree char *filterstr = NULL;
    g_autofree char *outputstr = NULL;
    g_autoptr(virCommand) cmd = NULL;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);

    cmd = virCommandNew(vm->def->emulator);

    /* The controller may call ip command, so we have to retain PATH. */
    virCommandAddEnvPass(cmd, "PATH");

    virCommandAddEnvFormat(cmd, "LIBVIRT_DEBUG=%d",
                           virLogGetDefaultPriority());

    if (virLogGetNbFilters() > 0) {
        filterstr = virLogGetFilters();

        virCommandAddEnvPair(cmd, "LIBVIRT_LOG_FILTERS", filterstr);
    }

    if (cfg->log_libvirtd) {
        if (virLogGetNbOutputs() > 0) {
            if (!(outputstr = virLogGetOutputs()))
                return NULL;

            virCommandAddEnvPair(cmd, "LIBVIRT_LOG_OUTPUTS", outputstr);
        }
    } else {
        virCommandAddEnvFormat(cmd,
                               "LIBVIRT_LOG_OUTPUTS=%d:stderr",
                               virLogGetDefaultPriority());
    }

    virCommandAddArgList(cmd, "--name", vm->def->name, NULL);
    for (i = 0; i < nttyFDs; i++) {
        virCommandAddArg(cmd, "--console");
        virCommandAddArgFormat(cmd, "%d", ttyFDs[i]);
        virCommandPassFD(cmd, ttyFDs[i], 0);
    }

    for (i = 0; i < nfiles; i++) {
        virCommandAddArg(cmd, "--passfd");
        virCommandAddArgFormat(cmd, "%d", files[i]);
        virCommandPassFD(cmd, files[i], 0);
    }

    for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++) {
        if (nsInheritFDs[i] > 0) {
            g_autofree char *tmp = g_strdup_printf("--share-%s",
                                                   nsInfoLocal[i]);
            virCommandAddArg(cmd, tmp);
            virCommandAddArgFormat(cmd, "%d", nsInheritFDs[i]);
            virCommandPassFD(cmd, nsInheritFDs[i], 0);
        }
    }

    virCommandAddArgPair(cmd, "--security",
                         virSecurityManagerGetModel(driver->securityManager));

    virCommandAddArg(cmd, "--handshakefds");
    virCommandAddArgFormat(cmd, "%d:%d", handshakefdR, handshakefdW);

    for (i = 0; veths && veths[i]; i++)
        virCommandAddArgList(cmd, "--veth", veths[i], NULL);

    virCommandPassFD(cmd, handshakefdW, 0);
    virCommandPassFD(cmd, handshakefdR, 0);
    virCommandDaemonize(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandSetOutputFD(cmd, logfd);
    virCommandSetErrorFD(cmd, logfd);
    /* So we can pause before exec'ing the controller to
     * write the live domain status XML with the PID */
    virCommandRequireHandshake(cmd);

    return g_steal_pointer(&cmd);
}


static bool
virLXCProcessIgnorableLogLine(const char *str)
{
    if (virLogProbablyLogMessage(str))
        return true;
    if (strstr(str, "PATH="))
        return true;
    if (strstr(str, "error receiving signal from container"))
        return true;
    if (STREQ(str, ""))
        return true;
    return false;
}

static int
virLXCProcessReadLogOutputData(virDomainObj *vm,
                               int fd,
                               char *buf,
                               size_t buflen)
{
    int retries = 10;
    int got = 0;
    char *filter_next = buf;
    bool filtered;

    buf[0] = '\0';

    while (retries) {
        ssize_t bytes;
        bool isdead = false;
        char *eol;

        if (vm->pid == 0 ||
            (kill(vm->pid, 0) == -1 && errno == ESRCH))
            isdead = true;

        /* Any failures should be detected before we read the log, so we
         * always have something useful to report on failure. */
        bytes = saferead(fd, buf+got, buflen-got-1);
        if (bytes < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failure while reading log output"));
            return -1;
        }

        got += bytes;
        buf[got] = '\0';

        /* Filter out debug messages from intermediate libvirt process */
        filtered = false;
        while ((eol = strchr(filter_next, '\n'))) {
            *eol = '\0';
            if (virLXCProcessIgnorableLogLine(filter_next)) {
                memmove(filter_next, eol + 1, got - (eol - buf));
                got -= eol + 1 - filter_next;
                filtered = true;
            } else {
                filter_next = eol + 1;
                *eol = '\n';
            }
        }

        if (got == buflen-1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Out of space while reading log output: %1$s"),
                           buf);
            return -1;
        }

        if (filtered)
            continue;

        if (isdead)
            return got;

        g_usleep(100*1000);
        retries--;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Timed out while reading log output: %1$s"),
                   buf);

    return -1;
}


static int
virLXCProcessReadLogOutput(virDomainObj *vm,
                           char *logfile,
                           off_t pos,
                           char *buf,
                           size_t buflen)
{
    VIR_AUTOCLOSE fd = -1;

    if ((fd = open(logfile, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open log file %1$s"),
                             logfile);
        return -1;
    }

    if (lseek(fd, pos, SEEK_SET) < 0) {
        virReportSystemError(errno,
                             _("Unable to seek log file %1$s to %2$llu"),
                             logfile, (unsigned long long)pos);
        return -1;
    }

    return virLXCProcessReadLogOutputData(vm, fd, buf, buflen);
}


/**
 * virLXCProcessReportStartupLogError:
 * @vm: domain object
 * @logfile: path to the VM logfile
 * @pos: position in @logfile to look for errors
 *
 * Looks for the error message from the LXC container process.
 * Returns:
 * -1: - When reading of error message failed. Reports appropriate error
 *     - When successfully read a non-empty error message. Reports an error with
 *       the following message
 *          'guest failed to start: ' with the error from the log appended
 *
 *  0: - When reading the error was successful but the error log was empty.
 */
static int
virLXCProcessReportStartupLogError(virDomainObj *vm,
                                   char *logfile,
                                   off_t pos)
{
    size_t buflen = 1024;
    g_autofree char *errbuf = g_new0(char, buflen);
    char *p;
    int rc;

    if ((rc = virLXCProcessReadLogOutput(vm, logfile, pos, errbuf, buflen)) < 0)
        return -1;

    if (rc == 0)
        return 0;

    /* strip last newline */
    if ((p = strrchr(errbuf, '\n')) &&
        p[1] == '\0')
        *p = '\0';

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("guest failed to start: %1$s"), errbuf);

    return -1;
}


static int
virLXCProcessEnsureRootFS(virDomainObj *vm)
{
    virDomainFSDef *root = virDomainGetFilesystemForTarget(vm->def, "/");

    if (root)
        return 0;

    if (!(root = virDomainFSDefNew(NULL)))
        goto error;

    root->type = VIR_DOMAIN_FS_TYPE_MOUNT;

    root->src->path = g_strdup("/");
    root->dst = g_strdup("/");

    if (VIR_INSERT_ELEMENT(vm->def->fss,
                           0,
                           vm->def->nfss,
                           root) < 0)
        goto error;

    return 0;

 error:
    virDomainFSDefFree(root);
    return -1;
}

/**
 * virLXCProcessStart:
 * @driver: pointer to driver structure
 * @vm: pointer to virtual machine structure
 * @autoDestroyConn: mark the domain for auto destruction for the passed connection object
 * @reason: reason for switching vm to running state
 *
 * Starts a vm
 *
 * Returns 0 on success or -1 in case of error
 */
int virLXCProcessStart(virLXCDriver * driver,
                       virDomainObj *vm,
                       unsigned int nfiles, int *files,
                       virConnectPtr autoDestroyConn,
                       virDomainRunningReason reason)
{
    int rc = -1, r;
    size_t nttyFDs = 0;
    g_autofree int *ttyFDs = NULL;
    size_t i;
    g_autofree char *logfile = NULL;
    int logfd = -1;
    g_auto(GStrv) veths = NULL;
    int handshakefds[4] = { -1, -1, -1, -1 }; /* two pipes */
    off_t pos = -1;
    g_autofree char *timestamp = NULL;
    int nsInheritFDs[VIR_LXC_DOMAIN_NAMESPACE_LAST];
    g_autoptr(virCommand) cmd = NULL;
    virLXCDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virCaps) caps = NULL;
    virErrorPtr err = NULL;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);
    g_autoptr(virCgroup) selfcgroup = NULL;
    int status;
    g_autofree char *pidfile = NULL;
    unsigned int stopFlags = 0;

    if (virCgroupNewSelf(&selfcgroup) < 0)
        return -1;

    if (!virCgroupHasController(selfcgroup,
                                VIR_CGROUP_CONTROLLER_CPUACCT)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to find 'cpuacct' cgroups controller mount"));
        return -1;
    }
    if (!virCgroupHasController(selfcgroup,
                                VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to find 'devices' cgroups controller mount"));
        return -1;
    }
    if (!virCgroupHasController(selfcgroup,
                                VIR_CGROUP_CONTROLLER_MEMORY)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to find 'memory' cgroups controller mount"));
        return -1;
    }

    if (vm->def->nconsoles == 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("At least one PTY console is required"));
        return -1;
    }

    for (i = 0; i < vm->def->nconsoles; i++) {
        if (vm->def->consoles[i]->source->type != VIR_DOMAIN_CHR_TYPE_PTY) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only PTY console types are supported"));
            return -1;
        }
    }

    if (g_mkdir_with_parents(cfg->logDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("Cannot create log directory '%1$s'"),
                             cfg->logDir);
        return -1;
    }

    if (!vm->def->resource)
        vm->def->resource = g_new0(virDomainResourceDef, 1);

    if (!vm->def->resource->partition)
        vm->def->resource->partition = g_strdup("/machine");

    logfile = g_strdup_printf("%s/%s.log", cfg->logDir, vm->def->name);

    if (!(pidfile = virPidFileBuildPath(cfg->stateDir, vm->def->name)))
        goto cleanup;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    /* Do this up front, so any part of the startup process can add
     * runtime state to vm->def that won't be persisted. This let's us
     * report implicit runtime defaults in the XML, like vnc listen/socket
     */
    VIR_DEBUG("Setting current domain def as transient");
    if (virDomainObjSetDefTransient(driver->xmlopt, vm, NULL) < 0)
        goto cleanup;
    stopFlags |= VIR_LXC_PROCESS_CLEANUP_REMOVE_TRANSIENT;

    /* Run an early hook to set-up missing devices */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        g_autofree char *xml = virDomainDefFormat(vm->def, driver->xmlopt, 0);

        /*
         * If the script raised an error abort the launch
         */
        if (virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                        VIR_HOOK_LXC_OP_PREPARE, VIR_HOOK_SUBOP_BEGIN,
                        NULL, xml, NULL) < 0)
            goto cleanup;
    }

    if (virLXCProcessEnsureRootFS(vm) < 0)
        goto cleanup;

    /* Must be run before security labelling */
    VIR_DEBUG("Preparing host devices");
    if (virLXCPrepareHostDevices(driver, vm->def) < 0)
        goto cleanup;

    /* Here we open all the PTYs we need on the host OS side.
     * The LXC controller will open the guest OS side PTYs
     * and forward I/O between them.
     */
    nttyFDs = vm->def->nconsoles;
    ttyFDs = g_new0(int, nttyFDs);
    for (i = 0; i < vm->def->nconsoles; i++)
        ttyFDs[i] = -1;

    /* If you are using a SecurityDriver with dynamic labelling,
       then generate a security label for isolation */
    VIR_DEBUG("Generating domain security label (if required)");

    if (vm->def->nseclabels &&
        vm->def->seclabels[0]->type == VIR_DOMAIN_SECLABEL_DEFAULT)
        vm->def->seclabels[0]->type = VIR_DOMAIN_SECLABEL_NONE;

    if (virSecurityManagerCheckAllLabel(driver->securityManager, vm->def) < 0)
        goto cleanup;

    if (virSecurityManagerGenLabel(driver->securityManager, vm->def) < 0) {
        virDomainAuditSecurityLabel(vm, false);
        goto cleanup;
    }
    virDomainAuditSecurityLabel(vm, true);
    stopFlags |= VIR_LXC_PROCESS_CLEANUP_RELEASE_SECLABEL;

    VIR_DEBUG("Setting domain security labels");
    if (virSecurityManagerSetAllLabel(driver->securityManager,
                                      vm->def, NULL, false, false) < 0)
        goto cleanup;
    stopFlags |= VIR_LXC_PROCESS_CLEANUP_RESTORE_SECLABEL;

    VIR_DEBUG("Setting up consoles");
    for (i = 0; i < vm->def->nconsoles; i++) {
        char *ttyPath;

        if (virFileOpenTty(&ttyFDs[i], &ttyPath, 1) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failed to allocate tty"));
            goto cleanup;
        }

        g_free(vm->def->consoles[i]->source->data.file.path);
        vm->def->consoles[i]->source->data.file.path = ttyPath;

        g_free(vm->def->consoles[i]->info.alias);
        vm->def->consoles[i]->info.alias = g_strdup_printf("console%zu", i);
    }

    VIR_DEBUG("Setting up Interfaces");
    if (virLXCProcessSetupInterfaces(driver, vm->def, &veths) < 0)
        goto cleanup;

    VIR_DEBUG("Setting up namespaces if any");
    if (virLXCProcessSetupNamespaces(driver, vm->def->namespaceData, nsInheritFDs) < 0)
        goto cleanup;

    VIR_DEBUG("Preparing to launch");
    if ((logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT,
             S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("Failed to open '%1$s'"),
                             logfile);
        goto cleanup;
    }

    if (virPipe(&handshakefds[0]) < 0 ||
        virPipe(&handshakefds[2]) < 0)
        goto cleanup;

    if (!(cmd = virLXCProcessBuildControllerCmd(driver,
                                                vm,
                                                veths,
                                                ttyFDs, nttyFDs,
                                                nsInheritFDs,
                                                files, nfiles,
                                                handshakefds[1],
                                                handshakefds[2],
                                                &logfd,
                                                pidfile)))
        goto cleanup;

    /* now that we know it is about to start call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        g_autofree char *xml = virDomainDefFormat(vm->def, driver->xmlopt, 0);

        /*
         * If the script raised an error abort the launch
         */
        if (virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                        VIR_HOOK_LXC_OP_START, VIR_HOOK_SUBOP_BEGIN,
                        NULL, xml, NULL) < 0)
            goto cleanup;
    }

    /* Log timestamp */
    if ((timestamp = virTimeStringNow()) == NULL)
        goto cleanup;
    if (safewrite(logfd, timestamp, strlen(timestamp)) < 0 ||
        safewrite(logfd, START_POSTFIX, strlen(START_POSTFIX)) < 0) {
        VIR_WARN("Unable to write timestamp to logfile: %s",
                 g_strerror(errno));
    }

    /* Log generated command line */
    virCommandWriteArgLog(cmd, logfd);
    if ((pos = lseek(logfd, 0, SEEK_END)) < 0)
        VIR_WARN("Unable to seek to end of logfile: %s",
                 g_strerror(errno));

    VIR_DEBUG("Launching container");
    virCommandRawStatus(cmd);
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    if (status != 0) {
        if (virLXCProcessReportStartupLogError(vm, logfile, pos) < 0)
            goto cleanup;

        /* In case there isn't an error in the logs report one based on the exit status */
        if (WIFEXITED(status)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("guest failed to start: unexpected exit status %1$d"),
                           WEXITSTATUS(status));
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("guest failed to start: terminated abnormally"));
        }
        goto cleanup;
    }

    /* It has started running, so get its pid */
    if ((r = virPidFileReadPath(pidfile, &vm->pid)) < 0) {
        if (virLXCProcessReportStartupLogError(vm, logfile, pos) < 0)
            goto cleanup;

        /* In case there isn't an error in the logs report that we failed to read the pidfile */
        virReportSystemError(-r, _("Failed to read pid file %1$s"), pidfile);
        goto cleanup;
    }

    priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_FAILED;
    priv->wantReboot = false;
    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);
    priv->doneStopEvent = false;

    if (VIR_CLOSE(handshakefds[1]) < 0 ||
        VIR_CLOSE(handshakefds[2]) < 0) {
        virReportSystemError(errno, "%s", _("could not close handshake fd"));
        goto cleanup;
    }

    if (virCommandHandshakeWait(cmd) < 0)
        goto cleanup;

    /* Write domain status to disk for the controller to
     * read when it starts */
    if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
        goto cleanup;

    /* Allow the child to exec the controller */
    if (virCommandHandshakeNotify(cmd) < 0)
        goto cleanup;

    if (g_atomic_int_add(&driver->nactive, 1) == 0 && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);

    /* The first synchronization point is when the controller creates CGroups. */
    if (lxcContainerWaitForContinue(handshakefds[0]) < 0) {
        virLXCProcessReportStartupLogError(vm, logfile, pos);
        goto cleanup;
    }

    priv->machineName = virLXCDomainGetMachineName(vm->def, vm->pid);
    if (!priv->machineName)
        goto cleanup;

    /* We know the cgroup must exist by this synchronization
     * point so lets detect that first, since it gives us a
     * more reliable way to kill everything off if something
     * goes wrong from here onwards ... */
    if (virCgroupNewDetectMachine(vm->def->name, "lxc",
                                  vm->pid, -1, priv->machineName,
                                  &priv->cgroup) < 0)
        goto cleanup;

    if (!priv->cgroup) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No valid cgroup for machine %1$s"),
                       vm->def->name);
        goto cleanup;
    }

    if (lxcContainerSendContinue(handshakefds[3]) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to send continue signal to controller"));
        goto cleanup;
    }

    /* The second synchronization point is when the controller finished
     * creating the container. */
    if (lxcContainerWaitForContinue(handshakefds[0]) < 0) {
        virLXCProcessReportStartupLogError(vm, logfile, pos);
        goto cleanup;
    }

    /* And we can get the first monitor connection now too */
    if (!(priv->monitor = virLXCProcessConnectMonitor(driver, vm))) {
        /* Intentionally overwrite the real monitor error message,
         * since a better one is almost always found in the logs
         */
        virLXCProcessReportStartupLogError(vm, logfile, pos);
        goto cleanup;
    }

    if (autoDestroyConn)
        virCloseCallbacksDomainAdd(vm, autoDestroyConn, lxcProcessAutoDestroy);

    /* We don't need the temporary NIC names anymore, clear them */
    virLXCProcessCleanInterfaces(vm->def);

    /* finally we can call the 'started' hook script if any */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        g_autofree char *xml = virDomainDefFormat(vm->def, driver->xmlopt, 0);

        /*
         * If the script raised an error abort the launch
         */
        if (virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                        VIR_HOOK_LXC_OP_STARTED, VIR_HOOK_SUBOP_BEGIN,
                        NULL, xml, NULL) < 0)
            goto cleanup;
    }

    rc = 0;

 cleanup:
    if (VIR_CLOSE(logfd) < 0) {
        virReportSystemError(errno, "%s", _("could not close logfile"));
        rc = -1;
    }
    if (rc != 0) {
        virErrorPreserveLast(&err);
        if (virDomainObjIsActive(vm)) {
            virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED, 0);
        } else {
            /* virLXCProcessStop() is NOP if the container is not active.
             * If there was a failure whilst creating it, cleanup manually. */
            virLXCProcessCleanup(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED, stopFlags);
        }
    }
    for (i = 0; i < nttyFDs; i++)
        VIR_FORCE_CLOSE(ttyFDs[i]);
    for (i = 0; i < G_N_ELEMENTS(handshakefds); i++)
        VIR_FORCE_CLOSE(handshakefds[i]);

    virErrorRestore(&err);

    return rc;
}


static int
virLXCProcessAutostartDomain(virDomainObj *vm,
                             void *opaque G_GNUC_UNUSED)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(vm);
    virLXCDomainObjPrivate *priv = vm->privateData;
    virObjectEvent *event;
    int rc = 0;

    if (!vm->autostart ||
        virDomainObjIsActive(vm))
        return 0;

    rc = virLXCProcessStart(priv->driver, vm, 0, NULL, NULL, VIR_DOMAIN_RUNNING_BOOTED);
    virDomainAuditStart(vm, "booted", rc >= 0);

    if (rc < 0) {
        VIR_ERROR(_("Failed to autostart VM '%1$s': %2$s"),
                  vm->def->name,
                  virGetLastErrorMessage());
        return -1;
    }

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STARTED,
                                              VIR_DOMAIN_EVENT_STARTED_BOOTED);
    virObjectEventStateQueue(priv->driver->domainEventState, event);

    return 0;
}


void
virLXCProcessAutostartAll(virLXCDriver *driver)
{
    virDomainObjListForEach(driver->domains, false, virLXCProcessAutostartDomain, NULL);
}


static void
virLXCProcessReconnectNotifyNets(virDomainDef *def)
{
    size_t i;
    g_autoptr(virConnect) conn = NULL;

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDef *net = def->nets[i];

        /* type='bridge|network|ethernet' interfaces may be using an
         * autogenerated netdev name, so we should update the counter
         * for autogenerated names to skip past this one.
         */
        switch (virDomainNetGetActualType(net)) {
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            virNetDevReserveName(net->ifname);
            break;
        case VIR_DOMAIN_NET_TYPE_DIRECT:
        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        case VIR_DOMAIN_NET_TYPE_UDP:
        case VIR_DOMAIN_NET_TYPE_VDPA:
        case VIR_DOMAIN_NET_TYPE_NULL:
        case VIR_DOMAIN_NET_TYPE_VDS:
        case VIR_DOMAIN_NET_TYPE_LAST:
            break;
        }

        if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK && !conn)
            conn = virGetConnectNetwork();

        virDomainNetNotifyActualDevice(conn, def, net);
    }
}


static int
virLXCProcessReconnectDomain(virDomainObj *vm,
                             void *opaque)
{
    virLXCDriver *driver = opaque;
    virLXCDomainObjPrivate *priv;
    g_autoptr(virLXCDriverConfig) cfg = virLXCDriverGetConfig(driver);
    int ret = -1;

    virObjectLock(vm);
    VIR_DEBUG("Reconnect id=%d pid=%d state=%d", vm->def->id, vm->pid, vm->state.state);

    priv = vm->privateData;

    if (vm->pid != 0) {
        vm->def->id = vm->pid;
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNKNOWN);

        if (g_atomic_int_add(&driver->nactive, 1) == 0 && driver->inhibitCallback)
            driver->inhibitCallback(true, driver->inhibitOpaque);

        if (!(priv->monitor = virLXCProcessConnectMonitor(driver, vm)))
            goto error;

        priv->machineName = virLXCDomainGetMachineName(vm->def, vm->pid);
        if (!priv->machineName)
            goto cleanup;

        if (virCgroupNewDetectMachine(vm->def->name, "lxc", vm->pid, -1,
                                      priv->machineName, &priv->cgroup) < 0)
            goto error;

        if (!priv->cgroup) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("No valid cgroup for machine %1$s"),
                           vm->def->name);
            goto error;
        }

        if (virLXCUpdateActiveUSBHostdevs(driver, vm->def) < 0)
            goto error;

        if (virSecurityManagerReserveLabel(driver->securityManager,
                                           vm->def, vm->pid) < 0)
            goto error;

        virLXCProcessReconnectNotifyNets(vm->def);

        if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0)
            VIR_WARN("Cannot update XML for running LXC guest %s", vm->def->name);

        /* now that we know it's reconnected call the hook if present */
        if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
            g_autofree char *xml = virDomainDefFormat(vm->def, driver->xmlopt, 0);

            /* we can't stop the operation even if the script raised an error */
            if (virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                            VIR_HOOK_LXC_OP_RECONNECT, VIR_HOOK_SUBOP_BEGIN,
                            NULL, xml, NULL) < 0)
                goto error;
        }

    } else {
        vm->def->id = -1;
    }

    ret = 0;
 cleanup:
    virObjectUnlock(vm);
    return ret;

 error:
    virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED, 0);
    virDomainAuditStop(vm, "failed");
    goto cleanup;
}


int virLXCProcessReconnectAll(virLXCDriver *driver,
                              virDomainObjList *doms)
{
    virDomainObjListForEach(doms, false, virLXCProcessReconnectDomain, driver);
    return 0;
}
