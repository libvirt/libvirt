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
#include "lxc_cgroup.h"
#include "lxc_fuse.h"
#include "datatypes.h"
#include "virfile.h"
#include "virpidfile.h"
#include "virnetdev.h"
#include "virnetdevveth.h"
#include "virnetdevbridge.h"
#include "virnetdevopenvswitch.h"
#include "virtime.h"
#include "domain_nwfilter.h"
#include "network/bridge_driver.h"
#include "viralloc.h"
#include "domain_audit.h"
#include "virerror.h"
#include "virlog.h"
#include "vircommand.h"
#include "lxc_hostdev.h"
#include "virhook.h"
#include "virstring.h"
#include "viratomic.h"
#include "virprocess.h"
#include "virsystemd.h"
#include "netdev_bandwidth_conf.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_process");

#define START_POSTFIX ": starting up\n"

static virDomainObjPtr
lxcProcessAutoDestroy(virDomainObjPtr dom,
                      virConnectPtr conn,
                      void *opaque)
{
    virLXCDriverPtr driver = opaque;
    virObjectEventPtr event = NULL;
    virLXCDomainObjPrivatePtr priv;

    VIR_DEBUG("driver=%p dom=%s conn=%p", driver, dom->def->name, conn);

    priv = dom->privateData;
    VIR_DEBUG("Killing domain");
    virLXCProcessStop(driver, dom, VIR_DOMAIN_SHUTOFF_DESTROYED);
    virDomainAuditStop(dom, "destroyed");
    event = virDomainEventLifecycleNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    priv->doneStopEvent = true;

    if (!dom->persistent) {
        virDomainObjListRemove(driver->domains, dom);
        dom = NULL;
    }

    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);

    return dom;
}

/*
 * Precondition: driver is locked
 */
static int
virLXCProcessReboot(virLXCDriverPtr driver,
                    virDomainObjPtr vm)
{
    virConnectPtr conn = virCloseCallbacksGetConn(driver->closeCallbacks, vm);
    int reason = vm->state.reason;
    bool autodestroy = false;
    int ret = -1;
    virDomainDefPtr savedDef;

    VIR_DEBUG("Faking reboot");

    if (conn) {
        virObjectRef(conn);
        autodestroy = true;
    } else {
        conn = virConnectOpen("lxc:///");
        /* Ignoring NULL conn which is mostly harmless here */
    }

    /* In a reboot scenario, we need to make sure we continue
     * to use the current 'def', and not switch to 'newDef'.
     * So temporarily hide the newDef and then reinstate it
     */
    savedDef = vm->newDef;
    vm->newDef = NULL;
    virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
    vm->newDef = savedDef;
    if (virLXCProcessStart(conn, driver, vm,
                           0, NULL, autodestroy, reason) < 0) {
        VIR_WARN("Unable to handle reboot of vm %s",
                 vm->def->name);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virObjectUnref(conn);
    return ret;
}


static void
lxcProcessRemoveDomainStatus(virLXCDriverConfigPtr cfg,
                              virDomainObjPtr vm)
{
    char ebuf[1024];
    char *file = NULL;

    if (virAsprintf(&file, "%s/%s.xml", cfg->stateDir, vm->def->name) < 0)
        return;

    if (unlink(file) < 0 && errno != ENOENT && errno != ENOTDIR)
        VIR_WARN("Failed to remove domain XML for %s: %s",
                 vm->def->name, virStrerror(errno, ebuf, sizeof(ebuf)));
    VIR_FREE(file);
}


/**
 * virLXCProcessCleanup:
 * @driver: pointer to driver structure
 * @vm: pointer to VM to clean up
 * @reason: reason for switching the VM to shutoff state
 *
 * Cleanout resources associated with the now dead VM
 *
 */
static void virLXCProcessCleanup(virLXCDriverPtr driver,
                                 virDomainObjPtr vm,
                                 virDomainShutoffReason reason)
{
    size_t i;
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virNetDevVPortProfilePtr vport = NULL;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    VIR_DEBUG("Cleanup VM name=%s pid=%d reason=%d",
              vm->def->name, (int)vm->pid, (int)reason);

    /* now that we know it's stopped call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, driver->caps, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                    VIR_HOOK_LXC_OP_STOPPED, VIR_HOOK_SUBOP_END,
                    NULL, xml, NULL);
        VIR_FREE(xml);
    }

    /* Stop autodestroy in case guest is restarted */
    virCloseCallbacksUnset(driver->closeCallbacks, vm,
                           lxcProcessAutoDestroy);

    if (priv->monitor) {
        virLXCMonitorClose(priv->monitor);
        virObjectUnref(priv->monitor);
        priv->monitor = NULL;
    }

    virPidFileDelete(cfg->stateDir, vm->def->name);
    lxcProcessRemoveDomainStatus(cfg, vm);

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);
    vm->pid = -1;
    vm->def->id = -1;

    if (virAtomicIntDecAndTest(&driver->nactive) && driver->inhibitCallback)
        driver->inhibitCallback(false, driver->inhibitOpaque);

    virLXCDomainReAttachHostDevices(driver, vm->def);

    for (i = 0; i < vm->def->nnets; i++) {
        virDomainNetDefPtr iface = vm->def->nets[i];
        vport = virDomainNetGetActualVirtPortProfile(iface);
        if (iface->ifname) {
            if (vport &&
                vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
                ignore_value(virNetDevOpenvswitchRemovePort(
                                virDomainNetGetActualBridgeName(iface),
                                iface->ifname));
            ignore_value(virNetDevVethDelete(iface->ifname));
        }
        networkReleaseActualDevice(vm->def, iface);
    }

    virDomainConfVMNWFilterTeardown(vm);

    if (priv->cgroup) {
        virCgroupRemove(priv->cgroup);
        virCgroupFree(&priv->cgroup);
    }

    /* Get machined to terminate the machine as it may not have cleaned it
     * properly. See https://bugs.freedesktop.org/show_bug.cgi?id=68370 for
     * the bug we are working around here.
     */
    virCgroupTerminateMachine(priv->machineName);

    /* The "release" hook cleans up additional resources */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, driver->caps, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                    VIR_HOOK_LXC_OP_RELEASE, VIR_HOOK_SUBOP_END,
                    NULL, xml, NULL);
        VIR_FREE(xml);
    }

    virDomainObjRemoveTransientDef(vm);
    virObjectUnref(cfg);
}


int
virLXCProcessValidateInterface(virDomainNetDefPtr net)
{
    if (net->script) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("scripts are not supported on LXC network interfaces"));
        return -1;
    }
    return 0;
}


char *
virLXCProcessSetupInterfaceTap(virDomainDefPtr vm,
                               virDomainNetDefPtr net,
                               const char *brname)
{
    char *ret = NULL;
    char *parentVeth;
    char *containerVeth = NULL;
    virNetDevVPortProfilePtr vport = virDomainNetGetActualVirtPortProfile(net);

    VIR_DEBUG("calling vethCreate()");
    parentVeth = net->ifname;
    if (virNetDevVethCreate(&parentVeth, &containerVeth) < 0)
        goto cleanup;
    VIR_DEBUG("parentVeth: %s, containerVeth: %s", parentVeth, containerVeth);

    if (net->ifname == NULL)
        net->ifname = parentVeth;

    if (virNetDevSetMAC(containerVeth, &net->mac) < 0)
        goto cleanup;

    if (brname) {
        if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH) {
            if (virNetDevOpenvswitchAddPort(brname, parentVeth, &net->mac, vm->uuid,
                                            vport, virDomainNetGetActualVlan(net)) < 0)
                goto cleanup;
        } else {
            if (virNetDevBridgeAddPort(brname, parentVeth) < 0)
                goto cleanup;
        }
    }

    if (virNetDevSetOnline(parentVeth, true) < 0)
        goto cleanup;

    if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_ETHERNET) {
        /* Set IP info for the host side, but only if the type is
         * 'ethernet'.
         */
        if (virNetDevIPInfoAddToDev(parentVeth, &net->hostIP) < 0)
            goto cleanup;
    }

    if (net->filter &&
        virDomainConfNWFilterInstantiate(vm->uuid, net) < 0)
        goto cleanup;

    ret = containerVeth;

 cleanup:
    return ret;
}


char *virLXCProcessSetupInterfaceDirect(virConnectPtr conn,
                                        virDomainDefPtr def,
                                        virDomainNetDefPtr net)
{
    char *ret = NULL;
    char *res_ifname = NULL;
    virLXCDriverPtr driver = conn->privateData;
    virNetDevBandwidthPtr bw;
    virNetDevVPortProfilePtr prof;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);
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
        goto cleanup;

    ret = res_ifname;

 cleanup:
    virObjectUnref(cfg);
    return ret;
}

static const char *nsInfoLocal[VIR_LXC_DOMAIN_NAMESPACE_LAST] = {
    [VIR_LXC_DOMAIN_NAMESPACE_SHARENET] = "net",
    [VIR_LXC_DOMAIN_NAMESPACE_SHAREIPC] = "ipc",
    [VIR_LXC_DOMAIN_NAMESPACE_SHAREUTS] = "uts",
};

static int virLXCProcessSetupNamespaceName(virConnectPtr conn, int ns_type, const char *name)
{
    virLXCDriverPtr driver = conn->privateData;
    int fd = -1;
    virDomainObjPtr vm;
    virLXCDomainObjPrivatePtr priv;
    char *path;

    vm = virDomainObjListFindByName(driver->domains, name);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("No domain with matching name '%s'"), name);
        return -1;
    }

    priv = vm->privateData;
    if (!priv->initpid) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Init pid is not yet available"));
        goto cleanup;
    }

    if (virAsprintf(&path, "/proc/%lld/ns/%s",
                    (long long int)priv->initpid,
                    nsInfoLocal[ns_type]) < 0)
        goto cleanup;

    if ((fd = open(path, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("failed to open ns %s"),
                             virLXCDomainNamespaceTypeToString(ns_type));
        goto cleanup;
    }

 cleanup:
    VIR_FREE(path);
    virObjectUnlock(vm);
    virObjectUnref(vm);
    return fd;
}


static int virLXCProcessSetupNamespacePID(int ns_type, const char *name)
{
    int fd;
    char *path;

    if (virAsprintf(&path, "/proc/%s/ns/%s",
                    name,
                    nsInfoLocal[ns_type]) < 0)
        return -1;
    fd = open(path, O_RDONLY);
    VIR_FREE(path);
    if (fd < 0) {
        virReportSystemError(errno,
                             _("failed to open ns %s"),
                             virLXCDomainNamespaceTypeToString(ns_type));
        return -1;
    }
    return fd;
}


static int virLXCProcessSetupNamespaceNet(int ns_type, const char *name)
{
    char *path;
    int fd;
    if (ns_type != VIR_LXC_DOMAIN_NAMESPACE_SHARENET) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("'netns' namespace source can only be "
                         "used with sharenet"));
        return -1;
    }

    if (virAsprintf(&path, "/var/run/netns/%s", name) < 0)
        return  -1;
    fd = open(path, O_RDONLY);
    VIR_FREE(path);
    if (fd < 0) {
        virReportSystemError(errno,
                             _("failed to open netns %s"), name);
        return -1;
    }
    return fd;
}


/**
 * virLXCProcessSetupNamespaces:
 * @conn: pointer to connection
 * @def: pointer to virtual machines namespaceData
 * @nsFDs: out parameter to store the namespace FD
 *
 * Opens the specified namespace that needs to be shared and
 * will moved into the container namespace later after clone has been called.
 *
 * Returns 0 on success or -1 in case of error
 */
static int virLXCProcessSetupNamespaces(virConnectPtr conn,
                                        lxcDomainDefPtr lxcDef,
                                        int *nsFDs)
{
    size_t i;

    for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++)
        nsFDs[i] = -1;
    /*If there are no namespace to be opened just return success*/
    if (lxcDef == NULL)
        return 0;

    for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++) {
        switch (lxcDef->ns_source[i]) {
        case VIR_LXC_DOMAIN_NAMESPACE_SOURCE_NONE:
            continue;
        case VIR_LXC_DOMAIN_NAMESPACE_SOURCE_NAME:
            if ((nsFDs[i] = virLXCProcessSetupNamespaceName(conn, i, lxcDef->ns_val[i])) < 0)
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
 * @conn: pointer to connection
 * @def: pointer to virtual machine structure
 * @nveths: number of interfaces
 * @veths: interface names
 *
 * Sets up the container interfaces by creating the veth device pairs and
 * attaching the parent end to the appropriate bridge.  The container end
 * will moved into the container namespace later after clone has been called.
 *
 * Returns 0 on success or -1 in case of error
 */
static int virLXCProcessSetupInterfaces(virConnectPtr conn,
                                        virDomainDefPtr def,
                                        size_t *nveths,
                                        char ***veths)
{
    int ret = -1;
    size_t i;
    size_t niface = 0;
    virDomainNetDefPtr net;
    virDomainNetType type;

    for (i = 0; i < def->nnets; i++) {
        char *veth = NULL;
        virNetDevBandwidthPtr actualBandwidth;
        /* If appropriate, grab a physical device from the configured
         * network's pool of devices, or resolve bridge device name
         * to the one defined in the network definition.
         */
        net = def->nets[i];

        if (virLXCProcessValidateInterface(net) < 0)
            return -1;

        if (networkAllocateActualDevice(def, net) < 0)
            goto cleanup;

        if (VIR_EXPAND_N(*veths, *nveths, 1) < 0)
            goto cleanup;

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
            if (!(veth = virLXCProcessSetupInterfaceDirect(conn, def, net)))
                goto cleanup;
            break;

        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_UDP:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_LAST:
        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unsupported network type %s"),
                           virDomainNetTypeToString(type));
            goto cleanup;

        }

        /* Set bandwidth or warn if requested and not supported. */
        actualBandwidth = virDomainNetGetActualBandwidth(net);
        if (actualBandwidth) {
            if (virNetDevSupportBandwidth(type)) {
                if (virNetDevBandwidthSet(net->ifname, actualBandwidth, false) < 0)
                    goto cleanup;
            } else {
                VIR_WARN("setting bandwidth on interfaces of "
                         "type '%s' is not implemented yet",
                         virDomainNetTypeToString(type));
            }
        }

        (*veths)[(*nveths)-1] = veth;

        if (VIR_STRDUP(def->nets[i]->ifname_guest_actual, veth) < 0)
            goto cleanup;

        /* Make sure all net definitions will have a name in the container */
        if (!net->ifname_guest) {
            if (virAsprintf(&net->ifname_guest, "eth%zu", niface) < 0)
                return -1;
            niface++;
        }
    }

    ret = 0;

 cleanup:
    if (ret < 0) {
        for (i = 0; i < def->nnets; i++) {
            virDomainNetDefPtr iface = def->nets[i];
            virNetDevVPortProfilePtr vport = virDomainNetGetActualVirtPortProfile(iface);
            if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
                ignore_value(virNetDevOpenvswitchRemovePort(
                                virDomainNetGetActualBridgeName(iface),
                                iface->ifname));
            networkReleaseActualDevice(def, iface);
        }
    }
    return ret;
}

static void
virLXCProcessCleanInterfaces(virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < def->nnets; i++) {
        VIR_FREE(def->nets[i]->ifname_guest_actual);
        VIR_DEBUG("Cleared net names: %s", def->nets[i]->ifname_guest);
    }
}


extern virLXCDriverPtr lxc_driver;
static void virLXCProcessMonitorEOFNotify(virLXCMonitorPtr mon,
                                          virDomainObjPtr vm)
{
    virLXCDriverPtr driver = lxc_driver;
    virObjectEventPtr event = NULL;
    virLXCDomainObjPrivatePtr priv;

    VIR_DEBUG("mon=%p vm=%p", mon, vm);

    virObjectLock(vm);

    priv = vm->privateData;
    virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
    if (!priv->wantReboot) {
        virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
        if (!priv->doneStopEvent) {
            event = virDomainEventLifecycleNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             priv->stopReason);
            virDomainAuditStop(vm, "shutdown");
        } else {
            VIR_DEBUG("Stop event has already been sent");
        }
        if (!vm->persistent) {
            virDomainObjListRemove(driver->domains, vm);
            vm = NULL;
        }
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
            if (!vm->persistent) {
                virDomainObjListRemove(driver->domains, vm);
                vm = NULL;
            }
        }
    }

    if (vm)
        virObjectUnlock(vm);
    if (event)
        virObjectEventStateQueue(driver->domainEventState, event);
}

static void virLXCProcessMonitorExitNotify(virLXCMonitorPtr mon ATTRIBUTE_UNUSED,
                                           virLXCMonitorExitStatus status,
                                           virDomainObjPtr vm)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;

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
    char *path = NULL;
    struct stat sb;
    int ret = -1;

    if (virAsprintf(&path, "/proc/%lld/ns/%s",
                    (long long) pid, nsname) < 0)
        goto cleanup;

    if (stat(path, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to stat %s"), path);
        goto cleanup;
    }

    *inode = sb.st_ino;
    ret = 0;

 cleanup:
    VIR_FREE(path);
    return ret;
}


/* XXX a little evil */
extern virLXCDriverPtr lxc_driver;
static void virLXCProcessMonitorInitNotify(virLXCMonitorPtr mon ATTRIBUTE_UNUSED,
                                           pid_t initpid,
                                           virDomainObjPtr vm)
{
    virLXCDriverPtr driver = lxc_driver;
    virLXCDomainObjPrivatePtr priv;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);
    ino_t inode = 0;

    virObjectLock(vm);

    priv = vm->privateData;
    priv->initpid = initpid;

    if (virLXCProcessGetNsInode(initpid, "pid", &inode) < 0) {
        VIR_WARN("Cannot obtain pid NS inode for %lld: %s",
                 (long long) initpid,
                 virGetLastErrorMessage());
        virResetLastError();
    }
    virDomainAuditInit(vm, initpid, inode);

    if (virDomainSaveStatus(lxc_driver->xmlopt, cfg->stateDir, vm, lxc_driver->caps) < 0)
        VIR_WARN("Cannot update XML with PID for LXC %s", vm->def->name);

    virObjectUnlock(vm);
    virObjectUnref(cfg);
}

static virLXCMonitorCallbacks monitorCallbacks = {
    .eofNotify = virLXCProcessMonitorEOFNotify,
    .exitNotify = virLXCProcessMonitorExitNotify,
    .initNotify = virLXCProcessMonitorInitNotify,
};


static virLXCMonitorPtr virLXCProcessConnectMonitor(virLXCDriverPtr driver,
                                                    virDomainObjPtr vm)
{
    virLXCMonitorPtr monitor = NULL;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    if (virSecurityManagerSetSocketLabel(driver->securityManager, vm->def) < 0)
        goto cleanup;

    /* Hold an extra reference because we can't allow 'vm' to be
     * deleted while the monitor is active */
    virObjectRef(vm);

    monitor = virLXCMonitorNew(vm, cfg->stateDir, &monitorCallbacks);

    if (monitor == NULL)
        virObjectUnref(vm);

    if (virSecurityManagerClearSocketLabel(driver->securityManager, vm->def) < 0) {
        if (monitor) {
            virObjectUnref(monitor);
            monitor = NULL;
        }
        goto cleanup;
    }

 cleanup:
    virObjectUnref(cfg);
    return monitor;
}


int virLXCProcessStop(virLXCDriverPtr driver,
                      virDomainObjPtr vm,
                      virDomainShutoffReason reason)
{
    int rc;
    virLXCDomainObjPrivatePtr priv;

    VIR_DEBUG("Stopping VM name=%s pid=%d reason=%d",
              vm->def->name, (int)vm->pid, (int)reason);
    if (!virDomainObjIsActive(vm)) {
        VIR_DEBUG("VM '%s' not active", vm->def->name);
        return 0;
    }

    priv = vm->privateData;

    virSecurityManagerRestoreAllLabel(driver->securityManager,
                                      vm->def, false, false);
    virSecurityManagerReleaseLabel(driver->securityManager, vm->def);
    /* Clear out dynamically assigned labels */
    if (vm->def->nseclabels &&
        vm->def->seclabels[0]->type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        VIR_FREE(vm->def->seclabels[0]->model);
        VIR_FREE(vm->def->seclabels[0]->label);
        VIR_FREE(vm->def->seclabels[0]->imagelabel);
    }

    /* If the LXC domain is suspended we send all processes a SIGKILL
     * and thaw them. Upon wakeup the process sees the pending signal
     * and dies immediately. It is guaranteed that priv->cgroup != NULL
     * here because the domain has aleady been suspended using the
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
    } else if (vm->pid > 0) {
        /* If cgroup doesn't exist, just try cleaning up the
         * libvirt_lxc process */
        if (virProcessKillPainfully(vm->pid, true) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Processes %d refused to die"), (int)vm->pid);
            return -1;
        }
    }

 cleanup:
    virLXCProcessCleanup(driver, vm, reason);

    return 0;
}


static virCommandPtr
virLXCProcessBuildControllerCmd(virLXCDriverPtr driver,
                                virDomainObjPtr vm,
                                int nveths,
                                char **veths,
                                int *ttyFDs,
                                size_t nttyFDs,
                                int *nsInheritFDs,
                                int *files,
                                size_t nfiles,
                                int handshakefd,
                                int * const logfd,
                                const char *pidfile)
{
    size_t i;
    char *filterstr;
    char *outputstr;
    virCommandPtr cmd;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);

    cmd = virCommandNew(vm->def->emulator);

    /* The controller may call ip command, so we have to retain PATH. */
    virCommandAddEnvPassBlockSUID(cmd, "PATH", "/bin:/usr/bin");

    virCommandAddEnvFormat(cmd, "LIBVIRT_DEBUG=%d",
                           virLogGetDefaultPriority());

    if (virLogGetNbFilters() > 0) {
        filterstr = virLogGetFilters();
        if (!filterstr) {
            virReportOOMError();
            goto cleanup;
        }

        virCommandAddEnvPair(cmd, "LIBVIRT_LOG_FILTERS", filterstr);
        VIR_FREE(filterstr);
    }

    if (cfg->log_libvirtd) {
        if (virLogGetNbOutputs() > 0) {
            outputstr = virLogGetOutputs();
            if (!outputstr) {
                virReportOOMError();
                goto cleanup;
            }

            virCommandAddEnvPair(cmd, "LIBVIRT_LOG_OUTPUTS", outputstr);
            VIR_FREE(outputstr);
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
            char *tmp = NULL;
            if (virAsprintf(&tmp, "--share-%s",
                            nsInfoLocal[i]) < 0)
                goto cleanup;
            virCommandAddArg(cmd, tmp);
            virCommandAddArgFormat(cmd, "%d", nsInheritFDs[i]);
            virCommandPassFD(cmd, nsInheritFDs[i], 0);
            VIR_FREE(tmp);
        }
    }

    virCommandAddArgPair(cmd, "--security",
                         virSecurityManagerGetModel(driver->securityManager));

    virCommandAddArg(cmd, "--handshake");
    virCommandAddArgFormat(cmd, "%d", handshakefd);

    for (i = 0; i < nveths; i++)
        virCommandAddArgList(cmd, "--veth", veths[i], NULL);

    virCommandPassFD(cmd, handshakefd, 0);
    virCommandDaemonize(cmd);
    virCommandSetPidFile(cmd, pidfile);
    virCommandSetOutputFD(cmd, logfd);
    virCommandSetErrorFD(cmd, logfd);
    /* So we can pause before exec'ing the controller to
     * write the live domain status XML with the PID */
    virCommandRequireHandshake(cmd);

    return cmd;
 cleanup:
    virCommandFree(cmd);
    virObjectUnref(cfg);
    return NULL;
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
virLXCProcessReadLogOutputData(virDomainObjPtr vm,
                               int fd,
                               char *buf,
                               size_t buflen)
{
    int retries = 10;
    int got = 0;
    int ret = -1;
    char *filter_next = buf;

    buf[0] = '\0';

    while (retries) {
        ssize_t bytes;
        bool isdead = false;
        char *eol;

        if (vm->pid <= 0 ||
            (kill(vm->pid, 0) == -1 && errno == ESRCH))
            isdead = true;

        /* Any failures should be detected before we read the log, so we
         * always have something useful to report on failure. */
        bytes = saferead(fd, buf+got, buflen-got-1);
        if (bytes < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failure while reading log output"));
            goto cleanup;
        }

        got += bytes;
        buf[got] = '\0';

        /* Filter out debug messages from intermediate libvirt process */
        while ((eol = strchr(filter_next, '\n'))) {
            *eol = '\0';
            if (virLXCProcessIgnorableLogLine(filter_next)) {
                memmove(filter_next, eol + 1, got - (eol - buf));
                got -= eol + 1 - filter_next;
            } else {
                filter_next = eol + 1;
                *eol = '\n';
            }
        }

        if (got == buflen-1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Out of space while reading log output: %s"),
                           buf);
            goto cleanup;
        }

        if (isdead) {
            ret = got;
            goto cleanup;
        }

        usleep(100*1000);
        retries--;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Timed out while reading log output: %s"),
                   buf);

 cleanup:
    return ret;
}


static int
virLXCProcessReadLogOutput(virDomainObjPtr vm,
                           char *logfile,
                           off_t pos,
                           char *buf,
                           size_t buflen)
{
    int fd = -1;
    int ret;

    if ((fd = open(logfile, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open log file %s"),
                             logfile);
        return -1;
    }

    if (lseek(fd, pos, SEEK_SET) < 0) {
        virReportSystemError(errno,
                             _("Unable to seek log file %s to %llu"),
                             logfile, (unsigned long long)pos);
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

    ret = virLXCProcessReadLogOutputData(vm,
                                         fd,
                                         buf,
                                         buflen);

    VIR_FORCE_CLOSE(fd);
    return ret;
}


static int
virLXCProcessEnsureRootFS(virDomainObjPtr vm)
{
    virDomainFSDefPtr root = virDomainGetFilesystemForTarget(vm->def, "/");

    if (root)
        return 0;

    if (!(root = virDomainFSDefNew()))
        goto error;

    root->type = VIR_DOMAIN_FS_TYPE_MOUNT;

    if (VIR_STRDUP(root->src->path, "/") < 0 ||
        VIR_STRDUP(root->dst, "/") < 0)
        goto error;

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
 * @conn: pointer to connection
 * @driver: pointer to driver structure
 * @vm: pointer to virtual machine structure
 * @autoDestroy: mark the domain for auto destruction
 * @reason: reason for switching vm to running state
 *
 * Starts a vm
 *
 * Returns 0 on success or -1 in case of error
 */
int virLXCProcessStart(virConnectPtr conn,
                       virLXCDriverPtr  driver,
                       virDomainObjPtr vm,
                       unsigned int nfiles, int *files,
                       bool autoDestroy,
                       virDomainRunningReason reason)
{
    int rc = -1, r;
    size_t nttyFDs = 0;
    int *ttyFDs = NULL;
    size_t i;
    char *logfile = NULL;
    int logfd = -1;
    size_t nveths = 0;
    char **veths = NULL;
    int handshakefds[2] = { -1, -1 };
    off_t pos = -1;
    char ebuf[1024];
    char *timestamp;
    int nsInheritFDs[VIR_LXC_DOMAIN_NAMESPACE_LAST];
    virCommandPtr cmd = NULL;
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virCapsPtr caps = NULL;
    virErrorPtr err = NULL;
    virLXCDriverConfigPtr cfg = virLXCDriverGetConfig(driver);
    virCgroupPtr selfcgroup;
    int status;
    char *pidfile = NULL;

    if (virCgroupNewSelf(&selfcgroup) < 0)
        return -1;

    if (!virCgroupHasController(selfcgroup,
                                VIR_CGROUP_CONTROLLER_CPUACCT)) {
        virCgroupFree(&selfcgroup);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to find 'cpuacct' cgroups controller mount"));
        return -1;
    }
    if (!virCgroupHasController(selfcgroup,
                                VIR_CGROUP_CONTROLLER_DEVICES)) {
        virCgroupFree(&selfcgroup);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to find 'devices' cgroups controller mount"));
        return -1;
    }
    if (!virCgroupHasController(selfcgroup,
                                VIR_CGROUP_CONTROLLER_MEMORY)) {
        virCgroupFree(&selfcgroup);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to find 'memory' cgroups controller mount"));
        return -1;
    }
    virCgroupFree(&selfcgroup);

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

    if (virFileMakePath(cfg->logDir) < 0) {
        virReportSystemError(errno,
                             _("Cannot create log directory '%s'"),
                             cfg->logDir);
        return -1;
    }

    if (!vm->def->resource) {
        virDomainResourceDefPtr res;

        if (VIR_ALLOC(res) < 0)
            goto cleanup;

        if (VIR_STRDUP(res->partition, "/machine") < 0) {
            VIR_FREE(res);
            goto cleanup;
        }

        vm->def->resource = res;
    }

    if (virAsprintf(&logfile, "%s/%s.log",
                    cfg->logDir, vm->def->name) < 0)
        goto cleanup;

    if (!(pidfile = virPidFileBuildPath(cfg->stateDir, vm->def->name)))
        goto cleanup;

    if (!(caps = virLXCDriverGetCapabilities(driver, false)))
        goto cleanup;

    /* Do this up front, so any part of the startup process can add
     * runtime state to vm->def that won't be persisted. This let's us
     * report implicit runtime defaults in the XML, like vnc listen/socket
     */
    VIR_DEBUG("Setting current domain def as transient");
    if (virDomainObjSetDefTransient(caps, driver->xmlopt, vm) < 0)
        goto cleanup;

    /* Run an early hook to set-up missing devices */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, driver->caps, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                              VIR_HOOK_LXC_OP_PREPARE, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, NULL);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
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
    if (VIR_ALLOC_N(ttyFDs, nttyFDs) < 0)
        goto cleanup;
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

    VIR_DEBUG("Setting domain security labels");
    if (virSecurityManagerSetAllLabel(driver->securityManager,
                                      vm->def, NULL, false) < 0)
        goto cleanup;

    VIR_DEBUG("Setting up consoles");
    for (i = 0; i < vm->def->nconsoles; i++) {
        char *ttyPath;

        if (virFileOpenTty(&ttyFDs[i], &ttyPath, 1) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failed to allocate tty"));
            goto cleanup;
        }

        VIR_FREE(vm->def->consoles[i]->source->data.file.path);
        vm->def->consoles[i]->source->data.file.path = ttyPath;

        VIR_FREE(vm->def->consoles[i]->info.alias);
        if (virAsprintf(&vm->def->consoles[i]->info.alias, "console%zu", i) < 0)
            goto cleanup;
    }

    VIR_DEBUG("Setting up Interfaces");
    if (virLXCProcessSetupInterfaces(conn, vm->def, &nveths, &veths) < 0)
        goto cleanup;

    VIR_DEBUG("Setting up namespaces if any");
    if (virLXCProcessSetupNamespaces(conn, vm->def->namespaceData, nsInheritFDs) < 0)
        goto cleanup;

    VIR_DEBUG("Preparing to launch");
    if ((logfd = open(logfile, O_WRONLY | O_APPEND | O_CREAT,
             S_IRUSR|S_IWUSR)) < 0) {
        virReportSystemError(errno,
                             _("Failed to open '%s'"),
                             logfile);
        goto cleanup;
    }

    if (pipe(handshakefds) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create pipe"));
        goto cleanup;
    }

    if (!(cmd = virLXCProcessBuildControllerCmd(driver,
                                                vm,
                                                nveths, veths,
                                                ttyFDs, nttyFDs,
                                                nsInheritFDs,
                                                files, nfiles,
                                                handshakefds[1],
                                                &logfd,
                                                pidfile)))
        goto cleanup;

    /* now that we know it is about to start call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, driver->caps, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                              VIR_HOOK_LXC_OP_START, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, NULL);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto cleanup;
    }

    /* Log timestamp */
    if ((timestamp = virTimeStringNow()) == NULL)
        goto cleanup;
    if (safewrite(logfd, timestamp, strlen(timestamp)) < 0 ||
        safewrite(logfd, START_POSTFIX, strlen(START_POSTFIX)) < 0) {
        VIR_WARN("Unable to write timestamp to logfile: %s",
                 virStrerror(errno, ebuf, sizeof(ebuf)));
    }
    VIR_FREE(timestamp);

    /* Log generated command line */
    virCommandWriteArgLog(cmd, logfd);
    if ((pos = lseek(logfd, 0, SEEK_END)) < 0)
        VIR_WARN("Unable to seek to end of logfile: %s",
                 virStrerror(errno, ebuf, sizeof(ebuf)));

    VIR_DEBUG("Launching container");
    virCommandRawStatus(cmd);
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    if (status != 0) {
        if (virLXCProcessReadLogOutput(vm, logfile, pos, ebuf,
                                       sizeof(ebuf)) <= 0) {
            if (WIFEXITED(status))
                snprintf(ebuf, sizeof(ebuf), _("unexpected exit status %d"),
                         WEXITSTATUS(status));
            else
                snprintf(ebuf, sizeof(ebuf), "%s", _("terminated abnormally"));
        }
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("guest failed to start: %s"), ebuf);
        goto cleanup;
    }

    /* It has started running, so get its pid */
    if ((r = virPidFileReadPath(pidfile, &vm->pid)) < 0) {
        if (virLXCProcessReadLogOutput(vm, logfile, pos, ebuf, sizeof(ebuf)) > 0)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("guest failed to start: %s"), ebuf);
        else
            virReportSystemError(-r,
                                 _("Failed to read pid file %s"),
                                 pidfile);
        goto cleanup;
    }

    priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_FAILED;
    priv->wantReboot = false;
    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);
    priv->doneStopEvent = false;

    if (VIR_CLOSE(handshakefds[1]) < 0) {
        virReportSystemError(errno, "%s", _("could not close handshake fd"));
        goto cleanup;
    }

    if (virCommandHandshakeWait(cmd) < 0)
        goto cleanup;

    /* Write domain status to disk for the controller to
     * read when it starts */
    if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        goto cleanup;

    /* Allow the child to exec the controller */
    if (virCommandHandshakeNotify(cmd) < 0)
        goto cleanup;

    if (virAtomicIntInc(&driver->nactive) == 1 && driver->inhibitCallback)
        driver->inhibitCallback(true, driver->inhibitOpaque);

    if (lxcContainerWaitForContinue(handshakefds[0]) < 0) {
        char out[1024];

        if (!(virLXCProcessReadLogOutput(vm, logfile, pos, out, 1024) < 0)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("guest failed to start: %s"), out);
        }

        goto cleanup;
    }

    /* We know the cgroup must exist by this synchronization
     * point so lets detect that first, since it gives us a
     * more reliable way to kill everything off if something
     * goes wrong from here onwards ... */
    if (virCgroupNewDetectMachine(vm->def->name, "lxc",
                                  vm->def->id, true,
                                  vm->pid, -1, &priv->cgroup) < 0)
        goto cleanup;

    if (!priv->cgroup) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No valid cgroup for machine %s"),
                       vm->def->name);
        goto cleanup;
    }

    /* Get the machine name so we can properly delete it through
     * systemd later */
    if (!(priv->machineName = virSystemdGetMachineNameByPID(vm->pid)))
        virResetLastError();

    /* And we can get the first monitor connection now too */
    if (!(priv->monitor = virLXCProcessConnectMonitor(driver, vm))) {
        /* Intentionally overwrite the real monitor error message,
         * since a better one is almost always found in the logs
         */
        if (virLXCProcessReadLogOutput(vm, logfile, pos, ebuf, sizeof(ebuf)) > 0) {
            virResetLastError();
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("guest failed to start: %s"), ebuf);
        }
        goto cleanup;
    }

    if (autoDestroy &&
        virCloseCallbacksSet(driver->closeCallbacks, vm,
                             conn, lxcProcessAutoDestroy) < 0)
        goto cleanup;

    /* We don't need the temporary NIC names anymore, clear them */
    virLXCProcessCleanInterfaces(vm->def);

    /* finally we can call the 'started' hook script if any */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, driver->caps, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                              VIR_HOOK_LXC_OP_STARTED, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, NULL);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto cleanup;
    }

    rc = 0;

 cleanup:
    if (VIR_CLOSE(logfd) < 0) {
        virReportSystemError(errno, "%s", _("could not close logfile"));
        rc = -1;
    }
    if (rc != 0) {
        err = virSaveLastError();
        virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);
    }
    virCommandFree(cmd);
    for (i = 0; i < nveths; i++)
        VIR_FREE(veths[i]);
    for (i = 0; i < nttyFDs; i++)
        VIR_FORCE_CLOSE(ttyFDs[i]);
    VIR_FREE(ttyFDs);
    VIR_FORCE_CLOSE(handshakefds[0]);
    VIR_FORCE_CLOSE(handshakefds[1]);
    VIR_FREE(pidfile);
    VIR_FREE(logfile);
    virObjectUnref(cfg);
    virObjectUnref(caps);

    if (err) {
        virSetError(err);
        virFreeError(err);
    }

    return rc;
}

struct virLXCProcessAutostartData {
    virLXCDriverPtr driver;
    virConnectPtr conn;
};

static int
virLXCProcessAutostartDomain(virDomainObjPtr vm,
                             void *opaque)
{
    const struct virLXCProcessAutostartData *data = opaque;
    int ret = 0;

    virObjectLock(vm);
    if (vm->autostart &&
        !virDomainObjIsActive(vm)) {
        ret = virLXCProcessStart(data->conn, data->driver, vm,
                                 0, NULL, false,
                                 VIR_DOMAIN_RUNNING_BOOTED);
        virDomainAuditStart(vm, "booted", ret >= 0);
        if (ret < 0) {
            VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                      vm->def->name,
                      virGetLastErrorMessage());
        } else {
            virObjectEventPtr event =
                virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);
            if (event)
                virObjectEventStateQueue(data->driver->domainEventState, event);
        }
    }
    virObjectUnlock(vm);
    return ret;
}


void
virLXCProcessAutostartAll(virLXCDriverPtr driver)
{
    /* XXX: Figure out a better way todo this. The domain
     * startup code needs a connection handle in order
     * to lookup the bridge associated with a virtual
     * network
     */
    virConnectPtr conn = virConnectOpen("lxc:///");
    /* Ignoring NULL conn which is mostly harmless here */

    struct virLXCProcessAutostartData data = { driver, conn };

    virDomainObjListForEach(driver->domains,
                            virLXCProcessAutostartDomain,
                            &data);

    virObjectUnref(conn);
}

static int
virLXCProcessReconnectDomain(virDomainObjPtr vm,
                             void *opaque)
{
    virLXCDriverPtr driver = opaque;
    virLXCDomainObjPrivatePtr priv;
    int ret = -1;

    virObjectLock(vm);
    VIR_DEBUG("Reconnect id=%d pid=%d state=%d", vm->def->id, vm->pid, vm->state.state);

    priv = vm->privateData;

    if (vm->pid != 0) {
        vm->def->id = vm->pid;
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNKNOWN);

        if (virAtomicIntInc(&driver->nactive) == 1 && driver->inhibitCallback)
            driver->inhibitCallback(true, driver->inhibitOpaque);

        if (!(priv->monitor = virLXCProcessConnectMonitor(driver, vm)))
            goto error;

        if (virCgroupNewDetectMachine(vm->def->name, "lxc", vm->def->id, true,
                                      vm->pid, -1, &priv->cgroup) < 0)
            goto error;

        if (!priv->cgroup) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("No valid cgroup for machine %s"),
                           vm->def->name);
            goto error;
        }

        if (!(priv->machineName = virSystemdGetMachineNameByPID(vm->pid)))
            virResetLastError();

        if (virLXCUpdateActiveUSBHostdevs(driver, vm->def) < 0)
            goto error;

        if (virSecurityManagerReserveLabel(driver->securityManager,
                                           vm->def, vm->pid) < 0)
            goto error;

        /* now that we know it's reconnected call the hook if present */
        if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
            char *xml = virDomainDefFormat(vm->def, driver->caps, 0);
            int hookret;

            /* we can't stop the operation even if the script raised an error */
            hookret = virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                                  VIR_HOOK_LXC_OP_RECONNECT, VIR_HOOK_SUBOP_BEGIN,
                                  NULL, xml, NULL);
            VIR_FREE(xml);
            if (hookret < 0)
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
    virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);
    virDomainAuditStop(vm, "failed");
    goto cleanup;
}


int virLXCProcessReconnectAll(virLXCDriverPtr driver,
                              virDomainObjListPtr doms)
{
    virDomainObjListForEach(doms, virLXCProcessReconnectDomain, driver);
    return 0;
}
