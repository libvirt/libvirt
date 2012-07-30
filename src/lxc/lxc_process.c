/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

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
#include "virtime.h"
#include "domain_nwfilter.h"
#include "network/bridge_driver.h"
#include "memory.h"
#include "domain_audit.h"
#include "virterror_internal.h"
#include "logging.h"
#include "command.h"
#include "hooks.h"

#define VIR_FROM_THIS VIR_FROM_LXC

#define START_POSTFIX ": starting up\n"

int virLXCProcessAutoDestroyInit(virLXCDriverPtr driver)
{
    if (!(driver->autodestroy = virHashCreate(5, NULL)))
        return -1;

    return 0;
}

struct virLXCProcessAutoDestroyData {
    virLXCDriverPtr driver;
    virConnectPtr conn;
};

static void virLXCProcessAutoDestroyDom(void *payload,
                                        const void *name,
                                        void *opaque)
{
    struct virLXCProcessAutoDestroyData *data = opaque;
    virConnectPtr conn = payload;
    const char *uuidstr = name;
    unsigned char uuid[VIR_UUID_BUFLEN];
    virDomainObjPtr dom;
    virDomainEventPtr event = NULL;
    virLXCDomainObjPrivatePtr priv;

    VIR_DEBUG("conn=%p uuidstr=%s thisconn=%p", conn, uuidstr, data->conn);

    if (data->conn != conn)
        return;

    if (virUUIDParse(uuidstr, uuid) < 0) {
        VIR_WARN("Failed to parse %s", uuidstr);
        return;
    }

    if (!(dom = virDomainFindByUUID(&data->driver->domains,
                                    uuid))) {
        VIR_DEBUG("No domain object to kill");
        return;
    }

    priv = dom->privateData;
    VIR_DEBUG("Killing domain");
    virLXCProcessStop(data->driver, dom, VIR_DOMAIN_SHUTOFF_DESTROYED);
    virDomainAuditStop(dom, "destroyed");
    event = virDomainEventNewFromObj(dom,
                                     VIR_DOMAIN_EVENT_STOPPED,
                                     VIR_DOMAIN_EVENT_STOPPED_DESTROYED);
    priv->doneStopEvent = true;

    if (dom && !dom->persistent)
        virDomainRemoveInactive(&data->driver->domains, dom);

    if (dom)
        virDomainObjUnlock(dom);
    if (event)
        virDomainEventStateQueue(data->driver->domainEventState, event);
    virHashRemoveEntry(data->driver->autodestroy, uuidstr);
}

/*
 * Precondition: driver is locked
 */
void virLXCProcessAutoDestroyRun(virLXCDriverPtr driver, virConnectPtr conn)
{
    struct virLXCProcessAutoDestroyData data = {
        driver, conn
    };
    VIR_DEBUG("conn=%p", conn);
    virHashForEach(driver->autodestroy, virLXCProcessAutoDestroyDom, &data);
}

void virLXCProcessAutoDestroyShutdown(virLXCDriverPtr driver)
{
    virHashFree(driver->autodestroy);
}

int virLXCProcessAutoDestroyAdd(virLXCDriverPtr driver,
                                virDomainObjPtr vm,
                                virConnectPtr conn)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s uuid=%s conn=%p", vm->def->name, uuidstr, conn);
    if (virHashAddEntry(driver->autodestroy, uuidstr, conn) < 0)
        return -1;
    return 0;
}

int virLXCProcessAutoDestroyRemove(virLXCDriverPtr driver,
                                   virDomainObjPtr vm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s uuid=%s", vm->def->name, uuidstr);
    if (virHashRemoveEntry(driver->autodestroy, uuidstr) < 0)
        return -1;
    return 0;
}

static virConnectPtr
virLXCProcessAutoDestroyGetConn(virLXCDriverPtr driver,
                                virDomainObjPtr vm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s uuid=%s", vm->def->name, uuidstr);
    return virHashLookup(driver->autodestroy, uuidstr);
}


static int
virLXCProcessReboot(virLXCDriverPtr driver,
                    virDomainObjPtr vm)
{
    virConnectPtr conn = virLXCProcessAutoDestroyGetConn(driver, vm);
    int reason = vm->state.reason;
    bool autodestroy = false;
    int ret = -1;
    virDomainDefPtr savedDef;

    if (conn) {
        virConnectRef(conn);
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
    if (virLXCProcessStart(conn, driver, vm, autodestroy, reason) < 0) {
        VIR_WARN("Unable to handle reboot of vm %s",
                 vm->def->name);
        goto cleanup;
    }

    if (conn)
        virConnectClose(conn);

    ret = 0;

cleanup:
    return ret;
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
    virCgroupPtr cgroup;
    int i;
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virNetDevVPortProfilePtr vport = NULL;

    VIR_DEBUG("Stopping VM name=%s pid=%d reason=%d",
              vm->def->name, (int)vm->pid, (int)reason);

    /* now that we know it's stopped call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                    VIR_HOOK_LXC_OP_STOPPED, VIR_HOOK_SUBOP_END,
                    NULL, xml, NULL);
        VIR_FREE(xml);
    }

    /* Stop autodestroy in case guest is restarted */
    virLXCProcessAutoDestroyRemove(driver, vm);

    if (priv->monitor) {
        virLXCMonitorClose(priv->monitor);
        virLXCMonitorLock(priv->monitor);
        if (virLXCMonitorUnref(priv->monitor) > 0)
            virLXCMonitorUnlock(priv->monitor);
        priv->monitor = NULL;
    }

    virPidFileDelete(driver->stateDir, vm->def->name);
    virDomainDeleteConfig(driver->stateDir, NULL, vm);

    virDomainObjSetState(vm, VIR_DOMAIN_SHUTOFF, reason);
    vm->pid = -1;
    vm->def->id = -1;

    for (i = 0 ; i < vm->def->nnets ; i++) {
        virDomainNetDefPtr iface = vm->def->nets[i];
        vport = virDomainNetGetActualVirtPortProfile(iface);
        ignore_value(virNetDevSetOnline(iface->ifname, false));
        if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
            ignore_value(virNetDevOpenvswitchRemovePort(
                            virDomainNetGetActualBridgeName(iface),
                            iface->ifname));
        ignore_value(virNetDevVethDelete(iface->ifname));
        networkReleaseActualDevice(iface);
    }

    virDomainConfVMNWFilterTeardown(vm);

    if (driver->cgroup &&
        virCgroupForDomain(driver->cgroup, vm->def->name, &cgroup, 0) == 0) {
        virCgroupRemove(cgroup);
        virCgroupFree(&cgroup);
    }

    /* now that we know it's stopped call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, 0);

        /* we can't stop the operation even if the script raised an error */
        virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                    VIR_HOOK_LXC_OP_RELEASE, VIR_HOOK_SUBOP_END,
                    NULL, xml, NULL);
        VIR_FREE(xml);
    }

    if (vm->newDef) {
        virDomainDefFree(vm->def);
        vm->def = vm->newDef;
        vm->def->id = -1;
        vm->newDef = NULL;
    }
}


static int virLXCProcessSetupInterfaceBridged(virConnectPtr conn,
                                              virDomainDefPtr vm,
                                              virDomainNetDefPtr net,
                                              const char *brname,
                                              unsigned int *nveths,
                                              char ***veths)
{
    int ret = -1;
    char *parentVeth;
    char *containerVeth = NULL;
    const virNetDevVPortProfilePtr vport = virDomainNetGetActualVirtPortProfile(net);

    VIR_DEBUG("calling vethCreate()");
    parentVeth = net->ifname;
    if (virNetDevVethCreate(&parentVeth, &containerVeth) < 0)
        goto cleanup;
    VIR_DEBUG("parentVeth: %s, containerVeth: %s", parentVeth, containerVeth);

    if (net->ifname == NULL)
        net->ifname = parentVeth;

    if (VIR_REALLOC_N(*veths, (*nveths)+1) < 0) {
        virReportOOMError();
        VIR_FREE(containerVeth);
        goto cleanup;
    }
    (*veths)[(*nveths)] = containerVeth;
    (*nveths)++;

    if (virNetDevSetMAC(containerVeth, &net->mac) < 0)
        goto cleanup;

    if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
        ret = virNetDevOpenvswitchAddPort(brname, parentVeth, &net->mac,
                                          vm->uuid, vport);
    else
        ret = virNetDevBridgeAddPort(brname, parentVeth);
    if (ret < 0)
        goto cleanup;

    if (virNetDevSetOnline(parentVeth, true) < 0)
        goto cleanup;

    if (virNetDevBandwidthSet(net->ifname,
                              virDomainNetGetActualBandwidth(net)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot set bandwidth limits on %s"),
                       net->ifname);
        goto cleanup;
    }

    if (net->filter &&
        virDomainConfNWFilterInstantiate(conn, vm->uuid, net) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    return ret;
}


static int virLXCProcessSetupInterfaceDirect(virConnectPtr conn,
                                             virDomainDefPtr def,
                                             virDomainNetDefPtr net,
                                             unsigned int *nveths,
                                             char ***veths)
{
    int ret = 0;
    char *res_ifname = NULL;
    virLXCDriverPtr driver = conn->privateData;
    virNetDevBandwidthPtr bw;
    virNetDevVPortProfilePtr prof;

    /* XXX how todo bandwidth controls ?
     * Since the 'net-ifname' is about to be moved to a different
     * namespace & renamed, there will be no host side visible
     * interface for the container to attach rules to
     */
    bw = virDomainNetGetActualBandwidth(net);
    if (bw) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Unable to set network bandwidth on direct interfaces"));
        return -1;
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
        return -1;
    }

    if (VIR_REALLOC_N(*veths, (*nveths)+1) < 0) {
        virReportOOMError();
        return -1;
    }
    (*veths)[(*nveths)] = NULL;

    if (virNetDevMacVLanCreateWithVPortProfile(
            net->ifname, &net->mac,
            virDomainNetGetActualDirectDev(net),
            virDomainNetGetActualDirectMode(net),
            false, false, def->uuid,
            virDomainNetGetActualVirtPortProfile(net),
            &res_ifname,
            VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
            driver->stateDir,
            virDomainNetGetActualBandwidth(net)) < 0)
        goto cleanup;

    (*veths)[(*nveths)] = res_ifname;
    (*nveths)++;

    ret = 0;

cleanup:
    return ret;
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
                                        unsigned int *nveths,
                                        char ***veths)
{
    int ret = -1;
    size_t i;

    for (i = 0 ; i < def->nnets ; i++) {
        /* If appropriate, grab a physical device from the configured
         * network's pool of devices, or resolve bridge device name
         * to the one defined in the network definition.
         */
        if (networkAllocateActualDevice(def->nets[i]) < 0)
            goto cleanup;

        switch (virDomainNetGetActualType(def->nets[i])) {
        case VIR_DOMAIN_NET_TYPE_NETWORK: {
            virNetworkPtr network;
            char *brname = NULL;
            bool fail = false;
            int active;
            virErrorPtr errobj;

            if (!(network = virNetworkLookupByName(conn,
                                                   def->nets[i]->data.network.name)))
                goto cleanup;

            active = virNetworkIsActive(network);
            if (active != 1) {
                fail = true;
                if (active == 0)
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Network '%s' is not active."),
                                   def->nets[i]->data.network.name);
                goto cleanup;
            }

            if (!fail) {
                brname = virNetworkGetBridgeName(network);
                if (brname == NULL)
                    fail = true;
            }

            /* Make sure any above failure is preserved */
            errobj = virSaveLastError();
            virNetworkFree(network);
            virSetError(errobj);
            virFreeError(errobj);

            if (fail)
                goto cleanup;

            if (virLXCProcessSetupInterfaceBridged(conn,
                                                   def,
                                                   def->nets[i],
                                                   brname,
                                                   nveths,
                                                   veths) < 0) {
                VIR_FREE(brname);
                goto cleanup;
            }
            VIR_FREE(brname);
            break;
        }
        case VIR_DOMAIN_NET_TYPE_BRIDGE: {
            const char *brname = virDomainNetGetActualBridgeName(def->nets[i]);
            if (!brname) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("No bridge name specified"));
                goto cleanup;
            }
            if (virLXCProcessSetupInterfaceBridged(conn,
                                                   def,
                                                   def->nets[i],
                                                   brname,
                                                   nveths,
                                                   veths) < 0)
                goto cleanup;
        }   break;

        case VIR_DOMAIN_NET_TYPE_DIRECT:
            if (virLXCProcessSetupInterfaceDirect(conn,
                                                  def,
                                                  def->nets[i],
                                                  nveths,
                                                  veths) < 0)
                goto cleanup;
            break;

        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unsupported network type %s"),
                           virDomainNetTypeToString(
                               virDomainNetGetActualType(def->nets[i])
                               ));
            goto cleanup;
        }
    }

    ret= 0;

cleanup:
    if (ret != 0) {
        for (i = 0 ; i < def->nnets ; i++) {
            virDomainNetDefPtr iface = def->nets[i];
            virNetDevVPortProfilePtr vport = virDomainNetGetActualVirtPortProfile(iface);
            if (vport && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH)
                ignore_value(virNetDevOpenvswitchRemovePort(
                                virDomainNetGetActualBridgeName(iface),
                                iface->ifname));
            networkReleaseActualDevice(iface);
        }
    }
    return ret;
}


static void virLXCProcessMonitorDestroy(virLXCMonitorPtr mon,
                                        virDomainObjPtr vm)
{
    virLXCDomainObjPrivatePtr priv;

    virDomainObjLock(vm);
    priv = vm->privateData;
    if (priv->monitor == mon)
        priv->monitor = NULL;
    if (virDomainObjUnref(vm) > 0)
        virDomainObjUnlock(vm);
}


extern virLXCDriverPtr lxc_driver;
static void virLXCProcessMonitorEOFNotify(virLXCMonitorPtr mon ATTRIBUTE_UNUSED,
                                          virDomainObjPtr vm)
{
    virLXCDriverPtr driver = lxc_driver;
    virDomainEventPtr event = NULL;
    virLXCDomainObjPrivatePtr priv;

    lxcDriverLock(driver);
    virDomainObjLock(vm);
    lxcDriverUnlock(driver);

    priv = vm->privateData;
    virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
    if (!priv->wantReboot) {
        virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_SHUTDOWN);
        if (!priv->doneStopEvent) {
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             priv->stopReason);
            virDomainAuditStop(vm, "shutdown");
        } else {
            VIR_DEBUG("Stop event has already been sent");
        }
        if (!vm->persistent) {
            virDomainRemoveInactive(&driver->domains, vm);
            vm = NULL;
        }
    } else {
        int ret = virLXCProcessReboot(driver, vm);
        virDomainAuditStop(vm, "reboot");
        virDomainAuditStart(vm, "reboot", ret == 0);
        if (ret == 0) {
            event = virDomainEventRebootNewFromObj(vm);
        } else {
            event = virDomainEventNewFromObj(vm,
                                             VIR_DOMAIN_EVENT_STOPPED,
                                             priv->stopReason);
            if (!vm->persistent) {
                virDomainRemoveInactive(&driver->domains, vm);
                vm = NULL;
            }
        }
    }

    if (vm)
        virDomainObjUnlock(vm);
    if (event) {
        lxcDriverLock(driver);
        virDomainEventStateQueue(driver->domainEventState, event);
        lxcDriverUnlock(driver);
    }
}

static void virLXCProcessMonitorExitNotify(virLXCMonitorPtr mon ATTRIBUTE_UNUSED,
                                           virLXCProtocolExitStatus status,
                                           virDomainObjPtr vm)
{
    virLXCDomainObjPrivatePtr priv = vm->privateData;

    switch (status) {
    case VIR_LXC_PROTOCOL_EXIT_STATUS_SHUTDOWN:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN;
        break;
    case VIR_LXC_PROTOCOL_EXIT_STATUS_ERROR:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_FAILED;
        break;
    case VIR_LXC_PROTOCOL_EXIT_STATUS_REBOOT:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_SHUTDOWN;
        priv->wantReboot = true;
        break;
    default:
        priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_FAILED;
        break;
    }
    VIR_DEBUG("Domain shutoff reason %d (from status %d)",
              priv->stopReason, status);
}

static virLXCMonitorCallbacks monitorCallbacks = {
    .eofNotify = virLXCProcessMonitorEOFNotify,
    .destroy = virLXCProcessMonitorDestroy,
    .exitNotify = virLXCProcessMonitorExitNotify,
};


static virLXCMonitorPtr virLXCProcessConnectMonitor(virLXCDriverPtr driver,
                                                    virDomainObjPtr vm)
{
    virLXCMonitorPtr monitor = NULL;

    if (virSecurityManagerSetSocketLabel(driver->securityManager, vm->def) < 0)
        goto cleanup;

    /* Hold an extra reference because we can't allow 'vm' to be
     * deleted while the monitor is active */
    virDomainObjRef(vm);

    monitor = virLXCMonitorNew(vm, driver->stateDir, &monitorCallbacks);

    if (monitor == NULL)
        ignore_value(virDomainObjUnref(vm));

    if (virSecurityManagerClearSocketLabel(driver->securityManager, vm->def) < 0) {
        if (monitor) {
            virLXCMonitorLock(monitor);
            virLXCMonitorUnref(monitor);
            monitor = NULL;
        }
        goto cleanup;
    }

cleanup:
    return monitor;
}


int virLXCProcessStop(virLXCDriverPtr driver,
                      virDomainObjPtr vm,
                      virDomainShutoffReason reason)
{
    virCgroupPtr group = NULL;
    int rc;

    VIR_DEBUG("Stopping VM name=%s pid=%d reason=%d",
              vm->def->name, (int)vm->pid, (int)reason);
    if (vm->pid <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid PID %d for container"), vm->pid);
        return -1;
    }

    virSecurityManagerRestoreAllLabel(driver->securityManager,
                                      vm->def, false);
    virSecurityManagerReleaseLabel(driver->securityManager, vm->def);
    /* Clear out dynamically assigned labels */
    if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
        VIR_FREE(vm->def->seclabel.model);
        VIR_FREE(vm->def->seclabel.label);
        VIR_FREE(vm->def->seclabel.imagelabel);
    }

    if (virCgroupForDomain(driver->cgroup, vm->def->name, &group, 0) == 0) {
        rc = virCgroupKillPainfully(group);
        if (rc < 0) {
            virReportSystemError(-rc, "%s",
                                 _("Failed to kill container PIDs"));
            rc = -1;
            goto cleanup;
        }
        if (rc == 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Some container PIDs refused to die"));
            rc = -1;
            goto cleanup;
        }
    } else {
        /* If cgroup doesn't exist, the VM pids must have already
         * died and so we're just cleaning up stale state
         */
    }

    virLXCProcessCleanup(driver, vm, reason);

    rc = 0;

cleanup:
    virCgroupFree(&group);
    return rc;
}


static virCommandPtr
virLXCProcessBuildControllerCmd(virLXCDriverPtr driver,
                                virDomainObjPtr vm,
                                int nveths,
                                char **veths,
                                int *ttyFDs,
                                size_t nttyFDs,
                                int handshakefd)
{
    size_t i;
    char *filterstr;
    char *outputstr;
    virCommandPtr cmd;

    cmd = virCommandNew(vm->def->emulator);

    /* The controller may call ip command, so we have to retain PATH. */
    virCommandAddEnvPass(cmd, "PATH");

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

    if (driver->log_libvirtd) {
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
    for (i = 0 ; i < nttyFDs ; i++) {
        virCommandAddArg(cmd, "--console");
        virCommandAddArgFormat(cmd, "%d", ttyFDs[i]);
        virCommandPreserveFD(cmd, ttyFDs[i]);
    }

    virCommandAddArgPair(cmd, "--security",
                         virSecurityManagerGetModel(driver->securityManager));

    virCommandAddArg(cmd, "--handshake");
    virCommandAddArgFormat(cmd, "%d", handshakefd);
    virCommandAddArg(cmd, "--background");

    for (i = 0 ; i < nveths ; i++) {
        virCommandAddArgList(cmd, "--veth", veths[i], NULL);
    }

    virCommandPreserveFD(cmd, handshakefd);

    return cmd;
cleanup:
    virCommandFree(cmd);
    return NULL;
}

static int
virLXCProcessReadLogOutput(virDomainObjPtr vm,
                           char *logfile,
                           off_t pos,
                           char *buf,
                           size_t buflen)
{
    int fd;
    off_t off;
    int whence;
    int got = 0, ret = -1;
    int retries = 10;

    if ((fd = open(logfile, O_RDONLY)) < 0) {
        virReportSystemError(errno, _("failed to open logfile %s"),
                             logfile);
        goto cleanup;
    }

    if (pos < 0) {
        off = 0;
        whence = SEEK_END;
    } else {
        off = pos;
        whence = SEEK_SET;
    }

    if (lseek(fd, off, whence) < 0) {
        if (whence == SEEK_END)
            virReportSystemError(errno,
                                 _("unable to seek to end of log for %s"),
                                 logfile);
        else
            virReportSystemError(errno,
                                 _("unable to seek to %lld from start for %s"),
                                 (long long)off, logfile);
        goto cleanup;
    }

    while (retries) {
        ssize_t bytes;
        int isdead = 0;

        if (kill(vm->pid, 0) == -1 && errno == ESRCH)
            isdead = 1;

        /* Any failures should be detected before we read the log, so we
         * always have something useful to report on failure. */
        bytes = saferead(fd, buf+got, buflen-got-1);
        if (bytes < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failure while reading guest log output"));
            goto cleanup;
        }

        got += bytes;
        buf[got] = '\0';

        if ((got == buflen-1) || isdead) {
            break;
        }

        usleep(100*1000);
        retries--;
    }


    ret = got;
cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
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
                       bool autoDestroy,
                       virDomainRunningReason reason)
{
    int rc = -1, r;
    size_t nttyFDs = 0;
    int *ttyFDs = NULL;
    size_t i;
    char *logfile = NULL;
    int logfd = -1;
    unsigned int nveths = 0;
    char **veths = NULL;
    int handshakefds[2] = { -1, -1 };
    off_t pos = -1;
    char ebuf[1024];
    char *timestamp;
    virCommandPtr cmd = NULL;
    virLXCDomainObjPrivatePtr priv = vm->privateData;
    virErrorPtr err = NULL;

    if (!lxc_driver->cgroup) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("The 'cpuacct', 'devices' & 'memory' cgroups controllers must be mounted"));
        return -1;
    }

    if (!virCgroupMounted(lxc_driver->cgroup,
                          VIR_CGROUP_CONTROLLER_CPUACCT)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to find 'cpuacct' cgroups controller mount"));
        return -1;
    }
    if (!virCgroupMounted(lxc_driver->cgroup,
                          VIR_CGROUP_CONTROLLER_DEVICES)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to find 'devices' cgroups controller mount"));
        return -1;
    }
    if (!virCgroupMounted(lxc_driver->cgroup,
                          VIR_CGROUP_CONTROLLER_MEMORY)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to find 'memory' cgroups controller mount"));
        return -1;
    }

    if (virFileMakePath(driver->logDir) < 0) {
        virReportSystemError(errno,
                             _("Cannot create log directory '%s'"),
                             driver->logDir);
        return -1;
    }

    if (virAsprintf(&logfile, "%s/%s.log",
                    driver->logDir, vm->def->name) < 0) {
        virReportOOMError();
        return -1;
    }

    /* Do this up front, so any part of the startup process can add
     * runtime state to vm->def that won't be persisted. This let's us
     * report implicit runtime defaults in the XML, like vnc listen/socket
     */
    VIR_DEBUG("Setting current domain def as transient");
    if (virDomainObjSetDefTransient(driver->caps, vm, true) < 0)
        goto cleanup;

    /* Run an early hook to set-up missing devices */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, 0);
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

    /* Here we open all the PTYs we need on the host OS side.
     * The LXC controller will open the guest OS side PTYs
     * and forward I/O between them.
     */
    nttyFDs = vm->def->nconsoles;
    if (VIR_ALLOC_N(ttyFDs, nttyFDs) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    /* If you are using a SecurityDriver with dynamic labelling,
       then generate a security label for isolation */
    VIR_DEBUG("Generating domain security label (if required)");
    if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_DEFAULT)
        vm->def->seclabel.type = VIR_DOMAIN_SECLABEL_NONE;

    if (virSecurityManagerGenLabel(driver->securityManager, vm->def) < 0) {
        virDomainAuditSecurityLabel(vm, false);
        goto cleanup;
    }
    virDomainAuditSecurityLabel(vm, true);

    VIR_DEBUG("Setting domain security labels");
    if (virSecurityManagerSetAllLabel(driver->securityManager,
                                      vm->def, NULL) < 0)
        goto cleanup;

    for (i = 0 ; i < vm->def->nconsoles ; i++)
        ttyFDs[i] = -1;

    for (i = 0 ; i < vm->def->nconsoles ; i++) {
        char *ttyPath;
        if (vm->def->consoles[i]->source.type != VIR_DOMAIN_CHR_TYPE_PTY) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only PTY console types are supported"));
            goto cleanup;
        }

        if (virFileOpenTty(&ttyFDs[i], &ttyPath, 1) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failed to allocate tty"));
            goto cleanup;
        }

        VIR_FREE(vm->def->consoles[i]->source.data.file.path);
        vm->def->consoles[i]->source.data.file.path = ttyPath;

        VIR_FREE(vm->def->consoles[i]->info.alias);
        if (virAsprintf(&vm->def->consoles[i]->info.alias, "console%zu", i) < 0) {
            virReportOOMError();
            goto cleanup;
        }
    }

    if (virLXCProcessSetupInterfaces(conn, vm->def, &nveths, &veths) != 0)
        goto cleanup;

    /* Save the configuration for the controller */
    if (virDomainSaveConfig(driver->stateDir, vm->def) < 0)
        goto cleanup;

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
                                                handshakefds[1])))
        goto cleanup;
    virCommandSetOutputFD(cmd, &logfd);
    virCommandSetErrorFD(cmd, &logfd);

    /* now that we know it is about to start call the hook if present */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, 0);
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
    if ((timestamp = virTimeStringNow()) == NULL) {
        virReportOOMError();
        goto cleanup;
    }
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

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    if (VIR_CLOSE(handshakefds[1]) < 0) {
        virReportSystemError(errno, "%s", _("could not close handshake fd"));
        goto cleanup;
    }

    /* Connect to the controller as a client *first* because
     * this will block until the child has written their
     * pid file out to disk */
    if (!(priv->monitor = virLXCProcessConnectMonitor(driver, vm)))
        goto cleanup;

    /* And get its pid */
    if ((r = virPidFileRead(driver->stateDir, vm->def->name, &vm->pid)) < 0) {
        virReportSystemError(-r,
                             _("Failed to read pid file %s/%s.pid"),
                             driver->stateDir, vm->def->name);
        goto cleanup;
    }

    priv->stopReason = VIR_DOMAIN_EVENT_STOPPED_FAILED;
    priv->wantReboot = false;
    vm->def->id = vm->pid;
    virDomainObjSetState(vm, VIR_DOMAIN_RUNNING, reason);
    priv->doneStopEvent = false;

    if (lxcContainerWaitForContinue(handshakefds[0]) < 0) {
        char out[1024];

        if (!(virLXCProcessReadLogOutput(vm, logfile, pos, out, 1024) < 0)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("guest failed to start: %s"), out);
        }

        goto error;
    }

    if (autoDestroy &&
        virLXCProcessAutoDestroyAdd(driver, vm, conn) < 0)
        goto error;

    if (virDomainObjSetDefTransient(driver->caps, vm, false) < 0)
        goto error;

    /* Write domain status to disk.
     *
     * XXX: Earlier we wrote the plain "live" domain XML to this
     * location for the benefit of libvirt_lxc. We're now overwriting
     * it with the live status XML instead. This is a (currently
     * harmless) inconsistency we should fix one day */
    if (virDomainSaveStatus(driver->caps, driver->stateDir, vm) < 0)
        goto error;

    /* finally we can call the 'started' hook script if any */
    if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
        char *xml = virDomainDefFormat(vm->def, 0);
        int hookret;

        hookret = virHookCall(VIR_HOOK_DRIVER_LXC, vm->def->name,
                              VIR_HOOK_LXC_OP_STARTED, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, NULL);
        VIR_FREE(xml);

        /*
         * If the script raised an error abort the launch
         */
        if (hookret < 0)
            goto error;
    }

    rc = 0;

cleanup:
    if (rc != 0 && !err)
        err = virSaveLastError();
    virCommandFree(cmd);
    if (VIR_CLOSE(logfd) < 0) {
        virReportSystemError(errno, "%s", _("could not close logfile"));
        rc = -1;
    }
    for (i = 0 ; i < nveths ; i++) {
        if (rc != 0)
            ignore_value(virNetDevVethDelete(veths[i]));
        VIR_FREE(veths[i]);
    }
    if (rc != 0) {
        if (priv->monitor) {
            virLXCMonitorLock(priv->monitor);
            if (virLXCMonitorUnref(priv->monitor) > 0)
                virLXCMonitorUnlock(priv->monitor);
            priv->monitor = NULL;
        }
        virDomainConfVMNWFilterTeardown(vm);

        virSecurityManagerRestoreAllLabel(driver->securityManager,
                                          vm->def, false);
        virSecurityManagerReleaseLabel(driver->securityManager, vm->def);
        /* Clear out dynamically assigned labels */
        if (vm->def->seclabel.type == VIR_DOMAIN_SECLABEL_DYNAMIC) {
            VIR_FREE(vm->def->seclabel.model);
            VIR_FREE(vm->def->seclabel.label);
            VIR_FREE(vm->def->seclabel.imagelabel);
        }
    }
    for (i = 0 ; i < nttyFDs ; i++)
        VIR_FORCE_CLOSE(ttyFDs[i]);
    VIR_FREE(ttyFDs);
    VIR_FORCE_CLOSE(handshakefds[0]);
    VIR_FORCE_CLOSE(handshakefds[1]);
    VIR_FREE(logfile);

    if (err) {
        virSetError(err);
        virFreeError(err);
    }

    return rc;

error:
    err = virSaveLastError();
    virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);
    goto cleanup;
}

struct virLXCProcessAutostartData {
    virLXCDriverPtr driver;
    virConnectPtr conn;
};

static void
virLXCProcessAutostartDomain(void *payload, const void *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr vm = payload;
    const struct virLXCProcessAutostartData *data = opaque;

    virDomainObjLock(vm);
    if (vm->autostart &&
        !virDomainObjIsActive(vm)) {
        int ret = virLXCProcessStart(data->conn, data->driver, vm, false,
                             VIR_DOMAIN_RUNNING_BOOTED);
        virDomainAuditStart(vm, "booted", ret >= 0);
        if (ret < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to autostart VM '%s': %s"),
                      vm->def->name,
                      err ? err->message : "");
        } else {
            virDomainEventPtr event =
                virDomainEventNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_BOOTED);
            if (event)
                virDomainEventStateQueue(data->driver->domainEventState, event);
        }
    }
    virDomainObjUnlock(vm);
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

    lxcDriverLock(driver);
    virHashForEach(driver->domains.objs, virLXCProcessAutostartDomain, &data);
    lxcDriverUnlock(driver);

    if (conn)
        virConnectClose(conn);
}

static void
virLXCProcessReconnectDomain(void *payload, const void *name ATTRIBUTE_UNUSED, void *opaque)
{
    virDomainObjPtr vm = payload;
    virLXCDriverPtr driver = opaque;
    virLXCDomainObjPrivatePtr priv;

    virDomainObjLock(vm);
    VIR_DEBUG("Reconnect %d %d %d\n", vm->def->id, vm->pid, vm->state.state);

    priv = vm->privateData;

    if (vm->pid != 0) {
        vm->def->id = vm->pid;
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_UNKNOWN);

        if (!(priv->monitor = virLXCProcessConnectMonitor(driver, vm)))
            goto error;

        if (virSecurityManagerReserveLabel(driver->securityManager,
                                           vm->def, vm->pid) < 0)
            goto error;

        /* now that we know it's reconnected call the hook if present */
        if (virHookPresent(VIR_HOOK_DRIVER_LXC)) {
            char *xml = virDomainDefFormat(vm->def, 0);
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

cleanup:
    virDomainObjUnlock(vm);
    return;

error:
    virLXCProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED);
    virDomainAuditStop(vm, "failed");
    goto cleanup;
}


int virLXCProcessReconnectAll(virLXCDriverPtr driver,
                              virDomainObjListPtr doms)
{
    virHashForEach(doms->objs, virLXCProcessReconnectDomain, driver);
    return 0;
}
