/* virhostdev.c: hostdev management
 *
 * Copyright (C) 2006-2007, 2009-2017 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
 * Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "virhostdev.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virutil.h"
#include "virnetdev.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.hostdev");

#define HOSTDEV_STATE_DIR RUNSTATEDIR "/libvirt/hostdevmgr"

static virHostdevManager *manager; /* global hostdev manager, never freed */

static virClass *virHostdevManagerClass;
static void virHostdevManagerDispose(void *obj);
static virHostdevManager *virHostdevManagerNew(void);

struct virHostdevIsPCINodeDeviceUsedData {
    virHostdevManager *mgr;
    const char *driverName;
    const char *domainName;
    bool usesVFIO;
};

/* This module makes heavy use of bookkeeping lists contained inside a
 * virHostdevManager instance to keep track of the devices' status. To make
 * it easy to spot potential ownership errors when moving devices from one
 * list to the other, variable names should comply with the following
 * conventions when it comes to virPCIDevice and virPCIDeviceList instances:
 *
 *   pci - a short-lived virPCIDevice whose purpose is usually just to look
 *         up the actual PCI device in one of the bookkeeping lists; basically
 *         little more than a fancy virPCIDeviceAddress
 *
 *   pcidevs - a list containing a bunch of the above
 *
 *   actual - a virPCIDevice instance that has either been retrieved from one
 *            of the bookkeeping lists, or is intended to be added or copied
 *            to one at some point
 *
 * Passing an 'actual' to a function that requires a 'pci' is fine, but the
 * opposite is usually not true; as a rule of thumb, functions in the virpci
 * module usually expect an 'actual'. Even with these conventions in place,
 * adding comments to highlight ownership-related issues is recommended */

static int virHostdevIsPCINodeDeviceUsed(virPCIDeviceAddress *devAddr, void *opaque)
{
    virPCIDevice *actual;
    struct virHostdevIsPCINodeDeviceUsedData *helperData = opaque;

    actual = virPCIDeviceListFindByIDs(helperData->mgr->activePCIHostdevs,
                                       devAddr->domain, devAddr->bus,
                                       devAddr->slot, devAddr->function);
    if (actual) {
        const char *actual_drvname = NULL;
        const char *actual_domname = NULL;
        virPCIDeviceGetUsedBy(actual, &actual_drvname, &actual_domname);

        if (helperData->usesVFIO &&
            STREQ_NULLABLE(actual_drvname, helperData->driverName) &&
            STREQ_NULLABLE(actual_domname, helperData->domainName))
            return 0;

        if (actual_drvname && actual_domname)
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("PCI device %1$s is in use by driver %2$s, domain %3$s"),
                           virPCIDeviceGetName(actual),
                           actual_drvname, actual_domname);
        else
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("PCI device %1$s is in use"),
                           virPCIDeviceGetName(actual));
        return -1;
    }

    return 0;
}

static int virHostdevManagerOnceInit(void)
{
    if (!VIR_CLASS_NEW(virHostdevManager, virClassForObject()))
        return -1;

    if (!(manager = virHostdevManagerNew()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virHostdevManager);

static void
virHostdevManagerDispose(void *obj)
{
    virHostdevManager *hostdevMgr = obj;

    virObjectUnref(hostdevMgr->activePCIHostdevs);
    virObjectUnref(hostdevMgr->inactivePCIHostdevs);
    virObjectUnref(hostdevMgr->activeUSBHostdevs);
    virObjectUnref(hostdevMgr->activeSCSIHostdevs);
    virObjectUnref(hostdevMgr->activeSCSIVHostHostdevs);
    virObjectUnref(hostdevMgr->activeMediatedHostdevs);
    virObjectUnref(hostdevMgr->activeNVMeHostdevs);
    g_free(hostdevMgr->stateDir);
}

static virHostdevManager *
virHostdevManagerNew(void)
{
    g_autoptr(virHostdevManager) hostdevMgr = NULL;
    bool privileged = geteuid() == 0;

    if (!(hostdevMgr = virObjectNew(virHostdevManagerClass)))
        return NULL;

    if (!(hostdevMgr->activePCIHostdevs = virPCIDeviceListNew()))
        return NULL;

    if (!(hostdevMgr->activeUSBHostdevs = virUSBDeviceListNew()))
        return NULL;

    if (!(hostdevMgr->inactivePCIHostdevs = virPCIDeviceListNew()))
        return NULL;

    if (!(hostdevMgr->activeSCSIHostdevs = virSCSIDeviceListNew()))
        return NULL;

    if (!(hostdevMgr->activeSCSIVHostHostdevs = virSCSIVHostDeviceListNew()))
        return NULL;

    if (!(hostdevMgr->activeMediatedHostdevs = virMediatedDeviceListNew()))
        return NULL;

    if (!(hostdevMgr->activeNVMeHostdevs = virNVMeDeviceListNew()))
        return NULL;

    if (privileged) {
        hostdevMgr->stateDir = g_strdup(HOSTDEV_STATE_DIR);

        if (g_mkdir_with_parents(hostdevMgr->stateDir, 0777) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Failed to create state dir '%1$s'"),
                           hostdevMgr->stateDir);
            return NULL;
        }
    } else {
        g_autofree char *rundir = NULL;
        mode_t old_umask;

        rundir = virGetUserRuntimeDirectory();

        hostdevMgr->stateDir = g_strdup_printf("%s/hostdevmgr", rundir);

        old_umask = umask(077);

        if (g_mkdir_with_parents(hostdevMgr->stateDir, 0777) < 0) {
            umask(old_umask);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Failed to create state dir '%1$s'"),
                           hostdevMgr->stateDir);
            return NULL;
        }
        umask(old_umask);
    }

    return g_steal_pointer(&hostdevMgr);
}

virHostdevManager *
virHostdevManagerGetDefault(void)
{
    if (virHostdevManagerInitialize() < 0)
        return NULL;

    return virObjectRef(manager);
}

/**
 * virHostdevGetPCIHostDevice:
 * @hostdev: domain hostdev definition
 * @pci: returned PCI device
 *
 * For given @hostdev which represents a PCI device construct its
 * virPCIDevice representation and return it in @pci. If @hostdev
 * does not represent a PCI device then @pci is set to NULL and 0
 * is returned.
 *
 * Returns: 0 on success (@pci might be NULL though),
 *         -1 otherwise (with error reported),
 *         -2 PCI device not found. @pci will be NULL
 */
static int
virHostdevGetPCIHostDevice(const virDomainHostdevDef *hostdev,
                           virPCIDevice **pci)
{
    g_autoptr(virPCIDevice) actual = NULL;
    const virDomainHostdevSubsysPCI *pcisrc = &hostdev->source.subsys.u.pci;

    *pci = NULL;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
        hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
        return 0;

    if (!virPCIDeviceExists(&pcisrc->addr))
        return -2;

    actual = virPCIDeviceNew(&pcisrc->addr);

    if (!actual)
        return -1;

    virPCIDeviceSetManaged(actual, hostdev->managed);

    if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
        virPCIDeviceSetStubDriverType(actual, VIR_PCI_STUB_DRIVER_VFIO);
    } else if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN) {
        virPCIDeviceSetStubDriverType(actual, VIR_PCI_STUB_DRIVER_XEN);
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("pci backend driver '%1$s' is not supported"),
                       virDomainHostdevSubsysPCIBackendTypeToString(pcisrc->backend));
        return -1;
    }

    *pci = g_steal_pointer(&actual);
    return 0;
}

static virPCIDeviceList *
virHostdevGetPCIHostDeviceList(virDomainHostdevDef **hostdevs, int nhostdevs)
{
    g_autoptr(virPCIDeviceList) pcidevs = NULL;
    size_t i;

    if (!(pcidevs = virPCIDeviceListNew()))
        return NULL;

    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDef *hostdev = hostdevs[i];
        g_autoptr(virPCIDevice) pci = NULL;

        if (virHostdevGetPCIHostDevice(hostdev, &pci) == -1)
            return NULL;

        if (!pci)
            continue;

        if (virPCIDeviceListAdd(pcidevs, pci) < 0)
            return NULL;
        pci = NULL;
    }

    return g_steal_pointer(&pcidevs);
}


static int
virHostdevPCISysfsPath(virDomainHostdevDef *hostdev,
                       char **sysfs_path)
{
    return virPCIDeviceAddressGetSysfsFile(&hostdev->source.subsys.u.pci.addr, sysfs_path);
}


static int
virHostdevIsVirtualFunction(virDomainHostdevDef *hostdev)
{
    g_autofree char *sysfs_path = NULL;

    if (virHostdevPCISysfsPath(hostdev, &sysfs_path) < 0)
        return -1;

    return virPCIIsVirtualFunction(sysfs_path);
}


static int
virHostdevNetDevice(virDomainHostdevDef *hostdev,
                    int pfNetDevIdx,
                    char **linkdev,
                    int *vf)
{
    g_autofree char *sysfs_path = NULL;

    if (virHostdevPCISysfsPath(hostdev, &sysfs_path) < 0)
        return -1;

    if (virPCIIsVirtualFunction(sysfs_path) == 1) {
        if (virPCIGetVirtualFunctionInfo(sysfs_path, pfNetDevIdx,
                                         linkdev, vf) < 0)
            return -1;
    } else {
        /* In practice this should never happen, since we currently
         * only support assigning SRIOV VFs via <interface
         * type='hostdev'>, and it is only those devices that should
         * end up calling this function.
         */
        if (virPCIGetNetName(sysfs_path, 0, NULL, linkdev) < 0)
            return -1;

        if (!(*linkdev)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("The device at %1$s has no network device name"),
                           sysfs_path);
            return -1;
        }

        *vf = -1;
    }

    return 0;
}


bool
virHostdevIsPCIDevice(const virDomainHostdevDef *hostdev)
{
    return hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
}


static bool
virHostdevIsPCINetDevice(const virDomainHostdevDef *hostdev)
{
    return virHostdevIsPCIDevice(hostdev) && hostdev->parentnet != NULL;
}


static int
virHostdevNetConfigVirtPortProfile(const char *linkdev, int vf,
                                   const virNetDevVPortProfile *virtPort,
                                   const virMacAddr *macaddr,
                                   const unsigned char *uuid,
                                   bool associate)
{
    int ret = -1;

    if (!virtPort)
        return ret;

    switch (virtPort->virtPortType) {
    case VIR_NETDEV_VPORT_PROFILE_NONE:
    case VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH:
    case VIR_NETDEV_VPORT_PROFILE_8021QBG:
    case VIR_NETDEV_VPORT_PROFILE_LAST:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("virtualport type %1$s is currently not supported on interfaces of type hostdev"),
                       virNetDevVPortTypeToString(virtPort->virtPortType));
        break;

    case VIR_NETDEV_VPORT_PROFILE_8021QBH:
        if (associate)
            ret = virNetDevVPortProfileAssociate(NULL, virtPort, macaddr,
                                                 linkdev, vf, uuid,
                                                 VIR_NETDEV_VPORT_PROFILE_OP_CREATE, false);
        else
            ret = virNetDevVPortProfileDisassociate(NULL, virtPort,
                                                    macaddr, linkdev, vf,
                                                    VIR_NETDEV_VPORT_PROFILE_OP_DESTROY);
        break;
    }

    return ret;
}


/**
 * virHostdevSaveNetConfig:
 * @hostdev: config object describing a hostdev device
 * @stateDir: directory to save device state into
 *
 * If the given hostdev device is an SRIOV network VF and *does not*
 * have a <virtualport> element (ie, it isn't being configured via
 * 802.11Qbh), determine its PF+VF#, and use that to save its current
 * "admin" MAC address and VF tag (the ones saved in the PF
 * driver).
 *
 * Returns 0 on success, -1 on failure.
 */
static int
virHostdevSaveNetConfig(virDomainHostdevDef *hostdev,
                        const char *stateDir)
{
    g_autofree char *linkdev = NULL;
    int vf = -1;

    if (!virHostdevIsPCINetDevice(hostdev) ||
        virDomainNetGetActualVirtPortProfile(hostdev->parentnet))
       return 0;

    if (virHostdevIsVirtualFunction(hostdev) != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Interface type hostdev is currently supported on SR-IOV Virtual Functions only"));
        return -1;
    }

    if (virHostdevNetDevice(hostdev, -1, &linkdev, &vf) < 0)
        return -1;

    if (virNetDevSaveNetConfig(linkdev, vf, stateDir, true) < 0)
        return -1;

    return 0;
}


/**
 * virHostdevSetNetConfig:
 * @hostdev: config object describing a hostdev device
 * @uuid: uuid of the domain
 *
 * If the given hostdev device is an SRIOV network VF, determine its
 * PF+VF#, and use that to set the "admin" MAC address and VF tag (the
 * ones saved in the PF driver).xs
 *
 * Returns 0 on success, -1 on failure.
 */
static int
virHostdevSetNetConfig(virDomainHostdevDef *hostdev,
                       const unsigned char *uuid)
{
    g_autofree char *linkdev = NULL;
    const virNetDevVlan *vlan;
    const virNetDevVPortProfile *virtPort;
    int vf = -1;
    bool port_profile_associate = true;
    bool setVlan = false;

    if (!virHostdevIsPCINetDevice(hostdev))
        return 0;

    if (virHostdevNetDevice(hostdev, -1, &linkdev, &vf) < 0)
        return -1;

    vlan = virDomainNetGetActualVlan(hostdev->parentnet);
    setVlan = vlan != NULL;
    virtPort = virDomainNetGetActualVirtPortProfile(hostdev->parentnet);
    if (virtPort) {
        if (vlan) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("direct setting of the vlan tag is not allowed for hostdev devices using %1$s mode"),
                           virNetDevVPortTypeToString(virtPort->virtPortType));
            return -1;
        }
        if (virHostdevNetConfigVirtPortProfile(linkdev, vf, virtPort,
                                               &hostdev->parentnet->mac,
                                               uuid, port_profile_associate) < 0)
            return -1;
    } else {
        if (virNetDevSetNetConfig(linkdev, vf, &hostdev->parentnet->mac,
                                  vlan, NULL, setVlan) < 0)
            return -1;
    }

    return 0;
}


static int
virHostdevRestoreNetConfig(virDomainHostdevDef *hostdev,
                           const char *stateDir)
{
    g_autofree char *linkdev = NULL;
    g_autofree virMacAddr *MAC = NULL;
    g_autofree virMacAddr *adminMAC = NULL;
    g_autoptr(virNetDevVlan) vlan = NULL;
    const virNetDevVPortProfile *virtPort;
    int vf = -1;
    bool port_profile_associate = false;


    /* This is only needed for PCI devices that have been defined
     * using <interface type='hostdev'>. For all others, it is a NOP.
     */
    if (!virHostdevIsPCINetDevice(hostdev))
       return 0;

    if (virHostdevIsVirtualFunction(hostdev) != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Interface type hostdev is currently supported on SR-IOV Virtual Functions only"));
        return -1;
    }

    if (virHostdevNetDevice(hostdev, 0, &linkdev, &vf) < 0)
        return -1;

    virtPort = virDomainNetGetActualVirtPortProfile(hostdev->parentnet);
    if (virtPort) {
        return virHostdevNetConfigVirtPortProfile(linkdev, vf, virtPort,
                                                  &hostdev->parentnet->mac,
                                                  NULL,
                                                  port_profile_associate);
    } else {
        /* we need to try 2 different places for the config file:
         * 1) ${stateDir}/${PF}_vf${vf}
         *    This is almost always where the saved config is
         *
         * 2) ${stateDir}${PF[1]}_vf${VF}
         *    PF[1] means "the netdev for port 2 of the PF device", and
         *    is only valid when the PF is a Mellanox dual port NIC with
         *    a VF that was created in "single port" mode.
         *
         *  NB: if virNetDevReadNetConfig() returns < 0, then it found
         *  the file, but there was a problem, so we should
         *  immediately return an error to our caller. If it returns
         *  0, but all of the interesting stuff is NULL, that means
         *  the file wasn't found, so we can/should check other
         *  locations for it.
         */

        /* 1) standard location */
        if (virNetDevReadNetConfig(linkdev, vf, stateDir,
                                   &adminMAC, &vlan, &MAC) < 0) {
            return -1;
        }

        /* 2) try using the PF's "port 2" netdev as the name of the
         * config file
         */
        if (!(adminMAC || vlan || MAC)) {
            VIR_FREE(linkdev);

            if (virHostdevNetDevice(hostdev, 1, &linkdev, &vf) < 0 ||
                virNetDevReadNetConfig(linkdev, vf, stateDir,
                                       &adminMAC, &vlan, &MAC) < 0) {
                return -1;
            }
        }

        /* if a MAC was stored for the VF, we should now restore
         * that as the adminMAC. We have to do it this way because
         * the VF is still not bound to the host's net driver, so
         * we can't directly set its MAC (and even after it is
         * re-bound to the host net driver, it will still have its
         * "administratively set" flag on, and that prohibits the
         * VF's net driver from directly setting the MAC
         * anyway). But it we set the desired VF MAC as the "admin
         * MAC" *now*, then when the VF is re-bound to the host
         * net driver (which will happen soon after returning from
         * this function), that adminMAC will be set (by the PF)
         * as the VF's new initial MAC.
         *
         * If no MAC was stored for the VF, that means it wasn't
         * bound to a net driver before we used it anyway, so the
         * adminMAC is all we have, and we can just restore it
         * directly.
         */
        if (MAC) {
            VIR_FREE(adminMAC);
            adminMAC = g_steal_pointer(&MAC);
        }

        ignore_value(virNetDevSetNetConfig(linkdev, vf,
                                           adminMAC, vlan, MAC, true));
        return 0;
    }
}

static int
virHostdevResetAllPCIDevices(virHostdevManager *mgr,
                             virPCIDeviceList *pcidevs)
{
    int ret = 0;
    size_t i;

    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevice *pci = virPCIDeviceListGet(pcidevs, i);

        /* We can avoid looking up the actual device here, because performing
         * a PCI reset on a device doesn't require any information other than
         * the address, which 'pci' already contains */
        VIR_DEBUG("Resetting PCI device %s", virPCIDeviceGetName(pci));
        if (virPCIDeviceReset(pci, mgr->activePCIHostdevs,
                              mgr->inactivePCIHostdevs) < 0) {
            VIR_ERROR(_("Failed to reset PCI device: %1$s"),
                      virGetLastErrorMessage());
            ret = -1;
        }
    }

    return ret;
}

static void
virHostdevReattachAllPCIDevices(virHostdevManager *mgr,
                                virPCIDeviceList *pcidevs)
{
    size_t i;

    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevice *pci = virPCIDeviceListGet(pcidevs, i);
        virPCIDevice *actual;

        /* We need to look up the actual device because that's what
         * virPCIDeviceReattach() expects as its argument */
        if (!(actual = virPCIDeviceListFind(mgr->inactivePCIHostdevs,
                                            virPCIDeviceGetAddress(pci))))
            continue;

        if (virPCIDeviceGetManaged(actual)) {
            VIR_DEBUG("Reattaching managed PCI device %s",
                      virPCIDeviceGetName(pci));
            if (virPCIDeviceReattach(actual,
                                     mgr->activePCIHostdevs,
                                     mgr->inactivePCIHostdevs) < 0) {
                VIR_ERROR(_("Failed to re-attach PCI device: %1$s"),
                          virGetLastErrorMessage());
            }
        } else {
            VIR_DEBUG("Not reattaching unmanaged PCI device %s",
                      virPCIDeviceGetName(actual));
        }
    }
}


static int
virHostdevPreparePCIDevicesImpl(virHostdevManager *mgr,
                                const char *drv_name,
                                const char *dom_name,
                                const unsigned char *uuid,
                                virPCIDeviceList *pcidevs,
                                virDomainHostdevDef **hostdevs,
                                int nhostdevs,
                                unsigned int flags)
{
    int last_processed_hostdev_vf = -1;
    size_t i;
    int ret = -1;
    virPCIDeviceAddress *devAddr = NULL;

    virObjectLock(mgr->activePCIHostdevs);
    virObjectLock(mgr->inactivePCIHostdevs);

    /* Detaching devices from the host involves several steps; each
     * of them is described at length below.
     *
     * All devices must be detached before we reset any of them,
     * because in some cases you have to reset the whole PCI, which
     * impacts all devices on it. Also, all devices must be reset
     * before being marked as active */

    /* Step 1: Perform some initial checks on the devices */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevice *pci = virPCIDeviceListGet(pcidevs, i);
        bool strict_acs_check = !!(flags & VIR_HOSTDEV_STRICT_ACS_CHECK);
        bool usesVFIO = (virPCIDeviceGetStubDriverType(pci) == VIR_PCI_STUB_DRIVER_VFIO);
        struct virHostdevIsPCINodeDeviceUsedData data = {mgr, drv_name, dom_name, false};
        int hdrType = -1;

        if (virPCIGetHeaderType(pci, &hdrType) < 0)
            goto cleanup;

        if (hdrType != VIR_PCI_HEADER_ENDPOINT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Non-endpoint PCI devices cannot be assigned to guests"));
            goto cleanup;
        }

        if (!usesVFIO && !virPCIDeviceIsAssignable(pci, strict_acs_check)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("PCI device %1$s is not assignable"),
                           virPCIDeviceGetName(pci));
            goto cleanup;
        }

        /* The device is in use by other active domain if
         * the dev is in list activePCIHostdevs. */
        devAddr = virPCIDeviceGetAddress(pci);
        if (virHostdevIsPCINodeDeviceUsed(devAddr, &data))
            goto cleanup;

        /* VFIO devices belonging to same IOMMU group can't be
         * shared across guests. Check if that's the case. */
        if (usesVFIO) {
            data.usesVFIO = true;
            if (virPCIDeviceAddressIOMMUGroupIterate(devAddr,
                                                     virHostdevIsPCINodeDeviceUsed,
                                                     &data) < 0)
                goto cleanup;
        }
    }

    /* Step 1.5: For non-802.11Qbh SRIOV network devices, save the
     * current device config
     */
    for (i = 0; i < nhostdevs; i++) {
        if (virHostdevSaveNetConfig(hostdevs[i], mgr->stateDir) < 0)
            goto cleanup;
    }

    /* Step 2: detach managed devices and make sure unmanaged devices
     *         have already been taken care of */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevice *pci = virPCIDeviceListGet(pcidevs, i);

        if (virPCIDeviceGetManaged(pci)) {

            /* We can't look up the actual device because it has not been
             * created yet: virPCIDeviceDetach() will insert a copy of 'pci'
             * into the list of inactive devices, and that copy will be the
             * actual device going forward */
            VIR_DEBUG("Detaching managed PCI device %s",
                      virPCIDeviceGetName(pci));
            if (virPCIDeviceDetach(pci,
                                   mgr->activePCIHostdevs,
                                   mgr->inactivePCIHostdevs) < 0)
                goto reattachdevs;
        } else {
            g_autofree char *drvName = NULL;
            virPCIStubDriver drvType;

            /* Unmanaged devices should already have been marked as
             * inactive: if that's the case, we can simply move on */
            if (virPCIDeviceListFind(mgr->inactivePCIHostdevs,
                                     virPCIDeviceGetAddress(pci))) {
                VIR_DEBUG("Not detaching unmanaged PCI device %s",
                          virPCIDeviceGetName(pci));
                continue;
            }

            /* If that's not the case, though, it might be because the
             * daemon has been restarted, causing us to lose track of the
             * device. Try and recover by marking the device as inactive
             * if it happens to be bound to a known stub driver.
             *
             * FIXME Get rid of this once a proper way to keep track of
             *       information about active / inactive device across
             *       daemon restarts has been implemented */

            if (virPCIDeviceGetCurrentDriverNameAndType(pci, &drvName,
                                                        &drvType) < 0) {
                goto reattachdevs;
            }

            if (drvType > VIR_PCI_STUB_DRIVER_NONE) {

                /* The device is bound to a known stub driver: store this
                 * information and add a copy to the inactive list */
                virPCIDeviceSetStubDriverType(pci, drvType);
                virPCIDeviceSetStubDriverName(pci, drvName);

                VIR_DEBUG("Adding PCI device %s to inactive list",
                          virPCIDeviceGetName(pci));
                if (virPCIDeviceListAddCopy(mgr->inactivePCIHostdevs, pci) < 0)
                    goto reattachdevs;
            } else {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("Unmanaged PCI device %1$s must be manually detached from the host"),
                               virPCIDeviceGetName(pci));
                goto reattachdevs;
            }
        }
    }

    /* At this point, all devices are attached to the stub driver and have
     * been marked as inactive */

    /* Step 3: Now that all the PCI hostdevs have been detached, we
     * can safely reset them */
    if (virHostdevResetAllPCIDevices(mgr, pcidevs) < 0)
        goto reattachdevs;

    /* Step 4: For SRIOV network devices, Now that we have detached the
     * the network device, set the new netdev config */
    for (i = 0; i < nhostdevs; i++) {

        if (virHostdevSetNetConfig(hostdevs[i], uuid) < 0)
            goto resetvfnetconfig;

        last_processed_hostdev_vf = i;
    }

    /* Step 5: Move devices from the inactive list to the active list */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevice *pci = virPCIDeviceListGet(pcidevs, i);
        virPCIDevice *actual;

        VIR_DEBUG("Removing PCI device %s from inactive list",
                  virPCIDeviceGetName(pci));
        actual = virPCIDeviceListSteal(mgr->inactivePCIHostdevs, virPCIDeviceGetAddress(pci));

        VIR_DEBUG("Adding PCI device %s to active list",
                  virPCIDeviceGetName(pci));
        if (!actual || virPCIDeviceListAdd(mgr->activePCIHostdevs, actual) < 0)
            goto inactivedevs;
    }

    /* Step 6: Set driver and domain information */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevice *pci;
        virPCIDevice *actual;

        /* We need to look up the actual device and set the information
         * there because 'pci' only contain address information and will
         * be released at the end of the function */
        pci = virPCIDeviceListGet(pcidevs, i);
        actual = virPCIDeviceListFind(mgr->activePCIHostdevs,
                                      virPCIDeviceGetAddress(pci));

        VIR_DEBUG("Setting driver and domain information for PCI device %s",
                  virPCIDeviceGetName(pci));
        if (actual)
            virPCIDeviceSetUsedBy(actual, drv_name, dom_name);
    }

    /* Step 7: Now set the original states for hostdev def */
    for (i = 0; i < nhostdevs; i++) {
        virPCIDevice *actual;
        virDomainHostdevDef *hostdev = hostdevs[i];
        virDomainHostdevSubsysPCI *pcisrc = &hostdev->source.subsys.u.pci;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        /* We need to look up the actual device because it's the one
         * that contains the information we care about (unbind_from_stub,
         * remove_slot, reprobe) */
        actual = virPCIDeviceListFindByIDs(mgr->activePCIHostdevs,
                                           pcisrc->addr.domain,
                                           pcisrc->addr.bus,
                                           pcisrc->addr.slot,
                                           pcisrc->addr.function);

        /* Appropriate values for the unbind_from_stub, remove_slot
         * and reprobe properties of the device were set earlier
         * by virPCIDeviceDetach() */
        if (actual) {
            VIR_DEBUG("Saving network configuration of PCI device %s",
                      virPCIDeviceGetName(actual));

            if (!pcisrc->origstates)
                pcisrc->origstates = virBitmapNew(VIR_DOMAIN_HOSTDEV_PCI_ORIGSTATE_LAST);
            else
                virBitmapClearAll(pcisrc->origstates);

            if (virPCIDeviceGetUnbindFromStub(actual))
                virBitmapSetBitExpand(pcisrc->origstates, VIR_DOMAIN_HOSTDEV_PCI_ORIGSTATE_UNBIND);
            if (virPCIDeviceGetRemoveSlot(actual))
                virBitmapSetBitExpand(pcisrc->origstates, VIR_DOMAIN_HOSTDEV_PCI_ORIGSTATE_REMOVESLOT);
            if (virPCIDeviceGetReprobe(actual))
                virBitmapSetBitExpand(pcisrc->origstates, VIR_DOMAIN_HOSTDEV_PCI_ORIGSTATE_REPROBE);
        }
    }

    ret = 0;
    goto cleanup;

 inactivedevs:
    /* Move devices back to the inactive list so that they can be
     * processed properly below (reattachdevs label) */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevice *pci = virPCIDeviceListGet(pcidevs, i);
        virPCIDevice *actual;

        VIR_DEBUG("Removing PCI device %s from active list",
                  virPCIDeviceGetName(pci));
        if (!(actual = virPCIDeviceListSteal(mgr->activePCIHostdevs,
                                             virPCIDeviceGetAddress(pci))))
            continue;

        VIR_DEBUG("Adding PCI device %s to inactive list",
                  virPCIDeviceGetName(pci));
        if (virPCIDeviceListAdd(mgr->inactivePCIHostdevs, actual) < 0)
            VIR_WARN("Failed to add PCI device %s to the inactive list",
                     virPCIDeviceGetName(pci));
    }

 resetvfnetconfig:
    if (last_processed_hostdev_vf >= 0) {
        for (i = 0; i <= last_processed_hostdev_vf; i++)
            virHostdevRestoreNetConfig(hostdevs[i], mgr->stateDir);
    }

 reattachdevs:
    virHostdevReattachAllPCIDevices(mgr, pcidevs);

 cleanup:
    virObjectUnlock(mgr->activePCIHostdevs);
    virObjectUnlock(mgr->inactivePCIHostdevs);

    return ret;
}


int
virHostdevPreparePCIDevices(virHostdevManager *mgr,
                            const char *drv_name,
                            const char *dom_name,
                            const unsigned char *uuid,
                            virDomainHostdevDef **hostdevs,
                            int nhostdevs,
                            unsigned int flags)
{
    g_autoptr(virPCIDeviceList) pcidevs = NULL;

    if (!nhostdevs)
        return 0;

    if (!(pcidevs = virHostdevGetPCIHostDeviceList(hostdevs, nhostdevs)))
        return -1;

    return virHostdevPreparePCIDevicesImpl(mgr, drv_name, dom_name, uuid,
                                           pcidevs, hostdevs, nhostdevs, flags);
}


static void
virHostdevReAttachPCIDevicesImpl(virHostdevManager *mgr,
                                 const char *drv_name,
                                 const char *dom_name,
                                 virPCIDeviceList *pcidevs,
                                 virDomainHostdevDef **hostdevs,
                                 int nhostdevs)
{
    size_t i;

    virObjectLock(mgr->activePCIHostdevs);
    virObjectLock(mgr->inactivePCIHostdevs);

    /* Reattaching devices to the host involves several steps; each
     * of them is described at length below */

    /* Step 1: Filter out all devices that are either not active or not
     *         used by the current domain and driver */
    i = 0;
    while (i < virPCIDeviceListCount(pcidevs)) {
        virPCIDevice *pci = virPCIDeviceListGet(pcidevs, i);
        virPCIDevice *actual = NULL;

        /* We need to look up the actual device, which is the one containing
         * information such as by which domain and driver it is used. As a
         * side effect, by looking it up we can also tell whether it was
         * really active in the first place */
        actual = virPCIDeviceListFind(mgr->activePCIHostdevs,
                                      virPCIDeviceGetAddress(pci));
        if (actual) {
            const char *actual_drvname;
            const char *actual_domname;
            virPCIDeviceGetUsedBy(actual, &actual_drvname, &actual_domname);
            if (STRNEQ_NULLABLE(drv_name, actual_drvname) ||
                STRNEQ_NULLABLE(dom_name, actual_domname)) {

                virPCIDeviceListDel(pcidevs, virPCIDeviceGetAddress(pci));
                continue;
            }
        } else {
            virPCIDeviceListDel(pcidevs, virPCIDeviceGetAddress(pci));
            continue;
        }

        i++;
    }

    /* Step 2: Move devices from the active list to the inactive list */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevice *pci = virPCIDeviceListGet(pcidevs, i);
        virPCIDevice *actual;

        VIR_DEBUG("Removing PCI device %s from active list",
                  virPCIDeviceGetName(pci));
        actual = virPCIDeviceListSteal(mgr->activePCIHostdevs,
                                       virPCIDeviceGetAddress(pci));

        VIR_DEBUG("Adding PCI device %s to inactive list",
                  virPCIDeviceGetName(pci));
        if (!actual ||
            virPCIDeviceListAdd(mgr->inactivePCIHostdevs, actual) < 0) {

            VIR_ERROR(_("Failed to add PCI device %1$s to the inactive list"),
                      virGetLastErrorMessage());
            virResetLastError();
        }
    }

    /* At this point, any device that had been used by the guest has been
     * moved to the inactive list */

    /* Step 3: restore original network config of hostdevs that used
     * <interface type='hostdev'>
     */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDef *hostdev = hostdevs[i];

        if (virHostdevIsPCINetDevice(hostdev)) {
            virDomainHostdevSubsysPCI *pcisrc = &hostdev->source.subsys.u.pci;
            virPCIDevice *actual;

            actual = virPCIDeviceListFindByIDs(mgr->inactivePCIHostdevs,
                                               pcisrc->addr.domain,
                                               pcisrc->addr.bus,
                                               pcisrc->addr.slot,
                                               pcisrc->addr.function);

            if (actual) {
                VIR_DEBUG("Restoring network configuration of PCI device %s",
                          virPCIDeviceGetName(actual));
                virHostdevRestoreNetConfig(hostdev, mgr->stateDir);
            }
        }
    }

    /* Step 4: perform a PCI Reset on all devices */
    virHostdevResetAllPCIDevices(mgr, pcidevs);

    /* Step 5: Reattach managed devices to their host drivers; unmanaged
     *         devices don't need to be processed further */
    virHostdevReattachAllPCIDevices(mgr, pcidevs);

    virObjectUnlock(mgr->activePCIHostdevs);
    virObjectUnlock(mgr->inactivePCIHostdevs);
}


static void
virHostdevDeleteMissingPCIDevices(virHostdevManager *mgr,
                                  virDomainHostdevDef **hostdevs,
                                  int nhostdevs)
{
    size_t i;

    if (nhostdevs == 0)
        return;

    virObjectLock(mgr->activePCIHostdevs);
    virObjectLock(mgr->inactivePCIHostdevs);

    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDef *hostdev = hostdevs[i];
        virDomainHostdevSubsysPCI *pcisrc = &hostdev->source.subsys.u.pci;
        g_autoptr(virPCIDevice) pci = NULL;

        if (virHostdevGetPCIHostDevice(hostdev, &pci) != -2)
            continue;

        /* The PCI device from 'hostdev' does not exist in the host
         * anymore. Delete it from both active and inactive lists to
         * reflect the current host state.
         */
        virPCIDeviceListDel(mgr->activePCIHostdevs, &pcisrc->addr);
        virPCIDeviceListDel(mgr->inactivePCIHostdevs, &pcisrc->addr);
    }

    virObjectUnlock(mgr->inactivePCIHostdevs);
    virObjectUnlock(mgr->activePCIHostdevs);
}


void
virHostdevReAttachPCIDevices(virHostdevManager *mgr,
                             const char *drv_name,
                             const char *dom_name,
                             virDomainHostdevDef **hostdevs,
                             int nhostdevs)
{
    g_autoptr(virPCIDeviceList) pcidevs = NULL;

    if (!nhostdevs)
        return;

    if (!(pcidevs = virHostdevGetPCIHostDeviceList(hostdevs, nhostdevs))) {
        VIR_ERROR(_("Failed to allocate PCI device list: %1$s"),
                  virGetLastErrorMessage());
        virResetLastError();
        return;
    }

    virHostdevReAttachPCIDevicesImpl(mgr, drv_name, dom_name, pcidevs,
                                     hostdevs, nhostdevs);

    /* Handle the case where PCI devices from the host went missing
     * during the domain lifetime */
    virHostdevDeleteMissingPCIDevices(mgr, hostdevs, nhostdevs);
}


int
virHostdevUpdateActivePCIDevices(virHostdevManager *mgr,
                                 virDomainHostdevDef **hostdevs,
                                 int nhostdevs,
                                 const char *drv_name,
                                 const char *dom_name)
{
    size_t i;
    int ret = -1;

    if (!nhostdevs)
        return 0;

    virObjectLock(mgr->activePCIHostdevs);
    virObjectLock(mgr->inactivePCIHostdevs);

    for (i = 0; i < nhostdevs; i++) {
        const virDomainHostdevDef *hostdev = hostdevs[i];
        g_autoptr(virPCIDevice) actual = NULL;
        virBitmap *orig = hostdev->source.subsys.u.pci.origstates;

        if (virHostdevGetPCIHostDevice(hostdev, &actual) < 0)
            goto cleanup;

        if (!actual)
            continue;

        if (virPCIDeviceSetUsedBy(actual, drv_name, dom_name) < 0)
            goto cleanup;

        /* Setup the original states for the PCI device */
        virPCIDeviceSetUnbindFromStub(actual, virBitmapIsBitSet(orig, VIR_DOMAIN_HOSTDEV_PCI_ORIGSTATE_UNBIND));
        virPCIDeviceSetRemoveSlot(actual, virBitmapIsBitSet(orig, VIR_DOMAIN_HOSTDEV_PCI_ORIGSTATE_REMOVESLOT));
        virPCIDeviceSetReprobe(actual, virBitmapIsBitSet(orig, VIR_DOMAIN_HOSTDEV_PCI_ORIGSTATE_REPROBE));

        if (virPCIDeviceListAdd(mgr->activePCIHostdevs, actual) < 0)
            goto cleanup;
        actual = NULL;
    }

    ret = 0;
 cleanup:
    virObjectUnlock(mgr->activePCIHostdevs);
    virObjectUnlock(mgr->inactivePCIHostdevs);
    return ret;
}

int
virHostdevUpdateActiveUSBDevices(virHostdevManager *mgr,
                                 virDomainHostdevDef **hostdevs,
                                 int nhostdevs,
                                 const char *drv_name,
                                 const char *dom_name)
{
    virDomainHostdevDef *hostdev = NULL;
    size_t i;
    int ret = -1;

    if (!nhostdevs)
        return 0;

    virObjectLock(mgr->activeUSBHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevSubsysUSB *usbsrc;
        g_autoptr(virUSBDevice) usb = NULL;
        hostdev = hostdevs[i];
        usbsrc = &hostdev->source.subsys.u.usb;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        if (!(usb = virUSBDeviceNew(usbsrc->bus, usbsrc->device, NULL))) {
            VIR_WARN("Unable to reattach USB device %03d.%03d on domain %s",
                     usbsrc->bus, usbsrc->device, dom_name);
            continue;
        }

        virUSBDeviceSetUsedBy(usb, drv_name, dom_name);

        if (virUSBDeviceListAdd(mgr->activeUSBHostdevs, &usb) < 0)
            goto cleanup;
        usb = NULL;
    }
    ret = 0;
 cleanup:
    virObjectUnlock(mgr->activeUSBHostdevs);
    return ret;
}

static int
virHostdevUpdateActiveSCSIHostDevices(virHostdevManager *mgr,
                                      virDomainHostdevDef *hostdev,
                                      virDomainHostdevSubsysSCSI *scsisrc,
                                      const char *drv_name,
                                      const char *dom_name)
{
    virDomainHostdevSubsysSCSIHost *scsihostsrc = &scsisrc->u.host;
    g_autoptr(virSCSIDevice) scsi = NULL;
    virSCSIDevice *tmp = NULL;

    if (!(scsi = virSCSIDeviceNew(NULL,
                                  scsihostsrc->adapter, scsihostsrc->bus,
                                  scsihostsrc->target, scsihostsrc->unit,
                                  hostdev->readonly, hostdev->shareable)))
        return -1;

    if ((tmp = virSCSIDeviceListFind(mgr->activeSCSIHostdevs, scsi))) {
        if (virSCSIDeviceSetUsedBy(tmp, drv_name, dom_name) < 0)
            return -1;
    } else {
        if (virSCSIDeviceSetUsedBy(scsi, drv_name, dom_name) < 0 ||
            virSCSIDeviceListAdd(mgr->activeSCSIHostdevs, scsi) < 0)
            return -1;
        scsi = NULL;
    }
    return 0;
}

int
virHostdevUpdateActiveSCSIDevices(virHostdevManager *mgr,
                                  virDomainHostdevDef **hostdevs,
                                  int nhostdevs,
                                  const char *drv_name,
                                  const char *dom_name)
{
    virDomainHostdevDef *hostdev = NULL;
    size_t i;
    int ret = -1;

    if (!nhostdevs)
        return 0;

    virObjectLock(mgr->activeSCSIHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevSubsysSCSI *scsisrc;
        hostdev = hostdevs[i];
        scsisrc = &hostdev->source.subsys.u.scsi;

        if (!virHostdevIsSCSIDevice(hostdev))
            continue;

        if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
            continue;  /* Not supported for iSCSI */
        } else {
            if (virHostdevUpdateActiveSCSIHostDevices(mgr, hostdev, scsisrc,
                                                      drv_name, dom_name) < 0)
                goto cleanup;
        }
    }
    ret = 0;

 cleanup:
    virObjectUnlock(mgr->activeSCSIHostdevs);
    return ret;
}


int
virHostdevUpdateActiveMediatedDevices(virHostdevManager *mgr,
                                      virDomainHostdevDef **hostdevs,
                                      int nhostdevs,
                                      const char *drv_name,
                                      const char *dom_name)
{
    int ret = -1;
    size_t i;
    g_autoptr(virMediatedDevice) mdev = NULL;

    if (nhostdevs == 0)
        return 0;

    virObjectLock(mgr->activeMediatedHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDef *hostdev = hostdevs[i];
        virDomainHostdevSubsysMediatedDev *mdevsrc;

        mdevsrc = &hostdev->source.subsys.u.mdev;

        if (!virHostdevIsMdevDevice(hostdev))
            continue;

        if (!(mdev = virMediatedDeviceNew(mdevsrc->uuidstr, mdevsrc->model)))
            goto cleanup;

        virMediatedDeviceSetUsedBy(mdev, drv_name, dom_name);

        if (virMediatedDeviceListAdd(mgr->activeMediatedHostdevs, &mdev) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnlock(mgr->activeMediatedHostdevs);
    return ret;
}


static int
virHostdevMarkUSBDevices(virHostdevManager *mgr,
                         const char *drv_name,
                         const char *dom_name,
                         virUSBDeviceList *list)
{
    size_t i, j;
    unsigned int count;
    virUSBDevice *tmp;

    virObjectLock(mgr->activeUSBHostdevs);
    count = virUSBDeviceListCount(list);

    for (i = 0; i < count; i++) {
        virUSBDevice *usb = virUSBDeviceListGet(list, i);
        if ((tmp = virUSBDeviceListFind(mgr->activeUSBHostdevs, usb))) {
            const char *other_drvname;
            const char *other_domname;

            virUSBDeviceGetUsedBy(tmp, &other_drvname, &other_domname);
            if (other_drvname && other_domname)
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("USB device %1$s is in use by driver %2$s, domain %3$s"),
                               virUSBDeviceGetName(tmp),
                               other_drvname, other_domname);
            else
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("USB device %1$s is already in use"),
                               virUSBDeviceGetName(tmp));
            goto error;
        }

        virUSBDeviceSetUsedBy(usb, drv_name, dom_name);
        VIR_DEBUG("Adding %03d.%03d dom=%s to activeUSBHostdevs",
                  virUSBDeviceGetBus(usb), virUSBDeviceGetDevno(usb),
                  dom_name);
        /*
         * The caller is responsible to steal these usb devices
         * from the virUSBDeviceList that passed in on success,
         * perform rollback on failure.
         */
        if (virUSBDeviceListAdd(mgr->activeUSBHostdevs, &usb) < 0)
            goto error;
    }

    virObjectUnlock(mgr->activeUSBHostdevs);
    return 0;

 error:
    for (j = 0; j < i; j++) {
        tmp = virUSBDeviceListGet(list, i);
        virUSBDeviceListSteal(mgr->activeUSBHostdevs, tmp);
    }
    virObjectUnlock(mgr->activeUSBHostdevs);
    return -1;
}


int
virHostdevFindUSBDevice(virDomainHostdevDef *hostdev,
                        bool mandatory,
                        virUSBDevice **usb)
{
    virDomainHostdevSubsysUSB *usbsrc = &hostdev->source.subsys.u.usb;
    unsigned vendor = usbsrc->vendor;
    unsigned product = usbsrc->product;
    unsigned bus = usbsrc->bus;
    unsigned device = usbsrc->device;
    bool autoAddress = usbsrc->autoAddress;
    int rc;

    *usb = NULL;

    if (vendor && bus) {
        rc = virUSBDeviceFind(vendor, product, bus, device,
                              NULL,
                              autoAddress ? false : mandatory,
                              usb);
        if (rc < 0) {
            return -1;
        } else if (!autoAddress) {
            goto out;
        } else {
            VIR_INFO("USB device %x:%x could not be found at previous"
                     " address (bus:%u device:%u)",
                     vendor, product, bus, device);
        }
    }

    /* When vendor is specified, its USB address is either unspecified or the
     * device could not be found at the USB device where it had been
     * automatically found before.
     */
    if (vendor) {
        g_autoptr(virUSBDeviceList) devs = NULL;

        rc = virUSBDeviceFindByVendor(vendor, product, NULL, mandatory, &devs);
        if (rc < 0) {
            return -1;
        } else if (rc == 0) {
            goto out;
        } else if (rc > 1) {
            if (autoAddress) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Multiple USB devices for %1$x:%2$x were found, but none of them is at bus:%3$u device:%4$u"),
                               vendor, product, bus, device);
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Multiple USB devices for %1$x:%2$x, use <address> to specify one"),
                               vendor, product);
            }
            return -1;
        }

        *usb = virUSBDeviceListGet(devs, 0);
        virUSBDeviceListSteal(devs, *usb);

        usbsrc->bus = virUSBDeviceGetBus(*usb);
        usbsrc->device = virUSBDeviceGetDevno(*usb);
        usbsrc->autoAddress = true;

        if (autoAddress) {
            VIR_INFO("USB device %x:%x found at bus:%u device:%u (moved"
                     " from bus:%u device:%u)",
                     vendor, product,
                     usbsrc->bus, usbsrc->device,
                     bus, device);
        }
    } else if (bus) {
        if (virUSBDeviceFindByBus(bus, device, NULL, mandatory, usb) < 0)
            return -1;
    }

 out:
    if (!*usb)
        hostdev->missing = true;
    return 0;
}

int
virHostdevPrepareUSBDevices(virHostdevManager *mgr,
                            const char *drv_name,
                            const char *dom_name,
                            virDomainHostdevDef **hostdevs,
                            int nhostdevs,
                            unsigned int flags)
{
    size_t i;
    g_autoptr(virUSBDeviceList) list = NULL;
    virUSBDevice *tmp;
    bool coldBoot = !!(flags & VIR_HOSTDEV_COLD_BOOT);

    if (!nhostdevs)
        return 0;

    /* To prevent situation where USB device is assigned to two domains
     * we need to keep a list of currently assigned USB devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See virHostdevPreparePCIDevices()
     */
    if (!(list = virUSBDeviceListNew()))
        return -1;

    /* Loop 1: build temporary list
     */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDef *hostdev = hostdevs[i];
        bool required = true;
        g_autoptr(virUSBDevice) usb = NULL;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        if (hostdev->startupPolicy == VIR_DOMAIN_STARTUP_POLICY_OPTIONAL ||
            (hostdev->startupPolicy == VIR_DOMAIN_STARTUP_POLICY_REQUISITE &&
             !coldBoot))
            required = false;

        if (virHostdevFindUSBDevice(hostdev, required, &usb) < 0)
            return -1;

        if (usb && virUSBDeviceListAdd(list, &usb) < 0)
            return -1;
        usb = NULL;
    }

    /* Mark devices in temporary list as used by @dom_name
     * and add them do driver list. However, if something goes
     * wrong, perform rollback.
     */
    if (virHostdevMarkUSBDevices(mgr, drv_name, dom_name, list) < 0)
        return -1;

    /* Loop 2: Temporary list was successfully merged with
     * driver list, so steal all items to avoid freeing them
     * in cleanup label.
     */
    while (virUSBDeviceListCount(list) > 0) {
        tmp = virUSBDeviceListGet(list, 0);
        virUSBDeviceListSteal(list, tmp);
    }

    return 0;
}

static int
virHostdevPrepareSCSIHostDevices(virDomainHostdevDef *hostdev,
                                 virDomainHostdevSubsysSCSI *scsisrc,
                                 virSCSIDeviceList *list)
{
    virDomainHostdevSubsysSCSIHost *scsihostsrc = &scsisrc->u.host;
    g_autoptr(virSCSIDevice) scsi = NULL;

    if (hostdev->managed) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("SCSI host device doesn't support managed mode"));
        return -1;
    }

    if (!(scsi = virSCSIDeviceNew(NULL,
                                  scsihostsrc->adapter, scsihostsrc->bus,
                                  scsihostsrc->target, scsihostsrc->unit,
                                  hostdev->readonly, hostdev->shareable)))
        return -1;

    if (virSCSIDeviceListAdd(list, scsi) < 0)
        return -1;
    scsi = NULL;

    return 0;
}

int
virHostdevPrepareSCSIDevices(virHostdevManager *mgr,
                             const char *drv_name,
                             const char *dom_name,
                             virDomainHostdevDef **hostdevs,
                             int nhostdevs)
{
    size_t i, j;
    int count;
    g_autoptr(virSCSIDeviceList) list = NULL;
    virSCSIDevice *tmp;

    if (!nhostdevs)
        return 0;

    /* To prevent situation where SCSI device is assigned to two domains
     * we need to keep a list of currently assigned SCSI devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See virHostdevPreparePCIDevices()
     */
    if (!(list = virSCSIDeviceListNew()))
        return -1;

    /* Loop 1: build temporary list */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDef *hostdev = hostdevs[i];
        virDomainHostdevSubsysSCSI *scsisrc = &hostdev->source.subsys.u.scsi;

        if (!virHostdevIsSCSIDevice(hostdev))
            continue;

        if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
            continue;  /* Not supported for iSCSI */
        } else {
            if (virHostdevPrepareSCSIHostDevices(hostdev, scsisrc, list) < 0)
                return -1;
        }
    }

    /* Loop 2: Mark devices in temporary list as used by @name
     * and add them to driver list. However, if something goes
     * wrong, perform rollback.
     */
    virObjectLock(mgr->activeSCSIHostdevs);
    count = virSCSIDeviceListCount(list);

    for (i = 0; i < count; i++) {
        virSCSIDevice *scsi = virSCSIDeviceListGet(list, i);
        if ((tmp = virSCSIDeviceListFind(mgr->activeSCSIHostdevs,
                                         scsi))) {
            bool scsi_shareable = virSCSIDeviceGetShareable(scsi);
            bool tmp_shareable = virSCSIDeviceGetShareable(tmp);

            if (!(scsi_shareable && tmp_shareable)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("SCSI device %1$s is already in use by other domain(s) as '%2$s'"),
                               virSCSIDeviceGetName(tmp),
                               tmp_shareable ? "shareable" : "non-shareable");
                goto error;
            }

            if (virSCSIDeviceSetUsedBy(tmp, drv_name, dom_name) < 0)
                goto error;
        } else {
            if (virSCSIDeviceSetUsedBy(scsi, drv_name, dom_name) < 0)
                goto error;

            VIR_DEBUG("Adding %s to activeSCSIHostdevs", virSCSIDeviceGetName(scsi));

            if (virSCSIDeviceListAdd(mgr->activeSCSIHostdevs, scsi) < 0)
                goto error;
        }
    }

    virObjectUnlock(mgr->activeSCSIHostdevs);

    /* Loop 3: Temporary list was successfully merged with
     * driver list, so steal all items to avoid freeing them
     * when freeing temporary list.
     */
    while (virSCSIDeviceListCount(list) > 0) {
        tmp = virSCSIDeviceListGet(list, 0);
        virSCSIDeviceListSteal(list, tmp);
    }

    return 0;

 error:
    for (j = 0; j < i; j++) {
        tmp = virSCSIDeviceListGet(list, i);
        virSCSIDeviceListSteal(mgr->activeSCSIHostdevs, tmp);
    }
    virObjectUnlock(mgr->activeSCSIHostdevs);
    return -1;
}

int
virHostdevPrepareSCSIVHostDevices(virHostdevManager *mgr,
                                  const char *drv_name,
                                  const char *dom_name,
                                  virDomainHostdevDef **hostdevs,
                                  int nhostdevs)
{
    g_autoptr(virSCSIVHostDeviceList) list = NULL;
    virSCSIVHostDevice *tmp;
    size_t i, j;

    if (!nhostdevs)
        return 0;

    /* To prevent situation where scsi_host device is assigned to two domains
     * we need to keep a list of currently assigned scsi_host devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See virHostdevPreparePCIDevices()
     */
    if (!(list = virSCSIVHostDeviceListNew()))
        return -1;

    /* Loop 1: build temporary list */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDef *hostdev = hostdevs[i];
        virDomainHostdevSubsysSCSIVHost *hostsrc = &hostdev->source.subsys.u.scsi_host;
        g_autoptr(virSCSIVHostDevice) host = NULL;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST)
            continue;

        if (hostsrc->protocol != VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_VHOST)
            continue;  /* Not supported */

        if (!(host = virSCSIVHostDeviceNew(hostsrc->wwpn)))
            return -1;

        if (virSCSIVHostDeviceSetUsedBy(host, drv_name, dom_name) < 0)
            return -1;

        if (virSCSIVHostDeviceListAdd(list, host) < 0)
            return -1;
        host = NULL;
    }

    /* Loop 2: Mark devices in temporary list as used by @name
     * and add them to driver list. However, if something goes
     * wrong, perform rollback.
     */
    virObjectLock(mgr->activeSCSIVHostHostdevs);

    for (i = 0; i < virSCSIVHostDeviceListCount(list); i++) {
        tmp = virSCSIVHostDeviceListGet(list, i);

        VIR_DEBUG("Adding %s to activeSCSIVHostHostdevs",
                  virSCSIVHostDeviceGetName(tmp));

        if (virSCSIVHostDeviceListAdd(mgr->activeSCSIVHostHostdevs, tmp) < 0)
            goto rollback;
    }

    virObjectUnlock(mgr->activeSCSIVHostHostdevs);

    /* Loop 3: Temporary list was successfully merged with
     * driver list, so steal all items to avoid freeing them
     * when freeing temporary list.
     */
    while (virSCSIVHostDeviceListCount(list) > 0) {
        tmp = virSCSIVHostDeviceListGet(list, 0);
        virSCSIVHostDeviceListSteal(list, tmp);
    }

    return 0;

 rollback:
    for (j = 0; j < i; j++) {
        tmp = virSCSIVHostDeviceListGet(list, i);
        virSCSIVHostDeviceListSteal(mgr->activeSCSIVHostHostdevs, tmp);
    }
    virObjectUnlock(mgr->activeSCSIVHostHostdevs);
    return -1;
}


int
virHostdevPrepareMediatedDevices(virHostdevManager *mgr,
                                 const char *drv_name,
                                 const char *dom_name,
                                 virDomainHostdevDef **hostdevs,
                                 int nhostdevs)
{
    size_t i;
    g_autoptr(virMediatedDeviceList) list = NULL;

    if (!nhostdevs)
        return 0;

    /* To prevent situation where mediated device is assigned to multiple
     * domains we maintain a driver list of currently assigned mediated devices.
     * A device is appended to the driver list after a series of preparations.
     */
    if (!(list = virMediatedDeviceListNew()))
        return -1;

    /* Loop 1: Build a temporary list of ALL mediated devices. */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDef *hostdev = hostdevs[i];
        virDomainHostdevSubsysMediatedDev *src = &hostdev->source.subsys.u.mdev;
        g_autoptr(virMediatedDevice) mdev = NULL;

        if (!virHostdevIsMdevDevice(hostdev))
            continue;

        if (!(mdev = virMediatedDeviceNew(src->uuidstr, src->model)))
            return -1;

        if (virMediatedDeviceListAdd(list, &mdev) < 0)
            return -1;
        mdev = NULL;
    }

    /* Mark the devices in the list as used by @drv_name-@dom_name and copy the
     * references to the driver list
     */
    if (virMediatedDeviceListMarkDevices(mgr->activeMediatedHostdevs,
                                         list, drv_name, dom_name) < 0)
        return -1;

    /* Loop 2: Temporary list was successfully merged with
     * driver list, so steal all items to avoid freeing them
     * in cleanup label.
     */
    while (virMediatedDeviceListCount(list) > 0) {
        virMediatedDevice *tmp = virMediatedDeviceListGet(list, 0);
        virMediatedDeviceListSteal(list, tmp);
    }

    return 0;
}

void
virHostdevReAttachUSBDevices(virHostdevManager *mgr,
                             const char *drv_name,
                             const char *dom_name,
                             virDomainHostdevDef **hostdevs,
                             int nhostdevs)
{
    size_t i;

    if (!nhostdevs)
        return;

    virObjectLock(mgr->activeUSBHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDef *hostdev = hostdevs[i];
        virDomainHostdevSubsysUSB *usbsrc = &hostdev->source.subsys.u.usb;
        g_autoptr(virUSBDevice) usb = NULL;
        virUSBDevice *tmp;
        const char *usedby_drvname;
        const char *usedby_domname;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;
        if (hostdev->missing)
            continue;

        if (!(usb = virUSBDeviceNew(usbsrc->bus, usbsrc->device, NULL))) {
            VIR_WARN("Unable to reattach USB device %03d.%03d on domain %s",
                     usbsrc->bus, usbsrc->device, NULLSTR(dom_name));
            continue;
        }

        /* Delete only those USB devices which belongs
         * to domain @name because qemuProcessStart() might
         * have failed because USB device is already taken.
         * Therefore we want to steal only those devices from
         * the list which were taken by @name */

        tmp = virUSBDeviceListFind(mgr->activeUSBHostdevs, usb);

        if (!tmp) {
            VIR_WARN("Unable to find device %03d.%03d "
                     "in list of active USB devices",
                     usbsrc->bus, usbsrc->device);
            continue;
        }

        virUSBDeviceGetUsedBy(tmp, &usedby_drvname, &usedby_domname);
        if (STREQ_NULLABLE(drv_name, usedby_drvname) &&
            STREQ_NULLABLE(dom_name, usedby_domname)) {
            VIR_DEBUG("Removing %03d.%03d dom=%s from activeUSBHostdevs",
                      usbsrc->bus, usbsrc->device, dom_name);
            virUSBDeviceListDel(mgr->activeUSBHostdevs, tmp);
        }
    }
    virObjectUnlock(mgr->activeUSBHostdevs);
}

static void
virHostdevReAttachSCSIHostDevices(virHostdevManager *mgr,
                                  virDomainHostdevDef *hostdev,
                                  virDomainHostdevSubsysSCSI *scsisrc,
                                  const char *drv_name,
                                  const char *dom_name)
{
    virDomainHostdevSubsysSCSIHost *scsihostsrc = &scsisrc->u.host;
    g_autoptr(virSCSIDevice) scsi = NULL;
    virSCSIDevice *tmp;

    if (!(scsi = virSCSIDeviceNew(NULL,
                                  scsihostsrc->adapter, scsihostsrc->bus,
                                  scsihostsrc->target, scsihostsrc->unit,
                                  hostdev->readonly, hostdev->shareable))) {
        VIR_WARN("Unable to reattach SCSI device %s:%u:%u:%llu on domain %s",
                 scsihostsrc->adapter, scsihostsrc->bus, scsihostsrc->target,
                 scsihostsrc->unit, dom_name);
        return;
    }

    /* Only delete the devices which are marked as being used by @name,
     * because qemuProcessStart could fail half way through. */

    if (!(tmp = virSCSIDeviceListFind(mgr->activeSCSIHostdevs, scsi))) {
        VIR_WARN("Unable to find device %s:%u:%u:%llu "
                 "in list of active SCSI devices",
                 scsihostsrc->adapter, scsihostsrc->bus,
                 scsihostsrc->target, scsihostsrc->unit);
        return;
    }

    VIR_DEBUG("Removing %s:%u:%u:%llu dom=%s from activeSCSIHostdevs",
              scsihostsrc->adapter, scsihostsrc->bus, scsihostsrc->target,
              scsihostsrc->unit, dom_name);

    virSCSIDeviceListDel(mgr->activeSCSIHostdevs, tmp,
                         drv_name, dom_name);
}

void
virHostdevReAttachSCSIDevices(virHostdevManager *mgr,
                              const char *drv_name,
                              const char *dom_name,
                              virDomainHostdevDef **hostdevs,
                              int nhostdevs)
{
    size_t i;

    if (!nhostdevs)
        return;

    virObjectLock(mgr->activeSCSIHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDef *hostdev = hostdevs[i];
        virDomainHostdevSubsysSCSI *scsisrc = &hostdev->source.subsys.u.scsi;

        if (!virHostdevIsSCSIDevice(hostdev))
            continue;

        if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI)
            continue; /* Not supported for iSCSI */
        else
            virHostdevReAttachSCSIHostDevices(mgr, hostdev, scsisrc,
                                              drv_name, dom_name);
    }
    virObjectUnlock(mgr->activeSCSIHostdevs);
}

void
virHostdevReAttachSCSIVHostDevices(virHostdevManager *mgr,
                                   const char *drv_name,
                                   const char *dom_name,
                                   virDomainHostdevDef **hostdevs,
                                   int nhostdevs)
{
    size_t i;

    if (!nhostdevs)
        return;

    virObjectLock(mgr->activeSCSIVHostHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        g_autoptr(virSCSIVHostDevice) host = NULL;
        virSCSIVHostDevice *tmp;
        virDomainHostdevDef *hostdev = hostdevs[i];
        virDomainHostdevSubsysSCSIVHost *hostsrc = &hostdev->source.subsys.u.scsi_host;
        const char *usedby_drvname;
        const char *usedby_domname;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST)
            continue;

        if (hostsrc->protocol != VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_VHOST)
            continue; /* Not supported */

        if (!(host = virSCSIVHostDeviceNew(hostsrc->wwpn))) {
            VIR_WARN("Unable to reattach SCSI_host device %s on domain %s",
                     hostsrc->wwpn, NULLSTR(dom_name));
            virObjectUnlock(mgr->activeSCSIVHostHostdevs);
            return;
        }

        /* Only delete the devices which are marked as being used by @name,
         * because qemuProcessStart could fail half way through. */

        if (!(tmp = virSCSIVHostDeviceListFind(mgr->activeSCSIVHostHostdevs,
                                               host))) {
            VIR_WARN("Unable to find device %s "
                     "in list of active SCSI_host devices",
                     hostsrc->wwpn);
            virObjectUnlock(mgr->activeSCSIVHostHostdevs);
            return;
        }

        virSCSIVHostDeviceGetUsedBy(tmp, &usedby_drvname, &usedby_domname);

        if (STREQ_NULLABLE(drv_name, usedby_drvname) &&
            STREQ_NULLABLE(dom_name, usedby_domname)) {
            VIR_DEBUG("Removing %s dom=%s from activeSCSIVHostHostdevs",
                      hostsrc->wwpn, dom_name);

            virSCSIVHostDeviceListDel(mgr->activeSCSIVHostHostdevs, tmp);
        }
    }
    virObjectUnlock(mgr->activeSCSIVHostHostdevs);
}

/* TODO: Rename this function along with all virHostdevReAttach* functions that
 * have nothing to do with an explicit re-attachment of a device back to the
 * host driver (like PCI).
 * Despite what the function name suggests, there's nothing to be re-attached
 * for mediated devices, the function merely removes a mediated device from the
 * list of active host devices.
 */
void
virHostdevReAttachMediatedDevices(virHostdevManager *mgr,
                                  const char *drv_name,
                                  const char *dom_name,
                                  virDomainHostdevDef **hostdevs,
                                  int nhostdevs)
{
    const char *used_by_drvname = NULL;
    const char *used_by_domname = NULL;
    size_t i;

    if (nhostdevs == 0)
        return;

    virObjectLock(mgr->activeMediatedHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        g_autofree char *sysfspath = NULL;
        virMediatedDevice *tmp;
        virDomainHostdevSubsysMediatedDev *mdevsrc;
        virDomainHostdevDef *hostdev = hostdevs[i];

        if (!virHostdevIsMdevDevice(hostdev))
            continue;

        mdevsrc = &hostdev->source.subsys.u.mdev;
        sysfspath = virMediatedDeviceGetSysfsPath(mdevsrc->uuidstr);

        /* Remove from the list only mdevs assigned to @drv_name/@dom_name */

        tmp = virMediatedDeviceListFind(mgr->activeMediatedHostdevs,
                                        sysfspath);

        /* skip inactive devices */
        if (!tmp)
            continue;

        virMediatedDeviceGetUsedBy(tmp, &used_by_drvname, &used_by_domname);
        if (STREQ_NULLABLE(drv_name, used_by_drvname) &&
            STREQ_NULLABLE(dom_name, used_by_domname)) {
            VIR_DEBUG("Removing %s dom=%s from activeMediatedHostdevs",
                      mdevsrc->uuidstr, dom_name);
            virMediatedDeviceListDel(mgr->activeMediatedHostdevs, tmp);
        }
    }
    virObjectUnlock(mgr->activeMediatedHostdevs);
}

int
virHostdevPCINodeDeviceDetach(virHostdevManager *mgr,
                              virPCIDevice *pci)
{
    struct virHostdevIsPCINodeDeviceUsedData data = {mgr, NULL, NULL, false};
    int ret = -1;

    virObjectLock(mgr->activePCIHostdevs);
    virObjectLock(mgr->inactivePCIHostdevs);

    if (virHostdevIsPCINodeDeviceUsed(virPCIDeviceGetAddress(pci), &data))
        goto cleanup;

    if (virPCIDeviceDetach(pci, mgr->activePCIHostdevs,
                           mgr->inactivePCIHostdevs) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnlock(mgr->inactivePCIHostdevs);
    virObjectUnlock(mgr->activePCIHostdevs);

    return ret;
}

int
virHostdevPCINodeDeviceReAttach(virHostdevManager *mgr,
                                virPCIDevice *pci)
{
    struct virHostdevIsPCINodeDeviceUsedData data = {mgr, NULL, NULL, false};
    int ret = -1;

    virObjectLock(mgr->activePCIHostdevs);
    virObjectLock(mgr->inactivePCIHostdevs);

    if (virHostdevIsPCINodeDeviceUsed(virPCIDeviceGetAddress(pci), &data))
        goto cleanup;

    virPCIDeviceSetUnbindFromStub(pci, true);
    virPCIDeviceSetRemoveSlot(pci, true);
    virPCIDeviceSetReprobe(pci, true);

    if (virPCIDeviceReattach(pci, mgr->activePCIHostdevs,
                             mgr->inactivePCIHostdevs) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnlock(mgr->inactivePCIHostdevs);
    virObjectUnlock(mgr->activePCIHostdevs);

    return ret;
}

int
virHostdevPCINodeDeviceReset(virHostdevManager *mgr,
                             virPCIDevice *pci)
{
    int ret = -1;

    virObjectLock(mgr->activePCIHostdevs);
    virObjectLock(mgr->inactivePCIHostdevs);
    if (virPCIDeviceReset(pci, mgr->activePCIHostdevs,
                          mgr->inactivePCIHostdevs) < 0)
        goto out;

    ret = 0;
 out:
    virObjectUnlock(mgr->inactivePCIHostdevs);
    virObjectUnlock(mgr->activePCIHostdevs);
    return ret;
}

int
virHostdevPrepareDomainDevices(virHostdevManager *mgr,
                               const char *driver,
                               virDomainDef *def,
                               unsigned int flags)
{
    if (!def->nhostdevs)
        return 0;

    if (!mgr) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no host device manager defined"));
        return -1;
    }

    if (flags & VIR_HOSTDEV_SP_PCI) {
        if (virHostdevPreparePCIDevices(mgr, driver,
                                        def->name, def->uuid,
                                        def->hostdevs,
                                        def->nhostdevs,
                                        flags) < 0)
            return -1;
    }

    if (flags & VIR_HOSTDEV_SP_USB) {
        if (virHostdevPrepareUSBDevices(mgr, driver, def->name,
                                        def->hostdevs, def->nhostdevs,
                                        flags) < 0)
            return -1;
    }

    if (flags & VIR_HOSTDEV_SP_SCSI) {
        if (virHostdevPrepareSCSIDevices(mgr, driver, def->name,
                                         def->hostdevs, def->nhostdevs) < 0)
        return -1;
    }

    return 0;
}

void
virHostdevReAttachDomainDevices(virHostdevManager *mgr,
                                const char *driver,
                                virDomainDef *def,
                                unsigned int flags)
{
    if (!def->nhostdevs || !mgr)
        return;

    if (flags & VIR_HOSTDEV_SP_PCI) {
        virHostdevReAttachPCIDevices(mgr, driver, def->name,
                                     def->hostdevs, def->nhostdevs);
    }

    if (flags & VIR_HOSTDEV_SP_USB) {
        virHostdevReAttachUSBDevices(mgr, driver, def->name,
                                     def->hostdevs, def->nhostdevs);
    }

    if (flags & VIR_HOSTDEV_SP_SCSI) {
        virHostdevReAttachSCSIDevices(mgr, driver, def->name,
                                      def->hostdevs, def->nhostdevs);
    }
}

int
virHostdevUpdateActiveDomainDevices(virHostdevManager *mgr,
                                    const char *driver,
                                    virDomainDef *def,
                                    unsigned int flags)
{
    if (!def->nhostdevs)
        return 0;

    if (flags & VIR_HOSTDEV_SP_PCI) {
        if (virHostdevUpdateActivePCIDevices(mgr,
                                             def->hostdevs,
                                             def->nhostdevs,
                                             driver, def->name) < 0)
            return -1;
    }

    if (flags & VIR_HOSTDEV_SP_USB) {
        if (virHostdevUpdateActiveUSBDevices(mgr,
                                             def->hostdevs,
                                             def->nhostdevs,
                                             driver, def->name) < 0)
            return -1;
    }

    if (flags & VIR_HOSTDEV_SP_SCSI) {
        if (virHostdevUpdateActiveSCSIDevices(mgr,
                                              def->hostdevs,
                                              def->nhostdevs,
                                              driver, def->name) < 0)
            return -1;
    }

    return 0;
}


static int
virHostdevGetNVMeDeviceList(virNVMeDeviceList *nvmeDevices,
                            virStorageSource *src,
                            const char *drv_name,
                            const char *dom_name)
{
    virStorageSource *n;

    for (n = src; virStorageSourceIsBacking(n); n = n->backingStore) {
        g_autoptr(virNVMeDevice) dev = NULL;
        const virStorageSourceNVMeDef *srcNVMe = n->nvme;

        if (n->type != VIR_STORAGE_TYPE_NVME)
            continue;

        if (!(dev = virNVMeDeviceNew(&srcNVMe->pciAddr,
                                     srcNVMe->namespc,
                                     srcNVMe->managed)))
            return -1;

        virNVMeDeviceUsedBySet(dev, drv_name, dom_name);

        if (virNVMeDeviceListAdd(nvmeDevices, dev) < 0)
            return -1;
    }

    return 0;
}


int
virHostdevPrepareOneNVMeDevice(virHostdevManager *hostdev_mgr,
                               const char *drv_name,
                               const char *dom_name,
                               virStorageSource *src)
{
    g_autoptr(virNVMeDeviceList) nvmeDevices = NULL;
    g_autoptr(virPCIDeviceList) pciDevices = NULL;
    const unsigned int pciFlags = 0;
    virNVMeDevice *temp = NULL;
    size_t i;
    ssize_t lastGoodNVMeIdx = -1;
    int ret = -1;

    if (!(nvmeDevices = virNVMeDeviceListNew()))
        return -1;

    if (virHostdevGetNVMeDeviceList(nvmeDevices, src, drv_name, dom_name) < 0)
        return -1;

    if (virNVMeDeviceListCount(nvmeDevices) == 0)
        return 0;

    virObjectLock(hostdev_mgr->activeNVMeHostdevs);

    /* Firstly, let's check if all devices are free */
    for (i = 0; i < virNVMeDeviceListCount(nvmeDevices); i++) {
        const virNVMeDevice *dev = virNVMeDeviceListGet(nvmeDevices, i);
        const virPCIDeviceAddress *addr = NULL;
        g_autofree char *addrStr = NULL;
        const char *actual_drvname = NULL;
        const char *actual_domname = NULL;

        temp = virNVMeDeviceListLookup(hostdev_mgr->activeNVMeHostdevs, dev);

        /* Not on the list means not used */
        if (!temp)
            continue;

        virNVMeDeviceUsedByGet(temp, &actual_drvname, &actual_domname);
        addr = virNVMeDeviceAddressGet(dev);
        addrStr = virPCIDeviceAddressAsString(addr);

        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("NVMe device %1$s already in use by driver %2$s domain %3$s"),
                       NULLSTR(addrStr), actual_drvname, actual_domname);
        goto cleanup;
    }

    if (!(pciDevices = virNVMeDeviceListCreateDetachList(hostdev_mgr->activeNVMeHostdevs,
                                                         nvmeDevices)))
        goto cleanup;

    /* Let's check if all PCI devices are NVMe disks. */
    for (i = 0; i < virPCIDeviceListCount(pciDevices); i++) {
        virPCIDevice *pci = virPCIDeviceListGet(pciDevices, i);
        g_autofree char *drvName = NULL;
        virPCIStubDriver drvType;

        if (virPCIDeviceGetCurrentDriverNameAndType(pci, &drvName, &drvType) < 0)
            goto cleanup;

        if (drvType == VIR_PCI_STUB_DRIVER_VFIO || STREQ_NULLABLE(drvName, "nvme"))
            continue;

        VIR_WARN("Suspicious NVMe disk assignment. PCI device "
                 "%s is not an NVMe disk, it has %s driver",
                 virPCIDeviceGetName(pci), NULLSTR(drvName));
    }

    /* This looks like a good opportunity to merge inactive NVMe devices onto
     * the active list. This, however, means that if something goes wrong we
     * have to perform a rollback before returning. */
    for (i = 0; i < virNVMeDeviceListCount(nvmeDevices); i++) {
        temp = virNVMeDeviceListGet(nvmeDevices, i);

        if (virNVMeDeviceListAdd(hostdev_mgr->activeNVMeHostdevs, temp) < 0)
            goto rollback;

        lastGoodNVMeIdx = i;
    }

    if (virHostdevPreparePCIDevicesImpl(hostdev_mgr,
                                        drv_name, dom_name, NULL,
                                        pciDevices, NULL, 0, pciFlags) < 0)
        goto rollback;

    ret = 0;
 cleanup:
    virObjectUnlock(hostdev_mgr->activeNVMeHostdevs);
    return ret;

 rollback:
    while (lastGoodNVMeIdx >= 0) {
        temp = virNVMeDeviceListGet(nvmeDevices, lastGoodNVMeIdx);

        virNVMeDeviceListDel(hostdev_mgr->activeNVMeHostdevs, temp);

        lastGoodNVMeIdx--;
    }
    goto cleanup;
}


int
virHostdevPrepareNVMeDevices(virHostdevManager *hostdev_mgr,
                             const char *drv_name,
                             const char *dom_name,
                             virDomainDiskDef **disks,
                             size_t ndisks)
{
    size_t i;
    ssize_t lastGoodDiskIdx = -1;

    for (i = 0; i < ndisks; i++) {
        if (virHostdevPrepareOneNVMeDevice(hostdev_mgr, drv_name,
                                           dom_name, disks[i]->src) < 0)
            goto rollback;

        lastGoodDiskIdx = i;
    }

    return 0;

 rollback:
    while (lastGoodDiskIdx >= 0) {
        if (virHostdevReAttachOneNVMeDevice(hostdev_mgr, drv_name, dom_name,
                                            disks[lastGoodDiskIdx]->src) < 0) {
            VIR_ERROR(_("Failed to reattach NVMe for disk target: %1$s"),
                      disks[lastGoodDiskIdx]->dst);
        }

        lastGoodDiskIdx--;
    }

    return -1;
}


int
virHostdevReAttachOneNVMeDevice(virHostdevManager *hostdev_mgr,
                                const char *drv_name,
                                const char *dom_name,
                                virStorageSource *src)
{
    g_autoptr(virNVMeDeviceList) nvmeDevices = NULL;
    g_autoptr(virPCIDeviceList) pciDevices = NULL;
    size_t i;
    int ret = -1;

    if (!(nvmeDevices = virNVMeDeviceListNew()))
        return -1;

    if (virHostdevGetNVMeDeviceList(nvmeDevices, src, drv_name, dom_name) < 0)
        return -1;

    if (virNVMeDeviceListCount(nvmeDevices) == 0)
        return 0;

    virObjectLock(hostdev_mgr->activeNVMeHostdevs);

    if (!(pciDevices = virNVMeDeviceListCreateReAttachList(hostdev_mgr->activeNVMeHostdevs,
                                                           nvmeDevices)))
        goto cleanup;

    virHostdevReAttachPCIDevicesImpl(hostdev_mgr,
                                     drv_name, dom_name, pciDevices, NULL, 0);

    for (i = 0; i < virNVMeDeviceListCount(nvmeDevices); i++) {
        virNVMeDevice *temp = virNVMeDeviceListGet(nvmeDevices, i);

        if (virNVMeDeviceListDel(hostdev_mgr->activeNVMeHostdevs, temp) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnlock(hostdev_mgr->activeNVMeHostdevs);
    return ret;
}


int
virHostdevReAttachNVMeDevices(virHostdevManager *hostdev_mgr,
                              const char *drv_name,
                              const char *dom_name,
                              virDomainDiskDef **disks,
                              size_t ndisks)
{
    size_t i;
    int ret = 0;

    /* Contrary to virHostdevPrepareNVMeDevices, this is a best
     * effort approach. Just iterate over all disks and try to
     * reattach them. Don't stop at the first failure. */
    for (i = 0; i < ndisks; i++) {
        if (virHostdevReAttachOneNVMeDevice(hostdev_mgr, drv_name,
                                            dom_name, disks[i]->src) < 0) {
            VIR_ERROR(_("Failed to reattach NVMe for disk target: %1$s"),
                      disks[i]->dst);
            ret = -1;
        }
    }

    return ret;
}


int
virHostdevUpdateActiveNVMeDevices(virHostdevManager *hostdev_mgr,
                                  const char *drv_name,
                                  const char *dom_name,
                                  virDomainDiskDef **disks,
                                  size_t ndisks)
{
    g_autoptr(virNVMeDeviceList) nvmeDevices = NULL;
    g_autoptr(virPCIDeviceList) pciDevices = NULL;
    virNVMeDevice *temp = NULL;
    size_t i;
    ssize_t lastGoodNVMeIdx = -1;
    ssize_t lastGoodPCIIdx = -1;
    int ret = -1;

    if (!(nvmeDevices = virNVMeDeviceListNew()))
        return -1;

    for (i = 0; i < ndisks; i++) {
        if (virHostdevGetNVMeDeviceList(nvmeDevices, disks[i]->src, drv_name, dom_name) < 0)
            return -1;
    }

    if (virNVMeDeviceListCount(nvmeDevices) == 0)
        return 0;

    virObjectLock(hostdev_mgr->activeNVMeHostdevs);
    virObjectLock(hostdev_mgr->activePCIHostdevs);
    virObjectLock(hostdev_mgr->inactivePCIHostdevs);

    if (!(pciDevices = virNVMeDeviceListCreateDetachList(hostdev_mgr->activeNVMeHostdevs,
                                                         nvmeDevices)))
        goto cleanup;

    for (i = 0; i < virNVMeDeviceListCount(nvmeDevices); i++) {
        temp = virNVMeDeviceListGet(nvmeDevices, i);

        if (virNVMeDeviceListAdd(hostdev_mgr->activeNVMeHostdevs, temp) < 0)
            goto rollback;

        lastGoodNVMeIdx = i;
    }

    for (i = 0; i < virPCIDeviceListCount(pciDevices); i++) {
        virPCIDevice *actual = virPCIDeviceListGet(pciDevices, i);

        /* We must restore some attributes that were lost on daemon restart. */
        virPCIDeviceSetUnbindFromStub(actual, true);
        if (virPCIDeviceSetUsedBy(actual, drv_name, dom_name) < 0)
            goto rollback;

        if (virPCIDeviceListAddCopy(hostdev_mgr->activePCIHostdevs, actual) < 0)
            goto rollback;

        lastGoodPCIIdx = i;
    }

    ret = 0;
 cleanup:
    virObjectUnlock(hostdev_mgr->inactivePCIHostdevs);
    virObjectUnlock(hostdev_mgr->activePCIHostdevs);
    virObjectUnlock(hostdev_mgr->activeNVMeHostdevs);
    return ret;

 rollback:
    while (lastGoodNVMeIdx >= 0) {
        temp = virNVMeDeviceListGet(nvmeDevices, lastGoodNVMeIdx);

        virNVMeDeviceListDel(hostdev_mgr->activeNVMeHostdevs, temp);

        lastGoodNVMeIdx--;
    }
    while (lastGoodPCIIdx >= 0) {
        virPCIDevice *actual = virPCIDeviceListGet(pciDevices, i);

        virPCIDeviceListDel(hostdev_mgr->activePCIHostdevs,
                            virPCIDeviceGetAddress(actual));

        lastGoodPCIIdx--;
    }
    goto cleanup;
}
