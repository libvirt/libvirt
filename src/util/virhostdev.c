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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 * Author: Chunyan Liu <cyliu@suse.com>
 */

#include <config.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "virhostdev.h"
#include "viralloc.h"
#include "virstring.h"
#include "virfile.h"
#include "virerror.h"
#include "virlog.h"
#include "virutil.h"
#include "virnetdev.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.hostdev");

#define HOSTDEV_STATE_DIR LOCALSTATEDIR "/run/libvirt/hostdevmgr"

static virHostdevManagerPtr manager; /* global hostdev manager, never freed */

static virClassPtr virHostdevManagerClass;
static void virHostdevManagerDispose(void *obj);
static virHostdevManagerPtr virHostdevManagerNew(void);

struct virHostdevIsPCINodeDeviceUsedData {
    virHostdevManagerPtr mgr;
    const char *domainName;
    const bool usesVFIO;
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

static int virHostdevIsPCINodeDeviceUsed(virPCIDeviceAddressPtr devAddr, void *opaque)
{
    virPCIDevicePtr actual;
    int ret = -1;
    struct virHostdevIsPCINodeDeviceUsedData *helperData = opaque;

    actual = virPCIDeviceListFindByIDs(helperData->mgr->activePCIHostdevs,
                                       devAddr->domain, devAddr->bus,
                                       devAddr->slot, devAddr->function);
    if (actual) {
        const char *actual_drvname = NULL;
        const char *actual_domname = NULL;
        virPCIDeviceGetUsedBy(actual, &actual_drvname, &actual_domname);

        if (helperData->usesVFIO &&
            (actual_domname && helperData->domainName) &&
            (STREQ(actual_domname, helperData->domainName)))
            goto iommu_owner;

        if (actual_drvname && actual_domname)
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("PCI device %s is in use by "
                             "driver %s, domain %s"),
                           virPCIDeviceGetName(actual),
                           actual_drvname, actual_domname);
        else
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("PCI device %s is in use"),
                           virPCIDeviceGetName(actual));
        goto cleanup;
    }
 iommu_owner:
    ret = 0;
 cleanup:
    return ret;
}

static int virHostdevManagerOnceInit(void)
{
    if (!(virHostdevManagerClass = virClassNew(virClassForObject(),
                                               "virHostdevManager",
                                               sizeof(virHostdevManager),
                                               virHostdevManagerDispose)))
        return -1;

    if (!(manager = virHostdevManagerNew()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virHostdevManager)

static void
virHostdevManagerDispose(void *obj)
{
    virHostdevManagerPtr hostdevMgr = obj;

    if (!hostdevMgr)
        return;

    virObjectUnref(hostdevMgr->activePCIHostdevs);
    virObjectUnref(hostdevMgr->inactivePCIHostdevs);
    virObjectUnref(hostdevMgr->activeUSBHostdevs);
    virObjectUnref(hostdevMgr->activeSCSIHostdevs);
    virObjectUnref(hostdevMgr->activeSCSIVHostHostdevs);
    virObjectUnref(hostdevMgr->activeMediatedHostdevs);
    VIR_FREE(hostdevMgr->stateDir);
}

static virHostdevManagerPtr
virHostdevManagerNew(void)
{
    virHostdevManagerPtr hostdevMgr;
    bool privileged = geteuid() == 0;

    if (!(hostdevMgr = virObjectNew(virHostdevManagerClass)))
        return NULL;

    if (!(hostdevMgr->activePCIHostdevs = virPCIDeviceListNew()))
        goto error;

    if (!(hostdevMgr->activeUSBHostdevs = virUSBDeviceListNew()))
        goto error;

    if (!(hostdevMgr->inactivePCIHostdevs = virPCIDeviceListNew()))
        goto error;

    if (!(hostdevMgr->activeSCSIHostdevs = virSCSIDeviceListNew()))
        goto error;

    if (!(hostdevMgr->activeSCSIVHostHostdevs = virSCSIVHostDeviceListNew()))
        goto error;

    if (!(hostdevMgr->activeMediatedHostdevs = virMediatedDeviceListNew()))
        goto error;

    if (privileged) {
        if (VIR_STRDUP(hostdevMgr->stateDir, HOSTDEV_STATE_DIR) < 0)
            goto error;

        if (virFileMakePath(hostdevMgr->stateDir) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Failed to create state dir '%s'"),
                           hostdevMgr->stateDir);
            goto error;
        }
    } else {
        char *rundir = NULL;
        mode_t old_umask;

        if (!(rundir = virGetUserRuntimeDirectory()))
            goto error;

        if (virAsprintf(&hostdevMgr->stateDir, "%s/hostdevmgr", rundir) < 0) {
            VIR_FREE(rundir);
            goto error;
        }
        VIR_FREE(rundir);

        old_umask = umask(077);

        if (virFileMakePath(hostdevMgr->stateDir) < 0) {
            umask(old_umask);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Failed to create state dir '%s'"),
                           hostdevMgr->stateDir);
            goto error;
        }
        umask(old_umask);
    }

    return hostdevMgr;

 error:
    virObjectUnref(hostdevMgr);
    return NULL;
}

virHostdevManagerPtr
virHostdevManagerGetDefault(void)
{
    if (virHostdevManagerInitialize() < 0)
        return NULL;

    return virObjectRef(manager);
}

static virPCIDeviceListPtr
virHostdevGetPCIHostDeviceList(virDomainHostdevDefPtr *hostdevs, int nhostdevs)
{
    virPCIDeviceListPtr pcidevs;
    size_t i;

    if (!(pcidevs = virPCIDeviceListNew()))
        return NULL;

    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virDomainHostdevSubsysPCIPtr pcisrc = &hostdev->source.subsys.u.pci;
        virPCIDevicePtr pci;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        pci = virPCIDeviceNew(pcisrc->addr.domain, pcisrc->addr.bus,
                              pcisrc->addr.slot, pcisrc->addr.function);
        if (!pci) {
            virObjectUnref(pcidevs);
            return NULL;
        }
        if (virPCIDeviceListAdd(pcidevs, pci) < 0) {
            virPCIDeviceFree(pci);
            virObjectUnref(pcidevs);
            return NULL;
        }

        virPCIDeviceSetManaged(pci, hostdev->managed);

        if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO)
            virPCIDeviceSetStubDriver(pci, VIR_PCI_STUB_DRIVER_VFIO);
        else if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN)
            virPCIDeviceSetStubDriver(pci, VIR_PCI_STUB_DRIVER_XEN);
        else
            virPCIDeviceSetStubDriver(pci, VIR_PCI_STUB_DRIVER_KVM);
    }

    return pcidevs;
}


static int
virHostdevPCISysfsPath(virDomainHostdevDefPtr hostdev,
                       char **sysfs_path)
{
    virPCIDeviceAddress config_address;

    config_address.domain = hostdev->source.subsys.u.pci.addr.domain;
    config_address.bus = hostdev->source.subsys.u.pci.addr.bus;
    config_address.slot = hostdev->source.subsys.u.pci.addr.slot;
    config_address.function = hostdev->source.subsys.u.pci.addr.function;

    return virPCIDeviceAddressGetSysfsFile(&config_address, sysfs_path);
}


static int
virHostdevIsVirtualFunction(virDomainHostdevDefPtr hostdev)
{
    char *sysfs_path = NULL;
    int ret = -1;

    if (virHostdevPCISysfsPath(hostdev, &sysfs_path) < 0)
        return ret;

    ret = virPCIIsVirtualFunction(sysfs_path);

    VIR_FREE(sysfs_path);

    return ret;
}


static int
virHostdevNetDevice(virDomainHostdevDefPtr hostdev, char **linkdev,
                    int *vf)
{
    int ret = -1;
    char *sysfs_path = NULL;

    if (virHostdevPCISysfsPath(hostdev, &sysfs_path) < 0)
        return ret;

    if (virPCIIsVirtualFunction(sysfs_path) == 1) {
        if (virPCIGetVirtualFunctionInfo(sysfs_path, linkdev,
                                         vf) < 0)
            goto cleanup;
    } else {
        /* In practice this should never happen, since we currently
         * only support assigning SRIOV VFs via <interface
         * type='hostdev'>, and it is only those devices that should
         * end up calling this function.
         */
        if (virPCIGetNetName(sysfs_path, linkdev) < 0)
            goto cleanup;

        if (!linkdev) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("The device at %s has no network device name"),
                             sysfs_path);
            goto cleanup;
        }

        *vf = -1;
    }

    ret = 0;

 cleanup:
    VIR_FREE(sysfs_path);

    return ret;
}


static bool
virHostdevIsPCINetDevice(virDomainHostdevDefPtr hostdev)
{
    return hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
        hostdev->parent.type == VIR_DOMAIN_DEVICE_NET &&
        hostdev->parent.data.net;
}


/**
 * virHostdevIsSCSIDevice:
 * @hostdev: host device to check
 *
 * Returns true if @hostdev is a SCSI device, false otherwise.
 */
bool
virHostdevIsSCSIDevice(virDomainHostdevDefPtr hostdev)
{
    return hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI;
}


static int
virHostdevNetConfigVirtPortProfile(const char *linkdev, int vf,
                                   virNetDevVPortProfilePtr virtPort,
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
                       _("virtualport type %s is "
                         "currently not supported on interfaces of type "
                         "hostdev"),
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
virHostdevSaveNetConfig(virDomainHostdevDefPtr hostdev,
                        const char *stateDir)
{
    int ret = -1;
    char *linkdev = NULL;
    int vf = -1;

    if (!virHostdevIsPCINetDevice(hostdev) ||
        virDomainNetGetActualVirtPortProfile(hostdev->parent.data.net))
       return 0;

    if (virHostdevIsVirtualFunction(hostdev) != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Interface type hostdev is currently supported on"
                         " SR-IOV Virtual Functions only"));
        goto cleanup;
    }

    if (virHostdevNetDevice(hostdev, &linkdev, &vf) < 0)
        goto cleanup;

    if (virNetDevSaveNetConfig(linkdev, vf, stateDir, true) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(linkdev);
    return ret;
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
virHostdevSetNetConfig(virDomainHostdevDefPtr hostdev,
                       const unsigned char *uuid)
{
    char *linkdev = NULL;
    virNetDevVlanPtr vlan;
    virNetDevVPortProfilePtr virtPort;
    int ret = -1;
    int vf = -1;
    bool port_profile_associate = true;

    if (!virHostdevIsPCINetDevice(hostdev))
        return 0;

    if (virHostdevNetDevice(hostdev, &linkdev, &vf) < 0)
        goto cleanup;

    vlan = virDomainNetGetActualVlan(hostdev->parent.data.net);
    virtPort = virDomainNetGetActualVirtPortProfile(hostdev->parent.data.net);
    if (virtPort) {
        if (vlan) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("direct setting of the vlan tag is not allowed "
                             "for hostdev devices using %s mode"),
                           virNetDevVPortTypeToString(virtPort->virtPortType));
            goto cleanup;
        }
        if (virHostdevNetConfigVirtPortProfile(linkdev, vf, virtPort,
                                               &hostdev->parent.data.net->mac,
                                               uuid, port_profile_associate) < 0) {
            goto cleanup;
        }
    } else {
        if (virNetDevSetNetConfig(linkdev, vf, &hostdev->parent.data.net->mac,
                                  vlan, NULL, true) < 0) {
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(linkdev);
    return ret;
}


/* @oldStateDir:
 * For upgrade purpose:
 * To an existing VM on QEMU, the hostdev netconfig file is originally stored
 * in cfg->stateDir (/var/run/libvirt/qemu). Switch to new version, it uses new
 * location (mgr->stateDir) but certainly will not find it. In this
 * case, try to find in the old state dir.
 */
static int
virHostdevRestoreNetConfig(virDomainHostdevDefPtr hostdev,
                           const char *stateDir,
                           const char *oldStateDir)
{
    char *linkdev = NULL;
    virNetDevVPortProfilePtr virtPort;
    int ret = -1;
    int vf = -1;
    bool port_profile_associate = false;

    /* This is only needed for PCI devices that have been defined
     * using <interface type='hostdev'>. For all others, it is a NOP.
     */
    if (!virHostdevIsPCINetDevice(hostdev))
       return 0;

    if (virHostdevIsVirtualFunction(hostdev) != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Interface type hostdev is currently supported on"
                         " SR-IOV Virtual Functions only"));
        return ret;
    }

    if (virHostdevNetDevice(hostdev, &linkdev, &vf) < 0)
        return ret;

    virtPort = virDomainNetGetActualVirtPortProfile(
                                 hostdev->parent.data.net);
    if (virtPort) {
        ret = virHostdevNetConfigVirtPortProfile(linkdev, vf, virtPort,
                                                 &hostdev->parent.data.net->mac,
                                                 NULL,
                                                 port_profile_associate);
    } else {
        virMacAddrPtr MAC = NULL;
        virMacAddrPtr adminMAC = NULL;
        virNetDevVlanPtr vlan = NULL;

        ret = virNetDevReadNetConfig(linkdev, vf, stateDir, &adminMAC, &vlan, &MAC);
        if (ret < 0 && oldStateDir)
            ret = virNetDevReadNetConfig(linkdev, vf, oldStateDir,
                                         &adminMAC, &vlan, &MAC);

        if (ret == 0) {
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
                adminMAC = MAC;
                MAC = NULL;
            }

            ignore_value(virNetDevSetNetConfig(linkdev, vf,
                                               adminMAC, vlan, MAC, true));
        }

        VIR_FREE(MAC);
        VIR_FREE(adminMAC);
        virNetDevVlanFree(vlan);
    }

    VIR_FREE(linkdev);

    return ret;
}

int
virHostdevPreparePCIDevices(virHostdevManagerPtr mgr,
                            const char *drv_name,
                            const char *dom_name,
                            const unsigned char *uuid,
                            virDomainHostdevDefPtr *hostdevs,
                            int nhostdevs,
                            unsigned int flags)
{
    virPCIDeviceListPtr pcidevs = NULL;
    int last_processed_hostdev_vf = -1;
    size_t i;
    int ret = -1;
    virPCIDeviceAddressPtr devAddr = NULL;

    if (!nhostdevs)
        return 0;

    virObjectLock(mgr->activePCIHostdevs);
    virObjectLock(mgr->inactivePCIHostdevs);

    if (!(pcidevs = virHostdevGetPCIHostDeviceList(hostdevs, nhostdevs)))
        goto cleanup;

    /* Detaching devices from the host involves several steps; each
     * of them is described at length below.
     *
     * All devices must be detached before we reset any of them,
     * because in some cases you have to reset the whole PCI, which
     * impacts all devices on it. Also, all devices must be reset
     * before being marked as active */

    /* Step 1: Perform some initial checks on the devices */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr pci = virPCIDeviceListGet(pcidevs, i);
        bool strict_acs_check = !!(flags & VIR_HOSTDEV_STRICT_ACS_CHECK);
        bool usesVFIO = (virPCIDeviceGetStubDriver(pci) == VIR_PCI_STUB_DRIVER_VFIO);
        struct virHostdevIsPCINodeDeviceUsedData data = { mgr, dom_name, usesVFIO };
        int hdrType = -1;

        if (virPCIGetHeaderType(pci, &hdrType) < 0)
            goto cleanup;

        if (hdrType != VIR_PCI_HEADER_ENDPOINT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Non-endpoint PCI devices cannot be assigned "
                             "to guests"));
            goto cleanup;
        }

        if (!usesVFIO && !virPCIDeviceIsAssignable(pci, strict_acs_check)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("PCI device %s is not assignable"),
                           virPCIDeviceGetName(pci));
            goto cleanup;
        }

        /* The device is in use by other active domain if
         * the dev is in list activePCIHostdevs. VFIO devices
         * belonging to same iommu group can't be shared
         * across guests.
         */
        devAddr = virPCIDeviceGetAddress(pci);
        if (usesVFIO) {
            if (virPCIDeviceAddressIOMMUGroupIterate(devAddr,
                                                     virHostdevIsPCINodeDeviceUsed,
                                                     &data) < 0)
                goto cleanup;
        } else if (virHostdevIsPCINodeDeviceUsed(devAddr, &data)) {
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
        virPCIDevicePtr pci = virPCIDeviceListGet(pcidevs, i);

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
            char *driverPath;
            char *driverName;
            int stub;

            /* Unmanaged devices should already have been marked as
             * inactive: if that's the case, we can simply move on */
            if (virPCIDeviceListFind(mgr->inactivePCIHostdevs, pci)) {
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

            if (virPCIDeviceGetDriverPathAndName(pci,
                                                 &driverPath, &driverName) < 0)
                goto reattachdevs;

            stub = virPCIStubDriverTypeFromString(driverName);

            VIR_FREE(driverPath);
            VIR_FREE(driverName);

            if (stub > VIR_PCI_STUB_DRIVER_NONE &&
                stub < VIR_PCI_STUB_DRIVER_LAST) {

                /* The device is bound to a known stub driver: store this
                 * information and add a copy to the inactive list */
                virPCIDeviceSetStubDriver(pci, stub);

                VIR_DEBUG("Adding PCI device %s to inactive list",
                          virPCIDeviceGetName(pci));
                if (virPCIDeviceListAddCopy(mgr->inactivePCIHostdevs, pci) < 0)
                    goto reattachdevs;
            } else {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("Unmanaged PCI device %s must be manually "
                               "detached from the host"),
                               virPCIDeviceGetName(pci));
                goto reattachdevs;
            }
        }
    }

    /* At this point, all devices are attached to the stub driver and have
     * been marked as inactive */

    /* Step 3: Now that all the PCI hostdevs have been detached, we
     * can safely reset them */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr pci = virPCIDeviceListGet(pcidevs, i);

        /* We can avoid looking up the actual device here, because performing
         * a PCI reset on a device doesn't require any information other than
         * the address, which 'pci' already contains */
        VIR_DEBUG("Resetting PCI device %s", virPCIDeviceGetName(pci));
        if (virPCIDeviceReset(pci, mgr->activePCIHostdevs,
                              mgr->inactivePCIHostdevs) < 0)
            goto reattachdevs;
    }

    /* Step 4: For SRIOV network devices, Now that we have detached the
     * the network device, set the new netdev config */
    for (i = 0; i < nhostdevs; i++) {

        if (virHostdevSetNetConfig(hostdevs[i], uuid) < 0)
            goto resetvfnetconfig;

        last_processed_hostdev_vf = i;
    }

    /* Step 5: Move devices from the inactive list to the active list */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr pci = virPCIDeviceListGet(pcidevs, i);
        virPCIDevicePtr actual;

        VIR_DEBUG("Removing PCI device %s from inactive list",
                  virPCIDeviceGetName(pci));
        actual = virPCIDeviceListSteal(mgr->inactivePCIHostdevs, pci);

        VIR_DEBUG("Adding PCI device %s to active list",
                  virPCIDeviceGetName(pci));
        if (!actual || virPCIDeviceListAdd(mgr->activePCIHostdevs, actual) < 0)
            goto inactivedevs;
    }

    /* Step 6: Set driver and domain information */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr pci, actual;

        /* We need to look up the actual device and set the information
         * there because 'pci' only contain address information and will
         * be released at the end of the function */
        pci = virPCIDeviceListGet(pcidevs, i);
        actual = virPCIDeviceListFind(mgr->activePCIHostdevs, pci);

        VIR_DEBUG("Setting driver and domain information for PCI device %s",
                  virPCIDeviceGetName(pci));
        if (actual)
            virPCIDeviceSetUsedBy(actual, drv_name, dom_name);
    }

    /* Step 7: Now set the original states for hostdev def */
    for (i = 0; i < nhostdevs; i++) {
        virPCIDevicePtr actual;
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virDomainHostdevSubsysPCIPtr pcisrc = &hostdev->source.subsys.u.pci;

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
            hostdev->origstates.states.pci.unbind_from_stub =
                virPCIDeviceGetUnbindFromStub(actual);
            hostdev->origstates.states.pci.remove_slot =
                virPCIDeviceGetRemoveSlot(actual);
            hostdev->origstates.states.pci.reprobe =
                virPCIDeviceGetReprobe(actual);
        }
    }

    ret = 0;
    goto cleanup;

 inactivedevs:
    /* Move devices back to the inactive list so that they can be
     * processed properly below (reattachdevs label) */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr pci = virPCIDeviceListGet(pcidevs, i);
        virPCIDevicePtr actual;

        VIR_DEBUG("Removing PCI device %s from active list",
                  virPCIDeviceGetName(pci));
        if (!(actual = virPCIDeviceListSteal(mgr->activePCIHostdevs, pci)))
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
            virHostdevRestoreNetConfig(hostdevs[i], mgr->stateDir, NULL);
    }

 reattachdevs:
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr pci = virPCIDeviceListGet(pcidevs, i);
        virPCIDevicePtr actual;

        /* We need to look up the actual device because that's what
         * virPCIDeviceReattach() expects as its argument */
        if (!(actual = virPCIDeviceListFind(mgr->inactivePCIHostdevs, pci)))
            continue;

        if (virPCIDeviceGetManaged(actual)) {
            VIR_DEBUG("Reattaching managed PCI device %s",
                      virPCIDeviceGetName(pci));
            ignore_value(virPCIDeviceReattach(actual,
                                              mgr->activePCIHostdevs,
                                              mgr->inactivePCIHostdevs));
        } else {
            VIR_DEBUG("Not reattaching unmanaged PCI device %s",
                      virPCIDeviceGetName(pci));
        }
    }

 cleanup:
    virObjectUnref(pcidevs);
    virObjectUnlock(mgr->activePCIHostdevs);
    virObjectUnlock(mgr->inactivePCIHostdevs);

    return ret;
}

/*
 * Pre-condition: inactivePCIHostdevs & activePCIHostdevs
 * are locked
 */
static void
virHostdevReattachPCIDevice(virHostdevManagerPtr mgr,
                            virPCIDevicePtr actual)
{
    /* Wait for device cleanup if it is qemu/kvm */
    if (virPCIDeviceGetStubDriver(actual) == VIR_PCI_STUB_DRIVER_KVM) {
        int retries = 100;
        while (virPCIDeviceWaitForCleanup(actual, "kvm_assigned_device")
               && retries) {
            usleep(100*1000);
            retries--;
        }
    }

    VIR_DEBUG("Reattaching PCI device %s", virPCIDeviceGetName(actual));
    if (virPCIDeviceReattach(actual, mgr->activePCIHostdevs,
                             mgr->inactivePCIHostdevs) < 0) {
        VIR_ERROR(_("Failed to re-attach PCI device: %s"),
                  virGetLastErrorMessage());
        virResetLastError();
    }
}

/* @oldStateDir:
 * For upgrade purpose: see virHostdevRestoreNetConfig
 */
void
virHostdevReAttachPCIDevices(virHostdevManagerPtr mgr,
                             const char *drv_name,
                             const char *dom_name,
                             virDomainHostdevDefPtr *hostdevs,
                             int nhostdevs,
                             const char *oldStateDir)
{
    virPCIDeviceListPtr pcidevs;
    size_t i;

    if (!nhostdevs)
        return;

    virObjectLock(mgr->activePCIHostdevs);
    virObjectLock(mgr->inactivePCIHostdevs);

    if (!(pcidevs = virHostdevGetPCIHostDeviceList(hostdevs, nhostdevs))) {
        VIR_ERROR(_("Failed to allocate PCI device list: %s"),
                  virGetLastErrorMessage());
        virResetLastError();
        goto cleanup;
    }

    /* Reattaching devices to the host involves several steps; each
     * of them is described at length below */

    /* Step 1: Filter out all devices that are either not active or not
     *         used by the current domain and driver */
    i = 0;
    while (i < virPCIDeviceListCount(pcidevs)) {
        virPCIDevicePtr pci = virPCIDeviceListGet(pcidevs, i);
        virPCIDevicePtr actual = NULL;

        /* We need to look up the actual device, which is the one containing
         * information such as by which domain and driver it is used. As a
         * side effect, by looking it up we can also tell whether it was
         * really active in the first place */
        actual = virPCIDeviceListFind(mgr->activePCIHostdevs, pci);
        if (actual) {
            const char *actual_drvname;
            const char *actual_domname;
            virPCIDeviceGetUsedBy(actual, &actual_drvname, &actual_domname);
            if (STRNEQ_NULLABLE(drv_name, actual_drvname) ||
                STRNEQ_NULLABLE(dom_name, actual_domname)) {

                virPCIDeviceListDel(pcidevs, pci);
                continue;
            }
        } else {
            virPCIDeviceListDel(pcidevs, pci);
            continue;
        }

        i++;
    }

    /* Step 2: Move devices from the active list to the inactive list */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr pci = virPCIDeviceListGet(pcidevs, i);
        virPCIDevicePtr actual;

        VIR_DEBUG("Removing PCI device %s from active list",
                  virPCIDeviceGetName(pci));
        actual = virPCIDeviceListSteal(mgr->activePCIHostdevs, pci);

        VIR_DEBUG("Adding PCI device %s to inactive list",
                  virPCIDeviceGetName(pci));
        if (!actual ||
            virPCIDeviceListAdd(mgr->inactivePCIHostdevs, actual) < 0) {

            VIR_ERROR(_("Failed to add PCI device %s to the inactive list"),
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
        virDomainHostdevDefPtr hostdev = hostdevs[i];

        if (virHostdevIsPCINetDevice(hostdev)) {
            virDomainHostdevSubsysPCIPtr pcisrc = &hostdev->source.subsys.u.pci;
            virPCIDevicePtr actual;

            actual = virPCIDeviceListFindByIDs(mgr->inactivePCIHostdevs,
                                               pcisrc->addr.domain,
                                               pcisrc->addr.bus,
                                               pcisrc->addr.slot,
                                               pcisrc->addr.function);

            if (actual) {
                VIR_DEBUG("Restoring network configuration of PCI device %s",
                          virPCIDeviceGetName(actual));
                virHostdevRestoreNetConfig(hostdev, mgr->stateDir,
                                           oldStateDir);
            }
        }
    }

    /* Step 4: perform a PCI Reset on all devices */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr pci = virPCIDeviceListGet(pcidevs, i);

        /* We can avoid looking up the actual device here, because performing
         * a PCI reset on a device doesn't require any information other than
         * the address, which 'pci' already contains */
        VIR_DEBUG("Resetting PCI device %s", virPCIDeviceGetName(pci));
        if (virPCIDeviceReset(pci, mgr->activePCIHostdevs,
                              mgr->inactivePCIHostdevs) < 0) {
            VIR_ERROR(_("Failed to reset PCI device: %s"),
                      virGetLastErrorMessage());
            virResetLastError();
        }
    }

    /* Step 5: Reattach managed devices to their host drivers; unmanaged
     *         devices don't need to be processed further */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr pci = virPCIDeviceListGet(pcidevs, i);
        virPCIDevicePtr actual;

        /* We need to look up the actual device because that's what
         * virHostdevReattachPCIDevice() expects as its argument */
        if (!(actual = virPCIDeviceListFind(mgr->inactivePCIHostdevs, pci)))
            continue;

        if (virPCIDeviceGetManaged(actual))
            virHostdevReattachPCIDevice(mgr, actual);
        else
            VIR_DEBUG("Not reattaching unmanaged PCI device %s",
                      virPCIDeviceGetName(actual));
    }

 cleanup:
    virObjectUnref(pcidevs);
    virObjectUnlock(mgr->activePCIHostdevs);
    virObjectUnlock(mgr->inactivePCIHostdevs);
}

int
virHostdevUpdateActivePCIDevices(virHostdevManagerPtr mgr,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs,
                                 const char *drv_name,
                                 const char *dom_name)
{
    virDomainHostdevDefPtr hostdev = NULL;
    virPCIDevicePtr actual = NULL;
    size_t i;
    int ret = -1;

    if (!nhostdevs)
        return 0;

    virObjectLock(mgr->activePCIHostdevs);
    virObjectLock(mgr->inactivePCIHostdevs);

    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevSubsysPCIPtr pcisrc;
        hostdev = hostdevs[i];
        pcisrc = &hostdev->source.subsys.u.pci;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        actual = virPCIDeviceNew(pcisrc->addr.domain, pcisrc->addr.bus,
                                 pcisrc->addr.slot, pcisrc->addr.function);

        if (!actual)
            goto cleanup;

        virPCIDeviceSetManaged(actual, hostdev->managed);
        virPCIDeviceSetUsedBy(actual, drv_name, dom_name);

        if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO)
            virPCIDeviceSetStubDriver(actual, VIR_PCI_STUB_DRIVER_VFIO);
        else if (pcisrc->backend == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_XEN)
            virPCIDeviceSetStubDriver(actual, VIR_PCI_STUB_DRIVER_XEN);
        else
            virPCIDeviceSetStubDriver(actual, VIR_PCI_STUB_DRIVER_KVM);

        /* Setup the original states for the PCI device */
        virPCIDeviceSetUnbindFromStub(actual, hostdev->origstates.states.pci.unbind_from_stub);
        virPCIDeviceSetRemoveSlot(actual, hostdev->origstates.states.pci.remove_slot);
        virPCIDeviceSetReprobe(actual, hostdev->origstates.states.pci.reprobe);

        if (virPCIDeviceListAdd(mgr->activePCIHostdevs, actual) < 0)
            goto cleanup;
        actual = NULL;
    }

    ret = 0;
 cleanup:
    virPCIDeviceFree(actual);
    virObjectUnlock(mgr->activePCIHostdevs);
    virObjectUnlock(mgr->inactivePCIHostdevs);
    return ret;
}

int
virHostdevUpdateActiveUSBDevices(virHostdevManagerPtr mgr,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs,
                                 const char *drv_name,
                                 const char *dom_name)
{
    virDomainHostdevDefPtr hostdev = NULL;
    size_t i;
    int ret = -1;

    if (!nhostdevs)
        return 0;

    virObjectLock(mgr->activeUSBHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevSubsysUSBPtr usbsrc;
        virUSBDevicePtr usb = NULL;
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

        if (virUSBDeviceListAdd(mgr->activeUSBHostdevs, usb) < 0) {
            virUSBDeviceFree(usb);
            goto cleanup;
        }
    }
    ret = 0;
 cleanup:
    virObjectUnlock(mgr->activeUSBHostdevs);
    return ret;
}

static int
virHostdevUpdateActiveSCSIHostDevices(virHostdevManagerPtr mgr,
                                      virDomainHostdevDefPtr hostdev,
                                      virDomainHostdevSubsysSCSIPtr scsisrc,
                                      const char *drv_name,
                                      const char *dom_name)
{
    virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;
    virSCSIDevicePtr scsi = NULL;
    virSCSIDevicePtr tmp = NULL;
    int ret = -1;

    if (!(scsi = virSCSIDeviceNew(NULL,
                                  scsihostsrc->adapter, scsihostsrc->bus,
                                  scsihostsrc->target, scsihostsrc->unit,
                                  hostdev->readonly, hostdev->shareable)))
        goto cleanup;

    if ((tmp = virSCSIDeviceListFind(mgr->activeSCSIHostdevs, scsi))) {
        if (virSCSIDeviceSetUsedBy(tmp, drv_name, dom_name) < 0) {
            virSCSIDeviceFree(scsi);
            goto cleanup;
        }
        virSCSIDeviceFree(scsi);
    } else {
        if (virSCSIDeviceSetUsedBy(scsi, drv_name, dom_name) < 0 ||
            virSCSIDeviceListAdd(mgr->activeSCSIHostdevs, scsi) < 0) {
            virSCSIDeviceFree(scsi);
            goto cleanup;
        }
    }
    ret = 0;

 cleanup:
    return ret;
}

int
virHostdevUpdateActiveSCSIDevices(virHostdevManagerPtr mgr,
                                  virDomainHostdevDefPtr *hostdevs,
                                  int nhostdevs,
                                  const char *drv_name,
                                  const char *dom_name)
{
    virDomainHostdevDefPtr hostdev = NULL;
    size_t i;
    int ret = -1;

    if (!nhostdevs)
        return 0;

    virObjectLock(mgr->activeSCSIHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevSubsysSCSIPtr scsisrc;
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
virHostdevUpdateActiveMediatedDevices(virHostdevManagerPtr mgr,
                                      virDomainHostdevDefPtr *hostdevs,
                                      int nhostdevs,
                                      const char *drv_name,
                                      const char *dom_name)
{
    int ret = -1;
    size_t i;
    virMediatedDevicePtr mdev = NULL;

    if (nhostdevs == 0)
        return 0;

    virObjectLock(mgr->activeMediatedHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virDomainHostdevSubsysMediatedDevPtr mdevsrc;

        mdevsrc = &hostdev->source.subsys.u.mdev;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV) {
            continue;
        }

        if (!(mdev = virMediatedDeviceNew(mdevsrc->uuidstr, mdevsrc->model)))
            goto cleanup;

        virMediatedDeviceSetUsedBy(mdev, drv_name, dom_name);

        if (virMediatedDeviceListAdd(mgr->activeMediatedHostdevs, &mdev) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virMediatedDeviceFree(mdev);
    virObjectUnlock(mgr->activeMediatedHostdevs);
    return ret;
}


static int
virHostdevMarkUSBDevices(virHostdevManagerPtr mgr,
                         const char *drv_name,
                         const char *dom_name,
                         virUSBDeviceListPtr list)
{
    size_t i, j;
    unsigned int count;
    virUSBDevicePtr tmp;

    virObjectLock(mgr->activeUSBHostdevs);
    count = virUSBDeviceListCount(list);

    for (i = 0; i < count; i++) {
        virUSBDevicePtr usb = virUSBDeviceListGet(list, i);
        if ((tmp = virUSBDeviceListFind(mgr->activeUSBHostdevs, usb))) {
            const char *other_drvname;
            const char *other_domname;

            virUSBDeviceGetUsedBy(tmp, &other_drvname, &other_domname);
            if (other_drvname && other_domname)
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("USB device %s is in use by "
                                 "driver %s, domain %s"),
                               virUSBDeviceGetName(tmp),
                               other_drvname, other_domname);
            else
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("USB device %s is already in use"),
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
        if (virUSBDeviceListAdd(mgr->activeUSBHostdevs, usb) < 0)
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
virHostdevFindUSBDevice(virDomainHostdevDefPtr hostdev,
                        bool mandatory,
                        virUSBDevicePtr *usb)
{
    virDomainHostdevSubsysUSBPtr usbsrc = &hostdev->source.subsys.u.usb;
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
        virUSBDeviceListPtr devs;

        rc = virUSBDeviceFindByVendor(vendor, product, NULL, mandatory, &devs);
        if (rc < 0)
            return -1;

        if (rc == 1) {
            *usb = virUSBDeviceListGet(devs, 0);
            virUSBDeviceListSteal(devs, *usb);
        }
        virObjectUnref(devs);

        if (rc == 0) {
            goto out;
        } else if (rc > 1) {
            if (autoAddress) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Multiple USB devices for %x:%x were found,"
                                 " but none of them is at bus:%u device:%u"),
                               vendor, product, bus, device);
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Multiple USB devices for %x:%x, "
                                 "use <address> to specify one"),
                               vendor, product);
            }
            return -1;
        }

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
    } else if (!vendor && bus) {
        if (virUSBDeviceFindByBus(bus, device, NULL, mandatory, usb) < 0)
            return -1;
    }

 out:
    if (!*usb)
        hostdev->missing = true;
    return 0;
}

int
virHostdevPrepareUSBDevices(virHostdevManagerPtr mgr,
                            const char *drv_name,
                            const char *dom_name,
                            virDomainHostdevDefPtr *hostdevs,
                            int nhostdevs,
                            unsigned int flags)
{
    size_t i;
    int ret = -1;
    virUSBDeviceListPtr list;
    virUSBDevicePtr tmp;
    bool coldBoot = !!(flags & VIR_HOSTDEV_COLD_BOOT);

    if (!nhostdevs)
        return 0;

    /* To prevent situation where USB device is assigned to two domains
     * we need to keep a list of currently assigned USB devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See virHostdevPreparePCIDevices()
     */
    if (!(list = virUSBDeviceListNew()))
        goto cleanup;

    /* Loop 1: build temporary list
     */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        bool required = true;
        virUSBDevicePtr usb;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        if (hostdev->startupPolicy == VIR_DOMAIN_STARTUP_POLICY_OPTIONAL ||
            (hostdev->startupPolicy == VIR_DOMAIN_STARTUP_POLICY_REQUISITE &&
             !coldBoot))
            required = false;

        if (virHostdevFindUSBDevice(hostdev, required, &usb) < 0)
            goto cleanup;

        if (usb && virUSBDeviceListAdd(list, usb) < 0) {
            virUSBDeviceFree(usb);
            goto cleanup;
        }
    }

    /* Mark devices in temporary list as used by @dom_name
     * and add them do driver list. However, if something goes
     * wrong, perform rollback.
     */
    if (virHostdevMarkUSBDevices(mgr, drv_name, dom_name, list) < 0)
        goto cleanup;

    /* Loop 2: Temporary list was successfully merged with
     * driver list, so steal all items to avoid freeing them
     * in cleanup label.
     */
    while (virUSBDeviceListCount(list) > 0) {
        tmp = virUSBDeviceListGet(list, 0);
        virUSBDeviceListSteal(list, tmp);
    }

    ret = 0;

 cleanup:
    virObjectUnref(list);
    return ret;
}

static int
virHostdevPrepareSCSIHostDevices(virDomainHostdevDefPtr hostdev,
                                 virDomainHostdevSubsysSCSIPtr scsisrc,
                                 virSCSIDeviceListPtr list)
{
    virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;
    virSCSIDevicePtr scsi;
    int ret = -1;

    if (hostdev->managed) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("SCSI host device doesn't support managed mode"));
        goto cleanup;
    }

    if (!(scsi = virSCSIDeviceNew(NULL,
                                  scsihostsrc->adapter, scsihostsrc->bus,
                                  scsihostsrc->target, scsihostsrc->unit,
                                  hostdev->readonly, hostdev->shareable)))
        goto cleanup;

    if (virSCSIDeviceListAdd(list, scsi) < 0) {
        virSCSIDeviceFree(scsi);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}

int
virHostdevPrepareSCSIDevices(virHostdevManagerPtr mgr,
                             const char *drv_name,
                             const char *dom_name,
                             virDomainHostdevDefPtr *hostdevs,
                             int nhostdevs)
{
    size_t i, j;
    int count;
    virSCSIDeviceListPtr list;
    virSCSIDevicePtr tmp;

    if (!nhostdevs)
        return 0;

    /* To prevent situation where SCSI device is assigned to two domains
     * we need to keep a list of currently assigned SCSI devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See virHostdevPreparePCIDevices()
     */
    if (!(list = virSCSIDeviceListNew()))
        goto cleanup;

    /* Loop 1: build temporary list */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virDomainHostdevSubsysSCSIPtr scsisrc = &hostdev->source.subsys.u.scsi;

        if (!virHostdevIsSCSIDevice(hostdev))
            continue;

        if (scsisrc->protocol == VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI) {
            continue;  /* Not supported for iSCSI */
        } else {
            if (virHostdevPrepareSCSIHostDevices(hostdev, scsisrc, list) < 0)
                goto cleanup;
        }
    }

    /* Loop 2: Mark devices in temporary list as used by @name
     * and add them to driver list. However, if something goes
     * wrong, perform rollback.
     */
    virObjectLock(mgr->activeSCSIHostdevs);
    count = virSCSIDeviceListCount(list);

    for (i = 0; i < count; i++) {
        virSCSIDevicePtr scsi = virSCSIDeviceListGet(list, i);
        if ((tmp = virSCSIDeviceListFind(mgr->activeSCSIHostdevs,
                                         scsi))) {
            bool scsi_shareable = virSCSIDeviceGetShareable(scsi);
            bool tmp_shareable = virSCSIDeviceGetShareable(tmp);

            if (!(scsi_shareable && tmp_shareable)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("SCSI device %s is already in use by "
                                 "other domain(s) as '%s'"),
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

    virObjectUnref(list);
    return 0;

 error:
    for (j = 0; j < i; j++) {
        tmp = virSCSIDeviceListGet(list, i);
        virSCSIDeviceListSteal(mgr->activeSCSIHostdevs, tmp);
    }
    virObjectUnlock(mgr->activeSCSIHostdevs);
 cleanup:
    virObjectUnref(list);
    return -1;
}

int
virHostdevPrepareSCSIVHostDevices(virHostdevManagerPtr mgr,
                                  const char *drv_name,
                                  const char *dom_name,
                                  virDomainHostdevDefPtr *hostdevs,
                                  int nhostdevs)
{
    size_t i, j;
    int count;
    virSCSIVHostDeviceListPtr list;
    virSCSIVHostDevicePtr host, tmp;

    if (!nhostdevs)
        return 0;

    /* To prevent situation where scsi_host device is assigned to two domains
     * we need to keep a list of currently assigned scsi_host devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See virHostdevPreparePCIDevices()
     */
    if (!(list = virSCSIVHostDeviceListNew()))
        goto cleanup;

    /* Loop 1: build temporary list */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virDomainHostdevSubsysSCSIVHostPtr hostsrc = &hostdev->source.subsys.u.scsi_host;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST)
            continue;

        if (hostsrc->protocol != VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_HOST_PROTOCOL_TYPE_VHOST)
            continue;  /* Not supported */

        if (!(host = virSCSIVHostDeviceNew(hostsrc->wwpn)))
            goto cleanup;

        if (virSCSIVHostDeviceListAdd(list, host) < 0) {
            virSCSIVHostDeviceFree(host);
            goto cleanup;
        }
    }

    /* Loop 2: Mark devices in temporary list as used by @name
     * and add them to driver list. However, if something goes
     * wrong, perform rollback.
     */
    virObjectLock(mgr->activeSCSIVHostHostdevs);
    count = virSCSIVHostDeviceListCount(list);

    for (i = 0; i < count; i++) {
        host = virSCSIVHostDeviceListGet(list, i);
        if ((tmp = virSCSIVHostDeviceListFind(mgr->activeSCSIVHostHostdevs,
                                              host))) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("SCSI_host device %s is already in use by "
                             "another domain"),
                           virSCSIVHostDeviceGetName(tmp));
            goto error;
        } else {
            if (virSCSIVHostDeviceSetUsedBy(host, drv_name, dom_name) < 0)
                goto error;

            VIR_DEBUG("Adding %s to activeSCSIVHostHostdevs",
                      virSCSIVHostDeviceGetName(host));

            if (virSCSIVHostDeviceListAdd(mgr->activeSCSIVHostHostdevs, host) < 0)
                goto error;
        }
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

    virObjectUnref(list);
    return 0;
 error:
    for (j = 0; j < i; j++) {
        tmp = virSCSIVHostDeviceListGet(list, i);
        virSCSIVHostDeviceListSteal(mgr->activeSCSIVHostHostdevs, tmp);
    }
    virObjectUnlock(mgr->activeSCSIVHostHostdevs);
 cleanup:
    virObjectUnref(list);
    return -1;
}


int
virHostdevPrepareMediatedDevices(virHostdevManagerPtr mgr,
                                 const char *drv_name,
                                 const char *dom_name,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs)
{
    size_t i;
    int ret = -1;
    virMediatedDeviceListPtr list;

    if (!nhostdevs)
        return 0;

    /* To prevent situation where mediated device is assigned to multiple
     * domains we maintain a driver list of currently assigned mediated devices.
     * A device is appended to the driver list after a series of preparations.
     */
    if (!(list = virMediatedDeviceListNew()))
        goto cleanup;

    /* Loop 1: Build a temporary list of ALL mediated devices. */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virDomainHostdevSubsysMediatedDevPtr src = &hostdev->source.subsys.u.mdev;
        virMediatedDevicePtr mdev;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV)
            continue;

        if (!(mdev = virMediatedDeviceNew(src->uuidstr, src->model)))
            goto cleanup;

        if (virMediatedDeviceListAdd(list, &mdev) < 0) {
            virMediatedDeviceFree(mdev);
            goto cleanup;
        }
    }

    /* Mark the devices in the list as used by @drv_name-@dom_name and copy the
     * references to the driver list
     */
    if (virMediatedDeviceListMarkDevices(mgr->activeMediatedHostdevs,
                                         list, drv_name, dom_name) < 0)
        goto cleanup;

    /* Loop 2: Temporary list was successfully merged with
     * driver list, so steal all items to avoid freeing them
     * in cleanup label.
     */
    while (virMediatedDeviceListCount(list) > 0) {
        virMediatedDevicePtr tmp = virMediatedDeviceListGet(list, 0);
        virMediatedDeviceListSteal(list, tmp);
    }

    ret = 0;
 cleanup:
    virObjectUnref(list);
    return ret;
}

void
virHostdevReAttachUSBDevices(virHostdevManagerPtr mgr,
                             const char *drv_name,
                             const char *dom_name,
                             virDomainHostdevDefPtr *hostdevs,
                             int nhostdevs)
{
    size_t i;

    if (!nhostdevs)
        return;

    virObjectLock(mgr->activeUSBHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virDomainHostdevSubsysUSBPtr usbsrc = &hostdev->source.subsys.u.usb;
        virUSBDevicePtr usb, tmp;
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
        virUSBDeviceFree(usb);

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
virHostdevReAttachSCSIHostDevices(virHostdevManagerPtr mgr,
                                  virDomainHostdevDefPtr hostdev,
                                  virDomainHostdevSubsysSCSIPtr scsisrc,
                                  const char *drv_name,
                                  const char *dom_name)
{
    virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;
    virSCSIDevicePtr scsi;
    virSCSIDevicePtr tmp;

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
        virSCSIDeviceFree(scsi);
        return;
    }

    VIR_DEBUG("Removing %s:%u:%u:%llu dom=%s from activeSCSIHostdevs",
               scsihostsrc->adapter, scsihostsrc->bus, scsihostsrc->target,
               scsihostsrc->unit, dom_name);

    virSCSIDeviceListDel(mgr->activeSCSIHostdevs, tmp,
                         drv_name, dom_name);
    virSCSIDeviceFree(scsi);
}

void
virHostdevReAttachSCSIDevices(virHostdevManagerPtr mgr,
                              const char *drv_name,
                              const char *dom_name,
                              virDomainHostdevDefPtr *hostdevs,
                              int nhostdevs)
{
    size_t i;

    if (!nhostdevs)
        return;

    virObjectLock(mgr->activeSCSIHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virDomainHostdevSubsysSCSIPtr scsisrc = &hostdev->source.subsys.u.scsi;

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
virHostdevReAttachSCSIVHostDevices(virHostdevManagerPtr mgr,
                                   const char *drv_name,
                                   const char *dom_name,
                                   virDomainHostdevDefPtr *hostdevs,
                                   int nhostdevs)
{
    size_t i;
    virSCSIVHostDevicePtr host, tmp;


    if (!nhostdevs)
        return;

    virObjectLock(mgr->activeSCSIVHostHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virDomainHostdevSubsysSCSIVHostPtr hostsrc = &hostdev->source.subsys.u.scsi_host;
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
            virSCSIVHostDeviceFree(host);
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

        virSCSIVHostDeviceFree(host);
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
virHostdevReAttachMediatedDevices(virHostdevManagerPtr mgr,
                                  const char *drv_name,
                                  const char *dom_name,
                                  virDomainHostdevDefPtr *hostdevs,
                                  int nhostdevs)
{
    const char *used_by_drvname = NULL;
    const char *used_by_domname = NULL;
    size_t i;

    if (nhostdevs == 0)
        return;

    virObjectLock(mgr->activeMediatedHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virMediatedDevicePtr mdev, tmp;
        virDomainHostdevSubsysMediatedDevPtr mdevsrc;
        virDomainHostdevDefPtr hostdev = hostdevs[i];

        mdevsrc = &hostdev->source.subsys.u.mdev;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV) {
            continue;
        }

        if (!(mdev = virMediatedDeviceNew(mdevsrc->uuidstr,
                                          mdevsrc->model)))
            continue;

        /* Remove from the list only mdevs assigned to @drv_name/@dom_name */

        tmp = virMediatedDeviceListFind(mgr->activeMediatedHostdevs, mdev);
        virMediatedDeviceFree(mdev);

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
virHostdevPCINodeDeviceDetach(virHostdevManagerPtr mgr,
                              virPCIDevicePtr pci)
{
    struct virHostdevIsPCINodeDeviceUsedData data = { mgr, NULL, false };
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
virHostdevPCINodeDeviceReAttach(virHostdevManagerPtr mgr,
                                virPCIDevicePtr pci)
{
    struct virHostdevIsPCINodeDeviceUsedData data = { mgr, NULL, false };
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
virHostdevPCINodeDeviceReset(virHostdevManagerPtr mgr,
                             virPCIDevicePtr pci)
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
virHostdevPrepareDomainDevices(virHostdevManagerPtr mgr,
                               const char *driver,
                               virDomainDefPtr def,
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

/* @oldStateDir
 * For upgrade purpose: see virHostdevReAttachPCIHostdevs
 */
void
virHostdevReAttachDomainDevices(virHostdevManagerPtr mgr,
                                const char *driver,
                                virDomainDefPtr def,
                                unsigned int flags,
                                const char *oldStateDir)
{
    if (!def->nhostdevs || !mgr)
        return;

    if (flags & VIR_HOSTDEV_SP_PCI) {
        virHostdevReAttachPCIDevices(mgr, driver, def->name,
                                     def->hostdevs, def->nhostdevs,
                                     oldStateDir);
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
virHostdevUpdateActiveDomainDevices(virHostdevManagerPtr mgr,
                                    const char *driver,
                                    virDomainDefPtr def,
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
