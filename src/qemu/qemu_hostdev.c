/*
 * qemu_hostdev.c: QEMU hostdev management
 *
 * Copyright (C) 2006-2007, 2009-2013 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 */

#include <config.h>

#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "qemu_hostdev.h"
#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virpci.h"
#include "virusb.h"
#include "virscsi.h"
#include "virnetdev.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

static virPCIDeviceListPtr
qemuGetPciHostDeviceList(virDomainHostdevDefPtr *hostdevs, int nhostdevs)
{
    virPCIDeviceListPtr list;
    size_t i;

    if (!(list = virPCIDeviceListNew()))
        return NULL;

    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virPCIDevicePtr dev;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        dev = virPCIDeviceNew(hostdev->source.subsys.u.pci.addr.domain,
                              hostdev->source.subsys.u.pci.addr.bus,
                              hostdev->source.subsys.u.pci.addr.slot,
                              hostdev->source.subsys.u.pci.addr.function);
        if (!dev) {
            virObjectUnref(list);
            return NULL;
        }

        if (virPCIDeviceListAdd(list, dev) < 0) {
            virPCIDeviceFree(dev);
            virObjectUnref(list);
            return NULL;
        }

        virPCIDeviceSetManaged(dev, hostdev->managed);
        if (hostdev->source.subsys.u.pci.backend
            == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            if (virPCIDeviceSetStubDriver(dev, "vfio-pci") < 0) {
                virObjectUnref(list);
                return NULL;
            }
        } else {
            if (virPCIDeviceSetStubDriver(dev, "pci-stub") < 0) {
                virObjectUnref(list);
                return NULL;
            }
        }
    }

    return list;
}


/*
 * qemuGetActivePciHostDeviceList - make a new list with a *copy* of
 *   every virPCIDevice object that is found on the activePciHostdevs
 *   list *and* is in the hostdev list for this domain.
 *
 * Return the new list, or NULL if there was a failure.
 *
 * Pre-condition: driver->activePciHostdevs is locked
 */
static virPCIDeviceListPtr
qemuGetActivePciHostDeviceList(virQEMUDriverPtr driver,
                               virDomainHostdevDefPtr *hostdevs,
                               int nhostdevs)
{
    virPCIDeviceListPtr list;
    size_t i;

    if (!(list = virPCIDeviceListNew()))
        return NULL;

    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virDevicePCIAddressPtr addr;
        virPCIDevicePtr activeDev;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        addr = &hostdev->source.subsys.u.pci.addr;
        activeDev = virPCIDeviceListFindByIDs(driver->activePciHostdevs,
                                              addr->domain, addr->bus,
                                              addr->slot, addr->function);
        if (activeDev && virPCIDeviceListAddCopy(list, activeDev) < 0) {
            virObjectUnref(list);
            return NULL;
        }
    }

    return list;
}


int
qemuUpdateActivePciHostdevs(virQEMUDriverPtr driver,
                            virDomainDefPtr def)
{
    virDomainHostdevDefPtr hostdev = NULL;
    virPCIDevicePtr dev = NULL;
    size_t i;
    int ret = -1;

    if (!def->nhostdevs)
        return 0;

    virObjectLock(driver->activePciHostdevs);
    virObjectLock(driver->inactivePciHostdevs);

    for (i = 0; i < def->nhostdevs; i++) {
        hostdev = def->hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        dev = virPCIDeviceNew(hostdev->source.subsys.u.pci.addr.domain,
                              hostdev->source.subsys.u.pci.addr.bus,
                              hostdev->source.subsys.u.pci.addr.slot,
                              hostdev->source.subsys.u.pci.addr.function);

        if (!dev)
            goto cleanup;

        virPCIDeviceSetManaged(dev, hostdev->managed);
        if (hostdev->source.subsys.u.pci.backend
            == VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO) {
            if (virPCIDeviceSetStubDriver(dev, "vfio-pci") < 0)
                goto cleanup;
        } else {
            if (virPCIDeviceSetStubDriver(dev, "pci-stub") < 0)
                goto cleanup;

        }
        virPCIDeviceSetUsedBy(dev, QEMU_DRIVER_NAME, def->name);

        /* Setup the original states for the PCI device */
        virPCIDeviceSetUnbindFromStub(dev, hostdev->origstates.states.pci.unbind_from_stub);
        virPCIDeviceSetRemoveSlot(dev, hostdev->origstates.states.pci.remove_slot);
        virPCIDeviceSetReprobe(dev, hostdev->origstates.states.pci.reprobe);

        if (virPCIDeviceListAdd(driver->activePciHostdevs, dev) < 0)
            goto cleanup;
        dev = NULL;
    }

    ret = 0;
cleanup:
    virPCIDeviceFree(dev);
    virObjectUnlock(driver->activePciHostdevs);
    virObjectUnlock(driver->inactivePciHostdevs);
    return ret;
}


int
qemuUpdateActiveUsbHostdevs(virQEMUDriverPtr driver,
                            virDomainDefPtr def)
{
    virDomainHostdevDefPtr hostdev = NULL;
    size_t i;
    int ret = -1;

    if (!def->nhostdevs)
        return 0;

    virObjectLock(driver->activeUsbHostdevs);
    for (i = 0; i < def->nhostdevs; i++) {
        virUSBDevicePtr usb = NULL;
        hostdev = def->hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        usb = virUSBDeviceNew(hostdev->source.subsys.u.usb.bus,
                              hostdev->source.subsys.u.usb.device,
                              NULL);
        if (!usb) {
            VIR_WARN("Unable to reattach USB device %03d.%03d on domain %s",
                     hostdev->source.subsys.u.usb.bus,
                     hostdev->source.subsys.u.usb.device,
                     def->name);
            continue;
        }

        virUSBDeviceSetUsedBy(usb, QEMU_DRIVER_NAME, def->name);

        if (virUSBDeviceListAdd(driver->activeUsbHostdevs, usb) < 0) {
            virUSBDeviceFree(usb);
            goto cleanup;
        }
    }
    ret = 0;
cleanup:
    virObjectUnlock(driver->activeUsbHostdevs);
    return ret;
}

int
qemuUpdateActiveScsiHostdevs(virQEMUDriverPtr driver,
                             virDomainDefPtr def)
{
    virDomainHostdevDefPtr hostdev = NULL;
    size_t i;
    int ret = -1;
    virSCSIDevicePtr scsi = NULL;
    virSCSIDevicePtr tmp = NULL;

    if (!def->nhostdevs)
        return 0;

    virObjectLock(driver->activeScsiHostdevs);
    for (i = 0; i < def->nhostdevs; i++) {
        hostdev = def->hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI)
            continue;

        if (!(scsi = virSCSIDeviceNew(NULL,
                                      hostdev->source.subsys.u.scsi.adapter,
                                      hostdev->source.subsys.u.scsi.bus,
                                      hostdev->source.subsys.u.scsi.target,
                                      hostdev->source.subsys.u.scsi.unit,
                                      hostdev->readonly,
                                      hostdev->shareable)))
            goto cleanup;

        if ((tmp = virSCSIDeviceListFind(driver->activeScsiHostdevs, scsi))) {
            if (virSCSIDeviceSetUsedBy(tmp, QEMU_DRIVER_NAME, def->name) < 0) {
                virSCSIDeviceFree(scsi);
                goto cleanup;
            }
            virSCSIDeviceFree(scsi);
        } else {
            if (virSCSIDeviceSetUsedBy(scsi, QEMU_DRIVER_NAME, def->name) < 0 ||
                virSCSIDeviceListAdd(driver->activeScsiHostdevs, scsi) < 0) {
                virSCSIDeviceFree(scsi);
                goto cleanup;
            }
        }
    }
    ret = 0;

cleanup:
    virObjectUnlock(driver->activeScsiHostdevs);
    return ret;
}


static int
qemuDomainHostdevPciSysfsPath(virDomainHostdevDefPtr hostdev,
                              char **sysfs_path)
{
    virPCIDeviceAddress config_address;

    config_address.domain = hostdev->source.subsys.u.pci.addr.domain;
    config_address.bus = hostdev->source.subsys.u.pci.addr.bus;
    config_address.slot = hostdev->source.subsys.u.pci.addr.slot;
    config_address.function = hostdev->source.subsys.u.pci.addr.function;

    return virPCIDeviceAddressGetSysfsFile(&config_address, sysfs_path);
}


int
qemuDomainHostdevIsVirtualFunction(virDomainHostdevDefPtr hostdev)
{
    char *sysfs_path = NULL;
    int ret = -1;

    if (qemuDomainHostdevPciSysfsPath(hostdev, &sysfs_path) < 0)
        return ret;

    ret = virPCIIsVirtualFunction(sysfs_path);

    VIR_FREE(sysfs_path);

    return ret;
}


static int
qemuDomainHostdevNetDevice(virDomainHostdevDefPtr hostdev, char **linkdev,
                           int *vf)
{
    int ret = -1;
    char *sysfs_path = NULL;

    if (qemuDomainHostdevPciSysfsPath(hostdev, &sysfs_path) < 0)
        return ret;

    if (virPCIIsVirtualFunction(sysfs_path) == 1) {
        if (virPCIGetVirtualFunctionInfo(sysfs_path, linkdev,
                                         vf) < 0)
            goto cleanup;
    } else {
        if (virPCIGetNetName(sysfs_path, linkdev) < 0)
            goto cleanup;
        *vf = -1;
    }

    ret = 0;

cleanup:
    VIR_FREE(sysfs_path);

    return ret;
}


static int
qemuDomainHostdevNetConfigVirtPortProfile(const char *linkdev, int vf,
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


int
qemuDomainHostdevNetConfigReplace(virDomainHostdevDefPtr hostdev,
                                  const unsigned char *uuid,
                                  char *stateDir)
{
    char *linkdev = NULL;
    virNetDevVlanPtr vlan;
    virNetDevVPortProfilePtr virtPort;
    int ret = -1;
    int vf = -1;
    int vlanid = -1;
    bool port_profile_associate = true;
    int isvf;

    isvf = qemuDomainHostdevIsVirtualFunction(hostdev);
    if (isvf <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Interface type hostdev is currently supported on"
                         " SR-IOV Virtual Functions only"));
        return ret;
    }

    if (qemuDomainHostdevNetDevice(hostdev, &linkdev, &vf) < 0)
        return ret;

    vlan = virDomainNetGetActualVlan(hostdev->parent.data.net);
    virtPort = virDomainNetGetActualVirtPortProfile(
                                 hostdev->parent.data.net);
    if (virtPort) {
        if (vlan) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("direct setting of the vlan tag is not allowed "
                             "for hostdev devices using %s mode"),
                           virNetDevVPortTypeToString(virtPort->virtPortType));
            goto cleanup;
        }
        ret = qemuDomainHostdevNetConfigVirtPortProfile(linkdev, vf,
                            virtPort, &hostdev->parent.data.net->mac, uuid,
                            port_profile_associate);
    } else {
        /* Set only mac and vlan */
        if (vlan) {
            if (vlan->nTags != 1 || vlan->trunk) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("vlan trunking is not supported "
                                 "by SR-IOV network devices"));
                goto cleanup;
            }
            if (vf == -1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("vlan can only be set for SR-IOV VFs, but "
                                 "%s is not a VF"), linkdev);
                goto cleanup;
            }
            vlanid = vlan->tag[0];
        } else  if (vf >= 0) {
            vlanid = 0; /* assure any current vlan tag is reset */
        }

        ret = virNetDevReplaceNetConfig(linkdev, vf,
                                        &hostdev->parent.data.net->mac,
                                        vlanid, stateDir);
    }
cleanup:
    VIR_FREE(linkdev);
    return ret;
}


int
qemuDomainHostdevNetConfigRestore(virDomainHostdevDefPtr hostdev,
                                  char *stateDir)
{
    char *linkdev = NULL;
    virNetDevVPortProfilePtr virtPort;
    int ret = -1;
    int vf = -1;
    bool port_profile_associate = false;
    int isvf;

    /* This is only needed for PCI devices that have been defined
     * using <interface type='hostdev'>. For all others, it is a NOP.
     */
    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
        hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI ||
        hostdev->parent.type != VIR_DOMAIN_DEVICE_NET ||
        !hostdev->parent.data.net)
       return 0;

    isvf = qemuDomainHostdevIsVirtualFunction(hostdev);
    if (isvf <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Interface type hostdev is currently supported on"
                         " SR-IOV Virtual Functions only"));
        return ret;
    }

    if (qemuDomainHostdevNetDevice(hostdev, &linkdev, &vf) < 0)
        return ret;

    virtPort = virDomainNetGetActualVirtPortProfile(
                                 hostdev->parent.data.net);
    if (virtPort)
        ret = qemuDomainHostdevNetConfigVirtPortProfile(linkdev, vf, virtPort,
                                          &hostdev->parent.data.net->mac, NULL,
                                          port_profile_associate);
    else
        ret = virNetDevRestoreNetConfig(linkdev, vf, stateDir);

    VIR_FREE(linkdev);

    return ret;
}


bool
qemuHostdevHostSupportsPassthroughVFIO(void)
{
    DIR *iommuDir = NULL;
    struct dirent *iommuGroup = NULL;
    bool ret = false;

    /* condition 1 - /sys/kernel/iommu_groups/ contains entries */
    if (!(iommuDir = opendir("/sys/kernel/iommu_groups/")))
        goto cleanup;

    while ((iommuGroup = readdir(iommuDir))) {
        /* skip ./ ../ */
        if (STRPREFIX(iommuGroup->d_name, "."))
            continue;

        /* assume we found a group */
        break;
    }

    if (!iommuGroup)
        goto cleanup;
    /* okay, iommu is on and recognizes groups */

    /* condition 2 - /dev/vfio/vfio exists */
    if (!virFileExists("/dev/vfio/vfio"))
        goto cleanup;

    ret = true;

cleanup:
    if (iommuDir)
        closedir(iommuDir);

    return ret;
}


#if HAVE_LINUX_KVM_H
# include <linux/kvm.h>
bool
qemuHostdevHostSupportsPassthroughLegacy(void)
{
    int kvmfd = -1;
    bool ret = false;

    if ((kvmfd = open("/dev/kvm", O_RDONLY)) < 0)
        goto cleanup;

# ifdef KVM_CAP_IOMMU
    if ((ioctl(kvmfd, KVM_CHECK_EXTENSION, KVM_CAP_IOMMU)) <= 0)
        goto cleanup;

    ret = true;
# endif

cleanup:
    VIR_FORCE_CLOSE(kvmfd);

    return ret;
}
#else
bool
qemuHostdevHostSupportsPassthroughLegacy(void)
{
    return false;
}
#endif


static bool
qemuPrepareHostdevPCICheckSupport(virDomainHostdevDefPtr *hostdevs,
                                  size_t nhostdevs,
                                  virQEMUCapsPtr qemuCaps)
{
    bool supportsPassthroughKVM = qemuHostdevHostSupportsPassthroughLegacy();
    bool supportsPassthroughVFIO = qemuHostdevHostSupportsPassthroughVFIO();
    size_t i;

    /* assign defaults for hostdev passthrough */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        int *backend = &hostdev->source.subsys.u.pci.backend;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        switch ((virDomainHostdevSubsysPciBackendType) *backend) {
        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_DEFAULT:
            if (supportsPassthroughVFIO &&
                virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VFIO_PCI)) {
                *backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO;
            } else if (supportsPassthroughKVM &&
                       (virQEMUCapsGet(qemuCaps, QEMU_CAPS_PCIDEVICE) ||
                        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE))) {
                *backend = VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM;
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("host doesn't support passthrough of "
                                 "host PCI devices"));
                return false;
            }

            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_VFIO:
            if (!supportsPassthroughVFIO) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("host doesn't support VFIO PCI passthrough"));
                return false;
            }
            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_KVM:
            if (!supportsPassthroughKVM) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("host doesn't support legacy PCI passthrough"));
                return false;
            }

            break;

        case VIR_DOMAIN_HOSTDEV_PCI_BACKEND_TYPE_LAST:
            break;
        }
    }

    return true;
}


int
qemuPrepareHostdevPCIDevices(virQEMUDriverPtr driver,
                             const char *name,
                             const unsigned char *uuid,
                             virDomainHostdevDefPtr *hostdevs,
                             int nhostdevs,
                             virQEMUCapsPtr qemuCaps)
{
    virPCIDeviceListPtr pcidevs = NULL;
    int last_processed_hostdev_vf = -1;
    size_t i;
    int ret = -1;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (!qemuPrepareHostdevPCICheckSupport(hostdevs, nhostdevs, qemuCaps))
        goto cleanup;

    virObjectLock(driver->activePciHostdevs);
    virObjectLock(driver->inactivePciHostdevs);

    if (!(pcidevs = qemuGetPciHostDeviceList(hostdevs, nhostdevs)))
        goto cleanup;

    /* We have to use 9 loops here. *All* devices must
     * be detached before we reset any of them, because
     * in some cases you have to reset the whole PCI,
     * which impacts all devices on it. Also, all devices
     * must be reset before being marked as active.
     */

    /* Loop 1: validate that non-managed device isn't in use, eg
     * by checking that device is either un-bound, or bound
     * to pci-stub.ko
     */

    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr dev = virPCIDeviceListGet(pcidevs, i);
        virPCIDevicePtr other;

        if (!virPCIDeviceIsAssignable(dev, !cfg->relaxedACS)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("PCI device %s is not assignable"),
                           virPCIDeviceGetName(dev));
            goto cleanup;
        }
        /* The device is in use by other active domain if
         * the dev is in list driver->activePciHostdevs.
         */
        if ((other = virPCIDeviceListFind(driver->activePciHostdevs, dev))) {
            const char *other_drvname;
            const char *other_domname;

            virPCIDeviceGetUsedBy(other, &other_drvname, &other_domname);
            if (other_drvname && other_domname)
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("PCI device %s is in use by "
                                 "driver %s, domain %s"),
                               virPCIDeviceGetName(dev),
                               other_drvname, other_domname);
            else
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("PCI device %s is already in use"),
                               virPCIDeviceGetName(dev));
            goto cleanup;
        }
    }

    /* Loop 2: detach managed devices (i.e. bind to appropriate stub driver) */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr dev = virPCIDeviceListGet(pcidevs, i);
        if (virPCIDeviceGetManaged(dev) &&
            virPCIDeviceDetach(dev, driver->activePciHostdevs, NULL) < 0)
            goto reattachdevs;
    }

    /* Loop 3: Now that all the PCI hostdevs have been detached, we
     * can safely reset them */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr dev = virPCIDeviceListGet(pcidevs, i);

        if (virPCIDeviceReset(dev, driver->activePciHostdevs,
                              driver->inactivePciHostdevs) < 0)
            goto reattachdevs;
    }

    /* Loop 4: For SRIOV network devices, Now that we have detached the
     * the network device, set the netdev config */
    for (i = 0; i < nhostdevs; i++) {
         virDomainHostdevDefPtr hostdev = hostdevs[i];
         if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
             continue;
         if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
             continue;
         if (hostdev->parent.type == VIR_DOMAIN_DEVICE_NET &&
             hostdev->parent.data.net) {
             if (qemuDomainHostdevNetConfigReplace(hostdev, uuid,
                                                   cfg->stateDir) < 0) {
                 goto resetvfnetconfig;
             }
         }
         last_processed_hostdev_vf = i;
    }

    /* Loop 5: Now mark all the devices as active */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr dev = virPCIDeviceListGet(pcidevs, i);
        if (virPCIDeviceListAdd(driver->activePciHostdevs, dev) < 0)
            goto inactivedevs;
    }

    /* Loop 6: Now remove the devices from inactive list. */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
         virPCIDevicePtr dev = virPCIDeviceListGet(pcidevs, i);
         virPCIDeviceListDel(driver->inactivePciHostdevs, dev);
    }

    /* Loop 7: Now set the used_by_domain of the device in
     * driver->activePciHostdevs as domain name.
     */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr dev, activeDev;

        dev = virPCIDeviceListGet(pcidevs, i);
        activeDev = virPCIDeviceListFind(driver->activePciHostdevs, dev);

        if (activeDev)
            virPCIDeviceSetUsedBy(activeDev, QEMU_DRIVER_NAME, name);
    }

    /* Loop 8: Now set the original states for hostdev def */
    for (i = 0; i < nhostdevs; i++) {
        virPCIDevicePtr dev;
        virPCIDevicePtr pcidev;
        virDomainHostdevDefPtr hostdev = hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        dev = virPCIDeviceNew(hostdev->source.subsys.u.pci.addr.domain,
                              hostdev->source.subsys.u.pci.addr.bus,
                              hostdev->source.subsys.u.pci.addr.slot,
                              hostdev->source.subsys.u.pci.addr.function);

        /* original states "unbind_from_stub", "remove_slot",
         * "reprobe" were already set by pciDettachDevice in
         * loop 2.
         */
        if ((pcidev = virPCIDeviceListFind(pcidevs, dev))) {
            hostdev->origstates.states.pci.unbind_from_stub =
                virPCIDeviceGetUnbindFromStub(pcidev);
            hostdev->origstates.states.pci.remove_slot =
                virPCIDeviceGetRemoveSlot(pcidev);
            hostdev->origstates.states.pci.reprobe =
                virPCIDeviceGetReprobe(pcidev);
        }

        virPCIDeviceFree(dev);
    }

    /* Loop 9: Now steal all the devices from pcidevs */
    while (virPCIDeviceListCount(pcidevs) > 0)
        virPCIDeviceListStealIndex(pcidevs, 0);

    ret = 0;
    goto cleanup;

inactivedevs:
    /* Only steal all the devices from driver->activePciHostdevs. We will
     * free them in virObjectUnref().
     */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr dev = virPCIDeviceListGet(pcidevs, i);
        virPCIDeviceListSteal(driver->activePciHostdevs, dev);
    }

resetvfnetconfig:
    for (i = 0;
         last_processed_hostdev_vf != -1 && i < last_processed_hostdev_vf; i++)
        qemuDomainHostdevNetConfigRestore(hostdevs[i], cfg->stateDir);

reattachdevs:
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr dev = virPCIDeviceListGet(pcidevs, i);

        /* NB: This doesn't actually re-bind to original driver, just
         * unbinds from the stub driver
         */
        ignore_value(virPCIDeviceReattach(dev, driver->activePciHostdevs,
                                          NULL));
    }

cleanup:
    virObjectUnlock(driver->activePciHostdevs);
    virObjectUnlock(driver->inactivePciHostdevs);
    virObjectUnref(pcidevs);
    virObjectUnref(cfg);
    return ret;
}


int
qemuPrepareHostdevUSBDevices(virQEMUDriverPtr driver,
                             const char *name,
                             virUSBDeviceListPtr list)
{
    size_t i, j;
    unsigned int count;
    virUSBDevicePtr tmp;

    virObjectLock(driver->activeUsbHostdevs);
    count = virUSBDeviceListCount(list);

    for (i = 0; i < count; i++) {
        virUSBDevicePtr usb = virUSBDeviceListGet(list, i);
        if ((tmp = virUSBDeviceListFind(driver->activeUsbHostdevs, usb))) {
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

        virUSBDeviceSetUsedBy(usb, QEMU_DRIVER_NAME, name);
        VIR_DEBUG("Adding %03d.%03d dom=%s to activeUsbHostdevs",
                  virUSBDeviceGetBus(usb), virUSBDeviceGetDevno(usb), name);
        /*
         * The caller is responsible to steal these usb devices
         * from the virUSBDeviceList that passed in on success,
         * perform rollback on failure.
         */
        if (virUSBDeviceListAdd(driver->activeUsbHostdevs, usb) < 0)
            goto error;
    }

    virObjectUnlock(driver->activeUsbHostdevs);
    return 0;

error:
    for (j = 0; j < i; j++) {
        tmp = virUSBDeviceListGet(list, i);
        virUSBDeviceListSteal(driver->activeUsbHostdevs, tmp);
    }
    virObjectUnlock(driver->activeUsbHostdevs);
    return -1;
}


int
qemuFindHostdevUSBDevice(virDomainHostdevDefPtr hostdev,
                         bool mandatory,
                         virUSBDevicePtr *usb)
{
    unsigned vendor = hostdev->source.subsys.u.usb.vendor;
    unsigned product = hostdev->source.subsys.u.usb.product;
    unsigned bus = hostdev->source.subsys.u.usb.bus;
    unsigned device = hostdev->source.subsys.u.usb.device;
    bool autoAddress = hostdev->source.subsys.u.usb.autoAddress;
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

        hostdev->source.subsys.u.usb.bus = virUSBDeviceGetBus(*usb);
        hostdev->source.subsys.u.usb.device = virUSBDeviceGetDevno(*usb);
        hostdev->source.subsys.u.usb.autoAddress = true;

        if (autoAddress) {
            VIR_INFO("USB device %x:%x found at bus:%u device:%u (moved"
                     " from bus:%u device:%u)",
                     vendor, product,
                     hostdev->source.subsys.u.usb.bus,
                     hostdev->source.subsys.u.usb.device,
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


static int
qemuPrepareHostUSBDevices(virQEMUDriverPtr driver,
                          virDomainDefPtr def,
                          bool coldBoot)
{
    size_t i;
    int ret = -1;
    virUSBDeviceListPtr list;
    virUSBDevicePtr tmp;
    virDomainHostdevDefPtr *hostdevs = def->hostdevs;
    int nhostdevs = def->nhostdevs;

    /* To prevent situation where USB device is assigned to two domains
     * we need to keep a list of currently assigned USB devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See qemuPrepareHostdevPCIDevices()
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

        if (qemuFindHostdevUSBDevice(hostdev, required, &usb) < 0)
            goto cleanup;

        if (usb && virUSBDeviceListAdd(list, usb) < 0) {
            virUSBDeviceFree(usb);
            goto cleanup;
        }
    }

    /* Mark devices in temporary list as used by @name
     * and add them do driver list. However, if something goes
     * wrong, perform rollback.
     */
    if (qemuPrepareHostdevUSBDevices(driver, def->name, list) < 0)
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


int
qemuPrepareHostdevSCSIDevices(virQEMUDriverPtr driver,
                              const char *name,
                              virDomainHostdevDefPtr *hostdevs,
                              int nhostdevs)
{
    size_t i, j;
    int count;
    virSCSIDeviceListPtr list;
    virSCSIDevicePtr tmp;

    /* Loop 1: Add the shared scsi host device to shared device
     * table.
     */
    for (i = 0; i < nhostdevs; i++) {
        virDomainDeviceDef dev;

        dev.type = VIR_DOMAIN_DEVICE_HOSTDEV;
        dev.data.hostdev = hostdevs[i];

        if (qemuAddSharedDevice(driver, &dev, name) < 0)
            return -1;

        if (qemuSetUnprivSGIO(&dev) < 0)
            return -1;
    }

    /* To prevent situation where SCSI device is assigned to two domains
     * we need to keep a list of currently assigned SCSI devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See qemuPrepareHostdevPCIDevices()
     */
    if (!(list = virSCSIDeviceListNew()))
        goto cleanup;

    /* Loop 2: build temporary list */
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virSCSIDevicePtr scsi;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI)
            continue;

        if (hostdev->managed) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("SCSI host device doesn't support managed mode"));
            goto cleanup;
        }

        if (!(scsi = virSCSIDeviceNew(NULL,
                                      hostdev->source.subsys.u.scsi.adapter,
                                      hostdev->source.subsys.u.scsi.bus,
                                      hostdev->source.subsys.u.scsi.target,
                                      hostdev->source.subsys.u.scsi.unit,
                                      hostdev->readonly,
                                      hostdev->shareable)))
            goto cleanup;

        if (scsi && virSCSIDeviceListAdd(list, scsi) < 0) {
            virSCSIDeviceFree(scsi);
            goto cleanup;
        }
    }

    /* Loop 3: Mark devices in temporary list as used by @name
     * and add them to driver list. However, if something goes
     * wrong, perform rollback.
     */
    virObjectLock(driver->activeScsiHostdevs);
    count = virSCSIDeviceListCount(list);

    for (i = 0; i < count; i++) {
        virSCSIDevicePtr scsi = virSCSIDeviceListGet(list, i);
        if ((tmp = virSCSIDeviceListFind(driver->activeScsiHostdevs, scsi))) {
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

            if (virSCSIDeviceSetUsedBy(tmp, QEMU_DRIVER_NAME, name) < 0)
                goto error;
        } else {
            if (virSCSIDeviceSetUsedBy(scsi, QEMU_DRIVER_NAME, name) < 0)
                goto error;

            VIR_DEBUG("Adding %s to activeScsiHostdevs", virSCSIDeviceGetName(scsi));

            if (virSCSIDeviceListAdd(driver->activeScsiHostdevs, scsi) < 0)
                goto error;
        }
    }

    virObjectUnlock(driver->activeScsiHostdevs);

    /* Loop 4: Temporary list was successfully merged with
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
        virSCSIDeviceListSteal(driver->activeScsiHostdevs, tmp);
    }
    virObjectUnlock(driver->activeScsiHostdevs);
cleanup:
    virObjectUnref(list);
    return -1;
}


int
qemuPrepareHostDevices(virQEMUDriverPtr driver,
                       virDomainDefPtr def,
                       virQEMUCapsPtr qemuCaps,
                       bool coldBoot)
{
    if (!def->nhostdevs)
        return 0;

    if (qemuPrepareHostdevPCIDevices(driver, def->name, def->uuid,
                                     def->hostdevs, def->nhostdevs,
                                     qemuCaps) < 0)
        return -1;

    if (qemuPrepareHostUSBDevices(driver, def, coldBoot) < 0)
        return -1;

    if (qemuPrepareHostdevSCSIDevices(driver, def->name,
                                      def->hostdevs, def->nhostdevs) < 0)
        return -1;

    return 0;
}


/*
 * Pre-condition: driver->inactivePciHostdevs & driver->activePciHostdevs
 * are locked
 */
void
qemuReattachPciDevice(virPCIDevicePtr dev, virQEMUDriverPtr driver)
{
    int retries = 100;

    /* If the device is not managed and was attached to guest
     * successfully, it must have been inactive.
     */
    if (!virPCIDeviceGetManaged(dev)) {
        if (virPCIDeviceListAdd(driver->inactivePciHostdevs, dev) < 0)
            virPCIDeviceFree(dev);
        return;
    }

    while (virPCIDeviceWaitForCleanup(dev, "kvm_assigned_device")
           && retries) {
        usleep(100*1000);
        retries--;
    }

    if (virPCIDeviceReattach(dev, driver->activePciHostdevs,
                             driver->inactivePciHostdevs) < 0) {
        virErrorPtr err = virGetLastError();
        VIR_ERROR(_("Failed to re-attach PCI device: %s"),
                  err ? err->message : _("unknown error"));
        virResetError(err);
    }
    virPCIDeviceFree(dev);
}


void
qemuDomainReAttachHostdevDevices(virQEMUDriverPtr driver,
                                 const char *name,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs)
{
    virPCIDeviceListPtr pcidevs;
    size_t i;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    virObjectLock(driver->activePciHostdevs);
    virObjectLock(driver->inactivePciHostdevs);

    if (!(pcidevs = qemuGetActivePciHostDeviceList(driver,
                                                   hostdevs,
                                                   nhostdevs))) {
        virErrorPtr err = virGetLastError();
        VIR_ERROR(_("Failed to allocate PCI device list: %s"),
                  err ? err->message : _("unknown error"));
        virResetError(err);
        goto cleanup;
    }

    /* Again 4 loops; mark all devices as inactive before reset
     * them and reset all the devices before re-attach.
     * Attach mac and port profile parameters to devices
     */
    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr dev = virPCIDeviceListGet(pcidevs, i);
        virPCIDevicePtr activeDev = NULL;

        /* delete the copy of the dev from pcidevs if it's used by
         * other domain. Or delete it from activePciHostDevs if it had
         * been used by this domain.
         */
        activeDev = virPCIDeviceListFind(driver->activePciHostdevs, dev);
        if (activeDev) {
            const char *usedby_drvname;
            const char *usedby_domname;
            virPCIDeviceGetUsedBy(activeDev, &usedby_drvname, &usedby_domname);
            if (STRNEQ_NULLABLE(QEMU_DRIVER_NAME, usedby_drvname) ||
                STRNEQ_NULLABLE(name, usedby_domname)) {
                    virPCIDeviceListDel(pcidevs, dev);
                    continue;
                }
        }

        virPCIDeviceListDel(driver->activePciHostdevs, dev);
    }

    /* At this point, any device that had been used by the guest is in
     * pcidevs, but has been removed from activePciHostdevs.
     */

    /*
     * For SRIOV net host devices, unset mac and port profile before
     * reset and reattach device
     */
    for (i = 0; i < nhostdevs; i++)
        qemuDomainHostdevNetConfigRestore(hostdevs[i], cfg->stateDir);

    for (i = 0; i < virPCIDeviceListCount(pcidevs); i++) {
        virPCIDevicePtr dev = virPCIDeviceListGet(pcidevs, i);

        if (virPCIDeviceReset(dev, driver->activePciHostdevs,
                              driver->inactivePciHostdevs) < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to reset PCI device: %s"),
                      err ? err->message : _("unknown error"));
            virResetError(err);
        }
    }

    while (virPCIDeviceListCount(pcidevs) > 0) {
        virPCIDevicePtr dev = virPCIDeviceListStealIndex(pcidevs, 0);
        qemuReattachPciDevice(dev, driver);
    }

    virObjectUnref(pcidevs);
cleanup:
    virObjectUnlock(driver->activePciHostdevs);
    virObjectUnlock(driver->inactivePciHostdevs);
    virObjectUnref(cfg);
}


static void
qemuDomainReAttachHostUsbDevices(virQEMUDriverPtr driver,
                                 const char *name,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs)
{
    size_t i;

    virObjectLock(driver->activeUsbHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virUSBDevicePtr usb, tmp;
        const char *usedby_drvname;
        const char *usedby_domname;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;
        if (hostdev->missing)
            continue;

        usb = virUSBDeviceNew(hostdev->source.subsys.u.usb.bus,
                              hostdev->source.subsys.u.usb.device,
                              NULL);

        if (!usb) {
            VIR_WARN("Unable to reattach USB device %03d.%03d on domain %s",
                     hostdev->source.subsys.u.usb.bus,
                     hostdev->source.subsys.u.usb.device,
                     name);
            continue;
        }

        /* Delete only those USB devices which belongs
         * to domain @name because qemuProcessStart() might
         * have failed because USB device is already taken.
         * Therefore we want to steal only those devices from
         * the list which were taken by @name */

        tmp = virUSBDeviceListFind(driver->activeUsbHostdevs, usb);
        virUSBDeviceFree(usb);

        if (!tmp) {
            VIR_WARN("Unable to find device %03d.%03d "
                     "in list of active USB devices",
                     hostdev->source.subsys.u.usb.bus,
                     hostdev->source.subsys.u.usb.device);
            continue;
        }

        virUSBDeviceGetUsedBy(tmp, &usedby_drvname, &usedby_domname);
        if (STREQ_NULLABLE(QEMU_DRIVER_NAME, usedby_drvname) &&
            STREQ_NULLABLE(name, usedby_domname)) {
            VIR_DEBUG("Removing %03d.%03d dom=%s from activeUsbHostdevs",
                      hostdev->source.subsys.u.usb.bus,
                      hostdev->source.subsys.u.usb.device,
                      name);

            virUSBDeviceListDel(driver->activeUsbHostdevs, tmp);
        }
    }
    virObjectUnlock(driver->activeUsbHostdevs);
}


void
qemuDomainReAttachHostScsiDevices(virQEMUDriverPtr driver,
                                  const char *name,
                                  virDomainHostdevDefPtr *hostdevs,
                                  int nhostdevs)
{
    size_t i;

    virObjectLock(driver->activeScsiHostdevs);
    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        virSCSIDevicePtr scsi;
        virSCSIDevicePtr tmp;
        virDomainDeviceDef dev;

        dev.type = VIR_DOMAIN_DEVICE_HOSTDEV;
        dev.data.hostdev = hostdev;

        ignore_value(qemuRemoveSharedDevice(driver, &dev, name));

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI)
            continue;

        if (!(scsi = virSCSIDeviceNew(NULL,
                                      hostdev->source.subsys.u.scsi.adapter,
                                      hostdev->source.subsys.u.scsi.bus,
                                      hostdev->source.subsys.u.scsi.target,
                                      hostdev->source.subsys.u.scsi.unit,
                                      hostdev->readonly,
                                      hostdev->shareable))) {
            VIR_WARN("Unable to reattach SCSI device %s:%d:%d:%d on domain %s",
                     hostdev->source.subsys.u.scsi.adapter,
                     hostdev->source.subsys.u.scsi.bus,
                     hostdev->source.subsys.u.scsi.target,
                     hostdev->source.subsys.u.scsi.unit,
                     name);
            continue;
        }

        /* Only delete the devices which are marked as being used by @name,
         * because qemuProcessStart could fail on the half way. */

        if (!(tmp = virSCSIDeviceListFind(driver->activeScsiHostdevs, scsi))) {
            VIR_WARN("Unable to find device %s:%d:%d:%d "
                     "in list of active SCSI devices",
                     hostdev->source.subsys.u.scsi.adapter,
                     hostdev->source.subsys.u.scsi.bus,
                     hostdev->source.subsys.u.scsi.target,
                     hostdev->source.subsys.u.scsi.unit);
            virSCSIDeviceFree(scsi);
            continue;
        }

        VIR_DEBUG("Removing %s:%d:%d:%d dom=%s from activeScsiHostdevs",
                   hostdev->source.subsys.u.scsi.adapter,
                   hostdev->source.subsys.u.scsi.bus,
                   hostdev->source.subsys.u.scsi.target,
                   hostdev->source.subsys.u.scsi.unit,
                   name);

        virSCSIDeviceListDel(driver->activeScsiHostdevs, tmp, QEMU_DRIVER_NAME, name);
        virSCSIDeviceFree(scsi);
    }
    virObjectUnlock(driver->activeScsiHostdevs);
}

void
qemuDomainReAttachHostDevices(virQEMUDriverPtr driver,
                              virDomainDefPtr def)
{
    if (!def->nhostdevs)
        return;

    qemuDomainReAttachHostdevDevices(driver, def->name, def->hostdevs,
                                     def->nhostdevs);

    qemuDomainReAttachHostUsbDevices(driver, def->name, def->hostdevs,
                                     def->nhostdevs);

    qemuDomainReAttachHostScsiDevices(driver, def->name, def->hostdevs,
                                      def->nhostdevs);
}
