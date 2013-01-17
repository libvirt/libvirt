/*
 * qemu_hostdev.c: QEMU hostdev management
 *
 * Copyright (C) 2006-2007, 2009-2012 Red Hat, Inc.
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

#include "qemu_hostdev.h"
#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virpci.h"
#include "virusb.h"
#include "virnetdev.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

static pciDeviceList *
qemuGetPciHostDeviceList(virDomainHostdevDefPtr *hostdevs, int nhostdevs)
{
    pciDeviceList *list;
    int i;

    if (!(list = pciDeviceListNew()))
        return NULL;

    for (i = 0 ; i < nhostdevs ; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        pciDevice *dev;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        dev = pciGetDevice(hostdev->source.subsys.u.pci.domain,
                           hostdev->source.subsys.u.pci.bus,
                           hostdev->source.subsys.u.pci.slot,
                           hostdev->source.subsys.u.pci.function);
        if (!dev) {
            pciDeviceListFree(list);
            return NULL;
        }

        if (pciDeviceListAdd(list, dev) < 0) {
            pciFreeDevice(dev);
            pciDeviceListFree(list);
            return NULL;
        }

        pciDeviceSetManaged(dev, hostdev->managed);
    }

    return list;
}

static pciDeviceList *
qemuGetActivePciHostDeviceList(virQEMUDriverPtr driver,
                               virDomainHostdevDefPtr *hostdevs,
                               int nhostdevs)
{
    pciDeviceList *list;
    int i;

    if (!(list = pciDeviceListNew()))
        return NULL;

    for (i = 0 ; i < nhostdevs ; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        pciDevice *dev;
        pciDevice *activeDev;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        dev = pciGetDevice(hostdev->source.subsys.u.pci.domain,
                           hostdev->source.subsys.u.pci.bus,
                           hostdev->source.subsys.u.pci.slot,
                           hostdev->source.subsys.u.pci.function);
        if (!dev) {
            pciDeviceListFree(list);
            return NULL;
        }

        if ((activeDev = pciDeviceListFind(driver->activePciHostdevs, dev))) {
            if (pciDeviceListAdd(list, activeDev) < 0) {
                pciFreeDevice(dev);
                pciDeviceListFree(list);
                return NULL;
            }
        }

        pciFreeDevice(dev);
    }

    return list;
}

int qemuUpdateActivePciHostdevs(virQEMUDriverPtr driver,
                                virDomainDefPtr def)
{
    virDomainHostdevDefPtr hostdev = NULL;
    int i;

    if (!def->nhostdevs)
        return 0;

    for (i = 0; i < def->nhostdevs; i++) {
        pciDevice *dev = NULL;
        hostdev = def->hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        dev = pciGetDevice(hostdev->source.subsys.u.pci.domain,
                           hostdev->source.subsys.u.pci.bus,
                           hostdev->source.subsys.u.pci.slot,
                           hostdev->source.subsys.u.pci.function);

        if (!dev)
            return -1;

        pciDeviceSetManaged(dev, hostdev->managed);
        pciDeviceSetUsedBy(dev, def->name);

        /* Setup the original states for the PCI device */
        pciDeviceSetUnbindFromStub(dev, hostdev->origstates.states.pci.unbind_from_stub);
        pciDeviceSetRemoveSlot(dev, hostdev->origstates.states.pci.remove_slot);
        pciDeviceSetReprobe(dev, hostdev->origstates.states.pci.reprobe);

        if (pciDeviceListAdd(driver->activePciHostdevs, dev) < 0) {
            pciFreeDevice(dev);
            return -1;
        }
    }

    return 0;
}

int
qemuUpdateActiveUsbHostdevs(virQEMUDriverPtr driver,
                            virDomainDefPtr def)
{
    virDomainHostdevDefPtr hostdev = NULL;
    int i;

    if (!def->nhostdevs)
        return 0;

    for (i = 0; i < def->nhostdevs; i++) {
        usbDevice *usb = NULL;
        hostdev = def->hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;

        usb = usbGetDevice(hostdev->source.subsys.u.usb.bus,
                           hostdev->source.subsys.u.usb.device,
                           NULL);
        if (!usb) {
            VIR_WARN("Unable to reattach USB device %03d.%03d on domain %s",
                     hostdev->source.subsys.u.usb.bus,
                     hostdev->source.subsys.u.usb.device,
                     def->name);
            continue;
        }

        usbDeviceSetUsedBy(usb, def->name);

        if (usbDeviceListAdd(driver->activeUsbHostdevs, usb) < 0) {
            usbFreeDevice(usb);
            return -1;
        }
    }

    return 0;
}

static int
qemuDomainHostdevPciSysfsPath(virDomainHostdevDefPtr hostdev, char **sysfs_path)
{
    struct pci_config_address config_address;

    config_address.domain = hostdev->source.subsys.u.pci.domain;
    config_address.bus = hostdev->source.subsys.u.pci.bus;
    config_address.slot = hostdev->source.subsys.u.pci.slot;
    config_address.function = hostdev->source.subsys.u.pci.function;

    return pciConfigAddressToSysfsFile(&config_address, sysfs_path);
}

int
qemuDomainHostdevIsVirtualFunction(virDomainHostdevDefPtr hostdev)
{
    char *sysfs_path = NULL;
    int ret = -1;

    if (qemuDomainHostdevPciSysfsPath(hostdev, &sysfs_path) < 0)
        return ret;

    ret = pciDeviceIsVirtualFunction(sysfs_path);

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

    if (pciDeviceIsVirtualFunction(sysfs_path) == 1) {
        if (pciDeviceGetVirtualFunctionInfo(sysfs_path, linkdev,
                                            vf) < 0)
            goto cleanup;
    } else {
        if (pciDeviceNetName(sysfs_path, linkdev) < 0)
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
                                          const virMacAddrPtr macaddr,
                                          const unsigned char *uuid,
                                          int associate)
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
    int port_profile_associate = 1;
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
    int port_profile_associate = 0;
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

int qemuPrepareHostdevPCIDevices(virQEMUDriverPtr driver,
                                 const char *name,
                                 const unsigned char *uuid,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs)
{
    pciDeviceList *pcidevs;
    int last_processed_hostdev_vf = -1;
    int i;
    int ret = -1;

    if (!(pcidevs = qemuGetPciHostDeviceList(hostdevs, nhostdevs)))
        return -1;

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

    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        pciDevice *other;

        if (!pciDeviceIsAssignable(dev, !driver->relaxedACS)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("PCI device %s is not assignable"),
                           pciDeviceGetName(dev));
            goto cleanup;
        }
        /* The device is in use by other active domain if
         * the dev is in list driver->activePciHostdevs.
         */
        if ((other = pciDeviceListFind(driver->activePciHostdevs, dev))) {
            const char *other_name = pciDeviceGetUsedBy(other);

            if (other_name)
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("PCI device %s is in use by domain %s"),
                               pciDeviceGetName(dev), other_name);
            else
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("PCI device %s is already in use"),
                               pciDeviceGetName(dev));
            goto cleanup;
        }
    }

    /* Loop 2: detach managed devices */
    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        if (pciDeviceGetManaged(dev) &&
            pciDettachDevice(dev, driver->activePciHostdevs, NULL, "pci-stub") < 0)
            goto reattachdevs;
    }

    /* Loop 3: Now that all the PCI hostdevs have been detached, we
     * can safely reset them */
    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        if (pciResetDevice(dev, driver->activePciHostdevs,
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
                                                   driver->stateDir) < 0) {
                 goto resetvfnetconfig;
             }
         }
         last_processed_hostdev_vf = i;
    }

    /* Loop 5: Now mark all the devices as active */
    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        if (pciDeviceListAdd(driver->activePciHostdevs, dev) < 0)
            goto inactivedevs;
    }

    /* Loop 6: Now remove the devices from inactive list. */
    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
         pciDevice *dev = pciDeviceListGet(pcidevs, i);
         pciDeviceListDel(driver->inactivePciHostdevs, dev);
    }

    /* Loop 7: Now set the used_by_domain of the device in
     * driver->activePciHostdevs as domain name.
     */
    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev, *activeDev;

        dev = pciDeviceListGet(pcidevs, i);
        activeDev = pciDeviceListFind(driver->activePciHostdevs, dev);

        if (activeDev)
            pciDeviceSetUsedBy(activeDev, name);
    }

    /* Loop 8: Now set the original states for hostdev def */
    for (i = 0; i < nhostdevs; i++) {
        pciDevice *dev;
        pciDevice *pcidev;
        virDomainHostdevDefPtr hostdev = hostdevs[i];

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        dev = pciGetDevice(hostdev->source.subsys.u.pci.domain,
                           hostdev->source.subsys.u.pci.bus,
                           hostdev->source.subsys.u.pci.slot,
                           hostdev->source.subsys.u.pci.function);

        /* original states "unbind_from_stub", "remove_slot",
         * "reprobe" were already set by pciDettachDevice in
         * loop 2.
         */
        if ((pcidev = pciDeviceListFind(pcidevs, dev))) {
            hostdev->origstates.states.pci.unbind_from_stub =
                pciDeviceGetUnbindFromStub(pcidev);
            hostdev->origstates.states.pci.remove_slot =
                pciDeviceGetRemoveSlot(pcidev);
            hostdev->origstates.states.pci.reprobe =
                pciDeviceGetReprobe(pcidev);
        }

        pciFreeDevice(dev);
    }

    /* Loop 9: Now steal all the devices from pcidevs */
    while (pciDeviceListCount(pcidevs) > 0)
        pciDeviceListStealIndex(pcidevs, 0);

    ret = 0;
    goto cleanup;

inactivedevs:
    /* Only steal all the devices from driver->activePciHostdevs. We will
     * free them in pciDeviceListFree().
     */
    while (pciDeviceListCount(pcidevs) > 0) {
        pciDevice *dev = pciDeviceListGet(pcidevs, 0);
        pciDeviceListSteal(driver->activePciHostdevs, dev);
    }

resetvfnetconfig:
    for (i = 0; i < last_processed_hostdev_vf; i++) {
         virDomainHostdevDefPtr hostdev = hostdevs[i];
         if (hostdev->parent.type == VIR_DOMAIN_DEVICE_NET &&
             hostdev->parent.data.net) {
             qemuDomainHostdevNetConfigRestore(hostdev, driver->stateDir);
         }
    }

reattachdevs:
    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        pciReAttachDevice(dev, driver->activePciHostdevs, NULL, "pci-stub");
    }

cleanup:
    pciDeviceListFree(pcidevs);
    return ret;
}

static int
qemuPrepareHostPCIDevices(virQEMUDriverPtr driver,
                          virDomainDefPtr def)
{
    return qemuPrepareHostdevPCIDevices(driver, def->name, def->uuid,
                                        def->hostdevs, def->nhostdevs);
}

int
qemuPrepareHostdevUSBDevices(virQEMUDriverPtr driver,
                             const char *name,
                             usbDeviceList *list)
{
    int i, j;
    unsigned int count;
    usbDevice *tmp;

    count = usbDeviceListCount(list);

    for (i = 0; i < count; i++) {
        usbDevice *usb = usbDeviceListGet(list, i);
        if ((tmp = usbDeviceListFind(driver->activeUsbHostdevs, usb))) {
            const char *other_name = usbDeviceGetUsedBy(tmp);

            if (other_name)
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("USB device %s is in use by domain %s"),
                               usbDeviceGetName(tmp), other_name);
            else
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("USB device %s is already in use"),
                               usbDeviceGetName(tmp));
            goto error;
        }

        usbDeviceSetUsedBy(usb, name);
        VIR_DEBUG("Adding %03d.%03d dom=%s to activeUsbHostdevs",
                  usbDeviceGetBus(usb), usbDeviceGetDevno(usb), name);
        /*
         * The caller is responsible to steal these usb devices
         * from the usbDeviceList that passed in on success,
         * perform rollback on failure.
         */
        if (usbDeviceListAdd(driver->activeUsbHostdevs, usb) < 0)
            goto error;
    }
    return 0;

error:
    for (j = 0; j < i; j++) {
        tmp = usbDeviceListGet(list, i);
        usbDeviceListSteal(driver->activeUsbHostdevs, tmp);
    }
    return -1;
}

int
qemuFindHostdevUSBDevice(virDomainHostdevDefPtr hostdev,
                         bool mandatory,
                         usbDevice **usb)
{
    unsigned vendor = hostdev->source.subsys.u.usb.vendor;
    unsigned product = hostdev->source.subsys.u.usb.product;
    unsigned bus = hostdev->source.subsys.u.usb.bus;
    unsigned device = hostdev->source.subsys.u.usb.device;
    bool autoAddress = hostdev->source.subsys.u.usb.autoAddress;
    int rc;

    *usb = NULL;

    if (vendor && bus) {
        rc = usbFindDevice(vendor, product, bus, device,
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
        usbDeviceList *devs;

        rc = usbFindDeviceByVendor(vendor, product, NULL, mandatory, &devs);
        if (rc < 0)
            return -1;

        if (rc == 1) {
            *usb = usbDeviceListGet(devs, 0);
            usbDeviceListSteal(devs, *usb);
        }
        usbDeviceListFree(devs);

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

        hostdev->source.subsys.u.usb.bus = usbDeviceGetBus(*usb);
        hostdev->source.subsys.u.usb.device = usbDeviceGetDevno(*usb);
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
        if (usbFindDeviceByBus(bus, device, NULL, mandatory, usb) < 0)
            return -1;
    }

out:
    if (!*usb)
        hostdev->missing = 1;
    return 0;
}

static int
qemuPrepareHostUSBDevices(virQEMUDriverPtr driver,
                          virDomainDefPtr def,
                          bool coldBoot)
{
    int i, ret = -1;
    usbDeviceList *list;
    usbDevice *tmp;
    virDomainHostdevDefPtr *hostdevs = def->hostdevs;
    int nhostdevs = def->nhostdevs;

    /* To prevent situation where USB device is assigned to two domains
     * we need to keep a list of currently assigned USB devices.
     * This is done in several loops which cannot be joined into one big
     * loop. See qemuPrepareHostdevPCIDevices()
     */
    if (!(list = usbDeviceListNew()))
        goto cleanup;

    /* Loop 1: build temporary list
     */
    for (i = 0 ; i < nhostdevs ; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        bool required = true;
        usbDevice *usb;

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

        if (usb && usbDeviceListAdd(list, usb) < 0) {
            usbFreeDevice(usb);
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
    while (usbDeviceListCount(list) > 0) {
        tmp = usbDeviceListGet(list, 0);
        usbDeviceListSteal(list, tmp);
    }

    ret = 0;

cleanup:
    usbDeviceListFree(list);
    return ret;
}

int qemuPrepareHostDevices(virQEMUDriverPtr driver,
                           virDomainDefPtr def,
                           bool coldBoot)
{
    if (!def->nhostdevs)
        return 0;

    if (qemuPrepareHostPCIDevices(driver, def) < 0)
        return -1;

    if (qemuPrepareHostUSBDevices(driver, def, coldBoot) < 0)
        return -1;

    return 0;
}


void qemuReattachPciDevice(pciDevice *dev, virQEMUDriverPtr driver)
{
    int retries = 100;

    /* If the device is not managed and was attached to guest
     * successfully, it must have been inactive.
     */
    if (!pciDeviceGetManaged(dev)) {
        if (pciDeviceListAdd(driver->inactivePciHostdevs, dev) < 0)
            pciFreeDevice(dev);
        return;
    }

    while (pciWaitForDeviceCleanup(dev, "kvm_assigned_device")
           && retries) {
        usleep(100*1000);
        retries--;
    }

    if (pciReAttachDevice(dev, driver->activePciHostdevs,
                          driver->inactivePciHostdevs, "pci-stub") < 0) {
        virErrorPtr err = virGetLastError();
        VIR_ERROR(_("Failed to re-attach PCI device: %s"),
                  err ? err->message : _("unknown error"));
        virResetError(err);
    }
    pciFreeDevice(dev);
}


void qemuDomainReAttachHostdevDevices(virQEMUDriverPtr driver,
                                      const char *name,
                                      virDomainHostdevDefPtr *hostdevs,
                                      int nhostdevs)
{
    pciDeviceList *pcidevs;
    int i;

    if (!(pcidevs = qemuGetActivePciHostDeviceList(driver,
                                                   hostdevs,
                                                   nhostdevs))) {
        virErrorPtr err = virGetLastError();
        VIR_ERROR(_("Failed to allocate pciDeviceList: %s"),
                  err ? err->message : _("unknown error"));
        virResetError(err);
        return;
    }

    /* Again 4 loops; mark all devices as inactive before reset
     * them and reset all the devices before re-attach.
     * Attach mac and port profile parameters to devices
     */
    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        pciDevice *activeDev = NULL;

        /* Never delete the dev from list driver->activePciHostdevs
         * if it's used by other domain.
         */
        activeDev = pciDeviceListFind(driver->activePciHostdevs, dev);
        if (activeDev &&
            STRNEQ_NULLABLE(name, pciDeviceGetUsedBy(activeDev))) {
            pciDeviceListSteal(pcidevs, dev);
            continue;
        }

        /* pciDeviceListFree() will take care of freeing the dev. */
        pciDeviceListSteal(driver->activePciHostdevs, dev);
    }

    /*
     * For SRIOV net host devices, unset mac and port profile before
     * reset and reattach device
     */
    for (i = 0; i < nhostdevs; i++) {
         virDomainHostdevDefPtr hostdev = hostdevs[i];
         if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
             continue;
         if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
             continue;
         if (hostdev->parent.type == VIR_DOMAIN_DEVICE_NET &&
             hostdev->parent.data.net) {
             qemuDomainHostdevNetConfigRestore(hostdev, driver->stateDir);
         }
    }

    for (i = 0; i < pciDeviceListCount(pcidevs); i++) {
        pciDevice *dev = pciDeviceListGet(pcidevs, i);
        if (pciResetDevice(dev, driver->activePciHostdevs,
                           driver->inactivePciHostdevs) < 0) {
            virErrorPtr err = virGetLastError();
            VIR_ERROR(_("Failed to reset PCI device: %s"),
                      err ? err->message : _("unknown error"));
            virResetError(err);
        }
    }

    while (pciDeviceListCount(pcidevs) > 0) {
        pciDevice *dev = pciDeviceListStealIndex(pcidevs, 0);
        qemuReattachPciDevice(dev, driver);
    }

    pciDeviceListFree(pcidevs);
}

static void
qemuDomainReAttachHostUsbDevices(virQEMUDriverPtr driver,
                                 const char *name,
                                 virDomainHostdevDefPtr *hostdevs,
                                 int nhostdevs)
{
    int i;

    for (i = 0; i < nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = hostdevs[i];
        usbDevice *usb, *tmp;
        const char *used_by = NULL;

        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)
            continue;
        if (hostdev->missing)
            continue;

        usb = usbGetDevice(hostdev->source.subsys.u.usb.bus,
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

        tmp = usbDeviceListFind(driver->activeUsbHostdevs, usb);
        usbFreeDevice(usb);

        if (!tmp) {
            VIR_WARN("Unable to find device %03d.%03d "
                     "in list of active USB devices",
                     hostdev->source.subsys.u.usb.bus,
                     hostdev->source.subsys.u.usb.device);
            continue;
        }

        used_by = usbDeviceGetUsedBy(tmp);
        if (STREQ_NULLABLE(used_by, name)) {
            VIR_DEBUG("Removing %03d.%03d dom=%s from activeUsbHostdevs",
                      hostdev->source.subsys.u.usb.bus,
                      hostdev->source.subsys.u.usb.device,
                      name);

            usbDeviceListDel(driver->activeUsbHostdevs, tmp);
        }
    }
}

void qemuDomainReAttachHostDevices(virQEMUDriverPtr driver,
                                   virDomainDefPtr def)
{
    if (!def->nhostdevs)
        return;

    qemuDomainReAttachHostdevDevices(driver, def->name, def->hostdevs,
                                     def->nhostdevs);

    qemuDomainReAttachHostUsbDevices(driver, def->name, def->hostdevs,
                                     def->nhostdevs);
}
