/*
 * qemu_domain_address.c: QEMU domain address
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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
 */

#include <config.h>

#include "qemu_domain_address.h"
#include "qemu_domain.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_domain_address");

#define VIO_ADDR_NET 0x1000ul
#define VIO_ADDR_SCSI 0x2000ul
#define VIO_ADDR_SERIAL 0x30000000ul
#define VIO_ADDR_NVRAM 0x3000ul


/**
 * @def: Domain definition
 * @cont: Domain controller def
 * @qemuCaps: qemu capabilities
 *
 * If the controller model is already defined, return it immediately;
 * otherwise, based on the @qemuCaps return a default model value.
 *
 * Returns model on success, -1 on failure with error set.
 */
int
qemuDomainGetSCSIControllerModel(const virDomainDef *def,
                                 const virDomainControllerDef *cont,
                                 virQEMUCapsPtr qemuCaps)
{
    if (cont->model > 0)
        return cont->model;

    if (qemuDomainIsPSeries(def))
        return VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI;
    else if (ARCH_IS_S390(def->os.arch))
        return VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI;
    else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_LSI))
        return VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC;
    else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_SCSI))
        return VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI;

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unable to determine model for SCSI controller idx=%d"),
                   cont->idx);
    return -1;
}


/**
 * @def: Domain definition
 * @cont: Domain controller def
 * @qemuCaps: qemu capabilities
 *
 * Set the controller model based on the existing value and the
 * capabilities if possible.
 *
 * Returns 0 on success, -1 on failure with error set.
 */
int
qemuDomainSetSCSIControllerModel(const virDomainDef *def,
                                 virDomainControllerDefPtr cont,
                                 virQEMUCapsPtr qemuCaps)
{
    int model = qemuDomainGetSCSIControllerModel(def, cont, qemuCaps);

    if (model < 0)
        return -1;

    cont->model = model;
    return 0;
}


/**
 * @def: Domain definition
 * @info: Domain device info
 *
 * Using the device info, find the controller related to the
 * device by index and use that controller to return the model.
 *
 * Returns the model if found, -1 if not with an error message set
 */
int
qemuDomainFindSCSIControllerModel(const virDomainDef *def,
                                  virDomainDeviceInfoPtr info)
{
    virDomainControllerDefPtr cont;

    if (!(cont = virDomainDeviceFindSCSIController(def, info))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to find a SCSI controller for idx=%d"),
                       info->addr.drive.controller);
        return -1;
    }

    return cont->model;
}


static int
qemuDomainAssignVirtioSerialAddresses(virDomainDefPtr def)
{
    int ret = -1;
    size_t i;
    virDomainVirtioSerialAddrSetPtr addrs = NULL;

    if (!(addrs = virDomainVirtioSerialAddrSetCreateFromDomain(def)))
        goto cleanup;

    VIR_DEBUG("Finished reserving existing ports");

    for (i = 0; i < def->nconsoles; i++) {
        virDomainChrDefPtr chr = def->consoles[i];
        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
            chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO &&
            !virDomainVirtioSerialAddrIsComplete(&chr->info) &&
            virDomainVirtioSerialAddrAutoAssignFromCache(def, addrs,
                                                         &chr->info, true) < 0)
            goto cleanup;
    }

    for (i = 0; i < def->nchannels; i++) {
        virDomainChrDefPtr chr = def->channels[i];
        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
            chr->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO &&
            !virDomainVirtioSerialAddrIsComplete(&chr->info) &&
            virDomainVirtioSerialAddrAutoAssignFromCache(def, addrs,
                                                         &chr->info, false) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virDomainVirtioSerialAddrSetFree(addrs);
    return ret;
}


static int
qemuDomainSpaprVIOFindByReg(virDomainDefPtr def ATTRIBUTE_UNUSED,
                            virDomainDeviceDefPtr device ATTRIBUTE_UNUSED,
                            virDomainDeviceInfoPtr info, void *opaque)
{
    virDomainDeviceInfoPtr target = opaque;

    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO)
        return 0;

    /* Match a dev that has a reg, is not us, and has a matching reg */
    if (info->addr.spaprvio.has_reg && info != target &&
        info->addr.spaprvio.reg == target->addr.spaprvio.reg)
        /* Has to be < 0 so virDomainDeviceInfoIterate() will exit */
        return -1;

    return 0;
}


static int
qemuDomainAssignSpaprVIOAddress(virDomainDefPtr def,
                                virDomainDeviceInfoPtr info,
                                unsigned long long default_reg)
{
    bool user_reg;
    int ret;

    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO)
        return 0;

    /* Check if the user has assigned the reg already, if so use it */
    user_reg = info->addr.spaprvio.has_reg;
    if (!user_reg) {
        info->addr.spaprvio.reg = default_reg;
        info->addr.spaprvio.has_reg = true;
    }

    ret = virDomainDeviceInfoIterate(def, qemuDomainSpaprVIOFindByReg, info);
    while (ret != 0) {
        if (user_reg) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("spapr-vio address %#llx already in use"),
                           info->addr.spaprvio.reg);
            return -EEXIST;
        }

        /* We assigned the reg, so try a new value */
        info->addr.spaprvio.reg += 0x1000;
        ret = virDomainDeviceInfoIterate(def, qemuDomainSpaprVIOFindByReg,
                                         info);
    }

    return 0;
}


static int
qemuDomainAssignSpaprVIOAddresses(virDomainDefPtr def)
{
    size_t i;
    int ret = -1;

    /* Default values match QEMU. See spapr_(llan|vscsi|vty).c */

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];

        if (STREQ_NULLABLE(net->model, "spapr-vlan"))
            net->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;

        if (qemuDomainAssignSpaprVIOAddress(def, &net->info, VIO_ADDR_NET) < 0)
            goto cleanup;
    }

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = def->controllers[i];

        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI &&
            cont->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            cont->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        }
        if (qemuDomainAssignSpaprVIOAddress(def, &cont->info,
                                            VIO_ADDR_SCSI) < 0) {
            goto cleanup;
        }
    }

    for (i = 0; i < def->nserials; i++) {
        if (def->serials[i]->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
            def->serials[i]->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SPAPR_VIO) {
            def->serials[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        }
        if (qemuDomainAssignSpaprVIOAddress(def, &def->serials[i]->info,
                                            VIO_ADDR_SERIAL) < 0)
            goto cleanup;
    }

    if (def->nvram) {
        if (qemuDomainIsPSeries(def))
            def->nvram->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        if (qemuDomainAssignSpaprVIOAddress(def, &def->nvram->info,
                                            VIO_ADDR_NVRAM) < 0)
            goto cleanup;
    }

    /* No other devices are currently supported on spapr-vio */

    ret = 0;

 cleanup:
    return ret;
}


static void
qemuDomainPrimeVfioDeviceAddresses(virDomainDefPtr def,
                                   virDomainDeviceAddressType type)
{
    size_t i;

    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevSubsysPtr subsys = &def->hostdevs[i]->source.subsys;

        if (virHostdevIsMdevDevice(def->hostdevs[i]) &&
            subsys->u.mdev.model == VIR_MDEV_MODEL_TYPE_VFIO_CCW &&
            def->hostdevs[i]->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->hostdevs[i]->info->type = type;

        if (virHostdevIsMdevDevice(def->hostdevs[i]) &&
            subsys->u.mdev.model == VIR_MDEV_MODEL_TYPE_VFIO_AP)
            def->hostdevs[i]->info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE;
    }
}


static void
qemuDomainPrimeVirtioDeviceAddresses(virDomainDefPtr def,
                                     virDomainDeviceAddressType type)
{
    /*
       declare address-less virtio devices to be of address type 'type'
       disks, networks, videos, consoles, controllers, memballoon and rng
       in this order
       if type is ccw filesystem and vsock devices are declared to be of
       address type ccw
    */
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i]->bus == VIR_DOMAIN_DISK_BUS_VIRTIO &&
            def->disks[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->disks[i]->info.type = type;
    }

    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];

        if (virDomainNetIsVirtioModel(net) &&
            net->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            net->info.type = type;
        }
    }

    for (i = 0; i < def->nvideos; i++) {
        virDomainVideoDefPtr video = def->videos[i];

        if (video->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            video->type == VIR_DOMAIN_VIDEO_TYPE_VIRTIO)
            video->info.type = type;
    }

    for (i = 0; i < def->ninputs; i++) {
        if (def->inputs[i]->bus == VIR_DOMAIN_INPUT_BUS_VIRTIO &&
            def->inputs[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->inputs[i]->info.type = type;
    }

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = def->controllers[i];

        if ((cont->type == VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL ||
             cont->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) &&
            cont->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            cont->info.type = type;
        }
    }

    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            def->hostdevs[i]->source.subsys.type ==
            VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST &&
            def->hostdevs[i]->info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->hostdevs[i]->info->type = type;
    }

    /* All memballoon devices accepted by the qemu driver are virtio */
    if (virDomainDefHasMemballoon(def) &&
        def->memballoon->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
        def->memballoon->info.type = type;

    for (i = 0; i < def->nrngs; i++) {
        /* All <rng> devices accepted by the qemu driver are virtio */
        if (def->rngs[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->rngs[i]->info.type = type;
    }

    if (type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
        for (i = 0; i < def->nfss; i++) {
            if (def->fss[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
                def->fss[i]->info.type = type;
        }
        if (def->vsock &&
            def->vsock->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            def->vsock->info.type = type;
        }
    }
}


/*
 * Three steps populating CCW devnos
 * 1. Allocate empty address set
 * 2. Gather addresses with explicit devno
 * 3. Assign defaults to the rest
 */
static int
qemuDomainAssignS390Addresses(virDomainDefPtr def,
                              virQEMUCapsPtr qemuCaps)
{
    int ret = -1;
    virDomainCCWAddressSetPtr addrs = NULL;

    if (qemuDomainIsS390CCW(def) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_CCW)) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VFIO_CCW))
            qemuDomainPrimeVfioDeviceAddresses(
                def, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW);
        qemuDomainPrimeVirtioDeviceAddresses(
            def, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW);

        if (!(addrs = virDomainCCWAddressSetCreateFromDomain(def)))
            goto cleanup;

    } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_S390)) {
        /* deal with legacy virtio-s390 */
        qemuDomainPrimeVirtioDeviceAddresses(
            def, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390);
    }

    ret = 0;

 cleanup:
    virDomainCCWAddressSetFree(addrs);

    return ret;
}


static int
qemuDomainHasVirtioMMIODevicesCallback(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                       virDomainDeviceDefPtr dev ATTRIBUTE_UNUSED,
                                       virDomainDeviceInfoPtr info,
                                       void *opaque)
{
    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO) {
        /* We can stop iterating as soon as we find the first
         * virtio-mmio device */
        *((bool *)opaque) = true;
        return -1;
    }

    return 0;
}


/**
 * qemuDomainHasVirtioMMIODevices:
 * @def: domain definition
 *
 * Scan @def looking for devices with a virtio-mmio address.
 *
 * Returns: true if there are any, false otherwise
 */
static bool
qemuDomainHasVirtioMMIODevices(virDomainDefPtr def)
{
    bool result = false;

    virDomainDeviceInfoIterate(def,
                               qemuDomainHasVirtioMMIODevicesCallback,
                               &result);

    return result;
}


static void
qemuDomainAssignVirtioMMIOAddresses(virDomainDefPtr def,
                                    virQEMUCapsPtr qemuCaps)
{
    if (def->os.arch != VIR_ARCH_ARMV6L &&
        def->os.arch != VIR_ARCH_ARMV7L &&
        def->os.arch != VIR_ARCH_AARCH64 &&
        !ARCH_IS_RISCV(def->os.arch)) {
        return;
    }

    if (!(STRPREFIX(def->os.machine, "vexpress-") ||
          qemuDomainIsARMVirt(def) ||
          qemuDomainIsRISCVVirt(def))) {
        return;
    }

    /* We use virtio-mmio by default on virt guests only if they already
     * have at least one virtio-mmio device: in all other cases, assuming
     * the QEMU binary supports all necessary capabilities (PCIe Root plus
     * some kind of PCIe Root Port), we prefer virtio-pci */
    if (qemuDomainHasPCIeRoot(def) &&
        (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PCIE_ROOT_PORT) ||
         virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_IOH3420)) &&
        !qemuDomainHasVirtioMMIODevices(def)) {
        qemuDomainPrimeVirtioDeviceAddresses(def,
                                             VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI);
    } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_MMIO)) {
        qemuDomainPrimeVirtioDeviceAddresses(def,
                                             VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO);
    }
}


static bool
qemuDomainDeviceSupportZPCI(virDomainDeviceDefPtr device)
{
    switch ((virDomainDeviceType)device->type) {
    case VIR_DOMAIN_DEVICE_CHR:
        return false;

    case VIR_DOMAIN_DEVICE_CONTROLLER:
    case VIR_DOMAIN_DEVICE_DISK:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_VSOCK:
        break;

    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_LAST:
    default:
        virReportEnumRangeError(virDomainDeviceType, device->type);
        return false;
    }

    return true;
}


static virPCIDeviceAddressExtensionFlags
qemuDomainDeviceCalculatePCIAddressExtensionFlags(virQEMUCapsPtr qemuCaps,
                                                  virDomainDeviceDefPtr dev)
{
    virPCIDeviceAddressExtensionFlags extFlags = 0;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_ZPCI) &&
        qemuDomainDeviceSupportZPCI(dev)) {
        extFlags |= VIR_PCI_ADDRESS_EXTENSION_ZPCI;
    }

    return extFlags;
}


/**
 * qemuDomainDeviceCalculatePCIConnectFlags:
 *
 * @dev: The device to be checked
 * @pcieFlags: flags to use for a known PCI Express device
 * @virtioFlags: flags to use for a virtio device (properly vetted
 *       for the current qemu binary and arch/machinetype)
 *
 * Lowest level function to determine PCI connectFlags for a
 * device. This function relies on the next higher-level function
 * determining the value for pcieFlags and virtioFlags in advance -
 * this is to make it more efficient to call multiple times.
 *
 * Returns appropriate virDomainPCIConnectFlags for this device in
 * this domain, or 0 if the device doesn't connect using PCI. There
 * is no failure.
 */
static virDomainPCIConnectFlags
qemuDomainDeviceCalculatePCIConnectFlags(virDomainDeviceDefPtr dev,
                                         virQEMUDriverPtr driver,
                                         virDomainPCIConnectFlags pcieFlags,
                                         virDomainPCIConnectFlags virtioFlags)
{
    virDomainPCIConnectFlags pciFlags = (VIR_PCI_CONNECT_TYPE_PCI_DEVICE |
                                         VIR_PCI_CONNECT_HOTPLUGGABLE);

    switch ((virDomainDeviceType)dev->type) {
    case VIR_DOMAIN_DEVICE_CONTROLLER: {
        virDomainControllerDefPtr cont = dev->data.controller;

        switch ((virDomainControllerType)cont->type) {
        case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
            return virDomainPCIControllerModelToConnectType(cont->model);

        case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
            return pciFlags;

        case VIR_DOMAIN_CONTROLLER_TYPE_USB:
            switch ((virDomainControllerModelUSB) cont->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_DEFAULT:
                /* qemuDomainControllerDefPostParse should have
                 * changed 'model' to an explicit USB model in
                 * most cases. Since we're still on the default
                 * though, we must be going to use "-usb", which
                 * is assumed to be a PCI default
                 */
                return pciFlags;

            case VIR_DOMAIN_CONTROLLER_MODEL_USB_NEC_XHCI:
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_QEMU_XHCI:
                return pcieFlags;

            case VIR_DOMAIN_CONTROLLER_MODEL_USB_EHCI:
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1:
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1:
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2:
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3:
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_VT82C686B_UHCI:
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI:
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX4_UHCI:
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_PCI_OHCI:
                return pciFlags;

            case VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB1: /* xen only */
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2: /* xen only */
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE:
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_LAST:
                return 0;
            }
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
            return pciFlags;

        case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
            switch ((virDomainControllerModelSCSI) cont->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DEFAULT:
                return 0;

            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_NON_TRANSITIONAL:
                return virtioFlags;

            /* Transitional devices only work in conventional PCI slots */
            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_TRANSITIONAL:
            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO:
            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_BUSLOGIC:
            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC:
            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068:
            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VMPVSCSI:
            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI:
            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1078:
                return pciFlags;

            case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LAST:
                return 0;
            }
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
            switch ((virDomainControllerModelVirtioSerial) cont->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_VIRTIO_SERIAL_VIRTIO_TRANSITIONAL:
                /* Transitional devices only work in conventional PCI slots */
                return pciFlags;

            case VIR_DOMAIN_CONTROLLER_MODEL_VIRTIO_SERIAL_VIRTIO:
            case VIR_DOMAIN_CONTROLLER_MODEL_VIRTIO_SERIAL_VIRTIO_NON_TRANSITIONAL:
            case VIR_DOMAIN_CONTROLLER_MODEL_VIRTIO_SERIAL_DEFAULT:
                return virtioFlags;

            case VIR_DOMAIN_CONTROLLER_MODEL_VIRTIO_SERIAL_LAST:
                return 0;
            }
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
        case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
        case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
        case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
            /* should be 0 */
            return pciFlags;
        }
    }
        break;

    case VIR_DOMAIN_DEVICE_FS:
        /* the only type of filesystem so far is virtio-9p-pci */
        switch ((virDomainFSModel) dev->data.fs->model) {
        case VIR_DOMAIN_FS_MODEL_VIRTIO_TRANSITIONAL:
            /* Transitional devices only work in conventional PCI slots */
            return pciFlags;
        case VIR_DOMAIN_FS_MODEL_VIRTIO:
        case VIR_DOMAIN_FS_MODEL_VIRTIO_NON_TRANSITIONAL:
        case VIR_DOMAIN_FS_MODEL_DEFAULT:
            return virtioFlags;
        case VIR_DOMAIN_FS_MODEL_LAST:
            break;
        }
        return 0;

    case VIR_DOMAIN_DEVICE_NET: {
        virDomainNetDefPtr net = dev->data.net;

        /* NB: a type='hostdev' will use PCI, but its
         * address is assigned when we're assigning the
         * addresses for other hostdev devices.
         */
        if (net->type == VIR_DOMAIN_NET_TYPE_HOSTDEV ||
            STREQ_NULLABLE(net->model, "usb-net")) {
            return 0;
        }

        if (STREQ_NULLABLE(net->model, "virtio") ||
            STREQ_NULLABLE(net->model, "virtio-non-transitional"))
            return virtioFlags;

        /* Transitional devices only work in conventional PCI slots */
        if (STREQ_NULLABLE(net->model, "virtio-transitional"))
            return pciFlags;

        if (STREQ_NULLABLE(net->model, "e1000e"))
            return pcieFlags;

        return pciFlags;
    }

    case VIR_DOMAIN_DEVICE_SOUND:
        switch ((virDomainSoundModel) dev->data.sound->model) {
        case VIR_DOMAIN_SOUND_MODEL_ES1370:
        case VIR_DOMAIN_SOUND_MODEL_AC97:
        case VIR_DOMAIN_SOUND_MODEL_ICH6:
        case VIR_DOMAIN_SOUND_MODEL_ICH9:
            return pciFlags;

        case VIR_DOMAIN_SOUND_MODEL_SB16:
        case VIR_DOMAIN_SOUND_MODEL_PCSPK:
        case VIR_DOMAIN_SOUND_MODEL_USB:
        case VIR_DOMAIN_SOUND_MODEL_LAST:
            return 0;
        }
        break;

    case VIR_DOMAIN_DEVICE_DISK:
        switch ((virDomainDiskBus) dev->data.disk->bus) {
        case VIR_DOMAIN_DISK_BUS_VIRTIO:
            /* only virtio disks use PCI */
            switch ((virDomainDiskModel) dev->data.disk->model) {
            case VIR_DOMAIN_DISK_MODEL_VIRTIO_TRANSITIONAL:
                /* Transitional devices only work in conventional PCI slots */
                return pciFlags;
            case VIR_DOMAIN_DISK_MODEL_VIRTIO:
            case VIR_DOMAIN_DISK_MODEL_VIRTIO_NON_TRANSITIONAL:
            case VIR_DOMAIN_DISK_MODEL_DEFAULT:
                return virtioFlags;
            case VIR_DOMAIN_DISK_MODEL_LAST:
                break;
            }
            return 0;

        case VIR_DOMAIN_DISK_BUS_IDE:
        case VIR_DOMAIN_DISK_BUS_FDC:
        case VIR_DOMAIN_DISK_BUS_SCSI:
        case VIR_DOMAIN_DISK_BUS_XEN:
        case VIR_DOMAIN_DISK_BUS_USB:
        case VIR_DOMAIN_DISK_BUS_UML:
        case VIR_DOMAIN_DISK_BUS_SATA:
        case VIR_DOMAIN_DISK_BUS_SD:
        case VIR_DOMAIN_DISK_BUS_LAST:
            return 0;
        }
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV: {
        virDomainHostdevDefPtr hostdev = dev->data.hostdev;
        bool isExpress = false;
        virPCIDevicePtr pciDev;
        virPCIDeviceAddressPtr hostAddr = &hostdev->source.subsys.u.pci.addr;

        if (!virHostdevIsMdevDevice(hostdev) &&
            (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
             (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
              hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST))) {
            return 0;
        }

        if (pciFlags == pcieFlags) {
            /* This arch/qemu only supports legacy PCI, so there
             * is no point in checking if the device is an Express
             * device.
             */
            return pciFlags;
        }

        if (virDeviceInfoPCIAddressIsPresent(hostdev->info)) {
            /* A guest-side address has already been assigned, so
             * we can avoid reading the PCI config, and just use
             * pcieFlags, since the pciConnectFlags checking is
             * more relaxed when an address is already assigned
             * than it is when we're looking for a new address (so
             * validation will pass regardless of whether we set
             * the flags to PCI or PCIe).
             */
            return pcieFlags;
        }

        /* mdevs don't have corresponding files in /sys that we can poke to
         * try and figure out whether they are legacy PCI or PCI Express, so
         * the logic below would never work; instead, we just go ahead and
         * assume they're PCI Express. This is a very reasonable assumption,
         * as all current mdev-capable devices are indeed PCI Express */
        if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV)
            return pcieFlags;

        /* according to pbonzini, from the guest PoV vhost-scsi devices
         * are the same as virtio-scsi, so they should follow virtio logic
         */
        if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST) {
            switch ((virDomainHostdevSubsysSCSIVHostModelType) hostdev->source.subsys.u.scsi_host.model) {
            case VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_VHOST_MODEL_TYPE_VIRTIO_TRANSITIONAL:
                /* Transitional devices only work in conventional PCI slots */
                return pciFlags;
            case VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_VHOST_MODEL_TYPE_VIRTIO:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_VHOST_MODEL_TYPE_VIRTIO_NON_TRANSITIONAL:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_VHOST_MODEL_TYPE_DEFAULT:
                return virtioFlags;
            case VIR_DOMAIN_HOSTDEV_SUBSYS_SCSI_VHOST_MODEL_TYPE_LAST:
                break;
            }
            return 0;
        }

        if (!(pciDev = virPCIDeviceNew(hostAddr->domain,
                                       hostAddr->bus,
                                       hostAddr->slot,
                                       hostAddr->function))) {
            /* libvirt should be able to perform all the
             * operations in virPCIDeviceNew() even if it's
             * running unprivileged, so if this fails, the device
             * apparently doesn't currently exist on the host.
             * Since the overwhelming majority of assignable host
             * devices are PCIe, assume this one is too.
             */
            return pcieFlags;
        }

        if (!driver->privileged) {
            /* unprivileged libvirtd is unable to read *all* of a
             * device's PCI config (it can only read the first 64
             * bytes, which isn't enough for the check that's done
             * in virPCIDeviceIsPCIExpress()), so instead of
             * trying and failing, we make an educated guess based
             * on the length of the device's config file - if it
             * is 256 bytes, then it is definitely a legacy PCI
             * device. If it's larger than that, then it is
             * *probably PCIe (although it could be PCI-x, but
             * those are extremely rare). If the config file can't
             * be found (in which case the "length" will be -1),
             * then we blindly assume the most likely outcome -
             * PCIe.
             */
            off_t configLen
               = virFileLength(virPCIDeviceGetConfigPath(pciDev), -1);

            virPCIDeviceFree(pciDev);

            if (configLen == 256)
                return pciFlags;

            return pcieFlags;
        }

        /* If we are running with privileges, we can examine the
         * PCI config contents with virPCIDeviceIsPCIExpress() for
         * a definitive answer.
         */
        isExpress = virPCIDeviceIsPCIExpress(pciDev);
        virPCIDeviceFree(pciDev);

        if (isExpress)
            return pcieFlags;

        return pciFlags;
    }

    case VIR_DOMAIN_DEVICE_MEMBALLOON:
        switch ((virDomainMemballoonModel) dev->data.memballoon->model) {
        case VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO_TRANSITIONAL:
            /* Transitional devices only work in conventional PCI slots */
            return pciFlags;
        case VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO:
        case VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO_NON_TRANSITIONAL:
            return virtioFlags;

        case VIR_DOMAIN_MEMBALLOON_MODEL_XEN:
        case VIR_DOMAIN_MEMBALLOON_MODEL_NONE:
        case VIR_DOMAIN_MEMBALLOON_MODEL_LAST:
            return 0;
        }
        break;

    case VIR_DOMAIN_DEVICE_RNG:
        switch ((virDomainRNGModel) dev->data.rng->model) {
        case VIR_DOMAIN_RNG_MODEL_VIRTIO_TRANSITIONAL:
            /* Transitional devices only work in conventional PCI slots */
            return pciFlags;
        case VIR_DOMAIN_RNG_MODEL_VIRTIO:
        case VIR_DOMAIN_RNG_MODEL_VIRTIO_NON_TRANSITIONAL:
            return virtioFlags;

        case VIR_DOMAIN_RNG_MODEL_LAST:
            return 0;
        }
        break;

    case VIR_DOMAIN_DEVICE_WATCHDOG:
        /* only one model connects using PCI */
        switch ((virDomainWatchdogModel) dev->data.watchdog->model) {
        case VIR_DOMAIN_WATCHDOG_MODEL_I6300ESB:
            return pciFlags;

        case VIR_DOMAIN_WATCHDOG_MODEL_IB700:
        case VIR_DOMAIN_WATCHDOG_MODEL_DIAG288:
        case VIR_DOMAIN_WATCHDOG_MODEL_LAST:
            return 0;
        }
        break;

    case VIR_DOMAIN_DEVICE_VIDEO:
        switch ((virDomainVideoType)dev->data.video->type) {
        case VIR_DOMAIN_VIDEO_TYPE_VIRTIO:
            return virtioFlags;

        case VIR_DOMAIN_VIDEO_TYPE_VGA:
        case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
        case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
        case VIR_DOMAIN_VIDEO_TYPE_XEN:
        case VIR_DOMAIN_VIDEO_TYPE_VBOX:
        case VIR_DOMAIN_VIDEO_TYPE_QXL:
        case VIR_DOMAIN_VIDEO_TYPE_PARALLELS:
            return pciFlags;

        case VIR_DOMAIN_VIDEO_TYPE_DEFAULT:
        case VIR_DOMAIN_VIDEO_TYPE_GOP:
        case VIR_DOMAIN_VIDEO_TYPE_NONE:
        case VIR_DOMAIN_VIDEO_TYPE_LAST:
            return 0;
        }
        break;

    case VIR_DOMAIN_DEVICE_SHMEM:
        return pciFlags;

    case VIR_DOMAIN_DEVICE_INPUT:
        switch ((virDomainInputBus) dev->data.input->bus) {
        case VIR_DOMAIN_INPUT_BUS_VIRTIO:
            switch ((virDomainInputModel) dev->data.input->model) {
            case VIR_DOMAIN_INPUT_MODEL_VIRTIO_TRANSITIONAL:
                /* Transitional devices only work in conventional PCI slots */
                return pciFlags;
            case VIR_DOMAIN_INPUT_MODEL_VIRTIO:
            case VIR_DOMAIN_INPUT_MODEL_VIRTIO_NON_TRANSITIONAL:
            case VIR_DOMAIN_INPUT_MODEL_DEFAULT:
                return virtioFlags;
            case VIR_DOMAIN_INPUT_MODEL_LAST:
                break;
            }
            return 0;

        case VIR_DOMAIN_INPUT_BUS_PS2:
        case VIR_DOMAIN_INPUT_BUS_USB:
        case VIR_DOMAIN_INPUT_BUS_XEN:
        case VIR_DOMAIN_INPUT_BUS_PARALLELS:
        case VIR_DOMAIN_INPUT_BUS_LAST:
            return 0;
        }
        break;

    case VIR_DOMAIN_DEVICE_CHR:
        switch ((virDomainChrSerialTargetType)dev->data.chr->targetType) {
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI:
            return pciFlags;

        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SPAPR_VIO:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SYSTEM:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SCLP:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_LAST:
            return 0;
        }
        break;

    case VIR_DOMAIN_DEVICE_VSOCK:
        switch ((virDomainVsockModel) dev->data.vsock->model) {
        case VIR_DOMAIN_VSOCK_MODEL_VIRTIO_TRANSITIONAL:
            /* Transitional devices only work in conventional PCI slots */
            return pciFlags;
        case VIR_DOMAIN_VSOCK_MODEL_VIRTIO:
        case VIR_DOMAIN_VSOCK_MODEL_VIRTIO_NON_TRANSITIONAL:
            return virtioFlags;

        case VIR_DOMAIN_VSOCK_MODEL_DEFAULT:
        case VIR_DOMAIN_VSOCK_MODEL_LAST:
            return 0;
        }
        break;

        /* These devices don't ever connect with PCI */
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
        /* These devices don't even have a DeviceInfo */
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_NONE:
        return 0;
    }

    /* We can never get here, because all cases are covered in the
     * switch, and they all return, but the compiler will still
     * complain "control reaches end of non-void function" unless
     * we add the following return.
     */
    return 0;
}


typedef struct {
    virDomainPCIConnectFlags virtioFlags;
    virDomainPCIConnectFlags pcieFlags;
    virQEMUDriverPtr driver;
} qemuDomainFillDevicePCIConnectFlagsIterData;


/**
 * qemuDomainFillDevicePCIConnectFlagsIterInit:
 *
 * Initialize the iterator data that is used when calling
 * qemuDomainCalculateDevicePCIConnectFlags().
 */
static void
qemuDomainFillDevicePCIConnectFlagsIterInit(virDomainDefPtr def,
                                            virQEMUCapsPtr qemuCaps,
                                            virQEMUDriverPtr driver,
                                            qemuDomainFillDevicePCIConnectFlagsIterData *data)
{
    data->driver = driver;

    if (qemuDomainHasPCIeRoot(def)) {
        data->pcieFlags = (VIR_PCI_CONNECT_TYPE_PCIE_DEVICE |
                           VIR_PCI_CONNECT_HOTPLUGGABLE);
    } else {
        data->pcieFlags = (VIR_PCI_CONNECT_TYPE_PCI_DEVICE |
                           VIR_PCI_CONNECT_HOTPLUGGABLE);
    }

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_PCI_DISABLE_LEGACY)) {
        data->virtioFlags = data->pcieFlags;
    } else {
        data->virtioFlags = (VIR_PCI_CONNECT_TYPE_PCI_DEVICE |
                             VIR_PCI_CONNECT_HOTPLUGGABLE);
    }
}


/**
 * qemuDomainFillDevicePCIConnectFlagsIter:
 *
 * @def: the entire DomainDef
 * @dev: The device to be checked
 * @info: virDomainDeviceInfo within the device
 * @opaque: points to iterator data setup beforehand.
 *
 * Sets the pciConnectFlags for a single device's info. Has properly
 * formatted arguments to be called by virDomainDeviceInfoIterate().
 *
 * Always returns 0 - there is no failure.
 */
static int
qemuDomainFillDevicePCIConnectFlagsIter(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                        virDomainDeviceDefPtr dev,
                                        virDomainDeviceInfoPtr info,
                                        void *opaque)
{
    qemuDomainFillDevicePCIConnectFlagsIterData *data = opaque;

    info->pciConnectFlags
        = qemuDomainDeviceCalculatePCIConnectFlags(dev, data->driver,
                                                   data->pcieFlags,
                                                   data->virtioFlags);
    return 0;
}


/**
 * qemuDomainFillAllPCIConnectFlags:
 *
 * @def: the entire DomainDef
 * @qemuCaps: as you'd expect
 *
 * Set the info->pciConnectFlags for all devices in the domain.
 *
 * Returns 0 on success or -1 on failure (the only possibility of
 * failure would be some internal problem with
 * virDomainDeviceInfoIterate())
 */
static int
qemuDomainFillAllPCIConnectFlags(virDomainDefPtr def,
                                 virQEMUCapsPtr qemuCaps,
                                 virQEMUDriverPtr driver)
{
    qemuDomainFillDevicePCIConnectFlagsIterData data;

    qemuDomainFillDevicePCIConnectFlagsIterInit(def, qemuCaps, driver, &data);

    return virDomainDeviceInfoIterate(def,
                                      qemuDomainFillDevicePCIConnectFlagsIter,
                                      &data);
}


/**
 * qemuDomainFillDevicePCIExtensionFlagsIter:
 *
 * @def: the entire DomainDef
 * @dev: The device to be checked
 * @info: virDomainDeviceInfo within the device
 * @opaque: qemu capabilities
 *
 * Sets the pciAddressExtFlags for a single device's info. Has properly
 * formatted arguments to be called by virDomainDeviceInfoIterate().
 *
 * Always returns 0 - there is no failure.
 */
static int
qemuDomainFillDevicePCIExtensionFlagsIter(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                          virDomainDeviceDefPtr dev,
                                          virDomainDeviceInfoPtr info,
                                          void *opaque)
{
    virQEMUCapsPtr qemuCaps = opaque;

    info->pciAddrExtFlags =
        qemuDomainDeviceCalculatePCIAddressExtensionFlags(qemuCaps, dev);

    return 0;
}


/**
 * qemuDomainFillAllPCIExtensionFlags:
 *
 * @def: the entire DomainDef
 * @qemuCaps: as you'd expect
 *
 * Set the info->pciAddressExtFlags for all devices in the domain.
 *
 * Returns 0 on success or -1 on failure (the only possibility of
 * failure would be some internal problem with
 * virDomainDeviceInfoIterate())
 */
static int
qemuDomainFillAllPCIExtensionFlags(virDomainDefPtr def,
                                   virQEMUCapsPtr qemuCaps)
{
    return virDomainDeviceInfoIterate(def,
                                      qemuDomainFillDevicePCIExtensionFlagsIter,
                                      qemuCaps);
}


/**
 * qemuDomainFindUnusedIsolationGroupIter:
 * @def: domain definition
 * @dev: device definition
 * @info: device information
 * @opaque: user data
 *
 * Used to implement qemuDomainFindUnusedIsolationGroup(). You probably
 * don't want to call this directly.
 *
 * Return: 0 if the isolation group is not used by the device, <1 otherwise.
 */
static int
qemuDomainFindUnusedIsolationGroupIter(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                       virDomainDeviceDefPtr dev ATTRIBUTE_UNUSED,
                                       virDomainDeviceInfoPtr info,
                                       void *opaque)
{
    unsigned int *isolationGroup = opaque;

    if (info->isolationGroup == *isolationGroup)
        return -1;

    return 0;
}


/**
 * qemuDomainFindUnusedIsolationGroup:
 * @def: domain definition
 *
 * Find an isolation group that is not used by any device in @def yet.
 *
 * Normally, we'd look up the device's IOMMU group and base its isolation
 * group on that; however, when a network interface uses a network backed
 * by SR-IOV Virtual Functions, we can't know at PCI address assignment
 * time which host device will be used so we can't look up its IOMMU group.
 *
 * We still want such a device to be isolated: this function can be used
 * to obtain a synthetic isolation group usable for the purpose.
 *
 * Return: unused isolation group
 */
static unsigned int
qemuDomainFindUnusedIsolationGroup(virDomainDefPtr def)
{
    unsigned int isolationGroup = UINT_MAX;

    /* We start from the highest possible isolation group and work our
     * way backwards so that we're working in a completely different range
     * from IOMMU groups, thus avoiding clashes. We're realistically going
     * to call this function just a few times per guest anyway */
    while (isolationGroup > 0 &&
           virDomainDeviceInfoIterate(def,
                                      qemuDomainFindUnusedIsolationGroupIter,
                                      &isolationGroup) < 0) {
        isolationGroup--;
    }

    return isolationGroup;
}


/**
 * qemuDomainFillDeviceIsolationGroup:
 * @def: domain definition
 * @dev: device definition
 *
 * Fill isolation group information for a single device.
 *
 * Return: 0 on success, <0 on failure
 * */
int
qemuDomainFillDeviceIsolationGroup(virDomainDefPtr def,
                                   virDomainDeviceDefPtr dev)
{
    /* Only host devices need their isolation group to be different from
     * the default. Interfaces of type hostdev are just host devices in
     * disguise, but we don't need to handle them separately because for
     * each such interface a corresponding hostdev is also added to the
     * guest configuration */
    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        virDomainHostdevDefPtr hostdev = dev->data.hostdev;
        virDomainDeviceInfoPtr info = hostdev->info;
        virPCIDeviceAddressPtr hostAddr;
        int tmp;

        /* Only PCI host devices are subject to isolation */
        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            goto skip;
        }

        hostAddr = &hostdev->source.subsys.u.pci.addr;

        /* If a non-default isolation has already been assigned to the
         * device, we can avoid looking up the information again */
        if (info->isolationGroup > 0)
            goto skip;

        /* The isolation group depends on the IOMMU group assigned by the host */
        tmp = virPCIDeviceAddressGetIOMMUGroupNum(hostAddr);

        if (tmp < 0) {
            VIR_WARN("Can't look up isolation group for host device "
                     "%04x:%02x:%02x.%x, device won't be isolated",
                     hostAddr->domain, hostAddr->bus,
                     hostAddr->slot, hostAddr->function);
            goto skip;
        }

        /* The isolation group for a host device is its IOMMU group,
         * increased by one: this is because zero is a valid IOMMU group but
         * that's also the default isolation group, which we want to save
         * for emulated devices. Shifting isolation groups for host devices
         * by one ensures there is no overlap */
        info->isolationGroup = tmp + 1;

        VIR_DEBUG("Isolation group for host device %04x:%02x:%02x.%x is %u",
                  hostAddr->domain, hostAddr->bus,
                  hostAddr->slot, hostAddr->function,
                  info->isolationGroup);

    } else if (dev->type == VIR_DOMAIN_DEVICE_NET) {
        virDomainNetDefPtr iface = dev->data.net;
        virDomainDeviceInfoPtr info = &iface->info;
        unsigned int tmp;

        /* Network interfaces can ultimately result in the guest being
         * assigned a host device if the libvirt network they're connected
         * to is of type hostdev. All other kinds of network interfaces don't
         * require us to isolate the guest device, so we can skip them */
        if (iface->type != VIR_DOMAIN_NET_TYPE_NETWORK ||
            virDomainNetResolveActualType(iface) != VIR_DOMAIN_NET_TYPE_HOSTDEV) {
            goto skip;
        }

        /* If a non-default isolation has already been assigned to the
         * device, we can avoid looking up the information again */
        if (info->isolationGroup > 0)
            goto skip;

        /* Obtain a synthetic isolation group for the device, since at this
         * point in time we don't have access to the IOMMU group of the host
         * device that will eventually be used by the guest */
        tmp = qemuDomainFindUnusedIsolationGroup(def);

        if (tmp == 0) {
            VIR_WARN("Can't obtain usable isolation group for interface "
                     "configured to use hostdev-backed network '%s', "
                     "device won't be isolated",
                     iface->data.network.name);
            goto skip;
        }

        info->isolationGroup = tmp;

        VIR_DEBUG("Isolation group for interface configured to use "
                  "hostdev-backed network '%s' is %u",
                  iface->data.network.name, info->isolationGroup);
    }

 skip:
    return 0;
}


/**
 * qemuDomainFillDeviceIsolationGroupIter:
 * @def: domain definition
 * @dev: device definition
 * @info: device information
 * @opaque: user data
 *
 * A version of qemuDomainFillDeviceIsolationGroup() to be used
 * with virDomainDeviceInfoIterate()
 *
 * Return: 0 on success, <0 on failure
 */
static int
qemuDomainFillDeviceIsolationGroupIter(virDomainDefPtr def,
                                       virDomainDeviceDefPtr dev,
                                       virDomainDeviceInfoPtr info ATTRIBUTE_UNUSED,
                                       void *opaque ATTRIBUTE_UNUSED)
{
    return qemuDomainFillDeviceIsolationGroup(def, dev);
}


/**
 * qemuDomainSetupIsolationGroups:
 * @def: domain definition
 *
 * High-level function to set up isolation groups for all devices
 * and controllers in @def. Isolation groups will only be set up if
 * the guest architecture and machine type require it, so this
 * function can and should be called unconditionally before attempting
 * to assign any PCI address.
 *
 * Return: 0 on success, <0 on failure
 */
static int
qemuDomainSetupIsolationGroups(virDomainDefPtr def)
{
    int idx;
    int ret = -1;

    /* Only pSeries guests care about isolation groups at the moment */
    if (!qemuDomainIsPSeries(def))
        return 0;

    idx = virDomainControllerFind(def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 0);
    if (idx < 0)
        goto cleanup;

    /* We want to prevent hostdevs from being plugged into the default PHB:
     * we can make sure that doesn't happen by locking its isolation group */
    def->controllers[idx]->info.isolationGroupLocked = true;

    /* Fill in isolation groups for all other devices */
    if (virDomainDeviceInfoIterate(def,
                                   qemuDomainFillDeviceIsolationGroupIter,
                                   NULL) < 0) {
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}


/**
 * qemuDomainFillDevicePCIConnectFlags:
 *
 * @def: the entire DomainDef
 * @dev: The device to be checked
 * @qemuCaps: as you'd expect
 *
 * Set the info->pciConnectFlags for a single device.
 *
 * No return value.
 */
static void
qemuDomainFillDevicePCIConnectFlags(virDomainDefPtr def,
                                    virDomainDeviceDefPtr dev,
                                    virQEMUCapsPtr qemuCaps,
                                    virQEMUDriverPtr driver)
{
    virDomainDeviceInfoPtr info = virDomainDeviceGetInfo(dev);

    if (info) {
        /* qemuDomainDeviceCalculatePCIConnectFlags() is called with
         * the data setup in the ...IterData by ...IterInit() rather
         * than setting the values directly here.  It may seem like
         * pointless posturing, but it's done this way to eliminate
         * duplicated setup code while allowing more efficient
         * operation when it's being done repeatedly with the device
         * iterator (since qemuDomainFillAllPCIConnectFlags() only
         * calls ...IterInit() once for all devices).
         */
        qemuDomainFillDevicePCIConnectFlagsIterData data;

        qemuDomainFillDevicePCIConnectFlagsIterInit(def, qemuCaps, driver, &data);

        info->pciConnectFlags
            = qemuDomainDeviceCalculatePCIConnectFlags(dev, data.driver,
                                                       data.pcieFlags,
                                                       data.virtioFlags);
    }
}


/**
 * qemuDomainFillDevicePCIExtensionFlags:
 *
 * @dev: The device to be checked
 * @info: virDomainDeviceInfo within the device
 * @qemuCaps: as you'd expect
 *
 * Set the info->pciAddressExtFlags for a single device.
 *
 * No return value.
 */
static void
qemuDomainFillDevicePCIExtensionFlags(virDomainDeviceDefPtr dev,
                                      virDomainDeviceInfoPtr info,
                                      virQEMUCapsPtr qemuCaps)
{
    info->pciAddrExtFlags =
        qemuDomainDeviceCalculatePCIAddressExtensionFlags(qemuCaps, dev);
}


static int
qemuDomainPCIAddressReserveNextAddr(virDomainPCIAddressSetPtr addrs,
                                    virDomainDeviceInfoPtr dev)
{
    return virDomainPCIAddressReserveNextAddr(addrs, dev,
                                              dev->pciConnectFlags, -1);
}


static int
qemuDomainAssignPCIAddressExtension(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                    virDomainDeviceDefPtr device ATTRIBUTE_UNUSED,
                                    virDomainDeviceInfoPtr info,
                                    void *opaque)
{
    virDomainPCIAddressSetPtr addrs = opaque;
    virPCIDeviceAddressPtr addr = &info->addr.pci;

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        addr->extFlags = info->pciAddrExtFlags;

    if (virDeviceInfoPCIAddressExtensionIsWanted(info))
        return virDomainPCIAddressExtensionReserveNextAddr(addrs, addr);

    return 0;
}

static int
qemuDomainCollectPCIAddress(virDomainDefPtr def ATTRIBUTE_UNUSED,
                            virDomainDeviceDefPtr device,
                            virDomainDeviceInfoPtr info,
                            void *opaque)
{
    virDomainPCIAddressSetPtr addrs = opaque;
    int ret = -1;
    virPCIDeviceAddressPtr addr = &info->addr.pci;

    if (!virDeviceInfoPCIAddressIsPresent(info) ||
        ((device->type == VIR_DOMAIN_DEVICE_HOSTDEV) &&
         (device->data.hostdev->parent.type != VIR_DOMAIN_DEVICE_NONE))) {
        /* If a hostdev has a parent, its info will be a part of the
         * parent, and will have its address collected during the scan
         * of the parent's device type.
        */
        return 0;
    }

    /* If we get to here, the device has a PCI address assigned in the
     * config and we should mark it as in-use. But if the
     * pciConnectFlags are 0, then this device shouldn't have a PCI
     * address associated with it. *BUT* since there are cases in the
     * past where we've apparently allowed that, we need to pretend
     * for now that it's okay, otherwise an existing domain could
     * "disappear" from the list of domains due to a parse failure. We
     * can fix this by just forcing the pciConnectFlags to be
     * PCI_DEVICE (and then relying on validation functions to report
     * inappropriate address types.
     */
    if (!info->pciConnectFlags) {
        char *addrStr = virPCIDeviceAddressAsString(&info->addr.pci);

        VIR_WARN("qemuDomainDeviceCalculatePCIConnectFlags() thinks that the "
                 "device with PCI address %s should not have a PCI address",
                 addrStr ? addrStr : "(unknown)");
        VIR_FREE(addrStr);

        info->pciConnectFlags = VIR_PCI_CONNECT_TYPE_PCI_DEVICE;
    }

    /* Ignore implicit controllers on slot 0:0:1.0:
     * implicit IDE controller on 0:0:1.1 (no qemu command line)
     * implicit USB controller on 0:0:1.2 (-usb)
     *
     * If the machine does have a PCI bus, they will get reserved
     * in qemuDomainAssignDevicePCISlots().
     */

    /* These are the IDE and USB controllers in the PIIX3, hardcoded
     * to bus 0 slot 1.  They cannot be attached to a PCIe slot, only
     * PCI.
     */
    if (device->type == VIR_DOMAIN_DEVICE_CONTROLLER && addr->domain == 0 &&
        addr->bus == 0 && addr->slot == 1) {
        virDomainControllerDefPtr cont = device->data.controller;

        if ((cont->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE && cont->idx == 0 &&
             addr->function == 1) ||
            (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB && cont->idx == 0 &&
             (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI ||
              cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_DEFAULT) &&
             addr->function == 2)) {
            /* Note the check for nbuses > 0 - if there are no PCI
             * buses, we skip this check. This is a quirk required for
             * some machinetypes such as s390, which pretend to have a
             * PCI bus for long enough to generate the "-usb" on the
             * commandline, but that don't really care if a PCI bus
             * actually exists. */
            if (addrs->nbuses > 0 &&
                !(addrs->buses[0].flags & VIR_PCI_CONNECT_TYPE_PCI_DEVICE)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Bus 0 must be PCI for integrated PIIX3 "
                                 "USB or IDE controllers"));
                return -1;
            } else {
                return 0;
            }
        }
    }

    if (virDomainPCIAddressReserveAddr(addrs, addr,
                                       info->pciConnectFlags,
                                       info->isolationGroup) < 0) {
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

static int
qemuDomainCollectPCIAddressExtension(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                     virDomainDeviceDefPtr device,
                                     virDomainDeviceInfoPtr info,
                                     void *opaque)
{
    virDomainPCIAddressSetPtr addrs = opaque;
    virPCIDeviceAddressPtr addr = &info->addr.pci;

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        addr->extFlags = info->pciAddrExtFlags;

    if (!virDeviceInfoPCIAddressExtensionIsPresent(info) ||
        ((device->type == VIR_DOMAIN_DEVICE_HOSTDEV) &&
         (device->data.hostdev->parent.type != VIR_DOMAIN_DEVICE_NONE))) {
        /* If a hostdev has a parent, its info will be a part of the
         * parent, and will have its address collected during the scan
         * of the parent's device type.
        */
        return 0;
    }

    return virDomainPCIAddressExtensionReserveAddr(addrs, addr);
}

static virDomainPCIAddressSetPtr
qemuDomainPCIAddressSetCreate(virDomainDefPtr def,
                              virQEMUCapsPtr qemuCaps,
                              unsigned int nbuses,
                              bool dryRun)
{
    virDomainPCIAddressSetPtr addrs;
    size_t i;
    bool hasPCIeRoot = false;
    virDomainControllerModelPCI defaultModel;
    virPCIDeviceAddressExtensionFlags extFlags = VIR_PCI_ADDRESS_EXTENSION_NONE;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_ZPCI))
        extFlags |= VIR_PCI_ADDRESS_EXTENSION_ZPCI;

    if ((addrs = virDomainPCIAddressSetAlloc(nbuses, extFlags)) == NULL)
        return NULL;

    addrs->dryRun = dryRun;

    /* pSeries domains support multiple pci-root controllers */
    if (qemuDomainIsPSeries(def))
        addrs->areMultipleRootsSupported = true;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PCIE_PCI_BRIDGE))
        addrs->isPCIeToPCIBridgeSupported = true;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = def->controllers[i];
        size_t idx = cont->idx;

        if (cont->type != VIR_DOMAIN_CONTROLLER_TYPE_PCI)
            continue;

        if (idx >= addrs->nbuses) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Inappropriate new pci controller index %zu "
                             "exceeds addrs array length"), idx);
            goto error;
        }

        if (virDomainPCIAddressBusSetModel(&addrs->buses[idx], cont->model) < 0)
            goto error;

        /* Forward the information about isolation groups */
        addrs->buses[idx].isolationGroup = cont->info.isolationGroup;
        addrs->buses[idx].isolationGroupLocked = cont->info.isolationGroupLocked;

        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT)
            hasPCIeRoot = true;
    }

    if (nbuses > 0 && !addrs->buses[0].model) {
        /* This is just here to replicate a safety measure already in
         * an older version of this code. In practice, the root bus
         * should have already been added at index 0 prior to
         * assigning addresses to devices.
         */
        if (virDomainPCIAddressBusSetModel(&addrs->buses[0],
                                           VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) < 0)
            goto error;
    }

    /* Now fill in a reasonable model for all the buses in the set
     * that don't yet have a corresponding controller in the domain
     * config.
     */
    if (qemuDomainIsPSeries(def)) {
        /* pSeries guests should use PHBs (pci-root controllers) */
        defaultModel = VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT;
    } else if (hasPCIeRoot) {
        defaultModel = VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT;
    } else {
        defaultModel = VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE;
    }

    for (i = 1; i < addrs->nbuses; i++) {

        if (addrs->buses[i].model)
            continue;

        if (virDomainPCIAddressBusSetModel(&addrs->buses[i], defaultModel) < 0)
            goto error;

        VIR_DEBUG("Auto-adding <controller type='pci' model='%s' index='%zu'/>",
                  virDomainControllerModelPCITypeToString(defaultModel), i);
    }

    if (virDomainDeviceInfoIterate(def, qemuDomainCollectPCIAddress, addrs) < 0)
        goto error;

    if (virDomainDeviceInfoIterate(def,
                                   qemuDomainCollectPCIAddressExtension,
                                   addrs) < 0) {
        goto error;
    }

    return addrs;

 error:
    virDomainPCIAddressSetFree(addrs);
    return NULL;
}


static int
qemuDomainValidateDevicePCISlotsPIIX3(virDomainDefPtr def,
                                      virQEMUCapsPtr qemuCaps,
                                      virDomainPCIAddressSetPtr addrs)
{
    int ret = -1;
    size_t i;
    virPCIDeviceAddress tmp_addr;
    bool qemuDeviceVideoUsable = virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    char *addrStr = NULL;
    virDomainPCIConnectFlags flags = (VIR_PCI_CONNECT_HOTPLUGGABLE
                                      | VIR_PCI_CONNECT_TYPE_PCI_DEVICE);

    /* Verify that first IDE and USB controllers (if any) is on the PIIX3, fn 1 */
    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = def->controllers[i];

        /* First IDE controller lives on the PIIX3 at slot=1, function=1 */
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
            cont->idx == 0) {
            if (virDeviceInfoPCIAddressIsPresent(&cont->info)) {
                if (cont->info.addr.pci.domain != 0 ||
                    cont->info.addr.pci.bus != 0 ||
                    cont->info.addr.pci.slot != 1 ||
                    cont->info.addr.pci.function != 1) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Primary IDE controller must have PCI address 0:0:1.1"));
                    goto cleanup;
                }
            } else {
                cont->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                cont->info.addr.pci.domain = 0;
                cont->info.addr.pci.bus = 0;
                cont->info.addr.pci.slot = 1;
                cont->info.addr.pci.function = 1;
            }
        } else if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
                   cont->idx == 0 &&
                   (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI ||
                    cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_DEFAULT)) {
            if (virDeviceInfoPCIAddressIsPresent(&cont->info)) {
                if (cont->info.addr.pci.domain != 0 ||
                    cont->info.addr.pci.bus != 0 ||
                    cont->info.addr.pci.slot != 1 ||
                    cont->info.addr.pci.function != 2) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("PIIX3 USB controller at index 0 must have PCI address 0:0:1.2"));
                    goto cleanup;
                }
            } else {
                cont->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                cont->info.addr.pci.domain = 0;
                cont->info.addr.pci.bus = 0;
                cont->info.addr.pci.slot = 1;
                cont->info.addr.pci.function = 2;
            }
        } else {
            /* this controller is not skipped in qemuDomainCollectPCIAddress */
            continue;
        }
        if (addrs->nbuses &&
            virDomainPCIAddressReserveAddr(addrs, &cont->info.addr.pci, flags, 0) < 0)
            goto cleanup;
    }

    /* Implicit PIIX3 devices living on slot 1 not handled above */
    if (addrs->nbuses) {
        memset(&tmp_addr, 0, sizeof(tmp_addr));
        tmp_addr.slot = 1;
        /* ISA Bridge at 00:01.0 */
        if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags, 0) < 0)
            goto cleanup;
        /* Bridge at 00:01.3 */
        tmp_addr.function = 3;
        if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags, 0) < 0)
            goto cleanup;
    }

    if (def->nvideos > 0 &&
        def->videos[0]->type != VIR_DOMAIN_VIDEO_TYPE_NONE) {
        /* Because the PIIX3 integrated IDE/USB controllers are
         * already at slot 1, when qemu looks for the first free slot
         * to place the VGA controller (which is always the first
         * device added after integrated devices), it *always* ends up
         * at slot 2.
         */
        virDomainVideoDefPtr primaryVideo = def->videos[0];

        if (virDeviceInfoPCIAddressIsWanted(&primaryVideo->info)) {
            memset(&tmp_addr, 0, sizeof(tmp_addr));
            tmp_addr.slot = 2;

            if (!(addrStr = virPCIDeviceAddressAsString(&tmp_addr)))
                goto cleanup;
            if (!virDomainPCIAddressValidate(addrs, &tmp_addr,
                                             addrStr, flags, true))
                goto cleanup;

            if (virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
                if (qemuDeviceVideoUsable) {
                    if (qemuDomainPCIAddressReserveNextAddr(addrs,
                                                            &primaryVideo->info) < 0) {
                        goto cleanup;
                    }
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("PCI address 0:0:2.0 is in use, "
                                     "QEMU needs it for primary video"));
                    goto cleanup;
                }
            } else {
                if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags, 0) < 0)
                    goto cleanup;
                primaryVideo->info.addr.pci = tmp_addr;
                primaryVideo->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            }
        } else if (!qemuDeviceVideoUsable) {
            if (primaryVideo->info.addr.pci.domain != 0 ||
                primaryVideo->info.addr.pci.bus != 0 ||
                primaryVideo->info.addr.pci.slot != 2 ||
                primaryVideo->info.addr.pci.function != 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Primary video card must have PCI address 0:0:2.0"));
                goto cleanup;
            }
            /* If TYPE == PCI, then qemuDomainCollectPCIAddress() function
             * has already reserved the address, so we must skip */
        }
    } else if (addrs->nbuses && !qemuDeviceVideoUsable) {
        memset(&tmp_addr, 0, sizeof(tmp_addr));
        tmp_addr.slot = 2;

        if (virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
            VIR_DEBUG("PCI address 0:0:2.0 in use, future addition of a video"
                      " device will not be possible without manual"
                      " intervention");
        } else if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags, 0) < 0) {
            goto cleanup;
        }
    }
    ret = 0;
 cleanup:
    VIR_FREE(addrStr);
    return ret;
}


static int
qemuDomainValidateDevicePCISlotsQ35(virDomainDefPtr def,
                                    virQEMUCapsPtr qemuCaps,
                                    virDomainPCIAddressSetPtr addrs)
{
    int ret = -1;
    size_t i;
    virPCIDeviceAddress tmp_addr;
    bool qemuDeviceVideoUsable = virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    char *addrStr = NULL;
    virDomainPCIConnectFlags flags = VIR_PCI_CONNECT_TYPE_PCIE_DEVICE;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = def->controllers[i];

        switch (cont->type) {
        case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
            /* Verify that the first SATA controller is at 00:1F.2 the
             * q35 machine type *always* has a SATA controller at this
             * address.
             */
            if (cont->idx == 0) {
                if (virDeviceInfoPCIAddressIsPresent(&cont->info)) {
                    if (cont->info.addr.pci.domain != 0 ||
                        cont->info.addr.pci.bus != 0 ||
                        cont->info.addr.pci.slot != 0x1F ||
                        cont->info.addr.pci.function != 2) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("Primary SATA controller must have PCI address 0:0:1f.2"));
                        goto cleanup;
                    }
                } else {
                    cont->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                    cont->info.addr.pci.domain = 0;
                    cont->info.addr.pci.bus = 0;
                    cont->info.addr.pci.slot = 0x1F;
                    cont->info.addr.pci.function = 2;
                }
            }
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_USB:
            if ((cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1) &&
                (cont->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)) {
                /* Try to assign the first found USB2 controller to
                 * 00:1D.0 and 2nd to 00:1A.0 (because that is their
                 * standard location on real Q35 hardware) unless they
                 * are already taken, but don't insist on it.
                 *
                 * (NB: all other controllers at the same index will
                 * get assigned to the same slot as the UHCI1 when
                 * addresses are later assigned to all devices.)
                 */
                bool assign = false;

                memset(&tmp_addr, 0, sizeof(tmp_addr));
                tmp_addr.slot = 0x1D;
                if (!virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
                    assign = true;
                } else {
                    tmp_addr.slot = 0x1A;
                    if (!virDomainPCIAddressSlotInUse(addrs, &tmp_addr))
                        assign = true;
                }
                if (assign) {
                    if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags, 0) < 0)
                        goto cleanup;

                    cont->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                    cont->info.addr.pci.domain = 0;
                    cont->info.addr.pci.bus = 0;
                    cont->info.addr.pci.slot = tmp_addr.slot;
                    cont->info.addr.pci.function = 0;
                    cont->info.addr.pci.multi = VIR_TRISTATE_SWITCH_ON;
                }
            }
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
            if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE &&
                cont->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
                /* Try to assign this bridge to 00:1E.0 (because that
                * is its standard location on real hardware) unless
                * it's already taken, but don't insist on it.
                */
                memset(&tmp_addr, 0, sizeof(tmp_addr));
                tmp_addr.slot = 0x1E;
                if (!virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
                    if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags, 0) < 0)
                        goto cleanup;

                    cont->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                    cont->info.addr.pci.domain = 0;
                    cont->info.addr.pci.bus = 0;
                    cont->info.addr.pci.slot = 0x1E;
                    cont->info.addr.pci.function = 0;
                }
            }
            break;
        }
    }

    /* Reserve slot 0x1F function 0 (ISA bridge, not in config model)
     * and function 3 (SMBus, also not (yet) in config model). As with
     * the SATA controller, these devices are always present in a q35
     * machine; there is no way to not have them.
     */
    if (addrs->nbuses) {
        memset(&tmp_addr, 0, sizeof(tmp_addr));
        tmp_addr.slot = 0x1F;
        tmp_addr.function = 0;
        tmp_addr.multi = VIR_TRISTATE_SWITCH_ON;
        if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags, 0) < 0)
           goto cleanup;

        tmp_addr.function = 3;
        tmp_addr.multi = VIR_TRISTATE_SWITCH_ABSENT;
        if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags, 0) < 0)
           goto cleanup;
    }

    if (def->nvideos > 0 &&
        def->videos[0]->type != VIR_DOMAIN_VIDEO_TYPE_NONE) {
        /* NB: unlike the pc machinetypes, on q35 machinetypes the
         * integrated devices are at slot 0x1f, so when qemu looks for
         * the first free slot for the first VGA, it will always be at
         * slot 1 (which was used up by the integrated PIIX3 devices
         * on pc machinetypes).
         */
        virDomainVideoDefPtr primaryVideo = def->videos[0];
        if (virDeviceInfoPCIAddressIsWanted(&primaryVideo->info)) {
            memset(&tmp_addr, 0, sizeof(tmp_addr));
            tmp_addr.slot = 1;

            if (!(addrStr = virPCIDeviceAddressAsString(&tmp_addr)))
                goto cleanup;
            if (!virDomainPCIAddressValidate(addrs, &tmp_addr,
                                             addrStr, flags, true))
                goto cleanup;

            if (virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
                if (qemuDeviceVideoUsable) {
                    if (qemuDomainPCIAddressReserveNextAddr(addrs,
                                                            &primaryVideo->info) < 0)
                        goto cleanup;
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("PCI address 0:0:1.0 is in use, "
                                     "QEMU needs it for primary video"));
                    goto cleanup;
                }
            } else {
                if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags, 0) < 0)
                    goto cleanup;
                primaryVideo->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                primaryVideo->info.addr.pci = tmp_addr;
            }
        } else if (!qemuDeviceVideoUsable) {
            if (primaryVideo->info.addr.pci.domain != 0 ||
                primaryVideo->info.addr.pci.bus != 0 ||
                primaryVideo->info.addr.pci.slot != 1 ||
                primaryVideo->info.addr.pci.function != 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Primary video card must have PCI address 0:0:1.0"));
                goto cleanup;
            }
            /* If TYPE == PCI, then qemuDomainCollectPCIAddress() function
             * has already reserved the address, so we must skip */
        }
    } else if (addrs->nbuses && !qemuDeviceVideoUsable) {
        memset(&tmp_addr, 0, sizeof(tmp_addr));
        tmp_addr.slot = 1;

        if (virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
            VIR_DEBUG("PCI address 0:0:1.0 in use, future addition of a video"
                      " device will not be possible without manual"
                      " intervention");
            virResetLastError();
        } else if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags, 0) < 0) {
            goto cleanup;
        }
    }

    memset(&tmp_addr, 0, sizeof(tmp_addr));
    tmp_addr.slot = 0x1B;
    if (!virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
        /* Since real Q35 hardware has an ICH9 chip that has an
         * integrated HD audio device at 0000:00:1B.0 put any
         * unaddressed ICH9 audio device at that address if it's not
         * already taken. If there's something already there, let the
         * normal device addressing assign something later.
         */
        for (i = 0; i < def->nsounds; i++) {
            virDomainSoundDefPtr sound = def->sounds[i];

            if (sound->model != VIR_DOMAIN_SOUND_MODEL_ICH9 ||
                !virDeviceInfoPCIAddressIsWanted(&sound->info)) {
                continue;
            }
            if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags, 0) < 0)
                goto cleanup;

            sound->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            sound->info.addr.pci = tmp_addr;
            break;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(addrStr);
    return ret;
}


static int
qemuDomainValidateDevicePCISlotsChipsets(virDomainDefPtr def,
                                         virQEMUCapsPtr qemuCaps,
                                         virDomainPCIAddressSetPtr addrs)
{
    if (qemuDomainIsI440FX(def) &&
        qemuDomainValidateDevicePCISlotsPIIX3(def, qemuCaps, addrs) < 0) {
        return -1;
    }

    if (qemuDomainIsQ35(def) &&
        qemuDomainValidateDevicePCISlotsQ35(def, qemuCaps, addrs) < 0) {
        return -1;
    }

    return 0;
}


/*
 * This assigns static PCI slots to all configured devices.
 * The ordering here is chosen to match the ordering used
 * with old QEMU < 0.12, so that if a user updates a QEMU
 * host from old QEMU to QEMU >= 0.12, their guests should
 * get PCI addresses in the same order as before.
 *
 * NB, if they previously hotplugged devices then all bets
 * are off. Hotplug for old QEMU was unfixably broken wrt
 * to stable PCI addressing.
 *
 * Order is:
 *
 *  - Host bridge (slot 0)
 *  - PIIX3 ISA bridge, IDE controller, something else unknown, USB controller (slot 1)
 *  - Video (slot 2)
 *
 *  - These integrated devices were already added by
 *    qemuDomainValidateDevicePCISlotsChipsets invoked right before this function
 *
 * Incrementally assign slots from 3 onwards:
 *
 *  - Net
 *  - Sound
 *  - SCSI controllers
 *  - VirtIO block
 *  - VirtIO balloon
 *  - Host device passthrough
 *  - Watchdog
 *  - pci serial devices
 *
 * Prior to this function being invoked, qemuDomainCollectPCIAddress() will have
 * added all existing PCI addresses from the 'def' to 'addrs'. Thus this
 * function must only try to reserve addresses if info.type == NONE and
 * skip over info.type == PCI
 */
static int
qemuDomainAssignDevicePCISlots(virDomainDefPtr def,
                               virQEMUCapsPtr qemuCaps,
                               virDomainPCIAddressSetPtr addrs)
{
    size_t i, j;

    /* PCI controllers */
    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = def->controllers[i];

        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
            virDomainControllerModelPCI model = cont->model;

            if (model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT ||
                model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT ||
                !virDeviceInfoPCIAddressIsWanted(&cont->info))
                continue;

            if (qemuDomainPCIAddressReserveNextAddr(addrs, &cont->info) < 0)
                goto error;
        }
    }

    for (i = 0; i < def->nfss; i++) {
        if (!virDeviceInfoPCIAddressIsWanted(&def->fss[i]->info))
            continue;

        /* Only support VirtIO-9p-pci so far. If that changes,
         * we might need to skip devices here */
        if (qemuDomainPCIAddressReserveNextAddr(addrs, &def->fss[i]->info) < 0)
            goto error;
    }

    /* Network interfaces */
    for (i = 0; i < def->nnets; i++) {
        virDomainNetDefPtr net = def->nets[i];

        /* type='hostdev' network devices might be USB, and are also
         * in hostdevs list anyway, so handle them with other hostdevs
         * instead of here.
         */
        if ((net->type == VIR_DOMAIN_NET_TYPE_HOSTDEV) ||
            !virDeviceInfoPCIAddressIsWanted(&net->info)) {
            continue;
        }

        if (qemuDomainPCIAddressReserveNextAddr(addrs, &net->info) < 0)
            goto error;
    }

    /* Sound cards */
    for (i = 0; i < def->nsounds; i++) {
        virDomainSoundDefPtr sound = def->sounds[i];

        if (!virDeviceInfoPCIAddressIsWanted(&sound->info))
            continue;

        /* Skip ISA sound card, PCSPK and usb-audio */
        if (sound->model == VIR_DOMAIN_SOUND_MODEL_SB16 ||
            sound->model == VIR_DOMAIN_SOUND_MODEL_PCSPK ||
            sound->model == VIR_DOMAIN_SOUND_MODEL_USB) {
            continue;
        }

        if (qemuDomainPCIAddressReserveNextAddr(addrs, &sound->info) < 0)
            goto error;
    }

    /* Device controllers (SCSI, USB, but not IDE, FDC or CCID) */
    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = def->controllers[i];

        /* PCI controllers have been dealt with earlier */
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI)
            continue;

        /* USB controller model 'none' doesn't need a PCI address */
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
            cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE)
            continue;

        /* FDC lives behind the ISA bridge; CCID is a usb device */
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_FDC ||
            cont->type == VIR_DOMAIN_CONTROLLER_TYPE_CCID)
            continue;

        /* First IDE controller lives on the PIIX3 at slot=1, function=1,
           dealt with earlier on*/
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
            cont->idx == 0)
            continue;

        if (!virDeviceInfoPCIAddressIsWanted(&cont->info))
            continue;

        /* USB2 needs special handling to put all companions in the same slot */
        if (IS_USB2_CONTROLLER(cont)) {
            virPCIDeviceAddress addr = {0};
            bool foundAddr = false;

            for (j = 0; j < def->ncontrollers; j++) {
                if (IS_USB2_CONTROLLER(def->controllers[j]) &&
                    def->controllers[j]->idx == cont->idx &&
                    virDeviceInfoPCIAddressIsPresent(&def->controllers[j]->info)) {
                    addr = def->controllers[j]->info.addr.pci;
                    foundAddr = true;
                    break;
                }
            }

            switch (cont->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1:
                addr.function = 7;
                addr.multi = VIR_TRISTATE_SWITCH_ABSENT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1:
                addr.function = 0;
                addr.multi = VIR_TRISTATE_SWITCH_ON;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2:
                addr.function = 1;
                addr.multi = VIR_TRISTATE_SWITCH_ABSENT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3:
                addr.function = 2;
                addr.multi = VIR_TRISTATE_SWITCH_ABSENT;
                break;
            }

            if (foundAddr) {
                /* Reserve this function on the slot we found */
                if (virDomainPCIAddressReserveAddr(addrs, &addr,
                                                   cont->info.pciConnectFlags,
                                                   cont->info.isolationGroup) < 0) {
                    goto error;
                }

                cont->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                cont->info.addr.pci = addr;
            } else {
                /* This is the first part of the controller, so need
                 * to find a free slot & then reserve this function */
                if (virDomainPCIAddressReserveNextAddr(addrs, &cont->info,
                                                       cont->info.pciConnectFlags,
                                                       addr.function) < 0) {
                    goto error;
                }

                cont->info.addr.pci.multi = addr.multi;
            }
        } else {
            if (qemuDomainPCIAddressReserveNextAddr(addrs, &cont->info) < 0)
                 goto error;
        }
    }

    /* Disks (VirtIO only for now) */
    for (i = 0; i < def->ndisks; i++) {
        /* Only VirtIO disks use PCI addrs */
        if (def->disks[i]->bus != VIR_DOMAIN_DISK_BUS_VIRTIO)
            continue;

        /* don't touch s390 devices */
        if (virDeviceInfoPCIAddressIsPresent(&def->disks[i]->info) ||
            def->disks[i]->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390 ||
            def->disks[i]->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW)
            continue;

        /* Also ignore virtio-mmio disks if our machine allows them */
        if (def->disks[i]->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_MMIO))
            continue;

        if (!virDeviceInfoPCIAddressIsWanted(&def->disks[i]->info)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("virtio disk cannot have an address of type '%s'"),
                           virDomainDeviceAddressTypeToString(def->disks[i]->info.type));
            goto error;
        }

        if (qemuDomainPCIAddressReserveNextAddr(addrs, &def->disks[i]->info) < 0)
            goto error;
    }

    /* Host PCI devices */
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevSubsysPtr subsys = &def->hostdevs[i]->source.subsys;
        if (!virDeviceInfoPCIAddressIsWanted(def->hostdevs[i]->info))
            continue;
        if (def->hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS)
            continue;
        if (subsys->type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
            subsys->type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST &&
            !(subsys->type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV &&
              subsys->u.mdev.model == VIR_MDEV_MODEL_TYPE_VFIO_PCI)) {
            continue;
        }

        if (qemuDomainPCIAddressReserveNextAddr(addrs,
                                                def->hostdevs[i]->info) < 0)
            goto error;
    }

    /* memballoon. the qemu driver only accepts virtio memballoon devices */
    if (virDomainDefHasMemballoon(def) &&
        virDeviceInfoPCIAddressIsWanted(&def->memballoon->info)) {
        if (qemuDomainPCIAddressReserveNextAddr(addrs,
                                                &def->memballoon->info) < 0)
            goto error;
    }

    /* the qemu driver only accepts virtio rng devices */
    for (i = 0; i < def->nrngs; i++) {
        if (!virDeviceInfoPCIAddressIsWanted(&def->rngs[i]->info))
            continue;

        if (qemuDomainPCIAddressReserveNextAddr(addrs, &def->rngs[i]->info) < 0)
            goto error;
    }

    /* A watchdog - check if it is a PCI device */
    if (def->watchdog &&
        def->watchdog->model == VIR_DOMAIN_WATCHDOG_MODEL_I6300ESB &&
        virDeviceInfoPCIAddressIsWanted(&def->watchdog->info)) {
        if (qemuDomainPCIAddressReserveNextAddr(addrs, &def->watchdog->info) < 0)
            goto error;
    }

    /* Video devices */
    for (i = 0; i < def->nvideos; i++) {
        if (def->videos[i]->type == VIR_DOMAIN_VIDEO_TYPE_NONE)
            continue;

        if (!virDeviceInfoPCIAddressIsWanted(&def->videos[i]->info))
            continue;

        if (qemuDomainPCIAddressReserveNextAddr(addrs, &def->videos[i]->info) < 0)
            goto error;
    }

    /* Shared Memory */
    for (i = 0; i < def->nshmems; i++) {
        if (!virDeviceInfoPCIAddressIsWanted(&def->shmems[i]->info))
            continue;

        if (qemuDomainPCIAddressReserveNextAddr(addrs, &def->shmems[i]->info) < 0)
            goto error;
    }
    for (i = 0; i < def->ninputs; i++) {
        if (def->inputs[i]->bus != VIR_DOMAIN_INPUT_BUS_VIRTIO ||
            !virDeviceInfoPCIAddressIsWanted(&def->inputs[i]->info))
            continue;

        if (qemuDomainPCIAddressReserveNextAddr(addrs, &def->inputs[i]->info) < 0)
            goto error;
    }
    for (i = 0; i < def->nparallels; i++) {
        /* Nada - none are PCI based (yet) */
    }
    for (i = 0; i < def->nserials; i++) {
        virDomainChrDefPtr chr = def->serials[i];

        if (chr->targetType != VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI ||
            !virDeviceInfoPCIAddressIsWanted(&chr->info))
            continue;

        if (qemuDomainPCIAddressReserveNextAddr(addrs, &chr->info) < 0)
            goto error;
    }
    for (i = 0; i < def->nchannels; i++) {
        /* Nada - none are PCI based (yet) */
    }
    for (i = 0; i < def->nhubs; i++) {
        /* Nada - none are PCI based (yet) */
    }

    if (def->vsock &&
        virDeviceInfoPCIAddressIsWanted(&def->vsock->info)) {

        if (qemuDomainPCIAddressReserveNextAddr(addrs,
                                                &def->vsock->info) < 0)
            goto error;
    }

    return 0;

 error:
    return -1;
}


static void
qemuDomainPCIControllerSetDefaultModelName(virDomainControllerDefPtr cont,
                                           virDomainDefPtr def,
                                           virQEMUCapsPtr qemuCaps)
{
    int *modelName = &cont->opts.pciopts.modelName;

    /* make sure it's not already set */
    if (*modelName != VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
        return;

    switch ((virDomainControllerModelPCI)cont->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
        *modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCI_BRIDGE;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
        *modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_I82801B11_BRIDGE;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        *modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCIE_PCI_BRIDGE;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
        /* Use generic PCIe Root Ports if available, falling back to
         * ioh3420 otherwise */
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PCIE_ROOT_PORT))
            *modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCIE_ROOT_PORT;
        else
            *modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_IOH3420;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
        *modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_X3130_UPSTREAM;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
        *modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_XIO3130_DOWNSTREAM;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
        *modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PXB;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
        *modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PXB_PCIE;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
        if (qemuDomainIsPSeries(def))
            *modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_SPAPR_PCI_HOST_BRIDGE;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
        break;
    }
}


/**
 * qemuDomainAddressFindNewTargetIndex:
 * @def: domain definition
 *
 * Find a target index that can be used for a PCI controller.
 *
 * Returns: an unused target index, or -1 if all available target
 *          indexes are already taken.
 */
static int
qemuDomainAddressFindNewTargetIndex(virDomainDefPtr def)
{
    int targetIndex;
    int ret = -1;

    /* Try all indexes between 1 and 31 - QEMU only supports 32
     * PHBs, and 0 is reserved for the default, implicit one */
    for (targetIndex = 1; targetIndex <= 31; targetIndex++) {
        bool found = false;
        size_t i;

        for (i = 0; i < def->ncontrollers; i++) {
            virDomainControllerDefPtr cont = def->controllers[i];

            /* Skip everything but PHBs */
            if (!virDomainControllerIsPSeriesPHB(cont))
                continue;

            /* Stop looking as soon as we find a PHB that's
             * already using this specific target index */
            if (cont->opts.pciopts.targetIndex == targetIndex) {
                found = true;
                break;
            }
        }

        /* If no existing PCI controller uses this index, great,
         * it means it's free and we can return it to the caller */
        if (!found) {
            ret = targetIndex;
            break;
        }
    }

    return ret;
}


static int
qemuDomainAddressFindNewBusNr(virDomainDefPtr def)
{
    /* Try to find a nice default for busNr for a new pci-expander-bus.
     * This is a bit tricky, since you need to satisfy the following:
     *
     * 1) There need to be enough unused bus numbers between busNr of this
     *    bus and busNr of the next highest bus for the guest to assign a
     *    unique bus number to each PCI bus that is a child of this
     *    bus. Each PCI controller. On top of this, the pxb device (which
     *    implements the pci-expander-bus) includes a pci-bridge within
     *    it, and that bridge also uses one bus number (so each pxb device
     *    requires at least 2 bus numbers).
     *
     * 2) There need to be enough bus numbers *below* this for all the
     *    child controllers of the pci-expander-bus with the next lower
     *    busNr (or the pci-root bus if there are no lower
     *    pci-expander-buses).
     *
     * 3) If at all possible, we want to avoid needing to change the busNr
     *    of a bus in the future, as that changes the guest's device ABI,
     *    which could potentially lead to issues with a guest OS that is
     *    picky about such things.
     *
     *  Due to the impossibility of predicting what might be added to the
     *  config in the future, we can't make a foolproof choice, but since
     *  a pci-expander-bus (pxb) has slots for 32 devices, and the only
     *  practical use for it is to assign real devices on a particular
     *  NUMA node in the host, it's reasonably safe to assume it should
     *  never need any additional child buses (probably only a few of the
     *  32 will ever be used). So for pci-expander-bus we find the lowest
     *  existing busNr, and set this one to the current lowest - 2 (one
     *  for the pxb, one for the intergrated pci-bridge), thus leaving the
     *  maximum possible bus numbers available for other buses plugged
     *  into pci-root (i.e. pci-bridges and other
     *  pci-expander-buses). Anyone who needs more than 32 devices
     *  descended from one pci-expander-bus should set the busNr manually
     *  in the config.
     *
     *  There is room for more error checking here - in particular we
     *  can/should determine the ultimate parent (root-bus) of each PCI
     *  controller and determine if there is enough space for all the
     *  buses within the current range allotted to the bus just prior to
     *  this one.
     */

    size_t i;
    int lowestBusNr = 256;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = def->controllers[i];

        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
            int thisBusNr = cont->opts.pciopts.busNr;

            if (thisBusNr >= 0 && thisBusNr < lowestBusNr)
                lowestBusNr = thisBusNr;
        }
    }

    /* If we already have a busNR = 1, then we can't auto-assign (0 is
     * the pci[e]-root, and the others may have been assigned
     * purposefully).
     */
    if (lowestBusNr <= 2)
        return -1;

    return lowestBusNr - 2;
}


static int
qemuDomainAssignPCIAddresses(virDomainDefPtr def,
                             virQEMUCapsPtr qemuCaps,
                             virQEMUDriverPtr driver,
                             virDomainObjPtr obj)
{
    int ret = -1;
    virDomainPCIAddressSetPtr addrs = NULL;
    qemuDomainObjPrivatePtr priv = NULL;
    int max_idx = -1;
    int nbuses = 0;
    size_t i;
    int rv;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDefPtr cont = def->controllers[i];

        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
            if ((int)cont->idx > max_idx)
                max_idx = cont->idx;
        }
    }

    nbuses = max_idx + 1;

    /* set the connect type flags (pci vs. pcie) in the DeviceInfo
     * of all devices. This will be used to pick an appropriate
     * bus when assigning addresses.
     */
    if (qemuDomainFillAllPCIConnectFlags(def, qemuCaps, driver) < 0)
        goto cleanup;

    if (qemuDomainFillAllPCIExtensionFlags(def, qemuCaps) < 0)
        goto cleanup;

    if (qemuDomainSetupIsolationGroups(def) < 0)
        goto cleanup;

    if (nbuses > 0) {
        /* 1st pass to figure out how many PCI bridges we need */
        if (!(addrs = qemuDomainPCIAddressSetCreate(def, qemuCaps, nbuses, true)))
            goto cleanup;

        if (qemuDomainValidateDevicePCISlotsChipsets(def, qemuCaps,
                                                     addrs) < 0)
            goto cleanup;

        /* For domains that have pci-root, reserve 1 extra slot for a
         * (potential) bridge (for future expansion) only if buses are
         * not fully reserved yet (if all buses are fully reserved
         * with manually/previously assigned addresses, any attempt to
         * reserve an extra slot would fail anyway. But if all buses
         * are *not* fully reserved, this extra reservation might push
         * the config to add a new pci-bridge to plug into the final
         * available slot, thus preserving the ability to expand)
         *
         * We only do this for those domains that have pci-root, since
         * those with pcie-root will usually want to expand using PCIe
         * controllers, which we will do after assigning addresses for
         * all *actual* devices.
         */

        if (qemuDomainHasPCIRoot(def)) {
            /* This is a dummy info used to reserve a slot for a
             * legacy PCI device that doesn't exist, but may in the
             * future, e.g.  if another device is hotplugged into the
             * domain.
             */
            virDomainDeviceInfo info = {
                .pciConnectFlags = (VIR_PCI_CONNECT_HOTPLUGGABLE |
                                    VIR_PCI_CONNECT_TYPE_PCI_DEVICE),
                .pciAddrExtFlags = VIR_PCI_ADDRESS_EXTENSION_NONE
            };
            bool buses_reserved = true;

            for (i = 0; i < addrs->nbuses; i++) {
                if (!virDomainPCIAddressBusIsFullyReserved(&addrs->buses[i])) {
                    buses_reserved = false;
                    break;
                }
            }
            if (!buses_reserved &&
                qemuDomainPCIAddressReserveNextAddr(addrs, &info) < 0)
                goto cleanup;
        }

        if (qemuDomainAssignDevicePCISlots(def, qemuCaps, addrs) < 0)
            goto cleanup;

        if (virDomainDeviceInfoIterate(def, qemuDomainAssignPCIAddressExtension, addrs) < 0)
            goto cleanup;

        /* Only for *new* domains with pcie-root (and no other
         * manually specified PCI controllers in the definition): If,
         * after assigning addresses/reserving slots for all devices,
         * we see that any extra buses have been auto-added, we
         * understand that the application has left management of PCI
         * addresses and controllers up to libvirt. In order to allow
         * such applications to easily support hotplug, we will do a
         * "one time" reservation of one extra PCIE|HOTPLUGGABLE
         * slots, which should cause us to auto-add 1 extra
         * pcie-root-port. The single slot in this root-port will be
         * available for hotplug, or may also be used when a device is
         * added to the config offline.
         */

        if (max_idx <= 0 &&
            addrs->nbuses > max_idx + 1 &&
            qemuDomainHasPCIeRoot(def)) {
            virDomainDeviceInfo info = {
                .pciConnectFlags = (VIR_PCI_CONNECT_HOTPLUGGABLE |
                                    VIR_PCI_CONNECT_TYPE_PCIE_DEVICE),
                .pciAddrExtFlags = VIR_PCI_ADDRESS_EXTENSION_NONE
            };

            /* if there isn't an empty pcie-root-port, this will
             * cause one to be added
             */
            if (qemuDomainPCIAddressReserveNextAddr(addrs, &info) < 0)
               goto cleanup;
        }

        /* now reflect any controllers auto-added to addrs into the
         * domain controllers list
         */
        for (i = 1; i < addrs->nbuses; i++) {
            virDomainDeviceDef dev;
            int contIndex;
            virDomainPCIAddressBusPtr bus = &addrs->buses[i];

            if ((rv = virDomainDefMaybeAddController(
                     def, VIR_DOMAIN_CONTROLLER_TYPE_PCI,
                     i, bus->model)) < 0)
                goto cleanup;

            if (rv == 0)
                continue; /* no new controller added */

            /* We did add a new controller, so we will need one more
             * address (and we need to set the new controller's
             * pciConnectFlags)
             */
            contIndex = virDomainControllerFind(def,
                                                VIR_DOMAIN_CONTROLLER_TYPE_PCI,
                                                i);
            if (contIndex < 0) {
                /* this should never happen - we just added it */
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not find auto-added %s controller "
                                 "with index %zu"),
                               virDomainControllerModelPCITypeToString(bus->model),
                               i);
                goto cleanup;
            }
            dev.type = VIR_DOMAIN_DEVICE_CONTROLLER;
            dev.data.controller = def->controllers[contIndex];
            /* set connect flags so it will be properly addressed */
            qemuDomainFillDevicePCIConnectFlags(def, &dev, qemuCaps, driver);

            /* Reserve an address for the controller. pci-root and pcie-root
             * controllers don't plug into any other PCI controller, hence
             * they should skip this step */
            if (bus->model != VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT &&
                bus->model != VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT &&
                qemuDomainPCIAddressReserveNextAddr(addrs,
                                                    &dev.data.controller->info) < 0) {
                goto cleanup;
            }
        }

        nbuses = addrs->nbuses;
        virDomainPCIAddressSetFree(addrs);
        addrs = NULL;
    }

    if (!(addrs = qemuDomainPCIAddressSetCreate(def, qemuCaps, nbuses, false)))
        goto cleanup;

    if (qemuDomainSupportsPCI(def, qemuCaps)) {
        if (qemuDomainValidateDevicePCISlotsChipsets(def, qemuCaps,
                                                     addrs) < 0)
            goto cleanup;

        if (qemuDomainAssignDevicePCISlots(def, qemuCaps, addrs) < 0)
            goto cleanup;

        if (virDomainDeviceInfoIterate(def, qemuDomainAssignPCIAddressExtension, addrs) < 0)
            goto cleanup;

        /* set multi attribute for devices at function 0 of
         * any slot that has multiple functions in use
         */
        virDomainPCIAddressSetAllMulti(def);

        for (i = 0; i < def->ncontrollers; i++) {
            virDomainControllerDefPtr cont = def->controllers[i];
            int idx = cont->idx;
            virPCIDeviceAddressPtr addr;
            virDomainPCIControllerOptsPtr options;

            if (cont->type != VIR_DOMAIN_CONTROLLER_TYPE_PCI)
                continue;

            addr = &cont->info.addr.pci;
            options = &cont->opts.pciopts;

            /* set default model name (the actual name of the
             * device in qemu) for any controller that doesn't yet
             * have it set.
             */
            qemuDomainPCIControllerSetDefaultModelName(cont, def, qemuCaps);

            /* set defaults for any other auto-generated config
             * options for this controller that haven't been
             * specified in config.
             */
            switch ((virDomainControllerModelPCI)cont->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
                if (options->chassisNr == -1)
                    options->chassisNr = cont->idx;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
                if (options->chassis == -1)
                   options->chassis = cont->idx;
                if (options->port == -1)
                   options->port = (addr->slot << 3) + addr->function;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
                if (options->chassis == -1)
                   options->chassis = cont->idx;
                if (options->port == -1)
                   options->port = addr->slot;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
                if (options->busNr == -1)
                    options->busNr = qemuDomainAddressFindNewBusNr(def);
                if (options->busNr == -1) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("No free busNr lower than current "
                                     "lowest busNr is available to "
                                     "auto-assign to bus %d. Must be "
                                     "manually assigned"),
                                   addr->bus);
                    goto cleanup;
                }
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
                if (!qemuDomainIsPSeries(def))
                    break;
                if (options->targetIndex == -1) {
                    if (cont->idx == 0) {
                        /* The pci-root controller with controller index 0
                         * must always be assigned target index 0, because
                         * it represents the implicit PHB which is treated
                         * differently than all other PHBs */
                        options->targetIndex = 0;
                    } else {
                        /* For all other PHBs the target index doesn't need
                         * to match the controller index or have any
                         * particular value, really */
                        options->targetIndex = qemuDomainAddressFindNewTargetIndex(def);
                    }
                }
                if (options->targetIndex == -1) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("No usable target index found for %d"),
                                   addr->bus);
                    goto cleanup;
                }
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
                break;
            }

            /* check if every PCI bridge controller's index is larger than
             * the bus it is placed onto
             */
            if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE &&
                idx <= addr->bus) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PCI controller at index %d (0x%02x) has "
                                 "bus='0x%02x', but index must be "
                                 "larger than bus"),
                               idx, idx, addr->bus);
                goto cleanup;
            }
        }
    }

    if (obj && obj->privateData) {
        priv = obj->privateData;
        /* if this is the live domain object, we persist the PCI addresses */
        priv->pciaddrs = addrs;
        addrs = NULL;
    }

    ret = 0;

 cleanup:
    virDomainPCIAddressSetFree(addrs);

    return ret;
}


struct qemuAssignUSBIteratorInfo {
    virDomainUSBAddressSetPtr addrs;
    size_t count;
};


static int
qemuDomainAssignUSBPortsIterator(virDomainDeviceInfoPtr info,
                                 void *opaque)
{
    struct qemuAssignUSBIteratorInfo *data = opaque;

    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB)
        return 0;

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB &&
        virDomainUSBAddressPortIsValid(info->addr.usb.port))
        return 0;

    return virDomainUSBAddressAssign(data->addrs, info);
}


static int
qemuDomainAssignUSBHubs(virDomainUSBAddressSetPtr addrs,
                        virDomainDefPtr def)
{
    size_t i;

    for (i = 0; i < def->nhubs; i++) {
        virDomainHubDefPtr hub = def->hubs[i];
        if (hub->type != VIR_DOMAIN_HUB_TYPE_USB)
            continue;

        if (hub->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB &&
            virDomainUSBAddressPortIsValid(hub->info.addr.usb.port))
            continue;
        if (virDomainUSBAddressAssign(addrs, &hub->info) < 0)
            return -1;

        if (virDomainUSBAddressSetAddHub(addrs, hub) < 0)
            return -1;
    }

    return 0;
}


static int
qemuDomainAssignUSBPorts(virDomainUSBAddressSetPtr addrs,
                         virDomainDefPtr def)
{
    struct qemuAssignUSBIteratorInfo data = { .addrs = addrs };

    return virDomainUSBDeviceDefForeach(def,
                                        qemuDomainAssignUSBPortsIterator,
                                        &data,
                                        true);
}


static int
qemuDomainAssignUSBPortsCounter(virDomainDeviceInfoPtr info ATTRIBUTE_UNUSED,
                                void *opaque)
{
    struct qemuAssignUSBIteratorInfo *data = opaque;

    data->count++;
    return 0;
}


static int
qemuDomainUSBAddressAddHubs(virDomainDefPtr def)
{
    struct qemuAssignUSBIteratorInfo data = { .count = 0 };
    virDomainHubDefPtr hub = NULL;
    size_t available_ports;
    size_t hubs_needed = 0;
    int ret = -1;
    size_t i;

    available_ports = virDomainUSBAddressCountAllPorts(def);
    ignore_value(virDomainUSBDeviceDefForeach(def,
                                              qemuDomainAssignUSBPortsCounter,
                                              &data,
                                              false));

    if (data.count > 0 && !virDomainDefHasUSB(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("USB is disabled for this domain, but USB devices "
                         "are present in the domain XML"));
        return -1;
    }

    if (data.count > available_ports)
        hubs_needed = VIR_DIV_UP(data.count - available_ports + 1,
                                 VIR_DOMAIN_USB_HUB_PORTS - 1);

    VIR_DEBUG("Found %zu USB devices and %zu provided USB ports; adding %zu hubs",
              data.count, available_ports, hubs_needed);

    for (i = 0; i < hubs_needed; i++) {
        if (VIR_ALLOC(hub) < 0)
            return -1;
        hub->type = VIR_DOMAIN_HUB_TYPE_USB;

        if (VIR_APPEND_ELEMENT(def->hubs, def->nhubs, hub) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(hub);
    return ret;
}


static virBitmapPtr
qemuDomainGetMemorySlotMap(const virDomainDef *def)
{
    virBitmapPtr ret;
    virDomainMemoryDefPtr mem;
    size_t i;

    if (!(ret = virBitmapNew(def->mem.memory_slots)))
        return NULL;

    for (i = 0; i < def->nmems; i++) {
        mem = def->mems[i];

        if (mem->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM)
            ignore_value(virBitmapSetBit(ret, mem->info.addr.dimm.slot));
    }

    return ret;
}


static int
qemuAssignMemoryDeviceSlot(virDomainMemoryDefPtr mem,
                           virBitmapPtr slotmap)
{
    ssize_t nextslot = -1;

    if (mem->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM)
        return 0;

    if ((nextslot = virBitmapNextClearBit(slotmap, -1)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to find an empty memory slot"));
        return -1;
    }

    ignore_value(virBitmapSetBit(slotmap, nextslot));
    mem->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM;
    mem->info.addr.dimm.slot = nextslot;

    return 0;
}


int
qemuDomainAssignMemoryDeviceSlot(virDomainDefPtr def,
                                 virDomainMemoryDefPtr mem)
{
    virBitmapPtr slotmap = NULL;
    int ret;

    if (!(slotmap = qemuDomainGetMemorySlotMap(def)))
        return -1;

    ret = qemuAssignMemoryDeviceSlot(mem, slotmap);

    virBitmapFree(slotmap);
    return ret;
}


static int
qemuDomainAssignMemorySlots(virDomainDefPtr def)
{
    virBitmapPtr slotmap = NULL;
    int ret = -1;
    size_t i;

    if (!virDomainDefHasMemoryHotplug(def))
        return 0;

    if (!(slotmap = qemuDomainGetMemorySlotMap(def)))
        return -1;

    for (i = 0; i < def->nmems; i++) {
        if (qemuAssignMemoryDeviceSlot(def->mems[i], slotmap) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virBitmapFree(slotmap);
    return ret;

}


static int
qemuDomainAssignUSBAddresses(virDomainDefPtr def,
                             virDomainObjPtr obj,
                             bool newDomain)
{
    int ret = -1;
    virDomainUSBAddressSetPtr addrs = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    if (!newDomain) {
        /* only create the address cache for:
         *  new domains
         *  domains that already have all the addresses specified
         * otherwise libvirt's attempt to recreate the USB topology via
         * QEMU command line might fail */
        if (virDomainUSBDeviceDefForeach(def, virDomainUSBAddressPresent, NULL,
                                         false) < 0)
            return 0;
    }

    if (!(addrs = virDomainUSBAddressSetCreate()))
        goto cleanup;

    if (qemuDomainUSBAddressAddHubs(def) < 0)
        goto cleanup;

    if (virDomainUSBAddressSetAddControllers(addrs, def) < 0)
        goto cleanup;

    if (virDomainUSBDeviceDefForeach(def, virDomainUSBAddressReserve, addrs,
                                     true) < 0)
        goto cleanup;

    VIR_DEBUG("Existing USB addresses have been reserved");

    if (qemuDomainAssignUSBHubs(addrs, def) < 0)
        goto cleanup;

    if (qemuDomainAssignUSBPorts(addrs, def) < 0)
        goto cleanup;

    VIR_DEBUG("Finished assigning USB ports");

    if (obj && obj->privateData) {
        priv = obj->privateData;
        priv->usbaddrs = addrs;
        addrs = NULL;
    }
    ret = 0;

 cleanup:
    virDomainUSBAddressSetFree(addrs);
    return ret;
}


int
qemuDomainAssignAddresses(virDomainDefPtr def,
                          virQEMUCapsPtr qemuCaps,
                          virQEMUDriverPtr driver,
                          virDomainObjPtr obj,
                          bool newDomain)
{
    if (qemuDomainAssignVirtioSerialAddresses(def) < 0)
        return -1;

    if (qemuDomainAssignSpaprVIOAddresses(def) < 0)
        return -1;

    if (qemuDomainAssignS390Addresses(def, qemuCaps) < 0)
        return -1;

    qemuDomainAssignVirtioMMIOAddresses(def, qemuCaps);

    if (qemuDomainAssignPCIAddresses(def, qemuCaps, driver, obj) < 0)
        return -1;

    if (qemuDomainAssignUSBAddresses(def, obj, newDomain) < 0)
        return -1;

    if (qemuDomainAssignMemorySlots(def) < 0)
        return -1;

    return 0;
}

/**
 * qemuDomainEnsurePCIAddress:
 *
 * @obj: the virDomainObjPtr for the domain. This will include
 *       qemuCaps and address cache (if there is one)
 *
 * @dev: the device that we need to ensure has a PCI address
 *
 * if @dev should have a PCI address but doesn't, assign an address on
 * a compatible PCI bus, and set it in @dev->...info. If there is an
 * address already, validate that it is on a compatible bus, based on
 * @dev->...info.pciConnectFlags.
 *
 * returns 0 on success -1 on failure.
 */
int
qemuDomainEnsurePCIAddress(virDomainObjPtr obj,
                           virDomainDeviceDefPtr dev,
                           virQEMUDriverPtr driver)
{
    qemuDomainObjPrivatePtr priv = obj->privateData;
    virDomainDeviceInfoPtr info = virDomainDeviceGetInfo(dev);

    if (!info)
        return 0;

    qemuDomainFillDevicePCIConnectFlags(obj->def, dev, priv->qemuCaps, driver);

    qemuDomainFillDevicePCIExtensionFlags(dev, info, priv->qemuCaps);

    return virDomainPCIAddressEnsureAddr(priv->pciaddrs, info,
                                         info->pciConnectFlags);
}

void
qemuDomainReleaseDeviceAddress(virDomainObjPtr vm,
                               virDomainDeviceInfoPtr info)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (virDeviceInfoPCIAddressIsPresent(info)) {
        virDomainPCIAddressReleaseAddr(priv->pciaddrs, &info->addr.pci);
        virDomainPCIAddressExtensionReleaseAddr(priv->pciaddrs, &info->addr.pci);
    }

    virDomainUSBAddressRelease(priv->usbaddrs, info);
}


int
qemuDomainEnsureVirtioAddress(bool *releaseAddr,
                              virDomainObjPtr vm,
                              virDomainDeviceDefPtr dev,
                              const char *devicename)
{
    virDomainDeviceInfoPtr info = virDomainDeviceGetInfo(dev);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainCCWAddressSetPtr ccwaddrs = NULL;
    virQEMUDriverPtr driver = priv->driver;
    int ret = -1;

    if (!info->type) {
        if (qemuDomainIsS390CCW(vm->def) &&
            virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_CCW))
            info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW;
        else if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_S390))
            info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390;
    } else {
        if (!qemuDomainCheckCCWS390AddressSupport(vm->def, info, priv->qemuCaps,
                                                  devicename))
            return -1;
    }

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
        if (!(ccwaddrs = virDomainCCWAddressSetCreateFromDomain(vm->def)))
            goto cleanup;
        if (virDomainCCWAddressAssign(info, ccwaddrs,
                                      !info->addr.ccw.assigned) < 0)
            goto cleanup;
    } else if (!info->type ||
               info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        if (qemuDomainEnsurePCIAddress(vm, dev, driver) < 0)
            goto cleanup;
        *releaseAddr = true;
    }

    ret = 0;

 cleanup:
    virDomainCCWAddressSetFree(ccwaddrs);
    return ret;
}
