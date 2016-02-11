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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
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


int
qemuDomainSetSCSIControllerModel(virDomainDefPtr def,
                                 virQEMUCapsPtr qemuCaps,
                                 int *model)
{
    if (*model > 0) {
        switch (*model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_LSI)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support "
                                 "the LSI 53C895A SCSI controller"));
                return -1;
            }
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_SCSI)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support "
                                 "virtio scsi controller"));
                return -1;
            }
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI:
            /*TODO: need checking work here if necessary */
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1068:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_MPTSAS1068)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support "
                                 "the LSI SAS1068 (MPT Fusion) controller"));
                return -1;
            }
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSISAS1078:
            if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_MEGASAS)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support "
                                 "the LSI SAS1078 (MegaRAID) controller"));
                return -1;
            }
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported controller model: %s"),
                           virDomainControllerModelSCSITypeToString(*model));
            return -1;
        }
    } else {
        if (ARCH_IS_PPC64(def->os.arch) &&
            STRPREFIX(def->os.machine, "pseries")) {
            *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI;
        } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_SCSI_LSI)) {
            *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC;
        } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_SCSI)) {
            *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to determine model for scsi controller"));
            return -1;
        }
    }

    return 0;
}


static int
qemuDomainAssignVirtioSerialAddresses(virDomainDefPtr def,
                                      virDomainObjPtr obj)
{
    int ret = -1;
    size_t i;
    virDomainVirtioSerialAddrSetPtr addrs = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    if (!(addrs = virDomainVirtioSerialAddrSetCreate()))
        goto cleanup;

    if (virDomainVirtioSerialAddrSetAddControllers(addrs, def) < 0)
        goto cleanup;

    if (virDomainDeviceInfoIterate(def, virDomainVirtioSerialAddrReserve,
                                   addrs) < 0)
        goto cleanup;

    VIR_DEBUG("Finished reserving existing ports");

    for (i = 0; i < def->nconsoles; i++) {
        virDomainChrDefPtr chr = def->consoles[i];
        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
            chr->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO &&
            !virDomainVirtioSerialAddrIsComplete(&chr->info) &&
            virDomainVirtioSerialAddrAutoAssign(def, addrs, &chr->info, true) < 0)
            goto cleanup;
    }

    for (i = 0; i < def->nchannels; i++) {
        virDomainChrDefPtr chr = def->channels[i];
        if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
            chr->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO &&
            !virDomainVirtioSerialAddrIsComplete(&chr->info) &&
            virDomainVirtioSerialAddrAutoAssign(def, addrs, &chr->info, false) < 0)
            goto cleanup;
    }

    if (obj && obj->privateData) {
        priv = obj->privateData;
        /* if this is the live domain object, we persist the addresses */
        virDomainVirtioSerialAddrSetFree(priv->vioserialaddrs);
        priv->persistentAddrs = 1;
        priv->vioserialaddrs = addrs;
        addrs = NULL;
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
qemuDomainAssignSpaprVIOAddresses(virDomainDefPtr def,
                                  virQEMUCapsPtr qemuCaps)
{
    size_t i;
    int ret = -1;
    int model;

    /* Default values match QEMU. See spapr_(llan|vscsi|vty).c */

    for (i = 0; i < def->nnets; i++) {
        if (def->nets[i]->model &&
            STREQ(def->nets[i]->model, "spapr-vlan"))
            def->nets[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        if (qemuDomainAssignSpaprVIOAddress(def, &def->nets[i]->info,
                                            VIO_ADDR_NET) < 0)
            goto cleanup;
    }

    for (i = 0; i < def->ncontrollers; i++) {
        model = def->controllers[i]->model;
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            if (qemuDomainSetSCSIControllerModel(def, qemuCaps, &model) < 0)
                goto cleanup;
        }

        if (model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI &&
            def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
            def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        if (qemuDomainAssignSpaprVIOAddress(def, &def->controllers[i]->info,
                                            VIO_ADDR_SCSI) < 0)
            goto cleanup;
    }

    for (i = 0; i < def->nserials; i++) {
        if (def->serials[i]->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
            ARCH_IS_PPC64(def->os.arch) &&
            STRPREFIX(def->os.machine, "pseries"))
            def->serials[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        if (qemuDomainAssignSpaprVIOAddress(def, &def->serials[i]->info,
                                            VIO_ADDR_SERIAL) < 0)
            goto cleanup;
    }

    if (def->nvram) {
        if (ARCH_IS_PPC64(def->os.arch) &&
            STRPREFIX(def->os.machine, "pseries"))
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
qemuDomainPrimeVirtioDeviceAddresses(virDomainDefPtr def,
                                     virDomainDeviceAddressType type)
{
    /*
       declare address-less virtio devices to be of address type 'type'
       disks, networks, consoles, controllers, memballoon and rng in this
       order
       if type is ccw filesystem devices are declared to be of address type ccw
    */
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (def->disks[i]->bus == VIR_DOMAIN_DISK_BUS_VIRTIO &&
            def->disks[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->disks[i]->info.type = type;
    }

    for (i = 0; i < def->nnets; i++) {
        if (STREQ(def->nets[i]->model, "virtio") &&
            def->nets[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            def->nets[i]->info.type = type;
        }
    }

    for (i = 0; i < def->ninputs; i++) {
        if (def->inputs[i]->bus == VIR_DOMAIN_DISK_BUS_VIRTIO &&
            def->inputs[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->inputs[i]->info.type = type;
    }

    for (i = 0; i < def->ncontrollers; i++) {
        if ((def->controllers[i]->type ==
             VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL ||
             def->controllers[i]->type ==
             VIR_DOMAIN_CONTROLLER_TYPE_SCSI) &&
            def->controllers[i]->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->controllers[i]->info.type = type;
    }

    if (def->memballoon &&
        def->memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO &&
        def->memballoon->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
        def->memballoon->info.type = type;

    for (i = 0; i < def->nrngs; i++) {
        if (def->rngs[i]->model == VIR_DOMAIN_RNG_MODEL_VIRTIO &&
            def->rngs[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->rngs[i]->info.type = type;
    }

    if (type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
        for (i = 0; i < def->nfss; i++) {
            if (def->fss[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
                def->fss[i]->info.type = type;
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
                              virQEMUCapsPtr qemuCaps,
                              virDomainObjPtr obj)
{
    int ret = -1;
    virDomainCCWAddressSetPtr addrs = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    if (qemuDomainMachineIsS390CCW(def) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_CCW)) {
        qemuDomainPrimeVirtioDeviceAddresses(
            def, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW);

        if (!(addrs = virDomainCCWAddressSetCreate()))
            goto cleanup;

        if (virDomainDeviceInfoIterate(def, virDomainCCWAddressValidate,
                                       addrs) < 0)
            goto cleanup;

        if (virDomainDeviceInfoIterate(def, virDomainCCWAddressAllocate,
                                       addrs) < 0)
            goto cleanup;
    } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_VIRTIO_S390)) {
        /* deal with legacy virtio-s390 */
        qemuDomainPrimeVirtioDeviceAddresses(
            def, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390);
    }

    if (obj && obj->privateData) {
        priv = obj->privateData;
        if (addrs) {
            /* if this is the live domain object, we persist the CCW addresses*/
            virDomainCCWAddressSetFree(priv->ccwaddrs);
            priv->persistentAddrs = 1;
            priv->ccwaddrs = addrs;
            addrs = NULL;
        } else {
            priv->persistentAddrs = 0;
        }
    }
    ret = 0;

 cleanup:
    virDomainCCWAddressSetFree(addrs);

    return ret;
}


static int
qemuDomainAssignARMVirtioMMIOAddresses(virDomainDefPtr def,
                                       virQEMUCapsPtr qemuCaps)
{
    if (((def->os.arch == VIR_ARCH_ARMV7L) ||
        (def->os.arch == VIR_ARCH_AARCH64)) &&
        (STRPREFIX(def->os.machine, "vexpress-") ||
            STREQ(def->os.machine, "virt") ||
            STRPREFIX(def->os.machine, "virt-")) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_MMIO)) {
        qemuDomainPrimeVirtioDeviceAddresses(
            def, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO);
    }
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
    virDevicePCIAddressPtr addr = &info->addr.pci;
    bool entireSlot;
    /* flags may be changed from default below */
    virDomainPCIConnectFlags flags = (VIR_PCI_CONNECT_HOTPLUGGABLE |
                                      VIR_PCI_CONNECT_TYPE_PCI);

    if ((info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        || ((device->type == VIR_DOMAIN_DEVICE_HOSTDEV) &&
            (device->data.hostdev->parent.type != VIR_DOMAIN_DEVICE_NONE))) {
        /* If a hostdev has a parent, its info will be a part of the
         * parent, and will have its address collected during the scan
         * of the parent's device type.
        */
        return 0;
    }

    /* Change flags according to differing requirements of different
     * devices.
     */
    switch (device->type) {
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        switch (device->data.controller->type) {
        case  VIR_DOMAIN_CONTROLLER_TYPE_PCI:
            switch (device->data.controller->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
                /* pci-bridge needs a PCI slot, but it isn't
                 * hot-pluggable, so it doesn't need a hot-pluggable slot.
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCI;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
                /* pci-bridge needs a PCIe slot, but it isn't
                 * hot-pluggable, so it doesn't need a hot-pluggable slot.
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
                /* pcie-root-port can only connect to pcie-root, isn't
                 * hot-pluggable
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_ROOT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
                /* pcie-switch can only connect to a true
                 * pcie bus, and can't be hot-plugged.
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_PORT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
                /* pcie-switch-downstream-port can only connect to a
                 * pcie-switch-upstream-port, and can't be hot-plugged.
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_SWITCH;
                break;
            default:
                break;
            }
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
            /* SATA controllers aren't hot-plugged, and can be put in
             * either a PCI or PCIe slot
             */
            flags = VIR_PCI_CONNECT_TYPE_PCI | VIR_PCI_CONNECT_TYPE_PCIE;
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_USB:
           /* allow UHCI and EHCI controllers to be manually placed on
            * the PCIe bus (but don't put them there automatically)
            */
           switch (device->data.controller->model) {
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_EHCI:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_VT82C686B_UHCI:
              flags = VIR_PCI_CONNECT_TYPE_PCI;
              break;
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_NEC_XHCI:
              /* should this be PCIE-only? Or do we need to allow PCI
               * for backward compatibility?
               */
              flags = VIR_PCI_CONNECT_TYPE_PCI | VIR_PCI_CONNECT_TYPE_PCIE;
              break;
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_PCI_OHCI:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI:
           case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX4_UHCI:
              /* Allow these for PCI only */
              break;
           }
        }
        break;

    case VIR_DOMAIN_DEVICE_SOUND:
        switch (device->data.sound->model) {
        case VIR_DOMAIN_SOUND_MODEL_ICH6:
        case VIR_DOMAIN_SOUND_MODEL_ICH9:
            flags = VIR_PCI_CONNECT_TYPE_PCI;
            break;
        }
        break;

    case VIR_DOMAIN_DEVICE_VIDEO:
        /* video cards aren't hot-plugged, and can be put in either a
         * PCI or PCIe slot
         */
        flags = VIR_PCI_CONNECT_TYPE_PCI | VIR_PCI_CONNECT_TYPE_PCIE;
        break;
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
              cont->model == -1) && addr->function == 2)) {
            /* Note the check for nbuses > 0 - if there are no PCI
             * buses, we skip this check. This is a quirk required for
             * some machinetypes such as s390, which pretend to have a
             * PCI bus for long enough to generate the "-usb" on the
             * commandline, but that don't really care if a PCI bus
             * actually exists. */
            if (addrs->nbuses > 0 &&
                !(addrs->buses[0].flags & VIR_PCI_CONNECT_TYPE_PCI)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Bus 0 must be PCI for integrated PIIX3 "
                                 "USB or IDE controllers"));
                return -1;
            } else {
                return 0;
            }
        }
    }

    entireSlot = (addr->function == 0 &&
                  addr->multi != VIR_TRISTATE_SWITCH_ON);

    if (virDomainPCIAddressReserveAddr(addrs, addr, flags,
                                       entireSlot, true) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    return ret;
}

static virDomainPCIAddressSetPtr
qemuDomainPCIAddressSetCreate(virDomainDefPtr def,
                              unsigned int nbuses,
                              bool dryRun)
{
    virDomainPCIAddressSetPtr addrs;
    size_t i;

    if ((addrs = virDomainPCIAddressSetAlloc(nbuses)) == NULL)
        return NULL;

    addrs->nbuses = nbuses;
    addrs->dryRun = dryRun;

    /* As a safety measure, set default model='pci-root' for first pci
     * controller and 'pci-bridge' for all subsequent. After setting
     * those defaults, then scan the config and set the actual model
     * for all addrs[idx]->bus that already have a corresponding
     * controller in the config.
     *
     */
    if (nbuses > 0)
        virDomainPCIAddressBusSetModel(&addrs->buses[0],
                                       VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT);
    for (i = 1; i < nbuses; i++) {
        virDomainPCIAddressBusSetModel(&addrs->buses[i],
                                       VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE);
    }

    for (i = 0; i < def->ncontrollers; i++) {
        size_t idx = def->controllers[i]->idx;

        if (def->controllers[i]->type != VIR_DOMAIN_CONTROLLER_TYPE_PCI)
            continue;

        if (idx >= addrs->nbuses) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Inappropriate new pci controller index %zu "
                             "not found in addrs"), idx);
            goto error;
        }

        if (virDomainPCIAddressBusSetModel(&addrs->buses[idx],
                                           def->controllers[i]->model) < 0)
            goto error;
        }

    if (virDomainDeviceInfoIterate(def, qemuDomainCollectPCIAddress, addrs) < 0)
        goto error;

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
    virDevicePCIAddress tmp_addr;
    bool qemuDeviceVideoUsable = virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    char *addrStr = NULL;
    virDomainPCIConnectFlags flags = VIR_PCI_CONNECT_HOTPLUGGABLE | VIR_PCI_CONNECT_TYPE_PCI;

    /* Verify that first IDE and USB controllers (if any) is on the PIIX3, fn 1 */
    for (i = 0; i < def->ncontrollers; i++) {
        /* First IDE controller lives on the PIIX3 at slot=1, function=1 */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
            def->controllers[i]->idx == 0) {
            if (def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                if (def->controllers[i]->info.addr.pci.domain != 0 ||
                    def->controllers[i]->info.addr.pci.bus != 0 ||
                    def->controllers[i]->info.addr.pci.slot != 1 ||
                    def->controllers[i]->info.addr.pci.function != 1) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Primary IDE controller must have PCI address 0:0:1.1"));
                    goto cleanup;
                }
            } else {
                def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                def->controllers[i]->info.addr.pci.domain = 0;
                def->controllers[i]->info.addr.pci.bus = 0;
                def->controllers[i]->info.addr.pci.slot = 1;
                def->controllers[i]->info.addr.pci.function = 1;
            }
        } else if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
                   def->controllers[i]->idx == 0 &&
                   (def->controllers[i]->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI ||
                    def->controllers[i]->model == -1)) {
            if (def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                if (def->controllers[i]->info.addr.pci.domain != 0 ||
                    def->controllers[i]->info.addr.pci.bus != 0 ||
                    def->controllers[i]->info.addr.pci.slot != 1 ||
                    def->controllers[i]->info.addr.pci.function != 2) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("PIIX3 USB controller must have PCI address 0:0:1.2"));
                    goto cleanup;
                }
            } else {
                def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                def->controllers[i]->info.addr.pci.domain = 0;
                def->controllers[i]->info.addr.pci.bus = 0;
                def->controllers[i]->info.addr.pci.slot = 1;
                def->controllers[i]->info.addr.pci.function = 2;
            }
        }
    }

    /* PIIX3 (ISA bridge, IDE controller, something else unknown, USB controller)
     * hardcoded slot=1, multifunction device
     */
    if (addrs->nbuses) {
        memset(&tmp_addr, 0, sizeof(tmp_addr));
        tmp_addr.slot = 1;
        if (virDomainPCIAddressReserveSlot(addrs, &tmp_addr, flags) < 0)
            goto cleanup;
    }

    if (def->nvideos > 0) {
        /* Because the PIIX3 integrated IDE/USB controllers are
         * already at slot 1, when qemu looks for the first free slot
         * to place the VGA controller (which is always the first
         * device added after integrated devices), it *always* ends up
         * at slot 2.
         */
        virDomainVideoDefPtr primaryVideo = def->videos[0];
        if (primaryVideo->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            memset(&tmp_addr, 0, sizeof(tmp_addr));
            tmp_addr.slot = 2;

            if (!(addrStr = virDomainPCIAddressAsString(&tmp_addr)))
                goto cleanup;
            if (!virDomainPCIAddressValidate(addrs, &tmp_addr,
                                             addrStr, flags, false))
                goto cleanup;

            if (virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
                if (qemuDeviceVideoUsable) {
                    if (virDomainPCIAddressReserveNextSlot(addrs,
                                                           &primaryVideo->info,
                                                           flags) < 0)
                        goto cleanup;
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("PCI address 0:0:2.0 is in use, "
                                     "QEMU needs it for primary video"));
                    goto cleanup;
                }
            } else {
                if (virDomainPCIAddressReserveSlot(addrs, &tmp_addr, flags) < 0)
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
        } else if (virDomainPCIAddressReserveSlot(addrs, &tmp_addr, flags) < 0) {
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
    virDevicePCIAddress tmp_addr;
    bool qemuDeviceVideoUsable = virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIDEO_PRIMARY);
    char *addrStr = NULL;
    virDomainPCIConnectFlags flags = VIR_PCI_CONNECT_TYPE_PCIE;

    for (i = 0; i < def->ncontrollers; i++) {
        switch (def->controllers[i]->type) {
        case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
            /* Verify that the first SATA controller is at 00:1F.2 the
             * q35 machine type *always* has a SATA controller at this
             * address.
             */
            if (def->controllers[i]->idx == 0) {
                if (def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                    if (def->controllers[i]->info.addr.pci.domain != 0 ||
                        def->controllers[i]->info.addr.pci.bus != 0 ||
                        def->controllers[i]->info.addr.pci.slot != 0x1F ||
                        def->controllers[i]->info.addr.pci.function != 2) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("Primary SATA controller must have PCI address 0:0:1f.2"));
                        goto cleanup;
                    }
                } else {
                    def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                    def->controllers[i]->info.addr.pci.domain = 0;
                    def->controllers[i]->info.addr.pci.bus = 0;
                    def->controllers[i]->info.addr.pci.slot = 0x1F;
                    def->controllers[i]->info.addr.pci.function = 2;
                }
            }
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_USB:
            if ((def->controllers[i]->model
                 == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1) &&
                (def->controllers[i]->info.type
                 == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)) {
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
                    if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr,
                                                       flags, false, true) < 0)
                        goto cleanup;
                    def->controllers[i]->info.type
                        = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                    def->controllers[i]->info.addr.pci.domain = 0;
                    def->controllers[i]->info.addr.pci.bus = 0;
                    def->controllers[i]->info.addr.pci.slot = tmp_addr.slot;
                    def->controllers[i]->info.addr.pci.function = 0;
                    def->controllers[i]->info.addr.pci.multi
                       = VIR_TRISTATE_SWITCH_ON;
                }
            }
            break;

        case VIR_DOMAIN_CONTROLLER_TYPE_PCI:
            if (def->controllers[i]->model == VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE &&
                def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
                /* Try to assign this bridge to 00:1E.0 (because that
                * is its standard location on real hardware) unless
                * it's already taken, but don't insist on it.
                */
                memset(&tmp_addr, 0, sizeof(tmp_addr));
                tmp_addr.slot = 0x1E;
                if (!virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
                    if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr,
                                                       flags, true, false) < 0)
                        goto cleanup;
                    def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                    def->controllers[i]->info.addr.pci.domain = 0;
                    def->controllers[i]->info.addr.pci.bus = 0;
                    def->controllers[i]->info.addr.pci.slot = 0x1E;
                    def->controllers[i]->info.addr.pci.function = 0;
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
        if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags,
                                           false, false) < 0)
           goto cleanup;
        tmp_addr.function = 3;
        tmp_addr.multi = VIR_TRISTATE_SWITCH_ABSENT;
        if (virDomainPCIAddressReserveAddr(addrs, &tmp_addr, flags,
                                           false, false) < 0)
           goto cleanup;
    }

    if (def->nvideos > 0) {
        /* NB: unlike the pc machinetypes, on q35 machinetypes the
         * integrated devices are at slot 0x1f, so when qemu looks for
         * the first free lot for the first VGA, it will always be at
         * slot 1 (which was used up by the integrated PIIX3 devices
         * on pc machinetypes).
         */
        virDomainVideoDefPtr primaryVideo = def->videos[0];
        if (primaryVideo->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            memset(&tmp_addr, 0, sizeof(tmp_addr));
            tmp_addr.slot = 1;

            if (!(addrStr = virDomainPCIAddressAsString(&tmp_addr)))
                goto cleanup;
            if (!virDomainPCIAddressValidate(addrs, &tmp_addr,
                                             addrStr, flags, false))
                goto cleanup;

            if (virDomainPCIAddressSlotInUse(addrs, &tmp_addr)) {
                if (qemuDeviceVideoUsable) {
                    if (virDomainPCIAddressReserveNextSlot(addrs,
                                                           &primaryVideo->info,
                                                           flags) < 0)
                        goto cleanup;
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("PCI address 0:0:1.0 is in use, "
                                     "QEMU needs it for primary video"));
                    goto cleanup;
                }
            } else {
                if (virDomainPCIAddressReserveSlot(addrs, &tmp_addr, flags) < 0)
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
        } else if (virDomainPCIAddressReserveSlot(addrs, &tmp_addr, flags) < 0) {
            goto cleanup;
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
    if (qemuDomainMachineIsI440FX(def) &&
        qemuDomainValidateDevicePCISlotsPIIX3(def, qemuCaps, addrs) < 0) {
        return -1;
    }

    if (qemuDomainMachineIsQ35(def) &&
        qemuDomainValidateDevicePCISlotsQ35(def, qemuCaps, addrs) < 0) {
        return -1;
    }

    return 0;
}


static bool
qemuDomainPCIBusFullyReserved(virDomainPCIAddressBusPtr bus)
{
    size_t i;

    for (i = bus->minSlot; i <= bus->maxSlot; i++)
        if (!bus->slots[i])
            return false;

    return true;
}


#define IS_USB2_CONTROLLER(ctrl) \
    (((ctrl)->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) && \
     ((ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3))

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
 *    qemuValidateDevicePCISlotsChipsets invoked right before this function
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
    virDomainPCIConnectFlags flags;
    virDevicePCIAddress tmp_addr;

    /* PCI controllers */
    for (i = 0; i < def->ncontrollers; i++) {
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
            if (def->controllers[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
                continue;
            switch (def->controllers[i]->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
                /* pci-root and pcie-root are implicit in the machine,
                 * and needs no address */
                continue;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
                /* pci-bridge doesn't require hot-plug
                 * (although it does provide hot-plug in its slots)
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCI;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
                /* dmi-to-pci-bridge requires a non-hotplug PCIe
                 * slot
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
                /* pcie-root-port can only plug into pcie-root */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_ROOT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
                /* pcie-switch really does need a real PCIe
                 * port, but it doesn't need to be pcie-root
                 */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_PORT;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
                /* pcie-switch-port can only plug into pcie-switch */
                flags = VIR_PCI_CONNECT_TYPE_PCIE_SWITCH;
                break;
            default:
                flags = VIR_PCI_CONNECT_HOTPLUGGABLE | VIR_PCI_CONNECT_TYPE_PCI;
                break;
            }
            if (virDomainPCIAddressReserveNextSlot(addrs,
                                                   &def->controllers[i]->info,
                                                   flags) < 0)
                goto error;
        }
    }

    flags = VIR_PCI_CONNECT_HOTPLUGGABLE | VIR_PCI_CONNECT_TYPE_PCI;

    for (i = 0; i < def->nfss; i++) {
        if (def->fss[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        /* Only support VirtIO-9p-pci so far. If that changes,
         * we might need to skip devices here */
        if (virDomainPCIAddressReserveNextSlot(addrs, &def->fss[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* Network interfaces */
    for (i = 0; i < def->nnets; i++) {
        /* type='hostdev' network devices might be USB, and are also
         * in hostdevs list anyway, so handle them with other hostdevs
         * instead of here.
         */
        if ((def->nets[i]->type == VIR_DOMAIN_NET_TYPE_HOSTDEV) ||
            (def->nets[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)) {
            continue;
        }
        if (virDomainPCIAddressReserveNextSlot(addrs, &def->nets[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* Sound cards */
    for (i = 0; i < def->nsounds; i++) {
        if (def->sounds[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        /* Skip ISA sound card, PCSPK and usb-audio */
        if (def->sounds[i]->model == VIR_DOMAIN_SOUND_MODEL_SB16 ||
            def->sounds[i]->model == VIR_DOMAIN_SOUND_MODEL_PCSPK ||
            def->sounds[i]->model == VIR_DOMAIN_SOUND_MODEL_USB)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs, &def->sounds[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* Device controllers (SCSI, USB, but not IDE, FDC or CCID) */
    for (i = 0; i < def->ncontrollers; i++) {
        /* PCI controllers have been dealt with earlier */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI)
            continue;

        /* USB controller model 'none' doesn't need a PCI address */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
            def->controllers[i]->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE)
            continue;

        /* FDC lives behind the ISA bridge; CCID is a usb device */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_FDC ||
            def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_CCID)
            continue;

        /* First IDE controller lives on the PIIX3 at slot=1, function=1,
           dealt with earlier on*/
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
            def->controllers[i]->idx == 0)
            continue;

        if (def->controllers[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        /* USB2 needs special handling to put all companions in the same slot */
        if (IS_USB2_CONTROLLER(def->controllers[i])) {
            virDevicePCIAddress addr = { 0, 0, 0, 0, false };
            bool foundAddr = false;

            memset(&tmp_addr, 0, sizeof(tmp_addr));
            for (j = 0; j < def->ncontrollers; j++) {
                if (IS_USB2_CONTROLLER(def->controllers[j]) &&
                    def->controllers[j]->idx == def->controllers[i]->idx &&
                    def->controllers[j]->info.type
                    == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                    addr = def->controllers[j]->info.addr.pci;
                    foundAddr = true;
                    break;
                }
            }

            switch (def->controllers[i]->model) {
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

            if (!foundAddr) {
                /* This is the first part of the controller, so need
                 * to find a free slot & then reserve a function */
                if (virDomainPCIAddressGetNextSlot(addrs, &tmp_addr, flags) < 0)
                    goto error;

                addr.bus = tmp_addr.bus;
                addr.slot = tmp_addr.slot;

                addrs->lastaddr = addr;
                addrs->lastaddr.function = 0;
                addrs->lastaddr.multi = VIR_TRISTATE_SWITCH_ABSENT;
            }
            /* Finally we can reserve the slot+function */
            if (virDomainPCIAddressReserveAddr(addrs, &addr, flags,
                                               false, foundAddr) < 0)
                goto error;

            def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            def->controllers[i]->info.addr.pci = addr;
        } else {
            if (virDomainPCIAddressReserveNextSlot(addrs,
                                                   &def->controllers[i]->info,
                                                   flags) < 0)
                goto error;
        }
    }

    /* Disks (VirtIO only for now) */
    for (i = 0; i < def->ndisks; i++) {
        /* Only VirtIO disks use PCI addrs */
        if (def->disks[i]->bus != VIR_DOMAIN_DISK_BUS_VIRTIO)
            continue;

        /* don't touch s390 devices */
        if (def->disks[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI ||
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

        if (def->disks[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("virtio disk cannot have an address of type '%s'"),
                           virDomainDeviceAddressTypeToString(def->disks[i]->info.type));
            goto error;
        }

        if (virDomainPCIAddressReserveNextSlot(addrs, &def->disks[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* Host PCI devices */
    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        if (def->hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            def->hostdevs[i]->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs,
                                               def->hostdevs[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* VirtIO balloon */
    if (def->memballoon &&
        def->memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO &&
        def->memballoon->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (virDomainPCIAddressReserveNextSlot(addrs,
                                               &def->memballoon->info,
                                               flags) < 0)
            goto error;
    }

    /* VirtIO RNG */
    for (i = 0; i < def->nrngs; i++) {
        if (def->rngs[i]->model != VIR_DOMAIN_RNG_MODEL_VIRTIO ||
            def->rngs[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs,
                                               &def->rngs[i]->info, flags) < 0)
            goto error;
    }

    /* A watchdog - check if it is a PCI device */
    if (def->watchdog &&
        def->watchdog->model == VIR_DOMAIN_WATCHDOG_MODEL_I6300ESB &&
        def->watchdog->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (virDomainPCIAddressReserveNextSlot(addrs, &def->watchdog->info,
                                               flags) < 0)
            goto error;
    }

    /* Assign a PCI slot to the primary video card if there is not an
     * assigned address. */
    if (def->nvideos > 0 &&
        def->videos[0]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (virDomainPCIAddressReserveNextSlot(addrs, &def->videos[0]->info,
                                               flags) < 0)
            goto error;
    }

    /* Further non-primary video cards which have to be qxl type */
    for (i = 1; i < def->nvideos; i++) {
        if (def->videos[i]->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("non-primary video device must be type of 'qxl'"));
            goto error;
        }
        if (def->videos[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        if (virDomainPCIAddressReserveNextSlot(addrs, &def->videos[i]->info,
                                               flags) < 0)
            goto error;
    }

    /* Shared Memory */
    for (i = 0; i < def->nshmems; i++) {
        if (def->shmems[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs,
                                               &def->shmems[i]->info, flags) < 0)
            goto error;
    }
    for (i = 0; i < def->ninputs; i++) {
        if (def->inputs[i]->bus != VIR_DOMAIN_INPUT_BUS_VIRTIO)
            continue;
        if (def->inputs[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs,
                                               &def->inputs[i]->info, flags) < 0)
            goto error;
    }
    for (i = 0; i < def->nparallels; i++) {
        /* Nada - none are PCI based (yet) */
    }
    for (i = 0; i < def->nserials; i++) {
        virDomainChrDefPtr chr = def->serials[i];

        if (chr->targetType != VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI)
            continue;

        if (chr->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        if (virDomainPCIAddressReserveNextSlot(addrs, &chr->info, flags) < 0)
            goto error;
    }
    for (i = 0; i < def->nchannels; i++) {
        /* Nada - none are PCI based (yet) */
    }
    for (i = 0; i < def->nhubs; i++) {
        /* Nada - none are PCI based (yet) */
    }

    return 0;

 error:
    return -1;
}


static bool
qemuDomainSupportsPCI(virDomainDefPtr def,
                      virQEMUCapsPtr qemuCaps)
{
    if ((def->os.arch != VIR_ARCH_ARMV7L) && (def->os.arch != VIR_ARCH_AARCH64))
        return true;

    if (STREQ(def->os.machine, "versatilepb"))
        return true;

    if ((STREQ(def->os.machine, "virt") ||
         STRPREFIX(def->os.machine, "virt-")) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_OBJECT_GPEX))
        return true;

    return false;
}


static int
qemuDomainAssignPCIAddresses(virDomainDefPtr def,
                             virQEMUCapsPtr qemuCaps,
                             virDomainObjPtr obj)
{
    int ret = -1;
    virDomainPCIAddressSetPtr addrs = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE)) {
        int max_idx = -1;
        int nbuses = 0;
        size_t i;
        int rv;
        bool buses_reserved = true;

        virDomainPCIConnectFlags flags = VIR_PCI_CONNECT_TYPE_PCI;

        for (i = 0; i < def->ncontrollers; i++) {
            if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
                if ((int) def->controllers[i]->idx > max_idx)
                    max_idx = def->controllers[i]->idx;
            }
        }

        nbuses = max_idx + 1;

        if (nbuses > 0 &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_PCI_BRIDGE)) {
            virDomainDeviceInfo info;

            /* 1st pass to figure out how many PCI bridges we need */
            if (!(addrs = qemuDomainPCIAddressSetCreate(def, nbuses, true)))
                goto cleanup;

            if (qemuDomainValidateDevicePCISlotsChipsets(def, qemuCaps,
                                                         addrs) < 0)
                goto cleanup;

            for (i = 0; i < addrs->nbuses; i++) {
                if (!qemuDomainPCIBusFullyReserved(&addrs->buses[i]))
                    buses_reserved = false;
            }

            /* Reserve 1 extra slot for a (potential) bridge only if buses
             * are not fully reserved yet
             */
            if (!buses_reserved &&
                virDomainPCIAddressReserveNextSlot(addrs, &info, flags) < 0)
                goto cleanup;

            if (qemuDomainAssignDevicePCISlots(def, qemuCaps, addrs) < 0)
                goto cleanup;

            for (i = 1; i < addrs->nbuses; i++) {
                virDomainPCIAddressBusPtr bus = &addrs->buses[i];

                if ((rv = virDomainDefMaybeAddController(
                         def, VIR_DOMAIN_CONTROLLER_TYPE_PCI,
                         i, bus->model)) < 0)
                    goto cleanup;
                /* If we added a new bridge, we will need one more address */
                if (rv > 0 &&
                    virDomainPCIAddressReserveNextSlot(addrs, &info, flags) < 0)
                    goto cleanup;
            }
            nbuses = addrs->nbuses;
            virDomainPCIAddressSetFree(addrs);
            addrs = NULL;

        } else if (max_idx > 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("PCI bridges are not supported "
                             "by this QEMU binary"));
            goto cleanup;
        }

        if (!(addrs = qemuDomainPCIAddressSetCreate(def, nbuses, false)))
            goto cleanup;

        if (qemuDomainSupportsPCI(def, qemuCaps)) {
            if (qemuDomainValidateDevicePCISlotsChipsets(def, qemuCaps,
                                                         addrs) < 0)
                goto cleanup;

            if (qemuDomainAssignDevicePCISlots(def, qemuCaps, addrs) < 0)
                goto cleanup;

            for (i = 0; i < def->ncontrollers; i++) {
                virDomainControllerDefPtr cont = def->controllers[i];
                int idx = cont->idx;
                virDevicePCIAddressPtr addr;
                virDomainPCIControllerOptsPtr options;

                if (cont->type != VIR_DOMAIN_CONTROLLER_TYPE_PCI)
                    continue;

                addr = &cont->info.addr.pci;
                options = &cont->opts.pciopts;

                /* set defaults for any other auto-generated config
                 * options for this controller that haven't been
                 * specified in config.
                 */
                switch ((virDomainControllerModelPCI)cont->model) {
                case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
                    if (options->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
                        options->modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_PCI_BRIDGE;
                    if (options->chassisNr == -1)
                        options->chassisNr = cont->idx;
                    break;
                case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
                    if (options->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
                        options->modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_I82801B11_BRIDGE;
                    break;
                case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
                    if (options->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
                        options->modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_IOH3420;
                    if (options->chassis == -1)
                       options->chassis = cont->idx;
                    if (options->port == -1)
                       options->port = (addr->slot << 3) + addr->function;
                    break;
                case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
                    if (options->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
                        options->modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_X3130_UPSTREAM;
                    break;
                case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
                    if (options->modelName == VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_NONE)
                        options->modelName = VIR_DOMAIN_CONTROLLER_PCI_MODEL_NAME_XIO3130_DOWNSTREAM;
                    if (options->chassis == -1)
                       options->chassis = cont->idx;
                    if (options->port == -1)
                       options->port = addr->slot;
                    break;
                case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
                case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
                case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
                    break;
                }

                /* check if every PCI bridge controller's ID is greater than
                 * the bus it is placed onto
                 */
                if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE &&
                    idx <= addr->bus) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("failed to create PCI bridge "
                                     "on bus %d: too many devices with fixed "
                                     "addresses"),
                                   addr->bus);
                    goto cleanup;
                }
            }
        }
    }

    if (obj && obj->privateData) {
        priv = obj->privateData;
        if (addrs) {
            /* if this is the live domain object, we persist the PCI addresses*/
            virDomainPCIAddressSetFree(priv->pciaddrs);
            priv->persistentAddrs = 1;
            priv->pciaddrs = addrs;
            addrs = NULL;
        } else {
            priv->persistentAddrs = 0;
        }
    }

    ret = 0;

 cleanup:
    virDomainPCIAddressSetFree(addrs);

    return ret;
}


int
qemuDomainAssignAddresses(virDomainDefPtr def,
                          virQEMUCapsPtr qemuCaps,
                          virDomainObjPtr obj)
{
    int rc;

    rc = qemuDomainAssignVirtioSerialAddresses(def, obj);
    if (rc)
        return rc;

    rc = qemuDomainAssignSpaprVIOAddresses(def, qemuCaps);
    if (rc)
        return rc;

    rc = qemuDomainAssignS390Addresses(def, qemuCaps, obj);
    if (rc)
        return rc;

    rc = qemuDomainAssignARMVirtioMMIOAddresses(def, qemuCaps);
    if (rc)
        return rc;

    return qemuDomainAssignPCIAddresses(def, qemuCaps, obj);
}


void
qemuDomainReleaseDeviceAddress(virDomainObjPtr vm,
                               virDomainDeviceInfoPtr info,
                               const char *devstr)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!devstr)
        devstr = info->alias;

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW &&
        qemuDomainMachineIsS390CCW(vm->def) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_VIRTIO_CCW) &&
        virDomainCCWAddressReleaseAddr(priv->ccwaddrs, info) < 0)
        VIR_WARN("Unable to release CCW address on %s",
                 NULLSTR(devstr));
    else if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
             virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DEVICE) &&
             virDomainPCIAddressReleaseSlot(priv->pciaddrs,
                                            &info->addr.pci) < 0)
        VIR_WARN("Unable to release PCI address on %s",
                 NULLSTR(devstr));
    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL &&
        virDomainVirtioSerialAddrRelease(priv->vioserialaddrs, info) < 0)
        VIR_WARN("Unable to release virtio-serial address on %s",
                 NULLSTR(devstr));
}
