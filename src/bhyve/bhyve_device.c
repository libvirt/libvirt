/*
 * bhyve_device.c: bhyve device management
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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

#include "bhyve_device.h"
#include "domain_addr.h"
#include "viralloc.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_device");

static int
bhyveCollectPCIAddress(virDomainDef *def G_GNUC_UNUSED,
                       virDomainDeviceDef *device G_GNUC_UNUSED,
                       virDomainDeviceInfo *info,
                       void *opaque)
{
    virDomainPCIAddressSet *addrs = NULL;
    virPCIDeviceAddress *addr = NULL;
    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
        return 0;

    addrs = opaque;
    addr = &info->addr.pci;

    if (addr->domain == 0 && addr->bus == 0 && addr->slot == 0) {
            return 0;
    }

    if (virDomainPCIAddressReserveAddr(addrs, addr,
                                       VIR_PCI_CONNECT_TYPE_PCI_DEVICE, 0) < 0) {
        return -1;
    }

    return 0;
}

virDomainPCIAddressSet *
bhyveDomainPCIAddressSetCreate(virDomainDef *def, unsigned int nbuses)
{
    virDomainPCIAddressSet *addrs;

    if ((addrs = virDomainPCIAddressSetAlloc(nbuses,
                                             VIR_PCI_ADDRESS_EXTENSION_NONE)) == NULL)
        return NULL;

    if (virDomainPCIAddressBusSetModel(&addrs->buses[0],
                                       VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT,
                                       true) < 0)
        goto error;

    if (virDomainDeviceInfoIterate(def, bhyveCollectPCIAddress, addrs) < 0)
        goto error;

    return addrs;

 error:
    virDomainPCIAddressSetFree(addrs);
    return NULL;
}

static int
bhyveAssignDevicePCISlots(virDomainDef *def,
                          virDomainPCIAddressSet *addrs)
{
    size_t i;
    virPCIDeviceAddress lpc_addr = { .slot = 0x1 };

    /* If the user didn't explicitly specify slot 1 for some of the devices,
       reserve it for LPC, even if there's no LPC device configured.
       If the slot 1 is used by some other device, LPC will have an address
       auto-assigned.

       The idea behind that is to try to use slot 1 for the LPC device unless
       user specifically configured otherwise.*/
    if (!virDomainPCIAddressSlotInUse(addrs, &lpc_addr)) {
        if (virDomainPCIAddressReserveAddr(addrs, &lpc_addr,
                                           VIR_PCI_CONNECT_TYPE_PCI_DEVICE, 0) < 0) {
            return -1;
        }

        for (i = 0; i < def->ncontrollers; i++) {
             if ((def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_ISA) &&
                  virDeviceInfoPCIAddressIsWanted(&def->controllers[i]->info)) {
                 def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                 def->controllers[i]->info.addr.pci = lpc_addr;
                 break;
             }
        }
    }

    for (i = 0; i < def->ncontrollers; i++) {
        if ((def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) ||
            (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_SATA) ||
            ((def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) &&
             (def->controllers[i]->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NEC_XHCI)) ||
            def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_ISA) {
            if (def->controllers[i]->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT ||
                !virDeviceInfoPCIAddressIsWanted(&def->controllers[i]->info))
                continue;

            if (virDomainPCIAddressReserveNextAddr(addrs,
                                                   &def->controllers[i]->info,
                                                   VIR_PCI_CONNECT_TYPE_PCI_DEVICE,
                                                   -1) < 0)
                return -1;
        }
    }

    for (i = 0; i < def->nnets; i++) {
        if (!virDeviceInfoPCIAddressIsWanted(&def->nets[i]->info))
            continue;
        if (virDomainPCIAddressReserveNextAddr(addrs,
                                               &def->nets[i]->info,
                                               VIR_PCI_CONNECT_TYPE_PCI_DEVICE,
                                               -1) < 0)
            return -1;
    }

    for (i = 0; i < def->ndisks; i++) {
        /* We only handle virtio disk addresses as SATA disks are
         * attached to a controller and don't have their own PCI
         * addresses */
        if (def->disks[i]->bus != VIR_DOMAIN_DISK_BUS_VIRTIO)
            continue;

        if (def->disks[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
            !virPCIDeviceAddressIsEmpty(&def->disks[i]->info.addr.pci))
            continue;
        if (virDomainPCIAddressReserveNextAddr(addrs, &def->disks[i]->info,
                                               VIR_PCI_CONNECT_TYPE_PCI_DEVICE,
                                               -1) < 0)
            return -1;
    }

    for (i = 0; i < def->nvideos; i++) {
        if (!virDeviceInfoPCIAddressIsWanted(&def->videos[i]->info))
            continue;
        if (virDomainPCIAddressReserveNextAddr(addrs,
                                               &def->videos[i]->info,
                                               VIR_PCI_CONNECT_TYPE_PCI_DEVICE,
                                               -1) < 0)
            return -1;
    }

    for (i = 0; i < def->nsounds; i++) {
        if (!virDeviceInfoPCIAddressIsWanted(&def->sounds[i]->info))
            continue;
        if (virDomainPCIAddressReserveNextAddr(addrs,
                                               &def->sounds[i]->info,
                                               VIR_PCI_CONNECT_TYPE_PCI_DEVICE,
                                               -1) < 0)
            return -1;
    }

    for (i = 0; i < def->nfss; i++) {
        if (!virDeviceInfoPCIAddressIsWanted(&def->fss[i]->info))
            continue;
        if (virDomainPCIAddressReserveNextAddr(addrs,
                                               &def->fss[i]->info,
                                               VIR_PCI_CONNECT_TYPE_PCI_DEVICE,
                                               -1) < 0)
            return -1;
    }

    return 0;
}

int bhyveDomainAssignPCIAddresses(virDomainDef *def,
                                  virDomainObj *obj)
{
    virDomainPCIAddressSet *addrs = NULL;
    bhyveDomainObjPrivate *priv = NULL;

    if (!(addrs = bhyveDomainPCIAddressSetCreate(def, 1)))
        return -1;

    if (bhyveAssignDevicePCISlots(def, addrs) < 0)
        return -1;

    if (obj && obj->privateData) {
        priv = obj->privateData;
        if (addrs) {
            virDomainPCIAddressSetFree(priv->pciaddrs);
            priv->persistentAddrs = 1;
            priv->pciaddrs = addrs;
        } else {
            priv->persistentAddrs = 0;
        }
    }

    return 0;
}

int bhyveDomainAssignAddresses(virDomainDef *def, virDomainObj *obj)
{
    return bhyveDomainAssignPCIAddresses(def, obj);
}
