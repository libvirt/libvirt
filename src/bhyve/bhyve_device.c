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
 *
 * Author: Roman Bogorodskiy
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
bhyveCollectPCIAddress(virDomainDefPtr def ATTRIBUTE_UNUSED,
                       virDomainDeviceDefPtr device ATTRIBUTE_UNUSED,
                       virDomainDeviceInfoPtr info,
                       void *opaque)
{
    int ret = -1;
    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
        return 0;

    virDomainPCIAddressSetPtr addrs = opaque;
    virPCIDeviceAddressPtr addr = &info->addr.pci;

    if (addr->domain == 0 && addr->bus == 0) {
        if (addr->slot == 0) {
            return 0;
        } else if (addr->slot == 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("PCI bus 0 slot 1 is reserved for the implicit "
                             "LPC PCI-ISA bridge"));
            return -1;
        }
    }

    if (virDomainPCIAddressReserveAddr(addrs, addr,
                                       VIR_PCI_CONNECT_TYPE_PCI_DEVICE) < 0) {
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

virDomainPCIAddressSetPtr
bhyveDomainPCIAddressSetCreate(virDomainDefPtr def, unsigned int nbuses)
{
    virDomainPCIAddressSetPtr addrs;

    if ((addrs = virDomainPCIAddressSetAlloc(nbuses)) == NULL)
        return NULL;

    if (virDomainPCIAddressBusSetModel(&addrs->buses[0],
                                       VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) < 0)
        goto error;

    if (virDomainDeviceInfoIterate(def, bhyveCollectPCIAddress, addrs) < 0)
        goto error;

    return addrs;

 error:
    virDomainPCIAddressSetFree(addrs);
    return NULL;
}

static int
bhyveAssignDevicePCISlots(virDomainDefPtr def,
                          virDomainPCIAddressSetPtr addrs)
{
    size_t i;
    virPCIDeviceAddress lpc_addr;

    /* explicitly reserve slot 1 for LPC-ISA bridge */
    memset(&lpc_addr, 0, sizeof(lpc_addr));
    lpc_addr.slot = 0x1;

    if (virDomainPCIAddressReserveAddr(addrs, &lpc_addr,
                                       VIR_PCI_CONNECT_TYPE_PCI_DEVICE) < 0) {
        goto error;
    }

    for (i = 0; i < def->ncontrollers; i++) {
        if ((def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) ||
            (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_SATA)) {
            if (def->controllers[i]->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT ||
                !virDeviceInfoPCIAddressWanted(&def->controllers[i]->info))
                continue;

            if (virDomainPCIAddressReserveNextAddr(addrs,
                                                   &def->controllers[i]->info,
                                                   VIR_PCI_CONNECT_TYPE_PCI_DEVICE,
                                                   -1) < 0)
                goto error;
        }
    }

    for (i = 0; i < def->nnets; i++) {
        if (!virDeviceInfoPCIAddressWanted(&def->nets[i]->info))
            continue;
        if (virDomainPCIAddressReserveNextAddr(addrs,
                                               &def->nets[i]->info,
                                               VIR_PCI_CONNECT_TYPE_PCI_DEVICE,
                                               -1) < 0)
            goto error;
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
            goto error;
    }

    return 0;

 error:
    return -1;
}

int bhyveDomainAssignPCIAddresses(virDomainDefPtr def,
                                  virDomainObjPtr obj)
{
    virDomainPCIAddressSetPtr addrs = NULL;
    bhyveDomainObjPrivatePtr priv = NULL;

    int ret = -1;

    if (!(addrs = bhyveDomainPCIAddressSetCreate(def, 1)))
        goto cleanup;

    if (bhyveAssignDevicePCISlots(def, addrs) < 0)
        goto cleanup;

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

    ret = 0;

 cleanup:
    return ret;
}

int bhyveDomainAssignAddresses(virDomainDefPtr def, virDomainObjPtr obj)
{
    return bhyveDomainAssignPCIAddresses(def, obj);
}
