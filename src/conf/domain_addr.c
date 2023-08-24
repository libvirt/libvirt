/*
 * domain_addr.c: helper APIs for managing domain device addresses
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

#include "viralloc.h"
#include "virlog.h"
#include "domain_addr.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.domain_addr");

static int
virDomainZPCIAddressReserveId(GHashTable *set,
                              virZPCIDeviceAddressID *id,
                              const char *name)
{
    int *idval;

    if (!id->isSet) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No zPCI %1$s to reserve"),
                       name);
        return -1;
    }

    if (g_hash_table_lookup(set, &id->value)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("zPCI %1$s %2$o is already reserved"),
                       name, id->value);
        return -1;
    }

    idval = g_new0(int, 1);
    *idval = (int) id->value;

    g_hash_table_add(set, idval);

    return 0;
}


static int
virDomainZPCIAddressReserveUid(GHashTable *set,
                               virZPCIDeviceAddress *addr)
{
    return virDomainZPCIAddressReserveId(set, &addr->uid, "uid");
}


static int
virDomainZPCIAddressReserveFid(GHashTable *set,
                               virZPCIDeviceAddress *addr)
{
    return virDomainZPCIAddressReserveId(set, &addr->fid, "fid");
}


static int
virDomainZPCIAddressAssignId(GHashTable *set,
                             virZPCIDeviceAddressID *id,
                             unsigned int min,
                             unsigned int max,
                             const char *name)
{
    if (id->isSet)
        return 0;

    while (g_hash_table_lookup(set, &min)) {
        if (min == max) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("There is no more free %1$s."),
                           name);
            return -1;
        }
        ++min;
    }

    id->value = min;
    id->isSet = true;

    return 0;
}


static int
virDomainZPCIAddressAssignUid(GHashTable *set,
                              virZPCIDeviceAddress *addr)
{
    return virDomainZPCIAddressAssignId(set, &addr->uid, 1,
                                        VIR_DOMAIN_DEVICE_ZPCI_MAX_UID, "uid");
}


static int
virDomainZPCIAddressAssignFid(GHashTable *set,
                              virZPCIDeviceAddress *addr)
{
    return virDomainZPCIAddressAssignId(set, &addr->fid, 0,
                                        VIR_DOMAIN_DEVICE_ZPCI_MAX_FID, "fid");
}


static void
virDomainZPCIAddressReleaseId(GHashTable *set,
                              virZPCIDeviceAddressID *id)
{
    if (!id->isSet)
        return;

    g_hash_table_remove(set, &id->value);

    id->value = 0;
    id->isSet = false;
}


static void
virDomainZPCIAddressReleaseIds(virDomainZPCIAddressIds *zpciIds,
                               virZPCIDeviceAddress *addr)
{
    if (!zpciIds)
        return;

    virDomainZPCIAddressReleaseId(zpciIds->uids, &addr->uid);
    virDomainZPCIAddressReleaseId(zpciIds->fids, &addr->fid);
}


static int
virDomainZPCIAddressEnsureAddr(virDomainZPCIAddressIds *zpciIds,
                               virZPCIDeviceAddress *addr)
{
    if (virDomainZPCIAddressAssignUid(zpciIds->uids, addr) < 0)
        return -1;

    if (virDomainZPCIAddressAssignFid(zpciIds->fids, addr) < 0)
        return -1;

    if (virDomainZPCIAddressReserveUid(zpciIds->uids, addr) < 0)
        return -1;

    if (virDomainZPCIAddressReserveFid(zpciIds->fids, addr) < 0) {
        virDomainZPCIAddressReleaseId(zpciIds->uids, &addr->uid);
        return -1;
    }

    return 0;
}


int
virDomainPCIAddressExtensionReserveAddr(virDomainPCIAddressSet *addrs,
                                        virPCIDeviceAddress *addr)
{
    if (addr->extFlags & VIR_PCI_ADDRESS_EXTENSION_ZPCI) {
        /* Reserve uid/fid to ZPCI device which has defined uid/fid
         * in the domain.
         */
        return virDomainZPCIAddressEnsureAddr(addrs->zpciIds, &addr->zpci);
    }

    return 0;
}


int
virDomainPCIAddressExtensionReserveNextAddr(virDomainPCIAddressSet *addrs,
                                            virPCIDeviceAddress *addr)
{
    if (addr->extFlags & VIR_PCI_ADDRESS_EXTENSION_ZPCI) {
        virZPCIDeviceAddress zpci = addr->zpci;

        if (virDomainZPCIAddressEnsureAddr(addrs->zpciIds, &zpci) < 0)
            return -1;

        if (!addrs->dryRun)
            addr->zpci = zpci;
    }

    return 0;
}


static int
virDomainPCIAddressExtensionEnsureAddr(virDomainPCIAddressSet *addrs,
                                       virPCIDeviceAddress *addr)
{
    if (addr->extFlags & VIR_PCI_ADDRESS_EXTENSION_ZPCI) {
        virZPCIDeviceAddress *zpci = &addr->zpci;

        if (virDomainZPCIAddressEnsureAddr(addrs->zpciIds, zpci) < 0)
            return -1;
    }

    return 0;
}


virDomainPCIConnectFlags
virDomainPCIControllerModelToConnectType(virDomainControllerModelPCI model)
{
    /* given a VIR_DOMAIN_CONTROLLER_MODEL_PCI*, return
     * the equivalent VIR_PCI_CONNECT_TYPE_*.
     */
    switch (model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
        /* pci-root and pcie-root are implicit in the machine,
         * and have no upstream connection, "last" will never actually
         * happen, it's just there so that all possible cases are
         * covered in the switch (keeps the compiler happy).
         */
        return 0;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
        return VIR_PCI_CONNECT_TYPE_PCI_BRIDGE;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
        return VIR_PCI_CONNECT_TYPE_PCI_EXPANDER_BUS;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
        return VIR_PCI_CONNECT_TYPE_PCIE_EXPANDER_BUS;

    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
        return VIR_PCI_CONNECT_TYPE_DMI_TO_PCI_BRIDGE;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        return VIR_PCI_CONNECT_TYPE_PCIE_TO_PCI_BRIDGE;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
        return VIR_PCI_CONNECT_TYPE_PCIE_ROOT_PORT | VIR_PCI_CONNECT_AGGREGATE_SLOT;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
        return VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_UPSTREAM_PORT;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
        return VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_DOWNSTREAM_PORT;
    }
    return 0;
}


static int
virDomainPCIControllerConnectTypeToModel(virDomainPCIConnectFlags flags)
{
    if (flags & VIR_PCI_CONNECT_TYPE_PCIE_ROOT_PORT)
        return VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT;

    if (flags & VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_UPSTREAM_PORT)
        return VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT;

    if (flags & VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_DOWNSTREAM_PORT)
        return VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT;

    if (flags & VIR_PCI_CONNECT_TYPE_DMI_TO_PCI_BRIDGE)
        return VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE;

    if (flags & VIR_PCI_CONNECT_TYPE_PCI_EXPANDER_BUS)
        return VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS;

    if (flags & VIR_PCI_CONNECT_TYPE_PCIE_EXPANDER_BUS)
        return VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS;

    if (flags & VIR_PCI_CONNECT_TYPE_PCI_BRIDGE)
        return VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE;

    /* some connect types don't correspond to a controller model */
    return -1;
}


static bool
virDomainPCIAddressFlagsCompatible(virPCIDeviceAddress *addr,
                                   const char *addrStr,
                                   virDomainPCIConnectFlags busFlags,
                                   virDomainPCIConnectFlags devFlags,
                                   bool reportError,
                                   bool fromConfig)
{
    virErrorNumber errType = (fromConfig
                              ? VIR_ERR_XML_ERROR : VIR_ERR_INTERNAL_ERROR);

    if (devFlags & VIR_PCI_CONNECT_INTEGRATED) {
        if (addr->bus == 0) {
            /* pcie-root doesn't usually allow endpoint devices to be
             * plugged directly into it, but for integrated devices
             * that's exactly what we want. It also refuses conventional
             * PCI devices by default, but in the case of integrated
             * devices both types are fine */
            busFlags |= VIR_PCI_CONNECT_TYPE_PCI_DEVICE |
                        VIR_PCI_CONNECT_AUTOASSIGN;
        } else {
            if (reportError) {
                virReportError(errType,
                               _("The device at PCI address %1$s needs to be an integrated device (bus=0)"),
                               addrStr);
            }
            return false;
        }
    }

    if (fromConfig) {
        /* If the requested connection was manually specified in
         * config, allow a PCI device to connect to a PCIe slot, or
         * vice versa. In order to do so, we add *both* the PCI_DEVICE
         * and the PCIE_DEVICE flags to the bus if it already has either
         * of them, using the ENDPOINT mask.
         */
        if (busFlags & VIR_PCI_CONNECT_TYPES_ENDPOINT)
            busFlags |= VIR_PCI_CONNECT_TYPES_ENDPOINT;
        /* if the device is a pci-bridge, allow manually
         * assigning to any bus that would also accept a
         * standard PCI device.
         */
        if (devFlags & VIR_PCI_CONNECT_TYPE_PCI_BRIDGE)
            devFlags |= VIR_PCI_CONNECT_TYPE_PCI_DEVICE;
    } else if ((devFlags & VIR_PCI_CONNECT_AUTOASSIGN) &&
               !(busFlags & VIR_PCI_CONNECT_AUTOASSIGN)) {
        if (reportError) {
            virReportError(errType,
                           _("The device at PCI address %1$s was auto-assigned this address, but the PCI controller with index='%2$d' doesn't allow auto-assignment"),
                           addrStr, addr->bus);
        }
        return false;
    }

    if ((devFlags & VIR_PCI_CONNECT_HOTPLUGGABLE) &&
        !(busFlags & VIR_PCI_CONNECT_HOTPLUGGABLE)) {
        if (reportError) {
            virReportError(errType,
                           _("The device at PCI address %1$s requires hotplug capability, but the PCI controller with index='%2$d' doesn't support hotplug"),
                           addrStr, addr->bus);
        }
        return false;
    }

    /* If this bus doesn't allow the type of connection (PCI
     * vs. PCIe) required by the device, or if the device requires
     * hot-plug and this bus doesn't have it, return false.
     */
    if (!(devFlags & busFlags & VIR_PCI_CONNECT_TYPES_MASK)) {
        const char *connectStr;

        if (!reportError)
            return false;

        if (devFlags & VIR_PCI_CONNECT_TYPE_PCI_DEVICE) {
            connectStr = "standard PCI device";
        } else if (devFlags & VIR_PCI_CONNECT_TYPE_PCIE_DEVICE) {
            connectStr = "PCI Express device";
        } else if (devFlags & VIR_PCI_CONNECT_TYPE_PCIE_ROOT_PORT) {
            connectStr = "pcie-root-port";
        } else if (devFlags & VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_UPSTREAM_PORT) {
            connectStr = "pcie-switch-upstream-port";
        } else if (devFlags & VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_DOWNSTREAM_PORT) {
            connectStr = "pcie-switch-downstream-port";
        } else if (devFlags & VIR_PCI_CONNECT_TYPE_DMI_TO_PCI_BRIDGE) {
            connectStr = "dmi-to-pci-bridge";
        } else if (devFlags & VIR_PCI_CONNECT_TYPE_PCIE_TO_PCI_BRIDGE) {
            connectStr = "pcie-to-pci-bridge";
        } else if (devFlags & VIR_PCI_CONNECT_TYPE_PCI_EXPANDER_BUS) {
            connectStr = "pci-expander-bus";
        } else if (devFlags & VIR_PCI_CONNECT_TYPE_PCIE_EXPANDER_BUS) {
            connectStr = "pcie-expander-bus";
        } else if (devFlags & VIR_PCI_CONNECT_TYPE_PCI_BRIDGE) {
            connectStr = "pci-bridge";
        } else {
            /* this should never happen. If it does, there is a
             * bug in the code that sets the flag bits for devices.
             */
            virReportError(errType,
                           _("The device at PCI address %1$s has unrecognized connection type flags 0x%2$.2x"),
                           addrStr, devFlags & VIR_PCI_CONNECT_TYPES_MASK);
            return false;
        }
        virReportError(errType,
                       _("The device at PCI address %1$s cannot be plugged into the PCI controller with index='%2$d'. It requires a controller that accepts a %3$s."),
                       addrStr, addr->bus, connectStr);
        return false;
    }
    return true;
}


/* Verify that the address is in bounds for the chosen bus, and
 * that the bus is of the correct type for the device (via
 * comparing the flags).
 */
bool
virDomainPCIAddressValidate(virDomainPCIAddressSet *addrs,
                            virPCIDeviceAddress *addr,
                            const char *addrStr,
                            virDomainPCIConnectFlags flags,
                            bool fromConfig)
{
    virDomainPCIAddressBus *bus;
    virErrorNumber errType = (fromConfig
                              ? VIR_ERR_XML_ERROR : VIR_ERR_INTERNAL_ERROR);

    if (addrs->nbuses == 0) {
        virReportError(errType, "%s", _("No PCI buses available"));
        return false;
    }
    if (addr->domain != 0) {
        virReportError(errType,
                       _("Invalid PCI address %1$s. Only PCI domain 0 is available"),
                       addrStr);
        return false;
    }
    if (addr->bus >= addrs->nbuses) {
        virReportError(errType,
                       _("Invalid PCI address %1$s. Only PCI buses up to %2$zu are available"),
                       addrStr, addrs->nbuses - 1);
        return false;
    }

    bus = &addrs->buses[addr->bus];

    /* assure that at least one of the requested connection types is
     * provided by this bus
     */
    if (!virDomainPCIAddressFlagsCompatible(addr, addrStr, bus->flags,
                                            flags, true, fromConfig))
        return false;

    /* some "buses" are really just a single port */
    if (bus->minSlot && addr->slot < bus->minSlot) {
        virReportError(errType,
                       _("Invalid PCI address %1$s. slot must be >= %2$zu"),
                       addrStr, bus->minSlot);
        return false;
    }
    if (addr->slot > bus->maxSlot) {
        virReportError(errType,
                       _("Invalid PCI address %1$s. slot must be <= %2$zu"),
                       addrStr, bus->maxSlot);
        return false;
    }
    if (addr->function > VIR_PCI_ADDRESS_FUNCTION_LAST) {
        virReportError(errType,
                       _("Invalid PCI address %1$s. function must be <= %2$u"),
                       addrStr, VIR_PCI_ADDRESS_FUNCTION_LAST);
        return false;
    }
    return true;
}


int
virDomainPCIAddressBusSetModel(virDomainPCIAddressBus *bus,
                               virDomainControllerModelPCI model,
                               bool allowHotplug)
{
    /* set flags for what can be connected *downstream* from each
     * bus.
     */
    virDomainPCIConnectFlags hotplugFlag = 0;

    if (allowHotplug)
        hotplugFlag = VIR_PCI_CONNECT_HOTPLUGGABLE;

    switch (model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT:
        bus->flags = (VIR_PCI_CONNECT_AUTOASSIGN |
                      VIR_PCI_CONNECT_TYPE_PCI_DEVICE |
                      VIR_PCI_CONNECT_TYPE_PCI_BRIDGE |
                      VIR_PCI_CONNECT_TYPE_PCI_EXPANDER_BUS |
                      hotplugFlag);
        bus->minSlot = 1;
        bus->maxSlot = VIR_PCI_ADDRESS_SLOT_LAST;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE:
        bus->flags = (VIR_PCI_CONNECT_AUTOASSIGN |
                      VIR_PCI_CONNECT_TYPE_PCI_DEVICE |
                      VIR_PCI_CONNECT_TYPE_PCI_BRIDGE |
                      hotplugFlag);
        bus->minSlot = 1;
        bus->maxSlot = VIR_PCI_ADDRESS_SLOT_LAST;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS:
        bus->flags = (VIR_PCI_CONNECT_AUTOASSIGN |
                      VIR_PCI_CONNECT_TYPE_PCI_DEVICE |
                      VIR_PCI_CONNECT_TYPE_PCI_BRIDGE |
                      hotplugFlag);
        bus->minSlot = 0;
        bus->maxSlot = VIR_PCI_ADDRESS_SLOT_LAST;
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT:
        /* slots 1 - 31, no hotplug, PCIe endpoint device or
         * pcie-root-port only, unless the address was specified in
         * user config *and* the particular device being attached also
         * allows it.
         */
        bus->flags = (VIR_PCI_CONNECT_TYPE_PCIE_DEVICE |
                      VIR_PCI_CONNECT_TYPE_PCIE_ROOT_PORT |
                      VIR_PCI_CONNECT_TYPE_DMI_TO_PCI_BRIDGE |
                      VIR_PCI_CONNECT_TYPE_PCIE_EXPANDER_BUS);
        bus->minSlot = 1;
        bus->maxSlot = VIR_PCI_ADDRESS_SLOT_LAST;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE:
        /* slots 0 - 31, standard PCI slots,
         * but *not* hot-pluggable */
        bus->flags = (VIR_PCI_CONNECT_TYPE_PCI_DEVICE |
                      VIR_PCI_CONNECT_TYPE_PCI_BRIDGE);
        bus->minSlot = 0;
        bus->maxSlot = VIR_PCI_ADDRESS_SLOT_LAST;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE:
        /* Same as pci-bridge: 32 hotpluggable traditional PCI slots (0-31),
         * the first of which is not usable because of the SHPC */
        bus->flags = (VIR_PCI_CONNECT_AUTOASSIGN |
                      VIR_PCI_CONNECT_TYPE_PCI_DEVICE |
                      VIR_PCI_CONNECT_TYPE_PCI_BRIDGE |
                      hotplugFlag);
        bus->minSlot = 1;
        bus->maxSlot = VIR_PCI_ADDRESS_SLOT_LAST;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_DOWNSTREAM_PORT:
        /* provides one slot which is pcie, can be used by endpoint
         * devices, pcie-switch-upstream-ports or pcie-to-pci-bridges,
         * and is hotpluggable */
        bus->flags = (VIR_PCI_CONNECT_AUTOASSIGN |
                      VIR_PCI_CONNECT_TYPE_PCIE_DEVICE |
                      VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_UPSTREAM_PORT |
                      VIR_PCI_CONNECT_TYPE_PCIE_TO_PCI_BRIDGE |
                      hotplugFlag);
        bus->minSlot = 0;
        bus->maxSlot = 0;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_SWITCH_UPSTREAM_PORT:
        /* 32 slots, can only accept pcie-switch-downstream-ports,
         * no hotplug
         */
        bus->flags = VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_DOWNSTREAM_PORT;
        bus->minSlot = 0;
        bus->maxSlot = VIR_PCI_ADDRESS_SLOT_LAST;
        break;
    case VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS:
        /* 32 slots, no hotplug, only accepts pcie-root-port or
         * dmi-to-pci-bridge
         */
        bus->flags = (VIR_PCI_CONNECT_TYPE_PCIE_ROOT_PORT |
                      VIR_PCI_CONNECT_TYPE_DMI_TO_PCI_BRIDGE);
        bus->minSlot = 0;
        bus->maxSlot = VIR_PCI_ADDRESS_SLOT_LAST;
        break;

    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_PCI_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("PCI controller model was not set correctly"));
        return -1;
    }

    bus->model = model;
    return 0;
}


bool
virDomainPCIAddressBusIsFullyReserved(virDomainPCIAddressBus *bus)
{
    size_t i;

    for (i = bus->minSlot; i <= bus->maxSlot; i++) {
        if (!bus->slot[i].functions)
            return false;
    }

    return true;
}


static bool ATTRIBUTE_NONNULL(1)
virDomainPCIAddressBusIsEmpty(virDomainPCIAddressBus *bus)
{
    size_t i;

    for (i = bus->minSlot; i <= bus->maxSlot; i++) {
        if (bus->slot[i].functions)
            return false;
    }

    return true;
}


/* Ensure addr fits in the address set, by expanding it if needed
 *
 * Return value:
 * -1 = OOM
 *  0 = no action performed
 * >0 = number of buses added
 */
static int
virDomainPCIAddressSetGrow(virDomainPCIAddressSet *addrs,
                           virPCIDeviceAddress *addr,
                           virDomainPCIConnectFlags flags)
{
    int add;
    size_t i;
    int model;
    bool needDMIToPCIBridge = false;
    bool needPCIeToPCIBridge = false;

    add = addr->bus - addrs->nbuses + 1;
    if (add <= 0)
        return 0;

    /* remember that the flags aren't for the type of controller that
     * we want to add, they are the type of *device* that we want to
     * plug in, and this function must decide on the appropriate
     * controller to add in order to give us a slot for that device.
     */

    if (flags & VIR_PCI_CONNECT_TYPE_PCI_DEVICE) {
        if (addrs->areMultipleRootsSupported) {
            /* Use a pci-root controller to expand the guest's PCI
             * topology if it supports having more than one */
            model = VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT;
        } else {
            model = VIR_DOMAIN_CONTROLLER_MODEL_PCI_BRIDGE;

            /* if there aren't yet any buses that will accept a
             * pci-bridge, but we need one for the device's PCI address
             * to make sense, it means the guest only has a PCIe topology
             * configured so far, and we need to create a traditional PCI
             * topology to accommodate the new device.
             */
            needDMIToPCIBridge = true;
            needPCIeToPCIBridge = true;
            for (i = 0; i < addrs->nbuses; i++) {
                if (addrs->buses[i].flags & VIR_PCI_CONNECT_TYPE_PCI_BRIDGE) {
                    needDMIToPCIBridge = false;
                    needPCIeToPCIBridge = false;
                    break;
                }
            }

            /* Prefer pcie-to-pci-bridge, fall back to dmi-to-pci-bridge */
            if (addrs->isPCIeToPCIBridgeSupported)
                needDMIToPCIBridge = false;
            else
                needPCIeToPCIBridge = false;

            if ((needDMIToPCIBridge || needPCIeToPCIBridge) && add == 1) {
                /* We need to add a single pci-bridge to provide the bus
                 * our legacy PCI device will be plugged into; however, we
                 * have also determined that there isn't yet any proper
                 * place to connect that pci-bridge we're about to add,
                 * which means we're dealing with a pure PCIe guest. We
                 * need to create a traditional PCI topology, and for that
                 * we have two options: dmi-to-pci-bridge + pci-bridge or
                 * pcie-root-port + pcie-to-pci-bridge (the latter of which
                 * is pretty much a pci-bridge as far as devices attached
                 * to it are concerned and as such makes the pci-bridge
                 * unnecessary). Either way, there's going to be one more
                 * controller than initially expected, and the 'bus' part
                 * of the device's address will need to be bumped.
                 */
                add++;
                addr->bus++;
            }
        }
    } else if (flags & (VIR_PCI_CONNECT_TYPE_PCIE_DEVICE |
                        VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_UPSTREAM_PORT)) {
        model = VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT;
    } else {
        /* The types of devices that we can't auto-add a controller for:
         *
         * VIR_CONNECT_TYPE_DMI_TO_PCI_BRIDGE &
         * VIR_PCI_CONNECT_TYPE_ROOT_PORT - these can only plug into
         *  pcie-root or pcie-expander-bus. By definition there is
         *  only 1 pcie-root, and we don't support auto-adding
         *  pcie-expander-bus (because it is intended for NUMA usage,
         *  and we can't automatically decide which numa node to
         *  associate it with)
         *
         * VIR_CONNECT_TYPE_PCIE_SWITCH_DOWNSTREAM_PORT - we ndon't
         *  support this, because it can only plug into an
         *  upstream-port, and the upstream port might need a
         *  root-port; supporting this extra layer needlessly
         *  complicates the code, and upstream/downstream ports are
         *  outside the scope of our "automatic-bus-expansion" model
         *  anyway.
         *
         * VIR_CONNECT_TYPE_PCI[E]_EXPANDER_BUS - these were created
         *  to support guest awareness of the NUMA node placement of
         *  devices on the host, and are also outside the scope of our
         *  "automatic-bus-expansion".
         *
         * VIR_PCI_CONNECT_TYPE_PCI_BRIDGE (when the root bus is
         *  pci-root) - see the comment above in the case that handles
         *  adding a slot for pci-bridge to a guest with pcie-root.
         *
         */
        int existingContModel = virDomainPCIControllerConnectTypeToModel(flags);

        if (existingContModel >= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("a PCI slot is needed to connect a PCI controller model='%1$s', but none is available, and it cannot be automatically added"),
                           virDomainControllerModelPCITypeToString(existingContModel));
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot automatically add a new PCI bus for a device with connect flags %1$.2x"),
                           flags);
        }
        return -1;
    }

    i = addrs->nbuses;

    VIR_EXPAND_N(addrs->buses, addrs->nbuses, add);

    if (needDMIToPCIBridge) {
        /* first of the new buses is dmi-to-pci-bridge, the
         * rest are of the requested type
         */
        if (virDomainPCIAddressBusSetModel(&addrs->buses[i++],
                                           VIR_DOMAIN_CONTROLLER_MODEL_DMI_TO_PCI_BRIDGE, false) < 0) {
            return -1;
        }
    }

    if (needPCIeToPCIBridge) {
        /* We need a pcie-root-port to plug pcie-to-pci-bridge into; however,
         * qemuDomainAssignPCIAddresses() will, in some cases, create a dummy
         * PCIe device and reserve an address for it in order to leave the
         * user with an empty pcie-root-port ready for hotplugging, and if
         * we didn't do anything other than adding the pcie-root-port here
         * it would be used for that, which we don't want. So we change the
         * connect flags to make sure only the pcie-to-pci-bridge will be
         * connected to the pcie-root-port we just added, and another one
         * will be allocated for the dummy PCIe device later on.
         */
        if (virDomainPCIAddressBusSetModel(&addrs->buses[i],
                                           VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT_PORT, true) < 0) {
            return -1;
        }
        addrs->buses[i].flags = VIR_PCI_CONNECT_TYPE_PCIE_TO_PCI_BRIDGE;
        i++;

        if (virDomainPCIAddressBusSetModel(&addrs->buses[i++],
                                           VIR_DOMAIN_CONTROLLER_MODEL_PCIE_TO_PCI_BRIDGE, true) < 0) {
            return -1;
        }
    }

    for (; i < addrs->nbuses; i++) {
        if (virDomainPCIAddressBusSetModel(&addrs->buses[i], model, true) < 0)
            return -1;
    }

    return add;
}


/*
 * Check if the PCI slot is used by another device.
 */
bool
virDomainPCIAddressSlotInUse(virDomainPCIAddressSet *addrs,
                             virPCIDeviceAddress *addr)
{
    return !!addrs->buses[addr->bus].slot[addr->slot].functions;
}


/*
 * Reserve a function in a slot. If fromConfig is true, the address
 * being requested came directly from the config and errors should be
 * worded appropriately. If fromConfig is false, the address was
 * automatically created by libvirt, so it is an internal error (not
 * XML).
 */
static int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
virDomainPCIAddressReserveAddrInternal(virDomainPCIAddressSet *addrs,
                                       virPCIDeviceAddress *addr,
                                       virDomainPCIConnectFlags flags,
                                       unsigned int isolationGroup,
                                       bool fromConfig)
{
    g_autofree char *addrStr = NULL;
    virDomainPCIAddressBus *bus;
    virErrorNumber errType = (fromConfig
                              ? VIR_ERR_XML_ERROR : VIR_ERR_INTERNAL_ERROR);

    if (!(addrStr = virPCIDeviceAddressAsString(addr)))
        return -1;

    /* Add an extra bus if necessary */
    if (addrs->dryRun && virDomainPCIAddressSetGrow(addrs, addr, flags) < 0)
        return -1;
    /* Check that the requested bus exists, is the correct type, and we
     * are asking for a valid slot
     */
    if (!virDomainPCIAddressValidate(addrs, addr, addrStr, flags, fromConfig))
        return -1;

    bus = &addrs->buses[addr->bus];

    if (bus->slot[addr->slot].functions & (1 << addr->function)) {
        virReportError(errType,
                       _("Attempted double use of PCI Address %1$s"), addrStr);
        return -1;
    }

    /* if this is the first function to be reserved on this slot, and
     * the device it's being reserved for can aggregate multiples on a
     * slot, set the slot's aggregate flag.
    */
    if (!bus->slot[addr->slot].functions &&
        flags & VIR_PCI_CONNECT_AGGREGATE_SLOT) {
        bus->slot[addr->slot].aggregate = true;
    }

    if (virDomainPCIAddressBusIsEmpty(bus) && !bus->isolationGroupLocked) {
        /* The first device decides the isolation group for the
         * entire bus */
        bus->isolationGroup = isolationGroup;
        VIR_DEBUG("PCI bus %04x:%02x assigned isolation group %u because of "
                  "first device %s",
                  addr->domain, addr->bus, isolationGroup, addrStr);
    } else if (bus->isolationGroup != isolationGroup && fromConfig) {
        /* If this is not the first function and its isolation group
         * doesn't match the bus', then it should not be using this
         * address. However, if the address comes from the user then
         * we comply with the request and change the isolation group
         * back to the default (because at that point isolation can't
         * be guaranteed anymore) */
        bus->isolationGroup = 0;
        VIR_DEBUG("PCI bus %04x:%02x assigned isolation group %u because of "
                  "user assigned address %s",
                  addr->domain, addr->bus, isolationGroup, addrStr);
    }

    /* mark the requested function as reserved */
    bus->slot[addr->slot].functions |= (1 << addr->function);
    VIR_DEBUG("Reserving PCI address %s (aggregate='%s')", addrStr,
              bus->slot[addr->slot].aggregate ? "true" : "false");

    return 0;
}


int
virDomainPCIAddressReserveAddr(virDomainPCIAddressSet *addrs,
                               virPCIDeviceAddress *addr,
                               virDomainPCIConnectFlags flags,
                               unsigned int isolationGroup)
{
    return virDomainPCIAddressReserveAddrInternal(addrs, addr, flags,
                                                  isolationGroup, true);
}

int
virDomainPCIAddressEnsureAddr(virDomainPCIAddressSet *addrs,
                              virDomainDeviceInfo *dev,
                              virDomainPCIConnectFlags flags)
{
    g_autofree char *addrStr = NULL;

    /* if flags is 0, the particular model of this device on this
     * machinetype doesn't need a PCI address, so we're done.
     */
    if (!flags)
       return 0;

    /* This function is only called during hotplug, so we require hotplug
     * support from the controller.
     */
    flags |= VIR_PCI_CONNECT_HOTPLUGGABLE;

    if (!(addrStr = virPCIDeviceAddressAsString(&dev->addr.pci)))
        return -1;

    if (virDeviceInfoPCIAddressIsPresent(dev)) {
        /* We do not support hotplug multi-function PCI device now, so we should
         * reserve the whole slot. The function of the PCI device must be 0.
         */
        if (dev->addr.pci.function != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Only PCI device addresses with function=0 are supported"));
            return -1;
        }

        if (!virDomainPCIAddressValidate(addrs, &dev->addr.pci,
                                         addrStr, flags, true))
            return -1;

        if (virDomainPCIAddressReserveAddrInternal(addrs, &dev->addr.pci,
                                                   flags, dev->isolationGroup,
                                                   true) < 0) {
            return -1;
        }
    } else {
        if (virDomainPCIAddressReserveNextAddr(addrs, dev, flags, -1) < 0)
            return -1;
    }

    dev->addr.pci.extFlags = dev->pciAddrExtFlags;
    if (virDomainPCIAddressExtensionEnsureAddr(addrs, &dev->addr.pci) < 0)
        return -1;

    return 0;
}


void
virDomainPCIAddressExtensionReleaseAddr(virDomainPCIAddressSet *addrs,
                                        virPCIDeviceAddress *addr)
{
    if (addr->extFlags & VIR_PCI_ADDRESS_EXTENSION_ZPCI)
        virDomainZPCIAddressReleaseIds(addrs->zpciIds, &addr->zpci);
}


void
virDomainPCIAddressReleaseAddr(virDomainPCIAddressSet *addrs,
                               virPCIDeviceAddress *addr)
{
    addrs->buses[addr->bus].slot[addr->slot].functions &= ~(1 << addr->function);
}


static void
virDomainPCIAddressSetExtensionFree(virDomainZPCIAddressIds *zpciIds)
{
    if (!zpciIds)
        return;

    g_clear_pointer(&zpciIds->uids, g_hash_table_unref);
    g_clear_pointer(&zpciIds->fids, g_hash_table_unref);

    g_free(zpciIds);
}


static void
virDomainPCIAddressSetExtensionAlloc(virDomainPCIAddressSet *addrs,
                                     virPCIDeviceAddressExtensionFlags extFlags)
{
    if (extFlags & VIR_PCI_ADDRESS_EXTENSION_ZPCI) {
        if (addrs->zpciIds)
            return;

        addrs->zpciIds = g_new0(virDomainZPCIAddressIds, 1);

        addrs->zpciIds->uids = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
        addrs->zpciIds->fids = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
    }
}


virDomainPCIAddressSet *
virDomainPCIAddressSetAlloc(unsigned int nbuses,
                            virPCIDeviceAddressExtensionFlags extFlags)
{
    virDomainPCIAddressSet *addrs;

    addrs = g_new0(virDomainPCIAddressSet, 1);
    addrs->buses = g_new0(virDomainPCIAddressBus, nbuses);
    addrs->nbuses = nbuses;

    virDomainPCIAddressSetExtensionAlloc(addrs, extFlags);

    return addrs;
}


void
virDomainPCIAddressSetFree(virDomainPCIAddressSet *addrs)
{
    if (!addrs)
        return;

    virDomainPCIAddressSetExtensionFree(addrs->zpciIds);
    g_free(addrs->buses);
    g_free(addrs);
}


static int
virDomainPCIAddressFindUnusedFunctionOnBus(virDomainPCIAddressBus *bus,
                                           virPCIDeviceAddress *searchAddr,
                                           int function,
                                           virDomainPCIConnectFlags flags,
                                           bool *found)
{
    g_autofree char *addrStr = NULL;

    *found = false;

    if (!(addrStr = virPCIDeviceAddressAsString(searchAddr)))
        return -1;

    if (!virDomainPCIAddressFlagsCompatible(searchAddr, addrStr, bus->flags,
                                            flags, false, false)) {
        VIR_DEBUG("PCI bus %04x:%02x is not compatible with the device",
                  searchAddr->domain, searchAddr->bus);
    } else {
        while (searchAddr->slot <= bus->maxSlot) {
            if (bus->slot[searchAddr->slot].functions == 0) {
                *found = true;
                break;
            }

            if (flags & VIR_PCI_CONNECT_AGGREGATE_SLOT &&
                bus->slot[searchAddr->slot].aggregate) {
                /* slot and device are okay with aggregating devices */
                if ((bus->slot[searchAddr->slot].functions &
                     (1 << searchAddr->function)) == 0) {
                    *found = true;
                    break;
                }

                /* also check for *any* unused function if caller
                 * sent function = -1
                 */
                if (function == -1) {
                    while (searchAddr->function < 8) {
                        if ((bus->slot[searchAddr->slot].functions &
                             (1 << searchAddr->function)) == 0) {
                            *found = true;
                            break; /* out of inner while */
                        }
                        searchAddr->function++;
                    }
                    if (*found)
                       break; /* out of outer while */
                    searchAddr->function = 0; /* reset for next try */
                }
            }

            VIR_DEBUG("PCI slot %04x:%02x:%02x already in use",
                      searchAddr->domain, searchAddr->bus, searchAddr->slot);
            searchAddr->slot++;
        }
    }

    return 0;
}


static int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
virDomainPCIAddressGetNextAddr(virDomainPCIAddressSet *addrs,
                               virPCIDeviceAddress *next_addr,
                               virDomainPCIConnectFlags flags,
                               unsigned int isolationGroup,
                               int function)
{
    virPCIDeviceAddress a = { 0 };

    if (addrs->nbuses == 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("No PCI buses available"));
        return -1;
    }

    /* if the caller asks for "any function", give them function 0 */
    if (function == -1)
        a.function = 0;
    else
        a.function = function;

    /* When looking for a suitable bus for the device, start by being
     * very strict and ignoring all those where the isolation groups
     * don't match. This ensures all devices sharing the same isolation
     * group will end up on the same bus */
    for (a.bus = 0; a.bus < addrs->nbuses; a.bus++) {
        virDomainPCIAddressBus *bus = &addrs->buses[a.bus];
        bool found = false;

        if (bus->isolationGroup != isolationGroup)
            continue;

        a.slot = bus->minSlot;

        if (virDomainPCIAddressFindUnusedFunctionOnBus(bus, &a, function,
                                                       flags, &found) < 0) {
            return -1;
        }

        if (found)
            goto success;
    }

    /* We haven't been able to find a perfectly matching bus, but we
     * might still be able to make this work by altering the isolation
     * group for a bus that's currently empty. So let's try that */
    for (a.bus = 0; a.bus < addrs->nbuses; a.bus++) {
        virDomainPCIAddressBus *bus = &addrs->buses[a.bus];
        bool found = false;

        /* We can only change the isolation group for a bus when
         * plugging in the first device; moreover, some buses are
         * prevented from ever changing it */
        if (!virDomainPCIAddressBusIsEmpty(bus) || bus->isolationGroupLocked)
            continue;

        a.slot = bus->minSlot;

        if (virDomainPCIAddressFindUnusedFunctionOnBus(bus, &a, function,
                                                       flags, &found) < 0) {
            return -1;
        }

        /* The isolation group for the bus will actually be changed
         * later, in virDomainPCIAddressReserveAddrInternal() */
        if (found)
            goto success;
    }

    /* There were no free slots after the last used one */
    if (addrs->dryRun) {
        /* a is already set to the first new bus */
        if (virDomainPCIAddressSetGrow(addrs, &a, flags) < 0)
            return -1;
        /* this device will use the first slot of the new bus */
        a.slot = addrs->buses[a.bus].minSlot;
        goto success;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("No more available PCI slots"));
    return -1;

 success:
    VIR_DEBUG("Found free PCI slot %04x:%02x:%02x",
              a.domain, a.bus, a.slot);
    *next_addr = a;
    return 0;
}


/**
 * virDomainPCIAddressReserveNextAddr:
 *
 * @addrs: a set of PCI addresses.
 * @dev: virDomainDeviceInfo that should get the new address.
 * @flags: CONNECT_TYPE flags for the device that needs an address.
 * @function: which function on the slot to mark as reserved
 *
 * Find the next *completely unreserved* slot with compatible
 * connection @flags, mark one function of the slot as in-use
 * (according to @function), then set @dev->addr.pci with this newly
 * reserved address. If @function is -1, then the lowest unused
 * function of the slot will be reserved (and since we only look for
 * completely unused slots, that means "0").
 *
 * returns 0 on success, or -1 on failure.
 */
int
virDomainPCIAddressReserveNextAddr(virDomainPCIAddressSet *addrs,
                                   virDomainDeviceInfo *dev,
                                   virDomainPCIConnectFlags flags,
                                   int function)
{
    virPCIDeviceAddress addr = { 0 };

    if (virDomainPCIAddressGetNextAddr(addrs, &addr, flags,
                                       dev->isolationGroup, function) < 0)
        return -1;

    if (virDomainPCIAddressReserveAddrInternal(addrs, &addr, flags,
                                               dev->isolationGroup, false) < 0)
        return -1;

    addr.extFlags = dev->addr.pci.extFlags;
    addr.zpci = dev->addr.pci.zpci;

    if (!addrs->dryRun) {
        dev->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
        dev->addr.pci = addr;
    }

    return 0;
}


static int
virDomainPCIAddressSetMultiIter(virDomainDef *def G_GNUC_UNUSED,
                                virDomainDeviceDef *dev G_GNUC_UNUSED,
                                virDomainDeviceInfo *info,
                                void *data)
{
    virPCIDeviceAddress *testAddr = data;
    virPCIDeviceAddress *thisAddr;

    if (!info || info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
       return 0;

    thisAddr = &info->addr.pci;

    if (thisAddr->domain == testAddr->domain &&
        thisAddr->bus == testAddr->bus &&
        thisAddr->slot == testAddr->slot &&
        thisAddr->function == 0) {

        /* only set to ON if it wasn't previously set
         * (assuming that the user must have better information
         * than us if they explicitly set it OFF)
         */
        if (thisAddr->multi == VIR_TRISTATE_SWITCH_ABSENT)
            thisAddr->multi = VIR_TRISTATE_SWITCH_ON;

        return -1; /* finish early, *NOT* an error */
    }

    return 0;
}


static int
virDomainPCIAddressSetAllMultiIter(virDomainDef *def,
                                   virDomainDeviceDef *dev G_GNUC_UNUSED,
                                   virDomainDeviceInfo *info,
                                   void *data G_GNUC_UNUSED)
{
    virPCIDeviceAddress *testAddr;

    if (!info || info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
       return 0;

    testAddr = &info->addr.pci;

    if (testAddr->function != 0) {
        ignore_value(virDomainDeviceInfoIterate(def,
                                                virDomainPCIAddressSetMultiIter,
                                                testAddr));
    }

    return 0;
}


/**
 * virDomainPCIAddressSetAllMulti():
 *
 * @def: the domain definition whose devices may need adjusting
 * @addrs: address set keeping track of all addresses in use.
 *
 * Look for any PCI slots that have multiple functions assigned, and
 * set multi to ON in the address for the device at function 0
 * (unless it has been explicitly set to OFF).
 *
 * No return code, since there is no possibility of failure.
 */
void
virDomainPCIAddressSetAllMulti(virDomainDef *def)
{
    /* Use nested iterators over all the devices - the outer iterator
     * scans through all the devices looking for those whose address
     * has a non-0 function; when one is found, the inner iterator looks
     * for the device that uses function 0 on the same slot and marks
     * it as multi = ON
     */
    ignore_value(virDomainDeviceInfoIterate(def,
                                            virDomainPCIAddressSetAllMultiIter,
                                            NULL));
}


int
virDomainCCWAddressAssign(virDomainDeviceInfo *dev,
                          virDomainCCWAddressSet *addrs,
                          bool autoassign)
{
    g_autofree char *addr = NULL;

    if (dev->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW)
        return 0;

    if (!autoassign && dev->addr.ccw.assigned) {
        if (!(addr = virCCWDeviceAddressAsString(&dev->addr.ccw)))
            return -1;

        if (virHashLookup(addrs->defined, addr)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("The CCW devno '%1$s' is in use already"),
                           addr);
            return -1;
        }
    } else if (autoassign && !dev->addr.ccw.assigned) {
        if (!(addr = virCCWDeviceAddressAsString(&addrs->next)))
            return -1;

        while (virHashLookup(addrs->defined, addr)) {
            if (virCCWDeviceAddressIncrement(&addrs->next) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("There are no more free CCW devnos."));
                return -1;
            }
            VIR_FREE(addr);
            if (!(addr = virCCWDeviceAddressAsString(&addrs->next)))
                return -1;
        }
        dev->addr.ccw = addrs->next;
        dev->addr.ccw.assigned = true;
    } else {
        return 0;
    }

    if (virHashAddEntry(addrs->defined, addr, addr) < 0)
        return -1;
    else
        addr = NULL; /* memory will be freed by hash table */

    return 0;
}

static int ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
virDomainCCWAddressAllocate(virDomainDef *def G_GNUC_UNUSED,
                            virDomainDeviceDef *dev G_GNUC_UNUSED,
                            virDomainDeviceInfo *info,
                            void *data)
{
    return virDomainCCWAddressAssign(info, data, true);
}

static int ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
virDomainCCWAddressValidate(virDomainDef *def G_GNUC_UNUSED,
                            virDomainDeviceDef *dev G_GNUC_UNUSED,
                            virDomainDeviceInfo *info,
                            void *data)
{
    return virDomainCCWAddressAssign(info, data, false);
}

void virDomainCCWAddressSetFree(virDomainCCWAddressSet *addrs)
{
    if (!addrs)
        return;

    g_clear_pointer(&addrs->defined, g_hash_table_unref);
    g_free(addrs);
}

static virDomainCCWAddressSet *
virDomainCCWAddressSetCreate(void)
{
    virDomainCCWAddressSet *addrs = NULL;

    addrs = g_new0(virDomainCCWAddressSet, 1);

    addrs->defined = virHashNew(g_free);

    /* must use cssid = 0xfe (254) for virtio-ccw devices */
    addrs->next.cssid = 254;
    addrs->next.ssid = 0;
    addrs->next.devno = 0;
    addrs->next.assigned = 0;
    return addrs;
}


virDomainCCWAddressSet *
virDomainCCWAddressSetCreateFromDomain(virDomainDef *def)
{
    virDomainCCWAddressSet *addrs = NULL;

    if (!(addrs = virDomainCCWAddressSetCreate()))
        goto error;

    if (virDomainDeviceInfoIterate(def, virDomainCCWAddressValidate,
                                   addrs) < 0)
        goto error;

    if (virDomainDeviceInfoIterate(def, virDomainCCWAddressAllocate,
                                   addrs) < 0)
        goto error;

    return addrs;

 error:
    virDomainCCWAddressSetFree(addrs);
    return NULL;
}


#define VIR_DOMAIN_DEFAULT_VIRTIO_SERIAL_PORTS 31


/* virDomainVirtioSerialAddrSetCreate
 *
 * Allocates an address set for virtio serial addresses
 */
static virDomainVirtioSerialAddrSet *
virDomainVirtioSerialAddrSetCreate(void)
{
    virDomainVirtioSerialAddrSet *ret = NULL;

    ret = g_new0(virDomainVirtioSerialAddrSet, 1);

    return ret;
}

static void
virDomainVirtioSerialControllerFree(virDomainVirtioSerialController *cont)
{
    if (cont) {
        virBitmapFree(cont->ports);
        g_free(cont);
    }
}

static ssize_t
virDomainVirtioSerialAddrPlaceController(virDomainVirtioSerialAddrSet *addrs,
                                         virDomainVirtioSerialController *cont)
{
    size_t i;

    for (i = 0; i < addrs->ncontrollers; i++) {
        if (addrs->controllers[i]->idx == cont->idx) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("virtio serial controller with index %1$u already exists in the address set"),
                           cont->idx);
            return -2;
        }
        if (addrs->controllers[i]->idx > cont->idx)
            return i;
    }
    return -1;
}

static ssize_t
virDomainVirtioSerialAddrFindController(virDomainVirtioSerialAddrSet *addrs,
                                        unsigned int idx)
{
    size_t i;

    for (i = 0; i < addrs->ncontrollers; i++) {
        if (addrs->controllers[i]->idx == idx)
            return i;
    }
    return -1;
}

/* virDomainVirtioSerialAddrSetAddController
 *
 * Adds virtio serial ports of the existing controller
 * to the address set.
 */
static int
virDomainVirtioSerialAddrSetAddController(virDomainVirtioSerialAddrSet *addrs,
                                          virDomainControllerDef *cont)
{
    int ret = -1;
    int ports;
    virDomainVirtioSerialController *cnt = NULL;
    ssize_t insertAt;

    if (cont->type != VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL)
        return 0;

    ports = cont->opts.vioserial.ports;
    if (ports == -1)
        ports = VIR_DOMAIN_DEFAULT_VIRTIO_SERIAL_PORTS;

    VIR_DEBUG("Adding virtio serial controller index %u with %d"
              " ports to the address set", cont->idx, ports);

    cnt = g_new0(virDomainVirtioSerialController, 1);

    cnt->ports = virBitmapNew(ports);
    cnt->idx = cont->idx;

    if ((insertAt = virDomainVirtioSerialAddrPlaceController(addrs, cnt)) < -1)
        goto cleanup;
    if (VIR_INSERT_ELEMENT(addrs->controllers, insertAt,
                           addrs->ncontrollers, cnt) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainVirtioSerialControllerFree(cnt);
    return ret;
}

/* virDomainVirtioSerialAddrSetAddControllers
 *
 * Adds virtio serial ports of controllers present in the domain definition
 * to the address set.
 */
static int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
virDomainVirtioSerialAddrSetAddControllers(virDomainVirtioSerialAddrSet *addrs,
                                           virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        if (virDomainVirtioSerialAddrSetAddController(addrs,
                                                      def->controllers[i]) < 0)
            return -1;
    }

    return 0;
}


void
virDomainVirtioSerialAddrSetFree(virDomainVirtioSerialAddrSet *addrs)
{
    size_t i;
    if (addrs) {
        for (i = 0; i < addrs->ncontrollers; i++)
            virDomainVirtioSerialControllerFree(addrs->controllers[i]);
        g_free(addrs->controllers);
        g_free(addrs);
    }
}

/* virDomainVirtioSerialAddrReserve
 *
 * Reserve the virtio serial address of the device
 *
 * For use with virDomainDeviceInfoIterate,
 * opaque should be the address set
 */
static int ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
virDomainVirtioSerialAddrReserve(virDomainDef *def G_GNUC_UNUSED,
                                 virDomainDeviceDef *dev G_GNUC_UNUSED,
                                 virDomainDeviceInfo *info,
                                 void *data)
{
    virDomainVirtioSerialAddrSet *addrs = data;
    virBitmap *map = NULL;
    bool b;
    ssize_t i;

    if (!virDomainVirtioSerialAddrIsComplete(info))
        return 0;

    VIR_DEBUG("Reserving virtio serial %u %u", info->addr.vioserial.controller,
              info->addr.vioserial.port);

    i = virDomainVirtioSerialAddrFindController(addrs, info->addr.vioserial.controller);
    if (i < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("virtio serial controller %1$u is missing"),
                       info->addr.vioserial.controller);
        return -1;
    }

    map = addrs->controllers[i]->ports;
    if (virBitmapGetBit(map, info->addr.vioserial.port, &b) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("virtio serial controller %1$u does not have port %2$u"),
                       info->addr.vioserial.controller,
                       info->addr.vioserial.port);
        return -1;
    }

    if (b) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("virtio serial port %1$u on controller %2$u is already occupied"),
                       info->addr.vioserial.port,
                       info->addr.vioserial.controller);
        return -1;
    }

    ignore_value(virBitmapSetBit(map, info->addr.vioserial.port));

    return 0;
}

/* virDomainVirtioSerialAddrSetCreateFromDomain
 *
 * @def: Domain def to introspect
 *
 * Inspect the domain definition and return an address set containing
 * every virtio serial address we find
 */
virDomainVirtioSerialAddrSet *
virDomainVirtioSerialAddrSetCreateFromDomain(virDomainDef *def)
{
    virDomainVirtioSerialAddrSet *addrs = NULL;
    virDomainVirtioSerialAddrSet *ret = NULL;

    if (!(addrs = virDomainVirtioSerialAddrSetCreate()))
        goto cleanup;

    if (virDomainVirtioSerialAddrSetAddControllers(addrs, def) < 0)
        goto cleanup;

    if (virDomainDeviceInfoIterate(def, virDomainVirtioSerialAddrReserve,
                                   addrs) < 0)
        goto cleanup;

    ret = g_steal_pointer(&addrs);
 cleanup:
    virDomainVirtioSerialAddrSetFree(addrs);
    return ret;
}

static int
virDomainVirtioSerialAddrSetAutoaddController(virDomainDef *def,
                                              virDomainVirtioSerialAddrSet *addrs,
                                              unsigned int idx)
{
    int contidx;

    if (virDomainDefMaybeAddController(def,
                                       VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL,
                                       idx, -1) < 0)
        return -1;

    contidx = virDomainControllerFind(def, VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL, idx);

    if (virDomainVirtioSerialAddrSetAddController(addrs, def->controllers[contidx]) < 0)
        return -1;

    return 0;
}

static int
virDomainVirtioSerialAddrNext(virDomainDef *def,
                              virDomainVirtioSerialAddrSet *addrs,
                              virDomainDeviceVirtioSerialAddress *addr,
                              bool allowZero)
{
    ssize_t port, startPort = 0;
    ssize_t i;
    unsigned int controller;

    /* port number 0 is reserved for virtconsoles */
    if (allowZero)
        startPort = -1;

    if (addrs->ncontrollers == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no virtio-serial controllers are available"));
        return -1;
    }

    for (i = 0; i < addrs->ncontrollers; i++) {
        virBitmap *map = addrs->controllers[i]->ports;
        if ((port = virBitmapNextClearBit(map, startPort)) >= 0) {
            controller = addrs->controllers[i]->idx;
            goto success;
        }
    }

    if (def) {
        for (i = 0; i < INT_MAX; i++) {
            int idx = virDomainControllerFind(def, VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL, i);

            if (idx == -1) {
                if (virDomainVirtioSerialAddrSetAutoaddController(def, addrs, i) < 0)
                    return -1;
                controller = i;
                port = startPort + 1;
                goto success;
            }
        }
    }

    virReportError(VIR_ERR_XML_ERROR, "%s",
                   _("Unable to find a free virtio-serial port"));

    return -1;

 success:
    addr->bus = 0;
    addr->port = port;
    addr->controller = controller;
    VIR_DEBUG("Found free virtio serial controller %u port %u", addr->controller,
              addr->port);
    return 0;
}

static int
virDomainVirtioSerialAddrNextFromController(virDomainVirtioSerialAddrSet *addrs,
                                            virDomainDeviceVirtioSerialAddress *addr)
{
    ssize_t port;
    ssize_t i;
    virBitmap *map;

    i = virDomainVirtioSerialAddrFindController(addrs, addr->controller);
    if (i < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("virtio-serial controller %1$u not available"),
                       addr->controller);
        return -1;
    }

    map = addrs->controllers[i]->ports;
    if ((port = virBitmapNextClearBit(map, 0)) <= 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unable to find a free port on virtio-serial controller %1$u"),
                       addr->controller);
        return -1;
    }

    addr->bus = 0;
    addr->port = port;
    VIR_DEBUG("Found free virtio serial controller %u port %u", addr->controller,
              addr->port);
    return 0;
}

static int ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
virDomainVirtioSerialAddrAssign(virDomainDef *def,
                                virDomainVirtioSerialAddrSet *addrs,
                                virDomainDeviceInfo *info,
                                bool allowZero,
                                bool portOnly)
{
    virDomainDeviceInfo nfo = { 0 };
    virDomainDeviceInfo *ptr = allowZero ? &nfo : info;

    ptr->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL;

    if (portOnly) {
        if (virDomainVirtioSerialAddrNextFromController(addrs,
                                                        &ptr->addr.vioserial) < 0)
            return -1;
    } else {
        if (virDomainVirtioSerialAddrNext(def, addrs, &ptr->addr.vioserial,
                                          allowZero) < 0)
            return -1;
    }

    if (virDomainVirtioSerialAddrReserve(NULL, NULL, ptr, addrs) < 0)
        return -1;

    return 0;
}

/* virDomainVirtioSerialAddrAutoAssign
 *
 * reserve a virtio serial address of the device (if it has one)
 * or assign a virtio serial address to the device
 */
int
virDomainVirtioSerialAddrAutoAssignFromCache(virDomainDef *def,
                                             virDomainVirtioSerialAddrSet *addrs,
                                             virDomainDeviceInfo *info,
                                             bool allowZero)
{
    bool portOnly = info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL;
    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL &&
        info->addr.vioserial.port)
        return virDomainVirtioSerialAddrReserve(NULL, NULL, info, addrs);
    else
        return virDomainVirtioSerialAddrAssign(def, addrs, info, allowZero, portOnly);
}

int
virDomainVirtioSerialAddrAutoAssign(virDomainDef *def,
                                    virDomainDeviceInfo *info,
                                    bool allowZero)
{
    virDomainVirtioSerialAddrSet *addrs = NULL;
    int ret = -1;

    if (!(addrs = virDomainVirtioSerialAddrSetCreateFromDomain(def)))
        goto cleanup;

    if (virDomainVirtioSerialAddrAutoAssignFromCache(def, addrs, info, allowZero) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainVirtioSerialAddrSetFree(addrs);
    return ret;
}


/* virDomainVirtioSerialAddrIsComplete
 *
 * Check if the address is complete, or it needs auto-assignment
 */
bool
virDomainVirtioSerialAddrIsComplete(virDomainDeviceInfo *info)
{
    return info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL &&
        info->addr.vioserial.port != 0;
}


bool
virDomainUSBAddressPortIsValid(const unsigned int *port)
{
    return port[0] != 0;
}


void
virDomainUSBAddressPortFormatBuf(virBuffer *buf,
                                 const unsigned int *port)
{
    size_t i;

    for (i = 0; i < VIR_DOMAIN_DEVICE_USB_MAX_PORT_DEPTH; i++) {
        if (port[i] == 0)
            break;
        virBufferAsprintf(buf, "%u.", port[i]);
    }
    virBufferTrim(buf, ".");
}


static char * ATTRIBUTE_NONNULL(1)
virDomainUSBAddressPortFormat(unsigned int *port)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virDomainUSBAddressPortFormatBuf(&buf, port);
    return virBufferContentAndReset(&buf);
}


virDomainUSBAddressSet *
virDomainUSBAddressSetCreate(void)
{
    return g_new0(virDomainUSBAddressSet, 1);
}


static void
virDomainUSBAddressHubFree(virDomainUSBAddressHub *hub)
{
    size_t i;

    if (!hub)
        return;

    for (i = 0; i < hub->nports; i++)
        virDomainUSBAddressHubFree(hub->ports[i]);
    g_free(hub->ports);
    virBitmapFree(hub->portmap);
    g_free(hub);
}


void
virDomainUSBAddressSetFree(virDomainUSBAddressSet *addrs)
{
    size_t i;

    if (!addrs)
        return;

    for (i = 0; i < addrs->nbuses; i++)
        virDomainUSBAddressHubFree(addrs->buses[i]);
    g_free(addrs->buses);
    g_free(addrs);
}


static size_t
virDomainUSBAddressControllerModelToPorts(virDomainControllerDef *cont)
{
    switch ((virDomainControllerModelUSB) cont->model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_DEFAULT:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX4_UHCI:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_VT82C686B_UHCI:
        return 2;

    case VIR_DOMAIN_CONTROLLER_MODEL_USB_EHCI:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1:
        return 6;

    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3:
        /* These have two ports each and are used to provide USB1.1
         * ports while ICH9_EHCI1 provides 6 USB2.0 ports.
         * Ignore these since we will add the EHCI1 too. */
        return 0;

    case VIR_DOMAIN_CONTROLLER_MODEL_USB_PCI_OHCI:
        return 3;

    case VIR_DOMAIN_CONTROLLER_MODEL_USB_NEC_XHCI:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_QEMU_XHCI:
        if (cont->opts.usbopts.ports != -1)
            return cont->opts.usbopts.ports;
        return 4;

    case VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB1:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2:
        if (cont->opts.usbopts.ports != -1)
            return cont->opts.usbopts.ports;
        return 8;

    case VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_LAST:
        break;
    }
    return 0;
}


static virDomainUSBAddressHub *
virDomainUSBAddressHubNew(size_t nports)
{
    virDomainUSBAddressHub *hub;

    hub = g_new0(virDomainUSBAddressHub, 1);

    hub->portmap = virBitmapNew(nports);

    hub->ports = g_new0(virDomainUSBAddressHub *, nports);
    hub->nports = nports;

    return hub;
}


static int
virDomainUSBAddressSetAddController(virDomainUSBAddressSet *addrs,
                                    virDomainControllerDef *cont)
{
    size_t nports = virDomainUSBAddressControllerModelToPorts(cont);
    virDomainUSBAddressHub *hub = NULL;
    int ret = -1;

    VIR_DEBUG("Adding a USB controller model=%s with %zu ports",
              virDomainControllerModelUSBTypeToString(cont->model),
              nports);

    /* Skip UHCI{1,2,3} companions; only add the EHCI1 */
    if (nports == 0)
        return 0;

    if (addrs->nbuses <= cont->idx) {
        VIR_EXPAND_N(addrs->buses, addrs->nbuses, cont->idx - addrs->nbuses + 1);
    } else if (addrs->buses[cont->idx]) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Duplicate USB controllers with index %1$u"),
                       cont->idx);
        goto cleanup;
    }

    if (!(hub = virDomainUSBAddressHubNew(nports)))
        goto cleanup;

    addrs->buses[cont->idx] = g_steal_pointer(&hub);

    ret = 0;
 cleanup:
    virDomainUSBAddressHubFree(hub);
    return ret;
}


static ssize_t
virDomainUSBAddressGetLastIdx(virDomainDeviceInfo *info)
{
    ssize_t i;
    for (i = VIR_DOMAIN_DEVICE_USB_MAX_PORT_DEPTH - 1; i > 0; i--) {
        if (info->addr.usb.port[i] != 0)
            break;
    }
    return i;
}


/* Find the USBAddressHub structure representing the hub/controller
 * that corresponds to the bus/port path specified by info.
 * Returns the index of the requested port in targetIdx.
 */
static virDomainUSBAddressHub *
virDomainUSBAddressFindPort(virDomainUSBAddressSet *addrs,
                            virDomainDeviceInfo *info,
                            int *targetIdx,
                            const char *portStr)
{
    virDomainUSBAddressHub *hub = NULL;
    ssize_t i, lastIdx, targetPort;

    if (info->addr.usb.bus >= addrs->nbuses ||
        !addrs->buses[info->addr.usb.bus]) {
        virReportError(VIR_ERR_XML_ERROR, _("Missing USB bus %1$u"),
                       info->addr.usb.bus);
        return NULL;
    }
    hub = addrs->buses[info->addr.usb.bus];

    lastIdx = virDomainUSBAddressGetLastIdx(info);

    for (i = 0; i < lastIdx; i++) {
        /* ports are numbered from 1 */
        int portIdx = info->addr.usb.port[i] - 1;

        if (hub->nports <= portIdx) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("port %1$u out of range in USB address bus: %2$u port: %3$s"),
                           info->addr.usb.port[i],
                           info->addr.usb.bus,
                           portStr);
            return NULL;
        }
        hub = hub->ports[portIdx];
        if (!hub) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("there is no hub at port %1$u in USB address bus: %2$u port: %3$s"),
                           info->addr.usb.port[i],
                           info->addr.usb.bus,
                           portStr);
            return NULL;
        }
    }

    targetPort = info->addr.usb.port[lastIdx] - 1;
    if (targetPort >= virBitmapSize(hub->portmap)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("requested USB port %1$s not present on USB bus %2$u"),
                       portStr, info->addr.usb.bus);
        return NULL;
    }

    *targetIdx = targetPort;
    return hub;
}


int
virDomainUSBAddressSetAddHub(virDomainUSBAddressSet *addrs,
                             virDomainHubDef *hub)
{
    virDomainUSBAddressHub *targetHub = NULL;
    virDomainUSBAddressHub *newHub = NULL;
    int ret = -1;
    int targetPort;
    g_autofree char *portStr = NULL;

    if (hub->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Wrong address type for USB hub"));
        goto cleanup;
    }

    if (!(portStr = virDomainUSBAddressPortFormat(hub->info.addr.usb.port)))
        goto cleanup;

    VIR_DEBUG("Adding a USB hub with 8 ports on bus=%u port=%s",
              hub->info.addr.usb.bus, portStr);

    if (!(newHub = virDomainUSBAddressHubNew(VIR_DOMAIN_USB_HUB_PORTS)))
        goto cleanup;

    if (!(targetHub = virDomainUSBAddressFindPort(addrs, &(hub->info), &targetPort,
                                                  portStr)))
        goto cleanup;

    if (targetHub->ports[targetPort]) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Duplicate USB hub on bus %1$u port %2$s"),
                       hub->info.addr.usb.bus, portStr);
        goto cleanup;
    }
    ignore_value(virBitmapSetBit(targetHub->portmap, targetPort));
    targetHub->ports[targetPort] = g_steal_pointer(&newHub);

    ret = 0;
 cleanup:
    virDomainUSBAddressHubFree(newHub);
    return ret;
}


int
virDomainUSBAddressSetAddControllers(virDomainUSBAddressSet *addrs,
                                     virDomainDef *def)
{
    size_t i;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDef *cont = def->controllers[i];
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) {
            if (virDomainUSBAddressSetAddController(addrs, cont) < 0)
                return -1;
        }
    }

    for (i = 0; i < def->nhubs; i++) {
        virDomainHubDef *hub = def->hubs[i];
        if (hub->type == VIR_DOMAIN_HUB_TYPE_USB &&
            hub->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB &&
            virDomainUSBAddressPortIsValid(hub->info.addr.usb.port)) {
            /* USB hubs that do not yet have an USB address have to be
             * dealt with later */
            if (virDomainUSBAddressSetAddHub(addrs, hub) < 0)
                return -1;
        }
    }
    return 0;
}


static int
virDomainUSBAddressFindFreePort(virDomainUSBAddressHub *hub,
                                unsigned int *portpath,
                                unsigned int level)
{
    unsigned int port;
    ssize_t portIdx;
    size_t i;

    /* Look for free ports on the current hub */
    if ((portIdx = virBitmapNextClearBit(hub->portmap, -1)) >= 0) {
        port = portIdx + 1;
        VIR_DEBUG("Found a free port %u at level %u", port, level);
        portpath[level] = port;
        return 0;
    }

    VIR_DEBUG("No ports found on hub %p, trying the hubs on it", hub);

    if (level >= VIR_DOMAIN_DEVICE_USB_MAX_PORT_DEPTH - 1)
        return -1;

    /* Recursively search through the ports that contain another hub */
    for (i = 0; i < hub->nports; i++) {
        if (!hub->ports[i])
            continue;

        port = i + 1;
        VIR_DEBUG("Looking at USB hub at level: %u port: %u", level, port);
        if (virDomainUSBAddressFindFreePort(hub->ports[i], portpath,
                                            level + 1) < 0)
            continue;

        portpath[level] = port;
        return 0;
    }
    return -1;
}


size_t
virDomainUSBAddressCountAllPorts(virDomainDef *def)
{
    size_t i, ret = 0;

    for (i = 0; i < def->ncontrollers; i++) {
        virDomainControllerDef *cont = def->controllers[i];
        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB)
            ret += virDomainUSBAddressControllerModelToPorts(cont);
    }

    for (i = 0; i < def->nhubs; i++) {
        virDomainHubDef *hub = def->hubs[i];
        if (hub->type == VIR_DOMAIN_HUB_TYPE_USB)
            ret += VIR_DOMAIN_USB_HUB_PORTS;
    }
    return ret;
}


/* Try to find a free port on bus @bus.
 *
 * Returns  0 on success
 *         -1 on fatal error (OOM)
 *         -2 if there is no bus at @bus or no free port on this bus
 */
static int
virDomainUSBAddressAssignFromBus(virDomainUSBAddressSet *addrs,
                                 virDomainDeviceInfo *info,
                                 size_t bus)
{
    unsigned int portpath[VIR_DOMAIN_DEVICE_USB_MAX_PORT_DEPTH] = { 0 };
    virDomainUSBAddressHub *hub = addrs->buses[bus];
    g_autofree char *portStr = NULL;

    if (!hub)
        return -2;

    if (virDomainUSBAddressFindFreePort(hub, portpath, 0) < 0)
        return -2;

    /* we found a free port */
    if (!(portStr = virDomainUSBAddressPortFormat(portpath)))
        return -1;

    info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB;
    info->addr.usb.bus = bus;
    memcpy(info->addr.usb.port, portpath, sizeof(portpath));
    VIR_DEBUG("Assigning USB addr bus=%u port=%s",
              info->addr.usb.bus, portStr);
    if (virDomainUSBAddressReserve(info, addrs) < 0)
        return -1;

    return 0;
}


int
virDomainUSBAddressAssign(virDomainUSBAddressSet *addrs,
                          virDomainDeviceInfo *info)
{
    size_t i;
    int rc;

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
        VIR_DEBUG("A USB port on bus %u was requested", info->addr.usb.bus);
        if (info->addr.usb.bus >= addrs->nbuses ||
            !addrs->buses[info->addr.usb.bus]) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("USB bus %1$u requested but no controller with that index is present"),
                           info->addr.usb.bus);
            return -1;
        }
        rc = virDomainUSBAddressAssignFromBus(addrs, info, info->addr.usb.bus);
        if (rc >= -1)
            return rc;
    } else {
        VIR_DEBUG("Looking for a free USB port on all the buses");
        for (i = 0; i < addrs->nbuses; i++) {
            rc = virDomainUSBAddressAssignFromBus(addrs, info, i);
            if (rc >= -1)
                return rc;
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("No free USB ports"));
    return -1;
}


int
virDomainUSBAddressPresent(virDomainDeviceInfo *info,
                           void *data G_GNUC_UNUSED)
{
    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB &&
        virDomainUSBAddressPortIsValid(info->addr.usb.port))
        return 0;

    return -1;
}


int
virDomainUSBAddressReserve(virDomainDeviceInfo *info,
                           void *data)
{
    virDomainUSBAddressSet *addrs = data;
    virDomainUSBAddressHub *targetHub = NULL;
    g_autofree char *portStr = NULL;
    int targetPort;

    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB)
        return 0;

    if (!virDomainUSBAddressPortIsValid(info->addr.usb.port))
        return 0;

    portStr = virDomainUSBAddressPortFormat(info->addr.usb.port);
    if (!portStr)
        return -1;
    VIR_DEBUG("Reserving USB address bus=%u port=%s", info->addr.usb.bus, portStr);

    if (!(targetHub = virDomainUSBAddressFindPort(addrs, info, &targetPort,
                                                  portStr)))
        return -1;

    if (virBitmapIsBitSet(targetHub->portmap, targetPort)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Duplicate USB address bus %1$u port %2$s"),
                       info->addr.usb.bus, portStr);
        return -1;
    }

    ignore_value(virBitmapSetBit(targetHub->portmap, targetPort));

    return 0;
}


int
virDomainUSBAddressEnsure(virDomainUSBAddressSet *addrs,
                          virDomainDeviceInfo *info)
{
    if (!addrs)
        return 0;

    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE ||
        (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB &&
         !virDomainUSBAddressPortIsValid(info->addr.usb.port))) {
        if (virDomainUSBAddressAssign(addrs, info) < 0)
            return -1;
    } else if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
        if (virDomainUSBAddressReserve(info, addrs) < 0)
            return -1;
    }

    return 0;
}


int
virDomainUSBAddressRelease(virDomainUSBAddressSet *addrs,
                           virDomainDeviceInfo *info)
{
    virDomainUSBAddressHub *targetHub = NULL;
    g_autofree char *portStr = NULL;
    int targetPort;

    if (!addrs || info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB ||
        !virDomainUSBAddressPortIsValid(info->addr.usb.port))
        return 0;

    portStr = virDomainUSBAddressPortFormat(info->addr.usb.port);
    VIR_DEBUG("Releasing USB addr bus=%u port=%s", info->addr.usb.bus, portStr);

    if (!(targetHub = virDomainUSBAddressFindPort(addrs, info, &targetPort,
                                                  portStr)))
        return -1;

    ignore_value(virBitmapClearBit(targetHub->portmap, targetPort));

    return 0;
}
