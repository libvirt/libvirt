/*
 * domain_addr.h: helper APIs for managing domain device addresses
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

#pragma once

#include "domain_conf.h"

#define VIR_PCI_ADDRESS_SLOT_LAST 31
#define VIR_PCI_ADDRESS_FUNCTION_LAST 7

typedef enum {
    VIR_PCI_ADDRESS_EXTENSION_NONE = 0, /* no extension */
    VIR_PCI_ADDRESS_EXTENSION_ZPCI = 1 << 0, /* zPCI support */
} virPCIDeviceAddressExtensionFlags;

typedef enum {
    VIR_PCI_CONNECT_AUTOASSIGN = 1 << 0, /* okay to autoassign a device to this controller */
    VIR_PCI_CONNECT_HOTPLUGGABLE = 1 << 1, /* is hotplug needed/supported */

    /* Set for devices that can only work as integrated devices (directly
     * connected to pci.0 or pcie.0, with no additional buses in between) */
    VIR_PCI_CONNECT_INTEGRATED = 1 << 2,

    /* set for devices that can share a single slot in auto-assignment
     * (by assigning one device to each of the 8 functions on the slot)
     */
    VIR_PCI_CONNECT_AGGREGATE_SLOT = 1 << 3,

    /* kinds of devices as a bitmap so they can be combined (some PCI
     * controllers permit connecting multiple types of devices)
     */
    VIR_PCI_CONNECT_TYPE_PCI_DEVICE = 1 << 4,
    VIR_PCI_CONNECT_TYPE_PCIE_DEVICE = 1 << 5,
    VIR_PCI_CONNECT_TYPE_PCIE_ROOT_PORT = 1 << 6,
    VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_UPSTREAM_PORT = 1 << 7,
    VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_DOWNSTREAM_PORT = 1 << 8,
    VIR_PCI_CONNECT_TYPE_DMI_TO_PCI_BRIDGE = 1 << 9,
    VIR_PCI_CONNECT_TYPE_PCI_EXPANDER_BUS = 1 << 10,
    VIR_PCI_CONNECT_TYPE_PCIE_EXPANDER_BUS = 1 << 11,
    VIR_PCI_CONNECT_TYPE_PCI_BRIDGE = 1 << 12,
    VIR_PCI_CONNECT_TYPE_PCIE_TO_PCI_BRIDGE = 1 << 13,
} virDomainPCIConnectFlags;

/* a combination of all bits that describe the type of connections
 * allowed, e.g. PCI, PCIe, switch
 */
#define VIR_PCI_CONNECT_TYPES_MASK \
   (VIR_PCI_CONNECT_TYPE_PCI_DEVICE | VIR_PCI_CONNECT_TYPE_PCIE_DEVICE | \
    VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_UPSTREAM_PORT | \
    VIR_PCI_CONNECT_TYPE_PCIE_SWITCH_DOWNSTREAM_PORT | \
    VIR_PCI_CONNECT_TYPE_PCIE_ROOT_PORT | \
    VIR_PCI_CONNECT_TYPE_DMI_TO_PCI_BRIDGE | \
    VIR_PCI_CONNECT_TYPE_PCI_EXPANDER_BUS | \
    VIR_PCI_CONNECT_TYPE_PCIE_EXPANDER_BUS | \
    VIR_PCI_CONNECT_TYPE_PCI_BRIDGE | \
    VIR_PCI_CONNECT_TYPE_PCIE_TO_PCI_BRIDGE)

/* combination of all bits that could be used to connect a normal
 * endpoint device (i.e. excluding the connection possible between an
 * upstream and downstream switch port, or a PCIe root port and a PCIe
 * port)
 */
#define VIR_PCI_CONNECT_TYPES_ENDPOINT \
   (VIR_PCI_CONNECT_TYPE_PCI_DEVICE | VIR_PCI_CONNECT_TYPE_PCIE_DEVICE)

virDomainPCIConnectFlags
virDomainPCIControllerModelToConnectType(virDomainControllerModelPCI model);

typedef struct {
    /* each function is represented by one bit, set if that function is
     * in use by a device, or clear if it isn't.
     */
    uint8_t functions;

    /* aggregate is true if this slot has only devices with
     * VIR_PCI_CONNECT_AGGREGATE assigned to its functions (meaning
     * that other devices with the same flags could also be
     * auto-assigned to the other functions)
     */
    bool aggregate;
} virDomainPCIAddressSlot;

typedef struct {
    virDomainControllerModelPCI model;
    /* flags and min/max can be computed from model, but
     * having them ready makes life easier.
     */
    virDomainPCIConnectFlags flags;
    size_t minSlot, maxSlot; /* usually 0,0 or 0,31, or 1,31 */
    /* Each bit in a slot represents one function on that slot. If the
     * bit is set, that function is in use by a device.
     */
    virDomainPCIAddressSlot slot[VIR_PCI_ADDRESS_SLOT_LAST + 1];

    /* See virDomainDeviceInfo::isolationGroup */
    unsigned int isolationGroup;

    /* See virDomainDeviceInfo::isolationGroupLocked */
    bool isolationGroupLocked;
} virDomainPCIAddressBus;

typedef struct {
    GHashTable *uids;
    GHashTable *fids;
} virDomainZPCIAddressIds;

struct _virDomainPCIAddressSet {
    virDomainPCIAddressBus *buses;
    size_t nbuses;
    bool dryRun;          /* on a dry run, new buses are auto-added
                             and addresses aren't saved in device infos */
    /* If true, the guest can have multiple pci-root controllers */
    bool areMultipleRootsSupported;
    /* If true, the guest can use the pcie-to-pci-bridge controller */
    bool isPCIeToPCIBridgeSupported;
    virDomainZPCIAddressIds *zpciIds;
};
typedef struct _virDomainPCIAddressSet virDomainPCIAddressSet;

virDomainPCIAddressSet *
virDomainPCIAddressSetAlloc(unsigned int nbuses,
                            virPCIDeviceAddressExtensionFlags extFlags);

void virDomainPCIAddressSetFree(virDomainPCIAddressSet *addrs);

bool virDomainPCIAddressValidate(virDomainPCIAddressSet *addrs,
                                 virPCIDeviceAddress *addr,
                                 const char *addrStr,
                                 virDomainPCIConnectFlags flags,
                                 bool fromConfig)
     ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);


int virDomainPCIAddressBusSetModel(virDomainPCIAddressBus *bus,
                                   virDomainControllerModelPCI model,
                                   bool allowHotplug)
    ATTRIBUTE_NONNULL(1);

bool virDomainPCIAddressBusIsFullyReserved(virDomainPCIAddressBus *bus)
    ATTRIBUTE_NONNULL(1);

bool virDomainPCIAddressSlotInUse(virDomainPCIAddressSet *addrs,
                                  virPCIDeviceAddress *addr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virDomainPCIAddressExtensionReserveAddr(virDomainPCIAddressSet *addrs,
                                            virPCIDeviceAddress *addr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virDomainPCIAddressExtensionReserveNextAddr(virDomainPCIAddressSet *addrs,
                                                virPCIDeviceAddress *addr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virDomainPCIAddressReserveAddr(virDomainPCIAddressSet *addrs,
                                   virPCIDeviceAddress *addr,
                                   virDomainPCIConnectFlags flags,
                                   unsigned int isolationGroup)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virDomainPCIAddressReserveNextAddr(virDomainPCIAddressSet *addrs,
                                       virDomainDeviceInfo *dev,
                                       virDomainPCIConnectFlags flags,
                                       int function)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virDomainPCIAddressEnsureAddr(virDomainPCIAddressSet *addrs,
                                  virDomainDeviceInfo *dev,
                                  virDomainPCIConnectFlags flags)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virDomainPCIAddressReleaseAddr(virDomainPCIAddressSet *addrs,
                                    virPCIDeviceAddress *addr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virDomainPCIAddressExtensionReleaseAddr(virDomainPCIAddressSet *addrs,
                                             virPCIDeviceAddress *addr)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virDomainPCIAddressSetAllMulti(virDomainDef *def)
    ATTRIBUTE_NONNULL(1);

struct _virDomainCCWAddressSet {
    GHashTable *defined;
    virCCWDeviceAddress next;
};
typedef struct _virDomainCCWAddressSet virDomainCCWAddressSet;

int virDomainCCWAddressAssign(virDomainDeviceInfo *dev,
                              virDomainCCWAddressSet *addrs,
                              bool autoassign)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
void virDomainCCWAddressSetFree(virDomainCCWAddressSet *addrs);

virDomainCCWAddressSet *
virDomainCCWAddressSetCreateFromDomain(virDomainDef *def)
    ATTRIBUTE_NONNULL(1);

struct _virDomainVirtioSerialController {
    unsigned int idx;
    virBitmap *ports;
};

typedef struct _virDomainVirtioSerialController virDomainVirtioSerialController;

struct _virDomainVirtioSerialAddrSet {
    virDomainVirtioSerialController **controllers;
    size_t ncontrollers;
};
typedef struct _virDomainVirtioSerialAddrSet virDomainVirtioSerialAddrSet;

void
virDomainVirtioSerialAddrSetFree(virDomainVirtioSerialAddrSet *addrs);
virDomainVirtioSerialAddrSet *
virDomainVirtioSerialAddrSetCreateFromDomain(virDomainDef *def)
    ATTRIBUTE_NONNULL(1);
bool
virDomainVirtioSerialAddrIsComplete(virDomainDeviceInfo *info);
int
virDomainVirtioSerialAddrAutoAssignFromCache(virDomainDef *def,
                                             virDomainVirtioSerialAddrSet *addrs,
                                             virDomainDeviceInfo *info,
                                             bool allowZero)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int
virDomainVirtioSerialAddrAutoAssign(virDomainDef *def,
                                    virDomainDeviceInfo *info,
                                    bool allowZero)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool
virDomainUSBAddressPortIsValid(const unsigned int *port)
    ATTRIBUTE_NONNULL(1);

void
virDomainUSBAddressPortFormatBuf(virBuffer *buf,
                                 const unsigned int *port)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

#define VIR_DOMAIN_USB_HUB_PORTS 8

typedef struct _virDomainUSBAddressHub virDomainUSBAddressHub;
struct _virDomainUSBAddressHub {
    /* indexes are shifted by one:
     * ports[0] represents port 1, because ports are numbered from 1 */
    virBitmap *portmap;
    size_t nports;
    virDomainUSBAddressHub **ports;
};

struct _virDomainUSBAddressSet {
    /* every <controller type='usb' index='i'> is represented
     * as a hub at buses[i] */
    virDomainUSBAddressHub **buses;
    size_t nbuses;
};
typedef struct _virDomainUSBAddressSet virDomainUSBAddressSet;

virDomainUSBAddressSet *virDomainUSBAddressSetCreate(void);

int virDomainUSBAddressSetAddControllers(virDomainUSBAddressSet *addrs,
                                         virDomainDef *def)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int
virDomainUSBAddressSetAddHub(virDomainUSBAddressSet *addrs,
                             virDomainHubDef *hub)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
size_t
virDomainUSBAddressCountAllPorts(virDomainDef *def);
void virDomainUSBAddressSetFree(virDomainUSBAddressSet *addrs);

int
virDomainUSBAddressPresent(virDomainDeviceInfo *info,
                           void *data)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int
virDomainUSBAddressReserve(virDomainDeviceInfo *info,
                           void *data)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
virDomainUSBAddressAssign(virDomainUSBAddressSet *addrs,
                          virDomainDeviceInfo *info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int
virDomainUSBAddressEnsure(virDomainUSBAddressSet *addrs,
                          virDomainDeviceInfo *info)
    ATTRIBUTE_NONNULL(2);

int
virDomainUSBAddressRelease(virDomainUSBAddressSet *addrs,
                           virDomainDeviceInfo *info)
    ATTRIBUTE_NONNULL(2);
