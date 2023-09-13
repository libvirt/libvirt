/*
 * device_conf.h: device XML handling entry points
 *
 * Copyright (C) 2006-2012, 2014-2016 Red Hat, Inc.
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

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

#include "internal.h"
#include "virbuffer.h"
#include "virccw.h"
#include "virpci.h"
#include "virnetdev.h"
#include "virenum.h"

typedef enum {
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE = 0,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM,
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED,

    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST
} virDomainDeviceAddressType;

VIR_ENUM_DECL(virDomainDeviceAddress);

typedef struct _virDomainDeviceDriveAddress virDomainDeviceDriveAddress;
struct _virDomainDeviceDriveAddress {
    unsigned int controller;
    unsigned int bus;
    unsigned int target;
    unsigned int unit;

    /* internal fields for the address formatter */
    unsigned int diskbus; /* virDomainDiskBus */
};

typedef struct _virDomainDeviceVirtioSerialAddress virDomainDeviceVirtioSerialAddress;
struct _virDomainDeviceVirtioSerialAddress {
    unsigned int controller;
    unsigned int bus;
    unsigned int port;
};

typedef struct _virDomainDeviceCcidAddress virDomainDeviceCcidAddress;
struct _virDomainDeviceCcidAddress {
    unsigned int controller;
    unsigned int slot;
};

#define VIR_DOMAIN_DEVICE_USB_MAX_PORT_DEPTH 4

typedef struct _virDomainDeviceUSBAddress virDomainDeviceUSBAddress;
struct _virDomainDeviceUSBAddress {
    unsigned int bus;
    unsigned int port[VIR_DOMAIN_DEVICE_USB_MAX_PORT_DEPTH];
};

typedef struct _virDomainDeviceSpaprVioAddress virDomainDeviceSpaprVioAddress;
struct _virDomainDeviceSpaprVioAddress {
    unsigned long long reg;
    bool has_reg;
};

typedef enum {
    VIR_DOMAIN_CONTROLLER_MASTER_NONE,
    VIR_DOMAIN_CONTROLLER_MASTER_USB,

    VIR_DOMAIN_CONTROLLER_MASTER_LAST
} virDomainControllerMaster;

typedef struct _virDomainDeviceUSBMaster virDomainDeviceUSBMaster;
struct _virDomainDeviceUSBMaster {
    unsigned int startport;
};

typedef struct _virDomainDeviceISAAddress virDomainDeviceISAAddress;
struct _virDomainDeviceISAAddress {
    unsigned int iobase;
    unsigned int irq;
};

typedef struct _virDomainDeviceDimmAddress virDomainDeviceDimmAddress;
struct _virDomainDeviceDimmAddress {
    unsigned int slot;
    unsigned long long base;
};

typedef struct _virDomainDeviceInfo virDomainDeviceInfo;
struct _virDomainDeviceInfo {
    char *alias;
    virDomainDeviceAddressType type;
    union {
        virPCIDeviceAddress pci;
        virDomainDeviceDriveAddress drive;
        virDomainDeviceVirtioSerialAddress vioserial;
        virDomainDeviceCcidAddress ccid;
        virDomainDeviceUSBAddress usb;
        virDomainDeviceSpaprVioAddress spaprvio;
        virCCWDeviceAddress ccw;
        virDomainDeviceISAAddress isa;
        virDomainDeviceDimmAddress dimm;
    } addr;
    int mastertype;
    union {
        virDomainDeviceUSBMaster usb;
    } master;
    /* rombar and romfile are only used for pci hostdev and network
     * devices. */
    virTristateBool romenabled;
    virTristateSwitch rombar;
    char *romfile;
    /* bootIndex is only used for disk, network interface, hostdev
     * and redirdev devices */
    unsigned int bootIndex;
    /* 'effectiveBootIndex' is same as 'bootIndex' (if provided in the XML) but
     * not formatted back. This allows HV drivers to update it if <os><boot ..
     * is present. */
    unsigned int effectiveBootIndex;
    /* Valid for any PCI device. Can be used for NIC to get
     * stable numbering in Linux */
    unsigned int acpiIndex;

    /* pciConnectFlags is only used internally during address
     * assignment, never saved and never reported.
     */
    int pciConnectFlags; /* enum virDomainPCIConnectFlags */
    /* pciAddrExtFlags is only used internally to calculate PCI
     * address extension flags during address assignment.
     */
    int pciAddrExtFlags; /* enum virDomainPCIAddressExtensionFlags */
    char *loadparm;

    /* PCI devices will only be automatically placed on a PCI bus
     * that shares the same isolation group */
    unsigned int isolationGroup;

    /* Usually, PCI buses will take on the same isolation group
     * as the first device that is plugged into them, but in some
     * cases we might want to prevent that from happening by
     * locking the isolation group */
    bool isolationGroupLocked;
};

void virDomainDeviceInfoClear(virDomainDeviceInfo *info);
void virDomainDeviceInfoFree(virDomainDeviceInfo *info);

bool virDomainDeviceInfoAddressIsEqual(const virDomainDeviceInfo *a,
                                       const virDomainDeviceInfo *b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

bool virDomainDeviceAddressIsValid(virDomainDeviceInfo *info,
                                   int type);

bool virDeviceInfoPCIAddressIsWanted(const virDomainDeviceInfo *info);
bool virDeviceInfoPCIAddressIsPresent(const virDomainDeviceInfo *info);

bool virDeviceInfoPCIAddressExtensionIsWanted(const virDomainDeviceInfo *info);
bool virDeviceInfoPCIAddressExtensionIsPresent(const virDomainDeviceInfo *info);

int virPCIDeviceAddressParseXML(xmlNodePtr node,
                                virPCIDeviceAddress *addr);

void virPCIDeviceAddressFormat(virBuffer *buf,
                               virPCIDeviceAddress addr,
                               bool includeTypeInAddr);

int virCCWDeviceAddressParseXML(xmlNodePtr node,
                                virCCWDeviceAddress *addr);

int virDomainDeviceDriveAddressParseXML(xmlNodePtr node,
                                        virDomainDeviceDriveAddress *addr);

int virDomainDeviceVirtioSerialAddressParseXML(xmlNodePtr node,
                                               virDomainDeviceVirtioSerialAddress *addr);

int virDomainDeviceCcidAddressParseXML(xmlNodePtr node,
                                       virDomainDeviceCcidAddress *addr);

int virDomainDeviceUSBAddressParseXML(xmlNodePtr node,
                                      virDomainDeviceUSBAddress *addr);

int virDomainDeviceSpaprVioAddressParseXML(xmlNodePtr node,
                                           virDomainDeviceSpaprVioAddress *addr);

int virInterfaceLinkParseXML(xmlNodePtr node,
                             virNetDevIfLink *lnk);

int virInterfaceLinkFormat(virBuffer *buf,
                           const virNetDevIfLink *lnk);
