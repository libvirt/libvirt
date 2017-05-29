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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __DEVICE_CONF_H__
# define __DEVICE_CONF_H__

# include <libxml/parser.h>
# include <libxml/tree.h>
# include <libxml/xpath.h>

# include "internal.h"
# include "virutil.h"
# include "virthread.h"
# include "virbuffer.h"
# include "virpci.h"
# include "virnetdev.h"

typedef enum {
    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE,
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

    VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST
} virDomainDeviceAddressType;

typedef struct _virDomainDeviceDriveAddress virDomainDeviceDriveAddress;
typedef virDomainDeviceDriveAddress *virDomainDeviceDriveAddressPtr;
struct _virDomainDeviceDriveAddress {
    unsigned int controller;
    unsigned int bus;
    unsigned int target;
    unsigned int unit;
};

typedef struct _virDomainDeviceVirtioSerialAddress virDomainDeviceVirtioSerialAddress;
typedef virDomainDeviceVirtioSerialAddress *virDomainDeviceVirtioSerialAddressPtr;
struct _virDomainDeviceVirtioSerialAddress {
    unsigned int controller;
    unsigned int bus;
    unsigned int port;
};

# define VIR_DOMAIN_DEVICE_CCW_MAX_CSSID    254
# define VIR_DOMAIN_DEVICE_CCW_MAX_SSID       3
# define VIR_DOMAIN_DEVICE_CCW_MAX_DEVNO  65535

typedef struct _virDomainDeviceCCWAddress virDomainDeviceCCWAddress;
typedef virDomainDeviceCCWAddress *virDomainDeviceCCWAddressPtr;
struct _virDomainDeviceCCWAddress {
    unsigned int cssid;
    unsigned int ssid;
    unsigned int devno;
    bool         assigned;
};

typedef struct _virDomainDeviceCcidAddress virDomainDeviceCcidAddress;
typedef virDomainDeviceCcidAddress *virDomainDeviceCcidAddressPtr;
struct _virDomainDeviceCcidAddress {
    unsigned int controller;
    unsigned int slot;
};

# define VIR_DOMAIN_DEVICE_USB_MAX_PORT_DEPTH 4

typedef struct _virDomainDeviceUSBAddress virDomainDeviceUSBAddress;
typedef virDomainDeviceUSBAddress *virDomainDeviceUSBAddressPtr;
struct _virDomainDeviceUSBAddress {
    unsigned int bus;
    unsigned int port[VIR_DOMAIN_DEVICE_USB_MAX_PORT_DEPTH];
};

typedef struct _virDomainDeviceSpaprVioAddress virDomainDeviceSpaprVioAddress;
typedef virDomainDeviceSpaprVioAddress *virDomainDeviceSpaprVioAddressPtr;
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
typedef virDomainDeviceUSBMaster *virDomainDeviceUSBMasterPtr;
struct _virDomainDeviceUSBMaster {
    unsigned int startport;
};

typedef struct _virDomainDeviceISAAddress virDomainDeviceISAAddress;
typedef virDomainDeviceISAAddress *virDomainDeviceISAAddressPtr;
struct _virDomainDeviceISAAddress {
    unsigned int iobase;
    unsigned int irq;
};

typedef struct _virDomainDeviceDimmAddress virDomainDeviceDimmAddress;
typedef virDomainDeviceDimmAddress *virDomainDeviceDimmAddressPtr;
struct _virDomainDeviceDimmAddress {
    unsigned int slot;
    unsigned long long base;
};

typedef struct _virDomainDeviceInfo virDomainDeviceInfo;
typedef virDomainDeviceInfo *virDomainDeviceInfoPtr;
struct _virDomainDeviceInfo {
    char *alias;
    int type; /* virDomainDeviceAddressType */
    union {
        virPCIDeviceAddress pci;
        virDomainDeviceDriveAddress drive;
        virDomainDeviceVirtioSerialAddress vioserial;
        virDomainDeviceCcidAddress ccid;
        virDomainDeviceUSBAddress usb;
        virDomainDeviceSpaprVioAddress spaprvio;
        virDomainDeviceCCWAddress ccw;
        virDomainDeviceISAAddress isa;
        virDomainDeviceDimmAddress dimm;
    } addr;
    int mastertype;
    union {
        virDomainDeviceUSBMaster usb;
    } master;
    /* rombar and romfile are only used for pci hostdev and network
     * devices. */
    int rombar;         /* enum virTristateSwitch */
    char *romfile;
    /* bootIndex is only used for disk, network interface, hostdev
     * and redirdev devices */
    unsigned int bootIndex;

    /* pciConnectFlags is only used internally during address
     * assignment, never saved and never reported.
     */
    int pciConnectFlags; /* enum virDomainPCIConnectFlags */
    char *loadparm;
};


int virPCIDeviceAddressIsValid(virPCIDeviceAddressPtr addr,
                               bool report);

static inline bool
virPCIDeviceAddressIsEmpty(const virPCIDeviceAddress *addr)
{
    return !(addr->domain || addr->bus || addr->slot);
}

static inline bool
virDeviceInfoPCIAddressWanted(const virDomainDeviceInfo *info)
{
    return info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE ||
        (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
         virPCIDeviceAddressIsEmpty(&info->addr.pci));
}

static inline bool
virDeviceInfoPCIAddressPresent(const virDomainDeviceInfo *info)
{
    return info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
       !virPCIDeviceAddressIsEmpty(&info->addr.pci);
}

int virPCIDeviceAddressParseXML(xmlNodePtr node,
                                virPCIDeviceAddressPtr addr);

int virPCIDeviceAddressFormat(virBufferPtr buf,
                              virPCIDeviceAddress addr,
                              bool includeTypeInAddr);

bool virPCIDeviceAddressEqual(virPCIDeviceAddress *addr1,
                              virPCIDeviceAddress *addr2);

int virInterfaceLinkParseXML(xmlNodePtr node,
                             virNetDevIfLinkPtr lnk);

int virInterfaceLinkFormat(virBufferPtr buf,
                           const virNetDevIfLink *lnk);

#endif /* __DEVICE_CONF_H__ */
