/*
 * device_conf.c: device XML handling
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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
#include "virerror.h"
#include "viralloc.h"
#include "virxml.h"
#include "virbuffer.h"
#include "device_conf.h"
#include "domain_addr.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_DEVICE

VIR_ENUM_IMPL(virDomainDeviceAddress,
              VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST,
              "none",
              "pci",
              "drive",
              "virtio-serial",
              "ccid",
              "usb",
              "spapr-vio",
              "virtio-s390",
              "ccw",
              "virtio-mmio",
              "isa",
              "dimm",
              "unassigned",
);

static int
virZPCIDeviceAddressParseXML(xmlNodePtr node,
                             virPCIDeviceAddress *addr)
{
    int retUid;
    int retFid;

    if ((retUid = virXMLPropUInt(node, "uid", 0, VIR_XML_PROP_NONE,
                                 &addr->zpci.uid.value)) < 0)
        return -1;

    if (retUid > 0)
        addr->zpci.uid.isSet = true;

    if ((retFid = virXMLPropUInt(node, "fid", 0, VIR_XML_PROP_NONE,
                                 &addr->zpci.fid.value)) < 0)
        return -1;

    if (retFid > 0)
        addr->zpci.fid.isSet = true;

    return 0;
}

void
virDomainDeviceInfoClear(virDomainDeviceInfo *info)
{
    VIR_FREE(info->alias);
    memset(&info->addr, 0, sizeof(info->addr));
    info->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE;
    VIR_FREE(info->romfile);
    VIR_FREE(info->loadparm);
    info->isolationGroup = 0;
    info->isolationGroupLocked = false;
}

void
virDomainDeviceInfoFree(virDomainDeviceInfo *info)
{
    if (info) {
        virDomainDeviceInfoClear(info);
        g_free(info);
    }
}

bool
virDomainDeviceInfoAddressIsEqual(const virDomainDeviceInfo *a,
                                  const virDomainDeviceInfo *b)
{
    if (a->type != b->type)
        return false;

    switch (a->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
    /* address types below don't have any specific data */
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED:
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        /* the 'multi' field shouldn't be checked */
        if (a->addr.pci.domain != b->addr.pci.domain ||
            a->addr.pci.bus != b->addr.pci.bus ||
            a->addr.pci.slot != b->addr.pci.slot ||
            a->addr.pci.function != b->addr.pci.function)
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        if (a->addr.drive.controller != b->addr.drive.controller ||
            a->addr.drive.unit != b->addr.drive.unit ||
            a->addr.drive.bus != b->addr.drive.bus ||
            a->addr.drive.target != b->addr.drive.target)
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL:
        if (memcmp(&a->addr.vioserial, &b->addr.vioserial, sizeof(a->addr.vioserial)))
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID:
        if (memcmp(&a->addr.ccid, &b->addr.ccid, sizeof(a->addr.ccid)))
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
        if (memcmp(&a->addr.usb, &b->addr.usb, sizeof(a->addr.usb)))
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO:
        if (memcmp(&a->addr.spaprvio, &b->addr.spaprvio, sizeof(a->addr.spaprvio)))
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
        /* the 'assigned' field denotes that the address was generated */
        if (a->addr.ccw.cssid != b->addr.ccw.cssid ||
            a->addr.ccw.ssid != b->addr.ccw.ssid ||
            a->addr.ccw.devno != b->addr.ccw.devno)
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
        if (memcmp(&a->addr.isa, &b->addr.isa, sizeof(a->addr.isa)))
            return false;
        break;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM:
        if (memcmp(&a->addr.dimm, &b->addr.dimm, sizeof(a->addr.dimm)))
            return false;
        break;
    }

    return true;
}

bool
virDeviceInfoPCIAddressIsWanted(const virDomainDeviceInfo *info)
{
    return info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE ||
           (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
            virPCIDeviceAddressIsEmpty(&info->addr.pci));
}

bool
virDeviceInfoPCIAddressIsPresent(const virDomainDeviceInfo *info)
{
    return info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
           !virPCIDeviceAddressIsEmpty(&info->addr.pci);
}

bool
virDeviceInfoPCIAddressExtensionIsWanted(const virDomainDeviceInfo *info)
{
    return (info->addr.pci.extFlags & VIR_PCI_ADDRESS_EXTENSION_ZPCI) &&
           virZPCIDeviceAddressIsIncomplete(&info->addr.pci.zpci);
}

bool
virDeviceInfoPCIAddressExtensionIsPresent(const virDomainDeviceInfo *info)
{
    return (info->addr.pci.extFlags & VIR_PCI_ADDRESS_EXTENSION_ZPCI) &&
           virZPCIDeviceAddressIsPresent(&info->addr.pci.zpci);
}

int
virPCIDeviceAddressParseXML(xmlNodePtr node,
                            virPCIDeviceAddress *addr)
{
    xmlNodePtr zpci;

    memset(addr, 0, sizeof(*addr));

    if (virXMLPropUInt(node, "domain", 0, VIR_XML_PROP_NONE,
                       &addr->domain) < 0)
        return -1;

    if (virXMLPropUInt(node, "bus", 0, VIR_XML_PROP_NONE,
                       &addr->bus) < 0)
        return -1;

    if (virXMLPropUInt(node, "slot", 0, VIR_XML_PROP_NONE,
                       &addr->slot) < 0)
        return -1;

    if (virXMLPropUInt(node, "function", 0, VIR_XML_PROP_NONE,
                       &addr->function) < 0)
        return -1;

    if (virXMLPropTristateSwitch(node, "multifunction", VIR_XML_PROP_NONE,
                                 &addr->multi) < 0)
        return -1;

    if (!virPCIDeviceAddressIsEmpty(addr) && !virPCIDeviceAddressIsValid(addr, true))
        return -1;

    if ((zpci = virXMLNodeGetSubelement(node, "zpci"))) {
        if (virZPCIDeviceAddressParseXML(zpci, addr) < 0)
            return -1;
    }

    return 0;
}

void
virPCIDeviceAddressFormat(virBuffer *buf,
                          virPCIDeviceAddress addr,
                          bool includeTypeInAddr)
{
    virBufferAsprintf(buf, "<address %sdomain='0x%04x' bus='0x%02x' "
                      "slot='0x%02x' function='0x%d'/>\n",
                      includeTypeInAddr ? "type='pci' " : "",
                      addr.domain,
                      addr.bus,
                      addr.slot,
                      addr.function);
}

int
virCCWDeviceAddressParseXML(xmlNodePtr node,
                            virCCWDeviceAddress *addr)
{
    int cssid;
    int ssid;
    int devno;

    memset(addr, 0, sizeof(*addr));

    if ((cssid = virXMLPropUInt(node, "cssid", 0, VIR_XML_PROP_NONE,
                                &addr->cssid)) < 0)
        return -1;

    if ((ssid = virXMLPropUInt(node, "ssid", 0, VIR_XML_PROP_NONE,
                               &addr->ssid)) < 0)
        return -1;

    if ((devno = virXMLPropUInt(node, "devno", 0, VIR_XML_PROP_NONE,
                                &addr->devno)) < 0)
        return -1;

    if (!virCCWDeviceAddressIsValid(addr)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid specification for virtio ccw address: cssid='0x%1$x' ssid='0x%2$x' devno='0x%3$04x'"),
                       addr->cssid, addr->ssid, addr->devno);
        return -1;
    }

    if (cssid && ssid && devno) {
        addr->assigned = true;
    } else if (cssid || ssid || devno) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Invalid partial specification for virtio ccw address"));
        return -1;
    }

    return 0;
}

int
virDomainDeviceDriveAddressParseXML(xmlNodePtr node,
                                    virDomainDeviceDriveAddress *addr)
{
    memset(addr, 0, sizeof(*addr));

    if (virXMLPropUInt(node, "controller", 10, VIR_XML_PROP_NONE,
                       &addr->controller) < 0)
        return -1;

    if (virXMLPropUInt(node, "bus", 10, VIR_XML_PROP_NONE, &addr->bus) < 0)
        return -1;

    if (virXMLPropUInt(node, "target", 10, VIR_XML_PROP_NONE,
                       &addr->target) < 0)
        return -1;

    if (virXMLPropUInt(node, "unit", 10, VIR_XML_PROP_NONE, &addr->unit) < 0)
        return -1;

    return 0;
}

int
virDomainDeviceVirtioSerialAddressParseXML(xmlNodePtr node,
                                           virDomainDeviceVirtioSerialAddress *addr)
{
    memset(addr, 0, sizeof(*addr));

    if (virXMLPropUInt(node, "controller", 10, VIR_XML_PROP_NONE,
                       &addr->controller) < 0)
        return -1;

    if (virXMLPropUInt(node, "bus", 10, VIR_XML_PROP_NONE, &addr->bus) < 0)
        return -1;

    if (virXMLPropUInt(node, "port", 10, VIR_XML_PROP_NONE, &addr->port) < 0)
        return -1;

    return 0;
}

int
virDomainDeviceCcidAddressParseXML(xmlNodePtr node,
                                   virDomainDeviceCcidAddress *addr)
{
    memset(addr, 0, sizeof(*addr));

    if (virXMLPropUInt(node, "controller", 10, VIR_XML_PROP_NONE,
                       &addr->controller) < 0)
        return -1;

    if (virXMLPropUInt(node, "slot", 10, VIR_XML_PROP_NONE, &addr->slot) < 0)
        return -1;

    return 0;
}

static int
virDomainDeviceUSBAddressParsePort(virDomainDeviceUSBAddress *addr,
                                   char *port)
{
    char *tmp = port;
    size_t i;

    for (i = 0; i < VIR_DOMAIN_DEVICE_USB_MAX_PORT_DEPTH; i++) {
        if (virStrToLong_uip(tmp, &tmp, 10, &addr->port[i]) < 0)
            break;

        if (*tmp == '\0')
            return 0;

        if (*tmp == '.')
            tmp++;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Cannot parse <address> 'port' attribute"));
    return -1;
}

int
virDomainDeviceUSBAddressParseXML(xmlNodePtr node,
                                  virDomainDeviceUSBAddress *addr)
{
    g_autofree char *port = virXMLPropString(node, "port");

    memset(addr, 0, sizeof(*addr));

    if (port && virDomainDeviceUSBAddressParsePort(addr, port) < 0)
        return -1;

    if (virXMLPropUInt(node, "bus", 10, VIR_XML_PROP_NONE, &addr->bus) < 0)
        return -1;

    return 0;
}

int
virDomainDeviceSpaprVioAddressParseXML(xmlNodePtr node,
                                      virDomainDeviceSpaprVioAddress *addr)
{
    int reg;

    memset(addr, 0, sizeof(*addr));

    if ((reg = virXMLPropULongLong(node, "reg", 16, VIR_XML_PROP_NONE,
                                   &addr->reg)) < 0)
        return -1;

    if (reg != 0)
        addr->has_reg = true;

    return 0;
}

bool
virDomainDeviceAddressIsValid(virDomainDeviceInfo *info,
                              int type)
{
    if (info->type != type)
        return false;

    switch (info->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        return virPCIDeviceAddressIsValid(&info->addr.pci, false);

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE:
        return true;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
        return true;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
        return virCCWDeviceAddressIsValid(&info->addr.ccw);

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
        return true;

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_ISA:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
        break;
    }

    return false;
}

int
virInterfaceLinkParseXML(xmlNodePtr node,
                         virNetDevIfLink *lnk)
{
    if (virXMLPropEnum(node, "state", virNetDevIfStateTypeFromString,
                       VIR_XML_PROP_NONE, &lnk->state) < 0)
        return -1;

    if (virXMLPropUInt(node, "speed", 10, VIR_XML_PROP_NONE, &lnk->speed) < 0)
        return -1;

    return 0;
}

int
virInterfaceLinkFormat(virBuffer *buf,
                       const virNetDevIfLink *lnk)
{
    if (!lnk->speed && !lnk->state) {
        /* If there's nothing to format, return early. */
        return 0;
    }

    virBufferAddLit(buf, "<link");
    if (lnk->speed)
        virBufferAsprintf(buf, " speed='%u'", lnk->speed);
    if (lnk->state)
        virBufferAsprintf(buf, " state='%s'",
                          virNetDevIfStateTypeToString(lnk->state));
    virBufferAddLit(buf, "/>\n");
    return 0;
}
