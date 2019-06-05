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
#include "datatypes.h"
#include "viralloc.h"
#include "virxml.h"
#include "viruuid.h"
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
);

static int
virZPCIDeviceAddressParseXML(xmlNodePtr node,
                             virPCIDeviceAddressPtr addr)
{
    virZPCIDeviceAddress def = { 0 };
    char *uid;
    char *fid;
    int ret = -1;

    uid = virXMLPropString(node, "uid");
    fid = virXMLPropString(node, "fid");

    if (uid &&
        virStrToLong_uip(uid, NULL, 0, &def.uid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'uid' attribute"));
        goto cleanup;
    }

    if (fid &&
        virStrToLong_uip(fid, NULL, 0, &def.fid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'fid' attribute"));
        goto cleanup;
    }

    if (!virZPCIDeviceAddressIsEmpty(&def) &&
        !virZPCIDeviceAddressIsValid(&def))
        goto cleanup;

    addr->zpci = def;
    ret = 0;

 cleanup:
    VIR_FREE(uid);
    VIR_FREE(fid);
    return ret;
}

void
virDomainDeviceInfoClear(virDomainDeviceInfoPtr info)
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
virDomainDeviceInfoFree(virDomainDeviceInfoPtr info)
{
    if (info) {
        virDomainDeviceInfoClear(info);
        VIR_FREE(info);
    }
}

bool
virDomainDeviceInfoAddressIsEqual(const virDomainDeviceInfo *a,
                                  const virDomainDeviceInfo *b)
{
    if (a->type != b->type)
        return false;

    switch ((virDomainDeviceAddressType) a->type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_LAST:
    /* address types below don't have any specific data */
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_MMIO:
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390:
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
        if (memcmp(&a->addr.drive, &b->addr.drive, sizeof(a->addr.drive)))
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
           virZPCIDeviceAddressIsEmpty(&info->addr.pci.zpci);
}

bool
virDeviceInfoPCIAddressExtensionIsPresent(const virDomainDeviceInfo *info)
{
    return (info->addr.pci.extFlags & VIR_PCI_ADDRESS_EXTENSION_ZPCI) &&
           !virZPCIDeviceAddressIsEmpty(&info->addr.pci.zpci);
}


int
virPCIDeviceAddressParseXML(xmlNodePtr node,
                            virPCIDeviceAddressPtr addr)
{
    char *domain, *slot, *bus, *function, *multi;
    xmlNodePtr cur;
    xmlNodePtr zpci = NULL;
    int ret = -1;

    memset(addr, 0, sizeof(*addr));

    domain   = virXMLPropString(node, "domain");
    bus      = virXMLPropString(node, "bus");
    slot     = virXMLPropString(node, "slot");
    function = virXMLPropString(node, "function");
    multi    = virXMLPropString(node, "multifunction");

    if (domain &&
        virStrToLong_uip(domain, NULL, 0, &addr->domain) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'domain' attribute"));
        goto cleanup;
    }

    if (bus &&
        virStrToLong_uip(bus, NULL, 0, &addr->bus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'bus' attribute"));
        goto cleanup;
    }

    if (slot &&
        virStrToLong_uip(slot, NULL, 0, &addr->slot) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'slot' attribute"));
        goto cleanup;
    }

    if (function &&
        virStrToLong_uip(function, NULL, 0, &addr->function) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'function' attribute"));
        goto cleanup;
    }

    if (multi &&
        ((addr->multi = virTristateSwitchTypeFromString(multi)) <= 0)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unknown value '%s' for <address> 'multifunction' attribute"),
                       multi);
        goto cleanup;

    }
    if (!virPCIDeviceAddressIsEmpty(addr) && !virPCIDeviceAddressIsValid(addr, true))
        goto cleanup;

    cur = node->children;
    while (cur) {
        if (cur->type == XML_ELEMENT_NODE &&
            virXMLNodeNameEqual(cur, "zpci")) {
            zpci = cur;
        }
        cur = cur->next;
    }

    if (zpci && virZPCIDeviceAddressParseXML(zpci, addr) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(domain);
    VIR_FREE(bus);
    VIR_FREE(slot);
    VIR_FREE(function);
    VIR_FREE(multi);
    return ret;
}

void
virPCIDeviceAddressFormat(virBufferPtr buf,
                          virPCIDeviceAddress addr,
                          bool includeTypeInAddr)
{
    virBufferAsprintf(buf, "<address %sdomain='0x%.4x' bus='0x%.2x' "
                      "slot='0x%.2x' function='0x%.1x'/>\n",
                      includeTypeInAddr ? "type='pci' " : "",
                      addr.domain,
                      addr.bus,
                      addr.slot,
                      addr.function);
}

bool
virDomainDeviceCCWAddressIsValid(virDomainDeviceCCWAddressPtr addr)
{
    return addr->cssid <= VIR_DOMAIN_DEVICE_CCW_MAX_CSSID &&
           addr->ssid <= VIR_DOMAIN_DEVICE_CCW_MAX_SSID &&
           addr->devno <= VIR_DOMAIN_DEVICE_CCW_MAX_DEVNO;
}

int
virDomainDeviceCCWAddressParseXML(xmlNodePtr node,
                                  virDomainDeviceCCWAddressPtr addr)
{
    int   ret = -1;
    char *cssid;
    char *ssid;
    char *devno;

    memset(addr, 0, sizeof(*addr));

    cssid = virXMLPropString(node, "cssid");
    ssid = virXMLPropString(node, "ssid");
    devno = virXMLPropString(node, "devno");

    if (cssid && ssid && devno) {
        if (cssid &&
            virStrToLong_uip(cssid, NULL, 0, &addr->cssid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse <address> 'cssid' attribute"));
            goto cleanup;
        }
        if (ssid &&
            virStrToLong_uip(ssid, NULL, 0, &addr->ssid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse <address> 'ssid' attribute"));
            goto cleanup;
        }
        if (devno &&
            virStrToLong_uip(devno, NULL, 0, &addr->devno) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse <address> 'devno' attribute"));
            goto cleanup;
        }
        if (!virDomainDeviceCCWAddressIsValid(addr)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid specification for virtio ccw"
                             " address: cssid='%s' ssid='%s' devno='%s'"),
                           cssid, ssid, devno);
            goto cleanup;
        }
        addr->assigned = true;
    } else if (cssid || ssid || devno) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Invalid partial specification for virtio ccw"
                         " address"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cssid);
    VIR_FREE(ssid);
    VIR_FREE(devno);
    return ret;
}

int
virDomainDeviceDriveAddressParseXML(xmlNodePtr node,
                                    virDomainDeviceDriveAddressPtr addr)
{
    char *bus, *unit, *controller, *target;
    int ret = -1;

    memset(addr, 0, sizeof(*addr));

    controller = virXMLPropString(node, "controller");
    bus = virXMLPropString(node, "bus");
    target = virXMLPropString(node, "target");
    unit = virXMLPropString(node, "unit");

    if (controller &&
        virStrToLong_uip(controller, NULL, 10, &addr->controller) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'controller' attribute"));
        goto cleanup;
    }

    if (bus &&
        virStrToLong_uip(bus, NULL, 10, &addr->bus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'bus' attribute"));
        goto cleanup;
    }

    if (target &&
        virStrToLong_uip(target, NULL, 10, &addr->target) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'target' attribute"));
        goto cleanup;
    }

    if (unit &&
        virStrToLong_uip(unit, NULL, 10, &addr->unit) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'unit' attribute"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(controller);
    VIR_FREE(bus);
    VIR_FREE(target);
    VIR_FREE(unit);
    return ret;
}

int
virDomainDeviceVirtioSerialAddressParseXML(xmlNodePtr node,
                                           virDomainDeviceVirtioSerialAddressPtr addr)
{
    char *controller, *bus, *port;
    int ret = -1;

    memset(addr, 0, sizeof(*addr));

    controller = virXMLPropString(node, "controller");
    bus = virXMLPropString(node, "bus");
    port = virXMLPropString(node, "port");

    if (controller &&
        virStrToLong_uip(controller, NULL, 10, &addr->controller) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'controller' attribute"));
        goto cleanup;
    }

    if (bus &&
        virStrToLong_uip(bus, NULL, 10, &addr->bus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'bus' attribute"));
        goto cleanup;
    }

    if (port &&
        virStrToLong_uip(port, NULL, 10, &addr->port) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'port' attribute"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(controller);
    VIR_FREE(bus);
    VIR_FREE(port);
    return ret;
}

int
virDomainDeviceCcidAddressParseXML(xmlNodePtr node,
                                   virDomainDeviceCcidAddressPtr addr)
{
    char *controller, *slot;
    int ret = -1;

    memset(addr, 0, sizeof(*addr));

    controller = virXMLPropString(node, "controller");
    slot = virXMLPropString(node, "slot");

    if (controller &&
        virStrToLong_uip(controller, NULL, 10, &addr->controller) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'controller' attribute"));
        goto cleanup;
    }

    if (slot &&
        virStrToLong_uip(slot, NULL, 10, &addr->slot) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'slot' attribute"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(controller);
    VIR_FREE(slot);
    return ret;
}

static int
virDomainDeviceUSBAddressParsePort(virDomainDeviceUSBAddressPtr addr,
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
                                  virDomainDeviceUSBAddressPtr addr)
{
    char *port, *bus;
    int ret = -1;

    memset(addr, 0, sizeof(*addr));

    port = virXMLPropString(node, "port");
    bus = virXMLPropString(node, "bus");

    if (port && virDomainDeviceUSBAddressParsePort(addr, port) < 0)
        goto cleanup;

    if (bus &&
        virStrToLong_uip(bus, NULL, 10, &addr->bus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot parse <address> 'bus' attribute"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(bus);
    VIR_FREE(port);
    return ret;
}

int
virDomainDeviceSpaprVioAddressParseXML(xmlNodePtr node,
                                      virDomainDeviceSpaprVioAddressPtr addr)
{
    char *reg;
    int ret;

    memset(addr, 0, sizeof(*addr));

    reg = virXMLPropString(node, "reg");
    if (reg) {
        if (virStrToLong_ull(reg, NULL, 16, &addr->reg) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse <address> 'reg' attribute"));
            ret = -1;
            goto cleanup;
        }

        addr->has_reg = true;
    }

    ret = 0;
 cleanup:
    VIR_FREE(reg);
    return ret;
}

bool
virDomainDeviceAddressIsValid(virDomainDeviceInfoPtr info,
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
        return virDomainDeviceCCWAddressIsValid(&info->addr.ccw);

    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB:
        return true;
    }

    return false;
}

int
virInterfaceLinkParseXML(xmlNodePtr node,
                         virNetDevIfLinkPtr lnk)
{
    int ret = -1;
    char *stateStr, *speedStr;
    int state;

    stateStr = virXMLPropString(node, "state");
    speedStr = virXMLPropString(node, "speed");

    if (stateStr) {
        if ((state = virNetDevIfStateTypeFromString(stateStr)) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown link state: %s"),
                           stateStr);
            goto cleanup;
        }
        lnk->state = state;
    }

    if (speedStr &&
        virStrToLong_ui(speedStr, NULL, 10, &lnk->speed) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unable to parse link speed: %s"),
                       speedStr);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(stateStr);
    VIR_FREE(speedStr);
    return ret;
}

int
virInterfaceLinkFormat(virBufferPtr buf,
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
