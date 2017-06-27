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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>
#include "virerror.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virxml.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "device_conf.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_DEVICE

int
virDomainDeviceInfoCopy(virDomainDeviceInfoPtr dst,
                        virDomainDeviceInfoPtr src)
{
    /* Assume that dst is already cleared */

    /* first a shallow copy of *everything* */
    *dst = *src;

    /* then copy whatever's left */
    dst->alias = NULL;
    dst->romfile = NULL;
    dst->loadparm = NULL;

    if (VIR_STRDUP(dst->alias, src->alias) < 0 ||
        VIR_STRDUP(dst->romfile, src->romfile) < 0 ||
        VIR_STRDUP(dst->loadparm, src->loadparm) < 0)
        return -1;
    return 0;
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

int virPCIDeviceAddressIsValid(virPCIDeviceAddressPtr addr,
                               bool report)
{
    if (addr->domain > 0xFFFF) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid PCI address domain='0x%x', "
                             "must be <= 0xFFFF"),
                           addr->domain);
        return 0;
    }
    if (addr->bus > 0xFF) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid PCI address bus='0x%x', "
                             "must be <= 0xFF"),
                           addr->bus);
        return 0;
    }
    if (addr->slot > 0x1F) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid PCI address slot='0x%x', "
                             "must be <= 0x1F"),
                           addr->slot);
        return 0;
    }
    if (addr->function > 7) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid PCI address function=0x%x, "
                             "must be <= 7"),
                           addr->function);
        return 0;
    }
    if (virPCIDeviceAddressIsEmpty(addr)) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Invalid PCI address 0000:00:00, at least "
                             "one of domain, bus, or slot must be > 0"));
        return 0;
    }
    return 1;
}


int
virPCIDeviceAddressParseXML(xmlNodePtr node,
                            virPCIDeviceAddressPtr addr)
{
    char *domain, *slot, *bus, *function, *multi;
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

    ret = 0;

 cleanup:
    VIR_FREE(domain);
    VIR_FREE(bus);
    VIR_FREE(slot);
    VIR_FREE(function);
    VIR_FREE(multi);
    return ret;
}

int
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
    return 0;
}

bool
virPCIDeviceAddressEqual(virPCIDeviceAddress *addr1,
                         virPCIDeviceAddress *addr2)
{
    if (addr1->domain == addr2->domain &&
        addr1->bus == addr2->bus &&
        addr1->slot == addr2->slot &&
        addr1->function == addr2->function) {
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
