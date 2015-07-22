/*
 * device_conf.c: device XML handling
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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

VIR_ENUM_IMPL(virInterfaceState,
              VIR_INTERFACE_STATE_LAST,
              "" /* value of zero means no state */,
              "unknown", "notpresent",
              "down", "lowerlayerdown",
              "testing", "dormant", "up")

VIR_ENUM_IMPL(virNetDevFeature,
              VIR_NET_DEV_FEAT_LAST,
              "rx",
              "tx",
              "sg",
              "tso",
              "gso",
              "gro",
              "lro",
              "rxvlan",
              "txvlan",
              "ntuple",
              "rxhash",
              "rdma",
              "txudptnl")

int virDevicePCIAddressIsValid(virDevicePCIAddressPtr addr,
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
    if (!(addr->domain || addr->bus || addr->slot)) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Invalid PCI address 0000:00:00, at least "
                             "one of domain, bus, or slot must be > 0"));
        return 0;
    }
    return 1;
}


int
virDevicePCIAddressParseXML(xmlNodePtr node,
                            virDevicePCIAddressPtr addr)
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
    if (!virDevicePCIAddressIsValid(addr, true))
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
virDevicePCIAddressFormat(virBufferPtr buf,
                          virDevicePCIAddress addr,
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
virDevicePCIAddressEqual(virDevicePCIAddress *addr1,
                         virDevicePCIAddress *addr2)
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
                         virInterfaceLinkPtr lnk)
{
    int ret = -1;
    char *stateStr, *speedStr;
    int state;

    stateStr = virXMLPropString(node, "state");
    speedStr = virXMLPropString(node, "speed");

    if (stateStr) {
        if ((state = virInterfaceStateTypeFromString(stateStr)) < 0) {
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
                       const virInterfaceLink *lnk)
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
                          virInterfaceStateTypeToString(lnk->state));
    virBufferAddLit(buf, "/>\n");
    return 0;
}
