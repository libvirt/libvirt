/*
 * interface_conf.c: interfaces XML handling
 *
 * Copyright (C) 2006-2010, 2013-2015 Red Hat, Inc.
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

#include "interface_conf.h"

#include "virxml.h"
#include "virbuffer.h"

#define VIR_FROM_THIS VIR_FROM_INTERFACE

VIR_ENUM_IMPL(virInterface,
              VIR_INTERFACE_TYPE_LAST,
              "ethernet", "bridge", "bond", "vlan",
);

static int
virInterfaceDefDevFormat(virBuffer *buf, const virInterfaceDef *def,
                         virInterfaceType parentIfType);

static void
virInterfaceIPDefFree(virInterfaceIPDef *def)
{
    if (def == NULL)
        return;
    g_free(def->address);
    g_free(def);
}


static void
virInterfaceProtocolDefFree(virInterfaceProtocolDef *def)
{
    size_t i;

    if (def == NULL)
        return;
    for (i = 0; i < def->nips; i++)
        virInterfaceIPDefFree(def->ips[i]);
    g_free(def->ips);
    g_free(def->family);
    g_free(def->gateway);
    g_free(def);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virInterfaceProtocolDef, virInterfaceProtocolDefFree);


void
virInterfaceDefFree(virInterfaceDef *def)
{
    size_t i;
    int pp;

    if (def == NULL)
        return;

    g_free(def->name);
    g_free(def->mac);

    switch (def->type) {
        case VIR_INTERFACE_TYPE_BRIDGE:
            g_free(def->data.bridge.delay);
            for (i = 0; i < def->data.bridge.nbItf; i++) {
                if (def->data.bridge.itf[i] == NULL)
                    break; /* to cope with half parsed data on errors */
                virInterfaceDefFree(def->data.bridge.itf[i]);
            }
            g_free(def->data.bridge.itf);
            break;
        case VIR_INTERFACE_TYPE_BOND:
            g_free(def->data.bond.target);
            for (i = 0; i < def->data.bond.nbItf; i++) {
                if (def->data.bond.itf[i] == NULL)
                    break; /* to cope with half parsed data on errors */
                virInterfaceDefFree(def->data.bond.itf[i]);
            }
            g_free(def->data.bond.itf);
            break;
        case VIR_INTERFACE_TYPE_VLAN:
            g_free(def->data.vlan.tag);
            g_free(def->data.vlan.dev_name);
            break;
    }

    /* free all protos */
    for (pp = 0; pp < def->nprotos; pp++)
        virInterfaceProtocolDefFree(def->protos[pp]);
    g_free(def->protos);
    g_free(def);
}


static int
virInterfaceDefParseMtu(virInterfaceDef *def,
                        xmlXPathContextPtr ctxt)
{
    if (virXPathUInt("string(./mtu/@size)", ctxt, &def->mtu) == -2)
        return -1;

    if (def->mtu > 100000) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("value of the 'size' attribute of 'mtu' element must be at most 100000"));
        return -1;
    }

    return 0;
}


static int
virInterfaceDefParseStartMode(virInterfaceDef *def,
                              xmlXPathContextPtr ctxt)
{
    g_autofree char *tmp = virXPathString("string(./start/@mode)", ctxt);

    if (tmp == NULL) {
        def->startmode = VIR_INTERFACE_START_UNSPECIFIED;
    } else if (STREQ(tmp, "onboot")) {
        def->startmode = VIR_INTERFACE_START_ONBOOT;
    } else if (STREQ(tmp, "hotplug")) {
        def->startmode = VIR_INTERFACE_START_HOTPLUG;
    } else if (STREQ(tmp, "none")) {
        def->startmode = VIR_INTERFACE_START_NONE;
    } else {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unknown interface startmode %1$s"), tmp);
        return -1;
    }
    return 0;
}


static int
virInterfaceDefParseBondMode(xmlXPathContextPtr ctxt)
{
    g_autofree char *tmp = virXPathString("string(./@mode)", ctxt);

    if (tmp == NULL)
        return VIR_INTERFACE_BOND_NONE;
    if (STREQ(tmp, "balance-rr")) {
        return VIR_INTERFACE_BOND_BALRR;
    } else if (STREQ(tmp, "active-backup")) {
        return VIR_INTERFACE_BOND_ABACKUP;
    } else if (STREQ(tmp, "balance-xor")) {
        return VIR_INTERFACE_BOND_BALXOR;
    } else if (STREQ(tmp, "broadcast")) {
        return VIR_INTERFACE_BOND_BCAST;
    } else if (STREQ(tmp, "802.3ad")) {
        return VIR_INTERFACE_BOND_8023AD;
    } else if (STREQ(tmp, "balance-tlb")) {
        return VIR_INTERFACE_BOND_BALTLB;
    } else if (STREQ(tmp, "balance-alb")) {
        return VIR_INTERFACE_BOND_BALALB;
    }

    virReportError(VIR_ERR_XML_ERROR, _("unknown bonding mode %1$s"), tmp);
    return -1;
}


static int
virInterfaceDefParseBondMiiCarrier(xmlXPathContextPtr ctxt)
{
    g_autofree char *tmp = virXPathString("string(./miimon/@carrier)", ctxt);

    if (tmp == NULL)
        return VIR_INTERFACE_BOND_MII_NONE;
    if (STREQ(tmp, "ioctl")) {
        return VIR_INTERFACE_BOND_MII_IOCTL;
    } else if (STREQ(tmp, "netif")) {
        return VIR_INTERFACE_BOND_MII_NETIF;
    }

    virReportError(VIR_ERR_XML_ERROR, _("unknown mii bonding carrier %1$s"), tmp);
    return -1;
}


static int
virInterfaceDefParseBondArpValid(xmlXPathContextPtr ctxt)
{
    g_autofree char *tmp = virXPathString("string(./arpmon/@validate)", ctxt);

    if (tmp == NULL)
        return VIR_INTERFACE_BOND_ARP_NONE;
    if (STREQ(tmp, "active")) {
        return VIR_INTERFACE_BOND_ARP_ACTIVE;
    } else if (STREQ(tmp, "backup")) {
        return VIR_INTERFACE_BOND_ARP_BACKUP;
    } else if (STREQ(tmp, "all")) {
        return VIR_INTERFACE_BOND_ARP_ALL;
    }

    virReportError(VIR_ERR_XML_ERROR, _("unknown arp bonding validate %1$s"), tmp);
    return -1;
}


static int
virInterfaceDefParseDhcp(virInterfaceProtocolDef *def,
                         xmlNodePtr dhcp)
{
    virTristateBool peerdns;

    def->dhcp = 1;
    def->peerdns = -1;

    if (virXMLPropTristateBool(dhcp, "peerdns", VIR_XML_PROP_NONE, &peerdns) < 0)
        return -1;

    if (peerdns != VIR_TRISTATE_BOOL_ABSENT) {
        def->peerdns = peerdns == VIR_TRISTATE_BOOL_YES ? 1 : 0;
    }

    return 0;
}


static int
virInterfaceDefParseIP(virInterfaceIPDef *def,
                       xmlNodePtr node)
{
    if (!(def->address = virXMLPropString(node, "address")))
        return 0;

    if (virXMLPropInt(node, "prefix", 0, VIR_XML_PROP_NONE, &def->prefix, 0) < 0)
        return -1;

    return 0;
}


static int
virInterfaceDefParseProtoIPv4(virInterfaceProtocolDef *def,
                              xmlXPathContextPtr ctxt)
{
    xmlNodePtr dhcp;
    g_autofree xmlNodePtr *ipNodes = NULL;
    int nipNodes;
    size_t i;

    def->gateway = virXPathString("string(./route[1]/@gateway)", ctxt);

    dhcp = virXPathNode("./dhcp", ctxt);
    if (dhcp != NULL) {
        if (virInterfaceDefParseDhcp(def, dhcp) < 0)
            return -1;
    }

    nipNodes = virXPathNodeSet("./ip", ctxt, &ipNodes);
    if (nipNodes < 0)
        return -1;
    if (ipNodes == NULL)
        return 0;

    def->ips = g_new0(virInterfaceIPDef *, nipNodes);

    def->nips = 0;
    for (i = 0; i < nipNodes; i++) {
        virInterfaceIPDef *ip = g_new0(virInterfaceIPDef, 1);

        if (virInterfaceDefParseIP(ip, ipNodes[i]) < 0) {
            virInterfaceIPDefFree(ip);
            return -1;
        }
        def->ips[def->nips++] = ip;
    }

    return 0;
}


static int
virInterfaceDefParseProtoIPv6(virInterfaceProtocolDef *def,
                              xmlXPathContextPtr ctxt)
{
    xmlNodePtr dhcp;
    g_autofree xmlNodePtr *ipNodes = NULL;
    int nipNodes;
    size_t i;

    def->gateway = virXPathString("string(./route[1]/@gateway)", ctxt);

    if (virXPathNode("./autoconf", ctxt) != NULL)
        def->autoconf = 1;

    dhcp = virXPathNode("./dhcp", ctxt);
    if (dhcp != NULL) {
        if (virInterfaceDefParseDhcp(def, dhcp) < 0)
            return -1;
    }

    nipNodes = virXPathNodeSet("./ip", ctxt, &ipNodes);
    if (nipNodes < 0)
        return -1;
    if (ipNodes == NULL)
        return 0;

    def->ips = g_new0(virInterfaceIPDef *, nipNodes);

    def->nips = 0;
    for (i = 0; i < nipNodes; i++) {
        virInterfaceIPDef *ip = g_new0(virInterfaceIPDef, 1);

        if (virInterfaceDefParseIP(ip, ipNodes[i]) < 0) {
            virInterfaceIPDefFree(ip);
            return -1;
        }
        def->ips[def->nips++] = ip;
    }

    return 0;
}


static int
virInterfaceDefParseIfAdressing(virInterfaceDef *def,
                                xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree xmlNodePtr *protoNodes = NULL;
    int nProtoNodes, pp;

    nProtoNodes = virXPathNodeSet("./protocol", ctxt, &protoNodes);
    if (nProtoNodes < 0)
        return -1;

    if (nProtoNodes == 0) {
        /* no protocols is an acceptable outcome */
        return 0;
    }

    def->protos = g_new0(virInterfaceProtocolDef *, nProtoNodes);

    def->nprotos = 0;
    for (pp = 0; pp < nProtoNodes; pp++) {
        g_autoptr(virInterfaceProtocolDef) proto = g_new0(virInterfaceProtocolDef, 1);

        if (!(proto->family = virXMLPropString(protoNodes[pp], "family"))) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("protocol misses the family attribute"));
            return -1;
        }

        ctxt->node = protoNodes[pp];
        if (STREQ(proto->family, "ipv4")) {
            if (virInterfaceDefParseProtoIPv4(proto, ctxt) != 0)
                return -1;
        } else if (STREQ(proto->family, "ipv6")) {
            if (virInterfaceDefParseProtoIPv6(proto, ctxt) != 0)
                return -1;
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unsupported protocol family '%1$s'"),
                           proto->family);
            return -1;
        }
        def->protos[def->nprotos++] = g_steal_pointer(&proto);
    }

    return 0;
}


static int
virInterfaceDefParseBridge(virInterfaceDef *def,
                           xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree xmlNodePtr *interfaces = NULL;
    virInterfaceDef *itf;
    g_autofree char *tmp = NULL;
    int nbItf;
    size_t i;

    def->data.bridge.stp = -1;
    if ((tmp = virXMLPropString(ctxt->node, "stp"))) {
        if (STREQ(tmp, "on")) {
            def->data.bridge.stp = 1;
        } else if (STREQ(tmp, "off")) {
            def->data.bridge.stp = 0;
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("bridge interface stp should be on or off got %1$s"),
                           tmp);
            return 0;
        }
    }
    def->data.bridge.delay = virXMLPropString(ctxt->node, "delay");

    nbItf = virXPathNodeSet("./interface", ctxt, &interfaces);
    if (nbItf < 0) {
        return -1;
    }
    if (nbItf > 0) {
        def->data.bridge.itf = g_new0(struct _virInterfaceDef *, nbItf);
        def->data.bridge.nbItf = nbItf;

        for (i = 0; i < nbItf; i++) {
            ctxt->node = interfaces[i];
            itf = virInterfaceDefParseXML(ctxt, VIR_INTERFACE_TYPE_BRIDGE);
            if (itf == NULL) {
                def->data.bridge.nbItf = i;
                return -1;
            }
            def->data.bridge.itf[i] = itf;
        }
    }

    return 0;
}


static int
virInterfaceDefParseBondItfs(virInterfaceDef *def,
                             xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree xmlNodePtr *interfaces = NULL;
    virInterfaceDef *itf;
    int nbItf;
    size_t i;

    nbItf = virXPathNodeSet("./interface", ctxt, &interfaces);
    if (nbItf < 0)
        return -1;

    if (nbItf == 0) {
        return 0;
    }

    def->data.bond.itf = g_new0(struct _virInterfaceDef *, nbItf);

    def->data.bond.nbItf = nbItf;

    for (i = 0; i < nbItf; i++) {
        ctxt->node = interfaces[i];
        itf = virInterfaceDefParseXML(ctxt, VIR_INTERFACE_TYPE_BOND);
        if (itf == NULL) {
            def->data.bond.nbItf = i;
            return -1;
        }
        def->data.bond.itf[i] = itf;
    }

    return 0;
}


static int
virInterfaceDefParseBond(virInterfaceDef *def,
                         xmlXPathContextPtr ctxt)
{
    int res;

    def->data.bond.mode = virInterfaceDefParseBondMode(ctxt);
    if (def->data.bond.mode < 0)
        return -1;

    if (virInterfaceDefParseBondItfs(def, ctxt) != 0)
        return -1;

    if (virXPathNode("./miimon[1]", ctxt) != NULL) {
        def->data.bond.monit = VIR_INTERFACE_BOND_MONIT_MII;

        res = virXPathInt("string(./miimon/@freq)", ctxt,
                          &def->data.bond.frequency);
        if ((res == -2) || (res == -1)) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("bond interface miimon freq missing or invalid"));
            return -1;
        }

        res = virXPathInt("string(./miimon/@downdelay)", ctxt,
                          &def->data.bond.downdelay);
        if (res == -2) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("bond interface miimon downdelay invalid"));
            return -1;
        }

        res = virXPathInt("string(./miimon/@updelay)", ctxt,
                          &def->data.bond.updelay);
        if (res == -2) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("bond interface miimon updelay invalid"));
            return -1;
        }

        def->data.bond.carrier = virInterfaceDefParseBondMiiCarrier(ctxt);
        if (def->data.bond.carrier < 0)
            return -1;

    } else if (virXPathNode("./arpmon[1]", ctxt) != NULL) {

        def->data.bond.monit = VIR_INTERFACE_BOND_MONIT_ARP;

        res = virXPathInt("string(./arpmon/@interval)", ctxt,
                          &def->data.bond.interval);
        if ((res == -2) || (res == -1)) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("bond interface arpmon interval missing or invalid"));
            return -1;
        }

        def->data.bond.target =
            virXPathString("string(./arpmon/@target)", ctxt);
        if (def->data.bond.target == NULL) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("bond interface arpmon target missing"));
            return -1;
        }

        def->data.bond.validate = virInterfaceDefParseBondArpValid(ctxt);
        if (def->data.bond.validate < 0)
            return -1;
    }

    return 0;
}


static int
virInterfaceDefParseVlan(virInterfaceDef *def,
                         xmlXPathContextPtr ctxt)
{
    def->data.vlan.tag = virXPathString("string(./@tag)", ctxt);
    if (def->data.vlan.tag == NULL) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("vlan interface misses the tag attribute"));
        return -1;
    }

    def->data.vlan.dev_name =
         virXPathString("string(./interface/@name)", ctxt);
    if (def->data.vlan.dev_name == NULL) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("vlan interface misses name attribute"));
        return -1;
    }
    return 0;
}


virInterfaceDef *
virInterfaceDefParseXML(xmlXPathContextPtr ctxt,
                        int parentIfType)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autoptr(virInterfaceDef) def = NULL;
    virInterfaceType type;
    xmlNodePtr lnk;

    if (virXMLPropEnum(ctxt->node, "type", virInterfaceTypeFromString,
                       VIR_XML_PROP_REQUIRED, &type) < 0)
        return NULL;

    def = g_new0(virInterfaceDef, 1);

    if (((parentIfType == VIR_INTERFACE_TYPE_BOND)
         && (type != VIR_INTERFACE_TYPE_ETHERNET))
        || ((parentIfType == VIR_INTERFACE_TYPE_BRIDGE)
            && (type != VIR_INTERFACE_TYPE_ETHERNET)
            && (type != VIR_INTERFACE_TYPE_BOND)
            && (type != VIR_INTERFACE_TYPE_VLAN))
        || (parentIfType == VIR_INTERFACE_TYPE_ETHERNET)
        || (parentIfType == VIR_INTERFACE_TYPE_VLAN))
        {
        virReportError(VIR_ERR_XML_ERROR,
                       _("interface has unsupported type '%1$s'"),
                       virInterfaceTypeToString(type));
        return NULL;
    }
    def->type = type;

    if (!(def->name = virXMLPropString(ctxt->node, "name"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",  _("interface has no name"));
        return NULL;
    }

    if (parentIfType == VIR_INTERFACE_TYPE_LAST) {
        /* only recognize these in toplevel bond interfaces */
        if (virInterfaceDefParseStartMode(def, ctxt) < 0)
            return NULL;
        if (virInterfaceDefParseMtu(def, ctxt) < 0)
            return NULL;
        if (virInterfaceDefParseIfAdressing(def, ctxt) < 0)
            return NULL;
    }

    if (type != VIR_INTERFACE_TYPE_BRIDGE) {
        /* link status makes no sense for a bridge */
        lnk = virXPathNode("./link", ctxt);
        if (lnk && virInterfaceLinkParseXML(lnk, &def->lnk) < 0)
            return NULL;
    }

    switch (type) {
        case VIR_INTERFACE_TYPE_ETHERNET: {
            char *mac = virXPathString("string(./mac/@address)", ctxt);
            if (mac != NULL)
                def->mac = mac;
            break;
        }
        case VIR_INTERFACE_TYPE_BRIDGE: {
            xmlNodePtr bridge;

            if (!(bridge = virXPathNode("./bridge[1]", ctxt))) {
                virReportError(VIR_ERR_XML_ERROR,
                               "%s", _("bridge interface misses the bridge element"));
                return NULL;
            }
            ctxt->node = bridge;
            if (virInterfaceDefParseBridge(def, ctxt) < 0)
                return NULL;
            break;
        }
        case VIR_INTERFACE_TYPE_BOND: {
            xmlNodePtr bond;

            if (!(bond = virXPathNode("./bond[1]", ctxt))) {
                virReportError(VIR_ERR_XML_ERROR,
                               "%s", _("bond interface misses the bond element"));
                return NULL;
            }
            ctxt->node = bond;
            if (virInterfaceDefParseBond(def, ctxt)  < 0)
                return NULL;
            break;
        }
        case VIR_INTERFACE_TYPE_VLAN: {
            xmlNodePtr vlan;

            if (!(vlan = virXPathNode("./vlan[1]", ctxt))) {
                virReportError(VIR_ERR_XML_ERROR,
                               "%s", _("vlan interface misses the vlan element"));
                return NULL;
            }
            ctxt->node = vlan;
            if (virInterfaceDefParseVlan(def, ctxt)  < 0)
                return NULL;
            break;
        }
        case VIR_INTERFACE_TYPE_LAST:
            return NULL;
    }

    return g_steal_pointer(&def);
}


virInterfaceDef *
virInterfaceDefParseString(const char *xmlStr,
                           unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    bool validate = flags & VIR_INTERFACE_DEFINE_VALIDATE;

    if (!(xml = virXMLParse(NULL, xmlStr, _("(interface_definition)"),
                            "interface", &ctxt, "interface.rng", validate)))
        return NULL;

    return virInterfaceDefParseXML(ctxt, VIR_INTERFACE_TYPE_LAST);
}


static int
virInterfaceBridgeDefFormat(virBuffer *buf,
                            const virInterfaceDef *def)
{
    size_t i;

    virBufferAddLit(buf, "<bridge");
    if (def->data.bridge.stp == 1)
        virBufferAddLit(buf, " stp='on'");
    else if (def->data.bridge.stp == 0)
        virBufferAddLit(buf, " stp='off'");
    if (def->data.bridge.delay != NULL)
        virBufferAsprintf(buf, " delay='%s'", def->data.bridge.delay);
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < def->data.bridge.nbItf; i++) {
        if (virInterfaceDefDevFormat(buf, def->data.bridge.itf[i],
                                     VIR_INTERFACE_TYPE_BRIDGE) < 0)
            return -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bridge>\n");
    return 0;
}


static int
virInterfaceBondDefFormat(virBuffer *buf,
                          const virInterfaceDef *def)
{
    size_t i;

    virBufferAddLit(buf, "<bond");
    if (def->data.bond.mode == VIR_INTERFACE_BOND_BALRR)
        virBufferAddLit(buf, " mode='balance-rr'");
    else if (def->data.bond.mode == VIR_INTERFACE_BOND_ABACKUP)
        virBufferAddLit(buf, " mode='active-backup'");
    else if (def->data.bond.mode == VIR_INTERFACE_BOND_BALXOR)
        virBufferAddLit(buf, " mode='balance-xor'");
    else if (def->data.bond.mode == VIR_INTERFACE_BOND_BCAST)
        virBufferAddLit(buf, " mode='broadcast'");
    else if (def->data.bond.mode == VIR_INTERFACE_BOND_8023AD)
        virBufferAddLit(buf, " mode='802.3ad'");
    else if (def->data.bond.mode == VIR_INTERFACE_BOND_BALTLB)
        virBufferAddLit(buf, " mode='balance-tlb'");
    else if (def->data.bond.mode == VIR_INTERFACE_BOND_BALALB)
        virBufferAddLit(buf, " mode='balance-alb'");
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    if (def->data.bond.monit == VIR_INTERFACE_BOND_MONIT_MII) {
        virBufferAsprintf(buf, "<miimon freq='%d'",
                          def->data.bond.frequency);
        if (def->data.bond.downdelay > 0)
            virBufferAsprintf(buf, " downdelay='%d'", def->data.bond.downdelay);
        if (def->data.bond.updelay > 0)
            virBufferAsprintf(buf, " updelay='%d'", def->data.bond.updelay);
        if (def->data.bond.carrier == VIR_INTERFACE_BOND_MII_IOCTL)
            virBufferAddLit(buf, " carrier='ioctl'");
        else if (def->data.bond.carrier == VIR_INTERFACE_BOND_MII_NETIF)
            virBufferAddLit(buf, " carrier='netif'");
        virBufferAddLit(buf, "/>\n");
    } else if (def->data.bond.monit == VIR_INTERFACE_BOND_MONIT_ARP) {
        if (def->data.bond.target == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("bond arp monitoring has no target"));
            return -1;
        }
        virBufferAsprintf(buf, "<arpmon interval='%d' target='%s'",
                          def->data.bond.interval, def->data.bond.target);
        if (def->data.bond.validate == VIR_INTERFACE_BOND_ARP_ACTIVE)
            virBufferAddLit(buf, " validate='active'");
        else if (def->data.bond.validate == VIR_INTERFACE_BOND_ARP_BACKUP)
            virBufferAddLit(buf, " validate='backup'");
        else if (def->data.bond.validate == VIR_INTERFACE_BOND_ARP_ALL)
            virBufferAddLit(buf, " validate='all'");
        virBufferAddLit(buf, "/>\n");
    }
    for (i = 0; i < def->data.bond.nbItf; i++) {
        if (virInterfaceDefDevFormat(buf, def->data.bond.itf[i],
                                     VIR_INTERFACE_TYPE_BOND) < 0)
            return -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bond>\n");
    return 0;
}


static int
virInterfaceVlanDefFormat(virBuffer *buf,
                          const virInterfaceDef *def)
{
    if (def->data.vlan.tag == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("vlan misses the tag name"));
        return -1;
    }

    virBufferAsprintf(buf, "<vlan tag='%s'", def->data.vlan.tag);
    if (def->data.vlan.dev_name != NULL) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<interface name='%s'/>\n",
                          def->data.vlan.dev_name);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</vlan>\n");
    } else {
        virBufferAddLit(buf, "/>\n");
    }
    return 0;
}


static int
virInterfaceProtocolDefFormat(virBuffer *buf,
                              const virInterfaceDef *def)
{
    size_t i, j;

    for (i = 0; i < def->nprotos; i++) {

        virBufferAsprintf(buf, "<protocol family='%s'>\n",
                          def->protos[i]->family);
        virBufferAdjustIndent(buf, 2);

        if (def->protos[i]->autoconf)
            virBufferAddLit(buf, "<autoconf/>\n");
        if (def->protos[i]->dhcp) {
            if (def->protos[i]->peerdns == 0)
                virBufferAddLit(buf, "<dhcp peerdns='no'/>\n");
            else if (def->protos[i]->peerdns == 1)
                virBufferAddLit(buf, "<dhcp peerdns='yes'/>\n");
            else
                virBufferAddLit(buf, "<dhcp/>\n");
        }

        for (j = 0; j < def->protos[i]->nips; j++) {
            if (def->protos[i]->ips[j]->address != NULL) {

                virBufferAsprintf(buf, "<ip address='%s'",
                                  def->protos[i]->ips[j]->address);
                if (def->protos[i]->ips[j]->prefix != 0) {
                    virBufferAsprintf(buf, " prefix='%d'",
                                      def->protos[i]->ips[j]->prefix);
                }
                virBufferAddLit(buf, "/>\n");
            }
        }
        if (def->protos[i]->gateway != NULL) {
            virBufferAsprintf(buf, "<route gateway='%s'/>\n",
                              def->protos[i]->gateway);
        }

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</protocol>\n");
    }
    return 0;
}


static int
virInterfaceStartmodeDefFormat(virBuffer *buf,
                               virInterfaceStartMode startmode)
{
    const char *mode;
    switch (startmode) {
        case VIR_INTERFACE_START_UNSPECIFIED:
            return 0;
        case VIR_INTERFACE_START_NONE:
            mode = "none";
            break;
        case VIR_INTERFACE_START_ONBOOT:
            mode = "onboot";
            break;
        case VIR_INTERFACE_START_HOTPLUG:
            mode = "hotplug";
            break;
        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("virInterfaceDefFormat unknown startmode"));
            return -1;
    }
    virBufferAsprintf(buf, "<start mode='%s'/>\n", mode);
    return 0;
}


static int
virInterfaceDefDevFormat(virBuffer *buf,
                         const virInterfaceDef *def,
                         virInterfaceType parentIfType)
{
    const char *type = NULL;

    if (def == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("virInterfaceDefFormat NULL def"));
        return -1;
    }

    if ((def->name == NULL) && (def->type != VIR_INTERFACE_TYPE_VLAN)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("virInterfaceDefFormat missing interface name"));
        return -1;
    }

    if (!(type = virInterfaceTypeToString(def->type))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected interface type %1$d"), def->type);
        return -1;
    }

    virBufferAsprintf(buf, "<interface type='%s' ", type);
    if (def->name != NULL)
        virBufferEscapeString(buf, "name='%s'", def->name);
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    if (parentIfType == VIR_INTERFACE_TYPE_LAST) {
        /* these elements are only valid on top-level interfaces - IP
         * address info ("protocol") only makes sense for the
         * top-level, and subordinate interfaces inherit the toplevel
         * setting for mtu and start mode, which cannot be overridden.
         */
        virInterfaceStartmodeDefFormat(buf, def->startmode);
        if (def->mtu)
            virBufferAsprintf(buf, "<mtu size='%d'/>\n", def->mtu);
        virInterfaceProtocolDefFormat(buf, def);
    }

    if (def->type != VIR_INTERFACE_TYPE_BRIDGE)
        virInterfaceLinkFormat(buf, &def->lnk);
    switch (def->type) {
        case VIR_INTERFACE_TYPE_ETHERNET:
            if (def->mac)
                virBufferAsprintf(buf, "<mac address='%s'/>\n", def->mac);
            break;
        case VIR_INTERFACE_TYPE_BRIDGE:
            if (virInterfaceBridgeDefFormat(buf, def) < 0)
                return -1;
            break;
        case VIR_INTERFACE_TYPE_BOND:
            if (virInterfaceBondDefFormat(buf, def) < 0)
                return -1;
            break;
        case VIR_INTERFACE_TYPE_VLAN:
            if (virInterfaceVlanDefFormat(buf, def) < 0)
                return -1;
            break;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</interface>\n");

    return 0;
}


char *
virInterfaceDefFormat(const virInterfaceDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (virInterfaceDefDevFormat(&buf, def, VIR_INTERFACE_TYPE_LAST) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}
