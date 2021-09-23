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
#include "datatypes.h"

#include "interface_conf.h"

#include "viralloc.h"
#include "virxml.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_INTERFACE

VIR_ENUM_IMPL(virInterface,
              VIR_INTERFACE_TYPE_LAST,
              "ethernet", "bridge", "bond", "vlan",
);

static virInterfaceDef *
virInterfaceDefParseXML(xmlXPathContextPtr ctxt, int parentIfType);

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
virInterfaceDefParseName(virInterfaceDef *def,
                         xmlXPathContextPtr ctxt)
{
    char *tmp;

    tmp = virXPathString("string(./@name)", ctxt);
    if (tmp == NULL) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s",  _("interface has no name"));
        return -1;
    }
    def->name = tmp;
    return 0;
}


static int
virInterfaceDefParseMtu(virInterfaceDef *def,
                        xmlXPathContextPtr ctxt)
{
    unsigned long mtu;
    int ret;

    ret = virXPathULong("string(./mtu/@size)", ctxt, &mtu);
    if ((ret == -2) || ((ret == 0) && (mtu > 100000))) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("interface mtu value is improper"));
        return -1;
    } else if (ret == 0) {
        def->mtu = (unsigned int) mtu;
    }
    return 0;
}


static int
virInterfaceDefParseStartMode(virInterfaceDef *def,
                              xmlXPathContextPtr ctxt)
{
    char *tmp;

    tmp = virXPathString("string(./start/@mode)", ctxt);
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
                       _("unknown interface startmode %s"), tmp);
        VIR_FREE(tmp);
        return -1;
    }
    VIR_FREE(tmp);
    return 0;
}


static int
virInterfaceDefParseBondMode(xmlXPathContextPtr ctxt)
{
    char *tmp;
    int ret = 0;

    tmp = virXPathString("string(./@mode)", ctxt);
    if (tmp == NULL)
        return VIR_INTERFACE_BOND_NONE;
    if (STREQ(tmp, "balance-rr")) {
        ret = VIR_INTERFACE_BOND_BALRR;
    } else if (STREQ(tmp, "active-backup")) {
        ret = VIR_INTERFACE_BOND_ABACKUP;
    } else if (STREQ(tmp, "balance-xor")) {
        ret = VIR_INTERFACE_BOND_BALXOR;
    } else if (STREQ(tmp, "broadcast")) {
        ret = VIR_INTERFACE_BOND_BCAST;
    } else if (STREQ(tmp, "802.3ad")) {
        ret = VIR_INTERFACE_BOND_8023AD;
    } else if (STREQ(tmp, "balance-tlb")) {
        ret = VIR_INTERFACE_BOND_BALTLB;
    } else if (STREQ(tmp, "balance-alb")) {
        ret = VIR_INTERFACE_BOND_BALALB;
    } else {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unknown bonding mode %s"), tmp);
        ret = -1;
    }
    VIR_FREE(tmp);
    return ret;
}


static int
virInterfaceDefParseBondMiiCarrier(xmlXPathContextPtr ctxt)
{
    char *tmp;
    int ret = 0;

    tmp = virXPathString("string(./miimon/@carrier)", ctxt);
    if (tmp == NULL)
        return VIR_INTERFACE_BOND_MII_NONE;
    if (STREQ(tmp, "ioctl")) {
        ret = VIR_INTERFACE_BOND_MII_IOCTL;
    } else if (STREQ(tmp, "netif")) {
        ret = VIR_INTERFACE_BOND_MII_NETIF;
    } else {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unknown mii bonding carrier %s"), tmp);
        ret = -1;
    }
    VIR_FREE(tmp);
    return ret;
}


static int
virInterfaceDefParseBondArpValid(xmlXPathContextPtr ctxt)
{
    char *tmp;
    int ret = 0;

    tmp = virXPathString("string(./arpmon/@validate)", ctxt);
    if (tmp == NULL)
        return VIR_INTERFACE_BOND_ARP_NONE;
    if (STREQ(tmp, "active")) {
        ret = VIR_INTERFACE_BOND_ARP_ACTIVE;
    } else if (STREQ(tmp, "backup")) {
        ret = VIR_INTERFACE_BOND_ARP_BACKUP;
    } else if (STREQ(tmp, "all")) {
        ret = VIR_INTERFACE_BOND_ARP_ALL;
    } else {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unknown arp bonding validate %s"), tmp);
        ret = -1;
    }
    VIR_FREE(tmp);
    return ret;
}


static int
virInterfaceDefParseDhcp(virInterfaceProtocolDef *def,
                         xmlNodePtr dhcp, xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    char *tmp;
    int ret = 0;

    def->dhcp = 1;
    ctxt->node = dhcp;
    def->peerdns = -1;
    /* Not much to do in the current version */
    tmp = virXPathString("string(./@peerdns)", ctxt);
    if (tmp) {
        bool state = false;
        if (virStringParseYesNo(tmp, &state) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown dhcp peerdns value %s"), tmp);
            ret = -1;
        } else {
            def->peerdns = state ? 1 : 0;
        }
        VIR_FREE(tmp);
    }

    return ret;
}


static int
virInterfaceDefParseIP(virInterfaceIPDef *def,
                       xmlXPathContextPtr ctxt)
{
    int ret = 0;
    char *tmp;
    long l;

    tmp = virXPathString("string(./@address)", ctxt);
    def->address = tmp;
    if (tmp != NULL) {
        ret = virXPathLong("string(./@prefix)", ctxt, &l);
        if (ret == 0) {
            def->prefix = (int) l;
        } else if (ret == -2) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("Invalid ip address prefix value"));
            return -1;
        }
    }

    return 0;
}


static int
virInterfaceDefParseProtoIPv4(virInterfaceProtocolDef *def,
                              xmlXPathContextPtr ctxt)
{
    xmlNodePtr dhcp;
    xmlNodePtr *ipNodes = NULL;
    int nipNodes, ret = -1;
    size_t i;
    char *tmp;

    tmp = virXPathString("string(./route[1]/@gateway)", ctxt);
    def->gateway = tmp;

    dhcp = virXPathNode("./dhcp", ctxt);
    if (dhcp != NULL) {
        if (virInterfaceDefParseDhcp(def, dhcp, ctxt) < 0)
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

        virInterfaceIPDef *ip;

        ip = g_new0(virInterfaceIPDef, 1);

        ctxt->node = ipNodes[i];
        if (virInterfaceDefParseIP(ip, ctxt) < 0) {
            virInterfaceIPDefFree(ip);
            goto error;
        }
        def->ips[def->nips++] = ip;
    }

    ret = 0;

 error:
    VIR_FREE(ipNodes);
    return ret;
}


static int
virInterfaceDefParseProtoIPv6(virInterfaceProtocolDef *def,
                              xmlXPathContextPtr ctxt)
{
    xmlNodePtr dhcp, autoconf;
    xmlNodePtr *ipNodes = NULL;
    int nipNodes, ret = -1;
    size_t i;
    char *tmp;

    tmp = virXPathString("string(./route[1]/@gateway)", ctxt);
    def->gateway = tmp;

    autoconf = virXPathNode("./autoconf", ctxt);
    if (autoconf != NULL)
        def->autoconf = 1;

    dhcp = virXPathNode("./dhcp", ctxt);
    if (dhcp != NULL) {
        if (virInterfaceDefParseDhcp(def, dhcp, ctxt) < 0)
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

        virInterfaceIPDef *ip;

        ip = g_new0(virInterfaceIPDef, 1);

        ctxt->node = ipNodes[i];
        if (virInterfaceDefParseIP(ip, ctxt) < 0) {
            virInterfaceIPDefFree(ip);
            goto error;
        }
        def->ips[def->nips++] = ip;
    }

    ret = 0;

 error:
    VIR_FREE(ipNodes);
    return ret;
}


static int
virInterfaceDefParseIfAdressing(virInterfaceDef *def,
                                xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr *protoNodes = NULL;
    int nProtoNodes, pp, ret = -1;
    char *tmp;

    nProtoNodes = virXPathNodeSet("./protocol", ctxt, &protoNodes);
    if (nProtoNodes < 0)
        goto error;

    if (nProtoNodes == 0) {
        /* no protocols is an acceptable outcome */
        return 0;
    }

    def->protos = g_new0(virInterfaceProtocolDef *, nProtoNodes);

    def->nprotos = 0;
    for (pp = 0; pp < nProtoNodes; pp++) {

        virInterfaceProtocolDef *proto;

        proto = g_new0(virInterfaceProtocolDef, 1);

        ctxt->node = protoNodes[pp];
        tmp = virXPathString("string(./@family)", ctxt);
        if (tmp == NULL) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("protocol misses the family attribute"));
            virInterfaceProtocolDefFree(proto);
            goto error;
        }
        proto->family = tmp;
        if (STREQ(tmp, "ipv4")) {
            ret = virInterfaceDefParseProtoIPv4(proto, ctxt);
            if (ret != 0) {
                virInterfaceProtocolDefFree(proto);
                goto error;
            }
        } else if (STREQ(tmp, "ipv6")) {
            ret = virInterfaceDefParseProtoIPv6(proto, ctxt);
            if (ret != 0) {
                virInterfaceProtocolDefFree(proto);
                goto error;
            }
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unsupported protocol family '%s'"), tmp);
            virInterfaceProtocolDefFree(proto);
            goto error;
        }
        def->protos[def->nprotos++] = proto;
    }

    ret = 0;

 error:
    VIR_FREE(protoNodes);
    return ret;

}


static int
virInterfaceDefParseBridge(virInterfaceDef *def,
                           xmlXPathContextPtr ctxt)
{
    xmlNodePtr *interfaces = NULL;
    xmlNodePtr bridge;
    virInterfaceDef *itf;
    char *tmp = NULL;
    int nbItf;
    size_t i;
    int ret = 0;

    bridge = ctxt->node;
    def->data.bridge.stp = -1;
    if ((tmp = virXMLPropString(bridge, "stp"))) {
        if (STREQ(tmp, "on")) {
            def->data.bridge.stp = 1;
        } else if (STREQ(tmp, "off")) {
            def->data.bridge.stp = 0;
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("bridge interface stp should be on or off got %s"),
                           tmp);
            goto error;
        }
    }
    def->data.bridge.delay = virXMLPropString(bridge, "delay");

    nbItf = virXPathNodeSet("./interface", ctxt, &interfaces);
    if (nbItf < 0) {
        ret = -1;
        goto error;
    }
    if (nbItf > 0) {
        def->data.bridge.itf = g_new0(struct _virInterfaceDef *, nbItf);
        def->data.bridge.nbItf = nbItf;

        for (i = 0; i < nbItf; i++) {
            ctxt->node = interfaces[i];
            itf = virInterfaceDefParseXML(ctxt, VIR_INTERFACE_TYPE_BRIDGE);
            if (itf == NULL) {
                ret = -1;
                def->data.bridge.nbItf = i;
                goto error;
            }
            def->data.bridge.itf[i] = itf;
        }
    }

 error:
    VIR_FREE(tmp);
    VIR_FREE(interfaces);
    ctxt->node = bridge;
    return ret;
}


static int
virInterfaceDefParseBondItfs(virInterfaceDef *def,
                             xmlXPathContextPtr ctxt)
{
    xmlNodePtr *interfaces = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    virInterfaceDef *itf;
    int nbItf;
    size_t i;
    int ret = -1;

    nbItf = virXPathNodeSet("./interface", ctxt, &interfaces);
    if (nbItf < 0)
        goto cleanup;

    if (nbItf == 0) {
        ret = 0;
        goto cleanup;
    }

    def->data.bond.itf = g_new0(struct _virInterfaceDef *, nbItf);

    def->data.bond.nbItf = nbItf;

    for (i = 0; i < nbItf; i++) {
        ctxt->node = interfaces[i];
        itf = virInterfaceDefParseXML(ctxt, VIR_INTERFACE_TYPE_BOND);
        if (itf == NULL) {
            def->data.bond.nbItf = i;
            goto cleanup;
        }
        def->data.bond.itf[i] = itf;
    }

    ret = 0;
 cleanup:
    VIR_FREE(interfaces);
    return ret;
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


static virInterfaceDef *
virInterfaceDefParseXML(xmlXPathContextPtr ctxt,
                        int parentIfType)
{
    g_autoptr(virInterfaceDef) def = NULL;
    int type;
    char *tmp;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr lnk;


    /* check @type */
    tmp = virXPathString("string(./@type)", ctxt);
    if (tmp == NULL) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("interface misses the type attribute"));
        return NULL;
    }
    type = virInterfaceTypeFromString(tmp);
    if (type == -1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown interface type %s"), tmp);
        VIR_FREE(tmp);
        return NULL;
    }
    VIR_FREE(tmp);

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
                       _("interface has unsupported type '%s'"),
                       virInterfaceTypeToString(type));
        return NULL;
    }
    def->type = type;

    if (virInterfaceDefParseName(def, ctxt) < 0)
       return NULL;

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
        case VIR_INTERFACE_TYPE_ETHERNET:
            if ((tmp = virXPathString("string(./mac/@address)", ctxt)))
                def->mac = tmp;
            break;
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

    }

    return g_steal_pointer(&def);
}


virInterfaceDef *
virInterfaceDefParseNode(xmlDocPtr xml,
                         xmlNodePtr root)
{
    g_autoptr(xmlXPathContext) ctxt = NULL;

    if (!virXMLNodeNameEqual(root, "interface")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected root element <%s>, "
                         "expecting <interface>"),
                       root->name);
        return NULL;
    }

    if (!(ctxt = virXMLXPathContextNew(xml)))
        return NULL;

    ctxt->node = root;
    return virInterfaceDefParseXML(ctxt, VIR_INTERFACE_TYPE_LAST);
}


static virInterfaceDef *
virInterfaceDefParse(const char *xmlStr,
                     const char *filename,
                     unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    virInterfaceDef *def = NULL;

    if ((xml = virXMLParse(filename, xmlStr, _("(interface_definition)"), "interface.rng",
                           flags & VIR_INTERFACE_DEFINE_VALIDATE))) {
        def = virInterfaceDefParseNode(xml, xmlDocGetRootElement(xml));
    }

    return def;
}


virInterfaceDef *
virInterfaceDefParseString(const char *xmlStr,
                           unsigned int flags)
{
    return virInterfaceDefParse(xmlStr, NULL, flags);
}


virInterfaceDef *
virInterfaceDefParseFile(const char *filename)
{
    return virInterfaceDefParse(NULL, filename, 0);
}


static int
virInterfaceBridgeDefFormat(virBuffer *buf,
                            const virInterfaceDef *def)
{
    size_t i;
    int ret = 0;

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
            ret = -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bridge>\n");
    return ret;
}


static int
virInterfaceBondDefFormat(virBuffer *buf,
                          const virInterfaceDef *def)
{
    size_t i;
    int ret = 0;

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
            ret = -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bond>\n");
    return ret;
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
                       _("unexpected interface type %d"), def->type);
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
            virInterfaceBridgeDefFormat(buf, def);
            break;
        case VIR_INTERFACE_TYPE_BOND:
            virInterfaceBondDefFormat(buf, def);
            break;
        case VIR_INTERFACE_TYPE_VLAN:
            virInterfaceVlanDefFormat(buf, def);
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
