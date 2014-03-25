/*
 * interface_conf.c: interfaces XML handling
 *
 * Copyright (C) 2006-2010, 2013, 2014 Red Hat, Inc.
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
 * Author: Daniel Veillard <veillard@redhat.com>
 *         Laine Stump <laine@redhat.com>
 */

#include <config.h>
#include "virerror.h"
#include "datatypes.h"

#include "interface_conf.h"

#include "viralloc.h"
#include "virxml.h"
#include "viruuid.h"
#include "virbuffer.h"

#define VIR_FROM_THIS VIR_FROM_INTERFACE

VIR_ENUM_IMPL(virInterface,
              VIR_INTERFACE_TYPE_LAST,
              "ethernet", "bridge", "bond", "vlan")

static virInterfaceDefPtr
virInterfaceDefParseXML(xmlXPathContextPtr ctxt, int parentIfType);
static int
virInterfaceDefDevFormat(virBufferPtr buf, const virInterfaceDef *def);

static
void virInterfaceIpDefFree(virInterfaceIpDefPtr def)
{
    if (def == NULL)
        return;
    VIR_FREE(def->address);
    VIR_FREE(def);
}

static
void virInterfaceProtocolDefFree(virInterfaceProtocolDefPtr def)
{
    size_t i;

    if (def == NULL)
        return;
    for (i = 0; i < def->nips; i++) {
        virInterfaceIpDefFree(def->ips[i]);
    }
    VIR_FREE(def->ips);
    VIR_FREE(def->family);
    VIR_FREE(def->gateway);
    VIR_FREE(def);
}

void virInterfaceDefFree(virInterfaceDefPtr def)
{
    size_t i;
    int pp;

    if (def == NULL)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->mac);

    switch (def->type) {
        case VIR_INTERFACE_TYPE_BRIDGE:
            VIR_FREE(def->data.bridge.delay);
            for (i = 0; i < def->data.bridge.nbItf; i++) {
                if (def->data.bridge.itf[i] == NULL)
                    break; /* to cope with half parsed data on errors */
                virInterfaceDefFree(def->data.bridge.itf[i]);
            }
            VIR_FREE(def->data.bridge.itf);
            break;
        case VIR_INTERFACE_TYPE_BOND:
            VIR_FREE(def->data.bond.target);
            for (i = 0; i < def->data.bond.nbItf; i++) {
                if (def->data.bond.itf[i] == NULL)
                    break; /* to cope with half parsed data on errors */
                virInterfaceDefFree(def->data.bond.itf[i]);
            }
            VIR_FREE(def->data.bond.itf);
            break;
        case VIR_INTERFACE_TYPE_VLAN:
            VIR_FREE(def->data.vlan.tag);
            VIR_FREE(def->data.vlan.devname);
            break;
    }

    /* free all protos */
    for (pp = 0; pp < def->nprotos; pp++) {
        virInterfaceProtocolDefFree(def->protos[pp]);
    }
    VIR_FREE(def->protos);
    VIR_FREE(def);
}

static int
virInterfaceDefParseName(virInterfaceDefPtr def,
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
virInterfaceDefParseMtu(virInterfaceDefPtr def,
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
virInterfaceDefParseStartMode(virInterfaceDefPtr def,
                              xmlXPathContextPtr ctxt)
{
    char *tmp;

    tmp = virXPathString("string(./start/@mode)", ctxt);
    if (tmp == NULL)
        def->startmode = VIR_INTERFACE_START_UNSPECIFIED;
    else if (STREQ(tmp, "onboot"))
        def->startmode = VIR_INTERFACE_START_ONBOOT;
    else if (STREQ(tmp, "hotplug"))
        def->startmode = VIR_INTERFACE_START_HOTPLUG;
    else if (STREQ(tmp, "none"))
        def->startmode = VIR_INTERFACE_START_NONE;
    else {
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
    if (STREQ(tmp, "balance-rr"))
        ret = VIR_INTERFACE_BOND_BALRR;
    else if (STREQ(tmp, "active-backup"))
        ret = VIR_INTERFACE_BOND_ABACKUP;
    else if (STREQ(tmp, "balance-xor"))
        ret = VIR_INTERFACE_BOND_BALXOR;
    else if (STREQ(tmp, "broadcast"))
        ret = VIR_INTERFACE_BOND_BCAST;
    else if (STREQ(tmp, "802.3ad"))
        ret = VIR_INTERFACE_BOND_8023AD;
    else if (STREQ(tmp, "balance-tlb"))
        ret = VIR_INTERFACE_BOND_BALTLB;
    else if (STREQ(tmp, "balance-alb"))
        ret = VIR_INTERFACE_BOND_BALALB;
    else {
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
    if (STREQ(tmp, "ioctl"))
        ret = VIR_INTERFACE_BOND_MII_IOCTL;
    else if (STREQ(tmp, "netif"))
        ret = VIR_INTERFACE_BOND_MII_NETIF;
    else {
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
    if (STREQ(tmp, "active"))
        ret = VIR_INTERFACE_BOND_ARP_ACTIVE;
    else if (STREQ(tmp, "backup"))
        ret = VIR_INTERFACE_BOND_ARP_BACKUP;
    else if (STREQ(tmp, "all"))
        ret = VIR_INTERFACE_BOND_ARP_ALL;
    else {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unknown arp bonding validate %s"), tmp);
        ret = -1;
    }
    VIR_FREE(tmp);
    return ret;
}

static int
virInterfaceDefParseDhcp(virInterfaceProtocolDefPtr def,
                         xmlNodePtr dhcp, xmlXPathContextPtr ctxt)
{
    xmlNodePtr save;
    char *tmp;
    int ret = 0;

    def->dhcp = 1;
    save = ctxt->node;
    ctxt->node = dhcp;
    /* Not much to do in the current version */
    tmp = virXPathString("string(./@peerdns)", ctxt);
    if (tmp) {
        if (STREQ(tmp, "yes"))
            def->peerdns = 1;
        else if (STREQ(tmp, "no"))
            def->peerdns = 0;
        else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown dhcp peerdns value %s"), tmp);
            ret = -1;
        }
        VIR_FREE(tmp);
    } else
        def->peerdns = -1;

    ctxt->node = save;
    return ret;
}

static int
virInterfaceDefParseIp(virInterfaceIpDefPtr def,
                       xmlXPathContextPtr ctxt)
{
    int ret = 0;
    char *tmp;
    long l;

    tmp = virXPathString("string(./@address)", ctxt);
    def->address = tmp;
    if (tmp != NULL) {
        ret = virXPathLong("string(./@prefix)", ctxt, &l);
        if (ret == 0)
            def->prefix = (int) l;
        else if (ret == -2) {
            virReportError(VIR_ERR_XML_ERROR,
                           "%s", _("Invalid ip address prefix value"));
            return -1;
        }
    }

    return 0;
}

static int
virInterfaceDefParseProtoIPv4(virInterfaceProtocolDefPtr def,
                              xmlXPathContextPtr ctxt)
{
    xmlNodePtr dhcp;
    xmlNodePtr *ipNodes = NULL;
    int nIpNodes, ret = -1;
    size_t i;
    char *tmp;

    tmp = virXPathString("string(./route[1]/@gateway)", ctxt);
    def->gateway = tmp;

    dhcp = virXPathNode("./dhcp", ctxt);
    if (dhcp != NULL) {
        if (virInterfaceDefParseDhcp(def, dhcp, ctxt) < 0)
            return -1;
    }

    nIpNodes = virXPathNodeSet("./ip", ctxt, &ipNodes);
    if (nIpNodes < 0)
        return -1;
    if (ipNodes == NULL)
        return 0;

    if (VIR_ALLOC_N(def->ips, nIpNodes) < 0)
        goto error;

    def->nips = 0;
    for (i = 0; i < nIpNodes; i++) {

        virInterfaceIpDefPtr ip;

        if (VIR_ALLOC(ip) < 0)
            goto error;

        ctxt->node = ipNodes[i];
        if (virInterfaceDefParseIp(ip, ctxt) < 0) {
            virInterfaceIpDefFree(ip);
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
virInterfaceDefParseProtoIPv6(virInterfaceProtocolDefPtr def,
                              xmlXPathContextPtr ctxt)
{
    xmlNodePtr dhcp, autoconf;
    xmlNodePtr *ipNodes = NULL;
    int nIpNodes, ret = -1;
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

    nIpNodes = virXPathNodeSet("./ip", ctxt, &ipNodes);
    if (nIpNodes < 0)
        return -1;
    if (ipNodes == NULL)
        return 0;

    if (VIR_ALLOC_N(def->ips, nIpNodes) < 0)
        goto error;

    def->nips = 0;
    for (i = 0; i < nIpNodes; i++) {

        virInterfaceIpDefPtr ip;

        if (VIR_ALLOC(ip) < 0)
            goto error;

        ctxt->node = ipNodes[i];
        if (virInterfaceDefParseIp(ip, ctxt) < 0) {
            virInterfaceIpDefFree(ip);
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
virInterfaceDefParseIfAdressing(virInterfaceDefPtr def,
                                xmlXPathContextPtr ctxt)
{
    xmlNodePtr save;
    xmlNodePtr *protoNodes = NULL;
    int nProtoNodes, pp, ret = -1;
    char *tmp;

    save = ctxt->node;

    nProtoNodes = virXPathNodeSet("./protocol", ctxt, &protoNodes);
    if (nProtoNodes < 0)
        goto error;

    if (nProtoNodes == 0) {
        /* no protocols is an acceptable outcome */
        return 0;
    }

    if (VIR_ALLOC_N(def->protos, nProtoNodes) < 0)
        goto error;

    def->nprotos = 0;
    for (pp = 0; pp < nProtoNodes; pp++) {

        virInterfaceProtocolDefPtr proto;

        if (VIR_ALLOC(proto) < 0)
            goto error;

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
    ctxt->node = save;
    return ret;

}

static int
virInterfaceDefParseBridge(virInterfaceDefPtr def,
                           xmlXPathContextPtr ctxt)
{
    xmlNodePtr *interfaces = NULL;
    xmlNodePtr bridge;
    virInterfaceDefPtr itf;
    int nbItf;
    size_t i;
    int ret = 0;

    bridge = ctxt->node;
    nbItf = virXPathNodeSet("./interface", ctxt, &interfaces);
    if (nbItf < 0) {
        ret = -1;
        goto error;
    }
    if (nbItf > 0) {
        if (VIR_ALLOC_N(def->data.bridge.itf, nbItf) < 0) {
            ret = -1;
            goto error;
        }
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
    VIR_FREE(interfaces);
    ctxt->node = bridge;
    return ret;
}

static int
virInterfaceDefParseBondItfs(virInterfaceDefPtr def,
                             xmlXPathContextPtr ctxt)
{
    xmlNodePtr *interfaces = NULL;
    xmlNodePtr bond = ctxt->node;
    virInterfaceDefPtr itf;
    int nbItf;
    size_t i;
    int ret = 0;

    nbItf = virXPathNodeSet("./interface", ctxt, &interfaces);
    if (nbItf < 0) {
        ret = -1;
        goto error;
    }

    if (nbItf == 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("bond has no interfaces"));
        ret = -1;
        goto error;
    }

    if (VIR_ALLOC_N(def->data.bond.itf, nbItf) < 0) {
        ret = -1;
        goto error;
    }
    def->data.bond.nbItf = nbItf;

    for (i = 0; i < nbItf; i++) {
        ctxt->node = interfaces[i];
        itf = virInterfaceDefParseXML(ctxt, VIR_INTERFACE_TYPE_BOND);
        if (itf == NULL) {
            ret = -1;
            def->data.bond.nbItf = i;
            goto error;
        }
        def->data.bond.itf[i] = itf;
    }

 error:
    VIR_FREE(interfaces);
    ctxt->node = bond;
    return ret;
}

static int
virInterfaceDefParseBond(virInterfaceDefPtr def,
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
virInterfaceDefParseVlan(virInterfaceDefPtr def,
                         xmlXPathContextPtr ctxt)
{
    def->data.vlan.tag = virXPathString("string(./@tag)", ctxt);
    if (def->data.vlan.tag == NULL) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("vlan interface misses the tag attribute"));
        return -1;
    }

    def->data.vlan.devname =
         virXPathString("string(./interface/@name)", ctxt);
    if (def->data.vlan.devname == NULL) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("vlan interface misses name attribute"));
        return -1;
    }
    return 0;
}

static virInterfaceDefPtr
virInterfaceDefParseXML(xmlXPathContextPtr ctxt, int parentIfType)
{
    virInterfaceDefPtr def;
    int type;
    char *tmp;
    xmlNodePtr cur = ctxt->node;

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

    if (VIR_ALLOC(def) < 0)
        return NULL;

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
        goto error;
    }
    def->type = type;
    switch (type) {
        case VIR_INTERFACE_TYPE_ETHERNET:
            if (virInterfaceDefParseName(def, ctxt) < 0)
                goto error;
            tmp = virXPathString("string(./mac/@address)", ctxt);
            if (tmp != NULL)
                def->mac = tmp;
            if (parentIfType == VIR_INTERFACE_TYPE_LAST) {
                /* only recognize these in toplevel bond interfaces */
                if (virInterfaceDefParseStartMode(def, ctxt) < 0)
                    goto error;
                if (virInterfaceDefParseMtu(def, ctxt) < 0)
                    goto error;
                if (virInterfaceDefParseIfAdressing(def, ctxt) < 0)
                    goto error;
            }
            break;
        case VIR_INTERFACE_TYPE_BRIDGE: {
            xmlNodePtr bridge;

            if (virInterfaceDefParseName(def, ctxt) < 0)
                goto error;
            if (virInterfaceDefParseStartMode(def, ctxt) < 0)
                goto error;
            if (virInterfaceDefParseMtu(def, ctxt) < 0)
                goto error;
            if (virInterfaceDefParseIfAdressing(def, ctxt) < 0)
                goto error;

            bridge = virXPathNode("./bridge[1]", ctxt);
            if (bridge == NULL) {
                virReportError(VIR_ERR_XML_ERROR,
                               "%s", _("bridge interface misses the bridge element"));
                goto error;
            }
            tmp = virXMLPropString(bridge, "stp");
            def->data.bridge.stp = -1;
            if (tmp != NULL) {
                if (STREQ(tmp, "on")) {
                    def->data.bridge.stp = 1;
                } else if (STREQ(tmp, "off")) {
                    def->data.bridge.stp = 0;
                } else {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("bridge interface stp should be on or off got %s"),
                                   tmp);
                    VIR_FREE(tmp);
                    goto error;
                }
                VIR_FREE(tmp);
            }
            def->data.bridge.delay = virXMLPropString(bridge, "delay");
            ctxt->node = bridge;
            if (virInterfaceDefParseBridge(def, ctxt) < 0)
                goto error;
            break;
        }
        case VIR_INTERFACE_TYPE_BOND: {
            xmlNodePtr bond;

            if (virInterfaceDefParseName(def, ctxt) < 0)
                goto error;
            if (parentIfType == VIR_INTERFACE_TYPE_LAST) {
                /* only recognize these in toplevel bond interfaces */
                if (virInterfaceDefParseStartMode(def, ctxt) < 0)
                    goto error;
                if (virInterfaceDefParseMtu(def, ctxt) < 0)
                    goto error;
                if (virInterfaceDefParseIfAdressing(def, ctxt) < 0)
                    goto error;
            }

            bond = virXPathNode("./bond[1]", ctxt);
            if (bond == NULL) {
                virReportError(VIR_ERR_XML_ERROR,
                               "%s", _("bond interface misses the bond element"));
                goto error;
            }
            ctxt->node = bond;
            if (virInterfaceDefParseBond(def, ctxt)  < 0)
                goto error;
            break;
        }
        case VIR_INTERFACE_TYPE_VLAN: {
            xmlNodePtr vlan;

            tmp = virXPathString("string(./@name)", ctxt);
            if (tmp != NULL)
                def->name = tmp;
            if (virInterfaceDefParseStartMode(def, ctxt) < 0)
                goto error;
            if (virInterfaceDefParseIfAdressing(def, ctxt) < 0)
                goto error;
            vlan = virXPathNode("./vlan[1]", ctxt);
            if (vlan == NULL) {
                virReportError(VIR_ERR_XML_ERROR,
                               "%s", _("vlan interface misses the vlan element"));
                goto error;
            }
            ctxt->node = vlan;
            if (virInterfaceDefParseVlan(def, ctxt)  < 0)
                goto error;
            break;
        }

    }

    ctxt->node = cur;
    return def;

 error:
    ctxt->node = cur;
    virInterfaceDefFree(def);
    return NULL;
}

virInterfaceDefPtr virInterfaceDefParseNode(xmlDocPtr xml,
                                            xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virInterfaceDefPtr def = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "interface")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected root element <%s>, "
                         "expecting <interface>"),
                       root->name);
        return NULL;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    def = virInterfaceDefParseXML(ctxt, VIR_INTERFACE_TYPE_LAST);

 cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}

static virInterfaceDefPtr
virInterfaceDefParse(const char *xmlStr,
                     const char *filename)
{
    xmlDocPtr xml;
    virInterfaceDefPtr def = NULL;

    if ((xml = virXMLParse(filename, xmlStr, _("(interface_definition)")))) {
        def = virInterfaceDefParseNode(xml, xmlDocGetRootElement(xml));
        xmlFreeDoc(xml);
    }

    return def;
}

virInterfaceDefPtr virInterfaceDefParseString(const char *xmlStr)
{
    return virInterfaceDefParse(xmlStr, NULL);
}

virInterfaceDefPtr virInterfaceDefParseFile(const char *filename)
{
    return virInterfaceDefParse(NULL, filename);
}

static int
virInterfaceBridgeDefFormat(virBufferPtr buf, const virInterfaceDef *def)
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
        if (virInterfaceDefDevFormat(buf, def->data.bridge.itf[i]) < 0)
            ret = -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bridge>\n");
    return ret;
}

static int
virInterfaceBondDefFormat(virBufferPtr buf, const virInterfaceDef *def)
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
        if (virInterfaceDefDevFormat(buf, def->data.bond.itf[i]) < 0)
            ret = -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bond>\n");
    return ret;
}

static int
virInterfaceVlanDefFormat(virBufferPtr buf, const virInterfaceDef *def)
{
    if (def->data.vlan.tag == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("vlan misses the tag name"));
        return -1;
    }

    virBufferAsprintf(buf, "<vlan tag='%s'", def->data.vlan.tag);
    if (def->data.vlan.devname != NULL) {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<interface name='%s'/>\n",
                          def->data.vlan.devname);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</vlan>\n");
    } else
        virBufferAddLit(buf, "/>\n");
    return 0;
}

static int
virInterfaceProtocolDefFormat(virBufferPtr buf, const virInterfaceDef *def)
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
virInterfaceStartmodeDefFormat(virBufferPtr buf,
                               enum virInterfaceStartMode startmode)
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
virInterfaceDefDevFormat(virBufferPtr buf, const virInterfaceDef *def)
{
    const char *type = NULL;

    if (def == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("virInterfaceDefFormat NULL def"));
        goto cleanup;
    }

    if ((def->name == NULL) && (def->type != VIR_INTERFACE_TYPE_VLAN)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("virInterfaceDefFormat missing interface name"));
        goto cleanup;
    }

    if (!(type = virInterfaceTypeToString(def->type))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected interface type %d"), def->type);
        goto cleanup;
    }

    virBufferAsprintf(buf, "<interface type='%s' ", type);
    if (def->name != NULL)
        virBufferEscapeString(buf, "name='%s'", def->name);
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    switch (def->type) {
        case VIR_INTERFACE_TYPE_ETHERNET:
            virInterfaceStartmodeDefFormat(buf, def->startmode);
            if (def->mac != NULL)
                virBufferAsprintf(buf, "<mac address='%s'/>\n", def->mac);
            if (def->mtu != 0)
                virBufferAsprintf(buf, "<mtu size='%d'/>\n", def->mtu);
            virInterfaceProtocolDefFormat(buf, def);
            break;
        case VIR_INTERFACE_TYPE_BRIDGE:
            virInterfaceStartmodeDefFormat(buf, def->startmode);
            if (def->mtu != 0)
                virBufferAsprintf(buf, "<mtu size='%d'/>\n", def->mtu);
            virInterfaceProtocolDefFormat(buf, def);
            virInterfaceBridgeDefFormat(buf, def);
            break;
        case VIR_INTERFACE_TYPE_BOND:
            virInterfaceStartmodeDefFormat(buf, def->startmode);
            if (def->mtu != 0)
                virBufferAsprintf(buf, "<mtu size='%d'/>\n", def->mtu);
            virInterfaceProtocolDefFormat(buf, def);
            virInterfaceBondDefFormat(buf, def);
            break;
        case VIR_INTERFACE_TYPE_VLAN:
            virInterfaceStartmodeDefFormat(buf, def->startmode);
            if (def->mac != NULL)
                virBufferAsprintf(buf, "<mac address='%s'/>\n", def->mac);
            if (def->mtu != 0)
                virBufferAsprintf(buf, "<mtu size='%d'/>\n", def->mtu);
            virInterfaceProtocolDefFormat(buf, def);
            virInterfaceVlanDefFormat(buf, def);
            break;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</interface>\n");

    if (virBufferError(buf))
        goto no_memory;
    return 0;
 no_memory:
    virReportOOMError();
 cleanup:
    return -1;
}

char *virInterfaceDefFormat(const virInterfaceDef *def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (virInterfaceDefDevFormat(&buf, def) < 0) {
        virBufferFreeAndReset(&buf);
        return NULL;
    }
    return virBufferContentAndReset(&buf);
}

/* virInterfaceObj manipulation */

void virInterfaceObjLock(virInterfaceObjPtr obj)
{
    virMutexLock(&obj->lock);
}

void virInterfaceObjUnlock(virInterfaceObjPtr obj)
{
    virMutexUnlock(&obj->lock);
}

void virInterfaceObjFree(virInterfaceObjPtr iface)
{
    if (!iface)
        return;

    virInterfaceDefFree(iface->def);
    virMutexDestroy(&iface->lock);
    VIR_FREE(iface);
}

/* virInterfaceObjList manipulation */

int virInterfaceFindByMACString(virInterfaceObjListPtr interfaces,
                                const char *mac,
                                virInterfaceObjPtr *matches, int maxmatches)
{
    size_t i;
    unsigned int matchct = 0;

    for (i = 0; i < interfaces->count; i++) {

        virInterfaceObjLock(interfaces->objs[i]);
        if (STRCASEEQ(interfaces->objs[i]->def->mac, mac)) {
            matchct++;
            if (matchct <= maxmatches) {
                matches[matchct - 1] = interfaces->objs[i];
                /* keep the lock if we're returning object to caller */
                /* it is the caller's responsibility to unlock *all* matches */
                continue;
            }
        }
        virInterfaceObjUnlock(interfaces->objs[i]);

    }
    return matchct;
}

virInterfaceObjPtr virInterfaceFindByName(virInterfaceObjListPtr interfaces,
                                          const char *name)
{
    size_t i;

    for (i = 0; i < interfaces->count; i++) {
        virInterfaceObjLock(interfaces->objs[i]);
        if (STREQ(interfaces->objs[i]->def->name, name))
            return interfaces->objs[i];
        virInterfaceObjUnlock(interfaces->objs[i]);
    }

    return NULL;
}

void virInterfaceObjListFree(virInterfaceObjListPtr interfaces)
{
    size_t i;

    for (i = 0; i < interfaces->count; i++)
        virInterfaceObjFree(interfaces->objs[i]);

    VIR_FREE(interfaces->objs);
    interfaces->count = 0;
}

int virInterfaceObjListClone(virInterfaceObjListPtr src,
                             virInterfaceObjListPtr dest)
{
    int ret = -1;
    size_t i;
    unsigned int cnt;

    if (!src || !dest)
        goto cleanup;

    virInterfaceObjListFree(dest); /* start with an empty list */
    cnt = src->count;
    for (i = 0; i < cnt; i++) {
        virInterfaceDefPtr def = src->objs[i]->def;
        virInterfaceDefPtr backup;
        virInterfaceObjPtr iface;
        char *xml = virInterfaceDefFormat(def);

        if (!xml)
            goto cleanup;

        if ((backup = virInterfaceDefParseString(xml)) == NULL) {
            VIR_FREE(xml);
            goto cleanup;
        }

        VIR_FREE(xml);
        if ((iface = virInterfaceAssignDef(dest, backup)) == NULL)
            goto cleanup;
        virInterfaceObjUnlock(iface); /* was locked by virInterfaceAssignDef */
    }

    ret = cnt;
 cleanup:
    if ((ret < 0) && dest)
       virInterfaceObjListFree(dest);
    return ret;
}

virInterfaceObjPtr virInterfaceAssignDef(virInterfaceObjListPtr interfaces,
                                         virInterfaceDefPtr def)
{
    virInterfaceObjPtr iface;

    if ((iface = virInterfaceFindByName(interfaces, def->name))) {
        virInterfaceDefFree(iface->def);
        iface->def = def;

        return iface;
    }

    if (VIR_ALLOC(iface) < 0)
        return NULL;
    if (virMutexInit(&iface->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        VIR_FREE(iface);
        return NULL;
    }
    virInterfaceObjLock(iface);

    if (VIR_APPEND_ELEMENT_COPY(interfaces->objs,
                                interfaces->count, iface) < 0) {
        virInterfaceObjFree(iface);
        return NULL;
    }

    iface->def = def;
    return iface;

}

void virInterfaceRemove(virInterfaceObjListPtr interfaces,
                        virInterfaceObjPtr iface)
{
    size_t i;

    virInterfaceObjUnlock(iface);
    for (i = 0; i < interfaces->count; i++) {
        virInterfaceObjLock(interfaces->objs[i]);
        if (interfaces->objs[i] == iface) {
            virInterfaceObjUnlock(interfaces->objs[i]);
            virInterfaceObjFree(interfaces->objs[i]);

            VIR_DELETE_ELEMENT(interfaces->objs, i, interfaces->count);
            break;
        }
        virInterfaceObjUnlock(interfaces->objs[i]);
    }
}
