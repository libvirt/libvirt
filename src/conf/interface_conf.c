/*
 * interface_conf.c: interfaces XML handling
 *
 * Copyright (C) 2006-2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel Veillard <veillard@redhat.com>
 *         Laine Stump <laine@redhat.com>
 */

#include <config.h>
#include "virterror_internal.h"
#include "datatypes.h"

#include "interface_conf.h"

#include "memory.h"
#include "xml.h"
#include "uuid.h"
#include "util.h"
#include "buf.h"

#define VIR_FROM_THIS VIR_FROM_INTERFACE

VIR_ENUM_IMPL(virInterface,
              VIR_INTERFACE_TYPE_LAST,
              "ethernet", "bridge", "bond", "vlan" )

static virInterfaceDefPtr
virInterfaceDefParseXML(xmlXPathContextPtr ctxt, int parentIfType);
static int
virInterfaceDefDevFormat(virBufferPtr buf,
                         const virInterfaceDefPtr def, int level);

#define virInterfaceReportError(code, ...)                              \
    virReportErrorHelper(VIR_FROM_INTERFACE, code, __FILE__,            \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

static
void virInterfaceIpDefFree(virInterfaceIpDefPtr def) {
    if (def == NULL)
        return;
    VIR_FREE(def->address);
    VIR_FREE(def);
}

static
void virInterfaceProtocolDefFree(virInterfaceProtocolDefPtr def) {
    int ii;

    if (def == NULL)
        return;
    for (ii = 0; ii < def->nips; ii++) {
        virInterfaceIpDefFree(def->ips[ii]);
    }
    VIR_FREE(def->ips);
    VIR_FREE(def->family);
    VIR_FREE(def->gateway);
    VIR_FREE(def);
}

void virInterfaceDefFree(virInterfaceDefPtr def)
{
    int i, pp;

    if (def == NULL)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->mac);

    switch (def->type) {
        case VIR_INTERFACE_TYPE_BRIDGE:
            VIR_FREE(def->data.bridge.delay);
            for (i = 0;i < def->data.bridge.nbItf;i++) {
                if (def->data.bridge.itf[i] == NULL)
                    break; /* to cope with half parsed data on errors */
                virInterfaceDefFree(def->data.bridge.itf[i]);
            }
            VIR_FREE(def->data.bridge.itf);
            break;
        case VIR_INTERFACE_TYPE_BOND:
            VIR_FREE(def->data.bond.target);
            for (i = 0;i < def->data.bond.nbItf;i++) {
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
                         xmlXPathContextPtr ctxt) {
    char *tmp;

    tmp = virXPathString("string(./@name)", ctxt);
    if (tmp == NULL) {
        virInterfaceReportError(VIR_ERR_XML_ERROR,
                                "%s",  _("interface has no name"));
        return -1;
    }
    def->name = tmp;
    return 0;
}

static int
virInterfaceDefParseMtu(virInterfaceDefPtr def,
                        xmlXPathContextPtr ctxt) {
    unsigned long mtu;
    int ret;

    ret = virXPathULong("string(./mtu/@size)", ctxt, &mtu);
    if ((ret == -2) || ((ret == 0) && (mtu > 100000))) {
        virInterfaceReportError(VIR_ERR_XML_ERROR,
                         "%s", _("interface mtu value is improper"));
        return -1;
    } else if (ret == 0) {
        def->mtu = (unsigned int) mtu;
    }
    return 0;
}

static int
virInterfaceDefParseStartMode(virInterfaceDefPtr def,
                              xmlXPathContextPtr ctxt) {
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
        virInterfaceReportError(VIR_ERR_XML_ERROR,
                                _("unknown interface startmode %s"), tmp);
        VIR_FREE(tmp);
        return -1;
    }
    VIR_FREE(tmp);
    return 0;
}

static int
virInterfaceDefParseBondMode(xmlXPathContextPtr ctxt) {
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
        virInterfaceReportError(VIR_ERR_XML_ERROR,
                                _("unknown bonding mode %s"), tmp);
        ret = -1;
    }
    VIR_FREE(tmp);
    return ret;
}

static int
virInterfaceDefParseBondMiiCarrier(xmlXPathContextPtr ctxt) {
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
        virInterfaceReportError(VIR_ERR_XML_ERROR,
                                _("unknown mii bonding carrier %s"), tmp);
        ret = -1;
    }
    VIR_FREE(tmp);
    return ret;
}

static int
virInterfaceDefParseBondArpValid(xmlXPathContextPtr ctxt) {
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
        virInterfaceReportError(VIR_ERR_XML_ERROR,
                                _("unknown arp bonding validate %s"), tmp);
        ret = -1;
    }
    VIR_FREE(tmp);
    return ret;
}

static int
virInterfaceDefParseDhcp(virInterfaceProtocolDefPtr def,
                         xmlNodePtr dhcp, xmlXPathContextPtr ctxt) {
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
            virInterfaceReportError(VIR_ERR_XML_ERROR,
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
                       xmlXPathContextPtr ctxt) {
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
            virInterfaceReportError(VIR_ERR_XML_ERROR,
                              "%s", _("Invalid ip address prefix value"));
            return -1;
        }
    }

    return 0;
}

static int
virInterfaceDefParseProtoIPv4(virInterfaceProtocolDefPtr def,
                              xmlXPathContextPtr ctxt) {
    xmlNodePtr dhcp;
    xmlNodePtr *ipNodes = NULL;
    int nIpNodes, ii, ret = -1;
    char *tmp;

    tmp = virXPathString("string(./route[1]/@gateway)", ctxt);
    def->gateway = tmp;

    dhcp = virXPathNode("./dhcp", ctxt);
    if (dhcp != NULL) {
        ret = virInterfaceDefParseDhcp(def, dhcp, ctxt);
        if (ret != 0)
           return ret;
    }

    nIpNodes = virXPathNodeSet("./ip", ctxt, &ipNodes);
    if (nIpNodes < 0)
        return -1;
    if (ipNodes == NULL)
        return 0;

    if (VIR_ALLOC_N(def->ips, nIpNodes) < 0) {
        virReportOOMError();
        goto error;
    }

    def->nips = 0;
    for (ii = 0; ii < nIpNodes; ii++) {

        virInterfaceIpDefPtr ip;

        if (VIR_ALLOC(ip) < 0) {
            virReportOOMError();
            goto error;
        }

        ctxt->node = ipNodes[ii];
        ret = virInterfaceDefParseIp(ip, ctxt);
        if (ret != 0) {
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
                              xmlXPathContextPtr ctxt) {
    xmlNodePtr dhcp, autoconf;
    xmlNodePtr *ipNodes = NULL;
    int nIpNodes, ii, ret = -1;
    char *tmp;

    tmp = virXPathString("string(./route[1]/@gateway)", ctxt);
    def->gateway = tmp;

    autoconf = virXPathNode("./autoconf", ctxt);
    if (autoconf != NULL)
        def->autoconf = 1;

    dhcp = virXPathNode("./dhcp", ctxt);
    if (dhcp != NULL) {
        ret = virInterfaceDefParseDhcp(def, dhcp, ctxt);
        if (ret != 0)
           return ret;
    }

    nIpNodes = virXPathNodeSet("./ip", ctxt, &ipNodes);
    if (nIpNodes < 0)
        return -1;
    if (ipNodes == NULL)
        return 0;

    if (VIR_ALLOC_N(def->ips, nIpNodes) < 0) {
        virReportOOMError();
        goto error;
    }

    def->nips = 0;
    for (ii = 0; ii < nIpNodes; ii++) {

        virInterfaceIpDefPtr ip;

        if (VIR_ALLOC(ip) < 0) {
            virReportOOMError();
            goto error;
        }

        ctxt->node = ipNodes[ii];
        ret = virInterfaceDefParseIp(ip, ctxt);
        if (ret != 0) {
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
                                xmlXPathContextPtr ctxt) {
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

    if (VIR_ALLOC_N(def->protos, nProtoNodes) < 0) {
        virReportOOMError();
        goto error;
    }

    def->nprotos = 0;
    for (pp = 0; pp < nProtoNodes; pp++) {

        virInterfaceProtocolDefPtr proto;

        if (VIR_ALLOC(proto) < 0) {
            virReportOOMError();
            goto error;
        }

        ctxt->node = protoNodes[pp];
        tmp = virXPathString("string(./@family)", ctxt);
        if (tmp == NULL) {
            virInterfaceReportError(VIR_ERR_XML_ERROR,
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
            virInterfaceReportError(VIR_ERR_XML_ERROR,
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
                           xmlXPathContextPtr ctxt) {
    xmlNodePtr *interfaces = NULL;
    xmlNodePtr bridge;
    virInterfaceDefPtr itf;
    int nbItf, i;
    int ret = 0;

    bridge = ctxt->node;
    nbItf = virXPathNodeSet("./interface", ctxt, &interfaces);
    if (nbItf < 0) {
        ret = -1;
        goto error;
    }
    if (nbItf > 0) {
        if (VIR_ALLOC_N(def->data.bridge.itf, nbItf) < 0) {
            virReportOOMError();
            ret = -1;
            goto error;
        }
        def->data.bridge.nbItf = nbItf;

        for (i = 0; i < nbItf;i++) {
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
                             xmlXPathContextPtr ctxt) {
    xmlNodePtr *interfaces = NULL;
    xmlNodePtr bond = ctxt->node;
    virInterfaceDefPtr itf;
    int nbItf, i;
    int ret = 0;

    nbItf = virXPathNodeSet("./interface", ctxt, &interfaces);
    if (nbItf < 0) {
        ret = -1;
        goto error;
    }

    if (nbItf == 0) {
        virInterfaceReportError(VIR_ERR_XML_ERROR,
                                "%s", _("bond has no interfaces"));
        ret = -1;
        goto error;
    }

    if (VIR_ALLOC_N(def->data.bond.itf, nbItf) < 0) {
        virReportOOMError();
        ret = -1;
        goto error;
    }
    def->data.bond.nbItf = nbItf;

    for (i = 0; i < nbItf;i++) {
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
                         xmlXPathContextPtr ctxt) {
    int ret = -1;
    unsigned long tmp;

    def->data.bond.mode = virInterfaceDefParseBondMode(ctxt);
    if (def->data.bond.mode < 0)
        goto error;

    ret = virInterfaceDefParseBondItfs(def, ctxt);
    if (ret != 0)
       goto error;

    if (virXPathNode("./miimon[1]", ctxt) != NULL) {
        def->data.bond.monit = VIR_INTERFACE_BOND_MONIT_MII;

        ret = virXPathULong("string(./miimon/@freq)", ctxt, &tmp);
        if ((ret == -2) || (ret == -1)) {
            virInterfaceReportError(VIR_ERR_XML_ERROR,
                     "%s", _("bond interface miimon freq missing or invalid"));
            goto error;
        }
        def->data.bond.frequency = (int) tmp;

        ret = virXPathULong("string(./miimon/@downdelay)", ctxt, &tmp);
        if (ret == -2) {
            virInterfaceReportError(VIR_ERR_XML_ERROR,
                     "%s", _("bond interface miimon downdelay invalid"));
            goto error;
        } else if (ret == 0) {
            def->data.bond.downdelay = (int) tmp;
        }

        ret = virXPathULong("string(./miimon/@updelay)", ctxt, &tmp);
        if (ret == -2) {
            virInterfaceReportError(VIR_ERR_XML_ERROR,
                     "%s", _("bond interface miimon updelay invalid"));
            goto error;
        } else if (ret == 0) {
            def->data.bond.updelay = (int) tmp;
        }

        def->data.bond.carrier = virInterfaceDefParseBondMiiCarrier(ctxt);
        if (def->data.bond.carrier < 0) {
            ret = -1;
            goto error;
        }

    } else if (virXPathNode("./arpmon[1]", ctxt) != NULL) {

        def->data.bond.monit = VIR_INTERFACE_BOND_MONIT_ARP;

        ret = virXPathULong("string(./arpmon/@interval)", ctxt, &tmp);
        if ((ret == -2) || (ret == -1)) {
            virInterfaceReportError(VIR_ERR_XML_ERROR,
                 "%s", _("bond interface arpmon interval missing or invalid"));
            goto error;
        }
        def->data.bond.interval = (int) tmp;

        def->data.bond.target =
            virXPathString("string(./arpmon/@target)", ctxt);
        if (def->data.bond.target == NULL) {
            virInterfaceReportError(VIR_ERR_XML_ERROR,
                 "%s", _("bond interface arpmon target missing"));
            ret = -1;
            goto error;
        }

        def->data.bond.validate = virInterfaceDefParseBondArpValid(ctxt);
        if (def->data.bond.validate < 0) {
            ret = -1;
            goto error;
        }
    }
error:
    return ret;
}

static int
virInterfaceDefParseVlan(virInterfaceDefPtr def,
                         xmlXPathContextPtr ctxt) {
    def->data.vlan.tag = virXPathString("string(./@tag)", ctxt);
    if (def->data.vlan.tag == NULL) {
        virInterfaceReportError(VIR_ERR_XML_ERROR,
                    "%s", _("vlan interface misses the tag attribute"));
        return -1;
    }

    def->data.vlan.devname =
         virXPathString("string(./interface/@name)", ctxt);
    if (def->data.vlan.devname == NULL) {
        virInterfaceReportError(VIR_ERR_XML_ERROR,
                    "%s", _("vlan interface misses name attribute"));
        return -1;
    }
    return 0;
}

static virInterfaceDefPtr
virInterfaceDefParseXML(xmlXPathContextPtr ctxt, int parentIfType) {
    virInterfaceDefPtr def;
    int type;
    char *tmp;
    xmlNodePtr cur = ctxt->node;

    /* check @type */
    tmp = virXPathString("string(./@type)", ctxt);
    if (tmp == NULL) {
        virInterfaceReportError(VIR_ERR_XML_ERROR,
                                "%s", _("interface misses the type attribute"));
        return NULL;
    }
    type = virInterfaceTypeFromString(tmp);
    if (type == -1) {
        virInterfaceReportError(VIR_ERR_XML_ERROR,
                                _("unknown interface type %s"), tmp);
        VIR_FREE(tmp);
        return NULL;
    }
    VIR_FREE(tmp);

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (((parentIfType == VIR_INTERFACE_TYPE_BOND)
         && (type != VIR_INTERFACE_TYPE_ETHERNET))
        || ((parentIfType == VIR_INTERFACE_TYPE_BRIDGE)
            && (type != VIR_INTERFACE_TYPE_ETHERNET)
            && (type != VIR_INTERFACE_TYPE_BOND)
            && (type != VIR_INTERFACE_TYPE_VLAN))
        || (parentIfType == VIR_INTERFACE_TYPE_ETHERNET)
        || (parentIfType == VIR_INTERFACE_TYPE_VLAN))
        {
        virInterfaceReportError(VIR_ERR_XML_ERROR,
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
                virInterfaceReportError(VIR_ERR_XML_ERROR,
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
                    virInterfaceReportError(VIR_ERR_XML_ERROR,
                          _("bridge interface stp should be on or off got %s"),
                                            tmp);
                    VIR_FREE(tmp);
                    goto error;
                }
                VIR_FREE(tmp);
            }
            def->data.bridge.delay = virXMLPropString(bridge, "delay");
            ctxt->node = bridge;
            virInterfaceDefParseBridge(def, ctxt);
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
                virInterfaceReportError(VIR_ERR_XML_ERROR,
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
                virInterfaceReportError(VIR_ERR_XML_ERROR,
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
        virInterfaceReportError(VIR_ERR_XML_ERROR,
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
virInterfaceBridgeDefFormat(virBufferPtr buf,
                            const virInterfaceDefPtr def, int level) {
    int i;
    int ret = 0;

    virBufferAsprintf(buf, "%*s  <bridge", level*2, "");
    if (def->data.bridge.stp == 1)
        virBufferAddLit(buf, " stp='on'");
    else if (def->data.bridge.stp == 0)
        virBufferAddLit(buf, " stp='off'");
    if (def->data.bridge.delay != NULL)
        virBufferAsprintf(buf, " delay='%s'", def->data.bridge.delay);
    virBufferAddLit(buf, ">\n");

    for (i = 0;i < def->data.bridge.nbItf;i++) {
        if (virInterfaceDefDevFormat(buf,
                                     def->data.bridge.itf[i], level+2) < 0)
            ret = -1;
    }

    virBufferAsprintf(buf, "%*s  </bridge>\n", level*2, "");
    return ret;
}

static int
virInterfaceBondDefFormat(virBufferPtr buf,
                          const virInterfaceDefPtr def, int level) {
    int i;
    int ret = 0;

    virBufferAsprintf(buf, "%*s  <bond", level*2, "");
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

    if (def->data.bond.monit == VIR_INTERFACE_BOND_MONIT_MII) {
        virBufferAsprintf(buf, "%*s    <miimon freq='%d'",
                          level*2, "", def->data.bond.frequency);
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
            virInterfaceReportError(VIR_ERR_INTERNAL_ERROR,
                          "%s", _("bond arp monitoring has no target"));
            return -1;
        }
        virBufferAsprintf(buf, "%*s    <arpmon interval='%d' target='%s'",
                          level*2, "",
                          def->data.bond.interval, def->data.bond.target);
        if (def->data.bond.validate == VIR_INTERFACE_BOND_ARP_ACTIVE)
            virBufferAddLit(buf, " validate='active'");
        else if (def->data.bond.validate == VIR_INTERFACE_BOND_ARP_BACKUP)
            virBufferAddLit(buf, " validate='backup'");
        else if (def->data.bond.validate == VIR_INTERFACE_BOND_ARP_ALL)
            virBufferAddLit(buf, " validate='all'");
        virBufferAddLit(buf, "/>\n");
    }
    for (i = 0;i < def->data.bond.nbItf;i++) {
        if (virInterfaceDefDevFormat(buf, def->data.bond.itf[i], level+2) < 0)
            ret = -1;
    }

    virBufferAsprintf(buf, "%*s  </bond>\n", level*2, "");
    return ret;
}

static int
virInterfaceVlanDefFormat(virBufferPtr buf,
                          const virInterfaceDefPtr def, int level) {
    if (def->data.vlan.tag == NULL) {
        virInterfaceReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("vlan misses the tag name"));
        return -1;
    }

    virBufferAsprintf(buf, "%*s  <vlan tag='%s'",
                      level*2, "", def->data.vlan.tag);
    if (def->data.vlan.devname != NULL) {
        virBufferAddLit(buf, ">\n");
        virBufferAsprintf(buf, "%*s    <interface name='%s'/>\n",
                          level*2, "", def->data.vlan.devname);
        virBufferAsprintf(buf, "%*s  </vlan>\n", level*2, "");
    } else
        virBufferAddLit(buf, "/>\n");
    return 0;
}

static int
virInterfaceProtocolDefFormat(virBufferPtr buf, const virInterfaceDefPtr def,
                              int level) {
    int pp, ii;

    for (pp = 0; pp < def->nprotos; pp++) {

        virBufferAsprintf(buf, "%*s  <protocol family='%s'>\n",
                          level*2, "", def->protos[pp]->family);

        if (def->protos[pp]->autoconf) {
            virBufferAsprintf(buf, "%*s    <autoconf/>\n", level*2, "");
        }

        if (def->protos[pp]->dhcp) {
            if (def->protos[pp]->peerdns == 0)
                virBufferAsprintf(buf, "%*s    <dhcp peerdns='no'/>\n",
                                  level*2, "");
            else if (def->protos[pp]->peerdns == 1)
                virBufferAsprintf(buf, "%*s    <dhcp peerdns='yes'/>\n",
                                  level*2, "");
            else
                virBufferAsprintf(buf, "%*s    <dhcp/>\n", level*2, "");
        }

        for (ii = 0; ii < def->protos[pp]->nips; ii++) {
            if (def->protos[pp]->ips[ii]->address != NULL) {

                virBufferAsprintf(buf, "%*s    <ip address='%s'", level*2, "",
                                  def->protos[pp]->ips[ii]->address);
                if (def->protos[pp]->ips[ii]->prefix != 0) {
                    virBufferAsprintf(buf, " prefix='%d'",
                                      def->protos[pp]->ips[ii]->prefix);
                }
                virBufferAddLit(buf, "/>\n");
            }
        }
        if (def->protos[pp]->gateway != NULL) {
            virBufferAsprintf(buf, "%*s    <route gateway='%s'/>\n",
                              level*2, "", def->protos[pp]->gateway);
        }

        virBufferAsprintf(buf, "%*s  </protocol>\n", level*2, "");
    }
    return 0;
}

static int
virInterfaceStartmodeDefFormat(virBufferPtr buf,
                               enum virInterfaceStartMode startmode,
                               int level) {
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
            virInterfaceReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("virInterfaceDefFormat unknown startmode"));
            return -1;
    }
    virBufferAsprintf(buf, "%*s  <start mode='%s'/>\n", level*2, "", mode);
    return 0;
}

static int
virInterfaceDefDevFormat(virBufferPtr buf,
                         const virInterfaceDefPtr def, int level) {
    const char *type = NULL;

    if (def == NULL) {
        virInterfaceReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("virInterfaceDefFormat NULL def"));
        goto cleanup;
    }

    if ((def->name == NULL) && (def->type != VIR_INTERFACE_TYPE_VLAN)) {
        virInterfaceReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("virInterfaceDefFormat missing interface name"));
        goto cleanup;
    }

    if (!(type = virInterfaceTypeToString(def->type))) {
        virInterfaceReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unexpected interface type %d"), def->type);
        goto cleanup;
    }

    virBufferAsprintf(buf, "%*s<interface type='%s' ", level*2, "", type);
    if (def->name != NULL)
        virBufferEscapeString(buf, "name='%s'", def->name);
    virBufferAddLit(buf, ">\n");

    switch (def->type) {
        case VIR_INTERFACE_TYPE_ETHERNET:
            virInterfaceStartmodeDefFormat(buf, def->startmode, level);
            if (def->mac != NULL)
                virBufferAsprintf(buf, "%*s  <mac address='%s'/>\n",
                                  level*2, "", def->mac);
            if (def->mtu != 0)
                virBufferAsprintf(buf, "%*s  <mtu size='%d'/>\n",
                                  level*2, "", def->mtu);
            virInterfaceProtocolDefFormat(buf, def, level);
            break;
        case VIR_INTERFACE_TYPE_BRIDGE:
            virInterfaceStartmodeDefFormat(buf, def->startmode, level);
            if (def->mtu != 0)
                virBufferAsprintf(buf, "%*s  <mtu size='%d'/>\n",
                                  level*2, "", def->mtu);
            virInterfaceProtocolDefFormat(buf, def, level);
            virInterfaceBridgeDefFormat(buf, def, level);
            break;
        case VIR_INTERFACE_TYPE_BOND:
            virInterfaceStartmodeDefFormat(buf, def->startmode, level);
            if (def->mtu != 0)
                virBufferAsprintf(buf, "%*s  <mtu size='%d'/>\n",
                                  level*2, "", def->mtu);
            virInterfaceProtocolDefFormat(buf, def, level);
            virInterfaceBondDefFormat(buf, def, level);
            break;
        case VIR_INTERFACE_TYPE_VLAN:
            virInterfaceStartmodeDefFormat(buf, def->startmode, level);
            if (def->mac != NULL)
                virBufferAsprintf(buf, "%*s  <mac address='%s'/>\n",
                                  level*2, "", def->mac);
            if (def->mtu != 0)
                virBufferAsprintf(buf, "%*s  <mtu size='%d'/>\n",
                                  level*2, "", def->mtu);
            virInterfaceProtocolDefFormat(buf, def, level);
            virInterfaceVlanDefFormat(buf, def, level);
            break;
    }

    virBufferAsprintf(buf, "%*s</interface>\n", level*2, "");

    if (virBufferError(buf))
        goto no_memory;
    return 0;
no_memory:
    virReportOOMError();
cleanup:
    return -1;
}

char *virInterfaceDefFormat(const virInterfaceDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (virInterfaceDefDevFormat(&buf, def, 0) < 0) {
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

int virInterfaceFindByMACString(const virInterfaceObjListPtr interfaces,
                                const char *mac,
                                virInterfaceObjPtr *matches, int maxmatches)
{
    unsigned int i, matchct = 0;

    for (i = 0 ; i < interfaces->count ; i++) {

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

virInterfaceObjPtr virInterfaceFindByName(const virInterfaceObjListPtr
                                          interfaces,
                                          const char *name)
{
    unsigned int i;

    for (i = 0 ; i < interfaces->count ; i++) {
        virInterfaceObjLock(interfaces->objs[i]);
        if (STREQ(interfaces->objs[i]->def->name, name))
            return interfaces->objs[i];
        virInterfaceObjUnlock(interfaces->objs[i]);
    }

    return NULL;
}

void virInterfaceObjListFree(virInterfaceObjListPtr interfaces)
{
    unsigned int i;

    for (i = 0 ; i < interfaces->count ; i++)
        virInterfaceObjFree(interfaces->objs[i]);

    VIR_FREE(interfaces->objs);
    interfaces->count = 0;
}

int virInterfaceObjListClone(virInterfaceObjListPtr src,
                             virInterfaceObjListPtr dest)
{
    int ret = -1;
    unsigned int i, cnt;

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
                                         const virInterfaceDefPtr def)
{
    virInterfaceObjPtr iface;

    if ((iface = virInterfaceFindByName(interfaces, def->name))) {
        virInterfaceDefFree(iface->def);
        iface->def = def;

        return iface;
    }

    if (VIR_ALLOC(iface) < 0) {
        virReportOOMError();
        return NULL;
    }
    if (virMutexInit(&iface->lock) < 0) {
        virInterfaceReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("cannot initialize mutex"));
        VIR_FREE(iface);
        return NULL;
    }
    virInterfaceObjLock(iface);
    iface->def = def;

    if (VIR_REALLOC_N(interfaces->objs, interfaces->count + 1) < 0) {
        virReportOOMError();
        VIR_FREE(iface);
        return NULL;
    }

    interfaces->objs[interfaces->count] = iface;
    interfaces->count++;

    return iface;

}

void virInterfaceRemove(virInterfaceObjListPtr interfaces,
                        const virInterfaceObjPtr iface)
{
    unsigned int i;

    virInterfaceObjUnlock(iface);
    for (i = 0 ; i < interfaces->count ; i++) {
        virInterfaceObjLock(interfaces->objs[i]);
        if (interfaces->objs[i] == iface) {
            virInterfaceObjUnlock(interfaces->objs[i]);
            virInterfaceObjFree(interfaces->objs[i]);

            if (i < (interfaces->count - 1))
                memmove(interfaces->objs + i, interfaces->objs + i + 1,
                        sizeof(*(interfaces->objs)) * (interfaces->count - (i + 1)));

            if (VIR_REALLOC_N(interfaces->objs, interfaces->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            interfaces->count--;

            break;
        }
        virInterfaceObjUnlock(interfaces->objs[i]);
    }
}
