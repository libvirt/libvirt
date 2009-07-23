/*
 * interface_conf.c: interfaces XML handling
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
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

#define virInterfaceReportError(conn, code, fmt...)                            \
        virReportErrorHelper(conn, VIR_FROM_INTERFACE, code, __FILE__,       \
                               __FUNCTION__, __LINE__, fmt)

static
void virInterfaceBareDefFree(virInterfaceBareDefPtr def) {
    if (def == NULL)
        return;
    VIR_FREE(def->name);
    VIR_FREE(def->mac_or_tag);
    VIR_FREE(def->devname);
    VIR_FREE(def);
}

void virInterfaceDefFree(virInterfaceDefPtr def)
{
    int i;

    if (def == NULL)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->mac);

    switch (def->type) {
        case VIR_INTERFACE_TYPE_BRIDGE:
            for (i = 0;i < def->data.bridge.nbItf;i++) {
                if (def->data.bridge.itf[i] != NULL)
                    virInterfaceBareDefFree(def->data.bridge.itf[i]);
                else
                    break; /* to cope with half parsed data on errors */
            }
            VIR_FREE(def->data.bridge.itf);
            break;
        case VIR_INTERFACE_TYPE_BOND:
            VIR_FREE(def->data.bond.target);
            for (i = 0;i < def->data.bond.nbItf;i++) {
                if (def->data.bond.itf[i] != NULL)
                    virInterfaceBareDefFree(def->data.bond.itf[i]);
                else
                    break; /* to cope with half parsed data on errors */
            }
            VIR_FREE(def->data.bond.itf);
            break;
        case VIR_INTERFACE_TYPE_VLAN:
            VIR_FREE(def->data.vlan.tag);
            VIR_FREE(def->data.vlan.devname);
            break;
    }

    VIR_FREE(def->proto.family);
    VIR_FREE(def->proto.address);
    VIR_FREE(def->proto.gateway);

    VIR_FREE(def);
}

static int
virInterfaceDefParseBasicAttrs(virConnectPtr conn, virInterfaceDefPtr def,
                               xmlXPathContextPtr ctxt) {
    char *tmp;
    unsigned long mtu;
    int ret;

    tmp = virXPathString(conn, "string(./@name)", ctxt);
    if (tmp == NULL) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                              "%s",  _("interface has no name"));
        return(-1);
    }
    def->name = tmp;

    ret = virXPathULong(conn, "string(./mtu/@size)", ctxt, &mtu);
    if ((ret == -2) || ((ret == 0) && (mtu > 100000))) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                         "%s", _("interface mtu value is improper"));
        return(-1);
    } else if (ret == 0) {
        def->mtu = (unsigned int) mtu;
    }
    return(0);
}

static int
virInterfaceDefParseStartMode(virConnectPtr conn, virInterfaceDefPtr def,
                              xmlXPathContextPtr ctxt) {
    char *tmp;

    tmp = virXPathString(conn, "string(./start/@mode)", ctxt);
    if (tmp == NULL) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                        "%s", _("interface misses the start mode attribute"));
        return(-1);
    }
    if (STREQ(tmp, "onboot"))
        def->startmode = VIR_INTERFACE_START_ONBOOT;
    else if (STREQ(tmp, "hotplug"))
        def->startmode = VIR_INTERFACE_START_HOTPLUG;
    else if (STREQ(tmp, "none"))
        def->startmode = VIR_INTERFACE_START_NONE;
    else {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                _("unknown interface startmode %s"), tmp);
        VIR_FREE(tmp);
        return(-1);
    }
    VIR_FREE(tmp);
    return(0);
}

static int
virInterfaceDefParseBondMode(virConnectPtr conn, xmlXPathContextPtr ctxt) {
    char *tmp;
    int ret = 0;

    tmp = virXPathString(conn, "string(./@mode)", ctxt);
    if (tmp == NULL)
        return(VIR_INTERFACE_BOND_NONE);
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
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                _("unknown bonding mode %s"), tmp);
        ret = -1;
    }
    VIR_FREE(tmp);
    return(ret);
}

static int
virInterfaceDefParseBondMiiCarrier(virConnectPtr conn, xmlXPathContextPtr ctxt) {
    char *tmp;
    int ret = 0;

    tmp = virXPathString(conn, "string(./miimon/@carrier)", ctxt);
    if (tmp == NULL)
        return(VIR_INTERFACE_BOND_MII_NONE);
    if (STREQ(tmp, "ioctl"))
        ret = VIR_INTERFACE_BOND_MII_IOCTL;
    else if (STREQ(tmp, "netif"))
        ret = VIR_INTERFACE_BOND_MII_NETIF;
    else {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                _("unknown mii bonding carrier %s"), tmp);
        ret = -1;
    }
    VIR_FREE(tmp);
    return(ret);
}

static int
virInterfaceDefParseBondArpValid(virConnectPtr conn, xmlXPathContextPtr ctxt) {
    char *tmp;
    int ret = 0;

    tmp = virXPathString(conn, "string(./arpmon/@validate)", ctxt);
    if (tmp == NULL)
        return(VIR_INTERFACE_BOND_ARP_NONE);
    if (STREQ(tmp, "active"))
        ret = VIR_INTERFACE_BOND_ARP_ACTIVE;
    else if (STREQ(tmp, "backup"))
        ret = VIR_INTERFACE_BOND_ARP_BACKUP;
    else if (STREQ(tmp, "all"))
        ret = VIR_INTERFACE_BOND_ARP_ALL;
    else {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                _("unknown arp bonding validate %s"), tmp);
        ret = -1;
    }
    VIR_FREE(tmp);
    return(ret);
}

static int
virInterfaceDefParseDhcp(virConnectPtr conn, virInterfaceDefPtr def,
                         xmlNodePtr dhcp, xmlXPathContextPtr ctxt) {
    char *tmp;
    xmlNodePtr old;
    int ret = 0;

    def->proto.dhcp = 1;
    old = ctxt->node;
    ctxt->node = dhcp;
    /* Not much to do in the current version */
    tmp = virXPathString(conn, "string(./@peerdns)", ctxt);
    if (tmp) {
        if (STREQ(tmp, "yes"))
            def->proto.peerdns = 1;
        else if (STREQ(tmp, "no"))
            def->proto.peerdns = 0;
        else {
            virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                              _("unknown dhcp peerdns value %s"), tmp);
            ret = -1;
        }
        VIR_FREE(tmp);
    } else
        def->proto.peerdns = -1;

    return(ret);
}

static int
virInterfaceDefParseIp(virConnectPtr conn, virInterfaceDefPtr def,
                   xmlNodePtr ip ATTRIBUTE_UNUSED, xmlXPathContextPtr ctxt) {
    int ret = 0;
    char *tmp;
    long l;

    tmp = virXPathString(conn, "string(./ip[1]/@address)", ctxt);
    def->proto.address = tmp;
    if (tmp != NULL) {
        ret = virXPathLong(conn, "string(./ip[1]/@prefix)", ctxt, &l);
        if (ret == 0)
            def->proto.prefix = (int) l;
        else if (ret == -2) {
            virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("Invalid ip address prefix value"));
            return(-1);
        }
    }
    tmp = virXPathString(conn, "string(./route[1]/@gateway)", ctxt);
    def->proto.gateway = tmp;

    return(0);
}

static int
virInterfaceDefParseProtoIPv4(virConnectPtr conn, virInterfaceDefPtr def,
                              xmlXPathContextPtr ctxt) {
    xmlNodePtr cur;
    int ret;

    cur = virXPathNode(conn, "./dhcp", ctxt);
    if (cur != NULL)
        ret = virInterfaceDefParseDhcp(conn, def, cur, ctxt);
    else {
        cur = virXPathNode(conn, "./ip", ctxt);
        if (cur != NULL)
            ret = virInterfaceDefParseIp(conn, def, cur, ctxt);
        else {
            virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                "%s", _("interface miss dhcp or ip adressing"));
            ret = -1;
        }
    }
    return(ret);
}

static int
virInterfaceDefParseIfAdressing(virConnectPtr conn, virInterfaceDefPtr def,
                                xmlXPathContextPtr ctxt) {
    xmlNodePtr cur, save;
    int ret;
    char *tmp;

    cur = virXPathNode(conn, "./protocol[1]", ctxt);
    if (cur == NULL)
        return(0);
    save = ctxt->node;
    ctxt->node = cur;
    tmp = virXPathString(conn, "string(./@family)", ctxt);
    if (tmp == NULL) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                            "%s", _("protocol misses the family attribute"));
        ret = -1;
        goto done;
    }
    if (STREQ(tmp, "ipv4")) {
        def->proto.family = tmp;
        ret = virInterfaceDefParseProtoIPv4(conn, def, ctxt);
    } else {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                            _("unsupported protocol family '%s'"), tmp);
        ret = -1;
        VIR_FREE(tmp);
    }

done:
    ctxt->node = save;
    return(ret);

}

static virInterfaceBareDefPtr
virInterfaceDefParseBareInterface(virConnectPtr conn, xmlXPathContextPtr ctxt,
                                  int ethernet_only) {
    int t;
    char *name = NULL;
    char *type = NULL;
    char *mac_or_tag = NULL;
    char *devname = NULL;
    virInterfaceBareDefPtr ret = NULL;

    type = virXPathString(conn, "string(./@type)", ctxt);
    if (type == NULL) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                            "%s", _("interface has no type"));
        goto error;
    }
    if (STREQ(type, "ethernet")) {
        t = VIR_INTERFACE_TYPE_ETHERNET;
        name = virXPathString(conn, "string(./@name)", ctxt);
        mac_or_tag = virXPathString(conn, "string(./mac/@address)", ctxt);
    } else if ((STREQ(type, "vlan")) && (ethernet_only == 0)) {
        t = VIR_INTERFACE_TYPE_VLAN;
        name = virXPathString(conn, "string(./@name)", ctxt);
        mac_or_tag = virXPathString(conn, "string(./vlan/@tag)", ctxt);
        devname = virXPathString(conn, "string(./vlan/interface/@name)", ctxt);
    } else {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                            _("interface has unsupported type '%s'"), type);
        VIR_FREE(type);
        goto error;
    }
    VIR_FREE(type);
    if (name == NULL) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                            "%s", _("interface has no name"));
        goto error;
    }
    if (t == VIR_INTERFACE_TYPE_VLAN) {
        if (mac_or_tag == NULL) {
            virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                _("vlan %s has no tag"), name);
            goto error;
        }
        if (devname == NULL) {
            virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                _("vlan %s has interface name"), name);
            goto error;
        }
    }
    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError(conn);
        goto error;
    }
    ret->type = t;
    ret->name = name;
    ret->mac_or_tag = mac_or_tag;
    ret->devname = devname;
    return(ret);

error:
     VIR_FREE(name);
     VIR_FREE(type);
     VIR_FREE(name);
     VIR_FREE(name);
     VIR_FREE(ret);
     return(NULL);
}

static int
virInterfaceDefParseBridge(virConnectPtr conn, virInterfaceDefPtr def,
                           xmlXPathContextPtr ctxt) {
    xmlNodePtr *interfaces = NULL;
    xmlNodePtr bridge;
    virInterfaceBareDefPtr itf;
    int nbItf, i;
    int ret = 0;

    bridge = ctxt->node;
    nbItf = virXPathNodeSet(conn, "./interface", ctxt, &interfaces);
    if (nbItf <= 0) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                "%s", _("bridge has no interfaces"));
        ret = -1;
        goto error;
    }
    if (VIR_ALLOC_N(def->data.bridge.itf, nbItf) < 0) {
        virReportOOMError(conn);
        ret = -1;
        goto error;
    }
    def->data.bridge.nbItf = nbItf;

    for (i = 0; i < nbItf;i++) {
        ctxt->node = interfaces[i];
        itf = virInterfaceDefParseBareInterface(conn, ctxt, 0);
        if (itf == NULL) {
            ret = -1;
            def->data.bridge.nbItf = i;
            goto error;
        }
        def->data.bridge.itf[i] = itf;
    }

error:
    VIR_FREE(interfaces);
    ctxt->node = bridge;
    return(ret);
}

static int
virInterfaceDefParseBondItfs(virConnectPtr conn, virInterfaceDefPtr def,
                             xmlXPathContextPtr ctxt) {
    xmlNodePtr *interfaces = NULL;
    xmlNodePtr bond = ctxt->node;
    virInterfaceBareDefPtr itf;
    int nbItf, i;
    int ret = 0;

    nbItf = virXPathNodeSet(conn, "./interface", ctxt, &interfaces);
    if (nbItf <= 0) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                "%s", _("bond has no interfaces"));
        ret = -1;
        goto error;
    }
    if (VIR_ALLOC_N(def->data.bond.itf, nbItf) < 0) {
        virReportOOMError(conn);
        ret = -1;
        goto error;
    }
    def->data.bond.nbItf = nbItf;

    for (i = 0; i < nbItf;i++) {
        ctxt->node = interfaces[i];
        itf = virInterfaceDefParseBareInterface(conn, ctxt, 1);
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
    return(ret);
}

static int
virInterfaceDefParseBond(virConnectPtr conn, virInterfaceDefPtr def,
                         xmlXPathContextPtr ctxt) {
    xmlNodePtr node;
    int ret = 0;
    unsigned long tmp;

    def->data.bond.mode = virInterfaceDefParseBondMode(conn, ctxt);
    if (def->data.bond.mode < 0)
        goto error;

    node = virXPathNode(conn, "./miimon[1]", ctxt);
    if (node != NULL) {
        def->data.bond.monit = VIR_INTERFACE_BOND_MONIT_MII;

        ret = virXPathULong(conn, "string(./miimon/@freq)", ctxt, &tmp);
        if ((ret == -2) || (ret == -1)) {
            virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                     "%s", _("bond interface miimon freq missing or invalid"));
            goto error;
        }
        def->data.bond.frequency = (int) tmp;

        ret = virXPathULong(conn, "string(./miimon/@downdelay)", ctxt, &tmp);
        if (ret == -2) {
            virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                     "%s", _("bond interface miimon downdelay invalid"));
            goto error;
        } else if (ret == 0) {
            def->data.bond.downdelay = (int) tmp;
        }

        ret = virXPathULong(conn, "string(./miimon/@updelay)", ctxt, &tmp);
        if (ret == -2) {
            virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                     "%s", _("bond interface miimon updelay invalid"));
            goto error;
        } else if (ret == 0) {
            def->data.bond.updelay = (int) tmp;
        }

        def->data.bond.carrier = virInterfaceDefParseBondMiiCarrier(conn, ctxt);
        if (def->data.bond.carrier < 0)
            goto error;

        ret = virInterfaceDefParseBondItfs(conn, def, ctxt);

        goto done;
    }
    node = virXPathNode(conn, "./arpmon[1]", ctxt);
    if (node != NULL) {
        def->data.bond.monit = VIR_INTERFACE_BOND_MONIT_ARP;

        ret = virXPathULong(conn, "string(./arpmon/@interval)", ctxt, &tmp);
        if ((ret == -2) || (ret == -1)) {
            virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                 "%s", _("bond interface arpmon interval missing or invalid"));
            goto error;
        }
        def->data.bond.interval = (int) tmp;

        def->data.bond.target =
            virXPathString(conn, "string(./arpmon/@target)", ctxt);
        if (def->data.bond.target == NULL) {
            virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                 "%s", _("bond interface arpmon target missing"));
            goto error;
        }

        def->data.bond.validate = virInterfaceDefParseBondArpValid(conn, ctxt);
        if (def->data.bond.validate < 0)
            goto error;

        ret = virInterfaceDefParseBondItfs(conn, def, ctxt);

        goto done;
    }

    virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                "%s", _("bond interface need miimon or arpmon element"));
error:
    ret = -1;
done:
    return(ret);
}

static int
virInterfaceDefParseVlan(virConnectPtr conn, virInterfaceDefPtr def,
                         xmlXPathContextPtr ctxt) {
    def->data.vlan.tag = virXPathString(conn, "string(./@tag)", ctxt);
    if (def->data.vlan.tag == NULL) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                    "%s", _("vlan interface misses the tag attribute"));
        return(-1);
    }

    def->data.vlan.devname =
         virXPathString(conn, "string(./interface/@name)", ctxt);
    if (def->data.vlan.devname == NULL) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                    "%s", _("vlan interface misses name attribute"));
        return(-1);
    }
    return(0);
}

static virInterfaceDefPtr
virInterfaceDefParseXML(virConnectPtr conn, xmlXPathContextPtr ctxt) {
    virInterfaceDefPtr def;
    int type;
    char *tmp;
    xmlNodePtr cur = ctxt->node;

    /* check @type */
    tmp = virXPathString(conn, "string(./@type)", ctxt);
    if (tmp == NULL) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                "%s", _("interface misses the type attribute"));
        return(NULL);
    }
    type = virInterfaceTypeFromString(tmp);
    if (type == -1) {
        virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                _("unknown interface type %s"), tmp);
        VIR_FREE(tmp);
        return(NULL);
    }
    VIR_FREE(tmp);

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }
    def->type = type;
    switch (type) {
        case VIR_INTERFACE_TYPE_ETHERNET:
            if (virInterfaceDefParseBasicAttrs(conn, def, ctxt) < 0)
                goto error;
            tmp = virXPathString(conn, "string(./mac/@address)", ctxt);
            if (tmp != NULL)
                def->mac = tmp;
            if (virInterfaceDefParseStartMode(conn, def, ctxt) < 0)
                goto error;
            if (virInterfaceDefParseIfAdressing(conn, def, ctxt) < 0)
                goto error;
            break;
        case VIR_INTERFACE_TYPE_BRIDGE: {
            xmlNodePtr bridge;

            if (virInterfaceDefParseStartMode(conn, def, ctxt) < 0)
                goto error;
            if (virInterfaceDefParseBasicAttrs(conn, def, ctxt) < 0)
                goto error;
            if (virInterfaceDefParseIfAdressing(conn, def, ctxt) < 0)
                goto error;

            bridge = virXPathNode(conn, "./bridge[1]", ctxt);
            if (bridge == NULL) {
                virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
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
                    virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                          _("bridge interface stp should be on or off got %s"),
                                            tmp);
                    VIR_FREE(tmp);
                    goto error;
                }
                VIR_FREE(tmp);
            }
            ctxt->node = bridge;
            virInterfaceDefParseBridge(conn, def, ctxt);
            break;
        }
        case VIR_INTERFACE_TYPE_BOND: {
            xmlNodePtr bond;

            if (virInterfaceDefParseBasicAttrs(conn, def, ctxt) < 0)
                goto error;
            if (virInterfaceDefParseStartMode(conn, def, ctxt) < 0)
                goto error;
            if (virInterfaceDefParseIfAdressing(conn, def, ctxt) < 0)
                goto error;
            bond = virXPathNode(conn, "./bond[1]", ctxt);
            if (bond == NULL) {
                virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                            "%s", _("bond interface misses the bond element"));
                goto error;
            }
            ctxt->node = bond;
            if (virInterfaceDefParseBond(conn, def, ctxt)  < 0)
                goto error;
            break;
        }
        case VIR_INTERFACE_TYPE_VLAN: {
            xmlNodePtr vlan;

            tmp = virXPathString(conn, "string(./@name)", ctxt);
            if (tmp != NULL)
                def->name = tmp;
            if (virInterfaceDefParseStartMode(conn, def, ctxt) < 0)
                goto error;
            if (virInterfaceDefParseIfAdressing(conn, def, ctxt) < 0)
                goto error;
            vlan = virXPathNode(conn, "./vlan[1]", ctxt);
            if (vlan == NULL) {
                virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                            "%s", _("vlan interface misses the vlan element"));
                goto error;
            }
            ctxt->node = vlan;
            if (virInterfaceDefParseVlan(conn, def, ctxt)  < 0)
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

virInterfaceDefPtr virInterfaceDefParseNode(virConnectPtr conn,
                                        xmlDocPtr xml,
                                        xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virInterfaceDefPtr def = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "interface")) {
        virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("incorrect root element"));
        return NULL;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    ctxt->node = root;
    def = virInterfaceDefParseXML(conn, ctxt);

cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}

/* Called from SAX on parsing errors in the XML. */
static void
catchXMLError (void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    if (ctxt) {
        virConnectPtr conn = ctxt->_private;

        if (conn &&
            conn->err.code == VIR_ERR_NONE &&
            ctxt->lastError.level == XML_ERR_FATAL &&
            ctxt->lastError.message != NULL) {
            virInterfaceReportError (conn, VIR_ERR_XML_DETAIL,
                                     _("at line %d: %s"),
                                     ctxt->lastError.line,
                                     ctxt->lastError.message);
        }
    }
}

virInterfaceDefPtr virInterfaceDefParseString(virConnectPtr conn,
                                          const char *xmlStr)
{
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr root;
    virInterfaceDefPtr def = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    xml = xmlCtxtReadDoc (pctxt, BAD_CAST xmlStr, "interface.xml", NULL,
                          XML_PARSE_NOENT | XML_PARSE_NONET |
                          XML_PARSE_NOWARNING);
    if (!xml) {
        if (conn && conn->err.code == VIR_ERR_NONE)
              virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                    "%s", _("failed to parse xml document"));
        goto cleanup;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    def = virInterfaceDefParseNode(conn, xml, root);

cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc (xml);
    return def;
}

virInterfaceDefPtr virInterfaceDefParseFile(virConnectPtr conn,
                                        const char *filename)
{
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr root;
    virInterfaceDefPtr def = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    xml = xmlCtxtReadFile (pctxt, filename, NULL,
                           XML_PARSE_NOENT | XML_PARSE_NONET |
                           XML_PARSE_NOWARNING);
    if (!xml) {
        if (conn && conn->err.code == VIR_ERR_NONE)
              virInterfaceReportError(conn, VIR_ERR_XML_ERROR,
                                    "%s", _("failed to parse xml document"));
        goto cleanup;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("missing root element"));
        goto cleanup;
    }

    def = virInterfaceDefParseNode(conn, xml, root);

cleanup:
    xmlFreeParserCtxt (pctxt);
    xmlFreeDoc (xml);
    return def;
}

static int
virInterfaceBareDevDefFormat(virConnectPtr conn ATTRIBUTE_UNUSED,
                             virBufferPtr buf,
                             const virInterfaceBareDefPtr def) {
    if (def->type == VIR_INTERFACE_TYPE_ETHERNET) {
        if (def->name == NULL) {
            virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("bare ethernet has no name"));
            return(-1);
        }
        virBufferVSprintf(buf, "    <interface type='ethernet' name='%s'",
                          def->name);
        if (def->mac_or_tag != NULL) {
            virBufferVSprintf(buf, ">\n      <mac address='%s'/>\n",
                              def->mac_or_tag);
            virBufferAddLit(buf, "    </interface>\n");
        } else {
            virBufferAddLit(buf, "/>\n");
        }
    } else if (def->type == VIR_INTERFACE_TYPE_VLAN) {
        virBufferAddLit(buf, "    <interface type='vlan'");
        if (def->name != NULL)
            virBufferVSprintf(buf, " name='%s'", def->name);
        if (def->mac_or_tag != NULL) {
            virBufferAddLit(buf, ">\n");
            virBufferVSprintf(buf, "      <vlan tag='%s'", def->mac_or_tag);
            if (def->devname != NULL) {
                virBufferAddLit(buf, ">\n");
                virBufferVSprintf(buf, "        <interface  name='%s'/>\n",
                                  def->devname);
                virBufferAddLit(buf, "      </vlan>\n");
            } else
                virBufferAddLit(buf, "/>\n");
            virBufferAddLit(buf, "    </interface>\n");
        } else {
            virBufferAddLit(buf, "/>\n");
        }
    } else {
        virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                _("bare interface type %d unknown"),
                                def->type);
        return(-1);
    }
    return(0);
}

static int
virInterfaceBridgeDefFormat(virConnectPtr conn, virBufferPtr buf,
                            const virInterfaceDefPtr def) {
    int i;
    int ret = 0;

    if (def->data.bridge.stp == 1)
        virBufferAddLit(buf, "  <bridge stp='on'>\n");
    else if (def->data.bridge.stp == 0)
        virBufferAddLit(buf, "  <bridge stp='off'>\n");
    else
        virBufferAddLit(buf, "  <bridge>\n");

    for (i = 0;i < def->data.bridge.nbItf;i++) {
        if (virInterfaceBareDevDefFormat(conn, buf, def->data.bridge.itf[i])
            < 0)
            ret = -1;
    }

    virBufferAddLit(buf, "  </bridge>\n");
    return(ret);
}

static int
virInterfaceBondDefFormat(virConnectPtr conn, virBufferPtr buf,
                            const virInterfaceDefPtr def) {
    int i;
    int ret = 0;

    virBufferAddLit(buf, "  <bond");
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
        virBufferVSprintf(buf, "    <miimon freq='%d'",
                          def->data.bond.frequency);
        if (def->data.bond.downdelay > 0)
            virBufferVSprintf(buf, " downdelay='%d'", def->data.bond.downdelay);
        if (def->data.bond.updelay > 0)
            virBufferVSprintf(buf, " updelay='%d'", def->data.bond.updelay);
        if (def->data.bond.carrier == VIR_INTERFACE_BOND_MII_IOCTL)
            virBufferAddLit(buf, " carrier='ioctl'");
        else if (def->data.bond.carrier == VIR_INTERFACE_BOND_MII_NETIF)
            virBufferAddLit(buf, " carrier='netif'");
        virBufferAddLit(buf, "/>\n");
    } else if (def->data.bond.monit == VIR_INTERFACE_BOND_MONIT_ARP) {
        if (def->data.bond.target == NULL) {
            virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                          "%s", _("bond arp monitoring has no target"));
            return(-1);
        }
        virBufferVSprintf(buf, "    <arpmon interval='%d' target='%s'",
                          def->data.bond.interval, def->data.bond.target);
        if (def->data.bond.validate == VIR_INTERFACE_BOND_ARP_ACTIVE)
            virBufferAddLit(buf, " validate='active'");
        else if (def->data.bond.validate == VIR_INTERFACE_BOND_ARP_BACKUP)
            virBufferAddLit(buf, " validate='backup'");
        else if (def->data.bond.validate == VIR_INTERFACE_BOND_ARP_ALL)
            virBufferAddLit(buf, " validate='all'");
        virBufferAddLit(buf, "/>\n");
    } else {
        virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                _("bond monitoring type %d unknown"),
                                def->data.bond.monit);
        return(-1);
    }
    for (i = 0;i < def->data.bond.nbItf;i++) {
        if (virInterfaceBareDevDefFormat(conn, buf, def->data.bond.itf[i]) < 0)
            ret = -1;
    }

    virBufferAddLit(buf, "  </bond>\n");
    return(ret);
}

static int
virInterfaceVlanDefFormat(virConnectPtr conn, virBufferPtr buf,
                            const virInterfaceDefPtr def) {
    if (def->data.vlan.tag == NULL) {
        virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                "%s", _("vlan misses the tag name"));
        return(-1);
    }

    virBufferVSprintf(buf, "  <vlan tag='%s'", def->data.vlan.tag);
    if (def->data.vlan.devname != NULL) {
        virBufferAddLit(buf, ">\n");
        virBufferVSprintf(buf, "    <interface name='%s'/>\n",
                          def->data.vlan.devname);
        virBufferAddLit(buf, "  </vlan>\n");
    } else
        virBufferAddLit(buf, "/>\n");
    return(0);
}

static int
virInterfaceProtocolDefFormat(virConnectPtr conn ATTRIBUTE_UNUSED,
                              virBufferPtr buf, const virInterfaceDefPtr def) {
    if (def->proto.family == NULL)
        return(0);
    virBufferVSprintf(buf, "  <protocol family='%s'>\n", def->proto.family);
    if (def->proto.dhcp) {
        if (def->proto.peerdns == 0)
            virBufferAddLit(buf, "    <dhcp peerdns='no'/>\n");
        else if (def->proto.peerdns == 1)
            virBufferAddLit(buf, "    <dhcp peerdns='yes'/>\n");
        else
            virBufferAddLit(buf, "    <dhcp/>\n");
    } else {
        /* theorically if we don't have dhcp we should have an address */
        if (def->proto.address != NULL) {
            if (def->proto.prefix != 0)
                virBufferVSprintf(buf, "    <ip address='%s' prefix='%d'/>\n",
                                  def->proto.address, def->proto.prefix);
            else
                virBufferVSprintf(buf, "    <ip address='%s'/>\n",
                                  def->proto.address);
        }
        if (def->proto.gateway != NULL) {
            virBufferVSprintf(buf, "    <route gateway='%s'/>\n",
                              def->proto.gateway);
        }
    }
    virBufferAddLit(buf, "  </protocol>\n");
    return(0);
}

static int
virInterfaceStartmodeDefFormat(virConnectPtr conn, virBufferPtr buf,
                               enum virInterfaceStartMode startmode) {
    const char *mode;
    switch (startmode) {
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
            virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("virInterfaceDefFormat unknown startmode"));
            return -1;
    }
    virBufferVSprintf(buf, "  <start mode='%s'/>\n", mode);
    return(0);
}

char *virInterfaceDefFormat(virConnectPtr conn,
                          const virInterfaceDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *type = NULL, *tmp;

    if ((def == NULL) ||
        ((def->name == NULL) && (def->type != VIR_INTERFACE_TYPE_VLAN))) {
        virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("virInterfaceDefFormat argument problems"));
        goto cleanup;
    }

    if (!(type = virInterfaceTypeToString(def->type))) {
        virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                        _("unexpected interface type %d"), def->type);
        goto cleanup;
    }

    virBufferVSprintf(&buf, "<interface type='%s' ", type);
    if (def->name != NULL)
        virBufferEscapeString(&buf, "name='%s'", def->name);
    virBufferAddLit(&buf, ">\n");

    switch (def->type) {
        case VIR_INTERFACE_TYPE_ETHERNET:
            virInterfaceStartmodeDefFormat(conn, &buf, def->startmode);
            if (def->mac != NULL)
                virBufferVSprintf(&buf, "  <mac address='%s'/>\n", def->mac);
            if (def->mtu != 0)
                virBufferVSprintf(&buf, "  <mtu size='%d'/>\n", def->mtu);
            virInterfaceProtocolDefFormat(conn, &buf, def);
            break;
        case VIR_INTERFACE_TYPE_BRIDGE:
            virInterfaceStartmodeDefFormat(conn, &buf, def->startmode);
            if (def->mtu != 0)
                virBufferVSprintf(&buf, "  <mtu size='%d'/>\n", def->mtu);
            virInterfaceProtocolDefFormat(conn, &buf, def);
            virInterfaceBridgeDefFormat(conn, &buf, def);
            break;
        case VIR_INTERFACE_TYPE_BOND:
            virInterfaceStartmodeDefFormat(conn, &buf, def->startmode);
            if (def->mtu != 0)
                virBufferVSprintf(&buf, "  <mtu size='%d'/>\n", def->mtu);
            virInterfaceProtocolDefFormat(conn, &buf, def);
            virInterfaceBondDefFormat(conn, &buf, def);
            break;
        case VIR_INTERFACE_TYPE_VLAN:
            virInterfaceStartmodeDefFormat(conn, &buf, def->startmode);
            if (def->mac != NULL)
                virBufferVSprintf(&buf, "  <mac address='%s'/>\n", def->mac);
            if (def->mtu != 0)
                virBufferVSprintf(&buf, "  <mtu size='%d'/>\n", def->mtu);
            virInterfaceProtocolDefFormat(conn, &buf, def);
            virInterfaceVlanDefFormat(conn, &buf, def);
            break;
    }

    virBufferAddLit(&buf, "</interface>\n");

    if (virBufferError(&buf))
        goto no_memory;
    return virBufferContentAndReset(&buf);

no_memory:
    virReportOOMError(conn);
cleanup:
    tmp = virBufferContentAndReset(&buf);
    VIR_FREE(tmp);
    return NULL;
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

virInterfaceObjPtr virInterfaceAssignDef(virConnectPtr conn,
                                         virInterfaceObjListPtr interfaces,
                                         const virInterfaceDefPtr def)
{
    virInterfaceObjPtr iface;

    if ((iface = virInterfaceFindByName(interfaces, def->name))) {
        if (iface->def)
            virInterfaceDefFree(iface->def);
        iface->def = def;

        return iface;
    }

    if (VIR_ALLOC(iface) < 0) {
        virReportOOMError(conn);
        return NULL;
    }
    if (virMutexInit(&iface->lock) < 0) {
        virInterfaceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                "%s", _("cannot initialize mutex"));
        VIR_FREE(iface);
        return NULL;
    }
    virInterfaceObjLock(iface);
    iface->def = def;

    if (VIR_REALLOC_N(interfaces->objs, interfaces->count + 1) < 0) {
        virReportOOMError(conn);
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
