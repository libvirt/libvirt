/*
 * network_conf.c: network XML handling
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "virerror.h"
#include "network_conf.h"
#include "netdev_vport_profile_conf.h"
#include "netdev_bandwidth_conf.h"
#include "netdev_vlan_conf.h"
#include "viralloc.h"
#include "virxml.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

VIR_ENUM_IMPL(virNetworkForward,
              VIR_NETWORK_FORWARD_LAST,
              "none", "nat", "route", "open",
              "bridge", "private", "vepa", "passthrough",
              "hostdev",
);

VIR_ENUM_IMPL(virNetworkBridgeMACTableManager,
              VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_LAST,
              "default", "kernel", "libvirt",
);

VIR_ENUM_DECL(virNetworkForwardHostdevDevice);
VIR_ENUM_IMPL(virNetworkForwardHostdevDevice,
              VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_LAST,
              "none", "pci", "netdev",
);

VIR_ENUM_IMPL(virNetworkForwardDriverName,
              VIR_NETWORK_FORWARD_DRIVER_NAME_LAST,
              "default",
              "kvm",
              "vfio",
);

VIR_ENUM_IMPL(virNetworkTaint,
              VIR_NETWORK_TAINT_LAST,
              "hook-script",
);

VIR_ENUM_IMPL(virNetworkDHCPLeaseTimeUnit,
              VIR_NETWORK_DHCP_LEASETIME_UNIT_LAST,
              "seconds",
              "minutes",
              "hours",
);

static virClass *virNetworkXMLOptionClass;

static void
virNetworkXMLOptionDispose(void *obj G_GNUC_UNUSED)
{
    return;
}

static int
virNetworkXMLOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetworkXMLOption, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetworkXML);

virNetworkXMLOption *
virNetworkXMLOptionNew(virXMLNamespace *xmlns)
{
    virNetworkXMLOption *xmlopt;

    if (virNetworkXMLInitialize() < 0)
        return NULL;

    if (!(xmlopt = virObjectNew(virNetworkXMLOptionClass)))
        return NULL;

    if (xmlns)
        xmlopt->ns = *xmlns;

    return xmlopt;
}

static void
virPortGroupDefClear(virPortGroupDef *def)
{
    VIR_FREE(def->name);
    VIR_FREE(def->virtPortProfile);
    g_clear_pointer(&def->bandwidth, virNetDevBandwidthFree);
    virNetDevVlanClear(&def->vlan);
}


static void
virNetworkForwardIfDefClear(virNetworkForwardIfDef *def)
{
    if (def->type == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV)
        VIR_FREE(def->device.dev);
}


static void
virNetworkForwardPfDefClear(virNetworkForwardPfDef *def)
{
    VIR_FREE(def->dev);
}


static void
virNetworkDHCPLeaseTimeDefClear(virNetworkDHCPLeaseTimeDef *lease)
{
    VIR_FREE(lease);
}


static void
virNetworkDHCPHostDefClear(virNetworkDHCPHostDef *def)
{
    VIR_FREE(def->mac);
    VIR_FREE(def->id);
    VIR_FREE(def->name);
    VIR_FREE(def->lease);
}


static void
virNetworkIPDefClear(virNetworkIPDef *def)
{
    VIR_FREE(def->family);

    while (def->nranges)
        virNetworkDHCPLeaseTimeDefClear(def->ranges[--def->nranges].lease);
    VIR_FREE(def->ranges);

    while (def->nhosts)
        virNetworkDHCPHostDefClear(&def->hosts[--def->nhosts]);

    VIR_FREE(def->hosts);
    VIR_FREE(def->tftproot);
    VIR_FREE(def->bootfile);
}


static void
virNetworkDNSTxtDefClear(virNetworkDNSTxtDef *def)
{
    VIR_FREE(def->name);
    VIR_FREE(def->value);
}


static void
virNetworkDNSHostDefClear(virNetworkDNSHostDef *def)
{
    while (def->nnames)
        VIR_FREE(def->names[--def->nnames]);
    VIR_FREE(def->names);
}


static void
virNetworkDNSSrvDefClear(virNetworkDNSSrvDef *def)
{
    VIR_FREE(def->domain);
    VIR_FREE(def->service);
    VIR_FREE(def->protocol);
    VIR_FREE(def->target);
}


static void
virNetworkDNSForwarderClear(virNetworkDNSForwarder *def)
{
    VIR_FREE(def->domain);
}


static void
virNetworkDNSDefClear(virNetworkDNSDef *def)
{
    if (def->forwarders) {
        while (def->nfwds)
            virNetworkDNSForwarderClear(&def->forwarders[--def->nfwds]);
        VIR_FREE(def->forwarders);
    }
    if (def->txts) {
        while (def->ntxts)
            virNetworkDNSTxtDefClear(&def->txts[--def->ntxts]);
        VIR_FREE(def->txts);
    }
    if (def->hosts) {
        while (def->nhosts)
            virNetworkDNSHostDefClear(&def->hosts[--def->nhosts]);
        VIR_FREE(def->hosts);
    }
    if (def->srvs) {
        while (def->nsrvs)
            virNetworkDNSSrvDefClear(&def->srvs[--def->nsrvs]);
        VIR_FREE(def->srvs);
    }
}


static void
virNetworkForwardDefClear(virNetworkForwardDef *def)
{
    size_t i;

    for (i = 0; i < def->npfs && def->pfs; i++)
        virNetworkForwardPfDefClear(&def->pfs[i]);
    VIR_FREE(def->pfs);

    for (i = 0; i < def->nifs && def->ifs; i++)
        virNetworkForwardIfDefClear(&def->ifs[i]);
    VIR_FREE(def->ifs);
    def->nifs = def->npfs = 0;
}


void
virNetworkDefFree(virNetworkDef *def)
{
    size_t i;

    if (!def)
        return;

    g_free(def->name);
    g_free(def->bridge);
    g_free(def->bridgeZone);
    g_free(def->domain);

    virNetworkForwardDefClear(&def->forward);

    for (i = 0; i < def->nips && def->ips; i++)
        virNetworkIPDefClear(&def->ips[i]);
    g_free(def->ips);

    for (i = 0; i < def->nroutes && def->routes; i++)
        virNetDevIPRouteFree(def->routes[i]);
    g_free(def->routes);

    for (i = 0; i < def->nPortGroups && def->portGroups; i++)
        virPortGroupDefClear(&def->portGroups[i]);
    g_free(def->portGroups);

    virNetworkDNSDefClear(&def->dns);

    g_free(def->virtPortProfile);

    virNetDevBandwidthFree(def->bandwidth);
    virNetDevVlanClear(&def->vlan);

    g_free(def->title);
    g_free(def->description);
    xmlFreeNode(def->metadata);

    if (def->namespaceData && def->ns.free)
        (def->ns.free)(def->namespaceData);
    g_free(def);
}


/*
 * virNetworkDefCopy:
 * @def: NetworkDef to copy
 * @flags: VIR_NETWORK_XML_INACTIVE if appropriate
 *
 * make a deep copy of the given NetworkDef
 *
 * Returns a new NetworkDef on success, or NULL on failure.
 */
virNetworkDef *
virNetworkDefCopy(virNetworkDef *def,
                  virNetworkXMLOption *xmlopt,
                  unsigned int flags)
{
    g_autofree char *xml = NULL;

    if (!def) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("NULL NetworkDef"));
        return NULL;
    }

    /* deep copy with a format/parse cycle */
    if (!(xml = virNetworkDefFormat(def, xmlopt, flags)))
       return NULL;

    return virNetworkDefParse(xml, NULL, xmlopt, false);
}


/* return ips[index], or NULL if there aren't enough ips */
virNetworkIPDef *
virNetworkDefGetIPByIndex(const virNetworkDef *def,
                          int family,
                          size_t n)
{
    size_t i;

    if (!def->ips || n >= def->nips)
        return NULL;

    if (family == AF_UNSPEC)
        return &def->ips[n];

    /* find the nth ip of type "family" */
    for (i = 0; i < def->nips; i++) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&def->ips[i].address, family)
            && (n-- <= 0)) {
            return &def->ips[i];
        }
    }
    /* failed to find enough of the right family */
    return NULL;
}


/* return routes[index], or NULL if there aren't enough routes */
virNetDevIPRoute *
virNetworkDefGetRouteByIndex(const virNetworkDef *def,
                             int family,
                             size_t n)
{
    size_t i;

    if (!def->routes || n >= def->nroutes)
        return NULL;

    if (family == AF_UNSPEC)
        return def->routes[n];

    /* find the nth route of type "family" */
    for (i = 0; i < def->nroutes; i++) {
        virSocketAddr *addr = virNetDevIPRouteGetAddress(def->routes[i]);
        if (VIR_SOCKET_ADDR_IS_FAMILY(addr, family)
            && (n-- <= 0)) {
            return def->routes[i];
        }
    }

    /* failed to find enough of the right family */
    return NULL;
}


/* return number of 1 bits in netmask for the network's ipAddress,
 * or -1 on error
 */
int
virNetworkIPDefPrefix(const virNetworkIPDef *def)
{
    return virSocketAddrGetIPPrefix(&def->address,
                                    &def->netmask,
                                    def->prefix);
}


/* Fill in a virSocketAddr with the proper netmask for this
 * definition, based on either the definition's netmask, or its
 * prefix. Return -1 on error (and set the netmask family to AF_UNSPEC)
 */
int virNetworkIPDefNetmask(const virNetworkIPDef *def,
                           virSocketAddr *netmask)
{
    if (VIR_SOCKET_ADDR_IS_FAMILY(&def->netmask, AF_INET)) {
        *netmask = def->netmask;
        return 0;
    }

    return virSocketAddrPrefixToNetmask(virNetworkIPDefPrefix(def), netmask,
                                        VIR_SOCKET_ADDR_FAMILY(&def->address));
}


static int
virNetworkDHCPLeaseTimeDefParseXML(virNetworkDHCPLeaseTimeDef **lease,
                                   xmlNodePtr node)
{
    virNetworkDHCPLeaseTimeDef *new_lease = NULL;
    unsigned long long expiry;
    virNetworkDHCPLeaseTimeUnitType unit;
    int rc;

    if ((rc = virXMLPropULongLong(node, "expiry", 0, VIR_XML_PROP_NONE, &expiry)) < 0)
        return -1;

    if (rc == 0)
        return 0;

    if (virXMLPropEnumDefault(node, "unit",
                              virNetworkDHCPLeaseTimeUnitTypeFromString,
                              VIR_XML_PROP_NONE, &unit,
                              VIR_NETWORK_DHCP_LEASETIME_UNIT_MINUTES) < 0)
        return -1;

    /* infinite */
    if (expiry > 0) {
        /* This boundary check is related to dnsmasq man page settings:
         * "The minimum lease time is two minutes." */
        if ((unit == VIR_NETWORK_DHCP_LEASETIME_UNIT_SECONDS && expiry < 120) ||
            (unit == VIR_NETWORK_DHCP_LEASETIME_UNIT_MINUTES && expiry < 2)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("The minimum lease time should be greater than 2 minutes"));
            return -1;
        }
    }

    new_lease = g_new0(virNetworkDHCPLeaseTimeDef, 1);
    new_lease->expiry = expiry;
    new_lease->unit = unit;

    *lease = new_lease;

    return 0;
}


static int
virNetworkDHCPRangeDefParseXML(const char *networkName,
                               virNetworkIPDef *ipdef,
                               xmlNodePtr node,
                               virNetworkDHCPRangeDef *range)
{
    virSocketAddrRange *addr = &range->addr;
    xmlNodePtr lease;
    g_autofree char *start = NULL;
    g_autofree char *end = NULL;

    if (!(start = virXMLPropString(node, "start"))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing 'start' attribute in dhcp range for network '%1$s'"),
                       networkName);
        return -1;
    }
    if (virSocketAddrParse(&addr->start, start, AF_UNSPEC) < 0)
        return -1;

    if (!(end = virXMLPropString(node, "end"))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing 'end' attribute in dhcp range for network '%1$s'"),
                       networkName);
        return -1;
    }
    if (virSocketAddrParse(&addr->end, end, AF_UNSPEC) < 0)
        return -1;

    /* do a sanity check of the range */
    if (virSocketAddrGetRange(&addr->start, &addr->end, &ipdef->address,
                              virNetworkIPDefPrefix(ipdef)) < 0)
        return -1;

    if ((lease = virXMLNodeGetSubelement(node, "lease")) &&
        virNetworkDHCPLeaseTimeDefParseXML(&range->lease, lease) < 0)
        return -1;

    return 0;
}


static int
virNetworkDHCPHostDefParseXML(const char *networkName,
                              virNetworkIPDef *def,
                              xmlNodePtr node,
                              virNetworkDHCPHostDef *host,
                              bool partialOkay)
{
    g_autofree char *mac = NULL;
    g_autofree char *name = NULL;
    g_autofree char *ip = NULL;
    g_autofree char *id = NULL;
    virMacAddr addr;
    virSocketAddr inaddr;
    xmlNodePtr lease;

    mac = virXMLPropString(node, "mac");
    if (mac != NULL) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET6)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid to specify MAC address '%1$s' in network '%2$s' IPv6 static host definition"),
                           mac, networkName);
            return -1;
        }
        if (virMacAddrParse(mac, &addr) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Cannot parse MAC address '%1$s' in network '%2$s'"),
                           mac, networkName);
            return -1;
        }
        if (virMacAddrIsMulticast(&addr)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("expected unicast mac address, found multicast '%1$s' in network '%2$s'"),
                           (const char *)mac, networkName);
            return -1;
        }
    }

    id = virXMLPropString(node, "id");
    if (id) {
        char *cp = id + strspn(id, "0123456789abcdefABCDEF:");
        if (*cp) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid character '%1$c' in id '%2$s' of network '%3$s'"),
                           *cp, id, networkName);
            return -1;
        }
    }

    name = virXMLPropString(node, "name");
    if (name && !(g_ascii_isalpha(name[0]) || g_ascii_isdigit(name[0]))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Cannot use host name '%1$s' in network '%2$s'"),
                       name, networkName);
        return -1;
    }

    ip = virXMLPropString(node, "ip");
    if (ip && (virSocketAddrParse(&inaddr, ip, AF_UNSPEC) < 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid IP address in static host definition for network '%1$s'"),
                       networkName);
        return -1;
    }

    if (partialOkay) {
        /* for search/match, you just need one of the three */
        if (!(mac || name || ip)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("At least one of name, mac, or ip attribute must be specified for static host definition in network '%1$s'"),
                           networkName);
            return -1;
        }
    } else {
        /* normal usage - you need at least name (IPv6) or one of MAC
         * address or name (IPv4)
         */
        if (VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET6)) {
            if (!(id || name)) {
                virReportError(VIR_ERR_XML_ERROR,
                           _("Static host definition in IPv6 network '%1$s' must have id or name attribute"),
                           networkName);
                return -1;
            }
        } else if (!(mac || name)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Static host definition in IPv4 network '%1$s' must have mac or name attribute"),
                           networkName);
            return -1;
        }
        if (!ip) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Missing IP address in static host definition for network '%1$s'"),
                           networkName);
            return -1;
        }
    }

    if ((lease = virXMLNodeGetSubelement(node, "lease")) &&
        virNetworkDHCPLeaseTimeDefParseXML(&host->lease, lease) < 0)
        return -1;

    host->mac = g_steal_pointer(&mac);
    host->id = g_steal_pointer(&id);
    host->name = g_steal_pointer(&name);
    if (ip)
        host->ip = inaddr;

    return 0;

}


static int
virNetworkDHCPDefParseXML(const char *networkName,
                          xmlNodePtr node,
                          virNetworkIPDef *def)
{
    g_autofree xmlNodePtr *rangeNodes = NULL;
    size_t nrangeNodes = virXMLNodeGetSubelementList(node, "range", &rangeNodes);
    g_autofree xmlNodePtr *hostNodes = NULL;
    size_t nhostNodes = virXMLNodeGetSubelementList(node, "host", &hostNodes);
    xmlNodePtr bootp = virXMLNodeGetSubelement(node, "bootp");
    size_t i;

    for (i = 0; i < nrangeNodes; i++) {
        virNetworkDHCPRangeDef range = { 0 };

        if (virNetworkDHCPRangeDefParseXML(networkName, def, rangeNodes[i], &range) < 0)
            return -1;

        VIR_APPEND_ELEMENT(def->ranges, def->nranges, range);
    }

    for (i = 0; i < nhostNodes; i++) {
        virNetworkDHCPHostDef host = { 0 };

        if (virNetworkDHCPHostDefParseXML(networkName, def, hostNodes[i],
                                          &host, false) < 0)
            return -1;

        VIR_APPEND_ELEMENT(def->hosts, def->nhosts, host);
    }

    if (bootp &&
        VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET)) {
        g_autofree char *server = virXMLPropString(bootp, "server");

        if (!(def->bootfile = virXMLPropStringRequired(bootp, "file")))
            return -1;

        if (server &&
            virSocketAddrParse(&def->bootserver, server, AF_UNSPEC) < 0) {
            return -1;
        }
    }

    return 0;
}


static int
virNetworkDNSHostDefParseXML(const char *networkName,
                             xmlNodePtr node,
                             virNetworkDNSHostDef *def,
                             bool partialOkay)
{
    g_autofree xmlNodePtr *hostnameNodes = NULL;
    size_t nhostnameNodes = virXMLNodeGetSubelementList(node, "hostname", &hostnameNodes);
    size_t i;
    g_auto(GStrv) hostnames = NULL;
    g_autofree char *ip = virXMLPropString(node, "ip");

    if (nhostnameNodes > 0) {
        hostnames = g_new0(char *, nhostnameNodes + 1);

        for (i = 0; i < nhostnameNodes; i++) {
            if (!(hostnames[i] = virXMLNodeContentString(hostnameNodes[i])))
                return -1;

            if (*hostnames[i] == '\0') {
                virReportError(VIR_ERR_XML_DETAIL,
                               _("Missing hostname in network '%1$s' DNS HOST record"),
                               networkName);
                return -1;
            }
        }
    } else {
        if (!partialOkay) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("Missing hostname in network '%1$s' DNS HOST record"),
                           networkName);
            return -1;
        }
    }

    if (ip) {
        if (virSocketAddrParse(&def->ip, ip, AF_UNSPEC) < 0) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("Invalid IP address in network '%1$s' DNS HOST record"),
                           networkName);
            return -1;
        }
    } else {
        if (!partialOkay) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("Missing IP address in network '%1$s' DNS HOST record"),
                           networkName);
            return -1;
        }

        if (nhostnameNodes == 0) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("Missing ip and hostname in network '%1$s' DNS HOST record"),
                           networkName);
            return -1;
        }
    }

    def->names = g_steal_pointer(&hostnames);
    def->nnames = nhostnameNodes;
    return 0;
}


/* This includes all characters used in the names of current
 * /etc/services and /etc/protocols files (on Fedora 20), except ".",
 * which we can't allow because it would conflict with the use of "."
 * as a field separator in the SRV record, there appears to be no way
 * to escape it in, and the protocols/services that use "." in the
 * name are obscure and unlikely to be used anyway.
 */
#define PROTOCOL_CHARS \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" \
    "-+/"

#define SERVICE_CHARS \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" \
    "_-+/*"

static int
virNetworkDNSSrvDefParseXML(const char *networkName,
                            xmlNodePtr node,
                            xmlXPathContextPtr ctxt,
                            virNetworkDNSSrvDef *def,
                            bool partialOkay)
{
    int ret;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (!(def->service = virXMLPropString(node, "service")) && !partialOkay) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("missing required service attribute in DNS SRV record of network '%1$s'"),
                       networkName);
        goto error;
    }
    if (def->service) {
        if (strlen(def->service) > DNS_RECORD_LENGTH_SRV) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("service attribute '%1$s' in network '%2$s' is too long, limit is %3$d bytes"),
                           def->service, networkName, DNS_RECORD_LENGTH_SRV);
            goto error;
        }
        if (strspn(def->service, SERVICE_CHARS) < strlen(def->service)) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("invalid character in service attribute '%1$s' in DNS SRV record of network '%2$s'"),
                           def->service, networkName);
            goto error;
        }
    }

    if (!(def->protocol = virXMLPropString(node, "protocol")) && !partialOkay) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("missing required protocol attribute in DNS SRV record '%1$s' of network '%2$s'"),
                       def->service, networkName);
        goto error;
    }
    if (def->protocol &&
        strspn(def->protocol, PROTOCOL_CHARS) < strlen(def->protocol)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("invalid character in protocol attribute '%1$s' in DNS SRV record of network '%2$s'"),
                       def->protocol, networkName);
        goto error;
    }

    /* Following attributes are optional */
    def->domain = virXMLPropString(node, "domain");
    def->target = virXMLPropString(node, "target");

    ret = virXPathUInt("string(./@port)", ctxt, &def->port);
    if (ret >= 0 && !def->target) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("DNS SRV port attribute not permitted without target for service '%1$s' in network '%2$s'"),
                       def->service, networkName);
        goto error;
    }
    if (ret == -2 || (ret >= 0 && (def->port < 1 || def->port > 65535))) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("invalid DNS SRV port attribute for service '%1$s' in network '%2$s'"),
                       def->service, networkName);
        goto error;
    }

    ret = virXPathUInt("string(./@priority)", ctxt, &def->priority);
    if (ret >= 0 && !def->target) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("DNS SRV priority attribute not permitted without target for service '%1$s' in network '%2$s'"),
                       def->service, networkName);
        goto error;
    }
    if (ret == -2 || (ret >= 0 && def->priority > 65535)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Invalid DNS SRV priority attribute for service '%1$s' in network '%2$s'"),
                       def->service, networkName);
        goto error;
    }

    ret = virXPathUInt("string(./@weight)", ctxt, &def->weight);
    if (ret >= 0 && !def->target) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("DNS SRV weight attribute not permitted without target for service '%1$s' in network '%2$s'"),
                       def->service, networkName);
        goto error;
    }
    if (ret == -2 || (ret >= 0 && def->weight > 65535)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("invalid DNS SRV weight attribute for service '%1$s' in network '%2$s'"),
                       def->service, networkName);
        goto error;
    }

    return 0;

 error:
    virNetworkDNSSrvDefClear(def);
    return -1;
}


static int
virNetworkDNSTxtDefParseXML(const char *networkName,
                            xmlNodePtr node,
                            virNetworkDNSTxtDef *def,
                            bool partialOkay)
{
    const char *bad = " ,";

    if (!(def->name = virXMLPropString(node, "name"))) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("missing required name attribute in DNS TXT record of network %1$s"),
                       networkName);
        goto error;
    }
    if (strcspn(def->name, bad) != strlen(def->name)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("prohibited character in DNS TXT record name '%1$s' of network %2$s"),
                       def->name, networkName);
        goto error;
    }
    if (!(def->value = virXMLPropString(node, "value")) && !partialOkay) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("missing required value attribute in DNS TXT record named '%1$s' of network %2$s"),
                       def->name, networkName);
        goto error;
    }

    if (!(def->name || def->value)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Missing required name or value in DNS TXT record of network %1$s"),
                       networkName);
        goto error;
    }
    return 0;

 error:
    virNetworkDNSTxtDefClear(def);
    return -1;
}


static int
virNetworkDNSDefParseXML(const char *networkName,
                         xmlNodePtr node,
                         xmlXPathContextPtr ctxt,
                         virNetworkDNSDef *def)
{
    g_autofree xmlNodePtr *hostNodes = NULL;
    g_autofree xmlNodePtr *srvNodes = NULL;
    g_autofree xmlNodePtr *txtNodes = NULL;
    g_autofree xmlNodePtr *fwdNodes = NULL;
    int nhosts, nsrvs, ntxts, nfwds;
    size_t i;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (virXMLPropTristateBool(node, "enable",
                               VIR_XML_PROP_NONE,
                               &def->enable) < 0)
        return -1;

    if (virXMLPropTristateBool(node, "forwardPlainNames",
                               VIR_XML_PROP_NONE,
                               &def->forwardPlainNames) < 0)
        return -1;

    nfwds = virXPathNodeSet("./forwarder", ctxt, &fwdNodes);
    if (nfwds < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <forwarder> element found in <dns> of network %1$s"),
                       networkName);
        return -1;
    }
    if (nfwds > 0) {
        def->forwarders = g_new0(virNetworkDNSForwarder, nfwds);

        for (i = 0; i < nfwds; i++) {
            g_autofree char *addr = virXMLPropString(fwdNodes[i], "addr");

            if (addr && virSocketAddrParse(&def->forwarders[i].addr,
                                           addr, AF_UNSPEC) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Invalid forwarder IP address '%1$s' in network '%2$s'"),
                               addr, networkName);
                return -1;
            }
            def->forwarders[i].domain = virXMLPropString(fwdNodes[i], "domain");
            if (!(addr || def->forwarders[i].domain)) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Invalid forwarder element, must contain at least one of addr or domain"));
                return -1;
            }
            def->nfwds++;
        }
    }

    nhosts = virXPathNodeSet("./host", ctxt, &hostNodes);
    if (nhosts < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <host> element found in <dns> of network %1$s"),
                       networkName);
        return -1;
    }
    if (nhosts > 0) {
        def->hosts = g_new0(virNetworkDNSHostDef, nhosts);

        for (i = 0; i < nhosts; i++) {
            if (virNetworkDNSHostDefParseXML(networkName, hostNodes[i],
                                             &def->hosts[def->nhosts], false) < 0) {
                return -1;
            }
            def->nhosts++;
        }
    }

    nsrvs = virXPathNodeSet("./srv", ctxt, &srvNodes);
    if (nsrvs < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <srv> element found in <dns> of network %1$s"),
                       networkName);
        return -1;
    }
    if (nsrvs > 0) {
        def->srvs = g_new0(virNetworkDNSSrvDef, nsrvs);

        for (i = 0; i < nsrvs; i++) {
            if (virNetworkDNSSrvDefParseXML(networkName, srvNodes[i], ctxt,
                                            &def->srvs[def->nsrvs], false) < 0) {
                return -1;
            }
            def->nsrvs++;
        }
    }

    ntxts = virXPathNodeSet("./txt", ctxt, &txtNodes);
    if (ntxts < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <txt> element found in <dns> of network %1$s"),
                       networkName);
        return -1;
    }
    if (ntxts > 0) {
        def->txts = g_new0(virNetworkDNSTxtDef, ntxts);

        for (i = 0; i < ntxts; i++) {
            if (virNetworkDNSTxtDefParseXML(networkName, txtNodes[i],
                                            &def->txts[def->ntxts], false) < 0) {
                return -1;
            }
            def->ntxts++;
        }
    }

    if (def->enable == VIR_TRISTATE_BOOL_NO &&
        (nfwds || nhosts || nsrvs || ntxts)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Extra data in disabled network '%1$s'"),
                       networkName);
        return -1;
    }

    return 0;
}


static int
virNetworkIPDefParseXML(const char *networkName,
                        xmlNodePtr node,
                        xmlXPathContextPtr ctxt,
                        virNetworkIPDef *def)
{
    /*
     * virNetworkIPDef object is already allocated as part of an array.
     * On failure clear it out, but don't free it.
     */

    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr dhcp;
    g_autofree char *address = NULL;
    g_autofree char *netmask = NULL;
    int ret = -1;

    ctxt->node = node;

    /* grab raw data from XML */
    def->family = virXPathString("string(./@family)", ctxt);

    address = virXPathString("string(./@address)", ctxt);
    if (!address) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing required address attribute in network '%1$s'"),
                       networkName);
        goto cleanup;
    }
    if (virSocketAddrParse(&def->address, address, AF_UNSPEC) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid address '%1$s' in network '%2$s'"),
                       address, networkName);
        goto cleanup;
    }

    netmask = virXPathString("string(./@netmask)", ctxt);
    if (netmask &&
        (virSocketAddrParse(&def->netmask, netmask, AF_UNSPEC) < 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid netmask '%1$s' in network '%2$s'"),
                       netmask, networkName);
        goto cleanup;
    }

    if (virXMLPropUInt(node, "prefix", 10, VIR_XML_PROP_NONE, &def->prefix) < 0)
        goto cleanup;

    if (virXMLPropTristateBool(node, "localPtr",
                               VIR_XML_PROP_NONE,
                               &def->localPTR) < 0)
        goto cleanup;

    /* validate address, etc. for each family */
    if ((def->family == NULL) || (STREQ(def->family, "ipv4"))) {
        if (!(VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET) ||
              VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_UNSPEC))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%1$s family specified for non-IPv4 address '%2$s' in network '%3$s'"),
                           def->family == NULL? "no" : "ipv4", address, networkName);
            goto cleanup;
        }
        if (netmask) {
            if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->netmask, AF_INET)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid netmask '%1$s' for address '%2$s' in network '%3$s' (both must be IPv4)"),
                               netmask, address, networkName);
                goto cleanup;
            }
            if (def->prefix > 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Network '%1$s' IP address cannot have both a prefix and a netmask"),
                               networkName);
                goto cleanup;
            }
        } else if (def->prefix > 32) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid IPv4 prefix '%1$u' in network '%2$s'"),
                           def->prefix, networkName);
            goto cleanup;
        }
    } else if (STREQ(def->family, "ipv6")) {
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET6)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Family 'ipv6' specified for non-IPv6 address '%1$s' in network '%2$s'"),
                           address, networkName);
            goto cleanup;
        }
        if (netmask) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("netmask not allowed for IPv6 address '%1$s' in network '%2$s'"),
                           address, networkName);
            goto cleanup;
        }
        if (def->prefix > 128) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid IPv6 prefix '%1$u' in network '%2$s'"),
                           def->prefix, networkName);
            goto cleanup;
        }
    } else {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unrecognized family '%1$s' in network '%2$s'"),
                       def->family, networkName);
        goto cleanup;
    }

    if ((dhcp = virXPathNode("./dhcp[1]", ctxt)) &&
        virNetworkDHCPDefParseXML(networkName, dhcp, def) < 0)
        goto cleanup;

    if (virXPathNode("./tftp[1]", ctxt)) {
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported <tftp> element in an IPv6 element in network '%1$s'"),
                           networkName);
            goto cleanup;
        }

        def->tftproot = virXPathString("string(./tftp[1]/@root)", ctxt);
    }

    ret = 0;

 cleanup:
    if (ret < 0)
        virNetworkIPDefClear(def);

    return ret;
}


int
virNetworkPortOptionsParseXML(xmlXPathContextPtr ctxt,
                              virTristateBool *isolatedPort)
{
    xmlNodePtr port_node = virXPathNode("./port", ctxt);

    return virXMLPropTristateBool(port_node, "isolated",
                                  VIR_XML_PROP_NONE,
                                  isolatedPort);
}


static int
virNetworkPortGroupParseXML(virPortGroupDef *def,
                            xmlNodePtr node,
                            xmlXPathContextPtr ctxt)
{
    /*
     * virPortGroupDef object is already allocated as part of an array.
     * On failure clear it out, but don't free it.
     */

    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr virtPortNode;
    xmlNodePtr vlanNode;
    xmlNodePtr bandwidth_node;
    g_autofree char *isDefault = NULL;

    int ret = -1;

    ctxt->node = node;

    /* grab raw data from XML */
    def->name = virXPathString("string(./@name)", ctxt);
    if (!def->name) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing required name attribute in portgroup"));
        goto cleanup;
    }

    isDefault = virXPathString("string(./@default)", ctxt);
    def->isDefault = isDefault && STRCASEEQ(isDefault, "yes");

    if (virXMLPropTristateBool(node, "trustGuestRxFilters",
                               VIR_XML_PROP_NONE,
                               &def->trustGuestRxFilters) < 0)
        goto cleanup;

    virtPortNode = virXPathNode("./virtualport", ctxt);
    if (virtPortNode &&
        (!(def->virtPortProfile = virNetDevVPortProfileParse(virtPortNode, 0)))) {
        goto cleanup;
    }

    bandwidth_node = virXPathNode("./bandwidth", ctxt);
    if (bandwidth_node &&
        virNetDevBandwidthParse(&def->bandwidth, NULL, bandwidth_node, false) < 0)
        goto cleanup;

    vlanNode = virXPathNode("./vlan", ctxt);
    if (vlanNode && virNetDevVlanParse(vlanNode, ctxt, &def->vlan) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0)
        virPortGroupDefClear(def);

    return ret;
}


static int
virNetworkForwardNatDefParseXML(const char *networkName,
                                xmlNodePtr node,
                                xmlXPathContextPtr ctxt,
                                virNetworkForwardDef *def)
{
    int nNatAddrs, nNatPorts;
    g_autofree xmlNodePtr *natAddrNodes = NULL;
    g_autofree xmlNodePtr *natPortNodes = NULL;
    g_autofree char *addrStart = NULL;
    g_autofree char *addrEnd = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (def->type != VIR_NETWORK_FORWARD_NAT) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("The <nat> element can only be used when <forward> 'mode' is 'nat' in network %1$s"),
                       networkName);
        return -1;
    }

    if (virXMLPropTristateBool(node, "ipv6", VIR_XML_PROP_NONE,
                               &def->natIPv6) < 0)
        return -1;

    /* addresses for SNAT */
    nNatAddrs = virXPathNodeSet("./address", ctxt, &natAddrNodes);
    if (nNatAddrs < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <address> element found in <forward> of network %1$s"),
                       networkName);
        return -1;
    } else if (nNatAddrs > 1) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Only one <address> element is allowed in <nat> in <forward> in network %1$s"),
                       networkName);
        return -1;
    } else if (nNatAddrs == 1) {
        addrStart = virXMLPropString(*natAddrNodes, "start");
        if (addrStart == NULL) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("missing 'start' attribute in <address> element in <nat> in <forward> in network %1$s"),
                           networkName);
            return -1;
        }
        addrEnd = virXMLPropString(*natAddrNodes, "end");
        if (addrEnd == NULL) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("missing 'end' attribute in <address> element in <nat> in <forward> in network %1$s"),
                           networkName);
            return -1;
        }
    }

    if (addrStart && virSocketAddrParse(&def->addr.start, addrStart, AF_INET) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Bad ipv4 start address '%1$s' in <nat> in <forward> in network '%2$s'"),
                       addrStart, networkName);
        return -1;
    }

    if (addrEnd && virSocketAddrParse(&def->addr.end, addrEnd, AF_INET) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Bad ipv4 end address '%1$s' in <nat> in <forward> in network '%2$s'"),
                       addrEnd, networkName);
        return -1;
    }

    if (addrStart && addrEnd) {
        /* verify that start <= end */
        if (virSocketAddrGetRange(&def->addr.start, &def->addr.end, NULL, 0) < 0)
            return -1;
    } else {
        if (addrStart) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Only start address '%1$s' specified in <nat> in <forward> in network '%2$s'"),
                           addrStart, networkName);
            return -1;
        }
        if (addrEnd) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Only end address '%1$s' specified in <nat> in <forward> in network '%2$s'"),
                           addrEnd, networkName);
            return -1;
        }
    }

    /* ports for SNAT and MASQUERADE */
    nNatPorts = virXPathNodeSet("./port", ctxt, &natPortNodes);
    if (nNatPorts < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <port> element found in <forward> of network %1$s"),
                       networkName);
        return -1;
    } else if (nNatPorts > 1) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Only one <port> element is allowed in <nat> in <forward> in network %1$s"),
                       networkName);
        return -1;
    } else if (nNatPorts == 1) {
        if (virXPathUInt("string(./port[1]/@start)", ctxt, &def->port.start) < 0
            || def->port.start > 65535) {

            virReportError(VIR_ERR_XML_DETAIL,
                           _("Missing or invalid 'start' attribute in <port> in <nat> in <forward> in network %1$s"),
                           networkName);
            return -1;
        }
        if (virXPathUInt("string(./port[1]/@end)", ctxt, &def->port.end) < 0
            || def->port.end > 65535 || def->port.end < def->port.start) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("Missing or invalid 'end' attribute in <port> in <nat> in <forward> in network %1$s"),
                           networkName);
            return -1;
        }
    }
    return 0;
}


static int
virNetworkForwardDefParseXML(const char *networkName,
                             xmlNodePtr node,
                             xmlXPathContextPtr ctxt,
                             virNetworkForwardDef *def)
{
    size_t i, j;
    int nForwardIfs, nForwardAddrs, nForwardPfs, nForwardNats;
    g_autofree xmlNodePtr *forwardIfNodes = NULL;
    g_autofree xmlNodePtr *forwardPfNodes = NULL;
    g_autofree xmlNodePtr *forwardAddrNodes = NULL;
    g_autofree xmlNodePtr *forwardNatNodes = NULL;
    g_autofree char *forwardDev = NULL;
    g_autofree char *forwardManaged = NULL;
    g_autofree char *forwardDriverName = NULL;
    g_autofree char *type = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (!(type = virXPathString("string(./@mode)", ctxt))) {
        def->type = VIR_NETWORK_FORWARD_NAT;
    } else {
        if ((def->type = virNetworkForwardTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown forwarding type '%1$s'"), type);
            return -1;
        }
    }

    forwardManaged = virXPathString("string(./@managed)", ctxt);
    if (forwardManaged != NULL &&
        STRCASEEQ(forwardManaged, "yes")) {
        def->managed = true;
    }

    forwardDriverName = virXPathString("string(./driver/@name)", ctxt);
    if (forwardDriverName) {
        int driverName
            = virNetworkForwardDriverNameTypeFromString(forwardDriverName);

        if (driverName <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown forward <driver name='%1$s'/> in network %2$s"),
                           forwardDriverName, networkName);
            return -1;
        }
        def->driverName = driverName;
    }

    /* bridge and hostdev modes can use a pool of physical interfaces */
    nForwardIfs = virXPathNodeSet("./interface", ctxt, &forwardIfNodes);
    if (nForwardIfs < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <interface> element found in <forward> of network %1$s"),
                       networkName);
        return -1;
    }

    nForwardAddrs = virXPathNodeSet("./address", ctxt, &forwardAddrNodes);
    if (nForwardAddrs < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <address> element found in <forward> of network %1$s"),
                       networkName);
        return -1;
    }

    nForwardPfs = virXPathNodeSet("./pf", ctxt, &forwardPfNodes);
    if (nForwardPfs < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <pf> element found in <forward> of network %1$s"),
                       networkName);
        return -1;
    }

    nForwardNats = virXPathNodeSet("./nat", ctxt, &forwardNatNodes);
    if (nForwardNats < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <nat> element found in <forward> of network %1$s"),
                       networkName);
        return -1;
    } else if (nForwardNats > 1) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Only one <nat> element is allowed in <forward> of network %1$s"),
                       networkName);
        return -1;
    } else if (nForwardNats == 1) {
        if (virNetworkForwardNatDefParseXML(networkName,
                                            *forwardNatNodes,
                                            ctxt, def) < 0)
            return -1;
    }

    forwardDev = virXPathString("string(./@dev)", ctxt);
    if (forwardDev && (nForwardAddrs > 0 || nForwardPfs > 0)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("the <forward> 'dev' attribute cannot be used when <address> or <pf> sub-elements are present in network %1$s"));
        return -1;
    }

    if (nForwardIfs > 0 || forwardDev) {
        def->ifs = g_new0(virNetworkForwardIfDef, MAX(nForwardIfs, 1));

        if (forwardDev) {
            def->ifs[0].device.dev = g_steal_pointer(&forwardDev);
            def->ifs[0].type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV;
            def->nifs++;
        }

        /* parse each <interface> */
        for (i = 0; i < nForwardIfs; i++) {
            g_autofree char *forwardDevi = virXMLPropString(forwardIfNodes[i], "dev");

            if (!forwardDevi) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Missing required dev attribute in <forward> <interface> element of network %1$s"),
                               networkName);
                return -1;
            }

            if ((i == 0) && (def->nifs == 1)) {
                /* both <forward dev='x'> and <interface dev='x'/> are
                 * present.  If they don't match, it's an error.
                 */
                if (STRNEQ(forwardDevi, def->ifs[0].device.dev)) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("<forward dev='%1$s'> must match first <interface dev='%2$s'/> in network %3$s"),
                                   def->ifs[0].device.dev,
                                   forwardDevi, networkName);
                    return -1;
                }
                continue;
            }

            for (j = 0; j < i; j++) {
                if (STREQ_NULLABLE(def->ifs[j].device.dev, forwardDevi)) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("interface '%1$s' can only be listed once in network %2$s"),
                                   forwardDevi, networkName);
                    return -1;
                }
            }

            def->ifs[i].device.dev = g_steal_pointer(&forwardDevi);
            def->ifs[i].type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV;
            def->nifs++;
        }

    } else if (nForwardAddrs > 0) {
        def->ifs = g_new0(virNetworkForwardIfDef, nForwardAddrs);

        for (i = 0; i < nForwardAddrs; i++) {
            g_autofree char *addrType = NULL;

            if (!(addrType = virXMLPropString(forwardAddrNodes[i], "type"))) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("missing address type in network %1$s"),
                               networkName);
                return -1;
            }

            if ((def->ifs[i].type = virNetworkForwardHostdevDeviceTypeFromString(addrType)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown address type '%1$s' in network %2$s"),
                               addrType, networkName);
                return -1;
            }

            switch (def->ifs[i].type) {
            case VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI:
            {
                virPCIDeviceAddress *addr = &def->ifs[i].device.pci;

                if (virPCIDeviceAddressParseXML(forwardAddrNodes[i], addr) < 0)
                    return -1;

                for (j = 0; j < i; j++) {
                    if (virPCIDeviceAddressEqual(addr, &def->ifs[j].device.pci)) {
                        virReportError(VIR_ERR_XML_ERROR,
                                       _("PCI device '%1$04x:%2$02x:%3$02x.%4$x' can only be listed once in network %5$s"),
                                       addr->domain, addr->bus,
                                       addr->slot, addr->function,
                                       networkName);
                        return -1;
                    }
                }
                break;
            }
            /* Add USB case here if we ever find a reason to support it */

            default:
                virReportError(VIR_ERR_XML_ERROR,
                               _("unsupported address type '%1$s' in network %2$s"),
                               addrType, networkName);
                return -1;
            }
            def->nifs++;
        }

    } else if (nForwardPfs > 1) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Only one <pf> element is allowed in <forward> of network %1$s"),
                       networkName);
        return -1;
    } else if (nForwardPfs == 1) {
        def->pfs = g_new0(virNetworkForwardPfDef, nForwardPfs);

        forwardDev = virXMLPropString(*forwardPfNodes, "dev");
        if (!forwardDev) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Missing required dev attribute in <pf> element of network '%1$s'"),
                           networkName);
            return -1;
        }

        def->pfs->dev = g_steal_pointer(&forwardDev);
        def->npfs++;
    }

    return 0;
}


virNetworkDef *
virNetworkDefParseXML(xmlXPathContextPtr ctxt,
                      virNetworkXMLOption *xmlopt)
{
    g_autoptr(virNetworkDef) def = NULL;
    g_autofree char *uuid = NULL;
    g_autofree char *stp = NULL;
    g_autofree char *stpDelay = NULL;
    g_autofree char *macTableManager = NULL;
    g_autofree char *macAddr = NULL;
    g_autofree char *mtuSize = NULL;
    g_autofree xmlNodePtr *ipNodes = NULL;
    g_autofree xmlNodePtr *routeNodes = NULL;
    g_autofree xmlNodePtr *portGroupNodes = NULL;
    int nips, nPortGroups, nRoutes;
    xmlNodePtr dnsNode = NULL;
    xmlNodePtr virtPortNode = NULL;
    xmlNodePtr forwardNode = NULL;
    g_autofree char *ipv6nogwStr = NULL;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr bandwidthNode = NULL;
    xmlNodePtr vlanNode;
    xmlNodePtr metadataNode = NULL;
    xmlNodePtr domain_node = NULL;

    def = g_new0(virNetworkDef, 1);

    /* Extract network name */
    def->name = virXPathString("string(./name[1])", ctxt);
    if (!def->name) {
        virReportError(VIR_ERR_NO_NAME, NULL);
        return NULL;
    }

    if (virXMLCheckIllegalChars("name", def->name, "/") < 0)
        return NULL;

    /* Extract network uuid */
    uuid = virXPathString("string(./uuid[1])", ctxt);
    if (!uuid) {
        if (virUUIDGenerate(def->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Failed to generate UUID"));
            return NULL;
        }
    } else {
        if (virUUIDParse(uuid, def->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed uuid element"));
            return NULL;
        }
        def->uuid_specified = true;
    }

    /* Extract short description of network (title) */
    def->title = virXPathString("string(./title[1])", ctxt);
    if (def->title && strchr(def->title, '\n')) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Network title can't contain newlines"));
        return NULL;
    }

    /* Extract documentation if present */
    def->description = virXPathString("string(./description[1])", ctxt);

    /* check if definitions with no IPv6 gateway addresses is to
     * allow guest-to-guest communications.
     */
    ipv6nogwStr = virXPathString("string(./@ipv6)", ctxt);
    if (ipv6nogwStr) {
        if (virStringParseYesNo(ipv6nogwStr, &def->ipv6nogw) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid ipv6 setting '%1$s' in network '%2$s'"),
                           ipv6nogwStr, def->name);
            return NULL;
        }
    }

    if (virXMLPropTristateBool(ctxt->node, "trustGuestRxFilters",
                               VIR_XML_PROP_NONE,
                               &def->trustGuestRxFilters) < 0)
        return NULL;

    /* Parse network domain information */
    domain_node = virXPathNode("./domain[1]", ctxt);
    def->domain = virXMLPropString(domain_node, "name");
    if (virXMLPropTristateBool(domain_node, "localOnly",
                               VIR_XML_PROP_NONE,
                               &def->domainLocalOnly) < 0)
        return NULL;

    if ((bandwidthNode = virXPathNode("./bandwidth", ctxt)) &&
        virNetDevBandwidthParse(&def->bandwidth, NULL, bandwidthNode, false) < 0)
        return NULL;

    vlanNode = virXPathNode("./vlan", ctxt);
    if (vlanNode && virNetDevVlanParse(vlanNode, ctxt, &def->vlan) < 0)
        return NULL;

    if (virNetworkPortOptionsParseXML(ctxt, &def->isolatedPort) < 0)
        return NULL;

    /* Parse bridge information */
    def->bridge = virXPathString("string(./bridge[1]/@name)", ctxt);
    def->bridgeZone = virXPathString("string(./bridge[1]/@zone)", ctxt);
    stp = virXPathString("string(./bridge[1]/@stp)", ctxt);
    def->stp = (stp && STREQ(stp, "off")) ? false : true;

    stpDelay = virXPathString("string(./bridge[1]/@delay)", ctxt);
    if (stpDelay) {
        if (virStrToLong_ulp(stpDelay, NULL, 10, &def->delay) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid delay value in network '%1$s'"),
                           def->name);
            return NULL;
        }
    }

    macTableManager = virXPathString("string(./bridge[1]/@macTableManager)", ctxt);
    if (macTableManager) {
        if ((def->macTableManager
             = virNetworkBridgeMACTableManagerTypeFromString(macTableManager)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid macTableManager setting '%1$s' in network '%2$s'"),
                           macTableManager, def->name);
            return NULL;
        }
    }

    macAddr = virXPathString("string(./mac[1]/@address)", ctxt);
    if (macAddr) {
        if (virMacAddrParse(macAddr, &def->mac) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid bridge mac address '%1$s' in network '%2$s'"),
                           macAddr, def->name);
            return NULL;
        }
        if (virMacAddrIsMulticast(&def->mac)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid multicast bridge mac address '%1$s' in network '%2$s'"),
                           macAddr, def->name);
            return NULL;
        }
        def->mac_specified = true;
    }

    mtuSize = virXPathString("string(./mtu/@size)", ctxt);
    if (mtuSize) {
        if (virStrToLong_ui(mtuSize, NULL, 10, &def->mtu) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid mtu size '%1$s' in network '%2$s'"),
                           mtuSize, def->name);
            return NULL;
        }
    }

    dnsNode = virXPathNode("./dns", ctxt);
    if (dnsNode != NULL &&
        virNetworkDNSDefParseXML(def->name, dnsNode, ctxt, &def->dns) < 0) {
        return NULL;
    }

    virtPortNode = virXPathNode("./virtualport", ctxt);
    if (virtPortNode &&
        (!(def->virtPortProfile = virNetDevVPortProfileParse(virtPortNode,
                                                             VIR_VPORT_XML_REQUIRE_TYPE)))) {
        return NULL;
    }

    nPortGroups = virXPathNodeSet("./portgroup", ctxt, &portGroupNodes);
    if (nPortGroups < 0)
        return NULL;

    if (nPortGroups > 0) {
        size_t i;

        /* allocate array to hold all the portgroups */
        def->portGroups = g_new0(virPortGroupDef, nPortGroups);
        /* parse each portgroup */
        for (i = 0; i < nPortGroups; i++) {
            if (virNetworkPortGroupParseXML(&def->portGroups[i],
                                            portGroupNodes[i],
                                            ctxt) < 0)
                return NULL;
            def->nPortGroups++;
        }
    }

    nips = virXPathNodeSet("./ip", ctxt, &ipNodes);
    if (nips < 0)
        return NULL;

    if (nips > 0) {
        size_t i;

        /* allocate array to hold all the addrs */
        def->ips = g_new0(virNetworkIPDef, nips);
        /* parse each addr */
        for (i = 0; i < nips; i++) {
            if (virNetworkIPDefParseXML(def->name,
                                        ipNodes[i],
                                        ctxt,
                                        &def->ips[i]) < 0)
                return NULL;
            def->nips++;
        }
    }

    nRoutes = virXPathNodeSet("./route", ctxt, &routeNodes);
    if (nRoutes < 0)
        return NULL;

    if (nRoutes > 0) {
        size_t i;

        /* allocate array to hold all the route definitions */
        def->routes = g_new0(virNetDevIPRoute *, nRoutes);
        /* parse each definition */
        for (i = 0; i < nRoutes; i++) {
            virNetDevIPRoute *route = NULL;

            if (!(route = virNetDevIPRouteParseXML(def->name, routeNodes[i])))
                return NULL;
            def->routes[i] = route;
            def->nroutes++;
        }

        /* now validate the correctness of any static route gateways specified
         *
         * note: the parameters within each definition are verified/assumed valid;
         * the question being asked and answered here is if the specified gateway
         * is directly reachable from this bridge.
         */
        nRoutes = def->nroutes;
        nips = def->nips;
        for (i = 0; i < nRoutes; i++) {
            size_t j;
            virSocketAddr testAddr, testGw;
            bool addrMatch;
            virNetDevIPRoute *gwdef = def->routes[i];
            virSocketAddr *gateway = virNetDevIPRouteGetGateway(gwdef);
            addrMatch = false;
            for (j = 0; j < nips; j++) {
                virNetworkIPDef *def2 = &def->ips[j];
                int prefix;

                if (VIR_SOCKET_ADDR_FAMILY(gateway)
                    != VIR_SOCKET_ADDR_FAMILY(&def2->address)) {
                    continue;
                }
                prefix = virNetworkIPDefPrefix(def2);
                virSocketAddrMaskByPrefix(&def2->address, prefix, &testAddr);
                virSocketAddrMaskByPrefix(gateway, prefix, &testGw);
                if (VIR_SOCKET_ADDR_VALID(&testAddr) &&
                    VIR_SOCKET_ADDR_VALID(&testGw) &&
                    virSocketAddrEqual(&testAddr, &testGw)) {
                    addrMatch = true;
                    break;
                }
            }
            if (!addrMatch) {
                g_autofree char *gw = virSocketAddrFormat(gateway);
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unreachable static route gateway '%1$s' specified for network '%2$s'"),
                               gw, def->name);
                return NULL;
            }
        }
    }

    forwardNode = virXPathNode("./forward", ctxt);
    if (forwardNode &&
        virNetworkForwardDefParseXML(def->name, forwardNode, ctxt, &def->forward) < 0) {
        return NULL;
    }

    /* Validate some items in the main NetworkDef that need to align
     * with the chosen forward mode.
     */
    switch ((virNetworkForwardType) def->forward.type) {
    case VIR_NETWORK_FORWARD_NONE:
        break;

    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_OPEN:
        /* It's pointless to specify L3 forwarding without specifying
         * the network we're on.
         */
        if (def->nips == 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%1$s forwarding requested, but no IP address provided for network '%2$s'"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            return NULL;
        }
        if (def->forward.nifs > 1) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("multiple forwarding interfaces specified for network '%1$s', only one is supported"),
                           def->name);
            return NULL;
        }

        if (def->forward.type == VIR_NETWORK_FORWARD_OPEN && def->forward.nifs) {
            /* an open network by definition can't place any restrictions
             * on what traffic is allowed or where it goes, so specifying
             * a forwarding device is nonsensical.
             */
            virReportError(VIR_ERR_XML_ERROR,
                           _("forward dev not allowed for network '%1$s' with forward mode='%2$s'"),
                           def->name,
                           virNetworkForwardTypeToString(def->forward.type));
            return NULL;
        }
        break;

    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
    case VIR_NETWORK_FORWARD_HOSTDEV:
        if (def->bridge) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("bridge name not allowed in %1$s mode (network '%2$s')"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            return NULL;
        }
        if (def->bridgeZone) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("bridge zone not allowed in %1$s mode (network '%2$s')"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            return NULL;
        }
        if (def->macTableManager) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("bridge macTableManager setting not allowed in %1$s mode (network '%2$s')"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            return NULL;
        }
        G_GNUC_FALLTHROUGH;

    case VIR_NETWORK_FORWARD_BRIDGE:
        if (def->delay || stp || def->bridgeZone) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("bridge delay/stp/zone options only allowed in route, nat, and isolated mode, not in %1$s (network '%2$s')"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            return NULL;
        }
        if (def->bridge && (def->forward.nifs || def->forward.npfs)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("A network with forward mode='%1$s' can specify a bridge name or a forward dev, but not both (network '%2$s')"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            return NULL;
        }
        break;

    case VIR_NETWORK_FORWARD_LAST:
    default:
        virReportEnumRangeError(virNetworkForwardType, def->forward.type);
        return NULL;
    }

    if (def->mtu) {
        switch ((virNetworkForwardType) def->forward.type) {
        case VIR_NETWORK_FORWARD_NONE:
        case VIR_NETWORK_FORWARD_NAT:
        case VIR_NETWORK_FORWARD_ROUTE:
        case VIR_NETWORK_FORWARD_OPEN:
            break;

        case VIR_NETWORK_FORWARD_BRIDGE:
        case VIR_NETWORK_FORWARD_PRIVATE:
        case VIR_NETWORK_FORWARD_VEPA:
        case VIR_NETWORK_FORWARD_PASSTHROUGH:
        case VIR_NETWORK_FORWARD_HOSTDEV:
            virReportError(VIR_ERR_XML_ERROR,
                           _("mtu size only allowed in open, route, nat, and isolated mode, not in %1$s (network '%2$s')"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            return NULL;

        case VIR_NETWORK_FORWARD_LAST:
        default:
            virReportEnumRangeError(virNetworkForwardType, def->forward.type);
            return NULL;
        }
    }

    /* Extract custom metadata */
    if ((metadataNode = virXPathNode("./metadata[1]", ctxt)) != NULL) {
        def->metadata = xmlCopyNode(metadataNode, 1);
        virXMLNodeSanitizeNamespaces(def->metadata);
    }

    if (xmlopt)
        def->ns = xmlopt->ns;
    if (def->ns.parse) {
        if (virXMLNamespaceRegister(ctxt, &def->ns) < 0)
            return NULL;
        if ((def->ns.parse)(ctxt, &def->namespaceData) < 0)
            return NULL;
    }

    return g_steal_pointer(&def);
}


virNetworkDef *
virNetworkDefParse(const char *xmlStr,
                   const char *filename,
                   virNetworkXMLOption *xmlopt,
                   bool validate)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    xml = virXMLParse(filename, xmlStr, _("(network_definition)"),
                      "network", &ctxt, "network.rng", validate);
    xmlKeepBlanksDefault(keepBlanksDefault);

    if (!xml)
        return NULL;

    return virNetworkDefParseXML(ctxt, xmlopt);
}


static int
virNetworkDNSDefFormat(virBuffer *buf,
                       const virNetworkDNSDef *def)
{
    size_t i, j;

    if (!(def->enable || def->forwardPlainNames || def->nfwds || def->nhosts ||
          def->nsrvs || def->ntxts))
        return 0;

    virBufferAddLit(buf, "<dns");
    if (def->enable) {
        const char *fwd = virTristateBoolTypeToString(def->enable);

        if (!fwd) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown enable type %1$d in network"),
                           def->enable);
            return -1;
        }
        virBufferAsprintf(buf, " enable='%s'", fwd);
    }
    if (def->forwardPlainNames) {
        const char *fwd = virTristateBoolTypeToString(def->forwardPlainNames);

        if (!fwd) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown forwardPlainNames type %1$d in network"),
                           def->forwardPlainNames);
            return -1;
        }
        virBufferAsprintf(buf, " forwardPlainNames='%s'", fwd);
    }
    if (!(def->nfwds || def->nhosts || def->nsrvs || def->ntxts)) {
        virBufferAddLit(buf, "/>\n");
        return 0;
    }

    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < def->nfwds; i++) {

        virBufferAddLit(buf, "<forwarder");
        if (def->forwarders[i].domain) {
            virBufferEscapeString(buf, " domain='%s'",
                                  def->forwarders[i].domain);
        }
        if (VIR_SOCKET_ADDR_VALID(&def->forwarders[i].addr)) {
            g_autofree char *addr = virSocketAddrFormat(&def->forwarders[i].addr);

            if (!addr)
                return -1;

            virBufferAsprintf(buf, " addr='%s'", addr);
        }
        virBufferAddLit(buf, "/>\n");
    }

    for (i = 0; i < def->ntxts; i++) {
        virBufferEscapeString(buf, "<txt name='%s' ", def->txts[i].name);
        virBufferEscapeString(buf, "value='%s'/>\n", def->txts[i].value);
    }

    for (i = 0; i < def->nsrvs; i++) {
        if (def->srvs[i].service && def->srvs[i].protocol) {
            virBufferEscapeString(buf, "<srv service='%s' ",
                                  def->srvs[i].service);
            virBufferEscapeString(buf, "protocol='%s'", def->srvs[i].protocol);

            if (def->srvs[i].domain)
                virBufferEscapeString(buf, " domain='%s'", def->srvs[i].domain);
            if (def->srvs[i].target)
                virBufferEscapeString(buf, " target='%s'", def->srvs[i].target);
            if (def->srvs[i].port)
                virBufferAsprintf(buf, " port='%d'", def->srvs[i].port);
            if (def->srvs[i].priority)
                virBufferAsprintf(buf, " priority='%d'", def->srvs[i].priority);
            if (def->srvs[i].weight)
                virBufferAsprintf(buf, " weight='%d'", def->srvs[i].weight);

            virBufferAddLit(buf, "/>\n");
        }
    }

    if (def->nhosts) {
        for (i = 0; i < def->nhosts; i++) {
            g_autofree char *ip = virSocketAddrFormat(&def->hosts[i].ip);

            virBufferAsprintf(buf, "<host ip='%s'>\n", ip);
            virBufferAdjustIndent(buf, 2);
            for (j = 0; j < def->hosts[i].nnames; j++)
                virBufferEscapeString(buf, "<hostname>%s</hostname>\n",
                                      def->hosts[i].names[j]);

            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</host>\n");
        }
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</dns>\n");
    return 0;
}


static int
virNetworkIPDefFormat(virBuffer *buf,
                      const virNetworkIPDef *def)
{
    virBufferAddLit(buf, "<ip");

    if (def->family)
        virBufferAsprintf(buf, " family='%s'", def->family);
    if (VIR_SOCKET_ADDR_VALID(&def->address)) {
        g_autofree char *addr = virSocketAddrFormat(&def->address);
        if (!addr)
            return -1;
        virBufferAsprintf(buf, " address='%s'", addr);
    }
    if (VIR_SOCKET_ADDR_VALID(&def->netmask)) {
        g_autofree char *addr = virSocketAddrFormat(&def->netmask);
        if (!addr)
            return -1;
        virBufferAsprintf(buf, " netmask='%s'", addr);
    }
    if (def->prefix > 0)
        virBufferAsprintf(buf, " prefix='%u'", def->prefix);

    if (def->localPTR) {
        virBufferAsprintf(buf, " localPtr='%s'",
                          virTristateBoolTypeToString(def->localPTR));
    }

    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    if (def->tftproot) {
        virBufferEscapeString(buf, "<tftp root='%s'/>\n",
                              def->tftproot);
    }
    if ((def->nranges || def->nhosts)) {
        size_t i;
        virBufferAddLit(buf, "<dhcp>\n");
        virBufferAdjustIndent(buf, 2);

        for (i = 0; i < def->nranges; i++) {
            virSocketAddrRange addr = def->ranges[i].addr;
            virNetworkDHCPLeaseTimeDef *lease = def->ranges[i].lease;
            g_autofree char *saddr = NULL;
            g_autofree char *eaddr = NULL;

            if (!(saddr = virSocketAddrFormat(&addr.start)))
                return -1;

            if (!(eaddr = virSocketAddrFormat(&addr.end)))
                return -1;

            virBufferAsprintf(buf, "<range start='%s' end='%s'",
                              saddr, eaddr);
            if (lease) {
                virBufferAddLit(buf, ">\n");
                virBufferAdjustIndent(buf, 2);
                if (!lease->expiry) {
                    virBufferAddLit(buf, "<lease expiry='0'/>\n");
                } else {
                    virBufferAsprintf(buf, "<lease expiry='%llu' unit='%s'/>\n",
                                      lease->expiry,
                                      virNetworkDHCPLeaseTimeUnitTypeToString(lease->unit));
                }
                virBufferAdjustIndent(buf, -2);
                virBufferAddLit(buf, "</range>\n");
            } else {
                virBufferAddLit(buf, "/>\n");
            }
        }
        for (i = 0; i < def->nhosts; i++) {
            virNetworkDHCPLeaseTimeDef *lease = def->hosts[i].lease;
            virBufferAddLit(buf, "<host");
            if (def->hosts[i].mac)
                virBufferAsprintf(buf, " mac='%s'", def->hosts[i].mac);
            if (def->hosts[i].id)
                virBufferAsprintf(buf, " id='%s'", def->hosts[i].id);
            if (def->hosts[i].name)
                virBufferAsprintf(buf, " name='%s'", def->hosts[i].name);
            if (VIR_SOCKET_ADDR_VALID(&def->hosts[i].ip)) {
                g_autofree char *ipaddr = virSocketAddrFormat(&def->hosts[i].ip);
                if (!ipaddr)
                    return -1;

                virBufferAsprintf(buf, " ip='%s'", ipaddr);
            }
            if (lease) {
                virBufferAddLit(buf, ">\n");
                virBufferAdjustIndent(buf, 2);
                if (!lease->expiry) {
                    virBufferAddLit(buf, "<lease expiry='0'/>\n");
                } else {
                    virBufferAsprintf(buf, "<lease expiry='%llu' unit='%s'/>\n",
                                      lease->expiry,
                                      virNetworkDHCPLeaseTimeUnitTypeToString(lease->unit));
                }
                virBufferAdjustIndent(buf, -2);
                virBufferAddLit(buf, "</host>\n");
            } else {
                virBufferAddLit(buf, "/>\n");
            }
        }
        if (def->bootfile) {
            virBufferEscapeString(buf, "<bootp file='%s'",
                                  def->bootfile);
            if (VIR_SOCKET_ADDR_VALID(&def->bootserver)) {
                g_autofree char *ipaddr = virSocketAddrFormat(&def->bootserver);
                if (!ipaddr)
                    return -1;

                virBufferEscapeString(buf, " server='%s'", ipaddr);
            }
            virBufferAddLit(buf, "/>\n");

        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</dhcp>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</ip>\n");

    return 0;
}

void
virNetworkPortOptionsFormat(virTristateBool isolatedPort,
                            virBuffer *buf)
{
    if (isolatedPort != VIR_TRISTATE_BOOL_ABSENT)
        virBufferAsprintf(buf, "<port isolated='%s'/>\n",
                          virTristateBoolTypeToString(isolatedPort));
}

static int
virPortGroupDefFormat(virBuffer *buf,
                      const virPortGroupDef *def)
{
    virBufferAsprintf(buf, "<portgroup name='%s'", def->name);
    if (def->isDefault)
        virBufferAddLit(buf, " default='yes'");
    if (def->trustGuestRxFilters)
        virBufferAsprintf(buf, " trustGuestRxFilters='%s'",
                          virTristateBoolTypeToString(def->trustGuestRxFilters));
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);
    if (virNetDevVlanFormat(&def->vlan, buf) < 0)
        return -1;
    if (virNetDevVPortProfileFormat(def->virtPortProfile, buf) < 0)
        return -1;
    virNetDevBandwidthFormat(def->bandwidth, 0, buf);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</portgroup>\n");
    return 0;
}


static int
virNetworkForwardNatDefFormat(virBuffer *buf,
                              const virNetworkForwardDef *fwd)
{
    g_autofree char *addrStart = NULL;
    g_autofree char *addrEnd = NULL;

    if (VIR_SOCKET_ADDR_VALID(&fwd->addr.start)) {
        addrStart = virSocketAddrFormat(&fwd->addr.start);
        if (!addrStart)
            return -1;
    }

    if (VIR_SOCKET_ADDR_VALID(&fwd->addr.end)) {
        addrEnd = virSocketAddrFormat(&fwd->addr.end);
        if (!addrEnd)
            return -1;
    }

    if (!addrEnd && !addrStart && !fwd->port.start && !fwd->port.end && !fwd->natIPv6)
        return 0;

    virBufferAddLit(buf, "<nat");
    if (fwd->natIPv6)
        virBufferAsprintf(buf, " ipv6='%s'", virTristateBoolTypeToString(fwd->natIPv6));

    if (!addrEnd && !addrStart && !fwd->port.start && !fwd->port.end) {
        virBufferAddLit(buf, "/>\n");
        return 0;
    }
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    if (addrStart) {
        virBufferAsprintf(buf, "<address start='%s'", addrStart);
        if (addrEnd)
            virBufferAsprintf(buf, " end='%s'", addrEnd);
        virBufferAddLit(buf, "/>\n");
    }

    if (fwd->port.start || fwd->port.end) {
        virBufferAsprintf(buf, "<port start='%d'", fwd->port.start);
        if (fwd->port.end)
            virBufferAsprintf(buf, " end='%d'", fwd->port.end);
        virBufferAddLit(buf, "/>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</nat>\n");
    return 0;
}


int
virNetworkDefFormatBuf(virBuffer *buf,
                       const virNetworkDef *def,
                       virNetworkXMLOption *xmlopt G_GNUC_UNUSED,
                       unsigned int flags)
{
    const unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    size_t i;
    bool shortforward;
    bool hasbridge = false;

    virBufferAddLit(buf, "<network");
    if (def->namespaceData && def->ns.format)
        virXMLNamespaceFormatNS(buf, &def->ns);
    if (!(flags & VIR_NETWORK_XML_INACTIVE) && (def->connections > 0))
        virBufferAsprintf(buf, " connections='%d'", def->connections);
    if (def->ipv6nogw)
        virBufferAddLit(buf, " ipv6='yes'");
    if (def->trustGuestRxFilters)
        virBufferAsprintf(buf, " trustGuestRxFilters='%s'",
                          virTristateBoolTypeToString(def->trustGuestRxFilters));
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<name>%s</name>\n", def->name);

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuidstr);

    virBufferEscapeString(buf, "<title>%s</title>\n", def->title);

    virBufferEscapeString(buf, "<description>%s</description>\n",
                          def->description);

    if (virXMLFormatMetadata(buf, def->metadata) < 0)
        return -1;

    if (def->forward.type != VIR_NETWORK_FORWARD_NONE) {
        const char *dev = NULL;
        const char *mode = virNetworkForwardTypeToString(def->forward.type);

        if (!def->forward.npfs)
            dev = virNetworkDefForwardIf(def, 0);

        if (!mode) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown forward type %1$d in network '%2$s'"),
                           def->forward.type, def->name);
            return -1;
        }
        virBufferAddLit(buf, "<forward");
        virBufferEscapeString(buf, " dev='%s'", dev);
        virBufferAsprintf(buf, " mode='%s'", mode);
        if (def->forward.type == VIR_NETWORK_FORWARD_HOSTDEV) {
            if (def->forward.managed)
                virBufferAddLit(buf, " managed='yes'");
            else
                virBufferAddLit(buf, " managed='no'");
        }
        shortforward = !(def->forward.nifs || def->forward.npfs
                         || VIR_SOCKET_ADDR_VALID(&def->forward.addr.start)
                         || VIR_SOCKET_ADDR_VALID(&def->forward.addr.end)
                         || def->forward.port.start
                         || def->forward.port.end
                         || (def->forward.driverName
                             != VIR_NETWORK_FORWARD_DRIVER_NAME_DEFAULT)
                         || def->forward.natIPv6);
        virBufferAsprintf(buf, "%s>\n", shortforward ? "/" : "");
        virBufferAdjustIndent(buf, 2);

        if (def->forward.driverName
            != VIR_NETWORK_FORWARD_DRIVER_NAME_DEFAULT) {
            const char *driverName
                = virNetworkForwardDriverNameTypeToString(def->forward.driverName);
            if (!driverName) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected hostdev driver name type %1$d "),
                               def->forward.driverName);
                return -1;
            }
            virBufferAsprintf(buf, "<driver name='%s'/>\n", driverName);
        }
        if (def->forward.type == VIR_NETWORK_FORWARD_NAT) {
            if (virNetworkForwardNatDefFormat(buf, &def->forward) < 0)
                return -1;
        }

        /* For now, hard-coded to at most 1 forward.pfs */
        if (def->forward.npfs)
            virBufferEscapeString(buf, "<pf dev='%s'/>\n",
                                  def->forward.pfs[0].dev);

        if (def->forward.nifs &&
            (!def->forward.npfs || !(flags & VIR_NETWORK_XML_INACTIVE))) {
            for (i = 0; i < def->forward.nifs; i++) {
                if (def->forward.ifs[i].type == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV) {
                    virBufferEscapeString(buf, "<interface dev='%s'",
                                          def->forward.ifs[i].device.dev);
                    if (!(flags & VIR_NETWORK_XML_INACTIVE) &&
                        (def->forward.ifs[i].connections > 0)) {
                        virBufferAsprintf(buf, " connections='%d'",
                                          def->forward.ifs[i].connections);
                    }
                    virBufferAddLit(buf, "/>\n");
                } else {
                    if (def->forward.ifs[i].type ==  VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI) {
                        virPCIDeviceAddressFormat(buf,
                                                  def->forward.ifs[i].device.pci,
                                                  true);
                    }
                }
            }
        }
        virBufferAdjustIndent(buf, -2);
        if (!shortforward)
            virBufferAddLit(buf, "</forward>\n");
    }

    switch ((virNetworkForwardType) def->forward.type) {
    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        hasbridge = true;
        break;

    case VIR_NETWORK_FORWARD_BRIDGE:
    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
    case VIR_NETWORK_FORWARD_HOSTDEV:
        break;

    case VIR_NETWORK_FORWARD_LAST:
    default:
        virReportEnumRangeError(virNetworkForwardType, def->forward.type);
        return -1;
    }

    if (hasbridge || def->bridge || def->macTableManager) {
        virBufferAddLit(buf, "<bridge");
        virBufferEscapeString(buf, " name='%s'", def->bridge);
        virBufferEscapeString(buf, " zone='%s'", def->bridgeZone);
        if (hasbridge)
            virBufferAsprintf(buf, " stp='%s' delay='%ld'",
                              def->stp ? "on" : "off", def->delay);
        if (def->macTableManager) {
            virBufferAsprintf(buf, " macTableManager='%s'",
                             virNetworkBridgeMACTableManagerTypeToString(def->macTableManager));
        }
        virBufferAddLit(buf, "/>\n");
    }

    if (def->mtu)
        virBufferAsprintf(buf, "<mtu size='%u'/>\n", def->mtu);

    if (def->mac_specified) {
        char macaddr[VIR_MAC_STRING_BUFLEN];
        virMacAddrFormat(&def->mac, macaddr);
        virBufferAsprintf(buf, "<mac address='%s'/>\n", macaddr);
    }

    if (def->domain) {
        virBufferAsprintf(buf, "<domain name='%s'", def->domain);

        /* default to "no", but don't format it in the XML */
        if (def->domainLocalOnly) {
            const char *local = virTristateBoolTypeToString(def->domainLocalOnly);

            if (!local) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unknown localOnly type %1$d in network"),
                               def->domainLocalOnly);
                return -1;
            }
            virBufferAsprintf(buf, " localOnly='%s'", local);
        }

        virBufferAddLit(buf, "/>\n");
    }

    if (virNetworkDNSDefFormat(buf, &def->dns) < 0)
        return -1;

    if (virNetDevVlanFormat(&def->vlan, buf) < 0)
        return -1;
    if (virNetDevBandwidthFormat(def->bandwidth, 0, buf) < 0)
        return -1;
    virNetworkPortOptionsFormat(def->isolatedPort, buf);

    for (i = 0; i < def->nips; i++) {
        if (virNetworkIPDefFormat(buf, &def->ips[i]) < 0)
            return -1;
    }

    for (i = 0; i < def->nroutes; i++) {
        if (virNetDevIPRouteFormat(buf, def->routes[i]) < 0)
            return -1;
    }

    if (virNetDevVPortProfileFormat(def->virtPortProfile, buf) < 0)
        return -1;

    for (i = 0; i < def->nPortGroups; i++)
        if (virPortGroupDefFormat(buf, &def->portGroups[i]) < 0)
            return -1;

    if (def->namespaceData && def->ns.format) {
        if ((def->ns.format)(buf, def->namespaceData) < 0)
            return -1;
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</network>\n");

    return 0;
}


char *
virNetworkDefFormat(const virNetworkDef *def,
                    virNetworkXMLOption *xmlopt,
                    unsigned int flags)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (virNetworkDefFormatBuf(&buf, def, xmlopt, flags) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


const char *
virNetworkDefForwardIf(const virNetworkDef *def,
                       size_t n)
{
    return ((def->forward.ifs && (def->forward.nifs > n) &&
             def->forward.ifs[n].type == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV)
            ? def->forward.ifs[n].device.dev : NULL);
}


virPortGroupDef *
virPortGroupFindByName(virNetworkDef *net,
                       const char *portgroup)
{
    size_t i;
    for (i = 0; i < net->nPortGroups; i++) {
        if (portgroup) {
            if (STREQ(portgroup, net->portGroups[i].name))
                return &net->portGroups[i];
        } else {
            if (net->portGroups[i].isDefault)
                return &net->portGroups[i];
        }
    }
    return NULL;
}


int
virNetworkSaveXML(const char *configDir,
                  virNetworkDef *def,
                  const char *xml)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *configFile = NULL;

    if (!configDir)
        return 0;

    if ((configFile = virNetworkConfigFile(configDir, def->name)) == NULL)
        return -1;

    if (g_mkdir_with_parents(configDir, 0777) < 0) {
        virReportSystemError(errno,
                             _("cannot create config directory '%1$s'"),
                             configDir);
        return -1;
    }

    virUUIDFormat(def->uuid, uuidstr);
    return virXMLSaveFile(configFile,
                          virXMLPickShellSafeComment(def->name, uuidstr),
                          "net-edit", xml);
}


int
virNetworkSaveConfig(const char *configDir,
                     virNetworkDef *def,
                     virNetworkXMLOption *xmlopt)
{
    g_autofree char *xml = NULL;

    if (!(xml = virNetworkDefFormat(def, xmlopt, VIR_NETWORK_XML_INACTIVE)))
        return -1;

    if (virNetworkSaveXML(configDir, def, xml))
        return -1;

    return 0;
}


char *
virNetworkConfigFile(const char *dir,
                     const char *name)
{
    return g_strdup_printf("%s/%s.xml", dir, name);
}


void
virNetworkSetBridgeMacAddr(virNetworkDef *def)
{
    if (!def->mac_specified) {
        /* if the bridge doesn't have a mac address explicitly defined,
         * autogenerate a random one.
         */
        virMacAddrGenerate((unsigned char[]){ 0x52, 0x54, 0 },
                           &def->mac);
        def->mac_specified = true;
    }
}


/* NetworkObj backend of the virNetworkUpdate API */

static void
virNetworkDefUpdateNoSupport(virNetworkDef *def, const char *section)
{
    virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                   _("can't update '%1$s' section of network '%2$s'"),
                   section, def->name);
}


static void
virNetworkDefUpdateUnknownCommand(unsigned int command)
{
    virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                   _("unrecognized network update command code %1$d"), command);
}


static int
virNetworkDefUpdateCheckElementName(virNetworkDef *def,
                                    xmlNodePtr node,
                                    const char *section)
{
    if (!virXMLNodeNameEqual(node, section)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected element <%1$s>, expecting <%2$s>, while updating network '%3$s'"),
                       node->name, section, def->name);
        return -1;
    }
    return 0;
}


static int
virNetworkDefUpdateBridge(virNetworkDef *def,
                          unsigned int command G_GNUC_UNUSED,
                          int parentIndex G_GNUC_UNUSED,
                          xmlXPathContextPtr ctxt G_GNUC_UNUSED,
                          /* virNetworkUpdateFlags */
                          unsigned int fflags G_GNUC_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "bridge");
    return -1;
}


static int
virNetworkDefUpdateDomain(virNetworkDef *def,
                          unsigned int command G_GNUC_UNUSED,
                          int parentIndex G_GNUC_UNUSED,
                          xmlXPathContextPtr ctxt G_GNUC_UNUSED,
                          /* virNetworkUpdateFlags */
                          unsigned int fflags G_GNUC_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "domain");
    return -1;
}


static int
virNetworkDefUpdateIP(virNetworkDef *def,
                      unsigned int command G_GNUC_UNUSED,
                      int parentIndex G_GNUC_UNUSED,
                      xmlXPathContextPtr ctxt G_GNUC_UNUSED,
                      /* virNetworkUpdateFlags */
                      unsigned int fflags G_GNUC_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "ip");
    return -1;
}


static virNetworkIPDef *
virNetworkIPDefByIndex(virNetworkDef *def, int parentIndex)
{
    virNetworkIPDef *ipdef = NULL;
    size_t i;

    /* first find which ip element's dhcp host list to work on */
    if (parentIndex >= 0) {
        ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, parentIndex);
        if (!(ipdef)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't update dhcp host entry - no <ip> element found at index %1$d in network '%2$s'"),
                           parentIndex, def->name);
        }
        return ipdef;
    }

    /* -1 means "find the most appropriate", which in this case
     * means the one and only <ip> that has <dhcp> element
     */
    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (ipdef->nranges || ipdef->nhosts)
            break;
    }
    if (!ipdef) {
        ipdef = virNetworkDefGetIPByIndex(def, AF_INET, 0);
        if (!ipdef)
            ipdef = virNetworkDefGetIPByIndex(def, AF_INET6, 0);
    }
    if (!ipdef) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("couldn't update dhcp host entry - no <ip> element found in network '%1$s'"),
                       def->name);
    }
    return ipdef;
}


static int
virNetworkDefUpdateCheckMultiDHCP(virNetworkDef *def,
                                  virNetworkIPDef *ipdef)
{
    int family = VIR_SOCKET_ADDR_FAMILY(&ipdef->address);
    size_t i;
    virNetworkIPDef *ip;

    for (i = 0; (ip = virNetworkDefGetIPByIndex(def, family, i)); i++) {
        if (ip != ipdef) {
            if (ip->nranges || ip->nhosts) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("dhcp is supported only for a single %1$s address on each network"),
                               (family == AF_INET) ? "IPv4" : "IPv6");
                return -1;
            }
        }
    }
    return 0;
}


static int
virNetworkDefUpdateIPDHCPHost(virNetworkDef *def,
                              unsigned int command,
                              int parentIndex,
                              xmlXPathContextPtr ctxt,
                              /* virNetworkUpdateFlags */
                              unsigned int fflags G_GNUC_UNUSED)
{
    size_t i;
    int ret = -1;
    virNetworkIPDef *ipdef = virNetworkIPDefByIndex(def, parentIndex);
    virNetworkDHCPHostDef host = { 0 };
    bool partialOkay = (command == VIR_NETWORK_UPDATE_COMMAND_DELETE);

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "host") < 0)
        goto cleanup;

    /* ipdef is the ip element that needs its host array updated */
    if (!ipdef)
        goto cleanup;

    if (virNetworkDHCPHostDefParseXML(def->name, ipdef, ctxt->node,
                                      &host, partialOkay) < 0)
        goto cleanup;

    if (!partialOkay &&
        VIR_SOCKET_ADDR_FAMILY(&ipdef->address)
        != VIR_SOCKET_ADDR_FAMILY(&host.ip)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("the address family of a host entry IP must match the address family of the dhcp element's parent"));
        goto cleanup;
    }

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {

        /* search for the entry with this (ip|mac|name),
         * and update the IP+(mac|name) */
        for (i = 0; i < ipdef->nhosts; i++) {
            if ((host.mac && ipdef->hosts[i].mac &&
                 !virMacAddrCompare(host.mac, ipdef->hosts[i].mac)) ||
                (VIR_SOCKET_ADDR_VALID(&host.ip) &&
                 virSocketAddrEqual(&host.ip, &ipdef->hosts[i].ip)) ||
                (host.name &&
                 STREQ_NULLABLE(host.name, ipdef->hosts[i].name))) {
                break;
            }
        }

        if (i == ipdef->nhosts) {
            g_autofree char *ip = virSocketAddrFormat(&host.ip);
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate an existing dhcp host entry with \"mac='%1$s'\" \"name='%2$s'\" \"ip='%3$s'\" in network '%4$s'"),
                           host.mac ? host.mac : _("unknown"), host.name,
                           ip ? ip : _("unknown"), def->name);
            goto cleanup;
        }

        /* clear the existing hosts entry, move the new one in its place,
         * then clear out the extra copy to get rid of the duplicate pointers
         * to its data (mac and name strings).
         */
        virNetworkDHCPHostDefClear(&ipdef->hosts[i]);
        ipdef->hosts[i] = host;
        memset(&host, 0, sizeof(host));

    } else if ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
               (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST)) {

        if (virNetworkDefUpdateCheckMultiDHCP(def, ipdef) < 0)
            goto cleanup;

        /* log error if an entry with same name/address/ip already exists */
        for (i = 0; i < ipdef->nhosts; i++) {
            if ((host.mac && ipdef->hosts[i].mac &&
                 !virMacAddrCompare(host.mac, ipdef->hosts[i].mac)) ||
                (host.name &&
                 STREQ_NULLABLE(host.name, ipdef->hosts[i].name)) ||
                (VIR_SOCKET_ADDR_VALID(&host.ip) &&
                 virSocketAddrEqual(&host.ip, &ipdef->hosts[i].ip))) {
                g_autofree char *ip = virSocketAddrFormat(&host.ip);

                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("there is an existing dhcp host entry in network '%1$s' that matches \"<host mac='%2$s' name='%3$s' ip='%4$s'/>\""),
                               def->name, host.mac ? host.mac : _("unknown"),
                               host.name, ip ? ip : _("unknown"));
                goto cleanup;
            }
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(ipdef->hosts,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : ipdef->nhosts,
                               ipdef->nhosts, host) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        /* find matching entry - all specified attributes must match */
        for (i = 0; i < ipdef->nhosts; i++) {
            if ((!host.mac || !ipdef->hosts[i].mac ||
                 !virMacAddrCompare(host.mac, ipdef->hosts[i].mac)) &&
                (!host.name ||
                 STREQ_NULLABLE(host.name, ipdef->hosts[i].name)) &&
                (!VIR_SOCKET_ADDR_VALID(&host.ip) ||
                 virSocketAddrEqual(&host.ip, &ipdef->hosts[i].ip))) {
                break;
            }
        }
        if (i == ipdef->nhosts) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching dhcp host entry in network '%1$s'"),
                           def->name);
            goto cleanup;
        }

        /* remove it */
        virNetworkDHCPHostDefClear(&ipdef->hosts[i]);
        VIR_DELETE_ELEMENT(ipdef->hosts, i, ipdef->nhosts);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkDHCPHostDefClear(&host);
    return ret;
}


static int
virNetworkDefUpdateIPDHCPRange(virNetworkDef *def,
                               unsigned int command,
                               int parentIndex,
                               xmlXPathContextPtr ctxt,
                               /* virNetworkUpdateFlags */
                               unsigned int fflags G_GNUC_UNUSED)
{
    size_t i;
    virNetworkIPDef *ipdef = virNetworkIPDefByIndex(def, parentIndex);
    virNetworkDHCPRangeDef range = { 0 };

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "range") < 0)
        return -1;

    /* ipdef is the ip element that needs its range array updated */
    if (!ipdef)
        return -1;

    /* parse the xml into a virSocketAddrRange */
    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {

        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("dhcp ranges cannot be modified, only added or deleted"));
        return -1;
    }

    if (virNetworkDHCPRangeDefParseXML(def->name, ipdef, ctxt->node, &range) < 0)
        return -1;

    if (VIR_SOCKET_ADDR_FAMILY(&ipdef->address)
        != VIR_SOCKET_ADDR_FAMILY(&range.addr.start)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("the address family of a dhcp range must match the address family of the dhcp element's parent"));
        return -1;
    }

    /* check if an entry with same name/address/ip already exists */
    for (i = 0; i < ipdef->nranges; i++) {
        virSocketAddrRange addr = ipdef->ranges[i].addr;
        if (virSocketAddrEqual(&range.addr.start, &addr.start) &&
            virSocketAddrEqual(&range.addr.end, &addr.end)) {
            break;
        }
    }

    if ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
        (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST)) {

        if (virNetworkDefUpdateCheckMultiDHCP(def, ipdef) < 0)
            return -1;

        if (i < ipdef->nranges) {
            g_autofree char *startip = virSocketAddrFormat(&range.addr.start);
            g_autofree char *endip = virSocketAddrFormat(&range.addr.end);

            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("there is an existing dhcp range entry in network '%1$s' that matches \"<range start='%2$s' end='%3$s'/>\""),
                           def->name,
                           startip ? startip : "unknown",
                           endip ? endip : "unknown");
            return -1;
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(ipdef->ranges,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : ipdef->nranges,
                               ipdef->nranges, range) < 0)
            return -1;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (i == ipdef->nranges) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching dhcp range entry in network '%1$s'"),
                           def->name);
            return -1;
        }

        /* remove it */
        /* NB: nothing to clear from a RangeDef that's being freed */
        VIR_DELETE_ELEMENT(ipdef->ranges, i, ipdef->nranges);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        return -1;
    }

    return 0;
}


static int
virNetworkDefUpdateForward(virNetworkDef *def,
                           unsigned int command G_GNUC_UNUSED,
                           int parentIndex G_GNUC_UNUSED,
                           xmlXPathContextPtr ctxt G_GNUC_UNUSED,
                           /* virNetworkUpdateFlags */
                           unsigned int fflags G_GNUC_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "forward");
    return -1;
}


static int
virNetworkDefUpdateForwardInterface(virNetworkDef *def,
                                    unsigned int command,
                                    int parentIndex G_GNUC_UNUSED,
                                    xmlXPathContextPtr ctxt,
                                    /* virNetworkUpdateFlags */
                                    unsigned int fflags G_GNUC_UNUSED)
{
    size_t i;
    int ret = -1;
    virNetworkForwardIfDef iface = { 0 };

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "interface") < 0)
        goto cleanup;

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("forward interface entries cannot be modified, only added or deleted"));
        goto cleanup;
    }

    /* parsing this is so simple that it doesn't have its own function */
    iface.type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV;
    if (!(iface.device.dev = virXMLPropString(ctxt->node, "dev"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing dev attribute in <interface> element"));
        goto cleanup;
    }

    /* check if an <interface> with same dev name already exists */
    for (i = 0; i < def->forward.nifs; i++) {
        if (def->forward.ifs[i].type
            == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV &&
            STREQ(iface.device.dev, def->forward.ifs[i].device.dev))
            break;
    }

    if ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
        (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST)) {

        if (i < def->forward.nifs) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("there is an existing interface entry in network '%1$s' that matches \"<interface dev='%2$s'>\""),
                           def->name, iface.device.dev);
            goto cleanup;
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(def->forward.ifs,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : def->forward.nifs,
                               def->forward.nifs, iface) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (i == def->forward.nifs) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't find an interface entry in network '%1$s' matching <interface dev='%2$s'>"),
                           def->name, iface.device.dev);
            goto cleanup;
        }

        /* fail if the interface is being used */
        if (def->forward.ifs[i].connections > 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("unable to delete interface '%1$s' in network '%2$s'. It is currently being used by %3$d domains."),
                           iface.device.dev, def->name,
                           def->forward.ifs[i].connections);
            goto cleanup;
        }

        /* remove it */
        virNetworkForwardIfDefClear(&def->forward.ifs[i]);
        VIR_DELETE_ELEMENT(def->forward.ifs, i, def->forward.nifs);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkForwardIfDefClear(&iface);
    return ret;
}


static int
virNetworkDefUpdateForwardPF(virNetworkDef *def,
                             unsigned int command G_GNUC_UNUSED,
                             int parentIndex G_GNUC_UNUSED,
                             xmlXPathContextPtr ctxt G_GNUC_UNUSED,
                             /* virNetworkUpdateFlags */
                             unsigned int fflags G_GNUC_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "forward pf");
    return -1;
}


static int
virNetworkDefUpdatePortGroup(virNetworkDef *def,
                             unsigned int command,
                             int parentIndex G_GNUC_UNUSED,
                             xmlXPathContextPtr ctxt,
                             /* virNetworkUpdateFlags */
                             unsigned int fflags G_GNUC_UNUSED)
{
    size_t i;
    int foundName = -1, foundDefault = -1;
    int ret = -1;
    virPortGroupDef portgroup = { 0 };

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "portgroup") < 0)
        goto cleanup;

    if (virNetworkPortGroupParseXML(&portgroup, ctxt->node, ctxt) < 0)
        goto cleanup;

    /* check if a portgroup with same name already exists */
    for (i = 0; i < def->nPortGroups; i++) {
        if (STREQ(portgroup.name, def->portGroups[i].name))
            foundName = i;
        if (def->portGroups[i].isDefault)
            foundDefault = i;
    }
    if (foundName == -1 &&
        ((command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) ||
         (command == VIR_NETWORK_UPDATE_COMMAND_DELETE))) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("couldn't find a portgroup entry in network '%1$s' matching <portgroup name='%2$s'>"),
                       def->name, portgroup.name);
        goto cleanup;
    } else if (foundName >= 0 &&
               ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
                (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST))) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("there is an existing portgroup entry in network '%1$s' that matches \"<portgroup name='%2$s'>\""),
                       def->name, portgroup.name);
        goto cleanup;
    }

    /* if there is already a different default, we can't make this
     * one the default.
     */
    if (command != VIR_NETWORK_UPDATE_COMMAND_DELETE &&
        portgroup.isDefault &&
        foundDefault >= 0 && foundDefault != foundName) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("a different portgroup entry in network '%1$s' is already set as the default. Only one default is allowed."),
                       def->name);
        goto cleanup;
    }

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {

        /* replace existing entry */
        virPortGroupDefClear(&def->portGroups[foundName]);
        def->portGroups[foundName] = portgroup;
        memset(&portgroup, 0, sizeof(portgroup));

    } else if ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
        (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST)) {

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(def->portGroups,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : def->nPortGroups,
                               def->nPortGroups, portgroup) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        /* remove it */
        virPortGroupDefClear(&def->portGroups[foundName]);
        VIR_DELETE_ELEMENT(def->portGroups, foundName, def->nPortGroups);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virPortGroupDefClear(&portgroup);
    return ret;
}


static int
virNetworkDefUpdateDNSHost(virNetworkDef *def,
                           unsigned int command G_GNUC_UNUSED,
                           int parentIndex G_GNUC_UNUSED,
                           xmlXPathContextPtr ctxt G_GNUC_UNUSED,
                           /* virNetworkUpdateFlags */
                           unsigned int fflags G_GNUC_UNUSED)
{
    size_t i, j, k;
    int foundIdx = -1, ret = -1;
    virNetworkDNSDef *dns = &def->dns;
    virNetworkDNSHostDef host = { 0 };
    bool isAdd = (command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST ||
                  command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST);
    int foundCt = 0;

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("DNS HOST records cannot be modified, only added or deleted"));
        goto cleanup;
    }

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "host") < 0)
        goto cleanup;

    if (virNetworkDNSHostDefParseXML(def->name, ctxt->node, &host, !isAdd) < 0)
        goto cleanup;

    for (i = 0; i < dns->nhosts; i++) {
        bool foundThisTime = false;

        if (virSocketAddrEqual(&host.ip, &dns->hosts[i].ip))
            foundThisTime = true;

        /* when adding we want to only check duplicates of address since having
         * multiple addresses with the same hostname is a legitimate configuration */
        if (!isAdd) {
            for (j = 0; j < host.nnames && !foundThisTime; j++) {
                for (k = 0; k < dns->hosts[i].nnames && !foundThisTime; k++) {
                    if (STREQ(host.names[j], dns->hosts[i].names[k]))
                        foundThisTime = true;
                }
            }
        }

        if (foundThisTime) {
            foundCt++;
            foundIdx = i;
        }
    }

    if (isAdd) {

        if (foundCt > 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("there is already at least one DNS HOST record with a matching field in network %1$s"),
                           def->name);
            goto cleanup;
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(dns->hosts,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : dns->nhosts, dns->nhosts, host) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (foundCt == 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching DNS HOST record in network %1$s"),
                           def->name);
            goto cleanup;
        }
        if (foundCt > 1) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("multiple matching DNS HOST records were found in network %1$s"),
                           def->name);
            goto cleanup;
        }

        /* remove it */
        virNetworkDNSHostDefClear(&dns->hosts[foundIdx]);
        VIR_DELETE_ELEMENT(dns->hosts, foundIdx, dns->nhosts);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkDNSHostDefClear(&host);
    return ret;
}


static int
virNetworkDefUpdateDNSSrv(virNetworkDef *def,
                          unsigned int command G_GNUC_UNUSED,
                          int parentIndex G_GNUC_UNUSED,
                          xmlXPathContextPtr ctxt G_GNUC_UNUSED,
                          /* virNetworkUpdateFlags */
                          unsigned int fflags G_GNUC_UNUSED)
{
    size_t i;
    int foundIdx = -1, ret = -1;
    virNetworkDNSDef *dns = &def->dns;
    virNetworkDNSSrvDef srv = { 0 };
    bool isAdd = (command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST ||
                  command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST);
    int foundCt = 0;

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("DNS SRV records cannot be modified, only added or deleted"));
        goto cleanup;
    }

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "srv") < 0)
        goto cleanup;

    if (virNetworkDNSSrvDefParseXML(def->name, ctxt->node, ctxt, &srv, !isAdd) < 0)
        goto cleanup;

    for (i = 0; i < dns->nsrvs; i++) {
        if ((!srv.domain || STREQ_NULLABLE(srv.domain, dns->srvs[i].domain)) &&
            (!srv.service || STREQ_NULLABLE(srv.service, dns->srvs[i].service)) &&
            (!srv.protocol || STREQ_NULLABLE(srv.protocol, dns->srvs[i].protocol)) &&
            (!srv.target || STREQ_NULLABLE(srv.target, dns->srvs[i].target))) {
            foundCt++;
            foundIdx = i;
        }
    }

    if (isAdd) {

        if (foundCt > 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("there is already at least one DNS SRV record matching all specified fields in network %1$s"),
                           def->name);
            goto cleanup;
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(dns->srvs,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : dns->nsrvs, dns->nsrvs, srv) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (foundCt == 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching DNS SRV record in network %1$s"),
                           def->name);
            goto cleanup;
        }
        if (foundCt > 1) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("multiple DNS SRV records matching all specified fields were found in network %1$s"),
                           def->name);
            goto cleanup;
        }

        /* remove it */
        virNetworkDNSSrvDefClear(&dns->srvs[foundIdx]);
        VIR_DELETE_ELEMENT(dns->srvs, foundIdx, dns->nsrvs);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkDNSSrvDefClear(&srv);
    return ret;
}


static int
virNetworkDefUpdateDNSTxt(virNetworkDef *def,
                          unsigned int command G_GNUC_UNUSED,
                          int parentIndex G_GNUC_UNUSED,
                          xmlXPathContextPtr ctxt G_GNUC_UNUSED,
                          /* virNetworkUpdateFlags */
                          unsigned int fflags G_GNUC_UNUSED)
{
    int foundIdx, ret = -1;
    virNetworkDNSDef *dns = &def->dns;
    virNetworkDNSTxtDef txt = { 0 };
    bool isAdd = (command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST ||
                  command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST);

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("DNS TXT records cannot be modified, only added or deleted"));
        goto cleanup;
    }

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "txt") < 0)
        goto cleanup;

    if (virNetworkDNSTxtDefParseXML(def->name, ctxt->node, &txt, !isAdd) < 0)
        goto cleanup;

    for (foundIdx = 0; foundIdx < dns->ntxts; foundIdx++) {
        if (STREQ(txt.name, dns->txts[foundIdx].name))
            break;
    }

    if (isAdd) {

        if (foundIdx < dns->ntxts) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("there is already a DNS TXT record with name '%1$s' in network %2$s"),
                           txt.name, def->name);
            goto cleanup;
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(dns->txts,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : dns->ntxts, dns->ntxts, txt) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (foundIdx == dns->ntxts) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching DNS TXT record in network %1$s"),
                           def->name);
            goto cleanup;
        }

        /* remove it */
        virNetworkDNSTxtDefClear(&dns->txts[foundIdx]);
        VIR_DELETE_ELEMENT(dns->txts, foundIdx, dns->ntxts);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkDNSTxtDefClear(&txt);
    return ret;
}


int
virNetworkDefUpdateSection(virNetworkDef *def,
                           unsigned int command, /* virNetworkUpdateCommand */
                           unsigned int section, /* virNetworkUpdateSection */
                           int parentIndex,
                           const char *xml,
                           unsigned int flags)  /* virNetworkUpdateFlags */
{
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;

    if (!(doc = virXMLParseStringCtxt(xml, _("network_update_xml"), &ctxt)))
        return -1;

    switch (section) {
    case VIR_NETWORK_SECTION_BRIDGE:
        return virNetworkDefUpdateBridge(def, command, parentIndex, ctxt, flags);

    case VIR_NETWORK_SECTION_DOMAIN:
        return virNetworkDefUpdateDomain(def, command, parentIndex, ctxt, flags);
    case VIR_NETWORK_SECTION_IP:
        return virNetworkDefUpdateIP(def, command, parentIndex, ctxt, flags);
    case VIR_NETWORK_SECTION_IP_DHCP_HOST:
        return virNetworkDefUpdateIPDHCPHost(def, command,
                                             parentIndex, ctxt, flags);
    case VIR_NETWORK_SECTION_IP_DHCP_RANGE:
        return virNetworkDefUpdateIPDHCPRange(def, command,
                                              parentIndex, ctxt, flags);
    case VIR_NETWORK_SECTION_FORWARD:
        return virNetworkDefUpdateForward(def, command,
                                          parentIndex, ctxt, flags);
    case VIR_NETWORK_SECTION_FORWARD_INTERFACE:
        return virNetworkDefUpdateForwardInterface(def, command,
                                                   parentIndex, ctxt, flags);
    case VIR_NETWORK_SECTION_FORWARD_PF:
        return virNetworkDefUpdateForwardPF(def, command,
                                            parentIndex, ctxt, flags);
    case VIR_NETWORK_SECTION_PORTGROUP:
        return virNetworkDefUpdatePortGroup(def, command,
                                            parentIndex, ctxt, flags);
    case VIR_NETWORK_SECTION_DNS_HOST:
        return virNetworkDefUpdateDNSHost(def, command,
                                          parentIndex, ctxt, flags);
    case VIR_NETWORK_SECTION_DNS_TXT:
        return virNetworkDefUpdateDNSTxt(def, command, parentIndex, ctxt, flags);
    case VIR_NETWORK_SECTION_DNS_SRV:
        return virNetworkDefUpdateDNSSrv(def, command, parentIndex, ctxt, flags);
    default:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("can't update unrecognized section of network"));
        break;
    }

    return -1;
}
