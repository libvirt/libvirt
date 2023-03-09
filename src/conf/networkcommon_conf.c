/*
 * networkcommon_conf.c: network XML handling
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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

#include "virerror.h"
#include "networkcommon_conf.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

virNetDevIPRoute *
virNetDevIPRouteCreate(const char *errorDetail,
                       const char *family,
                       const char *address,
                       const char *netmask,
                       const char *gateway,
                       unsigned int prefix,
                       bool hasPrefix,
                       unsigned int metric,
                       bool hasMetric)
{
    g_autoptr(virNetDevIPRoute) def = NULL;
    virSocketAddr testAddr;

    def = g_new0(virNetDevIPRoute, 1);

    def->family = g_strdup(family);

    def->prefix = prefix;
    def->has_prefix = hasPrefix;
    def->metric = metric;
    def->has_metric = hasMetric;

    /* Note: both network and gateway addresses must be specified */

    if (!address) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%1$s: Missing required address attribute in route definition"),
                       errorDetail);
        return NULL;
    }

    if (!gateway) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%1$s: Missing required gateway attribute in route definition"),
                       errorDetail);
        return NULL;
    }

    if (virSocketAddrParse(&def->address, address, AF_UNSPEC) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%1$s: Bad network address '%2$s' in route definition"),
                       errorDetail, address);
        return NULL;
    }

    if (virSocketAddrParse(&def->gateway, gateway, AF_UNSPEC) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%1$s: Bad gateway address '%2$s' in route definition"),
                       errorDetail, gateway);
        return NULL;
    }

    /* validate network address, etc. for each family */
    if ((def->family == NULL) || (STREQ(def->family, "ipv4"))) {
        if (!(VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET) ||
              VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_UNSPEC))) {
            virReportError(VIR_ERR_XML_ERROR,
                           def->family == NULL ?
                           _("%1$s: No family specified for non-IPv4 address '%2$s' in route definition") :
                           _("%1$s: IPv4 family specified for non-IPv4 address '%2$s' in route definition"),
                           errorDetail, address);
            return NULL;
        }
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->gateway, AF_INET)) {
            virReportError(VIR_ERR_XML_ERROR,
                           def->family == NULL ?
                           _("%1$s: No family specified for non-IPv4 gateway '%2$s' in route definition") :
                           _("%1$s: IPv4 family specified for non-IPv4 gateway '%2$s' in route definition"),
                           errorDetail, address);
            return NULL;
        }
        if (netmask) {
            if (virSocketAddrParse(&def->netmask, netmask, AF_UNSPEC) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("%1$s: Bad netmask address '%2$s' in route definition"),
                               errorDetail, netmask);
                return NULL;
            }
            if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->netmask, AF_INET)) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("%1$s: Invalid netmask '%2$s' for address '%3$s' (both must be IPv4)"),
                               errorDetail, netmask, address);
                return NULL;
            }
            if (def->has_prefix) {
                /* can't have both netmask and prefix at the same time */
                virReportError(VIR_ERR_XML_ERROR,
                               _("%1$s: Route definition cannot have both a prefix and a netmask"),
                               errorDetail);
                return NULL;
            }
        }
        if (def->prefix > 32) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%1$s: Invalid prefix %2$u specified in route definition, must be 0 - 32"),
                           errorDetail, def->prefix);
            return NULL;
        }
    } else if (STREQ(def->family, "ipv6")) {
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET6)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%1$s: ipv6 family specified for non-IPv6 address '%2$s' in route definition"),
                           errorDetail, address);
            return NULL;
        }
        if (netmask) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%1$s: Specifying netmask invalid for IPv6 address '%2$s' in route definition"),
                           errorDetail, address);
            return NULL;
        }
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->gateway, AF_INET6)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%1$s: ipv6 specified for non-IPv6 gateway address '%2$s' in route definition"),
                           errorDetail, gateway);
            return NULL;
        }
        if (def->prefix > 128) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%1$s: Invalid prefix %2$u specified in route definition, must be 0 - 128"),
                           errorDetail, def->prefix);
            return NULL;
        }
    } else {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%1$s: Unrecognized family '%2$s' in route definition"),
                       errorDetail, def->family);
        return NULL;
    }

    /* make sure the address is a network address */
    if (netmask) {
        if (virSocketAddrMask(&def->address, &def->netmask, &testAddr) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%1$s: Error converting address '%2$s' with netmask '%3$s' to network-address in route definition"),
                           errorDetail, address, netmask);
            return NULL;
        }
    } else {
        if (virSocketAddrMaskByPrefix(&def->address,
                                      def->prefix, &testAddr) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%1$s: Error converting address '%2$s' with prefix %3$u to network-address in route definition"),
                           errorDetail, address, def->prefix);
            return NULL;
        }
    }
    if (!virSocketAddrEqual(&def->address, &testAddr)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%1$s: Address '%2$s' in route definition is not a network address"),
                       errorDetail, address);
        return NULL;
    }

    return g_steal_pointer(&def);
}

virNetDevIPRoute *
virNetDevIPRouteParseXML(const char *errorDetail,
                         xmlNodePtr node)
{
    g_autofree char *family = virXMLPropString(node, "family");
    g_autofree char *address = virXMLPropString(node, "address");
    g_autofree char *netmask = virXMLPropString(node, "netmask");
    g_autofree char *gateway = virXMLPropString(node, "gateway");
    unsigned int prefix = 0;
    unsigned int metric = 0;
    bool hasPrefix = false;
    bool hasMetric = false;
    int rc;

    if ((rc = virXMLPropUInt(node, "prefix", 10, VIR_XML_PROP_NONE, &prefix)) < 0)
        return NULL;

    if (rc == 1)
        hasPrefix = true;

    if ((rc = virXMLPropUInt(node, "metric", 10, VIR_XML_PROP_NONZERO, &metric)) < 0)
        return NULL;

    if (rc == 1)
        hasMetric = true;

    return virNetDevIPRouteCreate(errorDetail, family, address, netmask,
                                  gateway, prefix, hasPrefix, metric,
                                  hasMetric);
}

int
virNetDevIPRouteFormat(virBuffer *buf,
                       const virNetDevIPRoute *def)
{
    g_autofree char *address = NULL;
    g_autofree char *netmask = NULL;
    g_autofree char *gateway = NULL;

    virBufferAddLit(buf, "<route");

    if (def->family)
        virBufferAsprintf(buf, " family='%s'", def->family);

    if (!(address = virSocketAddrFormat(&def->address)))
        return -1;
    virBufferAsprintf(buf, " address='%s'", address);

    if (VIR_SOCKET_ADDR_VALID(&def->netmask)) {
        if (!(netmask = virSocketAddrFormat(&def->netmask)))
            return -1;
        virBufferAsprintf(buf, " netmask='%s'", netmask);
    }
    if (def->has_prefix)
        virBufferAsprintf(buf, " prefix='%u'", def->prefix);

    if (!(gateway = virSocketAddrFormat(&def->gateway)))
        return -1;
    virBufferAsprintf(buf, " gateway='%s'", gateway);

    if (def->has_metric && def->metric > 0)
        virBufferAsprintf(buf, " metric='%u'", def->metric);
    virBufferAddLit(buf, "/>\n");

    return 0;
}
