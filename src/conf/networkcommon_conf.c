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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "virerror.h"
#include "datatypes.h"
#include "networkcommon_conf.h"
#include "viralloc.h"
#include "virstring.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

struct _virNetworkRouteDef {
    char *family;               /* ipv4 or ipv6 - default is ipv4 */
    virSocketAddr address;      /* Routed Network IP address */

    /* One or the other of the following two will be used for a given
     * Network address, but never both. The parser guarantees this.
     * The virSocketAddrGetIpPrefix() can be used to get a
     * valid prefix.
     */
    virSocketAddr netmask;      /* ipv4 - either netmask or prefix specified */
    unsigned int prefix;        /* ipv6 - only prefix allowed */
    bool has_prefix;            /* prefix= was specified */
    unsigned int metric;        /* value for metric (defaults to 1) */
    bool has_metric;            /* metric= was specified */
    virSocketAddr gateway;      /* gateway IP address for ip-route */
};

void
virNetworkRouteDefFree(virNetworkRouteDefPtr def)
{
    if (!def)
        return;
    VIR_FREE(def->family);
    VIR_FREE(def);
}

virNetworkRouteDefPtr
virNetworkRouteDefCreate(const char *errorDetail,
                         char *family,
                         const char *address,
                         const char *netmask,
                         const char *gateway,
                         unsigned int prefix,
                         bool hasPrefix,
                         unsigned int metric,
                         bool hasMetric)
{
    virNetworkRouteDefPtr def = NULL;
    virSocketAddr testAddr;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    if (VIR_STRDUP(def->family, family) < 0)
        goto error;

    def->prefix = prefix;
    def->has_prefix = hasPrefix;
    def->metric = metric;
    def->has_metric = hasMetric;

    /* Note: both network and gateway addresses must be specified */

    if (!address) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%s: Missing required address attribute "
                         "in route definition"),
                       errorDetail);
        goto error;
    }

    if (!gateway) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%s: Missing required gateway attribute "
                         "in route definition"),
                       errorDetail);
        goto error;
    }

    if (virSocketAddrParse(&def->address, address, AF_UNSPEC) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%s: Bad network address '%s' "
                         "in route definition"),
                       errorDetail, address);
        goto error;
    }

    if (virSocketAddrParse(&def->gateway, gateway, AF_UNSPEC) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%s: Bad gateway address '%s' "
                         "in route definition"),
                       errorDetail, gateway);
        goto error;
    }

    /* validate network address, etc. for each family */
    if ((def->family == NULL) || (STREQ(def->family, "ipv4"))) {
        if (!(VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET) ||
              VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_UNSPEC))) {
            virReportError(VIR_ERR_XML_ERROR,
                           def->family == NULL ?
                           _("%s: No family specified for non-IPv4 address '%s' "
                             "in route definition") :
                           _("%s: IPv4 family specified for non-IPv4 address '%s' "
                             "in route definition"),
                           errorDetail, address);
            goto error;
        }
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->gateway, AF_INET)) {
            virReportError(VIR_ERR_XML_ERROR,
                           def->family == NULL ?
                           _("%s: No family specified for non-IPv4 gateway '%s' "
                             "in route definition") :
                           _("%s: IPv4 family specified for non-IPv4 gateway '%s' "
                             "in route definition"),
                           errorDetail, address);
            goto error;
        }
        if (netmask) {
            if (virSocketAddrParse(&def->netmask, netmask, AF_UNSPEC) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("%s: Bad netmask address '%s' "
                                 "in route definition"),
                               errorDetail, netmask);
                goto error;
            }
            if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->netmask, AF_INET)) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("%s: Invalid netmask '%s' "
                                 "for address '%s' (both must be IPv4)"),
                               errorDetail, netmask, address);
                goto error;
            }
            if (def->has_prefix) {
                /* can't have both netmask and prefix at the same time */
                virReportError(VIR_ERR_XML_ERROR,
                               _("%s: Route definition cannot have both "
                                 "a prefix and a netmask"),
                               errorDetail);
                goto error;
            }
        }
        if (def->prefix > 32) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%s: Invalid prefix %u specified "
                             "in route definition, "
                             "must be 0 - 32"),
                           errorDetail, def->prefix);
            goto error;
        }
    } else if (STREQ(def->family, "ipv6")) {
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET6)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%s: ipv6 family specified for non-IPv6 address '%s' "
                             "in route definition"),
                           errorDetail, address);
            goto error;
        }
        if (netmask) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%s: Specifying netmask invalid for IPv6 address '%s' "
                             "in route definition"),
                           errorDetail, address);
            goto error;
        }
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->gateway, AF_INET6)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%s: ipv6 specified for non-IPv6 gateway address '%s' "
                             "in route definition"),
                           errorDetail, gateway);
            goto error;
        }
        if (def->prefix > 128) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%s: Invalid prefix %u specified "
                             "in route definition, "
                             "must be 0 - 128"),
                           errorDetail, def->prefix);
            goto error;
        }
    } else {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%s: Unrecognized family '%s' "
                         "in route definition"),
                       errorDetail, def->family);
        goto error;
    }

    /* make sure the address is a network address */
    if (netmask) {
        if (virSocketAddrMask(&def->address, &def->netmask, &testAddr) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%s: Error converting address '%s' with netmask '%s' "
                             "to network-address "
                             "in route definition"),
                           errorDetail, address, netmask);
            goto error;
        }
    } else {
        if (virSocketAddrMaskByPrefix(&def->address,
                                      def->prefix, &testAddr) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%s: Error converting address '%s' with prefix %u "
                             "to network-address "
                             "in route definition"),
                           errorDetail, address, def->prefix);
            goto error;
        }
    }
    if (!virSocketAddrEqual(&def->address, &testAddr)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%s: Address '%s' in route definition "
                         "is not a network address"),
                       errorDetail, address);
        goto error;
    }

    return def;

 error:
    virNetworkRouteDefFree(def);
    return NULL;
}

virNetworkRouteDefPtr
virNetworkRouteDefParseXML(const char *errorDetail,
                           xmlNodePtr node,
                           xmlXPathContextPtr ctxt)
{
    /*
     * virNetworkRouteDef object is already allocated as part
     * of an array.  On failure clear: it out, but don't free it.
     */

    virNetworkRouteDefPtr def = NULL;
    xmlNodePtr save;
    char *family = NULL;
    char *address = NULL, *netmask = NULL;
    char *gateway = NULL;
    unsigned long prefix = 0, metric = 0;
    int prefixRc, metricRc;
    bool hasPrefix = false;
    bool hasMetric = false;

    save = ctxt->node;
    ctxt->node = node;

    /* grab raw data from XML */
    family = virXPathString("string(./@family)", ctxt);
    address = virXPathString("string(./@address)", ctxt);
    netmask = virXPathString("string(./@netmask)", ctxt);
    gateway = virXPathString("string(./@gateway)", ctxt);
    prefixRc = virXPathULong("string(./@prefix)", ctxt, &prefix);
    if (prefixRc == -2) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%s: Invalid prefix specified "
                         "in route definition"),
                       errorDetail);
        goto cleanup;
    }
    hasPrefix = (prefixRc == 0);
    metricRc = virXPathULong("string(./@metric)", ctxt, &metric);
    if (metricRc == -2) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("%s: Invalid metric specified "
                         "in route definition"),
                       errorDetail);
        goto cleanup;
    }
    if (metricRc == 0) {
        hasMetric = true;
        if (metric == 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%s: Invalid metric value, must be > 0 "
                             "in route definition"),
                           errorDetail);
            goto cleanup;
        }
    }

    def = virNetworkRouteDefCreate(errorDetail, family, address, netmask,
                                   gateway, prefix, hasPrefix, metric,
                                   hasMetric);

 cleanup:
    ctxt->node = save;
    VIR_FREE(family);
    VIR_FREE(address);
    VIR_FREE(netmask);
    VIR_FREE(gateway);
    return def;
}

int
virNetworkRouteDefFormat(virBufferPtr buf,
                         const virNetworkRouteDef *def)
{
    int result = -1;
    char *addr = NULL;

    virBufferAddLit(buf, "<route");

    if (def->family)
        virBufferAsprintf(buf, " family='%s'", def->family);

    if (!(addr = virSocketAddrFormat(&def->address)))
        goto cleanup;
    virBufferAsprintf(buf, " address='%s'", addr);
    VIR_FREE(addr);

    if (VIR_SOCKET_ADDR_VALID(&def->netmask)) {
        if (!(addr = virSocketAddrFormat(&def->netmask)))
            goto cleanup;
        virBufferAsprintf(buf, " netmask='%s'", addr);
        VIR_FREE(addr);
    }
    if (def->has_prefix)
        virBufferAsprintf(buf, " prefix='%u'", def->prefix);

    if (!(addr = virSocketAddrFormat(&def->gateway)))
        goto cleanup;
    virBufferAsprintf(buf, " gateway='%s'", addr);
    VIR_FREE(addr);

    if (def->has_metric && def->metric > 0)
        virBufferAsprintf(buf, " metric='%u'", def->metric);
    virBufferAddLit(buf, "/>\n");

    result = 0;
 cleanup:
    return result;
}

virSocketAddrPtr
virNetworkRouteDefGetAddress(virNetworkRouteDefPtr def)
{
    if (def)
        return &def->address;

    return NULL;
}

int
virNetworkRouteDefGetPrefix(virNetworkRouteDefPtr def)
{
    int prefix = 0;
    virSocketAddr zero;

    if (!def)
        return -1;

    /* this creates an all-0 address of the appropriate family */
    ignore_value(virSocketAddrParse(&zero,
                                    (VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET)
                                     ? VIR_SOCKET_ADDR_IPV4_ALL
                                     : VIR_SOCKET_ADDR_IPV6_ALL),
                                    VIR_SOCKET_ADDR_FAMILY(&def->address)));

    if (virSocketAddrEqual(&def->address, &zero)) {
        if (def->has_prefix && def->prefix == 0)
            prefix = 0;
        else if ((VIR_SOCKET_ADDR_IS_FAMILY(&def->netmask, AF_INET) &&
                  virSocketAddrEqual(&def->netmask, &zero)))
            prefix = 0;
        else
            prefix = virSocketAddrGetIpPrefix(&def->address, &def->netmask,
                                              def->prefix);
    } else {
        prefix = virSocketAddrGetIpPrefix(&def->address, &def->netmask,
                                          def->prefix);
    }

    return prefix;
}

unsigned int
virNetworkRouteDefGetMetric(virNetworkRouteDefPtr def)
{
    if (def && def->has_metric && def->metric > 0)
        return def->metric;

    return 1;
}

virSocketAddrPtr
virNetworkRouteDefGetGateway(virNetworkRouteDefPtr def)
{
    if (def)
        return &def->gateway;
    return NULL;
}
