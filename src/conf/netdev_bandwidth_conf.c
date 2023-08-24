/*
 * Copyright (C) 2009-2015 Red Hat, Inc.
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

#include "netdev_bandwidth_conf.h"
#include "virerror.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
virNetDevBandwidthParseRate(xmlNodePtr node,
                            virNetDevBandwidthRate *rate,
                            bool allowFloor)
{
    int rc_average;
    int rc_peak;
    int rc_burst;
    int rc_floor;

    if ((rc_average = virXMLPropULongLong(node, "average", 10, VIR_XML_PROP_NONE,
                                          &rate->average)) < 0)
        return -1;

    if ((rc_peak = virXMLPropULongLong(node, "peak", 10, VIR_XML_PROP_NONE,
                                       &rate->peak)) < 0)
        return -1;

    if ((rc_burst = virXMLPropULongLong(node, "burst", 10, VIR_XML_PROP_NONE,
                                        &rate->burst)) < 0)
        return -1;

    if ((rc_floor = virXMLPropULongLong(node, "floor", 10, VIR_XML_PROP_NONE,
                                        &rate->floor)) < 0)
        return -1;

    if (!rc_average && !rc_floor) {
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                       _("Missing mandatory average or floor attributes"));
        return -1;
    }

    if ((rc_peak || rc_burst) && !rc_average) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("'peak' and 'burst' require 'average' attribute"));
        return -1;
    }

    if (rc_floor && !allowFloor) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("floor attribute is not supported for this config"));
        return -1;
    }

    return 0;
}

/**
 * virNetDevBandwidthParse:
 * @bandwidth: parsed bandwidth
 * @class_id: parsed class ID
 * @node: XML node
 * @allowFloor: whether "floor" setting is supported
 *
 * Parse bandwidth XML and return pointer to structure.
 * The @allowFloor attribute indicates whether the caller
 * is able to support use of the "floor" setting.
 *
 * Returns !NULL on success, NULL on error.
 */
int
virNetDevBandwidthParse(virNetDevBandwidth **bandwidth,
                        unsigned int *class_id,
                        xmlNodePtr node,
                        bool allowFloor)
{
    g_autoptr(virNetDevBandwidth) def = NULL;
    xmlNodePtr in;
    xmlNodePtr out;
    unsigned int class_id_value;
    int rc;

    def = g_new0(virNetDevBandwidth, 1);


    if ((rc = virXMLPropUInt(node, "classID", 10, VIR_XML_PROP_NONE, &class_id_value)) < 0)
        return -1;

    if (rc == 1) {
        if (!class_id) {
            virReportError(VIR_ERR_XML_DETAIL, "%s",
                           _("classID attribute not supported on <bandwidth> in this usage context"));
            return -1;
        }

        *class_id = class_id_value;
    }

    if ((in = virXMLNodeGetSubelement(node, "inbound"))) {
        def->in = g_new0(virNetDevBandwidthRate, 1);

        if (virNetDevBandwidthParseRate(in, def->in, allowFloor) < 0)
            return -1;
    }

    if ((out = virXMLNodeGetSubelement(node, "outbound"))) {
        def->out = g_new0(virNetDevBandwidthRate, 1);

        /* floor is not allowed for <outbound> */
        if (virNetDevBandwidthParseRate(out, def->out, false) < 0)
            return -1;
    }

    if (def->in || def->out)
        *bandwidth = g_steal_pointer(&def);

    return 0;
}

static int
virNetDevBandwidthRateFormat(virNetDevBandwidthRate *def,
                             virBuffer *buf,
                             const char *elem_name)
{
    if (!buf || !elem_name)
        return -1;
    if (!def)
        return 0;

    if (def->average || def->floor) {
        virBufferAsprintf(buf, "<%s", elem_name);

        if (def->average)
            virBufferAsprintf(buf, " average='%llu'", def->average);

        if (def->peak)
            virBufferAsprintf(buf, " peak='%llu'", def->peak);

        if (def->floor)
            virBufferAsprintf(buf, " floor='%llu'", def->floor);

        if (def->burst)
            virBufferAsprintf(buf, " burst='%llu'", def->burst);
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}

/**
 * virNetDevBandwidthFormat:
 * @def: Data source
 * @class_id: the class ID to format, 0 to skip
 * @buf: Buffer to print to
 *
 * Formats bandwidth and prepend each line with @indent.
 * @buf may use auto-indentation.
 *
 * Returns 0 on success, else -1.
 */
int
virNetDevBandwidthFormat(const virNetDevBandwidth *def,
                         unsigned int class_id,
                         virBuffer *buf)
{
    if (!buf)
        return -1;

    if (!def)
        return 0;

    virBufferAddLit(buf, "<bandwidth");
    if (class_id)
        virBufferAsprintf(buf, " classID='%u'", class_id);
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);
    if (virNetDevBandwidthRateFormat(def->in, buf, "inbound") < 0 ||
        virNetDevBandwidthRateFormat(def->out, buf, "outbound") < 0)
        return -1;
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bandwidth>\n");

    return 0;
}

void
virDomainClearNetBandwidth(virDomainDef *def)
{
    size_t i;
    virDomainNetType type;

    for (i = 0; i < def->nnets; i++) {
        type = virDomainNetGetActualType(def->nets[i]);
        if (virDomainNetGetActualBandwidth(def->nets[i]) &&
            virNetDevSupportsBandwidth(type))
            virNetDevBandwidthClear(def->nets[i]->ifname);
    }
}


bool virNetDevSupportsBandwidth(virDomainNetType type)
{
    switch ((virDomainNetType) type) {
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        return true;
    case VIR_DOMAIN_NET_TYPE_USER:
    case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_MCAST:
    case VIR_DOMAIN_NET_TYPE_UDP:
    case VIR_DOMAIN_NET_TYPE_INTERNAL:
    case VIR_DOMAIN_NET_TYPE_HOSTDEV:
    case VIR_DOMAIN_NET_TYPE_VDPA:
    case VIR_DOMAIN_NET_TYPE_NULL:
    case VIR_DOMAIN_NET_TYPE_VDS:
    case VIR_DOMAIN_NET_TYPE_LAST:
        break;
    }
    return false;
}


bool
virNetDevBandwidthHasFloor(const virNetDevBandwidth *b)
{
    return b && b->in && b->in->floor != 0;
}


bool virNetDevBandwidthSupportsFloor(virNetworkForwardType type)
{
    switch (type) {
    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        return true;
    case VIR_NETWORK_FORWARD_BRIDGE:
    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
    case VIR_NETWORK_FORWARD_HOSTDEV:
    case VIR_NETWORK_FORWARD_LAST:
        break;
    }
    return false;
}
