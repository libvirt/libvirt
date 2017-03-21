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
 *
 * Authors:
 *     Michal Privoznik <mprivozn@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "netdev_bandwidth_conf.h"
#include "virerror.h"
#include "viralloc.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
virNetDevBandwidthParseRate(xmlNodePtr node, virNetDevBandwidthRatePtr rate)
{
    int ret = -1;
    char *average = NULL;
    char *peak = NULL;
    char *burst = NULL;
    char *floor = NULL;

    if (!node || !rate) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid argument supplied"));
        return -1;
    }

    average = virXMLPropString(node, "average");
    peak = virXMLPropString(node, "peak");
    burst = virXMLPropString(node, "burst");
    floor = virXMLPropString(node, "floor");

    if (average) {
        if (virStrToLong_ullp(average, NULL, 10, &rate->average) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("could not convert bandwidth average value '%s'"),
                           average);
            goto cleanup;
        }
    } else if (!floor) {
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                       _("Missing mandatory average or floor attributes"));
        goto cleanup;
    }

    if ((peak || burst) && !average) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("'peak' and 'burst' require 'average' attribute"));
        goto cleanup;
    }

    if (peak && virStrToLong_ullp(peak, NULL, 10, &rate->peak) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not convert bandwidth peak value '%s'"),
                       peak);
        goto cleanup;
    }

    if (burst && virStrToLong_ullp(burst, NULL, 10, &rate->burst) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not convert bandwidth burst value '%s'"),
                       burst);
        goto cleanup;
    }

    if (floor && virStrToLong_ullp(floor, NULL, 10, &rate->floor) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not convert bandwidth floor value '%s'"),
                       floor);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(average);
    VIR_FREE(peak);
    VIR_FREE(burst);
    VIR_FREE(floor);

    return ret;
}

/**
 * virNetDevBandwidthParse:
 * @bandwidth: parsed bandwidth
 * @node: XML node
 * @net_type: one of virDomainNetType
 *
 * Parse bandwidth XML and return pointer to structure.
 * @net_type tell to which type will/is interface connected to.
 * Pass -1 if this is not called on interface.
 *
 * Returns !NULL on success, NULL on error.
 */
int
virNetDevBandwidthParse(virNetDevBandwidthPtr *bandwidth,
                        xmlNodePtr node,
                        int net_type)
{
    int ret = -1;
    virNetDevBandwidthPtr def = NULL;
    xmlNodePtr cur;
    xmlNodePtr in = NULL, out = NULL;

    if (VIR_ALLOC(def) < 0)
        return ret;

    if (!node || !xmlStrEqual(node->name, BAD_CAST "bandwidth")) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid argument supplied"));
        goto cleanup;
    }

    cur = node->children;

    while (cur) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "inbound")) {
                if (in) {
                    virReportError(VIR_ERR_XML_DETAIL, "%s",
                                   _("Only one child <inbound> "
                                     "element allowed"));
                    goto cleanup;
                }
                in = cur;
            } else if (xmlStrEqual(cur->name, BAD_CAST "outbound")) {
                if (out) {
                    virReportError(VIR_ERR_XML_DETAIL, "%s",
                                   _("Only one child <outbound> "
                                     "element allowed"));
                    goto cleanup;
                }
                out = cur;
            }
            /* Silently ignore unknown elements */
        }
        cur = cur->next;
    }

    if (in) {
        if (VIR_ALLOC(def->in) < 0)
            goto cleanup;

        if (virNetDevBandwidthParseRate(in, def->in) < 0) {
            /* helper reported error for us */
            goto cleanup;
        }

        if (def->in->floor && net_type != VIR_DOMAIN_NET_TYPE_NETWORK) {
            if (net_type == -1) {
                /* 'floor' on network isn't supported */
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("floor attribute isn't supported for "
                                 "network's bandwidth yet"));
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("floor attribute is supported only for "
                                 "interfaces of type network"));
            }
            goto cleanup;
        }
    }

    if (out) {
        if (VIR_ALLOC(def->out) < 0)
            goto cleanup;

        if (virNetDevBandwidthParseRate(out, def->out) < 0) {
            /* helper reported error for us */
            goto cleanup;
        }

        if (def->out->floor) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'floor' attribute allowed "
                             "only in <inbound> element"));
            goto cleanup;
        }
    }

    if (!def->in && !def->out)
        VIR_FREE(def);

    *bandwidth = def;
    def = NULL;
    ret = 0;

 cleanup:
    virNetDevBandwidthFree(def);
    return ret;
}

static int
virNetDevBandwidthRateFormat(virNetDevBandwidthRatePtr def,
                             virBufferPtr buf,
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
 * @buf: Buffer to print to
 *
 * Formats bandwidth and prepend each line with @indent.
 * @buf may use auto-indentation.
 *
 * Returns 0 on success, else -1.
 */
int
virNetDevBandwidthFormat(virNetDevBandwidthPtr def, virBufferPtr buf)
{
    int ret = -1;

    if (!buf)
        goto cleanup;

    if (!def) {
        ret = 0;
        goto cleanup;
    }

    virBufferAddLit(buf, "<bandwidth>\n");
    virBufferAdjustIndent(buf, 2);
    if (virNetDevBandwidthRateFormat(def->in, buf, "inbound") < 0 ||
        virNetDevBandwidthRateFormat(def->out, buf, "outbound") < 0)
        goto cleanup;
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bandwidth>\n");

    ret = 0;

 cleanup:
    return ret;
}

void
virDomainClearNetBandwidth(virDomainObjPtr vm)
{
    size_t i;
    virDomainNetType type;

    for (i = 0; i < vm->def->nnets; i++) {
        type = virDomainNetGetActualType(vm->def->nets[i]);
        if (virDomainNetGetActualBandwidth(vm->def->nets[i]) &&
            virNetDevSupportBandwidth(type))
            virNetDevBandwidthClear(vm->def->nets[i]->ifname);
    }
}
