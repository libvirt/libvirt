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
virNetDevBandwidthParse(virNetDevBandwidthPtr *bandwidth,
                        unsigned int *class_id,
                        xmlNodePtr node,
                        bool allowFloor)
{
    int ret = -1;
    virNetDevBandwidthPtr def = NULL;
    xmlNodePtr cur;
    xmlNodePtr in = NULL, out = NULL;
    char *class_id_prop = NULL;

    if (VIR_ALLOC(def) < 0)
        return ret;

    if (!node || !virXMLNodeNameEqual(node, "bandwidth")) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid argument supplied"));
        goto cleanup;
    }

    class_id_prop = virXMLPropString(node, "classID");
    if (class_id_prop) {
        if (!class_id) {
            virReportError(VIR_ERR_XML_DETAIL, "%s",
                           _("classID attribute not supported on <bandwidth> "
                             "in this usage context"));
            goto cleanup;
        }
        if (virStrToLong_ui(class_id_prop, NULL, 10, class_id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse class id '%s'"),
                           class_id_prop);
            goto cleanup;
        }
    }

    cur = node->children;

    while (cur) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (virXMLNodeNameEqual(cur, "inbound")) {
                if (in) {
                    virReportError(VIR_ERR_XML_DETAIL, "%s",
                                   _("Only one child <inbound> "
                                     "element allowed"));
                    goto cleanup;
                }
                in = cur;
            } else if (virXMLNodeNameEqual(cur, "outbound")) {
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

        if (def->in->floor && !allowFloor) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("floor attribute is not supported for this config"));
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
    VIR_FREE(class_id_prop);
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
 * @class_id: the class ID to format, 0 to skip
 * @buf: Buffer to print to
 *
 * Formats bandwidth and prepend each line with @indent.
 * @buf may use auto-indentation.
 *
 * Returns 0 on success, else -1.
 */
int
virNetDevBandwidthFormat(virNetDevBandwidthPtr def,
                         unsigned int class_id,
                         virBufferPtr buf)
{
    int ret = -1;

    if (!buf)
        goto cleanup;

    if (!def) {
        ret = 0;
        goto cleanup;
    }

    virBufferAddLit(buf, "<bandwidth");
    if (class_id)
        virBufferAsprintf(buf, " classID='%u'", class_id);
    virBufferAddLit(buf, ">\n");
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
