/*
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
 * Authors:
 *     Michal Privoznik <mprivozn@redhat.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "netdev_bandwidth_conf.h"
#include "virterror_internal.h"
#include "util.h"
#include "memory.h"

#define VIR_FROM_THIS VIR_FROM_NONE
#define virNetDevError(code, ...)                                   \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,             \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


static int
virNetDevBandwidthParseRate(xmlNodePtr node, virNetDevBandwidthRatePtr rate)
{
    int ret = -1;
    char *average = NULL;
    char *peak = NULL;
    char *burst = NULL;

    if (!node || !rate) {
        virNetDevError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid argument supplied"));
        return -1;
    }

    average = virXMLPropString(node, "average");
    peak = virXMLPropString(node, "peak");
    burst = virXMLPropString(node, "burst");

    if (average) {
        if (virStrToLong_ull(average, NULL, 10, &rate->average) < 0) {
            virNetDevError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("could not convert %s"),
                           average);
            goto cleanup;
        }
    } else {
        virNetDevError(VIR_ERR_XML_DETAIL, "%s",
                       _("Missing mandatory average attribute"));
        goto cleanup;
    }

    if (peak && virStrToLong_ull(peak, NULL, 10, &rate->peak) < 0) {
        virNetDevError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not convert %s"),
                       peak);
        goto cleanup;
    }

    if (burst && virStrToLong_ull(burst, NULL, 10, &rate->burst) < 0) {
        virNetDevError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("could not convert %s"),
                       burst);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(average);
    VIR_FREE(peak);
    VIR_FREE(burst);

    return ret;
}

/**
 * virNetDevBandwidthParse:
 * @node: XML node
 *
 * Parse bandwidth XML and return pointer to structure
 *
 * Returns !NULL on success, NULL on error.
 */
virNetDevBandwidthPtr
virNetDevBandwidthParse(xmlNodePtr node)
{
    virNetDevBandwidthPtr def = NULL;
    xmlNodePtr cur = node->children;
    xmlNodePtr in = NULL, out = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (!node || !xmlStrEqual(node->name, BAD_CAST "bandwidth")) {
        virNetDevError(VIR_ERR_INVALID_ARG, "%s",
                       _("invalid argument supplied"));
        goto error;
    }

    while (cur) {
        if (cur->type == XML_ELEMENT_NODE) {
            if (xmlStrEqual(cur->name, BAD_CAST "inbound")) {
                if (in) {
                    virNetDevError(VIR_ERR_XML_DETAIL, "%s",
                                   _("Only one child <inbound> "
                                     "element allowed"));
                    goto error;
                }
                in = cur;
            } else if (xmlStrEqual(cur->name, BAD_CAST "outbound")) {
                if (out) {
                    virNetDevError(VIR_ERR_XML_DETAIL, "%s",
                                   _("Only one child <outbound> "
                                     "element allowed"));
                    goto error;
                }
                out = cur;
            }
            /* Silently ignore unknown elements */
        }
        cur = cur->next;
    }

    if (in) {
        if (VIR_ALLOC(def->in) < 0) {
            virReportOOMError();
            goto error;
        }

        if (virNetDevBandwidthParseRate(in, def->in) < 0) {
            /* helper reported error for us */
            goto error;
        }
    }

    if (out) {
        if (VIR_ALLOC(def->out) < 0) {
            virReportOOMError();
            goto error;
        }

        if (virNetDevBandwidthParseRate(out, def->out) < 0) {
            /* helper reported error for us */
            goto error;
        }
    }

    return def;

error:
    virNetDevBandwidthFree(def);
    return NULL;
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

    if (def->average) {
        virBufferAsprintf(buf, "  <%s average='%llu'", elem_name,
                          def->average);

        if (def->peak)
            virBufferAsprintf(buf, " peak='%llu'", def->peak);

        if (def->burst)
            virBufferAsprintf(buf, " burst='%llu'", def->burst);
        virBufferAddLit(buf, "/>\n");
    }

    return 0;
}

/**
 * virNetDevBandwidthDefFormat:
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
    if (virNetDevBandwidthRateFormat(def->in, buf, "inbound") < 0 ||
        virNetDevBandwidthRateFormat(def->out, buf, "outbound") < 0)
        goto cleanup;
    virBufferAddLit(buf, "</bandwidth>\n");

    ret = 0;

cleanup:
    return ret;
}
