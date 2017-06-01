/**
 * virsavecookie.c: Save cookie handling
 *
 * Copyright (C) 2017 Red Hat, Inc.
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
#include "virlog.h"
#include "virobject.h"
#include "virbuffer.h"
#include "virxml.h"
#include "virsavecookie.h"

#define VIR_FROM_THIS VIR_FROM_CONF

VIR_LOG_INIT("conf.savecookie");


static int
virSaveCookieParseNode(xmlXPathContextPtr ctxt,
                       virObjectPtr *obj,
                       virSaveCookieCallbacksPtr saveCookie)
{
    *obj = NULL;

    if (!xmlStrEqual(ctxt->node->name, BAD_CAST "cookie")) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("XML does not contain expected 'cookie' element"));
        return -1;
    }

    if (!saveCookie || !saveCookie->parse)
        return 0;

    return saveCookie->parse(ctxt, obj);
}


int
virSaveCookieParse(xmlXPathContextPtr ctxt,
                   virObjectPtr *obj,
                   virSaveCookieCallbacksPtr saveCookie)
{
    xmlNodePtr node = ctxt->node;
    int ret = -1;

    *obj = NULL;

    if (!(ctxt->node = virXPathNode("./cookie", ctxt))) {
        ret = 0;
        goto cleanup;
    }

    ret = virSaveCookieParseNode(ctxt, obj, saveCookie);

 cleanup:
    ctxt->node = node;
    return ret;
}


int
virSaveCookieParseString(const char *xml,
                         virObjectPtr *obj,
                         virSaveCookieCallbacksPtr saveCookie)
{
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr ctxt = NULL;
    int ret = -1;

    *obj = NULL;

    if (!xml) {
        ret = 0;
        goto cleanup;
    }

    if (!(doc = virXMLParseStringCtxt(xml, _("(save cookie)"), &ctxt)))
        goto cleanup;

    ret = virSaveCookieParseNode(ctxt, obj, saveCookie);

 cleanup:
    xmlXPathFreeContext(ctxt);
    xmlFreeDoc(doc);
    return ret;
}


int
virSaveCookieFormatBuf(virBufferPtr buf,
                       virObjectPtr obj,
                       virSaveCookieCallbacksPtr saveCookie)
{
    if (!obj || !saveCookie || !saveCookie->format)
        return 0;

    virBufferAddLit(buf, "<cookie>\n");
    virBufferAdjustIndent(buf, 2);

    if (saveCookie->format(buf, obj) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</cookie>\n");

    return 0;
}


char *
virSaveCookieFormat(virObjectPtr obj,
                    virSaveCookieCallbacksPtr saveCookie)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (virSaveCookieFormatBuf(&buf, obj, saveCookie) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}
