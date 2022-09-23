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


int
virSaveCookieParse(xmlXPathContextPtr ctxt,
                   virObject **obj,
                   virSaveCookieCallbacks *saveCookie)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    *obj = NULL;

    if (!(ctxt->node = virXPathNode("./cookie", ctxt)))
        return 0;

    if (!saveCookie || !saveCookie->parse)
        return 0;

    return saveCookie->parse(ctxt, obj);
}


int
virSaveCookieParseString(const char *xml,
                         virObject **obj,
                         virSaveCookieCallbacks *saveCookie)
{
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;

    *obj = NULL;

    if (!xml || !saveCookie || !saveCookie->parse)
        return 0;

    if (!(doc = virXMLParse(NULL, xml, _("(save cookie)"), "cookie", &ctxt, NULL, false)))
        return -1;

    return saveCookie->parse(ctxt, obj);
}


int
virSaveCookieFormatBuf(virBuffer *buf,
                       virObject *obj,
                       virSaveCookieCallbacks *saveCookie)
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
virSaveCookieFormat(virObject *obj,
                    virSaveCookieCallbacks *saveCookie)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (virSaveCookieFormatBuf(&buf, obj, saveCookie) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}
