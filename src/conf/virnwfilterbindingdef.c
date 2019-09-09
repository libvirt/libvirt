/*
 * virnwfilterbindingdef.c: network filter binding XML processing
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#include "viralloc.h"
#include "virerror.h"
#include "virstring.h"
#include "nwfilter_params.h"
#include "virnwfilterbindingdef.h"
#include "viruuid.h"


#define VIR_FROM_THIS VIR_FROM_NWFILTER

void
virNWFilterBindingDefFree(virNWFilterBindingDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->ownername);
    VIR_FREE(def->portdevname);
    VIR_FREE(def->linkdevname);
    VIR_FREE(def->filter);
    virHashFree(def->filterparams);

    VIR_FREE(def);
}


virNWFilterBindingDefPtr
virNWFilterBindingDefCopy(virNWFilterBindingDefPtr src)
{
    virNWFilterBindingDefPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (VIR_STRDUP(ret->ownername, src->ownername) < 0)
        goto error;

    memcpy(ret->owneruuid, src->owneruuid, sizeof(ret->owneruuid));

    if (VIR_STRDUP(ret->portdevname, src->portdevname) < 0)
        goto error;

    if (VIR_STRDUP(ret->linkdevname, src->linkdevname) < 0)
        goto error;

    ret->mac = src->mac;

    if (VIR_STRDUP(ret->filter, src->filter) < 0)
        goto error;

    if (!(ret->filterparams = virNWFilterHashTableCreate(0)))
        goto error;

    if (virNWFilterHashTablePutAll(src->filterparams, ret->filterparams) < 0)
        goto error;

    return ret;

 error:
    virNWFilterBindingDefFree(ret);
    return NULL;
}


static virNWFilterBindingDefPtr
virNWFilterBindingDefParseXML(xmlXPathContextPtr ctxt)
{
    virNWFilterBindingDefPtr ret;
    char *uuid = NULL;
    char *mac = NULL;
    xmlNodePtr node;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->portdevname = virXPathString("string(./portdev/@name)", ctxt);
    if (!ret->portdevname) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("filter binding has no port dev name"));
        goto cleanup;
    }

    if (virXPathNode("./linkdev", ctxt)) {
        ret->linkdevname = virXPathString("string(./linkdev/@name)", ctxt);
        if (!ret->linkdevname) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("filter binding has no link dev name"));
            goto cleanup;
        }
    }

    ret->ownername = virXPathString("string(./owner/name)", ctxt);
    if (!ret->ownername) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("filter binding has no owner name"));
        goto cleanup;
    }

    uuid = virXPathString("string(./owner/uuid)", ctxt);
    if (!uuid) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("filter binding has no owner UUID"));
        goto cleanup;
    }

    if (virUUIDParse(uuid, ret->owneruuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse UUID '%s'"), uuid);
        VIR_FREE(uuid);
        goto cleanup;
    }
    VIR_FREE(uuid);

    mac = virXPathString("string(./mac/@address)", ctxt);
    if (!mac) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("filter binding has no MAC address"));
        goto cleanup;
    }

    if (virMacAddrParse(mac, &ret->mac) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse MAC '%s'"), mac);
        VIR_FREE(mac);
        goto cleanup;
    }
    VIR_FREE(mac);

    ret->filter = virXPathString("string(./filterref/@filter)", ctxt);
    if (!ret->filter) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("filter binding has no filter reference"));
        goto cleanup;
    }

    node = virXPathNode("./filterref", ctxt);
    if (node &&
        !(ret->filterparams = virNWFilterParseParamAttributes(node)))
        goto cleanup;

    return ret;

 cleanup:
    virNWFilterBindingDefFree(ret);
    return NULL;
}


virNWFilterBindingDefPtr
virNWFilterBindingDefParseNode(xmlDocPtr xml,
                               xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virNWFilterBindingDefPtr def = NULL;

    if (STRNEQ((const char *)root->name, "filterbinding")) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s",
                       _("unknown root element for nwfilter binding"));
        goto cleanup;
    }

    if (!(ctxt = virXMLXPathContextNew(xml)))
        goto cleanup;

    ctxt->node = root;
    def = virNWFilterBindingDefParseXML(ctxt);

 cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}


static virNWFilterBindingDefPtr
virNWFilterBindingDefParse(const char *xmlStr,
                           const char *filename)
{
    virNWFilterBindingDefPtr def = NULL;
    xmlDocPtr xml;

    if ((xml = virXMLParse(filename, xmlStr, _("(nwfilterbinding_definition)")))) {
        def = virNWFilterBindingDefParseNode(xml, xmlDocGetRootElement(xml));
        xmlFreeDoc(xml);
    }

    return def;
}


virNWFilterBindingDefPtr
virNWFilterBindingDefParseString(const char *xmlStr)
{
    return virNWFilterBindingDefParse(xmlStr, NULL);
}


virNWFilterBindingDefPtr
virNWFilterBindingDefParseFile(const char *filename)
{
    return virNWFilterBindingDefParse(NULL, filename);
}


char *
virNWFilterBindingDefFormat(const virNWFilterBindingDef *def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (virNWFilterBindingDefFormatBuf(&buf, def) < 0) {
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


int
virNWFilterBindingDefFormatBuf(virBufferPtr buf,
                               const virNWFilterBindingDef *def)
{
    char uuid[VIR_UUID_STRING_BUFLEN];
    char mac[VIR_MAC_STRING_BUFLEN];

    virBufferAddLit(buf, "<filterbinding>\n");

    virBufferAdjustIndent(buf, 2);

    virBufferAddLit(buf, "<owner>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<name>%s</name>\n", def->ownername);
    virUUIDFormat(def->owneruuid, uuid);
    virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuid);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</owner>\n");

    virBufferEscapeString(buf, "<portdev name='%s'/>\n", def->portdevname);
    if (def->linkdevname)
        virBufferEscapeString(buf, "<linkdev name='%s'/>\n", def->linkdevname);

    virMacAddrFormat(&def->mac, mac);
    virBufferAsprintf(buf, "<mac address='%s'/>\n", mac);

    if (virNWFilterFormatParamAttributes(buf, def->filterparams, def->filter) < 0)
        return -1;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</filterbinding>\n");

    return 0;
}
