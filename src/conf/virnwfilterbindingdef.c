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
#include "nwfilter_params.h"
#include "virnwfilterbindingdef.h"
#include "viruuid.h"


#define VIR_FROM_THIS VIR_FROM_NWFILTER

void
virNWFilterBindingDefFree(virNWFilterBindingDef *def)
{
    if (!def)
        return;

    g_free(def->ownername);
    g_free(def->portdevname);
    g_free(def->linkdevname);
    g_free(def->filter);
    g_clear_pointer(&def->filterparams, g_hash_table_unref);

    g_free(def);
}


virNWFilterBindingDef *
virNWFilterBindingDefCopy(virNWFilterBindingDef *src)
{
    g_autoptr(virNWFilterBindingDef) ret = g_new0(virNWFilterBindingDef, 1);

    ret->ownername = g_strdup(src->ownername);

    memcpy(ret->owneruuid, src->owneruuid, sizeof(ret->owneruuid));

    ret->portdevname = g_strdup(src->portdevname);

    ret->linkdevname = g_strdup(src->linkdevname);

    ret->mac = src->mac;

    ret->filter = g_strdup(src->filter);

    ret->filterparams = virHashNew(virNWFilterVarValueHashFree);

    if (virNWFilterHashTablePutAll(src->filterparams, ret->filterparams) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


virNWFilterBindingDef *
virNWFilterBindingDefParseXML(xmlXPathContextPtr ctxt)
{
    virNWFilterBindingDef *ret;
    char *uuid = NULL;
    char *mac = NULL;
    xmlNodePtr node;

    ret = g_new0(virNWFilterBindingDef, 1);

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
                       _("Unable to parse UUID '%1$s'"), uuid);
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
                       _("Unable to parse MAC '%1$s'"), mac);
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


virNWFilterBindingDef *
virNWFilterBindingDefParse(const char *xmlStr,
                           const char *filename,
                           unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    bool validate = flags & VIR_NWFILTER_BINDING_CREATE_VALIDATE;

    if (!(xml = virXMLParse(filename, xmlStr, _("(nwfilterbinding_definition)"),
                            "filterbinding", &ctxt, "nwfilterbinding.rng", validate)))
        return NULL;

    return virNWFilterBindingDefParseXML(ctxt);
}


char *
virNWFilterBindingDefFormat(const virNWFilterBindingDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (virNWFilterBindingDefFormatBuf(&buf, def) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


int
virNWFilterBindingDefFormatBuf(virBuffer *buf,
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
