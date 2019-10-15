/*
 * secret_conf.c: internal <secret> XML handling
 *
 * Copyright (C) 2009-2014, 2016 Red Hat, Inc.
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

#include "internal.h"
#include "virbuffer.h"
#include "datatypes.h"
#include "virlog.h"
#include "viralloc.h"
#include "secret_conf.h"
#include "virsecretobj.h"
#include "virerror.h"
#include "virsecret.h"
#include "virstring.h"
#include "virxml.h"
#include "viruuid.h"

#define VIR_FROM_THIS VIR_FROM_SECRET

VIR_LOG_INIT("conf.secret_conf");

void
virSecretDefFree(virSecretDefPtr def)
{
    if (def == NULL)
        return;

    VIR_FREE(def->description);
    VIR_FREE(def->usage_id);
    VIR_FREE(def);
}

static int
virSecretDefParseUsage(xmlXPathContextPtr ctxt,
                       virSecretDefPtr def)
{
    char *type_str;
    int type;

    type_str = virXPathString("string(./usage/@type)", ctxt);
    if (type_str == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("unknown secret usage type"));
        return -1;
    }
    type = virSecretUsageTypeFromString(type_str);
    if (type < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown secret usage type %s"), type_str);
        VIR_FREE(type_str);
        return -1;
    }
    VIR_FREE(type_str);
    def->usage_type = type;
    switch (def->usage_type) {
    case VIR_SECRET_USAGE_TYPE_NONE:
        break;

    case VIR_SECRET_USAGE_TYPE_VOLUME:
        def->usage_id = virXPathString("string(./usage/volume)", ctxt);
        if (!def->usage_id) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("volume usage specified, but volume path is missing"));
            return -1;
        }
        break;

    case VIR_SECRET_USAGE_TYPE_CEPH:
        def->usage_id = virXPathString("string(./usage/name)", ctxt);
        if (!def->usage_id) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Ceph usage specified, but name is missing"));
            return -1;
        }
        break;

    case VIR_SECRET_USAGE_TYPE_ISCSI:
        def->usage_id = virXPathString("string(./usage/target)", ctxt);
        if (!def->usage_id) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("iSCSI usage specified, but target is missing"));
            return -1;
        }
        break;

    case VIR_SECRET_USAGE_TYPE_TLS:
        def->usage_id = virXPathString("string(./usage/name)", ctxt);
        if (!def->usage_id) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("TLS usage specified, but name is missing"));
            return -1;
        }
        break;

    case VIR_SECRET_USAGE_TYPE_VTPM:
        def->usage_id = virXPathString("string(./usage/name)", ctxt);
        if (!def->usage_id) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("vTPM usage specified, but name is missing"));
            return -1;
        }
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected secret usage type %d"),
                       def->usage_type);
        return -1;
    }
    return 0;
}

static virSecretDefPtr
secretXMLParseNode(xmlDocPtr xml, xmlNodePtr root)
{
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autoptr(virSecretDef) def = NULL;
    g_autofree char *prop = NULL;
    g_autofree char *uuidstr = NULL;

    if (!virXMLNodeNameEqual(root, "secret")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected root element <%s>, "
                         "expecting <secret>"),
                       root->name);
        return NULL;
    }

    if (!(ctxt = virXMLXPathContextNew(xml)))
        return NULL;

    ctxt->node = root;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    prop = virXPathString("string(./@ephemeral)", ctxt);
    if (prop != NULL) {
        if (virStringParseYesNo(prop, &def->isephemeral) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("invalid value of 'ephemeral'"));
            return NULL;
        }
        VIR_FREE(prop);
    }

    prop = virXPathString("string(./@private)", ctxt);
    if (prop != NULL) {
        if (virStringParseYesNo(prop, &def->isprivate) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("invalid value of 'private'"));
            return NULL;
        }
        VIR_FREE(prop);
    }

    uuidstr = virXPathString("string(./uuid)", ctxt);
    if (!uuidstr) {
        if (virUUIDGenerate(def->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Failed to generate UUID"));
            return NULL;
        }
    } else {
        if (virUUIDParse(uuidstr, def->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed uuid element"));
            return NULL;
        }
        VIR_FREE(uuidstr);
    }

    def->description = virXPathString("string(./description)", ctxt);
    if (virXPathNode("./usage", ctxt) != NULL
        && virSecretDefParseUsage(ctxt, def) < 0)
        return NULL;

    VIR_RETURN_PTR(def);
}

static virSecretDefPtr
virSecretDefParse(const char *xmlStr,
                  const char *filename)
{
    xmlDocPtr xml;
    virSecretDefPtr ret = NULL;

    if ((xml = virXMLParse(filename, xmlStr, _("(definition_of_secret)")))) {
        ret = secretXMLParseNode(xml, xmlDocGetRootElement(xml));
        xmlFreeDoc(xml);
    }

    return ret;
}

virSecretDefPtr
virSecretDefParseString(const char *xmlStr)
{
    return virSecretDefParse(xmlStr, NULL);
}

virSecretDefPtr
virSecretDefParseFile(const char *filename)
{
    return virSecretDefParse(NULL, filename);
}

static int
virSecretDefFormatUsage(virBufferPtr buf,
                        const virSecretDef *def)
{
    const char *type;

    type = virSecretUsageTypeToString(def->usage_type);
    if (type == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected secret usage type %d"),
                       def->usage_type);
        return -1;
    }
    virBufferAsprintf(buf, "<usage type='%s'>\n", type);
    virBufferAdjustIndent(buf, 2);
    switch (def->usage_type) {
    case VIR_SECRET_USAGE_TYPE_NONE:
        break;

    case VIR_SECRET_USAGE_TYPE_VOLUME:
        virBufferEscapeString(buf, "<volume>%s</volume>\n", def->usage_id);
        break;

    case VIR_SECRET_USAGE_TYPE_CEPH:
        virBufferEscapeString(buf, "<name>%s</name>\n", def->usage_id);
        break;

    case VIR_SECRET_USAGE_TYPE_ISCSI:
        virBufferEscapeString(buf, "<target>%s</target>\n", def->usage_id);
        break;

    case VIR_SECRET_USAGE_TYPE_TLS:
        virBufferEscapeString(buf, "<name>%s</name>\n", def->usage_id);
        break;

    case VIR_SECRET_USAGE_TYPE_VTPM:
        virBufferEscapeString(buf, "<name>%s</name>\n", def->usage_id);
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected secret usage type %d"),
                       def->usage_type);
        return -1;
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</usage>\n");

    return 0;
}

char *
virSecretDefFormat(const virSecretDef *def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virBufferAsprintf(&buf, "<secret ephemeral='%s' private='%s'>\n",
                      def->isephemeral ? "yes" : "no",
                      def->isprivate ? "yes" : "no");

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<uuid>%s</uuid>\n", uuidstr);
    if (def->description != NULL)
        virBufferEscapeString(&buf, "<description>%s</description>\n",
                              def->description);
    if (def->usage_type != VIR_SECRET_USAGE_TYPE_NONE &&
        virSecretDefFormatUsage(&buf, def) < 0)
        goto error;
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</secret>\n");

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}
