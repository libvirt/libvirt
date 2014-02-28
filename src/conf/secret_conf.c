/*
 * secret_conf.c: internal <secret> XML handling
 *
 * Copyright (C) 2009, 2011, 2013, 2014 Red Hat, Inc.
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
 * Red Hat Author: Miloslav Trmač <mitr@redhat.com>
 */

#include <config.h>

#include "internal.h"
#include "virbuffer.h"
#include "datatypes.h"
#include "virlog.h"
#include "viralloc.h"
#include "secret_conf.h"
#include "virerror.h"
#include "virxml.h"
#include "viruuid.h"

#define VIR_FROM_THIS VIR_FROM_SECRET

VIR_LOG_INIT("conf.secret_conf");

VIR_ENUM_IMPL(virSecretUsageType, VIR_SECRET_USAGE_TYPE_LAST,
              "none", "volume", "ceph", "iscsi")

void
virSecretDefFree(virSecretDefPtr def)
{
    if (def == NULL)
        return;

    VIR_FREE(def->description);
    switch (def->usage_type) {
    case VIR_SECRET_USAGE_TYPE_NONE:
        break;

    case VIR_SECRET_USAGE_TYPE_VOLUME:
        VIR_FREE(def->usage.volume);
        break;

    case VIR_SECRET_USAGE_TYPE_CEPH:
        VIR_FREE(def->usage.ceph);
        break;

    case VIR_SECRET_USAGE_TYPE_ISCSI:
        VIR_FREE(def->usage.target);
        break;

    default:
        VIR_ERROR(_("unexpected secret usage type %d"), def->usage_type);
        break;
    }
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
    type = virSecretUsageTypeTypeFromString(type_str);
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
        def->usage.volume = virXPathString("string(./usage/volume)", ctxt);
        if (!def->usage.volume) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("volume usage specified, but volume path is missing"));
            return -1;
        }
        break;

    case VIR_SECRET_USAGE_TYPE_CEPH:
        def->usage.ceph = virXPathString("string(./usage/name)", ctxt);
        if (!def->usage.ceph) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Ceph usage specified, but name is missing"));
            return -1;
        }
        break;

    case VIR_SECRET_USAGE_TYPE_ISCSI:
        def->usage.target = virXPathString("string(./usage/target)", ctxt);
        if (!def->usage.target) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("iSCSI usage specified, but target is missing"));
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
    xmlXPathContextPtr ctxt = NULL;
    virSecretDefPtr def = NULL, ret = NULL;
    char *prop = NULL;
    char *uuidstr = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "secret")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected root element <%s>, "
                         "expecting <secret>"),
                       root->name);
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }
    ctxt->node = root;

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    prop = virXPathString("string(./@ephemeral)", ctxt);
    if (prop != NULL) {
        if (STREQ(prop, "yes"))
            def->ephemeral = true;
        else if (STREQ(prop, "no"))
            def->ephemeral = false;
        else {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("invalid value of 'ephemeral'"));
            goto cleanup;
        }
        VIR_FREE(prop);
    }

    prop = virXPathString("string(./@private)", ctxt);
    if (prop != NULL) {
        if (STREQ(prop, "yes"))
            def->private = true;
        else if (STREQ(prop, "no"))
            def->private = false;
        else {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("invalid value of 'private'"));
            goto cleanup;
        }
        VIR_FREE(prop);
    }

    uuidstr = virXPathString("string(./uuid)", ctxt);
    if (!uuidstr) {
        if (virUUIDGenerate(def->uuid)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Failed to generate UUID"));
            goto cleanup;
        }
    } else {
        if (virUUIDParse(uuidstr, def->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed uuid element"));
            goto cleanup;
        }
        VIR_FREE(uuidstr);
    }

    def->description = virXPathString("string(./description)", ctxt);
    if (virXPathNode("./usage", ctxt) != NULL
        && virSecretDefParseUsage(ctxt, def) < 0)
        goto cleanup;
    ret = def;
    def = NULL;

 cleanup:
    VIR_FREE(prop);
    VIR_FREE(uuidstr);
    virSecretDefFree(def);
    xmlXPathFreeContext(ctxt);
    return ret;
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

    type = virSecretUsageTypeTypeToString(def->usage_type);
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
        if (def->usage.volume != NULL)
            virBufferEscapeString(buf, "<volume>%s</volume>\n",
                                  def->usage.volume);
        break;

    case VIR_SECRET_USAGE_TYPE_CEPH:
        if (def->usage.ceph != NULL) {
            virBufferEscapeString(buf, "<name>%s</name>\n",
                                  def->usage.ceph);
        }
        break;

    case VIR_SECRET_USAGE_TYPE_ISCSI:
        if (def->usage.target != NULL) {
            virBufferEscapeString(buf, "<target>%s</target>\n",
                                  def->usage.target);
        }
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
                      def->ephemeral ? "yes" : "no",
                      def->private ? "yes" : "no");

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

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virReportOOMError();
 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}
