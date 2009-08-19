/*
 * storage_encryption_conf.h: volume encryption information
 *
 * Copyright (C) 2009 Red Hat, Inc.
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
 * Red Hat Author: Miloslav Trmač <mitr@redhat.com>
 */

#include <config.h>

#include "internal.h"

#include "base64.h"
#include "buf.h"
#include "memory.h"
#include "storage_conf.h"
#include "storage_encryption_conf.h"
#include "util.h"
#include "xml.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_ENUM_IMPL(virStorageEncryptionSecretType,
              VIR_STORAGE_ENCRYPTION_SECRET_TYPE_LAST, "passphrase")

VIR_ENUM_IMPL(virStorageEncryptionFormat,
              VIR_STORAGE_ENCRYPTION_FORMAT_LAST,
              "default", "qcow")

static void
virStorageEncryptionSecretFree(virStorageEncryptionSecretPtr secret)
{
    if (!secret)
        return;
    VIR_FREE(secret->uuid);
    VIR_FREE(secret);
}

void
virStorageEncryptionFree(virStorageEncryptionPtr enc)
{
    size_t i;

    if (!enc)
        return;

    for (i = 0; i < enc->nsecrets; i++)
        virStorageEncryptionSecretFree(enc->secrets[i]);
    VIR_FREE(enc->secrets);
    VIR_FREE(enc);
}

static virStorageEncryptionSecretPtr
virStorageEncryptionSecretParse(virConnectPtr conn, xmlXPathContextPtr ctxt,
                                xmlNodePtr node)
{
    xmlNodePtr old_node;
    virStorageEncryptionSecretPtr ret;
    char *type_str;
    int type;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    old_node = ctxt->node;
    ctxt->node = node;

    type_str = virXPathString(conn, "string(./@type)", ctxt);
    if (type_str == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR, "%s",
                              _("unknown volume encryption secret type"));
        goto cleanup;
    }
    type = virStorageEncryptionSecretTypeTypeFromString(type_str);
    if (type < 0) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              _("unknown volume encryption secret type %s"),
                              type_str);
        VIR_FREE(type_str);
        goto cleanup;
    }
    VIR_FREE(type_str);
    ret->type = type;

    ret->uuid = virXPathString(conn, "string(./@uuid)", ctxt);
    ctxt->node = old_node;
    return ret;

  cleanup:
    virStorageEncryptionSecretFree(ret);
    ctxt->node = old_node;
    return NULL;
}

static virStorageEncryptionPtr
virStorageEncryptionParseXML(virConnectPtr conn, xmlXPathContextPtr ctxt)
{
    xmlNodePtr *nodes = NULL;
    virStorageEncryptionPtr ret;
    char *format_str;
    int format, i, n;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    format_str = virXPathString(conn, "string(./@format)", ctxt);
    if (format_str == NULL) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR, "%s",
                              _("unknown volume encryption format"));
        goto cleanup;
    }
    format = virStorageEncryptionFormatTypeFromString(format_str);
    if (format < 0) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              _("unknown volume encryption format type %s"),
                              format_str);
        VIR_FREE(format_str);
        goto cleanup;
    }
    VIR_FREE(format_str);
    ret->format = format;

    n = virXPathNodeSet(conn, "./secret", ctxt, &nodes);
    if (n < 0){
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                              _("cannot extract volume encryption secrets"));
        goto cleanup;
    }
    if (n != 0 && VIR_ALLOC_N(ret->secrets, n) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }
    ret->nsecrets = n;
    for (i = 0; i < n; i++) {
        ret->secrets[i] = virStorageEncryptionSecretParse(conn, ctxt, nodes[i]);
        if (ret->secrets[i] == NULL)
            goto cleanup;
    }
    VIR_FREE(nodes);

    return ret;

  cleanup:
    VIR_FREE(nodes);
    virStorageEncryptionFree(ret);
    return NULL;
}

virStorageEncryptionPtr
virStorageEncryptionParseNode(virConnectPtr conn,
                              xmlDocPtr xml, xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virStorageEncryptionPtr enc = NULL;

    if (STRNEQ((const char *) root->name, "encryption")) {
        virStorageReportError(conn, VIR_ERR_XML_ERROR,
                              "%s", _("unknown root element for volume "
                                      "encryption information"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    ctxt->node = root;
    enc = virStorageEncryptionParseXML(conn, ctxt);

  cleanup:
    xmlXPathFreeContext(ctxt);
    return enc;
}

static int
virStorageEncryptionSecretFormat(virConnectPtr conn,
                                 virBufferPtr buf,
                                 virStorageEncryptionSecretPtr secret)
{
    const char *type;

    type = virStorageEncryptionSecretTypeTypeToString(secret->type);
    if (!type) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                              _("unexpected volume encryption secret type"));
        return -1;
    }

    virBufferVSprintf(buf, "    <secret type='%s'", type);
    if (secret->uuid != NULL)
        virBufferEscapeString(buf, " uuid='%s'", secret->uuid);
    virBufferAddLit(buf, "/>\n");
    return 0;
}

int
virStorageEncryptionFormat(virConnectPtr conn,
                           virBufferPtr buf,
                           virStorageEncryptionPtr enc)
{
    const char *format;
    size_t i;

    format = virStorageEncryptionFormatTypeToString(enc->format);
    if (!format) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("unexpected encryption format"));
        return -1;
    }
    virBufferVSprintf(buf, "  <encryption format='%s'>\n", format);

    for (i = 0; i < enc->nsecrets; i++) {
        if (virStorageEncryptionSecretFormat(conn, buf, enc->secrets[i]) < 0)
            return -1;
    }

    virBufferAddLit(buf, "  </encryption>\n");

    return 0;
}
