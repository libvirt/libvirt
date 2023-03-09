/*
 * storage_encryption_conf.c: volume encryption information
 *
 * Copyright (C) 2009-2014 Red Hat, Inc.
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

#include <fcntl.h>
#include <unistd.h>

#include "internal.h"

#include "virbuffer.h"
#include "viralloc.h"
#include "storage_encryption_conf.h"
#include "virxml.h"
#include "virerror.h"
#include "virsecret.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_ENUM_IMPL(virStorageEncryptionSecret,
              VIR_STORAGE_ENCRYPTION_SECRET_TYPE_LAST,
              "passphrase",
);

VIR_ENUM_IMPL(virStorageEncryptionFormat,
              VIR_STORAGE_ENCRYPTION_FORMAT_LAST,
              "default", "qcow", "luks", "luks2", "luks-any",
);

VIR_ENUM_IMPL(virStorageEncryptionEngine,
              VIR_STORAGE_ENCRYPTION_ENGINE_LAST,
              "default", "qemu", "librbd",
);

static void
virStorageEncryptionInfoDefClear(virStorageEncryptionInfoDef *def)
{
    VIR_FREE(def->cipher_name);
    VIR_FREE(def->cipher_mode);
    VIR_FREE(def->cipher_hash);
    VIR_FREE(def->ivgen_name);
    VIR_FREE(def->ivgen_hash);
}


static void
virStorageEncryptionSecretFree(virStorageEncryptionSecret *secret)
{
    if (!secret)
        return;
    virSecretLookupDefClear(&secret->seclookupdef);
    g_free(secret);
}

void
virStorageEncryptionFree(virStorageEncryption *enc)
{
    size_t i;

    if (!enc)
        return;

    for (i = 0; i < enc->nsecrets; i++)
        virStorageEncryptionSecretFree(enc->secrets[i]);
    virStorageEncryptionInfoDefClear(&enc->encinfo);
    g_free(enc->secrets);
    g_free(enc);
}

static virStorageEncryptionSecret *
virStorageEncryptionSecretCopy(const virStorageEncryptionSecret *src)
{
    virStorageEncryptionSecret *ret = g_new0(virStorageEncryptionSecret, 1);

    ret->type = src->type;
    virSecretLookupDefCopy(&ret->seclookupdef, &src->seclookupdef);

    return ret;
}


static int
virStorageEncryptionInfoDefCopy(const virStorageEncryptionInfoDef *src,
                                virStorageEncryptionInfoDef *dst)
{
    dst->cipher_size = src->cipher_size;
    dst->cipher_name = g_strdup(src->cipher_name);
    dst->cipher_mode = g_strdup(src->cipher_mode);
    dst->cipher_hash = g_strdup(src->cipher_hash);
    dst->ivgen_name = g_strdup(src->ivgen_name);
    dst->ivgen_hash = g_strdup(src->ivgen_hash);

    return 0;
}


virStorageEncryption *
virStorageEncryptionCopy(const virStorageEncryption *src)
{
    virStorageEncryption *ret;
    size_t i;

    ret = g_new0(virStorageEncryption, 1);

    ret->secrets = g_new0(virStorageEncryptionSecret *, src->nsecrets);
    ret->nsecrets = src->nsecrets;
    ret->format = src->format;
    ret->engine = src->engine;

    for (i = 0; i < src->nsecrets; i++) {
        if (!(ret->secrets[i] = virStorageEncryptionSecretCopy(src->secrets[i])))
            goto error;
    }

    if (virStorageEncryptionInfoDefCopy(&src->encinfo, &ret->encinfo) < 0)
        goto error;

    return ret;

 error:
    virStorageEncryptionFree(ret);
    return NULL;
}

static virStorageEncryptionSecret *
virStorageEncryptionSecretParse(xmlXPathContextPtr ctxt,
                                xmlNodePtr node)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    virStorageEncryptionSecret *ret;
    g_autofree char *type_str = NULL;

    ret = g_new0(virStorageEncryptionSecret, 1);

    ctxt->node = node;

    if (!(type_str = virXPathString("string(./@type)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("unknown volume encryption secret type"));
        goto cleanup;
    }

    if ((ret->type = virStorageEncryptionSecretTypeFromString(type_str)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown volume encryption secret type %1$s"),
                       type_str);
        goto cleanup;
    }

    if (virSecretLookupParseSecret(node, &ret->seclookupdef) < 0)
        goto cleanup;

    return ret;

 cleanup:
    virStorageEncryptionSecretFree(ret);
    return NULL;
}


static int
virStorageEncryptionInfoParseCipher(xmlNodePtr info_node,
                                    virStorageEncryptionInfoDef *info)
{
    if (!(info->cipher_name = virXMLPropString(info_node, "name"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("cipher info missing 'name' attribute"));
        return -1;
    }

    if (virXMLPropUInt(info_node, "size", 10, VIR_XML_PROP_REQUIRED,
                       &info->cipher_size) < 0)
        return -1;

    info->cipher_mode = virXMLPropString(info_node, "mode");
    info->cipher_hash = virXMLPropString(info_node, "hash");

    return 0;
}


static int
virStorageEncryptionInfoParseIvgen(xmlNodePtr info_node,
                                   virStorageEncryptionInfoDef *info)
{
    if (!(info->ivgen_name = virXMLPropString(info_node, "name"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing ivgen info name string"));
        return -1;
    }

    info->ivgen_hash = virXMLPropString(info_node, "hash");

    return 0;
}


virStorageEncryption *
virStorageEncryptionParseNode(xmlNodePtr node,
                              xmlXPathContextPtr ctxt)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr *nodes = NULL;
    virStorageEncryption *encdef = NULL;
    virStorageEncryption *ret = NULL;
    g_autofree char *format_str = NULL;
    int n;
    size_t i;

    ctxt->node = node;

    encdef = g_new0(virStorageEncryption, 1);

    if (!(format_str = virXPathString("string(./@format)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("unknown volume encryption format"));
        goto cleanup;
    }

    if ((encdef->format =
         virStorageEncryptionFormatTypeFromString(format_str)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown volume encryption format type %1$s"),
                       format_str);
        goto cleanup;
    }

    if (virXMLPropEnum(node, "engine",
                       virStorageEncryptionEngineTypeFromString,
                       VIR_XML_PROP_NONZERO,
                       &encdef->engine) < 0)
      goto cleanup;

    if ((n = virXPathNodeSet("./secret", ctxt, &nodes)) < 0)
        goto cleanup;

    if (n > 0) {
        encdef->secrets = g_new0(virStorageEncryptionSecret *, n);
        encdef->nsecrets = n;

        for (i = 0; i < n; i++) {
            if (!(encdef->secrets[i] =
                  virStorageEncryptionSecretParse(ctxt, nodes[i])))
                goto cleanup;
        }
    }

    if (encdef->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
        xmlNodePtr tmpnode;

        if ((tmpnode = virXPathNode("./cipher[1]", ctxt))) {
            if (virStorageEncryptionInfoParseCipher(tmpnode, &encdef->encinfo) < 0)
                goto cleanup;
        }

        if ((tmpnode = virXPathNode("./ivgen[1]", ctxt))) {
            /* If no cipher node, then fail */
            if (!encdef->encinfo.cipher_name) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("ivgen element found, but cipher is missing"));
                goto cleanup;
            }

            if (virStorageEncryptionInfoParseIvgen(tmpnode, &encdef->encinfo) < 0)
                goto cleanup;
        }
    }

    ret = g_steal_pointer(&encdef);

 cleanup:
    VIR_FREE(nodes);
    virStorageEncryptionFree(encdef);

    return ret;
}


static int
virStorageEncryptionSecretFormat(virBuffer *buf,
                                 virStorageEncryptionSecret *secret)
{
    const char *type;

    if (!(type = virStorageEncryptionSecretTypeToString(secret->type))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unexpected volume encryption secret type"));
        return -1;
    }

    virSecretLookupFormatSecret(buf, type, &secret->seclookupdef);

    return 0;
}


static void
virStorageEncryptionInfoDefFormat(virBuffer *buf,
                                  const virStorageEncryptionInfoDef *enc)
{
    virBufferEscapeString(buf, "<cipher name='%s'", enc->cipher_name);
    virBufferAsprintf(buf, " size='%u'", enc->cipher_size);
    if (enc->cipher_mode)
        virBufferEscapeString(buf, " mode='%s'", enc->cipher_mode);
    if (enc->cipher_hash)
        virBufferEscapeString(buf, " hash='%s'", enc->cipher_hash);
    virBufferAddLit(buf, "/>\n");

    if (enc->ivgen_name) {
        virBufferEscapeString(buf, "<ivgen name='%s'", enc->ivgen_name);
        if (enc->ivgen_hash)
            virBufferEscapeString(buf, " hash='%s'", enc->ivgen_hash);
        virBufferAddLit(buf, "/>\n");
    }
}


int
virStorageEncryptionFormat(virBuffer *buf,
                           virStorageEncryption *enc)
{
    const char *engine;
    const char *format;
    size_t i;

    if (!(format = virStorageEncryptionFormatTypeToString(enc->format))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unexpected encryption format"));
        return -1;
    }
    if (enc->engine == VIR_STORAGE_ENCRYPTION_ENGINE_DEFAULT) {
        virBufferAsprintf(buf, "<encryption format='%s'>\n", format);
    } else {
        if (!(engine = virStorageEncryptionEngineTypeToString(enc->engine))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("unexpected encryption engine"));
            return -1;
        }
        virBufferAsprintf(buf, "<encryption format='%s' engine='%s'>\n",
                          format, engine);
    }

    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < enc->nsecrets; i++) {
        if (virStorageEncryptionSecretFormat(buf, enc->secrets[i]) < 0)
            return -1;
    }

    if (enc->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS &&
        enc->encinfo.cipher_name)
        virStorageEncryptionInfoDefFormat(buf, &enc->encinfo);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</encryption>\n");

    return 0;
}
