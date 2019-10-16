/*
 * virstorageencryption.c: volume encryption information
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
#include "virstorageencryption.h"
#include "virxml.h"
#include "virerror.h"
#include "viruuid.h"
#include "virfile.h"
#include "virsecret.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_ENUM_IMPL(virStorageEncryptionSecret,
              VIR_STORAGE_ENCRYPTION_SECRET_TYPE_LAST,
              "passphrase",
);

VIR_ENUM_IMPL(virStorageEncryptionFormat,
              VIR_STORAGE_ENCRYPTION_FORMAT_LAST,
              "default", "qcow", "luks",
);

static void
virStorageEncryptionInfoDefFree(virStorageEncryptionInfoDefPtr def)
{
    VIR_FREE(def->cipher_name);
    VIR_FREE(def->cipher_mode);
    VIR_FREE(def->cipher_hash);
    VIR_FREE(def->ivgen_name);
    VIR_FREE(def->ivgen_hash);
}


static void
virStorageEncryptionSecretFree(virStorageEncryptionSecretPtr secret)
{
    if (!secret)
        return;
    virSecretLookupDefClear(&secret->seclookupdef);
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
    virStorageEncryptionInfoDefFree(&enc->encinfo);
    VIR_FREE(enc->secrets);
    VIR_FREE(enc);
}

static virStorageEncryptionSecretPtr
virStorageEncryptionSecretCopy(const virStorageEncryptionSecret *src)
{
    virStorageEncryptionSecretPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    memcpy(ret, src, sizeof(*src));

    return ret;
}


static int
virStorageEncryptionInfoDefCopy(const virStorageEncryptionInfoDef *src,
                                virStorageEncryptionInfoDefPtr dst)
{
    dst->cipher_size = src->cipher_size;
    if (VIR_STRDUP(dst->cipher_name, src->cipher_name) < 0 ||
        VIR_STRDUP(dst->cipher_mode, src->cipher_mode) < 0 ||
        VIR_STRDUP(dst->cipher_hash, src->cipher_hash) < 0 ||
        VIR_STRDUP(dst->ivgen_name, src->ivgen_name) < 0 ||
        VIR_STRDUP(dst->ivgen_hash, src->ivgen_hash) < 0)
        return -1;

    return 0;
}


virStorageEncryptionPtr
virStorageEncryptionCopy(const virStorageEncryption *src)
{
    virStorageEncryptionPtr ret;
    size_t i;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (VIR_ALLOC_N(ret->secrets, src->nsecrets) < 0)
        goto error;

    ret->nsecrets = src->nsecrets;
    ret->format = src->format;

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

static virStorageEncryptionSecretPtr
virStorageEncryptionSecretParse(xmlXPathContextPtr ctxt,
                                xmlNodePtr node)
{
    xmlNodePtr old_node;
    virStorageEncryptionSecretPtr ret;
    char *type_str = NULL;
    char *uuidstr = NULL;
    char *usagestr = NULL;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    old_node = ctxt->node;
    ctxt->node = node;

    if (!(type_str = virXPathString("string(./@type)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("unknown volume encryption secret type"));
        goto cleanup;
    }

    if ((ret->type = virStorageEncryptionSecretTypeFromString(type_str)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown volume encryption secret type %s"),
                       type_str);
        goto cleanup;
    }

    if (virSecretLookupParseSecret(node, &ret->seclookupdef) < 0)
        goto cleanup;

    VIR_FREE(type_str);

    ctxt->node = old_node;
    return ret;

 cleanup:
    VIR_FREE(type_str);
    virStorageEncryptionSecretFree(ret);
    VIR_FREE(uuidstr);
    VIR_FREE(usagestr);
    ctxt->node = old_node;
    return NULL;
}


static int
virStorageEncryptionInfoParseCipher(xmlNodePtr info_node,
                                    virStorageEncryptionInfoDefPtr info)
{
    int ret = -1;
    char *size_str = NULL;

    if (!(info->cipher_name = virXMLPropString(info_node, "name"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("cipher info missing 'name' attribute"));
        goto cleanup;
    }

    if ((size_str = virXMLPropString(info_node, "size")) &&
        virStrToLong_uip(size_str, NULL, 10, &info->cipher_size) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("cannot parse cipher size: '%s'"),
                       size_str);
        goto cleanup;
    }

    if (!size_str) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("cipher info missing 'size' attribute"));
        goto cleanup;
    }

    info->cipher_mode = virXMLPropString(info_node, "mode");
    info->cipher_hash = virXMLPropString(info_node, "hash");

    ret = 0;

 cleanup:
    VIR_FREE(size_str);
    return ret;
}


static int
virStorageEncryptionInfoParseIvgen(xmlNodePtr info_node,
                                   virStorageEncryptionInfoDefPtr info)
{
    if (!(info->ivgen_name = virXMLPropString(info_node, "name"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing ivgen info name string"));
        return -1;
    }

    info->ivgen_hash = virXMLPropString(info_node, "hash");

    return 0;
}


virStorageEncryptionPtr
virStorageEncryptionParseNode(xmlNodePtr node,
                              xmlXPathContextPtr ctxt)
{
    xmlNodePtr saveNode = ctxt->node;
    xmlNodePtr *nodes = NULL;
    virStorageEncryptionPtr encdef = NULL;
    virStorageEncryptionPtr ret = NULL;
    char *format_str = NULL;
    int n;
    size_t i;

    ctxt->node = node;

    if (VIR_ALLOC(encdef) < 0)
        goto cleanup;

    if (!(format_str = virXPathString("string(./@format)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("unknown volume encryption format"));
        goto cleanup;
    }

    if ((encdef->format =
         virStorageEncryptionFormatTypeFromString(format_str)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown volume encryption format type %s"),
                       format_str);
        goto cleanup;
    }

    if ((n = virXPathNodeSet("./secret", ctxt, &nodes)) < 0)
        goto cleanup;

    if (n > 0) {
        if (VIR_ALLOC_N(encdef->secrets, n) < 0)
            goto cleanup;
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
    VIR_FREE(format_str);
    VIR_FREE(nodes);
    virStorageEncryptionFree(encdef);
    ctxt->node = saveNode;

    return ret;
}


static int
virStorageEncryptionSecretFormat(virBufferPtr buf,
                                 virStorageEncryptionSecretPtr secret)
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
virStorageEncryptionInfoDefFormat(virBufferPtr buf,
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
virStorageEncryptionFormat(virBufferPtr buf,
                           virStorageEncryptionPtr enc)
{
    const char *format;
    size_t i;

    if (!(format = virStorageEncryptionFormatTypeToString(enc->format))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("unexpected encryption format"));
        return -1;
    }
    virBufferAsprintf(buf, "<encryption format='%s'>\n", format);
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

int
virStorageGenerateQcowPassphrase(unsigned char *dest)
{
    int fd;
    size_t i;

    /* A qcow passphrase is up to 16 bytes, with any data following a NUL
       ignored.  Prohibit control and non-ASCII characters to avoid possible
       unpleasant surprises with the qemu monitor input mechanism. */
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot open /dev/urandom"));
        return -1;
    }
    i = 0;
    while (i < VIR_STORAGE_QCOW_PASSPHRASE_SIZE) {
        ssize_t r;

        while ((r = read(fd, dest + i, 1)) == -1 && errno == EINTR)
            ;
        if (r <= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot read from /dev/urandom"));
            VIR_FORCE_CLOSE(fd);
            return -1;
        }
        if (dest[i] >= 0x20 && dest[i] <= 0x7E)
            i++; /* Got an acceptable character */
    }
    VIR_FORCE_CLOSE(fd);
    return 0;
}
