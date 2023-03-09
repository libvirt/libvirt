/*
 * virsecret.c: secret utility functions
 *
 * Copyright (C) 2016 Red Hat, Inc.
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
 */

#include <config.h>

#include "datatypes.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virsecret.h"
#include "viruuid.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.secret");

VIR_ENUM_IMPL(virSecretUsage,
              VIR_SECRET_USAGE_TYPE_LAST,
              "none", "volume", "ceph", "iscsi", "tls", "vtpm",
);

void
virSecretLookupDefClear(virSecretLookupTypeDef *def)
{
    if (def->type == VIR_SECRET_LOOKUP_TYPE_USAGE)
        VIR_FREE(def->u.usage);
    else if (def->type == VIR_SECRET_LOOKUP_TYPE_UUID)
        memset(&def->u.uuid, 0, VIR_UUID_BUFLEN);
}


void
virSecretLookupDefCopy(virSecretLookupTypeDef *dst,
                       const virSecretLookupTypeDef *src)
{
    dst->type = src->type;
    if (dst->type == VIR_SECRET_LOOKUP_TYPE_UUID) {
        memcpy(dst->u.uuid, src->u.uuid, VIR_UUID_BUFLEN);
    } else if (dst->type == VIR_SECRET_LOOKUP_TYPE_USAGE) {
        dst->u.usage = g_strdup(src->u.usage);
    }
}


int
virSecretLookupParseSecret(xmlNodePtr secretnode,
                           virSecretLookupTypeDef *def)
{
    g_autofree char *uuid = NULL;
    g_autofree char *usage = NULL;

    uuid = virXMLPropString(secretnode, "uuid");
    usage = virXMLPropString(secretnode, "usage");
    if (uuid == NULL && usage == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing secret uuid or usage attribute"));
        return -1;
    }

    if (uuid && usage) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("either secret uuid or usage expected"));
        return -1;
    }

    if (uuid) {
        if (virUUIDParse(uuid, def->u.uuid) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("invalid secret uuid '%1$s'"), uuid);
            return -1;
        }
        def->type = VIR_SECRET_LOOKUP_TYPE_UUID;
    } else {
        def->u.usage = g_steal_pointer(&usage);
        def->type = VIR_SECRET_LOOKUP_TYPE_USAGE;
    }
    return 0;
}


void
virSecretLookupFormatSecret(virBuffer *buf,
                            const char *secrettype,
                            virSecretLookupTypeDef *def)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (secrettype)
        virBufferAsprintf(buf, "<secret type='%s'", secrettype);
    else
        virBufferAddLit(buf, "<secret");

    if (def->type == VIR_SECRET_LOOKUP_TYPE_UUID) {
        virUUIDFormat(def->u.uuid, uuidstr);
        virBufferAsprintf(buf, " uuid='%s'/>\n", uuidstr);
    } else if (def->type == VIR_SECRET_LOOKUP_TYPE_USAGE) {
        virBufferEscapeString(buf, " usage='%s'/>\n", def->u.usage);
    } else {
        virBufferAddLit(buf, "/>\n");
    }
}


/* virSecretGetSecretString:
 * @conn: Pointer to the connection driver to make secret driver call
 * @seclookupdef: Secret lookup def
 * @secretUsageType: Type of secret usage for usage lookup
 * @secret: returned secret as a sized stream of unsigned chars
 * @secret_size: Return size of the secret - either raw text or base64
 *
 * Lookup the secret for the usage type and return it as raw text.
 * It is up to the caller to encode the secret further.
 *
 * Returns 0 on success, -1 on failure.  On success the memory in secret
 * needs to be cleared and free'd after usage.
 */
int
virSecretGetSecretString(virConnectPtr conn,
                         virSecretLookupTypeDef *seclookupdef,
                         virSecretUsageType secretUsageType,
                         uint8_t **secret,
                         size_t *secret_size)
{
    g_autoptr(virSecret) sec = NULL;

    switch (seclookupdef->type) {
    case VIR_SECRET_LOOKUP_TYPE_UUID:
        sec = conn->secretDriver->secretLookupByUUID(conn, seclookupdef->u.uuid);
        break;

    case VIR_SECRET_LOOKUP_TYPE_USAGE:
        sec = conn->secretDriver->secretLookupByUsage(conn, secretUsageType,
                                                      seclookupdef->u.usage);
        break;
    }

    if (!sec)
        return -1;

    /* NB: NONE is a byproduct of the qemuxml2argvtest test mocking
     * for UUID lookups. Normal secret XML processing would fail if
     * the usage type was NONE and since we have no way to set the
     * expected usage in that environment, let's just accept NONE */
    if (sec->usageType != VIR_SECRET_USAGE_TYPE_NONE &&
        sec->usageType != secretUsageType) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(seclookupdef->u.uuid, uuidstr);
        virReportError(VIR_ERR_INVALID_ARG,
                       _("secret with uuid %1$s is of type '%2$s' not expected '%3$s' type"),
                       uuidstr, virSecretUsageTypeToString(sec->usageType),
                       virSecretUsageTypeToString(secretUsageType));
        return -1;
    }

    if (!(*secret = conn->secretDriver->secretGetValue(sec, secret_size, 0)))
        return -1;

    return 0;
}
