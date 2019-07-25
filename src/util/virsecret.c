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

#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virsecret.h"
#include "virstring.h"
#include "viruuid.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.secret");

VIR_ENUM_IMPL(virSecretUsage,
              VIR_SECRET_USAGE_TYPE_LAST,
              "none", "volume", "ceph", "iscsi", "tls", "vtpm",
);

void
virSecretLookupDefClear(virSecretLookupTypeDefPtr def)
{
    if (def->type == VIR_SECRET_LOOKUP_TYPE_USAGE)
        VIR_FREE(def->u.usage);
    else if (def->type == VIR_SECRET_LOOKUP_TYPE_UUID)
        memset(&def->u.uuid, 0, VIR_UUID_BUFLEN);
}


int
virSecretLookupDefCopy(virSecretLookupTypeDefPtr dst,
                       const virSecretLookupTypeDef *src)
{
    dst->type = src->type;
    if (dst->type == VIR_SECRET_LOOKUP_TYPE_UUID) {
        memcpy(dst->u.uuid, src->u.uuid, VIR_UUID_BUFLEN);
    } else if (dst->type == VIR_SECRET_LOOKUP_TYPE_USAGE) {
        if (VIR_STRDUP(dst->u.usage, src->u.usage) < 0)
            return -1;
    }
    return 0;
}


int
virSecretLookupParseSecret(xmlNodePtr secretnode,
                           virSecretLookupTypeDefPtr def)
{
    char *uuid;
    char *usage;
    int ret = -1;

    uuid = virXMLPropString(secretnode, "uuid");
    usage = virXMLPropString(secretnode, "usage");
    if (uuid == NULL && usage == NULL) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing secret uuid or usage attribute"));
        goto cleanup;
    }

    if (uuid && usage) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("either secret uuid or usage expected"));
        goto cleanup;
    }

    if (uuid) {
        if (virUUIDParse(uuid, def->u.uuid) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("invalid secret uuid '%s'"), uuid);
            goto cleanup;
        }
        def->type = VIR_SECRET_LOOKUP_TYPE_UUID;
    } else {
        def->u.usage = usage;
        usage = NULL;
        def->type = VIR_SECRET_LOOKUP_TYPE_USAGE;
    }
    ret = 0;

 cleanup:
    VIR_FREE(uuid);
    VIR_FREE(usage);
    return ret;
}


void
virSecretLookupFormatSecret(virBufferPtr buf,
                            const char *secrettype,
                            virSecretLookupTypeDefPtr def)
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
