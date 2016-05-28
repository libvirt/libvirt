/*
 * secret_util.c: secret related utility functions
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

#include "secret_util.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virobject.h"
#include "viruuid.h"
#include "datatypes.h"

#define VIR_FROM_THIS VIR_FROM_SECRET

VIR_LOG_INIT("secret.secret_util");


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
                         virSecretLookupTypeDefPtr seclookupdef,
                         virSecretUsageType secretUsageType,
                         uint8_t **secret,
                         size_t *secret_size)
{
    virSecretPtr sec = NULL;
    int ret = -1;

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
        goto cleanup;

    *secret = conn->secretDriver->secretGetValue(sec, secret_size, 0,
                                                 VIR_SECRET_GET_VALUE_INTERNAL_CALL);

    if (!*secret)
        goto cleanup;

    ret = 0;

 cleanup:
    virObjectUnref(sec);
    return ret;
}
