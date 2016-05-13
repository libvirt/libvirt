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
#include "base64.h"
#include "datatypes.h"

#define VIR_FROM_THIS VIR_FROM_SECRET

VIR_LOG_INIT("secret.secret_util");


/* virSecretGetSecretString:
 * @conn: Pointer to the connection driver to make secret driver call
 * @encoded: Whether the returned secret needs to be base64 encoded
 * @authdef: Pointer to the disk storage authentication
 * @secretUsageType: Type of secret usage for authdef lookup
 *
 * Lookup the secret for the authdef usage type and return it either as
 * raw text or encoded based on the caller's need.
 *
 * Returns a pointer to memory that needs to be cleared and free'd after
 * usage or NULL on error.
 */
char *
virSecretGetSecretString(virConnectPtr conn,
                         bool encoded,
                         virStorageAuthDefPtr authdef,
                         virSecretUsageType secretUsageType)
{
    size_t secret_size;
    virSecretPtr sec = NULL;
    char *secret = NULL;

    switch (authdef->secretType) {
    case VIR_STORAGE_SECRET_TYPE_UUID:
        sec = conn->secretDriver->secretLookupByUUID(conn, authdef->secret.uuid);
        break;

    case VIR_STORAGE_SECRET_TYPE_USAGE:
        sec = conn->secretDriver->secretLookupByUsage(conn, secretUsageType,
                                                      authdef->secret.usage);
        break;
    }

    if (!sec)
        goto cleanup;

    secret = (char *)conn->secretDriver->secretGetValue(sec, &secret_size, 0,
                                                        VIR_SECRET_GET_VALUE_INTERNAL_CALL);

    if (!secret)
        goto cleanup;

    if (encoded) {
        char *base64 = NULL;

        base64_encode_alloc(secret, secret_size, &base64);
        VIR_FREE(secret);
        if (!base64) {
            virReportOOMError();
            goto cleanup;
        }
        secret = base64;
    }

 cleanup:
    virObjectUnref(sec);
    return secret;
}
