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
 * @scheme: Unique enough string for error message to help determine cause
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
                         const char *scheme,
                         bool encoded,
                         virStorageAuthDefPtr authdef,
                         virSecretUsageType secretUsageType)
{
    size_t secret_size;
    virSecretPtr sec = NULL;
    char *secret = NULL;
    char uuidStr[VIR_UUID_STRING_BUFLEN];

    /* look up secret */
    switch (authdef->secretType) {
    case VIR_STORAGE_SECRET_TYPE_UUID:
        sec = virSecretLookupByUUID(conn, authdef->secret.uuid);
        virUUIDFormat(authdef->secret.uuid, uuidStr);
        break;
    case VIR_STORAGE_SECRET_TYPE_USAGE:
        sec = virSecretLookupByUsage(conn, secretUsageType,
                                     authdef->secret.usage);
        break;
    }

    if (!sec) {
        if (authdef->secretType == VIR_STORAGE_SECRET_TYPE_UUID) {
            virReportError(VIR_ERR_NO_SECRET,
                           _("%s no secret matches uuid '%s'"),
                           scheme, uuidStr);
        } else {
            virReportError(VIR_ERR_NO_SECRET,
                           _("%s no secret matches usage value '%s'"),
                           scheme, authdef->secret.usage);
        }
        goto cleanup;
    }

    secret = (char *)conn->secretDriver->secretGetValue(sec, &secret_size, 0,
                                                        VIR_SECRET_GET_VALUE_INTERNAL_CALL);
    if (!secret) {
        if (authdef->secretType == VIR_STORAGE_SECRET_TYPE_UUID) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not get value of the secret for "
                             "username '%s' using uuid '%s'"),
                           authdef->username, uuidStr);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("could not get value of the secret for "
                             "username '%s' using usage value '%s'"),
                           authdef->username, authdef->secret.usage);
        }
        goto cleanup;
    }

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
