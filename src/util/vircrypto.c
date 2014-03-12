/*
 * vircrypto.c: cryptographic helper APIs
 *
 * Copyright (C) 2014 Red Hat, Inc.
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

#include "vircrypto.h"
#include "virerror.h"
#include "viralloc.h"

#include "md5.h"
#include "sha256.h"

#define VIR_FROM_THIS VIR_FROM_CRYPTO

static const char hex[] = "0123456789abcdef";

struct virHashInfo {
    void *(*func)(const char *buf, size_t len, void *res);
    size_t hashlen;
} hashinfo[] = {
    { md5_buffer, MD5_DIGEST_SIZE },
    { sha256_buffer, SHA256_DIGEST_SIZE },
};

#define VIR_CRYPTO_LARGEST_DIGEST_SIZE SHA256_DIGEST_SIZE

verify(ARRAY_CARDINALITY(hashinfo) == VIR_CRYPTO_HASH_LAST);

int
virCryptoHashString(virCryptoHash hash,
                    const char *input,
                    char **output)
{
    unsigned char buf[VIR_CRYPTO_LARGEST_DIGEST_SIZE];
    size_t hashstrlen;
    size_t i;

    if (hash >= VIR_CRYPTO_HASH_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unknown crypto hash %d"), hash);
        return -1;
    }

    hashstrlen = (hashinfo[hash].hashlen * 2) + 1;

    if (!(hashinfo[hash].func(input, strlen(input), buf))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to compute hash of data"));
        return -1;
    }

    if (VIR_ALLOC_N(*output, hashstrlen) < 0)
        return -1;

    for (i = 0; i < hashinfo[hash].hashlen; i++) {
        (*output)[i * 2] = hex[(buf[i] >> 4) & 0xf];
        (*output)[(i * 2) + 1] = hex[buf[i] & 0xf];
    }

    return 0;
}
