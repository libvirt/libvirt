/*
 * vircryptotest.c: cryptographic helper test suite
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

#include "testutils.h"


struct testCryptoHashData {
    virCryptoHash hash;
    const char *input;
    const char *output;
};

static int
testCryptoHash(const void *opaque)
{
    const struct testCryptoHashData *data = opaque;
    char *actual = NULL;
    int ret = -1;

    if (virCryptoHashString(data->hash, data->input, &actual) < 0) {
        fprintf(stderr, "Failed to generate crypto hash\n");
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(data->output, actual)) {
        fprintf(stderr, "Expected hash '%s' but got '%s'\n",
                data->output, NULLSTR(actual));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(actual);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

#define VIR_CRYPTO_HASH(h, i, o)                \
    do {                                        \
        struct testCryptoHashData data = {      \
            .hash = h,                          \
            .input = i,                         \
            .output = o,                        \
        };                                      \
        if (virtTestRun("Hash " i, testCryptoHash, &data) < 0) \
            ret = -1;                                          \
    } while (0)

    VIR_CRYPTO_HASH(VIR_CRYPTO_HASH_MD5, "", "d41d8cd98f00b204e9800998ecf8427e");
    VIR_CRYPTO_HASH(VIR_CRYPTO_HASH_SHA256, "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    VIR_CRYPTO_HASH(VIR_CRYPTO_HASH_MD5, " ", "7215ee9c7d9dc229d2921a40e899ec5f");
    VIR_CRYPTO_HASH(VIR_CRYPTO_HASH_SHA256, " ", "36a9e7f1c95b82ffb99743e0c5c4ce95d83c9a430aac59f84ef3cbfab6145068");

    VIR_CRYPTO_HASH(VIR_CRYPTO_HASH_MD5, "\n", "68b329da9893e34099c7d8ad5cb9c940");
    VIR_CRYPTO_HASH(VIR_CRYPTO_HASH_SHA256, "\n", "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b");

    VIR_CRYPTO_HASH(VIR_CRYPTO_HASH_MD5, "The quick brown fox", "a2004f37730b9445670a738fa0fc9ee5");
    VIR_CRYPTO_HASH(VIR_CRYPTO_HASH_SHA256, "The quick brown fox", "5cac4f980fedc3d3f1f99b4be3472c9b30d56523e632d151237ec9309048bda9");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
