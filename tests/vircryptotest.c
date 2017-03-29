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
#include "virrandom.h"

#include "testutils.h"

#define VIR_FROM_THIS VIR_FROM_NONE

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


struct testCryptoEncryptData {
    virCryptoCipher algorithm;
    uint8_t *input;
    size_t inputlen;
    uint8_t *ciphertext;
    size_t ciphertextlen;
};

static int
testCryptoEncrypt(const void *opaque)
{
    const struct testCryptoEncryptData *data = opaque;
    uint8_t *enckey = NULL;
    size_t enckeylen = 32;
    uint8_t *iv = NULL;
    size_t ivlen = 16;
    uint8_t *ciphertext = NULL;
    size_t ciphertextlen = 0;
    int ret = -1;

    if (!virCryptoHaveCipher(data->algorithm)) {
        fprintf(stderr, "cipher algorithm=%d unavailable\n", data->algorithm);
        return EXIT_AM_SKIP;
    }

    if (VIR_ALLOC_N(enckey, enckeylen) < 0 ||
        VIR_ALLOC_N(iv, ivlen) < 0)
        goto cleanup;

    if (virRandomBytes(enckey, enckeylen) ||
        virRandomBytes(iv, ivlen)) {
        fprintf(stderr, "Failed to generate random bytes\n");
        goto cleanup;
    }

    if (virCryptoEncryptData(data->algorithm, enckey, enckeylen, iv, ivlen,
                             data->input, data->inputlen,
                             &ciphertext, &ciphertextlen) < 0)
        goto cleanup;

    if (data->ciphertextlen != ciphertextlen) {
        fprintf(stderr, "Expected ciphertextlen(%zu) doesn't match (%zu)\n",
                data->ciphertextlen, ciphertextlen);
        goto cleanup;
    }

    if (memcmp(data->ciphertext, ciphertext, ciphertextlen)) {
        fprintf(stderr, "Expected ciphertext doesn't match\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(enckey);
    VIR_FREE(iv);
    VIR_FREE(ciphertext);

    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    uint8_t secretdata[8];
    uint8_t expected_ciphertext[16] = {0x48, 0x8e, 0x9, 0xb9,
                                       0x6a, 0xa6, 0x24, 0x5f,
                                       0x1b, 0x8c, 0x3f, 0x48,
                                       0x27, 0xae, 0xb6, 0x7a};

#define VIR_CRYPTO_HASH(h, i, o)                \
    do {                                        \
        struct testCryptoHashData data = {      \
            .hash = h,                          \
            .input = i,                         \
            .output = o,                        \
        };                                      \
        if (virTestRun("Hash " i, testCryptoHash, &data) < 0)  \
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

#undef VIR_CRYPTO_HASH

#define VIR_CRYPTO_ENCRYPT(a, n, i, il, c, cl)   \
    do {                                         \
        struct testCryptoEncryptData data = {    \
            .algorithm = a,                      \
            .input = i,                          \
            .inputlen = il,                      \
            .ciphertext = c,                     \
            .ciphertextlen = cl,                 \
        };                                       \
        if (virTestRun("Encrypt " n, testCryptoEncrypt, &data) < 0)  \
            ret = -1;                                                \
    } while (0)

    memset(&secretdata, 0, 8);
    memcpy(&secretdata, "letmein", 7);

    VIR_CRYPTO_ENCRYPT(VIR_CRYPTO_CIPHER_AES256CBC, "aes265cbc",
                       secretdata, 7, expected_ciphertext, 16);

#undef VIR_CRYPTO_ENCRYPT

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* Forces usage of not so random virRandomBytes */
VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virrandommock.so")
