/*
 * vircrypto.c: cryptographic helper APIs
 *
 * Copyright (C) 2014, 2016 Red Hat, Inc.
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
#include "virlog.h"
#include "virerror.h"
#include "virsecureerase.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

VIR_LOG_INIT("util.crypto");

#define VIR_FROM_THIS VIR_FROM_CRYPTO

static const char hex[] = "0123456789abcdef";

#define VIR_CRYPTO_LARGEST_DIGEST_SIZE VIR_CRYPTO_HASH_SIZE_SHA256


struct virHashInfo {
    gnutls_digest_algorithm_t algorithm;
    size_t hashlen;
} hashinfo[] = {
    { GNUTLS_DIG_MD5, VIR_CRYPTO_HASH_SIZE_MD5 },
    { GNUTLS_DIG_SHA256, VIR_CRYPTO_HASH_SIZE_SHA256 },
};


G_STATIC_ASSERT(G_N_ELEMENTS(hashinfo) == VIR_CRYPTO_HASH_LAST);

ssize_t
virCryptoHashBuf(virCryptoHash hash,
                 const char *input,
                 unsigned char *output)
{
    int rc;
    if (hash >= VIR_CRYPTO_HASH_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unknown crypto hash %1$d"), hash);
        return -1;
    }

    rc = gnutls_hash_fast(hashinfo[hash].algorithm, input, strlen(input), output);
    if (rc < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to compute hash of data: %1$s"),
                       gnutls_strerror(rc));
        return -1;
    }

    return hashinfo[hash].hashlen;
}


int
virCryptoHashString(virCryptoHash hash,
                    const char *input,
                    char **output)
{
    unsigned char buf[VIR_CRYPTO_LARGEST_DIGEST_SIZE];
    ssize_t rc;
    size_t hashstrlen;
    size_t i;

    if ((rc = virCryptoHashBuf(hash, input, buf)) < 0)
        return -1;

    hashstrlen = (rc * 2) + 1;

    *output = g_new0(char, hashstrlen);

    for (i = 0; i < rc; i++) {
        (*output)[i * 2] = hex[(buf[i] >> 4) & 0xf];
        (*output)[(i * 2) + 1] = hex[buf[i] & 0xf];
    }

    return 0;
}


/* virCryptoEncryptDataAESgntuls:
 *
 * Performs the AES gnutls encryption
 *
 * Same input as virCryptoEncryptData, except the algorithm is replaced
 * by the specific gnutls algorithm.
 *
 * Encrypts the @data buffer using the @enckey and if available the @iv
 *
 * Returns 0 on success with the ciphertext being filled. It is the
 * caller's responsibility to clear and free it. Returns -1 on failure
 * w/ error set.
 */
static int
virCryptoEncryptDataAESgnutls(gnutls_cipher_algorithm_t gnutls_enc_alg,
                              uint8_t *enckey,
                              size_t enckeylen,
                              uint8_t *iv,
                              size_t ivlen,
                              uint8_t *data,
                              size_t datalen,
                              uint8_t **ciphertextret,
                              size_t *ciphertextlenret)
{
    int rc;
    size_t i;
    gnutls_cipher_hd_t handle = NULL;
    gnutls_datum_t enc_key = { .data = enckey, .size = enckeylen };
    gnutls_datum_t iv_buf = { .data = iv, .size = ivlen };
    g_autofree uint8_t *ciphertext = NULL;
    size_t ciphertextlen;

    if ((rc = gnutls_cipher_init(&handle, gnutls_enc_alg,
                                 &enc_key, &iv_buf)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to initialize cipher: '%1$s'"),
                       gnutls_strerror(rc));
        return -1;
    }

    /* Allocate a padded buffer, copy in the data.
     *
     * NB, we must *always* have at least 1 byte of
     * padding - we can't skip it on multiples of
     * 16, otherwise decoder can't distinguish padded
     * data from non-padded data. Hence datalen + 1
     */
    ciphertextlen = VIR_ROUND_UP(datalen + 1, 16);
    ciphertext = g_new0(uint8_t, ciphertextlen);
    memcpy(ciphertext, data, datalen);

     /* Fill in the padding of the buffer with the size of the padding
      * which is required for decryption. */
    for (i = datalen; i < ciphertextlen; i++)
        ciphertext[i] = ciphertextlen - datalen;

    /* Encrypt the data and free the memory for cipher operations */
    rc = gnutls_cipher_encrypt(handle, ciphertext, ciphertextlen);
    gnutls_cipher_deinit(handle);
    if (rc < 0) {
        virSecureErase(ciphertext, ciphertextlen);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to encrypt the data: '%1$s'"),
                       gnutls_strerror(rc));
        return -1;
    }

    *ciphertextret = g_steal_pointer(&ciphertext);
    *ciphertextlenret = ciphertextlen;
    return 0;
}


/* virCryptoEncryptData:
 * @algorithm: algorithm desired for encryption
 * @enckey: encryption key
 * @enckeylen: encryption key length
 * @iv: initialization vector
 * @ivlen: length of initialization vector
 * @data: data to encrypt
 * @datalen: length of data
 * @ciphertext: stream of bytes allocated to store ciphertext
 * @ciphertextlen: size of the stream of bytes
 *
 * If available, attempt and return the requested encryption type
 * using the parameters passed.
 *
 * Returns 0 on success, -1 on failure with error set
 */
int
virCryptoEncryptData(virCryptoCipher algorithm,
                     uint8_t *enckey,
                     size_t enckeylen,
                     uint8_t *iv,
                     size_t ivlen,
                     uint8_t *data,
                     size_t datalen,
                     uint8_t **ciphertext,
                     size_t *ciphertextlen)
{
    switch (algorithm) {
    case VIR_CRYPTO_CIPHER_AES256CBC:
        if (enckeylen != 32) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("AES256CBC encryption invalid keylen=%1$zu"),
                           enckeylen);
            return -1;
        }

        if (ivlen != 16) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("AES256CBC initialization vector invalid len=%1$zu"),
                           ivlen);
            return -1;
        }

        /*
         * Encrypt the data buffer using an encryption key and
         * initialization vector via the gnutls_cipher_encrypt API
         * for GNUTLS_CIPHER_AES_256_CBC.
         */
        return virCryptoEncryptDataAESgnutls(GNUTLS_CIPHER_AES_256_CBC,
                                             enckey, enckeylen, iv, ivlen,
                                             data, datalen,
                                             ciphertext, ciphertextlen);

    case VIR_CRYPTO_CIPHER_NONE:
    case VIR_CRYPTO_CIPHER_LAST:
        break;
    }

    virReportError(VIR_ERR_INVALID_ARG,
                   _("algorithm=%1$d is not supported"), algorithm);
    return -1;
}
