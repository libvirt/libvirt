/*
 * vircrypto.h: cryptographic helper APIs
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

#ifndef __VIR_CRYPTO_H__
# define __VIR_CRYPTO_H__

# include "internal.h"

typedef enum {
    VIR_CRYPTO_HASH_MD5, /* Don't use this except for historic compat */
    VIR_CRYPTO_HASH_SHA256,

    VIR_CRYPTO_HASH_LAST
} virCryptoHash;


typedef enum {
    VIR_CRYPTO_CIPHER_NONE = 0,
    VIR_CRYPTO_CIPHER_AES256CBC,

    VIR_CRYPTO_CIPHER_LAST
} virCryptoCipher;

int
virCryptoHashString(virCryptoHash hash,
                    const char *input,
                    char **output)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_RETURN_CHECK;

bool virCryptoHaveCipher(virCryptoCipher algorithm);

int virCryptoEncryptData(virCryptoCipher algorithm,
                         uint8_t *enckey, size_t enckeylen,
                         uint8_t *iv, size_t ivlen,
                         uint8_t *data, size_t datalen,
                         uint8_t **ciphertext, size_t *ciphertextlen)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(6)
    ATTRIBUTE_NONNULL(8) ATTRIBUTE_NONNULL(9) ATTRIBUTE_RETURN_CHECK;

uint8_t *virCryptoGenerateRandom(size_t nbytes);

#endif /* __VIR_CRYPTO_H__ */
