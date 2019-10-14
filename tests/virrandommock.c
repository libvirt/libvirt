/*
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
 */

#include <config.h>

#ifndef WIN32

# include <gnutls/gnutls.h>

# include "internal.h"
# include "virstring.h"
# include "virrandom.h"
# include "virmock.h"

# define VIR_FROM_THIS VIR_FROM_NONE

int
virRandomBytes(unsigned char *buf,
               size_t buflen)
{
    size_t i;

    for (i = 0; i < buflen; i++)
        buf[i] = i;

    return 0;
}

uint64_t virRandomBits(int nbits)
{
    /* Chosen by a fair roll of a 2^64 sided dice */
    uint64_t ret = 0x0706050403020100;
    if (nbits < 64)
        ret &= ((1ULL << nbits) - 1);
    return ret;
}

int virRandomGenerateWWN(char **wwn,
                         const char *virt_type G_GNUC_UNUSED)
{
    return virAsprintf(wwn, "5100000%09llx",
                       (unsigned long long)virRandomBits(36));
}


static int (*real_gnutls_dh_params_generate2)(gnutls_dh_params_t dparams,
                                              unsigned int bits);

static gnutls_dh_params_t params_cache;
static unsigned int cachebits;

int
gnutls_dh_params_generate2(gnutls_dh_params_t dparams,
                           unsigned int bits)
{
    int rc = 0;

    VIR_MOCK_REAL_INIT(gnutls_dh_params_generate2);

    if (!params_cache) {
        if (gnutls_dh_params_init(&params_cache) < 0) {
            fprintf(stderr, "Error initializing params cache");
            abort();
        }
        rc = real_gnutls_dh_params_generate2(params_cache, bits);

        if (rc < 0)
            return rc;
        cachebits = bits;
    }

    if (cachebits != bits) {
        fprintf(stderr, "Requested bits do not match the cached value");
        abort();
    }

    return gnutls_dh_params_cpy(dparams, params_cache);
}
#else /* WIN32 */
/* Can't mock on WIN32 */
#endif
