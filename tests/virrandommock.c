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

# include "internal.h"
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

#else /* WIN32 */
/* Can't mock on WIN32 */
#endif
