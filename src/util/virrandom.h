/*
 * Copyright (C) 2012, 2016 Red Hat, Inc.
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
 * Authors:
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_RANDOM_H__
# define __VIR_RANDOM_H__

# include "internal.h"

uint64_t virRandomBits(int nbits) ATTRIBUTE_NOINLINE;
double virRandom(void);
uint32_t virRandomInt(uint32_t max);
int virRandomBytes(unsigned char *buf, size_t buflen)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NOINLINE;
int virRandomGenerateWWN(char **wwn, const char *virt_type) ATTRIBUTE_NOINLINE;

#endif /* __VIR_RANDOM_H__ */
