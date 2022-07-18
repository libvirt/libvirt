/*
 * virhashcode.h: hash code generation
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 * The hash code generation is based on the public domain MurmurHash3 from Austin Appleby:
 * https://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
 *
 * We use only the 32 bit variant because the 2 produce different result while
 * we need to produce the same result regardless of the architecture as
 * clients can be both 64 or 32 bit at the same time.
 */

#pragma once

#include "internal.h"

uint32_t virHashCodeGen(const void *key, size_t len, uint32_t seed)
    G_NO_INLINE;
