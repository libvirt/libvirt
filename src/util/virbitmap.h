/*
 * virbitmap.h: Simple bitmap operations
 *
 * Copyright (C) 2012-2013 Red Hat, Inc.
 * Copyright (C) 2010 Novell, Inc.
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

#pragma once

#include "internal.h"

#include <sys/types.h>


typedef struct _virBitmap virBitmap;

/*
 * Allocate a bitmap capable of containing @size bits.
 */
virBitmap *virBitmapNew(size_t size);

/*
 * Free previously allocated bitmap
 */
void virBitmapFree(virBitmap *bitmap);

/*
 * Set bit position @b in @bitmap
 */
int virBitmapSetBit(virBitmap *bitmap, size_t b)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

void virBitmapSetBitExpand(virBitmap *bitmap, size_t b)
    ATTRIBUTE_NONNULL(1);


/*
 * Clear bit position @b in @bitmap
 */
int virBitmapClearBit(virBitmap *bitmap, size_t b)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

void virBitmapClearBitExpand(virBitmap *bitmap, size_t b)
    ATTRIBUTE_NONNULL(1);

/*
 * Get bit @b in @bitmap. Returns false if b is out of range.
 */
bool virBitmapIsBitSet(virBitmap *bitmap, size_t b)
    G_GNUC_WARN_UNUSED_RESULT;
/*
 * Get setting of bit position @b in @bitmap and store in @result
 */
int virBitmapGetBit(virBitmap *bitmap, size_t b, bool *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3) G_GNUC_WARN_UNUSED_RESULT;

virBitmap *
virBitmapNewString(const char *string)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

char *virBitmapToString(virBitmap *bitmap)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

char *virBitmapFormat(virBitmap *bitmap);

int virBitmapParse(const char *str,
                   virBitmap **bitmap,
                   size_t bitmapSize)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
virBitmap *
virBitmapParseUnlimited(const char *str);

virBitmap *virBitmapNewCopy(virBitmap *src) ATTRIBUTE_NONNULL(1);

virBitmap *virBitmapNewData(const void *data, int len) ATTRIBUTE_NONNULL(1);

int virBitmapToData(virBitmap *bitmap, unsigned char **data, int *dataLen)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

void virBitmapToDataBuf(virBitmap *bitmap, unsigned char *data, size_t len)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool virBitmapEqual(virBitmap *b1, virBitmap *b2);

size_t virBitmapSize(virBitmap *bitmap)
    ATTRIBUTE_NONNULL(1);

void virBitmapSetAll(virBitmap *bitmap)
    ATTRIBUTE_NONNULL(1);

void virBitmapClearAll(virBitmap *bitmap)
    ATTRIBUTE_NONNULL(1);

bool virBitmapIsAllSet(virBitmap *bitmap)
    ATTRIBUTE_NONNULL(1);

bool virBitmapIsAllClear(virBitmap *bitmap)
    ATTRIBUTE_NONNULL(1);

ssize_t virBitmapNextSetBit(virBitmap *bitmap, ssize_t pos);

ssize_t virBitmapLastSetBit(virBitmap *bitmap);

ssize_t virBitmapNextClearBit(virBitmap *bitmap, ssize_t pos);

size_t virBitmapCountBits(virBitmap *bitmap)
    ATTRIBUTE_NONNULL(1);

char *virBitmapDataFormat(const void *data,
                          int len)
    ATTRIBUTE_NONNULL(1);
bool virBitmapOverlaps(virBitmap *b1,
                       virBitmap *b2)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virBitmapIntersect(virBitmap *a, virBitmap *b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virBitmapUnion(virBitmap *a,
                    const virBitmap *b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virBitmapSubtract(virBitmap *a, virBitmap *b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virBitmapShrink(virBitmap *map, size_t b);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virBitmap, virBitmapFree);
