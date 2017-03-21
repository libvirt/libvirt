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
 *
 * Author: Jim Fehlig <jfehlig@novell.com>
 */

#ifndef __BITMAP_H__
# define __BITMAP_H__

# include "internal.h"

# include <sys/types.h>


typedef struct _virBitmap virBitmap;
typedef virBitmap *virBitmapPtr;

/*
 * Allocate a bitmap capable of containing @size bits.
 */
virBitmapPtr virBitmapNewQuiet(size_t size) ATTRIBUTE_RETURN_CHECK;
virBitmapPtr virBitmapNew(size_t size) ATTRIBUTE_RETURN_CHECK;
virBitmapPtr virBitmapNewEmpty(void) ATTRIBUTE_RETURN_CHECK;

/*
 * Free previously allocated bitmap
 */
void virBitmapFree(virBitmapPtr bitmap);

/*
 * Copy all bits from @src to @dst. The bitmap sizes
 * must be the same
 */
int virBitmapCopy(virBitmapPtr dst, virBitmapPtr src);

/*
 * Set bit position @b in @bitmap
 */
int virBitmapSetBit(virBitmapPtr bitmap, size_t b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virBitmapSetBitExpand(virBitmapPtr bitmap, size_t b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;


/*
 * Clear bit position @b in @bitmap
 */
int virBitmapClearBit(virBitmapPtr bitmap, size_t b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virBitmapClearBitExpand(virBitmapPtr bitmap, size_t b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

/*
 * Get bit @b in @bitmap. Returns false if b is out of range.
 */
bool virBitmapIsBitSet(virBitmapPtr bitmap, size_t b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
/*
 * Get setting of bit position @b in @bitmap and store in @result
 */
int virBitmapGetBit(virBitmapPtr bitmap, size_t b, bool *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;

char *virBitmapString(virBitmapPtr bitmap)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

char *virBitmapFormat(virBitmapPtr bitmap);

int virBitmapParse(const char *str,
                   virBitmapPtr *bitmap,
                   size_t bitmapSize)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);
int
virBitmapParseSeparator(const char *str,
                        char terminator,
                        virBitmapPtr *bitmap,
                        size_t bitmapSize);
virBitmapPtr
virBitmapParseUnlimited(const char *str);

virBitmapPtr virBitmapNewCopy(virBitmapPtr src) ATTRIBUTE_NONNULL(1);

virBitmapPtr virBitmapNewData(const void *data, int len) ATTRIBUTE_NONNULL(1);

int virBitmapToData(virBitmapPtr bitmap, unsigned char **data, int *dataLen)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

void virBitmapToDataBuf(virBitmapPtr bitmap, unsigned char *data, size_t len)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool virBitmapEqual(virBitmapPtr b1, virBitmapPtr b2);

size_t virBitmapSize(virBitmapPtr bitmap)
    ATTRIBUTE_NONNULL(1);

void virBitmapSetAll(virBitmapPtr bitmap)
    ATTRIBUTE_NONNULL(1);

void virBitmapClearAll(virBitmapPtr bitmap)
    ATTRIBUTE_NONNULL(1);

bool virBitmapIsAllSet(virBitmapPtr bitmap)
    ATTRIBUTE_NONNULL(1);

bool virBitmapIsAllClear(virBitmapPtr bitmap)
    ATTRIBUTE_NONNULL(1);

ssize_t virBitmapNextSetBit(virBitmapPtr bitmap, ssize_t pos)
    ATTRIBUTE_NONNULL(1);

ssize_t virBitmapLastSetBit(virBitmapPtr bitmap)
    ATTRIBUTE_NONNULL(1);

ssize_t virBitmapNextClearBit(virBitmapPtr bitmap, ssize_t pos)
    ATTRIBUTE_NONNULL(1);

size_t virBitmapCountBits(virBitmapPtr bitmap)
    ATTRIBUTE_NONNULL(1);

char *virBitmapDataToString(const void *data,
                            int len)
    ATTRIBUTE_NONNULL(1);
bool virBitmapOverlaps(virBitmapPtr b1,
                       virBitmapPtr b2)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void virBitmapSubtract(virBitmapPtr a, virBitmapPtr b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

#endif
