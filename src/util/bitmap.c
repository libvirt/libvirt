/*
 * bitmap.h: Simple bitmap operations
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Jim Fehlig <jfehlig@novell.com>
 */

#include <config.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#include "bitmap.h"
#include "memory.h"
#include "buf.h"


struct _virBitmap {
    size_t size;
    unsigned long *map;
};


#define VIR_BITMAP_BITS_PER_UNIT  ((int) sizeof(unsigned long) * CHAR_BIT)
#define VIR_BITMAP_UNIT_OFFSET(b) ((b) / VIR_BITMAP_BITS_PER_UNIT)
#define VIR_BITMAP_BIT_OFFSET(b)  ((b) % VIR_BITMAP_BITS_PER_UNIT)
#define VIR_BITMAP_BIT(b)         (1UL << VIR_BITMAP_BIT_OFFSET(b))


/**
 * virBitmapAlloc:
 * @size: number of bits
 *
 * Allocate a bitmap capable of containing @size bits.
 *
 * Returns a pointer to the allocated bitmap or NULL if
 * memory cannot be allocated.
 */
virBitmapPtr virBitmapAlloc(size_t size)
{
    virBitmapPtr bitmap;
    size_t sz;

    if (SIZE_MAX - VIR_BITMAP_BITS_PER_UNIT < size || size == 0)
        return NULL;

    sz = (size + VIR_BITMAP_BITS_PER_UNIT - 1) /
          VIR_BITMAP_BITS_PER_UNIT;

    if (VIR_ALLOC(bitmap) < 0)
        return NULL;

    if (VIR_ALLOC_N(bitmap->map, sz) < 0) {
        VIR_FREE(bitmap);
        return NULL;
    }

    bitmap->size = size;
    return bitmap;
}

/**
 * virBitmapFree:
 * @bitmap: previously allocated bitmap
 *
 * Free @bitmap previously allocated by virBitmapAlloc.
 */
void virBitmapFree(virBitmapPtr bitmap)
{
    if (bitmap) {
        VIR_FREE(bitmap->map);
        VIR_FREE(bitmap);
    }
}

/**
 * virBitmapSetBit:
 * @bitmap: Pointer to bitmap
 * @b: bit position to set
 *
 * Set bit position @b in @bitmap
 *
 * Returns 0 on if bit is successfully set, -1 on error.
 */
int virBitmapSetBit(virBitmapPtr bitmap, size_t b)
{
    if (bitmap->size <= b)
        return -1;

    bitmap->map[VIR_BITMAP_UNIT_OFFSET(b)] |= VIR_BITMAP_BIT(b);
    return 0;
}

/**
 * virBitmapClearBit:
 * @bitmap: Pointer to bitmap
 * @b: bit position to clear
 *
 * Clear bit position @b in @bitmap
 *
 * Returns 0 on if bit is successfully clear, -1 on error.
 */
int virBitmapClearBit(virBitmapPtr bitmap, size_t b)
{
    if (bitmap->size <= b)
        return -1;

    bitmap->map[VIR_BITMAP_UNIT_OFFSET(b)] &= ~VIR_BITMAP_BIT(b);
    return 0;
}

/**
 * virBitmapGetBit:
 * @bitmap: Pointer to bitmap
 * @b: bit position to get
 * @result: bool pointer to receive bit setting
 *
 * Get setting of bit position @b in @bitmap and store in @result
 *
 * On success, @result will contain the setting of @b and 0 is
 * returned.  On failure, -1 is returned and @result is unchanged.
 */
int virBitmapGetBit(virBitmapPtr bitmap, size_t b, bool *result)
{
    if (bitmap->size <= b)
        return -1;

    *result = !!(bitmap->map[VIR_BITMAP_UNIT_OFFSET(b)] & VIR_BITMAP_BIT(b));
    return 0;
}

/**
 * virBitmapString:
 * @bitmap: Pointer to bitmap
 *
 * Convert @bitmap to printable string.
 *
 * Returns pointer to the string or NULL on error.
 */
char *virBitmapString(virBitmapPtr bitmap)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t sz;

    virBufferAddLit(&buf, "0x");

    sz = (bitmap->size + VIR_BITMAP_BITS_PER_UNIT - 1) /
          VIR_BITMAP_BITS_PER_UNIT;

    while (sz--) {
        virBufferAsprintf(&buf, "%0*lx",
                          VIR_BITMAP_BITS_PER_UNIT / 4,
                          bitmap->map[sz]);
    }

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}
