/*
 * bitmap.h: Simple bitmap operations
 *
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

#ifndef __BITMAP_H__
# define __BITMAP_H__

# include "internal.h"

# include <sys/types.h>


typedef struct _virBitmap virBitmap;
typedef virBitmap *virBitmapPtr;

/*
 * Allocate a bitmap capable of containing @size bits.
 */
virBitmapPtr virBitmapAlloc(size_t size) ATTRIBUTE_RETURN_CHECK;

/*
 * Free previously allocated bitmap
 */
void virBitmapFree(virBitmapPtr bitmap);

/*
 * Set bit position @b in @bitmap
 */
int virBitmapSetBit(virBitmapPtr bitmap, size_t b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

/*
 * Clear bit position @b in @bitmap
 */
int virBitmapClearBit(virBitmapPtr bitmap, size_t b)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

/*
 * Get setting of bit position @b in @bitmap and store in @result
 */
int virBitmapGetBit(virBitmapPtr bitmap, size_t b, bool *result)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3) ATTRIBUTE_RETURN_CHECK;

char *virBitmapString(virBitmapPtr bitmap)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

#endif
