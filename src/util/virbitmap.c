/*
 * virbitmap.c: Simple bitmap operations
 *
 * Copyright (C) 2010-2013 Red Hat, Inc.
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

#include <config.h>

#include <sys/types.h>

#include "virbitmap.h"
#include "viralloc.h"
#include "virbuffer.h"
#include "c-ctype.h"
#include "virstring.h"
#include "virutil.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NONE

struct _virBitmap {
    size_t nbits;
    size_t map_len;
    size_t map_alloc;

    /* Note that code below depends on the fact that unused bits of the bitmap
     * are not set. Any function decreasing the size of the map needs clear
     * bits which don't belong to the bitmap any more. */
    unsigned long *map;
};


#define VIR_BITMAP_BITS_PER_UNIT  ((int) sizeof(unsigned long) * CHAR_BIT)
#define VIR_BITMAP_UNIT_OFFSET(b) ((b) / VIR_BITMAP_BITS_PER_UNIT)
#define VIR_BITMAP_BIT_OFFSET(b)  ((b) % VIR_BITMAP_BITS_PER_UNIT)
#define VIR_BITMAP_BIT(b)         (1UL << VIR_BITMAP_BIT_OFFSET(b))


/**
 * virBitmapNewQuiet:
 * @size: number of bits
 *
 * Allocate a bitmap capable of containing @size bits.
 *
 * Returns a pointer to the allocated bitmap or NULL if either memory cannot be
 * allocated or size is 0. Does not report libvirt errors.
 */
virBitmapPtr
virBitmapNewQuiet(size_t size)
{
    virBitmapPtr bitmap;
    size_t sz;

    if (SIZE_MAX - VIR_BITMAP_BITS_PER_UNIT < size || size == 0)
        return NULL;

    sz = VIR_DIV_UP(size, VIR_BITMAP_BITS_PER_UNIT);

    if (VIR_ALLOC_QUIET(bitmap) < 0)
        return NULL;

    if (VIR_ALLOC_N_QUIET(bitmap->map, sz) < 0) {
        VIR_FREE(bitmap);
        return NULL;
    }

    bitmap->nbits = size;
    bitmap->map_len = sz;
    bitmap->map_alloc = sz;
    return bitmap;
}


/**
 * virBitmapNew:
 * @size: number of bits
 *
 * Allocate a bitmap capable of containing @size bits.
 *
 * Returns a pointer to the allocated bitmap or NULL if either memory cannot be
 * allocated or size is 0. Reports libvirt errors.
 */
virBitmapPtr
virBitmapNew(size_t size)
{
    virBitmapPtr ret;

    if (!(ret = virBitmapNewQuiet(size)))
        virReportOOMError();

    return ret;
}


/**
 * virBitmapNewEmpty:
 *
 * Allocate an empty bitmap. It can be used with self-expanding APIs.
 *
 * Returns a pointer to the allocated bitmap or NULL if memory cannot be
 * allocated. Reports libvirt errors.
 */
virBitmapPtr
virBitmapNewEmpty(void)
{
    virBitmapPtr ret;

    ignore_value(VIR_ALLOC(ret));

    return ret;
}


/**
 * virBitmapFree:
 * @bitmap: previously allocated bitmap
 *
 * Free @bitmap previously allocated by virBitmapNew.
 */
void
virBitmapFree(virBitmapPtr bitmap)
{
    if (bitmap) {
        VIR_FREE(bitmap->map);
        VIR_FREE(bitmap);
    }
}


/**
 * virBitmapCopy:
 * @dst: destination bitmap
 * @src: source bitmap
 *
 * Copies contents of @src to @dst. @dst must have the same size as @src.
 * Returns -1 if the size is not the same or 0 on success.
 */
int
virBitmapCopy(virBitmapPtr dst,
              virBitmapPtr src)
{
    if (dst->nbits != src->nbits) {
        errno = EINVAL;
        return -1;
    }

    memcpy(dst->map, src->map, src->map_len * sizeof(src->map[0]));

    return 0;
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
int
virBitmapSetBit(virBitmapPtr bitmap,
                size_t b)
{
    if (bitmap->nbits <= b)
        return -1;

    bitmap->map[VIR_BITMAP_UNIT_OFFSET(b)] |= VIR_BITMAP_BIT(b);
    return 0;
}


/**
 * virBitmapExpand:
 * @map: Pointer to bitmap
 * @b: bit position to include in bitmap
 *
 * Resizes the bitmap so that bit @b will fit into it. This shall be called only
 * if @b would not fit into the map.
 *
 * Returns 0 on success, -1 on error.
 */
static int
virBitmapExpand(virBitmapPtr map,
                size_t b)
{
    size_t new_len = VIR_DIV_UP(b + 1, VIR_BITMAP_BITS_PER_UNIT);

    /* resize the memory if necessary */
    if (map->map_len < new_len) {
        if (VIR_RESIZE_N(map->map, map->map_alloc, map->map_len,
                         new_len - map->map_len) < 0)
            return -1;
    }

    map->nbits = b + 1;
    map->map_len = new_len;

    return 0;
}


/**
 * virBitmapSetBitExpand:
 * @bitmap: Pointer to bitmap
 * @b: bit position to set
 *
 * Set bit position @b in @bitmap. Expands the bitmap as necessary so that @b is
 * included in the map.
 *
 * Returns 0 on if bit is successfully set, -1 on error.
 */
int
virBitmapSetBitExpand(virBitmapPtr bitmap,
                      size_t b)
{
    if (bitmap->nbits <= b && virBitmapExpand(bitmap, b) < 0)
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
int
virBitmapClearBit(virBitmapPtr bitmap,
                  size_t b)
{
    if (bitmap->nbits <= b)
        return -1;

    bitmap->map[VIR_BITMAP_UNIT_OFFSET(b)] &= ~VIR_BITMAP_BIT(b);
    return 0;
}


/**
 * virBitmapClearBitExpand:
 * @bitmap: Pointer to bitmap
 * @b: bit position to set
 *
 * Clear bit position @b in @bitmap. Expands the bitmap as necessary so that
 * @b is included in the map.
 *
 * Returns 0 on if bit is successfully cleared, -1 on error.
 */
int
virBitmapClearBitExpand(virBitmapPtr bitmap,
                        size_t b)
{
    if (bitmap->nbits <= b) {
        if (virBitmapExpand(bitmap, b) < 0)
            return -1;
    } else {
        bitmap->map[VIR_BITMAP_UNIT_OFFSET(b)] &= ~VIR_BITMAP_BIT(b);
    }

    return 0;
}


/* Helper function. caller must ensure b < bitmap->nbits */
static bool
virBitmapIsSet(virBitmapPtr bitmap, size_t b)
{
    return !!(bitmap->map[VIR_BITMAP_UNIT_OFFSET(b)] & VIR_BITMAP_BIT(b));
}


/**
 * virBitmapIsBitSet:
 * @bitmap: Pointer to bitmap
 * @b: bit position to get
 *
 * Get setting of bit position @b in @bitmap.
 *
 * If @b is in the range of @bitmap, returns the value of the bit.
 * Otherwise false is returned.
 */
bool
virBitmapIsBitSet(virBitmapPtr bitmap,
                  size_t b)
{
    if (bitmap->nbits <= b)
        return false;

    return virBitmapIsSet(bitmap, b);
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
int
virBitmapGetBit(virBitmapPtr bitmap,
                size_t b,
                bool *result)
{
    if (bitmap->nbits <= b)
        return -1;

    *result = virBitmapIsSet(bitmap, b);
    return 0;
}


/**
 * virBitmapToString:
 * @bitmap: Pointer to bitmap
 * @prefix: Whether to prepend "0x"
 * @trim: Whether to output only the minimum required characters
 *
 * Convert @bitmap to printable string.
 *
 * Returns pointer to the string or NULL on error.
 */
char *
virBitmapToString(virBitmapPtr bitmap,
                  bool prefix,
                  bool trim)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    size_t sz;
    size_t len;
    size_t diff;
    char *ret = NULL;

    if (prefix)
        virBufferAddLit(&buf, "0x");

    sz = bitmap->map_len;

    while (sz--) {
        virBufferAsprintf(&buf, "%0*lx",
                          VIR_BITMAP_BITS_PER_UNIT / 4,
                          bitmap->map[sz]);
    }

    virBufferCheckError(&buf);
    ret = virBufferContentAndReset(&buf);
    if (!ret)
        return NULL;

    if (!trim)
        return ret;

    if (bitmap->nbits != bitmap->map_len * VIR_BITMAP_BITS_PER_UNIT) {
        char *tmp = ret;

        if (prefix)
            tmp += 2;

        len = strlen(tmp);
        sz = VIR_DIV_UP(bitmap->nbits, 4);
        diff = len - sz;

        if (diff)
            memmove(tmp, tmp + diff, sz + 1);
    }

    return ret;
}


/**
 * virBitmapFormat:
 * @bitmap: the bitmap
 *
 * This function is the counterpart of virBitmapParse. This function creates
 * a human-readable string representing the bits in bitmap.
 *
 * See virBitmapParse for the format of @str.
 *
 * If bitmap is NULL or it has no bits set, an empty string is returned.
 *
 * Returns the string on success or NULL otherwise. Caller should call
 * VIR_FREE to free the string.
 */
char *
virBitmapFormat(virBitmapPtr bitmap)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool first = true;
    int start, cur, prev;

    if (!bitmap || (cur = virBitmapNextSetBit(bitmap, -1)) < 0) {
        char *ret;
        ignore_value(VIR_STRDUP(ret, ""));
        return ret;
    }

    start = prev = cur;
    while (prev >= 0) {
        cur = virBitmapNextSetBit(bitmap, prev);

        if (cur == prev + 1) {
            prev = cur;
            continue;
        }

        /* cur < 0 or cur > prev + 1 */

        if (!first)
            virBufferAddLit(&buf, ",");
        else
            first = false;

        if (prev == start)
            virBufferAsprintf(&buf, "%d", start);
        else
            virBufferAsprintf(&buf, "%d-%d", start, prev);

        start = prev = cur;
    }

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}


/**
 * virBitmapParseSeparator:
 * @str: points to a string representing a human-readable bitmap
 * @terminator: character separating the bitmap to parse
 * @bitmap: a bitmap created from @str
 * @bitmapSize: the upper limit of num of bits in created bitmap
 *
 * This function is the counterpart of virBitmapFormat. This function creates
 * a bitmap, in which bits are set according to the content of @str.
 *
 * @str is a comma separated string of fields N, which means a number of bit
 * to set, and ^N, which means to unset the bit, and N-M for ranges of bits
 * to set.
 *
 * To allow parsing of bitmaps within larger strings it is possible to set
 * a termination character in the argument @terminator. When the character
 * in @terminator is encountered in @str, the parsing of the bitmap stops.
 * Pass 0 as @terminator if it is not needed. Whitespace characters may not
 * be used as terminators.
 *
 * Returns 0 on success, or -1 in case of error.
 */
int
virBitmapParseSeparator(const char *str,
                        char terminator,
                        virBitmapPtr *bitmap,
                        size_t bitmapSize)
{
    bool neg = false;
    const char *cur = str;
    char *tmp;
    size_t i;
    int start, last;

    if (!(*bitmap = virBitmapNew(bitmapSize)))
        return -1;

    if (!str)
        goto error;

    virSkipSpaces(&cur);

    if (*cur == '\0')
        goto error;

    while (*cur != 0 && *cur != terminator) {
        /*
         * 3 constructs are allowed:
         *     - N   : a single CPU number
         *     - N-M : a range of CPU numbers with N < M
         *     - ^N  : remove a single CPU number from the current set
         */
        if (*cur == '^') {
            cur++;
            neg = true;
        }

        if (!c_isdigit(*cur))
            goto error;

        if (virStrToLong_i(cur, &tmp, 10, &start) < 0)
            goto error;
        if (start < 0)
            goto error;

        cur = tmp;

        virSkipSpaces(&cur);

        if (*cur == ',' || *cur == 0 || *cur == terminator) {
            if (neg) {
                if (virBitmapClearBit(*bitmap, start) < 0)
                    goto error;
            } else {
                if (virBitmapSetBit(*bitmap, start) < 0)
                    goto error;
            }
        } else if (*cur == '-') {
            if (neg)
                goto error;

            cur++;
            virSkipSpaces(&cur);

            if (virStrToLong_i(cur, &tmp, 10, &last) < 0)
                goto error;
            if (last < start)
                goto error;

            cur = tmp;

            for (i = start; i <= last; i++) {
                if (virBitmapSetBit(*bitmap, i) < 0)
                    goto error;
            }

            virSkipSpaces(&cur);
        }

        if (*cur == ',') {
            cur++;
            virSkipSpaces(&cur);
            neg = false;
        } else if (*cur == 0 || *cur == terminator) {
            break;
        } else {
            goto error;
        }
    }

    return 0;

 error:
    virReportError(VIR_ERR_INVALID_ARG,
                   _("Failed to parse bitmap '%s'"), str);
    virBitmapFree(*bitmap);
    *bitmap = NULL;
    return -1;
}


/**
 * virBitmapParse:
 * @str: points to a string representing a human-readable bitmap
 * @bitmap: a bitmap created from @str
 * @bitmapSize: the upper limit of num of bits in created bitmap
 *
 * This function is the counterpart of virBitmapFormat. This function creates
 * a bitmap, in which bits are set according to the content of @str.
 *
 * @str is a comma separated string of fields N, which means a number of bit
 * to set, and ^N, which means to unset the bit, and N-M for ranges of bits
 * to set.
 *
 * Returns 0 on success, or -1 in case of error.
 */
int
virBitmapParse(const char *str,
               virBitmapPtr *bitmap,
               size_t bitmapSize)
{
    return virBitmapParseSeparator(str, '\0', bitmap, bitmapSize);
}


/**
 * virBitmapParseUnlimited:
 * @str: points to a string representing a human-readable bitmap
 *
 * This function is the counterpart of virBitmapFormat. This function creates
 * a bitmap, in which bits are set according to the content of @str.
 *
 * The bitmap is expanded to accommodate all the bits.
 *
 * @str is a comma separated string of fields N, which means a number of bit
 * to set, and ^N, which means to unset the bit, and N-M for ranges of bits
 * to set.
 *
 * Returns @bitmap on success, or NULL in case of error
 */
virBitmapPtr
virBitmapParseUnlimited(const char *str)
{
    virBitmapPtr bitmap;
    bool neg = false;
    const char *cur = str;
    char *tmp;
    size_t i;
    int start, last;

    if (!(bitmap = virBitmapNewEmpty()))
        return NULL;

    if (!str)
        goto error;

    virSkipSpaces(&cur);

    if (*cur == '\0')
        goto error;

    while (*cur != 0) {
        /*
         * 3 constructs are allowed:
         *     - N   : a single CPU number
         *     - N-M : a range of CPU numbers with N < M
         *     - ^N  : remove a single CPU number from the current set
         */
        if (*cur == '^') {
            cur++;
            neg = true;
        }

        if (!c_isdigit(*cur))
            goto error;

        if (virStrToLong_i(cur, &tmp, 10, &start) < 0)
            goto error;
        if (start < 0)
            goto error;

        cur = tmp;

        virSkipSpaces(&cur);

        if (*cur == ',' || *cur == 0) {
            if (neg) {
                if (virBitmapClearBitExpand(bitmap, start) < 0)
                    goto error;
            } else {
                if (virBitmapSetBitExpand(bitmap, start) < 0)
                    goto error;
            }
        } else if (*cur == '-') {
            if (neg)
                goto error;

            cur++;
            virSkipSpaces(&cur);

            if (virStrToLong_i(cur, &tmp, 10, &last) < 0)
                goto error;
            if (last < start)
                goto error;

            cur = tmp;

            for (i = start; i <= last; i++) {
                if (virBitmapSetBitExpand(bitmap, i) < 0)
                    goto error;
            }

            virSkipSpaces(&cur);
        }

        if (*cur == ',') {
            cur++;
            virSkipSpaces(&cur);
            neg = false;
        } else if (*cur == 0) {
            break;
        } else {
            goto error;
        }
    }

    return bitmap;

 error:
    virReportError(VIR_ERR_INVALID_ARG,
                   _("Failed to parse bitmap '%s'"), NULLSTR(str));
    virBitmapFree(bitmap);
    return NULL;
}


/**
 * virBitmapNewCopy:
 * @src: the source bitmap.
 *
 * Makes a copy of bitmap @src.
 *
 * returns the copied bitmap on success, or NULL otherwise. Caller
 * should call virBitmapFree to free the returned bitmap.
 */
virBitmapPtr
virBitmapNewCopy(virBitmapPtr src)
{
    virBitmapPtr dst;

    if ((dst = virBitmapNew(src->nbits)) == NULL)
        return NULL;

    if (virBitmapCopy(dst, src) != 0) {
        virBitmapFree(dst);
        return NULL;
    }

    return dst;
}


/**
 * virBitmapNewData:
 * @data: the data
 * @len: length of @data in bytes
 *
 * Allocate a bitmap from a chunk of data containing bits
 * information
 *
 * Returns a pointer to the allocated bitmap or NULL if
 * memory cannot be allocated.
 */
virBitmapPtr
virBitmapNewData(const void *data,
                 int len)
{
    virBitmapPtr bitmap;
    size_t i, j;
    unsigned long *p;
    const unsigned char *bytes = data;

    bitmap = virBitmapNew(len * CHAR_BIT);
    if (!bitmap)
        return NULL;

    /* le64toh is not provided by gnulib, so we do the conversion by hand */
    p = bitmap->map;
    for (i = j = 0; i < len; i++, j++) {
        if (j == sizeof(*p)) {
            j = 0;
            p++;
        }
        *p |= (unsigned long) bytes[i] << (j * CHAR_BIT);
    }

    return bitmap;
}


/**
 * virBitmapToData:
 * @data: the data
 * @len: len of @data in byte
 *
 * Convert a bitmap to a chunk of data containing bits information.
 * Data consists of sequential bytes, with lower bytes containing
 * lower bits. This function allocates @data.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virBitmapToData(virBitmapPtr bitmap,
                unsigned char **data,
                int *dataLen)
{
    ssize_t len;

    if ((len = virBitmapLastSetBit(bitmap)) < 0)
        len = 1;
    else
        len = (len + CHAR_BIT) / CHAR_BIT;

    if (VIR_ALLOC_N(*data, len) < 0)
        return -1;

    *dataLen = len;

    virBitmapToDataBuf(bitmap, *data, *dataLen);

    return 0;
}


/**
 * virBitmapToDataBuf:
 * @bytes: pointer to memory to fill
 * @len: len of @bytes in byte
 *
 * Convert a bitmap to a chunk of data containing bits information.
 * Data consists of sequential bytes, with lower bytes containing
 * lower bits.
 */
void
virBitmapToDataBuf(virBitmapPtr bitmap,
                   unsigned char *bytes,
                   size_t len)
{
    size_t nbytes = bitmap->map_len * (VIR_BITMAP_BITS_PER_UNIT / CHAR_BIT);
    unsigned long *l;
    size_t i, j;

    memset(bytes, 0, len);

    /* If bitmap and buffer differ in size, only fill to the smaller length */
    len = MIN(len, nbytes);

    /* htole64 is not provided by gnulib, so we do the conversion by hand */
    l = bitmap->map;
    for (i = j = 0; i < len; i++, j++) {
        if (j == sizeof(*l)) {
            j = 0;
            l++;
        }
        bytes[i] = *l >> (j * CHAR_BIT);
    }
}


/**
 * virBitmapEqual:
 * @b1: bitmap 1
 * @b2: bitmap 2
 *
 * Compares two bitmaps, whose lengths can be different from each other.
 *
 * Returns true if two bitmaps have exactly the same set of bits set,
 * otherwise false.
 */
bool
virBitmapEqual(virBitmapPtr b1,
               virBitmapPtr b2)
{
    virBitmapPtr tmp;
    size_t i;

    if (!b1 && !b2)
        return true;

    if (!b1 || !b2)
        return false;

    if (b1->nbits > b2->nbits) {
        tmp = b1;
        b1 = b2;
        b2 = tmp;
    }

    /* Now b1 is the smaller one, if not equal */

    for (i = 0; i < b1->map_len; i++) {
        if (b1->map[i] != b2->map[i])
            return false;
    }

    for (; i < b2->map_len; i++) {
        if (b2->map[i])
            return false;
    }

    return true;
}


/**
 * virBitmapSize:
 * @bitmap: virBitmap to inspect
 *
 * Returns number of bits @bitmap can store.
 */
size_t
virBitmapSize(virBitmapPtr bitmap)
{
    return bitmap->nbits;
}


/**
 * virBitmapSetAll:
 * @bitmap: the bitmap
 *
 * set all bits in @bitmap.
 */
void virBitmapSetAll(virBitmapPtr bitmap)
{
    int tail = bitmap->nbits % VIR_BITMAP_BITS_PER_UNIT;

    memset(bitmap->map, 0xff,
           bitmap->map_len * (VIR_BITMAP_BITS_PER_UNIT / CHAR_BIT));

    /* Ensure tail bits are clear.  */
    if (tail)
        bitmap->map[bitmap->map_len - 1] &=
            -1UL >> (VIR_BITMAP_BITS_PER_UNIT - tail);
}


/**
 * virBitmapClearAll:
 * @bitmap: the bitmap
 *
 * clear all bits in @bitmap.
 */
void
virBitmapClearAll(virBitmapPtr bitmap)
{
    memset(bitmap->map, 0,
           bitmap->map_len * (VIR_BITMAP_BITS_PER_UNIT / CHAR_BIT));
}


/**
 * virBitmapIsAllSet:
 * @bitmap: the bitmap to check
 *
 * check if all bits in @bitmap are set.
 */
bool
virBitmapIsAllSet(virBitmapPtr bitmap)
{
    size_t i;
    int unusedBits;
    size_t sz;

    unusedBits = bitmap->map_len * VIR_BITMAP_BITS_PER_UNIT - bitmap->nbits;

    sz = bitmap->map_len;
    if (unusedBits > 0)
        sz--;

    for (i = 0; i < sz; i++)
        if (bitmap->map[i] != -1)
            return false;

    if (unusedBits > 0) {
        if ((bitmap->map[sz] & ((1UL << (VIR_BITMAP_BITS_PER_UNIT - unusedBits)) - 1))
            != ((1UL << (VIR_BITMAP_BITS_PER_UNIT - unusedBits)) - 1))
            return false;
    }

    return true;
}


/**
 * virBitmapIsAllClear:
 * @bitmap: the bitmap to check
 *
 * check if all bits in @bitmap are clear
 */
bool
virBitmapIsAllClear(virBitmapPtr bitmap)
{
    size_t i;

    for (i = 0; i < bitmap->map_len; i++)
        if (bitmap->map[i] != 0)
            return false;

    return true;
}


/**
 * virBitmapNextSetBit:
 * @bitmap: the bitmap
 * @pos: the position after which to search for a set bit
 *
 * Search for the first set bit after position @pos in bitmap @bitmap.
 * @pos can be -1 to search for the first set bit. Position starts
 * at 0.
 *
 * Returns the position of the found bit, or -1 if no bit found.
 */
ssize_t
virBitmapNextSetBit(virBitmapPtr bitmap,
                    ssize_t pos)
{
    size_t nl;
    size_t nb;
    unsigned long bits;

    if (pos < 0)
        pos = -1;

    pos++;

    if (pos >= bitmap->nbits)
        return -1;

    nl = pos / VIR_BITMAP_BITS_PER_UNIT;
    nb = pos % VIR_BITMAP_BITS_PER_UNIT;

    bits = bitmap->map[nl] & ~((1UL << nb) - 1);

    while (bits == 0 && ++nl < bitmap->map_len)
        bits = bitmap->map[nl];

    if (bits == 0)
        return -1;

    return __builtin_ffsl(bits) - 1 + nl * VIR_BITMAP_BITS_PER_UNIT;
}


/**
 * virBitmapLastSetBit:
 * @bitmap: the bitmap
 *
 * Search for the last set bit in bitmap @bitmap.
 *
 * Returns the position of the found bit, or -1 if no bit is set.
 */
ssize_t
virBitmapLastSetBit(virBitmapPtr bitmap)
{
    ssize_t i;
    int unusedBits;
    ssize_t sz;
    unsigned long bits;

    /* If bitmap is empty then there is no set bit */
    if (bitmap->map_len == 0)
        return -1;

    unusedBits = bitmap->map_len * VIR_BITMAP_BITS_PER_UNIT - bitmap->nbits;

    sz = bitmap->map_len - 1;
    if (unusedBits > 0) {
        bits = bitmap->map[sz] & (VIR_BITMAP_BIT(VIR_BITMAP_BITS_PER_UNIT - unusedBits) - 1);
        if (bits != 0)
            goto found;

        sz--;
    }

    for (; sz >= 0; sz--) {
        bits = bitmap->map[sz];
        if (bits != 0)
            goto found;
    }

    /* Only reached if no set bit was found */
    return -1;

 found:
    for (i = VIR_BITMAP_BITS_PER_UNIT - 1; i >= 0; i--) {
        if (bits & 1UL << i)
            return i + sz * VIR_BITMAP_BITS_PER_UNIT;
    }

    return -1;
}


/**
 * virBitmapNextClearBit:
 * @bitmap: the bitmap
 * @pos: the position after which to search for a clear bit
 *
 * Search for the first clear bit after position @pos in bitmap @bitmap.
 * @pos can be -1 to search for the first set bit. Position starts
 * at 0.
 *
 * Returns the position of the found bit, or -1 if no bit found.
 */
ssize_t
virBitmapNextClearBit(virBitmapPtr bitmap,
                      ssize_t pos)
{
    size_t nl;
    size_t nb;
    unsigned long bits;

    if (pos < 0)
        pos = -1;

    pos++;

    if (pos >= bitmap->nbits)
        return -1;

    nl = pos / VIR_BITMAP_BITS_PER_UNIT;
    nb = pos % VIR_BITMAP_BITS_PER_UNIT;

    bits = ~bitmap->map[nl] & ~((1UL << nb) - 1);

    while (bits == 0 && ++nl < bitmap->map_len)
        bits = ~bitmap->map[nl];

    if (nl == bitmap->map_len - 1) {
        /* Ensure tail bits are ignored.  */
        int tail = bitmap->nbits % VIR_BITMAP_BITS_PER_UNIT;

        if (tail)
            bits &= -1UL >> (VIR_BITMAP_BITS_PER_UNIT - tail);
    }
    if (bits == 0)
        return -1;

    return __builtin_ffsl(bits) - 1 + nl * VIR_BITMAP_BITS_PER_UNIT;
}


/**
 * virBitmapCountBits:
 * @bitmap: bitmap to inspect
 *
 * Return the number of bits currently set in @bitmap.
 */
size_t
virBitmapCountBits(virBitmapPtr bitmap)
{
    size_t i;
    size_t ret = 0;

    for (i = 0; i < bitmap->map_len; i++)
        ret += __builtin_popcountl(bitmap->map[i]);

    return ret;
}


/**
 * virBitmapNewString:
 * @string: the string to be converted to a bitmap
 *
 * Allocate a bitmap from a string of hexadecimal data.
 *
 * Returns a pointer to the allocated bitmap or NULL if
 * memory cannot be allocated.
 */
virBitmapPtr
virBitmapNewString(const char *string)
{
    virBitmapPtr bitmap;
    size_t i = 0;
    size_t len = strlen(string);

    if (strspn(string, "0123456789abcdefABCDEF") != len) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid hexadecimal string '%s'"), string);
        return NULL;
    }

    bitmap = virBitmapNew(len * 4);
    if (!bitmap)
        return NULL;

    for (i = 0; i < len; i++) {
        unsigned long nibble = virHexToBin(string[len - i - 1]);
        nibble <<= VIR_BITMAP_BIT_OFFSET(i * 4);
        bitmap->map[VIR_BITMAP_UNIT_OFFSET(i * 4)] |= nibble;
    }

    return bitmap;
}


/**
 * virBitmapDataFormat:
 * @data: the data
 * @len: length of @data in bytes
 *
 * Convert a chunk of data containing bits information to a human
 * readable string, e.g.: 0-1,4
 *
 * Returns: a string representation of the data, or NULL on error
 */
char *
virBitmapDataFormat(const void *data,
                    int len)
{
    VIR_AUTOPTR(virBitmap) map = NULL;

    if (!(map = virBitmapNewData(data, len)))
        return NULL;

    return virBitmapFormat(map);
}


/**
 * virBitmapOverlaps:
 * @b1: virBitmap to inspect
 * @b2: virBitmap to inspect
 *
 * Returns true if at least one bit with the same index is set both in @b1 and
 * @b2.
 */
bool
virBitmapOverlaps(virBitmapPtr b1,
                  virBitmapPtr b2)
{
    size_t i;

    if (b1->nbits > b2->nbits) {
        virBitmapPtr tmp = b1;
        b1 = b2;
        b2 = tmp;
    }

    for (i = 0; i < b1->map_len; i++) {
        if (b1->map[i] & b2->map[i])
            return true;
    }

    return false;
}


/**
 * virBitmapIntersect:
 * @a: bitmap, modified to contain result
 * @b: bitmap
 *
 * Performs intersection of two bitmaps: a = intersect(a, b)
 */
void
virBitmapIntersect(virBitmapPtr a,
                   virBitmapPtr b)
{
    size_t i;
    size_t max = a->map_len;

    if (max > b->map_len)
        max = b->map_len;

    for (i = 0; i < max; i++)
        a->map[i] &= b->map[i];
}


/**
 * virBitmapUnion:
 * @a: bitmap, modified to contain result
 * @b: other bitmap
 *
 * Performs union of two bitmaps: a = union(a, b)
 *
 * Returns 0 on success, <0 on failure.
 */
int
virBitmapUnion(virBitmapPtr a,
               const virBitmap *b)
{
    size_t i;

    if (a->nbits < b->nbits &&
        virBitmapExpand(a, b->nbits - 1) < 0) {
        return -1;
    }

    for (i = 0; i < b->map_len; i++)
        a->map[i] |= b->map[i];

    return 0;
}


/**
 * virBitmapSubtract:
 * @a: minuend/result
 * @b: subtrahend
 *
 * Performs subtraction of two bitmaps: a = a - b
 */
void
virBitmapSubtract(virBitmapPtr a,
                  virBitmapPtr b)
{
    size_t i;
    size_t max = a->map_len;

    if (max > b->map_len)
        max = b->map_len;

    for (i = 0; i < max; i++)
        a->map[i] &= ~b->map[i];
}


/**
 * virBitmapShrink:
 * @map: Pointer to bitmap
 * @b: Size to reduce the bitmap to
 *
 * Reduces the bitmap to size @b.  Nothing will change if the size is already
 * smaller than or equal to @b.
 */
void
virBitmapShrink(virBitmapPtr map,
                size_t b)
{
    size_t toremove;
    size_t nl = 0;
    size_t nb = 0;

    if (!map)
        return;

    if (map->nbits >= b)
        map->nbits = b;

    nl = map->nbits / VIR_BITMAP_BITS_PER_UNIT;
    nb = map->nbits % VIR_BITMAP_BITS_PER_UNIT;
    map->map[nl] &= ((1UL << nb) - 1);

    toremove = map->map_alloc - (nl + 1);

    if (toremove == 0)
        return;

    VIR_SHRINK_N(map->map, map->map_alloc, toremove);

    /* length needs to be fixed as well */
    map->map_len = map->map_alloc;
}
