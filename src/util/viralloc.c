/*
 * viralloc.c: safer memory allocation
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2008 Daniel P. Berrange
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
 */

#include <config.h>

#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.alloc");


/**
 * virReallocN:
 * @ptrptr: pointer to pointer for address of allocated memory
 * @size: number of bytes to allocate
 * @count: number of elements in array
 *
 * Resize the block of memory in 'ptrptr' to be an array of
 * 'count' elements, each 'size' bytes in length. Update 'ptrptr'
 * with the address of the newly allocated memory. On failure,
 * 'ptrptr' is not changed and still points to the original memory
 * block. Any newly allocated memory in 'ptrptr' is uninitialized.
 *
 * Returns zero on success, aborts on OOM
 */
void virReallocN(void *ptrptr,
                 size_t size,
                 size_t count)
{
    *(void **)ptrptr = g_realloc_n(*(void**)ptrptr, size, count);
}

/**
 * virExpandN:
 * @ptrptr: pointer to pointer for address of allocated memory
 * @size: number of bytes per element
 * @countptr: pointer to number of elements in array
 * @add: number of elements to add
 *
 * Resize the block of memory in 'ptrptr' to be an array of
 * '*countptr' + 'add' elements, each 'size' bytes in length.
 * Update 'ptrptr' and 'countptr'  with the details of the newly
 * allocated memory. On failure, 'ptrptr' and 'countptr' are not
 * changed. Any newly allocated memory in 'ptrptr' is zero-filled.
 *
 * Aborts on OOM
 */
void virExpandN(void *ptrptr,
                size_t size,
                size_t *countptr,
                size_t add)
{
    if (*countptr + add < *countptr)
        abort();

    virReallocN(ptrptr, size, *countptr + add);
    memset(*(char **)ptrptr + (size * *countptr), 0, size * add);
    *countptr += add;
}

/**
 * virResizeN:
 * @ptrptr: pointer to pointer for address of allocated memory
 * @size: number of bytes per element
 * @allocptr: pointer to number of elements allocated in array
 * @count: number of elements currently used in array
 * @add: minimum number of additional elements to support in array
 *
 * If 'count' + 'add' is larger than '*allocptr', then resize the
 * block of memory in 'ptrptr' to be an array of at least 'count' +
 * 'add' elements, each 'size' bytes in length. Update 'ptrptr' and
 * 'allocptr' with the details of the newly allocated memory. On
 * failure, 'ptrptr' and 'allocptr' are not changed. Any newly
 * allocated memory in 'ptrptr' is zero-filled.
 *
 * Aborts on OOM
 */
void virResizeN(void *ptrptr,
                size_t size,
                size_t *allocptr,
                size_t count,
                size_t add)
{
    size_t delta;

    if (count + add < count)
        abort();

    if (count + add <= *allocptr)
        return;

    delta = count + add - *allocptr;
    if (delta < *allocptr / 2)
        delta = *allocptr / 2;

    virExpandN(ptrptr, size, allocptr, delta);
}

/**
 * virShrinkN:
 * @ptrptr: pointer to pointer for address of allocated memory
 * @size: number of bytes per element
 * @countptr: pointer to number of elements in array
 * @toremove: number of elements to remove
 *
 * Resize the block of memory in 'ptrptr' to be an array of
 * '*countptr' - 'toremove' elements, each 'size' bytes in length.
 * Update 'ptrptr' and 'countptr'  with the details of the newly
 * allocated memory. If 'toremove' is larger than 'countptr', free
 * the entire array.
 */
void virShrinkN(void *ptrptr, size_t size, size_t *countptr, size_t toremove)
{
    if (toremove < *countptr) {
        virReallocN(ptrptr, size, *countptr -= toremove);
    } else {
        g_clear_pointer(((void **)ptrptr), g_free);
        *countptr = 0;
    }
}

/**
 * virInsertElementsN:
 * @ptrptr:   pointer to hold address of allocated memory
 * @size:     the size of one element in bytes
 * @at:       index within array where new elements should be added, -1 for end
 * @countptr: variable tracking number of elements currently allocated
 * @newelems: pointer to array of one or more new elements to move into
 *            place (the originals will be zeroed out if successful
 *            and if clearOriginal is true)
 * @clearOriginal: false if the new item in the array should be copied
 *            from the original, and the original left intact.
 *            true if the original should be 0'd out on success.
 * @inPlace:  false if we should expand the allocated memory before
 *            moving, true if we should assume someone else *has
 *            already* done that.
 *
 * Re-allocate an array of *countptr elements, each sizeof(*ptrptr) bytes
 * long, to be *countptr elements long, then appropriately move
 * the elements starting at ptrptr[at] up by 1 elements, copy the
 * items from newelems into ptrptr[at], then store the address of
 * allocated memory in *ptrptr and the new size in *countptr.  If
 * newelems is NULL, the new elements at ptrptr[at] are instead filled
 * with zero.  at must be between [0,*countptr], except that -1 is
 * treated the same as *countptr for convenience.
 *
 * Aborts on OOM failure.
 */
static void
virInsertElementInternal(void *ptrptr,
                         size_t size,
                         size_t at,
                         size_t *countptr,
                         void *newelems,
                         bool clearOriginal,
                         bool inPlace)
{
    if (inPlace) {
        *countptr += 1;
    } else {
        virExpandN(ptrptr, size, countptr, 1);
    }

    /* memory was successfully re-allocated. Move up all elements from
     * ptrptr[at] to the end (if we're not "inserting" at the end
     * already), memcpy in the new elements, and clear the elements
     * from their original location. Remember that *countptr has
     * already been updated with new element count!
     */
    if (at < *countptr - 1) {
        memmove(*(char**)ptrptr + (size * (at + 1)),
                *(char**)ptrptr + (size * at),
                size * (*countptr - 1 - at));
    }

    if (newelems) {
        memcpy(*(char**)ptrptr + (size * at), newelems, size);
        if (clearOriginal)
           memset((char*)newelems, 0, size);
    } else if (inPlace || (at < *countptr - 1)) {
        /* NB: if inPlace, assume memory at the end wasn't initialized */
        memset(*(char**)ptrptr + (size * at), 0, size);
    }
}


/**
 * virInsertElementsN:
 * @ptrptr:   pointer to hold address of allocated memory
 * @size:     the size of one element in bytes
 * @at:       index within array where new elements should be added, -1 for end
 * @countptr: variable tracking number of elements currently allocated
 * @typematchDummy: helper variable to consume results of compile time checks
 * @newelems: pointer to array of one or more new elements to move into
 *            place (the originals will be zeroed out if successful
 *            and if clearOriginal is true)
 * @clearOriginal: false if the new item in the array should be copied
 *            from the original, and the original left intact.
 *            true if the original should be 0'd out on success.
 * @inPlace:  false if we should expand the allocated memory before
 *            moving, true if we should assume someone else *has
 *            already* done that.
 *
 * Re-allocate an array of *countptr elements, each sizeof(*ptrptr) bytes
 * long, to be *countptr elements long, then appropriately move
 * the elements starting at ptrptr[at] up by 1 elements, copy the
 * items from newelems into ptrptr[at], then store the address of
 * allocated memory in *ptrptr and the new size in *countptr.  If
 * newelems is NULL, the new elements at ptrptr[at] are instead filled
 * with zero.  at must be between [0,*countptr], except that -1 is
 * treated the same as *countptr for convenience.
 *
 * Returns -1 on failure, 0 on success
 */
int
virInsertElementsN(void *ptrptr,
                   size_t size,
                   size_t at,
                   size_t *countptr,
                   size_t typematchDummy G_GNUC_UNUSED,
                   void *newelems,
                   bool clearOriginal,
                   bool inPlace)
{
    if (at == -1) {
        at = *countptr;
    } else if (at > *countptr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("out of bounds index - count %1$zu at %2$zu"),
                       *countptr, at);
        return -1;
    }

    virInsertElementInternal(ptrptr, size, at, countptr, newelems, clearOriginal, inPlace);

    return 0;
}


/**
 * virAppendElement:
 * @ptrptr:   pointer to hold address of allocated memory
 * @size:     the size of one element in bytes
 * @countptr: variable tracking number of elements currently allocated
 * @typematchDummy: helper variable to consume results of compile time checks
 * @newelem: pointer to a new element to append to @ptrptr
 *           (the original will be zeroed out if clearOriginal is true)
 * @clearOriginal: false if the new item in the array should be copied
 *            from the original, and the original left intact.
 *            true if the original should be 0'd out on success.
 * @inPlace:  false if we should expand the allocated memory before
 *            moving, true if we should assume someone else *has
 *            already* done that.
 *
 * Re-allocate @ptrptr to fit an extra element and place @newelem at the end.
 */
void
virAppendElement(void *ptrptr,
                 size_t size,
                 size_t *countptr,
                 size_t typematchDummy G_GNUC_UNUSED,
                 void *newelem,
                 bool clearOriginal,
                 bool inPlace)
{
    virInsertElementInternal(ptrptr, size, *countptr, countptr, newelem, clearOriginal, inPlace);
}


/**
 * virDeleteElementsN:
 * @ptrptr:   pointer to hold address of allocated memory
 * @size:     the size of one element in bytes
 * @at:       index within array where new elements should be deleted
 * @countptr: variable tracking number of elements currently allocated
 * @toremove: number of elements to remove
 * @inPlace:  false if we should shrink the allocated memory when done,
 *            true if we should assume someone else will do that.
 *
 * Re-allocate an array of *countptr elements, each sizeof(*ptrptr)
 * bytes long, to be *countptr-remove elements long, then store the
 * address of allocated memory in *ptrptr and the new size in *countptr.
 * If *countptr <= remove, the entire array is freed.
 *
 * Returns -1 on failure, 0 on success
 */
int
virDeleteElementsN(void *ptrptr, size_t size, size_t at,
                   size_t *countptr, size_t toremove,
                   bool inPlace)
{
    if (at + toremove > *countptr) {
        VIR_WARN("out of bounds index - count %zu at %zu toremove %zu",
                 *countptr, at, toremove);
        return -1;
    }

    /* First move down the elements at the end that won't be deleted,
     * then realloc. We assume that the items being deleted have
     * already been cleared.
    */
    memmove(*(char**)ptrptr + (size * at),
            *(char**)ptrptr + (size * (at + toremove)),
            size * (*countptr - toremove - at));
    if (inPlace)
        *countptr -= toremove;
    else
        virShrinkN(ptrptr, size, countptr, toremove);
    return 0;
}
