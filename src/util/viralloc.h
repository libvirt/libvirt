/*
 * viralloc.h: safer memory allocation
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

#pragma once

#include "internal.h"

/**
 * DEPRECATION WARNING
 *
 * APIs in this file should only be used when modifying existing code.
 * Consider converting existing code to use the new APIs when touching
 * it. All new code must use the GLib memory allocation APIs and/or
 * GLib array data types. See the hacking file for more guidance.
 */

/* Don't call these directly - use the macros below */
void virReallocN(void *ptrptr, size_t size, size_t count)
    ATTRIBUTE_NONNULL(1);
void virExpandN(void *ptrptr, size_t size, size_t *count, size_t add)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
void virResizeN(void *ptrptr, size_t size, size_t *alloc, size_t count, size_t desired)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
void virShrinkN(void *ptrptr, size_t size, size_t *count, size_t toremove)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
int virInsertElementsN(void *ptrptr, size_t size, size_t at, size_t *countptr,
                       size_t typematchDummy, void *newelem,
                       bool clearOriginal, bool inPlace)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
void virAppendElement(void *ptrptr,
                      size_t size,
                      size_t *countptr,
                      size_t typematchDummy,
                      void *newelem,
                      bool clearOriginal,
                      bool inPlace)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
int virDeleteElementsN(void *ptrptr, size_t size, size_t at, size_t *countptr,
                       size_t toremove, bool inPlace)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);

/**
 * VIR_REALLOC_N:
 * @ptr: pointer to hold address of allocated memory
 * @count: number of elements to allocate
 *
 * Re-allocate an array of 'count' elements, each sizeof(*ptr)
 * bytes long and store the address of allocated memory in
 * 'ptr'. If 'ptr' grew, the added memory is uninitialized.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Aborts on OOM
 */
#define VIR_REALLOC_N(ptr, count) virReallocN(&(ptr), sizeof(*(ptr)), (count))

/**
 * VIR_EXPAND_N:
 * @ptr: pointer to hold address of allocated memory
 * @count: variable tracking number of elements currently allocated
 * @add: number of elements to add
 *
 * Re-allocate an array of 'count' elements, each sizeof(*ptr)
 * bytes long, to be 'count' + 'add' elements long, then store the
 * address of allocated memory in 'ptr' and the new size in 'count'.
 * The new elements are filled with zero.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Aborts on OOM
 */
#define VIR_EXPAND_N(ptr, count, add) virExpandN(&(ptr), sizeof(*(ptr)), &(count), add)

/**
 * VIR_RESIZE_N:
 * @ptr: pointer to hold address of allocated memory
 * @alloc: variable tracking number of elements currently allocated
 * @count: number of elements currently in use
 * @add: minimum number of elements to additionally support
 *
 * Blindly using VIR_EXPAND_N(array, alloc, 1) in a loop scales
 * quadratically, because every iteration must copy contents from
 * all prior iterations.  But amortized linear scaling can be achieved
 * by tracking allocation size separately from the number of used
 * elements, and growing geometrically only as needed.
 *
 * If 'count' + 'add' is larger than 'alloc', then geometrically reallocate
 * the array of 'alloc' elements, each sizeof(*ptr) bytes long, and store
 * the address of allocated memory in 'ptr' and the new size in 'alloc'.
 * The new elements are filled with zero.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Aborts on OOM
 */
#define VIR_RESIZE_N(ptr, alloc, count, add) \
    virResizeN(&(ptr), sizeof(*(ptr)), &(alloc), count, add)

/**
 * VIR_SHRINK_N:
 * @ptr: pointer to hold address of allocated memory
 * @count: variable tracking number of elements currently allocated
 * @remove: number of elements to remove
 *
 * Re-allocate an array of 'count' elements, each sizeof(*ptr)
 * bytes long, to be 'count' - 'remove' elements long, then store the
 * address of allocated memory in 'ptr' and the new size in 'count'.
 * If 'count' <= 'remove', the entire array is freed.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * No return value.
 */
#define VIR_SHRINK_N(ptr, count, remove) \
    virShrinkN(&(ptr), sizeof(*(ptr)), &(count), remove)

/**
 * VIR_TYPEMATCH:
 *
 * The following macro seems a bit cryptic, so it needs a thorough
 * explanation. Its purpose is to check for assignment compatibility
 * and identical size between two values without creating any side
 * effects (by doing something silly like actually assigning one to
 * the other). Note that it takes advantage of the C89-guaranteed
 * property of sizeof() - it cannot have any side effects, so anything
 * that happens inside sizeof() will not have any effect at runtime.
 *
 * VIR_TYPEMATCH evaluates to "1" if the two passed values are both
 * assignment-compatible and the same size, and otherwise generates a
 * compile-time error. It determines the result by performing the
 * following three operations:
 *
 *    * sizeof(*(a) = *(b)) assures that *a and *b are
 *      assignment-compatible (they may still have a different size
 *      though! e.g. longVar = intVar) (If not, there is a compile-time
 *      error. If so, the result of that subexpression is sizeof(*(a)),
 *      i.e. one element of the array)
 *
 *    * sizeof(*(a) = *(b)) == sizeof(*(b)) checks if *a and *b are also
 *      of the same size (so that, e.g. you don't accidentally copy an
 *      int plus the random bytes following it into an array of long). It
 *      evaluates to 1 if they are the same, and 0 otherwise.
 *
 *    * sizeof(char[2 * (result of previous step) - 1]) evaluates to 1
 *      if the previous step was successful (char [(2*1) - 1] i.e.
 *      char[1]), or generates a compile error if it wasn't successful
 *      (char[2*0 -1] i.e. char[-1], which isn't valid in C).
 *
 * So VIR_TYPEMATCH(a, b) will either abort the compile with an error,
 * or evaluate to "1", and in the meantime check that we've actually
 * added the correct &'s and/or *'s to the arguments. (Whew!)
*/
#define VIR_TYPEMATCH(a, b) \
    sizeof(char[2 * (sizeof(*(a) = *(b)) == sizeof(*(b))) - 1])

/**
 * VIR_INSERT_ELEMENT, VIR_INSERT_ELEMENT_INPLACE:
 * @ptr:     pointer to array of objects (*not* ptr to ptr)
 * @at:      index within array where new elements should be added
 * @count:   variable tracking number of elements currently allocated
 * @newelem: the new element to move into place (*not* a pointer to
 *           the element, but the element itself).
 *           (the original will be zeroed out if successful)
 *
 * Re-allocate an array of 'count' elements, each sizeof(*ptr) bytes
 * long, to be 'count' + 1 elements long, then appropriately move
 * the elements starting at ptr[at] up by 1 element, copy the
 * item 'newelem' into ptr[at], then store the address of
 * allocated memory in 'ptr' and the new size in 'count'.
 *
 * VIR_INSERT_ELEMENT_INPLACE is identical, but assumes any necessary
 * memory re-allocation has already been done.
 *
 * These macros are safe to use on arguments with side effects.
 *
 * Returns -1 on failure (with OOM error reported), 0 on success
 */
#define VIR_INSERT_ELEMENT(ptr, at, count, newelem) \
    virInsertElementsN(&(ptr), sizeof(*(ptr)), at, &(count), \
                       VIR_TYPEMATCH(ptr, &(newelem)), &(newelem), true, false)
#define VIR_INSERT_ELEMENT_INPLACE(ptr, at, count, newelem) \
    virInsertElementsN(&(ptr), sizeof(*(ptr)), at, &(count), \
                       VIR_TYPEMATCH(ptr, &(newelem)), &(newelem), true, true)

/**
 * VIR_APPEND_ELEMENT:
 * @ptr:     pointer to array of objects (*not* ptr to ptr)
 * @count:   variable tracking number of elements currently allocated
 * @newelem: the new element to move into place (*not* a pointer to
 *           the element, but the element itself).
 *           (the original will be zeroed out if successful)
 *
 * Re-allocate an array of 'count' elements, each sizeof(*ptr) bytes
 * long, to be 'count' + 1 elements long, then copy the item from
 * 'newelem' into ptr[count+1], and store the address of allocated
 * memory in 'ptr' and the new size in 'count'. If 'newelem' is NULL,
 * the new element at ptr[at] is instead filled with zero.
 *
 * VIR_APPEND_ELEMENT_COPY is identical, but doesn't clear out the
 *   original element to 0 on success, so there are two copies of the
 *   element. This is useful if the "element" is actually just a
 *   pointer to the real data, and you want to maintain a reference to
 *   it for use after the append is completed; but if the "element" is
 *   an object that points to other allocated memory, having multiple
 *   copies can cause problems (e.g. double free).
 *
 * VIR_APPEND_ELEMENT_*INPLACE are identical, but assume any
 *   necessary memory re-allocation has already been done.
 *
 * These macros are safe to use on arguments with side effects.
 */
#define VIR_APPEND_ELEMENT(ptr, count, newelem) \
    virAppendElement(&(ptr), sizeof(*(ptr)), &(count), \
                     VIR_TYPEMATCH(ptr, &(newelem)), &(newelem), true, false)
#define VIR_APPEND_ELEMENT_COPY(ptr, count, newelem) \
    virAppendElement(&(ptr), sizeof(*(ptr)), &(count), \
                     VIR_TYPEMATCH(ptr, &(newelem)), &(newelem), false, false)
#define VIR_APPEND_ELEMENT_INPLACE(ptr, count, newelem) \
    virAppendElement(&(ptr), sizeof(*(ptr)), &(count), \
                     VIR_TYPEMATCH(ptr, &(newelem)), \
                     &(newelem), true, true)
#define VIR_APPEND_ELEMENT_COPY_INPLACE(ptr, count, newelem) \
    virAppendElement(&(ptr), sizeof(*(ptr)), &(count), \
                     VIR_TYPEMATCH(ptr, &(newelem)), \
                     &(newelem), false, true)

/**
 * VIR_DELETE_ELEMENT:
 * @ptr:   pointer to array of objects (*not* ptr to ptr)
 * @at:    index within array where new elements should be deleted
 * @count: variable tracking number of elements currently allocated
 *
 * Re-allocate an array of 'count' elements, each sizeof(*ptr)
 * bytes long, to be 'count' - 1 elements long, then store the
 * address of allocated memory in 'ptr' and the new size in 'count'.
 * If 'count' <= 1, the entire array is freed.
 *
 * VIR_DELETE_ELEMENT_INPLACE is identical, but assumes any
 *   necessary memory re-allocation will be done later.
 *
 * These macros are safe to use on arguments with side effects.
 *
 * Returns -1 on failure, 0 on success
 */
#define VIR_DELETE_ELEMENT(ptr, at, count) \
    virDeleteElementsN(&(ptr), sizeof(*(ptr)), at, &(count), 1, false)
#define VIR_DELETE_ELEMENT_INPLACE(ptr, at, count) \
    virDeleteElementsN(&(ptr), sizeof(*(ptr)), at, &(count), 1, true)

/**
 * VIR_FREE:
 * @ptr: pointer holding address to be freed
 *
 * Free the memory stored in 'ptr' and update to point
 * to NULL.
 *
 * This macro is safe to use on arguments with side effects.
 */
#define VIR_FREE(ptr) g_clear_pointer(&(ptr), g_free)
