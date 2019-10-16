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

/* Return 1 if an array of N objects, each of size S, cannot exist due
   to size arithmetic overflow.  S must be positive and N must be
   nonnegative.  This is a macro, not an inline function, so that it
   works correctly even when SIZE_MAX < N.

   By gnulib convention, SIZE_MAX represents overflow in size
   calculations, so the conservative dividend to use here is
   SIZE_MAX - 1, since SIZE_MAX might represent an overflowed value.
   However, malloc (SIZE_MAX) fails on all known hosts where
   sizeof(ptrdiff_t) <= sizeof(size_t), so do not bother to test for
   exactly-SIZE_MAX allocations on such hosts; this avoids a test and
   branch when S is known to be 1.  */
#ifndef xalloc_oversized
# define xalloc_oversized(n, s) \
    ((size_t) (sizeof(ptrdiff_t) <= sizeof(size_t) ? -1 : -2) / (s) < (n))
#endif



/* Don't call these directly - use the macros below */
int virAlloc(void *ptrptr, size_t size)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1);
int virAllocN(void *ptrptr, size_t size, size_t count)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1);
int virReallocN(void *ptrptr, size_t size, size_t count)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1);
int virExpandN(void *ptrptr, size_t size, size_t *count, size_t add)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
int virResizeN(void *ptrptr, size_t size, size_t *alloc, size_t count, size_t desired)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
void virShrinkN(void *ptrptr, size_t size, size_t *count, size_t toremove)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
int virInsertElementsN(void *ptrptr, size_t size, size_t at, size_t *countptr,
                       size_t add, void *newelem,
                       bool clearOriginal, bool inPlace)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
int virDeleteElementsN(void *ptrptr, size_t size, size_t at, size_t *countptr,
                       size_t toremove, bool inPlace)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(4);
int virAllocVar(void *ptrptr, size_t struct_size, size_t element_size, size_t count)
    G_GNUC_WARN_UNUSED_RESULT ATTRIBUTE_NONNULL(1);
void virFree(void *ptrptr) ATTRIBUTE_NONNULL(1);

void virDispose(void *ptrptr, size_t count, size_t element_size, size_t *countptr)
    ATTRIBUTE_NONNULL(1);
void virDisposeString(char **strptr)
    ATTRIBUTE_NONNULL(1);

/**
 * VIR_ALLOC:
 * @ptr: pointer to hold address of allocated memory
 *
 * Allocate sizeof(*ptr) bytes of memory and store
 * the address of allocated memory in 'ptr'. Fill the
 * newly allocated memory with zeros.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Returns 0 on success, aborts on OOM
 */
#define VIR_ALLOC(ptr) virAlloc(&(ptr), sizeof(*(ptr)))

/**
 * VIR_ALLOC_QUIET:
 * @ptr: pointer to hold address of allocated memory
 *
 * Allocate sizeof(*ptr) bytes of memory and store
 * the address of allocated memory in 'ptr'. Fill the
 * newly allocated memory with zeros.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Returns 0 on success, aborts on OOM
 */
#define VIR_ALLOC_QUIET(ptr) VIR_ALLOC(ptr)

/**
 * VIR_ALLOC_N:
 * @ptr: pointer to hold address of allocated memory
 * @count: number of elements to allocate
 *
 * Allocate an array of 'count' elements, each sizeof(*ptr)
 * bytes long and store the address of allocated memory in
 * 'ptr'. Fill the newly allocated memory with zeros.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Returns 0 on success, aborts on OOM
 */
#define VIR_ALLOC_N(ptr, count) virAllocN(&(ptr), sizeof(*(ptr)), (count))

/**
 * VIR_ALLOC_N_QUIET:
 * @ptr: pointer to hold address of allocated memory
 * @count: number of elements to allocate
 *
 * Allocate an array of 'count' elements, each sizeof(*ptr)
 * bytes long and store the address of allocated memory in
 * 'ptr'. Fill the newly allocated memory with zeros.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Returns 0 on success, aborts on OOM
 */
#define VIR_ALLOC_N_QUIET(ptr, count) VIR_ALLOC_N(ptr, count)

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
 * Returns 0 on success, aborts on OOM
 */
#define VIR_REALLOC_N(ptr, count) virReallocN(&(ptr), sizeof(*(ptr)), (count))

/**
 * VIR_REALLOC_N_QUIET:
 * @ptr: pointer to hold address of allocated memory
 * @count: number of elements to allocate
 *
 * Re-allocate an array of 'count' elements, each sizeof(*ptr)
 * bytes long and store the address of allocated memory in
 * 'ptr'. If 'ptr' grew, the added memory is uninitialized.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Returns 0 on success, aborts on OOM
 */
#define VIR_REALLOC_N_QUIET(ptr, count) VIR_REALLOC_N(ptr, count)

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
 * Returns 0 on success, aborts on OOM
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
 * Returns 0 on success, aborts on OOM
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
 * VIR_INSERT_ELEMENT:
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
 * VIR_INSERT_ELEMENT_COPY is identical, but doesn't clear out the
 *   original element to 0 on success, so there are two copies of the
 *   element. This is useful if the "element" is actually just a
 *   pointer to the real data, and you want to maintain a reference to
 *   it for use after the insert is completed; but if the "element" is
 *   an object that points to other allocated memory, having multiple
 *   copies can cause problems (e.g. double free).
 *
 * VIR_INSERT_ELEMENT_*INPLACE are identical, but assume any necessary
 *   memory re-allocation has already been done.
 *
 * VIR_INSERT_ELEMENT_* all need to send "1" as the "add" argument to
 * virInsertElementsN (which has the currently-unused capability of
 * inserting multiple items at once). We use this to our advantage by
 * replacing it with VIR_TYPECHECK(ptr, &newelem) so that we can be
 * assured ptr and &newelem are of compatible types.
 *
 * These macros are safe to use on arguments with side effects.
 *
 * Returns -1 on failure (with OOM error reported), 0 on success
 */
#define VIR_INSERT_ELEMENT(ptr, at, count, newelem) \
    virInsertElementsN(&(ptr), sizeof(*(ptr)), at, &(count), \
                       VIR_TYPEMATCH(ptr, &(newelem)), &(newelem), true, false)
#define VIR_INSERT_ELEMENT_COPY(ptr, at, count, newelem) \
    virInsertElementsN(&(ptr), sizeof(*(ptr)), at, &(count), \
                       VIR_TYPEMATCH(ptr, &(newelem)), &(newelem), false, false)
#define VIR_INSERT_ELEMENT_INPLACE(ptr, at, count, newelem) \
    virInsertElementsN(&(ptr), sizeof(*(ptr)), at, &(count), \
                       VIR_TYPEMATCH(ptr, &(newelem)), &(newelem), true, true)
#define VIR_INSERT_ELEMENT_COPY_INPLACE(ptr, at, count, newelem) \
    virInsertElementsN(&(ptr), sizeof(*(ptr)), at, &(count), \
                       VIR_TYPEMATCH(ptr, &(newelem)), &(newelem), false, true)

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
 * VIR_APPEND_ELEMENT_* all need to send "1" as the "add" argument to
 * virInsertElementsN (which has the currently-unused capability of
 * inserting multiple items at once). We use this to our advantage by
 * replacing it with VIR_TYPECHECK(ptr, &newelem) so that we can be
 * assured ptr and &newelem are of compatible types.
 *
 * These macros are safe to use on arguments with side effects.
 *
 * Returns -1 on failure (with OOM error reported), 0 on success
 */
#define VIR_APPEND_ELEMENT(ptr, count, newelem) \
    virInsertElementsN(&(ptr), sizeof(*(ptr)), -1, &(count), \
                       VIR_TYPEMATCH(ptr, &(newelem)), &(newelem), true, false)
#define VIR_APPEND_ELEMENT_COPY(ptr, count, newelem) \
    virInsertElementsN(&(ptr), sizeof(*(ptr)), -1, &(count), \
                       VIR_TYPEMATCH(ptr, &(newelem)), &(newelem), false, false)
#define VIR_APPEND_ELEMENT_INPLACE(ptr, count, newelem) \
    ignore_value(virInsertElementsN(&(ptr), sizeof(*(ptr)), -1, &(count), \
                                    VIR_TYPEMATCH(ptr, &(newelem)), \
                                    &(newelem), true, true))
#define VIR_APPEND_ELEMENT_COPY_INPLACE(ptr, count, newelem) \
    ignore_value(virInsertElementsN(&(ptr), sizeof(*(ptr)), -1, &(count), \
                                    VIR_TYPEMATCH(ptr, &(newelem)), \
                                    &(newelem), false, true))

/* Quiet version of macros above */
#define VIR_APPEND_ELEMENT_QUIET(ptr, count, newelem) \
    VIR_APPEND_ELEMENT(ptr, count, newelem)

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
 * VIR_ALLOC_VAR_OVERSIZED:
 * @M: size of base structure
 * @N: number of array elements in trailing array
 * @S: size of trailing array elements
 *
 * Check to make sure that the requested allocation will not cause
 * arithmetic overflow in the allocation size.  The check is
 * essentially the same as that in gnulib's xalloc_oversized.
 */
#define VIR_ALLOC_VAR_OVERSIZED(M, N, S) ((((size_t)-1) - (M)) / (S) < (N))

/**
 * VIR_ALLOC_VAR:
 * @ptr: pointer to hold address of allocated memory
 * @type: element type of trailing array
 * @count: number of array elements to allocate
 *
 * Allocate sizeof(*ptr) bytes plus an array of 'count' elements, each
 * sizeof('type').  This sort of allocation is useful for receiving
 * the data of certain ioctls and other APIs which return a struct in
 * which the last element is an array of undefined length.  The caller
 * of this type of API is expected to know the length of the array
 * that will be returned and allocate a suitable buffer to contain the
 * returned data.  C99 refers to these variable length objects as
 * structs containing flexible array members.
 *
 * This macro is safe to use on arguments with side effects.
 *
 * Returns 0 on success, aborts on OOM
 */
#define VIR_ALLOC_VAR(ptr, type, count) \
    virAllocVar(&(ptr), sizeof(*(ptr)), sizeof(type), (count))

/**
 * VIR_FREE:
 * @ptr: pointer holding address to be freed
 *
 * Free the memory stored in 'ptr' and update to point
 * to NULL.
 *
 * This macro is safe to use on arguments with side effects.
 */
/* The ternary ensures that ptr is a non-const pointer and not an
 * integer type, all while evaluating ptr only once.  This gives us
 * extra compiler safety when compiling under gcc.
 */
#define VIR_FREE(ptr) virFree(1 ? (void *) &(ptr) : (ptr))


/**
 * VIR_DISPOSE_N:
 * @ptr: pointer holding address to be cleared and freed
 * @count: count of elements in @ptr
 *
 * Clear the memory of the array of elements pointed to by 'ptr' of 'count'
 * elements and free it. Update the pointer/count to NULL/0.
 *
 * This macro is safe to use on arguments with side effects.
 */
#define VIR_DISPOSE_N(ptr, count) virDispose(1 ? (void *) &(ptr) : (ptr), 0, \
                                             sizeof(*(ptr)), &(count))


/**
 * VIR_DISPOSE_STRING:
 * @ptr: pointer to a string to be cleared and freed
 *
 * Clears the string and frees the corresponding memory.
 *
 * This macro is not safe to be used on arguments with side effects.
 */
#define VIR_DISPOSE_STRING(ptr) virDisposeString(&(ptr))

/**
 * VIR_AUTODISPOSE_STR:
 *
 * Macro to automatically free and clear the memory allocated to
 * the string variable declared with it by calling virDisposeString
 * when the variable goes out of scope.
 */
#define VIR_AUTODISPOSE_STR \
    __attribute__((cleanup(virDisposeString))) char *

/**
 * VIR_DISPOSE:
 * @ptr: pointer to memory to be cleared and freed
 *
 * Clears and frees the corresponding memory.
 *
 * This macro is safe to be used on arguments with side effects.
 */
#define VIR_DISPOSE(ptr) virDispose(1 ? (void *) &(ptr) : (ptr), 1, \
                                    sizeof(*(ptr)), NULL)
