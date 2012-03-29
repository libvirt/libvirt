/*
 * memory.c: safer memory allocation
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */


#ifndef __VIR_MEMORY_H_
# define __VIR_MEMORY_H_

# include "internal.h"

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
# ifndef xalloc_oversized
#  define xalloc_oversized(n, s) \
    ((size_t) (sizeof(ptrdiff_t) <= sizeof(size_t) ? -1 : -2) / (s) < (n))
# endif



/* Don't call these directly - use the macros below */
int virAlloc(void *ptrptr, size_t size) ATTRIBUTE_RETURN_CHECK
    ATTRIBUTE_NONNULL(1);
int virAllocN(void *ptrptr, size_t size, size_t count) ATTRIBUTE_RETURN_CHECK
    ATTRIBUTE_NONNULL(1);
int virReallocN(void *ptrptr, size_t size, size_t count) ATTRIBUTE_RETURN_CHECK
    ATTRIBUTE_NONNULL(1);
int virExpandN(void *ptrptr, size_t size, size_t *count, size_t add)
    ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
int virResizeN(void *ptrptr, size_t size, size_t *alloc, size_t count,
               size_t desired)
    ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
void virShrinkN(void *ptrptr, size_t size, size_t *count, size_t toremove)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3);
int virAllocVar(void *ptrptr,
                size_t struct_size,
                size_t element_size,
                size_t count) ATTRIBUTE_RETURN_CHECK ATTRIBUTE_NONNULL(1);
void virFree(void *ptrptr) ATTRIBUTE_NONNULL(1);

/**
 * VIR_ALLOC:
 * @ptr: pointer to hold address of allocated memory
 *
 * Allocate sizeof(*ptr) bytes of memory and store
 * the address of allocated memory in 'ptr'. Fill the
 * newly allocated memory with zeros.
 *
 * Returns -1 on failure, 0 on success
 */
# define VIR_ALLOC(ptr) virAlloc(&(ptr), sizeof(*(ptr)))

/**
 * VIR_ALLOC_N:
 * @ptr: pointer to hold address of allocated memory
 * @count: number of elements to allocate
 *
 * Allocate an array of 'count' elements, each sizeof(*ptr)
 * bytes long and store the address of allocated memory in
 * 'ptr'. Fill the newly allocated memory with zeros.
 *
 * Returns -1 on failure, 0 on success
 */
# define VIR_ALLOC_N(ptr, count) virAllocN(&(ptr), sizeof(*(ptr)), (count))

/**
 * VIR_REALLOC_N:
 * @ptr: pointer to hold address of allocated memory
 * @count: number of elements to allocate
 *
 * Re-allocate an array of 'count' elements, each sizeof(*ptr)
 * bytes long and store the address of allocated memory in
 * 'ptr'. If 'ptr' grew, the added memory is uninitialized.
 *
 * Returns -1 on failure, 0 on success
 */
# define VIR_REALLOC_N(ptr, count) virReallocN(&(ptr), sizeof(*(ptr)), (count))

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
 * Returns -1 on failure, 0 on success
 */
# define VIR_EXPAND_N(ptr, count, add) \
    virExpandN(&(ptr), sizeof(*(ptr)), &(count), add)

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
 * Returns -1 on failure, 0 on success
 */
# define VIR_RESIZE_N(ptr, alloc, count, add) \
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
 * No return value.
 */
# define VIR_SHRINK_N(ptr, count, remove) \
    virShrinkN(&(ptr), sizeof(*(ptr)), &(count), remove)

/*
 * VIR_ALLOC_VAR_OVERSIZED:
 * @M: size of base structure
 * @N: number of array elements in trailing array
 * @S: size of trailing array elements
 *
 * Check to make sure that the requested allocation will not cause
 * arithmetic overflow in the allocation size.  The check is
 * essentially the same as that in gnulib's xalloc_oversized.
 */
# define VIR_ALLOC_VAR_OVERSIZED(M, N, S) ((((size_t)-1) - (M)) / (S) < (N))

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

 * Returns -1 on failure, 0 on success
 */
# define VIR_ALLOC_VAR(ptr, type, count) \
    virAllocVar(&(ptr), sizeof(*(ptr)), sizeof(type), (count))

/**
 * VIR_FREE:
 * @ptr: pointer holding address to be freed
 *
 * Free the memory stored in 'ptr' and update to point
 * to NULL.
 */
/* The ternary ensures that ptr is a pointer and not an integer type,
 * while evaluating ptr only once.  For now, we intentionally cast
 * away const, since a number of callers safely pass const char *.
 */
# define VIR_FREE(ptr) virFree((void *) (1 ? (const void *) &(ptr) : (ptr)))


# if TEST_OOM
void virAllocTestInit(void);
int virAllocTestCount(void);
void virAllocTestOOM(int n, int m);
void virAllocTestHook(void (*func)(int, void*), void *data);
# endif



#endif /* __VIR_MEMORY_H_ */
