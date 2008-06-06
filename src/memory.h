/*
 * memory.c: safer memory allocation
 *
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
#define __VIR_MEMORY_H_

#include "internal.h"

/* Return 1 if an array of N objects, each of size S, cannot exist due
   to size arithmetic overflow.  S must be positive and N must be
   nonnegative.  This is a macro, not an inline function, so that it
   works correctly even when SIZE_MAX < N.

   By gnulib convention, SIZE_MAX represents overflow in size
   calculations, so the conservative dividend to use here is
   SIZE_MAX - 1, since SIZE_MAX might represent an overflowed value.
   However, malloc (SIZE_MAX) fails on all known hosts where
   sizeof (ptrdiff_t) <= sizeof (size_t), so do not bother to test for
   exactly-SIZE_MAX allocations on such hosts; this avoids a test and
   branch when S is known to be 1.  */
#ifndef xalloc_oversized
# define xalloc_oversized(n, s) \
    ((size_t) (sizeof (ptrdiff_t) <= sizeof (size_t) ? -1 : -2) / (s) < (n))
#endif



/* Don't call these directly - use the macros below */
int __virAlloc(void *ptrptr, size_t size) ATTRIBUTE_RETURN_CHECK;
int __virAllocN(void *ptrptr, size_t size, size_t count) ATTRIBUTE_RETURN_CHECK;
int __virReallocN(void *ptrptr, size_t size, size_t count) ATTRIBUTE_RETURN_CHECK;
void __virFree(void *ptrptr);

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
#define VIR_ALLOC(ptr) __virAlloc(&(ptr), sizeof(*(ptr)))

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
#define VIR_ALLOC_N(ptr, count) __virAllocN(&(ptr), sizeof(*(ptr)), (count))

/**
 * VIR_REALLOC_N:
 * @ptr: pointer to hold address of allocated memory
 * @count: number of elements to allocate
 *
 * Re-allocate an array of 'count' elements, each sizeof(*ptr)
 * bytes long and store the address of allocated memory in
 * 'ptr'. Fill the newly allocated memory with zeros
 *
 * Returns -1 on failure, 0 on success
 */
#define VIR_REALLOC_N(ptr, count) __virReallocN(&(ptr), sizeof(*(ptr)), (count))

/**
 * VIR_FREE:
 * @ptr: pointer holding address to be freed
 *
 * Free the memory stored in 'ptr' and update to point
 * to NULL.
 */
#define VIR_FREE(ptr) __virFree(&(ptr))


#if TEST_OOM
void virAllocTestInit(void);
int virAllocTestCount(void);
void virAllocTestOOM(int n, int m);
void virAllocTestHook(void (*func)(int, void*), void *data);
#endif



#endif /* __VIR_MEMORY_H_ */
