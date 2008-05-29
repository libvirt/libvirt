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

/* Don't call these directly - use the macros below */
int virAlloc(void *ptrptr, size_t size) ATTRIBUTE_RETURN_CHECK;
int virAllocN(void *ptrptr, size_t size, size_t count) ATTRIBUTE_RETURN_CHECK;
int virReallocN(void *ptrptr, size_t size, size_t count) ATTRIBUTE_RETURN_CHECK;
void virFree(void *ptrptr);

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
#define VIR_ALLOC(ptr) virAlloc(&(ptr), sizeof(*(ptr)))

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
#define VIR_ALLOC_N(ptr, count) virAllocN(&(ptr), sizeof(*(ptr)), (count))

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
#define VIR_REALLOC_N(ptr, count) virReallocN(&(ptr), sizeof(*(ptr)), (count))

/**
 * VIR_FREE:
 * @ptr: pointer holding address to be freed
 *
 * Free the memory stored in 'ptr' and update to point
 * to NULL.
 */
#define VIR_FREE(ptr) virFree(&(ptr));


#if TEST_OOM
void virAllocTestInit(void);
int virAllocTestCount(void);
void virAllocTestOOM(int n, int m);
void virAllocTestHook(void (*func)(void*), void *data);
#endif



#endif /* __VIR_MEMORY_H_ */
