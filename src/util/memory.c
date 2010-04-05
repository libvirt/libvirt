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

#include <config.h>
#include <stdlib.h>
#include <stddef.h>

#include "memory.h"


#if TEST_OOM
static int testMallocNext = 0;
static int testMallocFailFirst = 0;
static int testMallocFailLast = 0;
static void (*testMallocHook)(int, void*) = NULL;
static void *testMallocHookData = NULL;

void virAllocTestInit(void)
{
    testMallocNext = 1;
    testMallocFailFirst = 0;
    testMallocFailLast = 0;
}

int virAllocTestCount(void)
{
    return testMallocNext - 1;
}

void virAllocTestHook(void (*func)(int, void*), void *data)
{
    testMallocHook = func;
    testMallocHookData = data;
}

void virAllocTestOOM(int n, int m)
{
    testMallocNext = 1;
    testMallocFailFirst = n;
    testMallocFailLast = n + m - 1;
}

static int virAllocTestFail(void)
{
    int fail = 0;
    if (testMallocNext == 0)
        return 0;

    fail =
        testMallocNext >= testMallocFailFirst &&
        testMallocNext <= testMallocFailLast;

    if (fail && testMallocHook)
        (testMallocHook)(testMallocNext, testMallocHookData);

    testMallocNext++;
    return fail;
}
#endif


/**
 * virAlloc:
 * @ptrptr: pointer to pointer for address of allocated memory
 * @size: number of bytes to allocate
 *
 * Allocate  'size' bytes of memory. Return the address of the
 * allocated memory in 'ptrptr'. The newly allocated memory is
 * filled with zeros.
 *
 * Returns -1 on failure to allocate, zero on success
 */
int virAlloc(void *ptrptr, size_t size)
{
#if TEST_OOM
    if (virAllocTestFail()) {
        *(void **)ptrptr = NULL;
        return -1;
    }
#endif

    *(void **)ptrptr = calloc(1, size);
    if (*(void **)ptrptr == NULL)
        return -1;
    return 0;
}

/**
 * virAllocN:
 * @ptrptr: pointer to pointer for address of allocated memory
 * @size: number of bytes to allocate
 * @count: number of elements to allocate
 *
 * Allocate an array of memory 'count' elements long,
 * each with 'size' bytes. Return the address of the
 * allocated memory in 'ptrptr'.  The newly allocated
 * memory is filled with zeros.
 *
 * Returns -1 on failure to allocate, zero on success
 */
int virAllocN(void *ptrptr, size_t size, size_t count)
{
#if TEST_OOM
    if (virAllocTestFail()) {
        *(void **)ptrptr = NULL;
        return -1;
    }
#endif

    *(void**)ptrptr = calloc(count, size);
    if (*(void**)ptrptr == NULL)
        return -1;
    return 0;
}

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
 * block. The newly allocated memory is filled with zeros.
 *
 * Returns -1 on failure to allocate, zero on success
 */
int virReallocN(void *ptrptr, size_t size, size_t count)
{
    void *tmp;
#if TEST_OOM
    if (virAllocTestFail())
        return -1;
#endif

    if (xalloc_oversized(count, size)) {
        errno = ENOMEM;
        return -1;
    }
    tmp = realloc(*(void**)ptrptr, size * count);
    if (!tmp && (size * count))
        return -1;
    *(void**)ptrptr = tmp;
    return 0;
}

/**
 * Vir_Alloc_Var:
 * @ptrptr: pointer to hold address of allocated memory
 * @struct_size: size of initial struct
 * @element_size: size of array elements
 * @count: number of array elements to allocate
 *
 * Allocate struct_size bytes plus an array of 'count' elements, each
 * of size element_size.  This sort of allocation is useful for
 * receiving the data of certain ioctls and other APIs which return a
 * struct in which the last element is an array of undefined length.
 * The caller of this type of API is expected to know the length of
 * the array that will be returned and allocate a suitable buffer to
 * contain the returned data.  C99 refers to these variable length
 * objects as structs containing flexible array members.
 *
 * Returns -1 on failure, 0 on success
 */
int virAllocVar(void *ptrptr, size_t struct_size, size_t element_size, size_t count)
{
    size_t alloc_size = 0;

#if TEST_OOM
    if (virAllocTestFail())
        return -1;
#endif

    if (VIR_ALLOC_VAR_OVERSIZED(struct_size, count, element_size)) {
        errno = ENOMEM;
        return -1;
    }

    alloc_size = struct_size + (element_size * count);
    *(void **)ptrptr = calloc(1, alloc_size);
    if (*(void **)ptrptr == NULL)
        return -1;
    return 0;
}


/**
 * virFree:
 * @ptrptr: pointer to pointer for address of memory to be freed
 *
 * Release the chunk of memory in the pointer pointed to by
 * the 'ptrptr' variable. After release, 'ptrptr' will be
 * updated to point to NULL.
 */
void virFree(void *ptrptr)
{
    free(*(void**)ptrptr);
    *(void**)ptrptr = NULL;
}
