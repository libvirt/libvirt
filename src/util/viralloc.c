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
#include <stdlib.h>

#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.alloc");

#if TEST_OOM
static int testMallocNext;
static int testMallocFailFirst;
static int testMallocFailLast;
static void (*testMallocHook)(int, void*);
static void *testMallocHookData;

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

#else

void virAllocTestOOM(int n ATTRIBUTE_UNUSED,
                     int m ATTRIBUTE_UNUSED)
{
    /* nada */
}

int virAllocTestCount(void)
{
    return 0;
}

void virAllocTestInit(void)
{
    /* nada */
}

void virAllocTestHook(void (*func)(int, void*) ATTRIBUTE_UNUSED,
                      void *data ATTRIBUTE_UNUSED)
{
    /* nada */
}
#endif


/**
 * virAlloc:
 * @ptrptr: pointer to pointer for address of allocated memory
 * @size: number of bytes to allocate
 * @report: whether to report OOM error, if there is one
 * @domcode: error domain code
 * @filename: caller's filename
 * @funcname: caller's funcname
 * @linenr: caller's line number
 *
 * Allocate  'size' bytes of memory. Return the address of the
 * allocated memory in 'ptrptr'. The newly allocated memory is
 * filled with zeros. If @report is true, OOM errors are
 * reported automatically.
 *
 * Returns -1 on failure to allocate, zero on success
 */
int virAlloc(void *ptrptr,
             size_t size,
             bool report,
             int domcode,
             const char *filename,
             const char *funcname,
             size_t linenr)
{
#if TEST_OOM
    if (virAllocTestFail()) {
        *(void **)ptrptr = NULL;
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        errno = ENOMEM;
        return -1;
    }
#endif

    *(void **)ptrptr = calloc(1, size);
    if (*(void **)ptrptr == NULL) {
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        return -1;
    }
    return 0;
}

/**
 * virAllocN:
 * @ptrptr: pointer to pointer for address of allocated memory
 * @size: number of bytes to allocate
 * @count: number of elements to allocate
 * @report: whether to report OOM error, if there is one
 * @domcode: error domain code
 * @filename: caller's filename
 * @funcname: caller's funcname
 * @linenr: caller's line number
 *
 * Allocate an array of memory 'count' elements long,
 * each with 'size' bytes. Return the address of the
 * allocated memory in 'ptrptr'.  The newly allocated
 * memory is filled with zeros. If @report is true,
 * OOM errors are reported automatically.
 *
 * Returns -1 on failure to allocate, zero on success
 */
int virAllocN(void *ptrptr,
              size_t size,
              size_t count,
              bool report,
              int domcode,
              const char *filename,
              const char *funcname,
              size_t linenr)
{
#if TEST_OOM
    if (virAllocTestFail()) {
        *(void **)ptrptr = NULL;
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        errno = ENOMEM;
        return -1;
    }
#endif

    *(void**)ptrptr = calloc(count, size);
    if (*(void**)ptrptr == NULL) {
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        return -1;
    }
    return 0;
}

/**
 * virReallocN:
 * @ptrptr: pointer to pointer for address of allocated memory
 * @size: number of bytes to allocate
 * @count: number of elements in array
 * @report: whether to report OOM error, if there is one
 * @domcode: error domain code
 * @filename: caller's filename
 * @funcname: caller's funcname
 * @linenr: caller's line number
 *
 * Resize the block of memory in 'ptrptr' to be an array of
 * 'count' elements, each 'size' bytes in length. Update 'ptrptr'
 * with the address of the newly allocated memory. On failure,
 * 'ptrptr' is not changed and still points to the original memory
 * block. Any newly allocated memory in 'ptrptr' is uninitialized.
 * If @report is true, OOM errors are reported automatically.
 *
 * Returns -1 on failure to allocate, zero on success
 */
int virReallocN(void *ptrptr,
                size_t size,
                size_t count,
                bool report,
                int domcode,
                const char *filename,
                const char *funcname,
                size_t linenr)
{
    void *tmp;
#if TEST_OOM
    if (virAllocTestFail()) {
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        errno = ENOMEM;
        return -1;
    }
#endif

    if (xalloc_oversized(count, size)) {
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        errno = ENOMEM;
        return -1;
    }
    tmp = realloc(*(void**)ptrptr, size * count);
    if (!tmp && ((size * count) != 0)) {
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        return -1;
    }
    *(void**)ptrptr = tmp;
    return 0;
}

/**
 * virExpandN:
 * @ptrptr: pointer to pointer for address of allocated memory
 * @size: number of bytes per element
 * @countptr: pointer to number of elements in array
 * @add: number of elements to add
 * @report: whether to report OOM error, if there is one
 * @domcode: error domain code
 * @filename: caller's filename
 * @funcname: caller's funcname
 * @linenr: caller's line number
 *
 * Resize the block of memory in 'ptrptr' to be an array of
 * '*countptr' + 'add' elements, each 'size' bytes in length.
 * Update 'ptrptr' and 'countptr'  with the details of the newly
 * allocated memory. On failure, 'ptrptr' and 'countptr' are not
 * changed. Any newly allocated memory in 'ptrptr' is zero-filled.
 * If @report is true, OOM errors are reported automatically.
 *
 * Returns -1 on failure to allocate, zero on success
 */
int virExpandN(void *ptrptr,
               size_t size,
               size_t *countptr,
               size_t add,
               bool report,
               int domcode,
               const char *filename,
               const char *funcname,
               size_t linenr)
{
    int ret;

    if (*countptr + add < *countptr) {
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        errno = ENOMEM;
        return -1;
    }
    ret = virReallocN(ptrptr, size, *countptr + add, report,
                      domcode, filename, funcname, linenr);
    if (ret == 0) {
        memset(*(char **)ptrptr + (size * *countptr), 0, size * add);
        *countptr += add;
    }
    return ret;
}

/**
 * virResizeN:
 * @ptrptr: pointer to pointer for address of allocated memory
 * @size: number of bytes per element
 * @allocptr: pointer to number of elements allocated in array
 * @count: number of elements currently used in array
 * @add: minimum number of additional elements to support in array
 * @report: whether to report OOM error, if there is one
 * @domcode: error domain code
 * @filename: caller's filename
 * @funcname: caller's funcname
 * @linenr: caller's line number
 *
 * If 'count' + 'add' is larger than '*allocptr', then resize the
 * block of memory in 'ptrptr' to be an array of at least 'count' +
 * 'add' elements, each 'size' bytes in length. Update 'ptrptr' and
 * 'allocptr' with the details of the newly allocated memory. On
 * failure, 'ptrptr' and 'allocptr' are not changed. Any newly
 * allocated memory in 'ptrptr' is zero-filled. If @report is true,
 * OOM errors are reported automatically.
 *
 *
 * Returns -1 on failure to allocate, zero on success
 */
int virResizeN(void *ptrptr,
               size_t size,
               size_t *allocptr,
               size_t count,
               size_t add,
               bool report,
               int domcode,
               const char *filename,
               const char *funcname,
               size_t linenr)
{
    size_t delta;

    if (count + add < count) {
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        errno = ENOMEM;
        return -1;
    }
    if (count + add <= *allocptr)
        return 0;

    delta = count + add - *allocptr;
    if (delta < *allocptr / 2)
        delta = *allocptr / 2;
    return virExpandN(ptrptr, size, allocptr, delta, report,
                      domcode, filename, funcname, linenr);
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
        ignore_value(virReallocN(ptrptr, size, *countptr -= toremove,
                                 false, 0, NULL, NULL, 0));
    } else {
        virFree(ptrptr);
        *countptr = 0;
    }
}

/**
 * virInsertElementsN:
 * @ptrptr:   pointer to hold address of allocated memory
 * @size:     the size of one element in bytes
 * @at:       index within array where new elements should be added, -1 for end
 * @countptr: variable tracking number of elements currently allocated
 * @add:      number of elements to add
 * @newelems: pointer to array of one or more new elements to move into
 *            place (the originals will be zeroed out if successful
 *            and if clearOriginal is true)
 * @clearOriginal: false if the new item in the array should be copied
 *            from the original, and the original left intact.
 *            true if the original should be 0'd out on success.
 * @inPlace:  false if we should expand the allocated memory before
 *            moving, true if we should assume someone else *has
 *            already* done that.
 * @report:   whether to report OOM error, if there is one
 * @domcode:  error domain code
 * @filename: caller's filename
 * @funcname: caller's funcname
 * @linenr:   caller's line number
 *
 * Re-allocate an array of *countptr elements, each sizeof(*ptrptr) bytes
 * long, to be *countptr+add elements long, then appropriately move
 * the elements starting at ptrptr[at] up by add elements, copy the
 * items from newelems into ptrptr[at], then store the address of
 * allocated memory in *ptrptr and the new size in *countptr.  If
 * newelems is NULL, the new elements at ptrptr[at] are instead filled
 * with zero.  at must be between [0,*countptr], except that -1 is
 * treated the same as *countptr for convenience. If @report is true,
 * OOM errors are reported automatically.
 *
 * Returns -1 on failure, 0 on success
 */
int
virInsertElementsN(void *ptrptr, size_t size, size_t at,
                   size_t *countptr,
                   size_t add, void *newelems,
                   bool clearOriginal, bool inPlace,
                   bool report,
                   int domcode,
                   const char *filename,
                   const char *funcname,
                   size_t linenr)
{
    if (at == -1) {
        at = *countptr;
    } else if (at > *countptr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("out of bounds index - count %zu at %zu add %zu"),
                       *countptr, at, add);
        return -1;
    }

    if (inPlace) {
        *countptr += add;
    } else if (virExpandN(ptrptr, size, countptr, add, report,
                          domcode, filename, funcname, linenr) < 0) {
        return -1;
    }

    /* memory was successfully re-allocated. Move up all elements from
     * ptrptr[at] to the end (if we're not "inserting" at the end
     * already), memcpy in the new elements, and clear the elements
     * from their original location. Remember that *countptr has
     * already been updated with new element count!
     */
    if (at < *countptr - add) {
        memmove(*(char**)ptrptr + (size * (at + add)),
                *(char**)ptrptr + (size * at),
                size * (*countptr - add - at));
    }

    if (newelems) {
        memcpy(*(char**)ptrptr + (size * at), newelems, size * add);
        if (clearOriginal)
           memset((char*)newelems, 0, size * add);
    } else if (inPlace || (at < *countptr - add)) {
        /* NB: if inPlace, assume memory at the end wasn't initialized */
        memset(*(char**)ptrptr + (size * at), 0, size * add);
    }

    return 0;
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

/**
 * virAllocVar:
 * @ptrptr: pointer to hold address of allocated memory
 * @struct_size: size of initial struct
 * @element_size: size of array elements
 * @count: number of array elements to allocate
 * @report: whether to report OOM error, if there is one
 * @domcode: error domain code
 * @filename: caller's filename
 * @funcname: caller's funcname
 * @linenr: caller's line number
 *
 * Allocate struct_size bytes plus an array of 'count' elements, each
 * of size element_size.  This sort of allocation is useful for
 * receiving the data of certain ioctls and other APIs which return a
 * struct in which the last element is an array of undefined length.
 * The caller of this type of API is expected to know the length of
 * the array that will be returned and allocate a suitable buffer to
 * contain the returned data.  C99 refers to these variable length
 * objects as structs containing flexible array members. If @report
 * is true, OOM errors are reported automatically.
 *
 * Returns -1 on failure, 0 on success
 */
int virAllocVar(void *ptrptr,
                size_t struct_size,
                size_t element_size,
                size_t count,
                bool report,
                int domcode,
                const char *filename,
                const char *funcname,
                size_t linenr)
{
    size_t alloc_size = 0;

#if TEST_OOM
    if (virAllocTestFail()) {
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        errno = ENOMEM;
        return -1;
    }
#endif

    if (VIR_ALLOC_VAR_OVERSIZED(struct_size, count, element_size)) {
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        errno = ENOMEM;
        return -1;
    }

    alloc_size = struct_size + (element_size * count);
    *(void **)ptrptr = calloc(1, alloc_size);
    if (*(void **)ptrptr == NULL) {
        if (report)
            virReportOOMErrorFull(domcode, filename, funcname, linenr);
        return -1;
    }
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
    int save_errno = errno;

    free(*(void**)ptrptr);
    *(void**)ptrptr = NULL;
    errno = save_errno;
}


/**
 * virDispose:
 * @ptrptr: pointer to pointer for address of memory to be sanitized and freed
 * @count: count of elements in the array to dispose
 * @elemet_size: size of one element
 * @countptr: pointer to the count variable to clear (may be NULL)
 *
 * Clear and release the chunk of memory in the pointer pointed to by 'prtptr'.
 *
 * If @countptr is provided, it's value is used instead of @count and it's set
 * to 0 after clearing and freeing the memory.
 *
 * After release, 'ptrptr' will be updated to point to NULL.
 */
void virDispose(void *ptrptr,
                size_t count,
                size_t element_size,
                size_t *countptr)
{
    int save_errno = errno;

    if (countptr)
        count = *countptr;

    if (*(void**)ptrptr && count > 0)
        memset(*(void **)ptrptr, 0, count * element_size);

    free(*(void**)ptrptr);
    *(void**)ptrptr = NULL;

    if (countptr)
        *countptr = 0;
    errno = save_errno;
}
