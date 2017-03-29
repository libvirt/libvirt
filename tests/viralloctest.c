/*
 * viralloctest.c: Test memory allocation APIs
 *
 * Copyright (C) 2014 Red Hat, Inc.
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

#include <viralloc.h>

#include "testutils.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct testDummyStruct {
    int a;
    int b;
} testDummyStruct;

static int
testCheckNonNull(void *t)
{
    if (t == NULL) {
        fprintf(stderr, "Allocation succeeded but pointer is NULL\n");
        return -1;
    }

    return 0;
}

static int
testAllocScalar(const void *opaque ATTRIBUTE_UNUSED)
{
    testDummyStruct *t;
    int ret = -1;

    if (VIR_ALLOC(t) < 0)
        return -1;

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    if (t->a != 0 ||
        t->b != 0) {
        fprintf(stderr, "Allocated ram was not zerod\n");
        goto cleanup;
    }

    VIR_FREE(t);

    if (t != NULL) {
        fprintf(stderr, "Pointer is still set after free\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(t);
    return ret;
}


static int
testAllocArray(const void *opaque ATTRIBUTE_UNUSED)
{
    testDummyStruct *t;
    size_t nt = 10, i;
    int ret = -1;

    if (VIR_ALLOC_N(t, nt) < 0)
        return -1;

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    for (i = 0; i < nt; i++) {
        if (t[i].a != 0 ||
            t[i].b != 0) {
            fprintf(stderr, "Allocated ram block %zu was not zerod\n", i);
            goto cleanup;
        }
    }

    VIR_FREE(t);

    if (t != NULL) {
        fprintf(stderr, "Pointer is still set after free\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(t);
    return ret;
}


static int
testReallocArray(const void *opaque ATTRIBUTE_UNUSED)
{
    testDummyStruct *t;
    size_t nt = 10, i;
    int ret = -1;

    if (VIR_ALLOC_N(t, nt) < 0)
        return -1;

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    for (i = 0; i < nt; i++) {
        t[i].a = 10;
        t[i].b = 20;
    }

    if (VIR_REALLOC_N(t, nt + 5) < 0)
        goto cleanup;

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    for (i = 0; i < nt; i++) {
        if (t[i].a != 10 ||
            t[i].b != 20) {
            fprintf(stderr, "Reallocated ram block %zu lost data\n", i);
            goto cleanup;
        }
    }

    if (VIR_REALLOC_N(t, nt) < 0)
        goto cleanup;

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    for (i = 0; i < nt; i++) {
        if (t[i].a != 10 ||
            t[i].b != 20) {
            fprintf(stderr, "Reallocated ram block %zu lost data\n", i);
            goto cleanup;
        }
    }

    if (VIR_REALLOC_N(t, nt - 5) < 0)
        goto cleanup;

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    for (i = 0; i < (nt - 5); i++) {
        if (t[i].a != 10 ||
            t[i].b != 20) {
            fprintf(stderr, "Reallocated ram block %zu lost data\n", i);
            goto cleanup;
        }
    }

    VIR_FREE(t);

    if (t != NULL) {
        fprintf(stderr, "Pointer is still set after free\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(t);
    return ret;
}


static int
testExpandArray(const void *opaque ATTRIBUTE_UNUSED)
{
    testDummyStruct *t;
    size_t nt = 10, i;
    int ret = -1;

    if (VIR_ALLOC_N(t, nt) < 0)
        return -1;

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    for (i = 0; i < nt; i++) {
        t[i].a = 10;
        t[i].b = 20;
    }

    if (VIR_EXPAND_N(t, nt, 5) < 0)
        goto cleanup;

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    for (i = 0; i < (nt - 5); i++) {
        if (t[i].a != 10 ||
            t[i].b != 20) {
            fprintf(stderr, "Reallocated ram block %zu lost data\n", i);
            goto cleanup;
        }
    }

    for (i = (nt - 5); i < nt; i++) {
        if (t[i].a != 0 ||
            t[i].b != 0) {
            fprintf(stderr, "New ram block %zu was not zerod\n", i);
            goto cleanup;
        }
    }

    VIR_SHRINK_N(t, nt, 5);

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    for (i = 0; i < nt; i++) {
        if (t[i].a != 10 ||
            t[i].b != 20) {
            fprintf(stderr, "Reallocated ram block %zu lost data\n", i);
            goto cleanup;
        }
    }

    VIR_SHRINK_N(t, nt, 5);

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    for (i = 0; i < nt; i++) {
        if (t[i].a != 10 ||
            t[i].b != 20) {
            fprintf(stderr, "Reallocated ram block %zu lost data\n", i);
            goto cleanup;
        }
    }

    VIR_FREE(t);

    if (t != NULL) {
        fprintf(stderr, "Pointer is still set after free\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(t);
    return ret;
}


static int
testResizeArray(const void *opaque ATTRIBUTE_UNUSED)
{
    testDummyStruct *t;
    size_t nt = 10, at, i;
    int ret = -1;

    if (VIR_ALLOC_N(t, nt) < 0)
        return -1;

    at = nt;

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    for (i = 0; i < nt; i++) {
        t[i].a = 10;
        t[i].b = 20;
    }

    if (VIR_RESIZE_N(t, at, nt, 8) < 0)
        goto cleanup;

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    if (at != 18) {
        fprintf(stderr, "Expected allocation of 16 not %zu\n", at);
        goto cleanup;
    }

    for (i = 0; i < at; i++) {
        if (i >= nt) {
            if (t[i].a != 0 ||
                t[i].b != 0) {
                fprintf(stderr, "New ram block %zu was not zerod\n", i);
                goto cleanup;
            }
        } else {
            if (t[i].a != 10 ||
                t[i].b != 20) {
                fprintf(stderr, "Reallocated ram block %zu lost data\n", i);
                goto cleanup;
            }
        }
    }

    VIR_FREE(t);

    if (t != NULL) {
        fprintf(stderr, "Pointer is still set after free\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(t);
    return ret;
}


static int
testInsertArray(const void *opaque ATTRIBUTE_UNUSED)
{
    testDummyStruct **t;
    size_t nt = 10, i;
    int ret = -1;
    testDummyStruct *n = (void *)0xff;

    if (VIR_ALLOC_N(t, nt) < 0)
        return -1;

    if (testCheckNonNull(t) < 0)
        goto cleanup;

    for (i = 0; i < nt; i++)
        t[i] = (void*)0x50;

    if (VIR_INSERT_ELEMENT(t, 3, nt, n) < 0) {
        if (nt != 10) {
            fprintf(stderr, "Expecting array size 10 after OOM not %zu\n", nt);
            goto cleanup;
        }
        goto cleanup;
    }

    if (nt != 11) {
        fprintf(stderr, "Expecting array size 11 not %zu\n", nt);
        goto cleanup;
    }

    if (n != NULL) {
        fprintf(stderr, "Expecting element to be set to NULL\n");
        goto cleanup;
    }

    for (i = 0; i < nt; i++) {
        void *expect = i == 3 ? (void *)0xff : (void*)0x50;
        if (t[i] != expect) {
            fprintf(stderr, "Expecting %p at offset %zu not %p\n",
                    expect, i, t[i]);
            goto cleanup;
        }
    }

    VIR_FREE(t);

    if (t != NULL) {
        fprintf(stderr, "Pointer is still set after free\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(t);
    return ret;
}


static int
testDispose(const void *opaque ATTRIBUTE_UNUSED)
{
    int *num = NULL;
    int *nums = NULL;
    size_t nnums = 0;
    char *str = NULL;

    VIR_DISPOSE(num);
    VIR_DISPOSE_N(nums, nnums);
    VIR_DISPOSE_STRING(str);

    nnums = 10;
    VIR_DISPOSE_N(nums, nnums);

    if (VIR_ALLOC(num) < 0)
        return -1;

    VIR_DISPOSE(num);

    nnums = 10;
    if (VIR_ALLOC_N(nums, nnums) < 0)
        return -1;

    VIR_DISPOSE_N(nums, nnums);

    if (VIR_STRDUP(str, "test") < 0)
        return -1;

    VIR_DISPOSE_STRING(str);

    return 0;
}


static int
mymain(void)
{
    int ret = 0;

    if (virTestRun("alloc scalar", testAllocScalar, NULL) < 0)
        ret = -1;
    if (virTestRun("alloc array", testAllocArray, NULL) < 0)
        ret = -1;
    if (virTestRun("realloc array", testReallocArray, NULL) < 0)
        ret = -1;
    if (virTestRun("expand array", testExpandArray, NULL) < 0)
        ret = -1;
    if (virTestRun("resize array", testResizeArray, NULL) < 0)
        ret = -1;
    if (virTestRun("insert array", testInsertArray, NULL) < 0)
        ret = -1;
    if (virTestRun("dispose tests", testDispose, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
