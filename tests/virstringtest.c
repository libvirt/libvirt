/*
 * Copyright (C) 2012-2013 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>

#include "testutils.h"
#include "virerror.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

struct testSplitData {
    const char *string;
    const char *delim;
    size_t max_tokens;
    const char **tokens;
};


struct testJoinData {
    const char *string;
    const char *delim;
    const char **tokens;
};

static int testSplit(const void *args)
{
    const struct testSplitData *data = args;
    char **got;
    char **tmp1;
    const char **tmp2;
    int ret = -1;

    if (!(got = virStringSplit(data->string, data->delim, data->max_tokens))) {
        VIR_DEBUG("Got no tokens at all");
        return -1;
    }

    tmp1 = got;
    tmp2 = data->tokens;
    while (*tmp1 && *tmp2) {
        if (STRNEQ(*tmp1, *tmp2)) {
            virFilePrintf(stderr, "Mismatch '%s' vs '%s'\n", *tmp1, *tmp2);
            goto cleanup;
        }
        tmp1++;
        tmp2++;
    }
    if (*tmp1) {
        virFilePrintf(stderr, "Too many pieces returned\n");
        goto cleanup;
    }
    if (*tmp2) {
        virFilePrintf(stderr, "Too few pieces returned\n");
        goto cleanup;
    }

    ret = 0;
cleanup:
    virStringFreeList(got);

    return ret;
}


static int testJoin(const void *args)
{
    const struct testJoinData *data = args;
    char *got;
    int ret = -1;

    if (!(got = virStringJoin(data->tokens, data->delim))) {
        VIR_DEBUG("Got no result");
        return -1;
    }
    if (STRNEQ(got, data->string)) {
        virFilePrintf(stderr, "Mismatch '%s' vs '%s'\n", got, data->string);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(got);

    return ret;
}

static bool fail;

static const char *
testStrdupLookup1(size_t i)
{
    switch (i) {
    case 0:
        return "hello";
    case 1:
        return NULL;
    default:
        fail = true;
        return "oops";
    }
}

static size_t
testStrdupLookup2(size_t i)
{
    if (i)
        fail = true;
    return 5;
}

static int
testStrdup(const void *data ATTRIBUTE_UNUSED)
{
    char *array[] = { NULL, NULL };
    size_t i = 0;
    size_t j = 0;
    size_t k = 0;
    int ret = -1;
    int value;

    value = VIR_STRDUP(array[i++], testStrdupLookup1(j++));
    if (value != 1) {
        virFilePrintf(stderr, "unexpected strdup result %d, expected 1\n", value);
        goto cleanup;
    }
    if (i != 1) {
        virFilePrintf(stderr, "unexpected side effects i=%zu, expected 1\n", i);
        goto cleanup;
    }
    if (j != 1) {
        virFilePrintf(stderr, "unexpected side effects j=%zu, expected 1\n", j);
        goto cleanup;
    }
    if (STRNEQ_NULLABLE(array[0], "hello") || array[1]) {
        virFilePrintf(stderr, "incorrect array contents '%s' '%s'\n",
                      NULLSTR(array[0]), NULLSTR(array[1]));
        goto cleanup;
    }

    value = VIR_STRNDUP(array[i++], testStrdupLookup1(j++),
                        testStrdupLookup2(k++));
    if (value != 0) {
        virFilePrintf(stderr, "unexpected strdup result %d, expected 0\n", value);
        goto cleanup;
    }
    if (i != 2) {
        virFilePrintf(stderr, "unexpected side effects i=%zu, expected 2\n", i);
        goto cleanup;
    }
    if (j != 2) {
        virFilePrintf(stderr, "unexpected side effects j=%zu, expected 2\n", j);
        goto cleanup;
    }
    if (k != 1) {
        virFilePrintf(stderr, "unexpected side effects k=%zu, expected 1\n", k);
        goto cleanup;
    }
    if (STRNEQ_NULLABLE(array[0], "hello") || array[1]) {
        virFilePrintf(stderr, "incorrect array contents '%s' '%s'\n",
                      NULLSTR(array[0]), NULLSTR(array[1]));
        goto cleanup;
    }

    if (fail) {
        virFilePrintf(stderr, "side effects failed\n");
        goto cleanup;
    }

    ret = 0;
cleanup:
    for (i = 0; i < ARRAY_CARDINALITY(array); i++)
        VIR_FREE(array[i]);
    return ret;
}

static int
testStrndupNegative(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    char *dst;
    const char *src = "Hello world";
    int value;

    if ((value = VIR_STRNDUP(dst, src, 5)) != 1) {
        fprintf(stderr, "unexpected virStrndup result %d, expected 1\n", value);
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(dst, "Hello")) {
        fprintf(stderr, "unexpected content '%s'", dst);
        goto cleanup;
    }

    VIR_FREE(dst);
    if ((value = VIR_STRNDUP(dst, src, -1)) != 1) {
        fprintf(stderr, "unexpected virStrndup result %d, expected 1\n", value);
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(dst, src)) {
        fprintf(stderr, "unexpected content '%s'", dst);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(dst);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

#define TEST_SPLIT(str, del, max, toks)                                 \
    do {                                                                \
        struct testSplitData splitData = {                              \
            .string = str,                                              \
            .delim = del,                                               \
            .max_tokens = max,                                          \
            .tokens = toks,                                             \
        };                                                              \
        struct testJoinData joinData = {                                \
            .string = str,                                              \
            .delim = del,                                               \
            .tokens = toks,                                             \
        };                                                              \
        if (virtTestRun("Split " #str, 1, testSplit, &splitData) < 0)   \
            ret = -1;                                                   \
        if (virtTestRun("Join " #str, 1, testJoin, &joinData) < 0)      \
            ret = -1;                                                   \
    } while (0)

    const char *tokens1[] = { NULL };
    TEST_SPLIT("", " ", 0, tokens1);

    const char *tokens2[] = { "", "", NULL };
    TEST_SPLIT(" ", " ", 0, tokens2);

    const char *tokens3[] = { "", "", "", NULL };
    TEST_SPLIT("  ", " ", 0, tokens3);

    const char *tokens4[] = { "The", "quick", "brown", "fox", NULL };
    TEST_SPLIT("The quick brown fox", " ", 0, tokens4);

    const char *tokens5[] = { "The quick ", " fox", NULL };
    TEST_SPLIT("The quick brown fox", "brown", 0, tokens5);

    const char *tokens6[] = { "", "The", "quick", "brown", "fox", NULL };
    TEST_SPLIT(" The quick brown fox", " ", 0, tokens6);

    const char *tokens7[] = { "The", "quick", "brown", "fox", "", NULL };
    TEST_SPLIT("The quick brown fox ", " ", 0, tokens7);

    if (virtTestRun("strdup", 1, testStrdup, NULL) < 0)
        ret = -1;

    if (virtTestRun("strdup", 1, testStrndupNegative, NULL) < 0)
        ret = -1;

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
