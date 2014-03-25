/*
 * Copyright (C) 2012-2014 Red Hat, Inc.
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

VIR_LOG_INIT("tests.stringtest");

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
testStringSortCompare(const void *opaque ATTRIBUTE_UNUSED)
{
    const char *randlist[] = {
        "tasty", "astro", "goat", "chicken", "turducken",
    };
    const char *randrlist[] = {
        "tasty", "astro", "goat", "chicken", "turducken",
    };
    const char *sortlist[] = {
        "astro", "chicken", "goat", "tasty", "turducken",
    };
    const char *sortrlist[] = {
        "turducken", "tasty", "goat", "chicken", "astro",
    };
    int ret = -1;
    size_t i;

    qsort(randlist, ARRAY_CARDINALITY(randlist), sizeof(randlist[0]),
          virStringSortCompare);
    qsort(randrlist, ARRAY_CARDINALITY(randrlist), sizeof(randrlist[0]),
          virStringSortRevCompare);

    for (i = 0; i < ARRAY_CARDINALITY(randlist); i++) {
        if (STRNEQ(randlist[i], sortlist[i])) {
            fprintf(stderr, "sortlist[%zu] '%s' != randlist[%zu] '%s'\n",
                    i, sortlist[i], i, randlist[i]);
            goto cleanup;
        }
        if (STRNEQ(randrlist[i], sortrlist[i])) {
            fprintf(stderr, "sortrlist[%zu] '%s' != randrlist[%zu] '%s'\n",
                    i, sortrlist[i], i, randrlist[i]);
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    return ret;
}


struct stringSearchData {
    const char *str;
    const char *regexp;
    size_t maxMatches;
    size_t expectNMatches;
    const char **expectMatches;
    bool expectError;
};

static int
testStringSearch(const void *opaque ATTRIBUTE_UNUSED)
{
    const struct stringSearchData *data = opaque;
    char **matches = NULL;
    ssize_t nmatches;
    int ret = -1;

    nmatches = virStringSearch(data->str, data->regexp,
                               data->maxMatches, &matches);

    if (data->expectError) {
        if (nmatches != -1) {
            fprintf(stderr, "expected error on %s but got %zd matches\n",
                    data->str, nmatches);
            goto cleanup;
        }
    } else {
        size_t i;

        if (nmatches < 0) {
            fprintf(stderr, "expected %zu matches on %s but got error\n",
                    data->expectNMatches, data->str);
            goto cleanup;
        }

        if (nmatches != data->expectNMatches) {
            fprintf(stderr, "expected %zu matches on %s but got %zd\n",
                    data->expectNMatches, data->str, nmatches);
            goto cleanup;
        }

        if (virStringListLength(matches) != nmatches) {
            fprintf(stderr, "expected %zu matches on %s but got %zd matches\n",
                    data->expectNMatches, data->str,
                    virStringListLength(matches));
            goto cleanup;
        }

        for (i = 0; i < nmatches; i++) {
            if (STRNEQ(matches[i], data->expectMatches[i])) {
                fprintf(stderr, "match %zu expected '%s' but got '%s'\n",
                        i, data->expectMatches[i], matches[i]);
                goto cleanup;
            }
        }
    }

    ret = 0;

 cleanup:
    virStringFreeList(matches);
    return ret;
}


struct stringReplaceData {
    const char *haystack;
    const char *oldneedle;
    const char *newneedle;
    const char *result;
};

static int
testStringReplace(const void *opaque ATTRIBUTE_UNUSED)
{
    const struct stringReplaceData *data = opaque;
    char *result;
    int ret = -1;

    result = virStringReplace(data->haystack,
                              data->oldneedle,
                              data->newneedle);

    if (STRNEQ_NULLABLE(data->result, result)) {
        fprintf(stderr, "Expected '%s' but got '%s'\n",
                data->result, NULLSTR(result));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(result);
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
        if (virtTestRun("Split " #str, testSplit, &splitData) < 0)      \
            ret = -1;                                                   \
        if (virtTestRun("Join " #str, testJoin, &joinData) < 0)         \
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

    if (virtTestRun("strdup", testStrdup, NULL) < 0)
        ret = -1;

    if (virtTestRun("strdup", testStrndupNegative, NULL) < 0)
        ret = -1;

    if (virtTestRun("virStringSortCompare", testStringSortCompare, NULL) < 0)
        ret = -1;

#define TEST_SEARCH(s, r, x, n, m, e)                                   \
    do {                                                                \
        struct stringSearchData data = {                                \
            .str = s,                                                   \
            .maxMatches = x,                                            \
            .regexp = r,                                                \
            .expectNMatches = n,                                        \
            .expectMatches = m,                                         \
            .expectError = e,                                           \
        };                                                              \
        if (virtTestRun("virStringSearch " s, testStringSearch, &data) < 0) \
            ret = -1;                                                   \
    } while (0)

    /* error due to missing () in regexp */
    TEST_SEARCH("foo", "bar", 10, 0, NULL, true);

    /* error due to too many () in regexp */
    TEST_SEARCH("foo", "(b)(a)(r)", 10, 0, NULL, true);

    /* None matching */
    TEST_SEARCH("foo", "(bar)", 10, 0, NULL, false);

    /* Full match */
    const char *matches1[] = { "foo" };
    TEST_SEARCH("foo", "(foo)", 10, 1, matches1, false);

    /* Multi matches */
    const char *matches2[] = { "foo", "bar", "eek" };
    TEST_SEARCH("1foo2bar3eek", "([a-z]+)", 10, 3, matches2, false);

    /* Multi matches, limited returns */
    const char *matches3[] = { "foo", "bar" };
    TEST_SEARCH("1foo2bar3eek", "([a-z]+)", 2, 2, matches3, false);

#define TEST_REPLACE(h, o, n, r)                                        \
    do {                                                                \
        struct stringReplaceData data = {                               \
            .haystack = h,                                              \
            .oldneedle = o,                                             \
            .newneedle = n,                                             \
            .result = r                                                 \
        };                                                              \
        if (virtTestRun("virStringReplace " h, testStringReplace, &data) < 0) \
            ret = -1;                                                   \
    } while (0)

    /* no matches */
    TEST_REPLACE("foo", "bar", "eek", "foo");

    /* complete match */
    TEST_REPLACE("foo", "foo", "bar", "bar");

    /* middle match */
    TEST_REPLACE("foobarwizz", "bar", "eek", "fooeekwizz");

    /* many matches */
    TEST_REPLACE("foofoofoofoo", "foo", "bar", "barbarbarbar");

    /* many matches */
    TEST_REPLACE("fooooofoooo", "foo", "bar", "barooobaroo");

    /* different length old/new needles */
    TEST_REPLACE("fooooofoooo", "foo", "barwizzeek", "barwizzeekooobarwizzeekoo");
    TEST_REPLACE("fooooofoooo", "foooo", "foo", "fooofoo");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
