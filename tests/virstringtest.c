/*
 * Copyright (C) 2012-2016 Red Hat, Inc.
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
#include "verify.h"
#include "virerror.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.stringtest");

struct testStreqData {
    const char *a;
    const char *b;
};

static int testStreq(const void *args)
{
    const struct testStreqData *data = args;
    int ret = -1;
    bool equal = true;
    bool streq_rv, strneq_rv;
    size_t i;

    if ((size_t) data->a ^ (size_t) data->b)
        equal = false;
    if (data->a && data->b) {
        for (i = 0; data->a[i] != '\0'; i++) {
            if (data->b[i] == '\0' ||
                data->a[i] != data->b[i]) {
                equal = false;
                break;
            }
        }
    }

    streq_rv = STREQ_NULLABLE(data->a, data->b);
    strneq_rv = STRNEQ_NULLABLE(data->a, data->b);

    if (streq_rv != equal) {
        virFilePrintf(stderr,
                      "STREQ not working correctly. Expected %d got %d",
                      (int) equal, (int) streq_rv);
        goto cleanup;
    }

    if (strneq_rv == equal) {
        virFilePrintf(stderr,
                      "STRNEQ not working correctly. Expected %d got %d",
                      (int) equal, (int) strneq_rv);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

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
    size_t ntokens;
    size_t exptokens = 0;
    char **tmp1;
    const char **tmp2;
    int ret = -1;

    if (!(got = virStringSplitCount(data->string, data->delim,
                                    data->max_tokens, &ntokens))) {
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
        exptokens++;
    }
    if (*tmp1) {
        virFilePrintf(stderr, "Too many pieces returned\n");
        goto cleanup;
    }
    if (*tmp2) {
        virFilePrintf(stderr, "Too few pieces returned\n");
        goto cleanup;
    }

    if (ntokens != exptokens) {
        virFilePrintf(stderr,
                      "Returned token count (%zu) doesn't match "
                      "expected count (%zu)",
                      ntokens, exptokens);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virStringListFree(got);

    return ret;
}


static int testJoin(const void *args)
{
    const struct testJoinData *data = args;
    char *got;
    int ret = -1;

    if (!(got = virStringListJoin(data->tokens, data->delim))) {
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


static int testAdd(const void *args)
{
    const struct testJoinData *data = args;
    char **list = NULL;
    char *got = NULL;
    int ret = -1;
    size_t i;

    for (i = 0; data->tokens[i]; i++) {
        char **tmp = virStringListAdd((const char **)list, data->tokens[i]);
        if (!tmp)
            goto cleanup;
        virStringListFree(list);
        list = tmp;
        tmp = NULL;
    }

    if (!list &&
        VIR_ALLOC(list) < 0)
        goto cleanup;

    if (!(got = virStringListJoin((const char **)list, data->delim))) {
        VIR_DEBUG("Got no result");
        goto cleanup;
    }

    if (STRNEQ(got, data->string)) {
        virFilePrintf(stderr, "Mismatch '%s' vs '%s'\n", got, data->string);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virStringListFree(list);
    VIR_FREE(got);
    return ret;
}


static int testRemove(const void *args)
{
    const struct testSplitData *data = args;
    char **list = NULL;
    size_t ntokens;
    size_t i;
    int ret = -1;

    if (!(list = virStringSplitCount(data->string, data->delim,
                                     data->max_tokens, &ntokens))) {
        VIR_DEBUG("Got no tokens at all");
        return -1;
    }

    for (i = 0; data->tokens[i]; i++) {
        virStringListRemove(&list, data->tokens[i]);
        if (virStringListHasString((const char **) list, data->tokens[i])) {
            virFilePrintf(stderr, "Not removed %s", data->tokens[i]);
            goto cleanup;
        }
    }

    if (list && list[0]) {
        virFilePrintf(stderr, "Not removed all tokens: %s", list[0]);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virStringListFree(list);
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
    /* coverity[dead_error_begin] */
    if (i != 1) {
        virFilePrintf(stderr, "unexpected side effects i=%zu, expected 1\n", i);
        goto cleanup;
    }
    /* coverity[dead_error_begin] */
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
    /* coverity[dead_error_begin] */
    if (i != 2) {
        virFilePrintf(stderr, "unexpected side effects i=%zu, expected 2\n", i);
        goto cleanup;
    }
    /* coverity[dead_error_begin] */
    if (j != 2) {
        virFilePrintf(stderr, "unexpected side effects j=%zu, expected 2\n", j);
        goto cleanup;
    }
    /* coverity[dead_error_begin] */
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
testStringSearch(const void *opaque)
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

        if (virStringListLength((const char * const *)matches) != nmatches) {
            fprintf(stderr, "expected %zu matches on %s but got %zd matches\n",
                    data->expectNMatches, data->str,
                    virStringListLength((const char * const *)matches));
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
    virStringListFree(matches);
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


struct stringToLongData {
    const char *str;
    const char *suffix;
    int si; /* syntax-check doesn't like bare 'i' */
    int si_ret;
    unsigned int ui;
    int ui_ret;
    /* No expected results for long: on 32-bit platforms, it is the
     * same as int, on 64-bit platforms it is the same as long long */
    long long ll;
    int ll_ret;
    unsigned long long ull;
    int ull_ret;
};

/* This test makes assumptions about our compilation platform that are
 * not guaranteed by POSIX.  Good luck to you if you are crazy enough
 * to try and port libvirt to a platform with 16-bit int.  Gnulib
 * already assumes that signed integers are two's complement. */
verify(sizeof(int) == 4);
verify(sizeof(long) == sizeof(int) || sizeof(long) == sizeof(long long));
verify(sizeof(long long) == 8);

static int
testStringToLong(const void *opaque)
{
    const struct stringToLongData *data = opaque;
    int ret = 0;
    char *end;
    long l;
    unsigned long ul;
    bool negative;

    if (data->suffix)
        negative = !!memchr(data->str, '-',
                            strlen(data->str) - strlen(data->suffix));
    else
        negative = !!strchr(data->str, '-');

#define TEST_ONE(Str, Suff, Type, Fn, Fmt, Exp, Exp_ret)                \
    do {                                                                \
        Type value = 5;                                                 \
        int result;                                                     \
        end = (char *) "oops";                                          \
        result = virStrToLong_ ## Fn(Str, Suff ? &end : NULL,           \
                                     0, &value);                        \
        /* On failure, end is modified, value is unchanged */           \
        if (result != (Exp_ret)) {                                      \
            fprintf(stderr,                                             \
                    "type " #Fn " returned %d expected %d\n",           \
                    result, Exp_ret);                                   \
            ret = -1;                                                   \
        }                                                               \
        if (value != ((Exp_ret) ? 5 : Exp)) {                           \
            fprintf(stderr,                                             \
                    "type " #Fn " value " Fmt " expected " Fmt "\n",    \
                    value, ((Exp_ret) ? 5 : Exp));                      \
            ret = -1;                                                   \
        }                                                               \
        if (Suff && STRNEQ_NULLABLE(Suff, end)) {                       \
            fprintf(stderr,                                             \
                    "type " #Fn " end '%s' expected '%s'\n",            \
                    NULLSTR(end), Suff);                                \
            ret = -1;                                                   \
        }                                                               \
    } while (0)

    TEST_ONE(data->str, data->suffix, int, i, "%d",
             data->si, data->si_ret);
    TEST_ONE(data->str, data->suffix, unsigned int, ui, "%u",
             data->ui, data->ui_ret);
    if (negative)
        TEST_ONE(data->str, data->suffix, unsigned int, uip, "%u", 0U, -1);
    else
        TEST_ONE(data->str, data->suffix, unsigned int, uip, "%u",
                 data->ui, data->ui_ret);

    /* We hate adding new API with 'long', and prefer 'int' or 'long
     * long' instead, since platform-specific results are evil */
    l = (sizeof(int) == sizeof(long)) ? data->si : data->ll;
    TEST_ONE(data->str, data->suffix, long, l, "%ld",
             l, (sizeof(int) == sizeof(long)) ? data->si_ret : data->ll_ret);
    ul = (sizeof(int) == sizeof(long)) ? data->ui : data->ull;
    TEST_ONE(data->str, data->suffix, unsigned long, ul, "%lu",
             ul, (sizeof(int) == sizeof(long)) ? data->ui_ret : data->ull_ret);
    if (negative)
        TEST_ONE(data->str, data->suffix, unsigned long, ulp, "%lu", 0UL, -1);
    else
        TEST_ONE(data->str, data->suffix, unsigned long, ulp, "%lu", ul,
                 (sizeof(int) == sizeof(long)) ? data->ui_ret : data->ull_ret);

    TEST_ONE(data->str, data->suffix, long long, ll, "%lld",
             data->ll, data->ll_ret);
    TEST_ONE(data->str, data->suffix, unsigned long long, ull, "%llu",
             data->ull, data->ull_ret);
    if (negative)
        TEST_ONE(data->str, data->suffix, unsigned long long, ullp, "%llu",
                 0ULL, -1);
    else
        TEST_ONE(data->str, data->suffix, unsigned long long, ullp, "%llu",
                 data->ull, data->ull_ret);

#undef TEST_ONE

    return ret;
}


/* The point of this test is to check whether all members of the array are
 * freed. The test has to be checked using valgrind. */
static int
testVirStringListFreeCount(const void *opaque ATTRIBUTE_UNUSED)
{
    char **list;

    if (VIR_ALLOC_N(list, 4) < 0)
        return -1;

    ignore_value(VIR_STRDUP(list[0], "test1"));
    ignore_value(VIR_STRDUP(list[2], "test2"));
    ignore_value(VIR_STRDUP(list[3], "test3"));

    virStringListFreeCount(list, 4);

    return 0;
}


struct testStripData {
    const char *string;
    const char *result;
};

static int testStripIPv6Brackets(const void *args)
{
    const struct testStripData *data = args;
    int ret = -1;
    char *res = NULL;

    if (VIR_STRDUP(res, data->string) < 0)
        goto cleanup;

    virStringStripIPv6Brackets(res);

    if (STRNEQ_NULLABLE(res, data->result)) {
        fprintf(stderr, "Returned '%s', expected '%s'\n",
                NULLSTR(res), NULLSTR(data->result));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(res);
    return ret;
}

static int testStripControlChars(const void *args)
{
    const struct testStripData *data = args;
    int ret = -1;
    char *res = NULL;

    if (VIR_STRDUP(res, data->string) < 0)
        goto cleanup;

    virStringStripControlChars(res);

    if (STRNEQ_NULLABLE(res, data->result)) {
        fprintf(stderr, "Returned '%s', expected '%s'\n",
                NULLSTR(res), NULLSTR(data->result));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(res);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

#define TEST_STREQ(aa, bb)                                              \
    do {                                                                \
        struct testStreqData streqData = {.a = aa, .b = bb};            \
        if (virTestRun("Streq", testStreq, &streqData) < 0)             \
            ret = -1;                                                   \
    } while (0)

    TEST_STREQ("hello", "world");
    TEST_STREQ(NULL, NULL);
    TEST_STREQ(NULL, "");
    TEST_STREQ("", NULL);
    TEST_STREQ("", "");
    TEST_STREQ("hello", "hello");

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
        if (virTestRun("Split " #str, testSplit, &splitData) < 0)       \
            ret = -1;                                                   \
        if (virTestRun("Join " #str, testJoin, &joinData) < 0)          \
            ret = -1;                                                   \
        if (virTestRun("Add " #str, testAdd, &joinData) < 0)            \
            ret = -1;                                                   \
        if (virTestRun("Remove " #str, testRemove, &splitData) < 0)     \
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

    const char *tokens8[] = { "gluster", "rdma", NULL };
    TEST_SPLIT("gluster+rdma", "+", 2, tokens8);

    if (virTestRun("strdup", testStrdup, NULL) < 0)
        ret = -1;

    if (virTestRun("strdup", testStrndupNegative, NULL) < 0)
        ret = -1;

    if (virTestRun("virStringSortCompare", testStringSortCompare, NULL) < 0)
        ret = -1;

#define TEST_SEARCH(s, r, x, n, m, e)                                      \
    do {                                                                   \
        struct stringSearchData data = {                                   \
            .str = s,                                                      \
            .maxMatches = x,                                               \
            .regexp = r,                                                   \
            .expectNMatches = n,                                           \
            .expectMatches = m,                                            \
            .expectError = e,                                              \
        };                                                                 \
        if (virTestRun("virStringSearch " s, testStringSearch, &data) < 0) \
            ret = -1;                                                      \
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

#define TEST_REPLACE(h, o, n, r)                                             \
    do {                                                                     \
        struct stringReplaceData data = {                                    \
            .haystack = h,                                                   \
            .oldneedle = o,                                                  \
            .newneedle = n,                                                  \
            .result = r                                                      \
        };                                                                   \
        if (virTestRun("virStringReplace " h, testStringReplace, &data) < 0) \
            ret = -1;                                                        \
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

#define TEST_STRTOL(str, suff, i, i_ret, u, u_ret,                      \
                    ll, ll_ret, ull, ull_ret)                           \
    do {                                                                \
        struct stringToLongData data = {                                \
            str, suff, i, i_ret, u, u_ret, ll, ll_ret, ull, ull_ret,    \
        };                                                              \
        if (virTestRun("virStringToLong '" str "'", testStringToLong,   \
                       &data) < 0)                                      \
            ret = -1;                                                   \
    } while (0)

    /* Start simple */
    TEST_STRTOL("0", NULL, 0, 0, 0U, 0, 0LL, 0, 0ULL, 0);

    /* All your base are belong to us */
    TEST_STRTOL("0x0", NULL, 0, 0, 0U, 0, 0LL, 0, 0ULL, 0);
    TEST_STRTOL("0XaB", NULL, 171, 0, 171U, 0, 171LL, 0, 171ULL, 0);
    TEST_STRTOL("010", NULL, 8, 0, 8U, 0, 8LL, 0, 8ULL, 0);

    /* Suffix handling */
    TEST_STRTOL("42", NULL, 42, 0, 42U, 0, 42LL, 0, 42ULL, 0);
    TEST_STRTOL("42", "",  42, 0, 42U, 0, 42LL, 0, 42ULL, 0);
    TEST_STRTOL("42.", NULL, 0, -1, 0U, -1, 0LL, -1, 0ULL, -1);
    TEST_STRTOL("42.", ".",  42, 0, 42U, 0, 42LL, 0, 42ULL, 0);

    /* Blatant invalid input */
    TEST_STRTOL("", "", 0, -1, 0U, -1, 0LL, -1, 0ULL, -1);
    TEST_STRTOL("", NULL, 0, -1, 0U, -1, 0LL, -1, 0ULL, -1);
    TEST_STRTOL("  ", "  ", 0, -1, 0U, -1, 0LL, -1, 0ULL, -1);
    TEST_STRTOL("  ", NULL, 0, -1, 0U, -1, 0LL, -1, 0ULL, -1);
    TEST_STRTOL("  -", "  -", 0, -1, 0U, -1, 0LL, -1, 0ULL, -1);
    TEST_STRTOL("  -", NULL, 0, -1, 0U, -1, 0LL, -1, 0ULL, -1);
    TEST_STRTOL("a", "a", 0, -1, 0U, -1, 0LL, -1, 0ULL, -1);
    TEST_STRTOL("a", NULL, 0, -1, 0U, -1, 0LL, -1, 0ULL, -1);

    /* Not a hex number, but valid when suffix expected */
    TEST_STRTOL("  0x", NULL, 0, -1, 0U, -1, 0LL, -1, 0ULL, -1);
    TEST_STRTOL("  0x", "x", 0, 0, 0U, 0, 0LL, 0, 0ULL, 0);

    /* Upper bounds */
    TEST_STRTOL("2147483647", NULL, 2147483647, 0, 2147483647U, 0,
                2147483647LL, 0, 2147483647ULL, 0);
    TEST_STRTOL("2147483648", NULL, 0, -1, 2147483648U, 0,
                2147483648LL, 0, 2147483648ULL, 0);
    TEST_STRTOL("4294967295", NULL, 0, -1, 4294967295U, 0,
                4294967295LL, 0, 4294967295ULL, 0);
    TEST_STRTOL("4294967296", NULL, 0, -1, 0U, -1,
                4294967296LL, 0, 4294967296ULL, 0);
    TEST_STRTOL("9223372036854775807", NULL, 0, -1, 0U, -1,
                9223372036854775807LL, 0, 9223372036854775807ULL, 0);
    TEST_STRTOL("9223372036854775808", NULL, 0, -1, 0U, -1,
                0LL, -1, 9223372036854775808ULL, 0);
    TEST_STRTOL("18446744073709551615", NULL, 0, -1, 0U, -1,
                0LL, -1, 18446744073709551615ULL, 0);
    TEST_STRTOL("18446744073709551616", NULL, 0, -1, 0U, -1,
                0LL, -1, 0ULL, -1);
    TEST_STRTOL("18446744073709551616", "", 0, -1, 0U, -1,
                0LL, -1, 0ULL, -1);

    /* Negative bounds */
    TEST_STRTOL("-0", NULL, 0, 0, 0U, 0, 0LL, 0, 0ULL, 0);
    TEST_STRTOL("-1", "", -1, 0, 4294967295U, 0,
                -1LL, 0, 18446744073709551615ULL, 0);
    TEST_STRTOL("-2147483647", NULL, -2147483647, 0, 2147483649U, 0,
                -2147483647LL, 0, 18446744071562067969ULL, 0);
    TEST_STRTOL("-2147483648", NULL, INT32_MIN, 0, 2147483648U, 0,
                -2147483648LL, 0, 18446744071562067968ULL, 0);
    TEST_STRTOL("-2147483649", NULL, 0, -1, 2147483647U, 0,
                -2147483649LL, 0, 18446744071562067967ULL, 0);
    TEST_STRTOL("-4294967295", NULL, 0, -1, 1U, 0,
                -4294967295LL, 0, 18446744069414584321ULL, 0);
    TEST_STRTOL("-4294967296", NULL, 0, -1, 0U, -1,
                -4294967296LL, 0, 18446744069414584320ULL, 0);
    TEST_STRTOL("-9223372036854775807", NULL, 0, -1, 0U, -1,
                -9223372036854775807LL, 0, 9223372036854775809ULL, 0);
    TEST_STRTOL("-9223372036854775808", NULL, 0, -1, 0U, -1,
                INT64_MIN, 0, 9223372036854775808ULL, 0);
    TEST_STRTOL("-9223372036854775809", NULL, 0, -1, 0U, -1,
                0LL, -1, 9223372036854775807ULL, 0);
    TEST_STRTOL("-18446744073709551615", NULL, 0, -1, 0U, -1,
                0LL, -1, 1ULL, 0);
    TEST_STRTOL("-18446744073709551616", NULL, 0, -1, 0U, -1,
                0LL, -1, 0ULL, -1);

    /* test virStringListFreeCount */
    if (virTestRun("virStringListFreeCount", testVirStringListFreeCount,
                   NULL) < 0)
        ret = -1;

#define TEST_STRIP_IPV6_BRACKETS(str, res)                              \
    do {                                                                \
        struct testStripData stripData = {                              \
            .string = str,                                              \
            .result = res,                                              \
        };                                                              \
        if (virTestRun("Strip brackets from IPv6 " #str,                \
                       testStripIPv6Brackets, &stripData) < 0)          \
            ret = -1;                                                   \
    } while (0)

    TEST_STRIP_IPV6_BRACKETS(NULL, NULL);
    TEST_STRIP_IPV6_BRACKETS("[]", "[]");
    TEST_STRIP_IPV6_BRACKETS("[:]", ":");
    TEST_STRIP_IPV6_BRACKETS("[::1]", "::1");
    TEST_STRIP_IPV6_BRACKETS("[hello:", "[hello:");
    TEST_STRIP_IPV6_BRACKETS(":hello]", ":hello]");
    TEST_STRIP_IPV6_BRACKETS(":[]:", ":[]:");

#define TEST_STRIP_CONTROL_CHARS(str, res)                              \
    do {                                                                \
        struct testStripData stripData = {                              \
            .string = str,                                              \
            .result = res,                                              \
        };                                                              \
        if (virTestRun("Strip control chars from " #str,                \
                       testStripControlChars, &stripData) < 0)          \
            ret = -1;                                                   \
    } while (0)

    TEST_STRIP_CONTROL_CHARS(NULL, NULL);
    TEST_STRIP_CONTROL_CHARS("\nhello \r hello\t", "\nhello \r hello\t");
    TEST_STRIP_CONTROL_CHARS("\x01H\x02" "E\x03L\x04L\x05O", "HELLO");
    TEST_STRIP_CONTROL_CHARS("\x01\x02\x03\x04HELL\x05O", "HELLO");
    TEST_STRIP_CONTROL_CHARS("\nhello \x01\x07hello\t", "\nhello hello\t");
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
