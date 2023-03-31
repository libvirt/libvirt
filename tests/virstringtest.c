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
 */

#include <config.h>


#include "testutils.h"
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
        fprintf(stderr,
                "STREQ not working correctly. Expected %d got %d",
                (int) equal, (int) streq_rv);
        return -1;
    }

    if (strneq_rv == equal) {
        fprintf(stderr,
                "STRNEQ not working correctly. Expected %d got %d",
                (int) equal, (int) strneq_rv);
        return -1;
    }

    return 0;
}


static int
testStringSortCompare(const void *opaque G_GNUC_UNUSED)
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
    size_t i;

    qsort(randlist, G_N_ELEMENTS(randlist), sizeof(randlist[0]),
          virStringSortCompare);
    qsort(randrlist, G_N_ELEMENTS(randrlist), sizeof(randrlist[0]),
          virStringSortRevCompare);

    for (i = 0; i < G_N_ELEMENTS(randlist); i++) {
        if (STRNEQ(randlist[i], sortlist[i])) {
            fprintf(stderr, "sortlist[%zu] '%s' != randlist[%zu] '%s'\n",
                    i, sortlist[i], i, randlist[i]);
            return -1;
        }
        if (STRNEQ(randrlist[i], sortrlist[i])) {
            fprintf(stderr, "sortrlist[%zu] '%s' != randrlist[%zu] '%s'\n",
                    i, sortrlist[i], i, randrlist[i]);
            return -1;
        }
    }

    return 0;
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
    g_auto(GStrv) matches = NULL;
    ssize_t nmatches;

    nmatches = virStringSearch(data->str, data->regexp,
                               data->maxMatches, &matches);

    if (data->expectError) {
        if (nmatches != -1) {
            fprintf(stderr, "expected error on %s but got %zd matches\n",
                    data->str, nmatches);
            return -1;
        }
    } else {
        size_t i;

        if (nmatches < 0) {
            fprintf(stderr, "expected %zu matches on %s but got error\n",
                    data->expectNMatches, data->str);
            return -1;
        }

        if (nmatches != data->expectNMatches) {
            fprintf(stderr, "expected %zu matches on %s but got %zd\n",
                    data->expectNMatches, data->str, nmatches);
            return -1;
        }

        if (g_strv_length(matches) != nmatches) {
            fprintf(stderr, "expected %zu matches on %s but got %u matches\n",
                    data->expectNMatches, data->str,
                    g_strv_length(matches));
            return -1;
        }

        for (i = 0; i < nmatches; i++) {
            if (STRNEQ(matches[i], data->expectMatches[i])) {
                fprintf(stderr, "match %zu expected '%s' but got '%s'\n",
                        i, data->expectMatches[i], matches[i]);
                return -1;
            }
        }
    }

    return 0;
}


struct stringMatchData {
    const char *str;
    const char *regexp;
    bool expectMatch;
};

static int
testStringMatch(const void *opaque)
{
    const struct stringMatchData *data = opaque;
    bool match;

    match = virStringMatch(data->str, data->regexp);

    if (data->expectMatch) {
        if (!match) {
            fprintf(stderr, "expected match for '%s' on '%s' but got no match\n",
                    data->regexp, data->str);
            return -1;
        }
    } else {
        if (match) {
            fprintf(stderr, "expected no match for '%s' on '%s' but got match\n",
                    data->regexp, data->str);
            return -1;
        }
    }

    return 0;
}


struct stringReplaceData {
    const char *haystack;
    const char *oldneedle;
    const char *newneedle;
    const char *result;
};

static int
testStringReplace(const void *opaque G_GNUC_UNUSED)
{
    const struct stringReplaceData *data = opaque;
    g_autofree char *result = NULL;

    result = virStringReplace(data->haystack,
                              data->oldneedle,
                              data->newneedle);

    if (STRNEQ_NULLABLE(data->result, result)) {
        fprintf(stderr, "Expected '%s' but got '%s'\n",
                data->result, NULLSTR(result));
        return -1;
    }

    return 0;
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
 * to try and port libvirt to a platform with 16-bit int. */
G_STATIC_ASSERT(sizeof(int) == 4);
G_STATIC_ASSERT(sizeof(long) == sizeof(int) || sizeof(long) == sizeof(long long));
G_STATIC_ASSERT(sizeof(long long) == 8);

static int
testStringToLong(const void *opaque)
{
    const struct stringToLongData *data = opaque;
    int ret = 0;
    char *end;
    unsigned long ul;
    bool negative;

    if (data->suffix)
        negative = !!memchr(data->str, '-',
                            strlen(data->str) - strlen(data->suffix));
    else
        negative = !!strchr(data->str, '-');

#define TEST_ONE(Str, Suff, Type, Fn, Fmt, Exp, Exp_ret) \
    do { \
        Type value = 5; \
        int result; \
        end = (char *) "oops"; \
        result = virStrToLong_ ## Fn(Str, Suff ? &end : NULL, \
                                     0, &value); \
        /* On failure, end is modified, value is unchanged */ \
        if (result != (Exp_ret)) { \
            fprintf(stderr, \
                    "type " #Fn " returned %d expected %d\n", \
                    result, Exp_ret); \
            ret = -1; \
        } \
        if (value != ((Exp_ret) ? 5 : Exp)) { \
            fprintf(stderr, \
                    "type " #Fn " value " Fmt " expected " Fmt "\n", \
                    value, ((Exp_ret) ? 5 : Exp)); \
            ret = -1; \
        } \
        if (Suff && STRNEQ_NULLABLE(Suff, end)) { \
            fprintf(stderr, \
                    "type " #Fn " end '%s' expected '%s'\n", \
                    NULLSTR(end), Suff); \
            ret = -1; \
        } \
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


struct stringToDoubleData {
    const char *str;
    const char *end_ptr;
    double res;
};

/* This test checks if double strings are successfully converted to double
 * number considering the byproduct string too. */
static int
testStringToDouble(const void *opaque)
{
    const struct stringToDoubleData *data = opaque;
    int ret = -1;
    char *end_ptr = NULL;
    double res = 0;

    /* end_ptr returns or a substring or an empty string.
     * It never returns a NULL pointer. */
    if ((ret = virStrToDouble(data->str,
                              data->end_ptr ? &end_ptr : NULL,
                              &res)) < 0) {
        fprintf(stderr, "Convert error of '%s', expected '%lf'\n",
                data->str, data->res);
        return ret;
    }

    if (res != data->res) {
        fprintf(stderr, "Returned '%lf', expected '%lf'\n",
                res, data->res);
        return -1;
    }

    /* Comparing substrings. */
    if (STRNEQ_NULLABLE(end_ptr, data->end_ptr)) {
        fprintf(stderr, "Expected substring '%s', but got '%s'\n",
                end_ptr, data->end_ptr);
        return -1;
    }

    return ret;
}


struct testStripData {
    const char *string;
    const char *result;
};

static int testStripIPv6Brackets(const void *args)
{
    const struct testStripData *data = args;
    g_autofree char *res = NULL;

    res = g_strdup(data->string);

    virStringStripIPv6Brackets(res);

    if (STRNEQ_NULLABLE(res, data->result)) {
        fprintf(stderr, "Returned '%s', expected '%s'\n",
                NULLSTR(res), NULLSTR(data->result));
        return -1;
    }

    return 0;
}

static int testStripControlChars(const void *args)
{
    const struct testStripData *data = args;
    g_autofree char *res = NULL;

    res = g_strdup(data->string);

    virStringStripControlChars(res);

    if (STRNEQ_NULLABLE(res, data->result)) {
        fprintf(stderr, "Returned '%s', expected '%s'\n",
                NULLSTR(res), NULLSTR(data->result));
        return -1;
    }

    return 0;
}

struct testFilterData {
    const char *string;
    const char *valid;
    const char *result;
};

static int testFilterChars(const void *args)
{
    const struct testFilterData *data = args;
    g_autofree char *res = NULL;

    res = g_strdup(data->string);

    virStringFilterChars(res, data->valid);

    if (STRNEQ_NULLABLE(res, data->result)) {
        fprintf(stderr, "Returned '%s', expected '%s'\n",
                NULLSTR(res), NULLSTR(data->result));
        return -1;
    }

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

#define TEST_STREQ(aa, bb) \
    do { \
        struct testStreqData streqData = {.a = aa, .b = bb}; \
        if (virTestRun("Streq", testStreq, &streqData) < 0) \
            ret = -1; \
    } while (0)

    TEST_STREQ("hello", "world");
    TEST_STREQ(NULL, NULL);
    TEST_STREQ(NULL, "");
    TEST_STREQ("", NULL);
    TEST_STREQ("", "");
    TEST_STREQ("hello", "hello");

    if (virTestRun("virStringSortCompare", testStringSortCompare, NULL) < 0)
        ret = -1;

#define TEST_SEARCH(s, r, x, n, m, e) \
    do { \
        struct stringSearchData data = { \
            .str = s, \
            .maxMatches = x, \
            .regexp = r, \
            .expectNMatches = n, \
            .expectMatches = m, \
            .expectError = e, \
        }; \
        if (virTestRun("virStringSearch " s, testStringSearch, &data) < 0) \
            ret = -1; \
    } while (0)

    /* error due to missing () in regexp */
    TEST_SEARCH("foo", "bar", 10, 0, NULL, true);

    /* error due to too many () in regexp */
    TEST_SEARCH("foo", "(b)(a)(r)", 10, 0, NULL, true);

    /* None matching */
    TEST_SEARCH("foo", "(bar)", 10, 0, NULL, false);

    VIR_WARNINGS_NO_DECLARATION_AFTER_STATEMENT
    /* Full match */
    const char *matches1[] = { "foo" };
    TEST_SEARCH("foo", "(foo)", 10, 1, matches1, false);

    /* Multi matches */
    const char *matches2[] = { "foo", "bar", "eek" };
    TEST_SEARCH("1foo2bar3eek", "([a-z]+)", 10, 3, matches2, false);

    /* Multi matches, limited returns */
    const char *matches3[] = { "foo", "bar" };
    TEST_SEARCH("1foo2bar3eek", "([a-z]+)", 2, 2, matches3, false);
    VIR_WARNINGS_RESET

#define TEST_MATCH(s, r, m) \
    do { \
        struct stringMatchData data = { \
            .str = s, \
            .regexp = r, \
            .expectMatch = m, \
        }; \
        if (virTestRun("virStringMatch " s, testStringMatch, &data) < 0) \
            ret = -1; \
    } while (0)

    TEST_MATCH("foo", "foo", true);
    TEST_MATCH("foobar", "f[o]+", true);
    TEST_MATCH("foobar", "^f[o]+$", false);

#define TEST_REPLACE(h, o, n, r) \
    do { \
        struct stringReplaceData data = { \
            .haystack = h, \
            .oldneedle = o, \
            .newneedle = n, \
            .result = r \
        }; \
        if (virTestRun("virStringReplace " h, testStringReplace, &data) < 0) \
            ret = -1; \
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

#define TEST_STRTOL(str, suff, i, i_ret, u, u_ret, \
                    ll, ll_ret, ull, ull_ret) \
    do { \
        struct stringToLongData data = { \
            str, suff, i, i_ret, u, u_ret, ll, ll_ret, ull, ull_ret, \
        }; \
        if (virTestRun("virStringToLong '" str "'", testStringToLong, \
                       &data) < 0) \
            ret = -1; \
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

#define TEST_STRTOD(str, end_ptr, res) \
    do { \
        struct stringToDoubleData data = { \
            str, end_ptr, res, \
        }; \
        if (virTestRun("virStringToDouble '" str "'", \
                       testStringToDouble, &data) < 0) \
            ret = -1; \
    } while (0)

    /* Simple numbers. */
    TEST_STRTOD("0.0", NULL, 0);
    TEST_STRTOD("1.0", NULL, 1);
    TEST_STRTOD("3.14159", NULL, 3.14159);
    TEST_STRTOD("0.57721", NULL, 0.57721);

    /* Testing ending string. */
    TEST_STRTOD("2.718", "", 2.718);
    TEST_STRTOD("2.718 281 828 459", " 281 828 459", 2.718);
    TEST_STRTOD("2.718,281,828,459", ",281,828,459", 2.718);

    /* Scientific numbers. */
    TEST_STRTOD("3.14159e+000", NULL, 3.14159);
    TEST_STRTOD("2.00600e+003", NULL, 2006);
    TEST_STRTOD("1.00000e-010", NULL, 1e-010);

    /* Negative numbers. */
    TEST_STRTOD("-1.6180339887", NULL, -1.6180339887);
    TEST_STRTOD("-0.00031e-010", NULL, -0.00031e-010);

    /* Long numbers. */
    TEST_STRTOD("57089907708238388904078437636832797971793838081897.0",
                NULL,
                57089907708238388904078437636832797971793838081897.0);
    TEST_STRTOD("3.141592653589793238462643383279502884197169399375105",
                NULL,
                3.141592653589793238462643383279502884197169399375105);

#define TEST_STRIP_IPV6_BRACKETS(str, res) \
    do { \
        struct testStripData stripData = { \
            .string = str, \
            .result = res, \
        }; \
        if (virTestRun("Strip brackets from IPv6 " #str, \
                       testStripIPv6Brackets, &stripData) < 0) \
            ret = -1; \
    } while (0)

    TEST_STRIP_IPV6_BRACKETS(NULL, NULL);
    TEST_STRIP_IPV6_BRACKETS("[]", "[]");
    TEST_STRIP_IPV6_BRACKETS("[:]", ":");
    TEST_STRIP_IPV6_BRACKETS("[::1]", "::1");
    TEST_STRIP_IPV6_BRACKETS("[hello:", "[hello:");
    TEST_STRIP_IPV6_BRACKETS(":hello]", ":hello]");
    TEST_STRIP_IPV6_BRACKETS(":[]:", ":[]:");

#define TEST_STRIP_CONTROL_CHARS(str, res) \
    do { \
        struct testStripData stripData = { \
            .string = str, \
            .result = res, \
        }; \
        if (virTestRun("Strip control chars from " #str, \
                       testStripControlChars, &stripData) < 0) \
            ret = -1; \
    } while (0)

    TEST_STRIP_CONTROL_CHARS(NULL, NULL);
    TEST_STRIP_CONTROL_CHARS("\nhello \r hello\t", "\nhello \r hello\t");
    TEST_STRIP_CONTROL_CHARS("\x01H\x02" "E\x03L\x04L\x05O", "HELLO");
    TEST_STRIP_CONTROL_CHARS("\x01\x02\x03\x04HELL\x05O", "HELLO");
    TEST_STRIP_CONTROL_CHARS("\nhello \x01\x07hello\t", "\nhello hello\t");

#define TEST_FILTER_CHARS(str, filter, res) \
    do { \
        struct testFilterData filterData = { \
            .string = str, \
            .valid = filter, \
            .result = res, \
        }; \
        if (virTestRun("Filter chars from " #str, \
                       testFilterChars, &filterData) < 0) \
            ret = -1; \
    } while (0)

    TEST_FILTER_CHARS(NULL, NULL, NULL);
    TEST_FILTER_CHARS("hello 123 hello", "helo", "hellohello");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
