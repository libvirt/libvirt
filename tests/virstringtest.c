/*
 * Copyright (C) 2012 Red Hat, Inc.
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
#include "virutil.h"
#include "virerror.h"
#include "viralloc.h"
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
            fprintf(stderr, "Mismatch '%s' vs '%s'\n", *tmp1, *tmp2);
            goto cleanup;
        }
        tmp1++;
        tmp2++;
    }
    if (*tmp1) {
        fprintf(stderr, "Too many pieces returned\n");
        goto cleanup;
    }
    if (*tmp2) {
        fprintf(stderr, "Too few pieces returned\n");
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
        fprintf(stderr, "Mismatch '%s' vs '%s'\n", got, data->string);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(got);

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


    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
