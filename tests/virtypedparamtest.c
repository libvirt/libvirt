/*
 * virtypedparamtest.c: Test typed param functions
 *
 * Copyright (C) 2015 Mirantis, Inc.
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

#include <stdio.h>
#include <virtypedparam.h>

#include "testutils.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct _TypedParameterTest {
    /* Test name for logging */
    const char          *name;
    /* Flags of the "foobar" parameter check */
    int                  foobar_flags;
    /* Parameters to validate */
    virTypedParameterPtr params;
    /* Amount of parameters */
    int                  nparams;

    /* Expected error code */
    int                  expected_errcode;
    /* Expected error message */
    const char          *expected_errmessage;
} TypedParameterTest;

static int
testTypedParamsValidate(const void *opaque)
{
    int rv;
    TypedParameterTest *test = (TypedParameterTest *)opaque;
    virErrorPtr errptr;

    rv = virTypedParamsValidate(
            test->params, test->nparams,
            "foobar", VIR_TYPED_PARAM_STRING | test->foobar_flags,
            "foo", VIR_TYPED_PARAM_INT,
            "bar", VIR_TYPED_PARAM_UINT,
            "zzz", VIR_TYPED_PARAM_UINT,
            NULL);

    if (test->expected_errcode) {
        errptr = virGetLastError();

        rv = (errptr == NULL) || ((rv < 0) &&
                                  !(errptr->code == test->expected_errcode));
        if (errptr && test->expected_errmessage) {
            rv = STRNEQ(test->expected_errmessage, errptr->message);
            if (rv)
                printf("%s\n", errptr->message);
        }
    }

    return rv;
}

#define PARAMS_ARRAY(...) ((virTypedParameter[]){ __VA_ARGS__ })
#define PARAMS_SIZE(...) ARRAY_CARDINALITY(PARAMS_ARRAY(__VA_ARGS__))

#define PARAMS(...) \
    .params  = PARAMS_ARRAY(__VA_ARGS__), \
    .nparams = PARAMS_SIZE(__VA_ARGS__),

static int
testTypedParamsFilter(const void *opaque ATTRIBUTE_UNUSED)
{
    size_t i, nfiltered;
    int rv = -1;
    virTypedParameter params[] = {
        { .field = "bar", .type = VIR_TYPED_PARAM_UINT },
        { .field = "foo", .type = VIR_TYPED_PARAM_INT },
        { .field = "bar", .type = VIR_TYPED_PARAM_UINT },
        { .field = "foo", .type = VIR_TYPED_PARAM_INT },
        { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
        { .field = "foo", .type = VIR_TYPED_PARAM_INT }
    };
    virTypedParameterPtr *filtered = NULL;


    nfiltered = virTypedParamsFilter(params, ARRAY_CARDINALITY(params),
                                     "foo", &filtered);
    if (nfiltered != 3)
        goto cleanup;

    for (i = 0; i < nfiltered; i++) {
        if (filtered[i] != &params[1 + i * 2])
            goto cleanup;
    }
    VIR_FREE(filtered);
    filtered = NULL;

    nfiltered = virTypedParamsFilter(params, ARRAY_CARDINALITY(params),
                                     "bar", &filtered);

    if (nfiltered != 2)
        goto cleanup;

    for (i = 0; i < nfiltered; i++) {
        if (filtered[i] != &params[i * 2])
            goto cleanup;
    }

    rv = 0;
 cleanup:
    VIR_FREE(filtered);
    return rv;
}

static int
testTypedParamsAddStringList(const void *opaque ATTRIBUTE_UNUSED)
{
    int rv = 0;
    virTypedParameterPtr params = NULL;
    int nparams = 0, maxparams = 0, i;

    const char *values[] = {
        "foo", "bar", "foobar", NULL
    };

    rv = virTypedParamsAddStringList(&params, &nparams, &maxparams, "param",
                                     values);

    for (i = 0; i < nparams; i++) {
        if (STRNEQ(params[i].field, "param") ||
            STRNEQ(params[i].value.s, values[i]) ||
            params[i].type != VIR_TYPED_PARAM_STRING)
            rv = -1;
    }

    virTypedParamsFree(params, nparams);
    return rv;
}

static int
testTypedParamsGetStringList(const void *opaque ATTRIBUTE_UNUSED)
{
    size_t i;
    int picked;
    int rv = -1;
    char l = '1';
    const char **strings = NULL;

    virTypedParameter params[] = {
        { .field = "bar", .type = VIR_TYPED_PARAM_STRING,
          .value = { .s = (char*)"bar1"} },
        { .field = "foo", .type = VIR_TYPED_PARAM_INT },
        { .field = "bar", .type = VIR_TYPED_PARAM_STRING,
          .value = { .s = (char*)"bar2"} },
        { .field = "foo", .type = VIR_TYPED_PARAM_INT },
        { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
        { .field = "bar", .type = VIR_TYPED_PARAM_STRING,
          .value = { .s = NULL } },
        { .field = "foo", .type = VIR_TYPED_PARAM_INT },
        { .field = "bar", .type = VIR_TYPED_PARAM_STRING,
          .value = { .s = (char*)"bar3"} }
    };

    picked = virTypedParamsGetStringList(params,
                                         ARRAY_CARDINALITY(params),
                                         "bar",
                                         &strings);

    if (picked < 0)
        goto cleanup;

    for (i = 0; i < picked; i++) {
        if (i == 2) {
            if (strings[i] != NULL)
                goto cleanup;
            continue;
        }
        if (STRNEQLEN(strings[i], "bar", 3))
            goto cleanup;
        if (strings[i][3] != l++)
            goto cleanup;
    }

    rv = 0;
 cleanup:
    VIR_FREE(strings);
    return rv;
}

static int
testTypedParamsValidator(void)
{
    size_t i;
    int rv = 0;

    TypedParameterTest test[] = {
        {
            .name = "Invalid arg type",
            .foobar_flags = 0,
            PARAMS({ .field = "foobar", .type = VIR_TYPED_PARAM_INT })
            .expected_errcode = VIR_ERR_INVALID_ARG,
            .expected_errmessage =
                "invalid argument: invalid type 'int' for parameter "
                "'foobar', expected 'string'"
        },
        {
            .name = "Extra arg",
            .foobar_flags = 0,
            PARAMS({ .field = "f", .type = VIR_TYPED_PARAM_INT })
            .expected_errcode = VIR_ERR_INVALID_ARG,
            .expected_errmessage =
                "argument unsupported: parameter 'f' not supported"
        },
        {
            .name = "Valid parameters",
            .foobar_flags = 0,
            PARAMS(
                { .field = "bar",    .type = VIR_TYPED_PARAM_UINT },
                { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
                { .field = "foo",    .type = VIR_TYPED_PARAM_INT }
            )
            .expected_errcode = 0, .expected_errmessage = NULL,
        },
        {
            .name = "Duplicates incorrect",
            .foobar_flags = 0,
            PARAMS(
                { .field = "bar",    .type = VIR_TYPED_PARAM_UINT },
                { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
                { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
                { .field = "foo",    .type = VIR_TYPED_PARAM_INT }
            )
            .expected_errcode = VIR_ERR_INVALID_ARG,
            .expected_errmessage =
                "invalid argument: parameter 'foobar' occurs multiple times"
        },
        {
            .name = "Duplicates OK for marked",
            .foobar_flags = VIR_TYPED_PARAM_MULTIPLE,
            PARAMS(
                { .field = "bar",    .type = VIR_TYPED_PARAM_UINT },
                { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
                { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
                { .field = "foo",    .type = VIR_TYPED_PARAM_INT }
            )
            .expected_errcode = 0, .expected_errmessage = NULL,
        },
        {
            .name = "BUG, non-duplicate marked as duplicate",
            .foobar_flags = VIR_TYPED_PARAM_MULTIPLE,
            PARAMS(
                { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
                { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
                { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
                { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
                { .field = "foobar", .type = VIR_TYPED_PARAM_STRING },
                { .field = "zzz",    .type = VIR_TYPED_PARAM_UINT },
            )
            .expected_errcode = 0, .expected_errmessage = NULL,
        },
        {
            .name = NULL
        }
    };

    for (i = 0; test[i].name; ++i) {
        if (virTestRun(test[i].name, testTypedParamsValidate, &test[i]) < 0)
            rv = -1;
    }

    return rv;
}

static int
mymain(void)
{
    int rv = 0;

    if (testTypedParamsValidator() < 0)
        rv = -1;

    if (virTestRun("Filtering", testTypedParamsFilter, NULL) < 0)
        rv = -1;

    if (virTestRun("Get All Strings", testTypedParamsGetStringList, NULL) < 0)
        rv = -1;

    if (virTestRun("Add string list", testTypedParamsAddStringList, NULL) < 0)
        rv = -1;

    if (rv < 0)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

VIR_TEST_MAIN(mymain)
