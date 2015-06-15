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
            .name = NULL
        }
    };

    for (i = 0; test[i].name; ++i) {
        if (virtTestRun(test[i].name, testTypedParamsValidate, &test[i]) < 0)
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

    if (rv < 0)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

VIRT_TEST_MAIN(mymain)
