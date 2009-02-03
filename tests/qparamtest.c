#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "testutils.h"
#include "qparams.h"
#include "util.h"
#include "memory.h"

struct qparamParseDataEntry {
    const char *name;
    const char *value;
};

struct qparamParseData {
    const char *queryIn;
    const char *queryOut;
    int nparams;
    const struct qparamParseDataEntry *params;
};

static int
qparamParseTest(const void *data)
{
    const struct qparamParseData *expect = data;
    struct qparam_set *actual = qparam_query_parse(expect->queryIn);
    int ret = -1, i;
    if (!actual)
        return -1;

    if (actual->n != expect->nparams)
        goto fail;

    for (i = 0 ; i < actual->n ; i++) {
        if (!STREQ(expect->params[i].name,
                   actual->p[i].name))
            goto fail;
        if (!STREQ(expect->params[i].value,
                   actual->p[i].value))
            goto fail;
    }

    ret = 0;

fail:
    free_qparam_set(actual);
    return ret;
}

static int
qparamFormatTest(const void *data)
{
    const struct qparamParseData *expect = data;
    struct qparam_set *actual = qparam_query_parse(expect->queryIn);
    char *output = NULL;
    int ret = -1;

    if (!actual)
        return -1;

    output = qparam_get_query(actual);
    if (!output)
        goto fail;

    if (!STREQ(output, expect->queryOut))
        goto fail;

    ret = 0;

fail:
    free(output);
    free_qparam_set(actual);
    return ret;
}

static int
qparamBuildTest(const void *data)
{
    const struct qparamParseData *expect = data;
    struct qparam_set *actual = new_qparam_set(0, NULL);
    int ret = -1, i;
    if (!actual)
        return -1;

    for (i = 0 ; i < expect->nparams ; i++) {
        if (append_qparam(actual,
                          expect->params[i].name,
                          expect->params[i].value) < 0)
            goto fail;
    }

    if (actual->n != expect->nparams)
        goto fail;

    for (i = 0 ; i < actual->n ; i++) {
        if (!STREQ(expect->params[i].name,
                   actual->p[i].name))
            goto fail;
        if (!STREQ(expect->params[i].value,
                   actual->p[i].value))
            goto fail;
    }

    ret = 0;

fail:
    free_qparam_set(actual);
    return ret;
}


static int
qparamTestNewVargs(const void *data ATTRIBUTE_UNUSED)
{
    struct qparam_set *actual = new_qparam_set(0, "foo", "one", "bar", "two", NULL);
    int ret = -1;
    if (!actual)
        return -1;

    if (actual->n != 2)
        goto fail;

    if (!STREQ(actual->p[0].name, "foo"))
        goto fail;

    if (!STREQ(actual->p[0].value, "one"))
        goto fail;

    if (!STREQ(actual->p[1].name, "bar"))
        goto fail;

    if (!STREQ(actual->p[1].value, "two"))
        goto fail;

    ret = 0;

fail:
    free_qparam_set(actual);
    return ret;
}

static int
qparamTestAddVargs(const void *data ATTRIBUTE_UNUSED)
{
    struct qparam_set *actual = new_qparam_set(0, NULL);
    int ret = -1;
    if (!actual)
        return -1;

    if (append_qparams(actual,  "foo", "one", "bar", "two", NULL) < 0)
        goto fail;

    if (actual->n != 2)
        goto fail;

    if (!STREQ(actual->p[0].name, "foo"))
        goto fail;

    if (!STREQ(actual->p[0].value, "one"))
        goto fail;

    if (!STREQ(actual->p[1].name, "bar"))
        goto fail;

    if (!STREQ(actual->p[1].value, "two"))
        goto fail;

    ret = 0;

fail:
    free_qparam_set(actual);
    return ret;
}

static const struct qparamParseDataEntry params1[] = { { "foo", "one" }, { "bar", "two" } };
static const struct qparamParseDataEntry params2[] = { { "foo", "one" }, { "foo", "two" } };
static const struct qparamParseDataEntry params3[] = { { "foo", "&one" }, { "bar", "&two" } };
static const struct qparamParseDataEntry params4[] = { { "foo", "" } };
static const struct qparamParseDataEntry params5[] = { { "foo", "one two" } };
static const struct qparamParseDataEntry params6[] = { { "foo", "one" } };

static int
mymain(int argc ATTRIBUTE_UNUSED,
       char **argv ATTRIBUTE_UNUSED)
{
    int ret = 0;

#define DO_TEST(queryIn,queryOut,params)                                \
    do {                                                                \
        struct qparamParseData info = {                                 \
            queryIn,                                                    \
            queryOut ? queryOut : queryIn,                              \
            ARRAY_CARDINALITY(params),                                  \
            params };                                                   \
        if (virtTestRun("Parse " queryIn,                               \
                        1, qparamParseTest, &info) < 0)                 \
            ret = -1;                                                   \
        if (virtTestRun("Format " queryIn,                              \
                        1, qparamFormatTest, &info) < 0)                \
            ret = -1;                                                   \
        if (virtTestRun("Build " queryIn,                               \
                        1, qparamBuildTest, &info) < 0)                 \
            ret = -1;                                                   \
    } while (0)


    DO_TEST("foo=one&bar=two", NULL, params1);
    DO_TEST("foo=one&foo=two", NULL, params2);
    DO_TEST("foo=one&&foo=two", "foo=one&foo=two", params2);
    DO_TEST("foo=one;foo=two", "foo=one&foo=two", params2);
    DO_TEST("foo", "foo=", params4);
    DO_TEST("foo=", NULL, params4);
    DO_TEST("foo=&", "foo=", params4);
    DO_TEST("foo=&&", "foo=", params4);
    DO_TEST("foo=one%20two", NULL, params5);
    DO_TEST("=bogus&foo=one", "foo=one", params6);

    if (virtTestRun("New vargs", 1, qparamTestNewVargs, NULL) < 0)
        ret = -1;
    if (virtTestRun("Add vargs", 1, qparamTestAddVargs, NULL) < 0)
        ret = -1;

    return(ret==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

VIRT_TEST_MAIN(mymain)
