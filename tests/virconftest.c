/*
 * virconftest.c: Test the config file API
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "virconf.h"
#include "viralloc.h"
#include "testutils.h"


#define VIR_FROM_THIS VIR_FROM_NONE

static int testConfRoundTrip(const void *opaque)
{
    const char *name = opaque;
    int ret = -1;
    virConfPtr conf = NULL;
    int len = 10000;
    char *buffer = NULL;
    char *srcfile = NULL;
    char *dstfile = NULL;

    if (virAsprintf(&srcfile, "%s/virconfdata/%s.conf",
                    abs_srcdir, name) < 0 ||
        virAsprintf(&dstfile, "%s/virconfdata/%s.out",
                    abs_srcdir, name) < 0)
        goto cleanup;

    if (VIR_ALLOC_N_QUIET(buffer, len) < 0) {
        fprintf(stderr, "out of memory\n");
        goto cleanup;
    }
    conf = virConfReadFile(srcfile, 0);
    if (conf == NULL) {
        fprintf(stderr, "Failed to process %s\n", srcfile);
        goto cleanup;
    }
    ret = virConfWriteMem(buffer, &len, conf);
    if (ret < 0) {
        fprintf(stderr, "Failed to serialize %s back\n", srcfile);
        goto cleanup;
    }

    if (virTestCompareToFile(buffer, dstfile) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(srcfile);
    VIR_FREE(dstfile);
    VIR_FREE(buffer);
    virConfFree(conf);
    return ret;
}


static int testConfParseInt(const void *opaque ATTRIBUTE_UNUSED)
{
    const char *srcdata =                       \
        "int = -1729\n"                         \
        "uint = 1729\n"                         \
        "llong = -6963472309248\n"              \
        "ullong = 6963472309248\n"              \
        "size_t = 87539319\n"                   \
        "ssize_t = -87539319\n"                 \
        "string = \"foo\"\n";

    int ret = -1;
    virConfPtr conf = virConfReadMem(srcdata, strlen(srcdata), 0);
    int iv;
    unsigned int ui;
    size_t s;
    ssize_t ss;
    long long l;
    unsigned long long ul;

    if (!conf)
        return -1;

    if (virConfGetValueType(conf, "int") !=
        VIR_CONF_LLONG) {
        fprintf(stderr, "expected a long for 'int'\n");
        goto cleanup;
    }

    if (virConfGetValueInt(conf, "int", &iv) < 0)
        goto cleanup;

    if (iv != -1729) {
        fprintf(stderr, "Expected -1729 got %d\n", iv);
        goto cleanup;
    }

    if (virConfGetValueInt(conf, "string", &iv) != -1) {
        fprintf(stderr, "Expected error for 'string' param\n");
        goto cleanup;
    }


    if (virConfGetValueType(conf, "uint") !=
        VIR_CONF_ULLONG) {
        fprintf(stderr, "expected a unsigned long for 'uint'\n");
        goto cleanup;
    }

    if (virConfGetValueUInt(conf, "uint", &ui) < 0)
        goto cleanup;

    if (ui != 1729) {
        fprintf(stderr, "Expected 1729 got %u\n", ui);
        goto cleanup;
    }

    if (virConfGetValueUInt(conf, "string", &ui) != -1) {
        fprintf(stderr, "Expected error for 'string' param\n");
        goto cleanup;
    }



    if (virConfGetValueType(conf, "llong") !=
        VIR_CONF_LLONG) {
        fprintf(stderr, "expected a long for 'llong'\n");
        goto cleanup;
    }

    if (virConfGetValueLLong(conf, "llong", &l) < 0)
        goto cleanup;

    if (l != -6963472309248) {
        fprintf(stderr, "Expected -6963472309248 got %lld\n", l);
        goto cleanup;
    }

    if (virConfGetValueLLong(conf, "string", &l) != -1) {
        fprintf(stderr, "Expected error for 'string' param\n");
        goto cleanup;
    }



    if (virConfGetValueType(conf, "ullong") !=
        VIR_CONF_ULLONG) {
        fprintf(stderr, "expected a unsigned long for 'ullong'\n");
        goto cleanup;
    }

    if (virConfGetValueULLong(conf, "ullong", &ul) < 0)
        goto cleanup;

    if (ul != 6963472309248) {
        fprintf(stderr, "Expected 6963472309248 got %llu\n", ul);
        goto cleanup;
    }

    if (virConfGetValueULLong(conf, "string", &ul) != -1) {
        fprintf(stderr, "Expected error for 'string' param\n");
        goto cleanup;
    }



    if (virConfGetValueType(conf, "size_t") !=
        VIR_CONF_ULLONG) {
        fprintf(stderr, "expected a unsigned long for 'size_T'\n");
        goto cleanup;
    }

    if (virConfGetValueSizeT(conf, "size_t", &s) < 0)
        goto cleanup;

    if (s != 87539319) {
        fprintf(stderr, "Expected 87539319 got %zu\n", s);
        goto cleanup;
    }

    if (virConfGetValueSizeT(conf, "string", &s) != -1) {
        fprintf(stderr, "Expected error for 'string' param\n");
        goto cleanup;
    }



    if (virConfGetValueType(conf, "ssize_t") !=
        VIR_CONF_LLONG) {
        fprintf(stderr, "expected a unsigned long for 'ssize_t'\n");
        goto cleanup;
    }

    if (virConfGetValueSSizeT(conf, "ssize_t", &ss) < 0)
        goto cleanup;

    if (ss != -87539319) {
        fprintf(stderr, "Expected -87539319 got %zd\n", ss);
        goto cleanup;
    }

    if (virConfGetValueSSizeT(conf, "string", &ss) != -1) {
        fprintf(stderr, "Expected error for 'string' param\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virConfFree(conf);
    return ret;
}

static int testConfParseBool(const void *opaque ATTRIBUTE_UNUSED)
{
    const char *srcdata =                         \
        "false = 0\n"                             \
        "true = 1\n"                              \
        "int = 6963472309248\n"                   \
        "string = \"foo\"\n";

    int ret = -1;
    virConfPtr conf = virConfReadMem(srcdata, strlen(srcdata), 0);
    bool f = true;
    bool t = false;

    if (!conf)
        return -1;

    if (virConfGetValueType(conf, "false") !=
        VIR_CONF_ULLONG) {
        fprintf(stderr, "expected a long for 'false'\n");
        goto cleanup;
    }

    if (virConfGetValueBool(conf, "false", &f) < 0)
        goto cleanup;

    if (f != false) {
        fprintf(stderr, "Expected 0 got %d\n", f);
        goto cleanup;
    }



    if (virConfGetValueType(conf, "true") !=
        VIR_CONF_ULLONG) {
        fprintf(stderr, "expected a long for 'true'\n");
        goto cleanup;
    }

    if (virConfGetValueBool(conf, "true", &t) < 0)
        goto cleanup;

    if (t != true) {
        fprintf(stderr, "Expected 1 got %d\n", t);
        goto cleanup;
    }



    if (virConfGetValueBool(conf, "int", &t) != -1) {
        fprintf(stderr, "Expected error for 'string' param\n");
        goto cleanup;
    }

    if (virConfGetValueBool(conf, "string", &t) != -1) {
        fprintf(stderr, "Expected error for 'string' param\n");
        goto cleanup;
    }


    ret = 0;
 cleanup:
    virConfFree(conf);
    return ret;
}


static int testConfParseString(const void *opaque ATTRIBUTE_UNUSED)
{
    const char *srcdata =                         \
        "int = 6963472309248\n"                   \
        "string = \"foo\"\n";

    int ret = -1;
    virConfPtr conf = virConfReadMem(srcdata, strlen(srcdata), 0);
    char *str = NULL;

    if (!conf)
        return -1;

    if (virConfGetValueType(conf, "string") !=
        VIR_CONF_STRING) {
        fprintf(stderr, "expected a string for 'string'\n");
        goto cleanup;
    }

    if (virConfGetValueString(conf, "string", &str) < 0)
        goto cleanup;

    if (STRNEQ_NULLABLE(str, "foo")) {
        fprintf(stderr, "Expected 'foo' got '%s'\n", str);
        goto cleanup;
    }

    if (virConfGetValueString(conf, "int", &str) != -1) {
        fprintf(stderr, "Expected error for 'int'\n");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(str);
    virConfFree(conf);
    return ret;
}


static int testConfParseStringList(const void *opaque ATTRIBUTE_UNUSED)
{
    const char *srcdata =                         \
        "string_list = [\"foo\", \"bar\"]\n"      \
        "string = \"foo\"\n";

    int ret = -1;
    virConfPtr conf = virConfReadMem(srcdata, strlen(srcdata), 0);
    char **str = NULL;

    if (!conf)
        return -1;

    if (virConfGetValueType(conf, "string_list") !=
        VIR_CONF_LIST) {
        fprintf(stderr, "expected a list for 'string_list'\n");
        goto cleanup;
    }

    if (virConfGetValueStringList(conf, "string_list", false, &str) < 0)
        goto cleanup;

    if (virStringListLength((const char *const*)str) != 2) {
        fprintf(stderr, "expected a 2 element list\n");
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(str[0], "foo")) {
        fprintf(stderr, "Expected 'foo' got '%s'\n", str[0]);
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(str[1], "bar")) {
        fprintf(stderr, "Expected 'bar' got '%s'\n", str[1]);
        goto cleanup;
    }


    if (virConfGetValueStringList(conf, "string", false, &str) != -1) {
        fprintf(stderr, "Expected error for 'string'\n");
        goto cleanup;
    }

    if (virConfGetValueStringList(conf, "string", true, &str) < 0)
        goto cleanup;

    if (virStringListLength((const char *const*)str) != 1) {
        fprintf(stderr, "expected a 1 element list\n");
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(str[0], "foo")) {
        fprintf(stderr, "Expected 'foo' got '%s'\n", str[0]);
        goto cleanup;
    }


    ret = 0;
 cleanup:
    virStringListFree(str);
    virConfFree(conf);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if (virTestRun("fc4", testConfRoundTrip, "fc4") < 0)
        ret = -1;

    if (virTestRun("libvirtd", testConfRoundTrip, "libvirtd") < 0)
        ret = -1;

    if (virTestRun("no-newline", testConfRoundTrip, "no-newline") < 0)
        ret = -1;

    if (virTestRun("int", testConfParseInt, NULL) < 0)
        ret = -1;

    if (virTestRun("bool", testConfParseBool, NULL) < 0)
        ret = -1;

    if (virTestRun("string", testConfParseString, NULL) < 0)
        ret = -1;

    if (virTestRun("string-list", testConfParseStringList, NULL) < 0)
        ret = -1;

    return ret;
}


VIR_TEST_MAIN(mymain)
