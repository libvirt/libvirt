/*
 * Copyright (C) 2015-2016 Red Hat, Inc.
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

#include "util/virjson.h"
#include "util/virqemu.h"
#include "testutils.h"
#include "testutilsqemu.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct
{
    const char *props;
    const char *expectprops;
} testQemuCommandBuildObjectFromJSONData;

static int
testQemuCommandBuildFromJSON(const void *opaque)
{
    const testQemuCommandBuildObjectFromJSONData *data = opaque;
    virJSONValuePtr val = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *result = NULL;
    int ret = -1;

    if (!(val = virJSONValueFromString(data->props))) {
        fprintf(stderr, "Failed to parse JSON string '%s'", data->props);
        return -1;
    }

    if (virQEMUBuildCommandLineJSON(val, &buf,
                                    virQEMUBuildCommandLineJSONArrayBitmap) < 0) {
        fprintf(stderr,
                "\nvirQEMUBuildCommandlineJSON failed process JSON:\n%s\n",
                data->props);
        goto cleanup;
    }

    result = virBufferContentAndReset(&buf);

    if (STRNEQ_NULLABLE(data->expectprops, result)) {
        fprintf(stderr, "\nFailed to create object string. "
                "\nExpected:\n'%s'\nGot:\n'%s'",
                NULLSTR(data->expectprops), NULLSTR(result));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virJSONValueFree(val);
    VIR_FREE(result);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;
    testQemuCommandBuildObjectFromJSONData data1;

#if !WITH_YAJL
    fputs("libvirt not compiled with yajl, skipping this test\n", stderr);
    return EXIT_AM_SKIP;
#endif

    virTestCounterReset("testQemuCommandBuildFromJSON");

#define DO_TEST_COMMAND_OBJECT_FROM_JSON(PROPS, EXPECT)             \
    do {                                                            \
        data1.props = PROPS;                                        \
        data1.expectprops = EXPECT;                                 \
        if (virTestRun(virTestCounterNext(),                        \
                       testQemuCommandBuildFromJSON,                \
                       &data1) < 0)                                 \
            ret = -1;                                               \
     } while (0)

    DO_TEST_COMMAND_OBJECT_FROM_JSON("{}", NULL);
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"string\":\"qwer\"}", "string=qwer");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"string\":\"qw,e,r\"}", "string=qw,,e,,r");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"number\":1234}", "number=1234");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"boolean\":true}", "boolean=yes");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"boolean\":false}", "boolean=no");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"bitmap\":[]}", NULL);
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"bitmap\":[0]}", "bitmap=0");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"bitmap\":[1,3,5]}",
                                     "bitmap=1,bitmap=3,bitmap=5");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"bitmap\":[0,1,2,3]}", "bitmap=0-3");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"bitmap\":[1,2,3,5]}",
                                     "bitmap=1-3,bitmap=5");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"bitmap\":[1,2,3,5,7,8,9]}",
                                     "bitmap=1-3,bitmap=5,bitmap=7-9");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"array\":[\"bleah\",\"qwerty\",1]}",
                                     "array=bleah,array=qwerty,array=1");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"boolean\":true,\"hyphen-name\":1234,\"some_string\":\"bleah\"}",
                                     "boolean=yes,hyphen-name=1234,some_string=bleah");
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"nest\": {\"boolean\":true,"
                                                 "\"hyphen-name\":1234,"
                                                 "\"some_string\":\"bleah\","
                                                 "\"bleah\":\"bl,eah\""
                                                 "}"
                                     "}",
                                     "nest.boolean=yes,nest.hyphen-name=1234,"
                                     "nest.some_string=bleah,nest.bleah=bl,,eah");

    return ret;

}

VIRT_TEST_MAIN(mymain)
