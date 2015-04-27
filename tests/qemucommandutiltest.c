/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#include "qemu/qemu_command.h"
#include "util/virjson.h"
#include "testutils.h"
#include "testutilsqemu.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct
{
    const char *props;
    const char *expectprops;
} testQemuCommandBuildObjectFromJSONData;

static int
testQemuCommandBuildObjectFromJSON(const void *opaque)
{
    const testQemuCommandBuildObjectFromJSONData *data = opaque;
    virJSONValuePtr val = NULL;
    char *expect = NULL;
    char *result = NULL;
    int ret = -1;

    if (!(val = virJSONValueFromString(data->props))) {
        fprintf(stderr, "Failed to parse JSON string '%s'", data->props);
        return -1;
    }

    if (virAsprintf(&expect, "testobject,id=testalias%s%s",
                    data->expectprops ? "," : "",
                    data->expectprops ? data->expectprops : "") < 0)
        return -1;

    result = qemuBuildObjectCommandlineFromJSON("testobject",
                                                "testalias",
                                                val);

    if (STRNEQ_NULLABLE(expect, result)) {
        fprintf(stderr, "\nFailed to create object string. "
                "\nExpected:\n'%s'\nGot:\n'%s'",
                NULLSTR(expect), NULLSTR(result));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virJSONValueFree(val);
    VIR_FREE(result);
    VIR_FREE(expect);
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

    virtTestCounterReset("testQemuCommandBuildObjectFromJSON");

#define DO_TEST_COMMAND_OBJECT_FROM_JSON(PROPS, EXPECT)             \
    do {                                                            \
        data1.props = PROPS;                                        \
        data1.expectprops = EXPECT;                                 \
        if (virtTestRun(virtTestCounterNext(),                      \
                        testQemuCommandBuildObjectFromJSON,         \
                        &data1) < 0)                                \
            ret = -1;                                               \
     } while (0)

    DO_TEST_COMMAND_OBJECT_FROM_JSON("{}", NULL);
    DO_TEST_COMMAND_OBJECT_FROM_JSON("{\"string\":\"qwer\"}", "string=qwer");
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

    return ret;

}

VIRT_TEST_MAIN(mymain)
