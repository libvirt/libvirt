/*
 * Copyright (C) 2013, 2014 Red Hat, Inc.
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

#include "virdbuspriv.h"
#include "virlog.h"
#include "testutils.h"

VIR_LOG_INIT("tests.dbustest");

#define VERIFY(typname, valorig, valnew, fmt)                           \
    do {                                                                \
        VIR_DEBUG("Compare " typname " '" fmt "' to '"                  \
                  fmt "'", valorig, valnew);                            \
        if (valorig != valnew) {                                        \
            fprintf(stderr, "Failed to round-trip " typname " '"        \
                    fmt "' to '" fmt "'\n", valorig, valnew);           \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

#define VERIFY_STR(typname, valorig, valnew, fmt)                       \
    do {                                                                \
        VIR_DEBUG("Compare " typname " '" fmt "' to '"                  \
                  fmt "'", valorig, valnew);                            \
        if (STRNEQ(valorig, valnew)) {                                  \
            fprintf(stderr, "Failed to round-trip " typname " '"        \
                    fmt "' to '" fmt "'\n", valorig, valnew);           \
            goto cleanup;                                               \
        }                                                               \
    } while (0)

static int testMessageSimple(const void *args ATTRIBUTE_UNUSED)
{
    DBusMessage *msg = NULL;
    int ret = -1;
    unsigned char in_byte = 200, out_byte = 0;
    int in_bool = true, out_bool = false;
    short in_int16 = 0xfefe, out_int16 = 0;
    unsigned short in_uint16 = 32000, out_uint16 = 0;
    int in_int32 = 100000000, out_int32 = 0;
    unsigned int in_uint32 = 200000000, out_uint32 = 0;
    long long in_int64 = 1000000000000LL, out_int64 = 0;
    unsigned long long in_uint64 = 2000000000000LL, out_uint64 = 0;
    double in_double = 3.14159265359, out_double = 0;;
    const char *in_string = "Hello World";
    char *out_string = NULL;
    const char *in_objectpath = "/org/libvirt/test";
    char *out_objectpath = NULL;
    const char *in_signature = "ybnqiuxtdsog";
    char *out_signature = NULL;

    if (!(msg = dbus_message_new_method_call("org.libvirt.test",
                                             "/org/libvirt/test",
                                             "org.libvirt.test.astrochicken",
                                             "cluck"))) {
        VIR_DEBUG("Failed to allocate method call");
        goto cleanup;
    }

    if (virDBusMessageEncode(msg,
                             "ybnqiuxtdsog",
                             in_byte, in_bool,
                             in_int16, in_uint16,
                             in_int32, in_uint32,
                             in_int64, in_uint64,
                             in_double, in_string,
                             in_objectpath, in_signature) < 0) {
        VIR_DEBUG("Failed to encode arguments");
        goto cleanup;
    }

    if (virDBusMessageDecode(msg,
                             "ybnqiuxtdsog",
                             &out_byte, &out_bool,
                             &out_int16, &out_uint16,
                             &out_int32, &out_uint32,
                             &out_int64, &out_uint64,
                             &out_double, &out_string,
                             &out_objectpath, &out_signature) < 0) {
        VIR_DEBUG("Failed to decode arguments");
        goto cleanup;
    }

    VERIFY("byte", in_byte, out_byte, "%d");
    VERIFY("bool", in_bool, out_bool, "%d");
    VERIFY("int16", in_int16, out_int16, "%d");
    VERIFY("uint16", in_int16, out_int16, "%d");
    VERIFY("int32", in_int32, out_int32, "%d");
    VERIFY("uint32", in_int32, out_int32, "%d");
    VERIFY("int64", in_int64, out_int64, "%lld");
    VERIFY("uint64", in_int64, out_int64, "%lld");
    VERIFY("double", in_double, out_double, "%lf");
    VERIFY_STR("string", in_string, out_string, "%s");
    VERIFY_STR("objectpath", in_objectpath, out_objectpath, "%s");
    VERIFY_STR("signature", in_signature, out_signature, "%s");

    ret = 0;

 cleanup:
    VIR_FREE(out_string);
    VIR_FREE(out_signature);
    VIR_FREE(out_objectpath);
    dbus_message_unref(msg);
    return ret;
}


static int testMessageVariant(const void *args ATTRIBUTE_UNUSED)
{
    DBusMessage *msg = NULL;
    int ret = -1;
    const char *in_str1 = "Hello";
    int in_int32 = 100000000, out_int32 = 0;
    const char *in_str2 = "World";
    char *out_str1 = NULL, *out_str2 = NULL;

    if (!(msg = dbus_message_new_method_call("org.libvirt.test",
                                             "/org/libvirt/test",
                                             "org.libvirt.test.astrochicken",
                                             "cluck"))) {
        VIR_DEBUG("Failed to allocate method call");
        goto cleanup;
    }

    if (virDBusMessageEncode(msg,
                             "svs",
                             in_str1,
                             "i", in_int32,
                             in_str2) < 0) {
        VIR_DEBUG("Failed to encode arguments");
        goto cleanup;
    }

    if (virDBusMessageDecode(msg,
                             "svs",
                             &out_str1,
                             "i", &out_int32,
                             &out_str2) < 0) {
        VIR_DEBUG("Failed to decode arguments");
        goto cleanup;
    }


    VERIFY_STR("str1", in_str1, out_str1, "%s");
    VERIFY("int32", in_int32, out_int32, "%d");
    VERIFY_STR("str2", in_str2, out_str2, "%s");

    ret = 0;

 cleanup:
    VIR_FREE(out_str1);
    VIR_FREE(out_str2);
    dbus_message_unref(msg);
    return ret;
}

static int testMessageArray(const void *args ATTRIBUTE_UNUSED)
{
    DBusMessage *msg = NULL;
    int ret = -1;
    const char *in_str1 = "Hello";
    int in_int32a = 1000000000, out_int32a = 0;
    int in_int32b = 2000000000, out_int32b = 0;
    int in_int32c = -2000000000, out_int32c = 0;
    const char *in_str2 = "World";
    char *out_str1 = NULL, *out_str2 = NULL;

    if (!(msg = dbus_message_new_method_call("org.libvirt.test",
                                             "/org/libvirt/test",
                                             "org.libvirt.test.astrochicken",
                                             "cluck"))) {
        VIR_DEBUG("Failed to allocate method call");
        goto cleanup;
    }

    if (virDBusMessageEncode(msg,
                             "sais",
                             in_str1,
                             3, in_int32a, in_int32b, in_int32c,
                             in_str2) < 0) {
        VIR_DEBUG("Failed to encode arguments");
        goto cleanup;
    }

    if (virDBusMessageDecode(msg,
                             "sais",
                             &out_str1,
                             3, &out_int32a, &out_int32b, &out_int32c,
                             &out_str2) < 0) {
        VIR_DEBUG("Failed to decode arguments");
        goto cleanup;
    }


    VERIFY_STR("str1", in_str1, out_str1, "%s");
    VERIFY("int32a", in_int32a, out_int32a, "%d");
    VERIFY("int32b", in_int32b, out_int32b, "%d");
    VERIFY("int32c", in_int32c, out_int32c, "%d");
    VERIFY_STR("str2", in_str2, out_str2, "%s");

    ret = 0;

 cleanup:
    VIR_FREE(out_str1);
    VIR_FREE(out_str2);
    dbus_message_unref(msg);
    return ret;
}

static int testMessageArrayRef(const void *args ATTRIBUTE_UNUSED)
{
    DBusMessage *msg = NULL;
    int ret = -1;
    const char *in_str1 = "Hello";
    int in_int32[] = {
        100000000, 2000000000, -2000000000
    };
    const char *in_strv1[] = {
        "Fishfood",
    };
    const char *in_strv2[] = {
        "Hello", "World",
    };
    int *out_int32 = NULL;
    size_t out_nint32 = 0;
    char **out_strv1 = NULL;
    char **out_strv2 = NULL;
    size_t out_nstrv1 = 0;
    size_t out_nstrv2 = 0;
    const char *in_str2 = "World";
    char *out_str1 = NULL, *out_str2 = NULL;

    if (!(msg = dbus_message_new_method_call("org.libvirt.test",
                                             "/org/libvirt/test",
                                             "org.libvirt.test.astrochicken",
                                             "cluck"))) {
        VIR_DEBUG("Failed to allocate method call");
        goto cleanup;
    }

    if (virDBusMessageEncode(msg,
                             "sa&sa&ia&ss",
                             in_str1,
                             1, in_strv1,
                             3, in_int32,
                             2, in_strv2,
                             in_str2) < 0) {
        VIR_DEBUG("Failed to encode arguments");
        goto cleanup;
    }

    if (virDBusMessageDecode(msg,
                             "sa&sa&ia&ss",
                             &out_str1,
                             &out_nstrv1, &out_strv1,
                             &out_nint32, &out_int32,
                             &out_nstrv2, &out_strv2,
                             &out_str2) < 0) {
        VIR_DEBUG("Failed to decode arguments");
        goto cleanup;
    }


    VERIFY_STR("str1", in_str1, out_str1, "%s");
    if (out_nstrv1 != 1) {
        fprintf(stderr, "Expected 1 string, but got %zu\n",
                out_nstrv1);
        goto cleanup;
    }
    VERIFY_STR("strv1[0]", in_strv1[0], out_strv1[0], "%s");

    if (out_nint32 != 3) {
        fprintf(stderr, "Expected 3 integers, but got %zu\n",
                out_nint32);
        goto cleanup;
    }
    VERIFY("int32a", in_int32[0], out_int32[0], "%d");
    VERIFY("int32b", in_int32[1], out_int32[1], "%d");
    VERIFY("int32c", in_int32[2], out_int32[2], "%d");

    if (out_nstrv2 != 2) {
        fprintf(stderr, "Expected 2 strings, but got %zu\n",
                out_nstrv2);
        goto cleanup;
    }
    VERIFY_STR("strv2[0]", in_strv2[0], out_strv2[0], "%s");
    VERIFY_STR("strv2[1]", in_strv2[1], out_strv2[1], "%s");

    VERIFY_STR("str2", in_str2, out_str2, "%s");

    ret = 0;

 cleanup:
    VIR_FREE(out_int32);
    VIR_FREE(out_str1);
    VIR_FREE(out_str2);
    dbus_message_unref(msg);
    return ret;
}

static int testMessageStruct(const void *args ATTRIBUTE_UNUSED)
{
    DBusMessage *msg = NULL;
    int ret = -1;
    unsigned char in_byte = 200, out_byte = 0;
    int in_bool = true, out_bool = false;
    short in_int16 = 12000, out_int16 = 0;
    unsigned short in_uint16 = 32000, out_uint16 = 0;
    int in_int32 = 100000000, out_int32 = 0;
    unsigned int in_uint32 = 200000000, out_uint32 = 0;
    long long in_int64 = -1000000000000LL, out_int64 = 0;
    unsigned long long in_uint64 = 2000000000000LL, out_uint64 = 0;
    double in_double = 3.14159265359, out_double = 0;;
    const char *in_string = "Hello World";
    char *out_string = NULL;
    const char *in_objectpath = "/org/libvirt/test";
    char *out_objectpath = NULL;
    const char *in_signature = "ybnqiuxtdsog";
    char *out_signature = NULL;

    if (!(msg = dbus_message_new_method_call("org.libvirt.test",
                                             "/org/libvirt/test",
                                             "org.libvirt.test.astrochicken",
                                             "cluck"))) {
        VIR_DEBUG("Failed to allocate method call");
        goto cleanup;
    }

    if (virDBusMessageEncode(msg,
                             "ybn(qiuxtds)og",
                             in_byte, in_bool,
                             in_int16, in_uint16,
                             in_int32, in_uint32,
                             in_int64, in_uint64,
                             in_double, in_string,
                             in_objectpath, in_signature) < 0) {
        VIR_DEBUG("Failed to encode arguments");
        goto cleanup;
    }

    if (virDBusMessageDecode(msg,
                             "ybn(qiuxtds)og",
                             &out_byte, &out_bool,
                             &out_int16, &out_uint16,
                             &out_int32, &out_uint32,
                             &out_int64, &out_uint64,
                             &out_double, &out_string,
                             &out_objectpath, &out_signature) < 0) {
        VIR_DEBUG("Failed to decode arguments");
        goto cleanup;
    }

    VERIFY("byte", in_byte, out_byte, "%d");
    VERIFY("bool", in_bool, out_bool, "%d");
    VERIFY("int16", in_int16, out_int16, "%d");
    VERIFY("uint16", in_int16, out_int16, "%d");
    VERIFY("int32", in_int32, out_int32, "%d");
    VERIFY("uint32", in_int32, out_int32, "%d");
    VERIFY("int64", in_int64, out_int64, "%lld");
    VERIFY("uint64", in_int64, out_int64, "%lld");
    VERIFY("double", in_double, out_double, "%lf");
    VERIFY_STR("string", in_string, out_string, "%s");
    VERIFY_STR("objectpath", in_objectpath, out_objectpath, "%s");
    VERIFY_STR("signature", in_signature, out_signature, "%s");

    ret = 0;

 cleanup:
    VIR_FREE(out_string);
    VIR_FREE(out_signature);
    VIR_FREE(out_objectpath);
    dbus_message_unref(msg);
    return ret;
}


static int testMessageDict(const void *args ATTRIBUTE_UNUSED)
{
    DBusMessage *msg = NULL;
    int ret = -1;
    const char *in_str1 = "Hello";
    int in_int32a = 100000000, out_int32a = 0;
    const char *in_key1 = "turnover";
    int in_int32b = 200000000, out_int32b = 0;
    const char *in_key2 = "revenue";
    int in_int32c = 300000000, out_int32c = 0;
    const char *in_key3 = "debt";
    const char *in_str2 = "World";
    char *out_str1 = NULL, *out_str2 = NULL;
    char *out_key1 = NULL, *out_key2 = NULL, *out_key3 = NULL;

    if (!(msg = dbus_message_new_method_call("org.libvirt.test",
                                             "/org/libvirt/test",
                                             "org.libvirt.test.astrochicken",
                                             "cluck"))) {
        VIR_DEBUG("Failed to allocate method call");
        goto cleanup;
    }

    if (virDBusMessageEncode(msg,
                             "sa{si}s",
                             in_str1,
                             3,
                             in_key1, in_int32a,
                             in_key2, in_int32b,
                             in_key3, in_int32c,
                             in_str2) < 0) {
        VIR_DEBUG("Failed to encode arguments");
        goto cleanup;
    }

    if (virDBusMessageDecode(msg,
                             "sa{si}s",
                             &out_str1,
                             3,
                             &out_key1, &out_int32a,
                             &out_key2, &out_int32b,
                             &out_key3, &out_int32c,
                             &out_str2) < 0) {
        VIR_DEBUG("Failed to decode arguments");
        goto cleanup;
    }


    VERIFY_STR("str1", in_str1, out_str1, "%s");
    VERIFY("int32a", in_int32a, out_int32a, "%d");
    VERIFY("int32b", in_int32b, out_int32b, "%d");
    VERIFY("int32c", in_int32c, out_int32c, "%d");
    VERIFY_STR("key1", in_key1, out_key1, "%s");
    VERIFY_STR("key1", in_key2, out_key2, "%s");
    VERIFY_STR("key1", in_key3, out_key3, "%s");
    VERIFY_STR("str2", in_str2, out_str2, "%s");

    ret = 0;

 cleanup:
    VIR_FREE(out_str1);
    VIR_FREE(out_str2);
    VIR_FREE(out_key1);
    VIR_FREE(out_key2);
    VIR_FREE(out_key3);
    dbus_message_unref(msg);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if (virtTestRun("Test message simple ", testMessageSimple, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test message variant ", testMessageVariant, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test message array ", testMessageArray, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test message array ref ", testMessageArrayRef, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test message struct ", testMessageStruct, NULL) < 0)
        ret = -1;
    if (virtTestRun("Test message dict ", testMessageDict, NULL) < 0)
        ret = -1;
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
