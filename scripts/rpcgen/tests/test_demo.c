#include <glib.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <stdbool.h>

#ifdef __APPLE__
# define xdr_uint64_t xdr_u_int64_t
#endif

#include "demo.h"
#include "demo.c"

static void test_xdr(xdrproc_t proc, void *vorig, void *vnew, const char *testname, bool fail)
{
    XDR xdr;
    /* 128kb is big enough for any of our test data */
    size_t buflen = 128 * 1000;
    g_autofree char *buf = g_new0(char, buflen);
    g_autofree char *expfile = g_strdup_printf(abs_srcdir "/test_demo_%s.bin", testname);
    g_autofree char *expected = NULL;
    size_t explen;
    size_t actlen;
    g_autoptr(GError) err = NULL;
    bool_t ret;

    /* Step 1:  serialize the vorig and compare to the data in test .bin files */
    xdrmem_create(&xdr, buf, buflen, XDR_ENCODE);

    ret = !!proc(&xdr, vorig, 0);
    g_assert_cmpint(ret, ==, !fail);

    if (fail)
        goto cleanup;

    actlen = xdr_getpos(&xdr);

    if (getenv("VIR_TEST_REGENERATE_OUTPUT")) {
        g_file_set_contents(expfile, buf, actlen, NULL);
    }

    g_file_get_contents(expfile, &expected, &explen, &err);
    if (err != NULL) {
        g_printerr("%s\n", err->message);
        abort();
    }

    g_assert_cmpint(explen, ==, actlen);

    g_assert_cmpint(memcmp(buf, expected, actlen), ==, 0);

    xdr_destroy(&xdr);

    /* Step 2: de-serialize the state to create a new object */
    xdrmem_create(&xdr, buf, buflen, XDR_DECODE);

    ret = !!proc(&xdr, vnew, 0);
    g_assert_cmpint(ret, ==, true);

    actlen = xdr_getpos(&xdr);
    g_assert_cmpint(explen, ==, actlen);

    xdr_destroy(&xdr);

    /* Step 3: serialize the new object again to prove we
     * round-tripped the original object */
    memset(buf, 0, buflen);

    xdrmem_create(&xdr, buf, buflen, XDR_ENCODE);

    ret = !!proc(&xdr, vnew, 0);
    g_assert_cmpint(ret, ==, true);

    actlen = xdr_getpos(&xdr);

    g_assert_cmpint(explen, ==, actlen);

    g_assert_cmpint(memcmp(buf, expected, actlen), ==, 0);
    xdr_destroy(&xdr);

 cleanup:
    xdr_destroy(&xdr);
}

static void test_enum(void)
{
    TestEnum vorig = TEST_ENUM_TWO;
    TestEnum vnew = 0;

    test_xdr((xdrproc_t)xdr_TestEnum, &vorig, &vnew, "enum", false);
}

static void test_struct(void)
{
    TestStruct vorig = {
        .c1 = 'a', .c2 = 'b',
    };
    g_auto(TestStruct) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestStruct, &vorig, &vnew, "struct", false);
}

static void test_union_case(void)
{
    TestUnion vorig = {
        .type = 20, .TestUnion_u = { .i1 = 1729 },
    };
    g_auto(TestUnion) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestUnion, &vorig, &vnew, "union_case", false);
}

static void test_union_default(void)
{
    TestUnion vorig = {
        .type = 87539319, .TestUnion_u = { .i3 = 1729 },
    };
    g_auto(TestUnion) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestUnion, &vorig, &vnew, "union_default", false);
}

static void test_union_void_default_case(void)
{
    TestUnionVoidDefault vorig = {
        .type = 21, .TestUnionVoidDefault_u = { .i1 = 1729 },
    };
    g_auto(TestUnionVoidDefault) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestUnionVoidDefault, &vorig, &vnew, "union_void_default_case", false);
}

static void test_union_void_default_default(void)
{
    TestUnionVoidDefault vorig = {
        .type = 87539319
    };
    g_auto(TestUnionVoidDefault) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestUnionVoidDefault, &vorig, &vnew, "union_void_default_default", false);
}

static void test_union_no_default_case(void)
{
    TestUnionNoDefault vorig = {
        .type = 22, .TestUnionNoDefault_u = { .i1 = 1729 },
    };
    g_auto(TestUnionNoDefault) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestUnionNoDefault, &vorig, &vnew, "union_no_default_case", false);
}

static void test_union_no_default_default(void)
{
    TestUnionNoDefault vorig = {
        .type = 87539319,
    };
    g_auto(TestUnionNoDefault) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestUnionNoDefault, &vorig, &vnew, "union_no_default_default", true);
}

static void test_int_scalar(void)
{
    TestIntScalar vorig = 1729;
    g_auto(TestIntScalar) vnew = 0;

    test_xdr((xdrproc_t)xdr_TestIntScalar, &vorig, &vnew, "int_scalar", false);
}

static void test_int_pointer_set(void)
{
    int vorigp = 1729;
    TestIntPointer vorig = &vorigp;
    g_auto(TestIntPointer) vnew = NULL;

    test_xdr((xdrproc_t)xdr_TestIntPointer, &vorig, &vnew, "int_pointer_set", false);
}

static void test_int_pointer_null(void)
{
    TestIntPointer vorig = NULL;
    g_auto(TestIntPointer) vnew = NULL;

    test_xdr((xdrproc_t)xdr_TestIntPointer, &vorig, &vnew, "int_pointer_null", false);
}

static void test_int_fixed_array(void)
{
    TestIntFixedArray vorig = { 1729, 0, 87539319 };
    g_auto(TestIntFixedArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestIntFixedArray,
             vorig, vnew, "int_fixed_array", false);
}

static void test_int_variable_array_set(void)
{
    TestIntVariableArray vorig = {
        .TestIntVariableArray_len = 3,
        .TestIntVariableArray_val = (int[]) { 1729, 0, 87539319 }
    };
    g_auto(TestIntVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestIntVariableArray,
             &vorig, &vnew, "int_variable_array_set", false);
}

static void test_int_variable_array_overflow(void)
{
    TestIntVariableArray vorig = {
        .TestIntVariableArray_len = 6,
        .TestIntVariableArray_val = (int[]) { 1729, 0, 87539319, 0, 1729 }
    };
    g_auto(TestIntVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestIntVariableArray,
             &vorig, &vnew, "int_variable_array_overflow", true);
}

static void test_int_variable_array_empty(void)
{
    TestIntVariableArray vorig = {
        .TestIntVariableArray_len = 0,
        .TestIntVariableArray_val = (int[]) {0},
    };
    g_auto(TestIntVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestIntVariableArray,
             &vorig, &vnew, "int_variable_array_empty", false);
}

static void test_string_variable_array_set(void)
{
    TestStringVariableArray vorig = (TestStringVariableArray) "taxis";
    g_auto(TestStringVariableArray) vnew = NULL;

    test_xdr((xdrproc_t)xdr_TestStringVariableArray,
             &vorig, &vnew, "string_variable_array_set", false);
}

static void test_string_variable_array_empty(void)
{
    TestStringVariableArray vorig = (TestStringVariableArray)"";
    g_auto(TestStringVariableArray) vnew = NULL;

    test_xdr((xdrproc_t)xdr_TestStringVariableArray,
             &vorig, &vnew, "string_variable_array_empty", false);
}

static void test_opaque_fixed_array(void)
{
    TestOpaqueFixedArray vorig = { 0xca, 0xfe, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78 };
    g_auto(TestOpaqueFixedArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestOpaqueFixedArray, vorig, vnew, "opaque_fixed_array", false);
}

static void test_opaque_variable_array_set(void)
{
    TestOpaqueVariableArray vorig = {
        .TestOpaqueVariableArray_len = 3,
        .TestOpaqueVariableArray_val = (char[]) { 0xca, 0xfe, 0x12 },
    };
    g_auto(TestOpaqueVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestOpaqueVariableArray,
             &vorig, &vnew, "opaque_variable_array_set", false);
}

static void test_opaque_variable_array_overflow(void)
{
    TestOpaqueVariableArray vorig = {
        .TestOpaqueVariableArray_len = 12,
        .TestOpaqueVariableArray_val = (char[]) {
            0xca, 0xfe, 0x12, 0xca, 0xfe, 0x12,
            0xca, 0xfe, 0x12, 0xca, 0xfe, 0x12,
        },
    };
    g_auto(TestOpaqueVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestOpaqueVariableArray,
             &vorig, &vnew, "opaque_variable_array_overflow", true);
}

static void test_opaque_variable_array_empty(void)
{
    TestOpaqueVariableArray vorig = {
        .TestOpaqueVariableArray_len = 0,
        .TestOpaqueVariableArray_val = (char[]) {0},
    };
    g_auto(TestOpaqueVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestOpaqueVariableArray,
             &vorig, &vnew, "opaque_variable_array_empty", false);
}

static void test_enum_scalar(void)
{
    TestEnumScalar vorig = TEST_ENUM_TWO;
    g_auto(TestEnumScalar) vnew = 0;

    test_xdr((xdrproc_t)xdr_TestEnumScalar,
             &vorig, &vnew, "enum_scalar", false);
}

static void test_enum_pointer_set(void)
{
    TestEnum vorigp = TEST_ENUM_TWO;
    TestEnumPointer vorig = &vorigp;
    g_auto(TestEnumPointer) vnew = NULL;

    test_xdr((xdrproc_t)xdr_TestEnumPointer,
             &vorig, &vnew, "enum_pointer_set", false);
}

static void test_enum_pointer_null(void)
{
    TestEnumPointer vorig = NULL;
    g_auto(TestEnumPointer) vnew = NULL;

    test_xdr((xdrproc_t)xdr_TestEnumPointer,
             &vorig, &vnew, "enum_pointer_null", false);
}

static void test_enum_fixed_array(void)
{
    TestEnumFixedArray vorig = {
        TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
        TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
        TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE
    };
    g_auto(TestEnumFixedArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestEnumFixedArray, vorig, vnew, "enum_fixed_array", false);
}

static void test_enum_variable_array_set(void)
{
    TestEnumVariableArray vorig = {
        .TestEnumVariableArray_len = 3,
        .TestEnumVariableArray_val = (TestEnum[]) {
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE,
        },
    };
    g_auto(TestEnumVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestEnumVariableArray,
             &vorig, &vnew, "enum_variable_array_set", false);
}

static void test_enum_variable_array_overflow(void)
{
    TestEnumVariableArray vorig = {
        .TestEnumVariableArray_len = 16,
        .TestEnumVariableArray_val = (TestEnum[]) {
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
        }
    };
    g_auto(TestEnumVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestEnumVariableArray,
             &vorig, &vnew, "enum_variable_array_overflow", true);
}

static void test_enum_variable_array_empty(void)
{
    TestEnumVariableArray vorig = {
        .TestEnumVariableArray_len = 0,
        .TestEnumVariableArray_val = (TestEnum[]) {0},
    };
    g_auto(TestEnumVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestEnumVariableArray,
             &vorig, &vnew, "enum_variable_array_empty", false);
}

#define TEST_STRUCT_INIT (TestStruct) { .c1 = 0x4a, .c2 = 0x7e }
#define TEST_STRUCT_INIT_ALT (TestStruct) { .c1 = 0x09, .c2 = 0x07 }

static void test_struct_scalar(void)
{
    TestStructScalar vorig = TEST_STRUCT_INIT;
    g_auto(TestStructScalar) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestStructScalar,
             &vorig, &vnew, "struct_scalar", false);
}

static void test_struct_pointer_set(void)
{
    TestStruct vorigp = TEST_STRUCT_INIT;
    TestStructPointer vorig = &vorigp;
    g_auto(TestStructPointer) vnew = NULL;

    test_xdr((xdrproc_t)xdr_TestStructPointer,
             &vorig, &vnew, "struct_pointer_set", false);
}

static void test_struct_pointer_null(void)
{
    TestStructPointer vorig = NULL;
    g_auto(TestStructPointer) vnew = NULL;

    test_xdr((xdrproc_t)xdr_TestStructPointer,
             &vorig, &vnew, "struct_pointer_null", false);
}

static void test_struct_fixed_array(void)
{
    TestStructFixedArray vorig = {
        TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT,
        TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT,
        TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
        TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
        TEST_STRUCT_INIT_ALT
    };
    g_auto(TestStructFixedArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestStructFixedArray, vorig, vnew, "struct_fixed_array", false);
}

static void test_struct_variable_array_set(void)
{
    TestStructVariableArray vorig = {
        .TestStructVariableArray_len = 3,
        .TestStructVariableArray_val = (TestStruct[]) {
            TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT_ALT,
        },
    };
    g_auto(TestStructVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestStructVariableArray,
             &vorig, &vnew, "struct_variable_array_set", false);
}

static void test_struct_variable_array_overflow(void)
{
    TestStructVariableArray vorig = {
        .TestStructVariableArray_len = 20,
        .TestStructVariableArray_val = (TestStruct[]) {
            TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
        }
    };
    g_auto(TestStructVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestStructVariableArray,
             &vorig, &vnew, "struct_variable_array_overflow", true);
}

static void test_struct_variable_array_empty(void)
{
    TestStructVariableArray vorig = {
        .TestStructVariableArray_len = 0,
        .TestStructVariableArray_val = (TestStruct[]) {},
    };
    g_auto(TestStructVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestStructVariableArray,
             &vorig, &vnew, "struct_variable_array_empty", false);
}

#define TEST_UNION_INIT (TestUnion) { .type = 20, .TestUnion_u = { .i1 = 1729 } }
#define TEST_UNION_INIT_ALT (TestUnion) { .type = 1729, .TestUnion_u = { .i3 = 87539319 } }

static void test_union_scalar(void)
{
    TestUnionScalar vorig = TEST_UNION_INIT;
    g_auto(TestUnionScalar) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestUnionScalar,
             &vorig, &vnew, "union_scalar", false);
}

static void test_union_pointer_set(void)
{
    TestUnion vorigp = TEST_UNION_INIT;
    TestUnionPointer vorig = &vorigp;
    g_auto(TestUnionPointer) vnew = NULL;

    test_xdr((xdrproc_t)xdr_TestUnionPointer,
             &vorig, &vnew, "union_pointer_set", false);
}

static void test_union_pointer_null(void)
{
    TestUnionPointer vorig = NULL;
    g_auto(TestUnionPointer) vnew = NULL;

    test_xdr((xdrproc_t)xdr_TestUnionPointer,
             &vorig, &vnew, "union_pointer_null", false);
}

static void test_union_fixed_array(void)
{
    TestUnionFixedArray vorig = {
        TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT_ALT,
        TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT,
        TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT,
        TEST_UNION_INIT_ALT, TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT,
        TEST_UNION_INIT_ALT
    };
    g_auto(TestUnionFixedArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestUnionFixedArray, vorig, vnew, "union_fixed_array", false);
}

static void test_union_variable_array_set(void)
{
    TestUnionVariableArray vorig = {
        .TestUnionVariableArray_len = 3,
        .TestUnionVariableArray_val = (TestUnion[]) {
            TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT_ALT,
        },
    };
    g_auto(TestUnionVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestUnionVariableArray,
             &vorig, &vnew, "union_variable_array_set", false);
}

static void test_union_variable_array_overflow(void)
{
    TestUnionVariableArray vorig = {
        .TestUnionVariableArray_len = 24,
        .TestUnionVariableArray_val = (TestUnion[]) {
            TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT,
        }
    };
    g_auto(TestUnionVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestUnionVariableArray,
             &vorig, &vnew, "union_variable_array_overflow", true);
}

static void test_union_variable_array_empty(void)
{
    TestUnionVariableArray vorig = {
        .TestUnionVariableArray_len = 0,
        .TestUnionVariableArray_val = (TestUnion[]) {},
    };
    g_auto(TestUnionVariableArray) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestUnionVariableArray,
             &vorig, &vnew, "union_variable_array_empty", false);
}

static void test_struct_all_types(void)
{
    int ip = 1729;
    TestEnum ep = TEST_ENUM_TWO;
    TestStruct sp = TEST_STRUCT_INIT;
    TestUnion up = TEST_UNION_INIT;
    TestStructAllTypes vorig = {
        .sc = 'x',
        .suc = 'y',
        .ss = -7,
        .sus = 14,
        .si = -1729,
        .sui = 1729,
        .sh = -87539319,
        .suh = -87539319,
        .sb = true,
        .sf = 0.1729,
        .sd = 8753.9319,
        .ip = &ip,
        .ifa = { 1, 2, 3 },
        .iva = {
            .iva_len = 3,
            .iva_val = (int[]) { 7, 8, 9 },
        },
        .stva = (char *)"hello",
        .ofa = {
            0x1, 0x2, 0x3, 0xff, 0xff, 0xff, 0xff, 0x1,
            0x1, 0x2, 0x3, 0xff, 0xff, 0xff, 0xff, 0x1,
            0x1, 0x2, 0x3, 0xff, 0xff, 0xff, 0xff, 0x1,
            0x1, 0x2, 0x3, 0xff, 0xff, 0xff, 0xff, 0x1,
            0xff,
        },
        .ova = {
            .ova_len = 3,
            .ova_val = (char[]) { 0x1, 0xca, 0xfe },
        },
        .e1 = TEST_ENUM_ONE,
        .e2 = TEST_ENUM_TWO,
        .ep = &ep,
        .efa = {
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE,
        },
        .eva = {
            .eva_len = 3,
            .eva_val = (TestEnum[]) {
                TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            },
        },
        .s = TEST_STRUCT_INIT,
        .sp = &sp,
        .sfa = {
            TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT,
            TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT,
            TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT,
            TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT,
        },
        .sva = {
            .sva_len = 3,
            .sva_val = (TestStruct[]) {
                TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT,
            },
        },
        .u = TEST_UNION_INIT,
        .up = &up,
        .ufa = {
            TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT_ALT,
            TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT_ALT, TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT_ALT,
            TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT_ALT, TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT_ALT,
            TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT_ALT,
        },
        .uva = {
            .uva_len = 3,
            .uva_val = (TestUnion[]) {
                TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT_ALT,
            },
        },
        .tis = 1729,
        .tip = &ip,
        .tifa = { 1, 2, 3 },
        .tiva = {
            .TestIntVariableArray_len = 3,
            .TestIntVariableArray_val = (int[]) { 7, 8, 9 },
        },
        .tstva = (char *)"hello",
        .tofa = {
            0x1, 0x2, 0x3, 0xff, 0xff, 0xff, 0xff, 0x1,
            0xff,
        },
        .tova = {
            .TestOpaqueVariableArray_len = 3,
            .TestOpaqueVariableArray_val = (char[]) { 0x1, 0xca, 0xfe },
        },
        .tes = TEST_ENUM_ONE,
        .tep = &ep,
        .tefa = {
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE, TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            TEST_ENUM_ONE,
        },
        .teva = {
            .TestEnumVariableArray_len = 3,
            .TestEnumVariableArray_val = (TestEnum[]) {
                TEST_ENUM_TWO, TEST_ENUM_ONE, TEST_ENUM_TWO,
            },
        },
        .tss = TEST_STRUCT_INIT,
        .tsp = &sp,
        .tsfa = {
            TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT,
            TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT, TEST_STRUCT_INIT,
            TEST_STRUCT_INIT,
        },
        .tsva = {
            .TestStructVariableArray_len = 3,
            .TestStructVariableArray_val = (TestStruct[]) {
                TEST_STRUCT_INIT, TEST_STRUCT_INIT_ALT, TEST_STRUCT_INIT,
            },
        },
        .tu = TEST_UNION_INIT,
        .tup = &up,
        .tufa = {
            TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT_ALT,
            TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT_ALT, TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT,
            TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT, TEST_UNION_INIT_ALT,
            TEST_UNION_INIT_ALT,
        },
        .tuva = {
            .TestUnionVariableArray_len = 3,
            .TestUnionVariableArray_val = (TestUnion[]) {
                TEST_UNION_INIT, TEST_UNION_INIT_ALT, TEST_UNION_INIT_ALT,
            },
        },
    };
    g_auto(TestStructAllTypes) vnew = {0};

    test_xdr((xdrproc_t)xdr_TestStructAllTypes,
             &vorig, &vnew, "test_struct_all_types", false);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_set_nonfatal_assertions();

    g_test_add_func("/xdr/enum", test_enum);

    g_test_add_func("/xdr/struct", test_struct);

    g_test_add_func("/xdr/union/case", test_union_case);
    g_test_add_func("/xdr/union/default", test_union_default);
    g_test_add_func("/xdr/union-void-default/case", test_union_void_default_case);
    g_test_add_func("/xdr/union-void-default/default", test_union_void_default_default);
    g_test_add_func("/xdr/union-no-default/case", test_union_no_default_case);
    g_test_add_func("/xdr/union-no-default/default", test_union_no_default_default);

    g_test_add_func("/xdr/int-scalar", test_int_scalar);
    g_test_add_func("/xdr/int-pointer/set", test_int_pointer_set);
    g_test_add_func("/xdr/int-pointer/null", test_int_pointer_null);
    g_test_add_func("/xdr/int-fixed-array", test_int_fixed_array);
    g_test_add_func("/xdr/int-variable-array/set", test_int_variable_array_set);
    g_test_add_func("/xdr/int-variable-array/overflow", test_int_variable_array_overflow);
    g_test_add_func("/xdr/int-variable-array/empty", test_int_variable_array_empty);

    g_test_add_func("/xdr/string-variable-array/set", test_string_variable_array_set);
    g_test_add_func("/xdr/string-variable-array/empty", test_string_variable_array_empty);

    g_test_add_func("/xdr/opaque-fixed-array", test_opaque_fixed_array);
    g_test_add_func("/xdr/opaque-variable-array/set", test_opaque_variable_array_set);
    g_test_add_func("/xdr/opaque-variable-array/overflow", test_opaque_variable_array_overflow);
    g_test_add_func("/xdr/opaque-variable-array/empty", test_opaque_variable_array_empty);

    g_test_add_func("/xdr/enum-scalar", test_enum_scalar);
    g_test_add_func("/xdr/enum-pointer/set", test_enum_pointer_set);
    g_test_add_func("/xdr/enum-pointer/null", test_enum_pointer_null);
    g_test_add_func("/xdr/enum-fixed-array", test_enum_fixed_array);
    g_test_add_func("/xdr/enum-variable-array/set", test_enum_variable_array_set);
    g_test_add_func("/xdr/enum-variable-array/overflow", test_enum_variable_array_overflow);
    g_test_add_func("/xdr/enum-variable-array/empty", test_enum_variable_array_empty);

    g_test_add_func("/xdr/struct-scalar", test_struct_scalar);
    g_test_add_func("/xdr/struct-pointer/set", test_struct_pointer_set);
    g_test_add_func("/xdr/struct-pointer/null", test_struct_pointer_null);
    g_test_add_func("/xdr/struct-fixed-array", test_struct_fixed_array);
    g_test_add_func("/xdr/struct-variable-array/set", test_struct_variable_array_set);
    g_test_add_func("/xdr/struct-variable-array/overflow", test_struct_variable_array_overflow);
    g_test_add_func("/xdr/struct-variable-array/empty", test_struct_variable_array_empty);

    g_test_add_func("/xdr/union-scalar", test_union_scalar);
    g_test_add_func("/xdr/union-pointer/set", test_union_pointer_set);
    g_test_add_func("/xdr/union-pointer/null", test_union_pointer_null);
    g_test_add_func("/xdr/union-fixed-array", test_union_fixed_array);
    g_test_add_func("/xdr/union-variable-array/set", test_union_variable_array_set);
    g_test_add_func("/xdr/union-variable-array/overflow", test_union_variable_array_overflow);
    g_test_add_func("/xdr/union-variable-array/empty", test_union_variable_array_empty);

    g_test_add_func("/xdr/struct-all-types", test_struct_all_types);

    return g_test_run();
}
