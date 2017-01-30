/*
 * virbitmaptest.c: Test the bitmap code
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright (C) 2012 Fujitsu.
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

#include "testutils.h"

#include "virbitmap.h"

static int
test1(const void *data ATTRIBUTE_UNUSED)
{
    virBitmapPtr bitmap;
    int size;
    int bit;
    bool result;
    int ret = -1;

    size = 1024;
    bit = 100;
    if (!(bitmap = virBitmapNew(size)))
        goto error;

    if (virBitmapSetBit(bitmap, bit) < 0)
        goto error;

    if (virBitmapGetBit(bitmap, bit, &result) < 0)
        goto error;

    if (!result)
        goto error;

    if (virBitmapGetBit(bitmap, bit + 1, &result) < 0)
        goto error;

    if (result)
        goto error;

    ret = 0;

 error:
    virBitmapFree(bitmap);
    return ret;
}

static int
testBit(virBitmapPtr bitmap,
        unsigned int start,
        unsigned int end,
        bool expected)
{
    size_t i;
    bool result;

    for (i = start; i <= end; i++) {
        if (virBitmapGetBit(bitmap, i, &result) < 0)
            return -1;
        if (result != expected)
            return -1;
    }

    return 0;
}

static int
test2(const void *data ATTRIBUTE_UNUSED)
{
    const char *bitsString1 = "1-32,50,88-99,1021-1023";
    char *bitsString2 = NULL;
    virBitmapPtr bitmap = NULL;
    int ret = -1;
    int size = 1025;

    if (virBitmapParse(bitsString1, &bitmap, size) < 0)
        goto error;

    if (testBit(bitmap, 1, 32, true) < 0)
        goto error;
    if (testBit(bitmap, 50, 50, true) < 0)
        goto error;
    if (testBit(bitmap, 88, 99, true) < 0)
        goto error;
    if (testBit(bitmap, 1021, 1023, true) < 0)
        goto error;

    if (testBit(bitmap, 0, 0, false) < 0)
        goto error;
    if (testBit(bitmap, 33, 49, false) < 0)
        goto error;
    if (testBit(bitmap, 51, 87, false) < 0)
        goto error;
    if (testBit(bitmap, 100, 1020, false) < 0)
        goto error;

    if (virBitmapCountBits(bitmap) != 48)
        goto error;

    if (!(bitsString2 = virBitmapFormat(bitmap)))
        goto error;
    if (strcmp(bitsString1, bitsString2))
        goto error;

    virBitmapSetAll(bitmap);
    if (testBit(bitmap, 0, size - 1, true) < 0)
        goto error;
    if (virBitmapCountBits(bitmap) != size)
        goto error;

    if (!virBitmapIsAllSet(bitmap))
        goto error;

    virBitmapClearAll(bitmap);
    if (!virBitmapIsAllClear(bitmap))
        goto error;
    if (testBit(bitmap, 0, size - 1, false) < 0)
        goto error;
    if (virBitmapCountBits(bitmap) != 0)
        goto error;

    ret = 0;

 error:
    virBitmapFree(bitmap);
    VIR_FREE(bitsString2);
    return ret;
}

static int
test3(const void *data ATTRIBUTE_UNUSED)
{
    virBitmapPtr bitmap = NULL;
    int ret = -1;
    int size = 5;
    size_t i;

    if ((bitmap = virBitmapNew(size)) == NULL)
        goto error;

    for (i = 0; i < size; i++)
        ignore_value(virBitmapSetBit(bitmap, i));

    if (!virBitmapIsAllSet(bitmap))
        goto error;

    virBitmapClearAll(bitmap);
    if (!virBitmapIsAllClear(bitmap))
        goto error;
    ret = 0;

 error:
    virBitmapFree(bitmap);
    return ret;
}

/* test for virBitmapNextSetBit, virBitmapLastSetBit, virBitmapNextClearBit */
static int
test4(const void *data ATTRIBUTE_UNUSED)
{
    const char *bitsString = "0, 2-4, 6-10, 12, 14-18, 20, 22, 25";
    int size = 40;
    int bitsPos[] = {
        0,  2,  3,  4,  6,  7,  8,  9, 10, 12,
        14, 15, 16, 17, 18, 20, 22, 25
    };
    int bitsPosInv[] = {
        1, 5, 11, 13, 19, 21, 23, 24, 26, 27,
        28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39
    };
    virBitmapPtr bitmap = NULL;
    ssize_t i, j;

    if (ARRAY_CARDINALITY(bitsPos) + ARRAY_CARDINALITY(bitsPosInv) != size)
        goto error;

    /* 0. empty set */

    if (!(bitmap = virBitmapNewEmpty()))
        goto error;

    if (virBitmapNextSetBit(bitmap, -1) != -1)
        goto error;

    if (virBitmapLastSetBit(bitmap) != -1)
        goto error;

    if (virBitmapNextClearBit(bitmap, -1) != -1)
        goto error;

    virBitmapFree(bitmap);
    bitmap = NULL;

    /* 1. zero set */

    bitmap = virBitmapNew(size);
    if (!bitmap)
        goto error;

    if (virBitmapNextSetBit(bitmap, -1) != -1)
        goto error;

    if (virBitmapLastSetBit(bitmap) != -1)
        goto error;

    for (i = 0; i < size; i++) {
        if (virBitmapNextClearBit(bitmap, i - 1) != i)
            goto error;
    }
    if (virBitmapNextClearBit(bitmap, i) != -1)
        goto error;

    if (!virBitmapIsAllClear(bitmap))
        goto error;

    virBitmapFree(bitmap);
    bitmap = NULL;

    /* 2. partial set */

    if (virBitmapParse(bitsString, &bitmap, size) < 0)
        goto error;
    if (!bitmap)
        goto error;

    j = 0;
    i = -1;

    while (j < ARRAY_CARDINALITY(bitsPos)) {
        i = virBitmapNextSetBit(bitmap, i);
        if (i != bitsPos[j++])
            goto error;
    }

    if (virBitmapNextSetBit(bitmap, i) != -1)
        goto error;

    j = sizeof(bitsPos)/sizeof(int) - 1;

    if (virBitmapLastSetBit(bitmap) != bitsPos[j])
        goto error;

    j = 0;
    i = -1;

    while (j < ARRAY_CARDINALITY(bitsPosInv)) {
        i = virBitmapNextClearBit(bitmap, i);
        if (i != bitsPosInv[j++])
            goto error;
    }

    if (virBitmapNextClearBit(bitmap, i) != -1)
        goto error;

    /* 3. full set */

    virBitmapSetAll(bitmap);

    for (i = 0; i < size; i++) {
        if (virBitmapNextSetBit(bitmap, i - 1) != i)
            goto error;
    }
    if (virBitmapNextSetBit(bitmap, i) != -1)
        goto error;

    if (virBitmapLastSetBit(bitmap) != size - 1)
        goto error;

    if (virBitmapNextClearBit(bitmap, -1) != -1)
        goto error;

    virBitmapFree(bitmap);
    return 0;

 error:
    virBitmapFree(bitmap);
    return -1;
}

/* test for virBitmapNewData/ToData/DataToString */
static int
test5(const void *v ATTRIBUTE_UNUSED)
{
    char data[] = {0x01, 0x02, 0x00, 0x00, 0x04};
    unsigned char *data2 = NULL;
    int len2;
    int bits[] = {0, 9, 34};
    virBitmapPtr bitmap;
    size_t i;
    ssize_t j;
    int ret = -1;
    char *str = NULL;

    bitmap = virBitmapNewData(data, sizeof(data));
    if (!bitmap)
        goto error;

    i = 0;
    j = -1;
    while (i < sizeof(bits)/sizeof(int) &&
           (j = virBitmapNextSetBit(bitmap, j)) >= 0) {
        if (j != bits[i++])
            goto error;
    }
    if (virBitmapNextSetBit(bitmap, j) > 0)
        goto error;

    ignore_value(virBitmapSetBit(bitmap, 2));
    ignore_value(virBitmapSetBit(bitmap, 15));

    if (virBitmapToData(bitmap, &data2, &len2) < 0)
        goto error;

    if (len2 != sizeof(data) ||
        data2[0] != 0x05 ||
        data2[1] != 0x82 ||
        data2[2] != 0x00 ||
        data2[3] != 0x00 ||
        data2[4] != 0x04)
        goto error;

    if (!(str = virBitmapDataToString(data, sizeof(data))))
        goto error;
    if (STRNEQ(str, "0,9,34"))
        goto error;
    VIR_FREE(str);
    if (!(str = virBitmapDataToString(data2, len2)))
        goto error;
    if (STRNEQ(str, "0,2,9,15,34"))
        goto error;

    ret = 0;
 error:
    VIR_FREE(str);
    virBitmapFree(bitmap);
    VIR_FREE(data2);
    return ret;
}


/* test for virBitmapFormat */
static int
test6(const void *v ATTRIBUTE_UNUSED)
{
    virBitmapPtr bitmap = NULL;
    char *str = NULL;
    int size = 64;
    int ret = -1;

    bitmap = virBitmapNew(size);
    if (!bitmap)
        goto error;

    str = virBitmapFormat(bitmap);
    if (!str)
        goto error;

    if (STRNEQ(str, ""))
        goto error;

    VIR_FREE(str);

    ignore_value(virBitmapSetBit(bitmap, 0));
    str = virBitmapFormat(bitmap);
    if (!str)
        goto error;

    if (STRNEQ(str, "0"))
        goto error;

    VIR_FREE(str);

    ignore_value(virBitmapSetBit(bitmap, 4));
    ignore_value(virBitmapSetBit(bitmap, 5));
    str = virBitmapFormat(bitmap);
    if (!str)
        goto error;

    if (STRNEQ(str, "0,4-5"))
        goto error;

    VIR_FREE(str);

    ignore_value(virBitmapSetBit(bitmap, 6));
    str = virBitmapFormat(bitmap);
    if (!str)
        goto error;

    if (STRNEQ(str, "0,4-6"))
        goto error;

    VIR_FREE(str);

    ignore_value(virBitmapSetBit(bitmap, 13));
    ignore_value(virBitmapSetBit(bitmap, 14));
    ignore_value(virBitmapSetBit(bitmap, 15));
    ignore_value(virBitmapSetBit(bitmap, 16));
    str = virBitmapFormat(bitmap);
    if (!str)
        goto error;

    if (STRNEQ(str, "0,4-6,13-16"))
        goto error;

    VIR_FREE(str);

    ignore_value(virBitmapSetBit(bitmap, 62));
    ignore_value(virBitmapSetBit(bitmap, 63));
    str = virBitmapFormat(bitmap);
    if (!str)
        goto error;

    if (STRNEQ(str, "0,4-6,13-16,62-63"))
        goto error;


    ret = 0;
 error:
    virBitmapFree(bitmap);
    VIR_FREE(str);
    return ret;
}

static int
test7(const void *v ATTRIBUTE_UNUSED)
{
    virBitmapPtr bitmap;
    size_t i;
    size_t maxBit[] = {
        1, 8, 31, 32, 63, 64, 95, 96, 127, 128, 159, 160
    };
    size_t nmaxBit = 12;

    for (i = 0; i < nmaxBit; i++) {
        bitmap = virBitmapNew(maxBit[i]);
        if (!bitmap)
            goto error;

        if (virBitmapIsAllSet(bitmap))
            goto error;

        ignore_value(virBitmapSetBit(bitmap, 1));
        if (virBitmapIsAllSet(bitmap))
            goto error;

        virBitmapSetAll(bitmap);
        if (!virBitmapIsAllSet(bitmap))
            goto error;

        virBitmapClearAll(bitmap);
        if (!virBitmapIsAllClear(bitmap))
            goto error;

        virBitmapFree(bitmap);
    }

    return 0;

 error:
    virBitmapFree(bitmap);
    return -1;
}

static int
test8(const void *v ATTRIBUTE_UNUSED)
{
    virBitmapPtr bitmap = NULL;
    char data[108] = {0x00,};
    int ret = -1;

    bitmap = virBitmapNewData(data, sizeof(data));
    if (!bitmap)
        goto cleanup;

    if (!virBitmapIsAllClear(bitmap))
        goto cleanup;

    if (virBitmapSetBit(bitmap, 11) < 0)
        goto cleanup;

    if (virBitmapIsAllClear(bitmap))
        goto cleanup;

    ret = 0;
 cleanup:
    virBitmapFree(bitmap);
    return ret;
}


/* test out of bounds conditions on virBitmapParse */
static int
test9(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    virBitmapPtr bitmap = NULL;

    if (virBitmapParse("100000000", &bitmap, 20) != -1)
        goto cleanup;

    if (bitmap)
        goto cleanup;

    if (virBitmapParse("1-1000000000", &bitmap, 20) != -1)
        goto cleanup;

    if (bitmap)
        goto cleanup;

    if (virBitmapParse("1-10^10000000000", &bitmap, 20) != -1)
        goto cleanup;

    if (bitmap)
        goto cleanup;

    ret = 0;
 cleanup:
    virBitmapFree(bitmap);
    return ret;

}

static int
test10(const void *opaque ATTRIBUTE_UNUSED)
{
    int ret = -1;
    virBitmapPtr b1 = NULL, b2 = NULL, b3 = NULL, b4 = NULL;

    if (virBitmapParseSeparator("0-3,5-8,11-15f16", 'f', &b1, 20) < 0 ||
        virBitmapParse("4,9,10,16-19", &b2, 20) < 0 ||
        virBitmapParse("15", &b3, 20) < 0 ||
        virBitmapParse("0,^0", &b4, 20) < 0)
        goto cleanup;

    if (!virBitmapIsAllClear(b4))
        goto cleanup;

    if (virBitmapOverlaps(b1, b2) ||
        virBitmapOverlaps(b1, b4) ||
        virBitmapOverlaps(b2, b3) ||
        virBitmapOverlaps(b2, b4) ||
        !virBitmapOverlaps(b1, b3) ||
        virBitmapOverlaps(b3, b4))
        goto cleanup;

    ret = 0;
 cleanup:
    virBitmapFree(b1);
    virBitmapFree(b2);
    virBitmapFree(b3);
    virBitmapFree(b4);
    return ret;
}

struct testBinaryOpData {
    const char *a;
    const char *b;
    const char *res;
};

static int
test11(const void *opaque)
{
    const struct testBinaryOpData *data = opaque;
    virBitmapPtr amap = NULL;
    virBitmapPtr bmap = NULL;
    virBitmapPtr resmap = NULL;
    int ret = -1;

    if (virBitmapParse(data->a, &amap, 256) < 0 ||
        virBitmapParse(data->b, &bmap, 256) < 0 ||
        virBitmapParse(data->res, &resmap, 256) < 0)
        goto cleanup;

    virBitmapSubtract(amap, bmap);

    if (!virBitmapEqual(amap, resmap)) {
        fprintf(stderr, "\n bitmap subtraction failed: '%s'-'%s'!='%s'\n",
                data->a, data->b, data->res);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virBitmapFree(amap);
    virBitmapFree(bmap);
    virBitmapFree(resmap);

    return ret;
}

#define TEST_MAP(sz, expect)                                                   \
    do {                                                                       \
        char *actual;                                                          \
        if (virBitmapSize(map) != sz) {                                        \
            fprintf(stderr, "\n expected bitmap size: '%d' actual size: "      \
                    "'%zu'\n", sz, virBitmapSize(map));                        \
            goto cleanup;                                                      \
        }                                                                      \
                                                                               \
        actual = virBitmapFormat(map);                                         \
                                                                               \
        if (STRNEQ_NULLABLE(expect, actual)) {                                 \
            fprintf(stderr, "\n expected bitmap contents '%s' actual contents "\
                    "'%s'\n", NULLSTR(expect), NULLSTR(actual));               \
            VIR_FREE(actual);                                                  \
            goto cleanup;                                                      \
        }                                                                      \
        VIR_FREE(actual);                                                      \
    } while (0)

/* test self-expanding bitmap APIs */
static int
test12(const void *opaque ATTRIBUTE_UNUSED)
{
    virBitmapPtr map = NULL;
    int ret = -1;

    if (!(map = virBitmapNewEmpty()))
        return -1;

    TEST_MAP(0, "");

    if (virBitmapSetBitExpand(map, 128) < 0)
        goto cleanup;

    TEST_MAP(129, "128");

    if (virBitmapClearBitExpand(map, 150) < 0)
        goto cleanup;

    TEST_MAP(151, "128");

    virBitmapFree(map);
    if (virBitmapParseUnlimited("34,1023", &map) < 0)
        goto cleanup;

    TEST_MAP(1024, "34,1023");

    ret = 0;

 cleanup:
    virBitmapFree(map);
    return ret;
}

#undef TEST_MAP


#define TESTBINARYOP(A, B, RES, FUNC)                                         \
    testBinaryOpData.a = A;                                                   \
    testBinaryOpData.b = B;                                                   \
    testBinaryOpData.res = RES;                                               \
    if (virTestRun(virTestCounterNext(), FUNC, &testBinaryOpData) < 0)        \
        ret = -1;

static int
mymain(void)
{
    struct testBinaryOpData testBinaryOpData;
    int ret = 0;

    if (virTestRun("test1", test1, NULL) < 0)
        ret = -1;
    if (virTestRun("test2", test2, NULL) < 0)
        ret = -1;
    if (virTestRun("test3", test3, NULL) < 0)
        ret = -1;
    if (virTestRun("test4", test4, NULL) < 0)
        ret = -1;
    if (virTestRun("test5", test5, NULL) < 0)
        ret = -1;
    if (virTestRun("test6", test6, NULL) < 0)
        ret = -1;
    if (virTestRun("test7", test7, NULL) < 0)
        ret = -1;
    if (virTestRun("test8", test8, NULL) < 0)
        ret = -1;
    if (virTestRun("test9", test9, NULL) < 0)
        ret = -1;
    if (virTestRun("test10", test10, NULL) < 0)
        ret = -1;

    virTestCounterReset("test11-");
    TESTBINARYOP("0", "0", "0,^0", test11);
    TESTBINARYOP("0-3", "0", "1-3", test11);
    TESTBINARYOP("0-3", "0,3", "1-2", test11);
    TESTBINARYOP("0,^0", "0", "0,^0", test11);
    TESTBINARYOP("0-3", "0-3", "0,^0", test11);
    TESTBINARYOP("0-3", "0,^0", "0-3", test11);
    TESTBINARYOP("0,2", "1,3", "0,2", test11);

    if (virTestRun("test12", test12, NULL) < 0)
        ret = -1;

    return ret;
}

VIRT_TEST_MAIN(mymain)
