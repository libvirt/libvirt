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
checkBitmap(virBitmap *map,
            const char *expect,
            ssize_t expectedSize)
{
    g_autofree char *actual = virBitmapFormat(map);

    if (expectedSize != -1 &&
        virBitmapSize(map) != expectedSize) {
        fprintf(stderr, "\n expected bitmap size: '%zd' actual size: "
                "'%zu'\n", expectedSize, virBitmapSize(map));
        return -1;
    }

    if (STRNEQ_NULLABLE(expect, actual)) {
        fprintf(stderr, "\n expected bitmap contents '%s' actual contents "\
                "'%s'\n", NULLSTR(expect), NULLSTR(actual));
        return -1;
    }

    return 0;
}


static int
test1(const void *data G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) bitmap = NULL;
    int size;
    int bit;
    bool result;

    size = 1024;
    bit = 100;
    bitmap = virBitmapNew(size);

    if (virBitmapSetBit(bitmap, bit) < 0)
        return -1;

    if (virBitmapGetBit(bitmap, bit, &result) < 0)
        return -1;

    if (!result)
        return -1;

    if (virBitmapGetBit(bitmap, bit + 1, &result) < 0)
        return -1;

    if (result)
        return -1;

    return 0;
}

static int
testBit(virBitmap *bitmap,
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
test2(const void *data G_GNUC_UNUSED)
{
    const char *bitsString1 = "1-32,50,88-99,1021-1023";
    g_autofree char *bitsString2 = NULL;
    g_autoptr(virBitmap) bitmap = NULL;
    int size = 1025;

    if (virBitmapParse(bitsString1, &bitmap, size) < 0)
        return -1;

    if (testBit(bitmap, 1, 32, true) < 0)
        return -1;
    if (testBit(bitmap, 50, 50, true) < 0)
        return -1;
    if (testBit(bitmap, 88, 99, true) < 0)
        return -1;
    if (testBit(bitmap, 1021, 1023, true) < 0)
        return -1;

    if (testBit(bitmap, 0, 0, false) < 0)
        return -1;
    if (testBit(bitmap, 33, 49, false) < 0)
        return -1;
    if (testBit(bitmap, 51, 87, false) < 0)
        return -1;
    if (testBit(bitmap, 100, 1020, false) < 0)
        return -1;

    if (virBitmapCountBits(bitmap) != 48)
        return -1;

    if (!(bitsString2 = virBitmapFormat(bitmap)))
        return -1;
    if (strcmp(bitsString1, bitsString2))
        return -1;

    virBitmapSetAll(bitmap);
    if (testBit(bitmap, 0, size - 1, true) < 0)
        return -1;
    if (virBitmapCountBits(bitmap) != size)
        return -1;

    if (!virBitmapIsAllSet(bitmap))
        return -1;

    virBitmapClearAll(bitmap);
    if (!virBitmapIsAllClear(bitmap))
        return -1;
    if (testBit(bitmap, 0, size - 1, false) < 0)
        return -1;
    if (virBitmapCountBits(bitmap) != 0)
        return -1;

    return 0;
}

static int
test3(const void *data G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) bitmap = NULL;
    int size = 5;
    size_t i;

    bitmap = virBitmapNew(size);

    for (i = 0; i < size; i++)
        ignore_value(virBitmapSetBit(bitmap, i));

    if (!virBitmapIsAllSet(bitmap))
        return -1;

    virBitmapClearAll(bitmap);
    if (!virBitmapIsAllClear(bitmap))
        return -1;

    return 0;
}

/* test for virBitmapNextSetBit, virBitmapLastSetBit, virBitmapNextClearBit */
static int
test4a(const void *data G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) bitmap = NULL;

    /* 0. empty set */

    bitmap = virBitmapNew(0);

    if (virBitmapNextSetBit(bitmap, -1) != -1)
        return -1;

    if (virBitmapLastSetBit(bitmap) != -1)
        return -1;

    if (virBitmapNextClearBit(bitmap, -1) != -1)
        return -1;

    return 0;
}


static int
test4b(const void *data G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) bitmap = NULL;
    int size = 40;
    size_t i;

    /* 1. zero set */

    bitmap = virBitmapNew(size);

    if (virBitmapNextSetBit(bitmap, -1) != -1)
        return -1;

    if (virBitmapLastSetBit(bitmap) != -1)
        return -1;

    for (i = 0; i < size; i++) {
        if (virBitmapNextClearBit(bitmap, i - 1) != i)
            return -1;
    }
    if (virBitmapNextClearBit(bitmap, i) != -1)
        return -1;

    if (!virBitmapIsAllClear(bitmap))
        return -1;

    return 0;
}


static int
test4c(const void *data G_GNUC_UNUSED)
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
    g_autoptr(virBitmap) bitmap = NULL;
    ssize_t i, j;

    if (G_N_ELEMENTS(bitsPos) + G_N_ELEMENTS(bitsPosInv) != size)
        return -1;

    /* 2. partial set */

    if (virBitmapParse(bitsString, &bitmap, size) < 0)
        return -1;
    if (!bitmap)
        return -1;

    j = 0;
    i = -1;

    while (j < G_N_ELEMENTS(bitsPos)) {
        i = virBitmapNextSetBit(bitmap, i);
        if (i != bitsPos[j++])
            return -1;
    }

    if (virBitmapNextSetBit(bitmap, i) != -1)
        return -1;

    j = G_N_ELEMENTS(bitsPos) - 1;

    if (virBitmapLastSetBit(bitmap) != bitsPos[j])
        return -1;

    j = 0;
    i = -1;

    while (j < G_N_ELEMENTS(bitsPosInv)) {
        i = virBitmapNextClearBit(bitmap, i);
        if (i != bitsPosInv[j++])
            return -1;
    }

    if (virBitmapNextClearBit(bitmap, i) != -1)
        return -1;

    /* 3. full set */

    virBitmapSetAll(bitmap);

    for (i = 0; i < size; i++) {
        if (virBitmapNextSetBit(bitmap, i - 1) != i)
            return -1;
    }
    if (virBitmapNextSetBit(bitmap, i) != -1)
        return -1;

    if (virBitmapLastSetBit(bitmap) != size - 1)
        return -1;

    if (virBitmapNextClearBit(bitmap, -1) != -1)
        return -1;

    return 0;
}

/* test for virBitmapNewData/ToData/DataFormat */
static int
test5(const void *v G_GNUC_UNUSED)
{
    char data[] = {0x01, 0x02, 0x00, 0x00, 0x04};
    g_autofree unsigned char *data2 = NULL;
    int len2;
    int bits[] = {0, 9, 34};
    g_autoptr(virBitmap) bitmap = NULL;
    size_t i;
    ssize_t j;
    g_autofree char *actual1 = NULL;
    g_autofree char *actual2 = NULL;

    bitmap = virBitmapNewData(data, sizeof(data));
    if (!bitmap)
        return -1;

    i = 0;
    j = -1;
    while (i < G_N_ELEMENTS(bits) &&
           (j = virBitmapNextSetBit(bitmap, j)) >= 0) {
        if (j != bits[i++])
            return -1;
    }
    if (virBitmapNextSetBit(bitmap, j) > 0)
        return -1;

    ignore_value(virBitmapSetBit(bitmap, 2));
    ignore_value(virBitmapSetBit(bitmap, 15));

    if (virBitmapToData(bitmap, &data2, &len2) < 0)
        return -1;

    if (len2 != sizeof(data) ||
        data2[0] != 0x05 ||
        data2[1] != 0x82 ||
        data2[2] != 0x00 ||
        data2[3] != 0x00 ||
        data2[4] != 0x04)
        return -1;

    if (!(actual1 = virBitmapDataFormat(data, sizeof(data))))
        return -1;
    if (STRNEQ(actual1, "0,9,34"))
        return -1;
    if (!(actual2 = virBitmapDataFormat(data2, len2)))
        return -1;
    if (STRNEQ(actual2, "0,2,9,15,34"))
        return -1;

    return 0;
}


/* test for virBitmapFormat */
static int
test6(const void *v G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) bitmap = NULL;
    int size = 64;

    bitmap = virBitmapNew(size);

    if (checkBitmap(bitmap, "", -1) < 0)
        return -1;

    ignore_value(virBitmapSetBit(bitmap, 0));

    if (checkBitmap(bitmap, "0", -1) < 0)
        return -1;

    ignore_value(virBitmapSetBit(bitmap, 4));
    ignore_value(virBitmapSetBit(bitmap, 5));

    if (checkBitmap(bitmap, "0,4-5", -1) < 0)
        return -1;

    ignore_value(virBitmapSetBit(bitmap, 6));

    if (checkBitmap(bitmap, "0,4-6", -1) < 0)
        return -1;

    ignore_value(virBitmapSetBit(bitmap, 13));
    ignore_value(virBitmapSetBit(bitmap, 14));
    ignore_value(virBitmapSetBit(bitmap, 15));
    ignore_value(virBitmapSetBit(bitmap, 16));

    if (checkBitmap(bitmap, "0,4-6,13-16", -1) < 0)
        return -1;

    ignore_value(virBitmapSetBit(bitmap, 62));
    ignore_value(virBitmapSetBit(bitmap, 63));

    if (checkBitmap(bitmap, "0,4-6,13-16,62-63", -1) < 0)
        return -1;

    return 0;
}

static int
test7(const void *v G_GNUC_UNUSED)
{
    size_t i;
    size_t maxBit[] = {
        1, 8, 31, 32, 63, 64, 95, 96, 127, 128, 159, 160
    };
    size_t nmaxBit = 12;

    for (i = 0; i < nmaxBit; i++) {
        g_autoptr(virBitmap) bitmap = virBitmapNew(maxBit[i]);

        if (virBitmapIsAllSet(bitmap))
            return -1;

        ignore_value(virBitmapSetBit(bitmap, 1));
        if (virBitmapIsAllSet(bitmap))
            return -1;

        virBitmapSetAll(bitmap);
        if (!virBitmapIsAllSet(bitmap))
            return -1;

        virBitmapClearAll(bitmap);
        if (!virBitmapIsAllClear(bitmap))
            return -1;
    }

    return 0;
}

static int
test8(const void *v G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) bitmap = NULL;
    char data[108] = {0x00,};

    bitmap = virBitmapNewData(data, sizeof(data));
    if (!bitmap)
        return -1;

    if (!virBitmapIsAllClear(bitmap))
        return -1;

    if (virBitmapSetBit(bitmap, 11) < 0)
        return -1;

    if (virBitmapIsAllClear(bitmap))
        return -1;

    return 0;
}


/* test out of bounds conditions on virBitmapParse */
static int
test9(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) bitmap = NULL;

    if (virBitmapParse("100000000", &bitmap, 20) != -1)
        return -1;

    if (bitmap)
        return -1;

    if (virBitmapParse("1-1000000000", &bitmap, 20) != -1)
        return -1;

    if (bitmap)
        return -1;

    if (virBitmapParse("1-10^10000000000", &bitmap, 20) != -1)
        return -1;

    if (bitmap)
        return -1;

    return 0;
}

static int
test10(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) b1 = NULL;
    g_autoptr(virBitmap) b2 = NULL;
    g_autoptr(virBitmap) b3 = NULL;
    g_autoptr(virBitmap) b4 = NULL;

    if (virBitmapParse("0-3,5-8,11-15", &b1, 20) < 0 ||
        virBitmapParse("4,9,10,16-19", &b2, 20) < 0 ||
        virBitmapParse("15", &b3, 20) < 0 ||
        virBitmapParse("0,^0", &b4, 20) < 0)
        return -1;

    if (!virBitmapIsAllClear(b4))
        return -1;

    if (virBitmapOverlaps(b1, b2) ||
        virBitmapOverlaps(b1, b4) ||
        virBitmapOverlaps(b2, b3) ||
        virBitmapOverlaps(b2, b4) ||
        !virBitmapOverlaps(b1, b3) ||
        virBitmapOverlaps(b3, b4))
        return -1;

    return 0;
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
    g_autoptr(virBitmap) amap = NULL;
    g_autoptr(virBitmap) bmap = NULL;
    g_autoptr(virBitmap) resmap = NULL;

    if (virBitmapParse(data->a, &amap, 256) < 0 ||
        virBitmapParse(data->b, &bmap, 256) < 0 ||
        virBitmapParse(data->res, &resmap, 256) < 0)
        return -1;

    virBitmapIntersect(amap, bmap);

    if (!virBitmapEqual(amap, resmap)) {
        fprintf(stderr,
                "\n bitmap intersection failed: intersect('%s','%s') !='%s'\n",
                data->a, data->b, data->res);
        return -1;
    }

    return 0;
}


/* test self-expanding bitmap APIs */
static int
test12a(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) map = virBitmapNew(0);

    if (checkBitmap(map, "", 0) < 0)
        return -1;

    virBitmapSetBitExpand(map, 128);

    if (checkBitmap(map, "128", 129) < 0)
        return -1;

    virBitmapClearBitExpand(map, 150);

    if (checkBitmap(map, "128", 151) < 0)
        return -1;

    return 0;
}


static int
test12b(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) map = NULL;

    if (!(map = virBitmapParseUnlimited("34,1023")))
        return -1;

    if (checkBitmap(map, "34,1023", 1024) < 0)
        return -1;

    virBitmapShrink(map, 35);
    if (checkBitmap(map, "34", 35) < 0)
        return -1;

    virBitmapShrink(map, 34);
    if (checkBitmap(map, "", 34) < 0)
        return -1;

    return 0;
}


/* virBitmap(New/To)String */
static int
test13(const void *opaque G_GNUC_UNUSED)
{
    const char *strings[] = { "1234feebee", "000c0fefe", "0", "" };
    size_t i = 0;

    for (i = 0; i < G_N_ELEMENTS(strings); i++) {
        g_autoptr(virBitmap) map = NULL;
        g_autofree char *str = NULL;

        if (!(map = virBitmapNewString(strings[i])))
            return -1;

        if (!(str = virBitmapToString(map)))
            return -1;

        if (STRNEQ(strings[i], str)) {
            fprintf(stderr, "\n expected bitmap string '%s' actual string "
                    "'%s'\n", strings[i], str);
            return -1;
        }
    }

    return 0;
}


static int
test14(const void *opaque)
{
    const struct testBinaryOpData *data = opaque;
    g_autoptr(virBitmap) amap = NULL;
    g_autoptr(virBitmap) bmap = NULL;
    g_autoptr(virBitmap) resmap = NULL;

    if (virBitmapParse(data->a, &amap, 256) < 0 ||
        virBitmapParse(data->b, &bmap, 256) < 0 ||
        virBitmapParse(data->res, &resmap, 256) < 0)
        return -1;

    virBitmapSubtract(amap, bmap);

    if (!virBitmapEqual(amap, resmap)) {
        fprintf(stderr,
                "\n bitmap subtraction failed: '%s' - '%s' != '%s'\n",
                data->a, data->b, data->res);
        return -1;
    }

    return 0;
}

/* virBitmapUnion() */
static int
test15(const void *opaque)
{
    const struct testBinaryOpData *data = opaque;
    g_autoptr(virBitmap) amap = NULL;
    g_autoptr(virBitmap) bmap = NULL;
    g_autoptr(virBitmap) resmap = NULL;

    if (!(amap = virBitmapParseUnlimited(data->a)) ||
        !(bmap = virBitmapParseUnlimited(data->b)) ||
        !(resmap = virBitmapParseUnlimited(data->res))) {
        return -1;
    }

    virBitmapUnion(amap, bmap);

    if (!virBitmapEqual(amap, resmap)) {
        fprintf(stderr,
                "\n bitmap union failed: union('%s', '%s') != '%s'\n",
                data->a, data->b, data->res);
        return -1;
    }

    return 0;
}


/* virBitmapNew(0) + virBitmapToString */
static int
test16(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) map = virBitmapNew(0);
    g_autofree char *res_empty = NULL;
    g_autofree char *res_set = NULL;

    if (!(res_empty = virBitmapToString(map)) ||
        STRNEQ_NULLABLE(res_empty, "")) {
        fprintf(stderr, "\n expected bitmap string '%s' actual string '%s'\n",
                "", NULLSTR(res_empty));
        return -1;
    }

    virBitmapSetBitExpand(map, 2);
    virBitmapSetBitExpand(map, 11);

    if (!(res_set = virBitmapToString(map)) ||
        STRNEQ_NULLABLE(res_set, "804")) {
        fprintf(stderr, "\n expected bitmap string '%s' actual string '%s'\n",
                "804", NULLSTR(res_set));
        return -1;
    }

    return 0;
}


#define TESTBINARYOP(A, B, RES, FUNC) \
    testBinaryOpData.a = A; \
    testBinaryOpData.b = B; \
    testBinaryOpData.res = RES; \
    if (virTestRun(virTestCounterNext(), FUNC, &testBinaryOpData) < 0) \
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
    if (virTestRun("test4a", test4a, NULL) < 0)
        ret = -1;
    if (virTestRun("test4b", test4b, NULL) < 0)
        ret = -1;
    if (virTestRun("test4c", test4c, NULL) < 0)
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
    TESTBINARYOP("0", "0", "0", test11);
    TESTBINARYOP("0-3", "0", "0", test11);
    TESTBINARYOP("0-3", "0,3", "0,3", test11);
    TESTBINARYOP("0,^0", "0", "0,^0", test11);
    TESTBINARYOP("0-3", "0-3", "0-3", test11);
    TESTBINARYOP("0-3", "0,^0", "0,^0", test11);
    TESTBINARYOP("0,2", "1,3", "0,^0", test11);

    if (virTestRun("test12a", test12a, NULL) < 0)
        ret = -1;
    if (virTestRun("test12b", test12b, NULL) < 0)
        ret = -1;
    if (virTestRun("test13", test13, NULL) < 0)
        ret = -1;

    virTestCounterReset("test14-");
    TESTBINARYOP("0", "0", "0,^0", test14);
    TESTBINARYOP("0-3", "0", "1-3", test14);
    TESTBINARYOP("0-3", "0,3", "1-2", test14);
    TESTBINARYOP("0,^0", "0", "0,^0", test14);
    TESTBINARYOP("0-3", "0-3", "0,^0", test14);
    TESTBINARYOP("0-3", "0,^0", "0-3", test14);
    TESTBINARYOP("0,2", "1,3", "0,2", test14);

    /* virBitmapUnion() */
    virTestCounterReset("test15-");
    TESTBINARYOP("0-1", "0-1", "0-1", test15);
    TESTBINARYOP("0", "1", "0-1", test15);
    TESTBINARYOP("0-1", "2-3", "0-3", test15);
    TESTBINARYOP("0-3", "1-2", "0-3", test15);
    TESTBINARYOP("0,^0", "12345", "12345", test15);
    TESTBINARYOP("12345", "0,^0", "12345", test15);
    TESTBINARYOP("0,^0", "0,^0", "0,^0", test15);

    if (virTestRun("test16", test16, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
