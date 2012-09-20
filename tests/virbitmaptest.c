/*
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

#include "bitmap.h"

static int test1(const void *data ATTRIBUTE_UNUSED)
{
    virBitmapPtr bitmap;
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
testBit(virBitmapPtr bitmap,
        unsigned int start,
        unsigned int end,
        bool expected)
{
    int i;
    bool result;

    for (i = start; i <= end; i++) {
        if (virBitmapGetBit(bitmap, i, &result) < 0)
            return -1;
        if (result == expected)
            return 0;
    }

    return -1;
}

static int test2(const void *data ATTRIBUTE_UNUSED)
{
    const char *bitsString1 = "1-32,50,88-99,1021-1023";
    char *bitsString2 = NULL;
    virBitmapPtr bitmap = NULL;
    int ret = -1;
    int size = 1025;

    if (virBitmapParse(bitsString1, 0, &bitmap, size) < 0)
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

    bitsString2 = virBitmapFormat(bitmap);
    if (strcmp(bitsString1, bitsString2))
        goto error;

    virBitmapSetAll(bitmap);
    if (testBit(bitmap, 0, size - 1, true) < 0)
        goto error;

    if (!virBitmapIsAllSet(bitmap))
        goto error;

    virBitmapClearAll(bitmap);
    if (testBit(bitmap, 0, size - 1, false) < 0)
        goto error;

    ret = 0;

error:
    virBitmapFree(bitmap);
    VIR_FREE(bitsString2);
    return ret;
}

static int test3(const void *data ATTRIBUTE_UNUSED)
{
    virBitmapPtr bitmap = NULL;
    int ret = -1;
    int size = 5;
    int i;

    if ((bitmap = virBitmapNew(size)) == NULL)
        goto error;

    for (i = 0; i < size; i++)
        ignore_value(virBitmapSetBit(bitmap, i));

    if (!virBitmapIsAllSet(bitmap))
        goto error;

    ret = 0;

error:
    virBitmapFree(bitmap);
    return ret;
}

/* test for virBitmapNextSetBit */
static int test4(const void *data ATTRIBUTE_UNUSED)
{
    const char *bitsString = "0, 2-4, 6-10, 12, 14-18, 20, 22, 25";
    int size = 40;
    int bitsPos[] = {
        0,  2,  3,  4,  6,  7,  8,  9, 10, 12,
        14, 15, 16, 17, 18, 20, 22, 25
    };
    int npos = 18;
    virBitmapPtr bitmap = NULL;
    int i, j;

    /* 1. zero set */

    bitmap = virBitmapNew(size);
    if (!bitmap)
        goto error;

    if (virBitmapNextSetBit(bitmap, -1) >= 0)
        goto error;

    virBitmapFree(bitmap);
    bitmap = NULL;

    /* 2. partial set */

    if (virBitmapParse(bitsString, 0, &bitmap, size) < 0)
        goto error;
    if (!bitmap)
        goto error;

    j = 0;
    i = -1;

    while (j < npos) {
        i = virBitmapNextSetBit(bitmap, i);
        if (i != bitsPos[j++])
            goto error;
    }

    if (virBitmapNextSetBit(bitmap, i) > 0)
        goto error;

    /* 3. full set */

    i = -1;
    virBitmapSetAll(bitmap);

    for (j = 0; j < size; j++) {
        i = virBitmapNextSetBit(bitmap, i);
        if (i != j)
            goto error;
    }

    if (virBitmapNextSetBit(bitmap, i) > 0)
        goto error;

    virBitmapFree(bitmap);
    return 0;

error:
    virBitmapFree(bitmap);
    return -1;
}

/* test for virBitmapNewData/ToData */
static int test5(const void *v ATTRIBUTE_UNUSED)
{
    char data[] = {0x01, 0x02, 0x00, 0x00, 0x04};
    unsigned char *data2 = NULL;
    int len2;
    int bits[] = {0, 9, 34};
    virBitmapPtr bitmap;
    int i, j;
    int ret = -1;

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

    ret = 0;
error:
    virBitmapFree(bitmap);
    VIR_FREE(data2);
    return ret;
}


/* test for virBitmapFormat */
static int test6(const void *v ATTRIBUTE_UNUSED)
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

    if (!STREQ(str, ""))
        goto error;

    VIR_FREE(str);

    ignore_value(virBitmapSetBit(bitmap, 0));
    str = virBitmapFormat(bitmap);
    if (!str)
        goto error;

    if (!STREQ(str, "0"))
        goto error;

    VIR_FREE(str);

    ignore_value(virBitmapSetBit(bitmap, 4));
    ignore_value(virBitmapSetBit(bitmap, 5));
    str = virBitmapFormat(bitmap);
    if (!str)
        goto error;

    if (!STREQ(str, "0,4-5"))
        goto error;

    VIR_FREE(str);

    ignore_value(virBitmapSetBit(bitmap, 6));
    str = virBitmapFormat(bitmap);
    if (!str)
        goto error;

    if (!STREQ(str, "0,4-6"))
        goto error;

    VIR_FREE(str);

    ignore_value(virBitmapSetBit(bitmap, 13));
    ignore_value(virBitmapSetBit(bitmap, 14));
    ignore_value(virBitmapSetBit(bitmap, 15));
    ignore_value(virBitmapSetBit(bitmap, 16));
    str = virBitmapFormat(bitmap);
    if (!str)
        goto error;

    if (!STREQ(str, "0,4-6,13-16"))
        goto error;

    VIR_FREE(str);

    ignore_value(virBitmapSetBit(bitmap, 62));
    ignore_value(virBitmapSetBit(bitmap, 63));
    str = virBitmapFormat(bitmap);
    if (!str)
        goto error;

    if (!STREQ(str, "0,4-6,13-16,62-63"))
        goto error;


    ret = 0;
error:
    virBitmapFree(bitmap);
    VIR_FREE(str);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

    if (virtTestRun("test1", 1, test1, NULL) < 0)
        ret = -1;
    if (virtTestRun("test2", 1, test2, NULL) < 0)
        ret = -1;
    if (virtTestRun("test3", 1, test3, NULL) < 0)
        ret = -1;
    if (virtTestRun("test4", 1, test4, NULL) < 0)
        ret = -1;
    if (virtTestRun("test5", 1, test5, NULL) < 0)
        ret = -1;
    if (virtTestRun("test6", 1, test6, NULL) < 0)
        ret = -1;


    return ret;
}

VIRT_TEST_MAIN(mymain)
