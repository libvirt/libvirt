/*
 * Copyright (C) 2013 Red Hat, Inc.
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

#include "virendian.h"

static int
test1(const void *data G_GNUC_UNUSED)
{
    /* Regular char should work, even if signed, and even with
     * unaligned access.  */
    char array[] = { 1, 2, 3, 4, 5, 6, 7, 8,
                     0x89, 0x8a, 0x8b, 0x8c, 0x8d };

    if (virReadBufInt64BE(array) != 0x0102030405060708ULL)
        return -1;
    if (virReadBufInt64BE(array + 5) != 0x060708898a8b8c8dULL)
        return -1;
    if (virReadBufInt64LE(array) != 0x0807060504030201ULL)
        return -1;
    if (virReadBufInt64LE(array + 5) != 0x8d8c8b8a89080706ULL)
        return -1;

    if (virReadBufInt32BE(array) != 0x01020304U)
        return -1;
    if (virReadBufInt32BE(array + 9) != 0x8a8b8c8dU)
        return -1;
    if (virReadBufInt32LE(array) != 0x04030201U)
        return -1;
    if (virReadBufInt32LE(array + 9) != 0x8d8c8b8aU)
        return -1;

    if (virReadBufInt16BE(array) != 0x0102U)
        return -1;
    if (virReadBufInt16BE(array + 11) != 0x8c8dU)
        return -1;
    if (virReadBufInt16LE(array) != 0x0201U)
        return -1;
    if (virReadBufInt16LE(array + 11) != 0x8d8cU)
        return -1;

    return 0;
}

static int
test2(const void *data G_GNUC_UNUSED)
{
    /* Unsigned char should work without cast, even if unaligned access.  */
    unsigned char array[] = { 1, 2, 3, 4, 5, 6, 7, 8,
                              0x89, 0x8a, 0x8b, 0x8c, 0x8d };

    if (virReadBufInt64BE(array) != 0x0102030405060708ULL)
        return -1;
    if (virReadBufInt64BE(array + 5) != 0x060708898a8b8c8dULL)
        return -1;
    if (virReadBufInt64LE(array) != 0x0807060504030201ULL)
        return -1;
    if (virReadBufInt64LE(array + 5) != 0x8d8c8b8a89080706ULL)
        return -1;

    if (virReadBufInt32BE(array) != 0x01020304U)
        return -1;
    if (virReadBufInt32BE(array + 9) != 0x8a8b8c8dU)
        return -1;
    if (virReadBufInt32LE(array) != 0x04030201U)
        return -1;
    if (virReadBufInt32LE(array + 9) != 0x8d8c8b8aU)
        return -1;

    if (virReadBufInt16BE(array) != 0x0102U)
        return -1;
    if (virReadBufInt16BE(array + 11) != 0x8c8dU)
        return -1;
    if (virReadBufInt16LE(array) != 0x0201U)
        return -1;
    if (virReadBufInt16LE(array + 11) != 0x8d8cU)
        return -1;

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

    if (virTestRun("test1", test1, NULL) < 0)
        ret = -1;
    if (virTestRun("test2", test2, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
