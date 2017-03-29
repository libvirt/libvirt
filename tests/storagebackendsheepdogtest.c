/*
 * storagebackendsheepdogtest.c: storage backend for Sheepdog handling
 *
 * Copyright (C) 2014 Red Hat, Inc.
 * Copyright (C) 2012 Sebastian Wiedenroth
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
 * Author: Sebastian Wiedenroth <sebastian.wiedenroth@skylime.net>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "storage/storage_backend_sheepdog_priv.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef struct {
    const char *output;
    int expected_return;
    uint64_t expected_capacity;
    uint64_t expected_allocation;
} collie_test;

struct testNodeInfoParserData {
    collie_test data;
    const char *poolxml;
};

struct testVDIListParserData {
    collie_test data;
    const char *poolxml;
    const char *volxml;
};


static int
test_node_info_parser(const void *opaque)
{
    const struct testNodeInfoParserData *data = opaque;
    collie_test test = data->data;
    int ret = -1;
    char *output = NULL;
    virStoragePoolDefPtr pool = NULL;

    if (!(pool = virStoragePoolDefParseFile(data->poolxml)))
        goto cleanup;

    if (VIR_STRDUP(output, test.output) < 0)
        goto cleanup;

    if (virStorageBackendSheepdogParseNodeInfo(pool, output) !=
        test.expected_return)
        goto cleanup;

    if (test.expected_return) {
        ret = 0;
        goto cleanup;
    }

    if (pool->capacity == test.expected_capacity &&
        pool->allocation == test.expected_allocation)
        ret = 0;

 cleanup:
    VIR_FREE(output);
    virStoragePoolDefFree(pool);
    return ret;
}

static int
test_vdi_list_parser(const void *opaque)
{
    const struct testVDIListParserData *data = opaque;
    collie_test test = data->data;
    int ret = -1;
    char *output = NULL;
    virStoragePoolDefPtr pool = NULL;
    virStorageVolDefPtr vol = NULL;

    if (!(pool = virStoragePoolDefParseFile(data->poolxml)))
        goto cleanup;

    if (!(vol = virStorageVolDefParseFile(pool, data->volxml, 0)))
        goto cleanup;

    if (VIR_STRDUP(output, test.output) < 0)
        goto cleanup;

    if (virStorageBackendSheepdogParseVdiList(vol, output) !=
        test.expected_return)
        goto cleanup;

    if (test.expected_return) {
        ret = 0;
        goto cleanup;
    }

    if (vol->target.capacity == test.expected_capacity &&
        vol->target.allocation == test.expected_allocation)
        ret = 0;

 cleanup:
    VIR_FREE(output);
    virStoragePoolDefFree(pool);
    virStorageVolDefFree(vol);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    char *poolxml = NULL;
    char *volxml = NULL;

    collie_test node_info_tests[] = {
        {"", -1, 0, 0},
        {"Total 15245667872 117571104 0% 20972341\n", 0, 15245667872, 117571104},
        {"To", -1, 0, 0},
        {"asdf\nasdf", -1, 0, 0},
        {"Total ", -1, 0, 0},
        {"Total 1", -1, 0, 0},
        {"Total 1\n", -1, 0, 0},
        {"Total 1 ", -1, 0, 0},
        {"Total 1 2", -1, 0, 0},
        {"Total 1 2 ", -1, 0, 0},
        {"Total 1 2\n", 0, 1, 2},
        {"Total 1 2 \n", 0, 1, 2},
        {"Total a 2 \n", -1, 0, 0},
        {"Total 1 b \n", -1, 0, 0},
        {"Total a b \n", -1, 0, 0},
        {"stuff\nTotal 1 2 \n", 0, 1, 2},
        {"0 1 2 3\nTotal 1 2 \n", 0, 1, 2},
        {NULL, 0, 0, 0}
    };

    collie_test vdi_list_tests[] = {
        {"", -1, 0, 0},
        {"= test 3 10 20 0 1336557216 7c2b27\n", 0, 10, 20},
        {"= test\\ with\\ spaces 3 10 20 0 1336557216 7c2b27\n", 0, 10, 20},
        {"= backslashattheend\\\\ 3 10 20 0 1336557216 7c2b27\n", 0, 10, 20},
        {"s test 1 10 20 0 1336556634 7c2b25\n= test 3 50 60 0 1336557216 7c2b27\n", 0, 50, 60},
        {"=", -1, 0, 0},
        {"= test", -1, 0, 0},
        {"= test ", -1, 0, 0},
        {"= test 1", -1, 0, 0},
        {"= test 1 ", -1, 0, 0},
        {"= test 1 2", -1, 0, 0},
        {"= test 1 2 ", -1, 0, 0},
        {"= test 1 2 3", -1, 0, 0},
        {NULL, 0, 0, 0}
    };

    collie_test *test = node_info_tests;

    if (virAsprintf(&poolxml, "%s/storagepoolxml2xmlin/pool-sheepdog.xml",
                    abs_srcdir) < 0)
        goto cleanup;

    if (virAsprintf(&volxml, "%s/storagevolxml2xmlin/vol-sheepdog.xml",
                    abs_srcdir) < 0)
        goto cleanup;

#define DO_TEST_NODE(collie)                                            \
    do {                                                                \
        struct testNodeInfoParserData data = {                          \
            .data = collie,                                             \
            .poolxml = poolxml,                                         \
        };                                                              \
        if (virTestRun("node_info_parser", test_node_info_parser,       \
                       &data) < 0)                                      \
            ret = -1;                                                   \
    } while (0)

    while (test->output != NULL) {
        DO_TEST_NODE(*test);
        ++test;
    }


#define DO_TEST_VDI(collie)                                             \
    do {                                                                \
        struct testVDIListParserData data = {                           \
            .data = collie,                                             \
            .poolxml = poolxml,                                         \
            .volxml = volxml,                                           \
        };                                                              \
        if (virTestRun("vdi_list_parser", test_vdi_list_parser,         \
                       &data) < 0)                                      \
            ret = -1;                                                   \
    } while (0)

    test = vdi_list_tests;

    while (test->output != NULL) {
        DO_TEST_VDI(*test);
        ++test;
    }

 cleanup:
    VIR_FREE(poolxml);
    VIR_FREE(volxml);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
