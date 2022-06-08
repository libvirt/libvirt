/*
 * Copyright (C) 2020 Red Hat, Inc.
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
 */

#include <config.h>

#include "libvirt_internal.h"

#include "testutils.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("tests.migtest");

struct migLocalData {
    const char *uri;
    bool fail;
};


static int
testMigNotLocal(const void *args)
{
    int ret = -1;
    const struct migLocalData *data = args;

    ret = virDomainMigrateCheckNotLocal(data->uri);

    if (ret == -1) {
        if (data->fail) {
            virResetLastError();
            return 0;
        }
        return -1;
    }

    if (data->fail) {
        VIR_TEST_DEBUG("passed instead of expected failure");
        return -1;
    }

    return ret;
}


static int
mymain(void)
{
    int ret = 0;

#define TEST_FULL(uri, fail) \
    do  { \
        const struct migLocalData data = { \
            uri, fail \
        }; \
        if (virTestRun("Test URI " # uri, testMigNotLocal, &data) < 0) \
            ret = -1; \
    } while (0)

#define TEST(uri) TEST_FULL(uri, false)
#define TEST_FAIL(uri) TEST_FULL(uri, true)

    TEST_FAIL("qemu:///system");

    TEST_FAIL("//localhost");
    TEST_FAIL("tcp://localhost.localdomain/");

    TEST("scheme://some.cryptorandom.fqdn.tld");

    TEST("hehe+unix:///?socket=/path/to/some-sock");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
