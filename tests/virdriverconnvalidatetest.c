/*
 * Copyright (C) 2019 IBM Corporation
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

#include "testutils.h"
#include "virlog.h"
#include "driver.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.driverconnvalidatetest");

struct testDriverConnValidateData {
    const char *uriPath;
    const char *entityName;
    bool privileged;
    bool expectFailure;
};


static int testDriverConnValidate(const void *args)
{
    const struct testDriverConnValidateData *data = args;

    bool ret = virConnectValidateURIPath(data->uriPath,
                                         data->entityName,
                                         data->privileged);
    if (data->expectFailure)
        ret = !ret;

    return ret ? 0 : -1;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_INTERNAL(name, entity, uri, _privileged, expectFail) \
    do { \
        static struct testDriverConnValidateData data = { \
            .entityName = entity, \
            .uriPath = uri, \
            .privileged = _privileged, \
            .expectFailure = expectFail, \
        }; \
        if (virTestRun("Test conn URI path validate ok " name, \
                       testDriverConnValidate, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_SUCCESS(name, entity, uri, _privileged) \
    DO_TEST_INTERNAL(name, entity, uri, _privileged, false)

#define DO_TEST_FAIL(name, entity, uri, _privileged) \
    DO_TEST_INTERNAL(name, entity, uri, _privileged, true)

    DO_TEST_SUCCESS("non-privileged /session", "any", "/session", false);
    DO_TEST_FAIL("non-privileged non-session fail", "any", "/system", false);

    DO_TEST_SUCCESS("privileged /system", "any", "/system", true);
    DO_TEST_FAIL("privileged non-system fail", "any", "any", true);

    DO_TEST_SUCCESS("privileged qemu /session", "qemu", "/session", true);
    DO_TEST_SUCCESS("privileged vbox /session", "vbox", "/session", true);
    DO_TEST_FAIL("privileged other /session fail", "any", "/session", true);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
