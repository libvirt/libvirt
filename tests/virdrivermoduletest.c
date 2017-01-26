/*
 * Copyright (C) 2012, 2014 Red Hat, Inc.
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

#include "testutils.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"
#include "driver.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.drivermoduletest");

struct testDriverModuleData {
    const char *module;
    const char *regfunc;
};


static int testDriverModule(const void *args)
{
    const struct testDriverModuleData *data = args;

    /* coverity[leaked_storage] */
    if (virDriverLoadModule(data->module, data->regfunc) != 0)
        return -1;

    return 0;
}


static int
mymain(void)
{
    int ret = 0;
    struct testDriverModuleData data;

#define TEST_FULL(name, fnc)                                                   \
    do  {                                                                      \
        data.module = name;                                                    \
        data.regfunc = fnc;                                                    \
        if (virTestRun("Test driver " # name, testDriverModule, &data) < 0)    \
            ret = -1;                                                          \
    } while (0)

#define TEST(name) TEST_FULL(name, name "Register")

#ifdef WITH_NETWORK
    TEST("network");
#endif
#ifdef WITH_INTERFACE
    TEST("interface");
#endif
#ifdef WITH_STORAGE
    TEST("storage");
#endif
#ifdef WITH_NODE_DEVICES
    TEST("nodedev");
#endif
#ifdef WITH_SECRETS
    TEST("secret");
#endif
#ifdef WITH_NWFILTER
    TEST("nwfilter");
#endif
#ifdef WITH_XEN
    TEST("xen");
#endif
#ifdef WITH_LIBXL
    TEST("libxl");
#endif
#ifdef WITH_QEMU
    TEST("qemu");
#endif
#ifdef WITH_LXC
    TEST("lxc");
#endif
#ifdef WITH_UML
    TEST("uml");
#endif
#ifdef WITH_VBOX
    TEST("vbox");
#endif
#ifdef WITH_BHYVE
    TEST("bhyve");
#endif

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
