/*
 * virnetworkportxml2xmltest.c: network port XML processing test suite
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "virnetworkportdef.h"

#define VIR_FROM_THIS VIR_FROM_NONE


static int
testCompareXMLToXMLFiles(const char *expected)
{
    g_autofree char *actual = NULL;
    g_autoptr(virNetworkPortDef) dev = NULL;

    if (!(dev = virNetworkPortDefParse(NULL, expected, 0)))
        return -1;

    if (!(actual = virNetworkPortDefFormat(dev)))
        return -1;

    if (virTestCompareToFile(actual, expected) < 0)
        return -1;

    return 0;
}

struct testInfo {
    const char *name;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    g_autofree char *xml = NULL;

    xml = g_strdup_printf("%s/virnetworkportxml2xmldata/%s.xml", abs_srcdir,
                          info->name);

    return testCompareXMLToXMLFiles(xml);
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(name) \
    do { \
        const struct testInfo info = {name}; \
        if (virTestRun("virnetworkportdeftest " name, \
                       testCompareXMLToXMLHelper, &info) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST("plug-none");
    DO_TEST("plug-bridge");
    DO_TEST("plug-bridge-mactbl");
    DO_TEST("plug-direct");
    DO_TEST("plug-hostdev-pci");
    DO_TEST("plug-hostdev-pci-unmanaged");
    DO_TEST("plug-network");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
