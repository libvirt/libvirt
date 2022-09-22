/*
 * virnwfilterbindingxml2xmltest.c: network filter binding XML testing
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
 *
 */

#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "virnwfilterbindingdef.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *xml)
{
    g_autofree char *actual = NULL;
    int ret = -1;
    virNWFilterBindingDef *dev = NULL;

    virResetLastError();

    if (!(dev = virNWFilterBindingDefParse(NULL, xml, 0)))
        goto fail;

    if (!(actual = virNWFilterBindingDefFormat(dev)))
        goto fail;

    if (virTestCompareToFile(actual, xml) < 0)
        goto fail;

    ret = 0;

 fail:
    virNWFilterBindingDefFree(dev);
    return ret;
}

typedef struct test_parms {
    const char *name;
} test_parms;

static int
testCompareXMLToXMLHelper(const void *data)
{
    int result = -1;
    const test_parms *tp = data;
    g_autofree char *xml = NULL;

    xml = g_strdup_printf("%s/virnwfilterbindingxml2xmldata/%s.xml", abs_srcdir,
                          tp->name);

    result = testCompareXMLToXMLFiles(xml);

    return result;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(NAME) \
    do { \
        test_parms tp = { \
            .name = NAME, \
        }; \
        if (virTestRun("NWFilter XML-2-XML " NAME, \
                       testCompareXMLToXMLHelper, (&tp)) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST("simple");
    DO_TEST("filter-vars");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
