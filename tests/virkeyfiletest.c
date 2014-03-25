/*
 * Copyright (C) 2011, 2012, 2014 Red Hat, Inc.
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

#include <stdlib.h>
#include <signal.h>

#include "testutils.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"

#include "virkeyfile.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("tests.keyfiletest");

static int testParse(const void *args ATTRIBUTE_UNUSED)
{
    static const char *cfg1 =
        "# Some config\n"
        "\n"
        "# The first group\n"
        "[Foo]\n"
        "one=The first entry is here\n"
        "two=The second entry\n"
        "  \n"
        "three=The third entry\n"
        "[Bar]\n"
        "; Another comment\n"
        "one=The first entry in second group";
    virKeyFilePtr kf = virKeyFileNew();
    int ret = -1;

    if (virKeyFileLoadData(kf, "demo.conf", cfg1, strlen(cfg1)) < 0)
        goto cleanup;

    if (!virKeyFileHasGroup(kf, "Foo")) {
        VIR_DEBUG("Missing group 'Foo'");
        goto cleanup;
    }
    if (!virKeyFileHasValue(kf, "Foo", "one")) {
        VIR_DEBUG("Missing Value 'Foo.one'");
        goto cleanup;
    }
    if (!virKeyFileHasValue(kf, "Foo", "two")) {
        VIR_DEBUG("Missing Value 'Foo.two'");
        goto cleanup;
    }
    if (!virKeyFileHasValue(kf, "Foo", "three")) {
        VIR_DEBUG("Missing Value 'Foo.three'");
        goto cleanup;
    }
    if (!STREQ(virKeyFileGetValueString(kf, "Foo", "one"),
               "The first entry is here")) {
        VIR_DEBUG("Wrong value for 'Foo.one'");
        goto cleanup;
    }
    if (!STREQ(virKeyFileGetValueString(kf, "Foo", "two"),
               "The second entry")) {
        VIR_DEBUG("Wrong value for 'Foo.one'");
        goto cleanup;
    }
    if (!STREQ(virKeyFileGetValueString(kf, "Foo", "three"),
               "The third entry")) {
        VIR_DEBUG("Wrong value for 'Foo.one'");
        goto cleanup;
    }

    if (!virKeyFileHasGroup(kf, "Bar")) {
        VIR_DEBUG("Missing group 'Bar'");
        goto cleanup;
    }
    if (!virKeyFileHasValue(kf, "Bar", "one")) {
        VIR_DEBUG("Missing Value 'Bar.one'");
        goto cleanup;
    }
    if (!STREQ(virKeyFileGetValueString(kf, "Bar", "one"),
               "The first entry in second group")) {
        VIR_DEBUG("Wrong value for 'Bar.one'");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virKeyFileFree(kf);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    signal(SIGPIPE, SIG_IGN);

    if (virtTestRun("Test parse", testParse, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
