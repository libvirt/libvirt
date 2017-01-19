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

#include "virstring.h"
#include "virutil.h"
#include "testutils.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static char *fchost_prefix;

#define TEST_FC_HOST_PREFIX fchost_prefix
#define TEST_FC_HOST_NUM 5
#define TEST_FC_HOST_NUM_NO_FAB 6

/* Test virIsCapableFCHost */
static int
test1(const void *data ATTRIBUTE_UNUSED)
{
    if (virIsCapableFCHost(TEST_FC_HOST_PREFIX,
                           TEST_FC_HOST_NUM) &&
        virIsCapableFCHost(TEST_FC_HOST_PREFIX,
                           TEST_FC_HOST_NUM_NO_FAB))
        return 0;

    return -1;
}

/* Test virIsCapableVport */
static int
test2(const void *data ATTRIBUTE_UNUSED)
{
    if (virIsCapableVport(TEST_FC_HOST_PREFIX,
                          TEST_FC_HOST_NUM))
        return 0;

    return -1;
}

/* Test virReadFCHost */
static int
test3(const void *data ATTRIBUTE_UNUSED)
{
    const char *expect_wwnn = "2001001b32a9da4e";
    const char *expect_wwpn = "2101001b32a9da4e";
    const char *expect_fabric_wwn = "2001000dec9877c1";
    const char *expect_max_vports = "127";
    const char *expect_vports = "0";
    char *wwnn = NULL;
    char *wwpn = NULL;
    char *fabric_wwn = NULL;
    char *max_vports = NULL;
    char *vports = NULL;
    int ret = -1;

    if (!(wwnn = virReadFCHost(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM,
                               "node_name")))
        return -1;

    if (!(wwpn = virReadFCHost(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM,
                               "port_name")))
        goto cleanup;

    if (!(fabric_wwn = virReadFCHost(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM,
                                     "fabric_name")))
        goto cleanup;

    if (!(max_vports = virReadFCHost(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM,
                                     "max_npiv_vports")))
        goto cleanup;


    if (!(vports = virReadFCHost(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM,
                                 "npiv_vports_inuse")))
        goto cleanup;

    if (STRNEQ(expect_wwnn, wwnn) ||
        STRNEQ(expect_wwpn, wwpn) ||
        STRNEQ(expect_fabric_wwn, fabric_wwn) ||
        STRNEQ(expect_max_vports, max_vports) ||
        STRNEQ(expect_vports, vports))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    VIR_FREE(fabric_wwn);
    VIR_FREE(max_vports);
    VIR_FREE(vports);
    return ret;
}

/* Test virGetFCHostNameByWWN */
static int
test4(const void *data ATTRIBUTE_UNUSED)
{
    const char *expect_hostname = "host5";
    char *hostname = NULL;
    int ret = -1;

    if (!(hostname = virGetFCHostNameByWWN(TEST_FC_HOST_PREFIX,
                                           "2001001b32a9da4e",
                                           "2101001b32a9da4e")))
        return -1;

    if (STRNEQ(hostname, expect_hostname))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(hostname);
    return ret;
}

/* Test virFindFCHostCapableVport (host4 is not Online) */
static int
test5(const void *data ATTRIBUTE_UNUSED)
{
    const char *expect_hostname = "host5";
    char *hostname = NULL;
    int ret = -1;

    if (!(hostname = virFindFCHostCapableVport(TEST_FC_HOST_PREFIX)))
        return -1;

    if (STRNEQ(hostname, expect_hostname))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(hostname);
    return ret;
}

/* Test virReadFCHost fabric name optional */
static int
test6(const void *data ATTRIBUTE_UNUSED)
{
    const char *expect_wwnn = "2002001b32a9da4e";
    const char *expect_wwpn = "2102001b32a9da4e";
    char *wwnn = NULL;
    char *wwpn = NULL;
    char *fabric_wwn = NULL;
    int ret = -1;

    if (!(wwnn = virReadFCHost(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM_NO_FAB,
                               "node_name")))
        return -1;

    if (!(wwpn = virReadFCHost(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM_NO_FAB,
                               "port_name")))
        goto cleanup;

    if ((fabric_wwn = virReadFCHost(TEST_FC_HOST_PREFIX,
                                    TEST_FC_HOST_NUM_NO_FAB,
                                    "fabric_name")))
        goto cleanup;

    if (STRNEQ(expect_wwnn, wwnn) ||
        STRNEQ(expect_wwpn, wwpn))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(wwnn);
    VIR_FREE(wwpn);
    VIR_FREE(fabric_wwn);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

    if (virAsprintf(&fchost_prefix, "%s/%s", abs_srcdir,
                    "fchostdata/fc_host/") < 0) {
        ret = -1;
        goto cleanup;
    }

    if (virTestRun("test1", test1, NULL) < 0)
        ret = -1;
    if (virTestRun("test2", test2, NULL) < 0)
        ret = -1;
    if (virTestRun("test3", test3, NULL) < 0)
        ret = -1;
    if (virTestRun("test4", test4, NULL) < 0)
        ret = -1;
    if (virTestRun("test5", test5, NULL) < 0)
        ret = -1;
    if (virTestRun("test6", test6, NULL) < 0)
        ret = -1;

 cleanup:
    VIR_FREE(fchost_prefix);
    return ret;
}

VIRT_TEST_MAIN(mymain)
