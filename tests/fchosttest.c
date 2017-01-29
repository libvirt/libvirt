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

#include "virlog.h"
#include "virstring.h"
#include "virvhba.h"
#include "testutils.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.fchosttest");

static char *fchost_prefix;

#define TEST_FC_HOST_PREFIX fchost_prefix
#define TEST_FC_HOST_NUM 5
#define TEST_FC_HOST_NUM_NO_FAB 6

/* virNodeDeviceCreateXML using "<parent>" to find the vport capable HBA */
static const char test7_xml[] =
"<device>"
"  <parent>scsi_host1</parent>"
"  <capability type='scsi_host'>"
"    <capability type='fc_host'>"
"    </capability>"
"  </capability>"
"</device>";

/* virNodeDeviceCreateXML without "<parent>" to find the vport capable HBA */
static const char test8_xml[] =
"<device>"
"  <capability type='scsi_host'>"
"    <capability type='fc_host'>"
"    </capability>"
"  </capability>"
"</device>";

/* virNodeDeviceCreateXML using "<parent wwnn='%s' wwpn='%s'/>" to find
 * the vport capable HBA */
static const char test9_xml[] =
"<device>"
"  <parent wwnn='2000000012341234' wwpn='1000000012341234'/>"
"  <capability type='scsi_host'>"
"    <capability type='fc_host'>"
"    </capability>"
"  </capability>"
"</device>";

/* virNodeDeviceCreateXML using "<parent fabric_wwn='%s'/>" to find the
 * vport capable HBA */
static const char test10_xml[] =
"<device>"
"  <parent fabric_wwn='2000000043214321'/>"
"  <capability type='scsi_host'>"
"    <capability type='fc_host'>"
"    </capability>"
"  </capability>"
"</device>";

/* virStoragePoolCreateXML using parent='%s' to find the vport capable HBA */
static const char test11_xml[] =
"<pool type='scsi'>"
"  <name>vhba_pool</name>"
"  <source>"
"    <adapter type='fc_host' parent='scsi_host1' wwnn='20000000c9831b4b' wwpn='10000000c9831b4b'/>"
"  </source>"
"  <target>"
"    <path>/dev/disk/by-path</path>"
"  </target>"
"</pool>";


/* Test virIsVHBACapable */
static int
test1(const void *data ATTRIBUTE_UNUSED)
{
    if (virVHBAPathExists(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM) &&
        virVHBAPathExists(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM_NO_FAB))
        return 0;

    return -1;
}

/* Test virVHBAIsVportCapable */
static int
test2(const void *data ATTRIBUTE_UNUSED)
{
    if (virVHBAIsVportCapable(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM))
        return 0;

    return -1;
}

/* Test virVHBAGetConfig */
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

    if (!(wwnn = virVHBAGetConfig(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM,
                                  "node_name")))
        return -1;

    if (!(wwpn = virVHBAGetConfig(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM,
                                  "port_name")))
        goto cleanup;

    if (!(fabric_wwn = virVHBAGetConfig(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM,
                                        "fabric_name")))
        goto cleanup;

    if (!(max_vports = virVHBAGetConfig(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM,
                                        "max_npiv_vports")))
        goto cleanup;


    if (!(vports = virVHBAGetConfig(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM,
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

/* Test virVHBAGetHostByWWN */
static int
test4(const void *data ATTRIBUTE_UNUSED)
{
    const char *expect_hostname = "host5";
    char *hostname = NULL;
    int ret = -1;

    if (!(hostname = virVHBAGetHostByWWN(TEST_FC_HOST_PREFIX,
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

/* Test virVHBAFindVportHost
 *
 * NB: host4 is not Online, so it should not be found
 */
static int
test5(const void *data ATTRIBUTE_UNUSED)
{
    const char *expect_hostname = "host5";
    char *hostname = NULL;
    int ret = -1;

    if (!(hostname = virVHBAFindVportHost(TEST_FC_HOST_PREFIX)))
        return -1;

    if (STRNEQ(hostname, expect_hostname))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(hostname);
    return ret;
}

/* Test virVHBAGetConfig fabric name optional */
static int
test6(const void *data ATTRIBUTE_UNUSED)
{
    const char *expect_wwnn = "2002001b32a9da4e";
    const char *expect_wwpn = "2102001b32a9da4e";
    char *wwnn = NULL;
    char *wwpn = NULL;
    char *fabric_wwn = NULL;
    int ret = -1;

    if (!(wwnn = virVHBAGetConfig(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM_NO_FAB,
                                  "node_name")))
        return -1;

    if (!(wwpn = virVHBAGetConfig(TEST_FC_HOST_PREFIX, TEST_FC_HOST_NUM_NO_FAB,
                                  "port_name")))
        goto cleanup;

    if ((fabric_wwn = virVHBAGetConfig(TEST_FC_HOST_PREFIX,
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



/* Test manageVHBAByNodeDevice
 *  - Test both virNodeDeviceCreateXML and virNodeDeviceDestroy
 *  - Create a node device vHBA allowing usage of various different
 *    methods based on the input data/xml argument.
 *  - Be sure that it's possible to destroy the node device as well.
 */
static int
manageVHBAByNodeDevice(const void *data)
{
    const char *expect_hostname = "scsi_host12";
    virConnectPtr conn = NULL;
    virNodeDevicePtr dev = NULL;
    int ret = -1;
    const char *vhba = data;

    if (!(conn = virConnectOpen("test:///default")))
        return -1;

    if (!(dev = virNodeDeviceCreateXML(conn, vhba, 0)))
        goto cleanup;

    if (virNodeDeviceDestroy(dev) < 0)
        goto cleanup;

    if (STRNEQ(virNodeDeviceGetName(dev), expect_hostname)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected hostname: '%s' got: '%s'",
                       expect_hostname, virNodeDeviceGetName(dev));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (dev)
        virNodeDeviceFree(dev);
    if (conn)
        virConnectClose(conn);
    return ret;
}


/* Test manageVHBAByStoragePool
 *  - Test both virStoragePoolCreateXML and virStoragePoolDestroy
 *  - Create a storage pool vHBA allowing usage of various different
 *    methods based on the input data/xml argument.
 *  - Be sure that it's possible to destroy the storage pool as well.
 */
static int
manageVHBAByStoragePool(const void *data)
{
    const char *expect_hostname = "scsi_host12";
    virConnectPtr conn = NULL;
    virStoragePoolPtr pool = NULL;
    virNodeDevicePtr dev = NULL;
    int ret = -1;
    const char *vhba = data;

    if (!(conn = virConnectOpen("test:///default")))
        return -1;

    if (!(pool = virStoragePoolCreateXML(conn, vhba, 0)))
        goto cleanup;

    if (!(dev = virNodeDeviceLookupByName(conn, expect_hostname))) {
        VIR_DEBUG("Failed to find expected_hostname '%s'", expect_hostname);
        ignore_value(virStoragePoolDestroy(pool));
        goto cleanup;
    }

    if (virStoragePoolDestroy(pool) < 0)
        goto cleanup;

    if ((dev = virNodeDeviceLookupByName(conn, expect_hostname))) {
        VIR_DEBUG("Found expected_hostname '%s' after destroy",
                  expect_hostname);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (pool)
        virStoragePoolFree(pool);
    if (conn)
        virConnectClose(conn);
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

    if (virTestRun("virVHBAPathExists", test1, NULL) < 0)
        ret = -1;
    if (virTestRun("virVHBAIsVportCapable", test2, NULL) < 0)
        ret = -1;
    if (virTestRun("virVHBAGetConfig", test3, NULL) < 0)
        ret = -1;
    if (virTestRun("virVHBAGetHostByWWN", test4, NULL) < 0)
        ret = -1;
    if (virTestRun("virVHBAFindVportHost", test5, NULL) < 0)
        ret = -1;
    if (virTestRun("virVHBAGetConfig-empty-fabric_wwn", test6, NULL) < 0)
        ret = -1;
    if (virTestRun("manageVHBAByNodeDevice-by-parent", manageVHBAByNodeDevice,
                   test7_xml) < 0)
        ret = -1;
    if (virTestRun("manageVHBAByNodeDevice-no-parent", manageVHBAByNodeDevice,
                   test8_xml) < 0)
        ret = -1;
    if (virTestRun("manageVHBAByNodeDevice-parent-wwn", manageVHBAByNodeDevice,
                   test9_xml) < 0)
        ret = -1;
    if (virTestRun("manageVHBAByNodeDevice-parent-fabric-wwn",
                   manageVHBAByNodeDevice, test10_xml) < 0)
        ret = -1;
    if (virTestRun("manageVHBAByStoragePool-by-parent", manageVHBAByStoragePool,
                   test11_xml) < 0)
        ret = -1;

 cleanup:
    VIR_FREE(fchost_prefix);
    return ret;
}

VIRT_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virrandommock.so")
