#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "network_conf.h"
#include "testutilsqemu.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

typedef enum {
    TEST_COMPARE_NET_XML2XML_RESULT_SUCCESS,
    TEST_COMPARE_NET_XML2XML_RESULT_FAIL_PARSE,
    TEST_COMPARE_NET_XML2XML_RESULT_FAIL_FORMAT,
    TEST_COMPARE_NET_XML2XML_RESULT_FAIL_COMPARE,
} testCompareNetXML2XMLResult;

static int
testCompareXMLToXMLFiles(const char *inxml, const char *outxml,
                         unsigned int flags,
                         testCompareNetXML2XMLResult expectResult)
{
    char *actual = NULL;
    int ret;
    testCompareNetXML2XMLResult result = TEST_COMPARE_NET_XML2XML_RESULT_SUCCESS;
    virNetworkDefPtr dev = NULL;

    if (!(dev = virNetworkDefParseFile(inxml))) {
        result = TEST_COMPARE_NET_XML2XML_RESULT_FAIL_PARSE;
        goto cleanup;
    }
    if (expectResult == TEST_COMPARE_NET_XML2XML_RESULT_FAIL_PARSE)
        goto cleanup;

    if (!(actual = virNetworkDefFormat(dev, flags))) {
        result = TEST_COMPARE_NET_XML2XML_RESULT_FAIL_FORMAT;
        goto cleanup;
    }
    if (expectResult == TEST_COMPARE_NET_XML2XML_RESULT_FAIL_FORMAT)
        goto cleanup;

    if (virTestCompareToFile(actual, outxml) < 0) {
        result = TEST_COMPARE_NET_XML2XML_RESULT_FAIL_COMPARE;
        goto cleanup;
    }
    if (expectResult == TEST_COMPARE_NET_XML2XML_RESULT_FAIL_COMPARE)
        goto cleanup;

 cleanup:
    if (result == expectResult) {
        ret = 0;
        if (expectResult != TEST_COMPARE_NET_XML2XML_RESULT_SUCCESS) {
            VIR_TEST_DEBUG("Got expected failure code=%d msg=%s",
                           result, virGetLastErrorMessage());
        }
    } else {
        ret = -1;
        VIR_TEST_DEBUG("Expected result code=%d but received code=%d",
                       expectResult, result);
    }
    virResetLastError();

    VIR_FREE(actual);
    virNetworkDefFree(dev);
    return ret;
}

struct testInfo {
    const char *name;
    unsigned int flags;
    testCompareNetXML2XMLResult expectResult;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    int result = -1;
    char *inxml = NULL;
    char *outxml = NULL;

    if (virAsprintf(&inxml, "%s/networkxml2xmlin/%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&outxml, "%s/networkxml2xmlout/%s.xml",
                    abs_srcdir, info->name) < 0) {
        goto cleanup;
    }

    result = testCompareXMLToXMLFiles(inxml, outxml, info->flags,
                                      info->expectResult);

 cleanup:
    VIR_FREE(inxml);
    VIR_FREE(outxml);

    return result;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_FULL(name, flags, expectResult)                         \
    do {                                                                \
        const struct testInfo info = {name, flags, expectResult};       \
        if (virTestRun("Network XML-2-XML " name,                       \
                       testCompareXMLToXMLHelper, &info) < 0)           \
            ret = -1;                                                   \
    } while (0)
#define DO_TEST(name) \
    DO_TEST_FULL(name, 0, TEST_COMPARE_NET_XML2XML_RESULT_SUCCESS)
#define DO_TEST_FLAGS(name, flags) \
    DO_TEST_FULL(name, flags, TEST_COMPARE_NET_XML2XML_RESULT_SUCCESS)
#define DO_TEST_PARSE_ERROR(name) \
    DO_TEST_FULL(name, 0, TEST_COMPARE_NET_XML2XML_RESULT_FAIL_PARSE)

    DO_TEST("dhcp6host-routed-network");
    DO_TEST("empty-allow-ipv6");
    DO_TEST("isolated-network");
    DO_TEST("routed-network");
    DO_TEST("routed-network-no-dns");
    DO_TEST_PARSE_ERROR("routed-network-no-dns-extra-elements");
    DO_TEST("open-network");
    DO_TEST_PARSE_ERROR("open-network-with-forward-dev");
    DO_TEST("nat-network");
    DO_TEST("netboot-network");
    DO_TEST("netboot-proxy-network");
    DO_TEST("nat-network-dns-txt-record");
    DO_TEST("nat-network-dns-srv-record");
    DO_TEST("nat-network-dns-srv-records");
    DO_TEST("nat-network-dns-srv-record-minimal");
    DO_TEST("nat-network-dns-hosts");
    DO_TEST("nat-network-dns-forward-plain");
    DO_TEST("nat-network-dns-forwarders");
    DO_TEST("nat-network-dns-forwarder-no-resolv");
    DO_TEST("nat-network-forward-nat-address");
    DO_TEST("nat-network-forward-nat-no-address");
    DO_TEST("8021Qbh-net");
    DO_TEST("direct-net");
    DO_TEST("host-bridge-net");
    DO_TEST("vepa-net");
    DO_TEST("bandwidth-network");
    DO_TEST("openvswitch-net");
    DO_TEST_FLAGS("passthrough-pf", VIR_NETWORK_XML_INACTIVE);
    DO_TEST("hostdev");
    DO_TEST_FLAGS("hostdev-pf", VIR_NETWORK_XML_INACTIVE);
    DO_TEST("passthrough-address-crash");
    DO_TEST("nat-network-explicit-flood");
    DO_TEST("host-bridge-no-flood");
    DO_TEST_PARSE_ERROR("hostdev-duplicate");
    DO_TEST_PARSE_ERROR("passthrough-duplicate");
    DO_TEST("metadata");
    DO_TEST("set-mtu");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
