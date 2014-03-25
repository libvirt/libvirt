#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "virxml.h"
#include "virthread.h"
#include "nwfilter_params.h"
#include "nwfilter_conf.h"
#include "testutilsqemu.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *inxml, const char *outxml,
                         bool expect_error)
{
    char *inXmlData = NULL;
    char *outXmlData = NULL;
    char *actual = NULL;
    int ret = -1;
    virNWFilterDefPtr dev = NULL;

    if (virtTestLoadFile(inxml, &inXmlData) < 0)
        goto fail;
    if (virtTestLoadFile(outxml, &outXmlData) < 0)
        goto fail;

    virResetLastError();

    if (!(dev = virNWFilterDefParseString(inXmlData))) {
        if (expect_error) {
            virResetLastError();
            goto done;
        }
        goto fail;
    }

    if (!(actual = virNWFilterDefFormat(dev)))
        goto fail;

    if (STRNEQ(outXmlData, actual)) {
        virtTestDifference(stderr, outXmlData, actual);
        goto fail;
    }

 done:
    ret = 0;

 fail:
    VIR_FREE(inXmlData);
    VIR_FREE(outXmlData);
    VIR_FREE(actual);
    virNWFilterDefFree(dev);
    return ret;
}

typedef struct test_parms {
    const char *name;
    bool expect_warning;
} test_parms;

static int
testCompareXMLToXMLHelper(const void *data)
{
    int result = -1;
    const test_parms *tp = data;
    char *inxml = NULL;
    char *outxml = NULL;

    if (virAsprintf(&inxml, "%s/nwfilterxml2xmlin/%s.xml",
                    abs_srcdir, tp->name) < 0 ||
        virAsprintf(&outxml, "%s/nwfilterxml2xmlout/%s.xml",
                    abs_srcdir, tp->name) < 0) {
        goto cleanup;
    }

    result = testCompareXMLToXMLFiles(inxml, outxml, tp->expect_warning);

 cleanup:
    VIR_FREE(inxml);
    VIR_FREE(outxml);

    return result;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(NAME, EXPECT_WARN)                                \
    do {                                                          \
        test_parms tp = {                                         \
            .name = NAME,                                         \
            .expect_warning = EXPECT_WARN,                        \
        };                                                        \
        if (virtTestRun("NWFilter XML-2-XML " NAME,               \
                        testCompareXMLToXMLHelper, (&tp)) < 0)    \
            ret = -1;                                             \
    } while (0)

    DO_TEST("mac-test", true);
    DO_TEST("vlan-test", true);
    DO_TEST("stp-test", false);
    DO_TEST("arp-test", true);
    DO_TEST("rarp-test", true);
    DO_TEST("ip-test", true);
    DO_TEST("ipv6-test", true);

    DO_TEST("tcp-test", true);
    DO_TEST("udp-test", true);
    DO_TEST("icmp-test", true);
    DO_TEST("igmp-test", false);
    DO_TEST("sctp-test", true);
    DO_TEST("udplite-test", false);
    DO_TEST("esp-test", false);
    DO_TEST("ah-test", false);
    DO_TEST("all-test", false);

    DO_TEST("tcp-ipv6-test", true);
    DO_TEST("udp-ipv6-test", true);
    DO_TEST("icmpv6-test", true);
    DO_TEST("sctp-ipv6-test", true);
    DO_TEST("udplite-ipv6-test", true);
    DO_TEST("esp-ipv6-test", true);
    DO_TEST("ah-ipv6-test", true);
    DO_TEST("all-ipv6-test", true);

    DO_TEST("ref-test", false);
    DO_TEST("ref-rule-test", false);
    DO_TEST("ipt-no-macspoof-test", false);
    DO_TEST("icmp-direction-test", false);
    DO_TEST("icmp-direction2-test", false);
    DO_TEST("icmp-direction3-test", false);

    DO_TEST("conntrack-test", false);

    DO_TEST("hex-data-test", true);

    DO_TEST("comment-test", true);

    DO_TEST("example-1", false);
    DO_TEST("example-2", false);

    DO_TEST("chain_prefixtest1", true); /* derived from arp-test */

    DO_TEST("attr-value-test", false);
    DO_TEST("iter-test1", false);
    DO_TEST("iter-test2", false);
    DO_TEST("iter-test3", false);

    DO_TEST("ipset-test", false);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
