#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "testutils.h"
#include "nwfilter_conf.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int
testCompareXMLToXMLFiles(const char *inxml, const char *outxml,
                         bool expect_error)
{
    g_autofree char *actual = NULL;
    g_autoptr(virNWFilterDef) def = NULL;

    virResetLastError();

    if (!(def = virNWFilterDefParse(NULL, inxml, 0))) {
        if (expect_error) {
            virResetLastError();
            return 0;
        }
        return -1;
    }

    if (!(actual = virNWFilterDefFormat(def)))
        return -1;

    if (virTestCompareToFile(actual, outxml) < 0)
        return -1;

    return 0;
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
    g_autofree char *inxml = NULL;
    g_autofree char *outxml = NULL;

    inxml = g_strdup_printf("%s/nwfilterxml2xmlin/%s.xml", abs_srcdir, tp->name);
    outxml = g_strdup_printf("%s/nwfilterxml2xmlout/%s.xml", abs_srcdir, tp->name);

    result = testCompareXMLToXMLFiles(inxml, outxml, tp->expect_warning);

    return result;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(NAME, EXPECT_WARN) \
    do { \
        test_parms tp = { \
            .name = NAME, \
            .expect_warning = EXPECT_WARN, \
        }; \
        if (virTestRun("NWFilter XML-2-XML " NAME, \
                       testCompareXMLToXMLHelper, (&tp)) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST("mac-test-invalid", true);
    DO_TEST("vlan-test-invalid", true);
    DO_TEST("stp-test", false);
    DO_TEST("arp-test-invalid", true);
    DO_TEST("rarp-test-invalid", true);
    DO_TEST("ip-test-invalid", true);
    DO_TEST("ipv6-test-invalid", true);

    DO_TEST("tcp-test-invalid", true);
    DO_TEST("udp-test-invalid", true);
    DO_TEST("icmp-test-invalid", true);
    DO_TEST("igmp-test", false);
    DO_TEST("sctp-test-invalid", true);
    DO_TEST("udplite-test", false);
    DO_TEST("esp-test", false);
    DO_TEST("ah-test", false);
    DO_TEST("all-test", false);

    DO_TEST("tcp-ipv6-test-invalid", true);
    DO_TEST("udp-ipv6-test-invalid", true);
    DO_TEST("icmpv6-test-invalid", true);
    DO_TEST("sctp-ipv6-test-invalid", true);
    DO_TEST("udplite-ipv6-test-invalid", true);
    DO_TEST("esp-ipv6-test-invalid", true);
    DO_TEST("ah-ipv6-test-invalid", true);
    DO_TEST("all-ipv6-test-invalid", true);

    DO_TEST("ref-test", false);
    DO_TEST("ref-rule-test", false);
    DO_TEST("ipt-no-macspoof-test", false);
    DO_TEST("icmp-direction-test", false);
    DO_TEST("icmp-direction2-test", false);
    DO_TEST("icmp-direction3-test", false);

    DO_TEST("conntrack-test", false);

    DO_TEST("hex-data-test-invalid", true);

    DO_TEST("comment-test-invalid", true);

    DO_TEST("example-1", false);
    DO_TEST("example-2", false);

    /* The parser and formatter for nwfilter rules was written in a quirky way.
     * Validate that it still works. Note that the files don't conform to the
     * schema */
    DO_TEST("quirks-invalid", false);

    DO_TEST("chain_prefixtest1-invalid", true); /* derived from arp-test */

    DO_TEST("attr-value-test", false);
    DO_TEST("iter-test1", false);
    DO_TEST("iter-test2", false);
    DO_TEST("iter-test3", false);

    DO_TEST("ipset-test", false);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
