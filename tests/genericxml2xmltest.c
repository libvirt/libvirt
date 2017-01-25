#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"
#include "internal.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virCapsPtr caps;
static virDomainXMLOptionPtr xmlopt;

struct testInfo {
    const char *name;
    int different;
    bool inactive_only;
    testCompareDomXML2XMLResult expectResult;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    char *xml_in = NULL;
    char *xml_out = NULL;
    int ret = -1;

    if (virAsprintf(&xml_in, "%s/genericxml2xmlindata/generic-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&xml_out, "%s/genericxml2xmloutdata/generic-%s.xml",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    ret = testCompareDomXML2XMLFiles(caps, xmlopt, xml_in,
                                     info->different ? xml_out : xml_in,
                                     !info->inactive_only, NULL, NULL, 0,
                                     info->expectResult);
 cleanup:
    VIR_FREE(xml_in);
    VIR_FREE(xml_out);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if (!(caps = virTestGenericCapsInit()))
        return EXIT_FAILURE;

    if (!(xmlopt = virTestGenericDomainXMLConfInit()))
        return EXIT_FAILURE;

#define DO_TEST_FULL(name, is_different, inactive, expectResult)        \
    do {                                                                \
        const struct testInfo info = {name, is_different, inactive,     \
                                      expectResult};                    \
        if (virTestRun("GENERIC XML-2-XML " name,                       \
                       testCompareXMLToXMLHelper, &info) < 0)           \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST(name) \
    DO_TEST_FULL(name, 0, false, TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS)

#define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, 1, false, TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS)

    DO_TEST_DIFFERENT("disk-virtio");

    DO_TEST_DIFFERENT("graphics-vnc-minimal");
    DO_TEST_DIFFERENT("graphics-vnc-manual-port");
    DO_TEST_DIFFERENT("graphics-vnc-socket");
    DO_TEST_DIFFERENT("graphics-vnc-socket-listen");
    DO_TEST_DIFFERENT("graphics-listen-back-compat");
    DO_TEST_FULL("graphics-listen-back-compat-mismatch", 0, false,
        TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST_DIFFERENT("graphics-vnc-listen-attr-only");
    DO_TEST_DIFFERENT("graphics-vnc-listen-element-minimal");
    DO_TEST_DIFFERENT("graphics-vnc-listen-element-with-address");
    DO_TEST_DIFFERENT("graphics-vnc-socket-attr-listen-address");
    DO_TEST_DIFFERENT("graphics-vnc-socket-attr-listen-socket");
    DO_TEST_FULL("graphics-vnc-socket-attr-listen-socket-mismatch", 0, false,
        TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);
    DO_TEST("graphics-vnc-autoport-no");

    DO_TEST_FULL("name-slash-fail", 0, false,
        TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE);

    DO_TEST("perf");

    DO_TEST("vcpus-individual");

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
