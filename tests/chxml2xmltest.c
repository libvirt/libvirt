#include <config.h>

#include <testutils.h>

#include "ch/ch_conf.h"

struct testInfo {
    const char *name;
    virCHDriver *driver;
    testCompareDomXML2XMLResult expectResult;
};

typedef enum {
    FLAG_IS_DIFFERENT =   1 << 0,
    FLAG_EXPECT_FAILURE = 1 << 1,
} virBhyveXMLToXMLTestFlags;

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    g_autofree char *xml_in = NULL;
    g_autofree char *xml_out = NULL;

    xml_in = g_strdup_printf("%s/chxml2xmlin/%s.xml",
                             abs_srcdir, info->name);
    xml_out = g_strdup_printf("%s/chxml2xmlout/%s.xml",
                              abs_srcdir, info->name);

    return testCompareDomXML2XMLFiles(NULL, info->driver->xmlopt,
                                      xml_in, xml_out, false, 0,
                                      info->expectResult);
}

static int
mymain(void)
{
    int ret = 0;
    virCHDriver *driver = NULL;

    driver = g_new0(virCHDriver, 1);

    if (!(driver->caps = virCHDriverCapsInit())) {
        fprintf(stderr, "unable to initialize driver capabilities\n");
        goto cleanup;
    }

    if (!(driver->xmlopt = chDomainXMLConfInit(driver))) {
        fprintf(stderr, "unable to initialize driver XMLOPT\n");
        goto cleanup;
    }

#define DO_TEST_FULL(name, expectResult) \
    do { \
        const struct testInfo info = {name, driver, expectResult}; \
        if (virTestRun("CH XML-2-XML " name, \
                       testCompareXMLToXMLHelper, &info) < 0) \
        ret = -1; \
    } while (0)

#define DO_TEST(name) \
    DO_TEST_FULL(name, TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS)

#define DO_TEST_FAIL_PARSE(name) \
    DO_TEST_FULL(name, TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE)

    DO_TEST("basic");

 cleanup:
    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->caps);
    g_free(driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
