#include <config.h>

#include "testutils.h"

#ifdef WITH_BHYVE

# include "bhyve/bhyve_capabilities.h"
# include "bhyve/bhyve_utils.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static bhyveConn driver;

static int
testCompareXMLToXMLFiles(const char *inxml, const char *outxml)
{
    char *inXmlData = NULL;
    char *outXmlData = NULL;
    char *actual = NULL;
    virDomainDefPtr def = NULL;
    int ret = -1;

    if (virtTestLoadFile(inxml, &inXmlData) < 0)
        goto fail;

    if (virtTestLoadFile(outxml, &outXmlData) < 0)
        goto fail;

    if (!(def = virDomainDefParseString(inXmlData, driver.caps, driver.xmlopt,
                                        1 << VIR_DOMAIN_VIRT_BHYVE,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto fail;

    if (!(actual = virDomainDefFormat(def, VIR_DOMAIN_DEF_FORMAT_INACTIVE)))
        goto fail;

    if (STRNEQ(outXmlData, actual)) {
        virtTestDifference(stderr, outXmlData, actual);
        goto fail;
    }

    ret = 0;

 fail:
    VIR_FREE(inXmlData);
    VIR_FREE(outXmlData);
    VIR_FREE(actual);
    virDomainDefFree(def);
    return ret;
}

struct testInfo {
    const char *name;
    bool different;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    char *xml_in = NULL;
    char *xml_out = NULL;
    int ret = -1;

    if (virAsprintf(&xml_in, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&xml_out, "%s/bhyvexml2xmloutdata/bhyvexml2xmlout-%s.xml",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    ret = testCompareXMLToXMLFiles(xml_in,
                                   info->different ? xml_out : xml_in);

 cleanup:
    VIR_FREE(xml_in);
    VIR_FREE(xml_out);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

    if ((driver.caps = virBhyveCapsBuild()) == NULL)
        return EXIT_FAILURE;

    if ((driver.xmlopt = virDomainXMLOptionNew(NULL, NULL, NULL)) == NULL)
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, is_different)                        \
    do {                                                         \
        const struct testInfo info = {name, is_different};       \
        if (virtTestRun("BHYVE XML-2-XML " name,                 \
                       testCompareXMLToXMLHelper, &info) < 0)    \
            ret = -1;                                            \
    } while (0)

# define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, true)

    DO_TEST_DIFFERENT("metadata");

    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_BHYVE */
