#include <config.h>

#include "testutils.h"

#ifdef WITH_BHYVE

# include "bhyve/bhyve_capabilities.h"
# include "bhyve/bhyve_utils.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static bhyveConn driver;

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

    ret = testCompareDomXML2XMLFiles(driver.caps, driver.xmlopt, xml_in,
                                     info->different ? xml_out : xml_in,
                                     false);

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
