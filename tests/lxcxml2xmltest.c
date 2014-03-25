#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#ifdef WITH_LXC

# include "internal.h"
# include "lxc/lxc_conf.h"
# include "testutilslxc.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static virCapsPtr caps;
static virDomainXMLOptionPtr xmlopt;

static int
testCompareXMLToXMLFiles(const char *inxml, const char *outxml, bool live)
{
    char *inXmlData = NULL;
    char *outXmlData = NULL;
    char *actual = NULL;
    int ret = -1;
    virDomainDefPtr def = NULL;

    if (virtTestLoadFile(inxml, &inXmlData) < 0)
        goto fail;
    if (virtTestLoadFile(outxml, &outXmlData) < 0)
        goto fail;

    if (!(def = virDomainDefParseString(inXmlData, caps, xmlopt,
                                        1 << VIR_DOMAIN_VIRT_LXC,
                                        live ? 0 : VIR_DOMAIN_XML_INACTIVE)))
        goto fail;

    if (!virDomainDefCheckABIStability(def, def)) {
        fprintf(stderr, "ABI stability check failed on %s", inxml);
        goto fail;
    }

    if (!(actual = virDomainDefFormat(def, VIR_DOMAIN_XML_SECURE)))
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
    int different;
    bool inactive_only;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    char *xml_in = NULL;
    char *xml_out = NULL;
    int ret = -1;

    if (virAsprintf(&xml_in, "%s/lxcxml2xmldata/lxc-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&xml_out, "%s/lxcxml2xmloutdata/lxc-%s.xml",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    if (info->different) {
        if (testCompareXMLToXMLFiles(xml_in, xml_out, false) < 0)
            goto cleanup;
    } else {
        if (testCompareXMLToXMLFiles(xml_in, xml_in, false) < 0)
            goto cleanup;
    }
    if (!info->inactive_only) {
        if (info->different) {
            if (testCompareXMLToXMLFiles(xml_in, xml_out, true) < 0)
                goto cleanup;
        } else {
            if (testCompareXMLToXMLFiles(xml_in, xml_in, true) < 0)
                goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(xml_in);
    VIR_FREE(xml_out);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if ((caps = testLXCCapsInit()) == NULL)
        return EXIT_FAILURE;

    if (!(xmlopt = lxcDomainXMLConfInit()))
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, is_different, inactive)                     \
    do {                                                                \
        const struct testInfo info = {name, is_different, inactive};    \
        if (virtTestRun("LXC XML-2-XML " name,                          \
                        testCompareXMLToXMLHelper, &info) < 0)          \
            ret = -1;                                                   \
    } while (0)

# define DO_TEST(name) \
    DO_TEST_FULL(name, 0, false)

# define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, 1, false)

    /* Unset or set all envvars here that are copied in lxcdBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

    DO_TEST("systemd");
    DO_TEST("hostdev");
    DO_TEST("disk-formats");
    DO_TEST_DIFFERENT("filesystem-ram");
    DO_TEST("filesystem-root");
    DO_TEST("idmap");

    virObjectUnref(caps);
    virObjectUnref(xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_LXC */
