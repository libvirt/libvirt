#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#ifdef WITH_LXC

# include "internal.h"
# include "lxc/lxc_conf.h"
# include "testutilslxc.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static virLXCDriver *driver;

struct testInfo {
    const char *name;
    int different;
    bool active_only;
    unsigned int parse_flags;
};

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    g_autofree char *xml_in = NULL;
    g_autofree char *xml_out = NULL;
    int ret = -1;

    xml_in = g_strdup_printf("%s/lxcxml2xmldata/lxc-%s.xml",
                             abs_srcdir, info->name);
    xml_out = g_strdup_printf("%s/lxcxml2xmloutdata/lxc-%s.xml",
                              abs_srcdir, info->name);

    ret = testCompareDomXML2XMLFiles(driver->caps, driver->xmlopt, xml_in,
                                     info->different ? xml_out : xml_in,
                                     info->active_only,
                                     info->parse_flags,
                                     TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if (!(driver = testLXCDriverInit()))
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, is_different, active, parse_flags) \
    do { \
        const struct testInfo info = {name, is_different, active, \
                                      parse_flags}; \
        if (virTestRun("LXC XML-2-XML " name, \
                       testCompareXMLToXMLHelper, &info) < 0) \
            ret = -1; \
    } while (0)

# define DO_TEST(name) \
    DO_TEST_FULL(name, 0, true, 0)

# define DO_TEST_DIFFERENT(name) \
    DO_TEST_FULL(name, 1, true, 0)

    /* Unset or set all envvars here that are copied in lxcdBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    g_setenv("PATH", "/bin", TRUE);

    DO_TEST("systemd");
    DO_TEST("hostdev");
    DO_TEST("disk-formats");
    DO_TEST_DIFFERENT("filesystem-ram");
    DO_TEST("filesystem-root");
    DO_TEST("idmap");
    DO_TEST("capabilities");
    DO_TEST("sharenet");
    DO_TEST("ethernet");
    DO_TEST("ethernet-hostip");
    DO_TEST("initenv");
    DO_TEST("initdir");
    DO_TEST("inituser");

    testLXCDriverFree(driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_LXC */
