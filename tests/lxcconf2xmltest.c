#include <config.h>

#include "testutils.h"

#ifdef WITH_LXC

# include "lxc/lxc_native.h"
# include "lxc/lxc_conf.h"
# include "testutilslxc.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static virLXCDriver *driver;

static int testSanitizeDef(virDomainDef *vmdef)
{
    /* Remove UUID randomness */
    if (virUUIDParse("c7a5fdbd-edaf-9455-926a-d65c16db1809", vmdef->uuid) < 0)
        return -1;
    return 0;
}

static int
testCompareXMLToConfigFiles(const char *xmlfile,
                            const char *configfile,
                            bool expectError)
{
    g_autofree char *config = NULL;
    g_autofree char *actualxml = NULL;
    g_autoptr(virDomainDef) vmdef = NULL;

    if (virTestLoadFile(configfile, &config) < 0)
        return -1;

    vmdef = lxcParseConfigString(config, driver->caps, driver->xmlopt);
    if ((vmdef && expectError) || (!vmdef && !expectError))
        return -1;

    if (vmdef) {
        if (testSanitizeDef(vmdef) < 0)
            return -1;

        if (!(actualxml = virDomainDefFormat(vmdef, driver->xmlopt, 0)))
            return -1;

        if (virTestCompareToFile(actualxml, xmlfile) < 0)
            return -1;
    }

    return 0;
}

struct testInfo {
    const char *name;
    bool expectError;
};

static int
testCompareXMLToConfigHelperLegacy(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    g_autofree char *xml = NULL;
    g_autofree char *config = NULL;

    xml = g_strdup_printf("%s/lxcconf2xmldata/lxcconf2xml-%s.xml",
                          abs_srcdir, info->name);
    config = g_strdup_printf("%s/lxcconf2xmldata/lxcconf2xml-%s.config",
                             abs_srcdir, info->name);

    result = testCompareXMLToConfigFiles(xml, config, info->expectError);

    return result;
}

static int
testCompareXMLToConfigHelperV3(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    g_autofree char *xml = NULL;
    g_autofree char *config = NULL;

    xml = g_strdup_printf("%s/lxcconf2xmldata/lxcconf2xml-%s.xml",
                          abs_srcdir, info->name);
    config = g_strdup_printf("%s/lxcconf2xmldata/lxcconf2xml-%s-v3.config",
                             abs_srcdir, info->name);

    result = testCompareXMLToConfigFiles(xml, config, info->expectError);

    return result;
}


static int
mymain(void)
{
    int ret = EXIT_SUCCESS;

    if (!(driver = testLXCDriverInit()))
        return EXIT_FAILURE;

# define DO_TEST(name, expectError) \
    do { \
        const struct testInfo info = { name, expectError }; \
        if (virTestRun("LXC Native-2-XML " name, \
                       testCompareXMLToConfigHelperLegacy, \
                       &info) < 0) \
            ret = EXIT_FAILURE; \
    } while (0)

    DO_TEST("simple", false);
    DO_TEST("fstab", true);
    DO_TEST("nonetwork", false);
    DO_TEST("nonenetwork", false);
    DO_TEST("physnetwork", false);
    DO_TEST("macvlannetwork", false);
    DO_TEST("vlannetwork", false);
    DO_TEST("miscnetwork", false);
    DO_TEST("idmap", false);
    DO_TEST("memtune", false);
    DO_TEST("cputune", false);
    DO_TEST("cpusettune", false);
    DO_TEST("blkiotune", false);
    DO_TEST("ethernet", false);

    /* Tests for LXC 3.0 and higher */
# define DO_TEST3(name, expectError) \
    do { \
        const struct testInfo info = { name, expectError }; \
        if (virTestRun("LXC Native-3-XML " name, \
                       testCompareXMLToConfigHelperV3, \
                       &info) < 0) \
            ret = EXIT_FAILURE; \
    } while (0)

    DO_TEST3("simple", false);
    DO_TEST3("fstab", true);
    DO_TEST3("nonetwork", false);
    DO_TEST3("nonenetwork", false);
    DO_TEST3("physnetwork", false);
    DO_TEST3("macvlannetwork", false);
    DO_TEST3("vlannetwork", false);
    DO_TEST3("miscnetwork", false);
    DO_TEST3("idmap", false);
    DO_TEST3("memtune", false);
    DO_TEST3("cputune", false);
    DO_TEST3("cpusettune", false);
    DO_TEST3("blkiotune", false);
    DO_TEST3("ethernet", false);

    testLXCDriverFree(driver);

    return ret;
}

VIR_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_LXC */
