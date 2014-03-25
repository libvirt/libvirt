#include <config.h>

#include "testutils.h"

#ifdef WITH_LXC

# include "lxc/lxc_native.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static int
blankProblemElements(char *data)
{
    if (virtTestClearLineRegex("<uuid>([[:alnum:]]|-)+</uuid>", data) < 0)
        return -1;
    return 0;
}

static int
testCompareXMLToConfigFiles(const char *xml,
                            const char *configfile,
                            bool expectError)
{
    int ret = -1;
    char *config = NULL;
    char *expectxml = NULL;
    char *actualxml = NULL;
    virDomainDefPtr vmdef = NULL;

    if (virtTestLoadFile(configfile, &config) < 0)
        goto fail;

    vmdef = lxcParseConfigString(config);
    if ((vmdef && expectError) || (!vmdef && !expectError))
        goto fail;

    if (vmdef) {
        if (!(actualxml = virDomainDefFormat(vmdef, 0)))
            goto fail;

        if (virtTestLoadFile(xml, &expectxml) < 0)
            goto fail;

        if (blankProblemElements(expectxml) < 0 ||
            blankProblemElements(actualxml) < 0)
            goto fail;

        if (STRNEQ(expectxml, actualxml)) {
            virtTestDifference(stderr, expectxml, actualxml);
            goto fail;
        }
    }

    ret = 0;

 fail:
    VIR_FREE(expectxml);
    VIR_FREE(actualxml);
    VIR_FREE(config);
    virDomainDefFree(vmdef);
    return ret;
}

struct testInfo {
    const char *name;
    bool expectError;
};

static int
testCompareXMLToConfigHelper(const void *data)
{
    int result = -1;
    const struct testInfo *info = data;
    char *xml = NULL;
    char *config = NULL;

    if (virAsprintf(&xml, "%s/lxcconf2xmldata/lxcconf2xml-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&config, "%s/lxcconf2xmldata/lxcconf2xml-%s.config",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    result = testCompareXMLToConfigFiles(xml, config, info->expectError);

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(config);
    return result;
}

static int
mymain(void)
{
    int ret = EXIT_SUCCESS;

# define DO_TEST(name, expectError)                         \
    do {                                                    \
        const struct testInfo info = { name, expectError }; \
        if (virtTestRun("LXC Native-2-XML " name,           \
                        testCompareXMLToConfigHelper,       \
                        &info) < 0)                         \
            ret = EXIT_FAILURE;                             \
    } while (0)

    DO_TEST("simple", false);
    DO_TEST("fstab", true);
    DO_TEST("nonetwork", false);
    DO_TEST("nonenetwork", false);
    DO_TEST("physnetwork", false);
    DO_TEST("macvlannetwork", false);
    DO_TEST("vlannetwork", false);
    DO_TEST("idmap", false);
    DO_TEST("memtune", false);
    DO_TEST("cputune", false);
    DO_TEST("cpusettune", false);
    DO_TEST("blkiotune", false);

    return ret;
}

VIRT_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_LXC */
