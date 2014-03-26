#include <config.h>

#include "testutils.h"

#ifdef WITH_BHYVE

# include "datatypes.h"

# include "bhyve/bhyve_utils.h"
# include "bhyve/bhyve_command.h"

# define VIR_FROM_THIS VIR_FROM_BHYVE

static bhyveConn driver;

static virCapsPtr
testBhyveBuildCapabilities(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(virArchFromHost(),
                                   0, 0)) == NULL)
        return NULL;

    if ((guest = virCapabilitiesAddGuest(caps, "hvm",
                                         VIR_ARCH_X86_64,
                                         "bhyve",
                                         NULL, 0, NULL)) == NULL)
        goto error;

    if (virCapabilitiesAddGuestDomain(guest,
                                      "bhyve", NULL, NULL, 0, NULL) == NULL)
        goto error;

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline)
{
    char *expectargv = NULL;
    int len;
    char *actualargv = NULL;
    virDomainDefPtr vmdef = NULL;
    virDomainObj vm;
    virCommandPtr cmd = NULL;
    int ret = -1;


    if (!(vmdef = virDomainDefParseFile(xml, driver.caps, driver.xmlopt,
                                        1 << VIR_DOMAIN_VIRT_BHYVE,
                                        VIR_DOMAIN_XML_INACTIVE)))
        goto out;

    vm.def = vmdef;

    if (!(cmd = virBhyveProcessBuildBhyveCmd(&driver, &vm)))
        goto out;

    if (!(actualargv = virCommandToString(cmd)))
        goto out;

    len = virtTestLoadFile(cmdline, &expectargv);
    if (len < 0)
        goto out;

    if (len && expectargv[len - 1] == '\n')
        expectargv[len - 1] = '\0';

    if (STRNEQ(expectargv, actualargv)) {
        virtTestDifference(stderr, expectargv, actualargv);
        goto out;
    }

    ret = 0;

 out:
    VIR_FREE(expectargv);
    VIR_FREE(actualargv);
    virCommandFree(cmd);
    virDomainDefFree(vmdef);
    return ret;
}

static int
testCompareXMLToArgvHelper(const void *data)
{
    int ret = -1;
    const char *name = data;
    char *xml = NULL;
    char *args = NULL;

    if (virAsprintf(&xml, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.xml",
                    abs_srcdir, name) < 0 ||
        virAsprintf(&args, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.args",
                    abs_srcdir, name) < 0)
        goto cleanup;

    ret = testCompareXMLToArgvFiles(xml, args);

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(args);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

    if ((driver.caps = testBhyveBuildCapabilities()) == NULL)
        return EXIT_FAILURE;

    if ((driver.xmlopt = virDomainXMLOptionNew(NULL, NULL, NULL)) == NULL)
        return EXIT_FAILURE;

# define DO_TEST(name)                                        \
    do {                                                      \
        if (virtTestRun("BHYVE XML-2-ARGV " name,             \
                       testCompareXMLToArgvHelper, name) < 0) \
            ret = -1;                                         \
    } while (0)


    DO_TEST("base");
    DO_TEST("acpiapic");
    DO_TEST("disk-virtio");
    DO_TEST("macaddr");

    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/bhyvexml2argvmock.so")

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_BHYVE */
