#include <config.h>

#include "testutils.h"

#ifdef WITH_BHYVE

# include "datatypes.h"

# include "bhyve/bhyve_capabilities.h"
# include "bhyve/bhyve_utils.h"
# include "bhyve/bhyve_command.h"

# define VIR_FROM_THIS VIR_FROM_BHYVE

static bhyveConn driver;

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline,
                                     const char *ldcmdline,
                                     const char *dmcmdline)
{
    char *actualargv = NULL, *actualld = NULL, *actualdm = NULL;
    virDomainDefPtr vmdef = NULL;
    virCommandPtr cmd = NULL, ldcmd = NULL;
    virConnectPtr conn;
    int ret = -1;

    if (!(conn = virGetConnect()))
        goto out;

    if (!(vmdef = virDomainDefParseFile(xml, driver.caps, driver.xmlopt,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE)))
        goto out;

    conn->privateData = &driver;

    if (!(cmd = virBhyveProcessBuildBhyveCmd(conn, vmdef, false)))
        goto out;

    if (!(actualargv = virCommandToString(cmd)))
        goto out;

    if (!(ldcmd = virBhyveProcessBuildLoadCmd(conn, vmdef, "<device.map>",
                                              &actualdm)))
        goto out;

    if (actualdm != NULL)
        virTrimSpaces(actualdm, NULL);

    if (!(actualld = virCommandToString(ldcmd)))
        goto out;

    if (virtTestCompareToFile(actualargv, cmdline) < 0)
        goto out;

    if (virtTestCompareToFile(actualld, ldcmdline) < 0)
        goto out;

    if (virFileExists(dmcmdline) || actualdm) {
        if (virtTestCompareToFile(actualdm, dmcmdline) < 0)
            goto out;
    }

    ret = 0;

 out:
    VIR_FREE(actualargv);
    VIR_FREE(actualld);
    VIR_FREE(actualdm);
    virCommandFree(cmd);
    virCommandFree(ldcmd);
    virDomainDefFree(vmdef);
    return ret;
}

static int
testCompareXMLToArgvHelper(const void *data)
{
    int ret = -1;
    const char *name = data;
    char *xml = NULL;
    char *args = NULL, *ldargs = NULL, *dmargs = NULL;

    if (virAsprintf(&xml, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.xml",
                    abs_srcdir, name) < 0 ||
        virAsprintf(&args, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.args",
                    abs_srcdir, name) < 0 ||
        virAsprintf(&ldargs, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.ldargs",
                    abs_srcdir, name) < 0 ||
        virAsprintf(&dmargs, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.devmap",
                    abs_srcdir, name) < 0)
        goto cleanup;

    ret = testCompareXMLToArgvFiles(xml, args, ldargs, dmargs);

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(args);
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

# define DO_TEST(name)                                        \
    do {                                                      \
        if (virtTestRun("BHYVE XML-2-ARGV " name,             \
                       testCompareXMLToArgvHelper, name) < 0) \
            ret = -1;                                         \
    } while (0)

    driver.grubcaps = BHYVE_GRUB_CAP_CONSDEV;
    driver.bhyvecaps = BHYVE_CAP_RTC_UTC;

    DO_TEST("base");
    DO_TEST("acpiapic");
    DO_TEST("disk-cdrom");
    DO_TEST("disk-virtio");
    DO_TEST("macaddr");
    DO_TEST("serial");
    DO_TEST("console");
    DO_TEST("grub-defaults");
    DO_TEST("grub-bootorder");
    DO_TEST("grub-bootorder2");
    DO_TEST("bhyveload-explicitargs");
    DO_TEST("custom-loader");
    DO_TEST("disk-cdrom-grub");
    DO_TEST("serial-grub");
    DO_TEST("localtime");

    driver.grubcaps = 0;

    DO_TEST("serial-grub-nocons");

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
