#include <config.h>

#include "testutils.h"

#ifdef WITH_BHYVE

# include "datatypes.h"

# include "bhyve/bhyve_capabilities.h"
# include "bhyve/bhyve_domain.h"
# include "bhyve/bhyve_utils.h"
# include "bhyve/bhyve_command.h"

# define VIR_FROM_THIS VIR_FROM_BHYVE

static bhyveConn driver;

typedef enum {
    FLAG_EXPECT_FAILURE     = 1 << 0,
    FLAG_EXPECT_PARSE_ERROR = 1 << 1,
} virBhyveXMLToArgvTestFlags;

static int testCompareXMLToArgvFiles(const char *xml,
                                     const char *cmdline,
                                     const char *ldcmdline,
                                     const char *dmcmdline,
                                     unsigned int flags)
{
    char *actualargv = NULL, *actualld = NULL, *actualdm = NULL;
    virDomainDefPtr vmdef = NULL;
    virCommandPtr cmd = NULL, ldcmd = NULL;
    virConnectPtr conn;
    int ret = -1;

    if (!(conn = virGetConnect()))
        goto out;

    if (!(vmdef = virDomainDefParseFile(xml, driver.caps, driver.xmlopt,
                                        NULL, VIR_DOMAIN_DEF_PARSE_INACTIVE))) {
        if (flags & FLAG_EXPECT_PARSE_ERROR)
            ret = 0;
        goto out;
    }

    conn->privateData = &driver;

    cmd = virBhyveProcessBuildBhyveCmd(conn, vmdef, false);
    ldcmd = virBhyveProcessBuildLoadCmd(conn, vmdef, "<device.map>",
                                        &actualdm);

    if ((cmd == NULL) || (ldcmd == NULL)) {
        if (flags & FLAG_EXPECT_FAILURE) {
            ret = 0;
            VIR_TEST_DEBUG("Got expected error: %s\n",
                    virGetLastErrorMessage());
            virResetLastError();
        }
        goto out;
    }

    if (!(actualargv = virCommandToString(cmd)))
        goto out;

    if (actualdm != NULL)
        virTrimSpaces(actualdm, NULL);

    if (!(actualld = virCommandToString(ldcmd)))
        goto out;

    if (virTestCompareToFile(actualargv, cmdline) < 0)
        goto out;

    if (virTestCompareToFile(actualld, ldcmdline) < 0)
        goto out;

    if (virFileExists(dmcmdline) || actualdm) {
        if (virTestCompareToFile(actualdm, dmcmdline) < 0)
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
    virObjectUnref(conn);
    return ret;
}

struct testInfo {
    const char *name;
    unsigned int flags;
};

static int
testCompareXMLToArgvHelper(const void *data)
{
    int ret = -1;
    const struct testInfo *info = data;
    char *xml = NULL;
    char *args = NULL, *ldargs = NULL, *dmargs = NULL;

    if (virAsprintf(&xml, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.xml",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&args, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.args",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&ldargs, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.ldargs",
                    abs_srcdir, info->name) < 0 ||
        virAsprintf(&dmargs, "%s/bhyvexml2argvdata/bhyvexml2argv-%s.devmap",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    ret = testCompareXMLToArgvFiles(xml, args, ldargs, dmargs, info->flags);

 cleanup:
    VIR_FREE(xml);
    VIR_FREE(args);
    VIR_FREE(ldargs);
    VIR_FREE(dmargs);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

    if ((driver.caps = virBhyveCapsBuild()) == NULL)
        return EXIT_FAILURE;

    if ((driver.xmlopt = virBhyveDriverCreateXMLConf(&driver)) == NULL)
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, flags)                             \
    do {                                                       \
        static struct testInfo info = {                        \
            name, (flags)                                      \
        };                                                     \
        if (virTestRun("BHYVE XML-2-ARGV " name,               \
                       testCompareXMLToArgvHelper, &info) < 0) \
            ret = -1;                                          \
    } while (0)

# define DO_TEST(name)                                         \
    DO_TEST_FULL(name, 0)

# define DO_TEST_FAILURE(name)                                 \
    DO_TEST_FULL(name, FLAG_EXPECT_FAILURE)

# define DO_TEST_PARSE_ERROR(name)                             \
    DO_TEST_FULL(name, FLAG_EXPECT_PARSE_ERROR)

    driver.grubcaps = BHYVE_GRUB_CAP_CONSDEV;
    driver.bhyvecaps = BHYVE_CAP_RTC_UTC | BHYVE_CAP_AHCI32SLOT;

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
    DO_TEST("bhyveload-bootorder");
    DO_TEST("bhyveload-bootorder1");
    DO_TEST_FAILURE("bhyveload-bootorder2");
    DO_TEST("bhyveload-bootorder3");
    DO_TEST("bhyveload-explicitargs");
    DO_TEST_FAILURE("bhyveload-bootorder4");
    DO_TEST_PARSE_ERROR("bhyveload-bootorder5");
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
