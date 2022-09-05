#include <config.h>

#include "testutils.h"

#ifdef WITH_BHYVE

# include "datatypes.h"

# include "util/viruuid.h"
# include "bhyve/bhyve_driver.h"
# include "bhyve/bhyve_capabilities.h"
# include "bhyve/bhyve_utils.h"
# include "bhyve/bhyve_parse_command.h"

# define VIR_FROM_THIS VIR_FROM_BHYVE

static bhyveConn driver;

typedef enum {
    FLAG_EXPECT_FAILURE     = 1 << 0,
    FLAG_EXPECT_PARSE_ERROR = 1 << 1,
    FLAG_EXPECT_WARNING     = 1 << 2,
} virBhyveArgv2XMLTestFlags;

static int
testCompareXMLToArgvFiles(const char *xmlfile,
                          const char *cmdfile,
                          unsigned int flags)

{
    g_autofree char *actualxml = NULL;
    g_autofree char *cmd = NULL;
    g_autofree char *log = NULL;
    g_autoptr(virDomainDef) vmdef = NULL;

    if (virTestLoadFile(cmdfile, &cmd) < 0)
        return -1;

    if (!(vmdef = bhyveParseCommandLineString(cmd, driver.bhyvecaps,
                                              driver.xmlopt))) {
        if ((flags & FLAG_EXPECT_FAILURE)) {
            VIR_TEST_DEBUG("Got expected failure from "
                           "bhyveParseCommandLineString.");
        } else {
            return -1;
        }
    } else if ((flags & FLAG_EXPECT_FAILURE)) {
        VIR_TEST_DEBUG("Did not get expected failure from "
                       "bhyveParseCommandLineString.");
        return -1;
    }

    if ((log = virTestLogContentAndReset()) == NULL)
        return -1;
    if (flags & FLAG_EXPECT_WARNING) {
        if (*log) {
            VIR_TEST_DEBUG("Got expected warning from "
                           "bhyveParseCommandLineString:\n%s",
                           log);
        } else {
            VIR_TEST_DEBUG("bhyveParseCommandLineString "
                           "should have logged a warning");
            return -1;
        }
    } else { /* didn't expect a warning */
        if (*log) {
            VIR_TEST_DEBUG("Got unexpected warning from "
                           "bhyveParseCommandLineString:\n%s",
                           log);
            return -1;
        }
    }

    if (vmdef && !virDomainDefCheckABIStability(vmdef, vmdef, driver.xmlopt)) {
        VIR_TEST_DEBUG("ABI stability check failed on %s", xmlfile);
        return -1;
    }

    if (vmdef && !(actualxml = virDomainDefFormat(vmdef, driver.xmlopt, VIR_DOMAIN_DEF_FORMAT_SECURE)))
        return -1;

    if (vmdef && virTestCompareToFile(actualxml, xmlfile) < 0)
        return -1;

    return 0;
}

struct testInfo {
    const char *name;
    unsigned int flags;
};

static int
testCompareXMLToArgvHelper(const void *data)
{
    const struct testInfo *info = data;
    g_autofree char *xml = NULL;
    g_autofree char *args = NULL;

    xml = g_strdup_printf("%s/bhyveargv2xmldata/bhyveargv2xml-%s.xml",
                          abs_srcdir, info->name);
    args = g_strdup_printf("%s/bhyveargv2xmldata/bhyveargv2xml-%s.args",
                           abs_srcdir, info->name);

    return testCompareXMLToArgvFiles(xml, args, info->flags);
}

static int
mymain(void)
{
    int ret = 0;

    if ((driver.caps = virBhyveCapsBuild()) == NULL)
        return EXIT_FAILURE;

    if ((driver.xmlopt = virDomainXMLOptionNew(NULL, NULL, NULL,
                                               NULL, NULL, NULL)) == NULL)
        return EXIT_FAILURE;

# define DO_TEST_FULL(name, flags) \
    do { \
        static struct testInfo info = { \
            name, (flags) \
        }; \
        if (virTestRun("BHYVE ARGV-2-XML " name, \
                       testCompareXMLToArgvHelper, &info) < 0) \
            ret = -1; \
    } while (0)

# define DO_TEST(name) \
    DO_TEST_FULL(name, 0)

# define DO_TEST_FAIL(name) \
    DO_TEST_FULL(name, FLAG_EXPECT_FAILURE | FLAG_EXPECT_WARNING)

# define DO_TEST_WARN(name) \
    DO_TEST_FULL(name, FLAG_EXPECT_WARNING)

# define DO_TEST_FAIL_SILENT(name) \
    DO_TEST_FULL(name, FLAG_EXPECT_FAILURE)

# define DO_TEST_PARSE_ERROR(name) \
    DO_TEST_FULL(name, FLAG_EXPECT_PARSE_ERROR)

    driver.grubcaps = BHYVE_GRUB_CAP_CONSDEV;
    driver.bhyvecaps = BHYVE_CAP_RTC_UTC;

    DO_TEST("base");
    DO_TEST("wired");
    DO_TEST("oneline");
    DO_TEST("name");
    DO_TEST("console");
    DO_TEST_FAIL("console2");
    DO_TEST_FAIL("console3");
    DO_TEST_FAIL("console4");
    DO_TEST("acpiapic");
    DO_TEST("utc");
    DO_TEST("vcpus");
    DO_TEST("cdrom");
    DO_TEST("ahci-hd");
    DO_TEST("virtio-blk");
    DO_TEST("virtio-net");
    DO_TEST("e1000");
    DO_TEST_WARN("virtio-net2");
    DO_TEST_WARN("virtio-net3");
    DO_TEST_WARN("virtio-net4");
    DO_TEST_WARN("disk-toomany");
    DO_TEST("uuid");
    DO_TEST_FAIL("uuid2");
    DO_TEST("memsize-large");
    DO_TEST("memsize-human");
    DO_TEST_FAIL("memsize-fail");
    DO_TEST("custom-loader");
    DO_TEST("bhyveload-custom");
    DO_TEST("bhyveload-vda");
    DO_TEST_FAIL("bhyveload-name-mismatch");
    DO_TEST_FAIL("bhyverun-name-mismatch");
    DO_TEST_FAIL("bhyveload-mem-mismatch");
    DO_TEST_FAIL("bhyverun-mem-mismatch");
    DO_TEST_FAIL("bhyveload-mem-mismatch");
    DO_TEST_FAIL("bhyveload-memsize-fail");
    DO_TEST("bhyveload-bootorder");
    DO_TEST_FAIL("extraargs");
    DO_TEST("vnc");
    DO_TEST("vnc-listen");
    DO_TEST("vnc-vga-on");
    DO_TEST("vnc-vga-off");
    DO_TEST("vnc-vga-io");
    DO_TEST("vnc-resolution");
    DO_TEST("vnc-password");

    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("bhyveargv2xml"))

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_BHYVE */
