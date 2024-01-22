#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#include "internal.h"
#include "testutilsqemu.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static virQEMUDriver driver;

static int
testCompareStatusXMLToXMLFiles(const void *opaque)
{
    const testQemuInfo *data = opaque;
    virDomainObj *obj = NULL;
    g_autofree char *actual = NULL;
    int ret = -1;

    /* this test suite doesn't yet need testQemuInfoInitArgs() */

    if (!(obj = virDomainObjParseFile(data->infile, driver.xmlopt,
                                      VIR_DOMAIN_DEF_PARSE_STATUS |
                                      VIR_DOMAIN_DEF_PARSE_ACTUAL_NET |
                                      VIR_DOMAIN_DEF_PARSE_PCI_ORIG_STATES |
                                      VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE |
                                      VIR_DOMAIN_DEF_PARSE_ALLOW_POST_PARSE_FAIL |
                                      VIR_DOMAIN_DEF_PARSE_VOLUME_TRANSLATED))) {
        VIR_TEST_DEBUG("\nfailed to parse '%s'", data->infile);
        goto cleanup;
    }

    if (!(actual = virDomainObjFormat(obj, driver.xmlopt,
                                      VIR_DOMAIN_DEF_FORMAT_SECURE |
                                      VIR_DOMAIN_DEF_FORMAT_STATUS |
                                      VIR_DOMAIN_DEF_FORMAT_ACTUAL_NET |
                                      VIR_DOMAIN_DEF_FORMAT_PCI_ORIG_STATES |
                                      VIR_DOMAIN_DEF_FORMAT_CLOCK_ADJUST |
                                      VIR_DOMAIN_DEF_FORMAT_VOLUME_TRANSLATED))) {
        VIR_TEST_DEBUG("\nfailed to format back '%s'", data->infile);
        goto cleanup;
    }

    if (virTestCompareToFile(actual, data->outfile) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virDomainObjEndAPI(&obj);
    return ret;
}


static const char *statusPath = abs_srcdir "/qemustatusxml2xmldata/";


static int
testRunStatus(const char *name,
              struct testQemuConf *testConf,
              ...)
{
    g_autofree char *testname = g_strdup_printf("QEMU status XML-2-XML %s", name);
    g_autoptr(testQemuInfo) info = g_new0(testQemuInfo, 1);
    va_list ap;

    info->name = name;
    info->conf = testConf;

    va_start(ap, testConf);
    testQemuInfoSetArgs(info, ap);
    va_end(ap);

    info->infile = g_strdup_printf("%s%s-in.xml", statusPath, info->name);
    info->outfile = g_strdup_printf("%s%s-out.xml", statusPath, info->name);

    if (virTestRun(testname, testCompareStatusXMLToXMLFiles, info) < 0)
        return -1;

    return 0;
}


static int
testqemuActiveXML2XMLCommon(testQemuInfo *info,
                            bool live)
{
    g_autofree char *actual = NULL;
    const char *outfile = info->out_xml_active;
    unsigned int format_flags = VIR_DOMAIN_DEF_FORMAT_SECURE;

    /* Prepare the test data and parse the input just once */
    if (!info->def) {
        if (testQemuInfoInitArgs((testQemuInfo *) info) < 0)
            return -1;

        virFileCacheClear(driver.qemuCapsCache);

        if (qemuTestCapsCacheInsert(driver.qemuCapsCache, info->qemuCaps) < 0)
            return -1;

        if (!(info->def = virDomainDefParseFile(info->infile,
                                                driver.xmlopt, NULL,
                                                info->parseFlags)))
            return -1;

        if (!virDomainDefCheckABIStability(info->def, info->def, driver.xmlopt)) {
            VIR_TEST_DEBUG("ABI stability check failed on %s", info->infile);
            return -1;
        }

        /* make sure that the XML definition looks active, by setting an ID
         * as otherwise the XML formatter will simply assume that it's inactive */
        if (info->def->id == -1)
            info->def->id = 1337;
    }

    if (!live) {
        format_flags |= VIR_DOMAIN_DEF_FORMAT_INACTIVE;
        outfile = info->out_xml_inactive;
    }

    if (!(actual = virDomainDefFormat(info->def, driver.xmlopt, format_flags))) {
        VIR_TEST_VERBOSE("failed to format output XML\n");
        return -1;
    }

    if (virTestCompareToFile(actual, outfile) < 0)
        return -1;

    return 0;
}


static int
testqemuActiveXML2XMLActive(const void *opaque)
{
    testQemuInfo *info = (testQemuInfo *) opaque;

    return testqemuActiveXML2XMLCommon(info, true);
}


static int
testqemuActiveXML2XMLInactive(const void *opaque)
{
    testQemuInfo *info = (testQemuInfo *) opaque;

    return testqemuActiveXML2XMLCommon(info, false);
}


static void
testRunActive(const char *name,
              const char *suffix,
              struct testQemuConf *testConf,
              int *ret,
              ...)
{
    g_autofree char *name_active = g_strdup_printf("QEMU active-XML -> active-XML %s", name);
    g_autofree char *name_inactive = g_strdup_printf("QEMU activeXML -> inactive-XMLXML %s", name);
    g_autoptr(testQemuInfo) info = g_new0(testQemuInfo, 1);
    va_list ap;

    info->name = name;
    info->conf = testConf;

    va_start(ap, ret);
    testQemuInfoSetArgs(info, ap);
    va_end(ap);

    info->infile = g_strdup_printf("%s/qemuxmlconfdata/%s.xml", abs_srcdir,
                                   info->name);

    info->out_xml_active = g_strdup_printf("%s/qemuxmlactive2xmldata/%s-active%s.xml",
                                           abs_srcdir, info->name, suffix);

    info->out_xml_inactive = g_strdup_printf("%s/qemuxmlactive2xmldata/%s-inactive%s.xml",
                                             abs_srcdir, info->name, suffix);

    virTestRunLog(ret, name_inactive, testqemuActiveXML2XMLInactive, info);
    virTestRunLog(ret, name_active, testqemuActiveXML2XMLActive, info);
}


static int
mymain(void)
{
    int ret = 0;
    g_autoptr(virConnect) conn = NULL;
    g_autoptr(GHashTable) capslatest = testQemuGetLatestCaps();
    g_autoptr(GHashTable) capscache = virHashNew(virObjectUnref);
    struct testQemuConf testConf = { .capslatest = capslatest,
                                     .capscache = capscache,
                                     .qapiSchemaCache = NULL };

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    if (!(conn = virGetConnect()))
        goto cleanup;

    virSetConnectInterface(conn);
    virSetConnectNetwork(conn);
    virSetConnectNWFilter(conn);
    virSetConnectNodeDev(conn);
    virSetConnectSecret(conn);
    virSetConnectStorage(conn);

#define DO_TEST_ACTIVE_CAPS_LATEST(_name) \
    testRunActive(_name, ".x86_64-latest", &testConf, &ret, \
                  ARG_CAPS_ARCH, "x86_64", ARG_CAPS_VER, "latest", ARG_END);

    DO_TEST_ACTIVE_CAPS_LATEST("channel-unix-source-path");
    DO_TEST_ACTIVE_CAPS_LATEST("channel-virtio-state");
    DO_TEST_ACTIVE_CAPS_LATEST("disk-active-commit");
    DO_TEST_ACTIVE_CAPS_LATEST("disk-backing-chains-index");
    DO_TEST_ACTIVE_CAPS_LATEST("disk-mirror");
    DO_TEST_ACTIVE_CAPS_LATEST("disk-mirror-old");
    DO_TEST_ACTIVE_CAPS_LATEST("genid");
    DO_TEST_ACTIVE_CAPS_LATEST("genid-auto");
    DO_TEST_ACTIVE_CAPS_LATEST("graphics-vnc-remove-generated-socket");
    DO_TEST_ACTIVE_CAPS_LATEST("seclabel-static-labelskip");

#define DO_TEST_STATUS(_name) \
    do { \
        if (testRunStatus(_name, &testConf, ARG_END) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_STATUS("blockjob-mirror");
    DO_TEST_STATUS("vcpus-multi");
    DO_TEST_STATUS("modern");
    DO_TEST_STATUS("migration-out-nbd");
    DO_TEST_STATUS("migration-in-params");
    DO_TEST_STATUS("migration-out-params");
    DO_TEST_STATUS("migration-out-nbd-tls");
    DO_TEST_STATUS("migration-out-nbd-bitmaps");
    DO_TEST_STATUS("upgrade");

    DO_TEST_STATUS("blockjob-blockdev");

    DO_TEST_STATUS("backup-pull");

 cleanup:
    qemuTestDriverFree(&driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virpci"),
                      VIR_TEST_MOCK("virrandom"),
                      VIR_TEST_MOCK("domaincaps"))
