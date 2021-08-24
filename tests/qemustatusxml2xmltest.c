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
    const struct testQemuInfo *data = opaque;
    virDomainObj *obj = NULL;
    g_autofree char *actual = NULL;
    int ret = -1;

    if (testQemuInfoInitArgs((struct testQemuInfo *) data) < 0)
        return -1;

    if (qemuTestCapsCacheInsert(driver.qemuCapsCache, data->qemuCaps) < 0)
        return -1;

    if (!(obj = virDomainObjParseFile(data->infile, driver.xmlopt,
                                      VIR_DOMAIN_DEF_PARSE_STATUS |
                                      VIR_DOMAIN_DEF_PARSE_ACTUAL_NET |
                                      VIR_DOMAIN_DEF_PARSE_PCI_ORIG_STATES |
                                      VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE |
                                      VIR_DOMAIN_DEF_PARSE_ALLOW_POST_PARSE_FAIL))) {
        VIR_TEST_DEBUG("\nfailed to parse '%s'", data->infile);
        goto cleanup;
    }

    if (!(actual = virDomainObjFormat(obj, driver.xmlopt,
                                      VIR_DOMAIN_DEF_FORMAT_SECURE |
                                      VIR_DOMAIN_DEF_FORMAT_STATUS |
                                      VIR_DOMAIN_DEF_FORMAT_ACTUAL_NET |
                                      VIR_DOMAIN_DEF_FORMAT_PCI_ORIG_STATES |
                                      VIR_DOMAIN_DEF_FORMAT_CLOCK_ADJUST))) {
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

static void
testInfoSetStatusPaths(struct testQemuInfo *info)
{
    info->infile = g_strdup_printf("%s%s-in.xml", statusPath, info->name);
    info->outfile = g_strdup_printf("%s%s-out.xml", statusPath, info->name);
}


#define FAKEROOTDIRTEMPLATE abs_builddir "/fakerootdir-XXXXXX"

static int
mymain(void)
{
    int ret = 0;
    g_autofree char *fakerootdir = NULL;
    g_autoptr(GHashTable) capslatest = testQemuGetLatestCaps();
    g_autoptr(GHashTable) capscache = virHashNew(virObjectFreeHashData);
    g_autoptr(virConnect) conn = NULL;
    struct testQemuConf testConf = { .capslatest = capslatest,
                                     .capscache = capscache,
                                     .qapiSchemaCache = NULL };

    if (!capslatest)
        return EXIT_FAILURE;

    fakerootdir = g_strdup(FAKEROOTDIRTEMPLATE);

    if (!g_mkdtemp(fakerootdir)) {
        fprintf(stderr, "Cannot create fakerootdir");
        abort();
    }

    g_setenv("LIBVIRT_FAKE_ROOT_DIR", fakerootdir, TRUE);

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    driver.privileged = true;

    if (!(conn = virGetConnect()))
        goto cleanup;

    virSetConnectInterface(conn);
    virSetConnectNetwork(conn);
    virSetConnectNWFilter(conn);
    virSetConnectNodeDev(conn);
    virSetConnectSecret(conn);
    virSetConnectStorage(conn);

#define DO_TEST_STATUS(_name) \
    do { \
        static struct testQemuInfo info = { \
            .name = _name, \
        }; \
        testQemuInfoSetArgs(&info, &testConf, ARG_END); \
        testInfoSetStatusPaths(&info); \
\
        if (virTestRun("QEMU status XML-2-XML " _name, \
                       testCompareStatusXMLToXMLFiles, &info) < 0) \
            ret = -1; \
\
        testQemuInfoClear(&info); \
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
    if (getenv("LIBVIRT_SKIP_CLEANUP") == NULL)
        virFileDeleteTree(fakerootdir);

    qemuTestDriverFree(&driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virpci"),
                      VIR_TEST_MOCK("virrandom"),
                      VIR_TEST_MOCK("domaincaps"))
