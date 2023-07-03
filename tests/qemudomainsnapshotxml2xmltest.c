#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#ifdef WITH_QEMU

# include "internal.h"
# include "qemu/qemu_conf.h"
# include "testutilsqemu.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static virQEMUDriver driver;

enum {
    TEST_INTERNAL = 1 << 0, /* Test use of INTERNAL parse/format flag */
    TEST_REDEFINE = 1 << 1, /* Test use of REDEFINE parse flag */
    TEST_RUNNING = 1 << 2, /* Set snapshot state to running after parse */
};

static int
testCompareXMLToXMLFiles(const char *inxml,
                         const char *outxml,
                         const char *uuid,
                         unsigned int flags)
{
    g_autofree char *inXmlData = NULL;
    g_autofree char *actual = NULL;
    unsigned int parseflags = 0;
    unsigned int formatflags = VIR_DOMAIN_SNAPSHOT_FORMAT_SECURE;
    bool cur = false;
    g_autoptr(virDomainSnapshotDef) def = NULL;

    if (flags & TEST_INTERNAL) {
        parseflags |= VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL;
        formatflags |= VIR_DOMAIN_SNAPSHOT_FORMAT_INTERNAL;
    }

    if (flags & TEST_REDEFINE)
        parseflags |= VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE;

    if (virTestLoadFile(inxml, &inXmlData) < 0)
        return -1;

    if (!(def = virDomainSnapshotDefParseString(inXmlData,
                                                driver.xmlopt, NULL, &cur,
                                                parseflags)))
        return -1;
    if (cur) {
        if (!(flags & TEST_INTERNAL))
            return -1;
        formatflags |= VIR_DOMAIN_SNAPSHOT_FORMAT_CURRENT;
    }
    if (flags & TEST_RUNNING) {
        if (def->state)
            return -1;
        def->state = VIR_DOMAIN_RUNNING;
    }

    if (!(actual = virDomainSnapshotDefFormat(uuid, def,
                                              driver.xmlopt,
                                              formatflags)))
        return -1;

    if (virTestCompareToFile(actual, outxml) < 0)
        return -1;

    return 0;
}

struct testInfo {
    const char *inxml;
    const char *outxml;
    const char *uuid;
    long long creationTime;
    unsigned int flags;
};
static long long mocktime;

static int
testSnapshotPostParse(virDomainMomentDef *def)
{
    if (!mocktime)
        return 0;
    if (def->creationTime)
        return -1;
    def->creationTime = mocktime;
    if (!def->name)
        def->name = g_strdup_printf("%lld", def->creationTime);
    return 0;
}

static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;

    mocktime = info->creationTime;
    return testCompareXMLToXMLFiles(info->inxml, info->outxml, info->uuid,
                                    info->flags);
}


static int
mymain(void)
{
    g_autoptr(GHashTable) capslatest = testQemuGetLatestCaps();
    g_autoptr(GHashTable) capscache = virHashNew(virObjectUnref);
    int ret = 0;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    if (testQemuInsertRealCaps(driver.qemuCapsCache, "x86_64", "latest", "",
                               capslatest, capscache, NULL, NULL) < 0)
        return EXIT_FAILURE;

    virDomainXMLOptionSetMomentPostParse(driver.xmlopt,
                                         testSnapshotPostParse);

# define DO_TEST(prefix, name, inpath, outpath, uuid, time, flags) \
    do { \
        const struct testInfo info = {abs_srcdir "/" inpath "/" name ".xml", \
                                      abs_srcdir "/" outpath "/" name ".xml", \
                                      uuid, time, flags}; \
        if (virTestRun("SNAPSHOT XML-2-XML " prefix " " name, \
                       testCompareXMLToXMLHelper, &info) < 0) \
            ret = -1; \
    } while (0)

# define DO_TEST_IN(name, uuid) DO_TEST("in->in", name, \
                                        "qemudomainsnapshotxml2xmlin", \
                                        "qemudomainsnapshotxml2xmlin", \
                                        uuid, 0, 0)

# define DO_TEST_OUT(name, uuid, internal) \
    DO_TEST("out->out", name, "qemudomainsnapshotxml2xmlout", \
            "qemudomainsnapshotxml2xmlout", uuid, 0, internal | TEST_REDEFINE)

# define DO_TEST_INOUT(name, uuid, time, flags) \
    DO_TEST("in->out", name, \
            "qemudomainsnapshotxml2xmlin",\
            "qemudomainsnapshotxml2xmlout",\
            uuid, time, flags)

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    g_setenv("PATH", "/bin", TRUE);

    DO_TEST_OUT("all_parameters", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8",
                TEST_INTERNAL);
    DO_TEST_OUT("disk_snapshot_redefine", "c7a5fdbd-edaf-9455-926a-d65c16db1809",
                TEST_INTERNAL);
    DO_TEST_OUT("full_domain", "c7a5fdbd-edaf-9455-926a-d65c16db1809",
                TEST_INTERNAL);
    DO_TEST_OUT("noparent_nodescription_noactive", NULL, 0);
    DO_TEST_OUT("noparent_nodescription", NULL, TEST_INTERNAL);
    DO_TEST_OUT("noparent", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8", 0);
    DO_TEST_OUT("metadata", "c7a5fdbd-edaf-9455-926a-d65c16db1809", 0);
    DO_TEST_OUT("external_vm_redefine", "c7a5fdbd-edaf-9455-926a-d65c16db1809",
                0);

    DO_TEST_OUT("memory-snapshot-inactivedomain", "14beef2c-8cae-4ea8-bf55-e48fe0cd4b73", 0);

    DO_TEST_INOUT("empty", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8",
                  1386166249, 0);
    DO_TEST_INOUT("noparent", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8",
                  1272917631, TEST_RUNNING);
    DO_TEST_INOUT("external_vm", NULL, 1555419243, 0);
    DO_TEST_INOUT("disk_snapshot", NULL, 1555419243, 0);
    DO_TEST_INOUT("disk_driver_name_null", NULL, 1555419243, 0);
    DO_TEST_INOUT("disk-seclabel", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8", 581484660, 0);

    DO_TEST_IN("name_and_description", NULL);
    DO_TEST_IN("description_only", NULL);
    DO_TEST_IN("name_only", NULL);

    DO_TEST_INOUT("qcow2-metadata-cache", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8",
                  1386166249, 0);

    qemuTestDriverFree(&driver);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
