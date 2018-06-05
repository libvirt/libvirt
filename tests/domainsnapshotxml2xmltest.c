#include <config.h>

#include <unistd.h>

#include <sys/types.h>
#include <fcntl.h>

#include "testutils.h"

#ifdef WITH_QEMU

# include "internal.h"
# include "qemu/qemu_conf.h"
# include "qemu/qemu_domain.h"
# include "testutilsqemu.h"
# include "virstring.h"

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
    char *inXmlData = NULL;
    char *outXmlData = NULL;
    char *actual = NULL;
    int ret = -1;
    unsigned int parseflags = VIR_DOMAIN_SNAPSHOT_PARSE_DISKS;
    unsigned int formatflags = VIR_DOMAIN_SNAPSHOT_FORMAT_SECURE;
    bool cur = false;
    VIR_AUTOUNREF(virDomainSnapshotDefPtr) def = NULL;

    if (flags & TEST_INTERNAL) {
        parseflags |= VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL;
        formatflags |= VIR_DOMAIN_SNAPSHOT_FORMAT_INTERNAL;
    }

    if (flags & TEST_REDEFINE)
        parseflags |= VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE;

    if (virTestLoadFile(inxml, &inXmlData) < 0)
        goto cleanup;

    if (virTestLoadFile(outxml, &outXmlData) < 0)
        goto cleanup;

    if (!(def = virDomainSnapshotDefParseString(inXmlData, driver.caps,
                                                driver.xmlopt, &cur,
                                                parseflags)))
        goto cleanup;
    if (cur) {
        if (!(flags & TEST_INTERNAL))
            goto cleanup;
        formatflags |= VIR_DOMAIN_SNAPSHOT_FORMAT_CURRENT;
    }
    if (flags & TEST_RUNNING) {
        if (def->state)
            goto cleanup;
        def->state = VIR_DOMAIN_RUNNING;
    }

    if (!(actual = virDomainSnapshotDefFormat(uuid, def, driver.caps,
                                              driver.xmlopt,
                                              formatflags)))
        goto cleanup;

    if (STRNEQ(outXmlData, actual)) {
        virTestDifferenceFull(stderr, outXmlData, outxml, actual, inxml);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(inXmlData);
    VIR_FREE(outXmlData);
    VIR_FREE(actual);
    return ret;
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
testSnapshotPostParse(virDomainMomentDefPtr def)
{
    if (!mocktime)
        return 0;
    if (def->creationTime)
        return -1;
    def->creationTime = mocktime;
    if (!def->name &&
        virAsprintf(&def->name, "%lld", def->creationTime) < 0)
        return -1;
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
    int ret = 0;

    if (qemuTestDriverInit(&driver) < 0)
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
                                        "domainsnapshotxml2xmlin", \
                                        "domainsnapshotxml2xmlin", \
                                        uuid, 0, 0)

# define DO_TEST_OUT(name, uuid, internal) \
    DO_TEST("out->out", name, "domainsnapshotxml2xmlout", \
            "domainsnapshotxml2xmlout", uuid, 0, internal | TEST_REDEFINE)

# define DO_TEST_INOUT(name, uuid, time, flags) \
    DO_TEST("in->out", name, \
            "domainsnapshotxml2xmlin",\
            "domainsnapshotxml2xmlout",\
            uuid, time, flags)

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

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
