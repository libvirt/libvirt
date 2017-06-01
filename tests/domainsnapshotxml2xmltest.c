#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <fcntl.h>

#include <regex.h>

#include "testutils.h"

#ifdef WITH_QEMU

# include "internal.h"
# include "qemu/qemu_conf.h"
# include "qemu/qemu_domain.h"
# include "testutilsqemu.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static virQEMUDriver driver;

/* This regex will skip the following XML constructs in test files
 * that are dynamically generated and thus problematic to test:
 * <name>1234352345</name> if the snapshot has no name,
 * <creationTime>23523452345</creationTime>,
 * <state>nostate</state> as the backend code doesn't fill this
 */
static const char *testSnapshotXMLVariableLineRegexStr =
    "(<(name|creationTime)>[0-9]+</(name|creationTime)>|"
    "<state>nostate</state>)";

regex_t *testSnapshotXMLVariableLineRegex = NULL;

static char *
testFilterXML(char *xml)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char **xmlLines = NULL;
    char **xmlLine;
    char *ret = NULL;

    if (!(xmlLines = virStringSplit(xml, "\n", 0))) {
        VIR_FREE(xml);
        goto cleanup;
    }
    VIR_FREE(xml);

    for (xmlLine = xmlLines; *xmlLine; xmlLine++) {
        if (regexec(testSnapshotXMLVariableLineRegex,
                    *xmlLine, 0, NULL, 0) == 0)
            continue;

        virBufferStrcat(&buf, *xmlLine, "\n", NULL);
    }

    if (virBufferCheckError(&buf) < 0)
        goto cleanup;

    ret = virBufferContentAndReset(&buf);

 cleanup:
    virBufferFreeAndReset(&buf);
    virStringListFree(xmlLines);
    return ret;
}

static int
testCompareXMLToXMLFiles(const char *inxml,
                         const char *outxml,
                         const char *uuid,
                         bool internal,
                         bool redefine)
{
    char *inXmlData = NULL;
    char *outXmlData = NULL;
    char *actual = NULL;
    int ret = -1;
    virDomainSnapshotDefPtr def = NULL;
    unsigned int flags = VIR_DOMAIN_SNAPSHOT_PARSE_DISKS;

    if (internal)
        flags |= VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL;

    if (redefine)
        flags |= VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE;

    if (virTestLoadFile(inxml, &inXmlData) < 0)
        goto cleanup;

    if (virTestLoadFile(outxml, &outXmlData) < 0)
        goto cleanup;

    if (!(def = virDomainSnapshotDefParseString(inXmlData, driver.caps,
                                                driver.xmlopt,
                                                flags)))
        goto cleanup;

    if (!(actual = virDomainSnapshotDefFormat(uuid, def, driver.caps,
                                              driver.xmlopt,
                                              VIR_DOMAIN_DEF_FORMAT_SECURE,
                                              internal)))
        goto cleanup;

    if (!redefine) {
        if (!(actual = testFilterXML(actual)))
            goto cleanup;

        if (!(outXmlData = testFilterXML(outXmlData)))
            goto cleanup;
    }

    if (STRNEQ(outXmlData, actual)) {
        virTestDifferenceFull(stderr, outXmlData, outxml, actual, inxml);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(inXmlData);
    VIR_FREE(outXmlData);
    VIR_FREE(actual);
    virDomainSnapshotDefFree(def);
    return ret;
}

struct testInfo {
    const char *inxml;
    const char *outxml;
    const char *uuid;
    bool internal;
    bool redefine;
};


static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;

    return testCompareXMLToXMLFiles(info->inxml, info->outxml, info->uuid,
                                    info->internal, info->redefine);
}


static int
mymain(void)
{
    int ret = 0;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    /* TODO: test with format probing disabled too */
    driver.config->allowDiskFormatProbing = true;

    if (VIR_ALLOC(testSnapshotXMLVariableLineRegex) < 0)
        goto cleanup;

    if (regcomp(testSnapshotXMLVariableLineRegex,
                testSnapshotXMLVariableLineRegexStr,
                REG_EXTENDED | REG_NOSUB) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "failed to compile test regex");
        goto cleanup;
    }


# define DO_TEST(prefix, name, inpath, outpath, uuid, internal, redefine)     \
    do {                                                                      \
        const struct testInfo info = {abs_srcdir "/" inpath "/" name ".xml",  \
                                      abs_srcdir "/" outpath "/" name ".xml", \
                                      uuid, internal, redefine};              \
        if (virTestRun("SNAPSHOT XML-2-XML " prefix " " name,                 \
                       testCompareXMLToXMLHelper, &info) < 0)                 \
            ret = -1;                                                         \
    } while (0)

# define DO_TEST_IN(name, uuid) DO_TEST("in->in", name,\
                                        "domainsnapshotxml2xmlin",\
                                        "domainsnapshotxml2xmlin",\
                                        uuid, false, false)

# define DO_TEST_OUT(name, uuid, internal) DO_TEST("out->out", name,\
                                                   "domainsnapshotxml2xmlout",\
                                                   "domainsnapshotxml2xmlout",\
                                                   uuid, internal, true)

# define DO_TEST_INOUT(name, uuid, internal, redefine) \
    DO_TEST("in->out", name,\
            "domainsnapshotxml2xmlin",\
            "domainsnapshotxml2xmlout",\
            uuid, internal, redefine)

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

    DO_TEST_OUT("all_parameters", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8", true);
    DO_TEST_OUT("disk_snapshot_redefine", "c7a5fdbd-edaf-9455-926a-d65c16db1809", true);
    DO_TEST_OUT("full_domain", "c7a5fdbd-edaf-9455-926a-d65c16db1809", true);
    DO_TEST_OUT("noparent_nodescription_noactive", NULL, false);
    DO_TEST_OUT("noparent_nodescription", NULL, true);
    DO_TEST_OUT("noparent", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8", false);
    DO_TEST_OUT("metadata", "c7a5fdbd-edaf-9455-926a-d65c16db1809", false);
    DO_TEST_OUT("external_vm_redefine", "c7a5fdbd-edaf-9455-926a-d65c16db1809", false);

    DO_TEST_INOUT("empty", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8", false, false);
    DO_TEST_INOUT("noparent", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8", false, false);
    DO_TEST_INOUT("external_vm", NULL, false, false);
    DO_TEST_INOUT("noparent", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8", false, false);
    DO_TEST_INOUT("disk_snapshot", NULL, false, false);
    DO_TEST_INOUT("disk_driver_name_null", NULL, false, false);

    DO_TEST_IN("name_and_description", NULL);
    DO_TEST_IN("description_only", NULL);
    DO_TEST_IN("name_only", NULL);

 cleanup:
    if (testSnapshotXMLVariableLineRegex)
        regfree(testSnapshotXMLVariableLineRegex);
    VIR_FREE(testSnapshotXMLVariableLineRegex);
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
