#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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

static int
testCompareXMLToXMLFiles(const char *inxml, const char *uuid, bool internal)
{
    char *inXmlData = NULL;
    char *actual = NULL;
    int ret = -1;
    virDomainSnapshotDefPtr def = NULL;
    unsigned int flags = (VIR_DOMAIN_SNAPSHOT_PARSE_REDEFINE |
                          VIR_DOMAIN_SNAPSHOT_PARSE_DISKS);

    if (virtTestLoadFile(inxml, &inXmlData) < 0)
        goto cleanup;

    if (internal)
        flags |= VIR_DOMAIN_SNAPSHOT_PARSE_INTERNAL;
    if (!(def = virDomainSnapshotDefParseString(inXmlData, driver.caps,
                                                driver.xmlopt,
                                                QEMU_EXPECTED_VIRT_TYPES,
                                                flags)))
        goto cleanup;

    if (!(actual = virDomainSnapshotDefFormat(uuid, def,
                                              VIR_DOMAIN_XML_SECURE,
                                              internal)))
        goto cleanup;


    if (STRNEQ(inXmlData, actual)) {
        virtTestDifference(stderr, inXmlData, actual);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(inXmlData);
    VIR_FREE(actual);
    virDomainSnapshotDefFree(def);
    return ret;
}

struct testInfo {
    const char *name;
    const char *uuid;
    bool internal;
};


static int
testCompareXMLToXMLHelper(const void *data)
{
    const struct testInfo *info = data;
    char *xml_in = NULL;
    int ret = -1;

    if (virAsprintf(&xml_in, "%s/domainsnapshotxml2xmlout/%s.xml",
                    abs_srcdir, info->name) < 0)
        goto cleanup;

    ret = testCompareXMLToXMLFiles(xml_in, info->uuid, info->internal);

cleanup:
    VIR_FREE(xml_in);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

    if ((driver.caps = testQemuCapsInit()) == NULL)
        return EXIT_FAILURE;

    if (!(driver.xmlopt = virQEMUDriverCreateXMLConf(&driver))) {
        virObjectUnref(driver.caps);
        return EXIT_FAILURE;
    }

# define DO_TEST(name, uuid, internal)                                  \
    do {                                                                \
        const struct testInfo info = {name, uuid, internal};            \
        if (virtTestRun("SNAPSHOT XML-2-XML " name,                     \
                        testCompareXMLToXMLHelper, &info) < 0)          \
            ret = -1;                                                   \
    } while (0)

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

    DO_TEST("all_parameters", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8", true);
    DO_TEST("disk_snapshot", "c7a5fdbd-edaf-9455-926a-d65c16db1809", true);
    DO_TEST("full_domain", "c7a5fdbd-edaf-9455-926a-d65c16db1809", true);
    DO_TEST("noparent_nodescription_noactive", NULL, false);
    DO_TEST("noparent_nodescription", NULL, true);
    DO_TEST("noparent", "9d37b878-a7cc-9f9a-b78f-49b3abad25a8", false);
    DO_TEST("metadata", "c7a5fdbd-edaf-9455-926a-d65c16db1809", false);
    DO_TEST("external_vm", "c7a5fdbd-edaf-9455-926a-d65c16db1809", false);

    virObjectUnref(driver.caps);
    virObjectUnref(driver.xmlopt);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
