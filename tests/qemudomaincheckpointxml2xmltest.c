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
# include "checkpoint_conf.h"
# include "testutilsqemu.h"
# include "virstring.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static virQEMUDriver driver;

enum {
    TEST_REDEFINE = 1 << 0, /* Test use of REDEFINE parse flag */
    TEST_PARENT = 1 << 1, /* hard-code parent after parse */
    TEST_VDA_BITMAP = 1 << 2, /* hard-code disk vda after parse */
    TEST_SIZE = 1 << 3, /* Test use of SIZE format flag */
    TEST_INVALID = 1 << 4, /* Test that input fails parse */
};

static int
testCompareXMLToXMLFiles(const char *inxml,
                         const char *outxml,
                         unsigned int flags)
{
    unsigned int parseflags = 0;
    unsigned int formatflags = VIR_DOMAIN_CHECKPOINT_FORMAT_SECURE;
    g_autofree char *inXmlData = NULL;
    g_autofree char *outXmlData = NULL;
    g_autofree char *actual = NULL;
    g_autoptr(virDomainCheckpointDef) def = NULL;

    if (flags & TEST_REDEFINE)
        parseflags |= VIR_DOMAIN_CHECKPOINT_PARSE_REDEFINE;

    if (virTestLoadFile(inxml, &inXmlData) < 0)
        return -1;

    if (!(flags & TEST_INVALID) &&
        virTestLoadFile(outxml, &outXmlData) < 0)
        return -1;

    if (!(def = virDomainCheckpointDefParseString(inXmlData, driver.caps,
                                                  driver.xmlopt, NULL,
                                                  parseflags))) {
        if (flags & TEST_INVALID)
            return 0;
        return -1;
    }
    if (flags & TEST_PARENT) {
        if (def->parent.parent_name)
            return -1;
        if (VIR_STRDUP(def->parent.parent_name, "1525111885") < 0)
            return -1;
    }
    if (flags & TEST_VDA_BITMAP) {
        virDomainCheckpointDiskDefPtr disk;

        if (VIR_EXPAND_N(def->disks, def->ndisks, 1) < 0)
            return -1;
        disk = &def->disks[0];
        if (disk->bitmap)
            return -1;
        if (!disk->name) {
            disk->type = VIR_DOMAIN_CHECKPOINT_TYPE_BITMAP;
            if (VIR_STRDUP(disk->name, "vda") < 0)
                return -1;
        } else if (STRNEQ(disk->name, "vda")) {
            return -1;
        }
        if (VIR_STRDUP(disk->bitmap, def->parent.name) < 0)
            return -1;
    }
    if (flags & TEST_SIZE) {
        def->disks[0].size = 1048576;
        formatflags |= VIR_DOMAIN_CHECKPOINT_FORMAT_SIZE;
    }

    /* Parsing XML does not populate the domain definition; work
     * around that by not requesting domain on output */
    if (!def->parent.dom)
        formatflags |= VIR_DOMAIN_CHECKPOINT_FORMAT_NO_DOMAIN;

    if (!(actual = virDomainCheckpointDefFormat(def, driver.caps,
                                                driver.xmlopt,
                                                formatflags)))
        return -1;

    if (STRNEQ(outXmlData, actual)) {
        virTestDifferenceFull(stderr, outXmlData, outxml, actual, inxml);
        return -1;
    }

    return 0;
}

struct testInfo {
    const char *inxml;
    const char *outxml;
    long long creationTime;
    unsigned int flags;
};
static long long mocktime;

static int
testCheckpointPostParse(virDomainMomentDefPtr def)
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
    return testCompareXMLToXMLFiles(info->inxml, info->outxml, info->flags);
}


static int
mymain(void)
{
    int ret = 0;

    if (qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    virDomainXMLOptionSetMomentPostParse(driver.xmlopt,
                                         testCheckpointPostParse);

# define DO_TEST(prefix, name, inpath, outpath, time, flags) \
    do { \
        const struct testInfo info = {abs_srcdir "/" inpath "/" name ".xml", \
                                      abs_srcdir "/" outpath "/" name ".xml", \
                                      time, flags}; \
        if (virTestRun("CHECKPOINT XML-2-XML " prefix " " name, \
                       testCompareXMLToXMLHelper, &info) < 0) \
            ret = -1; \
    } while (0)

# define DO_TEST_INOUT(name, time, flags) \
    DO_TEST("in->out", name, \
            "qemudomaincheckpointxml2xmlin", \
            "qemudomaincheckpointxml2xmlout", \
            time, flags)
# define DO_TEST_OUT(name, flags) \
    DO_TEST("out->out", name, \
            "qemudomaincheckpointxml2xmlout", \
            "qemudomaincheckpointxml2xmlout", \
            0, flags | TEST_REDEFINE)
# define DO_TEST_INVALID(name) \
    DO_TEST("in->out", name, \
            "qemudomaincheckpointxml2xmlin", \
            "qemudomaincheckpointxml2xmlout", \
            0, TEST_INVALID)

    /* Unset or set all envvars here that are copied in qemudBuildCommandLine
     * using ADD_ENV_COPY, otherwise these tests may fail due to unexpected
     * values for these envvars */
    setenv("PATH", "/bin", 1);

    /* Test a normal user redefine */
    DO_TEST_OUT("redefine", 0);

    /* Tests of valid user input, and resulting output */
    DO_TEST_INOUT("empty", 1525889631, TEST_VDA_BITMAP);
    DO_TEST_INOUT("disk-default", 1525889631, TEST_PARENT | TEST_VDA_BITMAP);
    DO_TEST_INOUT("sample", 1525889631, TEST_PARENT | TEST_VDA_BITMAP);
    DO_TEST_INOUT("size", 1553648510,
                  TEST_PARENT | TEST_VDA_BITMAP | TEST_SIZE);

    /* Tests of invalid user input */
    DO_TEST_INVALID("disk-invalid");
    DO_TEST_INVALID("name-invalid");

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
