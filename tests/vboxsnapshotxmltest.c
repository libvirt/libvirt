#include <config.h>

#include "testutils.h"

#ifdef WITH_VBOX

# include <stdio.h>
# include <stdlib.h>
# include <regex.h>
# include "vbox/vbox_snapshot_conf.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static const char *testSnapshotXMLVariableLineRegexStr =
        "lastStateChange=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z";

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

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto cleanup;
    }

    ret = virBufferContentAndReset(&buf);

 cleanup:
   virBufferFreeAndReset(&buf);
   virStringListFree(xmlLines);
   return ret;
}

static int
testCompareXMLtoXMLFiles(const char *xml)
{
    char *xmlData = NULL;
    char *actual = NULL;
    char *pathResult = NULL;
    int ret = -1;
    virVBoxSnapshotConfMachinePtr machine = NULL;

    if (VIR_STRDUP(pathResult,
                   abs_builddir "/vboxsnapshotxmldata/testResult.vbox") < 0)
        return -1;

    if (virFileMakePath(abs_builddir "/vboxsnapshotxmldata") < 0)
        goto cleanup;

    if (virTestLoadFile(xml, &xmlData) < 0)
        goto cleanup;

    if (!(machine = virVBoxSnapshotConfLoadVboxFile(xml, (char*)"")))
        goto cleanup;

    if (virVBoxSnapshotConfSaveVboxFile(machine, pathResult) < 0)
        goto cleanup;

    if (virTestLoadFile(pathResult, &actual) < 0)
        goto cleanup;

    if (!(actual = testFilterXML(actual)))
        goto cleanup;
    if (!(xmlData = testFilterXML(xmlData)))
        goto cleanup;

    if (STRNEQ(actual, xmlData)) {
        virTestDifference(stderr, xmlData, actual);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    unlink(pathResult);
    rmdir(abs_builddir "/vboxsnapshotxmldata");
    VIR_FREE(xmlData);
    VIR_FREE(actual);
    virVBoxSnapshotConfMachineFree(machine);
    VIR_FREE(pathResult);

    return ret;
}

static int
testCompareXMLToXMLHelper(const void *data)
{
    int result = -1;
    char *xml = NULL;

    if (virAsprintf(&xml, "%s/vboxsnapshotxmldata/%s.vbox",
                    abs_srcdir, (const char*)data) < 0)
        return -1;

    result = testCompareXMLtoXMLFiles(xml);

    VIR_FREE(xml);
    return result;
}

static int
mymain(void)
{
    int ret = 0;
    if (VIR_ALLOC(testSnapshotXMLVariableLineRegex) < 0)
        goto cleanup;

    if (regcomp(testSnapshotXMLVariableLineRegex,
                testSnapshotXMLVariableLineRegexStr,
                REG_EXTENDED | REG_NOSUB) != 0) {
        ret = -1;
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "failed to compile test regex");
        goto cleanup;
    }

# define DO_TEST(name)                                       \
    if (virTestRun("VBox Snapshot XML-2-XML " name,          \
                   testCompareXMLToXMLHelper, (name)) < 0)   \
        ret = -1

    DO_TEST("2disks-nosnap");
    DO_TEST("2disks-1snap");
    DO_TEST("2disks-2snap");
    DO_TEST("2disks-3snap");
    DO_TEST("2disks-3snap-brother");

 cleanup:
    if (testSnapshotXMLVariableLineRegex)
        regfree(testSnapshotXMLVariableLineRegex);
    VIR_FREE(testSnapshotXMLVariableLineRegex);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /*WITH_VBOX*/
