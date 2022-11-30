#include <config.h>

#include <unistd.h>

#include "testutils.h"

#ifdef WITH_VBOX

# include "vbox/vbox_snapshot_conf.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static const char *testSnapshotXMLVariableLineRegexStr =
        "lastStateChange=[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z";

GRegex *testSnapshotXMLVariableLineRegex = NULL;

static char *
testFilterXML(char *xml)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_auto(GStrv) xmlLines = NULL;
    char **xmlLine;

    if (!(xmlLines = g_strsplit(xml, "\n", 0))) {
        VIR_FREE(xml);
        return NULL;
    }
    VIR_FREE(xml);

    for (xmlLine = xmlLines; *xmlLine; xmlLine++) {
        if (g_regex_match(testSnapshotXMLVariableLineRegex, *xmlLine, 0, NULL))
            continue;

        virBufferStrcat(&buf, *xmlLine, "\n", NULL);
    }

    return virBufferContentAndReset(&buf);
}

static int
testCompareXMLtoXMLFiles(const char *xml)
{
    g_autofree char *xmlData = NULL;
    g_autofree char *actual = NULL;
    g_autofree char *pathResult = NULL;
    int ret = -1;
    virVBoxSnapshotConfMachine *machine = NULL;

    pathResult = g_strdup(abs_builddir "/vboxsnapshotxmldata/testResult.vbox");

    if (g_mkdir_with_parents(abs_builddir "/vboxsnapshotxmldata", 0777) < 0)
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

    if (virTestCompareToString(xmlData, actual) < 0) {
        goto cleanup;
    }

    ret = 0;

 cleanup:
    unlink(pathResult);
    rmdir(abs_builddir "/vboxsnapshotxmldata");
    virVBoxSnapshotConfMachineFree(machine);

    return ret;
}

static int
testCompareXMLToXMLHelper(const void *data)
{
    int result = -1;
    g_autofree char *xml = NULL;

    xml = g_strdup_printf("%s/vboxsnapshotxmldata/%s.vbox", abs_srcdir,
                          (const char *)data);

    result = testCompareXMLtoXMLFiles(xml);

    return result;
}

static int
mymain(void)
{
    int ret = 0;
    g_autoptr(GError) err = NULL;

    testSnapshotXMLVariableLineRegex = g_regex_new(testSnapshotXMLVariableLineRegexStr,
                                                   0, 0, &err);

    if (!testSnapshotXMLVariableLineRegex) {
        ret = -1;
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "failed to compile test regex");
        goto cleanup;
    }

# define DO_TEST(name) \
    if (virTestRun("VBox Snapshot XML-2-XML " name, \
                   testCompareXMLToXMLHelper, (name)) < 0) \
        ret = -1

    DO_TEST("2disks-nosnap");
    DO_TEST("2disks-1snap");
    DO_TEST("2disks-2snap");
    DO_TEST("2disks-3snap");
    DO_TEST("2disks-3snap-brother");

 cleanup:
    if (testSnapshotXMLVariableLineRegex)
        g_regex_unref(testSnapshotXMLVariableLineRegex);
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_VBOX */
