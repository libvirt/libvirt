#include <config.h>

#ifdef WITH_ESX

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "memory.h"
#include "testutils.h"
#include "esx/esx_util.h"
#include "esx/esx_vmx.h"

static char *progname;



static void
testQuietError(void *userData ATTRIBUTE_UNUSED,
               virErrorPtr error ATTRIBUTE_UNUSED)
{
    /* nothing */
}



static const char* names[] = {
    "sda",  "sdb",  "sdc",  "sdd",  "sde",  "sdf",  "sdg",  "sdh",  "sdi",  "sdj",  "sdk",  "sdl",  "sdm",  "sdn",  "sdo",  "sdp",  "sdq",  "sdr",  "sds",  "sdt",  "sdu",  "sdv",  "sdw",  "sdx",  "sdy",  "sdz",
    "sdaa", "sdab", "sdac", "sdad", "sdae", "sdaf", "sdag", "sdah", "sdai", "sdaj", "sdak", "sdal", "sdam", "sdan", "sdao", "sdap", "sdaq", "sdar", "sdas", "sdat", "sdau", "sdav", "sdaw", "sdax", "sday", "sdaz",
    "sdba", "sdbb", "sdbc", "sdbd", "sdbe", "sdbf", "sdbg", "sdbh", "sdbi", "sdbj", "sdbk", "sdbl", "sdbm", "sdbn", "sdbo", "sdbp", "sdbq", "sdbr", "sdbs", "sdbt", "sdbu", "sdbv", "sdbw", "sdbx", "sdby", "sdbz",
    "sdca", "sdcb", "sdcc", "sdcd", "sdce", "sdcf", "sdcg", "sdch", "sdci", "sdcj", "sdck", "sdcl", "sdcm", "sdcn", "sdco", "sdcp", "sdcq", "sdcr", "sdcs", "sdct", "sdcu", "sdcv", "sdcw", "sdcx", "sdcy", "sdcz",
    "sdda", "sddb", "sddc", "sddd", "sdde", "sddf", "sddg", "sddh", "sddi", "sddj", "sddk", "sddl", "sddm", "sddn", "sddo", "sddp", "sddq", "sddr", "sdds", "sddt", "sddu", "sddv", "sddw", "sddx", "sddy", "sddz",
    "sdea", "sdeb", "sdec", "sded", "sdee", "sdef", "sdeg", "sdeh", "sdei", "sdej", "sdek", "sdel", "sdem", "sden", "sdeo", "sdep", "sdeq", "sder", "sdes", "sdet", "sdeu", "sdev", "sdew", "sdex", "sdey", "sdez",
    "sdfa", "sdfb", "sdfc", "sdfd", "sdfe", "sdff", "sdfg", "sdfh", "sdfi", "sdfj", "sdfk", "sdfl", "sdfm", "sdfn", "sdfo", "sdfp", "sdfq", "sdfr", "sdfs", "sdft", "sdfu", "sdfv", "sdfw", "sdfx", "sdfy", "sdfz",
    "sdga", "sdgb", "sdgc", "sdgd", "sdge", "sdgf", "sdgg", "sdgh", "sdgi", "sdgj", "sdgk", "sdgl", "sdgm", "sdgn", "sdgo", "sdgp", "sdgq", "sdgr", "sdgs", "sdgt", "sdgu", "sdgv", "sdgw", "sdgx", "sdgy", "sdgz",
    "sdha", "sdhb", "sdhc", "sdhd", "sdhe", "sdhf", "sdhg", "sdhh", "sdhi", "sdhj", "sdhk", "sdhl", "sdhm", "sdhn", "sdho", "sdhp", "sdhq", "sdhr", "sdhs", "sdht", "sdhu", "sdhv", "sdhw", "sdhx", "sdhy", "sdhz",
    "sdia", "sdib", "sdic", "sdid", "sdie", "sdif", "sdig", "sdih", "sdii", "sdij", "sdik", "sdil", "sdim", "sdin", "sdio", "sdip", "sdiq", "sdir", "sdis", "sdit", "sdiu", "sdiv", "sdiw", "sdix", "sdiy", "sdiz"
};

static int
testIndexToDiskName(const void *data ATTRIBUTE_UNUSED)
{
    int i;
    char *name = NULL;

    for (i = 0; i < ARRAY_CARDINALITY(names); ++i) {
        VIR_FREE(name);

        name = esxVMX_IndexToDiskName(NULL, i, "sd");

        if (STRNEQ(names[i], name)) {
            virtTestDifference(stderr, names[i], name);
            VIR_FREE(name);

            return -1;
        }

        if (virDiskNameToIndex(name) != i) {
            VIR_FREE(name);

            return -1;
        }
    }

    VIR_FREE(name);

    return 0;
}



struct testPath {
    const char *datastoreRelatedPath;
    int result;
    const char *datastoreName;
    const char *directoryName;
    const char *fileName;
};

static struct testPath paths[] = {
    { "[datastore] directory/file", 0, "datastore", "directory", "file" },
    { "[datastore] file", 0, "datastore", NULL, "file" },
    { "[] directory/file", -1, NULL, NULL, NULL },
    { "[datastore] directory/", -1, NULL, NULL, NULL },
    { "directory/file", -1, NULL, NULL, NULL },
};

static int
testParseDatastoreRelatedPath(const void *data ATTRIBUTE_UNUSED)
{
    int i, result = 0;
    char *datastoreName = NULL;
    char *directoryName = NULL;
    char *fileName = NULL;

    for (i = 0; i < ARRAY_CARDINALITY(paths); ++i) {
        VIR_FREE(datastoreName);
        VIR_FREE(directoryName);
        VIR_FREE(fileName);

        if (esxUtil_ParseDatastoreRelatedPath(NULL,
                                              paths[i].datastoreRelatedPath,
                                              &datastoreName, &directoryName,
                                              &fileName) != paths[i].result) {
            goto failure;
        }

        if (paths[i].result < 0) {
            continue;
        }

        if (STRNEQ(paths[i].datastoreName, datastoreName)) {
            virtTestDifference(stderr, paths[i].datastoreName, datastoreName);
            goto failure;
        }

        if (paths[i].directoryName != NULL &&
            STRNEQ(paths[i].directoryName, directoryName)) {
            virtTestDifference(stderr, paths[i].directoryName, directoryName);
            goto failure;
        }

        if (STRNEQ(paths[i].fileName, fileName)) {
            virtTestDifference(stderr, paths[i].fileName, fileName);
            goto failure;
        }
    }

  cleanup:
    VIR_FREE(datastoreName);
    VIR_FREE(directoryName);
    VIR_FREE(fileName);

    return result;

  failure:
    result = -1;

    goto cleanup;
}



static int
mymain(int argc, char **argv)
{
    int result = 0;

    progname = argv[0];

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return EXIT_FAILURE;
    }

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", progname);
        return EXIT_FAILURE;
    }

    virSetErrorFunc(NULL, testQuietError);

    #define DO_TEST(_name)                                                    \
        do {                                                                  \
            if (virtTestRun("VMware "#_name, 1, test##_name,                  \
                            NULL) < 0) {                                      \
                result = -1;                                                  \
            }                                                                 \
        } while (0)

    DO_TEST(IndexToDiskName);
    DO_TEST(ParseDatastoreRelatedPath);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else

int main (void)
{
    return 77; /* means 'test skipped' for automake */
}

#endif /* WITH_ESX */
