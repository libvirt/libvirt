#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "memory.h"
#include "testutils.h"
#include "util.h"


static void
testQuietError(void *userData ATTRIBUTE_UNUSED,
               virErrorPtr error ATTRIBUTE_UNUSED)
{
    /* nothing */
}



static const char* diskNames[] = {
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
    char *diskName = NULL;

    for (i = 0; i < ARRAY_CARDINALITY(diskNames); ++i) {
        VIR_FREE(diskName);

        diskName = virIndexToDiskName(i, "sd");

        if (STRNEQ(diskNames[i], diskName)) {
            virtTestDifference(stderr, diskNames[i], diskName);
            VIR_FREE(diskName);

            return -1;
        }
    }

    VIR_FREE(diskName);

    return 0;
}



static int
testDiskNameToIndex(const void *data ATTRIBUTE_UNUSED)
{
    int i, k;
    char *diskName = NULL;

    for (i = 0; i < 100000; ++i) {
        VIR_FREE(diskName);

        diskName = virIndexToDiskName(i, "sd");
        k = virDiskNameToIndex(diskName);

        if (k != i) {
            if (virTestGetDebug() > 0) {
                fprintf(stderr, "\nExpect [%d]\n", i);
                fprintf(stderr, "Actual [%d]\n", k);
            }

            VIR_FREE(diskName);

            return -1;
        }
    }

    VIR_FREE(diskName);

    return 0;
}



struct testVersionString
{
    const char *string;
    bool allowMissing;
    int result;
    unsigned long version;
};

static struct testVersionString versions[] = {
    { "2.6.38-8-generic", false,  0, 1000000 * 2 + 1000 * 6 + 38 },
    { "3.0-1-virtual",    true,   0, 1000000 * 3 + 1000 * 0 + 0 },
    { "5",                true,   0, 1000000 * 5 + 1000 * 0 + 0 },
    { "4.1.0",            false,  0, 1000000 * 4 + 1000 * 1 + 0 },
    { "12.345.678",       false,  0, 1000000 * 12 + 1000 * 345 + 678 },
    { "1.234.5678",       false, -1, 0 },
    { "1.2345.678",       false, -1, 0 },
    { "12345.6.78",       false, -1, 0 },
    { "123456789",        true,  -1, 0 },
    { "3.0-2-virtual",    false, -1, 0 },
    { "no-number-here",   false, -1, 0 },
};

static int
testParseVersionString(const void *data ATTRIBUTE_UNUSED)
{
    int i, result;
    unsigned long version;

    for (i = 0; i < ARRAY_CARDINALITY(versions); ++i) {
        result = virParseVersionString(versions[i].string, &version,
                                       versions[i].allowMissing);

        if (result != versions[i].result) {
            if (virTestGetDebug() > 0) {
                fprintf(stderr, "\nVersion string [%s]\n", versions[i].string);
                fprintf(stderr, "Expect result [%d]\n", versions[i].result);
                fprintf(stderr, "Actual result [%d]\n", result);
            }

            return -1;
        }

        if (result < 0) {
            continue;
        }

        if (version != versions[i].version) {
            if (virTestGetDebug() > 0) {
                fprintf(stderr, "\nVersion string [%s]\n", versions[i].string);
                fprintf(stderr, "Expect version [%lu]\n", versions[i].version);
                fprintf(stderr, "Actual version [%lu]\n", version);
            }

            return -1;
        }
    }

    return 0;
}




static int
mymain(void)
{
    int result = 0;

    virSetErrorFunc(NULL, testQuietError);

#define DO_TEST(_name)                                                  \
        do {                                                                  \
            if (virtTestRun("Util "#_name, 1, test##_name,                    \
                            NULL) < 0) {                                      \
                result = -1;                                                  \
            }                                                                 \
        } while (0)

    DO_TEST(IndexToDiskName);
    DO_TEST(DiskNameToIndex);
    DO_TEST(ParseVersionString);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
