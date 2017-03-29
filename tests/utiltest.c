#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "internal.h"
#include "viralloc.h"
#include "testutils.h"
#include "virutil.h"

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

struct testDiskName
{
    const char *name;
    int idx;
    int partition;
};

static struct testDiskName diskNamesPart[] = {
    {"sda0",          0,           0},
    {"sdb10",         1,          10},
    {"sdc2147483647", 2,  2147483647},
};

static const char* diskNamesInvalid[] = {
    "sda00", "sda01", "sdb-1",
    "vd2"
};

static int
testIndexToDiskName(const void *data ATTRIBUTE_UNUSED)
{
    size_t i;
    char *diskName = NULL;

    for (i = 0; i < ARRAY_CARDINALITY(diskNames); ++i) {
        VIR_FREE(diskName);

        diskName = virIndexToDiskName(i, "sd");

        if (STRNEQ(diskNames[i], diskName)) {
            virTestDifference(stderr, diskNames[i], diskName);
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
    size_t i;
    int idx;
    char *diskName = NULL;

    for (i = 0; i < 100000; ++i) {
        VIR_FREE(diskName);

        diskName = virIndexToDiskName(i, "sd");
        idx = virDiskNameToIndex(diskName);

        if (idx < 0 || idx != i) {
            VIR_TEST_DEBUG("\nExpect [%zu]\n", i);
            VIR_TEST_DEBUG("Actual [%d]\n", idx);

            VIR_FREE(diskName);

            return -1;
        }
    }

    VIR_FREE(diskName);

    return 0;
}



static int
testDiskNameParse(const void *data ATTRIBUTE_UNUSED)
{
    size_t i;
    int idx;
    int partition;
    struct testDiskName *disk = NULL;

    for (i = 0; i < ARRAY_CARDINALITY(diskNamesPart); ++i) {
        disk = &diskNamesPart[i];
        if (virDiskNameParse(disk->name, &idx, &partition))
            return -1;

        if (disk->idx != idx) {
            VIR_TEST_DEBUG("\nExpect [%d]\n", disk->idx);
            VIR_TEST_DEBUG("Actual [%d]\n", idx);
            return -1;
        }

        if (disk->partition != partition) {
            VIR_TEST_DEBUG("\nExpect [%d]\n", disk->partition);
            VIR_TEST_DEBUG("Actual [%d]\n", partition);
            return -1;
        }
    }

    for (i = 0; i < ARRAY_CARDINALITY(diskNamesInvalid); ++i) {
        if (!virDiskNameParse(diskNamesInvalid[i], &idx, &partition)) {
            VIR_TEST_DEBUG("Should Fail [%s]\n", diskNamesInvalid[i]);
            return -1;
        }
    }

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
    int result;
    size_t i;
    unsigned long version;

    for (i = 0; i < ARRAY_CARDINALITY(versions); ++i) {
        result = virParseVersionString(versions[i].string, &version,
                                       versions[i].allowMissing);

        if (result != versions[i].result) {
            VIR_TEST_DEBUG("\nVersion string [%s]\n", versions[i].string);
            VIR_TEST_DEBUG("Expect result [%d]\n", versions[i].result);
            VIR_TEST_DEBUG("Actual result [%d]\n", result);

            return -1;
        }

        if (result < 0)
            continue;

        if (version != versions[i].version) {
            VIR_TEST_DEBUG("\nVersion string [%s]\n", versions[i].string);
            VIR_TEST_DEBUG("Expect version [%lu]\n", versions[i].version);
            VIR_TEST_DEBUG("Actual version [%lu]\n", version);

            return -1;
        }
    }

    return 0;
}



struct testRoundData {
    unsigned int input;
    unsigned int output;
};

static struct testRoundData roundData[] = {
    { 0, 0 },
    { 1, 1 },
    { 1000, 1024 },
    { 1024, 1024 },
    { 1025, 2048 },
    { UINT_MAX, 0 },
};

static int
testRoundValueToPowerOfTwo(const void *data ATTRIBUTE_UNUSED)
{
    unsigned int result;
    size_t i;

    for (i = 0; i < ARRAY_CARDINALITY(roundData); i++) {
        result = VIR_ROUND_UP_POWER_OF_TWO(roundData[i].input);
        if (roundData[i].output != result) {
            VIR_TEST_DEBUG("\nInput number [%u]\n", roundData[i].input);
            VIR_TEST_DEBUG("Expected number [%u]\n", roundData[i].output);
            VIR_TEST_DEBUG("Actual number [%u]\n", result);

            return -1;
        }
    }

    return 0;
}


#define TEST_OVERFLOW(var, val, expect)                                        \
    tmp = val;                                                                 \
    if (VIR_ASSIGN_IS_OVERFLOW(var, tmp) != expect) {                          \
        fprintf(stderr, "\noverflow check failed: "                            \
                "var: " #var " val: " #val "\n");                              \
        return -1;                                                             \
    }

static int
testOverflowCheckMacro(const void *data ATTRIBUTE_UNUSED)
{
    long long tmp;
    uint8_t luchar;
    int8_t lchar;

    TEST_OVERFLOW(luchar, 254, false);
    TEST_OVERFLOW(luchar, 255, false);
    TEST_OVERFLOW(luchar, 256, true);
    TEST_OVERFLOW(luchar, 767, true);

    TEST_OVERFLOW(lchar, 127, false);
    TEST_OVERFLOW(lchar, -128, false);
    TEST_OVERFLOW(lchar, -129, true);
    TEST_OVERFLOW(lchar, 128, true);

    return 0;
}




static int
mymain(void)
{
    int result = 0;

    virTestQuiesceLibvirtErrors(true);

#define DO_TEST(_name)                                                        \
        do {                                                                  \
            if (virTestRun("Util "#_name, test##_name,                        \
                           NULL) < 0) {                                       \
                result = -1;                                                  \
            }                                                                 \
        } while (0)

    DO_TEST(IndexToDiskName);
    DO_TEST(DiskNameToIndex);
    DO_TEST(DiskNameParse);
    DO_TEST(ParseVersionString);
    DO_TEST(RoundValueToPowerOfTwo);
    DO_TEST(OverflowCheckMacro);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
