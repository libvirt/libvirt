#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "testutils.h"

#ifdef WITH_QEMU

# include "internal.h"
# include "viralloc.h"
# include "qemu/qemu_monitor.h"
# include "qemu/qemu_monitor_text.h"
# include "qemumonitortestutils.h"
# include "testutilsqemu.h"

# define VIR_FROM_THIS VIR_FROM_NONE

struct testEscapeString
{
    const char *unescaped;
    const char *escaped;
};

static struct testEscapeString escapeStrings[] = {
    { "", "" },
    { " ", " " },
    { "\\", "\\\\" },
    { "\n", "\\n" },
    { "\r", "\\r" },
    { "\"", "\\\"" },
    { "\"\"\"\\\\\n\r\\\\\n\r\"\"\"", "\\\"\\\"\\\"\\\\\\\\\\n\\r\\\\\\\\\\n\\r\\\"\\\"\\\"" },
    { "drive_add dummy file=foo\\", "drive_add dummy file=foo\\\\" },
    { "block info", "block info" },
    { "set_password \":\\\"\"", "set_password \\\":\\\\\\\"\\\"" },
};

static int testEscapeArg(const void *data ATTRIBUTE_UNUSED)
{
    size_t i;
    char *escaped = NULL;
    for (i = 0; i < ARRAY_CARDINALITY(escapeStrings); ++i) {
        escaped = qemuMonitorEscapeArg(escapeStrings[i].unescaped);
        if (!escaped) {
            VIR_TEST_DEBUG("\nUnescaped string [%s]\n",
                    escapeStrings[i].unescaped);
            VIR_TEST_DEBUG("Expect result [%s]\n",
                    escapeStrings[i].escaped);
            VIR_TEST_DEBUG("Actual result [(null)]\n");
            return -1;
        }
        if (STRNEQ(escapeStrings[i].escaped, escaped)) {
            virTestDifference(stderr, escapeStrings[i].escaped, escaped);
            VIR_FREE(escaped);
            return -1;
        }
        VIR_FREE(escaped);
    }

    return 0;
}

static int testUnescapeArg(const void *data ATTRIBUTE_UNUSED)
{
    size_t i;
    char *unescaped = NULL;
    for (i = 0; i < ARRAY_CARDINALITY(escapeStrings); ++i) {
        unescaped = qemuMonitorUnescapeArg(escapeStrings[i].escaped);
        if (!unescaped) {
            VIR_TEST_DEBUG("\nEscaped string [%s]\n",
                    escapeStrings[i].escaped);
            VIR_TEST_DEBUG("Expect result [%s]\n",
                    escapeStrings[i].unescaped);
            VIR_TEST_DEBUG("Actual result [(null)]\n");
            return -1;
        }
        if (STRNEQ(escapeStrings[i].unescaped, unescaped)) {
            virTestDifference(stderr, escapeStrings[i].unescaped, unescaped);
            VIR_FREE(unescaped);
            return -1;
        }
        VIR_FREE(unescaped);
    }

    return 0;
}

struct blockInfoData {
    const char *dev;
    qemuBlockStats data;
};

static const struct blockInfoData testBlockInfoData[] =
{
/* NAME, rd_req, rd_bytes, wr_req, wr_bytes, rd_total_time, wr_total_time,
 * flush_req, flush_total_time, capacity, physical, wr_highest_offset,
 * wr_highest_offset_valid*/
    {"vda", {11, 12, 13, 14, 15, 16, 17, 18, 0, 0, 0, false}},
    {"vdb", {21, 22, 23, 24, 25, 26, 27, 28, 0, 0, 0, false}},
    {"vdc", {31, 32, 33, -1, 35, 36, 37, 38, 0, 0, 0, false}},
    {"vdd", {-1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, false}},
    {"vde", {41, 42, 43, 44, 45, 46, 47, 48, 0, 0, 0, false}}
};

static const char testBlockInfoReply[] =
"(qemu) info blockstats\r\n"
"vda: rd_operations=11 rd_bytes=12 wr_operations=13 wr_bytes=14 rd_total_time_ns=15 wr_total_time_ns=16 flush_operations=17 flush_total_time_ns=18\n"
"vdb: rd_total_time_ns=25 wr_total_time_ns=26 flush_operations=27 flush_total_time_ns=28 rd_operations=21 rd_bytes=22 wr_operations=23 wr_bytes=24 \n"
"drive-vdc: rd_operations=31 rd_bytes=32 wr_operations=33 rd_total_time_ns=35 wr_total_time_ns=36 flush_operations=37 flush_total_time_ns=38\n"
"vdd: \n"
"vde: rd_operations=41 rd_bytes=42 wr_operations=43 wr_bytes=44 rd_total_time_ns=45 wr_total_time_ns=46 flush_operations=47 flush_total_time_ns=48\n"
"(qemu) ";

static int
testMonitorTextBlockInfo(const void *opaque)
{
    virDomainXMLOptionPtr xmlopt = (virDomainXMLOptionPtr) opaque;
    qemuMonitorTestPtr test = qemuMonitorTestNewSimple(false, xmlopt);
    virHashTablePtr blockstats = NULL;
    size_t i;
    int ret = -1;

    if (!test)
        return -1;

    if (!(blockstats = virHashCreate(10, virHashValueFree)))
        goto cleanup;

    if (qemuMonitorTestAddItem(test, "info", testBlockInfoReply) < 0)
        goto cleanup;

    if (qemuMonitorTextGetAllBlockStatsInfo(qemuMonitorTestGetMonitor(test),
                                            blockstats) < 0)
        goto cleanup;

    for (i = 0; i < ARRAY_CARDINALITY(testBlockInfoData); i++) {
        qemuBlockStatsPtr entry;

        if (!(entry = virHashLookup(blockstats, testBlockInfoData[i].dev))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "device '%s' was not found in text block stats reply",
                           testBlockInfoData[i].dev);
            goto cleanup;
        }

        if (memcmp(entry, &testBlockInfoData[i].data, sizeof(qemuBlockStats)) != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "block stats for device '%s' differ",
                           testBlockInfoData[i].dev);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    qemuMonitorTestFree(test);
    virHashFree(blockstats);
    return ret;
}


static int
mymain(void)
{
    virQEMUDriver driver;
    int result = 0;

    if (virThreadInitialize() < 0 ||
        qemuTestDriverInit(&driver) < 0)
        return EXIT_FAILURE;

    virEventRegisterDefaultImpl();

# define DO_TEST(_name)                                                 \
    do {                                                                \
        if (virTestRun("qemu monitor "#_name, test##_name,              \
                       driver.xmlopt) < 0) {                            \
            result = -1;                                                \
        }                                                               \
    } while (0)

    DO_TEST(EscapeArg);
    DO_TEST(UnescapeArg);
    DO_TEST(MonitorTextBlockInfo);

    qemuTestDriverFree(&driver);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
