#include <config.h>

#include "testutils.h"

#ifdef WITH_ESX

# include <stdio.h>
# include <string.h>
# include <unistd.h>

# include "internal.h"
# include "viralloc.h"
# include "vmx/vmx.h"
# include "esx/esx_util.h"
# include "esx/esx_vi_types.h"

struct testPath {
    const char *datastorePath;
    int result;
    const char *datastoreName;
    const char *directoryName;
    const char *directoryAndFileName;
};

static struct testPath paths[] = {
    { "[datastore] directory/file", 0, "datastore", "directory",
      "directory/file" },
    { "[datastore] directory1/directory2/file", 0, "datastore",
      "directory1/directory2", "directory1/directory2/file" },
    { "[datastore] file", 0, "datastore", "file", "file" },
    { "[datastore] directory/", 0, "datastore", "directory", "directory/" },
    { "[datastore]", 0, "datastore", "", "" },
    { "[] directory/file", -1, NULL, NULL, NULL },
    { "directory/file", -1, NULL, NULL, NULL },
};

static int
testParseDatastorePath(const void *data ATTRIBUTE_UNUSED)
{
    int result = 0;
    size_t i;
    char *datastoreName = NULL;
    char *directoryName = NULL;
    char *directoryAndFileName = NULL;

    for (i = 0; i < ARRAY_CARDINALITY(paths); ++i) {
        VIR_FREE(datastoreName);
        VIR_FREE(directoryName);
        VIR_FREE(directoryAndFileName);

        if (esxUtil_ParseDatastorePath
             (paths[i].datastorePath, &datastoreName, &directoryName,
              &directoryAndFileName) != paths[i].result) {
            goto failure;
        }

        if (paths[i].result < 0)
            continue;

        if (STRNEQ(paths[i].datastoreName, datastoreName)) {
            virTestDifference(stderr, paths[i].datastoreName, datastoreName);
            goto failure;
        }

        if (STRNEQ(paths[i].directoryName, directoryName)) {
            virTestDifference(stderr, paths[i].directoryName, directoryName);
            goto failure;
        }

        if (STRNEQ(paths[i].directoryAndFileName, directoryAndFileName)) {
            virTestDifference(stderr, paths[i].directoryAndFileName,
                              directoryAndFileName);
            goto failure;
        }
    }

 cleanup:
    VIR_FREE(datastoreName);
    VIR_FREE(directoryName);
    VIR_FREE(directoryAndFileName);

    return result;

 failure:
    result = -1;

    goto cleanup;
}



struct testDateTime {
    const char *dateTime;
    long long calendarTime;
};

static struct testDateTime times[] = {
    /* different timezones */
    { "2010-04-08T05:45:11-07:00", 1270730711 },
    { "2010-04-08T07:45:11-05:00", 1270730711 },
    { "2010-04-08T12:45:11+00:00", 1270730711 },
    { "2010-04-08T14:45:11+02:00", 1270730711 },
    { "2010-04-08T22:15:11+09:30", 1270730711 },
    { "2010-04-09T01:30:11+12:45", 1270730711 },

    /* optional parts */
    { "2010-04-08T12:45:11Z", 1270730711 },
    { "2010-04-08T12:45:11", 1270730711 },
    { "-2010-04-08T14:45:11+02:00", 0 },
    { "2010-04-08T14:45:11.529576+02:00", 1270730711 },

    /* borders */
    { "1970-01-01T00:00:00+00:00", 0 },
    { "2038-01-19T03:14:07+00:00", 2147483647 },

    /* random */
    { "1999-08-02T01:19:55+02:00", 933549595 },
    { "2004-03-07T23:23:55+02:00", 1078694635 },
    { "1984-10-27T14:33:45+02:00", 467728425 },
    { "1970-01-12T16:11:04+02:00", 1001464 },
    { "2014-07-20T13:35:38+02:00", 1405856138 },
    { "2032-06-24T17:04:49+02:00", 1971702289 },
};

static int
testConvertDateTimeToCalendarTime(const void *data ATTRIBUTE_UNUSED)
{
    size_t i;
    esxVI_DateTime dateTime;
    long long calendarTime;

    for (i = 0; i < ARRAY_CARDINALITY(times); ++i) {
        dateTime.value = (char *)times[i].dateTime;

        if (esxVI_DateTime_ConvertToCalendarTime(&dateTime,
                                                 &calendarTime) < 0) {
            return -1;
        }

        if (times[i].calendarTime != calendarTime)
            return -1;
    }

    return 0;
}



struct testDatastoreItem {
    const char *string;
    const char *escaped;
};

static struct testDatastoreItem datastoreItems[] = {
    { "normal", "normal" },
    { /* "Aä1ö2ü3ß4#5~6!7§8/9%Z" */
      "A\303\2441\303\2662\303\2743\303\2374#5~6!7\302\2478/9%Z",
      "A+w6Q-1+w7Y-2+w7w-3+w58-4+Iw-5+fg-6+IQ-7+wqc-8+JQ-2f9+JQ-25Z" },
    { /* "Z~6!7§8/9%0#1\"2'3`4&A" */ "Z~6!7\302\2478/9%0#1\"2'3`4&A",
      "Z+fg-6+IQ-7+wqc-8+JQ-2f9+JQ-250+Iw-1_2'3+YA-4+Jg-A" },
    { /* "標準語" */ "\346\250\231\346\272\226\350\252\236", "+5qiZ5rqW6Kqe" },
    { "!\"#$%&'()*+,-./0123456789:;<=>?",
      "+IQ-_+IyQl-25+Jg-'()_+Kw-,-.+JQ-2f0123456789_+Ow-_+PQ-__" },
    { "A Z[\\]^_B", "A Z+WyU-5c+XV4-_B" },
    { "A`B@{|}~DEL", "A+YA-B+QHs-_+fX4-DEL" },
    { /* "hÀÁÂÃÄÅH" */ "h\303\200\303\201\303\202\303\203\303\204\303\205H",
      "h+w4DDgcOCw4PDhMOF-H" },
    { /* "A쿀Z" */ "A\354\277\200Z", "A+7L+A-Z" },
    { /* "!쿀A" */ "!\354\277\200A", "+Iey,gA-A" },
    { "~~~", "+fn5+" },
    { "~~~A", "+fn5+-A" },
    { "K%U/H\\Z", "K+JQ-25U+JQ-2fH+JQ-5cZ" },
    { "vvv<A\"B\"C>zzz", "vvv_A_B_C_zzz" },
};

static int
testEscapeDatastoreItem(const void *data ATTRIBUTE_UNUSED)
{
    size_t i;
    char *escaped = NULL;

    for (i = 0; i < ARRAY_CARDINALITY(datastoreItems); ++i) {
        VIR_FREE(escaped);

        escaped = esxUtil_EscapeDatastoreItem(datastoreItems[i].string);

        if (escaped == NULL)
            return -1;

        if (STRNEQ(datastoreItems[i].escaped, escaped)) {
            VIR_FREE(escaped);
            return -1;
        }
    }

    VIR_FREE(escaped);
    return 0;
}



struct testWindows1252ToUTF8 {
    const char *windows1252;
    const char *utf8;
};

static struct testWindows1252ToUTF8 windows1252ToUTF8[] = {
    { "normal", "normal" },
    { /* "A€Z" */ "A\200Z", "A\342\202\254Z" },
    { /* "Aä1ö2ü3ß4#5~6!7§8/9%Z" */ "A\3441\3662\3743\3374#5~6!7\2478/9%Z",
      "A\303\2441\303\2662\303\2743\303\2374#5~6!7\302\2478/9%Z" },
    { /* "hÀÁÂÃÄÅH" */ "h\300\301\302\303\304\305H",
      "h\303\200\303\201\303\202\303\203\303\204\303\205H" },
};

static int
testConvertWindows1252ToUTF8(const void *data ATTRIBUTE_UNUSED)
{
    size_t i;
    char *utf8 = NULL;

    for (i = 0; i < ARRAY_CARDINALITY(windows1252ToUTF8); ++i) {
        VIR_FREE(utf8);

        utf8 = virVMXConvertToUTF8("Windows-1252",
                                   windows1252ToUTF8[i].windows1252);

        if (utf8 == NULL)
            return -1;

        if (STRNEQ(windows1252ToUTF8[i].utf8, utf8)) {
            VIR_FREE(utf8);
            return -1;
        }
    }

    VIR_FREE(utf8);
    return 0;
}



static int
mymain(void)
{
    int result = 0;

    virTestQuiesceLibvirtErrors(true);

# define DO_TEST(_name)                                                       \
        do {                                                                  \
            if (virTestRun("VMware "#_name, test##_name,                      \
                           NULL) < 0) {                                       \
                result = -1;                                                  \
            }                                                                 \
        } while (0)

    DO_TEST(ParseDatastorePath);
    DO_TEST(ConvertDateTimeToCalendarTime);
    DO_TEST(EscapeDatastoreItem);
    DO_TEST(ConvertWindows1252ToUTF8);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)

#else

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_ESX */
