#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_QEMU

# include "internal.h"
# include "memory.h"
# include "testutils.h"
# include "util.h"
# include "qemu/qemu_monitor.h"

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
    int i;
    char *escaped = NULL;
    for (i = 0; i < ARRAY_CARDINALITY(escapeStrings); ++i) {
        escaped = qemuMonitorEscapeArg(escapeStrings[i].unescaped);
        if (!escaped) {
            if (virTestGetDebug() > 0) {
                fprintf(stderr, "\nUnescaped string [%s]\n",
                        escapeStrings[i].unescaped);
                fprintf(stderr, "Expect result [%s]\n",
                        escapeStrings[i].escaped);
                fprintf(stderr, "Actual result [(null)]\n");
            }
            return -1;
        }
        if (STRNEQ(escapeStrings[i].escaped, escaped)) {
            virtTestDifference(stderr, escapeStrings[i].escaped, escaped);
            VIR_FREE(escaped);
            return -1;
        }
        VIR_FREE(escaped);
    }

    return 0;
}

static int testUnescapeArg(const void *data ATTRIBUTE_UNUSED)
{
    int i;
    char *unescaped = NULL;
    for (i = 0; i < ARRAY_CARDINALITY(escapeStrings); ++i) {
        unescaped = qemuMonitorUnescapeArg(escapeStrings[i].escaped);
        if (!unescaped) {
            if (virTestGetDebug() > 0) {
                fprintf(stderr, "\nEscaped string [%s]\n",
                        escapeStrings[i].escaped);
                fprintf(stderr, "Expect result [%s]\n",
                        escapeStrings[i].unescaped);
                fprintf(stderr, "Actual result [(null)]\n");
            }
            return -1;
        }
        if (STRNEQ(escapeStrings[i].unescaped, unescaped)) {
            virtTestDifference(stderr, escapeStrings[i].unescaped, unescaped);
            VIR_FREE(unescaped);
            return -1;
        }
        VIR_FREE(unescaped);
    }

    return 0;
}

static int
mymain(void)
{
    int result = 0;

# define DO_TEST(_name)                                                 \
    do {                                                                \
        if (virtTestRun("qemu monitor "#_name, 1, test##_name,          \
                        NULL) < 0) {                                    \
            result = -1;                                                \
        }                                                               \
    } while (0)

    DO_TEST(EscapeArg);
    DO_TEST(UnescapeArg);

    return result == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)

#else
# include "testutils.h"

int main(void)
{
    return EXIT_AM_SKIP;
}

#endif /* WITH_QEMU */
