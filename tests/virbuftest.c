#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "util.h"
#include "testutils.h"
#include "buf.h"
#include "memory.h"

#define TEST_ERROR(...)                             \
    do {                                            \
        if (virTestGetDebug())                      \
            fprintf(stderr, __VA_ARGS__);           \
    } while (0)

struct testInfo {
    int doEscape;
};

static int testBufInfiniteLoop(const void *data)
{
    virBuffer bufinit = VIR_BUFFER_INITIALIZER;
    virBufferPtr buf = &bufinit;
    char *addstr = NULL, *bufret = NULL;
    int ret = -1;
    const struct testInfo *info = data;

    virBufferAddChar(buf, 'a');

    /*
     * Infinite loop used to trigger if:
     * (strlen + 1 > 1000) && (strlen == buf-size - buf-use - 1)
     * which was the case after the above addchar at the time of the bug.
     * This test is a bit fragile, since it relies on virBuffer internals.
     */
    if (virAsprintf(&addstr, "%*s", buf->a - buf->b - 1, "a") < 0) {
        goto out;
    }

    if (info->doEscape)
        virBufferEscapeString(buf, "%s", addstr);
    else
        virBufferAsprintf(buf, "%s", addstr);

    ret = 0;
out:
    bufret = virBufferContentAndReset(buf);
    if (!bufret) {
        TEST_ERROR("Buffer had error set");
        ret = -1;
    }

    VIR_FREE(addstr);
    VIR_FREE(bufret);
    return ret;
}

static int testBufAutoIndent(const void *data ATTRIBUTE_UNUSED)
{
    virBuffer bufinit = VIR_BUFFER_INITIALIZER;
    virBufferPtr buf = &bufinit;
    const char expected[] =
        "  1\n  2\n  3\n  4\n  5\n  6\n  7\n  &amp;\n  8\n  9\n  10\n  ' 11'\n";
    char *result = NULL;
    int ret = 0;

    if (virBufferGetIndent(buf, false) != 0 ||
        virBufferGetIndent(buf, true) != 0) {
        TEST_ERROR("Wrong indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, 3);
    if (STRNEQ(virBufferCurrentContent(buf), "")) {
        TEST_ERROR("Wrong content");
        ret = -1;
    }
    if (virBufferGetIndent(buf, false) != 3 ||
        virBufferGetIndent(buf, true) != 3 ||
        virBufferError(buf)) {
        TEST_ERROR("Wrong indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, -2);
    if (virBufferGetIndent(buf, false) != 1 ||
        virBufferGetIndent(buf, true) != 1 ||
        virBufferError(buf)) {
        TEST_ERROR("Wrong indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, -3);
    if (virBufferGetIndent(buf, false) != -1 ||
        virBufferGetIndent(buf, true) != -1 ||
        virBufferError(buf) != -1) {
        TEST_ERROR("Usage error not flagged");
        ret = -1;
    }
    virBufferFreeAndReset(buf);
    if (virBufferGetIndent(buf, false) != 0 ||
        virBufferGetIndent(buf, true) != 0 ||
        virBufferError(buf)) {
        TEST_ERROR("Reset didn't clear indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, 2);
    virBufferAddLit(buf, "1");
    if (STRNEQ(virBufferCurrentContent(buf), "  1")) {
        TEST_ERROR("Wrong content");
        ret = -1;
    }
    if (virBufferGetIndent(buf, false) != 2 ||
        virBufferGetIndent(buf, true) != 0) {
        TEST_ERROR("Wrong indentation");
        ret = -1;
    }
    virBufferAddLit(buf, "\n");
    virBufferAdd(buf, "" "2\n", -1); /* Extra "" appeases syntax-check */
    virBufferAddChar(buf, '3');
    virBufferAddChar(buf, '\n');
    virBufferAsprintf(buf, "%d", 4);
    virBufferAsprintf(buf, "%c", '\n');
    virBufferStrcat(buf, "5", "\n", "6\n", NULL);
    virBufferEscapeString(buf, "%s\n", "7");
    virBufferEscapeString(buf, "%s\n", "&");
    virBufferEscapeSexpr(buf, "%s", "8\n");
    virBufferURIEncodeString(buf, "9");
    virBufferAddChar(buf, '\n');
    virBufferEscapeShell(buf, "10");
    virBufferAddChar(buf, '\n');
    virBufferEscapeShell(buf, " 11");
    virBufferAddChar(buf, '\n');

    result = virBufferContentAndReset(buf);
    if (!result || STRNEQ(result, expected)) {
        virtTestDifference(stderr, expected, result);
        ret = -1;
    }
    VIR_FREE(result);
    return ret;
}

static int testBufTrim(const void *data ATTRIBUTE_UNUSED)
{
    virBuffer bufinit = VIR_BUFFER_INITIALIZER;
    virBufferPtr buf = NULL;
    char *result = NULL;
    const char *expected = "a,b";
    int ret = -1;
    int i = 1;

#define ACT(str, len, result) \
    do {                                          \
        if (virBufferTrim(buf, str, len) != result) {   \
            TEST_ERROR("trim %d failed", i);            \
            goto cleanup;                               \
        }                                               \
        i++;                                            \
    } while (0);

    if (virBufferTrim(buf, "", 0) != -1) {
        TEST_ERROR("Wrong failure detection 1");
        goto cleanup;
    }
    buf = &bufinit;
    if (virBufferTrim(buf, NULL, -1) != -1) {
        TEST_ERROR("Wrong failure detection 2");
        goto cleanup;
    }

    virBufferAddLit(buf, "a;");
    ACT("", 0, 1);
    ACT("", -1, 1);
    ACT(NULL, 1, 1);
    ACT(NULL, 5, 0);
    ACT("a", 2, 0);

    virBufferAddLit(buf, ",b,,");
    ACT("b", -1, 0);
    ACT("b,,", 1, 1);
    ACT(",", -1, 1);

    result = virBufferContentAndReset(buf);
    if (!result || STRNEQ(result, expected)) {
        virtTestDifference(stderr, expected, result);
        goto cleanup;
    }

    ret = 0;

cleanup:
    virBufferFreeAndReset(buf);
    VIR_FREE(result);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;


#define DO_TEST(msg, cb, data)                                         \
    do {                                                               \
        struct testInfo info = { data };                               \
        if (virtTestRun("Buf: " msg, 1, cb, &info) < 0)                 \
            ret = -1;                                                  \
    } while (0)

    DO_TEST("EscapeString infinite loop", testBufInfiniteLoop, 1);
    DO_TEST("VSprintf infinite loop", testBufInfiniteLoop, 0);
    DO_TEST("Auto-indentation", testBufAutoIndent, 0);
    DO_TEST("Trim", testBufTrim, 0);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
