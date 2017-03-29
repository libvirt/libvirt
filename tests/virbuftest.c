#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "testutils.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

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
    if (virAsprintf(&addstr, "%*s", buf->a - buf->b - 1, "a") < 0)
        goto out;

    if (info->doEscape)
        virBufferEscapeString(buf, "%s", addstr);
    else
        virBufferAsprintf(buf, "%s", addstr);

    ret = 0;
 out:
    bufret = virBufferContentAndReset(buf);
    if (!bufret) {
        VIR_TEST_DEBUG("Buffer had error set");
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
        VIR_TEST_DEBUG("Wrong indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, 3);
    if (STRNEQ(virBufferCurrentContent(buf), "")) {
        VIR_TEST_DEBUG("Wrong content");
        ret = -1;
    }
    if (virBufferGetIndent(buf, false) != 3 ||
        virBufferGetIndent(buf, true) != 3 ||
        virBufferError(buf)) {
        VIR_TEST_DEBUG("Wrong indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, -2);
    if (virBufferGetIndent(buf, false) != 1 ||
        virBufferGetIndent(buf, true) != 1 ||
        virBufferError(buf)) {
        VIR_TEST_DEBUG("Wrong indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, -3);
    if (virBufferGetIndent(buf, false) != -1 ||
        virBufferGetIndent(buf, true) != -1 ||
        virBufferError(buf) != -1) {
        VIR_TEST_DEBUG("Usage error not flagged");
        ret = -1;
    }
    virBufferFreeAndReset(buf);
    if (virBufferGetIndent(buf, false) != 0 ||
        virBufferGetIndent(buf, true) != 0 ||
        virBufferError(buf)) {
        VIR_TEST_DEBUG("Reset didn't clear indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, 2);
    virBufferAddLit(buf, "1");
    if (virBufferError(buf)) {
        VIR_TEST_DEBUG("Buffer had error");
        return -1;
    }
    if (STRNEQ(virBufferCurrentContent(buf), "  1")) {
        VIR_TEST_DEBUG("Wrong content");
        ret = -1;
    }
    if (virBufferGetIndent(buf, false) != 2 ||
        virBufferGetIndent(buf, true) != 0) {
        VIR_TEST_DEBUG("Wrong indentation");
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

    if (virBufferError(buf)) {
        VIR_TEST_DEBUG("Buffer had error");
        return -1;
    }

    result = virBufferContentAndReset(buf);
    if (!result || STRNEQ(result, expected)) {
        virTestDifference(stderr, expected, result);
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

    virBufferTrim(buf, "", 0);
    buf = &bufinit;

    virBufferAddLit(buf, "a;");
    virBufferTrim(buf, "", 0);
    virBufferTrim(buf, "", -1);
    virBufferTrim(buf, NULL, 1);
    virBufferTrim(buf, NULL, 5);
    virBufferTrim(buf, "a", 2);

    virBufferAddLit(buf, ",b,,");
    virBufferTrim(buf, "b", -1);
    virBufferTrim(buf, "b,,", 1);
    virBufferTrim(buf, ",", -1);

    if (virBufferError(buf)) {
        VIR_TEST_DEBUG("Buffer had error");
        return -1;
    }

    result = virBufferContentAndReset(buf);
    if (!result || STRNEQ(result, expected)) {
        virTestDifference(stderr, expected, result);
        goto cleanup;
    }

    virBufferTrim(buf, NULL, -1);
    if (virBufferError(buf) != -1) {
        VIR_TEST_DEBUG("Usage error not flagged");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virBufferFreeAndReset(buf);
    VIR_FREE(result);
    return ret;
}

static int testBufAddBuffer(const void *data ATTRIBUTE_UNUSED)
{
    virBuffer buf1 = VIR_BUFFER_INITIALIZER;
    virBuffer buf2 = VIR_BUFFER_INITIALIZER;
    virBuffer buf3 = VIR_BUFFER_INITIALIZER;
    int ret = -1;
    char *result = NULL;
    const char *expected = \
"  A long time ago, in a galaxy far,\n" \
"  far away...\n"                       \
"    It is a period of civil war.\n"    \
"    Rebel spaceships, striking\n"      \
"    from a hidden base, have won\n"    \
"    their first victory against\n"     \
"    the evil Galactic Empire.\n"       \
"  During the battle, rebel\n"          \
"  spies managed to steal secret\n"     \
"  plans to the Empire's\n"             \
"  ultimate weapon, the DEATH\n"        \
"  STAR, an armored space\n"            \
"  station with enough power to\n"      \
"  destroy an entire planet.\n";

    if (virBufferUse(&buf1)) {
        VIR_TEST_DEBUG("buf1 already in use");
        goto cleanup;
    }

    if (virBufferUse(&buf2)) {
        VIR_TEST_DEBUG("buf2 already in use");
        goto cleanup;
    }

    if (virBufferUse(&buf3)) {
        VIR_TEST_DEBUG("buf3 already in use");
        goto cleanup;
    }

    virBufferAdjustIndent(&buf1, 2);
    virBufferAddLit(&buf1, "A long time ago, in a galaxy far,\n");
    virBufferAddLit(&buf1, "far away...\n");

    virBufferAdjustIndent(&buf2, 4);
    virBufferAddLit(&buf2, "It is a period of civil war.\n");
    virBufferAddLit(&buf2, "Rebel spaceships, striking\n");
    virBufferAddLit(&buf2, "from a hidden base, have won\n");
    virBufferAddLit(&buf2, "their first victory against\n");
    virBufferAddLit(&buf2, "the evil Galactic Empire.\n");

    virBufferAdjustIndent(&buf3, 2);
    virBufferAddLit(&buf3, "During the battle, rebel\n");
    virBufferAddLit(&buf3, "spies managed to steal secret\n");
    virBufferAddLit(&buf3, "plans to the Empire's\n");
    virBufferAddLit(&buf3, "ultimate weapon, the DEATH\n");
    virBufferAddLit(&buf3, "STAR, an armored space\n");
    virBufferAddLit(&buf3, "station with enough power to\n");
    virBufferAddLit(&buf3, "destroy an entire planet.\n");

    if (!virBufferUse(&buf1)) {
        VIR_TEST_DEBUG("Error adding to buf1");
        goto cleanup;
    }

    if (!virBufferUse(&buf2)) {
        VIR_TEST_DEBUG("Error adding to buf2");
        goto cleanup;
    }

    if (!virBufferUse(&buf3)) {
        VIR_TEST_DEBUG("Error adding to buf3");
        goto cleanup;
    }

    virBufferAddBuffer(&buf2, &buf3);

    if (!virBufferUse(&buf2)) {
        VIR_TEST_DEBUG("buf2 cleared mistakenly");
        goto cleanup;
    }

    if (virBufferUse(&buf3)) {
        VIR_TEST_DEBUG("buf3 is not clear even though it should be");
        goto cleanup;
    }

    virBufferAddBuffer(&buf1, &buf2);

    if (!virBufferUse(&buf1)) {
        VIR_TEST_DEBUG("buf1 cleared mistakenly");
        goto cleanup;
    }

    if (virBufferUse(&buf2)) {
        VIR_TEST_DEBUG("buf2 is not clear even though it should be");
        goto cleanup;
    }

    result = virBufferContentAndReset(&buf1);
    if (STRNEQ_NULLABLE(result, expected)) {
        virTestDifference(stderr, expected, result);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&buf1);
    virBufferFreeAndReset(&buf2);
    VIR_FREE(result);
    return ret;
}

struct testBufAddStrData {
    const char *data;
    const char *expect;
};

static int
testBufAddStr(const void *opaque ATTRIBUTE_UNUSED)
{
    const struct testBufAddStrData *data = opaque;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *actual;
    int ret = -1;

    virBufferAddLit(&buf, "<c>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferAddStr(&buf, data->data);
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</c>");

    if (!(actual = virBufferContentAndReset(&buf))) {
        VIR_TEST_DEBUG("buf is empty");
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(actual, data->expect)) {
        VIR_TEST_DEBUG("testBufAddStr(): Strings don't match:\n");
        virTestDifference(stderr, data->expect, actual);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(actual);
    return ret;
}


static int
testBufEscapeStr(const void *opaque ATTRIBUTE_UNUSED)
{
    const struct testBufAddStrData *data = opaque;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *actual;
    int ret = -1;

    virBufferAddLit(&buf, "<c>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<el>%s</el>\n", data->data);
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</c>");

    if (!(actual = virBufferContentAndReset(&buf))) {
        VIR_TEST_DEBUG("buf is empty");
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(actual, data->expect)) {
        VIR_TEST_DEBUG("testBufEscapeStr(): Strings don't match:\n");
        virTestDifference(stderr, data->expect, actual);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(actual);
    return ret;
}


static int
testBufEscapeN(const void *opaque)
{
    const struct testBufAddStrData *data = opaque;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *actual;
    int ret = -1;

    virBufferEscapeN(&buf, "%s", data->data, '\\', "=", ',', ",", NULL);

    if (!(actual = virBufferContentAndReset(&buf))) {
        VIR_TEST_DEBUG("testBufEscapeN: buf is empty");
        goto cleanup;
    }

    if (STRNEQ_NULLABLE(actual, data->expect)) {
        VIR_TEST_DEBUG("testBufEscapeN: Strings don't match:\n");
        virTestDifference(stderr, data->expect, actual);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(actual);
    return ret;
}


static int
testBufSetIndent(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *actual;
    int ret = -1;

    virBufferSetIndent(&buf, 11);
    virBufferAddLit(&buf, "test\n");
    virBufferSetIndent(&buf, 2);
    virBufferAddLit(&buf, "test2\n");

    if (!(actual = virBufferContentAndReset(&buf)))
        goto cleanup;

    if (STRNEQ(actual, "           test\n  test2\n")) {
        VIR_TEST_DEBUG("testBufSetIndent: expected indent not set\n");
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(actual);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;


#define DO_TEST(msg, cb, data)                                         \
    do {                                                               \
        struct testInfo info = { data };                               \
        if (virTestRun("Buf: " msg, cb, &info) < 0)                    \
            ret = -1;                                                  \
    } while (0)

    DO_TEST("EscapeString infinite loop", testBufInfiniteLoop, 1);
    DO_TEST("VSprintf infinite loop", testBufInfiniteLoop, 0);
    DO_TEST("Auto-indentation", testBufAutoIndent, 0);
    DO_TEST("Trim", testBufTrim, 0);
    DO_TEST("AddBuffer", testBufAddBuffer, 0);
    DO_TEST("set indent", testBufSetIndent, 0);

#define DO_TEST_ADD_STR(DATA, EXPECT)                                  \
    do {                                                               \
        struct testBufAddStrData info = { DATA, EXPECT };              \
        if (virTestRun("Buf: AddStr", testBufAddStr, &info) < 0)       \
            ret = -1;                                                  \
    } while (0)

    DO_TEST_ADD_STR("", "<c>\n</c>");
    DO_TEST_ADD_STR("<a/>", "<c>\n  <a/></c>");
    DO_TEST_ADD_STR("<a/>\n", "<c>\n  <a/>\n</c>");
    DO_TEST_ADD_STR("<b>\n  <a/>\n</b>\n", "<c>\n  <b>\n    <a/>\n  </b>\n</c>");

#define DO_TEST_ESCAPE(data, expect)                                   \
    do {                                                               \
        struct testBufAddStrData info = { data, expect };              \
        if (virTestRun("Buf: EscapeStr", testBufEscapeStr, &info) < 0) \
            ret = -1;                                                  \
    } while (0)

    DO_TEST_ESCAPE("<td></td><td></td>",
                   "<c>\n  <el>&lt;td&gt;&lt;/td&gt;&lt;td&gt;&lt;/td&gt;</el>\n</c>");
    DO_TEST_ESCAPE("\007\"&&\"\x15",
                   "<c>\n  <el>&quot;&amp;&amp;&quot;</el>\n</c>");
    DO_TEST_ESCAPE(",,'..',,",
                   "<c>\n  <el>,,&apos;..&apos;,,</el>\n</c>");
    DO_TEST_ESCAPE("\x01\x01\x02\x03\x05\x08",
                   "<c>\n  <el></el>\n</c>");

#define DO_TEST_ESCAPEN(data, expect)                                   \
    do {                                                                \
        struct testBufAddStrData info = { data, expect };               \
        if (virTestRun("Buf: EscapeN", testBufEscapeN, &info) < 0)      \
            ret = -1;                                                   \
    } while (0)

    DO_TEST_ESCAPEN("noescape", "noescape");
    DO_TEST_ESCAPEN("comma,escape", "comma,,escape");
    DO_TEST_ESCAPEN("equal=escape", "equal\\=escape");
    DO_TEST_ESCAPEN("comma,equal=escape", "comma,,equal\\=escape");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
