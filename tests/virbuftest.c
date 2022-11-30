#include <config.h>


#include "internal.h"
#include "testutils.h"
#include "virbuffer.h"

#define VIR_FROM_THIS VIR_FROM_NONE

struct testBufAddStrData {
    const char *data;
    const char *expect;
    const char *arg;
};

static int testBufAutoIndent(const void *data G_GNUC_UNUSED)
{
    g_auto(virBuffer) bufinit = VIR_BUFFER_INITIALIZER;
    virBuffer *buf = &bufinit;
    const char expected[] =
        "  1\n  2\n  3\n  4\n  5\n  6\n  7\n  &amp;\n  8\n  9\n  10\n"
        "  ' 11'\n  ''\\''12'\n  '\"13'\n  ''\n";
    g_autofree char *result = NULL;
    int ret = 0;

    if (virBufferGetIndent(buf) != 0 ||
        virBufferGetEffectiveIndent(buf) != 0) {
        VIR_TEST_DEBUG("Wrong indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, 3);
    if (STRNEQ(virBufferCurrentContent(buf), "")) {
        VIR_TEST_DEBUG("Wrong content");
        ret = -1;
    }
    if (virBufferGetIndent(buf) != 3 ||
        virBufferGetEffectiveIndent(buf) != 3) {
        VIR_TEST_DEBUG("Wrong indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, -2);
    if (virBufferGetIndent(buf) != 1 ||
        virBufferGetEffectiveIndent(buf) != 1) {
        VIR_TEST_DEBUG("Wrong indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, -3);
    if (virBufferGetIndent(buf) != 0 ||
        virBufferGetEffectiveIndent(buf) != 0) {
        VIR_TEST_DEBUG("Indentation level not truncated");
        ret = -1;
    }
    virBufferAdjustIndent(buf, 3);
    virBufferFreeAndReset(buf);
    if (virBufferGetIndent(buf) != 0 ||
        virBufferGetEffectiveIndent(buf) != 0) {
        VIR_TEST_DEBUG("Reset didn't clear indentation");
        ret = -1;
    }
    virBufferAdjustIndent(buf, 2);
    virBufferAddLit(buf, "1");
    if (STRNEQ(virBufferCurrentContent(buf), "  1")) {
        VIR_TEST_DEBUG("Wrong content");
        ret = -1;
    }
    if (virBufferGetIndent(buf) != 2 ||
        virBufferGetEffectiveIndent(buf) != 0) {
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
    virBufferEscapeShell(buf, "'12");
    virBufferAddChar(buf, '\n');
    virBufferEscapeShell(buf, "\"13");
    virBufferAddChar(buf, '\n');
    virBufferEscapeShell(buf, "");
    virBufferAddChar(buf, '\n');

    result = virBufferContentAndReset(buf);
    if (virTestCompareToString(expected, result) < 0) {
        ret = -1;
    }
    return ret;
}

static int testBufTrim(const void *data G_GNUC_UNUSED)
{
    g_auto(virBuffer) bufinit = VIR_BUFFER_INITIALIZER;
    virBuffer *buf = NULL;
    g_autofree char *result = NULL;
    const char *expected = "a,b";

    virBufferTrim(buf, "");
    buf = &bufinit;

    virBufferAddLit(buf, "a;");
    virBufferTrim(buf, "");
    virBufferTrim(buf, "");
    virBufferTrimLen(buf, 1);
    virBufferTrimLen(buf, 5);
    virBufferTrimLen(buf, 2);

    virBufferAddLit(buf, ",b,,");
    virBufferTrim(buf, NULL);
    virBufferTrim(buf, "b");
    virBufferTrim(buf, ",,");

    result = virBufferContentAndReset(buf);
    if (virTestCompareToString(expected, result) < 0) {
        return -1;
    }

    return 0;
}

static int
testBufTrimChars(const void *opaque)
{
    const struct testBufAddStrData *data = opaque;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *actual = NULL;

    virBufferAddStr(&buf, data->data);
    virBufferTrimChars(&buf, data->arg);

    if (!(actual = virBufferContentAndReset(&buf))) {
        VIR_TEST_DEBUG("buf is empty");
        return -1;
    }

    if (virTestCompareToString(data->expect, actual) < 0) {
        return -1;
    }

    return 0;
}

static int testBufAddBuffer(const void *data G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf1 = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) buf2 = VIR_BUFFER_INITIALIZER;
    g_auto(virBuffer) buf3 = VIR_BUFFER_INITIALIZER;
    g_autofree char *result = NULL;
    const char *expected = \
"  A long time ago, in a galaxy far,\n" \
"  far away...\n" \
"    It is a period of civil war.\n" \
"    Rebel spaceships, striking\n" \
"    from a hidden base, have won\n" \
"    their first victory against\n" \
"    the evil Galactic Empire.\n" \
"  During the battle, rebel\n" \
"  spies managed to steal secret\n" \
"  plans to the Empire's\n" \
"  ultimate weapon, the DEATH\n" \
"  STAR, an armored space\n" \
"  station with enough power to\n" \
"  destroy an entire planet.\n";

    if (virBufferUse(&buf1)) {
        VIR_TEST_DEBUG("buf1 already in use");
        return -1;
    }

    if (virBufferUse(&buf2)) {
        VIR_TEST_DEBUG("buf2 already in use");
        return -1;
    }

    if (virBufferUse(&buf3)) {
        VIR_TEST_DEBUG("buf3 already in use");
        return -1;
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
        return -1;
    }

    if (!virBufferUse(&buf2)) {
        VIR_TEST_DEBUG("Error adding to buf2");
        return -1;
    }

    if (!virBufferUse(&buf3)) {
        VIR_TEST_DEBUG("Error adding to buf3");
        return -1;
    }

    virBufferAddBuffer(&buf2, &buf3);

    if (!virBufferUse(&buf2)) {
        VIR_TEST_DEBUG("buf2 cleared mistakenly");
        return -1;
    }

    if (virBufferUse(&buf3)) {
        VIR_TEST_DEBUG("buf3 is not clear even though it should be");
        return -1;
    }

    virBufferAddBuffer(&buf1, &buf2);

    if (!virBufferUse(&buf1)) {
        VIR_TEST_DEBUG("buf1 cleared mistakenly");
        return -1;
    }

    if (virBufferUse(&buf2)) {
        VIR_TEST_DEBUG("buf2 is not clear even though it should be");
        return -1;
    }

    result = virBufferContentAndReset(&buf1);
    if (virTestCompareToString(expected, result) < 0) {
        return -1;
    }

    return 0;
}

static int
testBufAddStr(const void *opaque)
{
    const struct testBufAddStrData *data = opaque;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *actual = NULL;

    virBufferAddLit(&buf, "<c>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferAddStr(&buf, data->data);
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</c>");

    if (!(actual = virBufferContentAndReset(&buf))) {
        VIR_TEST_DEBUG("buf is empty");
        return -1;
    }

    if (virTestCompareToString(data->expect, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testBufEscapeStr(const void *opaque)
{
    const struct testBufAddStrData *data = opaque;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *actual = NULL;

    virBufferAddLit(&buf, "<c>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<el>%s</el>\n", data->data);
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</c>");

    if (!(actual = virBufferContentAndReset(&buf))) {
        VIR_TEST_DEBUG("buf is empty");
        return -1;
    }

    if (virTestCompareToString(data->expect, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testBufEscapeRegex(const void *opaque)
{
    const struct testBufAddStrData *data = opaque;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *actual = NULL;

    virBufferEscapeRegex(&buf, "%s", data->data);

    if (!(actual = virBufferContentAndReset(&buf))) {
        VIR_TEST_DEBUG("testBufEscapeRegex: buf is empty");
        return -1;
    }

    if (virTestCompareToString(data->expect, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testBufSetIndent(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *actual = NULL;

    virBufferSetIndent(&buf, 11);
    virBufferAddLit(&buf, "test\n");
    virBufferSetIndent(&buf, 2);
    virBufferAddLit(&buf, "test2\n");

    if (!(actual = virBufferContentAndReset(&buf)))
        return -1;

    if (STRNEQ(actual, "           test\n  test2\n")) {
        VIR_TEST_DEBUG("testBufSetIndent: expected indent not set");
        return -1;
    }

    return 0;
}


/* Result of this shows up only in valgrind or similar */
static int
testBufferAutoclean(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "test test test\n");
    return 0;
}


static int
mymain(void)
{
    int ret = 0;


#define DO_TEST(msg, cb) \
    do { \
        if (virTestRun("Buf: " msg, cb, NULL) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST("Auto-indentation", testBufAutoIndent);
    DO_TEST("Trim", testBufTrim);
    DO_TEST("AddBuffer", testBufAddBuffer);
    DO_TEST("set indent", testBufSetIndent);
    DO_TEST("autoclean", testBufferAutoclean);

#define DO_TEST_ADD_STR(_data, _expect) \
    do { \
        struct testBufAddStrData info = { .data = _data, .expect = _expect }; \
        if (virTestRun("Buf: AddStr", testBufAddStr, &info) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_ADD_STR("", "<c>\n</c>");
    DO_TEST_ADD_STR("<a/>", "<c>\n  <a/></c>");
    DO_TEST_ADD_STR("<a/>\n", "<c>\n  <a/>\n</c>");
    DO_TEST_ADD_STR("<b>\n  <a/>\n</b>\n", "<c>\n  <b>\n    <a/>\n  </b>\n</c>");

#define DO_TEST_ESCAPE(_data, _expect) \
    do { \
        struct testBufAddStrData info = { .data = _data, .expect = _expect }; \
        if (virTestRun("Buf: EscapeStr", testBufEscapeStr, &info) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_ESCAPE("<td></td><td></td>",
                   "<c>\n  <el>&lt;td&gt;&lt;/td&gt;&lt;td&gt;&lt;/td&gt;</el>\n</c>");
    DO_TEST_ESCAPE("\007\"&&\"\x15",
                   "<c>\n  <el>&quot;&amp;&amp;&quot;</el>\n</c>");
    DO_TEST_ESCAPE(",,'..',,",
                   "<c>\n  <el>,,&apos;..&apos;,,</el>\n</c>");
    DO_TEST_ESCAPE("\x01\x01\x02\x03\x05\x08",
                   "<c>\n  <el></el>\n</c>");

#define DO_TEST_ESCAPE_REGEX(_data, _expect) \
    do { \
        struct testBufAddStrData info = { .data = _data, .expect = _expect }; \
        if (virTestRun("Buf: EscapeRegex", testBufEscapeRegex, &info) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_ESCAPE_REGEX("noescape", "noescape");
    DO_TEST_ESCAPE_REGEX("^$.|?*+()[]{}\\",
                         "\\^\\$\\.\\|\\?\\*\\+\\(\\)\\[\\]\\{\\}\\\\");

#define DO_TEST_TRIM_CHARS(_data, _arg, _expect) \
    do { \
        struct testBufAddStrData info = { .data = _data, .expect = _expect, .arg = _arg }; \
        if (virTestRun("Buf: Trim: " #_data, testBufTrimChars, &info) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_TRIM_CHARS("Trimmm", "m", "Tri");
    DO_TEST_TRIM_CHARS("-abcd-efgh--", "-", "-abcd-efgh");
    DO_TEST_TRIM_CHARS("-hABC-efgh--", "-h", "-hABC-efg");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
