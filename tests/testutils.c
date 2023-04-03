/*
 * testutils.c: basic test utils
 *
 * Copyright (C) 2005-2015 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <stdarg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "testutils.h"
#include "internal.h"
#include "viralloc.h"
#include "virerror.h"
#include "virbuffer.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.testutils");

#include "virbitmap.h"
#include "virfile.h"

static unsigned int testDebug = -1;
static unsigned int testVerbose = -1;
static unsigned int testExpensive = -1;
static unsigned int testRegenerate = -1;


static size_t testCounter;
static virBitmap *testBitmap;
static virBitmap *failedTests;

static virArch virTestHostArch = VIR_ARCH_X86_64;

virArch
virArchFromHost(void)
{
    return virTestHostArch;
}

void
virTestSetHostArch(virArch arch)
{
    virTestHostArch = arch;
}

static int virTestUseTerminalColors(void)
{
    return isatty(STDOUT_FILENO);
}

static unsigned int
virTestGetFlag(const char *name)
{
    char *flagStr;
    unsigned int flag;

    if ((flagStr = getenv(name)) == NULL)
        return 0;

    if (virStrToLong_ui(flagStr, NULL, 10, &flag) < 0)
        return 0;

    return flag;
}


/**
 * virTestPropagateLibvirtError:
 *
 * In cases when a libvirt utility function which reports libvirt errors is
 * used in the test suite outside of the virTestRun call and the failure of such
 * a function would cause an test failure the error message reported by that
 * function will not be propagated to the user as the error callback is not
 * invoked.
 *
 * In cases when the error message may be beneficial in debugging this helper
 * provides means to dispatch the errors including invocation of the error
 * callback.
 */
void
virTestPropagateLibvirtError(void)
{
    if (virGetLastErrorCode() == VIR_ERR_OK)
        return;

    if (virTestGetVerbose() || virTestGetDebug())
        virDispatchError(NULL);
}


/*
 * Runs test
 *
 * returns: -1 = error, 0 = success
 */
int
virTestRun(const char *title,
           int (*body)(const void *data), const void *data)
{
    int ret = 0;

    /* Some test are fragile about environ settings.  If that's
     * the case, don't poison it. */
    if (getenv("VIR_TEST_MOCK_PROGNAME"))
        g_setenv("VIR_TEST_MOCK_TESTNAME", title, TRUE);

    if (testCounter == 0 && !virTestGetVerbose())
        fprintf(stderr, "      ");

    testCounter++;


    /* Skip tests if out of range */
    if (testBitmap && !virBitmapIsBitSet(testBitmap, testCounter))
        return 0;

    if (virTestGetVerbose())
        fprintf(stderr, "%2zu) %-65s ... ", testCounter, title);

    virResetLastError();
    ret = body(data);
    virTestPropagateLibvirtError();

    if (virTestGetVerbose()) {
        if (ret == 0)
            if (virTestUseTerminalColors())
                fprintf(stderr, "\e[32mOK\e[0m\n");  /* green */
            else
                fprintf(stderr, "OK\n");
        else if (ret == EXIT_AM_SKIP)
            if (virTestUseTerminalColors())
                fprintf(stderr, "\e[34m\e[1mSKIP\e[0m\n");  /* bold blue */
            else
                fprintf(stderr, "SKIP\n");
        else
            if (virTestUseTerminalColors())
                fprintf(stderr, "\e[31m\e[1mFAILED\e[0m\n");  /* bold red */
            else
                fprintf(stderr, "FAILED\n");
    } else {
        if (testCounter != 1 &&
            !((testCounter-1) % 40)) {
            fprintf(stderr, " %-3zu\n", (testCounter-1));
            fprintf(stderr, "      ");
        }
        if (ret == 0)
                fprintf(stderr, ".");
        else if (ret == EXIT_AM_SKIP)
            fprintf(stderr, "_");
        else
            fprintf(stderr, "!");
    }

    if (ret != 0 && ret != EXIT_AM_SKIP)
        virBitmapSetBitExpand(failedTests, testCounter);

    g_unsetenv("VIR_TEST_MOCK_TESTNAME");
    return ret;
}


/*
 * A wrapper for virTestRun that resets the log content before each run
 * and sets ret to -1 on failure. On success, ret is untouched.
 */
void
virTestRunLog(int *ret,
              const char *title,
              int (*body)(const void *data),
              const void *data)
{
    int rc;

    g_free(virTestLogContentAndReset());

    rc = virTestRun(title, body, data);

    if (rc >= 0)
        return;

    *ret = -1;

    if (virTestGetDebug()) {
        g_autofree char *log = virTestLogContentAndReset();

        if (strlen(log) > 0)
            VIR_TEST_DEBUG("\n%s", log);
    }
}


/**
 * virTestLoadFile:
 * @file: name of the file to load
 * @buf: buffer to load the file into
 *
 * Allocates @buf to the size of FILE. Reads FILE into buffer BUF.
 * Upon any failure, error is printed to stderr and -1 is returned. 'errno' is
 * not preserved. On success 0 is returned. Caller is responsible for freeing
 * @buf.
 */
int
virTestLoadFile(const char *file, char **buf)
{
    g_autoptr(FILE) fp = fopen(file, "r");
    struct stat st;
    char *tmp;
    int len, tmplen, buflen;

    if (!fp) {
        fprintf(stderr, "%s: failed to open: %s\n", file, g_strerror(errno));
        return -1;
    }

    if (fstat(fileno(fp), &st) < 0) {
        fprintf(stderr, "%s: failed to fstat: %s\n", file, g_strerror(errno));
        return -1;
    }

    tmplen = buflen = st.st_size + 1;

    *buf = g_new0(char, buflen);

    tmp = *buf;
    (*buf)[0] = '\0';
    if (st.st_size) {
        /* read the file line by line */
        while (fgets(tmp, tmplen, fp) != NULL) {
            len = strlen(tmp);
            /* stop on an empty line */
            if (len == 0)
                break;
            /* remove trailing backslash-newline pair */
            if (len >= 2 && tmp[len-2] == '\\' && tmp[len-1] == '\n') {
                len -= 2;
                tmp[len] = '\0';
            }
            /* advance the temporary buffer pointer */
            tmp += len;
            tmplen -= len;
        }
        if (ferror(fp)) {
            fprintf(stderr, "%s: read failed: %s\n", file, g_strerror(errno));
            VIR_FREE(*buf);
            return -1;
        }
    }

    return 0;
}


static char *
virTestLoadFileGetPath(const char *p,
                       va_list ap)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    char *path = NULL;

    virBufferAddLit(&buf, abs_srcdir "/");

    if (p) {
        virBufferAdd(&buf, p, -1);
        virBufferStrcatVArgs(&buf, ap);
    }

    if (!(path = virBufferContentAndReset(&buf)))
        VIR_TEST_VERBOSE("failed to format file path");

    return path;
}


/**
 * virTestLoadFilePath:
 * @...: file name components terminated with a NULL
 *
 * Constructs the test file path from variable arguments and loads the file.
 * 'abs_srcdir' is automatically prepended.
 */
char *
virTestLoadFilePath(const char *p, ...)
{
    g_autofree char *path = NULL;
    char *ret = NULL;
    va_list ap;

    va_start(ap, p);

    if (!(path = virTestLoadFileGetPath(p, ap)))
        goto cleanup;

    ignore_value(virTestLoadFile(path, &ret));

 cleanup:
    va_end(ap);

    return ret;
}


/**
 * virTestLoadFileJSON:
 * @...: name components terminated with a NULL
 *
 * Constructs the test file path from variable arguments and loads and parses
 * the JSON file. 'abs_srcdir' is automatically prepended to the path.
 */
virJSONValue *
virTestLoadFileJSON(const char *p, ...)
{
    virJSONValue *ret = NULL;
    g_autofree char *jsonstr = NULL;
    g_autofree char *path = NULL;
    va_list ap;

    va_start(ap, p);

    if (!(path = virTestLoadFileGetPath(p, ap)))
        goto cleanup;

    if (virFileReadAll(path, INT_MAX, &jsonstr) < 0)
        goto cleanup;

    if (!(ret = virJSONValueFromString(jsonstr)))
        VIR_TEST_VERBOSE("failed to parse json from file '%s'", path);

 cleanup:
    va_end(ap);
    return ret;
}


/**
 * @param stream: output stream to write differences to
 * @param expect: expected output text
 * @param expectName: name designator of the expected text
 * @param actual: actual output text
 * @param actualName: name designator of the actual text
 * @param regenerate: enable or disable regenerate functionality
 * @param rewrap: enable or disable rewrapping when regenerating
 *
 * Display expected and actual output text, trimmed to first and last
 * characters at which differences occur. Displays names of the text strings if
 * non-NULL.
 */
static int
virTestDifferenceFullInternal(FILE *stream,
                              const char *expect,
                              const char *expectName,
                              const char *actual,
                              const char *actualName,
                              bool regenerate)
{
    const char *expectStart;
    const char *expectEnd;
    const char *actualStart;
    const char *actualEnd;

    if (!expect)
        expect = "";
    if (!actual)
        actual = "";

    expectStart = expect;
    expectEnd = expect + (strlen(expect)-1);
    actualStart = actual;
    actualEnd = actual + (strlen(actual)-1);

    if (expectName && regenerate && (virTestGetRegenerate() > 0)) {
        if (virFileWriteStr(expectName, actual, 0666) < 0) {
            virDispatchError(NULL);
            return -1;
        }
    }

    if (!virTestGetDebug())
        return 0;

    if (virTestGetDebug() < 2) {
        /* Skip to first character where they differ */
        while (*expectStart && *actualStart &&
               *actualStart == *expectStart) {
            actualStart++;
            expectStart++;
        }

        /* Work backwards to last character where they differ */
        while (actualEnd > actualStart &&
               expectEnd > expectStart &&
               *actualEnd == *expectEnd) {
            actualEnd--;
            expectEnd--;
        }
    }

    /* Show the trimmed differences */
    if (expectName)
        fprintf(stream, "\nIn '%s':", expectName);
    fprintf(stream, "\nOffset %d\nExpect [", (int) (expectStart - expect));
    if ((expectEnd - expectStart + 1) &&
        fwrite(expectStart, (expectEnd-expectStart+1), 1, stream) != 1)
        return -1;
    fprintf(stream, "]\n");
    if (actualName)
        fprintf(stream, "In '%s':\n", actualName);
    fprintf(stream, "Actual [");
    if ((actualEnd - actualStart + 1) &&
        fwrite(actualStart, (actualEnd-actualStart+1), 1, stream) != 1)
        return -1;
    fprintf(stream, "]\n");

    /* Pad to line up with test name ... in virTestRun */
    fprintf(stream, "                                                                      ... ");

    return 0;
}

/**
 * @param stream: output stream to write differences to
 * @param expect: expected output text
 * @param expectName: name designator of the expected text
 * @param actual: actual output text
 * @param actualName: name designator of the actual text
 *
 * Display expected and actual output text, trimmed to first and last
 * characters at which differences occur. Displays names of the text strings if
 * non-NULL. If VIR_TEST_REGENERATE_OUTPUT is used, this function will
 * regenerate the expected file.
 */
int
virTestDifferenceFull(FILE *stream,
                      const char *expect,
                      const char *expectName,
                      const char *actual,
                      const char *actualName)
{
    return virTestDifferenceFullInternal(stream, expect, expectName,
                                         actual, actualName, true);
}

/**
 * @param stream: output stream to write differences to
 * @param expect: expected output text
 * @param expectName: name designator of the expected text
 * @param actual: actual output text
 * @param actualName: name designator of the actual text
 *
 * Display expected and actual output text, trimmed to first and last
 * characters at which differences occur. Displays names of the text strings if
 * non-NULL. If VIR_TEST_REGENERATE_OUTPUT is used, this function will not
 * regenerate the expected file.
 */
int
virTestDifferenceFullNoRegenerate(FILE *stream,
                                  const char *expect,
                                  const char *expectName,
                                  const char *actual,
                                  const char *actualName)
{
    return virTestDifferenceFullInternal(stream, expect, expectName,
                                         actual, actualName, false);
}

/**
 * @param stream: output stream to write differences to
 * @param expect: expected output text
 * @param actual: actual output text
 *
 * Display expected and actual output text, trimmed to
 * first and last characters at which differences occur
 */
int
virTestDifference(FILE *stream,
                  const char *expect,
                  const char *actual)
{
    return virTestDifferenceFullNoRegenerate(stream,
                                             expect, NULL,
                                             actual, NULL);
}


/**
 * @param stream: output stream to write differences to
 * @param expect: expected output text
 * @param actual: actual output text
 *
 * Display expected and actual output text, trimmed to
 * first and last characters at which differences occur
 */
int virTestDifferenceBin(FILE *stream,
                         const char *expect,
                         const char *actual,
                         size_t length)
{
    size_t start = 0, end = length;
    ssize_t i;

    if (!virTestGetDebug())
        return 0;

    if (virTestGetDebug() < 2) {
        /* Skip to first character where they differ */
        for (i = 0; i < length; i++) {
            if (expect[i] != actual[i]) {
                start = i;
                break;
            }
        }

        /* Work backwards to last character where they differ */
        for (i = (length -1); i >= 0; i--) {
            if (expect[i] != actual[i]) {
                end = i;
                break;
            }
        }
    }
    /* Round to nearest boundary of 4, except that last word can be short */
    start -= (start % 4);
    end += 4 - (end % 4);
    if (end >= length)
        end = length - 1;

    /* Show the trimmed differences */
    fprintf(stream, "\nExpect [ Region %d-%d", (int)start, (int)end);
    for (i = start; i < end; i++) {
        if ((i % 4) == 0)
            fprintf(stream, "\n    ");
        fprintf(stream, "0x%02x, ", ((int)expect[i])&0xff);
    }
    fprintf(stream, "]\n");
    fprintf(stream, "Actual [ Region %d-%d", (int)start, (int)end);
    for (i = start; i < end; i++) {
        if ((i % 4) == 0)
            fprintf(stream, "\n    ");
        fprintf(stream, "0x%02x, ", ((int)actual[i])&0xff);
    }
    fprintf(stream, "]\n");

    /* Pad to line up with test name ... in virTestRun */
    fprintf(stream, "                                                                      ... ");

    return 0;
}

/*
 * @param actual: String input content
 * @param filename: File to compare @actual against
 * @param unwrap: Remove '\\\n' sequences from file content before comparison
 *
 * If @actual is NULL, it's treated as an empty string.
 */
int
virTestCompareToFileFull(const char *actual,
                         const char *filename,
                         bool unwrap)
{
    g_autofree char *filecontent = NULL;
    g_autofree char *fixedcontent = NULL;
    const char *cmpcontent = actual;

    if (!cmpcontent)
        cmpcontent = "";

    if (unwrap) {
        if (virTestLoadFile(filename, &filecontent) < 0 && !virTestGetRegenerate())
            return -1;
    } else {
        if (virFileReadAll(filename, INT_MAX, &filecontent) < 0 && !virTestGetRegenerate())
            return -1;
    }

    if (filecontent) {
        size_t filecontentLen = strlen(filecontent);
        size_t cmpcontentLen = strlen(cmpcontent);

        if (filecontentLen > 0 &&
            filecontent[filecontentLen - 1] == '\n' &&
            (cmpcontentLen == 0 || cmpcontent[cmpcontentLen - 1] != '\n')) {
            fixedcontent = g_strdup_printf("%s\n", cmpcontent);
            cmpcontent = fixedcontent;
        }
    }

    if (STRNEQ_NULLABLE(cmpcontent, filecontent)) {
        virTestDifferenceFullInternal(stderr, filecontent, filename,
                                      cmpcontent, NULL, true);
        return -1;
    }

    return 0;
}


/*
 * @param actual: String input content
 * @param filename: File to compare @actual against
 *
 * If @actual is NULL, it's treated as an empty string.
 */
int
virTestCompareToFile(const char *actual,
                     const char *filename)
{
    return virTestCompareToFileFull(actual, filename, true);
}


int
virTestCompareToULL(unsigned long long expect,
                    unsigned long long actual)
{
    g_autofree char *expectStr = NULL;
    g_autofree char *actualStr = NULL;

    expectStr = g_strdup_printf("%llu", expect);

    actualStr = g_strdup_printf("%llu", actual);

    return virTestCompareToString(expectStr, actualStr);
}

int
virTestCompareToString(const char *expect,
                       const char *actual)
{
    if (STRNEQ_NULLABLE(expect, actual)) {
        virTestDifference(stderr, expect, actual);
        return -1;
    }

    return 0;
}

static void
virTestErrorFuncQuiet(void *data G_GNUC_UNUSED,
                      virErrorPtr err G_GNUC_UNUSED)
{ }


/* register an error handler in tests when using connections */
void
virTestQuiesceLibvirtErrors(bool always)
{
    if (always || !virTestGetVerbose())
        virSetErrorFunc(NULL, virTestErrorFuncQuiet);
}

struct virtTestLogData {
    virBuffer buf;
};

static struct virtTestLogData testLog = { VIR_BUFFER_INITIALIZER };

static void
virtTestLogOutput(virLogSource *source G_GNUC_UNUSED,
                  virLogPriority priority G_GNUC_UNUSED,
                  const char *filename G_GNUC_UNUSED,
                  int lineno G_GNUC_UNUSED,
                  const char *funcname G_GNUC_UNUSED,
                  const char *timestamp,
                  struct _virLogMetadata *metadata G_GNUC_UNUSED,
                  const char *rawstr G_GNUC_UNUSED,
                  const char *str,
                  void *data)
{
    struct virtTestLogData *log = data;
    virBufferAsprintf(&log->buf, "%s: %s", timestamp, str);
}

static void
virtTestLogClose(void *data)
{
    struct virtTestLogData *log = data;

    virBufferFreeAndReset(&log->buf);
}

/* Return a malloc'd string (possibly with strlen of 0) of all data
 * logged since the last call to this function, or NULL on failure.  */
char *
virTestLogContentAndReset(void)
{
    char *ret;

    ret = virBufferContentAndReset(&testLog.buf);
    if (!ret)
        ret = g_strdup("");
    return ret;
}


unsigned int
virTestGetDebug(void)
{
    if (testDebug == -1)
        testDebug = virTestGetFlag("VIR_TEST_DEBUG");
    return testDebug;
}

unsigned int
virTestGetVerbose(void)
{
    if (testVerbose == -1)
        testVerbose = virTestGetFlag("VIR_TEST_VERBOSE");
    return testVerbose || virTestGetDebug();
}

unsigned int
virTestGetExpensive(void)
{
    if (testExpensive == -1)
        testExpensive = virTestGetFlag("VIR_TEST_EXPENSIVE");
    return testExpensive;
}

unsigned int
virTestGetRegenerate(void)
{
    if (testRegenerate == -1)
        testRegenerate = virTestGetFlag("VIR_TEST_REGENERATE_OUTPUT");
    return testRegenerate;
}

static int
virTestSetEnvPath(void)
{
    const char *path = getenv("PATH");
    g_autofree char *new_path = NULL;

    if (path) {
        if (strstr(path, abs_builddir) != path)
            new_path = g_strdup_printf("%s:%s", abs_builddir, path);
    } else {
        new_path = g_strdup(abs_builddir);
    }

    if (new_path &&
        g_setenv("PATH", new_path, TRUE) == FALSE)
        return -1;

    return 0;
}

#define FAKEROOTDIRTEMPLATE abs_builddir "/fakerootdir-XXXXXX"

char*
virTestFakeRootDirInit(void)
{
    g_autofree char *fakerootdir = g_strdup(FAKEROOTDIRTEMPLATE);

    if (!g_mkdtemp(fakerootdir)) {
        fprintf(stderr, "Cannot create fakerootdir");
        return NULL;
    }

    g_setenv("LIBVIRT_FAKE_ROOT_DIR", fakerootdir, TRUE);

    return g_steal_pointer(&fakerootdir);
}

void
virTestFakeRootDirCleanup(char *fakerootdir)
{
    g_unsetenv("LIBVIRT_FAKE_ROOT_DIR");

    if (!g_getenv("LIBVIRT_SKIP_CLEANUP"))
        virFileDeleteTree(fakerootdir);
    else
        fprintf(stderr, "Test data ready for inspection: %s\n", fakerootdir);
}

int virTestMain(int argc,
                char **argv,
                int (*func)(void),
                ...)
{
    const char *lib;
    va_list ap;
    int ret;
    char *testRange = NULL;
    size_t noutputs = 0;
    virLogOutput *output = NULL;
    virLogOutput **outputs = NULL;
    g_autofree char *progname = NULL;
    g_autofree const char **preloads = NULL;
    size_t npreloads = 0;
    g_autofree char *mock = NULL;
    g_autofree char *fakerootdir = NULL;

    if (getenv("VIR_TEST_FILE_ACCESS")) {
        preloads = g_renew(const char *, preloads, npreloads + 2);
        preloads[npreloads++] = VIR_TEST_MOCK("virtest");
        preloads[npreloads] = NULL;
    }

    g_setenv("HOME", "/bad-test-used-env-home", TRUE);
    g_setenv("XDG_RUNTIME_DIR", "/bad-test-used-env-xdg-runtime-dir", TRUE);
    g_setenv("XDG_DATA_HOME", "/bad-test-used-env-xdg-data-home", TRUE);
    g_setenv("XDG_CACHE_HOME", "/bad-test-used-env-xdg-cache-home", TRUE);
    g_setenv("XDG_CONFIG_HOME", "/bad-test-used-env-xdg-config-home", TRUE);

    va_start(ap, func);
    while ((lib = va_arg(ap, const char *))) {
        if (!virFileIsExecutable(lib)) {
            perror(lib);
            va_end(ap);
            return EXIT_FAILURE;
        }

        preloads = g_renew(const char *, preloads, npreloads + 2);
        preloads[npreloads++] = lib;
        preloads[npreloads] = NULL;
    }
    va_end(ap);

    if (preloads) {
        mock = g_strjoinv(":", (char **)preloads);
        VIR_TEST_PRELOAD(mock);
    }

    progname = g_path_get_basename(argv[0]);

    g_setenv("VIR_TEST_MOCK_PROGNAME", progname, TRUE);

    virFileActivateDirOverrideForProg(argv[0]);

    if (virTestSetEnvPath() < 0)
        return EXIT_AM_HARDFAIL;

    if (!virFileExists(abs_srcdir))
        return EXIT_AM_HARDFAIL;

    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        fputs("effective environment variables:\n"
              "VIR_TEST_VERBOSE set to show names of individual tests\n"
              "VIR_TEST_DEBUG set to show information for debugging failures\n",
              stderr);
        return EXIT_FAILURE;
    }
    fprintf(stderr, "TEST: %s\n", progname);

    if (virErrorInitialize() < 0)
        return EXIT_FAILURE;

    if (virLogSetFromEnv() < 0)
        return EXIT_FAILURE;

    if (!getenv("LIBVIRT_DEBUG") && !virLogGetNbOutputs()) {
        if (!(output = virLogOutputNew(virtTestLogOutput, virtTestLogClose,
                                       &testLog, VIR_LOG_DEBUG,
                                       VIR_LOG_TO_STDERR, NULL)))
            return EXIT_FAILURE;

        VIR_APPEND_ELEMENT(outputs, noutputs, output);

        if (virLogDefineOutputs(outputs, noutputs) < 0) {
            virLogOutputListFree(outputs, noutputs);
            return EXIT_FAILURE;
        }
    }

    if ((testRange = getenv("VIR_TEST_RANGE")) != NULL) {
        if (!(testBitmap = virBitmapParseUnlimited(testRange))) {
            fprintf(stderr, "Cannot parse range %s\n", testRange);
            return EXIT_FAILURE;
        }
    }

    failedTests = virBitmapNew(1);

    if (!(fakerootdir = virTestFakeRootDirInit()))
        return EXIT_FAILURE;

    ret = (func)();

    virResetLastError();
    if (!virTestGetVerbose() && ret != EXIT_AM_SKIP) {
        if (testCounter == 0 || testCounter % 40)
            fprintf(stderr, "%*s", 40 - (int)(testCounter % 40), "");
        fprintf(stderr, " %-3zu %s\n", testCounter, ret == 0 ? "OK" : "FAIL");
    }

    virTestFakeRootDirCleanup(fakerootdir);

    switch (ret) {
    case EXIT_FAILURE:
    case EXIT_SUCCESS:
    case EXIT_AM_SKIP:
    case EXIT_AM_HARDFAIL:
        break;
    default:
        fprintf(stderr, "Test callback returned invalid value: %d\n", ret);
        ret = EXIT_AM_HARDFAIL;
        break;
    }

    if (ret == EXIT_FAILURE && !virBitmapIsAllClear(failedTests)) {
        g_autofree char *failed = virBitmapFormat(failedTests);
        fprintf(stderr, "%zu tests failed. Run them using:\n", virBitmapCountBits(failedTests));
        fprintf(stderr, "VIR_TEST_DEBUG=1 VIR_TEST_RANGE=%s %s\n", failed, argv[0]);
    }

    virBitmapFree(testBitmap);
    virBitmapFree(failedTests);
    virLogReset();
    return ret;
}


virCaps *
virTestGenericCapsInit(void)
{
    g_autoptr(virCaps) caps = NULL;
    virCapsGuest *guest;

    if ((caps = virCapabilitiesNew(VIR_ARCH_X86_64,
                                   false, false)) == NULL)
        return NULL;

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_I686,
                                    "/usr/bin/acme-virt", NULL, 0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_TEST,
                                  NULL, NULL, 0, NULL);
    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU,
                                  NULL, NULL, 0, NULL);
    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM,
                                  NULL, NULL, 0, NULL);

    guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_X86_64,
                                    "/usr/bin/acme-virt", NULL, 0, NULL);

    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_TEST,
                                  NULL, NULL, 0, NULL);
    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_QEMU,
                                  NULL, NULL, 0, NULL);
    virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_KVM,
                                  NULL, NULL, 0, NULL);

    if (virTestGetDebug() > 1) {
        g_autofree char *caps_str = NULL;

        caps_str = virCapabilitiesFormatXML(caps);
        if (!caps_str)
            return NULL;

        VIR_TEST_DEBUG("Generic driver capabilities:\n%s", caps_str);
    }

    return g_steal_pointer(&caps);
}


#define MAX_CELLS 4
#define MAX_CPUS_IN_CELL 2
#define MAX_MEM_IN_CELL 2097152

/*
 * Build NUMA topology with cell id starting from (0 + seq)
 * for testing
 */
virCapsHostNUMA *
virTestCapsBuildNUMATopology(int seq)
{
    g_autoptr(virCapsHostNUMA) caps = virCapabilitiesHostNUMANew();
    virCapsHostNUMACellCPU *cell_cpus = NULL;
    int core_id, cell_id;
    int id;

    id = 0;
    for (cell_id = 0; cell_id < MAX_CELLS; cell_id++) {
        cell_cpus = g_new0(virCapsHostNUMACellCPU, MAX_CPUS_IN_CELL);

        for (core_id = 0; core_id < MAX_CPUS_IN_CELL; core_id++) {
            cell_cpus[core_id].id = id + core_id;
            cell_cpus[core_id].socket_id = cell_id + seq;
            cell_cpus[core_id].core_id = id + core_id;
            cell_cpus[core_id].siblings = virBitmapNew(MAX_CPUS_IN_CELL);
            ignore_value(virBitmapSetBit(cell_cpus[core_id].siblings, id));
        }
        id++;

        virCapabilitiesHostNUMAAddCell(caps, cell_id + seq,
                                       MAX_MEM_IN_CELL,
                                       MAX_CPUS_IN_CELL, &cell_cpus,
                                       0, NULL,
                                       0, NULL,
                                       NULL);

        cell_cpus = NULL;
    }

    return g_steal_pointer(&caps);
}

static virDomainDefParserConfig virTestGenericDomainDefParserConfig = {
    .features = VIR_DOMAIN_DEF_FEATURE_INDIVIDUAL_VCPUS,
};

virDomainXMLOption *virTestGenericDomainXMLConfInit(void)
{
    return virDomainXMLOptionNew(&virTestGenericDomainDefParserConfig,
                                 NULL, NULL, NULL, NULL, NULL);
}


int
testCompareDomXML2XMLFiles(virCaps *caps G_GNUC_UNUSED,
                           virDomainXMLOption *xmlopt,
                           const char *infile, const char *outfile, bool live,
                           unsigned int parseFlags,
                           testCompareDomXML2XMLResult expectResult)
{
    g_autofree char *actual = NULL;
    int ret = -1;
    testCompareDomXML2XMLResult result;
    g_autoptr(virDomainDef) def = NULL;
    unsigned int parse_flags = live ? 0 : VIR_DOMAIN_DEF_PARSE_INACTIVE;
    unsigned int format_flags = VIR_DOMAIN_DEF_FORMAT_SECURE;

    parse_flags |= parseFlags;

    if (!virFileExists(infile)) {
        VIR_TEST_DEBUG("Test input file '%s' is missing", infile);
        return -1;
    }

    if (!live)
        format_flags |= VIR_DOMAIN_DEF_FORMAT_INACTIVE;

    if (!(def = virDomainDefParseFile(infile, xmlopt, NULL, parse_flags))) {
        result = TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE;
        goto out;
    }

    if (!virDomainDefCheckABIStability(def, def, xmlopt)) {
        VIR_TEST_DEBUG("ABI stability check failed on %s", infile);
        result = TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_STABILITY;
        goto out;
    }

    if (!(actual = virDomainDefFormat(def, xmlopt, format_flags))) {
        result = TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_FORMAT;
        goto out;
    }

    if (virTestCompareToFile(actual, outfile) < 0) {
        result = TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_COMPARE;
        goto out;
    }

    result = TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS;

 out:
    if (result == expectResult) {
        ret = 0;
        if (expectResult != TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS) {
            VIR_TEST_DEBUG("Got expected failure code=%d msg=%s",
                           result, virGetLastErrorMessage());
        }
    } else {
        ret = -1;
        VIR_TEST_DEBUG("Expected result code=%d but received code=%d",
                       expectResult, result);
    }

    return ret;
}


static int virtTestCounter;
static char virtTestCounterStr[128];
static char *virtTestCounterPrefixEndOffset;


/**
 * virTestCounterReset:
 * @prefix: name of the test group
 *
 * Resets the counter and sets up the test group name to use with
 * virTestCounterNext(). This function is not thread safe.
 *
 * Note: The buffer for the assembled message is 128 bytes long. Longer test
 * case names (including the number index) will be silently truncated.
 */
void
virTestCounterReset(const char *prefix)
{
    virtTestCounter = 0;

    ignore_value(virStrcpyStatic(virtTestCounterStr, prefix));
    virtTestCounterPrefixEndOffset = virtTestCounterStr + strlen(virtTestCounterStr);
}


/**
 * virTestCounterNext:
 *
 * This function is designed to ease test creation and reordering by adding
 * a way to do automagic test case numbering.
 *
 * Returns string consisting of test name prefix configured via
 * virTestCounterReset() and a number that increments in every call of this
 * function. This function is not thread safe.
 *
 * Note: The buffer for the assembled message is 128 bytes long. Longer test
 * case names (including the number index) will be silently truncated.
 */
const char
*virTestCounterNext(void)
{
    size_t len = G_N_ELEMENTS(virtTestCounterStr);

    /* calculate length of the rest of the string */
    len -= (virtTestCounterPrefixEndOffset - virtTestCounterStr);

    g_snprintf(virtTestCounterPrefixEndOffset, len, "%d", ++virtTestCounter);

    return virtTestCounterStr;
}


/**
 * virTestStablePath:
 * @path: path to make stable
 *
 * If @path starts with the absolute source directory path, the prefix
 * is replaced with the string "ABS_SRCDIR" and similarly the build directory
 * is replaced by "ABS_BUILDDIR". This is useful when paths e.g. in output
 * test files need to be made stable.
 *
 * If @path is NULL the equivalent to NULLSTR(path) is returned.
 *
 * The caller is responsible for freeing the returned buffer.
 */
char *
virTestStablePath(const char *path)
{
    const char *tmp;

    path = NULLSTR(path);

    if ((tmp = STRSKIP(path, abs_srcdir)))
        return g_strdup_printf("ABS_SRCDIR%s", tmp);

    if ((tmp = STRSKIP(path, abs_builddir)))
        return g_strdup_printf("ABS_BUILDDIR%s", tmp);

    return g_strdup(path);
}

#ifdef __linux__
/**
 * virCreateAnonymousFile:
 * @data: a pointer to data to be written into a new file.
 * @len: the length of data to be written (in bytes).
 *
 * Create a fake fd, write initial data to it.
 *
 */
int
virCreateAnonymousFile(const uint8_t *data, size_t len)
{
    int fd = -1;
    char path[] = abs_builddir "testutils-memfd-XXXXXX";
    /* A temp file is used since not all supported distributions support memfd. */
    if ((fd = g_mkstemp_full(path, O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR)) < 0) {
        return fd;
    }
    g_unlink(path);

    if (safewrite(fd, data, len) != len) {
        VIR_TEST_DEBUG("%s: %s", "failed to write to an anonymous file",
                g_strerror(errno));
        goto cleanup;
    }
    return fd;
 cleanup:
    if (VIR_CLOSE(fd) < 0) {
        VIR_TEST_DEBUG("%s: %s", "failed to close an anonymous file",
                g_strerror(errno));
    }
    return -1;
}
#endif
