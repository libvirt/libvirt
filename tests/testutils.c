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
 *
 * Karel Zak <kzak@redhat.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <regex.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include "testutils.h"
#include "internal.h"
#include "viralloc.h"
#include "virutil.h"
#include "virthread.h"
#include "virerror.h"
#include "virbuffer.h"
#include "virlog.h"
#include "vircommand.h"
#include "virrandom.h"
#include "dirname.h"
#include "virprocess.h"
#include "virstring.h"

#ifdef TEST_OOM
# ifdef TEST_OOM_TRACE
#  include <dlfcn.h>
#  include <execinfo.h>
# endif
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.testutils");

#include "virbitmap.h"
#include "virfile.h"

static unsigned int testDebug = -1;
static unsigned int testVerbose = -1;
static unsigned int testExpensive = -1;
static unsigned int testRegenerate = -1;

#ifdef TEST_OOM
static unsigned int testOOM;
static unsigned int testOOMStart = -1;
static unsigned int testOOMEnd = -1;
static unsigned int testOOMTrace;
# ifdef TEST_OOM_TRACE
void *testAllocStack[30];
int ntestAllocStack;
# endif
#endif
static bool testOOMActive;

static size_t testCounter;
static virBitmapPtr testBitmap;

char *progname;
static char *perl;

bool virTestOOMActive(void)
{
    return testOOMActive;
}

static int virTestUseTerminalColors(void)
{
    return isatty(STDIN_FILENO);
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

#ifdef TEST_OOM_TRACE
static void virTestAllocHook(int nalloc ATTRIBUTE_UNUSED,
                             void *opaque ATTRIBUTE_UNUSED)
{
    ntestAllocStack = backtrace(testAllocStack, ARRAY_CARDINALITY(testAllocStack));
}
#endif

#ifdef TEST_OOM_TRACE
static void
virTestShowTrace(void)
{
    size_t j;
    for (j = 2; j < ntestAllocStack; j++) {
        Dl_info info;
        char *cmd;

        dladdr(testAllocStack[j], &info);
        if (info.dli_fname &&
            strstr(info.dli_fname, ".so")) {
            if (virAsprintf(&cmd, ADDR2LINE " -f -e %s %p",
                            info.dli_fname,
                            ((void*)((unsigned long long)testAllocStack[j]
                                     - (unsigned long long)info.dli_fbase))) < 0)
                continue;
        } else {
            if (virAsprintf(&cmd, ADDR2LINE " -f -e %s %p",
                            (char*)(info.dli_fname ? info.dli_fname : "<unknown>"),
                            testAllocStack[j]) < 0)
                continue;
        }
        ignore_value(system(cmd));
        VIR_FREE(cmd);
    }
}
#endif

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
        setenv("VIR_TEST_MOCK_TESTNAME", title, 1);

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
    virErrorPtr err = virGetLastError();
    if (err) {
        if (virTestGetVerbose() || virTestGetDebug())
            virDispatchError(NULL);
    }

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

#ifdef TEST_OOM
    if (testOOM && ret != EXIT_AM_SKIP) {
        int nalloc;
        int oomret;
        int start, end;
        size_t i;
        virResetLastError();
        virAllocTestInit();
# ifdef TEST_OOM_TRACE
        virAllocTestHook(virTestAllocHook, NULL);
# endif
        oomret = body(data);
        nalloc = virAllocTestCount();
        fprintf(stderr, "    Test OOM for nalloc=%d ", nalloc);
        if (testOOMStart == -1 ||
            testOOMEnd == -1) {
            start = 0;
            end = nalloc;
        } else {
            start = testOOMStart;
            end = testOOMEnd + 1;
        }
        testOOMActive = true;
        for (i = start; i < end; i++) {
            bool missingFail = false;
# ifdef TEST_OOM_TRACE
            memset(testAllocStack, 0, ARRAY_CARDINALITY(testAllocStack));
            ntestAllocStack = 0;
# endif
            virAllocTestOOM(i + 1, 1);
            oomret = body(data);

            /* fprintf() disabled because XML parsing APIs don't allow
             * distinguish between element / attribute not present
             * in the XML (which is non-fatal), vs OOM / malformed
             * which should be fatal. Thus error reporting for
             * optionally present XML is mostly broken.
             */
            if (oomret == 0) {
                missingFail = true;
# if 0
                fprintf(stderr, " alloc %zu failed but no err status\n", i + 1);
# endif
            } else {
                virErrorPtr lerr = virGetLastError();
                if (!lerr) {
# if 0
                    fprintf(stderr, " alloc %zu failed but no error report\n", i + 1);
# endif
                    missingFail = true;
                }
            }
            if ((missingFail && testOOMTrace) || (testOOMTrace > 1)) {
                fprintf(stderr, "%s", "!");
# ifdef TEST_OOM_TRACE
                virTestShowTrace();
# endif
                ret = -1;
            } else {
                fprintf(stderr, "%s", ".");
            }
        }
        testOOMActive = false;
        if (ret == 0)
            fprintf(stderr, " OK\n");
        else
            fprintf(stderr, " FAILED\n");
        virAllocTestInit();
    }
#endif /* TEST_OOM */

    unsetenv("VIR_TEST_MOCK_TESTNAME");
    return ret;
}

/* Allocate BUF to the size of FILE. Read FILE into buffer BUF.
   Upon any failure, diagnose it and return -1, but don't bother trying
   to preserve errno. Otherwise, return the number of bytes copied into BUF. */
int
virTestLoadFile(const char *file, char **buf)
{
    FILE *fp = fopen(file, "r");
    struct stat st;
    char *tmp;
    int len, tmplen, buflen;

    if (!fp) {
        fprintf(stderr, "%s: failed to open: %s\n", file, strerror(errno));
        return -1;
    }

    if (fstat(fileno(fp), &st) < 0) {
        fprintf(stderr, "%s: failed to fstat: %s\n", file, strerror(errno));
        VIR_FORCE_FCLOSE(fp);
        return -1;
    }

    tmplen = buflen = st.st_size + 1;

    if (VIR_ALLOC_N(*buf, buflen) < 0) {
        VIR_FORCE_FCLOSE(fp);
        return -1;
    }

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
            fprintf(stderr, "%s: read failed: %s\n", file, strerror(errno));
            VIR_FORCE_FCLOSE(fp);
            VIR_FREE(*buf);
            return -1;
        }
    }

    VIR_FORCE_FCLOSE(fp);
    return strlen(*buf);
}

#ifndef WIN32
static
void virTestCaptureProgramExecChild(const char *const argv[],
                                    int pipefd)
{
    size_t i;
    int open_max;
    int stdinfd = -1;
    const char *const env[] = {
        "LANG=C",
# if WITH_DRIVER_MODULES
        "LIBVIRT_DRIVER_DIR=" TEST_DRIVER_DIR,
# endif
        NULL
    };

    if ((stdinfd = open("/dev/null", O_RDONLY)) < 0)
        goto cleanup;

    open_max = sysconf(_SC_OPEN_MAX);
    if (open_max < 0)
        goto cleanup;

    for (i = 0; i < open_max; i++) {
        if (i != stdinfd &&
            i != pipefd) {
            int tmpfd;
            tmpfd = i;
            VIR_FORCE_CLOSE(tmpfd);
        }
    }

    if (dup2(stdinfd, STDIN_FILENO) != STDIN_FILENO)
        goto cleanup;
    if (dup2(pipefd, STDOUT_FILENO) != STDOUT_FILENO)
        goto cleanup;
    if (dup2(pipefd, STDERR_FILENO) != STDERR_FILENO)
        goto cleanup;

    /* SUS is crazy here, hence the cast */
    execve(argv[0], (char *const*)argv, (char *const*)env);

 cleanup:
    VIR_FORCE_CLOSE(stdinfd);
}

int
virTestCaptureProgramOutput(const char *const argv[], char **buf, int maxlen)
{
    int pipefd[2];
    int len;

    if (pipe(pipefd) < 0)
        return -1;

    pid_t pid = fork();
    switch (pid) {
    case 0:
        VIR_FORCE_CLOSE(pipefd[0]);
        virTestCaptureProgramExecChild(argv, pipefd[1]);

        VIR_FORCE_CLOSE(pipefd[1]);
        _exit(EXIT_FAILURE);

    case -1:
        return -1;

    default:
        VIR_FORCE_CLOSE(pipefd[1]);
        len = virFileReadLimFD(pipefd[0], maxlen, buf);
        VIR_FORCE_CLOSE(pipefd[0]);
        if (virProcessWait(pid, NULL, false) < 0)
            return -1;

        return len;
    }
}
#else /* !WIN32 */
int
virTestCaptureProgramOutput(const char *const argv[] ATTRIBUTE_UNUSED,
                            char **buf ATTRIBUTE_UNUSED,
                            int maxlen ATTRIBUTE_UNUSED)
{
    return -1;
}
#endif /* !WIN32 */

static int
virTestRewrapFile(const char *filename)
{
    int ret = -1;
    char *script = NULL;
    virCommandPtr cmd = NULL;

    if (!(virFileHasSuffix(filename, ".args") ||
          virFileHasSuffix(filename, ".ldargs")))
        return 0;

    if (!perl) {
        fprintf(stderr, "cannot rewrap %s: unable to find perl in path", filename);
        return -1;
    }

    if (virAsprintf(&script, "%s/test-wrap-argv.pl", abs_srcdir) < 0)
        goto cleanup;

    cmd = virCommandNewArgList(perl, script, "--in-place", filename, NULL);
    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(script);
    virCommandFree(cmd);
    return ret;
}

/**
 * @param stream: output stream to write differences to
 * @param expect: expected output text
 * @param expectName: name designator of the expected text
 * @param actual: actual output text
 * @param actualName: name designator of the actual text
 * @param regenerate: enable or disable regenerate functionality
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

        if (virTestRewrapFile(expectName) < 0) {
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
 * @param strcontent: String input content
 * @param filename: File to compare strcontent against
 */
int
virTestCompareToFile(const char *strcontent,
                     const char *filename)
{
    int ret = -1;
    char *filecontent = NULL;
    char *fixedcontent = NULL;
    const char *cmpcontent = strcontent;

    if (virTestLoadFile(filename, &filecontent) < 0 && !virTestGetRegenerate())
        goto failure;

    if (filecontent &&
        filecontent[strlen(filecontent) - 1] == '\n' &&
        strcontent[strlen(strcontent) - 1] != '\n') {
        if (virAsprintf(&fixedcontent, "%s\n", strcontent) < 0)
            goto failure;
        cmpcontent = fixedcontent;
    }

    if (STRNEQ_NULLABLE(cmpcontent, filecontent)) {
        virTestDifferenceFull(stderr,
                              filecontent, filename,
                              cmpcontent, NULL);
        goto failure;
    }

    ret = 0;
 failure:
    VIR_FREE(fixedcontent);
    VIR_FREE(filecontent);
    return ret;
}

/*
 * @param content: Input content
 * @param src: Source to compare @content against
 */
int
virTestCompareToULL(unsigned long long content,
                    unsigned long long src)
{
    char *strcontent = NULL;
    char *strsrc = NULL;
    int ret = -1;

    if (virAsprintf(&strcontent, "%llu", content) < 0)
        goto cleanup;

    if (virAsprintf(&strsrc, "%llu", src) < 0)
        goto cleanup;

    ret = virTestCompareToString(strcontent, strsrc);

 cleanup:
    VIR_FREE(strcontent);
    VIR_FREE(strsrc);

    return ret;
}

/*
 * @param strcontent: String input content
 * @param strsrc: String source to compare strcontent against
 */
int
virTestCompareToString(const char *strcontent,
                       const char *strsrc)
{
    if (STRNEQ_NULLABLE(strcontent, strsrc)) {
        virTestDifference(stderr, strcontent, strsrc);
        return -1;
    }

    return 0;
}

static void
virTestErrorFuncQuiet(void *data ATTRIBUTE_UNUSED,
                      virErrorPtr err ATTRIBUTE_UNUSED)
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
virtTestLogOutput(virLogSourcePtr source ATTRIBUTE_UNUSED,
                  virLogPriority priority ATTRIBUTE_UNUSED,
                  const char *filename ATTRIBUTE_UNUSED,
                  int lineno ATTRIBUTE_UNUSED,
                  const char *funcname ATTRIBUTE_UNUSED,
                  const char *timestamp,
                  virLogMetadataPtr metadata ATTRIBUTE_UNUSED,
                  unsigned int flags,
                  const char *rawstr ATTRIBUTE_UNUSED,
                  const char *str,
                  void *data)
{
    struct virtTestLogData *log = data;
    virCheckFlags(VIR_LOG_STACK_TRACE,);
    if (!testOOMActive)
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

    if (virBufferError(&testLog.buf))
        return NULL;
    ret = virBufferContentAndReset(&testLog.buf);
    if (!ret)
        ignore_value(VIR_STRDUP(ret, ""));
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
    int ret = -1;
    const char *path = getenv("PATH");
    char *new_path = NULL;

    if (path) {
        if (strstr(path, abs_builddir) != path &&
            virAsprintf(&new_path, "%s:%s", abs_builddir, path) < 0)
            goto cleanup;
    } else {
        if (VIR_STRDUP(new_path, abs_builddir) < 0)
            goto cleanup;
    }

    if (new_path &&
        setenv("PATH", new_path, 1) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(new_path);
    return ret;
}

#define TEST_MOCK (abs_builddir "/.libs/virtestmock.so")

int virTestMain(int argc,
                char **argv,
                int (*func)(void),
                ...)
{
    const char *lib;
    va_list ap;
    int ret;
    char *testRange = NULL;
#ifdef TEST_OOM
    char *oomstr;
#endif
    size_t noutputs = 0;
    virLogOutputPtr output = NULL;
    virLogOutputPtr *outputs = NULL;

    if (getenv("VIR_TEST_FILE_ACCESS"))
        VIR_TEST_PRELOAD(TEST_MOCK);

    va_start(ap, func);
    while ((lib = va_arg(ap, const char *)))
        VIR_TEST_PRELOAD(lib);
    va_end(ap);

    progname = last_component(argv[0]);
    if (STRPREFIX(progname, "lt-"))
        progname += 3;

    setenv("VIR_TEST_MOCK_PROGNAME", progname, 1);

    virFileActivateDirOverride(argv[0]);

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

    if (virThreadInitialize() < 0 ||
        virErrorInitialize() < 0)
        return EXIT_FAILURE;

    virLogSetFromEnv();
    if (!getenv("LIBVIRT_DEBUG") && !virLogGetNbOutputs()) {
        if (!(output = virLogOutputNew(virtTestLogOutput, virtTestLogClose,
                                       &testLog, VIR_LOG_DEBUG,
                                       VIR_LOG_TO_STDERR, NULL)) ||
            VIR_APPEND_ELEMENT(outputs, noutputs, output) < 0 ||
            virLogDefineOutputs(outputs, noutputs) < 0) {
            virLogOutputFree(output);
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

#ifdef TEST_OOM
    if ((oomstr = getenv("VIR_TEST_OOM")) != NULL) {
        char *next;
        if (testDebug == -1)
            testDebug = 1;
        testOOM = 1;
        if (oomstr[0] != '\0' &&
            oomstr[1] == ':') {
            if (virStrToLong_ui(oomstr + 2, &next, 10, &testOOMStart) < 0) {
                fprintf(stderr, "Cannot parse range %s\n", oomstr);
                return EXIT_FAILURE;
            }
            if (*next == '\0') {
                testOOMEnd = testOOMStart;
            } else {
                if (*next != '-') {
                    fprintf(stderr, "Cannot parse range %s\n", oomstr);
                    return EXIT_FAILURE;
                }
                if (virStrToLong_ui(next+1, NULL, 10, &testOOMEnd) < 0) {
                    fprintf(stderr, "Cannot parse range %s\n", oomstr);
                    return EXIT_FAILURE;
                }
            }
        } else {
            testOOMStart = -1;
            testOOMEnd = -1;
        }
    }

# ifdef TEST_OOM_TRACE
    if ((oomstr = getenv("VIR_TEST_OOM_TRACE")) != NULL) {
        if (virStrToLong_ui(oomstr, NULL, 10, &testOOMTrace) < 0) {
            fprintf(stderr, "Cannot parse oom trace %s\n", oomstr);
            return EXIT_FAILURE;
        }
    }
# else
    if (getenv("VIR_TEST_OOM_TRACE")) {
        fprintf(stderr, "%s", "OOM test tracing not enabled in this build\n");
        return EXIT_FAILURE;
    }
# endif
#else /* TEST_OOM */
    if (getenv("VIR_TEST_OOM")) {
        fprintf(stderr, "%s", "OOM testing not enabled in this build\n");
        return EXIT_FAILURE;
    }
    if (getenv("VIR_TEST_OOM_TRACE")) {
        fprintf(stderr, "%s", "OOM test tracing not enabled in this build\n");
        return EXIT_FAILURE;
    }
#endif /* TEST_OOM */

    /* Find perl early because some tests override PATH */
    perl = virFindFileInPath("perl");

    ret = (func)();

    virResetLastError();
    if (!virTestGetVerbose() && ret != EXIT_AM_SKIP) {
        if (testCounter == 0 || testCounter % 40)
            fprintf(stderr, "%*s", 40 - (int)(testCounter % 40), "");
        fprintf(stderr, " %-3zu %s\n", testCounter, ret == 0 ? "OK" : "FAIL");
    }
    virLogReset();
    VIR_FREE(perl);
    return ret;
}


/*
 * @cmdset contains a list of command line args, eg
 *
 * "/usr/sbin/iptables --table filter --insert INPUT --in-interface virbr0 --protocol tcp --destination-port 53 --jump ACCEPT
 *  /usr/sbin/iptables --table filter --insert INPUT --in-interface virbr0 --protocol udp --destination-port 53 --jump ACCEPT
 *  /usr/sbin/iptables --table filter --insert FORWARD --in-interface virbr0 --jump REJECT
 *  /usr/sbin/iptables --table filter --insert FORWARD --out-interface virbr0 --jump REJECT
 *  /usr/sbin/iptables --table filter --insert FORWARD --in-interface virbr0 --out-interface virbr0 --jump ACCEPT"
 *
 * And we're munging it in-place to strip the path component
 * of the command line, to produce
 *
 * "iptables --table filter --insert INPUT --in-interface virbr0 --protocol tcp --destination-port 53 --jump ACCEPT
 *  iptables --table filter --insert INPUT --in-interface virbr0 --protocol udp --destination-port 53 --jump ACCEPT
 *  iptables --table filter --insert FORWARD --in-interface virbr0 --jump REJECT
 *  iptables --table filter --insert FORWARD --out-interface virbr0 --jump REJECT
 *  iptables --table filter --insert FORWARD --in-interface virbr0 --out-interface virbr0 --jump ACCEPT"
 */
void virTestClearCommandPath(char *cmdset)
{
    size_t offset = 0;
    char *lineStart = cmdset;
    char *lineEnd = strchr(lineStart, '\n');

    while (lineStart) {
        char *dirsep;
        char *movestart;
        size_t movelen;
        dirsep = strchr(lineStart, ' ');
        if (dirsep) {
            while (dirsep > lineStart && *dirsep != '/')
                dirsep--;
            if (*dirsep == '/')
                dirsep++;
            movestart = dirsep;
        } else {
            movestart = lineStart;
        }
        movelen = lineEnd ? lineEnd - movestart : strlen(movestart);

        if (movelen) {
            memmove(cmdset + offset, movestart, movelen + 1);
            offset += movelen + 1;
        }
        lineStart = lineEnd ? lineEnd + 1 : NULL;
        lineEnd = lineStart ? strchr(lineStart, '\n') : NULL;
    }
    cmdset[offset] = '\0';
}


virCapsPtr virTestGenericCapsInit(void)
{
    virCapsPtr caps;
    virCapsGuestPtr guest;

    if ((caps = virCapabilitiesNew(VIR_ARCH_X86_64,
                                   false, false)) == NULL)
        return NULL;

    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_I686,
                                         "/usr/bin/acme-virt", NULL,
                                         0, NULL)) == NULL)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_TEST, NULL, NULL, 0, NULL))
        goto error;


    if ((guest = virCapabilitiesAddGuest(caps, VIR_DOMAIN_OSTYPE_HVM, VIR_ARCH_X86_64,
                                         "/usr/bin/acme-virt", NULL,
                                         0, NULL)) == NULL)
        goto error;

    if (!virCapabilitiesAddGuestDomain(guest, VIR_DOMAIN_VIRT_TEST, NULL, NULL, 0, NULL))
        goto error;


    if (virTestGetDebug()) {
        char *caps_str;

        caps_str = virCapabilitiesFormatXML(caps);
        if (!caps_str)
            goto error;

        VIR_TEST_DEBUG("Generic driver capabilities:\n%s", caps_str);

        VIR_FREE(caps_str);
    }

    return caps;

 error:
    virObjectUnref(caps);
    return NULL;
}

static virDomainDefParserConfig virTestGenericDomainDefParserConfig = {
    .features = VIR_DOMAIN_DEF_FEATURE_INDIVIDUAL_VCPUS,
};
static virDomainXMLPrivateDataCallbacks virTestGenericPrivateDataCallbacks;

virDomainXMLOptionPtr virTestGenericDomainXMLConfInit(void)
{
    return virDomainXMLOptionNew(&virTestGenericDomainDefParserConfig,
                                 &virTestGenericPrivateDataCallbacks,
                                 NULL, NULL);
}


int
testCompareDomXML2XMLFiles(virCapsPtr caps, virDomainXMLOptionPtr xmlopt,
                           const char *infile, const char *outfile, bool live,
                           testCompareDomXML2XMLPreFormatCallback cb,
                           const void *opaque, unsigned int parseFlags,
                           testCompareDomXML2XMLResult expectResult)
{
    char *actual = NULL;
    int ret = -1;
    testCompareDomXML2XMLResult result;
    virDomainDefPtr def = NULL;
    unsigned int parse_flags = live ? 0 : VIR_DOMAIN_DEF_PARSE_INACTIVE;
    unsigned int format_flags = VIR_DOMAIN_DEF_FORMAT_SECURE;

    parse_flags |= parseFlags;

    if (!virFileExists(infile)) {
        VIR_TEST_DEBUG("Test input file '%s' is missing", infile);
        return -1;
    }

    if (!live)
        format_flags |= VIR_DOMAIN_DEF_FORMAT_INACTIVE;

    if (!(def = virDomainDefParseFile(infile, caps, xmlopt, NULL, parse_flags))) {
        result = TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE;
        goto out;
    }

    if (!virDomainDefCheckABIStability(def, def, xmlopt)) {
        VIR_TEST_DEBUG("ABI stability check failed on %s", infile);
        result = TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_STABILITY;
        goto out;
    }

    if (cb && cb(def, opaque) < 0) {
        result = TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_CB;
        goto out;
    }

    if (!(actual = virDomainDefFormat(def, caps, format_flags))) {
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

    VIR_FREE(actual);
    virDomainDefFree(def);
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
    virtTestCounterPrefixEndOffset = strchrnul(virtTestCounterStr, '\0');
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
    size_t len = ARRAY_CARDINALITY(virtTestCounterStr);

    /* calculate length of the rest of the string */
    len -= (virtTestCounterPrefixEndOffset - virtTestCounterStr);

    snprintf(virtTestCounterPrefixEndOffset, len, "%d", ++virtTestCounter);

    return virtTestCounterStr;
}
