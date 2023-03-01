/*
 * testutils.h: test utils
 *
 * Copyright (C) 2005, 2008-2013 Red Hat, Inc.
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

#pragma once

#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"
#include "virjson.h"
#include "domain_conf.h"

#define EXIT_AM_SKIP 77 /* tell Automake we're skipping a test */
#define EXIT_AM_HARDFAIL 99 /* tell Automake that the framework is broken */

/* Meson provides these two definitions */
#if !defined(abs_srcdir) || !defined(abs_builddir)
# error Fix build system
#endif

void virTestSetHostArch(virArch arch);

int virTestRun(const char *title,
               int (*body)(const void *data),
               const void *data);
void virTestRunLog(int *ret,
                   const char *title,
                   int (*body)(const void *data),
                   const void *data);
int virTestLoadFile(const char *file, char **buf);
char *virTestLoadFilePath(const char *p, ...)
    G_GNUC_NULL_TERMINATED;
virJSONValue *virTestLoadFileJSON(const char *p, ...)
    G_GNUC_NULL_TERMINATED;

int virTestDifference(FILE *stream,
                      const char *expect,
                      const char *actual);
int virTestDifferenceFull(FILE *stream,
                          const char *expect,
                          const char *expectName,
                          const char *actual,
                          const char *actualName);
int virTestDifferenceFullNoRegenerate(FILE *stream,
                                      const char *expect,
                                      const char *expectName,
                                      const char *actual,
                                      const char *actualName);
int virTestDifferenceBin(FILE *stream,
                         const char *expect,
                         const char *actual,
                         size_t length);
int virTestCompareToFileFull(const char *actual,
                             const char *filename,
                             bool unwrap);
int virTestCompareToFile(const char *actual,
                         const char *filename);
int virTestCompareToString(const char *expect,
                           const char *actual);
int virTestCompareToULL(unsigned long long expect,
                        unsigned long long actual);

unsigned int virTestGetDebug(void);
unsigned int virTestGetVerbose(void);
unsigned int virTestGetExpensive(void);
unsigned int virTestGetRegenerate(void);
void virTestPropagateLibvirtError(void);

#define VIR_TEST_DEBUG(fmt, ...) \
    do { \
        if (virTestGetDebug()) \
            fprintf(stderr, fmt "\n", ## __VA_ARGS__); \
    } while (0)

#define VIR_TEST_VERBOSE(fmt, ...) \
    do { \
        if (virTestGetVerbose()) \
            fprintf(stderr, fmt "\n", ## __VA_ARGS__); \
    } while (0)

char *virTestLogContentAndReset(void);

void virTestQuiesceLibvirtErrors(bool always);

void virTestCounterReset(const char *prefix);
const char *virTestCounterNext(void);

char *virTestFakeRootDirInit(void);
void virTestFakeRootDirCleanup(char *fakerootdir);

/**
 * The @func shall return  EXIT_FAILURE or EXIT_SUCCESS or
 * EXIT_AM_SKIP or EXIT_AM_HARDFAIL.
 */
int virTestMain(int argc,
                char **argv,
                int (*func)(void),
                ...);

/* Setup, then call func() */
#define VIR_TEST_MAIN(func) \
    int main(int argc, char **argv) { \
        return virTestMain(argc, argv, func, NULL); \
    }

#ifdef __APPLE__
# define PRELOAD_VAR "DYLD_INSERT_LIBRARIES"
# define FORCE_FLAT_NAMESPACE \
            g_setenv("DYLD_FORCE_FLAT_NAMESPACE", "1", TRUE);
# define MOCK_EXT ".dylib"
#else
# define PRELOAD_VAR "LD_PRELOAD"
# define FORCE_FLAT_NAMESPACE
# define MOCK_EXT ".so"
#endif

#define VIR_TEST_PRELOAD(libs) \
    do { \
        const char *preload = getenv(PRELOAD_VAR); \
        if (preload == NULL || strstr(preload, libs) == NULL) { \
            char *newenv; \
            if (!preload) { \
                newenv = (char *) libs; \
            } else { \
                newenv = g_strdup_printf("%s:%s", libs, preload); \
            } \
            g_setenv(PRELOAD_VAR, newenv, TRUE); \
            FORCE_FLAT_NAMESPACE \
            execv(argv[0], argv); \
        } \
    } while (0)

#define VIR_TEST_MAIN_PRELOAD(func, ...) \
    int main(int argc, char **argv) { \
        return virTestMain(argc, argv, func, __VA_ARGS__, NULL); \
    }

#define VIR_TEST_MOCK(mock) (abs_builddir "/lib" mock "mock" MOCK_EXT)

virCaps *virTestGenericCapsInit(void);
virCapsHostNUMA *virTestCapsBuildNUMATopology(int seq);
virDomainXMLOption *virTestGenericDomainXMLConfInit(void);

typedef enum {
    TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS,
    TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE,
    TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_STABILITY,
    TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_FORMAT,
    TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_COMPARE,
} testCompareDomXML2XMLResult;

int testCompareDomXML2XMLFiles(virCaps *caps,
                               virDomainXMLOption *xmlopt,
                               const char *inxml,
                               const char *outfile,
                               bool live,
                               unsigned int parseFlags,
                               testCompareDomXML2XMLResult expectResult);

char *
virTestStablePath(const char *path);

#ifdef __linux__
int virCreateAnonymousFile(const uint8_t *data, size_t len);
#endif
