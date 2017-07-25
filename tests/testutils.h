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
 *
 * Karel Zak <kzak@redhat.com>
 */

#ifndef __VIR_TEST_UTILS_H__
# define __VIR_TEST_UTILS_H__

# include <stdio.h>
# include "viralloc.h"
# include "virfile.h"
# include "virstring.h"
# include "capabilities.h"
# include "domain_conf.h"

# define EXIT_AM_SKIP 77 /* tell Automake we're skipping a test */
# define EXIT_AM_HARDFAIL 99 /* tell Automake that the framework is broken */

/* Work around lack of gnulib support for fprintf %z */
# ifndef NO_LIBVIRT
#  undef fprintf
#  define fprintf virFilePrintf
# endif

extern char *progname;

/* Makefile.am provides these two definitions */
# if !defined(abs_srcdir) || !defined(abs_builddir)
#  error Fix Makefile.am
# endif

bool virTestOOMActive(void);

int virTestRun(const char *title,
               int (*body)(const void *data),
               const void *data);
int virTestLoadFile(const char *file, char **buf);
char *virTestLoadFilePath(const char *p, ...)
    ATTRIBUTE_SENTINEL;
int virTestCaptureProgramOutput(const char *const argv[], char **buf, int maxlen);

void virTestClearCommandPath(char *cmdset);

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
int virTestCompareToFile(const char *strcontent,
                         const char *filename);
int virTestCompareToString(const char *strcontent,
                           const char *strsrc);
int virTestCompareToULL(unsigned long long content,
                        unsigned long long src);

unsigned int virTestGetDebug(void);
unsigned int virTestGetVerbose(void);
unsigned int virTestGetExpensive(void);
unsigned int virTestGetRegenerate(void);

# define VIR_TEST_DEBUG(...)                    \
    do {                                        \
        if (virTestGetDebug())                  \
            fprintf(stderr, __VA_ARGS__);       \
    } while (0)

# define VIR_TEST_VERBOSE(...)                  \
    do {                                        \
        if (virTestGetVerbose())                \
            fprintf(stderr, __VA_ARGS__);       \
    } while (0)

char *virTestLogContentAndReset(void);

void virTestQuiesceLibvirtErrors(bool always);

void virTestCounterReset(const char *prefix);
const char *virTestCounterNext(void);

int virTestMain(int argc,
                char **argv,
                int (*func)(void),
                ...);

/* Setup, then call func() */
# define VIR_TEST_MAIN(func)                            \
    int main(int argc, char **argv) {                   \
        return virTestMain(argc, argv, func, NULL);     \
    }

# define VIR_TEST_PRELOAD(lib)                                          \
    do {                                                                \
        const char *preload = getenv("LD_PRELOAD");                     \
        if (preload == NULL || strstr(preload, lib) == NULL) {          \
            char *newenv;                                               \
            if (!virFileIsExecutable(lib)) {                            \
                perror(lib);                                            \
                return EXIT_FAILURE;                                    \
            }                                                           \
            if (!preload) {                                             \
                newenv = (char *) lib;                                  \
            } else if (virAsprintf(&newenv, "%s:%s", lib, preload) < 0) {   \
                perror("virAsprintf");                                  \
                return EXIT_FAILURE;                                    \
            }                                                           \
            setenv("LD_PRELOAD", newenv, 1);                            \
            execv(argv[0], argv);                                       \
        }                                                               \
    } while (0)

# define VIR_TEST_MAIN_PRELOAD(func, ...)                               \
    int main(int argc, char **argv) {                                   \
        return virTestMain(argc, argv, func, __VA_ARGS__, NULL);        \
    }

virCapsPtr virTestGenericCapsInit(void);
virDomainXMLOptionPtr virTestGenericDomainXMLConfInit(void);

typedef enum {
    TEST_COMPARE_DOM_XML2XML_RESULT_SUCCESS,
    TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_PARSE,
    TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_STABILITY,
    TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_CB,
    TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_FORMAT,
    TEST_COMPARE_DOM_XML2XML_RESULT_FAIL_COMPARE,
} testCompareDomXML2XMLResult;

typedef int (*testCompareDomXML2XMLPreFormatCallback)(virDomainDefPtr def,
                                                      const void *opaque);
int testCompareDomXML2XMLFiles(virCapsPtr caps,
                               virDomainXMLOptionPtr xmlopt,
                               const char *inxml,
                               const char *outfile,
                               bool live,
                               testCompareDomXML2XMLPreFormatCallback cb,
                               const void *opaque,
                               unsigned int parseFlags,
                               testCompareDomXML2XMLResult expectResult);

#endif /* __VIR_TEST_UTILS_H__ */
