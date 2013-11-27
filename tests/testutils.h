/*
 * utils.c: test utils
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

#ifndef __VIT_TEST_UTILS_H__
# define __VIT_TEST_UTILS_H__

# include <stdio.h>
# include "viralloc.h"
# include "virfile.h"
# include "virstring.h"

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

void virtTestResult(const char *name, int ret, const char *msg, ...)
    ATTRIBUTE_FMT_PRINTF(3,4);
int virtTestRun(const char *title,
                int (*body)(const void *data),
                const void *data);
int virtTestLoadFile(const char *file, char **buf);
int virtTestCaptureProgramOutput(const char *const argv[], char **buf, int maxlen);

int virtTestClearLineRegex(const char *pattern,
                           char *string);

int virtTestDifference(FILE *stream,
                       const char *expect,
                       const char *actual);
int virtTestDifferenceBin(FILE *stream,
                          const char *expect,
                          const char *actual,
                          size_t length);

unsigned int virTestGetDebug(void);
unsigned int virTestGetVerbose(void);
unsigned int virTestGetExpensive(void);

char *virtTestLogContentAndReset(void);

void virtTestQuiesceLibvirtErrors(bool always);

int virtTestMain(int argc,
                 char **argv,
                 int (*func)(void));

/* Setup, then call func() */
# define VIRT_TEST_MAIN(func)                   \
    int main(int argc, char **argv) {           \
        return virtTestMain(argc, argv, func);  \
    }

# define VIRT_TEST_MAIN_PRELOAD(func, lib)                              \
    int main(int argc, char **argv) {                                   \
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
        return virtTestMain(argc, argv, func);                          \
    }

#endif /* __VIT_TEST_UTILS_H__ */
