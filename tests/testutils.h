/*
 * utils.c: test utils
 *
 * Copyright (C) 2005, 2008-2012 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Karel Zak <kzak@redhat.com>
 */

#ifndef __VIT_TEST_UTILS_H__
# define __VIT_TEST_UTILS_H__

# include <stdio.h>
# include "memory.h"

# define EXIT_AM_SKIP 77 /* tell Automake we're skipping a test */
# define EXIT_AM_HARDFAIL 99 /* tell Automake that the framework is broken */

extern char *progname;
extern char *abs_srcdir;

double virtTestCountAverage(double *items,
                            int nitems);

void virtTestResult(const char *name, int ret, const char *msg, ...);
int virtTestRun(const char *title,
                int nloops,
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

char *virtTestLogContentAndReset(void);

int virtTestMain(int argc,
                 char **argv,
                 int (*func)(void));

/* Setup, then call func() */
# define VIRT_TEST_MAIN(func)                   \
    int main(int argc, char **argv) {           \
        return virtTestMain(argc, argv, func);  \
    }

#endif /* __VIT_TEST_UTILS_H__ */
