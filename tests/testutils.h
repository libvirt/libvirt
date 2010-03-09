/*
 * utils.c: test utils
 *
 * Copyright (C) 2005, 2008-2009 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Karel Zak <kzak@redhat.com>
 */

#ifndef __VIT_TEST_UTILS_H__
# define __VIT_TEST_UTILS_H__

# include <stdio.h>

# define EXIT_AM_SKIP 77 /* tell Automake we're skipping a test */

double virtTestCountAverage(double *items,
                            int nitems);

void virtTestResult(const char *name, int ret, const char *msg, ...);
int virtTestRun(const char *title,
                int nloops,
                int (*body)(const void *data),
                const void *data);
int virtTestLoadFile(const char *name,
                     char **buf,
                     int buflen);
int virtTestCaptureProgramOutput(const char *const argv[],
                                 char **buf,
                                 int buflen);

int virtTestClearLineRegex(const char *pattern,
                           char *string);

int virtTestDifference(FILE *stream,
                       const char *expect,
                       const char *actual);

unsigned int virTestGetDebug(void);
unsigned int virTestGetVerbose(void);

int virtTestMain(int argc,
                 char **argv,
                 int (*func)(int, char **));

# define VIRT_TEST_MAIN(func)                    \
    int main(int argc, char **argv)  {          \
        return virtTestMain(argc,argv, func);   \
    }

#endif /* __VIT_TEST_UTILS_H__ */
