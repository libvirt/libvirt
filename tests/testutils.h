/*
 * utils.c: test utils
 *
 * Copyright (C) 2005, 2008 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Karel Zak <kzak@redhat.com>
 */

#ifndef __VIT_TEST_UTILS_H__
#define __VIT_TEST_UTILS_H__

double virtTestCountAverage(double *items,
                            int nitems);

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


int virtTestDifference(FILE *stream,
                       const char *expect,
                       const char *actual);

int virtTestMain(int argc,
                 char **argv,
                 int (*func)(int, char **));

#define VIRT_TEST_MAIN(func)                    \
    int main(int argc, char **argv)  {          \
        return virtTestMain(argc,argv, func);   \
    }

#endif /* __VIT_TEST_UTILS_H__ */
