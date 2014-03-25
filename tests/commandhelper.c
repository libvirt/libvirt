/*
 * commandhelper.c: Auxiliary program for commandtest
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include "internal.h"
#include "virutil.h"
#include "viralloc.h"
#include "virfile.h"
#include "testutils.h"
#include "virstring.h"

#ifndef WIN32

# define VIR_FROM_THIS VIR_FROM_NONE

static int envsort(const void *a, const void *b)
{
    const char *const*astrptr = a;
    const char *const*bstrptr = b;
    const char *astr = *astrptr;
    const char *bstr = *bstrptr;
    char *aeq = strchr(astr, '=');
    char *beq = strchr(bstr, '=');
    char *akey;
    char *bkey;
    int ret;

    ignore_value(VIR_STRNDUP_QUIET(akey, astr, aeq - astr));
    ignore_value(VIR_STRNDUP_QUIET(bkey, bstr, beq - bstr));
    ret = strcmp(akey, bkey);
    VIR_FREE(akey);
    VIR_FREE(bkey);
    return ret;
}

int main(int argc, char **argv) {
    size_t i, n;
    int open_max;
    char **origenv;
    char **newenv;
    char *cwd;
    FILE *log = fopen(abs_builddir "/commandhelper.log", "w");

    if (!log)
        goto error;

    for (i = 1; i < argc; i++) {
        fprintf(log, "ARG:%s\n", argv[i]);
    }

    origenv = environ;
    n = 0;
    while (*origenv != NULL) {
        n++;
        origenv++;
    }

    if (VIR_ALLOC_N_QUIET(newenv, n) < 0)
        return EXIT_FAILURE;

    origenv = environ;
    n = i = 0;
    while (*origenv != NULL) {
        newenv[i++] = *origenv;
        n++;
        origenv++;
    }
    qsort(newenv, n, sizeof(newenv[0]), envsort);

    for (i = 0; i < n; i++) {
        /* Ignore the variables used to instruct the loader into
         * behaving differently, as they could throw the tests off. */
        if (!STRPREFIX(newenv[i], "LD_"))
            fprintf(log, "ENV:%s\n", newenv[i]);
    }

    open_max = sysconf(_SC_OPEN_MAX);
    if (open_max < 0)
        return EXIT_FAILURE;
    for (i = 0; i < open_max; i++) {
        int f;
        int closed;
        if (i == fileno(log))
            continue;
        closed = fcntl(i, F_GETFD, &f) == -1 &&
            errno == EBADF;
        if (!closed)
            fprintf(log, "FD:%zu\n", i);
    }

    fprintf(log, "DAEMON:%s\n", getpgrp() == getsid(0) ? "yes" : "no");
    if (!(cwd = getcwd(NULL, 0)))
        return EXIT_FAILURE;
    if (strlen(cwd) > strlen(".../commanddata") &&
        STREQ(cwd + strlen(cwd) - strlen("/commanddata"), "/commanddata"))
        strcpy(cwd, ".../commanddata");
    fprintf(log, "CWD:%s\n", cwd);
    VIR_FREE(cwd);

    VIR_FORCE_FCLOSE(log);

    if (argc > 1 && STREQ(argv[1], "--close-stdin")) {
        if (freopen("/dev/null", "r", stdin) != stdin)
            goto error;
        usleep(100*1000);
    }

    char buf[1024];
    ssize_t got;

    fprintf(stdout, "BEGIN STDOUT\n");
    fflush(stdout);
    fprintf(stderr, "BEGIN STDERR\n");
    fflush(stderr);

    for (;;) {
        got = read(STDIN_FILENO, buf, sizeof(buf));
        if (got < 0)
            goto error;
        if (got == 0)
            break;
        if (safewrite(STDOUT_FILENO, buf, got) != got)
            goto error;
        if (safewrite(STDERR_FILENO, buf, got) != got)
            goto error;
    }

    fprintf(stdout, "END STDOUT\n");
    fflush(stdout);
    fprintf(stderr, "END STDERR\n");
    fflush(stderr);

    return EXIT_SUCCESS;

 error:
    return EXIT_FAILURE;
}

#else

int
main(void)
{
    return EXIT_AM_SKIP;
}

#endif
