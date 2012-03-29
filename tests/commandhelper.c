/*
 * commandhelper.c: Auxiliary program for commandtest
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <config.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include "internal.h"
#include "util.h"
#include "memory.h"
#include "virfile.h"
#include "testutils.h"

#ifndef WIN32


static int envsort(const void *a, const void *b) {
    const char *const*astrptr = a;
    const char *const*bstrptr = b;
    const char *astr = *astrptr;
    const char *bstr = *bstrptr;
    char *aeq = strchr(astr, '=');
    char *beq = strchr(bstr, '=');
    char *akey = strndup(astr, aeq - astr);
    char *bkey = strndup(bstr, beq - bstr);
    int ret = strcmp(akey, bkey);
    VIR_FREE(akey);
    VIR_FREE(bkey);
    return ret;
}

int main(int argc, char **argv) {
    int i, n;
    char **origenv;
    char **newenv;
    char *cwd;
    FILE *log = fopen(abs_builddir "/commandhelper.log", "w");

    if (!log)
        goto error;

    for (i = 1 ; i < argc ; i++) {
        fprintf(log, "ARG:%s\n", argv[i]);
    }

    origenv = environ;
    n = 0;
    while (*origenv != NULL) {
        n++;
        origenv++;
    }

    if (VIR_ALLOC_N(newenv, n) < 0) {
        exit(EXIT_FAILURE);
    }

    origenv = environ;
    n = i = 0;
    while (*origenv != NULL) {
        newenv[i++] = *origenv;
        n++;
        origenv++;
    }
    qsort(newenv, n, sizeof(newenv[0]), envsort);

    for (i = 0 ; i < n ; i++) {
        /* Ignore the variables used to instruct the loader into
         * behaving differently, as they could throw the tests off. */
        if (!STRPREFIX(newenv[i], "LD_"))
            fprintf(log, "ENV:%s\n", newenv[i]);
    }

    for (i = 0 ; i < sysconf(_SC_OPEN_MAX) ; i++) {
        int f;
        int closed;
        if (i == fileno(log))
            continue;
        closed = fcntl(i, F_GETFD, &f) == -1 &&
            errno == EBADF;
        if (!closed)
            fprintf(log, "FD:%d\n", i);
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
