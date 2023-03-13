/*
 * virt-login-shell.c: a setuid shell to connect to a container
 *
 * Copyright (C) 2019 Red Hat, Inc.
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

#include <unistd.h>
#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "configmake.h"

#define G_N_ELEMENTS(Array) (sizeof(Array) / sizeof(*(Array)))
#define VIR_INT64_STR_BUFLEN 21

int main(int argc, char **argv) {
    char uidstr[VIR_INT64_STR_BUFLEN];
    char gidstr[VIR_INT64_STR_BUFLEN];
    const char * newargv[6];
    size_t nargs = 0;
    char *newenv[] = {
        NULL,
        NULL,
    };
    char *term = getenv("TERM");

    if (getuid() == 0 || getgid() == 0) {
        fprintf(stderr, "%s: must not be run as root\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "%s: must be run as setuid root\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    newargv[nargs++] = LIBEXECDIR "/virt-login-shell-helper";
    if (argc == 3) {
        if (strcmp(argv[1], "-c") != 0) {
            fprintf(stderr, "%s: syntax: %s [-c CMDSTR]\n", argv[0], argv[0]);
            exit(EXIT_FAILURE);
        }
        newargv[nargs++] = argv[1];
        newargv[nargs++] = argv[2];
    } else if (argc != 1) {
        fprintf(stderr, "%s: syntax: %s [-c CMDSTR]\n", argv[0], argv[0]);
        exit(EXIT_FAILURE);
    }
    newargv[nargs++] = uidstr;
    newargv[nargs++] = gidstr;
    newargv[nargs++] = NULL;

    assert(nargs <= G_N_ELEMENTS(newargv));

    if (term &&
        asprintf(&(newenv[0]), "TERM=%s", term) < 0) {
        fprintf(stderr, "%s: cannot set TERM env variable: %s\n",
                argv[0], strerror(errno));
        exit(EXIT_FAILURE);
    }

    assert(snprintf(uidstr, sizeof(uidstr), "%d", getuid()) < sizeof(uidstr));
    assert(snprintf(gidstr, sizeof(gidstr), "%d", getgid()) < sizeof(gidstr));

    if (setuid(0) < 0) {
        fprintf(stderr, "%s: unable to set real UID to root: %s\n",
                argv[0], strerror(errno));
        exit(EXIT_FAILURE);
    }

    execve(newargv[0], (char *const*)newargv, newenv);
    fprintf(stderr, "%s: failed to run %s/virt-login-shell-helper: %s\n",
            argv[0], LIBEXECDIR, strerror(errno));
    exit(EXIT_FAILURE);
}
