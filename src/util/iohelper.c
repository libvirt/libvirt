/*
 * iohelper.c: Helper program to perform I/O operations on files
 *
 * Copyright (C) 2011-2012 Red Hat, Inc.
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
 * Current support
 *   - Read existing file
 *   - Write existing file
 *   - Create & write new file
 */

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "virthread.h"
#include "virfile.h"
#include "viralloc.h"
#include "virerror.h"
#include "virrandom.h"
#include "virstring.h"
#include "virgettext.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

static const char *program_name;

G_GNUC_NORETURN static void
usage(int status)
{
    if (status) {
        fprintf(stderr, _("%s: try --help for more details"), program_name);
    } else {
        printf(_("Usage: %s FILENAME FD"), program_name);
    }
    exit(status);
}

int
main(int argc, char **argv)
{
    const char *path;
    int fd = -1;

    program_name = argv[0];

    if (virGettextInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%s: initialization failed"), program_name);
        exit(EXIT_FAILURE);
    }

    path = argv[1];

    if (argc > 1 && STREQ(argv[1], "--help"))
        usage(EXIT_SUCCESS);
    if (argc == 3) { /* FILENAME FD */
        if (virStrToLong_i(argv[2], NULL, 10, &fd) < 0) {
            fprintf(stderr, _("%s: malformed fd %s"),
                    program_name, argv[3]);
            exit(EXIT_FAILURE);
        }
    } else { /* unknown argc pattern */
        usage(EXIT_FAILURE);
    }

    if (fd < 0 || virFileDiskCopy(fd, path, -1, "stdio") < 0)
        goto error;

    return 0;

 error:
    fprintf(stderr, _("%s: failure with %s: %s"),
            program_name, path, virGetLastErrorMessage());
    exit(EXIT_FAILURE);
}
