/*
 * iohelper.c: Helper program to perform I/O operations on files
 *
 * Copyright (C) 2011 Red Hat, Inc.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 *
 * Current support
 *   - Read existing file
 *   - Write existing file
 *   - Create & write new file
 */

#include <config.h>

#include <locale.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"
#include "threads.h"
#include "files.h"
#include "memory.h"
#include "virterror_internal.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

static int runIO(const char *path,
                 int flags,
                 int mode,
                 unsigned long long offset,
                 unsigned long long length)
{
    char *buf = NULL;
    size_t buflen = 1024*1024;
    int fd;
    int ret = -1;
    int fdin, fdout;
    const char *fdinname, *fdoutname;
    unsigned long long total = 0;

    if (flags & O_CREAT) {
        fd = open(path, flags, mode);
    } else {
        fd = open(path, flags);
    }
    if (fd < 0) {
        virReportSystemError(errno, _("Unable to open %s"), path);
        goto cleanup;
    }

    if (offset) {
        if (lseek(fd, offset, SEEK_SET) < 0) {
            virReportSystemError(errno, _("Unable to seek %s to %llu"),
                                 path, offset);
            goto cleanup;
        }
    }

    if (VIR_ALLOC_N(buf, buflen) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    switch (flags & O_ACCMODE) {
    case O_RDONLY:
        fdin = fd;
        fdinname = path;
        fdout = STDOUT_FILENO;
        fdoutname = "stdout";
        break;
    case O_WRONLY:
        fdin = STDIN_FILENO;
        fdinname = "stdin";
        fdout = fd;
        fdoutname = path;
        break;

    case O_RDWR:
    default:
        virReportSystemError(EINVAL,
                             _("Unable to process file with flags %d"),
                             (flags & O_ACCMODE));
        goto cleanup;
    }

    while (1) {
        ssize_t got;

        if (length &&
            (length - total) < buflen)
            buflen = length - total;

        if (buflen == 0)
            break; /* End of requested data from client */

        if ((got = saferead(fdin, buf, buflen)) < 0) {
            virReportSystemError(errno, _("Unable to read %s"), fdinname);
            goto cleanup;
        }
        if (got == 0)
            break; /* End of file before end of requested data */

        total += got;
        if (safewrite(fdout, buf, got) < 0) {
            virReportSystemError(errno, _("Unable to write %s"), fdoutname);
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    if (VIR_CLOSE(fd) < 0 &&
        ret == 0) {
        virReportSystemError(errno, _("Unable to close %s"), path);
        ret = -1;
    }

    VIR_FREE(buf);
    return ret;
}

int main(int argc, char **argv)
{
    const char *path;
    virErrorPtr err;
    unsigned long long offset;
    unsigned long long length;
    int flags;
    int mode;

    if (setlocale(LC_ALL, "") == NULL ||
        bindtextdomain(PACKAGE, LOCALEDIR) == NULL ||
        textdomain(PACKAGE) == NULL) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    if (virThreadInitialize() < 0 ||
        virErrorInitialize() < 0 ||
        virRandomInitialize(time(NULL) ^ getpid())) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    if (argc != 6) {
        fprintf(stderr, _("%s: syntax FILENAME FLAGS MODE OFFSET LENGTH\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    path = argv[1];

    if (virStrToLong_i(argv[2], NULL, 10, &flags) < 0) {
        fprintf(stderr, _("%s: malformed file flags %s"), argv[0], argv[2]);
        exit(EXIT_FAILURE);
    }

    if (virStrToLong_i(argv[3], NULL, 10, &mode) < 0) {
        fprintf(stderr, _("%s: malformed file mode %s"), argv[0], argv[3]);
        exit(EXIT_FAILURE);
    }

    if (virStrToLong_ull(argv[4], NULL, 10, &offset) < 0) {
        fprintf(stderr, _("%s: malformed file offset %s"), argv[0], argv[4]);
        exit(EXIT_FAILURE);
    }
    if (virStrToLong_ull(argv[5], NULL, 10, &length) < 0) {
        fprintf(stderr, _("%s: malformed file length %s"), argv[0], argv[5]);
        exit(EXIT_FAILURE);
    }

    if (runIO(path, flags, mode, offset, length) < 0)
        goto error;

    return 0;

error:
    err = virGetLastError();
    if (err) {
        fprintf(stderr, "%s: %s\n", argv[0], err->message);
    } else {
        fprintf(stderr, _("%s: unknown failure with %s\n"), argv[0], path);
    }
    exit(EXIT_FAILURE);
}
