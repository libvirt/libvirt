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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 *
 * Current support
 *   - Read existing file
 *   - Write existing file
 *   - Create & write new file
 */

#include <config.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "virutil.h"
#include "virthread.h"
#include "virfile.h"
#include "viralloc.h"
#include "virerror.h"
#include "virrandom.h"
#include "virstring.h"
#include "virgettext.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

static int
prepare(const char *path, int oflags, int mode,
        unsigned long long offset)
{
    int fd = -1;

    if (oflags & O_CREAT) {
        fd = open(path, oflags, mode);
    } else {
        fd = open(path, oflags);
    }
    if (fd < 0) {
        virReportSystemError(errno, _("Unable to open %s"), path);
        goto cleanup;
    }

    if (offset) {
        if (lseek(fd, offset, SEEK_SET) < 0) {
            virReportSystemError(errno, _("Unable to seek %s to %llu"),
                                 path, offset);
            VIR_FORCE_CLOSE(fd);
            goto cleanup;
        }
    }

 cleanup:
    return fd;
}

static int
runIO(const char *path, int fd, int oflags, unsigned long long length)
{
    void *base = NULL; /* Location to be freed */
    char *buf = NULL; /* Aligned location within base */
    size_t buflen = 1024*1024;
    intptr_t alignMask = 64*1024 - 1;
    int ret = -1;
    int fdin, fdout;
    const char *fdinname, *fdoutname;
    unsigned long long total = 0;
    bool direct = O_DIRECT && ((oflags & O_DIRECT) != 0);
    bool shortRead = false; /* true if we hit a short read */
    off_t end = 0;

#if HAVE_POSIX_MEMALIGN
    if (posix_memalign(&base, alignMask + 1, buflen)) {
        virReportOOMError();
        goto cleanup;
    }
    buf = base;
#else
    if (VIR_ALLOC_N(buf, buflen + alignMask) < 0)
        goto cleanup;
    base = buf;
    buf = (char *) (((intptr_t) base + alignMask) & ~alignMask);
#endif

    switch (oflags & O_ACCMODE) {
    case O_RDONLY:
        fdin = fd;
        fdinname = path;
        fdout = STDOUT_FILENO;
        fdoutname = "stdout";
        /* To make the implementation simpler, we give up on any
         * attempt to use O_DIRECT in a non-trivial manner.  */
        if (direct && ((end = lseek(fd, 0, SEEK_CUR)) != 0 || length)) {
            virReportSystemError(end < 0 ? errno : EINVAL, "%s",
                                 _("O_DIRECT read needs entire seekable file"));
            goto cleanup;
        }
        break;
    case O_WRONLY:
        fdin = STDIN_FILENO;
        fdinname = "stdin";
        fdout = fd;
        fdoutname = path;
        /* To make the implementation simpler, we give up on any
         * attempt to use O_DIRECT in a non-trivial manner.  */
        if (direct && (end = lseek(fd, 0, SEEK_END)) != 0) {
            virReportSystemError(end < 0 ? errno : EINVAL, "%s",
                                 _("O_DIRECT write needs empty seekable file"));
            goto cleanup;
        }
        break;

    case O_RDWR:
    default:
        virReportSystemError(EINVAL,
                             _("Unable to process file with flags %d"),
                             (oflags & O_ACCMODE));
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
        if (got < buflen || (buflen & alignMask)) {
            /* O_DIRECT can handle at most one short read, at end of file */
            if (direct && shortRead) {
                virReportSystemError(EINVAL, "%s",
                                     _("Too many short reads for O_DIRECT"));
            }
            shortRead = true;
        }

        total += got;
        if (fdout == fd && direct && shortRead) {
            end = total;
            memset(buf + got, 0, buflen - got);
            got = (got + alignMask) & ~alignMask;
        }
        if (safewrite(fdout, buf, got) < 0) {
            virReportSystemError(errno, _("Unable to write %s"), fdoutname);
            goto cleanup;
        }
        if (end && ftruncate(fd, end) < 0) {
            virReportSystemError(errno, _("Unable to truncate %s"), fdoutname);
            goto cleanup;
        }
    }

    /* Ensure all data is written */
    if (fdatasync(fdout) < 0) {
        if (errno != EINVAL && errno != EROFS) {
            /* fdatasync() may fail on some special FDs, e.g. pipes */
            virReportSystemError(errno, _("unable to fsync %s"), fdoutname);
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

    VIR_FREE(base);
    return ret;
}

static const char *program_name;

ATTRIBUTE_NORETURN static void
usage(int status)
{
    if (status) {
        fprintf(stderr, _("%s: try --help for more details"), program_name);
    } else {
        printf(_("Usage: %s FILENAME OFLAGS MODE OFFSET LENGTH DELETE\n"
                 "   or: %s FILENAME LENGTH FD\n"),
               program_name, program_name);
    }
    exit(status);
}

int
main(int argc, char **argv)
{
    const char *path;
    unsigned long long offset;
    unsigned long long length;
    int oflags = -1;
    int mode;
    unsigned int delete = 0;
    int fd = -1;
    int lengthIndex = 0;

    program_name = argv[0];

    if (virGettextInitialize() < 0 ||
        virThreadInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%s: initialization failed\n"), program_name);
        exit(EXIT_FAILURE);
    }

    path = argv[1];

    if (argc > 1 && STREQ(argv[1], "--help"))
        usage(EXIT_SUCCESS);
    if (argc == 7) { /* FILENAME OFLAGS MODE OFFSET LENGTH DELETE */
        lengthIndex = 5;
        if (virStrToLong_i(argv[2], NULL, 10, &oflags) < 0) {
            fprintf(stderr, _("%s: malformed file flags %s"),
                    program_name, argv[2]);
            exit(EXIT_FAILURE);
        }
        if (virStrToLong_i(argv[3], NULL, 10, &mode) < 0) {
            fprintf(stderr, _("%s: malformed file mode %s"),
                    program_name, argv[3]);
            exit(EXIT_FAILURE);
        }
        if (virStrToLong_ull(argv[4], NULL, 10, &offset) < 0) {
            fprintf(stderr, _("%s: malformed file offset %s"),
                    program_name, argv[4]);
            exit(EXIT_FAILURE);
        }
        if (argc == 7 && virStrToLong_ui(argv[6], NULL, 10, &delete) < 0) {
            fprintf(stderr, _("%s: malformed delete flag %s"),
                    program_name, argv[6]);
            exit(EXIT_FAILURE);
        }
        fd = prepare(path, oflags, mode, offset);
    } else if (argc == 4) { /* FILENAME LENGTH FD */
        lengthIndex = 2;
        if (virStrToLong_i(argv[3], NULL, 10, &fd) < 0) {
            fprintf(stderr, _("%s: malformed fd %s"),
                    program_name, argv[3]);
            exit(EXIT_FAILURE);
        }
#ifdef F_GETFL
        oflags = fcntl(fd, F_GETFL);
#else
        /* Stupid mingw.  */
        if (fd == STDIN_FILENO)
            oflags = O_RDONLY;
        else if (fd == STDOUT_FILENO)
            oflags = O_WRONLY;
#endif
        if (oflags < 0) {
            fprintf(stderr, _("%s: unable to determine access mode of fd %d"),
                    program_name, fd);
            exit(EXIT_FAILURE);
        }
    } else { /* unknown argc pattern */
        usage(EXIT_FAILURE);
    }

    if (virStrToLong_ull(argv[lengthIndex], NULL, 10, &length) < 0) {
        fprintf(stderr, _("%s: malformed file length %s"),
                program_name, argv[lengthIndex]);
        exit(EXIT_FAILURE);
    }

    if (fd < 0 || runIO(path, fd, oflags, length) < 0)
        goto error;

    if (delete)
        unlink(path);

    return 0;

 error:
    fprintf(stderr, _("%s: failure with %s\n: %s"),
            program_name, path, virGetLastErrorMessage());
    exit(EXIT_FAILURE);
}
