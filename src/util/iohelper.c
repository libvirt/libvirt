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
runIO(const char *path, int fd, int oflags)
{
    VIR_AUTOFREE(void *) base = NULL; /* Location to be freed */
    char *buf = NULL; /* Aligned location within base */
    size_t buflen = 1024*1024;
    intptr_t alignMask = 64*1024 - 1;
    int ret = -1;
    int fdin, fdout;
    const char *fdinname, *fdoutname;
    unsigned long long total = 0;
    bool direct = O_DIRECT && ((oflags & O_DIRECT) != 0);
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
        if (direct && ((end = lseek(fd, 0, SEEK_CUR)) != 0)) {
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

        /* If we read with O_DIRECT from file we can't use saferead as
         * it can lead to unaligned read after reading last bytes.
         * If we write with O_DIRECT use should use saferead so that
         * writes will be aligned.
         * In other cases using saferead reduces number of syscalls.
         */
        if (fdin == fd && direct) {
            if ((got = read(fdin, buf, buflen)) < 0 &&
                errno == EINTR)
                continue;
        } else {
            got = saferead(fdin, buf, buflen);
        }

        if (got < 0) {
            virReportSystemError(errno, _("Unable to read %s"), fdinname);
            goto cleanup;
        }
        if (got == 0)
            break;

        total += got;

        /* handle last write size align in direct case */
        if (got < buflen && direct && fdout == fd) {
            ssize_t aligned_got = (got + alignMask) & ~alignMask;

            memset(buf + got, 0, aligned_got - got);

            if (safewrite(fdout, buf, aligned_got) < 0) {
                virReportSystemError(errno, _("Unable to write %s"), fdoutname);
                goto cleanup;
            }

            if (ftruncate(fd, total) < 0) {
                virReportSystemError(errno, _("Unable to truncate %s"), fdoutname);
                goto cleanup;
            }

            break;
        }

        if (safewrite(fdout, buf, got) < 0) {
            virReportSystemError(errno, _("Unable to write %s"), fdoutname);
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
    return ret;
}

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
    int oflags = -1;
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

    if (fd < 0 || runIO(path, fd, oflags) < 0)
        goto error;

    return 0;

 error:
    fprintf(stderr, _("%s: failure with %s: %s"),
            program_name, path, virGetLastErrorMessage());
    exit(EXIT_FAILURE);
}
