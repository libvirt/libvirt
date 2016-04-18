/*
 * Copyright (C) 2016 Red Hat, Inc.
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
 * Author: Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>

#include "virmock.h"
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <execinfo.h>
#include <sys/file.h>

#include "internal.h"
#include "configmake.h"
#include "virstring.h"
#include "viralloc.h"
#include "virfile.h"

static int (*real_open)(const char *path, int flags, ...);
static FILE *(*real_fopen)(const char *path, const char *mode);
static int (*real_access)(const char *path, int mode);
static int (*real_stat)(const char *path, struct stat *sb);
static int (*real___xstat)(int ver, const char *path, struct stat *sb);
static int (*real_lstat)(const char *path, struct stat *sb);
static int (*real___lxstat)(int ver, const char *path, struct stat *sb);

static const char *progname;
const char *output;

#define VIR_FILE_ACCESS_DEFAULT abs_builddir "/test_file_access.txt"

static void init_syms(void)
{
    if (real_open)
        return;

    VIR_MOCK_REAL_INIT(open);
    VIR_MOCK_REAL_INIT(fopen);
    VIR_MOCK_REAL_INIT(access);
    VIR_MOCK_REAL_INIT_ALT(stat, __xstat);
    VIR_MOCK_REAL_INIT_ALT(lstat, __lxstat);
}

static void
printFile(const char *file)
{
    FILE *fp;
    const char *testname = getenv("VIR_TEST_MOCK_TESTNAME");

    if (!progname) {
        progname = getenv("VIR_TEST_MOCK_PROGNAME");

        if (!progname)
            return;

        output = getenv("VIR_TEST_FILE_ACCESS_OUTPUT");
        if (!output)
            output = VIR_FILE_ACCESS_DEFAULT;
    }

    if (!(fp = real_fopen(output, "a"))) {
        fprintf(stderr, "Unable to open %s: %s\n", output, strerror(errno));
        abort();
    }

    if (flock(fileno(fp), LOCK_EX) < 0) {
        fprintf(stderr, "Unable to lock %s: %s\n", output, strerror(errno));
        fclose(fp);
        abort();
    }

    /* Now append the following line into the output file:
     * $file: $progname $testname */

    fprintf(fp, "%s: %s", file, progname);
    if (testname)
        fprintf(fp, ": %s", testname);

    fputc('\n', fp);

    flock(fileno(fp), LOCK_UN);
    fclose(fp);
}

static void
checkPath(const char *path)
{
    char *fullPath = NULL;
    char *relPath = NULL;
    char *crippledPath = NULL;

    if (path[0] != '/' &&
        virAsprintfQuiet(&relPath, "./%s", path) < 0)
        goto error;

    /* Le sigh. Both canonicalize_file_name() and realpath()
     * expect @path to exist otherwise they return an error. So
     * if we are called over an non-existent file, this could
     * return an error. In that case do our best and hope we will
     * catch possible error. */
    if ((fullPath = canonicalize_file_name(relPath ? relPath : path))) {
        path = fullPath;
    } else {
        /* Yeah, our worst nightmares just became true. Path does
         * not exist. Cut off the last component and retry. */
        if (VIR_STRDUP_QUIET(crippledPath, relPath ? relPath : path) < 0)
            goto error;

        virFileRemoveLastComponent(crippledPath);

        if ((fullPath = canonicalize_file_name(crippledPath)))
            path = fullPath;
    }


    if (!STRPREFIX(path, abs_topsrcdir) &&
        !STRPREFIX(path, abs_topbuilddir)) {
        printFile(path);
    }

    VIR_FREE(crippledPath);
    VIR_FREE(relPath);
    VIR_FREE(fullPath);

    return;
 error:
    fprintf(stderr, "Out of memory\n");
    abort();
}


int open(const char *path, int flags, ...)
{
    int ret;

    init_syms();

    checkPath(path);

    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        ret = real_open(path, flags, mode);
    } else {
        ret = real_open(path, flags);
    }
    return ret;
}

FILE *fopen(const char *path, const char *mode)
{
    init_syms();

    checkPath(path);

    return real_fopen(path, mode);
}


int access(const char *path, int mode)
{
    init_syms();

    checkPath(path);

    return real_access(path, mode);
}

int stat(const char *path, struct stat *sb)
{
    init_syms();

    checkPath(path);

    return VIR_MOCK_CALL_STAT(_STAT_VER, path, sb);
}

int
__xstat(int ver, const char *path, struct stat *sb)
{
    init_syms();

    checkPath(path);

    return VIR_MOCK_CALL_STAT(ver, path, sb);
}

int
lstat(const char *path, struct stat *sb)
{
    init_syms();

    checkPath(path);

    return VIR_MOCK_CALL_LSTAT(_STAT_VER, path, sb);
}

int
__lxstat(int ver, const char *path, struct stat *sb)
{
    init_syms();

    checkPath(path);

    return VIR_MOCK_CALL_LSTAT(ver, path, sb);
}
