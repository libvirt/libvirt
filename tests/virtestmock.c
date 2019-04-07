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
 */

#include <config.h>

#include "virmock.h"
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <execinfo.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_UN_H
# include <sys/un.h>
#endif

#include "internal.h"
#include "configmake.h"
#include "virstring.h"
#include "viralloc.h"
#include "virfile.h"

static int (*real_open)(const char *path, int flags, ...);
static FILE *(*real_fopen)(const char *path, const char *mode);
static int (*real_access)(const char *path, int mode);
static int (*real_connect)(int fd, const struct sockaddr *addr, socklen_t addrlen);

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
    VIR_MOCK_REAL_INIT(connect);
}

static void
printFile(const char *file,
          const char *func)
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
     * $file: $progname: $func: $testname */

    fprintf(fp, "%s: %s: %s", file, func, progname);
    if (testname)
        fprintf(fp, ": %s", testname);

    fputc('\n', fp);

    flock(fileno(fp), LOCK_UN);
    fclose(fp);
}

#define CHECK_PATH(path) \
    checkPath(path, __FUNCTION__)

static void
checkPath(const char *path,
          const char *func)
{
    char *fullPath = NULL;
    char *relPath = NULL;
    char *crippledPath = NULL;

    if (path[0] != '/' &&
        virAsprintfQuiet(&relPath, "./%s", path) < 0)
        goto error;

    /* Le sigh. virFileCanonicalizePath() expects @path to exist, otherwise
     * it will return an error. So if we are called over an non-existent
     * file, this could return an error. In that case do our best and hope
     * we will catch possible errors. */
    if ((fullPath = virFileCanonicalizePath(relPath ? relPath : path))) {
        path = fullPath;
    } else {
        /* Yeah, our worst nightmares just became true. Path does
         * not exist. Cut off the last component and retry. */
        if (VIR_STRDUP_QUIET(crippledPath, relPath ? relPath : path) < 0)
            goto error;

        virFileRemoveLastComponent(crippledPath);

        if ((fullPath = virFileCanonicalizePath(crippledPath)))
            path = fullPath;
    }


    if (!STRPREFIX(path, abs_top_srcdir) &&
        !STRPREFIX(path, abs_top_builddir)) {
        printFile(path, func);
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

    CHECK_PATH(path);

    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
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

    CHECK_PATH(path);

    return real_fopen(path, mode);
}


int access(const char *path, int mode)
{
    init_syms();

    CHECK_PATH(path);

    return real_access(path, mode);
}


#define VIR_MOCK_STAT_HOOK CHECK_PATH(path)

#include "virmockstathelpers.c"

static int virMockStatRedirect(const char *path ATTRIBUTE_UNUSED, char **newpath ATTRIBUTE_UNUSED)
{
    return 0;
}


int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    init_syms();

#ifdef HAVE_SYS_UN_H
    if (addrlen == sizeof(struct sockaddr_un)) {
        struct sockaddr_un *tmp = (struct sockaddr_un *) addr;
        if (tmp->sun_family == AF_UNIX)
            CHECK_PATH(tmp->sun_path);
    }
#endif

    return real_connect(sockfd, addr, addrlen);
}
