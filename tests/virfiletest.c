/*
 * Copyright (C) 2013 Red Hat, Inc.
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
 */

#include <config.h>

#include <stdlib.h>
#include <fcntl.h>

#include "testutils.h"
#include "virfile.h"
#include "virstring.h"


#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
static int testFileCheckMounts(const char *prefix,
                               char **gotmounts,
                               size_t gotnmounts,
                               const char *const*wantmounts,
                               size_t wantnmounts)
{
    size_t i;
    if (gotnmounts != wantnmounts) {
        fprintf(stderr, "Expected %zu mounts under %s, but got %zu\n",
                wantnmounts, prefix, gotnmounts);
        return -1;
    }
    for (i = 0; i < gotnmounts; i++) {
        if (STRNEQ(gotmounts[i], wantmounts[i])) {
            fprintf(stderr, "Expected mount[%zu] '%s' but got '%s'\n",
                    i, wantmounts[i], gotmounts[i]);
            return -1;
        }
    }
    return 0;
}

struct testFileGetMountSubtreeData {
    const char *path;
    const char *prefix;
    const char *const *mounts;
    size_t nmounts;
    bool rev;
};

static int testFileGetMountSubtree(const void *opaque)
{
    int ret = -1;
    char **gotmounts = NULL;
    size_t gotnmounts = 0;
    const struct testFileGetMountSubtreeData *data = opaque;

    if (data->rev) {
        if (virFileGetMountReverseSubtree(data->path,
                                          data->prefix,
                                          &gotmounts,
                                          &gotnmounts) < 0)
            goto cleanup;
    } else {
        if (virFileGetMountSubtree(data->path,
                                   data->prefix,
                                   &gotmounts,
                                   &gotnmounts) < 0)
            goto cleanup;
    }

    ret = testFileCheckMounts(data->prefix,
                              gotmounts, gotnmounts,
                              data->mounts, data->nmounts);

 cleanup:
    virStringListFree(gotmounts);
    return ret;
}
#endif /* ! defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R */

struct testFileSanitizePathData
{
    const char *path;
    const char *expect;
};

static int
testFileSanitizePath(const void *opaque)
{
    const struct testFileSanitizePathData *data = opaque;
    int ret = -1;
    char *actual;

    if (!(actual = virFileSanitizePath(data->path)))
        return -1;

    if (STRNEQ(actual, data->expect)) {
        fprintf(stderr, "\nexpect: '%s'\nactual: '%s'\n", data->expect, actual);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(actual);
    return ret;
}


static int
makeSparseFile(const off_t offsets[],
               const bool startData);

#ifdef __linux__
/* Create a sparse file. @offsets in KiB. */
static int
makeSparseFile(const off_t offsets[],
               const bool startData)
{
    int fd = -1;
    char path[] = abs_builddir "fileInData.XXXXXX";
    off_t len = 0;
    size_t i;

    if ((fd = mkostemp(path,  O_CLOEXEC|O_RDWR)) < 0)
        goto error;

    if (unlink(path) < 0)
        goto error;

    for (i = 0; offsets[i] != (off_t) -1; i++)
        len += offsets[i] * 1024;

    while (len) {
        const char buf[] = "abcdefghijklmnopqrstuvwxyz";
        off_t toWrite = sizeof(buf);

        if (toWrite > len)
            toWrite = len;

        if (safewrite(fd, buf, toWrite) < 0) {
            fprintf(stderr, "unable to write to %s (errno=%d)\n", path, errno);
            goto error;
        }

        len -= toWrite;
    }

    len = 0;
    for (i = 0; offsets[i] != (off_t) -1; i++) {
        bool inData = startData;

        if (i % 2)
            inData = !inData;

        if (!inData &&
            fallocate(fd,
                      FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                      len, offsets[i] * 1024) < 0) {
            fprintf(stderr, "unable to punch a hole at offset %lld length %lld\n",
                    (long long) len, (long long) offsets[i]);
            goto error;
        }

        len += offsets[i] * 1024;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t) -1) {
        fprintf(stderr, "unable to lseek (errno=%d)\n", errno);
        goto error;
    }

    return fd;
 error:
    VIR_FORCE_CLOSE(fd);
    return -1;
}

#else /* !__linux__ */

static int
makeSparseFile(const off_t offsets[] ATTRIBUTE_UNUSED,
               const bool startData ATTRIBUTE_UNUSED)
{
    return -1;
}

#endif /* !__linux__ */


#define EXTENT 4
static bool
holesSupported(void)
{
    off_t offsets[] = {EXTENT, EXTENT, EXTENT, -1};
    off_t tmp;
    int fd;
    bool ret = false;

    if ((fd = makeSparseFile(offsets, true)) < 0)
        goto cleanup;

    /* The way this works is: there are 4K of data followed by 4K hole followed
     * by 4K hole again. Check if the filesystem we are running the test suite
     * on supports holes. */
    if ((tmp = lseek(fd, 0, SEEK_DATA)) == (off_t) -1)
        goto cleanup;

    if (tmp != 0)
        goto cleanup;

    if ((tmp = lseek(fd, tmp, SEEK_HOLE)) == (off_t) -1)
        goto cleanup;

    if (tmp != EXTENT * 1024)
        goto cleanup;

    if ((tmp = lseek(fd, tmp, SEEK_DATA)) == (off_t) -1)
        goto cleanup;

    if (tmp != 2 * EXTENT * 1024)
        goto cleanup;

    if ((tmp = lseek(fd, tmp, SEEK_HOLE)) == (off_t) -1)
        goto cleanup;

    if (tmp != 3 * EXTENT * 1024)
        goto cleanup;

    ret = true;
 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


struct testFileInData {
    bool startData;     /* whether the list of offsets starts with data section */
    off_t *offsets;
};


static int
testFileInData(const void *opaque)
{
    const struct testFileInData *data = opaque;
    int fd = -1;
    int ret = -1;
    size_t i;

    if ((fd = makeSparseFile(data->offsets, data->startData)) < 0)
        goto cleanup;

    for (i = 0; data->offsets[i] != (off_t) -1; i++) {
        bool shouldInData = data->startData;
        int realInData;
        long long shouldLen;
        long long realLen;

        if (i % 2)
            shouldInData = !shouldInData;

        if (virFileInData(fd, &realInData, &realLen) < 0)
            goto cleanup;

        if (realInData != shouldInData) {
            fprintf(stderr, "Unexpected data/hole. Expected %s got %s\n",
                    shouldInData ? "data" : "hole",
                    realInData ? "data" : "hole");
            goto cleanup;
        }

        shouldLen = data->offsets[i] * 1024;
        if (realLen != shouldLen) {
            fprintf(stderr, "Unexpected section length. Expected %lld got %lld\n",
                    shouldLen, realLen);
            goto cleanup;
        }

        if (lseek(fd, shouldLen, SEEK_CUR) < 0) {
            fprintf(stderr, "Unable to seek\n");
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;
    struct testFileSanitizePathData data1;

#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
# define MTAB_PATH1 abs_srcdir "/virfiledata/mounts1.txt"
# define MTAB_PATH2 abs_srcdir "/virfiledata/mounts2.txt"

    static const char *wantmounts1[] = {
        "/proc", "/proc/sys/fs/binfmt_misc", "/proc/sys/fs/binfmt_misc",
    };
    static const char *wantmounts1rev[] = {
        "/proc/sys/fs/binfmt_misc", "/proc/sys/fs/binfmt_misc", "/proc"
    };
    static const char *wantmounts2a[] = {
        "/etc/aliases"
    };
    static const char *wantmounts2b[] = {
        "/etc/aliases.db"
    };

# define DO_TEST_MOUNT_SUBTREE(name, path, prefix, mounts, rev)    \
    do {                                                           \
        struct testFileGetMountSubtreeData data = {                \
            path, prefix, mounts, ARRAY_CARDINALITY(mounts), rev   \
        };                                                         \
        if (virTestRun(name, testFileGetMountSubtree, &data) < 0)  \
            ret = -1;                                              \
    } while (0)

    DO_TEST_MOUNT_SUBTREE("/proc normal", MTAB_PATH1, "/proc", wantmounts1, false);
    DO_TEST_MOUNT_SUBTREE("/proc reverse", MTAB_PATH1, "/proc", wantmounts1rev, true);
    DO_TEST_MOUNT_SUBTREE("/etc/aliases", MTAB_PATH2, "/etc/aliases", wantmounts2a, false);
    DO_TEST_MOUNT_SUBTREE("/etc/aliases.db", MTAB_PATH2, "/etc/aliases.db", wantmounts2b, false);
#endif /* ! defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R */

#define DO_TEST_SANITIZE_PATH(PATH, EXPECT)                                    \
    do {                                                                       \
        data1.path = PATH;                                                     \
        data1.expect = EXPECT;                                                 \
        if (virTestRun(virTestCounterNext(), testFileSanitizePath,             \
                       &data1) < 0)                                            \
            ret = -1;                                                          \
    } while (0)

#define DO_TEST_SANITIZE_PATH_SAME(PATH) DO_TEST_SANITIZE_PATH(PATH, PATH)

    virTestCounterReset("testFileSanitizePath ");
    DO_TEST_SANITIZE_PATH("", "");
    DO_TEST_SANITIZE_PATH("/", "/");
    DO_TEST_SANITIZE_PATH("/path", "/path");
    DO_TEST_SANITIZE_PATH("/path/to/blah", "/path/to/blah");
    DO_TEST_SANITIZE_PATH("/path/", "/path");
    DO_TEST_SANITIZE_PATH("///////", "/");
    DO_TEST_SANITIZE_PATH("//", "//");
    DO_TEST_SANITIZE_PATH(".", ".");
    DO_TEST_SANITIZE_PATH("../", "..");
    DO_TEST_SANITIZE_PATH("../../", "../..");
    DO_TEST_SANITIZE_PATH("//foo//bar", "//foo/bar");
    DO_TEST_SANITIZE_PATH("/bar//foo", "/bar/foo");
    DO_TEST_SANITIZE_PATH_SAME("gluster://bar.baz/foo/hoo");
    DO_TEST_SANITIZE_PATH_SAME("gluster://bar.baz//fooo/hoo");
    DO_TEST_SANITIZE_PATH_SAME("gluster://bar.baz//////fooo/hoo");
    DO_TEST_SANITIZE_PATH_SAME("gluster://bar.baz/fooo//hoo");
    DO_TEST_SANITIZE_PATH_SAME("gluster://bar.baz/fooo///////hoo");

#define DO_TEST_IN_DATA(inData, ...)                                        \
    do {                                                                    \
        off_t offsets[] = {__VA_ARGS__, -1};                                \
        struct testFileInData data = {                                      \
            .startData = inData, .offsets = offsets,                        \
        };                                                                  \
        if (virTestRun(virTestCounterNext(), testFileInData, &data) < 0)    \
            ret = -1;                                                       \
    } while (0)

    if (holesSupported()) {
        DO_TEST_IN_DATA(true, 4, 4, 4);
        DO_TEST_IN_DATA(false, 4, 4, 4);
        DO_TEST_IN_DATA(true, 8, 8, 8);
        DO_TEST_IN_DATA(false, 8, 8, 8);
        DO_TEST_IN_DATA(true, 8, 16, 32, 64, 128, 256, 512);
        DO_TEST_IN_DATA(false, 8, 16, 32, 64, 128, 256, 512);
    }
    return ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

VIR_TEST_MAIN(mymain)
