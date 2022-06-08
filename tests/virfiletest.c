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
 */

#include <config.h>

#include <fcntl.h>
#include <unistd.h>

#include "testutils.h"
#include "virfile.h"

#ifdef __linux__
# include <linux/falloc.h>
#endif

#define VIR_FROM_THIS VIR_FROM_NONE

#if defined WITH_MNTENT_H && defined WITH_GETMNTENT_R
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
    g_auto(GStrv) gotmounts = NULL;
    size_t gotnmounts = 0;
    const struct testFileGetMountSubtreeData *data = opaque;

    if (data->rev) {
        if (virFileGetMountReverseSubtree(data->path,
                                          data->prefix,
                                          &gotmounts,
                                          &gotnmounts) < 0)
            return -1;
    } else {
        if (virFileGetMountSubtree(data->path,
                                   data->prefix,
                                   &gotmounts,
                                   &gotnmounts) < 0)
            return -1;
    }

    return testFileCheckMounts(data->prefix,
                               gotmounts, gotnmounts,
                               data->mounts, data->nmounts);
}
#endif /* ! defined WITH_MNTENT_H && defined WITH_GETMNTENT_R */

struct testFileSanitizePathData
{
    const char *path;
    const char *expect;
};

static int
testFileSanitizePath(const void *opaque)
{
    const struct testFileSanitizePathData *data = opaque;
    g_autofree char *actual = NULL;

    if (!(actual = virFileSanitizePath(data->path)))
        return -1;

    if (STRNEQ(actual, data->expect)) {
        fprintf(stderr, "\nexpect: '%s'\nactual: '%s'\n", data->expect, actual);
        return -1;
    }

    return 0;
}


#if WITH_DECL_SEEK_HOLE && defined(__linux__)

/* Create a sparse file. @offsets in KiB. */
static int
makeSparseFile(const off_t offsets[],
               const bool startData)
{
    int fd = -1;
    char path[] = abs_builddir "fileInData.XXXXXX";
    off_t len = 0;
    size_t i;

    if ((fd = g_mkstemp_full(path, O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR)) < 0)
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


# define EXTENT 4
static bool
holesSupported(void)
{
    off_t offsets[] = {EXTENT, EXTENT, EXTENT, -1};
    off_t tmp;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = makeSparseFile(offsets, true)) < 0)
        return false;

    /* The way this works is: there are 4K of data followed by 4K hole followed
     * by 4K hole again. Check if the filesystem we are running the test suite
     * on supports holes. */
    if ((tmp = lseek(fd, 0, SEEK_DATA)) == (off_t) -1)
        return false;

    if (tmp != 0)
        return false;

    if ((tmp = lseek(fd, tmp, SEEK_HOLE)) == (off_t) -1)
        return false;

    if (tmp != EXTENT * 1024)
        return false;

    if ((tmp = lseek(fd, tmp, SEEK_DATA)) == (off_t) -1)
        return false;

    if (tmp != 2 * EXTENT * 1024)
        return false;

    if ((tmp = lseek(fd, tmp, SEEK_HOLE)) == (off_t) -1)
        return false;

    if (tmp != 3 * EXTENT * 1024)
        return false;

    return true;
}

#else /* !WITH_DECL_SEEK_HOLE || !defined(__linux__)*/

static int
makeSparseFile(const off_t offsets[] G_GNUC_UNUSED,
               const bool startData G_GNUC_UNUSED)
{
    return -1;
}


static bool
holesSupported(void)
{
    return false;
}

#endif /* !WITH_DECL_SEEK_HOLE || !defined(__linux__)*/

struct testFileInData {
    bool startData;     /* whether the list of offsets starts with data section */
    off_t *offsets;
};


static int
testFileInData(const void *opaque)
{
    const struct testFileInData *data = opaque;
    VIR_AUTOCLOSE fd = -1;
    size_t i;

    if ((fd = makeSparseFile(data->offsets, data->startData)) < 0)
        return -1;

    for (i = 0; data->offsets[i] != (off_t) -1; i++) {
        bool shouldInData = data->startData;
        int realInData;
        long long shouldLen;
        long long realLen;

        if (i % 2)
            shouldInData = !shouldInData;

        if (virFileInData(fd, &realInData, &realLen) < 0)
            return -1;

        if (realInData != shouldInData) {
            fprintf(stderr, "Unexpected data/hole. Expected %s got %s\n",
                    shouldInData ? "data" : "hole",
                    realInData ? "data" : "hole");
            return -1;
        }

        shouldLen = data->offsets[i] * 1024;
        if (realLen != shouldLen) {
            fprintf(stderr, "Unexpected section length. Expected %lld got %lld\n",
                    shouldLen, realLen);
            return -1;
        }

        if (lseek(fd, shouldLen, SEEK_CUR) < 0) {
            fprintf(stderr, "Unable to seek\n");
            return -1;
        }
    }

    return 0;
}


struct testFileIsSharedFSType {
    const char *mtabFile;
    const char *filename;
    const bool expected;
};

static int
testFileIsSharedFSType(const void *opaque G_GNUC_UNUSED)
{
#ifndef __linux__
    return EXIT_AM_SKIP;
#else
    const struct testFileIsSharedFSType *data = opaque;
    g_autofree char *mtabFile = NULL;
    bool actual;
    int ret = -1;

    mtabFile = g_strdup_printf(abs_srcdir "/virfiledata/%s", data->mtabFile);

    if (g_setenv("LIBVIRT_MTAB", mtabFile, TRUE) == FALSE) {
        fprintf(stderr, "Unable to set env variable\n");
        goto cleanup;
    }

    actual = virFileIsSharedFS(data->filename);

    if (actual != data->expected) {
        fprintf(stderr, "Unexpected FS type. Expected %d got %d\n",
                data->expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    g_unsetenv("LIBVIRT_MTAB");
    return ret;
#endif
}


static int
mymain(void)
{
    int ret = 0;
    struct testFileSanitizePathData data1;

#if defined WITH_MNTENT_H && defined WITH_GETMNTENT_R
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

# define DO_TEST_MOUNT_SUBTREE(name, path, prefix, mounts, rev) \
    do { \
        struct testFileGetMountSubtreeData data = { \
            path, prefix, mounts, G_N_ELEMENTS(mounts), rev \
        }; \
        if (virTestRun(name, testFileGetMountSubtree, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_MOUNT_SUBTREE("/proc normal", MTAB_PATH1, "/proc", wantmounts1, false);
    DO_TEST_MOUNT_SUBTREE("/proc reverse", MTAB_PATH1, "/proc", wantmounts1rev, true);
    DO_TEST_MOUNT_SUBTREE("/etc/aliases", MTAB_PATH2, "/etc/aliases", wantmounts2a, false);
    DO_TEST_MOUNT_SUBTREE("/etc/aliases.db", MTAB_PATH2, "/etc/aliases.db", wantmounts2b, false);
#endif /* ! defined WITH_MNTENT_H && defined WITH_GETMNTENT_R */

#define DO_TEST_SANITIZE_PATH(PATH, EXPECT) \
    do { \
        data1.path = PATH; \
        data1.expect = EXPECT; \
        if (virTestRun(virTestCounterNext(), testFileSanitizePath, \
                       &data1) < 0) \
            ret = -1; \
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

#define DO_TEST_IN_DATA(inData, ...) \
    do { \
        off_t offsets[] = {__VA_ARGS__, -1}; \
        struct testFileInData data = { \
            .startData = inData, .offsets = offsets, \
        }; \
        if (virTestRun(virTestCounterNext(), testFileInData, &data) < 0) \
            ret = -1; \
    } while (0)

    if (holesSupported()) {
        virTestCounterReset("testFileInData ");
        DO_TEST_IN_DATA(true, 4, 4, 4);
        DO_TEST_IN_DATA(false, 4, 4, 4);
        DO_TEST_IN_DATA(true, 8, 8, 8);
        DO_TEST_IN_DATA(false, 8, 8, 8);
        DO_TEST_IN_DATA(true, 8, 16, 32, 64, 128, 256, 512);
        DO_TEST_IN_DATA(false, 8, 16, 32, 64, 128, 256, 512);
    }

#define DO_TEST_FILE_IS_SHARED_FS_TYPE(mtab, file, exp) \
    do { \
        struct testFileIsSharedFSType data = { \
            .mtabFile = mtab, .filename = file, .expected = exp \
        }; \
        if (virTestRun(virTestCounterNext(), testFileIsSharedFSType, &data) < 0) \
            ret = -1; \
    } while (0)

    virTestCounterReset("testFileIsSharedFSType ");
    DO_TEST_FILE_IS_SHARED_FS_TYPE("mounts1.txt", "/boot/vmlinuz", false);
    DO_TEST_FILE_IS_SHARED_FS_TYPE("mounts2.txt", "/run/user/501/gvfs/some/file", false);
    DO_TEST_FILE_IS_SHARED_FS_TYPE("mounts3.txt", "/nfs/file", true);
    DO_TEST_FILE_IS_SHARED_FS_TYPE("mounts3.txt", "/nfs/blah", false);
    DO_TEST_FILE_IS_SHARED_FS_TYPE("mounts3.txt", "/gluster/file", true);
    DO_TEST_FILE_IS_SHARED_FS_TYPE("mounts3.txt", "/gluster/sshfs/file", false);
    DO_TEST_FILE_IS_SHARED_FS_TYPE("mounts3.txt", "/some/symlink/file", true);
    DO_TEST_FILE_IS_SHARED_FS_TYPE("mounts3.txt", "/ceph/file", true);
    DO_TEST_FILE_IS_SHARED_FS_TYPE("mounts3.txt", "/ceph/multi/file", true);
    DO_TEST_FILE_IS_SHARED_FS_TYPE("mounts3.txt", "/gpfs/data", true);
    DO_TEST_FILE_IS_SHARED_FS_TYPE("mounts3.txt", "/quobyte", true);

    return ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

#ifdef __linux__
VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virfile"))
#else
VIR_TEST_MAIN(mymain)
#endif
