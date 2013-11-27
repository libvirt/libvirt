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
    virStringFreeList(gotmounts);
    return ret;
}
#endif /* ! defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R */

static int
mymain(void)
{
    int ret = 0;

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
        if (virtTestRun(name, testFileGetMountSubtree, &data) < 0) \
            ret = -1;                                              \
    } while (0)

    DO_TEST_MOUNT_SUBTREE("/proc normal", MTAB_PATH1, "/proc", wantmounts1, false);
    DO_TEST_MOUNT_SUBTREE("/proc reverse", MTAB_PATH1, "/proc", wantmounts1rev, true);
    DO_TEST_MOUNT_SUBTREE("/etc/aliases", MTAB_PATH2, "/etc/aliases", wantmounts2a, false);
    DO_TEST_MOUNT_SUBTREE("/etc/aliases.db", MTAB_PATH2, "/etc/aliases.db", wantmounts2b, false);
#endif /* ! defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R */

    return ret != 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

VIRT_TEST_MAIN(mymain)
