/*
 * virdevmapper.c: Functions for handling device mapper
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#ifdef MAJOR_IN_MKDEV
# include <sys/mkdev.h>
#elif MAJOR_IN_SYSMACROS
# include <sys/sysmacros.h>
#endif

#ifdef WITH_DEVMAPPER
# include <libdevmapper.h>
#endif

#include "virdevmapper.h"
#include "internal.h"
#include "virthread.h"
#include "viralloc.h"
#include "virstring.h"

#ifdef WITH_DEVMAPPER
static void
virDevMapperDummyLogger(int level G_GNUC_UNUSED,
                        const char *file G_GNUC_UNUSED,
                        int line G_GNUC_UNUSED,
                        int dm_errno G_GNUC_UNUSED,
                        const char *fmt G_GNUC_UNUSED,
                        ...)
{
    return;
}

static int
virDevMapperOnceInit(void)
{
    /* Ideally, we would not need this. But libdevmapper prints
     * error messages to stderr by default. Sad but true. */
    dm_log_with_errno_init(virDevMapperDummyLogger);
    return 0;
}


VIR_ONCE_GLOBAL_INIT(virDevMapper);


static int
virDevMapperGetTargetsImpl(const char *path,
                           char ***devPaths_ret,
                           unsigned int ttl)
{
    struct dm_task *dmt = NULL;
    struct dm_deps *deps;
    struct dm_info info;
    char **devPaths = NULL;
    char **recursiveDevPaths = NULL;
    size_t i;
    int ret = -1;

    *devPaths_ret = NULL;

    if (virDevMapperInitialize() < 0)
        return ret;

    if (ttl == 0) {
        errno = ELOOP;
        return ret;
    }

    if (!(dmt = dm_task_create(DM_DEVICE_DEPS))) {
        if (errno == ENOENT || errno == ENODEV) {
            /* It's okay. Kernel is probably built without
             * devmapper support. */
            ret = 0;
        }
        return ret;
    }

    if (!dm_task_set_name(dmt, path)) {
        if (errno == ENOENT) {
            /* It's okay, @path is not managed by devmapper =>
             * not a devmapper device. */
            ret = 0;
        }
        goto cleanup;
    }

    dm_task_no_open_count(dmt);

    if (!dm_task_run(dmt)) {
        if (errno == ENXIO) {
            /* If @path = "/dev/mapper/control" ENXIO is returned. */
            ret = 0;
        }
        goto cleanup;
    }

    if (!dm_task_get_info(dmt, &info))
        goto cleanup;

    if (!info.exists) {
        ret = 0;
        goto cleanup;
    }

    if (!(deps = dm_task_get_deps(dmt)))
        goto cleanup;

    if (VIR_ALLOC_N_QUIET(devPaths, deps->count + 1) < 0)
        goto cleanup;

    for (i = 0; i < deps->count; i++) {
        if (virAsprintfQuiet(&devPaths[i], "/dev/block/%u:%u",
                             major(deps->device[i]),
                             minor(deps->device[i])) < 0)
            goto cleanup;
    }

    recursiveDevPaths = NULL;
    for (i = 0; i < deps->count; i++) {
        char **tmpPaths;

        if (virDevMapperGetTargetsImpl(devPaths[i], &tmpPaths, ttl - 1) < 0)
            goto cleanup;

        if (tmpPaths &&
            virStringListMerge(&recursiveDevPaths, &tmpPaths) < 0) {
            virStringListFree(tmpPaths);
            goto cleanup;
        }
    }

    if (virStringListMerge(&devPaths, &recursiveDevPaths) < 0)
        goto cleanup;

    VIR_STEAL_PTR(*devPaths_ret, devPaths);
    ret = 0;
 cleanup:
    virStringListFree(recursiveDevPaths);
    virStringListFree(devPaths);
    dm_task_destroy(dmt);
    return ret;
}


/**
 * virDevMapperGetTargets:
 * @path: devmapper target
 * @devPaths: returned string list of devices
 *
 * For given @path figure out its targets, and store them in
 * @devPaths array. Note, @devPaths is a string list so it's NULL
 * terminated.
 *
 * If @path is not a devmapper device, @devPaths is set to NULL and
 * success is returned.
 *
 * If @path consists of yet another devmapper targets these are
 * consulted recursively.
 *
 * If we don't have permissions to talk to kernel, -1 is returned
 * and errno is set to EBADF.
 *
 * Returns 0 on success,
 *        -1 otherwise (with errno set, no libvirt error is
 *        reported)
 */
int
virDevMapperGetTargets(const char *path,
                       char ***devPaths)
{
    const unsigned int ttl = 32;

    /* Arbitrary limit on recursion level. A devmapper target can
     * consist of devices or yet another targets. If that's the
     * case, we have to stop recursion somewhere. */

    return virDevMapperGetTargetsImpl(path, devPaths, ttl);
}

#else /* ! WITH_DEVMAPPER */

int
virDevMapperGetTargets(const char *path G_GNUC_UNUSED,
                       char ***devPaths G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}
#endif /* ! WITH_DEVMAPPER */
