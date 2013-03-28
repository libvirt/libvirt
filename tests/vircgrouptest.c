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

#include "testutils.h"

#ifdef __linux__

# include <stdlib.h>

# define __VIR_CGROUP_ALLOW_INCLUDE_PRIV_H__
# include "vircgrouppriv.h"
# include "virutil.h"
# include "virerror.h"
# include "virlog.h"
# include "virfile.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static int validateCgroup(virCgroupPtr cgroup,
                          const char *expectPath,
                          const char **expectMountPoint,
                          const char **expectPlacement)
{
    int i;

    if (STRNEQ(cgroup->path, expectPath)) {
        fprintf(stderr, "Wrong path '%s', expected '%s'\n",
                cgroup->path, expectPath);
        return -1;
    }

    for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
        if (STRNEQ_NULLABLE(expectMountPoint[i],
                            cgroup->controllers[i].mountPoint)) {
            fprintf(stderr, "Wrong mount '%s', expected '%s' for '%s'\n",
                    cgroup->controllers[i].mountPoint,
                    expectMountPoint[i],
                    virCgroupControllerTypeToString(i));
            return -1;
        }
        if (STRNEQ_NULLABLE(expectPlacement[i],
                            cgroup->controllers[i].placement)) {
            fprintf(stderr, "Wrong placement '%s', expected '%s' for '%s'\n",
                    cgroup->controllers[i].placement,
                    expectPlacement[i],
                    virCgroupControllerTypeToString(i));
            return -1;
        }
    }

    return 0;
}

const char *mountsSmall[VIR_CGROUP_CONTROLLER_LAST] = {
    [VIR_CGROUP_CONTROLLER_CPU] = "/not/really/sys/fs/cgroup/cpu,cpuacct",
    [VIR_CGROUP_CONTROLLER_CPUACCT] = "/not/really/sys/fs/cgroup/cpu,cpuacct",
    [VIR_CGROUP_CONTROLLER_CPUSET] = NULL,
    [VIR_CGROUP_CONTROLLER_MEMORY] = "/not/really/sys/fs/cgroup/memory",
    [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
    [VIR_CGROUP_CONTROLLER_FREEZER] = NULL,
    [VIR_CGROUP_CONTROLLER_BLKIO] = NULL,
};
const char *mountsFull[VIR_CGROUP_CONTROLLER_LAST] = {
    [VIR_CGROUP_CONTROLLER_CPU] = "/not/really/sys/fs/cgroup/cpu,cpuacct",
    [VIR_CGROUP_CONTROLLER_CPUACCT] = "/not/really/sys/fs/cgroup/cpu,cpuacct",
    [VIR_CGROUP_CONTROLLER_CPUSET] = "/not/really/sys/fs/cgroup/cpuset",
    [VIR_CGROUP_CONTROLLER_MEMORY] = "/not/really/sys/fs/cgroup/memory",
    [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
    [VIR_CGROUP_CONTROLLER_FREEZER] = "/not/really/sys/fs/cgroup/freezer",
    [VIR_CGROUP_CONTROLLER_BLKIO] = "/not/really/sys/fs/cgroup/blkio",
};

static int testCgroupNewForSelf(const void *args ATTRIBUTE_UNUSED)
{
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/system",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/system",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "",
    };

    if (virCgroupNewSelf(&cgroup) < 0) {
        fprintf(stderr, "Cannot create cgroup for self\n");
        goto cleanup;
    }

    ret = validateCgroup(cgroup, "/", mountsFull, placement);

cleanup:
    virCgroupFree(&cgroup);
    return ret;
}


static int testCgroupNewForDriver(const void *args ATTRIBUTE_UNUSED)
{
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    int rv;
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/system",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/system",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "",
    };

    if ((rv = virCgroupNewDriver("lxc", true, false, -1, &cgroup)) != -ENOENT) {
        fprintf(stderr, "Unexpected found LXC cgroup: %d\n", -rv);
        goto cleanup;
    }

    /* Asking for impossible combination since CPU is co-mounted */
    if ((rv = virCgroupNewDriver("lxc", true, true,
                                 (1 << VIR_CGROUP_CONTROLLER_CPU),
                                 &cgroup)) != -EINVAL) {
        fprintf(stderr, "Should not have created LXC cgroup: %d\n", -rv);
        goto cleanup;
    }

    /* Asking for impossible combination since devices is not mounted */
    if ((rv = virCgroupNewDriver("lxc", true, true,
                                 (1 << VIR_CGROUP_CONTROLLER_DEVICES),
                                 &cgroup)) != -ENOENT) {
        fprintf(stderr, "Should not have created LXC cgroup: %d\n", -rv);
        goto cleanup;
    }

    /* Asking for small combination since devices is not mounted */
    if ((rv = virCgroupNewDriver("lxc", true, true,
                                 (1 << VIR_CGROUP_CONTROLLER_CPU) |
                                 (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
                                 (1 << VIR_CGROUP_CONTROLLER_MEMORY),
                                 &cgroup)) != 0) {
        fprintf(stderr, "Cannot create LXC cgroup: %d\n", -rv);
        goto cleanup;
    }
    ret = validateCgroup(cgroup, "/libvirt/lxc", mountsSmall, placement);
    virCgroupFree(&cgroup);

    if ((rv = virCgroupNewDriver("lxc", true, true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Cannot create LXC cgroup: %d\n", -rv);
        goto cleanup;
    }
    ret = validateCgroup(cgroup, "/libvirt/lxc", mountsFull, placement);

cleanup:
    virCgroupFree(&cgroup);
    return ret;
}


static int testCgroupNewForDomain(const void *args ATTRIBUTE_UNUSED)
{
    virCgroupPtr drivercgroup = NULL;
    virCgroupPtr domaincgroup = NULL;
    int ret = -1;
    int rv;
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/system",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/system",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "",
    };

    if ((rv = virCgroupNewDriver("lxc", true, false, -1, &drivercgroup)) != 0) {
        fprintf(stderr, "Cannot find LXC cgroup: %d\n", -rv);
        goto cleanup;
    }

    if ((rv = virCgroupNewDomain(drivercgroup, "wibble", true, &domaincgroup)) != 0) {
        fprintf(stderr, "Cannot create LXC cgroup: %d\n", -rv);
        goto cleanup;
    }

    ret = validateCgroup(domaincgroup, "/libvirt/lxc/wibble", mountsFull, placement);

cleanup:
    virCgroupFree(&drivercgroup);
    virCgroupFree(&domaincgroup);
    return ret;
}


# define FAKESYSFSDIRTEMPLATE abs_builddir "/fakesysfsdir-XXXXXX"



static int
mymain(void)
{
    int ret = 0;
    char *fakesysfsdir;

    if (!(fakesysfsdir = strdup(FAKESYSFSDIRTEMPLATE))) {
        fprintf(stderr, "Out of memory\n");
        abort();
    }

    if (!mkdtemp(fakesysfsdir)) {
        fprintf(stderr, "Cannot create fakesysfsdir");
        abort();
    }

    setenv("LIBVIRT_FAKE_SYSFS_DIR", fakesysfsdir, 1);

    if (virtTestRun("New cgroup for self", 1, testCgroupNewForSelf, NULL) < 0)
        ret = -1;

    if (virtTestRun("New cgroup for driver", 1, testCgroupNewForDriver, NULL) < 0)
        ret = -1;

    if (virtTestRun("New cgroup for domain", 1, testCgroupNewForDomain, NULL) < 0)
        ret = -1;

    if (getenv("LIBVIRT_SKIP_CLEANUP") == NULL)
        virFileDeleteTree(fakesysfsdir);

    VIR_FREE(fakesysfsdir);

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/vircgroupmock.so")

#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
