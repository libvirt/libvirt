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
# include "virstring.h"
# include "virerror.h"
# include "virlog.h"
# include "virfile.h"

# define VIR_FROM_THIS VIR_FROM_NONE

static int validateCgroup(virCgroupPtr cgroup,
                          const char *expectPath,
                          const char **expectMountPoint,
                          const char **expectLinkPoint,
                          const char **expectPlacement)
{
    size_t i;

    if (STRNEQ(cgroup->path, expectPath)) {
        fprintf(stderr, "Wrong path '%s', expected '%s'\n",
                cgroup->path, expectPath);
        return -1;
    }

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (STRNEQ_NULLABLE(expectMountPoint[i],
                            cgroup->controllers[i].mountPoint)) {
            fprintf(stderr, "Wrong mount '%s', expected '%s' for '%s'\n",
                    cgroup->controllers[i].mountPoint,
                    expectMountPoint[i],
                    virCgroupControllerTypeToString(i));
            return -1;
        }
        if (STRNEQ_NULLABLE(expectLinkPoint[i],
                            cgroup->controllers[i].linkPoint)) {
            fprintf(stderr, "Wrong link '%s', expected '%s' for '%s'\n",
                    cgroup->controllers[i].linkPoint,
                    expectLinkPoint[i],
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

const char *links[VIR_CGROUP_CONTROLLER_LAST] = {
    [VIR_CGROUP_CONTROLLER_CPU] = "/not/really/sys/fs/cgroup/cpu",
    [VIR_CGROUP_CONTROLLER_CPUACCT] = "/not/really/sys/fs/cgroup/cpuacct",
    [VIR_CGROUP_CONTROLLER_CPUSET] = NULL,
    [VIR_CGROUP_CONTROLLER_MEMORY] = NULL,
    [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
    [VIR_CGROUP_CONTROLLER_FREEZER] = NULL,
    [VIR_CGROUP_CONTROLLER_BLKIO] = NULL,
};


static int testCgroupNewForSelf(const void *args ATTRIBUTE_UNUSED)
{
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/system",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/system",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/",
    };

    if (virCgroupNewSelf(&cgroup) < 0) {
        fprintf(stderr, "Cannot create cgroup for self\n");
        goto cleanup;
    }

    ret = validateCgroup(cgroup, "", mountsFull, links, placement);

cleanup:
    virCgroupFree(&cgroup);
    return ret;
}


# define ENSURE_ERRNO(en)                                           \
    do {                                                            \
    if (!virLastErrorIsSystemErrno(en)) {                           \
        virErrorPtr err = virGetLastError();                        \
        fprintf(stderr, "Did not get " #en " error code: %d:%d\n",  \
                err ? err->code : 0, err ? err->int1 : 0);          \
        goto cleanup;                                               \
    } } while (0)

    /* Asking for impossible combination since CPU is co-mounted */


static int testCgroupNewForPartition(const void *args ATTRIBUTE_UNUSED)
{
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    int rv;
    const char *placementSmall[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_CPUSET] = NULL,
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = NULL,
        [VIR_CGROUP_CONTROLLER_BLKIO] = NULL,
    };
    const char *placementFull[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/virtualmachines.partition",
    };

    if ((rv = virCgroupNewPartition("/virtualmachines", false, -1, &cgroup)) != -1) {
        fprintf(stderr, "Unexpected found /virtualmachines cgroup: %d\n", -rv);
        goto cleanup;
    }
    ENSURE_ERRNO(ENOENT);

    /* Asking for impossible combination since CPU is co-mounted */
    if ((rv = virCgroupNewPartition("/virtualmachines", true,
                                    (1 << VIR_CGROUP_CONTROLLER_CPU),
                                    &cgroup)) != -1) {
        fprintf(stderr, "Should not have created /virtualmachines cgroup: %d\n", -rv);
        goto cleanup;
    }
    ENSURE_ERRNO(EINVAL);

    /* Asking for impossible combination since devices is not mounted */
    if ((rv = virCgroupNewPartition("/virtualmachines", true,
                                    (1 << VIR_CGROUP_CONTROLLER_DEVICES),
                                    &cgroup)) != -1) {
        fprintf(stderr, "Should not have created /virtualmachines cgroup: %d\n", -rv);
        goto cleanup;
    }
    ENSURE_ERRNO(ENXIO);

    /* Asking for small combination since devices is not mounted */
    if ((rv = virCgroupNewPartition("/virtualmachines", true,
                                    (1 << VIR_CGROUP_CONTROLLER_CPU) |
                                    (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
                                    (1 << VIR_CGROUP_CONTROLLER_MEMORY),
                                    &cgroup)) != 0) {
        fprintf(stderr, "Cannot create /virtualmachines cgroup: %d\n", -rv);
        goto cleanup;
    }
    ret = validateCgroup(cgroup, "/virtualmachines.partition", mountsSmall, links, placementSmall);
    virCgroupFree(&cgroup);

    if ((rv = virCgroupNewPartition("/virtualmachines", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Cannot create /virtualmachines cgroup: %d\n", -rv);
        goto cleanup;
    }
    ret = validateCgroup(cgroup, "/virtualmachines.partition", mountsFull, links, placementFull);

cleanup:
    virCgroupFree(&cgroup);
    return ret;
}


static int testCgroupNewForPartitionNested(const void *args ATTRIBUTE_UNUSED)
{
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    int rv;
    const char *placementFull[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/deployment.partition/production.partition",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/deployment.partition/production.partition",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/deployment.partition/production.partition",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/deployment.partition/production.partition",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/deployment.partition/production.partition",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/deployment.partition/production.partition",
    };

    if ((rv = virCgroupNewPartition("/deployment/production", false, -1, &cgroup)) != -1) {
        fprintf(stderr, "Unexpected found /deployment/production cgroup: %d\n", -rv);
        goto cleanup;
    }
    ENSURE_ERRNO(ENOENT);

    /* Should not work, since we require /deployment to be pre-created */
    if ((rv = virCgroupNewPartition("/deployment/production", true, -1, &cgroup)) != -1) {
        fprintf(stderr, "Unexpected created /deployment/production cgroup: %d\n", -rv);
        goto cleanup;
    }
    ENSURE_ERRNO(ENOENT);

    if ((rv = virCgroupNewPartition("/deployment", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Failed to create /deployment cgroup: %d\n", -rv);
        goto cleanup;
    }

    /* Should now work */
    if ((rv = virCgroupNewPartition("/deployment/production", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Failed to create /deployment/production cgroup: %d\n", -rv);
        goto cleanup;
    }

    ret = validateCgroup(cgroup, "/deployment.partition/production.partition",
                         mountsFull, links, placementFull);

cleanup:
    virCgroupFree(&cgroup);
    return ret;
}


static int testCgroupNewForPartitionNestedDeep(const void *args ATTRIBUTE_UNUSED)
{
    virCgroupPtr cgroup = NULL;
    int ret = -1;
    int rv;
    const char *placementFull[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/user/berrange.user/production.partition",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/user/berrange.user/production.partition",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/user/berrange.user/production.partition",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/user/berrange.user/production.partition",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/user/berrange.user/production.partition",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/user/berrange.user/production.partition",
    };

    if ((rv = virCgroupNewPartition("/user/berrange.user/production", false, -1, &cgroup)) != -1) {
        fprintf(stderr, "Unexpected found /user/berrange.user/production cgroup: %d\n", -rv);
        goto cleanup;
    }
    ENSURE_ERRNO(ENOENT);

    /* Should not work, since we require /user/berrange.user to be pre-created */
    if ((rv = virCgroupNewPartition("/user/berrange.user/production", true, -1, &cgroup)) != -1) {
        fprintf(stderr, "Unexpected created /user/berrange.user/production cgroup: %d\n", -rv);
        goto cleanup;
    }
    ENSURE_ERRNO(ENOENT);

    if ((rv = virCgroupNewPartition("/user", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Failed to create /user/berrange.user cgroup: %d\n", -rv);
        goto cleanup;
    }

    if ((rv = virCgroupNewPartition("/user/berrange.user", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Failed to create /user/berrange.user cgroup: %d\n", -rv);
        goto cleanup;
    }

    /* Should now work */
    if ((rv = virCgroupNewPartition("/user/berrange.user/production", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Failed to create /user/berrange.user/production cgroup: %d\n", -rv);
        goto cleanup;
    }

    ret = validateCgroup(cgroup, "/user/berrange.user/production.partition",
                         mountsFull, links, placementFull);

cleanup:
    virCgroupFree(&cgroup);
    return ret;
}



static int testCgroupNewForPartitionDomain(const void *args ATTRIBUTE_UNUSED)
{
    virCgroupPtr partitioncgroup = NULL;
    virCgroupPtr domaincgroup = NULL;
    int ret = -1;
    int rv;
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/production.partition/foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/production.partition/foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/production.partition/foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/production.partition/foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/production.partition/foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/production.partition/foo.libvirt-lxc",
    };

    if ((rv = virCgroupNewPartition("/production", true, -1, &partitioncgroup)) != 0) {
        fprintf(stderr, "Failed to create /production cgroup: %d\n", -rv);
        goto cleanup;
    }

    if ((rv = virCgroupNewDomainPartition(partitioncgroup, "lxc", "foo", true, &domaincgroup)) != 0) {
        fprintf(stderr, "Cannot create LXC cgroup: %d\n", -rv);
        goto cleanup;
    }

    ret = validateCgroup(domaincgroup, "/production.partition/foo.libvirt-lxc", mountsFull, links, placement);

cleanup:
    virCgroupFree(&partitioncgroup);
    virCgroupFree(&domaincgroup);
    return ret;
}

static int testCgroupNewForPartitionDomainEscaped(const void *args ATTRIBUTE_UNUSED)
{
    virCgroupPtr partitioncgroup1 = NULL;
    virCgroupPtr partitioncgroup2 = NULL;
    virCgroupPtr partitioncgroup3 = NULL;
    virCgroupPtr domaincgroup = NULL;
    int ret = -1;
    int rv;
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
    };

    if ((rv = virCgroupNewPartition("/cgroup.evil", true, -1, &partitioncgroup1)) != 0) {
        fprintf(stderr, "Failed to create /cgroup.evil cgroup: %d\n", -rv);
        goto cleanup;
    }

    if ((rv = virCgroupNewPartition("/cgroup.evil/net_cls.evil", true, -1, &partitioncgroup2)) != 0) {
        fprintf(stderr, "Failed to create /cgroup.evil/cpu.evil cgroup: %d\n", -rv);
        goto cleanup;
    }

    if ((rv = virCgroupNewPartition("/cgroup.evil/net_cls.evil/_evil.evil", true, -1, &partitioncgroup3)) != 0) {
        fprintf(stderr, "Failed to create /cgroup.evil cgroup: %d\n", -rv);
        goto cleanup;
    }

    if ((rv = virCgroupNewDomainPartition(partitioncgroup3, "lxc", "cpu.foo", true, &domaincgroup)) != 0) {
        fprintf(stderr, "Cannot create LXC cgroup: %d\n", -rv);
        goto cleanup;
    }

    /* NB we're not expecting 'net_cls.evil' to be escaped,
     * since our fake /proc/cgroups pretends this controller
     * isn't compiled into the kernel
     */
    ret = validateCgroup(domaincgroup, "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc", mountsFull, links, placement);

cleanup:
    virCgroupFree(&partitioncgroup3);
    virCgroupFree(&partitioncgroup2);
    virCgroupFree(&partitioncgroup1);
    virCgroupFree(&domaincgroup);
    return ret;
}

# define FAKESYSFSDIRTEMPLATE abs_builddir "/fakesysfsdir-XXXXXX"

static int
mymain(void)
{
    int ret = 0;
    char *fakesysfsdir;

    if (VIR_STRDUP_QUIET(fakesysfsdir, FAKESYSFSDIRTEMPLATE) < 0) {
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

    if (virtTestRun("New cgroup for partition", 1, testCgroupNewForPartition, NULL) < 0)
        ret = -1;

    if (virtTestRun("New cgroup for partition nested", 1, testCgroupNewForPartitionNested, NULL) < 0)
        ret = -1;

    if (virtTestRun("New cgroup for partition nested deeply", 1, testCgroupNewForPartitionNestedDeep, NULL) < 0)
        ret = -1;

    if (virtTestRun("New cgroup for domain partition", 1, testCgroupNewForPartitionDomain, NULL) < 0)
        ret = -1;

    if (virtTestRun("New cgroup for domain partition escaped", 1, testCgroupNewForPartitionDomainEscaped, NULL) < 0)
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
