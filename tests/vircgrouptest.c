/*
 * Copyright (C) 2013-2015 Red Hat, Inc.
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

#include "testutils.h"

#ifdef __linux__


# define LIBVIRT_VIRCGROUPPRIV_H_ALLOW
# include "vircgrouppriv.h"
# include "virerror.h"
# include "virlog.h"
# include "virfile.h"
# include "virbuffer.h"
# include "testutilslxc.h"
# include "virhostcpu.h"

# define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("tests.cgrouptest");

static int validateCgroup(virCgroup *cgroup,
                          const char **expectMountPoint,
                          const char **expectLinkPoint,
                          const char **expectPlacement,
                          const char *expectUnifiedMountPoint,
                          const char *expectUnifiedPlacement,
                          unsigned int expectUnifiedControllers)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (STRNEQ_NULLABLE(expectMountPoint[i],
                            cgroup->legacy[i].mountPoint)) {
            fprintf(stderr, "Wrong mount '%s', expected '%s' for '%s'\n",
                    cgroup->legacy[i].mountPoint,
                    expectMountPoint[i],
                    virCgroupControllerTypeToString(i));
            return -1;
        }
        if (STRNEQ_NULLABLE(expectLinkPoint[i],
                            cgroup->legacy[i].linkPoint)) {
            fprintf(stderr, "Wrong link '%s', expected '%s' for '%s'\n",
                    cgroup->legacy[i].linkPoint,
                    expectLinkPoint[i],
                    virCgroupControllerTypeToString(i));
            return -1;
        }
        if (STRNEQ_NULLABLE(expectPlacement[i],
                            cgroup->legacy[i].placement)) {
            fprintf(stderr, "Wrong placement '%s', expected '%s' for '%s'\n",
                    cgroup->legacy[i].placement,
                    expectPlacement[i],
                    virCgroupControllerTypeToString(i));
            return -1;
        }
    }

    if (STRNEQ_NULLABLE(expectUnifiedMountPoint,
                        cgroup->unified.mountPoint)) {
        fprintf(stderr, "Wrong mount '%s', expected '%s' for 'unified'\n",
                cgroup->unified.mountPoint,
                expectUnifiedMountPoint);
        return -1;
    }
    if (STRNEQ_NULLABLE(expectUnifiedPlacement,
                        cgroup->unified.placement)) {
        fprintf(stderr, "Wrong placement '%s', expected '%s' for 'unified'\n",
                cgroup->unified.placement,
                expectUnifiedPlacement);
        return -1;
    }
    if (expectUnifiedControllers != cgroup->unified.controllers) {
        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            int type = 1 << i;
            if ((expectUnifiedControllers & type) != (cgroup->unified.controllers & type)) {
                const char *typeStr = virCgroupControllerTypeToString(i);
                if (expectUnifiedControllers & type) {
                    fprintf(stderr, "expected controller '%s' for 'unified', "
                            "but it's missing\n", typeStr);
                } else {
                    fprintf(stderr, "existing controller '%s' for 'unified', "
                            "but it's not expected\n", typeStr);
                }
            }

        }
        return -1;
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
    [VIR_CGROUP_CONTROLLER_SYSTEMD] = NULL,
};
const char *mountsFull[VIR_CGROUP_CONTROLLER_LAST] = {
    [VIR_CGROUP_CONTROLLER_CPU] = "/not/really/sys/fs/cgroup/cpu,cpuacct",
    [VIR_CGROUP_CONTROLLER_CPUACCT] = "/not/really/sys/fs/cgroup/cpu,cpuacct",
    [VIR_CGROUP_CONTROLLER_CPUSET] = "/not/really/sys/fs/cgroup/cpuset",
    [VIR_CGROUP_CONTROLLER_MEMORY] = "/not/really/sys/fs/cgroup/memory",
    [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
    [VIR_CGROUP_CONTROLLER_FREEZER] = "/not/really/sys/fs/cgroup/freezer",
    [VIR_CGROUP_CONTROLLER_BLKIO] = "/not/really/sys/fs/cgroup/blkio",
    [VIR_CGROUP_CONTROLLER_SYSTEMD] = "/not/really/sys/fs/cgroup/systemd",
};
const char *mountsAllInOne[VIR_CGROUP_CONTROLLER_LAST] = {
    [VIR_CGROUP_CONTROLLER_CPU] = "/not/really/sys/fs/cgroup",
    [VIR_CGROUP_CONTROLLER_CPUACCT] = "/not/really/sys/fs/cgroup",
    [VIR_CGROUP_CONTROLLER_CPUSET] = "/not/really/sys/fs/cgroup",
    [VIR_CGROUP_CONTROLLER_MEMORY] = "/not/really/sys/fs/cgroup",
    [VIR_CGROUP_CONTROLLER_DEVICES] = "/not/really/sys/fs/cgroup",
    [VIR_CGROUP_CONTROLLER_FREEZER] = NULL,
    [VIR_CGROUP_CONTROLLER_BLKIO] = "/not/really/sys/fs/cgroup",
    [VIR_CGROUP_CONTROLLER_SYSTEMD] = NULL,
};

const char *links[VIR_CGROUP_CONTROLLER_LAST] = {
    [VIR_CGROUP_CONTROLLER_CPU] = "/not/really/sys/fs/cgroup/cpu",
    [VIR_CGROUP_CONTROLLER_CPUACCT] = "/not/really/sys/fs/cgroup/cpuacct",
    [VIR_CGROUP_CONTROLLER_CPUSET] = NULL,
    [VIR_CGROUP_CONTROLLER_MEMORY] = NULL,
    [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
    [VIR_CGROUP_CONTROLLER_FREEZER] = NULL,
    [VIR_CGROUP_CONTROLLER_BLKIO] = NULL,
    [VIR_CGROUP_CONTROLLER_SYSTEMD] = NULL,
};

const char *linksAllInOne[VIR_CGROUP_CONTROLLER_LAST] = {
    [VIR_CGROUP_CONTROLLER_CPU] = NULL,
    [VIR_CGROUP_CONTROLLER_CPUACCT] = NULL,
    [VIR_CGROUP_CONTROLLER_CPUSET] = NULL,
    [VIR_CGROUP_CONTROLLER_MEMORY] = NULL,
    [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
    [VIR_CGROUP_CONTROLLER_FREEZER] = NULL,
    [VIR_CGROUP_CONTROLLER_BLKIO] = NULL,
    [VIR_CGROUP_CONTROLLER_SYSTEMD] = NULL,
};


struct _detectMountsData {
    const char *file;
    bool fail;
};


static int
testCgroupDetectMounts(const void *args)
{
    int result = -1;
    const struct _detectMountsData *data = args;
    g_autofree char *parsed = NULL;
    const char *actual;
    g_autoptr(virCgroup) group = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    g_setenv("VIR_CGROUP_MOCK_FILENAME", data->file, TRUE);

    parsed = g_strdup_printf("%s/vircgroupdata/%s.parsed", abs_srcdir, data->file);

    if (virCgroupNewSelf(&group) < 0) {
        if (data->fail)
            result = 0;
        goto cleanup;
    }

    if (data->fail)
        goto cleanup;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        virBufferAsprintf(&buf, "%-12s %s\n",
                          virCgroupControllerTypeToString(i),
                          NULLSTR(group->legacy[i].mountPoint));
    }
    virBufferAsprintf(&buf, "%-12s %s\n",
                      "unified", NULLSTR(group->unified.mountPoint));

    actual = virBufferCurrentContent(&buf);
    if (virTestCompareToFile(actual, parsed) < 0)
        goto cleanup;

    result = 0;

 cleanup:
    g_unsetenv("VIR_CGROUP_MOCK_FILENAME");
    return result;
}


static int testCgroupNewForSelf(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/system",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/system",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/",
        [VIR_CGROUP_CONTROLLER_SYSTEMD] = "/user/berrange/123",
    };

    if (virCgroupNewSelf(&cgroup) < 0) {
        fprintf(stderr, "Cannot create cgroup for self\n");
        return -1;
    }

    return validateCgroup(cgroup, mountsFull, links, placement, NULL, NULL, 0);
}


# define ENSURE_ERRNO(en) \
    do { \
    if (!virLastErrorIsSystemErrno(en)) { \
        virErrorPtr err = virGetLastError(); \
        fprintf(stderr, "Did not get " #en " error code: %d:%d\n", \
                err ? err->code : 0, err ? err->int1 : 0); \
        return -1; \
    } } while (0)

    /* Asking for impossible combination since CPU is co-mounted */


static int testCgroupNewForPartition(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    int rv;
    const char *placementSmall[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_CPUSET] = NULL,
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = NULL,
        [VIR_CGROUP_CONTROLLER_BLKIO] = NULL,
        [VIR_CGROUP_CONTROLLER_SYSTEMD] = NULL,
    };
    const char *placementFull[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/virtualmachines.partition",
        [VIR_CGROUP_CONTROLLER_SYSTEMD] = "/user/berrange/123",
    };

    if ((rv = virCgroupNewPartition("/virtualmachines", false, -1, &cgroup)) != -1) {
        fprintf(stderr, "Unexpected found /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }
    ENSURE_ERRNO(ENOENT);

    /* Asking for impossible combination since CPU is co-mounted */
    if ((rv = virCgroupNewPartition("/virtualmachines", true,
                                    (1 << VIR_CGROUP_CONTROLLER_CPU),
                                    &cgroup)) != -1) {
        fprintf(stderr, "Should not have created /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }
    ENSURE_ERRNO(EINVAL);

    /* Asking for impossible combination since devices is not mounted */
    if ((rv = virCgroupNewPartition("/virtualmachines", true,
                                    (1 << VIR_CGROUP_CONTROLLER_DEVICES),
                                    &cgroup)) != -1) {
        fprintf(stderr, "Should not have created /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }
    ENSURE_ERRNO(ENXIO);

    /* Asking for small combination since devices is not mounted */
    if ((rv = virCgroupNewPartition("/virtualmachines", true,
                                    (1 << VIR_CGROUP_CONTROLLER_CPU) |
                                    (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
                                    (1 << VIR_CGROUP_CONTROLLER_MEMORY),
                                    &cgroup)) != 0) {
        fprintf(stderr, "Cannot create /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }
    rv = validateCgroup(cgroup, mountsSmall, links, placementSmall, NULL, NULL, 0);
    virCgroupFree(cgroup);

    if ((rv = virCgroupNewPartition("/virtualmachines", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Cannot create /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }
    return validateCgroup(cgroup, mountsFull, links, placementFull, NULL, NULL, 0);
}


static int testCgroupNewForPartitionNested(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    int rv;
    const char *placementFull[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/deployment.partition/production.partition",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/deployment.partition/production.partition",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/deployment.partition/production.partition",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/deployment.partition/production.partition",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/deployment.partition/production.partition",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/deployment.partition/production.partition",
        [VIR_CGROUP_CONTROLLER_SYSTEMD] = "/user/berrange/123",
    };

    if ((rv = virCgroupNewPartition("/deployment/production", false, -1, &cgroup)) != -1) {
        fprintf(stderr, "Unexpected found /deployment/production cgroup: %d\n", -rv);
        return -1;
    }
    ENSURE_ERRNO(ENOENT);

    /* Should not work, since we require /deployment to be pre-created */
    if ((rv = virCgroupNewPartition("/deployment/production", true, -1, &cgroup)) != -1) {
        fprintf(stderr, "Unexpected created /deployment/production cgroup: %d\n", -rv);
        return -1;
    }
    ENSURE_ERRNO(ENOENT);

    if ((rv = virCgroupNewPartition("/deployment", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Failed to create /deployment cgroup: %d\n", -rv);
        return -1;
    }

    /* Should now work */
    virCgroupFree(cgroup);
    if ((rv = virCgroupNewPartition("/deployment/production", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Failed to create /deployment/production cgroup: %d\n", -rv);
        return -1;
    }

    return validateCgroup(cgroup, mountsFull, links, placementFull, NULL, NULL, 0);
}


static int testCgroupNewForPartitionNestedDeep(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    int rv;
    const char *placementFull[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/user/berrange.user/production.partition",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/user/berrange.user/production.partition",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/user/berrange.user/production.partition",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/user/berrange.user/production.partition",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/user/berrange.user/production.partition",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/user/berrange.user/production.partition",
        [VIR_CGROUP_CONTROLLER_SYSTEMD] = "/user/berrange/123",
    };

    if ((rv = virCgroupNewPartition("/user/berrange.user/production", false, -1, &cgroup)) != -1) {
        fprintf(stderr, "Unexpected found /user/berrange.user/production cgroup: %d\n", -rv);
        return -1;
    }
    ENSURE_ERRNO(ENOENT);

    /* Should not work, since we require /user/berrange.user to be pre-created */
    if ((rv = virCgroupNewPartition("/user/berrange.user/production", true, -1, &cgroup)) != -1) {
        fprintf(stderr, "Unexpected created /user/berrange.user/production cgroup: %d\n", -rv);
        return -1;
    }
    ENSURE_ERRNO(ENOENT);

    if ((rv = virCgroupNewPartition("/user", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Failed to create /user/berrange.user cgroup: %d\n", -rv);
        return -1;
    }

    virCgroupFree(cgroup);
    if ((rv = virCgroupNewPartition("/user/berrange.user", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Failed to create /user/berrange.user cgroup: %d\n", -rv);
        return -1;
    }

    /* Should now work */
    virCgroupFree(cgroup);
    if ((rv = virCgroupNewPartition("/user/berrange.user/production", true, -1, &cgroup)) != 0) {
        fprintf(stderr, "Failed to create /user/berrange.user/production cgroup: %d\n", -rv);
        return -1;
    }

    return validateCgroup(cgroup, mountsFull, links, placementFull, NULL, NULL, 0);
}



static int testCgroupNewForPartitionDomain(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) partitioncgroup = NULL;
    g_autoptr(virCgroup) domaincgroup = NULL;
    int rv;
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/production.partition/foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/production.partition/foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/production.partition/foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/production.partition/foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/production.partition/foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/production.partition/foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_SYSTEMD] = "/user/berrange/123",
    };

    if ((rv = virCgroupNewPartition("/production", true, -1, &partitioncgroup)) != 0) {
        fprintf(stderr, "Failed to create /production cgroup: %d\n", -rv);
        return -1;
    }

    if ((rv = virCgroupNewDomainPartition(partitioncgroup, "lxc", "foo", &domaincgroup)) != 0) {
        fprintf(stderr, "Cannot create LXC cgroup: %d\n", -rv);
        return -1;
    }

    return validateCgroup(domaincgroup, mountsFull, links, placement, NULL, NULL, 0);
}

static int testCgroupNewForPartitionDomainEscaped(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) partitioncgroup1 = NULL;
    g_autoptr(virCgroup) partitioncgroup2 = NULL;
    g_autoptr(virCgroup) partitioncgroup3 = NULL;
    g_autoptr(virCgroup) domaincgroup = NULL;
    int rv;
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_DEVICES] = NULL,
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/_cgroup.evil/net_cls.evil/__evil.evil/_cpu.foo.libvirt-lxc",
        [VIR_CGROUP_CONTROLLER_SYSTEMD] = "/user/berrange/123",
    };

    if ((rv = virCgroupNewPartition("/cgroup.evil", true, -1, &partitioncgroup1)) != 0) {
        fprintf(stderr, "Failed to create /cgroup.evil cgroup: %d\n", -rv);
        return -1;
    }

    if ((rv = virCgroupNewPartition("/cgroup.evil/net_cls.evil", true, -1, &partitioncgroup2)) != 0) {
        fprintf(stderr, "Failed to create /cgroup.evil/cpu.evil cgroup: %d\n", -rv);
        return -1;
    }

    if ((rv = virCgroupNewPartition("/cgroup.evil/net_cls.evil/_evil.evil", true, -1, &partitioncgroup3)) != 0) {
        fprintf(stderr, "Failed to create /cgroup.evil cgroup: %d\n", -rv);
        return -1;
    }

    if ((rv = virCgroupNewDomainPartition(partitioncgroup3, "lxc", "cpu.foo", &domaincgroup)) != 0) {
        fprintf(stderr, "Cannot create LXC cgroup: %d\n", -rv);
        return -1;
    }

    /* NB we're not expecting 'net_cls.evil' to be escaped,
     * since our fake /proc/cgroups pretends this controller
     * isn't compiled into the kernel
     */
    return validateCgroup(domaincgroup, mountsFull, links, placement, NULL, NULL, 0);
}

static int testCgroupNewForSelfAllInOne(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPU] = "/",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/",
        [VIR_CGROUP_CONTROLLER_DEVICES] = "/",
        [VIR_CGROUP_CONTROLLER_FREEZER] = NULL,
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/",
    };

    if (virCgroupNewSelf(&cgroup) < 0) {
        fprintf(stderr, "Cannot create cgroup for self\n");
        return -1;
    }

    return validateCgroup(cgroup, mountsAllInOne, linksAllInOne, placement, NULL, NULL, 0);
}


static int testCgroupNewForSelfLogind(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;

    if (virCgroupNewSelf(&cgroup) >= 0) {
        fprintf(stderr, "Expected to fail, only systemd cgroup available.\n");
        return -1;
    }

    return 0;
}


static int testCgroupNewForSelfUnified(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    const char *empty[VIR_CGROUP_CONTROLLER_LAST] = { 0 };
    unsigned int controllers =
        (1 << VIR_CGROUP_CONTROLLER_CPU) |
        (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
        (1 << VIR_CGROUP_CONTROLLER_MEMORY) |
        (1 << VIR_CGROUP_CONTROLLER_DEVICES) |
        (1 << VIR_CGROUP_CONTROLLER_BLKIO);

    if (virCgroupNewSelf(&cgroup) < 0) {
        fprintf(stderr, "Cannot create cgroup for self\n");
        return -1;
    }

    return validateCgroup(cgroup, empty, empty, empty,
                          "/not/really/sys/fs/cgroup", "/", controllers);
}


static int testCgroupNewForSelfHybrid(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    const char *empty[VIR_CGROUP_CONTROLLER_LAST] = { 0 };
    const char *mounts[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/not/really/sys/fs/cgroup/cpuset",
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/not/really/sys/fs/cgroup/freezer",
        [VIR_CGROUP_CONTROLLER_NET_CLS] = "/not/really/sys/fs/cgroup/net_cls",
        [VIR_CGROUP_CONTROLLER_PERF_EVENT] = "/not/really/sys/fs/cgroup/perf_event",
    };
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/",
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/",
        [VIR_CGROUP_CONTROLLER_NET_CLS] = "/",
        [VIR_CGROUP_CONTROLLER_PERF_EVENT] = "/",
    };
    unsigned int controllers =
        (1 << VIR_CGROUP_CONTROLLER_CPU) |
        (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
        (1 << VIR_CGROUP_CONTROLLER_MEMORY) |
        (1 << VIR_CGROUP_CONTROLLER_DEVICES) |
        (1 << VIR_CGROUP_CONTROLLER_BLKIO);

    if (virCgroupNewSelf(&cgroup) < 0) {
        fprintf(stderr, "Cannot create cgroup for self\n");
        return -1;
    }

    return validateCgroup(cgroup, mounts, empty, placement,
                          "/not/really/sys/fs/cgroup/unified", "/", controllers);
}


static int testCgroupNewForSelfSystemdLegacy(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    const char *empty[VIR_CGROUP_CONTROLLER_LAST] = { 0 };
    const char *mounts[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_BLKIO] = "/not/really/sys/fs/cgroup/blkio",
        [VIR_CGROUP_CONTROLLER_CPU] = "/not/really/sys/fs/cgroup/cpu",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "/not/really/sys/fs/cgroup/cpuacct",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "/not/really/sys/fs/cgroup/cpuset",
        [VIR_CGROUP_CONTROLLER_DEVICES] = "/not/really/sys/fs/cgroup/devices",
        [VIR_CGROUP_CONTROLLER_FREEZER] = "/not/really/sys/fs/cgroup/freezer",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "/not/really/sys/fs/cgroup/memory",
        [VIR_CGROUP_CONTROLLER_NET_CLS] = "/not/really/sys/fs/cgroup/net_cls",
        [VIR_CGROUP_CONTROLLER_PERF_EVENT] = "/not/really/sys/fs/cgroup/perf_event",
    };
    const char *placement[VIR_CGROUP_CONTROLLER_LAST] = {
        [VIR_CGROUP_CONTROLLER_BLKIO] = "",
        [VIR_CGROUP_CONTROLLER_CPU] = "",
        [VIR_CGROUP_CONTROLLER_CPUACCT] = "",
        [VIR_CGROUP_CONTROLLER_CPUSET] = "",
        [VIR_CGROUP_CONTROLLER_DEVICES] = "",
        [VIR_CGROUP_CONTROLLER_FREEZER] = "",
        [VIR_CGROUP_CONTROLLER_MEMORY] = "",
        [VIR_CGROUP_CONTROLLER_NET_CLS] = "",
        [VIR_CGROUP_CONTROLLER_PERF_EVENT] = "",
    };

    if (virCgroupNewSelf(&cgroup) < 0) {
        fprintf(stderr, "Cannot create cgroup for self\n");
        return -1;
    }

    return validateCgroup(cgroup, mounts, empty, placement, NULL, NULL, 0);
}


static int testCgroupNewForSelfSystemdUnified(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    const char *empty[VIR_CGROUP_CONTROLLER_LAST] = { 0 };
    unsigned int controllers =
        (1 << VIR_CGROUP_CONTROLLER_CPU) |
        (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
        (1 << VIR_CGROUP_CONTROLLER_MEMORY) |
        (1 << VIR_CGROUP_CONTROLLER_DEVICES) |
        (1 << VIR_CGROUP_CONTROLLER_BLKIO);

    if (virCgroupNewSelf(&cgroup) < 0) {
        fprintf(stderr, "Cannot create cgroup for self\n");
        return -1;
    }

    return validateCgroup(cgroup, empty, empty, empty,
                          "/not/really/sys/fs/cgroup", "",
                          controllers);
}


static int testCgroupAvailable(const void *args)
{
    bool got = virCgroupAvailable();
    bool want = args == (void*)0x1;

    if (got != want) {
        fprintf(stderr, "Expected cgroup %savailable, but state was wrong\n",
                want ? "" : "not ");
        return -1;
    }

    return 0;
}

static int testCgroupControllerAvailable(const void *args G_GNUC_UNUSED)
{
    int ret = 0;

# define CHECK_CONTROLLER(c, present) \
    if ((present && !virCgroupControllerAvailable(c)) || \
        (!present && virCgroupControllerAvailable(c))) { \
        fprintf(stderr, present ? \
                "Expected controller %s not available\n" : \
                "Unexpected controller %s available\n", #c); \
        ret = -1; \
    }

    CHECK_CONTROLLER(VIR_CGROUP_CONTROLLER_CPU, true)
    CHECK_CONTROLLER(VIR_CGROUP_CONTROLLER_CPUACCT, true)
    CHECK_CONTROLLER(VIR_CGROUP_CONTROLLER_CPUSET, true)
    CHECK_CONTROLLER(VIR_CGROUP_CONTROLLER_MEMORY, true)
    CHECK_CONTROLLER(VIR_CGROUP_CONTROLLER_DEVICES, false)
    CHECK_CONTROLLER(VIR_CGROUP_CONTROLLER_FREEZER, true)
    CHECK_CONTROLLER(VIR_CGROUP_CONTROLLER_BLKIO, true)
    CHECK_CONTROLLER(VIR_CGROUP_CONTROLLER_NET_CLS, false)
    CHECK_CONTROLLER(VIR_CGROUP_CONTROLLER_PERF_EVENT, false)
    CHECK_CONTROLLER(VIR_CGROUP_CONTROLLER_SYSTEMD, true)

# undef CHECK_CONTROLLER
    return ret;
}

static int testCgroupGetPercpuStats(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    size_t i;
    int rv, ret = -1;
    virTypedParameterPtr params = NULL;
# define EXPECTED_NCPUS 160

    unsigned long long expected[EXPECTED_NCPUS] = {
        0, 0, 0, 0, 0, 0, 0, 0,
        7059492996ULL, 0, 0, 0, 0, 0, 0, 0,
        4180532496ULL, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        1957541268ULL, 0, 0, 0, 0, 0, 0, 0,
        2065932204ULL, 0, 0, 0, 0, 0, 0, 0,
        18228689414ULL, 0, 0, 0, 0, 0, 0, 0,
        4245525148ULL, 0, 0, 0, 0, 0, 0, 0,
        2911161568ULL, 0, 0, 0, 0, 0, 0, 0,
        1407758136ULL, 0, 0, 0, 0, 0, 0, 0,
        1836807700ULL, 0, 0, 0, 0, 0, 0, 0,
        1065296618ULL, 0, 0, 0, 0, 0, 0, 0,
        2046213266ULL, 0, 0, 0, 0, 0, 0, 0,
        747889778ULL, 0, 0, 0, 0, 0, 0, 0,
        709566900ULL, 0, 0, 0, 0, 0, 0, 0,
        444777342ULL, 0, 0, 0, 0, 0, 0, 0,
        5683512916ULL, 0, 0, 0, 0, 0, 0, 0,
        635751356ULL, 0, 0, 0, 0, 0, 0, 0,
    };

    params = g_new0(virTypedParameter, EXPECTED_NCPUS);

    if ((rv = virCgroupNewPartition("/virtualmachines", true,
                                    (1 << VIR_CGROUP_CONTROLLER_CPU) |
                                    (1 << VIR_CGROUP_CONTROLLER_CPUACCT),
                                    &cgroup)) < 0) {
        fprintf(stderr, "Could not create /virtualmachines cgroup: %d\n", -rv);
        goto cleanup;
    }

    if (virHostCPUGetCount() != EXPECTED_NCPUS) {
        fprintf(stderr, "Unexpected: virHostCPUGetCount() yields: %d\n", virHostCPUGetCount());
        goto cleanup;
    }

    if ((rv = virCgroupGetPercpuStats(cgroup,
                                      params,
                                      1, 0, EXPECTED_NCPUS, NULL)) < 0) {
        fprintf(stderr, "Failed call to virCgroupGetPercpuStats for /virtualmachines cgroup: %d\n", -rv);
        goto cleanup;
    }

    for (i = 0; i < EXPECTED_NCPUS; i++) {
        if (STRNEQ(params[i].field, VIR_DOMAIN_CPU_STATS_CPUTIME)) {
            fprintf(stderr,
                    "Wrong parameter name value from virCgroupGetPercpuStats at %zu (is: %s)\n",
                    i, params[i].field);
            goto cleanup;
        }

        if (params[i].type != VIR_TYPED_PARAM_ULLONG) {
            fprintf(stderr,
                    "Wrong parameter value type from virCgroupGetPercpuStats at %zu (is: %d)\n",
                    i, params[i].type);
            goto cleanup;
        }

        if (params[i].value.ul != expected[i]) {
            fprintf(stderr,
                    "Wrong value from virCgroupGetPercpuStats at %zu (expected %llu)\n",
                    i, params[i].value.ul);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    VIR_FREE(params);
    return ret;
}

static int testCgroupGetMemoryUsage(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    int rv;
    unsigned long kb;

    if ((rv = virCgroupNewPartition("/virtualmachines", true,
                                    (1 << VIR_CGROUP_CONTROLLER_MEMORY),
                                    &cgroup)) < 0) {
        fprintf(stderr, "Could not create /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }

    if ((rv = virCgroupGetMemoryUsage(cgroup, &kb)) < 0) {
        fprintf(stderr, "Could not retrieve GetMemoryUsage for /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }

    if (kb != 1421212UL) {
        fprintf(stderr,
                "Wrong value from virCgroupGetMemoryUsage (expected %ld)\n",
                1421212UL);
        return -1;
    }

    return 0;
}


static int
testCgroupGetMemoryStat(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    int rv;
    size_t i;

    const unsigned long long expected_values[] = {
        1336619008ULL,
        67100672ULL,
        145887232ULL,
        661872640ULL,
        627400704UL,
        3690496ULL
    };
    const char* names[] = {
        "cache",
        "active_anon",
        "inactive_anon",
        "active_file",
        "inactive_file",
        "unevictable"
    };
    unsigned long long values[G_N_ELEMENTS(expected_values)];

    if ((rv = virCgroupNewPartition("/virtualmachines", true,
                                    (1 << VIR_CGROUP_CONTROLLER_MEMORY),
                                    &cgroup)) < 0) {
        fprintf(stderr, "Could not create /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }

    if ((rv = virCgroupGetMemoryStat(cgroup, &values[0],
                                     &values[1], &values[2],
                                     &values[3], &values[4],
                                     &values[5])) < 0) {
        fprintf(stderr, "Could not retrieve GetMemoryStat for /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }

    for (i = 0; i < G_N_ELEMENTS(expected_values); i++) {
        /* NB: virCgroupGetMemoryStat returns a KiB scaled value */
        if ((expected_values[i] >> 10) != values[i]) {
            fprintf(stderr,
                    "Wrong value (%llu) for %s from virCgroupGetMemoryStat "
                    "(expected %llu)\n",
                    values[i], names[i], (expected_values[i] >> 10));
            return -1;
        }
    }

    return 0;
}


static int testCgroupGetBlkioIoServiced(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    size_t i;
    int rv;

    const long long expected_values[] = {
        119084214273ULL,
        822880960513ULL,
        9665167,
        73283807
    };
    const char* names[] = {
        "bytes read",
        "bytes written",
        "requests read",
        "requests written"
    };
    long long values[G_N_ELEMENTS(expected_values)];

    if ((rv = virCgroupNewPartition("/virtualmachines", true,
                                    (1 << VIR_CGROUP_CONTROLLER_BLKIO),
                                    &cgroup)) < 0) {
        fprintf(stderr, "Could not create /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }

    if ((rv = virCgroupGetBlkioIoServiced(cgroup,
                                          values, &values[1],
                                          &values[2], &values[3])) < 0) {
        fprintf(stderr, "Could not retrieve BlkioIoServiced for /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }

    for (i = 0; i < G_N_ELEMENTS(expected_values); i++) {
        if (expected_values[i] != values[i]) {
            fprintf(stderr,
                    "Wrong value for %s from virCgroupBlkioIoServiced (expected %lld)\n",
                    names[i], expected_values[i]);
            return -1;
        }
    }

    return 0;
}

static int testCgroupGetBlkioIoDeviceServiced(const void *args G_GNUC_UNUSED)
{
    g_autoptr(virCgroup) cgroup = NULL;
    size_t i;
    int rv;
    const long long expected_values0[] = {
        59542107136ULL,
        411440480256ULL,
        4832583,
        36641903
    };
    const long long expected_values1[] = {
        59542107137ULL,
        411440480257ULL,
        4832584,
        36641904
    };
    const char* names[] = {
        "bytes read",
        "bytes written",
        "requests read",
        "requests written"
    };
    long long values[G_N_ELEMENTS(expected_values0)];

    if ((rv = virCgroupNewPartition("/virtualmachines", true,
                                    (1 << VIR_CGROUP_CONTROLLER_BLKIO),
                                    &cgroup)) < 0) {
        fprintf(stderr, "Could not create /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }

    if ((rv = virCgroupGetBlkioIoDeviceServiced(cgroup,
                                                FAKEDEVDIR0,
                                                values, &values[1],
                                                &values[2], &values[3])) < 0) {
        fprintf(stderr, "Could not retrieve BlkioIoDeviceServiced for /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }

    for (i = 0; i < G_N_ELEMENTS(expected_values0); i++) {
        if (expected_values0[i] != values[i]) {
            fprintf(stderr,
                    "Wrong value for %s from virCgroupGetBlkioIoDeviceServiced (expected %lld)\n",
                    names[i], expected_values0[i]);
            return -1;
        }
    }

    if ((rv = virCgroupGetBlkioIoDeviceServiced(cgroup,
                                                FAKEDEVDIR1,
                                                values, &values[1],
                                                &values[2], &values[3])) < 0) {
        fprintf(stderr, "Could not retrieve BlkioIoDeviceServiced for /virtualmachines cgroup: %d\n", -rv);
        return -1;
    }

    for (i = 0; i < G_N_ELEMENTS(expected_values1); i++) {
        if (expected_values1[i] != values[i]) {
            fprintf(stderr,
                    "Wrong value for %s from virCgroupGetBlkioIoDeviceServiced (expected %lld)\n",
                    names[i], expected_values1[i]);
            return -1;
        }
    }

    return 0;
}

static char *
initFakeFS(const char *mode,
           const char *filename)
{
    char *fakerootdir;

    if (!(fakerootdir = virTestFakeRootDirInit()))
        abort();

    if (mode)
        g_setenv("VIR_CGROUP_MOCK_MODE", mode, TRUE);

    if (filename)
        g_setenv("VIR_CGROUP_MOCK_FILENAME", filename, TRUE);

    return fakerootdir;
}

static void
cleanupFakeFS(char *fakerootdir)
{
    g_unsetenv("VIR_CGROUP_MOCK_MODE");
    g_unsetenv("VIR_CGROUP_MOCK_FILENAME");

    virTestFakeRootDirCleanup(fakerootdir);
    VIR_FREE(fakerootdir);
}

static int
mymain(void)
{
    int ret = 0;
    char *fakerootdir;

# define DETECT_MOUNTS_FULL(file, fail) \
    do { \
        struct _detectMountsData data = { file, fail }; \
        if (virTestRun("Detect cgroup mounts for " file, \
                       testCgroupDetectMounts, \
                       &data) < 0) \
            ret = -1; \
    } while (0)
# define DETECT_MOUNTS(file) DETECT_MOUNTS_FULL(file, false);
# define DETECT_MOUNTS_FAIL(file) DETECT_MOUNTS_FULL(file, true);

    DETECT_MOUNTS("ovirt-node-6.6");
    DETECT_MOUNTS("ovirt-node-7.1");
    DETECT_MOUNTS("fedora-18");
    DETECT_MOUNTS("fedora-21");
    DETECT_MOUNTS("rhel-7.1");
    DETECT_MOUNTS("cgroups1");
    DETECT_MOUNTS("cgroups2");
    DETECT_MOUNTS("cgroups3");
    fakerootdir = initFakeFS(NULL, "all-in-one");
    DETECT_MOUNTS("all-in-one");
    cleanupFakeFS(fakerootdir);
    DETECT_MOUNTS_FAIL("no-cgroups");
    DETECT_MOUNTS("kubevirt");
    fakerootdir = initFakeFS("unified", NULL);
    DETECT_MOUNTS("unified");
    cleanupFakeFS(fakerootdir);
    fakerootdir = initFakeFS("hybrid", NULL);
    DETECT_MOUNTS("hybrid");
    cleanupFakeFS(fakerootdir);

    fakerootdir = initFakeFS(NULL, "systemd");
    if (virTestRun("New cgroup for self", testCgroupNewForSelf, NULL) < 0)
        ret = -1;

    if (virTestRun("New cgroup for partition", testCgroupNewForPartition, NULL) < 0)
        ret = -1;

    if (virTestRun("New cgroup for partition nested", testCgroupNewForPartitionNested, NULL) < 0)
        ret = -1;

    if (virTestRun("New cgroup for partition nested deeply", testCgroupNewForPartitionNestedDeep, NULL) < 0)
        ret = -1;

    if (virTestRun("New cgroup for domain partition", testCgroupNewForPartitionDomain, NULL) < 0)
        ret = -1;

    if (virTestRun("New cgroup for domain partition escaped", testCgroupNewForPartitionDomainEscaped, NULL) < 0)
        ret = -1;

    if (virTestRun("Cgroup available", testCgroupAvailable, (void*)0x1) < 0)
        ret = -1;

    if (virTestRun("Cgroup controller available", testCgroupControllerAvailable, NULL) < 0)
        ret = -1;

    if (virTestRun("virCgroupGetBlkioIoServiced works", testCgroupGetBlkioIoServiced, NULL) < 0)
        ret = -1;

    if (virTestRun("virCgroupGetBlkioIoDeviceServiced works", testCgroupGetBlkioIoDeviceServiced, NULL) < 0)
        ret = -1;

    if (virTestRun("virCgroupGetMemoryUsage works", testCgroupGetMemoryUsage, NULL) < 0)
        ret = -1;

    if (virTestRun("virCgroupGetMemoryStat works", testCgroupGetMemoryStat, NULL) < 0)
        ret = -1;

    if (virTestRun("virCgroupGetPercpuStats works", testCgroupGetPercpuStats, NULL) < 0)
        ret = -1;
    cleanupFakeFS(fakerootdir);

    fakerootdir = initFakeFS(NULL, "all-in-one");
    if (virTestRun("New cgroup for self (allinone)", testCgroupNewForSelfAllInOne, NULL) < 0)
        ret = -1;
    if (virTestRun("Cgroup available", testCgroupAvailable, (void*)0x1) < 0)
        ret = -1;
    cleanupFakeFS(fakerootdir);

    fakerootdir = initFakeFS(NULL, "logind");
    if (virTestRun("New cgroup for self (logind)", testCgroupNewForSelfLogind, NULL) < 0)
        ret = -1;
    if (virTestRun("Cgroup available", testCgroupAvailable, (void*)0x0) < 0)
        ret = -1;
    cleanupFakeFS(fakerootdir);

    /* cgroup unified */

    fakerootdir = initFakeFS("unified", "unified");
    if (virTestRun("New cgroup for self (unified)", testCgroupNewForSelfUnified, NULL) < 0)
        ret = -1;
    if (virTestRun("Cgroup available (unified)", testCgroupAvailable, (void*)0x1) < 0)
        ret = -1;
    cleanupFakeFS(fakerootdir);

    /* cgroup hybrid */

    fakerootdir = initFakeFS("hybrid", "hybrid");
    if (virTestRun("New cgroup for self (hybrid)", testCgroupNewForSelfHybrid, NULL) < 0)
        ret = -1;
    if (virTestRun("Cgroup available (hybrid)", testCgroupAvailable, (void*)0x1) < 0)
        ret = -1;
    cleanupFakeFS(fakerootdir);

    fakerootdir = initFakeFS("legacy", "systemd-legacy");
    if (virTestRun("New cgroup for self (systemd-legacy)",
                   testCgroupNewForSelfSystemdLegacy, NULL) < 0) {
        ret = -1;
    }
    cleanupFakeFS(fakerootdir);

    fakerootdir = initFakeFS("unified", "systemd-unified");
    if (virTestRun("New cgroup for self (systemd-unified)",
                   testCgroupNewForSelfSystemdUnified, NULL) < 0) {
        ret = -1;
    }
    cleanupFakeFS(fakerootdir);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("vircgroup"))

#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
