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

#ifdef __linux__
# include "virmock.h"
# include <unistd.h>
# include <fcntl.h>
# include <sys/stat.h>
# include <sys/sysmacros.h>
# include <stdarg.h>
# include "testutilslxc.h"
# include "viralloc.h"
# include "vircgroupv2devices.h"

static int (*real_open)(const char *path, int flags, ...);
static FILE *(*real_fopen)(const char *path, const char *mode);
static int (*real_access)(const char *path, int mode);
static int (*real_mkdir)(const char *path, mode_t mode);

static char *fakerootdir;
static char *fakesysfscgroupdir;
static const char *fakedevicedir0 = FAKEDEVDIR0;
static const char *fakedevicedir1 = FAKEDEVDIR1;


# define SYSFS_CGROUP_PREFIX "/not/really/sys/fs/cgroup"
# define SYSFS_CPU_PRESENT "/sys/devices/system/cpu/present"
# define SYSFS_CPU_PRESENT_MOCKED "devices_system_cpu_present"

/*
 * The plan:
 *
 * We fake out /proc/mounts, so make it look as is cgroups
 * are mounted on /not/really/sys/fs/cgroup. We don't
 * use /sys/fs/cgroup, because we want to make it easy to
 * detect places where we've not mocked enough syscalls.
 *
 * In any open/access/mkdir calls we look at path and if
 * it starts with /not/really/sys/fs/cgroup, we rewrite
 * the path to point at a subdirectory of the temporary
 * directory referred to by LIBVIRT_FAKE_ROOT_DIR env
 * variable that is set by the main test suite
 *
 * In mkdir() calls, we simulate the cgroups behaviour
 * whereby creating the directory auto-creates a bunch
 * of files beneath it
 */

static int make_file(const char *path,
                     const char *name,
                     const char *value)
{
    int fd = -1;
    int ret = -1;
    char *filepath = NULL;

    if (asprintf(&filepath, "%s/%s", path, name) < 0)
        return -1;

    if ((fd = real_open(filepath, O_CREAT|O_WRONLY, 0600)) < 0)
        goto cleanup;

    if (write(fd, value, strlen(value)) != strlen(value)) /* sc_avoid_write */
        goto cleanup;

    ret = 0;
 cleanup:
    if (fd != -1 && close(fd) < 0)
        ret = -1;
    free(filepath);

    return ret;
}


static int make_controller_v1(const char *path, mode_t mode)
{
    const char *controller;

    if (!STRPREFIX(path, fakesysfscgroupdir)) {
        errno = EINVAL;
        return -1;
    }
    controller = path + strlen(fakesysfscgroupdir) + 1;

    if (STREQ(controller, "cpu"))
        return symlink("cpu,cpuacct", path);
    if (STREQ(controller, "cpuacct"))
        return symlink("cpu,cpuacct", path);

    if (real_mkdir(path, mode) < 0)
        return -1;

# define MAKE_FILE(name, value) \
    do { \
        if (make_file(path, name, value) < 0) \
            return -1; \
    } while (0)

    if (STRPREFIX(controller, "cpu,cpuacct")) {
        MAKE_FILE("cpu.cfs_period_us", "100000\n");
        MAKE_FILE("cpu.cfs_quota_us", "-1\n");
        MAKE_FILE("cpu.shares", "1024\n");
        MAKE_FILE("cpuacct.stat",
                  "user 216687025\n"
                  "system 43421396\n");
        MAKE_FILE("cpuacct.usage", "2787788855799582\n");
        MAKE_FILE("cpuacct.usage_percpu",
                  "7059492996 0 0 0 0 0 0 0 4180532496 0 0 0 0 0 0 0 "
                  "1957541268 0 0 0 0 0 0 0 2065932204 0 0 0 0 0 0 0 "
                  "18228689414 0 0 0 0 0 0 0 4245525148 0 0 0 0 0 0 0 "
                  "2911161568 0 0 0 0 0 0 0 1407758136 0 0 0 0 0 0 0 "
                  "1836807700 0 0 0 0 0 0 0 1065296618 0 0 0 0 0 0 0 "
                  "2046213266 0 0 0 0 0 0 0 747889778 0 0 0 0 0 0 0 "
                  "709566900 0 0 0 0 0 0 0 444777342 0 0 0 0 0 0 0 "
                  "5683512916 0 0 0 0 0 0 0 635751356 0 0 0 0 0 0 0\n");
    } else if (STRPREFIX(controller, "cpuset")) {
        if (STREQ(controller, "cpuset"))
            MAKE_FILE("cpuset.cpus", "0-1");
        else
            MAKE_FILE("cpuset.cpus", ""); /* Values don't inherit */
        MAKE_FILE("cpuset.memory_migrate", "0\n");
        if (STREQ(controller, "cpuset"))
            MAKE_FILE("cpuset.mems", "0");
        else
            MAKE_FILE("cpuset.mems", ""); /* Values don't inherit */
    } else if (STRPREFIX(controller, "memory")) {
        MAKE_FILE("memory.limit_in_bytes", "9223372036854775807\n");
        MAKE_FILE("memory.memsw.limit_in_bytes", ""); /* Not supported */
        MAKE_FILE("memory.memsw.usage_in_bytes", ""); /* Not supported */
        MAKE_FILE("memory.soft_limit_in_bytes", "9223372036854775807\n");
        MAKE_FILE("memory.stat",
                  "cache 1336619008\n"
                  "rss 97792000\n"
                  "mapped_file 42090496\n"
                  "pgpgin 13022605027\n"
                  "pgpgout 13023820533\n"
                  "pgfault 54429417056\n"
                  "pgmajfault 315715\n"
                  "inactive_anon 145887232\n"
                  "active_anon 67100672\n"
                  "inactive_file 627400704\n"
                  "active_file 661872640\n"
                  "unevictable 3690496\n"
                  "hierarchical_memory_limit 9223372036854775807\n"
                  "total_cache 1336635392\n"
                  "total_rss 118689792\n"
                  "total_mapped_file 42106880\n"
                  "total_pgpgin 13022606816\n"
                  "total_pgpgout 13023820793\n"
                  "total_pgfault 54429422313\n"
                  "total_pgmajfault 315715\n"
                  "total_inactive_anon 145891328\n"
                  "total_active_anon 88010752\n"
                  "total_inactive_file 627400704\n"
                  "total_active_file 661872640\n"
                  "total_unevictable 3690496\n"
                  "recent_rotated_anon 112807028\n"
                  "recent_rotated_file 2547948\n"
                  "recent_scanned_anon 113796164\n"
                  "recent_scanned_file 8199863\n");
        MAKE_FILE("memory.usage_in_bytes", "1455321088\n");
        MAKE_FILE("memory.use_hierarchy", "0\n");
    } else if (STRPREFIX(controller, "freezer")) {
        MAKE_FILE("freezer.state", "THAWED");
    } else if (STRPREFIX(controller, "blkio")) {
        MAKE_FILE("blkio.throttle.io_service_bytes",
                  "8:0 Read 59542107136\n"
                  "8:0 Write 411440480256\n"
                  "8:0 Sync 248486822912\n"
                  "8:0 Async 222495764480\n"
                  "8:0 Total 470982587392\n"
                  "9:0 Read 59542107137\n"
                  "9:0 Write 411440480257\n"
                  "9:0 Sync 248486822912\n"
                  "9:0 Async 222495764480\n"
                  "9:0 Total 470982587392\n");
        MAKE_FILE("blkio.throttle.io_serviced",
                  "8:0 Read 4832583\n"
                  "8:0 Write 36641903\n"
                  "8:0 Sync 30723171\n"
                  "8:0 Async 10751315\n"
                  "8:0 Total 41474486\n"
                  "9:0 Read 4832584\n"
                  "9:0 Write 36641904\n"
                  "9:0 Sync 30723171\n"
                  "9:0 Async 10751315\n"
                  "9:0 Total 41474486\n");
        MAKE_FILE("blkio.throttle.read_bps_device", "");
        MAKE_FILE("blkio.throttle.read_iops_device", "");
        MAKE_FILE("blkio.throttle.write_bps_device", "");
        MAKE_FILE("blkio.throttle.write_iops_device", "");
        MAKE_FILE("blkio.weight", "1000\n");
        MAKE_FILE("blkio.weight_device", "");

    } else {
        errno = EINVAL;
        return -1;
    }

# undef MAKE_FILE

    return 0;
}


static int make_controller_v2(const char *path, mode_t mode)
{
    if (!STRPREFIX(path, fakesysfscgroupdir)) {
        errno = EINVAL;
        return -1;
    }

    if (real_mkdir(path, mode) < 0 && errno != EEXIST)
        return -1;

# define MAKE_FILE(name, value) \
    do { \
        if (make_file(path, name, value) < 0) \
            return -1; \
    } while (0)

    MAKE_FILE("cgroup.controllers", "cpu io memory\n");
    MAKE_FILE("cgroup.subtree_control", "");
    MAKE_FILE("cgroup.type", "domain\n");
    MAKE_FILE("cpu.max", "max 100000\n");
    MAKE_FILE("cpu.stat",
              "usage_usec 0\n"
              "user_usec 0\n"
              "system_usec 0\n"
              "nr_periods 0\n"
              "nr_throttled 0\n"
              "throttled_usec 0\n");
    MAKE_FILE("cpu.weight", "100\n");
    MAKE_FILE("memory.current", "1455321088\n");
    MAKE_FILE("memory.high", "max\n");
    MAKE_FILE("memory.max", "max\n");
    MAKE_FILE("memory.stat",
              "anon 0\n"
              "file 0\n"
              "kernel_stack 0\n"
              "slab 0\n"
              "sock 0\n"
              "shmem 0\n"
              "file_mapped 0\n"
              "file_dirty 0\n"
              "file_writeback 0\n"
              "inactive_anon 0\n"
              "active_anon 0\n"
              "inactive_file 0\n"
              "active_file 0\n"
              "unevictable 0\n"
              "slab_reclaimable 0\n"
              "slab_unreclaimable 0\n"
              "pgfault 0\n"
              "pgmajfault 0\n"
              "pgrefill 0\n"
              "pgscan 0\n"
              "pgsteal 0\n"
              "pgactivate 0\n"
              "pgdeactivate 0\n"
              "pglazyfree 0\n"
              "pglazyfreed 0\n"
              "workingset_refault 0\n"
              "workingset_activate 0\n"
              "workingset_nodereclaim 0\n");
    MAKE_FILE("memory.swap.current", "0\n");
    MAKE_FILE("memory.swap.max", "max\n");
    MAKE_FILE("io.stat", "8:0 rbytes=26828800 wbytes=77062144 rios=2256 wios=7849 dbytes=0 dios=0\n");
    MAKE_FILE("io.max", "");
    MAKE_FILE("io.weight", "default 100\n");

# undef MAKE_FILE

    return 0;
}


static void init_syms(void)
{
    if (real_fopen)
        return;

    VIR_MOCK_REAL_INIT(fopen);
    VIR_MOCK_REAL_INIT(access);
    VIR_MOCK_REAL_INIT(mkdir);
    VIR_MOCK_REAL_INIT(open);
}


static int make_controller(const char *path, mode_t mode)
{
    const char *mock;
    bool unified = false;
    bool hybrid = false;

    mock = getenv("VIR_CGROUP_MOCK_MODE");
    if (mock) {
        if (STREQ(mock, "unified")) {
            unified = true;
        } else if (STREQ(mock, "hybrid")) {
            hybrid = true;
        } else if (STRNEQ(mock, "legacy")) {
            fprintf(stderr, "invalid mode '%s'\n", mock);
            abort();
        }
    }

    if (unified || (hybrid && strstr(path, "unified"))) {
        return make_controller_v2(path, mode);
    } else {
        return make_controller_v1(path, mode);
    }
}


static void init_sysfs(void)
{
    const char *mock;
    char *newfakerootdir;
    bool unified = false;
    bool hybrid = false;

    if (!(newfakerootdir = getenv("LIBVIRT_FAKE_ROOT_DIR"))) {
        fprintf(stderr, "Missing LIBVIRT_FAKE_ROOT_DIR env variable\n");
        abort();
    }

    if (fakerootdir && STREQ(fakerootdir, newfakerootdir))
        return;

    VIR_FREE(fakerootdir);
    fakerootdir = g_strdup(newfakerootdir);

    mock = getenv("VIR_CGROUP_MOCK_MODE");
    if (mock) {
        if (STREQ(mock, "unified")) {
            unified = true;
        } else if (STREQ(mock, "hybrid")) {
            hybrid = true;
        } else if (STRNEQ(mock, "legacy")) {
            fprintf(stderr, "invalid mode '%s'\n", mock);
            abort();
        }
    }

    VIR_FREE(fakesysfscgroupdir);

    fakesysfscgroupdir = g_strdup_printf("%s%s",
                                         fakerootdir, SYSFS_CGROUP_PREFIX);

    if (g_mkdir_with_parents(fakesysfscgroupdir, 0777) < 0) {
        fprintf(stderr, "Cannot create %s\n", fakesysfscgroupdir);
        abort();
    }

# define MAKE_CONTROLLER(subpath) \
    do { \
        char *path; \
        if (asprintf(&path, "%s/%s", fakesysfscgroupdir, subpath) < 0) \
            abort(); \
        if (make_controller(path, 0755) < 0) { \
            fprintf(stderr, "Cannot initialize %s\n", path); \
            free(path); \
            abort(); \
        } \
        free(path); \
    } while (0)

    if (unified) {
        MAKE_CONTROLLER("");
    } else if (hybrid) {
        MAKE_CONTROLLER("unified");
        MAKE_CONTROLLER("cpuset");
        MAKE_CONTROLLER("freezer");
    } else {
        MAKE_CONTROLLER("cpu");
        MAKE_CONTROLLER("cpuacct");
        MAKE_CONTROLLER("cpu,cpuacct");
        MAKE_CONTROLLER("cpuset");
        MAKE_CONTROLLER("blkio");
        MAKE_CONTROLLER("memory");
        MAKE_CONTROLLER("freezer");

        if (make_file(fakesysfscgroupdir,
                      SYSFS_CPU_PRESENT_MOCKED, "8-23,48-159\n") < 0)
            abort();
    }
}


FILE *fopen(const char *path, const char *mode)
{
    char *filepath = NULL;
    const char *type = NULL;
    FILE *rc = NULL;
    const char *filename = getenv("VIR_CGROUP_MOCK_FILENAME");

    init_syms();

    if (STREQ(path, "/proc/mounts")) {
        if (STREQ(mode, "r")) {
            type = "mounts";
        } else {
            errno = EACCES;
            return NULL;
        }
    }
    if (STREQ(path, "/proc/cgroups")) {
        if (STREQ(mode, "r")) {
            type = "cgroups";
        } else {
            errno = EACCES;
            return NULL;
        }
    }
    if (STREQ(path, "/proc/self/cgroup")) {
        if (STREQ(mode, "r")) {
            type = "self.cgroup";
        } else {
            errno = EACCES;
            return NULL;
        }
    }

    if (type) {
        if (!filename) {
            errno = EACCES;
            return NULL;
        }
        filepath = g_strdup_printf("%s/vircgroupdata/%s.%s",
                                   abs_srcdir, filename, type);
        rc = real_fopen(filepath, mode);
        free(filepath);
        return rc;
    }

    return real_fopen(path, mode);
}

int access(const char *path, int mode)
{
    int ret;

    init_syms();

    if (STRPREFIX(path, SYSFS_CGROUP_PREFIX)) {
        char *newpath;

        init_sysfs();

        if (asprintf(&newpath, "%s%s",
                     fakesysfscgroupdir,
                     path + strlen(SYSFS_CGROUP_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
        ret = real_access(newpath, mode);
        free(newpath);
    } else if (STREQ(path, "/proc/cgroups") ||
               STREQ(path, "/proc/self/cgroup") ||
               STREQ(path, SYSFS_CPU_PRESENT)) {
        /* These files are readable for all. */
        ret = (mode == F_OK || mode == R_OK) ? 0 : -1;
    } else if (STREQ(path, "/proc/mounts")) {
        /* This one is accessible anytime for anybody. In fact, it's just
         * a symlink to /proc/self/mounts. */
        ret = 0;
    } else {
        ret = real_access(path, mode);
    }
    return ret;
}

# define VIR_MOCK_STAT_HOOK \
    do { \
        if (STRPREFIX(path, fakedevicedir0)) { \
            sb->st_mode = S_IFBLK; \
            sb->st_rdev = makedev(8, 0); \
            return 0; \
        } else if (STRPREFIX(path, fakedevicedir1)) { \
            sb->st_mode = S_IFBLK; \
            sb->st_rdev = makedev(9, 0); \
            return 0; \
        } \
    } while (0)

# include "virmockstathelpers.c"

static int
virMockStatRedirect(const char *path, char **newpath)
{
    if (STREQ(path, SYSFS_CPU_PRESENT)) {
        init_sysfs();
        if (asprintf(newpath, "%s/%s",
                     fakesysfscgroupdir,
                     SYSFS_CPU_PRESENT_MOCKED) < 0)
            return -1;
    } else if (STRPREFIX(path, SYSFS_CGROUP_PREFIX)) {
        init_sysfs();
        if (asprintf(newpath, "%s%s",
                     fakesysfscgroupdir,
                     path + strlen(SYSFS_CGROUP_PREFIX)) < 0)
            return -1;
    }
    return 0;
}


int mkdir(const char *path, mode_t mode)
{
    int ret;

    init_syms();

    if (STRPREFIX(path, SYSFS_CGROUP_PREFIX)) {
        char *newpath;

        init_sysfs();

        if (asprintf(&newpath, "%s%s",
                     fakesysfscgroupdir,
                     path + strlen(SYSFS_CGROUP_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
        ret = make_controller(newpath, mode);
        free(newpath);
    } else {
        ret = real_mkdir(path, mode);
    }
    return ret;
}

int open(const char *path, int flags, ...)
{
    int ret;
    char *newpath = NULL;

    init_syms();

    if (STREQ(path, SYSFS_CPU_PRESENT)) {
        init_sysfs();
        if (asprintf(&newpath, "%s/%s",
                     fakesysfscgroupdir,
                     SYSFS_CPU_PRESENT_MOCKED) < 0) {
            errno = ENOMEM;
            return -1;
        }
    }

    if (STRPREFIX(path, SYSFS_CGROUP_PREFIX)) {
        init_sysfs();
        if (asprintf(&newpath, "%s%s",
                     fakesysfscgroupdir,
                     path + strlen(SYSFS_CGROUP_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
    }
    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
        ret = real_open(newpath ? newpath : path, flags, mode);
    } else {
        ret = real_open(newpath ? newpath : path, flags);
    }
    free(newpath);
    return ret;
}

bool
virCgroupV2DevicesAvailable(virCgroup *group G_GNUC_UNUSED)
{
    return true;
}
#else
/* Nothing to override on non-__linux__ platforms */
#endif
