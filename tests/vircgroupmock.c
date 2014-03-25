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

#ifdef __linux__
# include "internal.h"

# include <stdio.h>
# include <dlfcn.h>
# include <stdlib.h>
# include <unistd.h>
# include <fcntl.h>
# include <sys/stat.h>
# include <stdarg.h>
# include "testutilslxc.h"

static int (*realopen)(const char *path, int flags, ...);
static FILE *(*realfopen)(const char *path, const char *mode);
static int (*realaccess)(const char *path, int mode);
static int (*realstat)(const char *path, struct stat *sb);
static int (*real__xstat)(int ver, const char *path, struct stat *sb);
static int (*reallstat)(const char *path, struct stat *sb);
static int (*real__lxstat)(int ver, const char *path, struct stat *sb);
static int (*realmkdir)(const char *path, mode_t mode);

/* Don't make static, since it causes problems with clang
 * when passed as an arg to asprintf()
 * vircgroupmock.c:462:22: error: static variable 'fakesysfsdir' is used in an inline function with external linkage [-Werror,-Wstatic-in-inline]
 */
char *fakesysfsdir;
const char *fakedevicedir0 = FAKEDEVDIR0;
const char *fakedevicedir1 = FAKEDEVDIR1;


# define SYSFS_PREFIX "/not/really/sys/fs/cgroup/"

/*
 * The plan:
 *
 * We fake out /proc/mounts, so make it look as is cgroups
 * are mounted on /not/really/sys/fs/cgroup. We don't
 * use /sys/fs/cgroup, because we want to make it easy to
 * detect places where we've not mocked enough syscalls.
 *
 * In any open/acces/mkdir calls we look at path and if
 * it starts with /not/really/sys/fs/cgroup, we rewrite
 * the path to point at a temporary directory referred
 * to by LIBVIRT_FAKE_SYSFS_DIR env variable that is
 * set by the main test suite
 *
 * In mkdir() calls, we simulate the cgroups behaviour
 * whereby creating the directory auto-creates a bunch
 * of files beneath it
 */

/*
 * Intentionally missing the 'devices' mount.
 * Co-mounting cpu & cpuacct controllers
 * An anonymous controller for systemd
 */
const char *procmounts =
    "rootfs / rootfs rw 0 0\n"
    "tmpfs /run tmpfs rw,seclabel,nosuid,nodev,mode=755 0 0\n"
    "tmpfs /not/really/sys/fs/cgroup tmpfs rw,seclabel,nosuid,nodev,noexec,mode=755 0 0\n"
    "cgroup /not/really/sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd 0 0\n"
    "cgroup /not/really/sys/fs/cgroup/cpuset cgroup rw,nosuid,nodev,noexec,relatime,cpuset 0 0\n"
    "cgroup /not/really/sys/fs/cgroup/cpu,cpuacct cgroup rw,nosuid,nodev,noexec,relatime,cpuacct,cpu 0 0\n"
    "cgroup /not/really/sys/fs/cgroup/freezer cgroup rw,nosuid,nodev,noexec,relatime,freezer 0 0\n"
    "cgroup /not/really/sys/fs/cgroup/blkio cgroup rw,nosuid,nodev,noexec,relatime,blkio 0 0\n"
    "cgroup /not/really/sys/fs/cgroup/memory cgroup rw,nosuid,nodev,noexec,relatime,memory 0 0\n"
    "/dev/sda1 /boot ext4 rw,seclabel,relatime,data=ordered 0 0\n"
    "tmpfs /tmp tmpfs rw,seclabel,relatime,size=1024000k 0 0\n";

const char *procselfcgroups =
    "115:memory:/\n"
    "8:blkio:/\n"
    "6:freezer:/\n"
    "3:cpuacct,cpu:/system\n"
    "2:cpuset:/\n"
    "1:name=systemd:/user/berrange/123\n";

const char *proccgroups =
    "#subsys_name    hierarchy       num_cgroups     enabled\n"
    "cpuset  2       4       1\n"
    "cpu     3       48      1\n"
    "cpuacct 3       48      1\n"
    "memory  4       4       1\n"
    "devices 5       4       1\n"
    "freezer 6       4       1\n"
    "blkio   8       4       1\n";


const char *procmountsallinone =
    "rootfs / rootfs rw 0 0\n"
    "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
    "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
    "udev /dev devtmpfs rw,relatime,size=16458560k,nr_inodes=4114640,mode=755 0 0\n"
    "devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0\n"
    "nfsd /proc/fs/nfsd nfsd rw,relatime 0 0\n"
    "cgroup /not/really/sys/fs/cgroup cgroup rw,relatime,blkio,devices,memory,cpuacct,cpu,cpuset 0 0\n";

const char *procselfcgroupsallinone =
    "6:blkio,devices,memory,cpuacct,cpu,cpuset:/";

const char *proccgroupsallinone =
    "#subsys_name    hierarchy       num_cgroups     enabled\n"
    "cpuset   6   1  1\n"
    "cpu      6   1  1\n"
    "cpuacct  6   1  1\n"
    "memory   6   1  1\n"
    "devices  6   1  1\n"
    "blkio    6   1  1\n";

const char *procmountslogind =
    "none /not/really/sys/fs/cgroup tmpfs rw,rootcontext=system_u:object_r:sysfs_t:s0,seclabel,relatime,size=4k,mode=755 0 0\n"
    "systemd /not/really/sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,name=systemd 0 0\n";

const char *procselfcgroupslogind =
    "1:name=systemd:/\n";

const char *proccgroupslogind =
    "#subsys_name    hierarchy       num_cgroups     enabled\n"
    "cpuset    0  1  1\n"
    "cpu       0  1  1\n"
    "cpuacct   0  1  1\n"
    "memory    0  1  0\n"
    "devices   0  1  1\n"
    "freezer   0  1  1\n"
    "net_cls   0  1  1\n"
    "blkio     0  1  1\n"
    "perf_event  0  1  1\n";



static int make_file(const char *path,
                     const char *name,
                     const char *value)
{
    int fd = -1;
    int ret = -1;
    char *filepath = NULL;

    if (asprintf(&filepath, "%s/%s", path, name) < 0)
        return -1;

    if ((fd = realopen(filepath, O_CREAT|O_WRONLY, 0600)) < 0)
        goto cleanup;

    if (write(fd, value, strlen(value)) != strlen(value))
        goto cleanup;

    ret = 0;
 cleanup:
    if (fd != -1 && close(fd) < 0)
        ret = -1;
    free(filepath);

    return ret;
}

static int make_controller(const char *path, mode_t mode)
{
    int ret = -1;
    const char *controller;

    if (!STRPREFIX(path, fakesysfsdir)) {
        errno = EINVAL;
        return -1;
    }
    controller = path + strlen(fakesysfsdir) + 1;

    if (STREQ(controller, "cpu"))
        return symlink("cpu,cpuacct", path);
    if (STREQ(controller, "cpuacct"))
        return symlink("cpu,cpuacct", path);

    if (realmkdir(path, mode) < 0)
        goto cleanup;

# define MAKE_FILE(name, value)                 \
    do {                                        \
        if (make_file(path, name, value) < 0)   \
            goto cleanup;                       \
    } while (0)

    if (STRPREFIX(controller, "cpu,cpuacct")) {
        MAKE_FILE("cpu.cfs_period_us", "100000\n");
        MAKE_FILE("cpu.cfs_quota_us", "-1\n");
        MAKE_FILE("cpu.rt_period_us", "1000000\n");
        MAKE_FILE("cpu.rt_runtime_us", "950000\n");
        MAKE_FILE("cpu.shares", "1024\n");
        MAKE_FILE("cpu.stat",
                  "nr_periods 0\n"
                  "nr_throttled 0\n"
                  "throttled_time 0\n");
        MAKE_FILE("cpuacct.stat",
                  "user 216687025\n"
                  "system 43421396\n");
        MAKE_FILE("cpuacct.usage", "2787788855799582\n");
        MAKE_FILE("cpuacct.usage_percpu", "1413142688153030 1374646168910542\n");
    } else if (STRPREFIX(controller, "cpuset")) {
        MAKE_FILE("cpuset.cpu_exclusive", "1\n");
        if (STREQ(controller, "cpuset"))
            MAKE_FILE("cpuset.cpus", "0-1");
        else
            MAKE_FILE("cpuset.cpus", ""); /* Values don't inherit */
        MAKE_FILE("cpuset.mem_exclusive", "1\n");
        MAKE_FILE("cpuset.mem_hardwall", "0\n");
        MAKE_FILE("cpuset.memory_migrate", "0\n");
        MAKE_FILE("cpuset.memory_pressure", "0\n");
        MAKE_FILE("cpuset.memory_pressure_enabled", "0\n");
        MAKE_FILE("cpuset.memory_spread_page", "0\n");
        MAKE_FILE("cpuset.memory_spread_slab", "0\n");
        if (STREQ(controller, "cpuset"))
            MAKE_FILE("cpuset.mems", "0");
        else
            MAKE_FILE("cpuset.mems", ""); /* Values don't inherit */
        MAKE_FILE("cpuset.sched_load_balance", "1\n");
        MAKE_FILE("cpuset.sched_relax_domain_level", "-1\n");
    } else if (STRPREFIX(controller, "memory")) {
        MAKE_FILE("memory.failcnt", "0\n");
        MAKE_FILE("memory.force_empty", ""); /* Write only */
        MAKE_FILE("memory.kmem.tcp.failcnt", "0\n");
        MAKE_FILE("memory.kmem.tcp.limit_in_bytes", "9223372036854775807\n");
        MAKE_FILE("memory.kmem.tcp.max_usage_in_bytes", "0\n");
        MAKE_FILE("memory.kmem.tcp.usage_in_bytes", "16384\n");
        MAKE_FILE("memory.limit_in_bytes", "9223372036854775807\n");
        MAKE_FILE("memory.max_usage_in_bytes", "0\n");
        MAKE_FILE("memory.memsw.failcnt", ""); /* Not supported */
        MAKE_FILE("memory.memsw.limit_in_bytes", ""); /* Not supported */
        MAKE_FILE("memory.memsw.max_usage_in_bytes", ""); /* Not supported */
        MAKE_FILE("memory.memsw.usage_in_bytes", ""); /* Not supported */
        MAKE_FILE("memory.move_charge_at_immigrate", "0\n");
        MAKE_FILE("memory.numa_stat",
                  "total=367664 N0=367664\n"
                  "file=314764 N0=314764\n"
                  "anon=51999 N0=51999\n"
                  "unevictable=901 N0=901\n");
        MAKE_FILE("memory.oom_control",
                  "oom_kill_disable 0\n"
                  "under_oom 0\n");
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
        MAKE_FILE("memory.swappiness", "60\n");
        MAKE_FILE("memory.usage_in_bytes", "1455321088\n");
        MAKE_FILE("memory.use_hierarchy", "0\n");
    } else if (STRPREFIX(controller, "freezer")) {
        MAKE_FILE("freezer.state", "THAWED");
    } else if (STRPREFIX(controller, "blkio")) {
        MAKE_FILE("blkio.io_merged",
                  "8:0 Read 1100949\n"
                  "8:0 Write 2248076\n"
                  "8:0 Sync 63063\n"
                  "8:0 Async 3285962\n"
                  "8:0 Total 3349025\n");
        MAKE_FILE("blkio.io_queued",
                  "8:0 Read 0\n"
                  "8:0 Write 0\n"
                  "8:0 Sync 0\n"
                  "8:0 Async 0\n"
                  "8:0 Total 0\n");
        MAKE_FILE("blkio.io_service_bytes",
                  "8:0 Read 59542078464\n"
                  "8:0 Write 397369182208\n"
                  "8:0 Sync 234080922624\n"
                  "8:0 Async 222830338048\n"
                  "8:0 Total 456911260672\n");
        MAKE_FILE("blkio.io_serviced",
                  "8:0 Read 3402504\n"
                  "8:0 Write 14966516\n"
                  "8:0 Sync 12064031\n"
                  "8:0 Async 6304989\n"
                  "8:0 Total 18369020\n");
        MAKE_FILE("blkio.io_service_time",
                  "8:0 Read 10747537542349\n"
                  "8:0 Write 9200028590575\n"
                  "8:0 Sync 6449319855381\n"
                  "8:0 Async 13498246277543\n"
                  "8:0 Total 19947566132924\n");
        MAKE_FILE("blkio.io_wait_time",
                  "8:0 Read 14687514824889\n"
                  "8:0 Write 357748452187691\n"
                  "8:0 Sync 55296974349413\n"
                  "8:0 Async 317138992663167\n"
                  "8:0 Total 372435967012580\n");
        MAKE_FILE("blkio.reset_stats", ""); /* Write only */
        MAKE_FILE("blkio.sectors", "8:0 892404806\n");
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
        MAKE_FILE("blkio.time", "8:0 61019089\n");
        MAKE_FILE("blkio.weight", "1000\n");
        MAKE_FILE("blkio.weight_device", "");

    } else {
        errno = EINVAL;
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

static void init_syms(void)
{
    if (realfopen)
        return;

# define LOAD_SYM(name)                                                 \
    do {                                                                \
        if (!(real ## name = dlsym(RTLD_NEXT, #name))) {                \
            fprintf(stderr, "Cannot find real '%s' symbol\n", #name);   \
            abort();                                                    \
        }                                                               \
    } while (0)

# define LOAD_SYM_ALT(name1, name2)                                     \
    do {                                                                \
        if (!(real ## name1 = dlsym(RTLD_NEXT, #name1)) &&              \
            !(real ## name2 = dlsym(RTLD_NEXT, #name2))) {              \
            fprintf(stderr, "Cannot find real '%s' or '%s' symbol\n", #name1, #name2); \
            abort();                                                    \
        }                                                               \
    } while (0)

    LOAD_SYM(fopen);
    LOAD_SYM(access);
    LOAD_SYM_ALT(lstat, __lxstat);
    LOAD_SYM_ALT(stat, __xstat);
    LOAD_SYM(mkdir);
    LOAD_SYM(open);
}

static void init_sysfs(void)
{
    if (fakesysfsdir)
        return;

    if (!(fakesysfsdir = getenv("LIBVIRT_FAKE_SYSFS_DIR"))) {
        fprintf(stderr, "Missing LIBVIRT_FAKE_SYSFS_DIR env variable\n");
        abort();
    }

# define MAKE_CONTROLLER(subpath)                               \
    do {                                                        \
        char *path;                                             \
        if (asprintf(&path, "%s/%s", fakesysfsdir, subpath) < 0)\
            abort();                                            \
        if (make_controller(path, 0755) < 0) {                  \
            fprintf(stderr, "Cannot initialize %s\n", path);    \
            abort();                                            \
        }                                                       \
    } while (0)

    MAKE_CONTROLLER("cpu");
    MAKE_CONTROLLER("cpuacct");
    MAKE_CONTROLLER("cpu,cpuacct");
    MAKE_CONTROLLER("cpu,cpuacct/system");
    MAKE_CONTROLLER("cpuset");
    MAKE_CONTROLLER("blkio");
    MAKE_CONTROLLER("memory");
    MAKE_CONTROLLER("freezer");
}


FILE *fopen(const char *path, const char *mode)
{
    const char *mock;
    bool allinone = false, logind = false;
    init_syms();

    mock = getenv("VIR_CGROUP_MOCK_MODE");
    if (mock) {
        if (STREQ(mock, "allinone"))
            allinone = true;
        else if (STREQ(mock, "logind"))
            logind = true;
    }

    if (STREQ(path, "/proc/mounts")) {
        if (STREQ(mode, "r")) {
            if (allinone)
                return fmemopen((void *)procmountsallinone,
                                strlen(procmountsallinone), mode);
            else if (logind)
                return fmemopen((void *)procmountslogind,
                                strlen(procmountslogind), mode);
            else
                return fmemopen((void *)procmounts, strlen(procmounts), mode);
        } else {
            errno = EACCES;
            return NULL;
        }
    }
    if (STREQ(path, "/proc/cgroups")) {
        if (STREQ(mode, "r")) {
            if (allinone)
                return fmemopen((void *)proccgroupsallinone,
                                strlen(proccgroupsallinone), mode);
            else if (logind)
                return fmemopen((void *)proccgroupslogind,
                                strlen(proccgroupslogind), mode);
            else
                return fmemopen((void *)proccgroups, strlen(proccgroups), mode);
        } else {
            errno = EACCES;
            return NULL;
        }
    }
    if (STREQ(path, "/proc/self/cgroup")) {
        if (STREQ(mode, "r")) {
            if (allinone)
                return fmemopen((void *)procselfcgroupsallinone,
                                strlen(procselfcgroupsallinone), mode);
            else if (logind)
                return fmemopen((void *)procselfcgroupslogind,
                                strlen(procselfcgroupslogind), mode);
            else
                return fmemopen((void *)procselfcgroups, strlen(procselfcgroups), mode);
        } else {
            errno = EACCES;
            return NULL;
        }
    }

    return realfopen(path, mode);
}

int access(const char *path, int mode)
{
    int ret;

    init_syms();

    if (STRPREFIX(path, SYSFS_PREFIX)) {
        init_sysfs();
        char *newpath;
        if (asprintf(&newpath, "%s/%s",
                     fakesysfsdir,
                     path + strlen(SYSFS_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
        ret = realaccess(newpath, mode);
        free(newpath);
    } else if (STREQ(path, "/proc/cgroups") ||
               STREQ(path, "/proc/self/cgroup")) {
        /* These files are readable for all. */
        ret = (mode == F_OK || mode == R_OK) ? 0 : -1;
    } else if (STREQ(path, "/proc/mounts")) {
        /* This one is accessible anytime for anybody. In fact, it's just
         * a symlink to /proc/self/mounts. */
        ret = 0;
    } else {
        ret = realaccess(path, mode);
    }
    return ret;
}

int __lxstat(int ver, const char *path, struct stat *sb)
{
    int ret;

    init_syms();

    if (STRPREFIX(path, SYSFS_PREFIX)) {
        init_sysfs();
        char *newpath;
        if (asprintf(&newpath, "%s/%s",
                     fakesysfsdir,
                     path + strlen(SYSFS_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
        ret = real__lxstat(ver, newpath, sb);
        free(newpath);
    } else if (STRPREFIX(path, fakedevicedir0)) {
        sb->st_mode = S_IFBLK;
        sb->st_rdev = makedev(8, 0);
        return 0;
    } else if (STRPREFIX(path, fakedevicedir1)) {
        sb->st_mode = S_IFBLK;
        sb->st_rdev = makedev(9, 0);
        return 0;
    } else {
        ret = real__lxstat(ver, path, sb);
    }
    return ret;
}

int lstat(const char *path, struct stat *sb)
{
    int ret;

    init_syms();

    if (STRPREFIX(path, SYSFS_PREFIX)) {
        init_sysfs();
        char *newpath;
        if (asprintf(&newpath, "%s/%s",
                     fakesysfsdir,
                     path + strlen(SYSFS_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
        ret = reallstat(newpath, sb);
        free(newpath);
    } else if (STRPREFIX(path, fakedevicedir0)) {
        sb->st_mode = S_IFBLK;
        sb->st_rdev = makedev(8, 0);
        return 0;
    } else if (STRPREFIX(path, fakedevicedir1)) {
        sb->st_mode = S_IFBLK;
        sb->st_rdev = makedev(9, 0);
        return 0;
    } else {
        ret = reallstat(path, sb);
    }
    return ret;
}

int __xstat(int ver, const char *path, struct stat *sb)
{
    int ret;

    init_syms();

    if (STRPREFIX(path, SYSFS_PREFIX)) {
        init_sysfs();
        char *newpath;
        if (asprintf(&newpath, "%s/%s",
                     fakesysfsdir,
                     path + strlen(SYSFS_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
        ret = real__xstat(ver, newpath, sb);
        free(newpath);
    } else if (STRPREFIX(path, fakedevicedir0)) {
        sb->st_mode = S_IFBLK;
        sb->st_rdev = makedev(8, 0);
        return 0;
    } else if (STRPREFIX(path, fakedevicedir1)) {
        sb->st_mode = S_IFBLK;
        sb->st_rdev = makedev(9, 0);
        return 0;
    } else {
        ret = real__xstat(ver, path, sb);
    }
    return ret;
}

int stat(const char *path, struct stat *sb)
{
    int ret;

    init_syms();

    if (STRPREFIX(path, SYSFS_PREFIX)) {
        init_sysfs();
        char *newpath;
        if (asprintf(&newpath, "%s/%s",
                     fakesysfsdir,
                     path + strlen(SYSFS_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
        ret = realstat(newpath, sb);
        free(newpath);
    } else if (STRPREFIX(path, fakedevicedir0)) {
        sb->st_mode = S_IFBLK;
        sb->st_rdev = makedev(8, 0);
        return 0;
    } else if (STRPREFIX(path, fakedevicedir1)) {
        sb->st_mode = S_IFBLK;
        sb->st_rdev = makedev(9, 0);
        return 0;
    } else {
        ret = realstat(path, sb);
    }
    return ret;
}

int mkdir(const char *path, mode_t mode)
{
    int ret;

    init_syms();

    if (STRPREFIX(path, SYSFS_PREFIX)) {
        init_sysfs();
        char *newpath;
        if (asprintf(&newpath, "%s/%s",
                     fakesysfsdir,
                     path + strlen(SYSFS_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
        ret = make_controller(newpath, mode);
        free(newpath);
    } else {
        ret = realmkdir(path, mode);
    }
    return ret;
}

int open(const char *path, int flags, ...)
{
    int ret;
    char *newpath = NULL;

    init_syms();

    if (STRPREFIX(path, SYSFS_PREFIX)) {
        init_sysfs();
        if (asprintf(&newpath, "%s/%s",
                     fakesysfsdir,
                     path + strlen(SYSFS_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
    }
    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        ret = realopen(newpath ? newpath : path, flags, mode);
    } else {
        ret = realopen(newpath ? newpath : path, flags);
    }
    free(newpath);
    return ret;
}
#else
/* Nothing to override on non-__linux__ platforms */
#endif
