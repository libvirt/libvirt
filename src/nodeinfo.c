/*
 * nodeinfo.c: Helper routines for OS specific node information
 *
 * Copyright (C) 2006-2008, 2010-2015 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <dirent.h>
#include <sys/utsname.h>
#include "conf/domain_conf.h"
#include <fcntl.h>
#include <sys/ioctl.h>

#if HAVE_LINUX_KVM_H
# include <linux/kvm.h>
#endif

#if defined(__FreeBSD__) || defined(__APPLE__)
# include <sys/time.h>
# include <sys/types.h>
# include <sys/sysctl.h>
# include <sys/resource.h>
#endif

#include "c-ctype.h"
#include "viralloc.h"
#include "nodeinfopriv.h"
#include "nodeinfo.h"
#include "physmem.h"
#include "virerror.h"
#include "count-one-bits.h"
#include "intprops.h"
#include "virarch.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virstring.h"
#include "virnuma.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("nodeinfo");

#define SYSFS_SYSTEM_PATH "/sys/devices/system"

#if defined(__FreeBSD__) || defined(__APPLE__)
static int
appleFreebsdNodeGetCPUCount(void)
{
    int ncpu_mib[2] = { CTL_HW, HW_NCPU };
    unsigned long ncpu;
    size_t ncpu_len = sizeof(ncpu);

    if (sysctl(ncpu_mib, 2, &ncpu, &ncpu_len, NULL, 0) == -1) {
        virReportSystemError(errno, "%s", _("Cannot obtain CPU count"));
        return -1;
    }

    return ncpu;
}

/* VIR_HW_PHYSMEM - the resulting value of HW_PHYSMEM of FreeBSD
 * is 64 bits while that of Mac OS X is still 32 bits.
 * Mac OS X provides HW_MEMSIZE for 64 bits version of HW_PHYSMEM
 * since 10.6.8 (Snow Leopard) at least.
 */
# ifdef HW_MEMSIZE
#  define VIR_HW_PHYSMEM HW_MEMSIZE
# else
#  define VIR_HW_PHYSMEM HW_PHYSMEM
# endif
static int
appleFreebsdNodeGetMemorySize(unsigned long *memory)
{
    int mib[2] = { CTL_HW, VIR_HW_PHYSMEM };
    unsigned long physmem;
    size_t len = sizeof(physmem);

    if (sysctl(mib, 2, &physmem, &len, NULL, 0) == -1) {
        virReportSystemError(errno, "%s", _("cannot obtain memory size"));
        return -1;
    }

    *memory = (unsigned long)(physmem / 1024);

    return 0;
}
#endif /* defined(__FreeBSD__) || defined(__APPLE__) */

#ifdef __FreeBSD__
# define BSD_CPU_STATS_ALL 4
# define BSD_MEMORY_STATS_ALL 4

# define TICK_TO_NSEC (1000ull * 1000ull * 1000ull / (stathz ? stathz : hz))

static int
freebsdNodeGetCPUStats(int cpuNum,
                       virNodeCPUStatsPtr params,
                       int *nparams)
{
    const char *sysctl_name;
    long *cpu_times;
    struct clockinfo clkinfo;
    size_t i, j, cpu_times_size, clkinfo_size;
    int cpu_times_num, offset, hz, stathz, ret = -1;
    struct field_cpu_map {
        const char *field;
        int idx[CPUSTATES];
    } cpu_map[] = {
        {VIR_NODE_CPU_STATS_KERNEL, {CP_SYS}},
        {VIR_NODE_CPU_STATS_USER, {CP_USER, CP_NICE}},
        {VIR_NODE_CPU_STATS_IDLE, {CP_IDLE}},
        {VIR_NODE_CPU_STATS_INTR, {CP_INTR}},
        {NULL, {0}}
    };

    if ((*nparams) == 0) {
        *nparams = BSD_CPU_STATS_ALL;
        return 0;
    }

    if ((*nparams) != BSD_CPU_STATS_ALL) {
        virReportInvalidArg(*nparams,
                            _("nparams in %s must be equal to %d"),
                            __FUNCTION__, BSD_CPU_STATS_ALL);
        return -1;
    }

    clkinfo_size = sizeof(clkinfo);
    if (sysctlbyname("kern.clockrate", &clkinfo, &clkinfo_size, NULL, 0) < 0) {
        virReportSystemError(errno,
                             _("sysctl failed for '%s'"),
                             "kern.clockrate");
        return -1;
    }

    stathz = clkinfo.stathz;
    hz = clkinfo.hz;

    if (cpuNum == VIR_NODE_CPU_STATS_ALL_CPUS) {
        sysctl_name = "kern.cp_time";
        cpu_times_num = 1;
        offset = 0;
    } else {
        sysctl_name = "kern.cp_times";
        cpu_times_num = appleFreebsdNodeGetCPUCount();

        if (cpuNum >= cpu_times_num) {
            virReportInvalidArg(cpuNum,
                                _("Invalid cpuNum in %s"),
                                __FUNCTION__);
            return -1;
        }

        offset = cpu_times_num * CPUSTATES;
    }

    cpu_times_size = sizeof(long) * cpu_times_num * CPUSTATES;

    if (VIR_ALLOC_N(cpu_times, cpu_times_num * CPUSTATES) < 0)
        goto cleanup;

    if (sysctlbyname(sysctl_name, cpu_times, &cpu_times_size, NULL, 0) < 0) {
        virReportSystemError(errno,
                             _("sysctl failed for '%s'"),
                             sysctl_name);
        goto cleanup;
    }

    for (i = 0; cpu_map[i].field != NULL; i++) {
        virNodeCPUStatsPtr param = &params[i];

        if (virStrcpyStatic(param->field, cpu_map[i].field) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Field '%s' too long for destination"),
                           cpu_map[i].field);
            goto cleanup;
        }

        param->value = 0;
        for (j = 0; j < ARRAY_CARDINALITY(cpu_map[i].idx); j++)
            param->value += cpu_times[offset + cpu_map[i].idx[j]] * TICK_TO_NSEC;
    }

    ret = 0;

 cleanup:
    VIR_FREE(cpu_times);

    return ret;
}

static int
freebsdNodeGetMemoryStats(virNodeMemoryStatsPtr params,
                          int *nparams)
{
    size_t i, j = 0;
    unsigned long pagesize = getpagesize() >> 10;
    long bufpages;
    size_t bufpages_size = sizeof(bufpages);
    struct field_sysctl_map {
        const char *field;
        const char *sysctl_name;
    } sysctl_map[] = {
        {VIR_NODE_MEMORY_STATS_TOTAL, "vm.stats.vm.v_page_count"},
        {VIR_NODE_MEMORY_STATS_FREE, "vm.stats.vm.v_free_count"},
        {VIR_NODE_MEMORY_STATS_CACHED, "vm.stats.vm.v_cache_count"},
        {NULL, NULL}
    };

    if ((*nparams) == 0) {
        *nparams = BSD_MEMORY_STATS_ALL;
        return 0;
    }

    if ((*nparams) != BSD_MEMORY_STATS_ALL) {
        virReportInvalidArg(nparams,
                            _("nparams in %s must be %d"),
                            __FUNCTION__, BSD_MEMORY_STATS_ALL);
        return -1;
    }

    for (i = 0; sysctl_map[i].field != NULL; i++) {
        u_int value;
        size_t value_size = sizeof(value);
        virNodeMemoryStatsPtr param;

        if (sysctlbyname(sysctl_map[i].sysctl_name, &value,
                         &value_size, NULL, 0) < 0) {
            virReportSystemError(errno,
                                 _("sysctl failed for '%s'"),
                                 sysctl_map[i].sysctl_name);
            return -1;
        }

        param = &params[j++];
        if (virStrcpyStatic(param->field, sysctl_map[i].field) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Field '%s' too long for destination"),
                           sysctl_map[i].field);
            return -1;
        }
        param->value = (unsigned long long)value * pagesize;
    }

    {
        virNodeMemoryStatsPtr param = &params[j++];

        if (sysctlbyname("vfs.bufspace", &bufpages, &bufpages_size, NULL, 0) < 0) {
            virReportSystemError(errno,
                                 _("sysctl failed for '%s'"),
                                 "vfs.bufspace");
            return -1;
        }
        if (virStrcpyStatic(param->field, VIR_NODE_MEMORY_STATS_BUFFERS) == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Field '%s' too long for destination"),
                           VIR_NODE_MEMORY_STATS_BUFFERS);
            return -1;
        }
        param->value = (unsigned long long)bufpages >> 10;
    }

    return 0;
}
#endif /* __FreeBSD__ */

#ifdef __linux__
# define CPUINFO_PATH "/proc/cpuinfo"
# define PROCSTAT_PATH "/proc/stat"
# define MEMINFO_PATH "/proc/meminfo"
# define SYSFS_MEMORY_SHARED_PATH "/sys/kernel/mm/ksm"
# define SYSFS_THREAD_SIBLINGS_LIST_LENGTH_MAX 8192

# define LINUX_NB_CPU_STATS 4
# define LINUX_NB_MEMORY_STATS_ALL 4
# define LINUX_NB_MEMORY_STATS_CELL 2

/* Return the positive decimal contents of the given
 * DIR/cpu%u/FILE, or -1 on error.  If DEFAULT_VALUE is non-negative
 * and the file could not be found, return that instead of an error;
 * this is useful for machines that cannot hot-unplug cpu0, or where
 * hot-unplugging is disabled, or where the kernel is too old
 * to support NUMA cells, etc.  */
static int
virNodeGetCpuValue(const char *dir, unsigned int cpu, const char *file,
                   int default_value)
{
    char *path;
    FILE *pathfp;
    int value = -1;
    char value_str[INT_BUFSIZE_BOUND(value)];
    char *tmp;

    if (virAsprintf(&path, "%s/cpu%u/%s", dir, cpu, file) < 0)
        return -1;

    pathfp = fopen(path, "r");
    if (pathfp == NULL) {
        if (default_value >= 0 && errno == ENOENT)
            value = default_value;
        else
            virReportSystemError(errno, _("cannot open %s"), path);
        goto cleanup;
    }

    if (fgets(value_str, sizeof(value_str), pathfp) == NULL) {
        virReportSystemError(errno, _("cannot read from %s"), path);
        goto cleanup;
    }
    if (virStrToLong_i(value_str, &tmp, 10, &value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("could not convert '%s' to an integer"),
                       value_str);
        goto cleanup;
    }

 cleanup:
    VIR_FORCE_FCLOSE(pathfp);
    VIR_FREE(path);

    return value;
}

static unsigned long
virNodeCountThreadSiblings(const char *dir, unsigned int cpu)
{
    unsigned long ret = 0;
    char *path;
    char *str = NULL;
    size_t i;

    if (virAsprintf(&path, "%s/cpu%u/topology/thread_siblings",
                    dir, cpu) < 0)
        return 0;

    if (!virFileExists(path)) {
        /* If file doesn't exist, then pretend our only
         * sibling is ourself */
        ret = 1;
        goto cleanup;
    }

    if (virFileReadAll(path, SYSFS_THREAD_SIBLINGS_LIST_LENGTH_MAX, &str) < 0)
        goto cleanup;

    for (i = 0; str[i] != '\0'; i++) {
        if (c_isxdigit(str[i]))
            ret += count_one_bits(virHexToBin(str[i]));
    }

 cleanup:
    VIR_FREE(str);
    VIR_FREE(path);
    return ret;
}

static int
virNodeParseSocket(const char *dir,
                   virArch arch,
                   unsigned int cpu)
{
    int ret = virNodeGetCpuValue(dir, cpu, "topology/physical_package_id", 0);

    if (ARCH_IS_ARM(arch) || ARCH_IS_PPC(arch) || ARCH_IS_S390(arch)) {
        /* arm, ppc and s390(x) has -1 */
        if (ret < 0)
            ret = 0;
    }

    return ret;
}

/* parses a node entry, returning number of processors in the node and
 * filling arguments */
static int
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(3)
ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(6)
ATTRIBUTE_NONNULL(7) ATTRIBUTE_NONNULL(8)
ATTRIBUTE_NONNULL(9)
virNodeParseNode(const char *node,
                 virArch arch,
                 virBitmapPtr present_cpus_map,
                 virBitmapPtr online_cpus_map,
                 int threads_per_subcore,
                 int *sockets,
                 int *cores,
                 int *threads,
                 int *offline)
{
    /* Biggest value we can expect to be used as either socket id
     * or core id. Bitmaps will need to be sized accordingly */
    const int ID_MAX = 4095;
    int ret = -1;
    int processors = 0;
    DIR *cpudir = NULL;
    struct dirent *cpudirent = NULL;
    virBitmapPtr node_cpus_map = NULL;
    virBitmapPtr sockets_map = NULL;
    virBitmapPtr *cores_maps = NULL;
    int npresent_cpus = virBitmapSize(present_cpus_map);
    int sock_max = 0;
    int sock;
    int core;
    size_t i;
    int siblings;
    unsigned int cpu;
    int direrr;

    *threads = 0;
    *cores = 0;
    *sockets = 0;

    if (!(cpudir = opendir(node))) {
        virReportSystemError(errno, _("cannot opendir %s"), node);
        goto cleanup;
    }

    /* Keep track of the CPUs that belong to the current node */
    if (!(node_cpus_map = virBitmapNew(npresent_cpus)))
        goto cleanup;

    /* enumerate sockets in the node */
    if (!(sockets_map = virBitmapNew(ID_MAX + 1)))
        goto cleanup;

    while ((direrr = virDirRead(cpudir, &cpudirent, node)) > 0) {
        if (sscanf(cpudirent->d_name, "cpu%u", &cpu) != 1)
            continue;

        if (!virBitmapIsBitSet(present_cpus_map, cpu))
            continue;

        /* Mark this CPU as part of the current node */
        if (virBitmapSetBit(node_cpus_map, cpu) < 0)
            goto cleanup;

        if (!virBitmapIsBitSet(online_cpus_map, cpu))
            continue;

        /* Parse socket */
        if ((sock = virNodeParseSocket(node, arch, cpu)) < 0)
            goto cleanup;
        if (sock > ID_MAX) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Socket %d can't be handled (max socket is %d)"),
                           sock, ID_MAX);
            goto cleanup;
        }

        if (virBitmapSetBit(sockets_map, sock) < 0)
            goto cleanup;

        if (sock > sock_max)
            sock_max = sock;
    }

    if (direrr < 0)
        goto cleanup;

    sock_max++;

    /* allocate cores maps for each socket */
    if (VIR_ALLOC_N(cores_maps, sock_max) < 0)
        goto cleanup;

    for (i = 0; i < sock_max; i++)
        if (!(cores_maps[i] = virBitmapNew(ID_MAX + 1)))
            goto cleanup;

    /* Iterate over all CPUs in the node, in ascending order */
    for (cpu = 0; cpu < npresent_cpus; cpu++) {

        /* Skip CPUs that are not part of the current node */
        if (!virBitmapIsBitSet(node_cpus_map, cpu))
            continue;

        if (!virBitmapIsBitSet(online_cpus_map, cpu)) {
            if (threads_per_subcore > 0 &&
                cpu % threads_per_subcore != 0 &&
                virBitmapIsBitSet(online_cpus_map,
                                  cpu - (cpu % threads_per_subcore))) {
                /* Secondary offline threads are counted as online when
                 * subcores are in use and the corresponding primary
                 * thread is online */
                processors++;
            } else {
                /* But they are counted as offline otherwise */
                (*offline)++;
            }
            continue;
        }

        processors++;

        /* Parse socket */
        if ((sock = virNodeParseSocket(node, arch, cpu)) < 0)
            goto cleanup;
        if (!virBitmapIsBitSet(sockets_map, sock)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("CPU socket topology has changed"));
            goto cleanup;
        }

        /* Parse core */
        if (ARCH_IS_S390(arch)) {
            /* logical cpu is equivalent to a core on s390 */
            core = cpu;
        } else {
            if ((core = virNodeGetCpuValue(node, cpu,
                                           "topology/core_id", 0)) < 0)
                goto cleanup;
        }
        if (core > ID_MAX) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Core %d can't be handled (max core is %d)"),
                           core, ID_MAX);
            goto cleanup;
        }

        if (virBitmapSetBit(cores_maps[sock], core) < 0)
            goto cleanup;

        if (!(siblings = virNodeCountThreadSiblings(node, cpu)))
            goto cleanup;

        if (siblings > *threads)
            *threads = siblings;
    }

    /* finalize the returned data */
    *sockets = virBitmapCountBits(sockets_map);

    for (i = 0; i < sock_max; i++) {
        if (!virBitmapIsBitSet(sockets_map, i))
            continue;

        core = virBitmapCountBits(cores_maps[i]);
        if (core > *cores)
            *cores = core;
    }

    if (threads_per_subcore > 0) {
        /* The thread count ignores offline threads, which means that only
         * only primary threads have been considered so far. If subcores
         * are in use, we need to also account for secondary threads */
        *threads *= threads_per_subcore;
    }
    ret = processors;

 cleanup:
    /* don't shadow a more serious error */
    if (cpudir && closedir(cpudir) < 0 && ret >= 0) {
        virReportSystemError(errno, _("problem closing %s"), node);
        ret = -1;
    }
    if (cores_maps)
        for (i = 0; i < sock_max; i++)
            virBitmapFree(cores_maps[i]);
    VIR_FREE(cores_maps);
    virBitmapFree(sockets_map);
    virBitmapFree(node_cpus_map);

    return ret;
}

/* Check whether the host subcore configuration is valid.
 *
 * A valid configuration is one where no secondary thread is online;
 * the primary thread in a subcore is always the first one */
static bool
nodeHasValidSubcoreConfiguration(const char *sysfs_prefix,
                                 int threads_per_subcore)
{
    virBitmapPtr online_cpus = NULL;
    int cpu = -1;
    bool ret = false;

    /* No point in checking if subcores are not in use */
    if (threads_per_subcore <= 0)
        goto cleanup;

    if (!(online_cpus = nodeGetOnlineCPUBitmap(sysfs_prefix)))
        goto cleanup;

    while ((cpu = virBitmapNextSetBit(online_cpus, cpu)) >= 0) {

        /* A single online secondary thread is enough to
         * make the configuration invalid */
        if (cpu % threads_per_subcore != 0)
            goto cleanup;
    }

    ret = true;

 cleanup:
    virBitmapFree(online_cpus);

    return ret;
}

int
linuxNodeInfoCPUPopulate(const char *sysfs_prefix,
                         FILE *cpuinfo,
                         virArch arch,
                         virNodeInfoPtr nodeinfo)
{
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SYSTEM_PATH;
    virBitmapPtr present_cpus_map = NULL;
    virBitmapPtr online_cpus_map = NULL;
    char line[1024];
    DIR *nodedir = NULL;
    struct dirent *nodedirent = NULL;
    int cpus, cores, socks, threads, offline = 0;
    int threads_per_subcore = 0;
    unsigned int node;
    int ret = -1;
    char *sysfs_nodedir = NULL;
    char *sysfs_cpudir = NULL;
    int direrr;

    /* Start with parsing CPU clock speed from /proc/cpuinfo */
    while (fgets(line, sizeof(line), cpuinfo) != NULL) {
        if (ARCH_IS_X86(arch)) {
            char *buf = line;
            if (STRPREFIX(buf, "cpu MHz")) {
                char *p;
                unsigned int ui;

                buf += 7;
                while (*buf && c_isspace(*buf))
                    buf++;

                if (*buf != ':' || !buf[1]) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("parsing cpu MHz from cpuinfo"));
                    goto cleanup;
                }

                if (virStrToLong_ui(buf+1, &p, 10, &ui) == 0 &&
                    /* Accept trailing fractional part.  */
                    (*p == '\0' || *p == '.' || c_isspace(*p)))
                    nodeinfo->mhz = ui;
            }

        } else if (ARCH_IS_PPC(arch)) {
            char *buf = line;
            if (STRPREFIX(buf, "clock")) {
                char *p;
                unsigned int ui;

                buf += 5;
                while (*buf && c_isspace(*buf))
                    buf++;

                if (*buf != ':' || !buf[1]) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("parsing cpu MHz from cpuinfo"));
                    goto cleanup;
                }

                if (virStrToLong_ui(buf+1, &p, 10, &ui) == 0 &&
                    /* Accept trailing fractional part.  */
                    (*p == '\0' || *p == '.' || c_isspace(*p)))
                    nodeinfo->mhz = ui;
                /* No other interesting infos are available in /proc/cpuinfo.
                 * However, there is a line identifying processor's version,
                 * identification and machine, but we don't want it to be caught
                 * and parsed in next iteration, because it is not in expected
                 * format and thus lead to error. */
            }
        } else if (ARCH_IS_ARM(arch)) {
            char *buf = line;
            if (STRPREFIX(buf, "BogoMIPS")) {
                char *p;
                unsigned int ui;

                buf += 8;
                while (*buf && c_isspace(*buf))
                    buf++;

                if (*buf != ':' || !buf[1]) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("parsing cpu MHz from cpuinfo"));
                    goto cleanup;
                }

                if (virStrToLong_ui(buf+1, &p, 10, &ui) == 0
                    /* Accept trailing fractional part.  */
                    && (*p == '\0' || *p == '.' || c_isspace(*p)))
                    nodeinfo->mhz = ui;
            }
        } else if (ARCH_IS_S390(arch)) {
            /* s390x has no realistic value for CPU speed,
             * assign a value of zero to signify this */
            nodeinfo->mhz = 0;
        } else {
            VIR_WARN("Parser for /proc/cpuinfo needs to be adapted for your architecture");
            break;
        }
    }

    /* Get information about what CPUs are present in the host and what
     * CPUs are online, so that we don't have to so for each node */
    present_cpus_map = nodeGetPresentCPUBitmap(sysfs_prefix);
    if (!present_cpus_map)
        goto cleanup;
    online_cpus_map = nodeGetOnlineCPUBitmap(sysfs_prefix);
    if (!online_cpus_map)
        goto cleanup;

    /* OK, we've parsed clock speed out of /proc/cpuinfo. Get the
     * core, node, socket, thread and topology information from /sys
     */
    if (virAsprintf(&sysfs_nodedir, "%s/node", prefix) < 0)
        goto cleanup;

    if (!(nodedir = opendir(sysfs_nodedir))) {
        /* the host isn't probably running a NUMA architecture */
        goto fallback;
    }

    /* PPC-KVM needs the secondary threads of a core to be offline on the
     * host. The kvm scheduler brings the secondary threads online in the
     * guest context. Moreover, P8 processor has split-core capability
     * where, there can be 1,2 or 4 subcores per core. The primaries of the
     * subcores alone will be online on the host for a subcore in the
     * host. Even though the actual threads per core for P8 processor is 8,
     * depending on the subcores_per_core = 1, 2 or 4, the threads per
     * subcore will vary accordingly to 8, 4 and 2 repectively.
     * So, On host threads_per_core what is arrived at from sysfs in the
     * current logic is actually the subcores_per_core. Threads per subcore
     * can only be obtained from the kvm device. For example, on P8 wih 1
     * core having 8 threads, sub_cores_percore=4, the threads 0,2,4 & 6
     * will be online. The sysfs reflects this and in the current logic
     * variable 'threads' will be 4 which is nothing but subcores_per_core.
     * If the user tampers the cpu online/offline states using chcpu or other
     * means, then it is an unsupported configuration for kvm.
     * The code below tries to keep in mind
     *  - when the libvirtd is run inside a KVM guest or Phyp based guest.
     *  - Or on the kvm host where user manually tampers the cpu states to
     *    offline/online randomly.
     * On hosts other than POWER this will be 0, in which case a simpler
     * thread-counting logic will be used  */
    if ((threads_per_subcore = nodeGetThreadsPerSubcore(arch)) < 0)
        goto cleanup;

    /* If the subcore configuration is not valid, just pretend subcores
     * are not in use and count threads one by one */
    if (!nodeHasValidSubcoreConfiguration(sysfs_prefix, threads_per_subcore))
        threads_per_subcore = 0;

    while ((direrr = virDirRead(nodedir, &nodedirent, sysfs_nodedir)) > 0) {
        if (sscanf(nodedirent->d_name, "node%u", &node) != 1)
            continue;

        nodeinfo->nodes++;

        if (virAsprintf(&sysfs_cpudir, "%s/node/%s",
                        prefix, nodedirent->d_name) < 0)
            goto cleanup;

        if ((cpus = virNodeParseNode(sysfs_cpudir, arch,
                                     present_cpus_map,
                                     online_cpus_map,
                                     threads_per_subcore,
                                     &socks, &cores,
                                     &threads, &offline)) < 0)
            goto cleanup;

        VIR_FREE(sysfs_cpudir);

        nodeinfo->cpus += cpus;

        if (socks > nodeinfo->sockets)
            nodeinfo->sockets = socks;

        if (cores > nodeinfo->cores)
            nodeinfo->cores = cores;

        if (threads > nodeinfo->threads)
            nodeinfo->threads = threads;
    }

    if (direrr < 0)
        goto cleanup;

    if (nodeinfo->cpus && nodeinfo->nodes)
        goto done;

 fallback:
    VIR_FREE(sysfs_cpudir);

    if (virAsprintf(&sysfs_cpudir, "%s/cpu", prefix) < 0)
        goto cleanup;

    if ((cpus = virNodeParseNode(sysfs_cpudir, arch,
                                 present_cpus_map,
                                 online_cpus_map,
                                 threads_per_subcore,
                                 &socks, &cores,
                                 &threads, &offline)) < 0)
        goto cleanup;

    nodeinfo->nodes = 1;
    nodeinfo->cpus = cpus;
    nodeinfo->sockets = socks;
    nodeinfo->cores = cores;
    nodeinfo->threads = threads;

 done:
    /* There should always be at least one cpu, socket, node, and thread. */
    if (nodeinfo->cpus == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("no CPUs found"));
        goto cleanup;
    }

    if (nodeinfo->sockets == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("no sockets found"));
        goto cleanup;
    }

    if (nodeinfo->threads == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("no threads found"));
        goto cleanup;
    }

    /* Now check if the topology makes sense. There are machines that don't
     * expose their real number of nodes or for example the AMD Bulldozer
     * architecture that exposes their Clustered integer core modules as both
     * threads and cores. This approach throws off our detection. Unfortunately
     * the nodeinfo structure isn't designed to carry the full topology so
     * we're going to lie about the detected topology to notify the user
     * to check the host capabilities for the actual topology. */
    if ((nodeinfo->nodes *
         nodeinfo->sockets *
         nodeinfo->cores *
         nodeinfo->threads) != (nodeinfo->cpus + offline)) {
        nodeinfo->nodes = 1;
        nodeinfo->sockets = 1;
        nodeinfo->cores = nodeinfo->cpus + offline;
        nodeinfo->threads = 1;
    }

    ret = 0;

 cleanup:
    /* don't shadow a more serious error */
    if (nodedir && closedir(nodedir) < 0 && ret >= 0) {
        virReportSystemError(errno, _("problem closing %s"), sysfs_nodedir);
        ret = -1;
    }

    virBitmapFree(present_cpus_map);
    virBitmapFree(online_cpus_map);
    VIR_FREE(sysfs_nodedir);
    VIR_FREE(sysfs_cpudir);
    return ret;
}

static int
virNodeCPUStatsAssign(virNodeCPUStatsPtr param,
                      const char *name,
                      unsigned long long value)
{
    if (virStrcpyStatic(param->field, name) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("kernel cpu time field is too long"
                               " for the destination"));
        return -1;
    }
    param->value = value;
    return 0;
}

# define TICK_TO_NSEC (1000ull * 1000ull * 1000ull / sysconf(_SC_CLK_TCK))

int
linuxNodeGetCPUStats(FILE *procstat,
                     int cpuNum,
                     virNodeCPUStatsPtr params,
                     int *nparams)
{
    int ret = -1;
    char line[1024];
    unsigned long long usr, ni, sys, idle, iowait;
    unsigned long long irq, softirq, steal, guest, guest_nice;
    char cpu_header[4 + INT_BUFSIZE_BOUND(cpuNum)];

    if ((*nparams) == 0) {
        /* Current number of cpu stats supported by linux */
        *nparams = LINUX_NB_CPU_STATS;
        ret = 0;
        goto cleanup;
    }

    if ((*nparams) != LINUX_NB_CPU_STATS) {
        virReportInvalidArg(*nparams,
                            _("nparams in %s must be equal to %d"),
                            __FUNCTION__, LINUX_NB_CPU_STATS);
        goto cleanup;
    }

    if (cpuNum == VIR_NODE_CPU_STATS_ALL_CPUS) {
        strcpy(cpu_header, "cpu ");
    } else {
        snprintf(cpu_header, sizeof(cpu_header), "cpu%d ", cpuNum);
    }

    while (fgets(line, sizeof(line), procstat) != NULL) {
        char *buf = line;

        if (STRPREFIX(buf, cpu_header)) { /* aka logical CPU time */
            if (sscanf(buf,
                       "%*s %llu %llu %llu %llu %llu" // user ~ iowait
                       "%llu %llu %llu %llu %llu",    // irq  ~ guest_nice
                       &usr, &ni, &sys, &idle, &iowait,
                       &irq, &softirq, &steal, &guest, &guest_nice) < 4) {
                continue;
            }

            if (virNodeCPUStatsAssign(&params[0], VIR_NODE_CPU_STATS_KERNEL,
                                      (sys + irq + softirq) * TICK_TO_NSEC) < 0)
                goto cleanup;

            if (virNodeCPUStatsAssign(&params[1], VIR_NODE_CPU_STATS_USER,
                                      (usr + ni) * TICK_TO_NSEC) < 0)
                goto cleanup;

            if (virNodeCPUStatsAssign(&params[2], VIR_NODE_CPU_STATS_IDLE,
                                      idle * TICK_TO_NSEC) < 0)
                goto cleanup;

            if (virNodeCPUStatsAssign(&params[3], VIR_NODE_CPU_STATS_IOWAIT,
                                      iowait * TICK_TO_NSEC) < 0)
                goto cleanup;

            ret = 0;
            goto cleanup;
        }
    }

    virReportInvalidArg(cpuNum,
                        _("Invalid cpuNum in %s"),
                        __FUNCTION__);

 cleanup:
    return ret;
}

static int
linuxNodeGetMemoryStats(FILE *meminfo,
                        int cellNum,
                        virNodeMemoryStatsPtr params,
                        int *nparams)
{
    int ret = -1;
    size_t i = 0, j = 0, k = 0;
    int found = 0;
    int nr_param;
    char line[1024];
    char meminfo_hdr[VIR_NODE_MEMORY_STATS_FIELD_LENGTH];
    unsigned long val;
    struct field_conv {
        const char *meminfo_hdr;  // meminfo header
        const char *field;        // MemoryStats field name
    } field_conv[] = {
        {"MemTotal:", VIR_NODE_MEMORY_STATS_TOTAL},
        {"MemFree:",  VIR_NODE_MEMORY_STATS_FREE},
        {"Buffers:",  VIR_NODE_MEMORY_STATS_BUFFERS},
        {"Cached:",   VIR_NODE_MEMORY_STATS_CACHED},
        {NULL,        NULL}
    };

    if (cellNum == VIR_NODE_MEMORY_STATS_ALL_CELLS) {
        nr_param = LINUX_NB_MEMORY_STATS_ALL;
    } else {
        nr_param = LINUX_NB_MEMORY_STATS_CELL;
    }

    if ((*nparams) == 0) {
        /* Current number of memory stats supported by linux */
        *nparams = nr_param;
        ret = 0;
        goto cleanup;
    }

    if ((*nparams) != nr_param) {
        virReportInvalidArg(nparams,
                            _("nparams in %s must be %d"),
                            __FUNCTION__, nr_param);
        goto cleanup;
    }

    while (fgets(line, sizeof(line), meminfo) != NULL) {
        char *buf = line;

        if (STRPREFIX(buf, "Node ")) {
            /*
             * /sys/devices/system/node/nodeX/meminfo format is below.
             * So, skip prefix "Node XX ".
             *
             * Node 0 MemTotal:        8386980 kB
             * Node 0 MemFree:         5300920 kB
             *         :
             */
            char *p;

            p = buf;
            for (i = 0; i < 2; i++) {
                p = strchr(p, ' ');
                if (p == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("no prefix found"));
                    goto cleanup;
                }
                p++;
            }
            buf = p;
        }

        if (sscanf(buf, "%s %lu kB", meminfo_hdr, &val) < 2)
            continue;

        for (j = 0; field_conv[j].meminfo_hdr != NULL; j++) {
            struct field_conv *convp = &field_conv[j];

            if (STREQ(meminfo_hdr, convp->meminfo_hdr)) {
                virNodeMemoryStatsPtr param = &params[k++];

                if (virStrcpyStatic(param->field, convp->field) == NULL) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("Field kernel memory too long for destination"));
                    goto cleanup;
                }
                param->value = val;
                found++;
                break;
            }
        }
        if (found >= nr_param)
            break;
    }

    if (found == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no available memory line found"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    return ret;
}

static char *
linuxGetCPUGlobalPath(const char *sysfs_prefix,
                      const char *file)
{
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SYSTEM_PATH;
    char *path = NULL;

    if (virAsprintf(&path, "%s/cpu/%s", prefix, file) < 0)
        return NULL;

    return path;
}

static char *
linuxGetCPUPresentPath(const char *sysfs_prefix)
{
    return linuxGetCPUGlobalPath(sysfs_prefix, "present");
}

static char *
linuxGetCPUOnlinePath(const char *sysfs_prefix)
{
    return linuxGetCPUGlobalPath(sysfs_prefix, "online");
}

/* Determine the number of CPUs (maximum CPU id + 1) from a file containing
 * a list of CPU ids, like the Linux sysfs cpu/present file */
static int
linuxParseCPUCount(const char *path)
{
    char *str = NULL;
    char *tmp;
    int ret = -1;

    if (virFileReadAll(path, 5 * VIR_DOMAIN_CPUMASK_LEN, &str) < 0)
        goto cleanup;

    tmp = str;
    do {
        if (virStrToLong_i(tmp, &tmp, 10, &ret) < 0 ||
            !strchr(",-\n", *tmp)) {
            virReportError(VIR_ERR_NO_SUPPORT,
                           _("failed to parse %s"), path);
            ret = -1;
            goto cleanup;
        }
    } while (*tmp++ != '\n');
    ret++;

 cleanup:
    VIR_FREE(str);
    return ret;
}

/*
 * Linux maintains cpu bit map under cpu/online. For example, if
 * cpuid=5's flag is not set and max cpu is 7, the map file shows
 * 0-4,6-7. This function parses it and returns cpumap.
 */
static virBitmapPtr
linuxParseCPUmap(int max_cpuid, const char *path)
{
    virBitmapPtr map = NULL;
    char *str = NULL;

    if (virFileReadAll(path, 5 * VIR_DOMAIN_CPUMASK_LEN, &str) < 0)
        goto error;

    if (virBitmapParse(str, 0, &map, max_cpuid) < 0)
        goto error;

    VIR_FREE(str);
    return map;

 error:
    VIR_FREE(str);
    virBitmapFree(map);
    return NULL;
}


static virBitmapPtr
virNodeGetSiblingsList(const char *dir, int cpu_id)
{
    char *path = NULL;
    char *buf = NULL;
    virBitmapPtr ret = NULL;

    if (virAsprintf(&path, "%s/cpu%u/topology/thread_siblings_list",
                    dir, cpu_id) < 0)
        goto cleanup;

    if (virFileReadAll(path, SYSFS_THREAD_SIBLINGS_LIST_LENGTH_MAX, &buf) < 0)
        goto cleanup;

    if (virBitmapParse(buf, 0, &ret, virNumaGetMaxCPUs()) < 0)
        goto cleanup;

 cleanup:
    VIR_FREE(buf);
    VIR_FREE(path);
    return ret;
}
#endif

int
nodeGetInfo(const char *sysfs_prefix ATTRIBUTE_UNUSED,
            virNodeInfoPtr nodeinfo)
{
    virArch hostarch = virArchFromHost();

    memset(nodeinfo, 0, sizeof(*nodeinfo));

    if (virStrcpyStatic(nodeinfo->model, virArchToString(hostarch)) == NULL)
        return -1;

#ifdef __linux__
    {
    int ret = -1;
    FILE *cpuinfo = fopen(CPUINFO_PATH, "r");

    if (!cpuinfo) {
        virReportSystemError(errno,
                             _("cannot open %s"), CPUINFO_PATH);
        return -1;
    }

    ret = linuxNodeInfoCPUPopulate(sysfs_prefix, cpuinfo,
                                   hostarch, nodeinfo);
    if (ret < 0)
        goto cleanup;

    /* Convert to KB. */
    nodeinfo->memory = physmem_total() / 1024;

 cleanup:
    VIR_FORCE_FCLOSE(cpuinfo);
    return ret;
    }
#elif defined(__FreeBSD__) || defined(__APPLE__)
    {
    nodeinfo->nodes = 1;
    nodeinfo->sockets = 1;
    nodeinfo->threads = 1;

    nodeinfo->cpus = appleFreebsdNodeGetCPUCount();
    if (nodeinfo->cpus == -1)
        return -1;

    nodeinfo->cores = nodeinfo->cpus;

    unsigned long cpu_freq;
    size_t cpu_freq_len = sizeof(cpu_freq);

# ifdef __FreeBSD__
    if (sysctlbyname("dev.cpu.0.freq", &cpu_freq, &cpu_freq_len, NULL, 0) < 0) {
        virReportSystemError(errno, "%s", _("cannot obtain CPU freq"));
        return -1;
    }

    nodeinfo->mhz = cpu_freq;
# else
    if (sysctlbyname("hw.cpufrequency", &cpu_freq, &cpu_freq_len, NULL, 0) < 0) {
        virReportSystemError(errno, "%s", _("cannot obtain CPU freq"));
        return -1;
    }

    nodeinfo->mhz = cpu_freq / 1000000;
# endif

    if (appleFreebsdNodeGetMemorySize(&nodeinfo->memory) < 0)
        return -1;

    return 0;
    }
#else
    /* XXX Solaris will need an impl later if they port QEMU driver */
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node info not implemented on this platform"));
    return -1;
#endif
}

int
nodeGetCPUStats(int cpuNum ATTRIBUTE_UNUSED,
                virNodeCPUStatsPtr params ATTRIBUTE_UNUSED,
                int *nparams ATTRIBUTE_UNUSED,
                unsigned int flags)
{
    virCheckFlags(0, -1);

#ifdef __linux__
    {
        int ret;
        FILE *procstat = fopen(PROCSTAT_PATH, "r");
        if (!procstat) {
            virReportSystemError(errno,
                                 _("cannot open %s"), PROCSTAT_PATH);
            return -1;
        }
        ret = linuxNodeGetCPUStats(procstat, cpuNum, params, nparams);
        VIR_FORCE_FCLOSE(procstat);

        return ret;
    }
#elif defined(__FreeBSD__)
    return freebsdNodeGetCPUStats(cpuNum, params, nparams);
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node CPU stats not implemented on this platform"));
    return -1;
#endif
}

int
nodeGetMemoryStats(const char *sysfs_prefix ATTRIBUTE_UNUSED,
                   int cellNum ATTRIBUTE_UNUSED,
                   virNodeMemoryStatsPtr params ATTRIBUTE_UNUSED,
                   int *nparams ATTRIBUTE_UNUSED,
                   unsigned int flags)
{
    virCheckFlags(0, -1);

#ifdef __linux__
    {
        int ret;
        const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SYSTEM_PATH;
        char *meminfo_path = NULL;
        FILE *meminfo;
        int max_node;

        if (cellNum == VIR_NODE_MEMORY_STATS_ALL_CELLS) {
            if (VIR_STRDUP(meminfo_path, MEMINFO_PATH) < 0)
                return -1;
        } else {
            if ((max_node = virNumaGetMaxNode()) < 0)
                return -1;

            if (cellNum > max_node) {
                virReportInvalidArg(cellNum,
                                    _("cellNum in %s must be less than or equal to %d"),
                                    __FUNCTION__, max_node);
                return -1;
            }

            if (virAsprintf(&meminfo_path, "%s/node/node%d/meminfo",
                            prefix, cellNum) < 0)
                return -1;
        }
        meminfo = fopen(meminfo_path, "r");

        if (!meminfo) {
            virReportSystemError(errno,
                                 _("cannot open %s"), meminfo_path);
            VIR_FREE(meminfo_path);
            return -1;
        }
        ret = linuxNodeGetMemoryStats(meminfo, cellNum, params, nparams);
        VIR_FORCE_FCLOSE(meminfo);
        VIR_FREE(meminfo_path);

        return ret;
    }
#elif defined(__FreeBSD__)
    return freebsdNodeGetMemoryStats(params, nparams);
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node memory stats not implemented on this platform"));
    return -1;
#endif
}

int
nodeGetCPUCount(const char *sysfs_prefix ATTRIBUTE_UNUSED)
{
#if defined(__linux__)
    /* To support older kernels that lack cpu/present, such as 2.6.18
     * in RHEL5, we fall back to count cpu/cpuNN entries; this assumes
     * that such kernels also lack hotplug, and therefore cpu/cpuNN
     * will be consecutive.
     */
    char *present_path = NULL;
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SYSTEM_PATH;
    char *cpupath = NULL;
    int ncpu = -1;

    if (!(present_path = linuxGetCPUPresentPath(sysfs_prefix)))
        return -1;

    if (virFileExists(present_path)) {
        ncpu = linuxParseCPUCount(present_path);
        goto cleanup;
    }

    if (virAsprintf(&cpupath, "%s/cpu/cpu0", prefix) < 0)
        goto cleanup;
    if (virFileExists(cpupath)) {
        ncpu = 0;
        do {
            ncpu++;
            VIR_FREE(cpupath);
            if (virAsprintf(&cpupath, "%s/cpu/cpu%d",
                            prefix, ncpu) < 0) {
                ncpu = -1;
                goto cleanup;
            }
        } while (virFileExists(cpupath));
    } else {
        /* no cpu/cpu0: we give up */
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("host cpu counting not supported on this node"));
    }

 cleanup:
    VIR_FREE(present_path);
    VIR_FREE(cpupath);
    return ncpu;
#elif defined(__FreeBSD__) || defined(__APPLE__)
    return appleFreebsdNodeGetCPUCount();
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("host cpu counting not implemented on this platform"));
    return -1;
#endif
}

virBitmapPtr
nodeGetPresentCPUBitmap(const char *sysfs_prefix ATTRIBUTE_UNUSED)
{
#ifdef __linux__
    virBitmapPtr present_cpus = NULL;
    char *present_path = NULL;
    int npresent_cpus;

    if ((npresent_cpus = nodeGetCPUCount(sysfs_prefix)) < 0)
        goto cleanup;

    if (!(present_path = linuxGetCPUPresentPath(sysfs_prefix)))
        goto cleanup;

    /* If the cpu/present file is available, parse it and exit */
    if (virFileExists(present_path)) {
        present_cpus = linuxParseCPUmap(npresent_cpus, present_path);
        goto cleanup;
    }

    /* If the file is not available, we can assume that the kernel is
     * too old to support non-consecutive CPU ids and just mark all
     * possible CPUs as present */
    if (!(present_cpus = virBitmapNew(npresent_cpus)))
        goto cleanup;

    virBitmapSetAll(present_cpus);

 cleanup:
    VIR_FREE(present_path);

    return present_cpus;
#endif
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node present CPU map not implemented on this platform"));
    return NULL;
}

virBitmapPtr
nodeGetOnlineCPUBitmap(const char *sysfs_prefix ATTRIBUTE_UNUSED)
{
#ifdef __linux__
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SYSTEM_PATH;
    char *online_path = NULL;
    char *cpudir = NULL;
    virBitmapPtr cpumap;
    int present;

    present = nodeGetCPUCount(sysfs_prefix);
    if (present < 0)
        return NULL;

    if (!(online_path = linuxGetCPUOnlinePath(sysfs_prefix)))
        return NULL;
    if (virFileExists(online_path)) {
        cpumap = linuxParseCPUmap(present, online_path);
    } else {
        size_t i;

        cpumap = virBitmapNew(present);
        if (!cpumap)
            goto cleanup;

        if (virAsprintf(&cpudir, "%s/cpu", prefix) < 0)
            goto cleanup;

        for (i = 0; i < present; i++) {
            int online = virNodeGetCpuValue(cpudir, i, "online", 1);
            if (online < 0) {
                virBitmapFree(cpumap);
                cpumap = NULL;
                goto cleanup;
            }
            if (online)
                ignore_value(virBitmapSetBit(cpumap, i));
        }
    }

 cleanup:
    VIR_FREE(online_path);
    VIR_FREE(cpudir);
    return cpumap;
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node online CPU map not implemented on this platform"));
    return NULL;
#endif
}

#ifdef __linux__
static int
nodeSetMemoryParameterValue(virTypedParameterPtr param)
{
    char *path = NULL;
    char *strval = NULL;
    int ret = -1;
    int rc = -1;

    char *field = strchr(param->field, '_');
    sa_assert(field);
    field++;
    if (virAsprintf(&path, "%s/%s",
                    SYSFS_MEMORY_SHARED_PATH, field) < 0) {
        ret = -2;
        goto cleanup;
    }

    if (virAsprintf(&strval, "%u", param->value.ui) == -1) {
        ret = -2;
        goto cleanup;
    }

    if ((rc = virFileWriteStr(path, strval, 0)) < 0) {
        virReportSystemError(-rc, _("failed to set %s"), param->field);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(path);
    VIR_FREE(strval);
    return ret;
}

static bool
nodeMemoryParametersIsAllSupported(virTypedParameterPtr params,
                                   int nparams)
{
    char *path = NULL;
    size_t i;

    for (i = 0; i < nparams; i++) {
        virTypedParameterPtr param = &params[i];

        char *field = strchr(param->field, '_');
        sa_assert(field);
        field++;
        if (virAsprintf(&path, "%s/%s",
                        SYSFS_MEMORY_SHARED_PATH, field) < 0)
            return false;

        if (!virFileExists(path)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Parameter '%s' is not supported by "
                             "this kernel"), param->field);
            VIR_FREE(path);
            return false;
        }

        VIR_FREE(path);
    }

    return true;
}
#endif

int
nodeSetMemoryParameters(virTypedParameterPtr params ATTRIBUTE_UNUSED,
                        int nparams ATTRIBUTE_UNUSED,
                        unsigned int flags)
{
    virCheckFlags(0, -1);

#ifdef __linux__
    size_t i;
    int rc;

    if (virTypedParamsValidate(params, nparams,
                               VIR_NODE_MEMORY_SHARED_PAGES_TO_SCAN,
                               VIR_TYPED_PARAM_UINT,
                               VIR_NODE_MEMORY_SHARED_SLEEP_MILLISECS,
                               VIR_TYPED_PARAM_UINT,
                               VIR_NODE_MEMORY_SHARED_MERGE_ACROSS_NODES,
                               VIR_TYPED_PARAM_UINT,
                               NULL) < 0)
        return -1;

    if (!nodeMemoryParametersIsAllSupported(params, nparams))
        return -1;

    for (i = 0; i < nparams; i++) {
        rc = nodeSetMemoryParameterValue(&params[i]);

        if (rc < 0)
            return -1;
    }

    return 0;
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node set memory parameters not implemented"
                     " on this platform"));
    return -1;
#endif
}

#ifdef __linux__
static int
nodeGetMemoryParameterValue(const char *field,
                            void *value)
{
    char *path = NULL;
    char *buf = NULL;
    char *tmp = NULL;
    int ret = -1;
    int rc = -1;

    if (virAsprintf(&path, "%s/%s",
                    SYSFS_MEMORY_SHARED_PATH, field) < 0)
        goto cleanup;

    if (!virFileExists(path)) {
        ret = -2;
        goto cleanup;
    }

    if (virFileReadAll(path, 1024, &buf) < 0)
        goto cleanup;

    if ((tmp = strchr(buf, '\n')))
        *tmp = '\0';

    if (STREQ(field, "pages_to_scan")   ||
        STREQ(field, "sleep_millisecs") ||
        STREQ(field, "merge_across_nodes"))
        rc = virStrToLong_ui(buf, NULL, 10, (unsigned int *)value);
    else if (STREQ(field, "pages_shared")    ||
             STREQ(field, "pages_sharing")   ||
             STREQ(field, "pages_unshared")  ||
             STREQ(field, "pages_volatile")  ||
             STREQ(field, "full_scans"))
        rc = virStrToLong_ull(buf, NULL, 10, (unsigned long long *)value);

    if (rc < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse %s"), field);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(path);
    VIR_FREE(buf);
    return ret;
}
#endif

#define NODE_MEMORY_PARAMETERS_NUM 8
int
nodeGetMemoryParameters(virTypedParameterPtr params ATTRIBUTE_UNUSED,
                        int *nparams ATTRIBUTE_UNUSED,
                        unsigned int flags)
{
    virCheckFlags(VIR_TYPED_PARAM_STRING_OKAY, -1);

#ifdef __linux__
    unsigned int pages_to_scan;
    unsigned int sleep_millisecs;
    unsigned int merge_across_nodes;
    unsigned long long pages_shared;
    unsigned long long pages_sharing;
    unsigned long long pages_unshared;
    unsigned long long pages_volatile;
    unsigned long long full_scans = 0;
    size_t i;
    int ret;

    if ((*nparams) == 0) {
        *nparams = NODE_MEMORY_PARAMETERS_NUM;
        return 0;
    }

    for (i = 0; i < *nparams && i < NODE_MEMORY_PARAMETERS_NUM; i++) {
        virTypedParameterPtr param = &params[i];

        switch (i) {
        case 0:
            ret = nodeGetMemoryParameterValue("pages_to_scan", &pages_to_scan);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_PAGES_TO_SCAN,
                                        VIR_TYPED_PARAM_UINT, pages_to_scan) < 0)
                return -1;

            break;

        case 1:
            ret = nodeGetMemoryParameterValue("sleep_millisecs", &sleep_millisecs);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_SLEEP_MILLISECS,
                                        VIR_TYPED_PARAM_UINT, sleep_millisecs) < 0)
                return -1;

            break;

        case 2:
            ret = nodeGetMemoryParameterValue("pages_shared", &pages_shared);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_PAGES_SHARED,
                                        VIR_TYPED_PARAM_ULLONG, pages_shared) < 0)
                return -1;

            break;

        case 3:
            ret = nodeGetMemoryParameterValue("pages_sharing", &pages_sharing);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_PAGES_SHARING,
                                        VIR_TYPED_PARAM_ULLONG, pages_sharing) < 0)
                return -1;

            break;

        case 4:
            ret = nodeGetMemoryParameterValue("pages_unshared", &pages_unshared);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_PAGES_UNSHARED,
                                        VIR_TYPED_PARAM_ULLONG, pages_unshared) < 0)
                return -1;

            break;

        case 5:
            ret = nodeGetMemoryParameterValue("pages_volatile", &pages_volatile);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_PAGES_VOLATILE,
                                        VIR_TYPED_PARAM_ULLONG, pages_volatile) < 0)
                return -1;

            break;

        case 6:
            ret = nodeGetMemoryParameterValue("full_scans", &full_scans);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_FULL_SCANS,
                                        VIR_TYPED_PARAM_ULLONG, full_scans) < 0)
                return -1;

            break;

        case 7:
            ret = nodeGetMemoryParameterValue("merge_across_nodes", &merge_across_nodes);
            if (ret == -2)
                continue;
            else if (ret == -1)
                return -1;

            if (virTypedParameterAssign(param, VIR_NODE_MEMORY_SHARED_MERGE_ACROSS_NODES,
                                        VIR_TYPED_PARAM_UINT, merge_across_nodes) < 0)
                return -1;

            break;
        }
    }

    return 0;
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node get memory parameters not implemented"
                     " on this platform"));
    return -1;
#endif
}

int
nodeGetCPUMap(const char *sysfs_prefix,
              unsigned char **cpumap,
              unsigned int *online,
              unsigned int flags)
{
    virBitmapPtr cpus = NULL;
    int ret = -1;
    int dummy;

    virCheckFlags(0, -1);

    if (!cpumap && !online)
        return nodeGetCPUCount(sysfs_prefix);

    if (!(cpus = nodeGetOnlineCPUBitmap(sysfs_prefix)))
        goto cleanup;

    if (cpumap && virBitmapToData(cpus, cpumap, &dummy) < 0)
        goto cleanup;
    if (online)
        *online = virBitmapCountBits(cpus);

    ret = virBitmapSize(cpus);

 cleanup:
    if (ret < 0 && cpumap)
        VIR_FREE(*cpumap);
    virBitmapFree(cpus);
    return ret;
}

static int
nodeCapsInitNUMAFake(const char *sysfs_prefix,
                     const char *cpupath ATTRIBUTE_UNUSED,
                     virCapsPtr caps ATTRIBUTE_UNUSED)
{
    virNodeInfo nodeinfo;
    virCapsHostNUMACellCPUPtr cpus;
    int ncpus;
    int s, c, t;
    int id, cid;
    int onlinecpus ATTRIBUTE_UNUSED;

    if (nodeGetInfo(sysfs_prefix, &nodeinfo) < 0)
        return -1;

    ncpus = VIR_NODEINFO_MAXCPUS(nodeinfo);
    onlinecpus = nodeinfo.cpus;

    if (VIR_ALLOC_N(cpus, ncpus) < 0)
        return -1;

    id = cid = 0;
    for (s = 0; s < nodeinfo.sockets; s++) {
        for (c = 0; c < nodeinfo.cores; c++) {
            for (t = 0; t < nodeinfo.threads; t++) {
#ifdef __linux__
                if (virNodeGetCpuValue(cpupath, id, "online", 1)) {
#endif
                    cpus[cid].id = id;
                    cpus[cid].socket_id = s;
                    cpus[cid].core_id = c;
                    if (!(cpus[cid].siblings = virBitmapNew(ncpus)))
                        goto error;
                    ignore_value(virBitmapSetBit(cpus[cid].siblings, id));
                    cid++;
#ifdef __linux__
                }
#endif

                id++;
            }
        }
    }

    if (virCapabilitiesAddHostNUMACell(caps, 0,
                                       nodeinfo.memory,
#ifdef __linux__
                                       onlinecpus, cpus,
#else
                                       ncpus, cpus,
#endif
                                       0, NULL,
                                       0, NULL) < 0)
        goto error;

    return 0;

 error:
    for (; id >= 0; id--)
        virBitmapFree(cpus[id].siblings);
    VIR_FREE(cpus);
    return -1;
}

static int
nodeGetCellsFreeMemoryFake(unsigned long long *freeMems,
                           int startCell,
                           int maxCells ATTRIBUTE_UNUSED)
{
    double avail = physmem_available();

    if (startCell != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %d out of range (0-%d)"),
                       startCell, 0);
        return -1;
    }

    freeMems[0] = (unsigned long long)avail;

    if (!freeMems[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot determine free memory"));
        return -1;
    }

    return 1;
}

static int
nodeGetMemoryFake(unsigned long long *mem,
                  unsigned long long *freeMem)
{
    int ret = -1;

#if defined(__FreeBSD__)
    unsigned long pagesize = getpagesize();
    u_int value;
    size_t value_size = sizeof(value);

    if (mem) {
        if (sysctlbyname("vm.stats.vm.v_page_count", &value,
                         &value_size, NULL, 0) < 0) {
            virReportSystemError(errno, "%s",
                                 _("sysctl failed for vm.stats.vm.v_page_count"));
            goto cleanup;
        }
        *mem = value * (unsigned long long)pagesize;
    }

    if (freeMem) {
        if (sysctlbyname("vm.stats.vm.v_free_count", &value,
                         &value_size, NULL, 0) < 0) {
            virReportSystemError(errno, "%s",
                                 _("sysctl failed for vm.stats.vm.v_free_count"));
            goto cleanup;
        }

        *freeMem = value * (unsigned long long)pagesize;
    }

#else
    if (mem) {
        double total = physmem_total();
        if (!total) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot determine free memory"));
            goto cleanup;
        }

        *mem = (unsigned long long) total;
    }

    if (freeMem) {
        double avail = physmem_available();

        if (!avail) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot determine free memory"));
            goto cleanup;
        }

        *freeMem = (unsigned long long) avail;
    }
#endif

    ret = 0;
 cleanup:
    return ret;
}

/* returns 1 on success, 0 if the detection failed and -1 on hard error */
static int
virNodeCapsFillCPUInfo(const char *cpupath ATTRIBUTE_UNUSED,
                       int cpu_id ATTRIBUTE_UNUSED,
                       virCapsHostNUMACellCPUPtr cpu ATTRIBUTE_UNUSED)
{
#ifdef __linux__
    int tmp;
    cpu->id = cpu_id;

    if ((tmp = virNodeGetCpuValue(cpupath, cpu_id,
                                  "topology/physical_package_id", -1)) < 0)
        return 0;

    cpu->socket_id = tmp;

    if ((tmp = virNodeGetCpuValue(cpupath, cpu_id,
                                  "topology/core_id", -1)) < 0)
        return 0;

    cpu->core_id = tmp;

    if (!(cpu->siblings = virNodeGetSiblingsList(cpupath, cpu_id)))
        return -1;

    return 0;
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node cpu info not implemented on this platform"));
    return -1;
#endif
}

static int
virNodeCapsGetSiblingInfo(int node,
                          virCapsHostNUMACellSiblingInfoPtr *siblings,
                          int *nsiblings)
{
    virCapsHostNUMACellSiblingInfoPtr tmp = NULL;
    int tmp_size = 0;
    int ret = -1;
    int *distances = NULL;
    int ndistances = 0;
    size_t i;

    if (virNumaGetDistances(node, &distances, &ndistances) < 0)
        goto cleanup;

    if (!distances) {
        *siblings = NULL;
        *nsiblings = 0;
        return 0;
    }

    if (VIR_ALLOC_N(tmp, ndistances) < 0)
        goto cleanup;

    for (i = 0; i < ndistances; i++) {
        if (!distances[i])
            continue;

        tmp[tmp_size].node = i;
        tmp[tmp_size].distance = distances[i];
        tmp_size++;
    }

    if (VIR_REALLOC_N(tmp, tmp_size) < 0)
        goto cleanup;

    *siblings = tmp;
    *nsiblings = tmp_size;
    tmp = NULL;
    tmp_size = 0;
    ret = 0;
 cleanup:
    VIR_FREE(distances);
    VIR_FREE(tmp);
    return ret;
}

static int
virNodeCapsGetPagesInfo(int node,
                        virCapsHostNUMACellPageInfoPtr *pageinfo,
                        int *npageinfo)
{
    int ret = -1;
    unsigned int *pages_size = NULL, *pages_avail = NULL;
    size_t npages, i;

    if (virNumaGetPages(node, &pages_size, &pages_avail, NULL, &npages) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(*pageinfo, npages) < 0)
        goto cleanup;
    *npageinfo = npages;

    for (i = 0; i < npages; i++) {
        (*pageinfo)[i].size = pages_size[i];
        (*pageinfo)[i].avail = pages_avail[i];
    }

    ret = 0;

 cleanup:
    VIR_FREE(pages_avail);
    VIR_FREE(pages_size);
    return ret;
}

int
nodeCapsInitNUMA(const char *sysfs_prefix,
                 virCapsPtr caps)
{
    const char *prefix = sysfs_prefix ? sysfs_prefix : SYSFS_SYSTEM_PATH;
    char *cpupath;
    int n;
    unsigned long long memory;
    virCapsHostNUMACellCPUPtr cpus = NULL;
    virBitmapPtr cpumap = NULL;
    virCapsHostNUMACellSiblingInfoPtr siblings = NULL;
    int nsiblings = 0;
    virCapsHostNUMACellPageInfoPtr pageinfo = NULL;
    int npageinfo;
    int ret = -1;
    int ncpus = 0;
    int cpu;
    bool topology_failed = false;
    int max_node;

    if (virAsprintf(&cpupath, "%s/cpu", prefix) < 0)
        return -1;

    if (!virNumaIsAvailable()) {
        ret = nodeCapsInitNUMAFake(sysfs_prefix, cpupath, caps);
        goto cleanup;
    }

    if ((max_node = virNumaGetMaxNode()) < 0)
        goto cleanup;

    for (n = 0; n <= max_node; n++) {
        size_t i;

        if ((ncpus = virNumaGetNodeCPUs(n, &cpumap)) < 0) {
            if (ncpus == -2)
                continue;

            goto cleanup;
        }

        if (VIR_ALLOC_N(cpus, ncpus) < 0)
            goto cleanup;
        cpu = 0;

        for (i = 0; i < virBitmapSize(cpumap); i++) {
            if (virBitmapIsBitSet(cpumap, i)) {
                if (virNodeCapsFillCPUInfo(cpupath, i, cpus + cpu++) < 0) {
                    topology_failed = true;
                    virResetLastError();
                }
            }
        }

        if (virNodeCapsGetSiblingInfo(n, &siblings, &nsiblings) < 0)
            goto cleanup;

        if (virNodeCapsGetPagesInfo(n, &pageinfo, &npageinfo) < 0)
            goto cleanup;

        /* Detect the amount of memory in the numa cell in KiB */
        virNumaGetNodeMemory(n, &memory, NULL);
        memory >>= 10;

        if (virCapabilitiesAddHostNUMACell(caps, n, memory,
                                           ncpus, cpus,
                                           nsiblings, siblings,
                                           npageinfo, pageinfo) < 0)
            goto cleanup;

        cpus = NULL;
        siblings = NULL;
        pageinfo = NULL;
        virBitmapFree(cpumap);
        cpumap = NULL;
    }

    ret = 0;

 cleanup:
    if ((topology_failed || ret < 0) && cpus)
        virCapabilitiesClearHostNUMACellCPUTopology(cpus, ncpus);

    virBitmapFree(cpumap);
    VIR_FREE(cpus);
    VIR_FREE(siblings);
    VIR_FREE(pageinfo);
    VIR_FREE(cpupath);
    return ret;
}


int
nodeGetCellsFreeMemory(unsigned long long *freeMems,
                       int startCell,
                       int maxCells)
{
    unsigned long long mem;
    int n, lastCell, numCells;
    int ret = -1;
    int maxCell;

    if (!virNumaIsAvailable())
        return nodeGetCellsFreeMemoryFake(freeMems,
                                          startCell, maxCells);

    if ((maxCell = virNumaGetMaxNode()) < 0)
        return 0;

    if (startCell > maxCell) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %d out of range (0-%d)"),
                       startCell, maxCell);
        goto cleanup;
    }
    lastCell = startCell + maxCells - 1;
    if (lastCell > maxCell)
        lastCell = maxCell;

    for (numCells = 0, n = startCell; n <= lastCell; n++) {
        virNumaGetNodeMemory(n, NULL, &mem);

        freeMems[numCells++] = mem;
    }
    ret = numCells;

 cleanup:
    return ret;
}

int
nodeGetMemory(unsigned long long *mem,
              unsigned long long *freeMem)
{
    int max_node;
    int n;

    if (mem)
        *mem = 0;

    if (freeMem)
        *freeMem = 0;

    if (!virNumaIsAvailable())
        return nodeGetMemoryFake(mem, freeMem);

    if ((max_node = virNumaGetMaxNode()) < 0)
        return -1;

    for (n = 0; n <= max_node; n++) {
        unsigned long long tmp_mem = 0, tmp_freeMem = 0;

        if (!virNumaNodeIsAvailable(n))
            continue;

        if (virNumaGetNodeMemory(n, &tmp_mem, &tmp_freeMem) < 0)
            return -1;

        if (mem)
            *mem += tmp_mem;

        if (freeMem)
            *freeMem += tmp_freeMem;
    }

    return 0;
}

int
nodeGetFreePages(unsigned int npages,
                 unsigned int *pages,
                 int startCell,
                 unsigned int cellCount,
                 unsigned long long *counts)
{
    int ret = -1;
    int cell, lastCell;
    size_t i, ncounts = 0;

    if ((lastCell = virNumaGetMaxNode()) < 0)
        return 0;

    if (startCell > lastCell) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %d out of range (0-%d)"),
                       startCell, lastCell);
        goto cleanup;
    }

    lastCell = MIN(lastCell, startCell + (int) cellCount - 1);

    for (cell = startCell; cell <= lastCell; cell++) {
        for (i = 0; i < npages; i++) {
            unsigned int page_size = pages[i];
            unsigned int page_free;

            if (virNumaGetPageInfo(cell, page_size, 0, NULL, &page_free) < 0)
                goto cleanup;

            counts[ncounts++] = page_free;
        }
    }

    if (!ncounts) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no suitable info found"));
        goto cleanup;
    }

    ret = ncounts;
 cleanup:
    return ret;
}

int
nodeAllocPages(unsigned int npages,
               unsigned int *pageSizes,
               unsigned long long *pageCounts,
               int startCell,
               unsigned int cellCount,
               bool add)
{
    int ret = -1;
    int cell, lastCell;
    size_t i, ncounts = 0;

    if ((lastCell = virNumaGetMaxNode()) < 0)
        return 0;

    if (startCell > lastCell) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("start cell %d out of range (0-%d)"),
                       startCell, lastCell);
        goto cleanup;
    }

    lastCell = MIN(lastCell, startCell + (int) cellCount - 1);

    for (cell = startCell; cell <= lastCell; cell++) {
        for (i = 0; i < npages; i++) {
            unsigned int page_size = pageSizes[i];
            unsigned long long page_count = pageCounts[i];

            if (virNumaSetPagePoolSize(cell, page_size, page_count, add) < 0)
                goto cleanup;

            ncounts++;
        }
    }

    ret = ncounts;
 cleanup:
    return ret;
}

#if HAVE_LINUX_KVM_H && defined(KVM_CAP_PPC_SMT)

/* Get the number of threads per subcore.
 *
 * This will be 2, 4 or 8 on POWER hosts, depending on the current
 * micro-threading configuration, and 0 everywhere else.
 *
 * Returns the number of threads per subcore if subcores are in use, zero
 * if subcores are not in use, and a negative value on error */
int
nodeGetThreadsPerSubcore(virArch arch)
{
    int threads_per_subcore = 0;
    const char *kvmpath = "/dev/kvm";
    int kvmfd;

    if (ARCH_IS_PPC64(arch)) {

        /* It's okay if /dev/kvm doesn't exist, because
         *   a. we might be running in a guest
         *   b. the kvm module might not be installed or enabled
         * In either case, falling back to the subcore-unaware thread
         * counting logic is the right thing to do */
        if (!virFileExists(kvmpath))
            goto out;

        if ((kvmfd = open(kvmpath, O_RDONLY)) < 0) {
            /* This can happen when running as a regular user if
             * permissions are tight enough, in which case erroring out
             * is better than silently falling back and reporting
             * different nodeinfo depending on the user */
            virReportSystemError(errno,
                                 _("Failed to open '%s'"),
                                 kvmpath);
            threads_per_subcore = -1;
            goto out;
        }

        /* For Phyp and KVM based guests the ioctl for KVM_CAP_PPC_SMT
         * returns zero and both primary and secondary threads will be
         * online */
        threads_per_subcore = ioctl(kvmfd,
                                    KVM_CHECK_EXTENSION,
                                    KVM_CAP_PPC_SMT);

        VIR_FORCE_CLOSE(kvmfd);
    }

 out:
    return threads_per_subcore;
}

#else

/* Fallback for nodeGetThreadsPerSubcore() used when KVM headers
 * are not available on the system */
int
nodeGetThreadsPerSubcore(virArch arch ATTRIBUTE_UNUSED)
{
    return 0;
}

#endif /* HAVE_LINUX_KVM_H && defined(KVM_CAP_PPC_SMT) */
