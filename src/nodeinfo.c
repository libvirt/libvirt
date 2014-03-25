/*
 * nodeinfo.c: Helper routines for OS specific node information
 *
 * Copyright (C) 2006-2008, 2010-2013 Red Hat, Inc.
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
#include <sched.h>
#include "conf/domain_conf.h"

#if defined(__FreeBSD__) || defined(__APPLE__)
# include <sys/time.h>
# include <sys/types.h>
# include <sys/sysctl.h>
# include <sys/resource.h>
#endif

#include "c-ctype.h"
#include "viralloc.h"
#include "nodeinfopriv.h"
#include "physmem.h"
#include "virerror.h"
#include "count-one-bits.h"
#include "intprops.h"
#include "virarch.h"
#include "virfile.h"
#include "virtypedparam.h"
#include "virstring.h"
#include "virnuma.h"

#define VIR_FROM_THIS VIR_FROM_NONE

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
# define SYSFS_SYSTEM_PATH "/sys/devices/system"
# define SYSFS_CPU_PATH SYSFS_SYSTEM_PATH"/cpu"
# define PROCSTAT_PATH "/proc/stat"
# define MEMINFO_PATH "/proc/meminfo"
# define SYSFS_MEMORY_SHARED_PATH "/sys/kernel/mm/ksm"
# define SYSFS_THREAD_SIBLINGS_LIST_LENGTH_MAX 1024

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
    FILE *pathfp;
    char str[1024];
    size_t i;

    if (virAsprintf(&path, "%s/cpu%u/topology/thread_siblings",
                    dir, cpu) < 0)
        return 0;

    pathfp = fopen(path, "r");
    if (pathfp == NULL) {
        /* If file doesn't exist, then pretend our only
         * sibling is ourself */
        if (errno == ENOENT) {
            VIR_FREE(path);
            return 1;
        }
        virReportSystemError(errno, _("cannot open %s"), path);
        VIR_FREE(path);
        return 0;
    }

    if (fgets(str, sizeof(str), pathfp) == NULL) {
        virReportSystemError(errno, _("cannot read from %s"), path);
        goto cleanup;
    }

    i = 0;
    while (str[i] != '\0') {
        if (c_isdigit(str[i]))
            ret += count_one_bits(str[i] - '0');
        else if (str[i] >= 'A' && str[i] <= 'F')
            ret += count_one_bits(str[i] - 'A' + 10);
        else if (str[i] >= 'a' && str[i] <= 'f')
            ret += count_one_bits(str[i] - 'a' + 10);
        i++;
    }

 cleanup:
    VIR_FORCE_FCLOSE(pathfp);
    VIR_FREE(path);

    return ret;
}

static int
virNodeParseSocket(const char *dir, unsigned int cpu)
{
    int ret = virNodeGetCpuValue(dir, cpu, "topology/physical_package_id",
                                 0);
# if defined(__powerpc__) || \
    defined(__powerpc64__) || \
    defined(__s390__) || \
    defined(__s390x__) || \
    defined(__aarch64__)
    /* ppc and s390(x) has -1 */
    if (ret < 0)
        ret = 0;
# endif
    return ret;
}

# ifndef CPU_COUNT
static int
CPU_COUNT(cpu_set_t *set)
{
    size_t i, count = 0;

    for (i = 0; i < CPU_SETSIZE; i++)
        if (CPU_ISSET(i, set))
            count++;
    return count;
}
# endif /* !CPU_COUNT */

/* parses a node entry, returning number of processors in the node and
 * filling arguments */
static int
ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
ATTRIBUTE_NONNULL(5)
virNodeParseNode(const char *node,
                 int *sockets,
                 int *cores,
                 int *threads,
                 int *offline)
{
    int ret = -1;
    int processors = 0;
    DIR *cpudir = NULL;
    struct dirent *cpudirent = NULL;
    int sock_max = 0;
    cpu_set_t sock_map;
    int sock;
    cpu_set_t *core_maps = NULL;
    int core;
    size_t i;
    int siblings;
    unsigned int cpu;
    int online;

    *threads = 0;
    *cores = 0;
    *sockets = 0;

    if (!(cpudir = opendir(node))) {
        virReportSystemError(errno, _("cannot opendir %s"), node);
        goto cleanup;
    }

    /* enumerate sockets in the node */
    CPU_ZERO(&sock_map);
    errno = 0;
    while ((cpudirent = readdir(cpudir))) {
        if (sscanf(cpudirent->d_name, "cpu%u", &cpu) != 1)
            continue;

        if ((online = virNodeGetCpuValue(node, cpu, "online", 1)) < 0)
            goto cleanup;

        if (!online)
            continue;

        /* Parse socket */
        if ((sock = virNodeParseSocket(node, cpu)) < 0)
            goto cleanup;
        CPU_SET(sock, &sock_map);

        if (sock > sock_max)
            sock_max = sock;

        errno = 0;
    }

    if (errno) {
        virReportSystemError(errno, _("problem reading %s"), node);
        goto cleanup;
    }

    sock_max++;

    /* allocate cpu maps for each socket */
    if (VIR_ALLOC_N(core_maps, sock_max) < 0)
        goto cleanup;

    for (i = 0; i < sock_max; i++)
        CPU_ZERO(&core_maps[i]);

    /* iterate over all CPU's in the node */
    rewinddir(cpudir);
    errno = 0;
    while ((cpudirent = readdir(cpudir))) {
        if (sscanf(cpudirent->d_name, "cpu%u", &cpu) != 1)
            continue;

        if ((online = virNodeGetCpuValue(node, cpu, "online", 1)) < 0)
            goto cleanup;

        if (!online) {
            (*offline)++;
            continue;
        }

        processors++;

        /* Parse socket */
        if ((sock = virNodeParseSocket(node, cpu)) < 0)
            goto cleanup;
        if (!CPU_ISSET(sock, &sock_map)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("CPU socket topology has changed"));
            goto cleanup;
        }

        /* Parse core */
# if defined(__s390__) || \
    defined(__s390x__)
        /* logical cpu is equivalent to a core on s390 */
        core = cpu;
# else
        core = virNodeGetCpuValue(node, cpu, "topology/core_id", 0);
# endif

        CPU_SET(core, &core_maps[sock]);

        if (!(siblings = virNodeCountThreadSiblings(node, cpu)))
            goto cleanup;

        if (siblings > *threads)
            *threads = siblings;

        errno = 0;
    }

    if (errno) {
        virReportSystemError(errno, _("problem reading %s"), node);
        goto cleanup;
    }

    /* finalize the returned data */
    *sockets = CPU_COUNT(&sock_map);

    for (i = 0; i < sock_max; i++) {
        if (!CPU_ISSET(i, &sock_map))
            continue;

        core = CPU_COUNT(&core_maps[i]);
        if (core > *cores)
            *cores = core;
    }

    ret = processors;

 cleanup:
    /* don't shadow a more serious error */
    if (cpudir && closedir(cpudir) < 0 && ret >= 0) {
        virReportSystemError(errno, _("problem closing %s"), node);
        ret = -1;
    }
    VIR_FREE(core_maps);

    return ret;
}

int linuxNodeInfoCPUPopulate(FILE *cpuinfo,
                             const char *sysfs_dir,
                             virNodeInfoPtr nodeinfo)
{
    char line[1024];
    DIR *nodedir = NULL;
    struct dirent *nodedirent = NULL;
    int cpus, cores, socks, threads, offline = 0;
    unsigned int node;
    int ret = -1;
    char *sysfs_nodedir = NULL;
    char *sysfs_cpudir = NULL;

    /* Start with parsing CPU clock speed from /proc/cpuinfo */
    while (fgets(line, sizeof(line), cpuinfo) != NULL) {
# if defined(__x86_64__) || \
    defined(__amd64__)  || \
    defined(__i386__)
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

# elif defined(__powerpc__) || \
      defined(__powerpc64__)
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
# elif defined(__arm__) || defined(__aarch64__)
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
# elif defined(__s390__) || \
      defined(__s390x__)
        /* s390x has no realistic value for CPU speed,
         * assign a value of zero to signify this */
        nodeinfo->mhz = 0;
# else
#  warning Parser for /proc/cpuinfo needs to be adapted for your architecture
# endif
    }

    /* OK, we've parsed clock speed out of /proc/cpuinfo. Get the
     * core, node, socket, thread and topology information from /sys
     */
    if (virAsprintf(&sysfs_nodedir, "%s/node", sysfs_dir) < 0)
        goto cleanup;

    if (!(nodedir = opendir(sysfs_nodedir))) {
        /* the host isn't probably running a NUMA architecture */
        goto fallback;
    }

    errno = 0;
    while ((nodedirent = readdir(nodedir))) {
        if (sscanf(nodedirent->d_name, "node%u", &node) != 1)
            continue;

        nodeinfo->nodes++;

        if (virAsprintf(&sysfs_cpudir, "%s/node/%s",
                        sysfs_dir, nodedirent->d_name) < 0)
            goto cleanup;

        if ((cpus = virNodeParseNode(sysfs_cpudir, &socks, &cores,
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

        errno = 0;
    }

    if (errno) {
        virReportSystemError(errno, _("problem reading %s"), sysfs_nodedir);
        goto cleanup;
    }

    if (nodeinfo->cpus && nodeinfo->nodes)
        goto done;

 fallback:
    VIR_FREE(sysfs_cpudir);

    if (virAsprintf(&sysfs_cpudir, "%s/cpu", sysfs_dir) < 0)
        goto cleanup;

    if ((cpus = virNodeParseNode(sysfs_cpudir, &socks, &cores,
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


/* Determine the maximum cpu id from a Linux sysfs cpu/present file. */
static int
linuxParseCPUmax(const char *path)
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

int nodeGetInfo(virNodeInfoPtr nodeinfo)
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

    ret = linuxNodeInfoCPUPopulate(cpuinfo, SYSFS_SYSTEM_PATH, nodeinfo);
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

int nodeGetCPUStats(int cpuNum ATTRIBUTE_UNUSED,
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

int nodeGetMemoryStats(int cellNum ATTRIBUTE_UNUSED,
                       virNodeMemoryStatsPtr params ATTRIBUTE_UNUSED,
                       int *nparams ATTRIBUTE_UNUSED,
                       unsigned int flags)
{
    virCheckFlags(0, -1);

#ifdef __linux__
    {
        int ret;
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
                            SYSFS_SYSTEM_PATH, cellNum) < 0)
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
nodeGetCPUCount(void)
{
#if defined(__linux__)
    /* To support older kernels that lack cpu/present, such as 2.6.18
     * in RHEL5, we fall back to count cpu/cpuNN entries; this assumes
     * that such kernels also lack hotplug, and therefore cpu/cpuNN
     * will be consecutive.
     */
    char *cpupath = NULL;
    int ncpu;

    if (virFileExists(SYSFS_SYSTEM_PATH "/cpu/present")) {
        ncpu = linuxParseCPUmax(SYSFS_SYSTEM_PATH "/cpu/present");
    } else if (virFileExists(SYSFS_SYSTEM_PATH "/cpu/cpu0")) {
        ncpu = 0;
        do {
            ncpu++;
            VIR_FREE(cpupath);
            if (virAsprintf(&cpupath, "%s/cpu/cpu%d",
                            SYSFS_SYSTEM_PATH, ncpu) < 0)
                return -1;
        } while (virFileExists(cpupath));
    } else {
        /* no cpu/cpu0: we give up */
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("host cpu counting not supported on this node"));
        return -1;
    }

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
nodeGetCPUBitmap(int *max_id ATTRIBUTE_UNUSED)
{
#ifdef __linux__
    virBitmapPtr cpumap;
    int present;

    present = nodeGetCPUCount();
    if (present < 0)
        return NULL;

    if (virFileExists(SYSFS_SYSTEM_PATH "/cpu/online")) {
        cpumap = linuxParseCPUmap(present, SYSFS_SYSTEM_PATH "/cpu/online");
    } else {
        size_t i;

        cpumap = virBitmapNew(present);
        if (!cpumap)
            return NULL;
        for (i = 0; i < present; i++) {
            int online = virNodeGetCpuValue(SYSFS_SYSTEM_PATH, i, "online", 1);
            if (online < 0) {
                virBitmapFree(cpumap);
                return NULL;
            }
            if (online)
                ignore_value(virBitmapSetBit(cpumap, i));
        }
    }
    if (max_id && cpumap)
        *max_id = present;
    return cpumap;
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node cpumap not implemented on this platform"));
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

        /* Out of memory */
        if (rc == -2)
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
nodeGetCPUMap(unsigned char **cpumap,
              unsigned int *online,
              unsigned int flags)
{
    virBitmapPtr cpus = NULL;
    int maxpresent;
    int ret = -1;
    int dummy;

    virCheckFlags(0, -1);

    if (!cpumap && !online)
        return nodeGetCPUCount();

    if (!(cpus = nodeGetCPUBitmap(&maxpresent)))
        goto cleanup;

    if (cpumap && virBitmapToData(cpus, cpumap, &dummy) < 0)
        goto cleanup;
    if (online)
        *online = virBitmapCountBits(cpus);

    ret = maxpresent;
 cleanup:
    if (ret < 0 && cpumap)
        VIR_FREE(*cpumap);
    virBitmapFree(cpus);
    return ret;
}

static int
nodeCapsInitNUMAFake(virCapsPtr caps ATTRIBUTE_UNUSED)
{
    virNodeInfo nodeinfo;
    virCapsHostNUMACellCPUPtr cpus;
    int ncpus;
    int s, c, t;
    int id;

    if (nodeGetInfo(&nodeinfo) < 0)
        return -1;

    ncpus = VIR_NODEINFO_MAXCPUS(nodeinfo);

    if (VIR_ALLOC_N(cpus, ncpus) < 0)
        return -1;

    id = 0;
    for (s = 0; s < nodeinfo.sockets; s++) {
        for (c = 0; c < nodeinfo.cores; c++) {
            for (t = 0; t < nodeinfo.threads; t++) {
                cpus[id].id = id;
                cpus[id].socket_id = s;
                cpus[id].core_id = c;
                if (!(cpus[id].siblings = virBitmapNew(ncpus)))
                    goto error;
                ignore_value(virBitmapSetBit(cpus[id].siblings, id));
                id++;
            }
        }
    }

    if (virCapabilitiesAddHostNUMACell(caps, 0,
                                       ncpus,
                                       nodeinfo.memory,
                                       cpus) < 0)
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

static unsigned long long
nodeGetFreeMemoryFake(void)
{
#if defined(__FreeBSD__)
    unsigned long pagesize = getpagesize();
    u_int value;
    size_t value_size = sizeof(value);
    unsigned long long freemem;

    if (sysctlbyname("vm.stats.vm.v_free_count", &value,
                     &value_size, NULL, 0) < 0) {
        virReportSystemError(errno, "%s",
                             _("sysctl failed for vm.stats.vm.v_free_count"));
        return 0;
    }

    freemem = value * (unsigned long long)pagesize;

    return freemem;
#else
    double avail = physmem_available();
    unsigned long long ret;

    if (!(ret = (unsigned long long)avail)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot determine free memory"));
        return 0;
    }

    return ret;
#endif
}

/* returns 1 on success, 0 if the detection failed and -1 on hard error */
static int
virNodeCapsFillCPUInfo(int cpu_id ATTRIBUTE_UNUSED,
                       virCapsHostNUMACellCPUPtr cpu ATTRIBUTE_UNUSED)
{
#ifdef __linux__
    int tmp;
    cpu->id = cpu_id;

    if ((tmp = virNodeGetCpuValue(SYSFS_CPU_PATH, cpu_id,
                                  "topology/physical_package_id", -1)) < 0)
        return 0;

    cpu->socket_id = tmp;

    if ((tmp = virNodeGetCpuValue(SYSFS_CPU_PATH, cpu_id,
                                  "topology/core_id", -1)) < 0)
        return 0;

    cpu->core_id = tmp;

    if (!(cpu->siblings = virNodeGetSiblingsList(SYSFS_CPU_PATH, cpu_id)))
        return -1;

    return 0;
#else
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("node cpu info not implemented on this platform"));
    return -1;
#endif
}

int
nodeCapsInitNUMA(virCapsPtr caps)
{
    int n;
    unsigned long long memory;
    virCapsHostNUMACellCPUPtr cpus = NULL;
    virBitmapPtr cpumap = NULL;
    int ret = -1;
    int ncpus = 0;
    int cpu;
    bool topology_failed = false;
    int max_node;

    if (!virNumaIsAvailable())
        return nodeCapsInitNUMAFake(caps);

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
            bool cpustate;
            if (virBitmapGetBit(cpumap, i, &cpustate) < 0)
                continue;

            if (cpustate) {
                if (virNodeCapsFillCPUInfo(i, cpus + cpu++) < 0) {
                    topology_failed = true;
                    virResetLastError();
                }
            }
        }

        /* Detect the amount of memory in the numa cell in KiB */
        virNumaGetNodeMemory(n, &memory, NULL);
        memory >>= 10;

        if (virCapabilitiesAddHostNUMACell(caps, n, ncpus, memory, cpus) < 0)
            goto cleanup;

        cpus = NULL;
    }

    ret = 0;

 cleanup:
    if (topology_failed || ret < 0)
        virCapabilitiesClearHostNUMACellCPUTopology(cpus, ncpus);

    virBitmapFree(cpumap);
    VIR_FREE(cpus);

    if (ret < 0)
        VIR_FREE(cpus);

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

unsigned long long
nodeGetFreeMemory(void)
{
    unsigned long long mem;
    unsigned long long freeMem = 0;
    int max_node;
    int n;

    if (!virNumaIsAvailable())
        return nodeGetFreeMemoryFake();

    if ((max_node = virNumaGetMaxNode()) < 0)
        return 0;

    for (n = 0; n <= max_node; n++) {
        virNumaGetNodeMemory(n, NULL, &mem);

        freeMem += mem;
    }

    return freeMem;
}
