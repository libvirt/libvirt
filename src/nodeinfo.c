/*
 * nodeinfo.c: Helper routines for OS specific node information
 *
 * Copyright (C) 2006-2008, 2010-2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
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

#if HAVE_NUMACTL
# define NUMA_VERSION1_COMPATIBILITY 1
# include <numa.h>
#endif

#include "c-ctype.h"
#include "memory.h"
#include "nodeinfo.h"
#include "physmem.h"
#include "util.h"
#include "logging.h"
#include "virterror_internal.h"
#include "count-one-bits.h"
#include "intprops.h"
#include "virfile.h"


#define VIR_FROM_THIS VIR_FROM_NONE

#define nodeReportError(code, ...)                                      \
    virReportErrorHelper(VIR_FROM_NONE, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#ifdef __linux__
# define CPUINFO_PATH "/proc/cpuinfo"
# define CPU_SYS_PATH "/sys/devices/system/cpu"
# define PROCSTAT_PATH "/proc/stat"
# define MEMINFO_PATH "/proc/meminfo"
# define NODE_SYS_PATH "/sys/devices/system/node"

# define LINUX_NB_CPU_STATS 4
# define LINUX_NB_MEMORY_STATS_ALL 4
# define LINUX_NB_MEMORY_STATS_CELL 2

/* NB, this is not static as we need to call it from the testsuite */
int linuxNodeInfoCPUPopulate(FILE *cpuinfo,
                             const char *sysfs_cpudir,
                             virNodeInfoPtr nodeinfo);

static int linuxNodeGetCPUStats(FILE *procstat,
                                int cpuNum,
                                virNodeCPUStatsPtr params,
                                int *nparams);
static int linuxNodeGetMemoryStats(FILE *meminfo,
                                   int cellNum,
                                   virNodeMemoryStatsPtr params,
                                   int *nparams);

static char sysfs_path[1024];
/* Return the positive decimal contents of the given
 * (*sysfs_path)/cpu%u/FILE, or -1 on error.  If MISSING_OK and the
 * file could not be found, return 1 instead of an error; this is
 * because some machines cannot hot-unplug cpu0, or because
 * hot-unplugging is disabled.  */
static int
get_cpu_value(unsigned int cpu, const char *file, bool missing_ok)
{
    char *path;
    FILE *pathfp;
    int value = -1;
    char value_str[INT_BUFSIZE_BOUND(value)];
    char *tmp;

    if (virAsprintf(&path, "%s/cpu%u/%s", sysfs_path, cpu, file) < 0) {
        virReportOOMError();
        return -1;
    }

    pathfp = fopen(path, "r");
    if (pathfp == NULL) {
        if (missing_ok && errno == ENOENT)
            value = 1;
        else
            virReportSystemError(errno, _("cannot open %s"), path);
        goto cleanup;
    }

    if (fgets(value_str, sizeof(value_str), pathfp) == NULL) {
        virReportSystemError(errno, _("cannot read from %s"), path);
        goto cleanup;
    }
    if (virStrToLong_i(value_str, &tmp, 10, &value) < 0) {
        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                        _("could not convert '%s' to an integer"),
                        value_str);
        goto cleanup;
    }

cleanup:
    VIR_FORCE_FCLOSE(pathfp);
    VIR_FREE(path);

    return value;
}

/* Check if CPU is online via sysfs_path/cpu%u/online.  Return 1 if online,
   0 if offline, and -1 on error.  */
static int
cpu_online(unsigned int cpu)
{
    return get_cpu_value(cpu, "online", true);
}

static unsigned long count_thread_siblings(unsigned int cpu)
{
    unsigned long ret = 0;
    char *path;
    FILE *pathfp;
    char str[1024];
    int i;

    if (virAsprintf(&path, "%s/cpu%u/topology/thread_siblings",
                    sysfs_path, cpu) < 0) {
        virReportOOMError();
        return 0;
    }

    pathfp = fopen(path, "r");
    if (pathfp == NULL) {
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

static int parse_socket(unsigned int cpu)
{
    int ret = get_cpu_value(cpu, "topology/physical_package_id", false);
# if defined(__powerpc__) || \
    defined(__powerpc64__) || \
    defined(__s390__) || \
    defined(__s390x__)
    /* ppc and s390(x) has -1 */
    if (ret < 0)
        ret = 0;
# endif
    return ret;
}

static int parse_core(unsigned int cpu)
{
    return get_cpu_value(cpu, "topology/core_id", false);
}

int linuxNodeInfoCPUPopulate(FILE *cpuinfo,
                             const char *sysfs_cpudir,
                             virNodeInfoPtr nodeinfo)
{
    char line[1024];
    DIR *cpudir = NULL;
    struct dirent *cpudirent = NULL;
    unsigned int cpu;
    unsigned long core, sock, cur_threads;
    cpu_set_t core_mask;
    cpu_set_t socket_mask;
    int online;

    nodeinfo->cpus = 0;
    nodeinfo->mhz = 0;
    nodeinfo->cores = 0;

    nodeinfo->nodes = 1;
# if HAVE_NUMACTL
    if (numa_available() >= 0)
        nodeinfo->nodes = numa_max_node() + 1;
# endif

    if (!virStrcpyStatic(sysfs_path, sysfs_cpudir)) {
        virReportSystemError(errno, _("cannot copy %s"), sysfs_cpudir);
        return -1;
    }
    /* NB: It is impossible to fill our nodes, since cpuinfo
     * has no knowledge of NUMA nodes */

    /* NOTE: hyperthreads are ignored here; they are parsed out of /sys */
    while (fgets(line, sizeof(line), cpuinfo) != NULL) {
        char *buf = line;
# if defined(__x86_64__) || \
    defined(__amd64__)  || \
    defined(__i386__)
        if (STRPREFIX(buf, "cpu MHz")) {
            char *p;
            unsigned int ui;
            buf += 9;
            while (*buf && c_isspace(*buf))
                buf++;
            if (*buf != ':' || !buf[1]) {
                nodeReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("parsing cpuinfo cpu MHz"));
                return -1;
            }
            if (virStrToLong_ui(buf+1, &p, 10, &ui) == 0
                /* Accept trailing fractional part.  */
                && (*p == '\0' || *p == '.' || c_isspace(*p)))
                nodeinfo->mhz = ui;
        }
# elif defined(__powerpc__) || \
      defined(__powerpc64__)
        if (STRPREFIX(buf, "clock")) {
            char *p;
            unsigned int ui;
            buf += 5;
            while (*buf && c_isspace(*buf))
                buf++;
            if (*buf != ':' || !buf[1]) {
                nodeReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("parsing cpuinfo cpu MHz"));
                return -1;
            }
            if (virStrToLong_ui(buf+1, &p, 10, &ui) == 0
                /* Accept trailing fractional part.  */
                && (*p == '\0' || *p == '.' || c_isspace(*p)))
                nodeinfo->mhz = ui;
            /* No other interesting infos are available in /proc/cpuinfo.
             * However, there is a line identifying processor's version,
             * identification and machine, but we don't want it to be caught
             * and parsed in next iteration, because it is not in expected
             * format and thus lead to error. */
        }
# else
#  warning Parser for /proc/cpuinfo needs to be adapted for your architecture
# endif
    }

    /* OK, we've parsed clock speed out of /proc/cpuinfo. Get the core, socket
     * thread and topology information from /sys
     */
    cpudir = opendir(sysfs_cpudir);
    if (cpudir == NULL) {
        virReportSystemError(errno, _("cannot opendir %s"), sysfs_cpudir);
        return -1;
    }

    CPU_ZERO(&core_mask);
    CPU_ZERO(&socket_mask);

    while ((cpudirent = readdir(cpudir))) {
        if (sscanf(cpudirent->d_name, "cpu%u", &cpu) != 1)
            continue;

        online = cpu_online(cpu);
        if (online < 0) {
            closedir(cpudir);
            return -1;
        }
        if (!online)
            continue;
        nodeinfo->cpus++;

        /* Parse core */
        core = parse_core(cpu);
        if (!CPU_ISSET(core, &core_mask)) {
            CPU_SET(core, &core_mask);
            nodeinfo->cores++;
        }

        /* Parse socket */
        sock = parse_socket(cpu);
        if (!CPU_ISSET(sock, &socket_mask)) {
            CPU_SET(sock, &socket_mask);
            nodeinfo->sockets++;
        }

        cur_threads = count_thread_siblings(cpu);
        if (cur_threads == 0) {
            closedir(cpudir);
            return -1;
        }
        if (cur_threads > nodeinfo->threads)
            nodeinfo->threads = cur_threads;
    }
    if (errno) {
        virReportSystemError(errno,
                             _("problem reading %s"), sysfs_path);
        closedir(cpudir);
        return -1;
    }

    closedir(cpudir);

    /* there should always be at least one cpu, socket and one thread */
    if (nodeinfo->cpus == 0) {
        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("no CPUs found"));
        return -1;
    }
    if (nodeinfo->sockets == 0) {
        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("no sockets found"));
        return -1;
    }
    if (nodeinfo->threads == 0) {
        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("no threads found"));
        return -1;
    }

    /* nodeinfo->sockets is supposed to be a number of sockets per NUMA node,
     * however if NUMA nodes are not composed of whole sockets, we just lie
     * about the number of NUMA nodes and force apps to check capabilities XML
     * for the actual NUMA topology.
     */
    if (nodeinfo->sockets % nodeinfo->nodes == 0)
        nodeinfo->sockets /= nodeinfo->nodes;
    else
        nodeinfo->nodes = 1;

    return 0;
}

# define TICK_TO_NSEC (1000ull * 1000ull * 1000ull / sysconf(_SC_CLK_TCK))

int linuxNodeGetCPUStats(FILE *procstat,
                         int cpuNum,
                         virNodeCPUStatsPtr params,
                         int *nparams)
{
    int ret = -1;
    char line[1024];
    unsigned long long usr, ni, sys, idle, iowait;
    unsigned long long irq, softirq, steal, guest, guest_nice;
    char cpu_header[3 + INT_BUFSIZE_BOUND(cpuNum)];

    if ((*nparams) == 0) {
        /* Current number of cpu stats supported by linux */
        *nparams = LINUX_NB_CPU_STATS;
        ret = 0;
        goto cleanup;
    }

    if ((*nparams) != LINUX_NB_CPU_STATS) {
        nodeReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("Invalid parameter count"));
        goto cleanup;
    }

    if (cpuNum == VIR_NODE_CPU_STATS_ALL_CPUS) {
        strcpy(cpu_header, "cpu");
    } else {
        snprintf(cpu_header, sizeof(cpu_header), "cpu%d", cpuNum);
    }

    while (fgets(line, sizeof(line), procstat) != NULL) {
        char *buf = line;

        if (STRPREFIX(buf, cpu_header)) { /* aka logical CPU time */
            int i;

            if (sscanf(buf,
                       "%*s %llu %llu %llu %llu %llu" // user ~ iowait
                       "%llu %llu %llu %llu %llu",    // irq  ~ guest_nice
                       &usr, &ni, &sys, &idle, &iowait,
                       &irq, &softirq, &steal, &guest, &guest_nice) < 4) {
                continue;
            }

            for (i = 0; i < *nparams; i++) {
                virNodeCPUStatsPtr param = &params[i];

                switch (i) {
                case 0: /* fill kernel cpu time here */
                    if (virStrcpyStatic(param->field, VIR_NODE_CPU_STATS_KERNEL) == NULL) {
                        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                                        "%s", _("Field kernel cpu time too long for destination"));
                        goto cleanup;
                    }
                    param->value = (sys + irq + softirq) * TICK_TO_NSEC;
                    break;

                case 1: /* fill user cpu time here */
                    if (virStrcpyStatic(param->field, VIR_NODE_CPU_STATS_USER) == NULL) {
                        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                                        "%s", _("Field kernel cpu time too long for destination"));
                        goto cleanup;
                    }
                    param->value = (usr + ni) * TICK_TO_NSEC;
                    break;

                case 2: /* fill idle cpu time here */
                    if (virStrcpyStatic(param->field, VIR_NODE_CPU_STATS_IDLE) == NULL) {
                        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                                        "%s", _("Field kernel cpu time too long for destination"));
                        goto cleanup;
                    }
                    param->value = idle * TICK_TO_NSEC;
                    break;

                case 3: /* fill iowait cpu time here */
                    if (virStrcpyStatic(param->field, VIR_NODE_CPU_STATS_IOWAIT) == NULL) {
                        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                                        "%s", _("Field kernel cpu time too long for destination"));
                        goto cleanup;
                    }
                    param->value = iowait * TICK_TO_NSEC;
                    break;

                default:
                    break;
                    /* should not hit here */
                }
            }
            ret = 0;
            goto cleanup;
        }
    }

    nodeReportError(VIR_ERR_INVALID_ARG, "%s", _("Invalid cpu number"));

cleanup:
    return ret;
}

int linuxNodeGetMemoryStats(FILE *meminfo,
                            int cellNum,
                            virNodeMemoryStatsPtr params,
                            int *nparams)
{
    int ret = -1;
    int i = 0, j = 0, k = 0;
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
        nodeReportError(VIR_ERR_INVALID_ARG,
                        "%s", _("Invalid stats count"));
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
                    nodeReportError(VIR_ERR_INTERNAL_ERROR,
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
                    nodeReportError(VIR_ERR_INTERNAL_ERROR,
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
        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("no available memory line found"));
        goto cleanup;
    }

    ret = 0;

cleanup:
    return ret;
}

/*
 * Linux maintains cpu bit map. For example, if cpuid=5's flag is not set
 * and max cpu is 7. The map file shows 0-4,6-7. This function parses
 * it and returns cpumap.
 */
static char *
linuxParseCPUmap(int *max_cpuid, const char *path)
{
    char *map = NULL;
    char *str = NULL;
    int max_id = 0, i;

    if (virFileReadAll(path, 5 * VIR_DOMAIN_CPUMASK_LEN, &str) < 0) {
        virReportOOMError();
        goto error;
    }

    if (VIR_ALLOC_N(map, VIR_DOMAIN_CPUMASK_LEN) < 0) {
        virReportOOMError();
        goto error;
    }
    if (virDomainCpuSetParse(str, 0, map,
                             VIR_DOMAIN_CPUMASK_LEN) < 0) {
        goto error;
    }

    for (i = 0; i < VIR_DOMAIN_CPUMASK_LEN; i++) {
        if (map[i]) {
            max_id = i;
        }
    }
    *max_cpuid = max_id;

    return map;

error:
    VIR_FREE(str);
    VIR_FREE(map);
    return NULL;
}
#endif

int nodeGetInfo(virConnectPtr conn ATTRIBUTE_UNUSED, virNodeInfoPtr nodeinfo) {
    struct utsname info;

    memset(nodeinfo, 0, sizeof(*nodeinfo));
    uname(&info);

    if (virStrcpyStatic(nodeinfo->model, info.machine) == NULL)
        return -1;

#ifdef __linux__
    {
    int ret;
    char *sysfs_cpuinfo;
    FILE *cpuinfo = fopen(CPUINFO_PATH, "r");
    if (!cpuinfo) {
        virReportSystemError(errno,
                             _("cannot open %s"), CPUINFO_PATH);
        return -1;
    }

    if (virAsprintf(&sysfs_cpuinfo, CPU_SYS_PATH) < 0) {
        virReportOOMError();
        return -1;
    }

    ret = linuxNodeInfoCPUPopulate(cpuinfo, sysfs_cpuinfo, nodeinfo);
    VIR_FORCE_FCLOSE(cpuinfo);
    if (ret < 0) {
        VIR_FREE(sysfs_cpuinfo);
        return -1;
    }

    VIR_FREE(sysfs_cpuinfo);
    /* Convert to KB. */
    nodeinfo->memory = physmem_total () / 1024;

    return ret;
    }
#else
    /* XXX Solaris will need an impl later if they port QEMU driver */
    nodeReportError(VIR_ERR_NO_SUPPORT, "%s",
                    _("node info not implemented on this platform"));
    return -1;
#endif
}

int nodeGetCPUStats(virConnectPtr conn ATTRIBUTE_UNUSED,
                    int cpuNum ATTRIBUTE_UNUSED,
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
#else
    nodeReportError(VIR_ERR_NO_SUPPORT, "%s",
                    _("node CPU stats not implemented on this platform"));
    return -1;
#endif
}

int nodeGetMemoryStats(virConnectPtr conn ATTRIBUTE_UNUSED,
                       int cellNum ATTRIBUTE_UNUSED,
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

        if (cellNum == VIR_NODE_MEMORY_STATS_ALL_CELLS) {
            meminfo_path = strdup(MEMINFO_PATH);
            if (!meminfo_path) {
                virReportOOMError();
                return -1;
            }
        } else {
# if HAVE_NUMACTL
            if (numa_available() < 0) {
# endif
                nodeReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("NUMA not supported on this host"));
                return -1;
# if HAVE_NUMACTL
            }
# endif

# if HAVE_NUMACTL
            if (cellNum > numa_max_node()) {
                nodeReportError(VIR_ERR_INVALID_ARG, "%s",
                                _("Invalid cell number"));
                return -1;
            }
# endif

            if (virAsprintf(&meminfo_path, "%s/node%d/meminfo",
                            NODE_SYS_PATH, cellNum) < 0) {
                virReportOOMError();
                return -1;
            }
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
#else
    nodeReportError(VIR_ERR_NO_SUPPORT, "%s",
                    _("node memory stats not implemented on this platform"));
    return -1;
#endif
}

char *
nodeGetCPUmap(virConnectPtr conn ATTRIBUTE_UNUSED,
              int *max_id ATTRIBUTE_UNUSED,
              const char *mapname ATTRIBUTE_UNUSED)
{
#ifdef __linux__
    char *path;
    char *cpumap;

    if (virAsprintf(&path, CPU_SYS_PATH "/%s", mapname) < 0) {
        virReportOOMError();
        return NULL;
    }

    cpumap = linuxParseCPUmap(max_id, path);
    VIR_FREE(path);
    return cpumap;
#else
    nodeReportError(VIR_ERR_NO_SUPPORT, "%s",
                    _("node cpumap not implemented on this platform"));
    return NULL;
#endif
}

#if HAVE_NUMACTL
# if LIBNUMA_API_VERSION <= 1
#  define NUMA_MAX_N_CPUS 4096
# else
#  define NUMA_MAX_N_CPUS (numa_all_cpus_ptr->size)
# endif

# define n_bits(var) (8 * sizeof(var))
# define MASK_CPU_ISSET(mask, cpu) \
  (((mask)[((cpu) / n_bits(*(mask)))] >> ((cpu) % n_bits(*(mask)))) & 1)

int
nodeCapsInitNUMA(virCapsPtr caps)
{
    int n;
    unsigned long *mask = NULL;
    unsigned long *allonesmask = NULL;
    int *cpus = NULL;
    int ret = -1;
    int max_n_cpus = NUMA_MAX_N_CPUS;

    if (numa_available() < 0)
        return 0;

    int mask_n_bytes = max_n_cpus / 8;
    if (VIR_ALLOC_N(mask, mask_n_bytes / sizeof(*mask)) < 0)
        goto cleanup;
    if (VIR_ALLOC_N(allonesmask, mask_n_bytes / sizeof(*mask)) < 0)
        goto cleanup;
    memset(allonesmask, 0xff, mask_n_bytes);

    for (n = 0 ; n <= numa_max_node() ; n++) {
        int i;
        int ncpus;
        /* The first time this returns -1, ENOENT if node doesn't exist... */
        if (numa_node_to_cpus(n, mask, mask_n_bytes) < 0) {
            VIR_WARN("NUMA topology for cell %d of %d not available, ignoring",
                     n, numa_max_node()+1);
            continue;
        }
        /* second, third... times it returns an all-1's mask */
        if (memcmp(mask, allonesmask, mask_n_bytes) == 0) {
            VIR_DEBUG("NUMA topology for cell %d of %d is all ones, ignoring",
                      n, numa_max_node()+1);
            continue;
        }

        for (ncpus = 0, i = 0 ; i < max_n_cpus ; i++)
            if (MASK_CPU_ISSET(mask, i))
                ncpus++;

        if (VIR_ALLOC_N(cpus, ncpus) < 0)
            goto cleanup;

        for (ncpus = 0, i = 0 ; i < max_n_cpus ; i++)
            if (MASK_CPU_ISSET(mask, i))
                cpus[ncpus++] = i;

        if (virCapabilitiesAddHostNUMACell(caps,
                                           n,
                                           ncpus,
                                           cpus) < 0)
            goto cleanup;

        VIR_FREE(cpus);
    }

    ret = 0;

cleanup:
    VIR_FREE(cpus);
    VIR_FREE(mask);
    VIR_FREE(allonesmask);
    return ret;
}


int
nodeGetCellsFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED,
                       unsigned long long *freeMems,
                       int startCell,
                       int maxCells)
{
    int n, lastCell, numCells;
    int ret = -1;
    int maxCell;

    if (numa_available() < 0) {
        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("NUMA not supported on this host"));
        goto cleanup;
    }
    maxCell = numa_max_node();
    if (startCell > maxCell) {
        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                        _("start cell %d out of range (0-%d)"),
                        startCell, maxCell);
        goto cleanup;
    }
    lastCell = startCell + maxCells - 1;
    if (lastCell > maxCell)
        lastCell = maxCell;

    for (numCells = 0, n = startCell ; n <= lastCell ; n++) {
        long long mem;
        if (numa_node_size64(n, &mem) < 0) {
            nodeReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to query NUMA free memory for node: %d"),
                           n);
            goto cleanup;
        }
        freeMems[numCells++] = mem;
    }
    ret = numCells;

cleanup:
    return ret;
}

unsigned long long
nodeGetFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    unsigned long long freeMem = 0;
    int n;

    if (numa_available() < 0) {
        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("NUMA not supported on this host"));
        goto cleanup;
    }

    for (n = 0 ; n <= numa_max_node() ; n++) {
        long long mem;
        if (numa_node_size64(n, &mem) < 0) {
            nodeReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("Failed to query NUMA free memory"));
            goto cleanup;
        }
        freeMem += mem;
    }

cleanup:
    return freeMem;
}

#else
int nodeCapsInitNUMA(virCapsPtr caps ATTRIBUTE_UNUSED) {
    return 0;
}

int nodeGetCellsFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED,
                              unsigned long long *freeMems ATTRIBUTE_UNUSED,
                              int startCell ATTRIBUTE_UNUSED,
                              int maxCells ATTRIBUTE_UNUSED)
{
    nodeReportError(VIR_ERR_NO_SUPPORT, "%s",
                    _("NUMA memory information not available on this platform"));
    return -1;
}

unsigned long long nodeGetFreeMemory(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    nodeReportError(VIR_ERR_NO_SUPPORT, "%s",
                    _("NUMA memory information not available on this platform"));
    return 0;
}
#endif
