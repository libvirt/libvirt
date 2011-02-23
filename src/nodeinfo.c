/*
 * nodeinfo.c: Helper routines for OS specific node information
 *
 * Copyright (C) 2006, 2007, 2008, 2010 Red Hat, Inc.
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
#include "files.h"


#define VIR_FROM_THIS VIR_FROM_NONE

#define nodeReportError(code, ...)                                      \
    virReportErrorHelper(NULL, VIR_FROM_NONE, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

#ifdef __linux__
# define CPUINFO_PATH "/proc/cpuinfo"
# define CPU_SYS_PATH "/sys/devices/system/cpu"

/* NB, this is not static as we need to call it from the testsuite */
int linuxNodeInfoCPUPopulate(FILE *cpuinfo,
                             virNodeInfoPtr nodeinfo,
                             bool need_hyperthreads);

/* Return the positive decimal contents of the given
 * CPU_SYS_PATH/cpu%u/FILE, or -1 on error.  If MISSING_OK and the
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

    if (virAsprintf(&path, CPU_SYS_PATH "/cpu%u/%s", cpu, file) < 0) {
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

/* Check if CPU is online via CPU_SYS_PATH/cpu%u/online.  Return 1 if online,
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

    if (virAsprintf(&path, CPU_SYS_PATH "/cpu%u/topology/thread_siblings",
                    cpu) < 0) {
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
    return get_cpu_value(cpu, "topology/physical_package_id", false);
}

int linuxNodeInfoCPUPopulate(FILE *cpuinfo,
                             virNodeInfoPtr nodeinfo,
                             bool need_hyperthreads)
{
    char line[1024];
    DIR *cpudir = NULL;
    struct dirent *cpudirent = NULL;
    unsigned int cpu;
    unsigned long cur_threads;
    int socket;
    unsigned long long socket_mask = 0;
    unsigned int remaining;
    int online;

    nodeinfo->cpus = 0;
    nodeinfo->mhz = 0;
    nodeinfo->cores = 1;

    nodeinfo->nodes = 1;
# if HAVE_NUMACTL
    if (numa_available() >= 0)
        nodeinfo->nodes = numa_max_node() + 1;
# endif

    /* NB: It is impossible to fill our nodes, since cpuinfo
     * has no knowledge of NUMA nodes */

    /* NOTE: hyperthreads are ignored here; they are parsed out of /sys */
    while (fgets(line, sizeof(line), cpuinfo) != NULL) {
        char *buf = line;
        if (STRPREFIX(buf, "processor")) { /* aka a single logical CPU */
            buf += 9;
            while (*buf && c_isspace(*buf))
                buf++;
            if (*buf != ':') {
                nodeReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("parsing cpuinfo processor"));
                return -1;
            }
            nodeinfo->cpus++;
        } else if (STRPREFIX(buf, "cpu MHz")) {
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
        } else if (STRPREFIX(buf, "cpu cores")) { /* aka cores */
            char *p;
            unsigned int id;
            buf += 9;
            while (*buf && c_isspace(*buf))
                buf++;
            if (*buf != ':' || !buf[1]) {
                nodeReportError(VIR_ERR_INTERNAL_ERROR,
                                "parsing cpuinfo cpu cores %c", *buf);
                return -1;
            }
            if (virStrToLong_ui(buf+1, &p, 10, &id) == 0
                && (*p == '\0' || c_isspace(*p))
                && id > nodeinfo->cores)
                nodeinfo->cores = id;
        }
    }

    if (!nodeinfo->cpus) {
        nodeReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("no cpus found"));
        return -1;
    }

    if (!need_hyperthreads)
        return 0;

    /* OK, we've parsed what we can out of /proc/cpuinfo.  Get the socket
     * and thread information from /sys
     */
    remaining = nodeinfo->cpus;
    cpudir = opendir(CPU_SYS_PATH);
    if (cpudir == NULL) {
        virReportSystemError(errno, _("cannot opendir %s"), CPU_SYS_PATH);
        return -1;
    }
    while ((errno = 0), remaining && (cpudirent = readdir(cpudir))) {
        if (sscanf(cpudirent->d_name, "cpu%u", &cpu) != 1)
            continue;

        online = cpu_online(cpu);
        if (online < 0) {
            closedir(cpudir);
            return -1;
        }
        if (!online)
            continue;
        remaining--;

        socket = parse_socket(cpu);
        if (socket < 0) {
            closedir(cpudir);
            return -1;
        }
        if (!(socket_mask & (1 << socket))) {
            socket_mask |= (1 << socket);
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
                             _("problem reading %s"), CPU_SYS_PATH);
        closedir(cpudir);
        return -1;
    }

    closedir(cpudir);

    /* there should always be at least one socket and one thread */
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
    FILE *cpuinfo = fopen(CPUINFO_PATH, "r");
    if (!cpuinfo) {
        virReportSystemError(errno,
                             _("cannot open %s"), CPUINFO_PATH);
        return -1;
    }
    ret = linuxNodeInfoCPUPopulate(cpuinfo, nodeinfo, true);
    VIR_FORCE_FCLOSE(cpuinfo);
    if (ret < 0)
        return -1;

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
    if (VIR_ALLOC_N(mask, mask_n_bytes / sizeof *mask) < 0)
        goto cleanup;
    if (VIR_ALLOC_N(allonesmask, mask_n_bytes / sizeof *mask) < 0)
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
        nodeReportError(VIR_ERR_NO_SUPPORT,
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
        nodeReportError(VIR_ERR_NO_SUPPORT,
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
