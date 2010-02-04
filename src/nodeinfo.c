/*
 * nodeinfo.c: Helper routines for OS specific node information
 *
 * Copyright (C) 2006, 2007, 2008 Red Hat, Inc.
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

#if HAVE_NUMACTL
# define NUMA_VERSION1_COMPATIBILITY 1
# include <numa.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#include "c-ctype.h"
#include "memory.h"
#include "nodeinfo.h"
#include "physmem.h"
#include "util.h"
#include "logging.h"
#include "virterror_internal.h"


#define VIR_FROM_THIS VIR_FROM_NONE

#define nodeReportError(conn, code, fmt...)                              \
    virReportErrorHelper(conn, VIR_FROM_NONE, code, __FILE__,           \
                         __FUNCTION__, __LINE__, fmt)

#ifdef __linux__
#define CPUINFO_PATH "/proc/cpuinfo"

/* NB, these are not static as we need to call them from testsuite */
int linuxNodeInfoCPUPopulate(virConnectPtr conn, FILE *cpuinfo,
                             virNodeInfoPtr nodeinfo);

int linuxNodeInfoCPUPopulate(virConnectPtr conn, FILE *cpuinfo, virNodeInfoPtr nodeinfo) {
    char line[1024];

    nodeinfo->cpus = 0;
    nodeinfo->mhz = 0;
    nodeinfo->nodes = nodeinfo->sockets = nodeinfo->cores = nodeinfo->threads = 1;

    /* NB: It is impossible to fill our nodes, since cpuinfo
     * has not knowledge of NUMA nodes */

    /* XXX hyperthreads */
    while (fgets(line, sizeof(line), cpuinfo) != NULL) {
        char *buf = line;
        if (STRPREFIX(buf, "processor")) { /* aka a single logical CPU */
            buf += 9;
            while (*buf && c_isspace(*buf))
                buf++;
            if (*buf != ':') {
                nodeReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
                nodeReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
                nodeReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
        nodeReportError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("no cpus found"));
        return -1;
    }

    /*
     * Can't reliably count sockets from proc metadata, so
     * infer it based on total CPUs vs cores.
     * XXX hyperthreads
     */
    nodeinfo->sockets = nodeinfo->cpus / nodeinfo->cores;

    return 0;
}

#endif

int nodeGetInfo(virConnectPtr conn,
                virNodeInfoPtr nodeinfo) {
#ifdef HAVE_UNAME
    struct utsname info;

    uname(&info);

    if (virStrcpyStatic(nodeinfo->model, info.machine) == NULL)
        return -1;

#else /* !HAVE_UNAME */

    nodeinfo->model[0] = '\0';

#endif /* !HAVE_UNAME */

#ifdef __linux__
    {
    int ret;
    FILE *cpuinfo = fopen(CPUINFO_PATH, "r");
    if (!cpuinfo) {
        virReportSystemError(errno,
                             _("cannot open %s"), CPUINFO_PATH);
        return -1;
    }
    ret = linuxNodeInfoCPUPopulate(conn, cpuinfo, nodeinfo);
    fclose(cpuinfo);
    if (ret < 0)
        return -1;

    /* Convert to KB. */
    nodeinfo->memory = physmem_total () / 1024;

    return ret;
    }
#else
    /* XXX Solaris will need an impl later if they port QEMU driver */
    nodeReportError(conn, VIR_ERR_NO_SUPPORT, "%s",
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
    int *cpus = NULL;
    int ret = -1;
    int max_n_cpus = NUMA_MAX_N_CPUS;

    if (numa_available() < 0)
        return 0;

    int mask_n_bytes = max_n_cpus / 8;
    if (VIR_ALLOC_N(mask, mask_n_bytes / sizeof *mask) < 0)
        goto cleanup;

    for (n = 0 ; n <= numa_max_node() ; n++) {
        int i;
        int ncpus;
        if (numa_node_to_cpus(n, mask, mask_n_bytes) < 0) {
            VIR_WARN("NUMA topology for cell %d of %d not available, ignoring",
                     n, numa_max_node());
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
    return ret;
}


int
nodeGetCellsFreeMemory(virConnectPtr conn,
                       unsigned long long *freeMems,
                       int startCell,
                       int maxCells)
{
    int n, lastCell, numCells;
    int ret = -1;
    int maxCell;

    if (numa_available() < 0) {
        nodeReportError(conn, VIR_ERR_NO_SUPPORT,
                        "%s", _("NUMA not supported on this host"));
        goto cleanup;
    }
    maxCell = numa_max_node();
    if (startCell > maxCell) {
        nodeReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
            nodeReportError(conn, VIR_ERR_INTERNAL_ERROR,
                            "%s", _("Failed to query NUMA free memory"));
            goto cleanup;
        }
        freeMems[numCells++] = mem;
    }
    ret = numCells;

cleanup:
    return ret;
}

unsigned long long
nodeGetFreeMemory(virConnectPtr conn)
{
    unsigned long long freeMem = 0;
    int n;

    if (numa_available() < 0) {
        nodeReportError(conn, VIR_ERR_NO_SUPPORT,
                        "%s", _("NUMA not supported on this host"));
        goto cleanup;
    }

    for (n = 0 ; n <= numa_max_node() ; n++) {
        long long mem;
        if (numa_node_size64(n, &mem) < 0) {
            nodeReportError(conn, VIR_ERR_INTERNAL_ERROR,
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

int nodeGetCellsFreeMemory(virConnectPtr conn,
                              unsigned long long *freeMems ATTRIBUTE_UNUSED,
                              int startCell ATTRIBUTE_UNUSED,
                              int maxCells ATTRIBUTE_UNUSED)
{
    nodeReportError(conn, VIR_ERR_NO_SUPPORT, "%s",
                    _("NUMA memory information not available on this platform"));
    return -1;
}

unsigned long long nodeGetFreeMemory(virConnectPtr conn)
{
    nodeReportError(conn, VIR_ERR_NO_SUPPORT, "%s",
                    _("NUMA memory information not available on this platform"));
    return 0;
}
#endif
