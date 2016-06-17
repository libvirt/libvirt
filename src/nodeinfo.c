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
#include <sys/utsname.h>
#include "conf/domain_conf.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "viralloc.h"
#include "nodeinfo.h"
#include "virhostcpu.h"
#include "virhostmem.h"
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



#ifdef __linux__
# define SYSFS_SYSTEM_PATH "/sys/devices/system"
# define SYSFS_THREAD_SIBLINGS_LIST_LENGTH_MAX 8192


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


static virBitmapPtr
virNodeGetSiblingsListLinux(const char *dir, int cpu_id)
{
    char *path = NULL;
    char *buf = NULL;
    virBitmapPtr ret = NULL;

    if (virAsprintf(&path, "%s/cpu%u/topology/thread_siblings_list",
                    dir, cpu_id) < 0)
        goto cleanup;

    if (virFileReadAll(path, SYSFS_THREAD_SIBLINGS_LIST_LENGTH_MAX, &buf) < 0)
        goto cleanup;

    if (virBitmapParse(buf, &ret, virNumaGetMaxCPUs()) < 0)
        goto cleanup;

 cleanup:
    VIR_FREE(buf);
    VIR_FREE(path);
    return ret;
}
#else
# define SYSFS_SYSTEM_PATH "fake"
#endif


int
nodeGetInfo(virNodeInfoPtr nodeinfo)
{
    virArch hostarch = virArchFromHost();
    unsigned long long memorybytes;

    memset(nodeinfo, 0, sizeof(*nodeinfo));

    if (virStrcpyStatic(nodeinfo->model, virArchToString(hostarch)) == NULL)
        return -1;

    if (virHostMemGetInfo(&memorybytes, NULL) < 0)
        return -1;
    nodeinfo->memory = memorybytes / 1024;

    if (virHostCPUGetInfo(hostarch,
                          &nodeinfo->cpus, &nodeinfo->mhz,
                          &nodeinfo->nodes, &nodeinfo->sockets,
                          &nodeinfo->cores, &nodeinfo->threads) < 0)
        return -1;

    return 0;
}


static int
nodeCapsInitNUMAFake(const char *cpupath ATTRIBUTE_UNUSED,
                     virCapsPtr caps ATTRIBUTE_UNUSED)
{
    virNodeInfo nodeinfo;
    virCapsHostNUMACellCPUPtr cpus;
    int ncpus;
    int s, c, t;
    int id, cid;
    int onlinecpus ATTRIBUTE_UNUSED;

    if (nodeGetInfo(&nodeinfo) < 0)
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

    if (!(cpu->siblings = virNodeGetSiblingsListLinux(cpupath, cpu_id)))
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
nodeCapsInitNUMA(virCapsPtr caps)
{
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

    if (!virNumaIsAvailable()) {
        ret = nodeCapsInitNUMAFake(SYSFS_SYSTEM_PATH "/cpu", caps);
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
                if (virNodeCapsFillCPUInfo(SYSFS_SYSTEM_PATH "/cpu",
                                           i, cpus + cpu++) < 0) {
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
    return ret;
}
