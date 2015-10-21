/*
 * virnuma.c: helper APIs for managing numa
 *
 * Copyright (C) 2011-2014 Red Hat, Inc.
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
 */

#include <config.h>

#define NUMA_MAX_N_CPUS 4096

#if WITH_NUMACTL
# define NUMA_VERSION1_COMPATIBILITY 1
# include <numa.h>

# if LIBNUMA_API_VERSION > 1
#  undef NUMA_MAX_N_CPUS
#  define NUMA_MAX_N_CPUS (numa_all_cpus_ptr->size)
# endif

#endif /* WITH_NUMACTL */

#include <sys/types.h>
#include <dirent.h>

#include "virnuma.h"
#include "vircommand.h"
#include "virerror.h"
#include "virlog.h"
#include "viralloc.h"
#include "virbitmap.h"
#include "virstring.h"
#include "virfile.h"
#include "nodeinfo.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.numa");


#if HAVE_NUMAD
char *
virNumaGetAutoPlacementAdvice(unsigned short vcpus,
                              unsigned long long balloon)
{
    virCommandPtr cmd = NULL;
    char *output = NULL;

    cmd = virCommandNewArgList(NUMAD, "-w", NULL);
    virCommandAddArgFormat(cmd, "%d:%llu", vcpus,
                           VIR_DIV_UP(balloon, 1024));

    virCommandSetOutputBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) < 0)
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to query numad for the "
                         "advisory nodeset"));

    virCommandFree(cmd);
    return output;
}
#else /* !HAVE_NUMAD */
char *
virNumaGetAutoPlacementAdvice(unsigned short vcpus ATTRIBUTE_UNUSED,
                              unsigned long long balloon ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                   _("numad is not available on this host"));
    return NULL;
}
#endif /* !HAVE_NUMAD */

#if WITH_NUMACTL
int
virNumaSetupMemoryPolicy(virDomainNumatuneMemMode mode,
                         virBitmapPtr nodeset)
{
    nodemask_t mask;
    int node = -1;
    int ret = -1;
    int bit = 0;
    size_t i;
    int maxnode = 0;

    if (!nodeset)
        return 0;

    if (!virNumaNodesetIsAvailable(nodeset))
        return -1;

    maxnode = numa_max_node();
    maxnode = maxnode < NUMA_NUM_NODES ? maxnode : NUMA_NUM_NODES;

    /* Convert nodemask to NUMA bitmask. */
    nodemask_zero(&mask);
    bit = -1;
    while ((bit = virBitmapNextSetBit(nodeset, bit)) >= 0) {
        if (bit > maxnode) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("NUMA node %d is out of range"), bit);
            return -1;
        }
        nodemask_set(&mask, bit);
    }

    switch (mode) {
    case VIR_DOMAIN_NUMATUNE_MEM_STRICT:
        numa_set_bind_policy(1);
        numa_set_membind(&mask);
        numa_set_bind_policy(0);
        break;

    case VIR_DOMAIN_NUMATUNE_MEM_PREFERRED:
    {
        int nnodes = 0;
        for (i = 0; i < NUMA_NUM_NODES; i++) {
            if (nodemask_isset(&mask, i)) {
                node = i;
                nnodes++;
            }
        }

        if (nnodes != 1) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("NUMA memory tuning in 'preferred' mode "
                                   "only supports single node"));
            goto cleanup;
        }

        numa_set_bind_policy(0);
        numa_set_preferred(node);
    }
    break;

    case VIR_DOMAIN_NUMATUNE_MEM_INTERLEAVE:
        numa_set_interleave_mask(&mask);
        break;

    case VIR_DOMAIN_NUMATUNE_MEM_LAST:
        break;
    }
    ret = 0;

 cleanup:
    return ret;
}

bool
virNumaIsAvailable(void)
{
    return numa_available() != -1;
}


/**
 * virNumaGetMaxNode:
 * Get the highest node number available on the current system.
 * (See the node numbers in /sys/devices/system/node/ ).
 *
 * Returns the highest NUMA node id on success, -1 on error.
 */
int
virNumaGetMaxNode(void)
{
    int ret;

    if (!virNumaIsAvailable()) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("NUMA isn't available on this host"));
        return -1;
    }

    if ((ret = numa_max_node()) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to request maximum NUMA node id"));
        return -1;
    }

    return ret;
}


/**
 * virNumaGetNodeMemory:
 * @node: identifier of the requested NUMA node
 * @memsize: returns the total size of memory in the NUMA node
 * @memfree: returns the total free memory in a NUMA node
 *
 * Returns the size of the memory in one NUMA node in bytes via the @size
 * argument and free memory of a node in the @free argument.  The caller has to
 * guarantee that @node is in range (see virNumaGetMaxNode).
 *
 * Returns 0 on success, -1 on error. Does not report errors.
 */
int
virNumaGetNodeMemory(int node,
                     unsigned long long *memsize,
                     unsigned long long *memfree)
{
    long long node_size;
    long long node_free;

    if (memsize)
        *memsize = 0;

    if (memfree)
        *memfree = 0;

    if ((node_size = numa_node_size64(node, &node_free)) < 0)
        return -1;

    if (memsize)
        *memsize = node_size;

    if (memfree)
        *memfree = node_free;

    return 0;
}


/**
 * virNumaGetNodeCPUs:
 * @node: identifier of the requested NUMA node
 * @cpus: returns a bitmap of CPUs in @node
 *
 * Returns count of CPUs in the selected node and sets the map of the cpus to
 * @cpus. On error if the @node doesn't exist in the system this function
 * returns -2 and sets @cpus to NULL. On other errors -1 is returned, @cpus
 * is set to NULL and an error is reported.
 */

# define n_bits(var) (8 * sizeof(var))
# define MASK_CPU_ISSET(mask, cpu) \
  (((mask)[((cpu) / n_bits(*(mask)))] >> ((cpu) % n_bits(*(mask)))) & 1)
int
virNumaGetNodeCPUs(int node,
                   virBitmapPtr *cpus)
{
    unsigned long *mask = NULL;
    unsigned long *allonesmask = NULL;
    virBitmapPtr cpumap = NULL;
    int ncpus = 0;
    int max_n_cpus = virNumaGetMaxCPUs();
    int mask_n_bytes = max_n_cpus / 8;
    size_t i;
    int ret = -1;

    *cpus = NULL;

    if (VIR_ALLOC_N(mask, mask_n_bytes / sizeof(*mask)) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(allonesmask, mask_n_bytes / sizeof(*mask)) < 0)
        goto cleanup;

    memset(allonesmask, 0xff, mask_n_bytes);

    /* The first time this returns -1, ENOENT if node doesn't exist... */
    if (numa_node_to_cpus(node, mask, mask_n_bytes) < 0) {
        VIR_WARN("NUMA topology for cell %d is not available, ignoring", node);
        ret = -2;
        goto cleanup;
    }

    /* second, third... times it returns an all-1's mask */
    if (memcmp(mask, allonesmask, mask_n_bytes) == 0) {
        VIR_DEBUG("NUMA topology for cell %d is invalid, ignoring", node);
        ret = -2;
        goto cleanup;
    }

    if (!(cpumap = virBitmapNew(max_n_cpus)))
        goto cleanup;

    for (i = 0; i < max_n_cpus; i++) {
        if (MASK_CPU_ISSET(mask, i)) {
            ignore_value(virBitmapSetBit(cpumap, i));
            ncpus++;
        }
    }

    *cpus = cpumap;
    cpumap = NULL;
    ret = ncpus;

 cleanup:
    VIR_FREE(mask);
    VIR_FREE(allonesmask);
    virBitmapFree(cpumap);

    return ret;
}
# undef MASK_CPU_ISSET
# undef n_bits

#else /* !WITH_NUMACTL */

int
virNumaSetupMemoryPolicy(virDomainNumatuneMemMode mode ATTRIBUTE_UNUSED,
                         virBitmapPtr nodeset)
{
    if (!virNumaNodesetIsAvailable(nodeset))
        return -1;

    return 0;
}

bool
virNumaIsAvailable(void)
{
    return false;
}


int
virNumaGetMaxNode(void)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("NUMA isn't available on this host"));
    return -1;
}


int
virNumaGetNodeMemory(int node ATTRIBUTE_UNUSED,
                     unsigned long long *memsize,
                     unsigned long long *memfree)
{
    if (memsize)
        *memsize = 0;

    if (memfree)
        *memfree = 0;

    VIR_DEBUG("NUMA isn't available on this host");
    return -1;
}


int
virNumaGetNodeCPUs(int node ATTRIBUTE_UNUSED,
                   virBitmapPtr *cpus)
{
    *cpus = NULL;

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("NUMA isn't available on this host"));
    return -1;
}
#endif /* !WITH_NUMACTL */

/**
 * virNumaGetMaxCPUs:
 *
 * Get the maximum count of CPUs supportable in the host.
 *
 * Returns the count of CPUs supported.
 */
unsigned int
virNumaGetMaxCPUs(void)
{
    return NUMA_MAX_N_CPUS;
}


#if WITH_NUMACTL && HAVE_NUMA_BITMASK_ISBITSET
/**
 * virNumaNodeIsAvailable:
 * @node: node to check
 *
 * On some hosts the set of NUMA nodes isn't continuous.
 * Use this function to test if the @node is available.
 *
 * Returns: true if @node is available,
 *          false if @node doesn't exist
 */
bool
virNumaNodeIsAvailable(int node)
{
    return numa_bitmask_isbitset(numa_nodes_ptr, node);
}


/**
 * virNumaGetDistances:
 * @node: identifier of the requested NUMA node
 * @distances: array of distances to sibling nodes
 * @ndistances: size of @distances
 *
 * Get array of distances to sibling nodes from @node. If a
 * distances[x] equals to zero, the node x is not enabled or
 * doesn't exist. As a special case, if @node itself refers to
 * disabled or nonexistent NUMA node, then @distances and
 * @ndistances are set to NULL and zero respectively.
 *
 * The distances are a bit of magic. For a local node the value
 * is 10, for remote it's typically 20 meaning that time penalty
 * for accessing a remote node is two time bigger than when
 * accessing a local node.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virNumaGetDistances(int node,
                    int **distances,
                    int *ndistances)
{
    int ret = -1;
    int max_node;
    size_t i;

    if (!virNumaNodeIsAvailable(node)) {
        VIR_DEBUG("Node %d does not exist", node);
        *distances = NULL;
        *ndistances = 0;
        return 0;
    }

    if ((max_node = virNumaGetMaxNode()) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(*distances, max_node + 1) < 0)
        goto cleanup;

    *ndistances = max_node + 1;

    for (i = 0; i <= max_node; i++) {
        if (!virNumaNodeIsAvailable(node))
            continue;

        (*distances)[i] = numa_distance(node, i);
    }

    ret = 0;
 cleanup:
    return ret;
}

#else /* !(WITH_NUMACTL && HAVE_NUMA_BITMASK_ISBITSET) */

bool
virNumaNodeIsAvailable(int node)
{
    int max_node = virNumaGetMaxNode();

    if (max_node < 0)
        return false;

    /* Do we have anything better? */
    return (node >= 0) && (node <= max_node);
}


int
virNumaGetDistances(int node ATTRIBUTE_UNUSED,
                    int **distances,
                    int *ndistances)
{
    *distances = NULL;
    *ndistances = 0;
    VIR_DEBUG("NUMA distance information isn't available on this host");
    return 0;
}
#endif /* !(WITH_NUMACTL && HAVE_NUMA_BITMASK_ISBITSET) */


/* currently all the huge page stuff below is linux only */
#ifdef __linux__

# define HUGEPAGES_NUMA_PREFIX "/sys/devices/system/node/"
# define HUGEPAGES_SYSTEM_PREFIX "/sys/kernel/mm/hugepages/"
# define HUGEPAGES_PREFIX "hugepages-"

static int
virNumaGetHugePageInfoPath(char **path,
                           int node,
                           unsigned int page_size,
                           const char *suffix)
{
    int ret;

    if (node == -1) {
        /* We are aiming at overall system info */
        ret = virAsprintf(path,
                          HUGEPAGES_SYSTEM_PREFIX HUGEPAGES_PREFIX "%ukB/%s",
                          page_size, suffix ? suffix : "");
    } else {
        /* We are aiming on specific NUMA node */
        ret = virAsprintf(path,
                          HUGEPAGES_NUMA_PREFIX "node%d/hugepages/"
                          HUGEPAGES_PREFIX "%ukB/%s",
                          node, page_size, suffix ? suffix : "");
    }

    if (ret >= 0 && !virFileExists(*path)) {
        ret = -1;
        if (node != -1) {
            if (!virNumaNodeIsAvailable(node)) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("NUMA node %d is not available"),
                               node);
            } else {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("page size %u is not available on node %d"),
                               page_size, node);
            }
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("page size %u is not available"),
                           page_size);
        }
    }

    return ret;
}

static int
virNumaGetHugePageInfoDir(char **path, int node)
{
    if (node == -1) {
        return VIR_STRDUP(*path, HUGEPAGES_SYSTEM_PREFIX);
    } else {
        return virAsprintf(path,
                           HUGEPAGES_NUMA_PREFIX "node%d/hugepages/",
                           node);
    }
}

/**
 * virNumaGetHugePageInfo:
 * @node: NUMA node id
 * @page_size: which huge page are we interested in
 * @page_avail: total number of huge pages in the pool
 * @page_free: the number of free huge pages in the pool
 *
 * For given NUMA node and huge page size fetch information on
 * total number of huge pages in the pool (both free and taken)
 * and count for free huge pages in the pool.
 *
 * If you're interested in just one bit, pass NULL to the other one.
 *
 * As a special case, if @node == -1, overall info is fetched
 * from the system.
 *
 * Returns 0 on success, -1 otherwise (with error reported).
 */
static int
virNumaGetHugePageInfo(int node,
                       unsigned int page_size,
                       unsigned int *page_avail,
                       unsigned int *page_free)
{
    int ret = -1;
    char *path = NULL;
    char *buf = NULL;
    char *end;

    if (page_avail) {
        if (virNumaGetHugePageInfoPath(&path, node,
                                       page_size, "nr_hugepages") < 0)
            goto cleanup;

        if (virFileReadAll(path, 1024, &buf) < 0)
            goto cleanup;

        if (virStrToLong_ui(buf, &end, 10, page_avail) < 0 ||
            *end != '\n') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to parse: %s"),
                           buf);
            goto cleanup;
        }
        VIR_FREE(buf);
        VIR_FREE(path);
    }

    if (page_free) {
        if (virNumaGetHugePageInfoPath(&path, node,
                                       page_size, "free_hugepages") < 0)
            goto cleanup;

        if (virFileReadAll(path, 1024, &buf) < 0)
            goto cleanup;

        if (virStrToLong_ui(buf, &end, 10, page_free) < 0 ||
            *end != '\n') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to parse: %s"),
                           buf);
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    VIR_FREE(buf);
    VIR_FREE(path);
    return ret;
}

/**
 * virNumaGetPageInfo:
 * @node: NUMA node id
 * @page_size: which huge page are we interested in (in KiB)
 * @huge_page_sum: the sum of memory taken by huge pages (in
 * bytes)
 * @page_avail: total number of huge pages in the pool
 * @page_free: the number of free huge pages in the pool
 *
 * For given NUMA node and page size fetch information on
 * total number of pages in the pool (both free and taken)
 * and count for free pages in the pool.
 *
 * The @huge_page_sum parameter exists due to the Linux kernel
 * limitation. The problem is, if there are some huge pages
 * allocated, they are accounted under the 'MemUsed' field in the
 * meminfo file instead of being subtracted from the 'MemTotal'.
 * We must do the subtraction ourselves.
 * If unsure, pass 0.
 *
 * If you're interested in just one bit, pass NULL to the other one.
 *
 * As a special case, if @node == -1, overall info is fetched
 * from the system.
 *
 * Returns 0 on success, -1 otherwise (with error reported).
 */
int
virNumaGetPageInfo(int node,
                   unsigned int page_size,
                   unsigned long long huge_page_sum,
                   unsigned int *page_avail,
                   unsigned int *page_free)
{
    int ret = -1;
    long system_page_size = virGetSystemPageSize();

    /* sysconf() returns page size in bytes,
     * the @page_size is however in kibibytes */
    if (page_size == system_page_size / 1024) {
        unsigned long long memsize, memfree;

        /* TODO: come up with better algorithm that takes huge pages into
         * account. The problem is huge pages cut off regular memory. */
        if (node == -1) {
            if (nodeGetMemory(&memsize, &memfree) < 0)
                goto cleanup;
        } else {
            if (virNumaGetNodeMemory(node, &memsize, &memfree) < 0)
                goto cleanup;
        }

        /* see description above */
        memsize -= huge_page_sum;

        if (page_avail)
            *page_avail = memsize / system_page_size;

        if (page_free)
            *page_free = memfree / system_page_size;
    } else {
        if (virNumaGetHugePageInfo(node, page_size, page_avail, page_free) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}


/**
 * virNumaGetPages:
 * @node: NUMA node id
 * @pages_size: list of pages supported on @node
 * @pages_avail: list of the pool sizes on @node
 * @pages_free: list of free pages on @node
 * @npages: the lists size
 *
 * For given NUMA node fetch info on pages. The size of pages
 * (e.g.  4K, 2M, 1G) is stored into @pages_size, the size of the
 * pool is then stored into @pages_avail and the number of free
 * pages in the pool is stored into @pages_free.
 *
 * If you're interested only in some lists, pass NULL to the
 * other ones.
 *
 * As a special case, if @node == -1, overall info is fetched
 * from the system.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
virNumaGetPages(int node,
                unsigned int **pages_size,
                unsigned int **pages_avail,
                unsigned int **pages_free,
                size_t *npages)
{
    int ret = -1;
    char *path = NULL;
    DIR *dir = NULL;
    int direrr = 0;
    struct dirent *entry;
    unsigned int *tmp_size = NULL, *tmp_avail = NULL, *tmp_free = NULL;
    unsigned int ntmp = 0;
    size_t i;
    bool exchange;
    long system_page_size;
    unsigned long long huge_page_sum = 0;

    /* sysconf() returns page size in bytes,
     * but we are storing the page size in kibibytes. */
    system_page_size = virGetSystemPageSizeKB();

    /* Query huge pages at first.
     * On Linux systems, the huge pages pool cuts off the available memory and
     * is always shown as used memory. Here, however, we want to report
     * slightly different information. So we take the total memory on a node
     * and subtract memory taken by the huge pages. */
    if (virNumaGetHugePageInfoDir(&path, node) < 0)
        goto cleanup;

    if (!(dir = opendir(path))) {
        /* It's okay if the @path doesn't exist. Maybe we are running on
         * system without huge pages support where the path may not exist. */
        if (errno != ENOENT) {
            virReportSystemError(errno,
                                 _("unable to open path: %s"),
                                 path);
            goto cleanup;
        }
    }

    while (dir && (direrr = virDirRead(dir, &entry, path)) > 0) {
        const char *page_name = entry->d_name;
        unsigned int page_size, page_avail = 0, page_free = 0;
        char *end;

        /* Just to give you a hint, we're dealing with this:
         * hugepages-2048kB/  or   hugepages-1048576kB/ */
        if (!STRPREFIX(entry->d_name, HUGEPAGES_PREFIX))
            continue;

        page_name += strlen(HUGEPAGES_PREFIX);

        if (virStrToLong_ui(page_name, &end, 10, &page_size) < 0 ||
            STRCASENEQ(end, "kB")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to parse %s"),
                           entry->d_name);
            goto cleanup;
        }

        if (virNumaGetHugePageInfo(node, page_size,
                                   &page_avail, &page_free) < 0)
            goto cleanup;

        if (VIR_REALLOC_N(tmp_size, ntmp + 1) < 0 ||
            VIR_REALLOC_N(tmp_avail, ntmp + 1) < 0 ||
            VIR_REALLOC_N(tmp_free, ntmp + 1) < 0)
            goto cleanup;

        tmp_size[ntmp] = page_size;
        tmp_avail[ntmp] = page_avail;
        tmp_free[ntmp] = page_free;
        ntmp++;

        /* page_size is in kibibytes while we want huge_page_sum
         * in just bytes. */
        huge_page_sum += 1024 * page_size * page_avail;
    }

    if (direrr < 0)
        goto cleanup;

    /* Now append the ordinary system pages */
    if (VIR_REALLOC_N(tmp_size, ntmp + 1) < 0 ||
        VIR_REALLOC_N(tmp_avail, ntmp + 1) < 0 ||
        VIR_REALLOC_N(tmp_free, ntmp + 1) < 0)
        goto cleanup;

    if (virNumaGetPageInfo(node, system_page_size, huge_page_sum,
                           &tmp_avail[ntmp], &tmp_free[ntmp]) < 0)
        goto cleanup;
    tmp_size[ntmp] = system_page_size;
    ntmp++;

    /* Just to produce nice output, sort the arrays by increasing page size */
    do {
        exchange = false;
        for (i = 0; i < ntmp -1; i++) {
            if (tmp_size[i] > tmp_size[i + 1]) {
                exchange = true;
                SWAP(tmp_size[i], tmp_size[i + 1]);
                SWAP(tmp_avail[i], tmp_avail[i + 1]);
                SWAP(tmp_free[i], tmp_free[i + 1]);
            }
        }
    } while (exchange);

    if (pages_size) {
        *pages_size = tmp_size;
        tmp_size = NULL;
    }
    if (pages_avail) {
        *pages_avail = tmp_avail;
        tmp_avail = NULL;
    }
    if (pages_free) {
        *pages_free = tmp_free;
        tmp_free = NULL;
    }
    *npages = ntmp;
    ret = 0;
 cleanup:
    VIR_FREE(tmp_free);
    VIR_FREE(tmp_avail);
    VIR_FREE(tmp_size);
    if (dir)
        closedir(dir);
    VIR_FREE(path);
    return ret;
}


int
virNumaSetPagePoolSize(int node,
                       unsigned int page_size,
                       unsigned long long page_count,
                       bool add)
{
    int ret = -1;
    char *nr_path = NULL, *nr_buf =  NULL;
    char *end;
    unsigned long long nr_count;

    if (page_size == virGetSystemPageSizeKB()) {
        /* Special case as kernel handles system pages
         * differently to huge pages. */
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("system pages pool can't be modified"));
        goto cleanup;
    }

    if (virNumaGetHugePageInfoPath(&nr_path, node, page_size, "nr_hugepages") < 0)
        goto cleanup;

    /* Firstly check, if there's anything for us to do */
    if (virFileReadAll(nr_path, 1024, &nr_buf) < 0)
        goto cleanup;

    if (virStrToLong_ull(nr_buf, &end, 10, &nr_count) < 0 ||
        *end != '\n') {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("invalid number '%s' in '%s'"),
                       nr_buf, nr_path);
        goto cleanup;
    }

    if (add) {
        if (!page_count) {
            VIR_DEBUG("Nothing left to do: add = true page_count = 0");
            ret = 0;
            goto cleanup;
        }
        page_count += nr_count;
    } else {
        if (nr_count == page_count) {
            VIR_DEBUG("Nothing left to do: nr_count = page_count = %llu",
                      page_count);
            ret = 0;
            goto cleanup;
        }
    }

    /* Okay, page pool adjustment must be done in two steps. In
     * first we write the desired number into nr_hugepages file.
     * Kernel then starts to allocate the pages (return from
     * write should be postponed until the kernel is finished).
     * However, kernel may have not been successful and reserved
     * all the pages we wanted. So do the second read to check.
     */
    VIR_FREE(nr_buf);
    if (virAsprintf(&nr_buf, "%llu", page_count) < 0)
        goto cleanup;

    if (virFileWriteStr(nr_path, nr_buf, 0) < 0) {
        virReportSystemError(errno,
                             _("Unable to write to: %s"), nr_path);
        goto cleanup;
    }

    /* And now do the check. */

    VIR_FREE(nr_buf);
    if (virFileReadAll(nr_path, 1024, &nr_buf) < 0)
        goto cleanup;

    if (virStrToLong_ull(nr_buf, &end, 10, &nr_count) < 0 ||
        *end != '\n') {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("invalid number '%s' in '%s'"),
                       nr_buf, nr_path);
        goto cleanup;
    }

    if (nr_count != page_count) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Unable to allocate %llu pages. Allocated only %llu"),
                       page_count, nr_count);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(nr_buf);
    VIR_FREE(nr_path);
    return ret;
}


#else /* #ifdef __linux__ */
int
virNumaGetPageInfo(int node ATTRIBUTE_UNUSED,
                   unsigned int page_size ATTRIBUTE_UNUSED,
                   unsigned long long huge_page_sum ATTRIBUTE_UNUSED,
                   unsigned int *page_avail ATTRIBUTE_UNUSED,
                   unsigned int *page_free ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                   _("page info is not supported on this platform"));
    return -1;
}


int
virNumaGetPages(int node ATTRIBUTE_UNUSED,
                unsigned int **pages_size ATTRIBUTE_UNUSED,
                unsigned int **pages_avail ATTRIBUTE_UNUSED,
                unsigned int **pages_free ATTRIBUTE_UNUSED,
                size_t *npages ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                   _("page info is not supported on this platform"));
    return -1;
}


int
virNumaSetPagePoolSize(int node ATTRIBUTE_UNUSED,
                       unsigned int page_size ATTRIBUTE_UNUSED,
                       unsigned long long page_count ATTRIBUTE_UNUSED,
                       bool add ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                   _("page pool allocation is not supported on this platform"));
    return -1;
}
#endif /* #ifdef __linux__ */

bool
virNumaNodesetIsAvailable(virBitmapPtr nodeset)
{
    ssize_t bit = -1;

    if (!nodeset)
        return true;

    while ((bit = virBitmapNextSetBit(nodeset, bit)) >= 0) {
        if (virNumaNodeIsAvailable(bit))
            continue;

        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("NUMA node %zd is unavailable"), bit);
        return false;
    }
    return true;
}

virBitmapPtr
virNumaGetHostNodeset(void)
{
    int maxnode = virNumaGetMaxNode();
    size_t i = 0;
    virBitmapPtr nodeset = NULL;

    if (maxnode < 0)
        return NULL;

    if (!(nodeset = virBitmapNew(maxnode + 1)))
        return NULL;

    for (i = 0; i <= maxnode; i++) {
        if (!virNumaNodeIsAvailable(i))
            continue;

        if (virBitmapSetBit(nodeset, i) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Problem setting bit in bitmap"));
            virBitmapFree(nodeset);
            return NULL;
        }
    }

    return nodeset;
}
