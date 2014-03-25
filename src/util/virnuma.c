/*
 * virnuma.c: helper APIs for managing numa
 *
 * Copyright (C) 2011-2013 Red Hat, Inc.
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

#include "virnuma.h"
#include "vircommand.h"
#include "virerror.h"
#include "virlog.h"
#include "viralloc.h"
#include "virbitmap.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.numa");

VIR_ENUM_IMPL(virDomainNumatuneMemMode,
              VIR_DOMAIN_NUMATUNE_MEM_LAST,
              "strict",
              "preferred",
              "interleave");

VIR_ENUM_IMPL(virNumaTuneMemPlacementMode,
              VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_LAST,
              "default",
              "static",
              "auto");

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
#else
char *
virNumaGetAutoPlacementAdvice(unsigned short vcpus ATTRIBUTE_UNUSED,
                              unsigned long long balloon ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                   _("numad is not available on this host"));
    return NULL;
}
#endif

#if WITH_NUMACTL
int
virNumaSetupMemoryPolicy(virNumaTuneDef numatune,
                         virBitmapPtr nodemask)
{
    nodemask_t mask;
    int mode = -1;
    int node = -1;
    int ret = -1;
    int bit = 0;
    size_t i;
    int maxnode = 0;
    virBitmapPtr tmp_nodemask = NULL;

    if (numatune.memory.placement_mode ==
        VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_STATIC) {
        if (!numatune.memory.nodemask)
            return 0;
        VIR_DEBUG("Set NUMA memory policy with specified nodeset");
        tmp_nodemask = numatune.memory.nodemask;
    } else if (numatune.memory.placement_mode ==
               VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_AUTO) {
        VIR_DEBUG("Set NUMA memory policy with advisory nodeset from numad");
        tmp_nodemask = nodemask;
    } else {
        return 0;
    }

    if (numa_available() < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Host kernel is not aware of NUMA."));
        return -1;
    }

    maxnode = numa_max_node();
    maxnode = maxnode < NUMA_NUM_NODES ? maxnode : NUMA_NUM_NODES;

    /* Convert nodemask to NUMA bitmask. */
    nodemask_zero(&mask);
    bit = -1;
    while ((bit = virBitmapNextSetBit(tmp_nodemask, bit)) >= 0) {
        if (bit > maxnode) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("NUMA node %d is out of range"), bit);
            return -1;
        }
        nodemask_set(&mask, bit);
    }

    mode = numatune.memory.mode;

    if (mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) {
        numa_set_bind_policy(1);
        numa_set_membind(&mask);
        numa_set_bind_policy(0);
    } else if (mode == VIR_DOMAIN_NUMATUNE_MEM_PREFERRED) {
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
    } else if (mode == VIR_DOMAIN_NUMATUNE_MEM_INTERLEAVE) {
        numa_set_interleave_mask(&mask);
    } else {
        /* XXX: Shouldn't go here, as we already do checking when
         * parsing domain XML.
         */
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("Invalid mode for memory NUMA tuning."));
        goto cleanup;
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
 * Returns the highes NUMA node id on success, -1 on error.
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
 * virNumaGetNodeMemorySize:
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
    VIR_FREE(cpumap);

    return ret;
}
# undef MASK_CPU_ISSET
# undef n_bits

#else
int
virNumaSetupMemoryPolicy(virNumaTuneDef numatune,
                         virBitmapPtr nodemask ATTRIBUTE_UNUSED)
{
    if (numatune.memory.nodemask) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("libvirt is compiled without NUMA tuning support"));

        return -1;
    }

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
#endif


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
