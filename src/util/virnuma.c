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

#if WITH_NUMACTL
# define NUMA_VERSION1_COMPATIBILITY 1
# include <numa.h>
#endif

#include "virnuma.h"
#include "vircommand.h"
#include "virerror.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

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

    maxnode = numa_max_node() + 1;

    /* Convert nodemask to NUMA bitmask. */
    nodemask_zero(&mask);
    bit = -1;
    while ((bit = virBitmapNextSetBit(tmp_nodemask, bit)) >= 0) {
        if (bit > maxnode || bit > NUMA_NUM_NODES) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Nodeset is out of range, host cannot support "
                             "NUMA node bigger than %d"), bit);
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
#endif
