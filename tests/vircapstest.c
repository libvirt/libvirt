/*
 * Copyright (C) IBM Corp 2014
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
#include <stdlib.h>

#include "testutils.h"
#include "capabilities.h"
#include "virbitmap.h"


#define VIR_FROM_THIS VIR_FROM_NONE

#define MAX_CELLS 4
#define MAX_CPUS_IN_CELL 2
#define MAX_MEM_IN_CELL 2097152


/*
 * Build  NUMA Toplogy with cell id starting from (0 + seq)
 * for testing
*/
static virCapsPtr
buildNUMATopology(int seq)
{
    virCapsPtr caps;
    virCapsHostNUMACellCPUPtr cell_cpus = NULL;
    int core_id, cell_id;
    int id;

    if ((caps = virCapabilitiesNew(VIR_ARCH_X86_64, 0, 0)) == NULL)
        goto error;

    id = 0;
    for (cell_id = 0; cell_id < MAX_CELLS; cell_id++) {
        if (VIR_ALLOC_N(cell_cpus, MAX_CPUS_IN_CELL) < 0)
            goto error;

        for (core_id = 0; core_id < MAX_CPUS_IN_CELL; core_id++) {
            cell_cpus[core_id].id = id + core_id;
            cell_cpus[core_id].socket_id = cell_id + seq;
            cell_cpus[core_id].core_id = id + core_id;
            if (!(cell_cpus[core_id].siblings =
                  virBitmapNew(MAX_CPUS_IN_CELL)))
                goto error;
            ignore_value(virBitmapSetBit(cell_cpus[core_id].siblings, id));
        }
        id++;

        if (virCapabilitiesAddHostNUMACell(caps, cell_id + seq,
                                           MAX_CPUS_IN_CELL,
                                           MAX_MEM_IN_CELL,
                                           cell_cpus) < 0)
           goto error;

        cell_cpus = NULL;
    }

    return caps;

 error:
    virCapabilitiesClearHostNUMACellCPUTopology(cell_cpus, MAX_CPUS_IN_CELL);
    VIR_FREE(cell_cpus);
    virObjectUnref(caps);
    return NULL;

}


static int
test_virCapabilitiesGetCpusForNodemask(const void *data ATTRIBUTE_UNUSED)
{
    const char *nodestr = "3,4,5,6";
    virBitmapPtr nodemask = NULL;
    virBitmapPtr cpumap = NULL;
    virCapsPtr caps = NULL;
    int mask_size = 8;
    int ret = -1;

    /*
     * Build a NUMA topology with cell_id (NUMA node id
     * being 3(0 + 3),4(1 + 3), 5 and 6
     */
    if (!(caps = buildNUMATopology(3)))
        goto error;

    if (virBitmapParse(nodestr, 0, &nodemask, mask_size) < 0)
        goto error;

    if (!(cpumap = virCapabilitiesGetCpusForNodemask(caps, nodemask)))
        goto error;

    ret = 0;

 error:
    virObjectUnref(caps);
    virBitmapFree(nodemask);
    virBitmapFree(cpumap);
    return ret;

}


static int
mymain(void)
{
    int ret = 0;

    if (virtTestRun("virCapabilitiesGetCpusForNodemask",
                    test_virCapabilitiesGetCpusForNodemask, NULL) < 0)
        ret = -1;

    return ret;
}

VIRT_TEST_MAIN(mymain)
