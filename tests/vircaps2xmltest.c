/*
 * Copyright (C) Red Hat, Inc. 2014
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
 * Authors:
 *      Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>
#include <stdlib.h>

#include "testutils.h"
#include "capabilities.h"
#include "virbitmap.h"


#define VIR_FROM_THIS VIR_FROM_NONE

static virCapsPtr
buildVirCapabilities(int max_cells,
                     int max_cpus_in_cell,
                     int max_mem_in_cell)
{
    virCapsPtr caps;
    virCapsHostNUMACellCPUPtr cell_cpus = NULL;
    virCapsHostNUMACellSiblingInfoPtr siblings = NULL;
    int core_id, cell_id, nsiblings;
    int id;
    size_t i;

    if ((caps = virCapabilitiesNew(VIR_ARCH_X86_64, false, false)) == NULL)
        goto error;

    id = 0;
    for (cell_id = 0; cell_id < max_cells; cell_id++) {
        if (VIR_ALLOC_N(cell_cpus, max_cpus_in_cell) < 0)
            goto error;

        for (core_id = 0; core_id < max_cpus_in_cell; core_id++) {
            cell_cpus[core_id].id = id;
            cell_cpus[core_id].socket_id = cell_id;
            cell_cpus[core_id].core_id = id + core_id;
            if (!(cell_cpus[core_id].siblings =
                  virBitmapNew(max_cpus_in_cell)))
                goto error;
            ignore_value(virBitmapSetBit(cell_cpus[core_id].siblings, id));
        }
        id++;

        if (VIR_ALLOC_N(siblings, max_cells) < 0)
            goto error;
        nsiblings = max_cells;

        for (i = 0; i < nsiblings; i++) {
            siblings[i].node = i;
            /* Some magical constants, see virNumaGetDistances()
             * for their description. */
            siblings[i].distance = cell_id == i ? 10 : 20;
        }

        if (virCapabilitiesAddHostNUMACell(caps, cell_id,
                                           max_mem_in_cell,
                                           max_cpus_in_cell, cell_cpus,
                                           nsiblings, siblings,
                                           0, NULL) < 0)
           goto error;

        cell_cpus = NULL;
        siblings = NULL;
    }

    return caps;

 error:
    virCapabilitiesClearHostNUMACellCPUTopology(cell_cpus, max_cpus_in_cell);
    VIR_FREE(cell_cpus);
    VIR_FREE(siblings);
    virObjectUnref(caps);
    return NULL;
}


struct virCapabilitiesFormatData {
    const char *filename;
    int max_cells;
    int max_cpus_in_cell;
    int max_mem_in_cell;
};

static int
test_virCapabilitiesFormat(const void *opaque)
{
    struct virCapabilitiesFormatData *data = (struct virCapabilitiesFormatData *) opaque;
    virCapsPtr caps = NULL;
    char *capsXML = NULL;
    char *path = NULL;
    int ret = -1;

    if (!(caps = buildVirCapabilities(data->max_cells, data->max_cpus_in_cell,
                                      data->max_mem_in_cell)))
        goto cleanup;

    if (!(capsXML = virCapabilitiesFormatXML(caps)))
        goto cleanup;

    if (virAsprintf(&path, "%s/vircaps2xmldata/vircaps-%s.xml",
                    abs_srcdir, data->filename) < 0)
        goto cleanup;

    if (virtTestCompareToFile(capsXML, path) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(path);
    VIR_FREE(capsXML);
    virObjectUnref(caps);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(filename, max_cells,                                        \
                max_cpus_in_cell, max_mem_in_cell)                          \
    do {                                                                    \
        struct virCapabilitiesFormatData data = {filename, max_cells,       \
                                                 max_cpus_in_cell,          \
                                                 max_mem_in_cell};          \
        if (virtTestRun(filename, test_virCapabilitiesFormat, &data) < 0)   \
        ret = -1;                                                           \
    } while (0)

    DO_TEST("basic-4-4-2G", 4, 4, 2*1024*1024);

    return ret;
}

VIRT_TEST_MAIN(mymain)
