/*
 * virnumamock.c: Mock some virNuma functions using virsysfs
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
 */

#include <config.h>

#include "internal.h"
#include "virmock.h"
#include "virnuma.h"
#include "virfile.h"
#include "viralloc.h"
#include "virstring.h"
#include "virsysfspriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static int numa_avail = -1;


/*
 * Poor man's mocked NUMA guesser.  We basically check if
 * /sys/devices/system/node (where /sys/devices/system can already be mocked or
 * changed in the tests) exists and cache the result.
 */
bool
virNumaIsAvailable(void)
{
    if (numa_avail < 0) {
        char *sysfs_node_path = NULL;

        if (virAsprintfQuiet(&sysfs_node_path, "%s/node", virSysfsGetSystemPath()) < 0)
            return false;

        numa_avail = virFileExists(sysfs_node_path);

        VIR_FREE(sysfs_node_path);
    }

    /*
     * Quite a few more things need to be mocked if NUMA is not available and
     * you are using this file.  Do not remove the abort() call below unless you
     * make sure all under virCapabilitiesInitNUMAFake() is mocked (and whatever
     * might have changed since this comment was added.  You are welcome.
     */
    if (!numa_avail)
        abort();

    return numa_avail;
}

int
virNumaGetMaxNode(void)
{
    int ret = -1;
    virBitmapPtr map = NULL;

    if (virSysfsGetValueBitmap("node/online", &map) < 0)
        return -1;

    ret = virBitmapLastSetBit(map);
    virBitmapFree(map);
    return ret;
}

bool
virNumaNodeIsAvailable(int node)
{
    bool ret = false;
    virBitmapPtr map = NULL;

    if (virSysfsGetValueBitmap("node/online", &map) < 0)
        return false;

    ret = virBitmapIsBitSet(map, node);
    virBitmapFree(map);
    return ret;
}

int
virNumaGetNodeMemory(int node,
                     unsigned long long *memsize,
                     unsigned long long *memfree)
{
    const unsigned long long base = 1 << 30;

    if (memsize)
        *memsize = base * (node + 1);

    if (memfree)
        *memfree = base;

    return 0;
}

int
virNumaGetDistances(int node ATTRIBUTE_UNUSED,
                    int **distances,
                    int *ndistances)
{
    *distances = NULL;
    *ndistances = 0;
    return 0;
}

/*
 * TODO: Adapt virNumaGetHugePageInfo{Path,Dir} to use virsysfs so that the
 * paths can be modified and this function can be thrown away and instead we'd
 * have copied info from /sys (as we do with /sys/devices/system).
 */
int
virNumaGetPages(int node,
                unsigned int **pages_size,
                unsigned int **pages_avail,
                unsigned int **pages_free,
                size_t *npages)
{
    const int pages_def[] = { 4, 2 * 1024, 1 * 1024 * 1024};
    const int npages_def = ARRAY_CARDINALITY(pages_def);
    size_t i = 0;

    if (pages_size)
        *pages_size = NULL;

    if (pages_avail)
        *pages_avail = NULL;

    if (pages_free)
        *pages_free = NULL;

    *npages = 0;

    if ((pages_size && VIR_ALLOC_N(*pages_size, npages_def) < 0) ||
        (pages_avail && VIR_ALLOC_N(*pages_avail, npages_def) < 0) ||
        (pages_free && VIR_ALLOC_N(*pages_free, npages_def) < 0)) {
        VIR_FREE(*pages_size);
        VIR_FREE(*pages_avail);
        return -1;
    }

    *npages = npages_def;
    if (pages_size)
        memcpy(*pages_size, pages_def, sizeof(pages_def));

    node++;
    if (node <= 0)
        node = 32;

    if (pages_avail || pages_free) {
        for (i = 0; i < *npages; i++) {
            if (pages_avail)
                (*pages_avail)[i] = (node + i) * 2 << 10;
            if (pages_free)
                (*pages_free)[i] = (node + i) * 1 << 10;
        }
    }

    return 0;
}

int
virNumaGetNodeCPUs(int node, virBitmapPtr *cpus)
{
    int ret = -1;
    char *cpulist = NULL;

    if (virSysfsGetNodeValueString(node, "cpulist", &cpulist) < 0)
        return -1;

    *cpus = virBitmapParseUnlimited(cpulist);
    if (!*cpus)
        goto cleanup;

    ret = virBitmapCountBits(*cpus);
 cleanup:
    VIR_FREE(cpulist);
    return ret;
}
