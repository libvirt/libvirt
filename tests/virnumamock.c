/*
 * virnumamock.c: Mock some virNuma functions using sysfs
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
#include "virnuma.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define SYSFS_SYSTEM_PATH "/sys/devices/system"

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
        g_autofree char *sysfs_node_path = NULL;

        sysfs_node_path = g_strdup_printf("%s/node", SYSFS_SYSTEM_PATH);

        numa_avail = virFileExists(sysfs_node_path);
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
    g_autoptr(virBitmap) map = NULL;

    if (virFileReadValueBitmap(&map, "%s/node/online", SYSFS_SYSTEM_PATH) < 0)
        return -1;

    return virBitmapLastSetBit(map);
}

bool
virNumaNodeIsAvailable(int node)
{
    g_autoptr(virBitmap) map = NULL;

    if (virFileReadValueBitmap(&map, "%s/node/online", SYSFS_SYSTEM_PATH) < 0)
        return false;

    return virBitmapIsBitSet(map, node);
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
virNumaGetDistances(int node G_GNUC_UNUSED,
                    int **distances,
                    int *ndistances)
{
    *distances = NULL;
    *ndistances = 0;
    return 0;
}

/*
 * TODO: Adapt virNumaGetHugePageInfo{Path,Dir} to use sysfs so that the
 * paths can be modified and this function can be thrown away and instead we'd
 * have copied info from /sys (as we do with /sys/devices/system).
 */
int
virNumaGetPages(int node,
                unsigned int **pages_size,
                unsigned long long **pages_avail,
                unsigned long long **pages_free,
                size_t *npages)
{
    const int pages_def[] = { 4, 2 * 1024, 1 * 1024 * 1024};
    const int npages_def = G_N_ELEMENTS(pages_def);
    size_t i = 0;

    if (pages_size)
        *pages_size = g_new0(unsigned int, npages_def);

    if (pages_avail)
        *pages_avail = g_new0(unsigned long long, npages_def);

    if (pages_free)
        *pages_free = g_new0(unsigned long long, npages_def);

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
virNumaGetNodeCPUs(int node, virBitmap **cpus)
{
    g_autofree char *cpulist = NULL;

    if (virFileReadValueString(&cpulist,
                               "%s/node/node%u/cpulist",
                               SYSFS_SYSTEM_PATH, node) < 0)
        return -1;

    if (STREQ(cpulist, "")) {
        unsigned int max_n_cpus = virNumaGetMaxCPUs();
        *cpus = virBitmapNew(max_n_cpus);
    } else {
        *cpus = virBitmapParseUnlimited(cpulist);
    }
    if (!*cpus)
        return -1;

    return virBitmapCountBits(*cpus);
}

int
virNumaGetNodeOfCPU(int cpu)
{
    g_autoptr(DIR) cpuDir = NULL;
    g_autofree char *sysfs_cpu_path = NULL;
    struct dirent *ent = NULL;
    int dirErr = 0;

    sysfs_cpu_path =  g_strdup_printf("%s/cpu/cpu%d", SYSFS_SYSTEM_PATH, cpu);

    if (virDirOpen(&cpuDir, sysfs_cpu_path) < 0)
        return -1;

    while ((dirErr = virDirRead(cpuDir, &ent, sysfs_cpu_path)) > 0) {
        g_autofree char *entPath = NULL;
        const char *number = NULL;
        int node;

        if (!(number = STRSKIP(ent->d_name, "node")))
            continue;

        entPath = g_strdup_printf("%s/%s", sysfs_cpu_path, ent->d_name);

        if (!virFileIsLink(entPath))
            continue;

        if (virStrToLong_i(number, NULL, 10, &node) < 0) {
            errno = EINVAL;
            return -1;
        }

        return node;
    }

    if (dirErr < 0)
        return -1;

    errno = EINVAL;
    return -1;
}
