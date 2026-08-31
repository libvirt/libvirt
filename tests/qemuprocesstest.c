/*
 * qemuprocesstest.c: tests for qemu_process.c internals
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

#include "testutils.h"
#include "virbitmap.h"
#include "qemu/qemu_process.h"
#include "qemuprocesstest.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

/*
 * Case 1: no isolated CPUs (sysfs file absent).
 *
 * qemuProcessGetAllCpuAffinity() must return NULL, indicating that
 * sched_setaffinity() should NOT be called so that CPUs hot-plugged
 * after startup remain usable.
 */
static int
testGetAllCpuAffinityNoIsolated(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) result = NULL;

    qemuProcessMockSetCpus("0-7", NULL, true);

    if (qemuProcessGetAllCpuAffinity(&result) < 0)
        return -1;

    if (result) {
        g_autofree char *str = virBitmapFormat(result);
        fprintf(stderr,
                "expected NULL (no sched_setaffinity) when no isolated CPUs, "
                "got '%s'\n", str);
        return -1;
    }

    return 0;
}


/*
 * Case 2: isolated CPUs that DO overlap with online CPUs.
 *
 * qemuProcessGetAllCpuAffinity() must return the online set minus the
 * isolated set so that QEMU is pinned away from the isolated cores.
 */
static int
testGetAllCpuAffinityOverlapping(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) result = NULL;
    g_autofree char *str = NULL;

    qemuProcessMockSetCpus("0-7", "6-7", true);

    if (qemuProcessGetAllCpuAffinity(&result) < 0)
        return -1;

    if (!result) {
        fprintf(stderr,
                "expected non-NULL affinity map when isolated CPUs overlap "
                "online CPUs\n");
        return -1;
    }

    str = virBitmapFormat(result);
    if (STRNEQ(str, "0-5")) {
        fprintf(stderr, "expected '0-5', got '%s'\n", str);
        return -1;
    }

    return 0;
}


/*
 * Case 3: isolated CPUs that do NOT overlap with online CPUs.
 *
 * This is the hot-plug regression scenario: CPUs 8-9 are listed as
 * isolated but are not currently online (online = 0-7).  Before the
 * fix, the function returned the full online bitmap, causing
 * sched_setaffinity() to pin QEMU to CPUs 0-7 at startup and thereby
 * preventing any subsequently hot-plugged CPU from being used.
 * After the fix it must return NULL.
 */
static int
testGetAllCpuAffinityNonOverlapping(const void *opaque G_GNUC_UNUSED)
{
    g_autoptr(virBitmap) result = NULL;

    qemuProcessMockSetCpus("0-7", "8-9", true);

    if (qemuProcessGetAllCpuAffinity(&result) < 0)
        return -1;

    if (result) {
        g_autofree char *str = virBitmapFormat(result);
        fprintf(stderr,
                "expected NULL when isolated CPUs do not overlap online CPUs "
                "(hot-plug regression), got '%s'\n", str);
        return -1;
    }

    return 0;
}


static int
mymain(void)
{
    int ret = 0;

#define DO_TEST(desc, func) \
    do { \
        if (virTestRun(desc, func, NULL) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST("GetAllCpuAffinity: no isolated CPUs -> NULL",
            testGetAllCpuAffinityNoIsolated);
    DO_TEST("GetAllCpuAffinity: overlapping isolated CPUs -> online minus isolated",
            testGetAllCpuAffinityOverlapping);
    DO_TEST("GetAllCpuAffinity: non-overlapping isolated CPUs -> NULL (hot-plug fix)",
            testGetAllCpuAffinityNonOverlapping);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
