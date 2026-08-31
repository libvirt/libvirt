/*
 * qemuprocessmock.c: mocks for qemuprocesstest
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
#include "virbitmap.h"
#include "virhostcpu.h"
#include "qemuprocesstest.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static const char *mock_online_cpus;
static const char *mock_isolated_cpus;
static bool mock_has_bitmap = true;

void
qemuProcessMockSetCpus(const char *online,
                        const char *isolated,
                        bool hasBitmap)
{
    mock_online_cpus = online;
    mock_isolated_cpus = isolated;
    mock_has_bitmap = hasBitmap;
}

bool
virHostCPUHasBitmap(void)
{
    return mock_has_bitmap;
}

virBitmap *
virHostCPUGetOnlineBitmap(void)
{
    if (!mock_online_cpus)
        return NULL;
    return virBitmapParseUnlimited(mock_online_cpus);
}

int
virHostCPUGetIsolated(virBitmap **isolated)
{
    *isolated = NULL;
    if (!mock_isolated_cpus)
        return 0;
    if (!(*isolated = virBitmapParseUnlimitedAllowEmpty(mock_isolated_cpus)))
        return -1;
    return 0;
}
