/*
 * Copyright (C) 2014 Red Hat, Inc.
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
 * Author: Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>

#include "internal.h"
#include "virnuma.h"
#include "virmock.h"
#include "virutil.h"
#include <time.h>
#include <unistd.h>

long virGetSystemPageSize(void)
{
    return 4096;
}

time_t time(time_t *t)
{
    const time_t ret = 1234567890;
    if (t)
        *t = ret;
    return ret;
}

int
virNumaGetMaxNode(void)
{
   const int maxnodesNum = 7;

   return maxnodesNum;
}

#if WITH_NUMACTL && HAVE_NUMA_BITMASK_ISBITSET
/*
 * In case libvirt is compiled with full NUMA support, we need to mock
 * this function in order to fake what numa nodes are available.
 */
bool
virNumaNodeIsAvailable(int node)
{
    return node >= 0 && node <= virNumaGetMaxNode();
}
#endif /* WITH_NUMACTL && HAVE_NUMA_BITMASK_ISBITSET */
