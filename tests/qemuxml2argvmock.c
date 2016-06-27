/*
 * Copyright (C) 2014-2016 Red Hat, Inc.
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
#include "viralloc.h"
#include "vircommand.h"
#include "vircrypto.h"
#include "virmock.h"
#include "virnetdev.h"
#include "virnetdevip.h"
#include "virnetdevtap.h"
#include "virnuma.h"
#include "virrandom.h"
#include "virscsi.h"
#include "virstring.h"
#include "virtpm.h"
#include "virutil.h"
#include <time.h>
#include <unistd.h>

#define VIR_FROM_THIS VIR_FROM_NONE

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

char *
virTPMCreateCancelPath(const char *devpath)
{
    char *path;
    (void)devpath;

    ignore_value(VIR_STRDUP(path, "/sys/class/misc/tpm0/device/cancel"));

    return path;
}

/**
 * Large values for memory would fail on 32 bit systems, despite having
 * variables that support it.
 */
unsigned long long
virMemoryMaxValue(bool capped ATTRIBUTE_UNUSED)
{
    return LLONG_MAX;
}

char *
virSCSIDeviceGetSgName(const char *sysfs_prefix ATTRIBUTE_UNUSED,
                       const char *adapter ATTRIBUTE_UNUSED,
                       unsigned int bus ATTRIBUTE_UNUSED,
                       unsigned int target ATTRIBUTE_UNUSED,
                       unsigned long long unit ATTRIBUTE_UNUSED)
{
    char *ret;

    ignore_value(VIR_STRDUP(ret, "sg0"));
    return ret;
}

int
virNetDevTapCreate(char **ifname,
                   const char *tunpath ATTRIBUTE_UNUSED,
                   int *tapfd,
                   size_t tapfdSize,
                   unsigned int flags ATTRIBUTE_UNUSED)
{
    size_t i;

    for (i = 0; i < tapfdSize; i++)
        tapfd[i] = STDERR_FILENO + 1 + i;

    return VIR_STRDUP(*ifname, "vnet0");
}

int
virNetDevSetMAC(const char *ifname ATTRIBUTE_UNUSED,
                const virMacAddr *macaddr ATTRIBUTE_UNUSED)
{
    return 0;
}

int virNetDevIPAddrAdd(const char *ifname ATTRIBUTE_UNUSED,
                       virSocketAddr *addr ATTRIBUTE_UNUSED,
                       virSocketAddr *peer ATTRIBUTE_UNUSED,
                       unsigned int prefix ATTRIBUTE_UNUSED)
{
    return 0;
}

int
virNetDevSetOnline(const char *ifname ATTRIBUTE_UNUSED,
                   bool online ATTRIBUTE_UNUSED)
{
    return 0;
}

int
virNetDevRunEthernetScript(const char *ifname ATTRIBUTE_UNUSED,
                           const char *script ATTRIBUTE_UNUSED)
{
    return 0;
}

void
virCommandPassFD(virCommandPtr cmd ATTRIBUTE_UNUSED,
                 int fd ATTRIBUTE_UNUSED,
                 unsigned int flags ATTRIBUTE_UNUSED)
{
    /* nada */
}

uint8_t *
virCryptoGenerateRandom(size_t nbytes)
{
    uint8_t *buf;

    if (VIR_ALLOC_N(buf, nbytes) < 0)
        return NULL;

    ignore_value(virRandomBytes(buf, nbytes));

    return buf;
}
