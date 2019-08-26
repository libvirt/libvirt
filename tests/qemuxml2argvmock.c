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
#include "virnetdevopenvswitch.h"
#include "virnuma.h"
#include "virrandom.h"
#include "virscsi.h"
#include "virscsivhost.h"
#include "virstring.h"
#include "virtpm.h"
#include "virutil.h"
#include "qemu/qemu_interface.h"
#include "qemu/qemu_command.h"
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

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

bool
virNumaIsAvailable(void)
{
    return true;
}

int
virNumaGetMaxNode(void)
{
    return 7;
}

/* We shouldn't need to mock virNumaNodeIsAvailable() and *definitely* not
 * virNumaNodesetIsAvailable(), but it seems to be the only way to get
 * mocking to work with Clang on FreeBSD, so keep these duplicates around
 * until we figure out a cleaner solution */
bool
virNumaNodeIsAvailable(int node)
{
    return node >= 0 && node <= virNumaGetMaxNode();
}

bool
virNumaNodesetIsAvailable(virBitmapPtr nodeset)
{
    ssize_t bit = -1;

    if (!nodeset)
        return true;

    while ((bit = virBitmapNextSetBit(nodeset, bit)) >= 0) {
        if (virNumaNodeIsAvailable(bit))
            continue;

        return false;
    }

    return true;
}

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
virSCSIVHostOpenVhostSCSI(int *vhostfd)
{
    *vhostfd = STDERR_FILENO + 1;

    return 0;
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

    if (STREQ_NULLABLE(*ifname, "mytap0")) {
        return 0;
    } else {
        VIR_FREE(*ifname);
        return VIR_STRDUP(*ifname, "vnet0");
    }
}

int
virNetDevSetMAC(const char *ifname ATTRIBUTE_UNUSED,
                const virMacAddr *macaddr ATTRIBUTE_UNUSED)
{
    return 0;
}


int
virNetDevExists(const char *ifname)
{
    return STREQ_NULLABLE(ifname, "mytap0");
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

char *
virHostGetDRMRenderNode(void)
{
    char *dst = NULL;

    ignore_value(VIR_STRDUP(dst, "/dev/dri/foo"));
    return dst;
}

static void (*real_virCommandPassFD)(virCommandPtr cmd, int fd, unsigned int flags);

static const int testCommandPassSafeFDs[] = { 1730, 1731 };

void
virCommandPassFD(virCommandPtr cmd,
                 int fd,
                 unsigned int flags)
{
    size_t i;

    for (i = 0; i < ARRAY_CARDINALITY(testCommandPassSafeFDs); i++) {
        if (testCommandPassSafeFDs[i] == fd) {
            if (!real_virCommandPassFD)
                VIR_MOCK_REAL_INIT(virCommandPassFD);

            real_virCommandPassFD(cmd, fd, flags);
            return;
        }
    }
}

int
virNetDevOpenvswitchGetVhostuserIfname(const char *path ATTRIBUTE_UNUSED,
                                       char **ifname)
{
    return VIR_STRDUP(*ifname, "vhost-user0");
}

int
qemuInterfaceOpenVhostNet(virDomainDefPtr def ATTRIBUTE_UNUSED,
                          virDomainNetDefPtr net,
                          int *vhostfd,
                          size_t *vhostfdSize)
{
    size_t i;

    if (!virDomainNetIsVirtioModel(net)) {
        *vhostfdSize = 0;
        return 0;
    }

    for (i = 0; i < *vhostfdSize; i++)
        vhostfd[i] = STDERR_FILENO + 42 + i;
    return 0;
}


int
qemuOpenChrChardevUNIXSocket(const virDomainChrSourceDef *dev ATTRIBUTE_UNUSED)

{
    /* We need to return an FD number for a UNIX listener socket,
     * which will be given to QEMU via a CLI arg. We need a fixed
     * number to get stable tests. This is obviously not a real
     * FD number, so when virCommand closes the FD in the parent
     * it will get EINVAL, but that's (hopefully) not going to
     * be a problem....
     */
    if (fcntl(1729, F_GETFD) != -1)
        abort();
    return 1729;
}


int
qemuBuildTPMOpenBackendFDs(const char *tpmdev ATTRIBUTE_UNUSED,
                           const char *cancel_path ATTRIBUTE_UNUSED,
                           int *tpmfd,
                           int *cancelfd)
{
    if (fcntl(1730, F_GETFD) != -1 ||
        fcntl(1731, F_GETFD) != -1)
        abort();

    *tpmfd = 1730;
    *cancelfd = 1731;
    return 0;
}
